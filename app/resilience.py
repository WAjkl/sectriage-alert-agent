# -*- coding: utf-8 -*-
"""三态熔断器：closed → open → half_open。

为什么需要（这是真实故障，不是理论）：
  研判层对每个事件调一次模型。模型服务挂掉时，`_call_llm` 每次都要等满超时
  （默认 25s）。40 个事件 = 最坏 1000 秒。用户看到的是"页面一直转圈"，
  而且这 1000 秒里每一次都是注定失败的调用。

熔断做三件事：
  1) 连续失败到阈值就"开门"，之后**直接拒绝**，不再等超时（毫秒级返回）
  2) 冷却结束后进入"半开"，只放**一次**探针出去试水
  3) 探针成功 → 关门恢复；探针失败 → 重新开门的冷却计时

设计取舍（面试会被追问）：
  - 用**连续失败**计数而不是错误率：单实例、低 QPS，错误率需要滑窗，反而更复杂。
  - 冷却用**固定时长**而不是指数退避：模型故障通常是分钟级（重启/限流），
    固定 30 秒足够；指数退避会让恢复时间不可预测，排查时更难受。
  - 半开只放 1 个探针：放多了会把刚恢复的服务再打死（惊群）。
"""
import threading
import time
from typing import Callable, Dict, Optional


class CircuitOpenError(Exception):
    """熔断打开时抛出。注意：它不是"调用失败"，不计入失败计数。"""


class CircuitBreaker:
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"

    def __init__(self, name: str = "llm", threshold: int = 3,
                 cooldown_s: float = 30.0, clock: Callable[[], float] = None):
        self.name = name
        self.threshold = threshold
        self.cooldown_s = cooldown_s
        self._clock = clock or time.monotonic
        self._lock = threading.Lock()
        self._state = self.CLOSED
        self._fails = 0
        self._opened_at = 0.0
        self._probe_taken = False
        # 指标（给 /resilience 看，也给面试讲）
        self.calls = 0
        self.failures = 0
        self.rejected = 0
        self.successes = 0
        self.last_error: Optional[str] = None
        self.last_state_change = self._clock()

    # ---------- 状态 ----------
    @property
    def state(self) -> str:
        with self._lock:
            self._maybe_half_open()
            return self._state

    def _maybe_half_open(self):
        """冷却结束自动从 open 转 half_open（调用方无需关心时间）。"""
        if self._state == self.OPEN and self._clock() - self._opened_at >= self.cooldown_s:
            self._state = self.HALF_OPEN
            self._probe_taken = False
            self.last_state_change = self._clock()

    # ---------- 主入口 ----------
    def call(self, fn: Callable, *args, **kwargs):
        with self._lock:
            self._maybe_half_open()
            if self._state == self.OPEN:
                self.rejected += 1
                raise CircuitOpenError(
                    "%s 熔断中（已拒 %d 次），不再发起真实调用" % (self.name, self.rejected))
            if self._state == self.HALF_OPEN:
                if self._probe_taken:
                    self.rejected += 1
                    raise CircuitOpenError("%s 半开中，探针已发出，其余请求直接拒绝" % self.name)
                self._probe_taken = True
            self.calls += 1

        try:
            out = fn(*args, **kwargs)
        except Exception as e:
            self._on_failure(e)
            raise
        self._on_success()
        return out

    def _on_success(self):
        with self._lock:
            self.successes += 1
            self._fails = 0
            if self._state in (self.HALF_OPEN, self.OPEN):
                self._state = self.CLOSED
                self.last_state_change = self._clock()

    def _on_failure(self, e: Exception):
        with self._lock:
            self.failures += 1
            self.last_error = ("%s: %s" % (e.__class__.__name__, str(e)))[:120]
            self._fails += 1
            if self._state == self.HALF_OPEN:
                # 探针挂了：立刻回到 open，重新计时
                self._state = self.OPEN
                self._opened_at = self._clock()
                self.last_state_change = self._clock()
            elif self._fails >= self.threshold:
                self._state = self.OPEN
                self._opened_at = self._clock()
                self.last_state_change = self._clock()

    # ---------- 观测 ----------
    def snapshot(self) -> Dict:
        with self._lock:
            self._maybe_half_open()
            return {
                "name": self.name,
                "state": self._state,
                "consecutive_failures": self._fails,
                "threshold": self.threshold,
                "cooldown_s": self.cooldown_s,
                "calls": self.calls,
                "successes": self.successes,
                "failures": self.failures,
                "rejected": self.rejected,
                "last_error": self.last_error,
                "open_for_s": round(self._clock() - self._opened_at, 1)
                if self._state != self.CLOSED else 0,
            }

    def reset(self):
        """手工复位（运维用：确认下游恢复后立刻放行，不用等冷却）。"""
        with self._lock:
            self._state = self.CLOSED
            self._fails = 0
            self._probe_taken = False
            self.last_state_change = self._clock()


# 全局单例：研判层共用同一个（模型服务是同一个下游，没必要每个事件一个）
from . import config as _cfg          # 延迟导入，避免循环依赖

LLM_BREAKER = CircuitBreaker(
    "llm",
    threshold=_cfg.BREAKER_THRESHOLD,
    cooldown_s=_cfg.BREAKER_COOLDOWN,
)
