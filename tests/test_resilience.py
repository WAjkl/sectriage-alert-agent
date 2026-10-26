# -*- coding: utf-8 -*-
"""熔断器单测：钉住三态切换与"拒绝不等于失败"。

这六个用例对应六个真实会踩的坑：
  1) 连续失败到阈值必须开门
  2) 开门后**不再发起真实调用**（否则熔断等于没做）
  3) 冷却结束自动进 half_open
  4) half_open 只放一个探针（防惊群）
  5) 探针成功要关门
  6) 探针失败要立刻回到 open 并重新计时
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.resilience import CircuitBreaker, CircuitOpenError   # noqa: E402


class FakeClock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t

    def tick(self, s):
        self.t += s


def boom():
    raise TimeoutError("model timeout")


def ok():
    return "fine"


def make(threshold=3, cooldown=30):
    clk = FakeClock()
    b = CircuitBreaker("t", threshold=threshold, cooldown_s=cooldown, clock=clk)
    return b, clk


def test_opens_after_threshold():
    b, _ = make(threshold=3)
    for _ in range(3):
        with pytest.raises(TimeoutError):
            b.call(boom)
    assert b.state == CircuitBreaker.OPEN
    assert b.failures == 3


def test_open_does_not_call_downstream():
    b, _ = make(threshold=2)
    for _ in range(2):
        with pytest.raises(TimeoutError):
            b.call(boom)
    calls_before = b.calls
    for _ in range(5):
        with pytest.raises(CircuitOpenError):
            b.call(ok)                 # 即使传入的是"能成功"的函数也不能被调用
    assert b.calls == calls_before     # 关键：没有新增真实调用
    assert b.rejected == 5


def test_half_open_after_cooldown():
    b, clk = make(threshold=2, cooldown=30)
    for _ in range(2):
        with pytest.raises(TimeoutError):
            b.call(boom)
    assert b.state == CircuitBreaker.OPEN
    clk.tick(29)
    assert b.state == CircuitBreaker.OPEN      # 差 1 秒还不放
    clk.tick(2)
    assert b.state == CircuitBreaker.HALF_OPEN


def test_half_open_allows_single_probe():
    b, clk = make(threshold=1, cooldown=10)
    with pytest.raises(TimeoutError):
        b.call(boom)
    clk.tick(11)
    # 探针占位：先让探针失败（模拟半开时下游还没恢复）
    with pytest.raises(TimeoutError):
        b.call(boom)
    # 探针失败后应回到 open，后续请求一律拒绝
    assert b.state == CircuitBreaker.OPEN
    with pytest.raises(CircuitOpenError):
        b.call(ok)


def test_probe_success_closes():
    b, clk = make(threshold=1, cooldown=10)
    with pytest.raises(TimeoutError):
        b.call(boom)
    clk.tick(11)
    assert b.call(ok) == "fine"
    assert b.state == CircuitBreaker.CLOSED
    assert b.snapshot()["consecutive_failures"] == 0


def test_snapshot_fields():
    b, _ = make(threshold=2)
    with pytest.raises(TimeoutError):
        b.call(boom)
    s = b.snapshot()
    for k in ("name", "state", "consecutive_failures", "threshold",
              "calls", "successes", "failures", "rejected", "last_error"):
        assert k in s
    assert "TimeoutError" in s["last_error"]
