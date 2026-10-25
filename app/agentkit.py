# -*- coding: utf-8 -*-
"""agentkit —— 一个 150 行的通用 Agent 内核。

它不关心业务：告警研判、数据问答、文档处理都用同一套 loop。

为什么单独抽出来：
  面试"通用 Agent 岗"时，对方关心的不是"你会不会做安全"，
  而是"你写的 Agent 是绑死在某个场景，还是领域无关的"。
  这个文件就是回答：工具注册表 + 记忆 + 循环 + 三道闸 + 轨迹，全部与业务解耦。

用法：
    from agentkit import ToolRegistry, Agent, Policy
    reg = ToolRegistry(); reg.register("foo", fn, "说明")
    agent = Agent(reg, policy=MyPolicy())
    result = agent.run(task)     # 返回 verdict/steps/trace
"""
import json
import time
import hashlib
from typing import Any, Callable, Dict, List, Optional


# ============ 1. 工具注册表 ============
class ToolRegistry:
    """工具必须显式注册（白名单），未注册的一律拒绝。

    为什么不搞"自动发现"：Agent 能调什么必须由人决定，
    否则模型幻觉出一个工具名，系统要么崩要么乱调。
    """

    def __init__(self):
        self._tools: Dict[str, dict] = {}

    def register(self, name: str, fn: Callable, desc: str = "", schema: dict = None):
        self._tools[name] = {"fn": fn, "desc": desc, "schema": schema or {}}
        return self

    def has(self, name: str) -> bool:
        return name in self._tools

    def specs(self) -> List[dict]:
        """给模型看的工具清单（OpenAI tools 格式的简化版）。"""
        return [{"name": k, "description": v["desc"], "parameters": v["schema"]}
                for k, v in self._tools.items()]

    def call(self, name: str, args: dict) -> dict:
        if name not in self._tools:
            return {"error": "unknown_tool", "tool": name}      # 不抛异常，交给策略处理
        fn = self._tools[name]["fn"]
        try:
            return {"ok": True, "result": fn(**args)}
        except TypeError as e:
            return {"error": "bad_args", "detail": str(e)[:120]}
        except Exception as e:
            # 工具报错要回到循环里让模型知道，而不是让整个 Agent 挂掉
            return {"error": "tool_failed", "detail": str(e)[:120]}


# ============ 2. 记忆 ============
class Memory:
    """短期 = 本次轨迹；长期 = 跨任务的 key-value（这里用内存实现，生产可换 Redis）。"""

    def __init__(self):
        self.trace: List[dict] = []
        self.kv: Dict[str, Any] = {}

    def add(self, step: dict):
        self.trace.append(step)

    def remember(self, key: str, value: Any):
        self.kv[key] = value

    def recall(self, key: str, default=None):
        return self.kv.get(key, default)

    def to_json(self) -> str:
        return json.dumps(self.trace, ensure_ascii=False, indent=1)


# ============ 3. 策略接口（可插拔）============
class Policy:
    """决定"下一步做什么"。可以是用规则写的，也可以是 LLM。

    这样设计的好处：换决策器不动 loop；
    没有 API key 时用规则版跑通链路，有 key 时换成 LLM 版，接口一样。
    """

    def next_action(self, task: dict, memory: Memory) -> dict:
        raise NotImplementedError

    def is_final(self, action: dict) -> bool:
        return action.get("tool") in ("finish", "close_alert")


# ============ 4. 循环 + 三道闸 ============
class Agent:
    MAX_STEPS = 6
    TOKEN_BUDGET = 6000
    EST_TOKENS_PER_STEP = 800

    def __init__(self, registry: ToolRegistry, policy: Policy,
                 max_steps: int = None, token_budget: int = None):
        self.reg = registry
        self.policy = policy
        self.max_steps = max_steps or self.MAX_STEPS
        self.token_budget = token_budget or self.TOKEN_BUDGET

    def run(self, task: dict, verbose: bool = False) -> dict:
        mem, seen, tokens = Memory(), set(), 0

        for step in range(1, self.max_steps + 1):
            tokens += self.EST_TOKENS_PER_STEP
            if tokens > self.token_budget:                       # 闸② 预算
                return self._final("need_human", 0.4, "token 预算超限", mem, step, "budget")

            action = self.policy.next_action(task, mem)
            tool, args = action.get("tool"), action.get("args", {}) or {}

            # 闸③ 重复检测：同名工具 + 同参数
            key = tool + "|" + json.dumps(args, sort_keys=True, ensure_ascii=False)
            h = hashlib.md5(key.encode()).hexdigest()[:10]
            if h in seen:
                return self._final("need_human", 0.4, "检测到重复调用", mem, step, "dup")
            seen.add(h)

            if self.policy.is_final(action):                      # 收尾
                mem.add({"step": step, "tool": tool, "args": args, "result": args})
                return self._final(args.get("verdict", "done"),
                                   float(args.get("confidence", 0.8)),
                                   args.get("reason", ""), mem, step, "finish",
                                   args.get("sop_id", ""))

            res = self.reg.call(tool, args)
            mem.add({"step": step, "tool": tool, "args": args, "result": res})
            if verbose:
                print("   step%d %-20s %s → %s" % (step, tool, args,
                                                   json.dumps(res, ensure_ascii=False)[:90]))

        return self._final("need_human", 0.4, "达到最大步数", mem, self.max_steps, "max_steps")   # 闸①

    @staticmethod
    def _final(verdict, conf, reason, mem: Memory, steps, stop, ref=""):
        return {"verdict": verdict, "confidence": conf, "reason": reason,
                "ref": ref, "steps": steps, "stop_reason": stop,
                "tools_used": [t["tool"] for t in mem.trace],
                "trace": mem.trace}


# ============ 5. 轨迹评测 ============
def evaluate(results: List[dict], expect_tools: List[str] = None) -> dict:
    """不只看结论对不对，还看"该查的有没有查"。"""
    n = len(results) or 1
    steps = [r["steps"] for r in results]
    coverage = []
    for r in results:
        if not expect_tools:
            continue
        used = set(r["tools_used"])
        coverage.append(len(used & set(expect_tools)) / len(expect_tools))
    return {
        "tasks": len(results),
        "avg_steps": round(sum(steps) / n, 2),
        "max_steps_used": max(steps) if steps else 0,
        "stop_reasons": {s: sum(1 for r in results if r["stop_reason"] == s)
                         for s in set(r["stop_reason"] for r in results)},
        "tool_coverage": round(sum(coverage) / len(coverage), 4) if coverage else None,
        "avg_confidence": round(sum(r["confidence"] for r in results) / n, 3),
    }
