# -*- coding: utf-8 -*-
"""第二个领域：数据问答 Agent（和告警研判用同一个内核）。

存在的意义只有一句话：
  **证明 agentkit 是领域无关的**——同一个 loop、同一套三道闸、同一套轨迹评测，
  只换工具注册表和策略，就能做完全不同的活。

跑法：
    python examples/data_qa_agent.py
"""
import os
import sys
import csv
import json

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from app.agentkit import ToolRegistry, Agent, Policy, evaluate   # noqa: E402

CSV_PATH = os.path.join(ROOT, "data", "sales.csv")


def ensure_data():
    """造一份销售数据（真实项目这里是查数据库）。"""
    if os.path.exists(CSV_PATH):
        return
    os.makedirs(os.path.dirname(CSV_PATH), exist_ok=True)
    rows = [
        ("2026-01", "华南", 128000, 420), ("2026-02", "华南", 96000, 310),
        ("2026-03", "华南", 154000, 505), ("2026-01", "华东", 176000, 610),
        ("2026-02", "华东", 132000, 470), ("2026-03", "华东", 188000, 690),
        ("2026-01", "华北", 87000, 260), ("2026-02", "华北", 79000, 240),
        ("2026-03", "华北", 92000, 300),
    ]
    with open(CSV_PATH, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["month", "region", "amount", "orders"])
        w.writerows(rows)


def load_rows():
    with open(CSV_PATH, encoding="utf-8") as f:
        return list(csv.DictReader(f))


# ============ 领域 B 的工具（和安全零关系）============
def tool_list_columns():
    rows = load_rows()
    return {"columns": list(rows[0].keys()), "rows": len(rows)}


def tool_aggregate(column: str, fn: str = "sum", group_by: str = None):
    rows = load_rows()
    col = column
    groups = {}
    for r in rows:
        if group_by:
            groups.setdefault(r[group_by], []).append(float(r[col]))
        else:
            groups.setdefault("all", []).append(float(r[col]))
    out = {}
    for k, vals in groups.items():
        if fn == "sum":
            out[k] = sum(vals)
        elif fn == "avg":
            out[k] = round(sum(vals) / len(vals), 2)
        elif fn == "count":
            out[k] = len(vals)
        elif fn == "max":
            out[k] = max(vals)
    return {"group_by": group_by or "all", "column": col, "fn": fn, "result": out}


def tool_filter_rows(month: str = None, region: str = None):
    rows = load_rows()
    hit = [r for r in rows
           if (month is None or r["month"] == month)
           and (region is None or r["region"] == region)]
    return {"matched": len(hit), "rows": hit[:6]}


def tool_top_n(column: str, n: int = 1):
    rows = load_rows()
    order = sorted(rows, key=lambda r: -float(r[column]))[:n]
    return {"top": [{"month": r["month"], "region": r["region"], column: r[column]}
                    for r in order]}


REG = (ToolRegistry()
       .register("list_columns", tool_list_columns, "列出数据有哪些列、共几行")
       .register("aggregate", tool_aggregate, "对某列做聚合：sum/avg/count/max，可按列分组",
                 {"column": "string", "fn": "string", "group_by": "string|null"})
       .register("filter_rows", tool_filter_rows, "按月份/区域筛选明细行",
                 {"month": "string|null", "region": "string|null"})
       .register("top_n", tool_top_n, "按某列取前 n 条", {"column": "string", "n": "int"}))


# ============ 领域 B 的策略（规则版，模拟"会查数的分析员"）============
class DataQAPolicy(Policy):
    """真实场景这里换成 LLM：把 tools 清单和问题给它，让它自己选工具。
    规则版的作用是：没有 API key 也能跑通 loop、产出可评测的轨迹。"""

    def next_action(self, task: dict, mem):
        q = task["question"]
        done = [t["tool"] for t in mem.trace]

        if "list_columns" not in done:
            return {"tool": "list_columns", "args": {}}

        # 简单解析问题意图（LLM 版就是把这段换成模型调用）
        if "哪个区域" in q or "哪个地区" in q:
            if "aggregate" not in done:
                col = "orders" if "订单" in q else "amount"
                return {"tool": "aggregate", "args": {"column": col, "fn": "sum", "group_by": "region"}}
            res = self._last(mem, "aggregate")["result"]["result"]
            best = max(res, key=lambda k: res[k])
            return {"tool": "finish", "args": {
                "verdict": f"{best}", "confidence": 0.95,
                "reason": f"{best} 聚合值最高（{res[best]:.0f}）"}}

        if "订单" in q and ("多少" in q or "几" in q):
            if "filter_rows" not in done:
                month = "2026-03" if "3" in q else None
                return {"tool": "filter_rows", "args": {"month": month}}
            rows = self._last(mem, "filter_rows")["result"]["rows"]
            total = sum(int(r["orders"]) for r in rows)
            return {"tool": "finish", "args": {
                "verdict": str(total), "confidence": 0.9,
                "reason": f"按条件筛出 {len(rows)} 行，订单数合计 {total}"}}

        if "平均" in q:
            if "aggregate" not in done:
                return {"tool": "aggregate", "args": {"column": "amount", "fn": "avg"}}
            res = self._last(mem, "aggregate")["result"]["result"]
            return {"tool": "finish", "args": {
                "verdict": str(res["all"]), "confidence": 0.9,
                "reason": f"amount 平均值 {res['all']}"}}

        return {"tool": "finish", "args": {
            "verdict": "无法回答", "confidence": 0.3, "reason": "问题里没有可识别的聚合意图"}}

    @staticmethod
    def _last(mem, tool):
        for t in reversed(mem.trace):
            if t["tool"] == tool:
                return t["result"]
        return {}


TASKS = [
    {"question": "哪个区域的销售额最高？"},
    {"question": "哪个区域订单数最高？"},
    {"question": "3 月的订单数是多少？"},
    {"question": "平均销售额是多少？"},
]


def main():
    ensure_data()
    agent = Agent(REG, DataQAPolicy())
    print("=== 领域 B：数据问答（工具与安全完全无关）===")
    print("工具清单：", [t["name"] for t in REG.specs()])
    print()

    results = []
    for t in TASKS:
        r = agent.run(t)
        results.append(r)
        print("Q: %s" % t["question"])
        print("   A: %-10s 置信 %.2f  步数 %d  （%s）"
              % (r["verdict"], r["confidence"], r["steps"], r["reason"]))
        print("   轨迹：", " → ".join(r["tools_used"][:-1]))
        print()

    print("=== 轨迹评测（同一套 evaluate，和安全领域共用）===")
    print(json.dumps(evaluate(results, expect_tools=["list_columns", "aggregate"]),
                     ensure_ascii=False, indent=1))

    out = os.path.join(ROOT, "data", "dataqa_eval.json")
    json.dump({"results": results, "summary": evaluate(results)}, open(out, "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)
    print("\n明细写入", out)


if __name__ == "__main__":
    main()
