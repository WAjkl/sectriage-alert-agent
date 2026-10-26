# -*- coding: utf-8 -*-
"""评测门槛（CI 用）：核心指标跌出合理区间就让流水线红。

为什么需要：单测只保证"函数没写错"，不保证"整体效果没退化"。
改了聚合窗口、检索阈值、置信度门槛，单测可能全绿，但降噪率从 98.7% 掉到 70%。
这个脚本就是拦这种情况。

判据（都是区间，不是单点——单点会被过度拟合）：
  1) 降噪率 ≥ 0.95          聚合失效会立刻掉下来
  2) 簇数 30–60             太少=过度合并（可能漏事件），太多=聚合没生效
  3) 平均每簇告警 ≥ 50       证明聚合真的在合，不是一条一簇
  4) 路由只出现在合法集合内   防止新加的分支没接入决策层
  5) 没有单簇告警 > 800      防止时间窗/指纹 bug 把不同攻击合成一个

用法：
    python scripts/eval_gate.py            # 不达标返回 1
    python scripts/eval_gate.py --json     # 输出 JSON（给 CI 收集）
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import pipeline, store      # noqa: E402

LEGAL_ROUTES = {"auto_close", "review", "escalate", "need_human"}
MIN_DENOISE = 0.95
CLUSTER_RANGE = (30, 60)
MIN_PER_CLUSTER = 50
MAX_CLUSTER_SIZE = 800


def check() -> dict:
    alerts = store.load_alerts()
    clusters = pipeline.aggregate(alerts)
    n_a, n_c = len(alerts), len(clusters)
    denoise = 1 - n_c / max(n_a, 1)
    per = n_a / max(n_c, 1)

    routes = {}
    for r in pipeline.run_all(alerts):
        k = r["decision"]["route"]
        routes[k] = routes.get(k, 0) + 1

    checks = []

    def ck(name, ok, detail):
        checks.append({"check": name, "ok": bool(ok), "detail": detail})

    ck("有数据", n_a > 0, "告警 %d 条" % n_a)
    ck("降噪率 ≥ %.2f" % MIN_DENOISE, denoise >= MIN_DENOISE,
       "实际 %.4f" % denoise)
    ck("簇数在 %d–%d" % CLUSTER_RANGE, CLUSTER_RANGE[0] <= n_c <= CLUSTER_RANGE[1],
       "实际 %d" % n_c)
    ck("平均每簇 ≥ %d 条" % MIN_PER_CLUSTER, per >= MIN_PER_CLUSTER, "实际 %.1f" % per)
    illegal = set(routes) - LEGAL_ROUTES
    ck("路由都在合法集合内", not illegal,
       "实际 %s%s" % (sorted(routes), "｜非法：%s" % illegal if illegal else ""))
    biggest = max((c["count"] for c in clusters), default=0)
    ck("单簇 ≤ %d 条" % MAX_CLUSTER_SIZE, biggest <= MAX_CLUSTER_SIZE, "实际 %d" % biggest)

    return {
        "alerts": n_a, "clusters": n_c,
        "denoise_rate": round(denoise, 4),
        "avg_per_cluster": round(per, 1),
        "routes": routes,
        "max_cluster_size": biggest,
        "checks": checks,
        "passed": all(c["ok"] for c in checks),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    r = check()

    if a.json:
        print(json.dumps(r, ensure_ascii=False, indent=2))
    else:
        print("=== 评测门槛 ===")
        print("告警 %d 条 → 簇 %d 个｜降噪率 %.2f%%｜平均 %.1f 条/簇｜最大簇 %d"
              % (r["alerts"], r["clusters"], r["denoise_rate"] * 100,
                 r["avg_per_cluster"], r["max_cluster_size"]))
        print("路由分布：%s" % r["routes"])
        print("-" * 46)
        for c in r["checks"]:
            print("  %s %-24s %s" % ("[OK]  " if c["ok"] else "[FAIL]", c["check"], c["detail"]))
        print("-" * 46)
        print("结论：%s" % ("通过" if r["passed"] else "未通过（流水线应红）"))

    sys.exit(0 if r["passed"] else 1)


if __name__ == "__main__":
    main()
