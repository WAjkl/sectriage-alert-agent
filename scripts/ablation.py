# -*- coding: utf-8 -*-
"""消融实验：把「降噪」的功劳拆开——聚合层干了多少，研判层干了多少。

为什么必须做这件事：
  简历/汇报里说"降噪 98.7%"很危险。因为聚合层（纯规则、不调模型）就能把 3000 压到 40，
  面试官会立刻问"那 Agent 到底贡献了什么"。答不上来，这块就成了减分项。

这个脚本算三件事：
  1) 只聚合（关掉研判）：原始 → 簇，这是**规则层的贡献**
  2) 研判层做了什么：每个簇得到判定/置信度/依据/SOP，人工阅读量从"N 条"变"N 张卡片"
  3) 人工工时对比（按"一条 30 秒、一张卡片 2.5 分钟"的口径，参数可换）

用法：
    python scripts/ablation.py
    python scripts/ablation.py --sec-per-alert 30 --min-per-card 2.5
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import pipeline, store      # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sec-per-alert", type=float, default=30)   # 人工读一条原始告警
    ap.add_argument("--min-per-card", type=float, default=2.5)   # 人工读一张事件卡片
    a = ap.parse_args()

    alerts = store.load_alerts()
    clusters = pipeline.aggregate(alerts)
    rows = pipeline.run_all(alerts)

    n_a, n_c = len(alerts), len(alerts) and len(clusters) or 0
    print("=== 消融：降噪到底是谁干的 ===")
    print("原始告警            : %d 条" % n_a)
    print("仅聚合（规则，无模型）: %d 个簇 → 合并率 %.2f%%，平均 %.1f 条/簇"
          % (n_c, (1 - n_c / max(n_a, 1)) * 100, n_a / max(n_c, 1)))

    # 研判层不再合并，只定性 —— 用簇数不变来证明
    print("再叠加研判（Agent）  : %d 个簇 → 合并率 %.2f%%（**簇数不变，研判不合并**）"
          % (len(rows), (1 - len(rows) / max(n_a, 1)) * 100))

    routes, verdicts = {}, {}
    for r in rows:
        routes[r["decision"]["route"]] = routes.get(r["decision"]["route"], 0) + 1
        verdicts[r["verdict"]["verdict"]] = verdicts.get(r["verdict"]["verdict"], 0) + 1

    print("\n=== 研判层的产出（这才是 Agent 的贡献）===")
    print("  · 每个簇都得到：判定 + 置信度 + 理由 + SOP 引用 + 路由")
    print("  · 判定分布：%s" % verdicts)
    print("  · 路由分布：%s" % routes)

    t_raw = n_a * a.sec_per_alert / 60
    t_card = n_c * a.min_per_card
    print("\n=== 人工工时（口径要写清，别含糊）===")
    print("  改进前：读 %d 条原始告警 × %.0fs = %.0f 分钟（%.1f 小时）"
          % (n_a, a.sec_per_alert, t_raw, t_raw / 60))
    print("  改进后：读 %d 张卡片 × %.1f 分钟 = %.0f 分钟（%.1f 小时）"
          % (n_c, a.min_per_card, t_card, t_card / 60))
    print("  压缩  ：%.1f 小时 → %.1f 小时，约 %.1f 倍"
          % (t_raw / 60, t_card / 60, t_raw / max(t_card, 0.1)))
    print("\n注意：这两个耗时是**假设**（%.0fs/条、%.1fmin/卡），不是测出来的。"
          % (a.sec_per_alert, a.min_per_card))
    print("      面试时要把假设说出来，不要报成实测值。")


if __name__ == "__main__":
    main()
