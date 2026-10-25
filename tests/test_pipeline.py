# -*- coding: utf-8 -*-
"""核心逻辑的单测。

只测纯函数（不测 HTTP、不测 LLM 调用）：这类测试快、稳、改代码时真能拦住问题。
跑法：  pytest -q
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import config, pipeline, retrieve   # noqa: E402


def A(ts, rule="Web 登录爆破", ip="1.2.3.4", asset="srv-web-lab",
      tech="T1110", sev="high", tp=True):
    return {"alert_id": "x", "ts": ts, "rule": rule, "asset": asset, "src_ip": ip,
            "technique": tech, "severity": sev, "raw": "r", "is_true_positive": tp}


# ---------------- 指纹 ----------------
def test_norm_ip_strips_port():
    assert pipeline.norm_ip("45.12.33.7:52341") == "45.12.33.7"
    assert pipeline.norm_ip(" 10.0.0.1 ") == "10.0.0.1"


def test_fingerprint_same_for_same_entity():
    a = A("2026-10-26T01:00:00", ip="45.12.33.7:50000")
    b = A("2026-10-26T01:00:05", ip="45.12.33.7:50999")
    assert pipeline.fingerprint(a) == pipeline.fingerprint(b), "端口不同但应视为同一实体"


def test_fingerprint_differs_by_technique():
    a = A("2026-10-26T01:00:00", tech="T1110")
    b = A("2026-10-26T01:00:00", tech="T1595")
    assert pipeline.fingerprint(a) != pipeline.fingerprint(b)


# ---------------- 聚合 ----------------
def test_aggregate_merges_within_window():
    alerts = [A("2026-10-26T01:00:%02d" % (i * 5)) for i in range(5)]   # 0~20 秒
    cs = pipeline.aggregate(alerts, window_min=10)
    assert len(cs) == 1 and cs[0]["count"] == 5


def test_aggregate_splits_over_window():
    alerts = [A("2026-10-26T01:00:00"), A("2026-10-26T01:40:00")]      # 相隔 40 分钟
    cs = pipeline.aggregate(alerts, window_min=10)
    assert len(cs) == 2, "超过窗口必须切成两个簇"


def test_aggregate_handles_unordered_input():
    alerts = [A("2026-10-26T01:20:00"), A("2026-10-26T01:00:00"), A("2026-10-26T01:10:00")]
    cs = pipeline.aggregate(alerts, window_min=15)
    assert len(cs) == 1, "乱序到达也要合并"
    assert cs[0]["first_ts"] == "2026-10-26T01:00:00", "first_ts 应取最早"


def test_aggregate_separates_by_asset():
    a = A("2026-10-26T01:00:00", asset="srv-a")
    b = A("2026-10-26T01:00:00", asset="srv-b")
    assert len(pipeline.aggregate([a, b], window_min=10)) == 2


# ---------------- 检索 ----------------
def test_bm25_ranks_relevant_higher():
    texts = ["弱口令需二十四小时内修改", "食堂午餐十一点半开饭"]
    scores = retrieve.bm25("弱口令 修改", texts)
    assert scores[0] > scores[1]


def test_rrf_ignores_score_scale():
    # 两路排名一致时，融合结果也应一致，不受"分数量纲"影响
    fused = retrieve.rrf([[0, 1, 2], [0, 1, 2]])
    assert [i for i, _ in fused] == [0, 1, 2]


def test_retrieve_sop_returns_sop_id():
    if not retrieve.retrieve_sop("SSH 暴力破解"):
        pytest.skip("data/sop.jsonl 不存在，跳过")
    hits = retrieve.retrieve_sop("SSH 暴力破解 失败 100 次", 1)
    assert hits and hits[0]["id"].startswith("SOP-")


# ---------------- 决策 ----------------
def test_decide_auto_close_only_low_value():
    v = {"verdict": "false_positive", "confidence": 0.9}
    assert pipeline.decide(v, {"asset_importance": 2})["route"] == "auto_close"
    assert pipeline.decide(v, {"asset_importance": 5})["route"] == "need_human", \
        "核心资产的误报不能自动关"


def test_decide_escalate_needs_approval():
    v = {"verdict": "true_positive", "confidence": 0.9}
    d = pipeline.decide(v, {"asset_importance": 5})
    assert d["route"] == "escalate" and d["need_approval"] is True


def test_decide_low_confidence_goes_human():
    v = {"verdict": "true_positive", "confidence": 0.5}
    assert pipeline.decide(v, {"asset_importance": 5})["route"] == "need_human"


# ---------------- zone 台账 ----------------
def test_zone_uses_ledger_not_rfc1918():
    # 172.24 是 WSL 的 NAT 段，RFC1918 会判成"内网"，但台账里是攻击机
    assert config.zone_of("172.24.60.109") == "lab-attacker"
    assert config.zone_of("127.0.0.1") == "localhost"
    assert config.zone_of("8.8.8.8") == "external"
