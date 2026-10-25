# -*- coding: utf-8 -*-
"""核心流水线：聚合 → 富化 → 研判 → 决策。

四个函数的边界很硬：
  aggregate  只看时间与实体，不看内容语义
  enrich     只补上下文，不做判断
  triage     只出"真假+置信度+依据"，不做动作
  decide     只做路由，不重新判真假
这样每层都能单测，出问题也知道是哪一层的锅。
"""
import re
import json
import urllib.request
from datetime import datetime
from typing import List, Dict

from . import config, store, retrieve


# ---------------- 聚合 ----------------
def norm_ip(ip: str) -> str:
    """去掉端口、去空白。真实日志常带 :port，不归一化会把簇炸开。"""
    ip = (ip or "").strip()
    return re.sub(r":\d+$", "", ip).lower()


def fingerprint(a: dict) -> str:
    """实体指纹。聚合看实体，不看措辞——这是不用 LLM 聚合的核心原因。"""
    return "|".join([a.get("asset", ""), norm_ip(a.get("src_ip", "")),
                     a.get("rule", ""), a.get("technique", "")])


def _ts(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%S")


def _make_cluster(fp: str, group: List[dict]) -> dict:
    asset, src_ip, rule, tech = fp.split("|")
    tp = sum(1 for a in group if a.get("is_true_positive")) * 2 >= len(group)
    return {
        "fingerprint": fp, "asset": asset, "src_ip": src_ip,
        "rule": rule, "technique": tech, "zone": config.zone_of(src_ip),
        "count": len(group),
        "first_ts": group[0]["ts"], "last_ts": group[-1]["ts"],
        "severity": max((a.get("severity", "low") for a in group),
                        key=lambda s: config.SEV_RANK.get(s, 0)),
        "sample_raw": group[0].get("raw", ""),
        "alerts": group,
        "is_true_positive": tp,        # 评测用；对外接口默认不返回
    }


def aggregate(alerts: List[dict], window_min: int = None) -> List[dict]:
    """按指纹分组 → 组内按时间排序 → 相邻间隔 > 窗口就切新簇。"""
    window = config.WINDOW_MIN if window_min is None else window_min
    buckets: Dict[str, List[dict]] = {}
    for a in alerts:
        buckets.setdefault(fingerprint(a), []).append(a)

    clusters = []
    for fp, group in buckets.items():
        group.sort(key=lambda x: _ts(x["ts"]))     # 必须排序：告警是乱序到达的
        cur = [group[0]]
        for a in group[1:]:
            gap = (_ts(a["ts"]) - _ts(cur[-1]["ts"])).total_seconds() / 60
            if gap <= window:
                cur.append(a)
            else:
                clusters.append(_make_cluster(fp, cur))
                cur = [a]
        clusters.append(_make_cluster(fp, cur))

    clusters.sort(key=lambda c: c["first_ts"])
    for i, c in enumerate(clusters, start=1):
        c["cluster_id"] = "C%03d" % i
    return clusters


# ---------------- 富化 ----------------
def enrich(cluster: dict, all_clusters: List[dict]) -> dict:
    assets = store.load_assets()
    a = assets.get(cluster["asset"], {})
    # TODO: 这里只统计当前批次的簇数，真实项目应查 7 天历史库
    hist = sum(1 for c in all_clusters if c["fingerprint"] == cluster["fingerprint"])
    return {
        "asset_importance": a.get("importance", 1),
        "asset_public": a.get("public", False),
        "asset_desc": a.get("desc", "未知资产"),
        "history_clusters": hist,
        "severity": cluster["severity"],
        "zone": cluster["zone"],
    }


# ---------------- 研判 ----------------
SYS_PROMPT = """你是安全运营中心的告警研判助手。根据证据判断该事件属于：
- true_positive：真实攻击或真实风险
- false_positive：业务正常行为导致的误报
- need_human：证据不足，需要人工确认
只输出 JSON：{"verdict":"...","confidence":0到1,"reason":"不超过60字","sop_id":"SOP编号或空"}
证据不足时必须降低 confidence 或直接判 need_human。"""


def build_evidence(c: dict, ctx: dict, sops: List[dict]) -> str:
    sop_txt = "\n".join("[%s] %s：%s" % (s["id"], s["title"], s["text"][:120])
                        for s in sops) or "（无匹配SOP）"
    return ("事件：%s（%s）\n资产：%s（重要性 %d/5，%s，网段 %s）\n源IP：%s\n"
            "告警条数：%d，时间 %s ~ %s\n最高严重级：%s\n同指纹历史簇数：%d\n"
            "样本日志：%s\n可能相关的处置SOP：\n%s"
            % (c["rule"], c["technique"], c["asset"], ctx["asset_importance"],
               ctx["asset_desc"], ctx["zone"], c["src_ip"], c["count"],
               c["first_ts"], c["last_ts"], c["severity"],
               ctx["history_clusters"], c["sample_raw"][:160], sop_txt))


def _call_llm(prompt: str) -> str:
    body = json.dumps({
        "model": config.LLM_MODEL, "temperature": 0,
        "response_format": {"type": "json_object"},
        "messages": [{"role": "system", "content": SYS_PROMPT},
                     {"role": "user", "content": prompt}],
    }).encode()
    req = urllib.request.Request(
        config.LLM_BASE.rstrip("/") + "/chat/completions", data=body,
        headers={"Content-Type": "application/json",
                 "Authorization": "Bearer " + config.LLM_KEY})
    with urllib.request.urlopen(req, timeout=config.LLM_TIMEOUT) as r:
        raw = json.loads(r.read())["choices"][0]["message"]["content"]
    raw = re.sub(r"^```(?:json)?|```$", "", raw.strip(), flags=re.M).strip()
    return raw


def _rule_based(c: dict, ctx: dict) -> dict:
    """朴素基线：只看严重级 + 网段台账。它一定会犯错，这是故意的——
    基线要是全对，就说明我把答案写进去了。"""
    if c["severity"] in ("high", "critical"):
        return {"verdict": "true_positive", "confidence": 0.85,
                "reason": "严重级 high/critical", "sop_id": ""}
    if ctx["zone"] in ("localhost", "office-lan", "server-lan"):
        return {"verdict": "false_positive", "confidence": 0.65,
                "reason": "内网来源，倾向业务行为", "sop_id": ""}
    return {"verdict": "true_positive", "confidence": 0.6,
            "reason": "外网来源，倾向攻击", "sop_id": ""}


def triage(c: dict, ctx: dict) -> dict:
    query = "%s %s %s" % (c["rule"], c["technique"], c["sample_raw"][:60])
    sops = retrieve.retrieve_sop(query, 2)
    if config.LLM_BASE and config.LLM_KEY:
        try:
            d = json.loads(_call_llm(build_evidence(c, ctx, sops)))
            return {"verdict": d.get("verdict", "need_human"),
                    "confidence": float(d.get("confidence", 0.5)),
                    "reason": d.get("reason", "")[:80],
                    "sop_id": d.get("sop_id", ""), "mode": "llm",
                    "sop_candidates": [s["id"] for s in sops]}
        except Exception as e:
            d = _rule_based(c, ctx)
            d.update(mode="fallback_rule", error=str(e)[:80])
            return d
    d = _rule_based(c, ctx)
    d["mode"] = "rule"
    return d


# ---------------- 决策 ----------------
def decide(verdict: dict, ctx: dict) -> dict:
    """路由规则：只有"可逆低风险"的动作才自动执行。"""
    v, conf, imp = verdict["verdict"], float(verdict["confidence"]), ctx["asset_importance"]
    if v == "false_positive" and conf >= config.AUTO_CONF and imp <= 3:
        return {"route": "auto_close", "action": "标记误报并关闭工单", "need_approval": False}
    if v == "false_positive" and conf >= config.AUTO_CONF:
        return {"route": "need_human", "action": "核心资产误报，转人工确认", "need_approval": True}
    if v == "true_positive" and conf >= config.AUTO_CONF and imp >= 4:
        return {"route": "escalate", "action": "生成工单并通知值班（处置需人工确认）",
                "need_approval": True}
    if v == "true_positive" and conf >= config.AUTO_CONF:
        return {"route": "review", "action": "建议排查（低价值资产）", "need_approval": True}
    return {"route": "need_human", "action": "置信度不足，转人工研判", "need_approval": True}


# ---------------- 全链路 ----------------
def run_all(alerts: List[dict] = None) -> List[dict]:
    alerts = alerts if alerts is not None else store.load_alerts()
    clusters = aggregate(alerts)
    out = []
    for c in clusters:
        ctx = enrich(c, clusters)
        v = triage(c, ctx)
        d = decide(v, ctx)
        out.append({"cluster_id": c["cluster_id"], "rule": c["rule"],
                    "asset": c["asset"], "src_ip": c["src_ip"], "zone": c["zone"],
                    "count": c["count"], "severity": c["severity"],
                    "verdict": v, "decision": d, "context": ctx,
                    "_truth": c["is_true_positive"]})
    return out
