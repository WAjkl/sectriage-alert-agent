# -*- coding: utf-8 -*-
"""检索：字符 bigram 向量 + BM25 + RRF 融合。

为什么不上向量库：这个项目的语料只有几十条 SOP，装 Chroma/PGVector 属于过度设计。
真到上万条再换，接口保持不变（retrieve_sop 的签名就是稳定边界）。
"""
import re
import math
from typing import List, Dict, Tuple

from . import store


def bigrams(s: str) -> List[str]:
    s = re.sub(r"\s+", "", s or "")
    return [s[i:i + 2] for i in range(len(s) - 1)] or ([s] if s else [])


def to_vec(s: str) -> Dict[str, int]:
    v = {}
    for g in bigrams(s):
        v[g] = v.get(g, 0) + 1
    return v


def cosine(a: Dict[str, int], b: Dict[str, int]) -> float:
    dot = sum(v * b.get(k, 0) for k, v in a.items())
    na = math.sqrt(sum(v * v for v in a.values()))
    nb = math.sqrt(sum(v * v for v in b.values()))
    return 0.0 if na == 0 or nb == 0 else dot / (na * nb)


def bm25(query: str, texts: List[str], k1: float = 1.5, b: float = 0.75) -> List[float]:
    qt = list(dict.fromkeys(bigrams(query)))
    dts = [bigrams(t) for t in texts]
    avgdl = sum(len(d) for d in dts) / max(len(dts), 1)
    out = []
    for dt in dts:
        tf = {}
        for t in dt:
            tf[t] = tf.get(t, 0) + 1
        score = 0.0
        for t in qt:
            f = tf.get(t, 0)
            if not f:
                continue
            n = sum(1 for d in dts if t in d)
            idf = math.log((len(dts) - n + 0.5) / (n + 0.5) + 1)
            score += idf * (f * (k1 + 1)) / (f + k1 * (1 - b + b * len(dt) / avgdl))
        out.append(score)
    return out


def rrf(rank_lists: List[List[int]], k: int = 60) -> List[Tuple[int, float]]:
    """只用排名，免疫量纲差异。代价是丢掉分差信息。"""
    score: Dict[int, float] = {}
    for lst in rank_lists:
        for rank, idx in enumerate(lst, start=1):
            score[idx] = score.get(idx, 0.0) + 1.0 / (k + rank)
    return sorted(score.items(), key=lambda x: -x[1])


def retrieve_sop(query: str, top_k: int = 2) -> List[dict]:
    """检索处置 SOP。返回带 score 的条目，供研判引用与审计。"""
    sops = store.load_sops()
    if not sops or not query:
        return []
    texts = [s["title"] + " " + s["text"] for s in sops]
    qv = to_vec(query)
    vsim = [cosine(qv, to_vec(t)) for t in texts]
    bm = bm25(query, texts)
    v_order = sorted(range(len(sops)), key=lambda i: -vsim[i])
    b_order = sorted(range(len(sops)), key=lambda i: -bm[i])
    fused = rrf([v_order, b_order])[:top_k]
    return [dict(sops[i], score=round(sc, 4)) for i, sc in fused]
