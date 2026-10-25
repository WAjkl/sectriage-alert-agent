# -*- coding: utf-8 -*-
"""HTTP 层：只做参数校验、调用 pipeline、返回 JSON。不含业务逻辑。

为什么这么薄：接口是给前端和面试官看的，业务在 pipeline 里，
换 Web 框架（FastAPI → Flask）只需要重写这个文件。
"""
import os
from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.responses import HTMLResponse, JSONResponse
import time
import uuid

from . import config, store, pipeline, retrieve

app = FastAPI(
    title="SecTriage",
    version="1.0.0",
    description="安全告警降噪与研判：把几千条告警压成几十个事件，并给出判定、置信度与依据",
)

_start_ts = time.time()


def _public(c: dict) -> dict:
    """对外输出时去掉 alerts 数组与真值，避免泄露。"""
    d = {k: v for k, v in c.items() if k not in ("alerts", "is_true_positive")}
    return d


@app.get("/", response_class=HTMLResponse)
def index():
    p = os.path.join(config.WEB_DIR, "index.html")
    if os.path.exists(p):
        return open(p, encoding="utf-8").read()
    return "<h1>SecTriage</h1><p>前端文件缺失，接口文档见 <a href='/docs'>/docs</a></p>"


@app.get("/health")
def health():
    return {"ok": True, "service": "sectriage", "version": "1.0.0",
            "uptime_s": round(time.time() - _start_ts, 1)}


@app.get("/stats")
def stats():
    alerts = store.load_alerts()
    clusters = pipeline.aggregate(alerts)
    return {
        "alerts": len(alerts),
        "clusters": len(clusters),
        "denoise_rate": round(1 - len(clusters) / max(len(alerts), 1), 4),
        "avg_alerts_per_cluster": round(len(alerts) / max(len(clusters), 1), 1),
    }


@app.get("/clusters")
def clusters(limit: int = 20, with_truth: bool = False):
    cs = pipeline.aggregate(store.load_alerts())
    items = []
    for c in cs[:limit]:
        d = _public(c)
        if with_truth:
            d["is_true_positive"] = c["is_true_positive"]
        items.append(d)
    return {"total": len(cs), "items": items}


@app.get("/clusters/enriched")
def clusters_enriched(limit: int = 10):
    cs = pipeline.aggregate(store.load_alerts())
    return {"items": [{"cluster_id": c["cluster_id"], "rule": c["rule"],
                       "asset": c["asset"], "src_ip": c["src_ip"], "count": c["count"],
                       "context": pipeline.enrich(c, cs)} for c in cs[:limit]]}


@app.get("/sop/search")
def sop_search(q: str, k: int = 2):
    if not q:
        raise HTTPException(400, "q 不能为空")
    return {"query": q, "results": retrieve.retrieve_sop(q, k)}


@app.get("/triage")
def triage(limit: int = 10):
    cs = pipeline.aggregate(store.load_alerts())
    items = []
    for c in cs[:limit]:
        ctx = pipeline.enrich(c, cs)
        items.append({"cluster_id": c["cluster_id"], "rule": c["rule"], "count": c["count"],
                      "context": ctx, "verdict": pipeline.triage(c, ctx)})
    return {"total": len(cs), "items": items}


@app.get("/run")
def run():
    rows = pipeline.run_all()
    routes = {}
    for r in rows:
        k = r["decision"]["route"]
        routes[k] = routes.get(k, 0) + 1
    return {"alerts": len(store.load_alerts()), "clusters": len(rows), "routes": routes}


@app.post("/decide/{cluster_id}")
def decide_one(cluster_id: str, request: Request,
               x_operator: str = Header(default="anonymous")):
    """对单个事件做决策并写审计。注意：这里不执行处置动作，只出工单草稿。"""
    rows = pipeline.run_all()
    hit = next((r for r in rows if r["cluster_id"] == cluster_id), None)
    if not hit:
        raise HTTPException(404, "cluster 不存在")
    rec = {
        "cluster_id": cluster_id, "rule": hit["rule"], "asset": hit["asset"],
        "verdict": hit["verdict"]["verdict"], "confidence": hit["verdict"]["confidence"],
        "route": hit["decision"]["route"], "need_approval": hit["decision"]["need_approval"],
        "mode": hit["verdict"].get("mode"), "operator": x_operator,
        "trace": uuid.uuid4().hex[:12],
    }
    store.write_audit(rec)
    return {"item": hit, "audit": rec}


@app.get("/audit")
def audit(limit: int = 20):
    rows = store.read_audit(limit)
    return {"total": len(rows), "rows": rows}


@app.exception_handler(Exception)
async def on_error(request: Request, exc: Exception):
    """统一错误出口：不让堆栈直接吐给调用方。"""
    return JSONResponse(status_code=500,
                        content={"error": exc.__class__.__name__, "detail": str(exc)[:200]})
