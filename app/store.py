# -*- coding: utf-8 -*-
"""数据读写：只负责从磁盘拿数据、写审计，不做业务判断。

为什么单独拆出来：换存储（SQLite/MySQL/ES）时只改这一个文件，
上层 pipeline 不用动。这是"可交付"和"能跑"的区别之一。
"""
import os
import json
import time
from typing import List, Dict

from . import config


def load_alerts(path: str = None) -> List[dict]:
    """读告警。没有文件就返回空列表，不抛异常——上层自己决定怎么提示。"""
    path = path or config.ALERTS_PATH
    if not os.path.exists(path):
        return []
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue          # 单行坏了跳过，不让整个服务挂掉
    return rows


def load_assets() -> Dict[str, dict]:
    if not os.path.exists(config.ASSETS_PATH):
        return {}
    with open(config.ASSETS_PATH, encoding="utf-8") as f:
        return {a["asset"]: a for a in json.load(f)}


def load_sops() -> List[dict]:
    if not os.path.exists(config.SOP_PATH):
        return []
    out = []
    with open(config.SOP_PATH, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def write_audit(rec: dict):
    """审计只追加不覆盖。日志轮转交给外部（logrotate / 定时任务）。"""
    config.ensure_dirs()
    rec = dict(rec, ts=time.strftime("%Y-%m-%dT%H:%M:%S"))
    with open(config.AUDIT_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def read_audit(limit: int = 20) -> List[dict]:
    if not os.path.exists(config.AUDIT_PATH):
        return []
    with open(config.AUDIT_PATH, encoding="utf-8") as f:
        rows = [json.loads(l) for l in f if l.strip()]
    return rows[-limit:]
