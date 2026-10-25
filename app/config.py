# -*- coding: utf-8 -*-
"""集中配置：所有环境变量从这里读，别散落在各处。"""
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # 项目根
DATA_DIR = os.path.join(BASE_DIR, "data")
WEB_DIR = os.path.join(BASE_DIR, "app", "web")

# 文件路径
ALERTS_PATH = os.path.join(DATA_DIR, "alerts.jsonl")
ASSETS_PATH = os.path.join(DATA_DIR, "assets.json")
SOP_PATH = os.path.join(DATA_DIR, "sop.jsonl")
AUDIT_PATH = os.path.join(DATA_DIR, "audit.jsonl")

# 聚合
WINDOW_MIN = int(os.getenv("WINDOW_MIN", "10"))

# 研判
SCORE_THRESHOLD = float(os.getenv("SCORE_THRESHOLD", "0.15"))
AUTO_CONF = float(os.getenv("AUTO_CONF", "0.8"))

# LLM（留空则走规则降级）
LLM_BASE = os.getenv("LLM_BASE", "")
LLM_KEY = os.getenv("LLM_KEY", "")
LLM_MODEL = os.getenv("LLM_MODEL", "deepseek-chat")
LLM_TIMEOUT = int(os.getenv("LLM_TIMEOUT", "25"))

# 严重级权重（本来想从规则引擎元数据读，靶场这套没有，先硬编码）
SEV_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# 网段台账（比 RFC1918 前缀判断可靠，见 docs/实现思想详解.md 第 4 节）
ZONE_RULES = [
    ("127.", "localhost"),
    ("10.20.1.", "office-lan"),
    ("10.20.3.", "server-lan"),
    ("172.24.", "lab-attacker"),
]


def zone_of(ip: str) -> str:
    ip = (ip or "").strip()
    for prefix, zone in ZONE_RULES:
        if ip.startswith(prefix):
            return zone
    return "external"


def ensure_dirs():
    os.makedirs(DATA_DIR, exist_ok=True)
