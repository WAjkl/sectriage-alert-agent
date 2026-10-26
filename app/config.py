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

# 边缘设备（ESP32）事件：单独一个文件，不和 alerts.jsonl 混。
# 原因：alerts.jsonl 是评测基准，混进设备事件会让"3000 条 → 40 个事件"这类
# 数字不可复现，别人拉下来一跑就对不上。
DEVICE_PATH = os.path.join(DATA_DIR, "device_events.jsonl")

# 设备上报的共享令牌（留空 = 不校验，仅限本机演示；对局域网开放时必须设置）
INGEST_TOKEN = os.getenv("INGEST_TOKEN", "")

# 熔断：连续失败几次开门 / 开门后冷却多少秒
BREAKER_THRESHOLD = int(os.getenv("BREAKER_THRESHOLD", "3"))
BREAKER_COOLDOWN = float(os.getenv("BREAKER_COOLDOWN", "30"))

# 多久没上报算掉线（秒）。
# **必须 ≥ 3× 设备心跳间隔**，否则设备永远"假离线"（真机上踩过：心跳 300s、阈值 120s，
# 后端每分钟报一次心跳丢失，板子其实一直活着）。当前固件心跳 60s → 阈值 180s。
DEVICE_OFFLINE_SEC = int(os.getenv("DEVICE_OFFLINE_SEC", "180"))

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
