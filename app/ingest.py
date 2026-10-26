# -*- coding: utf-8 -*-
"""边缘事件接入：把 ESP32 这类设备上报的"本地已降噪"的事件，转成标准告警格式。

为什么单独一层，而不是塞进 store.py：
  设备事件和"告警"不是一回事，差在三处，随便混会出事——
  1) **没有可信时钟**：ESP32 起来时不知道真实时间（没有 RTC、不一定有 NTP）。
     所以不信任设备时间，用 `boot_id + seq` 保证顺序，用服务端接收时间做 ts。
  2) **会重复、会乱序**：断网补传会把同一批再发一遍，所以必须幂等。
  3) **会重启**：`boot_id` 变一次就是一次重启，重启本身要能看见（这是可用性信号）。

所以这一层做三件事：校验 → 去重（幂等）→ 转成 pipeline 认识的告警字段。
真正的研判逻辑一行都不动。

设备侧约定（固件里按这个发）：
    POST /ingest
    {"device": {"id": "esp32-lab-01", "boot_id": "3f9a", "fw": "1.0.0"},
     "events": [{"seq": 12, "dev_ms": 83000, "kind": "probe_surge", "value": 47, "detail": {...}}]}

`seq` 每次上报自增、设备重启后归零（配 boot_id 才唯一）。
`dev_ms` 是设备上电后的毫秒数，仅用于算"设备端窗口长度"，不参与排序。
"""
import json
import os
import time
from typing import Dict, List, Tuple

from . import config

# 设备事件 → 标准告警字段的映射。
# 注意两个刻意的设计：
#   1) 可用性类事件（重启/掉线）**故意不套 ATT&CK 编号**——强行对齐会让 technique
#      变成噪音，按 technique 做统计时被污染。
#   2) 心跳（heartbeat）只更新"我还活着"，**不产生告警**。否则一台设备每 5 分钟
#      就制造一条噪音，等于把边缘降噪的成果又还回去了。
KINDS = {
    "probe_surge":    {"rule": "无线探测请求突增", "technique": "T1595", "severity": "medium", "alert": True},
    "ap_rogue":       {"rule": "疑似钓鱼热点(同名SSID)", "technique": "T1557", "severity": "high", "alert": True},
    # BLE 与链路质量是"环境/可用性"信号，**不套 ATT&CK**：
    # 蓝牙设备变多不等于攻击，无线抖动也不是；硬套编号会污染按 technique 的统计。
    "ble_burst":      {"rule": "蓝牙设备密度异常", "technique": "", "severity": "low", "alert": True},
    "link_degraded":  {"rule": "无线链路质量下降", "technique": "", "severity": "low", "alert": True},
    "device_reboot":  {"rule": "边缘设备重启", "technique": "", "severity": "low", "alert": True},
    "device_offline": {"rule": "边缘设备心跳丢失", "technique": "", "severity": "medium", "alert": True},
    "heartbeat":      {"rule": "心跳", "technique": "", "severity": "info", "alert": False},
}

_seen = None          # 幂等表：{("boot_id","seq")} 缓存，首次使用时从文件加载
_offline_mark = {}    # {device_id: 最后一次已告警的 last_seen}，防止同一次掉线反复报


def _path() -> str:
    return config.DEVICE_PATH


def reset_cache():
    """清掉内存态的幂等表与掉线标记（测试与切换数据文件时用）。"""
    global _seen
    _seen = None
    _offline_mark.clear()


def _load_seen() -> set:
    global _seen
    if _seen is not None:
        return _seen
    _seen = set()
    p = _path()
    if os.path.exists(p):
        with open(p, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                key = (rec.get("boot_id"), rec.get("seq"))
                if key[0] is not None and key[1] is not None:
                    _seen.add(key)
    return _seen


def _append(rec: dict):
    config.ensure_dirs()
    with open(_path(), "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def to_alert(rec: dict) -> dict:
    """把一条设备事件转成 pipeline 认识的标准告警。"""
    meta = KINDS.get(rec["kind"], {"rule": rec["kind"], "technique": "", "severity": "low"})
    detail = rec.get("detail") or {}
    return {
        "alert_id": "D-%s-%s" % (rec["boot_id"], rec["seq"]),
        "ts": rec["recv_ts"],                       # 服务端接收时间，不是设备时间
        "rule": meta["rule"],
        "asset": rec["device_id"],
        "src_ip": detail.get("ip", "0.0.0.0"),
        "dst_port": 0,
        "technique": meta["technique"],
        "severity": meta["severity"],
        "raw": "%s kind=%s value=%s dev_ms=%s" % (
            rec["device_id"], rec["kind"], rec.get("value"), rec.get("dev_ms")),
    }


def ingest(payload: dict, recv_ts: str = None) -> Dict[str, int]:
    """接收一批设备事件。返回 {accepted, duplicated, rejected}。

    幂等键 = (boot_id, seq)。重复的直接丢弃并计数，不改写已有记录——
    补传要能被安全重放，这是"至少一次投递"下唯一可行的做法。
    """
    recv_ts = recv_ts or time.strftime("%Y-%m-%dT%H:%M:%S")
    dev = payload.get("device") or {}
    dev_id = (dev.get("id") or "").strip()
    boot_id = (dev.get("boot_id") or "").strip()
    if not dev_id or not boot_id:
        return {"accepted": 0, "duplicated": 0, "rejected": 1, "error": "device.id/boot_id 必填"}

    seen = _load_seen()
    accepted = duplicated = rejected = 0
    for ev in payload.get("events") or []:
        seq = ev.get("seq")
        kind = ev.get("kind")
        if seq is None or not isinstance(seq, int) or kind not in KINDS:
            rejected += 1
            continue
        key = (boot_id, seq)
        if key in seen:
            duplicated += 1
            continue
        rec = {
            "device_id": dev_id,
            "boot_id": boot_id,
            "fw": dev.get("fw", ""),
            "seq": seq,
            "kind": kind,
            "value": ev.get("value"),
            "dev_ms": ev.get("dev_ms"),
            "detail": ev.get("detail") or {},
            "recv_ts": recv_ts,
        }
        _append(rec)
        seen.add(key)
        accepted += 1

    return {"accepted": accepted, "duplicated": duplicated, "rejected": rejected}


def load_events(limit: int = None) -> List[dict]:
    p = _path()
    if not os.path.exists(p):
        return []
    rows = []
    with open(p, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows[-limit:] if limit else rows


def load_device_alerts() -> List[dict]:
    """供 pipeline 使用的告警列表（只读，不改 alerts.jsonl，保证原有评测数字可复现）。

    心跳不在这里——它只用于判活，不该进研判管线。
    """
    out = []
    for r in load_events():
        meta = KINDS.get(r.get("kind"), {})
        if not meta.get("alert", True):
            continue
        out.append(to_alert(r))
    return out


def device_status(offline_sec: int = None) -> List[dict]:
    """每台设备的活跃度。掉线只能算出来，设备自己报不了"我掉线了"。"""
    offline_sec = offline_sec or config.DEVICE_OFFLINE_SEC
    now = time.time()
    out: Dict[str, dict] = {}
    for r in load_events():
        d = out.setdefault(r["device_id"], {
            "device_id": r["device_id"], "boot_id": r["boot_id"], "fw": r.get("fw", ""),
            "events": 0, "beats": 0, "last_recv": r["recv_ts"], "last_seq": r["seq"],
        })
        if r.get("kind") == "heartbeat":
            d["beats"] += 1
        else:
            d["events"] += 1
        d["boot_id"] = r["boot_id"]
        d["last_seq"] = r["seq"]
        if r["recv_ts"] >= d["last_recv"]:
            d["last_recv"] = r["recv_ts"]
    for d in out.values():
        try:
            age = now - time.mktime(time.strptime(d["last_recv"], "%Y-%m-%dT%H:%M:%S"))
        except ValueError:
            age = 0
        d["silent_s"] = int(age)
        d["online"] = age <= offline_sec
    return sorted(out.values(), key=lambda x: x["device_id"])


def sweep_offline(offline_sec: int = None) -> int:
    """把"长时间没上报"落成一条告警。同一次沉默只报一次，避免刷屏。"""
    n = 0
    for d in device_status(offline_sec):
        if d["online"]:
            continue
        if _offline_mark.get(d["device_id"]) == d["last_recv"]:
            continue
        _offline_mark[d["device_id"]] = d["last_recv"]
        _append({
            "device_id": d["device_id"], "boot_id": d["boot_id"], "fw": d["fw"],
            # 合成序号：用时间戳低位，避开设备自增段，也不会和别的事件撞
            "seq": 900000 + int(time.time()) % 100000,
            "kind": "device_offline", "value": d["silent_s"],
            "dev_ms": None, "detail": {"last_recv": d["last_recv"]},
            "recv_ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        })
        n += 1
    return n
