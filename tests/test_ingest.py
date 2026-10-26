# -*- coding: utf-8 -*-
"""边缘事件接入的单元测试。

钉住四件事（每条都是真踩过或一定会踩的坑）：
  1) 映射字段对不对（pipeline 靠 asset|ip|rule|technique 做指纹）
  2) 幂等：同一 boot_id+seq 重发只算一次
  3) 校验：kind 不认识、缺 device.id 要拒
  4) 掉线只在服务端算，且同一次沉默只报一次
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import config, ingest      # noqa: E402


@pytest.fixture(autouse=True)
def tmp_device_file(tmp_path, monkeypatch):
    p = tmp_path / "device_events.jsonl"
    monkeypatch.setattr(config, "DEVICE_PATH", str(p))
    ingest.reset_cache()
    yield
    ingest.reset_cache()


def b(seq, kind="probe_surge", value=47, boot="b1", dev="esp32-lab-01"):
    return {"device": {"id": dev, "boot_id": boot, "fw": "1.0.0"},
            "events": [{"seq": seq, "dev_ms": 1000 * seq, "kind": kind,
                        "value": value, "detail": {"ip": "192.168.1.42"}}]}


def test_to_alert_maps_to_standard_fields():
    ingest.ingest(b(1))
    al = ingest.load_device_alerts()[0]
    assert al["rule"] == "无线探测请求突增"
    assert al["asset"] == "esp32-lab-01"
    assert al["technique"] == "T1595"
    assert al["severity"] == "medium"
    assert al["alert_id"] == "D-b1-1"
    # ts 必须是服务端接收时间（%Y-%m-%dT%H:%M:%S），pipeline 的 _ts() 依赖这个格式
    assert len(al["ts"]) == 19 and al["ts"][4] == "-" and al["ts"][10] == "T"


def test_idempotent_on_replay():
    r1 = ingest.ingest(b(1))
    r2 = ingest.ingest(b(1))            # 断网补传：同一批再发一次
    assert r1["accepted"] == 1
    assert r2["accepted"] == 0 and r2["duplicated"] == 1
    assert len(ingest.load_device_alerts()) == 1     # 没有写重


def test_reboot_gets_new_identity():
    """重启后 boot_id 变了、seq 归零，不能被当成重复丢掉。"""
    ingest.ingest(b(1, boot="b1"))
    r = ingest.ingest(b(1, boot="b2"))
    assert r["accepted"] == 1
    assert len(ingest.load_device_alerts()) == 2


def test_reject_unknown_kind_and_missing_device():
    r = ingest.ingest({"device": {"id": "x", "boot_id": "b"},
                       "events": [{"seq": 1, "kind": "不认识的事件"}]})
    assert r["rejected"] == 1 and r["accepted"] == 0

    r2 = ingest.ingest({"events": [{"seq": 1, "kind": "probe_surge"}]})
    assert r2.get("error")


def test_availability_event_has_no_technique():
    """可用性事件故意不套 ATT&CK，否则按 technique 统计会被污染。"""
    ingest.ingest(b(1, kind="device_reboot"))
    al = ingest.load_device_alerts()[0]
    assert al["technique"] == ""
    assert al["rule"] == "边缘设备重启"


def test_heartbeat_does_not_become_alert():
    """心跳只证明"我还活着"，不能进研判管线，否则每 5 分钟一条噪音。"""
    ingest.ingest(b(1, kind="heartbeat", value=1))
    assert ingest.load_device_alerts() == []          # 不产生告警
    st = ingest.device_status()[0]
    assert st["beats"] == 1 and st["events"] == 0     # 但活跃度看得见
    assert st["online"] is True


def test_sweep_offline_reports_once(monkeypatch):
    ingest.ingest(b(1))
    # 把所有事件的接收时间改成很久以前，制造"沉默"
    rows = ingest.load_events()
    for r in rows:
        r["recv_ts"] = "2026-01-01T00:00:00"
    import json
    with open(config.DEVICE_PATH, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    ingest.reset_cache()

    assert ingest.sweep_offline(offline_sec=10) == 1     # 第一次：报
    assert ingest.sweep_offline(offline_sec=10) == 0     # 第二次：同一次沉默不重复报

    kinds = [r["kind"] for r in ingest.load_events()]
    assert kinds.count("device_offline") == 1
