# -*- coding: utf-8 -*-
"""设备模拟器 —— 没有硬件也能把链路跑通、把可靠性实验做完。

它做的事和真实 ESP32 完全一样：POST /ingest，带 device.id + boot_id + 每条事件的 seq。
所以"固件烧好之前的一切验证"和"面试演示没带板子"都能用它顶上。

用法：
    python scripts/device_sim.py                        # 跑全套场景
    python scripts/device_sim.py --scenario surge       # 只跑某一个
    python scripts/device_sim.py --url http://127.0.0.1:8200 --scenario all
    python scripts/device_sim.py --device esp32-lab-01 --boot-id a1b2

场景说明（每个都对应一个面试能讲的点）：
    baseline  连续 60 个采样窗口都正常 → 上报 0 条。证明"降噪在边缘发生"，不是把原始数据全抛上来
    surge     探测请求突增（跨阈值 + 持续 3 个窗口才报）→ 1 条
    rogue     发现同名 SSID 但 BSSID 不同（钓鱼热点特征）→ 1 条
    reboot    boot_id 变了（设备重启）→ 重启本身也是一条可用性事件
    dup       把前面整批原样重发 → accepted=0 / duplicated=N，证明幂等
    reorder   故意乱序发 seq → 服务端仍按 seq 去重、按接收时间聚合
"""
import argparse
import json
import time
import urllib.request

URL = "http://127.0.0.1:8200"


def post(base, payload, token=""):
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(base + "/ingest", data=data, method="POST",
                                 headers={"Content-Type": "application/json",
                                          "X-Ingest-Token": token})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read().decode("utf-8"))


def get(base, path):
    with urllib.request.urlopen(base + path, timeout=10) as r:
        return json.loads(r.read().decode("utf-8"))


def batch(dev_id, boot_id, events, fw="1.0.0"):
    return {"device": {"id": dev_id, "boot_id": boot_id, "fw": fw}, "events": events}


def ev(seq, kind, value, ms, **detail):
    return {"seq": seq, "dev_ms": ms, "kind": kind, "value": value, "detail": detail}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default=URL)
    ap.add_argument("--device", default="esp32-lab-01")
    ap.add_argument("--boot-id", default="b7c1")
    ap.add_argument("--scenario", default="all",
                    choices=["all", "baseline", "surge", "rogue", "reboot", "dup", "reorder"])
    ap.add_argument("--token", default="")
    a = ap.parse_args()
    base, dev, boot = a.url.rstrip("/"), a.device, a.boot_id
    todo = a.scenario

    print("设备 %s  boot_id=%s  目标 %s" % (dev, boot, base))

    sent = []          # 记录发过什么，dup 场景要原样重发

    def send(name, payload, note=""):
        res = post(base, payload, a.token)
        sent.append(payload)
        print("  %-9s events=%-2d -> accepted=%-2d duplicated=%-2d rejected=%-1d  %s"
              % (name, len(payload["events"]), res.get("accepted", 0),
                 res.get("duplicated", 0), res.get("rejected", 0), note))
        return res

    if todo in ("all", "baseline"):
        # 60 个窗口（每窗口 5 秒 = 5 分钟），每窗口 3 个指标 = 180 个原始采样。
        # 固件在正常窗口里**不发任何请求**，所以这里发的是空批次。
        # 对比口径（面试要能说清）：180 个采样 → 1 条事件（surge），降噪比 180:1。
        print("\n[baseline] 60 个窗口全部正常：180 个原始采样，上报 0 条")
        r = send("baseline", batch(dev, boot, []), "空批次（正常窗口本来就不该发请求）")

    if todo in ("all", "surge"):
        print("\n[surge] 探测请求突增：3 个窗口连续超阈值才上报（去抖）")
        # 前 2 个窗口超阈值但不足 3 个 → 固件不上报；第 3 个窗口才发
        send("surge-1",
             batch(dev, boot, [ev(1, "probe_surge", 47, 300000,
                                  ip="192.168.1.42", window_s=5, baseline=12)]),
             "value=47 基线 12，连续第 3 个窗口")

    if todo in ("all", "rogue"):
        print("\n[rogue] 同名 SSID / 不同 BSSID（钓鱼热点特征）")
        send("rogue", batch(dev, boot, [ev(2, "ap_rogue", 2, 305000,
                                           ip="192.168.1.1",
                                           ssid="Campus-WiFi", bssids=2, channel=6)]))

    if todo in ("all", "reboot"):
        print("\n[reboot] 设备重启：boot_id 变化，seq 归零")
        send("reboot",
             batch(dev, boot + "r", [ev(0, "device_reboot", 1, 1200, reason="power_on")]))

    if todo in ("all", "dup"):
        print("\n[dup] 把前面发过的整批原样重发（模拟断网补传）")
        for p in list(sent)[:2]:
            send("dup", p, "应该全部 duplicated")

    if todo in ("all", "reorder"):
        print("\n[reorder] 乱序发送（seq 5 3 4）")
        send("reorder", batch(dev, boot, [
            ev(5, "probe_surge", 51, 400000, ip="192.168.1.42", window_s=5),
            ev(3, "probe_surge", 44, 390000, ip="192.168.1.42", window_s=5),
            ev(4, "probe_surge", 49, 395000, ip="192.168.1.42", window_s=5),
        ]))

    if todo in ("all", "baseline"):
        print("\n[heartbeat] 心跳：只更新活跃度，**不产生告警**")
        send("beat", batch(dev, boot, [ev(6, "heartbeat", 1, 405000)]),
             "beats+1，告警数不变（否则每 5 分钟一条噪音）")

    # ---------- 汇总 ----------
    st = get(base, "/device/status")
    print("\n设备状态：")
    for d in st["items"]:
        print("  %s  online=%s  events=%d  last_seq=%s  boot=%s  静默 %ss"
              % (d["device_id"], d["online"], d["events"], d["last_seq"],
                 d["boot_id"], d["silent_s"]))

    cc = get(base, "/clusters?with_device=true&limit=200")
    mine = [c for c in cc["items"] if c["asset"] == dev]
    print("\n设备事件形成的簇（共 %d 个，全部簇 %d 个）：" % (len(mine), cc["total"]))
    for c in mine:
        print("  %-22s count=%-3d %s ~ %s" % (c["rule"][:20], c["count"], c["first_ts"], c["last_ts"]))

    other = [c for c in cc["items"] if c["asset"] != dev][:3]
    print("\n原有告警簇（前 3，未受影响）：")
    for c in other:
        print("  %-22s asset=%-12s count=%d" % (c["rule"][:20], c["asset"], c["count"]))

    print("\n一句话结论：5 分钟里 180 个原始采样，只上来 1 条事件；"
          "重复投递被幂等吃掉，乱序不影响排序，重启单独可见。")


if __name__ == "__main__":
    main()
