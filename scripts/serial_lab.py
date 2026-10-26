# -*- coding: utf-8 -*-
"""串口实验台：把「看串口」变成「有数字」。

三个用途：
  1) --watch    实时看板子输出（排障用）
  2) --measure  统计 N 秒内的窗口数 / 计数分布 / 上报数 → 直接给你降噪比（实验 1）
  3) --reset    只复位板子（改完固件重启，不用拔线）

依赖 pyserial。Windows 上串口是 COM7（CH340）。

用法：
    python scripts/serial_lab.py --watch
    python scripts/serial_lab.py --measure 120
    python scripts/serial_lab.py --reset
    python scripts/serial_lab.py --measure 120 --port COM7
"""
import argparse
import re
import statistics
import sys
import time

try:
    import serial
except ImportError:
    print("缺 pyserial：pip install pyserial")
    sys.exit(1)

RE_WIN = re.compile(r"\[win\] n=(\d+) th=(\d+) base=(\d+) over=(\d+)")
RE_SURGE = re.compile(r"\[surge\].*")
RE_POST = re.compile(r"\[post\]\s*(.+)")
RE_BLE = re.compile(r"\[ble\]\s*n=(\d+)\s*vendors=(\d+)")
RE_TICK = re.compile(r"\[tick\]\s*rssi=(-?\d+)\s+reconnect=(\d+)")


def open_port(port):
    s = serial.Serial()
    s.port = port
    s.baudrate = 115200
    s.timeout = 0.2
    s.dtr = False
    s.rts = False
    s.open()
    return s


def reset(s):
    s.rts = True
    time.sleep(0.15)
    s.rts = False
    time.sleep(0.05)


def clean(txt):
    txt = re.sub(r"\x1b\[[0-9;]*m", "", txt)
    return "".join(ch for ch in txt if ch == "\n" or ch == "\t" or ord(ch) >= 32)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", default="COM7")
    ap.add_argument("--watch", action="store_true")
    ap.add_argument("--measure", type=int, default=0, metavar="SEC")
    ap.add_argument("--reset", action="store_true")
    a = ap.parse_args()

    s = open_port(a.port)

    if a.reset:
        reset(s)
        print("已复位，监听 5 秒确认启动：")
        t0 = time.time()
        while time.time() - t0 < 5:
            c = s.read(4096)
            if c:
                sys.stdout.write(clean(c.decode("utf-8", "replace")))
                sys.stdout.flush()
        s.close()
        return

    if a.watch:
        print("实时输出，Ctrl+C 结束：")
        try:
            while True:
                c = s.read(4096)
                if c:
                    sys.stdout.write(clean(c.decode("utf-8", "replace")))
                    sys.stdout.flush()
        except KeyboardInterrupt:
            s.close()
        return

    secs = a.measure or 60
    print("采样 %d 秒（每 5 秒一个窗口，约 %d 个窗口）... Ctrl+C 可提前结束" % (secs, secs // 5 + 1))
    counts, ths, bases, overs = [], [], [], 0
    surges, posts, bootline = [], [], ""
    bles, rssis = [], []
    t0 = time.time()
    buf = ""
    try:
        while time.time() - t0 < secs:
            c = s.read(8192)
            if not c:
                continue
            buf += c.decode("utf-8", "replace")
            while "\n" in buf:
                line, buf = buf.split("\n", 1)
                line = clean(line).strip()
                if not line:
                    continue
                m = RE_WIN.search(line)
                if m:
                    n, th, base, over = (int(x) for x in m.groups())
                    counts.append(n)
                    ths.append(th)
                    bases.append(base)
                    overs = max(overs, over)
                    print("  " + line)
                    continue
                if RE_SURGE.search(line):
                    surges.append(line)
                    print("  \033[33m" + line + "\033[0m")
                    continue
                m = RE_BLE.search(line)
                if m:
                    bles.append((int(m.group(1)), int(m.group(2))))
                    print("  \033[36m" + line + "\033[0m")
                    continue
                m = RE_TICK.search(line)
                if m:
                    rssis.append(int(m.group(1)))
                    print("  " + line)
                    continue
                m = RE_POST.search(line)
                if m:
                    posts.append(m.group(1))
                    print("  " + line)
                    continue
                if "[boot]" in line:
                    bootline = line
                    print("  " + line)
                    continue
                # 关键：不认识的行走这里也要打印出来。
                # 之前这里静默丢弃，导致我误判"固件没打印 [ble]" —— 工具不能骗人。
                print("  \033[90m" + line + "\033[0m")
    except KeyboardInterrupt:
        pass
    s.close()

    print("\n================ 统计 ================")
    if bootline:
        print("启动：", bootline)
    if not counts:
        print("没抓到 [win] 行。可能原因：")
        print("  1) 固件没开 VERBOSE（.ino 里 #define VERBOSE 1）")
        print("  2) 串口被 Arduino IDE 的监视器占着 —— 先关掉它")
        print("  3) 端口不对，试试 --port COMx")
        return

    dur = time.time() - t0
    wins = len(counts)
    print("观测时长      : %.0f 秒" % dur)
    print("采样窗口数    : %d（每窗口 1 个计数样本 = %d 个原始采样）" % (wins, wins))
    print("probe 计数    : min %d / 中位 %.0f / 均值 %.1f / max %d"
          % (min(counts), statistics.median(counts), statistics.mean(counts), max(counts)))
    print("当前阈值      : %d（基线 %d）" % (ths[-1], bases[-1]))
    print("最大连续越界  : %d 个窗口（≥3 才上报）" % overs)
    print("触发 surge    : %d 次" % len(surges))
    if bles:
        ns = [b[0] for b in bles]; vs = [b[1] for b in bles]
        print("BLE 扫描轮次  : %d（设备数 min %d / 中位 %.0f / max %d；厂商数 max %d）"
              % (len(bles), min(ns), statistics.median(ns), max(ns), max(vs)))
    else:
        print("BLE 扫描轮次  : 0（没抓到 [ble] 行 —— 检查 ENABLE_BLE 和共存设置）")
    if rssis:
        print("RSSI 趋势     : min %d / 中位 %.0f / max %d dBm"
              % (min(rssis), statistics.median(rssis), max(rssis)))
    print("POST 成功     : %d 次" % len(posts))

    print("\n---- 降噪比（口径写清楚，别含糊）----")
    print("若按窗口全量上报 : %d 条 / %.0f 秒" % (wins, dur))
    print("实际事件上报     : %d 条 / %.0f 秒" % (len(surges), dur))
    if wins:
        if len(surges) == 0:
            print("本轮没有异常 → 上报 0 条，全量口径下本该是 %d 条" % wins)
            print("换算：约 %.0f 个窗口/天 → 全量 %.0f 条/天，事件化后 %d 条/天（本轮未触发）"
                  % (86400 / 5, 86400 / 5, 0))
        else:
            print("降噪比 ≈ %.0f : 1" % (wins / len(surges)))
            print("换算：约 %.0f 个窗口/天 → 全量 %.0f 条/天，事件化后约 %.1f 条/天"
                  % (86400 / 5, 86400 / 5, (86400 / 5) / (wins / len(surges))))
    print("\n提示：要触发 surge，拿一台手机反复开/关 WiFi（开关时会连续发 probe request），")
    print("      或几个人同时靠近板子。触发后应看到 [surge] 行，且间隔 ≥3 个窗口。")


if __name__ == "__main__":
    main()
