"""生成带 ground truth 的模拟告警流

关键设计：**故意让标签不能由单一规则推出**（避免标签泄漏）。
- 有外部 IP 的误报（合作方授权扫描）：外网 ≠ 一定攻击
- 有内网的误报（备份、探针、管理员登录）：内网 ≠ 一定安全
- 有内网的真事件（横向移动 SMB 爆破）：内网也可能是攻击
否则"内网=误报/外网=攻击"一条规则就能 100%，评测毫无意义。
"""
import json, os, random
from datetime import datetime, timedelta

random.seed(42)          # 固定种子：每次生成同样的数据，实验可复现

OUT = os.path.join(os.path.dirname(__file__), "..", "data")
os.makedirs(OUT, exist_ok=True)

ASSETS = [
    {"asset": "srv-db-01",   "importance": 5, "public": False, "desc": "核心数据库"},
    {"asset": "srv-web-01",  "importance": 4, "public": True,  "desc": "对外门户"},
    {"asset": "srv-jump-01", "importance": 3, "public": True,  "desc": "跳板机"},
    {"asset": "pc-hr-07",    "importance": 2, "public": False, "desc": "人事办公机"},
    {"asset": "srv-bak-01",  "importance": 2, "public": False, "desc": "备份服务器"},
]

BASE = datetime(2026, 10, 20, 0, 0, 0)
alerts = []


def add(ts, rule, asset, src_ip, port, tech, sev, raw, tp):
    alerts.append({
        "alert_id": "A%06d" % (len(alerts) + 1),
        "ts": ts.strftime("%Y-%m-%dT%H:%M:%S"),
        "rule": rule, "asset": asset, "src_ip": src_ip, "dst_port": port,
        "technique": tech, "severity": sev, "raw": raw,
        "is_true_positive": tp,
    })


# ① 真事件：外网 SSH 暴力破解（1500 条，3 个时间窗）
for burst, src in enumerate(["45.12.33.7", "103.44.9.21", "185.7.2.99"]):
    start = BASE + timedelta(hours=9 + burst * 7)
    for i in range(500):
        add(start + timedelta(seconds=i * 2), "SSH 暴力破解尝试", "srv-jump-01",
            src, 22, "T1110", "high",
            "Failed password for root from %s port %d ssh2" % (src, 50000 + i), True)

# ② 真事件：外网 Web 目录扫描（500 条）
for burst in range(2):
    start = BASE + timedelta(hours=14 + burst * 5)
    for i in range(250):
        add(start + timedelta(seconds=i), "Web 目录扫描", "srv-web-01",
            "91.240.118.6", 443, "T1595", "medium",
            "GET /admin%d HTTP/1.1 404 UA=dirb" % i, True)

# ③ 真事件：内网横向移动（380 条）—— 内网也可能是攻击，这条专门破"内网=误报"的偷懒规则
start = BASE + timedelta(hours=18)
for i in range(380):
    add(start + timedelta(seconds=i * 3), "SMB 暴力破解", "srv-db-01",
        "10.20.3.44", 445, "T1021", "high",
        "STATUS_LOGON_FAILURE user=sa from 10.20.3.44 nth=%d" % i, True)

# ④ 真事件：内网主机可疑外联 C2（120 条）
start = BASE + timedelta(hours=20)
for i in range(120):
    add(start + timedelta(minutes=i * 2), "可疑外联（非常用端口）", "pc-hr-07",
        "10.20.3.44", 8443, "T1041", "critical",
        "Outbound to 45.77.19.3:8443 bytes=%d" % (1024 * (i + 1)), True)

# ⑤ 误报：备份任务大流量（200 条）
start = BASE + timedelta(hours=2)
for i in range(200):
    add(start + timedelta(minutes=i), "异常流量突增", "srv-bak-01",
        "10.20.1.10", 445, "T1039", "medium",
        "SMB transfer 8GB from backup job nightly-%d" % i, False)

# ⑥ 误报：监控探针高频访问（150 条）
start = BASE + timedelta(hours=6)
for i in range(150):
    add(start + timedelta(minutes=i), "高频请求", "srv-web-01",
        "10.20.1.21", 80, "T1595", "low",
        "HEAD /health probe=%d" % i, False)

# ⑦ 误报：管理员正常登录（30 条，低频 → 不会聚合，会以单条进入研判）
start = BASE + timedelta(hours=8)
for i in range(30):
    add(start + timedelta(minutes=i * 20), "SSH 登录成功", "srv-jump-01",
        "10.20.1.5", 22, "T1078", "low",
        "Accepted publickey for ops from 10.20.1.5", False)

# ⑧ 误报：合作方授权扫描（120 条）—— 外网 IP 但是误报，专治"外网=攻击"
start = BASE + timedelta(hours=11)
for i in range(120):
    add(start + timedelta(seconds=i * 5), "Web 目录扫描", "srv-web-01",
        "203.0.113.20", 443, "T1595", "medium",
        "GET /api/v1/ping HTTP/1.1 404 UA=authorized-scanner", False)

random.shuffle(alerts)          # 打散：模拟真实乱序到达

with open(os.path.join(OUT, "alerts.jsonl"), "w", encoding="utf-8") as f:
    for a in alerts:
        f.write(json.dumps(a, ensure_ascii=False) + "\n")

with open(os.path.join(OUT, "assets.json"), "w", encoding="utf-8") as f:
    json.dump(ASSETS, f, ensure_ascii=False, indent=1)

tp = sum(1 for a in alerts if a["is_true_positive"])
ext = sum(1 for a in alerts if not a["src_ip"].startswith(("10.", "192.", "172.")))
ext_fp = sum(1 for a in alerts if not a["is_true_positive"]
             and not a["src_ip"].startswith(("10.", "192.", "172.")))
in_tp = sum(1 for a in alerts if a["is_true_positive"]
            and a["src_ip"].startswith(("10.", "192.", "172.")))
print("生成告警 %d 条：真事件 %d（%.0f%%）/ 误报 %d（%.0f%%）"
      % (len(alerts), tp, tp / len(alerts) * 100, len(alerts) - tp,
         (len(alerts) - tp) / len(alerts) * 100))
print("反泄漏检查：外网告警 %d 条，其中误报 %d 条；内网真事件 %d 条"
      % (ext, ext_fp, in_tp))
print("  若上面两个数都是 0，说明标签能由'内外网'直接推出，评测无效。")
