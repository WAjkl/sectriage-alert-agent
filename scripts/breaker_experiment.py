# -*- coding: utf-8 -*-
"""熔断前后对比实验：模型服务不可用时，跑一遍全量研判要多久。

做法：把 LLM_BASE 指向一个不会响应的地址（黑洞），LLM_TIMEOUT=2（缩短等待），
两次分别用「熔断几乎不生效」(threshold=999) 与「熔断生效」(threshold=3) 跑 /run，比总耗时。

注意：这是真跑出来的数字，不是推算。跑完记得把 .env 还原。
"""
import json
import os
import subprocess
import sys
import time
import urllib.request

BASE_PORT = 8302
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def wait_health(port, n=40):
    for _ in range(n):
        try:
            with urllib.request.urlopen("http://127.0.0.1:%d/health" % port, timeout=1) as r:
                if r.status == 200:
                    return True
        except Exception:
            time.sleep(0.5)
    return False


def run_case(threshold, label):
    env = dict(os.environ)
    env.update({
        "LLM_BASE": "http://10.255.255.1/v1",     # 黑洞：连不通也几乎不响应
        "LLM_KEY": "dummy",
        "LLM_TIMEOUT": "2",
        "BREAKER_THRESHOLD": str(threshold),
        "BREAKER_COOLDOWN": "30",
    })
    py = sys.executable
    p = subprocess.Popen([py, "main.py", "--host", "127.0.0.1", "--port", str(BASE_PORT)],
                         cwd=ROOT, env=env,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not wait_health(BASE_PORT):
            print("[%s] 服务没起来" % label)
            return None
        t0 = time.time()
        with urllib.request.urlopen("http://127.0.0.1:%d/run" % BASE_PORT, timeout=300) as r:
            data = json.loads(r.read().decode())
        cost = time.time() - t0
        with urllib.request.urlopen("http://127.0.0.1:%d/resilience" % BASE_PORT, timeout=5) as r:
            st = json.loads(r.read().decode())["items"][0]
        print("[%s] 耗时 %.1fs｜簇 %d｜熔断状态 %s｜真实调用 %d｜被拒 %d｜失败 %d"
              % (label, cost, data["clusters"], st["state"], st["calls"],
                 st["rejected"], st["failures"]))
        return {"cost": cost, "clusters": data["clusters"], "state": st["state"],
                "calls": st["calls"], "rejected": st["rejected"], "failures": st["failures"]}
    finally:
        p.terminate()
        try:
            p.wait(timeout=10)
        except Exception:
            p.kill()
        time.sleep(1)


if __name__ == "__main__":
    print("模型地址 = 黑洞 IP，单次超时 = 2s，簇数 40\n")
    a = run_case(999, "无熔断（阈值 999）")
    b = run_case(3, "有熔断（阈值 3）")
    if a and b:
        print("\n==== 结论 ====")
        print("无熔断 %.1fs  →  有熔断 %.1fs，快 %.1f 倍" %
              (a["cost"], b["cost"], a["cost"] / max(b["cost"], 0.1)))
        print("真实调用次数：%d → %d（其余 %d 次被直接拒绝，没再等超时）"
              % (a["calls"], b["calls"], b["rejected"]))
