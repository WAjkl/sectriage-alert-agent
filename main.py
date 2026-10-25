# -*- coding: utf-8 -*-
"""启动入口。

    python main.py                # 127.0.0.1:8100
    python main.py --port 8000    # 换端口
    python main.py --host 0.0.0.0 # 对外（容器里必须用这个）

首次启动如果 data/ 里没有告警，会自动跑一次生成器，省得新人卡在第一步。
"""
import os
import sys
import argparse
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from app import config, store          # noqa: E402


def ensure_data():
    config.ensure_dirs()
    if store.load_alerts():
        return
    gen = os.path.join(HERE, "scripts", "gen_alerts.py")
    if os.path.exists(gen):
        print("[init] data/ 里没有告警，先跑一次生成器：", gen)
        subprocess.run([sys.executable, gen], check=False)
    else:
        print("[warn] 没有 data/alerts.jsonl，也没有生成器；接口会返回空结果")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8100)
    ap.add_argument("--reload", action="store_true")
    a = ap.parse_args()

    ensure_data()
    import uvicorn
    print("打开 http://%s:%d/ 看页面，http://%s:%d/docs 看接口"
          % (a.host, a.port, a.host, a.port))
    uvicorn.run("app.api:app", host=a.host, port=a.port, reload=a.reload)


if __name__ == "__main__":
    main()
