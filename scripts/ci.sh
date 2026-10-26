#!/usr/bin/env bash
# 最小可跑的 CI 流水线（等价于 GitHub Actions / GitLab CI 的那几关）
#
# 为什么要有这个脚本：公司里的流水线是 YAML，你在本机没法验证；
# 但"流水线到底做了什么"可以在这一个文件里看全 —— 六关，顺序不能反。
#
# 用法（Git Bash / WSL / Linux 都行）：
#   bash scripts/ci.sh              # 全跑
#   SKIP_DOCKER=1 bash scripts/ci.sh  # 只跑前 3 关（没装 Docker / 守护进程没起时）
set -euo pipefail
cd "$(dirname "$0")/.."

PY=${PY:-python}
IMAGE=${IMAGE:-sectriage:ci}
PORT=${PORT:-18100}
SKIP_DOCKER=${SKIP_DOCKER:-0}

step() { printf '\n\033[1;34m==> %s\033[0m\n' "$1"; }

# ---------- 1) 装依赖 ----------
# 流水线第一关永远是"把环境装出来"。锁版本（requirements.txt 带 ==）是为了可复现：
# 今天能过、下周挂掉，九成是依赖漂了。
step "[1/6] 安装依赖"
$PY -m pip install -q --disable-pip-version-check -r requirements.txt

# ---------- 2) 静态检查 ----------
# 这一步不追求严格 lint，只保证"语法错误不要等到跑起来才发现"。
# 真项目里这里是 ruff / flake8 / mypy，几秒钟就能挡住一半低级错误。
step "[2/6] 语法检查（compileall）"
$PY -m compileall -q app main.py scripts

# ---------- 3) 单测 ----------
# 单测必须"快"。这套 14 个用例 0.07 秒，快到没人有借口跳过。
step "[3/6] 单元测试"
$PY -m pytest -q

# ---------- 3.5) 评测门槛 ----------
# 单测只证明"函数没写错"，不证明"整体效果没退化"。
# 改了聚合窗口/检索阈值/置信度门槛，单测可能全绿，但降噪率可能从 98.7% 掉到 94%。
# 这一关就是拦这种情况：核心指标跌出区间就让流水线红。
step "[4/6] 评测门槛（降噪率 / 簇数 / 路由合法性）"
$PY scripts/eval_gate.py

# ---------- 4) 构建镜像 ----------
if [ "$SKIP_DOCKER" = "1" ]; then
  step "[5/6] 构建镜像 —— 已跳过（SKIP_DOCKER=1）"
else
  if ! docker info >/dev/null 2>&1; then
    step "[5/6] 构建镜像 —— 跳过（Docker 守护进程没起）"
    echo "    Windows 上先打开 Docker Desktop，再重跑本脚本。"
  else
    step "[5/6] 构建镜像 $IMAGE"
    docker build -t "$IMAGE" .
  fi
fi

# ---------- 5) 起容器 + 健康检查 ----------
# 这一步才是"部署验证"：镜像能构建 ≠ 服务能起来。
# 所以起真容器、打真接口，失败就把日志打出来（不然线上只能靠猜）。
if [ "$SKIP_DOCKER" = "1" ] || ! docker info >/dev/null 2>&1; then
  step "[6/6] 起容器 + 健康检查 —— 跳过"
  echo "  提示：没有 Docker 时，可以直接 python main.py --port $PORT 手工验证。"
  exit 0
fi

step "[6/6] 起容器 + 健康检查"
cleanup() { docker rm -f sectriage-ci >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup
docker run -d --name sectriage-ci -p "$PORT:8100" "$IMAGE" >/dev/null

for i in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:$PORT/health" >/dev/null 2>&1; then
    echo "   健康检查通过：http://127.0.0.1:$PORT/health"
    echo "   接口抽样：$(curl -fsS "http://127.0.0.1:$PORT/stats" | head -c 200)"
    printf '\n\033[1;32mCI 通过\033[0m\n'
    exit 0
  fi
  sleep 1
done

echo "   健康检查超时，容器日志："
docker logs sectriage-ci | tail -40
printf '\n\033[1;31mCI 失败\033[0m\n'
exit 1
