# ---------- 构建阶段：只在这里装依赖（编译工具不带到运行镜像） ----------
FROM python:3.12-slim AS builder
WORKDIR /build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1

COPY requirements.txt .
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --upgrade pip \
 && /opt/venv/bin/pip install -r requirements.txt

# ---------- 运行阶段：只带运行时 ----------
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    TZ=Asia/Shanghai

# 非 root 运行：容器被拿下之后，攻击者拿到的也只是一个没权限的普通用户
RUN useradd -m -u 10001 appuser
WORKDIR /app

COPY --from=builder /opt/venv /opt/venv
COPY --chown=appuser:appuser app ./app
COPY --chown=appuser:appuser scripts ./scripts
COPY --chown=appuser:appuser main.py requirements.txt ./

# 数据目录会被卷挂载覆盖，这里先建好并授权，保证不挂卷也能起来
RUN mkdir -p /app/data && chown -R appuser:appuser /app

USER appuser
EXPOSE 8100

# 用标准库探活，slim 镜像里没有 curl
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request as u,sys; sys.exit(0 if u.urlopen('http://127.0.0.1:8100/health',timeout=2).status==200 else 1)"

# workers=1 是刻意的：SQLite 单写者 + 进程内缓存，多 worker 会各算各的、聚合结果不一致。
# 要横向扩容得先把存储换 MySQL/Postgres、缓存外置 Redis（已知边界，见 README）。
CMD ["uvicorn", "app.api:app", "--host", "0.0.0.0", "--port", "8100", "--workers", "1"]
