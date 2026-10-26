# SecTriage

把每天几千条安全告警，自动压成几十个"事件"，并对每个事件给出**判定 + 置信度 + 依据 + 处置建议**。

2026.10 开始做。设计思想见 [docs/实现思想详解.md](docs/实现思想详解.md)，
与标准企业级 Agent 骨架的对照见 [docs/架构与标准企业骨架对照.md](docs/架构与标准企业骨架对照.md)。
做这个项目踩过的 10 个坑（含误判与代价）见 [docs/走过的弯路.md](docs/走过的弯路.md)
——**如果只想判断"这是不是真做过"，看这一份最快**。

---

## 可验证证据（先看这一节，30 秒判断真假）

```bash
pip install -r requirements.txt
pytest -q                    # → 27 passed（0.1s 级）
python scripts/eval_gate.py  # → 6 项门槛，全部 OK
bash scripts/ci.sh           # → 六关流水线（依赖/静态检查/单测/评测门槛/镜像/健康检查）
python main.py --port 8200   # → 打开 http://127.0.0.1:8200/ 点几下
```

| 指标 | 实测值 | 怎么复现 |
|---|---|---|
| 告警 → 事件 | **3000 → 40**，降噪率 **98.67%** | `curl /stats` |
| 平均每簇 | **75.0 条** | `curl /stats` |
| 路由分布 | `need_human 35 / review 4 / escalate 1` | `curl /run` |
| 单测 | **27 个**，0.1s | `pytest -q` |
| 评测门槛 | 6 项（降噪率/簇数/每簇数/路由合法性/单簇上限/有数据） | `python scripts/eval_gate.py` |
| 模型挂掉时的全量研判耗时 | **80.2s → 6.1s（13.1×）** | `python scripts/breaker_experiment.py` |
| 熔断真实调用次数 | **40 → 3**（其余 37 次直接拒绝，不再等超时） | 同上 |
| 降噪归因（消融） | 聚合层吃掉全部合并量：3000→40（98.67%）；研判层不合并只定性，人工 25h→1.7h | `python scripts/ablation.py` |
| 代码量 | app 896 行 + 脚本 457 行 + 测试 216 行 = **1644 行** | `wc -l` |

> 所有数字都能用上面的命令重跑出来。**跑不出来的数字我不会写在这里。**

---

## 快速开始（三步，约 1 分钟）

```bash
# 1) 装依赖
pip install -r requirements.txt

# 2) 起服务（首次会自动生成 3000 条模拟告警）
python main.py

# 3) 打开
#    页面  http://127.0.0.1:8100/
#    接口  http://127.0.0.1:8100/docs
```

Windows 上也可以双击 `start.bat`。

**没有 LLM key 也能跑完整链路**——会走规则降级（`mode=rule`）。配了 key 才是真模型研判：

```bash
cp .env.example .env      # 填 LLM_BASE / LLM_KEY
```

---

## 它解决什么问题

| 数字 | 说明 |
|---|---|
| 3000 条/天 | 一台中等规模 WAF+EDR+IDS 的日告警量 |
| 30 秒/条 | 人工看一条的时间 |
| 3000 × 30s = **25 小时** | 一个人的日工作量 → 根本看不完 |
| 其中 80–92% | 重复告警或业务误报 |

结果就是**告警越多，真事件越容易被漏掉**。所以要做降噪（triage）+ 研判（investigation）。

## 实测效果

**合成数据（3000 条，带事件级真值）**

```
3000 条告警 → 40 个事件，降噪率 98.7%
TP=7  FP=1  FN=0  TN=32
准确率 97.5%   覆盖率 100%   误报率 3%
研判成本 ≈ ¥0.04/轮（40 次调用 × 1200 token）
```

**真实靶场流量（433 条真实 HTTP 请求，Windows 目标 + Kali 攻击）**

```
433 条 → 7 个事件，降噪率 98.4%
朴素基线（IP 前缀）  准确率 57%   漏报 33%
台账基线（资产台账）  准确率 71%   漏报 0
```

> 真实数据打穿了一个假设：用 IP 前缀判内外网会漏报（`127.0.0.1` 不在前缀表、`172.24` 是 NAT 段却被当内网）。详见 docs 第 3 节。

## 接口

| 方法 | 路径 | 作用 |
|---|---|---|
| GET | `/` | 前端页面 |
| GET | `/health` | 健康检查（含 uptime） |
| GET | `/stats` | 告警数 / 事件数 / 降噪率 |
| GET | `/clusters?limit=` | 事件列表（`with_truth=true` 可看真值，仅调试用） |
| GET | `/clusters/enriched` | 带上下文的事件（资产重要性/历史/网段） |
| GET | `/sop/search?q=` | 检索处置 SOP |
| GET | `/triage?limit=` | 对事件做研判 |
| GET | `/run` | 全量跑一遍，返回路由分布 |
| POST | `/decide/{cluster_id}` | 对单个事件出决策并写审计（不执行处置） |
| GET | `/audit?limit=` | 读审计日志 |
| POST | `/ingest` | 边缘设备上报（幂等，按 `boot_id+seq` 去重） |
| GET | `/device/events?limit=` | 设备事件流水（含心跳） |
| GET | `/device/status` | 每台设备活跃度；静默超 120s 判离线并产一条告警 |

> 设备事件单独存 `data/device_events.jsonl`，**不进 `alerts.jsonl`**——否则评测数字不可复现。
> 想一起看簇：`/clusters?with_device=true`（内存合并，不写盘）。
> 方案与实验清单见 `docs/ESP32_边缘告警源_方案.md`。

## 目录

```
app/
├── config.py     配置：环境变量、路径、网段台账
├── store.py      数据读写：告警/资产/SOP/审计
├── retrieve.py   检索：bigram + BM25 + RRF
├── pipeline.py   业务：聚合 → 富化 → 研判 → 决策
├── api.py        接口：路由 + 统一错误出口
└── web/index.html 前端单页
main.py           启动入口（首次自动造数据）
scripts/gen_alerts.py  告警生成器（8 类 + 反泄漏自检）
tests/            27 个单测（跑 0.1 秒）：pipeline 14 + 边缘接入 7 + 熔断 6
docs/             实现思想详解 / 架构对照 / 走过的弯路 / ESP32 方案
```

## 开发

```bash
pytest -q                       # 27 passed
python scripts/gen_alerts.py    # 重新生成数据
pytest -q -k aggregate          # 只跑聚合相关
```

## 部署

```bash
docker compose up -d
curl http://127.0.0.1:8100/health
```

数据卷挂在 `./data`，删容器数据不丢。对外暴露时必须 `--host 0.0.0.0`（`main.py` 已支持）。

## 已知局限

1. 存储是 JSONL，上万事件要换 SQLite/ES 并加索引
2. `history_clusters` 只统计当前批次，真实项目应查 7 天历史库
3. 没有跨事件记忆（同一 IP 打三次还是各判各的）
4. 未对接真实 EDR/WAF，只有自造数据 + 靶场
5. 没做过压测，不知道 100 QPS 卡在哪
6. 前端是单页，够演示不够值班用

## 数据说明

告警是**合成数据**（真实 SOC 数据受合规限制拿不到），但每条带 `is_true_positive` 真值，所以能算混淆矩阵和漏报率。

为防止标签泄漏，数据里特意包含两类反直觉样本：**外网授权扫描（误报）** 与 **内网横向移动（真事件）**。生成器里有反泄漏自检打印，两个数都不为 0 才算合格。

## License

MIT
