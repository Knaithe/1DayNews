# 架构设计

## 目录布局

```
1DayNews/
├── src/
│   ├── __init__.py
│   ├── vuln_monitor.py        # CLI 入口 + re-export（薄）
│   ├── config.py              # 路径、凭证、HTTP session、日志
│   ├── scoring.py             # RCE/bypass/资产 + score() + category
│   ├── db.py                  # SQLite schema / 迁移 / TTL
│   ├── sources.py             # 各数据源 fetchers
│   ├── notify.py              # Telegram / 企微 / 钉钉 / 飞书
│   ├── nvd.py                 # NVD/GH 查询、CVSS 回填、freshness
│   ├── push_gate.py           # pushed 门禁（正则 + LLM verdict）
│   ├── enrich.py              # LLM agent + 公平批处理队列
│   ├── pipeline.py            # fetch 流水线 / rescore / rebuild / push_pending
│   ├── web.py                 # 仪表盘 API
│   └── static/dashboard.html  # 前端模板
├── scripts/
│   ├── probe_feeds.py         # 源失效时用来批量探测替代 URL 的工具
│   └── configure.py           # 本地交互式写 ~/.config/vuln-monitor/config.json
├── systemd/
│   ├── vuln-monitor.service   # fetch+enrich 常驻 daemon（无需 timer）
│   └── vuln-web.service       # Web 仪表盘常驻服务
├── docs/
│   ├── architecture.md        # 本文
│   ├── sources.md             # 信息源清单与取舍理由
│   ├── filtering.md           # 过滤逻辑（RCE/资产/黑名单/score）
│   └── operations.md          # 运维：锁、原子写、日志、告警限流
├── deploy.sh                  # 一键部署脚本
├── requirements.txt
├── env.example                # .env 模板
└── README.md                  # 速览与快速开始
```

| 模块 | 职责 | I/O |
|---|---|---|
| `scoring.py` | 过滤/分类 | 无 |
| `push_gate.py` | 推送硬门禁 | 无（读 config 密钥） |
| `config.py` | 配置与共享 session | 读 env / config.json |
| `db.py` | 库表 | SQLite |
| `sources.py` | 采集 | HTTP |
| `nvd.py` | NVD/CVSS/freshness | HTTP |
| `enrich.py` | LLM 研判 | HTTP |
| `notify.py` | 多通道推送 | HTTP webhooks |
| `pipeline.py` | fetch/rescore/rebuild | 编排 |
| `vuln_monitor.py` | CLI + re-export | 入口 |
| `web.py` + `static/` | 仪表盘 | HTTP |

包导入统一走 `src.*`（避免 `nvd` / `src.nvd` 双模块身份），测试与 `import src.vuln_monitor` 共用同一实例。

### enrich 批处理（`ENRICH_LIMIT`，默认 200）

旧逻辑 `ORDER BY created_at DESC LIMIT 500` 在入库速度快于 LLM 时会**饿死**旧行（永远排不到）。  
现 `_select_enrich_candidates` 每轮：

1. 最多 `limit//2` 条**最新**高优先级（`RCE`/`bypass` + `1day`）
2. 剩余名额给**最旧**未研判行（FIFO 消化积压）

可用环境变量 `ENRICH_LIMIT` 调整；日志打印 `backlog` / `backlog_left`。  
LLM 故障 fallback 只作用于**本批** keys，避免全表突然灌推送。

## 部署布局（服务器）

```
/opt/vuln-monitor/
├── src/
│   ├── vuln_monitor.py / config.py / scoring.py / db.py
│   ├── sources.py / notify.py / web.py
│   └── static/dashboard.html
├── scripts/
├── systemd/
├── venv/
├── .env                       # 敏感变量，600
├── vuln_cache.db              # ←│ SQLite WAL 模式
├── vuln_monitor.lock          # ←│ runtime state（DATA_DIR）
├── vuln_monitor.log[.1-.5]    # ←│
├── .seeded                    # ←│ 冷启动标记（首次入库后 touch）
├── fetch_state.json           # ←│ 最近一次 fetch 统计
├── source_health.json         # ←│ 各源近 3 轮健康状态
└── vuln_alert_state.json      # ←│
```

**代码（`src/`）与运行态（根目录）分离**的目的：

- 升级（`git pull`）只动 `src/`，不会误删/误写 cache 或日志
- `ProtectSystem=strict` 只需要把 `/opt/vuln-monitor` 整体设为 `ReadWritePaths`
- 本地 `python src/vuln_monitor.py` 开发时，state 文件自动落在仓库根

## 凭证解析规则

Python 启动时按优先级解析推送/API 凭证：

```
1. 环境变量                              ← CI / systemd / 一次性覆盖
2. 用户配置文件 config.json              ← 个人本地持久化
3. 空字符串（TG_* 空即进入 dry mode）
```

| 平台 | 配置文件路径 |
|---|---|
| Linux / macOS | `$XDG_CONFIG_HOME/vuln-monitor/config.json`（默认 `~/.config/...`） |
| Windows | `%APPDATA%\vuln-monitor\config.json` |

创建：`python scripts/configure.py`（交互式，POSIX 下自动 `chmod 600`）。

**为什么不自动去读 `.env`**：`.env` 是 systemd `EnvironmentFile` 的目标格式，仅用于服务器部署。本地用 JSON 配置文件避免两种格式混淆，也避免需要 `python-dotenv` 依赖。

## DATA_DIR 解析规则

```python
1. $VULN_DATA_DIR (env)            ← systemd 在 service 里 pin 成 /opt/vuln-monitor
2. SCRIPT_DIR.parent if name=="src" ← 仓库里跑 `python src/vuln_monitor.py`，落在仓库根
3. SCRIPT_DIR                       ← 单文件直接跑，就地落
```

## 数据流水线（现状）

生产路径是 **daemon 循环**：`fetch(no_push) → enrich(LLM) → push → sleep`。

```
┌─────────────────────────────────────────────────────────────┐
│  daemon (systemd vuln-monitor.service)                      │
│  interval = FETCH_INTERVAL (default 300s)                   │
└────────────────────────┬────────────────────────────────────┘
                         │
           ┌─────────────▼─────────────┐
           │ SingletonLock (非阻塞)     │
           └─────────────┬─────────────┘
                         │
           ┌─────────────▼─────────────┐
           │ fetch (_run no_push=True) │
           │  · 拉全部源               │
           │  · CVE 去重入库           │
           │  · score + freshness      │
           │  · CVSS PR/UI 硬约束      │
           │  · 有 LLM 时 pushed 保持 0│
           │    （不在此处推送）        │
           └─────────────┬─────────────┘
                         │
           ┌─────────────▼─────────────┐
           │ enrich                    │
           │  · NVD CVSS/PR 回填       │
           │  · LLM 研判 / 高信任自动  │
           │  · _resolve_pushed()      │
           │  · _push_pending()        │
           └───────────────────────────┘
```

### 推送门禁（统一）

| 场景 | 谁决定 `pushed` | 谁真正发通知 |
|---|---|---|
| **配了 LLM**（`DEEPSEEK_API_KEY` / `OPENAI_API_KEY`） | 仅 `enrich` 经 `_resolve_pushed` | `_push_pending` 且要求 `llm_verified=1` |
| **未配 LLM** | `fetch`/`rescore` 的正则门禁 `_initial_pushed` | `_push_pending` 对 `pushed=1` 发送 |

因此：

- 单独跑 `fetch` **且已配 LLM** → 只入库，不推送（与 daemon 一致）
- 单独跑 `fetch` **未配 LLM** → 正则命中即推（regex-only 模式）
- LLM 故障 fallback 只放行 `vuln_type IN ('RCE','bypass')`，**不含 `other`**

硬约束（任何路径都不能推翻）：

- `freshness == '1day'`
- 非 `GitHub` / `PoC-GitHub`
- `cvss_pr == 'N'`（未认证）
- `cvss_ui` 为 `N` 或未知（`R` 锁 0）

### CLI 与 daemon 对照

| 入口 | 行为 |
|---|---|
| `daemon` | 循环：`fetch --no-push` 语义 + `enrich` + push |
| `fetch` | 采集入库；有 LLM 时不标 pushed / 推送被 llm 门挡住 |
| `fetch --no-push` | 显式只采集 |
| `enrich` / `enrich --dry` | NVD + LLM +（可选）push |
| `rescore` | 对 `llm_verified=0` 重算 score/freshness；有 LLM 时不单独抬 pushed |

## 为何现在是 daemon（而不是 timer oneshot）

历史上文档推荐 systemd timer + oneshot。当前部署改为 **常驻 daemon**：

- 一轮 = fetch + enrich（LLM 可能较慢），timer 容易与下一 tick 重叠
- daemon 内用 `SingletonLock` + `sleep(interval)`，逻辑集中在一个 service
- 失败用 `Restart=on-failure`；单轮异常会告警限流，不拖死整进程

oneshot 仍可用：`fetch --no-push && enrich`，效果等价。

## 去重为什么用 CVE 号

- 同一 CVE 会出现在多个源（ZDI → KEV → PoC → watchTowr）
- 按 URL 去重会重复推；按 CVE 主键只推第一次
- 无 CVE 时 fallback advisory id / `SHA1(link)` / title hash（见 `item_key()`）

## 冷启动抑制

避免首次开推把历史存量灌进 Telegram：

1. **代码层**：库为空且无 `.seeded` 时，入库后把各通道 `*_sent=1`，抑制首轮通知；然后 touch `.seeded`
2. **deploy 预热**（可选）：`env -i` 无 TG 凭证 dry-run 一次，只写 cache

之后 DB 被清空但 `.seeded` 仍在时，**不会**再次静默吞掉真 0day。

## 下一步可能的演进

| 功能 | 思路 |
|---|---|
| 继续拆分 | `sources.py` / `notify.py` / `db.py` |
| 按严重性分频道 | `_resolve_pushed` + 多 chat_id |
| GHSA 降噪 | 入库限 severity 或 score 更严门槛 |
| 版本化 schema | `schema_version` 表替代启动时一长串 ALTER |
