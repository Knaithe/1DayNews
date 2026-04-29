# vuln-monitor

聚合多源 0day/1day RCE 情报，关键词过滤后推 Telegram + Web 仪表盘。面向安全研究员的个人订阅器。

## 核心特性

- **17 个数据通道**：厂商 PSIRT（Fortinet/PaloAlto/Cisco/MSRC）、漏洞披露（ZDI/watchTowr/DailyCVE）、Exploit/PoC（Sploitus/GitHub/PoC-in-GitHub）、漏洞研究（Horizon3/Rapid7）、在野利用（CISA KEV）、漏洞库（长亭/微步）
- **聚焦 RCE**：60+ 正则 + 500 资产关键词 + 排除规则，过滤 XSS/CSRF/LPE/DoS 噪声
- **增量去重**：SQLite WAL 模式，CVE 为主键，60 天 TTL，同一 CVE 跨源只推一次
- **多视图查询**：简表 / 详细 / 通知友好 / JSON，支持 CVE/厂商/关键词/时间过滤
- **Web 仪表盘**：暖色卡片式界面，实时搜索过滤，只绑 localhost（SSH 隧道访问）
- **自动补全**：缺字段的高价值记录自动从 CVE/公告编号/标题推断链接和来源
- **AI 驱动**：Claude Code skill（`/vuln`），自然语言查询漏洞情报
- **LLM 研判**：DeepSeek/GPT function calling 自主核验 1day/RCE/影响面，NVD CVSS 自动补全
- **生产级**：文件锁防并发、失败重试、日志轮转、告警限流、一键部署/卸载

## 快速开始

```bash
git clone https://github.com/Knaithe/1DayNews.git && cd 1DayNews
pip install -r requirements.txt
python src/vuln_monitor.py fetch    # dry-run（不设 TG token 不推送）
python src/web.py                   # Web 仪表盘 http://127.0.0.1:8001
```

## CLI 子命令

```bash
python src/vuln_monitor.py fetch                              # 抓取 → 去重 → 存库 → 推送
python src/vuln_monitor.py query --pushed --days 1            # 简表
python src/vuln_monitor.py query --full --cve CVE-2026-1340   # 详细
python src/vuln_monitor.py query --json --source CISA_KEV     # JSON
python src/vuln_monitor.py brief --pushed --days 1            # 通知格式（自动补全+质量过滤）
python src/vuln_monitor.py stats                              # 统计
python src/vuln_monitor.py rebuild                            # 回填历史记录缺失字段
python src/vuln_monitor.py rescore                            # 用当前规则重新评估所有记录
python src/vuln_monitor.py fetch --no-push                    # 只采集不推送（配合 enrich）
python src/vuln_monitor.py enrich                             # LLM 研判 + NVD CVSS 补全 + 推送
python src/vuln_monitor.py enrich --dry                       # 研判但不推送
```

过滤参数：`--cve` / `--source` / `--keyword` / `--days` / `--pushed` / `--reason` / `--limit`

## Web 仪表盘

```bash
python src/web.py                    # http://127.0.0.1:8001
ssh -L 8001:127.0.0.1:8001 user@srv  # 远程 SSH 隧道访问
```

Pluto Security 风格暖色卡片布局，实时搜索，药丸式源/原因/时间筛选，严重性颜色编码。默认只显示精选（pushed），可切换全量。安全加固（CSP/X-Frame-Options/nosniff），只读 SQLite + waitress，只绑 127.0.0.1。部署时自动启用 systemd 服务。详见 [`docs/web-dashboard.md`](docs/web-dashboard.md)。

## Telegram 推送

```bash
python scripts/configure.py          # 交互式配置 TG_BOT_TOKEN / TG_CHAT_ID
python src/vuln_monitor.py fetch     # 配置后自动推送
```

支持多频道/群/个人同时推送：`TG_CHAT_ID=-100xxx,-100yyy,123456`

优先级：环境变量 > 配置文件 > 空（dry mode）。

### 凭证配置

| 变量 | 用途 | 获取 |
|---|---|---|
| `TG_BOT_TOKEN` | Telegram 推送 | @BotFather |
| `TG_CHAT_ID` | 推送目标（逗号分隔多个） | @userinfobot / @RawDataBot |
| `GH_TOKEN` | GitHub API 限频 60→5000 次/小时 | GitHub → Settings → Developer settings → PAT |
| `NVD_API_KEY` | NVD API 限频 5→50 次/30 秒 | https://nvd.nist.gov/developers/request-an-api-key |
| `DEEPSEEK_API_KEY` | LLM 研判（推荐，便宜） | https://platform.deepseek.com |
| `OPENAI_API_KEY` | LLM 研判（备选） | https://platform.openai.com |
| `LLM_MODEL` | 模型名（默认 deepseek-chat） | 可选 |
| `LLM_BASE_URL` | 自定义 API 端点 | 可选，兼容任意 OpenAI 格式 |

### LLM 研判（可选）

配了 `DEEPSEEK_API_KEY` 或 `OPENAI_API_KEY` 后，`enrich` 子命令会用 LLM 做二次研判。以下是每个模型的完整 .env 配置示例，选一个复制到 `.env` 即可。

#### DeepSeek deepseek-v4-flash（推荐，便宜快速，1M 上下文）

```bash
DEEPSEEK_API_KEY=sk-xxxxxxxxxxxxxxxx
LLM_MODEL=deepseek-v4-flash
LLM_TEMPERATURE=0.1
LLM_MAX_TOKENS=4096
LLM_TIMEOUT=60
LLM_MAX_CONTEXT=1048576
LLM_REASONING_EFFORT=high
LLM_TOP_P=0.9
```

#### OpenAI GPT-5.4（性价比，1M 上下文）

```bash
OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxx
LLM_MODEL=gpt-5.4
LLM_TEMPERATURE=0.1
LLM_MAX_TOKENS=4096
LLM_TIMEOUT=60
LLM_MAX_CONTEXT=1050000
LLM_REASONING_EFFORT=high
LLM_TOP_P=0.9
```

#### OpenAI GPT-5.5（最准，1M 上下文）

```bash
OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxx
LLM_MODEL=gpt-5.5
LLM_TEMPERATURE=0.1
LLM_MAX_TOKENS=8192
LLM_TIMEOUT=90
LLM_MAX_CONTEXT=1000000
LLM_REASONING_EFFORT=high
LLM_TOP_P=0.9
```

#### 第三方中转（OpenRouter / 自建代理）

```bash
OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxx
LLM_BASE_URL=https://openrouter.ai/api
LLM_MODEL=deepseek/deepseek-chat
LLM_TEMPERATURE=0.1
LLM_MAX_TOKENS=4096
LLM_TIMEOUT=60
LLM_MAX_CONTEXT=131072
LLM_REASONING_EFFORT=high
LLM_TOP_P=0.9
```

#### 本地 Ollama（受本地显存限制）

```bash
OPENAI_API_KEY=ollama
LLM_BASE_URL=http://localhost:11434
LLM_MODEL=llama3
LLM_TEMPERATURE=0.1
LLM_MAX_TOKENS=2048
LLM_TIMEOUT=120
LLM_MAX_CONTEXT=8192
LLM_REASONING_EFFORT=high
LLM_TOP_P=0.9
```

#### 参数说明

| 参数 | 默认 | 说明 |
|---|---|---|
| `LLM_TEMPERATURE` | 0.1 | 创造性，0=完全确定性，1=最大随机 |
| `LLM_MAX_TOKENS` | 1024 | 最大输出 token 数（GPT-5.5 建议 8192） |
| `LLM_TIMEOUT` | 60 | API 超时秒数，推理模型建议 120 |
| `LLM_MAX_CONTEXT` | 1048576 | 上下文窗口（1M），GPT-5.4/5.5/DeepSeek-V4 均为百万级 |
| `LLM_REASONING_EFFORT` | high | 思考等级：low / medium / high，支持的模型才生效 |
| `LLM_TOP_P` | 0.9 | 核采样，和 temperature 配合控制输出多样性 |

自定义 system prompt 放 `/opt/vuln-monitor/llm_prompt.txt`，不存在则用内置默认。不支持 temperature / tools / reasoning_effort 的模型会自动降级重试。

LLM 会自主决定是否调用工具（查 NVD、抓源页面、搜 GitHub/长亭），输出结构化研判：

| LLM 判定 | 含义 | 推送 |
|---|---|---|
| `1day_rce` | 新鲜 + 远程代码执行 | 推 |
| `1day_high` | 新鲜 + 高危非 RCE | 推 |
| `1day_low` | 新鲜但低影响 | 不推 |
| `nday` | 老洞 | 不推 |
| `noise` | 噪声 | 不推 |

不配 LLM key 时 enrich 跳过 LLM 步骤，直接走正则结果推送，不影响现有功能。

部署后 systemd 自动串联 `fetch --no-push && enrich`，无需手动操作。

## 一键部署

```bash
curl -sSL https://raw.githubusercontent.com/Knaithe/1DayNews/master/deploy.sh | sudo bash
```

卸载：`sudo bash uninstall.sh`（保留数据）或 `sudo bash uninstall.sh --purge`（彻底清除）。

## Claude Code / openclaw

```bash
cd /opt/vuln-monitor && claude
/vuln                            # 加载 skill
```

| 操作 | 说法 |
|---|---|
| 抓取 | "fetch" / "更新" |
| 查询 | "最近有什么新漏洞" / "查一下 CVE-2026-1340" |
| 转发格式 | "Fortinet 最近的漏洞，给我可以转发的格式" |
| 统计 | "stats" |

## 文档

| 主题 | 文档 |
|---|---|
| 目录布局、数据流、部署机制 | [`docs/architecture.md`](docs/architecture.md) |
| 数据源清单与评估 | [`docs/sources.md`](docs/sources.md) |
| RCE 过滤规则 | [`docs/filtering.md`](docs/filtering.md) |
| 运维、日志、故障定位 | [`docs/operations.md`](docs/operations.md) |
| Web 仪表盘 | [`docs/web-dashboard.md`](docs/web-dashboard.md) |

## 许可

个人使用。源站 TOS 不允许高频爬取的（比如 `sec.cloudapps.cisco.com`），请自觉降低频率。
