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

优先级：环境变量 > 配置文件 > 空（dry mode）。

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
