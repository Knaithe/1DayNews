# vuln-monitor

聚合多源 0day/1day RCE 情报，关键词过滤后推 Telegram。面向安全研究员的个人订阅器。

## 它是什么

把分散在 20+ 个信息源（厂商 PSIRT、研究团队博客、CISA KEV、GitHub PoC、Sploitus）的漏洞信息，用一套 RCE 聚焦的关键词规则筛一遍，去重后推到你的 Telegram 频道。

- **增量**：CVE 号为主键的去重 cache（60 天 TTL），同一 CVE 跨源只推一次
- **准实时**：systemd timer 5 分钟一触发（源刷新频率本身是上限）
- **生产级**：文件锁防并发、原子写 cache、日志轮转、失败告警限流
- **聚焦 RCE**：白名单正则 + 500 项资产关键词 + 黑名单，过滤 XSS/CSRF/LPE/DoS 噪声

想看细节：

| 主题 | 文档 |
|---|---|
| 目录布局、数据流、DATA_DIR、预热机制 | [`docs/architecture.md`](docs/architecture.md) |
| 源清单、故意未纳入的源、探针工具 | [`docs/sources.md`](docs/sources.md) |
| `RCE_PATTERNS` / `ASSET_KEYWORDS` / `EXCLUDE_PATTERNS` / `score()` | [`docs/filtering.md`](docs/filtering.md) |
| 文件锁、systemd 沙盒、日志、故障定位 | [`docs/operations.md`](docs/operations.md) |

## 快速开始（本地 dry-run）

```bash
git clone https://github.com/Knaithe/1DayNews.git
cd 1DayNews
pip install -r requirements.txt

# 不设 TG token = dry run，只打日志不推送
python src/vuln_monitor.py

# 输出：仓库根目录 vuln_monitor.log
```

首次跑会拉 KEV 1500+ 条 + 各源约 400 条，~20 分钟。之后 cache 里有 1900+ 条，增量运行只需几秒。

## 本地真推 Telegram

一次性配置，后续无需再导 env：

```bash
python scripts/configure.py
```

会交互式问 `TG_BOT_TOKEN` / `TG_CHAT_ID` / `GH_TOKEN` / `HTTPS_PROXY`，写到：

- Linux / macOS：`~/.config/vuln-monitor/config.json`（`chmod 600`）
- Windows：`%APPDATA%\vuln-monitor\config.json`
- 遵循 `$XDG_CONFIG_HOME` 覆盖

之后直接跑：

```bash
python src/vuln_monitor.py
```

**优先级**：环境变量 > 配置文件 > 空（dry mode）。所以临时覆盖 / CI / 调试时随时 `TG_CHAT_ID=-100xxx python src/vuln_monitor.py` 即可。

其他命令：

```bash
python scripts/configure.py --show   # 查看当前配置（token 打码）
python scripts/configure.py --path   # 只打印配置文件路径
```

## 一键部署到 Linux 服务器

### 方式 A：远程一行（推荐）

```bash
curl -sSL https://raw.githubusercontent.com/Knaithe/1DayNews/master/deploy.sh | sudo bash
```

TTY 下会交互问你 `TG_BOT_TOKEN` / `TG_CHAT_ID` / `GH_TOKEN`（最后一个可跳过）。

### 方式 B：非交互（CI / cloud-init）

```bash
curl -sSL https://raw.githubusercontent.com/Knaithe/1DayNews/master/deploy.sh | \
  sudo TG_BOT_TOKEN="123456:ABC..." \
       TG_CHAT_ID="-1001234567890" \
       GH_TOKEN="ghp_..." \
       bash
```

### 方式 C：从本地 checkout

```bash
git clone https://github.com/Knaithe/1DayNews.git
cd 1DayNews
sudo bash deploy.sh
```

### 升级

重跑同一条命令即可。`deploy.sh` 会 `git pull` 并保留 `.env` / `vuln_cache.json` / 日志。想强制重配 `.env`：`FORCE_ENV=1 sudo bash deploy.sh`。

部署细节（7 步脚本做了什么、沙盒配置、为什么能一次装好不刷屏）见 [`docs/architecture.md`](docs/architecture.md) 和 [`docs/operations.md`](docs/operations.md)。

## 运行时观察

```bash
systemctl list-timers vuln-monitor.timer   # 下次触发
journalctl -u vuln-monitor.service -f      # 实时日志
sudo systemctl start vuln-monitor.service  # 手动跑一次
tail -f /opt/vuln-monitor/vuln_monitor.log # 文件日志
```

## FAQ

**Q: 首次真推 Telegram 会不会刷屏？**
不会。`deploy.sh` 用 `env -i` 强制 dry-run 把 1900+ 条塞进 cache，之后 timer 只推增量（典型 0-10 条）。

**Q: 国内部署能用吗？**
Telegram API 直连被墙。需要 ① 部署在海外（推荐），或 ② 设 `HTTPS_PROXY`。GitHub/MSRC/KEV 国内直连也慢。

**Q: 某个 RSS 源抓不到了？**
跑 `python scripts/probe_feeds.py` 批量探测候选 URL，找到能用的换回 `src/vuln_monitor.py` 里的 `RSS_FEEDS`。

**Q: 为什么没收录 Citrix / F5 / AVD？**
见 [`docs/sources.md`](docs/sources.md) 的"故意未纳入的源"一节。

**Q: 想按严重性分频道？**
`score()` 返回带等级 dict，`send_telegram(chat_id, msg)` 按等级查不同 chat_id。见 [`docs/architecture.md`](docs/architecture.md) 最后一节"下一步演进"。

## 许可

个人使用。源站 TOS 不允许高频爬取的（比如 `sec.cloudapps.cisco.com`），请自觉降低频率。
