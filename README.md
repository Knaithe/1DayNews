# vuln-monitor

聚合多源 0day/1day RCE 情报，关键词过滤后推 Telegram。面向安全研究员的个人订阅器。

## 核心能力

- **增量**：CVE 号为主键的去重 cache（60 天 TTL）
- **去重**：同一 CVE 跨源（ZDI / KEV / GitHub / Sploitus）只推一次
- **准实时**：systemd timer 5 分钟触发（源本身不是实时，这是上限）
- **生产级**：文件锁防并发、原子写 cache、日志轮转（5MB×5）、失败 TG 告警（限流 1 次/小时）
- **聚焦 RCE**：白名单关键词 + 排除列表，过滤 XSS/CSRF/LPE/DoS 噪声

## 信息源

| 类型 | 源 | 说明 |
|---|---|---|
| 厂商 PSIRT | Fortinet, Palo Alto, Cisco, MSRC, VMware | 官方披露一手信息 |
| 研究团队 | watchTowr, ZDI, ProjectDiscovery, Horizon3, Rapid7, GreyNoise | 技术深度、PoC、在野扫描信号 |
| 在野基准 | **CISA KEV** (JSON, 1500+ 条) | 已被实际利用的漏洞权威列表 |
| PoC 第一现场 | GitHub `CVE-YYYY-` 仓库搜索 | PoC 发布速度最快 |
| WAF 兜底 | Sploitus (citrix / ivanti / f5) | 补厂商官方无 RSS 的空白 |

**故意未纳入的源**（别再问为啥）：
- **Citrix 官方** — 整站 Salesforce SPA，无 RSS。用 watchTowr + KEV + Sploitus 覆盖
- **F5 my.f5.com** — SPA，无 RSS。用 Sploitus 兜
- **Assetnote** — 被 Searchlight 收购后撤 RSS
- **AVD (avd.aliyun.com)** — 阿里云 WAF，纯 HTTP 抓不到。想要走 Playwright 或 NVD API

## 快速开始（本地 dry-run）

```bash
pip install -r requirements.txt

# 不设 TG token = dry run，只打日志不推送
python vuln_monitor.py

# 看输出：同目录 vuln_monitor.log
```

首次跑会拉 KEV 1500+ 条 + 各源当前全量约 400 条，DRY 模式下耗时 ~20 分钟。此后 cache 里有 1900+ 条，增量运行只需几秒。

## 本地真推 Telegram

```bash
export TG_BOT_TOKEN="123456:ABC..."   # BotFather /newbot 拿
export TG_CHAT_ID="-1001234567890"    # bot 拉进频道后 getUpdates
export  ="ghp_..."             # 可选，GitHub 限流 60→5000 req/hr

python vuln_monitor.py
```

Windows CMD 用 `set` 代替 `export`。

## 一键部署到 Linux 服务器

### 方式 A：远程一行（推荐）

```bash
curl -sSL https://raw.githubusercontent.com/Knaithe/1DayNews/master/deploy.sh | sudo bash
```

脚本会交互式问你三件事：`TG_BOT_TOKEN` / `TG_CHAT_ID` / `GH_TOKEN`（最后一个可跳过）。

### 方式 B：非交互（CI / cloud-init / ansible）

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

`deploy.sh` 做的 7 步：
1. 装系统依赖（`python3 / venv / git / curl`，自动识别 apt/dnf/yum）
2. 拉代码：已有 `.git` 则 `pull --ff-only`；本地 checkout 则 `cp`；都没有则 `git clone`
3. 建系统用户 `vuln`（nologin）
4. 写 `.env`（优先环境变量 → 交互输入 → 复用已有；`chmod 600`）
5. 建 venv、`pip install -r requirements.txt`
6. 拷 systemd unit/timer 到 `/etc/systemd/system/` + `daemon-reload`
7. **用 `env -i` 预热 cache**（强制 dry run 把 1900+ 条塞进去）→ 再 `enable --now` timer

这样设计的好处：首次真正触发 timer 时 cache 已满 → 只推增量（典型 0~10 条），不会刷屏。

### 升级

重新跑同一条命令即可。`deploy.sh` 会 `git pull` 并保留 `.env` / `vuln_cache.json` / 日志。想强制重配 `.env`：`FORCE_ENV=1 sudo bash deploy.sh`。

### 运行时观察

```bash
# 看下次触发
systemctl list-timers vuln-monitor.timer

# 看实时日志
journalctl -u vuln-monitor.service -f

# 手动跑一次
sudo systemctl start vuln-monitor.service

# 完整日志文件
tail -f /opt/vuln-monitor/vuln_monitor.log
```

## 配置调优

全在 `vuln_monitor.py` 顶部常量 + 三个关键词列表里：

| 位置 | 作用 |
|---|---|
| `RSS_FEEDS` | 源列表，加减源在这里 |
| `RCE_PATTERNS` | RCE 类正则白名单，命中才有资格推 |
| `ASSET_KEYWORDS` | 你关心的产品/厂商，~500 个，按大类分段 |
| `EXCLUDE_PATTERNS` | 黑名单，命中立即丢（XSS/CSRF/DoS/LPE 等） |
| `score()` 函数 | 组合逻辑，想更严就去掉 `RCE+exploit` 分支 |

**调优顺序建议**：先跑一周看日志里的 `[DRY]` 输出，把每条噪声归因——
- 来源不对 → 源从 `RSS_FEEDS` 移除
- 关键词太松 → `ASSET_KEYWORDS` 删掉该项
- 漏掉了想要的 → `RCE_PATTERNS` 加一条

## 文件布局

```
/opt/vuln-monitor/              # 部署后路径
├── vuln_monitor.py             # 主脚本
├── requirements.txt            # feedparser + requests
├── .env                        # 敏感变量，chmod 600，本仓库不入库
├── venv/                       # Python 虚拟环境
├── vuln_cache.json             # 运行态，CVE 去重表
├── vuln_monitor.log(.1-.5)     # 轮转日志
├── vuln_monitor.lock           # 防并发文件锁
└── vuln_alert_state.json       # 错误告警限流状态

仓库根目录额外：
├── deploy.sh                   # 一键部署
├── env.example                 # 环境变量模板
├── vuln-monitor.service        # systemd unit
├── vuln-monitor.timer          # 5 分钟触发
├── probe_feeds.py              # 探针：源失效时用它找替代
└── README.md
```

## 常见问题

**Q: 首次真推 Telegram 会不会刷屏？**  
A: 不会。`deploy.sh` 会先用 dry-run 把 1900+ 条 CVE 塞进 cache，systemd timer 才接管。之后每次触发只推新增（典型 0-10 条）。

**Q: 国内部署能用吗？**  
A: 技术上可以，但 Telegram API 直连被墙。需要：① 部署位置在海外（推荐），或 ② 设 `HTTPS_PROXY` 走代理。GitHub/MSRC/KEV 等源国内直连也偏慢，5 分钟 cron 可能有时抓不完。

**Q: 某个 RSS 源抓不到了怎么办？**  
A: 用 `python probe_feeds.py`，把失效那个源的候选 URL 填进去批量探测。找到能用的换回 `RSS_FEEDS`。

**Q: 想按严重性分频道推送？**  
A: 目前没实现。改造思路：`score()` 返回带等级的 dict，`send_telegram(chat_id, msg)` 根据等级查不同 chat_id。

**Q: KEV JSON 为什么不跟 RSS 一起走？**  
A: KEV 的 RSS endpoint 已经 404，只有 JSON 存活。格式不同（结构化字段含 `dueDate` / `knownRansomwareCampaignUse`），所以独立的 `fetch_kev_json()` 函数单独处理。

**Q: 日志会不会撑爆磁盘？**  
A: 不会。`RotatingFileHandler` 5MB 一个文件，最多保留 5 份 = 25MB 上限。首次 KEV 预热那一次会产生较大日志，之后每次几 KB。

## 许可

个人使用。源站 TOS 不允许高频爬取的（比如 `sec.cloudapps.cisco.com`），请自觉降低频率。
