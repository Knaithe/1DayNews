# 过滤逻辑

全部过滤逻辑集中在 `src/vuln_monitor.py` 的四个常量 + 一个 `score()` 函数。改这里就能改整套过滤行为。

## 三层清单

### `RCE_PATTERNS` — RCE 类正则白名单

- 命中才有资格进入下一步评分
- 正则匹配标题 + 摘要（大小写不敏感）
- 覆盖：`remote code execution`、`command injection`、`deserializ`、`RCE`、`unauthenticated`、`pre-auth`、"任意代码"、"命令执行"等
- **这是第一道门**：不命中直接丢

### `ASSET_KEYWORDS` — 资产/厂商/产品白名单（约 500 项）

- 命中代表"这条涉及我关心的东西"
- 分段组织（方便取舍）：
  - 边界/网络设备：Fortinet、Palo Alto、Cisco、Juniper、F5、Citrix、Ivanti、SonicWall、WatchGuard
  - 微软生态：Exchange、Windows、AD、Kerberos、SMB、RDP、Outlook、Office、MSSQL、WSUS、SharePoint、IIS
  - 数据库：MySQL、PostgreSQL、Redis、MongoDB、Elasticsearch、Oracle、MariaDB、ClickHouse
  - 虚拟化：VMware、ESXi、vCenter、Hyper-V、KVM、QEMU、Proxmox、XenServer
  - CI/CD：Jenkins、GitLab、Gitea、Bamboo、TeamCity、ArgoCD、Harbor、Nexus
  - 框架：Log4j、Spring、Struts、Laravel、Django、FastAPI、Rails、Express
  - CMS：WordPress、Drupal、Joomla、帝国 CMS、DedeCMS
  - 邮件：Postfix、Exim、Zimbra、Sendmail、Roundcube
  - 备份/存储：Veeam、Rubrik、NetApp、Synology、QNAP、TrueNAS
  - 监控：Zabbix、Grafana、Prometheus、Nagios、Cacti
  - 安全产品：Splunk、QRadar、ArcSight、CrowdStrike、SentinelOne
  - PKI/身份：Okta、Keycloak、CAS、SAML、LDAP
  - 媒体/解析：ffmpeg、ImageMagick、GhostScript、libpng
  - 浏览器：Chrome、Chromium、Firefox、WebKit
  - BMC/固件：iDRAC、iLO、Supermicro IPMI、BMC
  - 中国厂商：用友、金蝶、泛微、宝塔、蓝凌、致远、亿赛通、深信服
  - 云平台：AWS、Azure、GCP、阿里云、腾讯云
- 也识别 CVE 号格式（`CVE-\d{4}-\d{4,7}`），有 CVE 号视同命中

### `EXCLUDE_PATTERNS` — 黑名单

- 命中**立即丢**（优先级高于白名单）
- 用来压住常见噪声：
  - `\bXSS\b`、`cross.?site`、`\bCSRF\b` — Web 客户端漏洞
  - `\bDoS\b`、`denial of service` — 拒绝服务
  - `\bLPE\b`、`local privilege` — 本地提权（不是远程）
  - `information disclosure`、`sensitive data` — 信息泄露
  - `SSRF`（单独）、`open redirect`、`clickjacking`
  - `chromium`、`chrome release` — MSRC 的 Edge/Chromium 镜像公告
- 调黑名单前先看一周日志里的 `[FILTER]` / `[DRY]` 输出，归因到底是哪条正则没挡住

## 三档分类

> **1day = 漏洞本体新近公开且处于可利用窗口期，值得立刻关注和防御的新鲜攻击面。**

所有条目按两步判定分入三档：

| 档位 | 推送 Telegram | brief 显示 | 含义 |
|---|---|---|---|
| **1day** | 推 | 显示 | 新鲜漏洞，值得立刻关注 |
| **nday** | 不推 | 不显示 | 已知漏洞/老洞，仅入库 |
| **noise** | 不推 | 不显示 | 噪声，不匹配任何规则 |

### 第一步：score() — 高危判定

```python
def score(text):
    if _EXCLUDE_RE.search(text):
        return False, "excluded"              # → noise

    rce   = bool(_RCE_RE.search(text))
    asset = any(k in text.lower() for k in ASSET_KEYWORDS)
    cve   = bool(CVE_RE.search(text))

    # ── 1day 候选 ──
    if rce and (asset or cve):
        return True, "RCE+asset/CVE"          # → 1day 候选
    if asset and cve:
        return True, "asset+CVE"              # → 1day 候选

    # ── 直接 nday ──
    if rce and "exploit" in text.lower():
        return False, "nday:RCE+exploit"      # 有 exploit = 不是新鲜窗口期

    return False, "no hit"                    # → noise
```

`_run()` 中还有一条特判：**GitHub 源**（仅 GitHub 搜索，不含 PoC-GitHub）如果有 CVE 但 score 未命中 → `GitHub+CVE`（1day 候选）。PoC-GitHub 不走此特判，必须命中 score() 才推。

### 第二步：_is_fresh() — 1day 确认

score() 命中的 1day 候选还要过 freshness 检查：

```python
def _is_fresh(source, text):
    if source in FRESH_SOURCES:
        return True            # 高信任源发布 = 漏洞本体新
    # 低信任源：检查 CVE 年份
    cves = CVE_RE.findall(text)
    if not cves:
        return True            # 无 CVE，无法判定，放行
    return any(cve_year >= current_year - 1 for cve in cves)
```

不通过 → reason 加 `nday:` 前缀，降级到 nday 档。

### 源信任分层

| 信任级别 | 源 | freshness 判定 |
|---|---|---|
| **高信任** | Fortinet, PaloAlto, Cisco, MSRC, CISA_KEV, ZDI, watchTowr, Horizon3, Rapid7, Chaitin, ThreatBook, DailyCVE | 发布 = 新漏洞，无需额外验证 |
| **低信任** | Sploitus_*, GitHub, PoC-GitHub | 检查 CVE 年份 ≥ 当前年份-1 |

### reason 完整对照

| reason | 档位 | 推送 | 判定路径 |
|---|---|---|---|
| `RCE+asset/CVE` | 1day | 推 | RCE 关键词 + 资产或 CVE + freshness 通过 |
| `asset+CVE` | 1day | 推 | 资产关键词 + CVE + freshness 通过 |
| `GitHub+CVE` | 1day | 推 | GitHub 搜索源 + 有 CVE（特判） + freshness 通过 |
| `nday:RCE+exploit` | nday | 不推 | 有 RCE + exploit 字样（score 直接判 nday） |
| `nday:RCE+asset/CVE` | nday | 不推 | 高危但 CVE 太老（低信任源 freshness 不通过） |
| `nday:asset+CVE` | nday | 不推 | 同上 |
| `nday:GitHub+CVE` | nday | 不推 | 同上 |
| `excluded` | noise | 不推 | 命中排除规则（XSS/CSRF/DoS 等） |
| `no hit` | noise | 不推 | 未命中任何规则 |

### 判定场景示例

| 场景 | score | fresh | 最终 | reason |
|---|---|---|---|---|
| Fortinet 发 RCE 公告 | 命中 | 通过（高信任） | **1day** | `RCE+asset/CVE` |
| CISA KEV 新增条目 | 命中 | 通过（高信任） | **1day** | `RCE+asset/CVE` |
| GitHub 搜到 CVE-2026-* 仓库 | 特判 | 通过（近期 CVE） | **1day** | `GitHub+CVE` |
| Sploitus 收录老洞 CVE-2021-* | 命中 | 不通过（老 CVE） | **nday** | `nday:RCE+asset/CVE` |
| Sploitus 标题含 exploit | RCE+exploit | — | **nday** | `nday:RCE+exploit` |
| PoC-GitHub 新仓库无 RCE 关键词 | 未命中 | — | **noise** | `no hit` |
| XSS 漏洞公告 | excluded | — | **noise** | `excluded` |

性能：`RCE_PATTERNS` 和 `EXCLUDE_PATTERNS` 预编译为联合正则（`_RCE_RE` / `_EXCLUDE_RE`），`ASSET_KEYWORDS` 转 `frozenset`。

## rescore — 重新评估历史记录

改了评分规则后，库里的老记录不会自动重新评分（去重逻辑跳过已有 key）。用 `rescore` 一次性重跑：

```bash
python src/vuln_monitor.py rescore
# rescored 2083 records: 42 upgraded, 15 downgraded, 8 reason-changed, 2018 unchanged
```

| 输出 | 含义 |
|---|---|
| upgraded | 之前 no hit / nday → 现在变成 1day（如新增了 GitHub+CVE 特判） |
| downgraded | 之前推了 → 现在变成 nday（如 RCE+exploit 降级） |
| reason-changed | pushed 状态没变但 reason 文字更新了 |
| unchanged | 完全一样，无需更新 |

**注意**：rescore 只更新 reason 和 pushed 字段，不重新 fetch 数据，也不补发 Telegram 推送。

## 调优方法

**跑一周 DRY，再看日志**。不要凭空猜黑白名单。

归因四种情况：

| 症状 | 原因 | 修复 | 改后操作 |
|---|---|---|---|
| 推了不想要的（某源太水） | 源质量差 | `RSS_FEEDS` 移除该源 | — |
| 推了不想要的（关键词太宽） | `ASSET_KEYWORDS` 引入噪声 | 从 `ASSET_KEYWORDS` 删掉 | `rescore` |
| 漏了想要的（应推未推） | `RCE_PATTERNS` 不含该表达 | 在 `RCE_PATTERNS` 加正则 | `rescore` |
| 误杀（`excluded` 但你想看） | 黑名单太严 | 收窄 `EXCLUDE_PATTERNS` 正则 | `rescore` |

## 已知 false-positive 模式

运行中观察到的、未来可加入 `EXCLUDE_PATTERNS` 的候选：

- MSRC 的 Edge 浏览器 Chromium 基线公告（每月数条，无新漏洞信息）
- Horizon3 / Rapid7 的产品 marketing 博客（标题含 "NodeZero"、"InsightVM"）

默认没全塞进去是因为偶尔会误杀真漏洞博客。自己运行一段看日志再决定。
