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

## `score()` 判定

返回 `(hit: bool, reason: str)`，`hit=True` 进推送队列。

```python
def score(text):
    if _EXCLUDE_RE.search(text):
        return False, "excluded"         # 黑名单直接丢

    rce   = bool(_RCE_RE.search(text))
    asset = any(k in text.lower() for k in ASSET_KEYWORDS)
    cve   = bool(CVE_RE.search(text))

    if rce and (asset or cve):
        return True, "RCE+asset/CVE"     # RCE + 关心的资产或有 CVE
    if asset and cve:
        return True, "asset+CVE"         # 非 RCE 但涉及重要资产的 CVE
    if rce and "exploit" in text.lower():
        return True, "RCE+exploit"       # RCE + exploit 字样
    return False, "no hit"
```

`_run()` 中还有一条特判：GitHub/PoC-GitHub 源如果有 CVE 但 score 未命中，标为 `"GitHub+CVE"` 仍推送（因为 PoC 仓库描述常为空）。

### reason 汇总

| reason | 推送 | 含义 |
|---|---|---|
| `RCE+asset/CVE` | 是 | RCE + 资产关键词或 CVE |
| `asset+CVE` | 是 | 重要资产 + CVE（非 RCE） |
| `RCE+exploit` | 是 | RCE + exploit 字样 |
| `GitHub+CVE` | 是 | GitHub PoC 仓库 + CVE（特判） |
| `excluded` | 否 | 命中黑名单 |
| `no hit` | 否 | 未命中任何规则 |

性能：`RCE_PATTERNS` 和 `EXCLUDE_PATTERNS` 预编译为联合正则（`_RCE_RE` / `_EXCLUDE_RE`），`ASSET_KEYWORDS` 转 `frozenset`。

## 1day 判定（Freshness）

> **1day = 漏洞本体新近公开且处于可利用窗口期，值得立刻关注和防御的新鲜攻击面。**

不是"任意新内容"。老洞新 PoC、老洞被聚合站重新收录、老洞今天又有人写了 exploit 文章 — 都不算 1day。

推送的最终条件是 **exploitability（高危）+ freshness（1day）** 两个维度同时通过。

### Freshness 判定逻辑

```python
def _is_fresh(source, text):
    if source in FRESH_SOURCES:
        return True            # 这些源发布即代表漏洞本体是新的
    # 低信任源：检查 CVE 年份
    cves = CVE_RE.findall(text)
    if not cves:
        return True            # 无 CVE，无法判定，放行
    return any(cve_year >= current_year - 1 for cve in cves)
```

### 源信任分层

| 信任级别 | 源 | freshness 判定 |
|---|---|---|
| **高信任** | Fortinet, PaloAlto, Cisco, MSRC, CISA_KEV, ZDI, watchTowr, Horizon3, Rapid7, Chaitin, ThreatBook, DailyCVE | 发布 = 新漏洞，无需额外验证 |
| **低信任** | Sploitus_*, GitHub, PoC-GitHub | 检查 CVE 年份 ≥ 当前年份-1 |

### 判定结果

| 场景 | exploitability | freshness | 推送？ | reason |
|---|---|---|---|---|
| Fortinet RCE 公告 | 通过 | 通过（高信任源） | 推 | `RCE+asset/CVE` |
| CISA KEV 老 CVE 新入列 | 通过 | 通过（高信任源） | 推 | `RCE+asset/CVE` |
| Sploitus CVE-2026-* exploit | 通过 | 通过（近期 CVE） | 推 | `RCE+exploit` |
| Sploitus CVE-2021-* exploit | 通过 | **不通过**（老 CVE） | 不推 | `nday:RCE+exploit` |
| GitHub CVE-2026-* PoC 仓库 | 通过 | 通过（近期 CVE） | 推 | `GitHub+CVE` |
| GitHub CVE-2019-* PoC 仓库 | 通过 | **不通过**（老 CVE） | 不推 | `nday:GitHub+CVE` |

nday 条目仍入库（`pushed=0`，reason 带 `nday:` 前缀），`query` 可查但 `brief` 和 Telegram 不推。

## 调优方法

**跑一周 DRY，再看日志**。不要凭空猜黑白名单。

DRY 模式输出形如：

```
2026-04-18 03:21 [INFO] [DRY] score=2 PaloAlto | CVE-2025-XXXX: Pre-auth RCE in ...
2026-04-18 03:21 [INFO] [FILTER] score=0 MSRC | Chromium release XX.X.X...    ← 黑名单命中
2026-04-18 03:21 [INFO] [SKIP] no-RCE ZDI | Authentication bypass in ...       ← RCE 门没过
```

归因四种情况：

| 日志表现 | 原因 | 修复 |
|---|---|---|
| 推了不想要的（`score=2` 但你觉得没价值） | 某个源太水 | `RSS_FEEDS` 移除该源 |
| 推了不想要的（某关键词太宽） | `ASSET_KEYWORDS` 某项引入噪声 | 从 `ASSET_KEYWORDS` 删掉 |
| 漏了想要的（`score=0` 但你想看） | `RCE_PATTERNS` 不含该表达 | 在 `RCE_PATTERNS` 加正则 |
| 稳定漏某类（`EXCLUDE_PATTERNS` 误杀） | 黑名单太严 | 收窄该黑名单正则 |

## 已知 false-positive 模式

运行中观察到的、未来可加入 `EXCLUDE_PATTERNS` 的候选：

- MSRC 的 Edge 浏览器 Chromium 基线公告（每月数条，无新漏洞信息）
- Horizon3 / Rapid7 的产品 marketing 博客（标题含 "NodeZero"、"InsightVM"）
- VMware 博客转发的合作伙伴公告（标题含 "partner"、"customer success"）

默认没全塞进去是因为偶尔会误杀真漏洞博客。自己运行一段看日志再决定。
