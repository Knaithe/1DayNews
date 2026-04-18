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

伪代码：

```python
def score(title, summary):
    text = (title + " " + summary).lower()

    if any(p.search(text) for p in EXCLUDE_PATTERNS):
        return 0                                  # 黑名单直接丢

    rce_hit = any(p.search(text) for p in RCE_PATTERNS)
    cve_hit = CVE_RE.search(text) is not None
    asset_hit = any(kw in text for kw in ASSET_KEYWORDS)

    if rce_hit and (asset_hit or cve_hit):
        return 2    # 核心场景：RCE + 我关心的资产（或已分配 CVE）
    if rce_hit and "exploit" in text:
        return 1    # 宽放：有 RCE 关键词 + 有 exploit 字样，即使资产不在名单里
    return 0
```

- score > 0 → 进推送队列
- 当前把 score 1 和 2 一视同仁（都推）——想分级改 `send_telegram` 调用处

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
