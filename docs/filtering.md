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
        return False, "excluded", None

    rce   = bool(_RCE_RE.search(text))
    asset = any(k in text.lower() for k in ASSET_KEYWORDS)
    cve   = bool(CVE_RE.search(text))

    if rce and asset and cve:
        return True, "RCE+asset+CVE", "RCE"
    if rce and asset:
        return True, "RCE+asset", "RCE"
    if rce and cve:
        return True, "RCE+CVE", "RCE"
    if asset and cve:
        return True, "asset+CVE", "other"
    return False, "no hit", None
```

返回三元组 `(hit, reason, vuln_type)`。`reason` 保留详细匹配信息用于分析，`vuln_type` 是简化分类（RCE / other）用于过滤和统计。

### 第二步：_is_fresh() — 1day 确认

**所有含 CVE 的记录**（不限 hit=True）都过 freshness 检查，统一记录 `cve_published` 和 `freshness`。返回三元组 `(fresh, pub_date, reason)`。

判定逻辑：
1. 所有 CVE 年份 > 1 年 → `nday`（`freshness_reason=old_cve`），无例外
2. 高信任源 → `1day`（`freshness_reason=high_trust_source`），无 CVE 也放行（如 FG-IR）
3. 低信任源 + CVE + NVD 确认发布 ≤60 天 → `1day`（`freshness_reason=nvd_60d`）
4. 低信任源 + CVE + NVD 无数据或 >60 天 → `nday`（`freshness_reason=nvd_60d`）。**不使用 CVE 年份回退**，必须有 NVD 实际发布日期确认
5. 低信任源 + 无 CVE → `nday`（`freshness_reason=no_cve_low_trust`）
6. 低信任源 + hit + 无 CVE → `nday`（显式标记，不留 freshness=None）

多 CVE 记录：只要有一个近期 CVE（NVD 确认）就不整体判 nday。高信任源可回退 CVE 年份。

**推送硬约束：** `freshness` 必须为 `1day` 才允许推送。`nday`、`NULL` 都锁 0，LLM 不可推翻。

NVD 查询两级缓存（启动时 `_warm_nvd_cache` 从 DB 预热内存）：
1. `_nvd_cache`（内存 dict，区分"查到日期" / "确认不存在" / "限频待重试"）
2. NVD API（支持 `NVD_API_KEY`，限频 5→50 次/30 秒）

### 源信任分层

| 信任级别 | 源 | 说明 |
|---|---|---|
| **高信任** | Fortinet, PaloAlto, Cisco, MSRC, CISA_KEV, ZDI, watchTowr, Horizon3, Rapid7, Chaitin, ThreatBook, DailyCVE, NVD | 发布 = 新漏洞，无 CVE 也放行 |
| **低信任** | Sploitus_Citrix, Sploitus_Ivanti, Sploitus_F5, GitHub, PoC-GitHub | 需 CVE + 60 天内发布才放行 |

### freshness 判定矩阵

| 源信任 | CVE + NVD ≤60 天 | CVE + NVD >60 天 | CVE + NVD 无数据 | 无 CVE |
|---|---|---|---|---|
| **高信任** | 1day | 1day | 1day（年份回退） | **1day** |
| **低信任** | 1day | **nday** | **nday**（不回退） | **nday** |

### 字段对照

| 字段 | 含义 | 值 |
|---|---|---|
| `reason` | 详细匹配原因 | `RCE+asset+CVE` / `RCE+asset` / `RCE+CVE` / `asset+CVE` / `excluded` / `no hit` |
| `vuln_type` | 简化分类 | `RCE` / `other` / `NULL` |
| `freshness` | 新鲜度 | `1day` / `nday` / `NULL` |
| `freshness_reason` | 判定依据 | `high_trust_source` / `nvd_60d` / `old_cve` / `no_cve_low_trust` |

### 判定场景示例

| 场景 | reason | vuln_type | freshness | freshness_reason | pushed |
|---|---|---|---|---|---|
| Fortinet 发 RCE 公告 | RCE+asset+CVE | RCE | 1day | high_trust_source | 1 |
| Cisco 认证绕过公告 | asset+CVE | other | 1day | high_trust_source | 1 |
| Fortinet FG-IR 无 CVE | RCE+asset | RCE | 1day | high_trust_source | 1 |
| Sploitus 老洞 CVE-2021-* | RCE+asset+CVE | RCE | nday | old_cve | 0 |
| Sploitus 无 CVE exploit | RCE+asset | RCE | nday | no_cve_low_trust | 0 |
| Sploitus CVE 无 NVD 数据 | RCE+CVE | RCE | nday | nvd_60d | 0 |
| GitHub PoC 仓库 | RCE+CVE | RCE | 1day | nvd_60d | 0（GitHub 源锁定） |
| XSS 漏洞公告 | excluded | NULL | NULL | — | 0 |

性能：`RCE_PATTERNS` 和 `EXCLUDE_PATTERNS` 预编译为联合正则（`_RCE_RE` / `_EXCLUDE_RE`），`ASSET_KEYWORDS` 转 `frozenset`。

## rescore — 重新评估历史记录

改了评分规则后，库里的老记录不会自动重新评分（去重逻辑跳过已有 key）。用 `rescore` 一次性重跑：

```bash
python src/vuln_monitor.py rescore
# rescored 2083 records: 42 upgraded, 15 downgraded, 8 reason-changed, 2018 unchanged
```

| 输出 | 含义 |
|---|---|
| upgraded | 之前 no hit / nday → 现在变成 1day |
| downgraded | 之前推了 → 现在变成 nday |
| reason-changed | pushed 状态没变但 reason 文字更新了 |
| unchanged | 完全一样，无需更新 |

**注意**：rescore 只更新 reason/vuln_type/freshness/pushed 字段，不重新 fetch 数据，也不补发 Telegram 推送。GitHub/PoC-GitHub 源即使 rescore 后 hit=True 也不推送。

## LLM 研判（enrich）

正则粗筛之后，`enrich` 子命令用 LLM（DeepSeek/GPT）做二次核验。

### 流水线

```
fetch --no-push → 入库（pushed 由正则初判）
    ↓
enrich:
    1. NVD 补 severity/cvss（_backfill_nvd_severity，每轮 20 条）
    2. 自动 approve：高信任源 + CVSS ≥ 9.0 → confirmed（受 freshness/source 约束）
    3. LLM agent loop：发漏洞信息 → LLM 自主决定调工具 → 返回 verdict
    4. _resolve_pushed()：freshness=nday → 锁 0，GitHub 源 → 锁 0，其他由 LLM 决定
    5. 推送 pushed=1 AND tg_sent=0 → Telegram
```

### LLM 可调用的工具

| 工具 | 功能 | LLM 自主决定是否调用 |
|---|---|---|
| `fetch_nvd_detail(cve_id)` | NVD 完整信息（CVSS/描述/发布日期） | 需要确认严重等级 |
| `fetch_source_page(url)` | 抓源页面正文（截断 2000 字符） | 需要看公告原文 |
| `search_github(cve_id)` | 搜 GitHub PoC 仓库（stars/描述） | 确认是否有真实 exploit |
| `search_chaitin(keyword)` | 搜长亭漏洞库 | 需要中文漏洞信息 |

最多 5 轮工具调用，防止失控。

### LLM verdict

| verdict | 含义 | pushed 影响 |
|---|---|---|
| `confirmed` | 真实漏洞，值得关注 | 维持（受 freshness/source 约束） |
| `not_relevant` | 真实但低影响（需认证/冷门产品） | 降级为 0 |
| `noise` | 伪造/垃圾/非漏洞 | 降级为 0 |

LLM 只能降级（confirmed→not_relevant/noise），不能推翻 freshness=nday 或 GitHub 源锁定。

高信任源且已有 CVSS 数据时跳过工具调用，单次 API 直接判定。工具调用轮次用尽时强制出结论。

### 技术实现

- SDK：`openai` Python 包（兼容 DeepSeek/OpenAI/任意兼容端点）
- 客户端：`OpenAI(api_key=..., base_url=...)`
- 成本控制：CVE 去重（同 CVE 多源只审一次）+ 自动 approve + 500 条/轮上限
- 回退：LLM 连续 3 次错误 → 走正则结果推送（仅 freshness=1day 且非 GitHub 源）

### 配置

```bash
# .env 加一行（二选一）
DEEPSEEK_API_KEY=sk-xxx          # 默认模型 deepseek-chat
OPENAI_API_KEY=sk-xxx            # 默认模型 gpt-4o-mini
# 可选覆盖
LLM_MODEL=deepseek-reasoner
LLM_BASE_URL=http://localhost:11434/v1   # 本地 Ollama 等
```

不配 LLM key 时 enrich 跳过 LLM，直接推正则结果。

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
