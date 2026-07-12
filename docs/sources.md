# 信息源

## 当前源清单（18 个通道）

| 类别 | 源 | 采集方式 | CVE 覆盖率 | 说明 |
|---|---|---|---|---|
| **厂商 PSIRT** | Fortinet | HTML 门户刮取 | 0%（FG-IR 在 link 中） | RSS 2026-Q2 冻结，改 scrape fortiguard.com/psirt |
| | PaloAlto | RSS | 55% | 安全公告 |
| | Cisco | RSS | 100% | 安全公告 |
| | MSRC | CVRF XML API | 100% | RSS 已废弃/冻结，改 `api.msrc.microsoft.com/cvrf` |
| **漏洞披露** | ZDI | RSS | 85% | Zero Day Initiative 公告 |
| | watchTowr | posts sitemap | 73% | RSS 冻结，改 labs.watchtowr.com/sitemap-posts.xml |
| **漏洞披露** | DailyCVE | RSS | 42% | 每日 CVE 汇总，标题含产品+类型+严重等级 |
| **漏洞研究** | Horizon3 | RSS | 40% | 攻击面分析 |
| | Rapid7 | RSS | 35% | Metasploit 周报 + 研究 |
| **Exploit/PoC** | Sploitus (Citrix) | RSS | 20% | exploit 聚合 |
| | GitHub CVE Search | REST API | 100% | 搜索 CVE-YYYY- 仓库 |
| | PoC-in-GitHub | REST API | 100% | nomi-sec 每日 PoC 汇总 |
| **GitHub 公告** | GHSA | REST API | 100% | 全局 Advisory Database（绑定包生态的 reviewed 公告） |
| | GHSA-Repo | REST API | 100% | 仓库级 Security Advisories——独立软件产品（OPNsense/nginx/OpenSSL/PHP…）的公告，补全局 GHSA 盲区 |
| **在野利用** | CISA KEV | JSON | 100% | 权威在野利用列表 |
| **漏洞库** | 长亭 Chaitin | JSON API | 100% | 35 万+ 条，中文标题 |
| | 微步 ThreatBook | JSON API | ~80% | premium + highrisk 精选 |
| **CERT** | TWCERT/CC | RSS + 详情页 | 100% | 台灣漏洞揭露平台 TVN，详情页含 CVE/CVSS/产品/漏洞类型 |

### 采集特殊处理

| 源 | 特殊处理 |
|---|---|
| Fortinet | `fetch_fortinet` 刮 PSIRT 列表；CVE 常不在条目中，`ADVISORY_RE` 从 link 提取 FG-IR 编号 |
| MSRC | `fetch_msrc` 拉当月（及必要时上月）CVRF；解析 Vulnerability 节点 |
| watchTowr | `fetch_watchtowr` 解析 posts sitemap；URL slug 常带 CVE-Id |
| Chaitin | SafeLine WAF 限频，独立 session + Referer 头，每周期仅 1 次 API 调用 |
| ThreatBook | 独立 session，homePage 端点返回编辑精选；**不在** `FRESH_SOURCES`（混入旧洞） |
| PoC-in-GitHub | 解析最新 commit diff，只取当年+去年 CVE 的 JSON 文件变更；合法空结果不标红健康点 |
| GHSA | 全局 `/advisories` 端点按 severity=critical,high + published 时间窗（30 天，7 天滑动）分页拉取 |
| GHSA-Repo | 仓库级 `repos/{repo}/security-advisories`，遍历 `REPO_ADVISORY_SOURCES`（边界设备/核心运行时），客户端过滤 critical/high；与全局 GHSA 互补 |
| KEV | 按 `dateAdded` 过滤最近 60 天，不拉全量 1500+ 条 |
| TWCERT | RSS 仅含标题/链接，需抓详情页（cp-132-*）提取 CVE/CVSS/产品/漏洞类型。多 CVE 公告按 CVE 拆分。TLS 证书 SKI 非标准，故 `verify=False`；短超时 + 连续失败熔断 |
| 全部 | `_get_with_retry()` 3 次重试，间隔 3 秒（TWCERT 等例外见代码） |

## 故意未纳入的源

### Citrix 官方

Salesforce SPA，纯 HTTP 抓不到数据。替代：watchTowr + KEV + Sploitus_Citrix。

### F5 `my.f5.com`

同 Citrix，SPA。替代：Sploitus_F5。

### AVD (avd.aliyun.com)

阿里云 WAF 拦截（JS 挑战页）。数据本质是 NVD 中文翻译，KEV + 长亭已覆盖。

### 长亭 Stack vuldb (stack.chaitin.com)

SafeLine WAF 465 排队页。已通过隐藏 JSON API（`/api/v2/vuln/list/`）绕过。

### 奇安信 TI (ti.qianxin.com)

`nday/list` 需要登录态，`vuln/list` 返回 args error。无公开 API。

### OSCS1024

所有 API 端点返回 404 或 HTML，已下线或改版。

### 绿盟 VenusTech (nsfocus.net)

HTTP 连接被拒，服务不可达。

### SentinelOne vulnerability-database

React SPA + Contentstack CMS，API 需认证（401）。

### sec.today

无 RSS/API，HTML 聚合器。内容主要来自 xlab.tencent.com（已评估，学术偏重）。

### 已审查并移除的低质量源

| 源 | 移除原因 |
|---|---|
| VMware blog | 0% CVE，纯安全营销博客 |
| ProjectDiscovery | 0% CVE，产品营销 |
| GreyNoise | 10% CVE，趋势分析为主 |
| SentinelLabs | 0% CVE，研究博客/会议回放 |
| XuanwuLab | 45% CVE 但偏学术研究 |

## 源质量分层

| 层级 | 源 | 信噪比 |
|---|---|---|
| S（必推） | CISA KEV, watchTowr, Fortinet, PaloAlto | > 80% |
| A（高质量） | ZDI, MSRC, Cisco, Chaitin, ThreatBook, GHSA, GHSA-Repo | 50-100% |
| B（有噪声） | Sploitus×3, Horizon3, Rapid7 | 20-40% |
| B+ | DailyCVE | 42%（标题自带严重等级，覆盖面广） |
| PoC（候选） | GitHub CVE Search, PoC-in-GitHub | 不直接推送，仅标注（stars<3 过滤，真实 CVE 通过 PSIRT 源推送） |

## 添加新源

**RSS 源**：在 `RSS_FEEDS` 列表追加 `(name, url)` 元组即可，无需改其他代码。

**自定义 API 源**：照抄 `fetch_chaitin()` 或 `fetch_threatbook()` 的模式：
1. 写 `fetch_xxx()` 函数，返回 `[{"source":..., "title":..., "link":..., "summary":..., "text":...}]`
2. 在 `_fetch_all_sources()` 中注册

## 源探针工具

```bash
python scripts/probe_feeds.py    # 批量探测候选 URL
```
