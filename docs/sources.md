# 信息源

## 当前源清单（17 个通道）

| 类别 | 源 | 采集方式 | CVE 覆盖率 | 说明 |
|---|---|---|---|---|
| **厂商 PSIRT** | Fortinet | RSS | 0%（FG-IR 在 link 中） | FortiGuard 官方公告 |
| | PaloAlto | RSS | 55% | 安全公告 |
| | Cisco | RSS | 100% | 安全公告 |
| | MSRC | RSS | 100% | 微软安全更新 |
| **漏洞披露** | ZDI | RSS | 85% | Zero Day Initiative 公告 |
| | watchTowr | RSS | 73% | 高质量 1day 分析 + PoC |
| **漏洞披露** | DailyCVE | RSS | 42% | 每日 CVE 汇总，标题含产品+类型+严重等级 |
| **漏洞研究** | Horizon3 | RSS | 40% | 攻击面分析 |
| | Rapid7 | RSS | 35% | Metasploit 周报 + 研究 |
| **Exploit/PoC** | Sploitus (Citrix) | RSS | 20% | exploit 聚合 |
| | Sploitus (Ivanti) | RSS | 20% | exploit 聚合 |
| | Sploitus (F5) | RSS | 20% | exploit 聚合 |
| | GitHub CVE Search | REST API | 100% | 搜索 CVE-YYYY- 仓库 |
| | PoC-in-GitHub | REST API | 100% | nomi-sec 每日 PoC 汇总 |
| **在野利用** | CISA KEV | JSON | 100% | 权威在野利用列表 |
| **漏洞库** | 长亭 Chaitin | JSON API | 100% | 35 万+ 条，中文标题 |
| | 微步 ThreatBook | JSON API | ~80% | premium + highrisk 精选 |

### 采集特殊处理

| 源 | 特殊处理 |
|---|---|
| Fortinet | CVE 不在 RSS 中，通过 `ADVISORY_RE` 从 link 提取 FG-IR 编号 |
| Chaitin | SafeLine WAF 限频，独立 session + Referer 头，每周期仅 1 次 API 调用 |
| ThreatBook | 独立 session，homePage 端点返回编辑精选 |
| PoC-in-GitHub | 解析最新 commit diff，只取当年+去年 CVE 的 JSON 文件变更 |
| KEV | 按 `dateAdded` 过滤最近 60 天，不拉全量 1500+ 条 |
| 全部 | `_get_with_retry()` 3 次重试，间隔 3 秒 |

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
| A（高质量） | ZDI, MSRC, Cisco, Chaitin, ThreatBook | 50-100% |
| B（有噪声） | Sploitus×3, Horizon3, Rapid7 | 20-40% |
| B+ | DailyCVE | 42%（标题自带严重等级，覆盖面广） |
| PoC | GitHub CVE Search, PoC-in-GitHub | 100%（纯 CVE PoC，GitHub+CVE 特判不漏推） |

## 添加新源

**RSS 源**：在 `RSS_FEEDS` 列表追加 `(name, url)` 元组即可，无需改其他代码。

**自定义 API 源**：照抄 `fetch_chaitin()` 或 `fetch_threatbook()` 的模式：
1. 写 `fetch_xxx()` 函数，返回 `[{"source":..., "title":..., "link":..., "summary":..., "text":...}]`
2. 在 `_fetch_all_sources()` 中注册

## 源探针工具

```bash
python scripts/probe_feeds.py    # 批量探测候选 URL
```
