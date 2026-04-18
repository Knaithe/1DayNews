# 信息源

## 源分类与采集方式

| 类型 | 源 | 采集 | 作用 |
|---|---|---|---|
| 厂商 PSIRT | Fortinet / Palo Alto / Cisco / MSRC / VMware | RSS | 官方一手披露 |
| 研究团队 | watchTowr / ZDI / ProjectDiscovery / Horizon3 / Rapid7 / GreyNoise | RSS | 技术深度、PoC、在野信号 |
| 在野基准 | **CISA KEV** | JSON | 已被实际利用的权威列表（1500+ 条） |
| PoC 第一现场 | GitHub `CVE-YYYY-` 仓库搜索 | REST API | PoC 发布速度最快 |
| WAF 兜底 | Sploitus (citrix / ivanti / f5) | RSS | 补厂商无 RSS 的空白 |

## 具体 URL（已验证可用）

见 `src/vuln_monitor.py` 中 `RSS_FEEDS` 常量与 `KEV_JSON_URL`。

## 故意未纳入的源

### Citrix 官方

- 现状：`www.citrix.com/en-us/support/security-bulletins` 整站是 Salesforce Experience Cloud 的 SPA，初次请求返回 JS 壳，数据走 XHR
- 用纯 HTTP 抓到的永远是 "You need JavaScript" 提示
- 替代：watchTowr（Citrix 漏洞常客）+ CISA KEV（NetScaler 是 KEV 大户）+ Sploitus\_Citrix（keyword RSS）
- 如果非要抓官方：需要 Playwright，算 overhead 大于收益

### F5 `my.f5.com`

- 同 Citrix：SPA，Salesforce 基建
- 替代：Sploitus\_F5（keyword RSS）
- 历史上有个 `support.f5.com/rss/security.xml`，2024 年后 404

### Assetnote Research

- 2024-2025 年间被 Searchlight Cyber 收购，RSS endpoint 撤了
- 他们的研究现在散发在 `www.searchlight-cyber.com/blog` 里混合不相关内容
- 暂时放弃，考虑未来如果能找到干净的 RSS 再加回

### AVD (avd.aliyun.com)

- 阿里云 WAF 拦截：响应头带 `_waf_bd8ce2ce37` JS 挑战
- 用纯 `requests` 抓回来是 HTML 错误页，不是数据
- 替代方案（未实现）：
  1. 切换到 NVD 2.0 API（同样权威，非中国源）
  2. 用 Playwright 走浏览器自动化
  3. 反向走阿里云 NVD 镜像的别名域名（如有）

## 源探针工具

源失效（404 / 503 / 跳转到登录 / DNS 换）时不要在主脚本里试错——用 `scripts/probe_feeds.py`：

```bash
python scripts/probe_feeds.py
```

它会对每个 vendor 尝试多个候选 URL 并打印：

- HTTP 状态码
- Content-Type
- feedparser 能解析的 entries 数量
- feed 标题、第一条标题

找到能用的 URL 替换回 `RSS_FEEDS`，`git pull` 部署即可。

## 源质量分层（个人观察）

| 层级 | 源 | 说明 |
|---|---|---|
| S（必推） | CISA KEV / watchTowr / Fortinet PSIRT / Palo Alto PSIRT | 信噪比 > 80%，在野基准或一手 |
| A（常推） | ZDI / MSRC / ProjectDiscovery / Horizon3 / Cisco | 信噪比 50-80% |
| B（兜底） | Sploitus\_* / Rapid7 / VMware blog | 有用但噪声多，靠 `score()` + `EXCLUDE_PATTERNS` 压住 |
| C（待观察） | GreyNoise | 偶尔有超高价值的在野告警，但很多是 trend 博客（无 CVE） |
| 未纳入 | Citrix / F5 / Assetnote / AVD | 见上方"故意未纳入"说明 |

想加新源：在 `RSS_FEEDS` 追加 `(name, url)` 元组，`score()` 无需改动。想加新**采集方式**（例如 NVD JSON API）：照抄 `fetch_kev_json()` 的模式写一个 `fetch_xxx()`，在 `_run()` 里调用并合并到 `items` 列表。
