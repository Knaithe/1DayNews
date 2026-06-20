# Vulnpilot API

vuln-monitor 为 vulnpilot dispatcher 提供的接口，用于拉取待分析漏洞和标记已领取。

## 鉴权

所有接口共用 web dashboard 的 token（`.web_token` 文件），支持三种方式：

```
# 1. Authorization header（推荐）
Authorization: Bearer <token>

# 2. Query parameter
GET /api/pending?token=<token>

# 3. Cookie（浏览器访问 dashboard 后自动设置）
Cookie: _vmt=<token>
```

## GET /api/pending

返回已推送（pushed=1）且未被领取（dispatched=0）的漏洞，按 CVSS 降序排列。

**参数：**

| 参数 | 类型 | 必选 | 说明 |
|---|---|---|---|
| since | string | 否 | ISO 8601 时间，只返回此时间之后的记录 |
| limit | int | 否 | 最大返回数量，默认 50，范围 1-200 |

**请求示例：**

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  "http://100.x.x.x:8001/api/pending?limit=10"
```

**响应：**

```json
{
  "vulns": [
    {
      "cve_id": "CVE-2026-53519",
      "title": "Nezha Monitoring Unauthenticated File Read",
      "source": "Sploitus_Citrix",
      "link": "https://github.com/advisories/GHSA-xxx",
      "summary": "Unauthenticated arbitrary file read via path traversal...",
      "vuln_type": "bypass",
      "cvss": 9.1,
      "severity": "critical",
      "reason": "bypass+CVE",
      "created_at": "2026-06-19T12:00:00+00:00"
    }
  ],
  "count": 1
}
```

**说明：**
- 只返回通过评分筛选并推送到 TG 的漏洞
- 已被 `/api/ack` 标记的不再返回
- DB 没有 `dispatched` 字段时（未 migration）返回空列表

## POST /api/ack

标记漏洞已被 dispatcher 领取，后续 `/api/pending` 不再返回。

**请求：**

```bash
curl -X POST \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"cve_ids": ["CVE-2026-53519", "CVE-2026-54806"]}' \
  "http://100.x.x.x:8001/api/ack"
```

**响应：**

```json
{"acked": 2}
```

**错误：**

| 状态码 | 原因 |
|---|---|
| 400 | 缺少 `cve_ids`、空列表、或类型不是数组 |
| 403 | token 无效 |
| 500 | DB 没有 `dispatched` 字段（需要先跑一次 `vuln_monitor.py` 做 migration） |

## 典型调用流程

```
dispatcher                         vuln-monitor
    │                                    │
    ├── GET /api/pending ───────────────→│
    │←── [{cve_id, title, link, ...}] ──│
    │                                    │
    ├── (Claude Code 分析)                │
    │                                    │
    ├── POST /api/ack ─────────────────→│
    │   {"cve_ids": ["CVE-2026-53519"]}  │
    │←── {"acked": 1} ─────────────────│
    │                                    │
    ├── (SCP 到 C + TG 通知 Hermes)      │
```
