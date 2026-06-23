# Vulnpilot API

vuln-monitor 为 vulnpilot dispatcher 提供的只读接口，用于拉取待分析漏洞。去重由 B 侧自行管理。

## 鉴权

共用 web dashboard 的 token（`.web_token` 文件），支持三种方式：

```
# 1. Authorization header（推荐）
Authorization: Bearer <token>

# 2. Query parameter
GET /api/pending?token=<token>

# 3. Cookie（浏览器访问 dashboard 后自动设置）
Cookie: _vmt=<token>
```

## GET /api/pending

返回最近 7 天内已推送（pushed=1）的漏洞，按时间降序排列。

**参数：** 无（固定返回最近 7 天全部符合条件的记录，上限 1000）

**请求示例：**

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  "http://100.x.x.x:8001/api/pending"
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
- 固定 7 天窗口，无外部可控参数
- 只返回通过评分筛选并推送到 TG 的漏洞
- B 侧应自行维护已处理 CVE 的去重（如 `INSERT OR IGNORE`）

**错误：**

| 状态码 | 原因 |
|---|---|
| 403 | token 无效 |

## 典型调用流程

```
dispatcher                         vuln-monitor
    │                                    │
    ├── GET /api/pending ───────────────→│
    │←── [{cve_id, title, link, ...}] ──│
    │                                    │
    ├── (B 侧去重 + Claude Code 分析)    │
    │                                    │
    ├── (SCP 到 C + TG 通知 Hermes)      │
```
