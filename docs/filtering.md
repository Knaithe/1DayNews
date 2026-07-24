# 过滤逻辑

全部评分/分类纯逻辑在 `src/scoring.py`；新鲜度、CVSS 门禁与推送决议在 `src/vuln_monitor.py`。

改过滤行为：优先改 `scoring.py` 的模式常量 + `score()` / `asset_hit()`；改 1day 定义改 `_is_fresh()`；改推送硬约束改 `_resolve_pushed()` / `_regex_push_candidate()`；改 LLM 复核准入（含高分兜底）改 `enrich.py` 的 `_ENRICHABLE_WHERE`。

## 三层清单（`scoring.py`）

### `RCE_PATTERNS` — RCE 类正则

- 命中才有机会进入 RCE 类 `vuln_type`
- 匹配标题 + 摘要（大小写不敏感）
- 覆盖：remote code execution、command injection、deserializ*、RCE、任意代码/命令执行、webshell、memory corruption 等
- **注意**：`unauthenticated` / `pre-auth` **不在** RCE 清单里（避免把 unauth 提权/SQLi 标成 RCE）

### `BYPASS_PATTERNS` — 认证/授权绕过

- 独立 `vuln_type=bypass` 路径（与 RCE 并列可推送）
- 覆盖：auth bypass、account takeover、JWT/token 泄露、认证绕过 等

### `ASSET_KEYWORDS` — 资产/厂商/产品白名单（约 500 项）

- 命中代表「这条涉及我关心的东西」
- **匹配规则**（`asset_hit()`）：
  - **ASCII 且长度 ≤ 3**（如 `ise` / `nsa` / `tar` / `pip` / `adc`）：用字母数字词边界，避免 `enterprise` 命中 `ise`、`transaction` 命中 `nsa`、`CVSS` 命中 `cvs`
  - **更长关键词与 CJK**：仍用子串匹配（如 `palo alto`、`fortigate`、`用友`）

### `EXCLUDE_PATTERNS` — 黑名单

- 命中 → `excluded`（**除非**正文同时有强 RCE 信号 `_STRONG_RCE_RE`，用于 XSS→RCE 链等）
- 噪声：XSS / CSRF / 普通 DoS / LPE / 信息泄露 / 单独 SSRF / 浏览器补丁等

### `_WP_PLUGIN_RE` — WordPress 生态硬排除

WP 插件/主题漏洞量极大、多为小装机量插件，对基础设施/边界设备监控是噪声。三层检测：

1. **链接**：patchstack / wordfence / wpscan 漏洞库 URL（`score()` 同时检查 `text` + `link`）
2. **文本**：`WordPress` / `WooCommerce` / `Elementor` 字样
3. **NVD/GitHub references**：Patchstack 系插件洞的描述从不提 "WordPress"（如 CVE-2026-59544 "Unauthenticated PHP Object Injection in Thrive Quiz Builder"），只有 reference URL 暴露生态。`_nvd_detail()` 提取 references 入缓存后，由 `_backfill_nvd_severity`（回填时命中 → `reason='excluded', pushed=0`）与 `_nvd_refs_wp_excluded()`（`_run` 入库 / `rescore` 复查）拦截，零额外 HTTP

不受 `_STRONG_RCE_RE` 豁免影响。

## `score(text)` — 可利用性（实现真相）

```python
def score(text):
    if not _STRONG_RCE_RE.search(text) and _EXCLUDE_RE.search(text):
        return False, "excluded", None

    rce   = RCE_PATTERNS 命中
    asset = asset_hit(text.lower())
    cve   = CVE_RE 命中
    bypass = BYPASS_PATTERNS 命中

    if rce and asset and cve:  return True, "RCE+asset+CVE", "RCE"
    if rce and asset:          return True, "RCE+asset", "RCE"
    if rce and cve:            return True, "RCE+CVE", "RCE"
    if rce:                    return True, "RCE", "RCE"          # 可仅 RCE
    if bypass and asset and cve: ...
    if bypass and cve / asset / alone: ...                         # bypass 路径
    if asset and cve:          return True, "asset+CVE", "other"
    return False, "no hit", None
```

返回 `(hit, reason, vuln_type)`。

- `reason`：细粒度匹配，用于分析与 brief
- `vuln_type`：`RCE` / `bypass` / `other` / `None`
- **纯 RCE / 纯 bypass（无 asset、无 CVE）也会 `hit=True`**，再靠 freshness + CVSS PR/UI +（可选）LLM 收口

## 三档分类：1day / nday / noise

> **1day = 漏洞本体新近公开且处于可利用窗口期，值得立刻关注和防御的新鲜攻击面。**

| 档位 | 推送 | 含义 |
|---|---|---|
| **1day** | 可能推 | 新鲜；还要过 PR/UI 与（可选）LLM |
| **nday** | 不推 | 老洞/不可验证新鲜度 |
| **noise** | 不推 | excluded / no hit |

> 例外（高分兜底）：`no hit` 但 `cvss >= 9.0` 且 `cvss_pr = 'N'` 的记录仍会进 LLM 复核——regex 召回层不能静默埋掉 critical 未授权漏洞（如 OT 分段绕过这类不含 RCE/auth 关键词的措辞）。`excluded` 记录不兜底（那是主动的噪声判定：WP/XSS/DoS/LPE 等）。准入条件在 `enrich.py` 的 `_ENRICHABLE_WHERE`。

### `_is_fresh(source, text)` 摘要

1. 全部 CVE 年份 > 1 年 → `nday`（`old_cve`），无例外  
2. 高信任源（`FRESH_SOURCES`）：NVD 60 天内确认，或 NVD 无数据时年份回退；无 CVE 也可 1day  
3. 低信任源：必须 NVD 确认 ≤60 天；无 CVE → nday  
4. 多 CVE：任一近期 CVE 即可  

`FRESH_SOURCES` 含：Fortinet / PaloAlto / Cisco / MSRC / CISA_KEV / ZDI / watchTowr / Horizon3 / Rapid7 / Chaitin / DailyCVE / GHSA 等（ThreatBook 不在内，见源注释）。

### 推送硬约束

`_regex_push_candidate` / `_resolve_pushed`（`src/push_gate.py`）**同一套**门禁，LLM **不能**放宽：

1. `freshness == "1day"`
2. **`vuln_type in ("RCE", "bypass")`** — SQLi / 路径遍历读文件 / 硬编码凭据 / 纯密码学等（`other`）只入库不推送
3. 源不是 GitHub / PoC-GitHub  
4. `cvss_pr == "N"`（未知 PR 不推，等 NVD 回填）  
5. `cvss_ui` 为 `N` 或未知（`R` 锁 0）  
6. 有 LLM 时：还要 `llm_verdict == confirmed`，且 `llm_verified=1` 才发通道  

启动 `init_db` 会对存量执行：`pushed=0 WHERE vuln_type NOT IN ('RCE','bypass')`。

### LLM 回写 `vuln_type`

LLM 除 `verdict` 外还返回 `vuln_type`（RCE / bypass / other）。**仅当 regex 未分类（`vuln_type IS NULL`，即高分兜底进来的 `no hit` 记录）时**才采用该分类并同步刷新 `category`；已有 regex 分类绝不覆盖。回写后推送决议仍走 `_resolve_pushed` 同一套硬门禁——LLM 判 `other`（如 SQLi）依然不推。auto-approve（高可信源 + CVSS≥9.0）跳过含未分类记录的 CVE 组，交给 LLM 分类。

## 仪表盘 `category`

`classify_category()` 粗粒度标签：escape > RCE > SQLi / privilege escalation / bypass / data leak / XSS/SSRF / DoS > other。  
excluded 记录也会按关键词归类，方便全量浏览。

## 调参建议

1. 先看一周日志 / DB 里 `reason` 分布（`[FILTER]` / dry 输出）  
2. 短词误伤 → 改 `asset_hit` 边界或从 `ASSET_KEYWORDS` 删短歧义词  
3. 漏召回 → 扩 `RCE_PATTERNS` / `BYPASS_PATTERNS`，并补 `tests/test_score.py`  
4. 改完跑 `rescore`（只动 `llm_verified=0`）+ 相关单测  
