# Category Filter for vuln-monitor Dashboard

**Date:** 2026-06-27
**Status:** Design — awaiting review

## Goal

Add finer-grained vulnerability category filters to the web dashboard, so users can filter beyond the current `vuln_type` (RCE / bypass / other) — e.g. isolate SQLi, privilege escalation, or data leaks.

## Background

The audit of the RCE relabel (vuln_type=RCE 3493 → 1756) showed the "other" bucket contains distinct, useful sub-types: SQLi, auth/access-control bypass, file read, info disclosure, privesc, DoS, XSS. None of these is a stored field today. This spec adds a derived `category` column and exposes it as dashboard filter pills.

## Category scheme (9 classes, one per record, priority order)

Priority — first keyword match wins; excluded records and memory-corruption are handled specially:

```
RCE > SQLi > privilege escalation > bypass > SSRF > data leak > XSS > DoS > other
```

Labels follow the existing UI convention (acronyms uppercase, words/phrases lowercase):

| label | assigned when |
|---|---|
| `RCE` | `vuln_type = RCE` |
| `SQLi` | sql injection / sqli |
| `privilege escalation` | privilege escalation / privesc / 提权 / elevation of privilege |
| `bypass` | auth/authz/access-control/permission/RBAC/security-feature bypass, IDOR, account takeover, impersonation |
| `SSRF` | server-side request forgery / ssrf |
| `data leak` | arbitrary/unauthorized file read, path/directory traversal, LFI / local file inclusion, information disclosure, sensitive data, source/credential disclosure (file-read + info-disclosure **merged**) |
| `XSS` | xss / cross-site scripting / csrf / open redirect |
| `DoS` | dos / denial of service / crash |
| `other` | fallback |

**Special handling:**
- `reason = excluded` → `other` (excluded records are noise; never claim a category).
- Memory-corruption (buffer overflow / use-after-free / out-of-bounds / type confusion / integer overflow) is RCE-class, never `DoS` → falls to `other`.

**Overlap resolution (by priority):** SQLi dump → `SQLi` (not data leak); path traversal reading a sensitive file → `data leak`; "elevation of privilege" with access-control language → `privilege escalation` (privesc checked before bypass).

The `category` column stores the label string directly — same pattern as `vuln_type` storing `"RCE"` / `"bypass"`. No separate key/label mapping.

## Components

### `classify_category(vuln_type, text, reason=None)` — `src/vuln_monitor.py`

Pure function, returns one of the 9 labels:

```python
CATEGORY_KEYWORDS = [   # ordered; first match wins
    ("SQLi",                 [r"sql injection", r"\bsqli\b"]),
    ("bypass",               [r"auth(?:entication|orization)?\s*(?:bypass|weak|flaw)",
                              r"access control", r"improper access", r"permission\s*(?:bypass|flaw)",
                              r"\bRBAC\b", r"security (?:feature )?bypass", r"broken access"]),
    ("privilege escalation", [r"privilege escalation", r"\bprivesc\b", r"elevation of privilege", r"权限提升"]),
    ("data leak",            [r"arbitrary file read", r"file read", r"path traversal", r"directory traversal",
                              r"\bLFI\b", r"information disclosure", r"sensitive (?:data|information)",
                              r"data (?:leak|exposure|disclos)", r"source (?:code )?disclos",
                              r"credential(?:s)? leak", r"任意文件读取", r"信息泄露"]),
    ("XSS",                  [r"\bxss\b", r"cross[- ]site scripting", r"\bcsrf\b", r"open redirect"]),
    ("DoS",                  [r"\bdos\b", r"denial of service", r"\bcrash(?:es|ed)?\b"]),
]

def classify_category(vuln_type, text):
    if vuln_type == "RCE":
        return "RCE"
    low = text.lower()
    for cat, patterns in CATEGORY_KEYWORDS:
        if any(re.search(p, low) for p in patterns):
            return cat
    if vuln_type == "bypass":
        return "bypass"
    return "other"
```

### Storage — `category TEXT` column

- `init_db()`: idempotent `ALTER TABLE vulns ADD COLUMN category TEXT` (same migration pattern as the existing `dispatched` column).
- **Ingest**: at the point in `fetch` where `vuln_type`/`reason` are written, also set `category = classify_category(vuln_type, title + "\n" + summary)`. New records get it automatically.
- **Backfill**: one-off UPDATE over all existing rows (the same relabel-style script used for the RCE relabel), run once on prod after deploy.

### API — `/api/vulns`

- New `category` query param (comma-separated multi-select, mirrors the existing `vuln_type` param). Filtering is `WHERE category IN (...)` applied **before** `LIMIT`, so server-side pagination stays correct.
- Each vuln object in the response includes `category`.

### UI — `src/web.py` dashboard

- The existing `typeRow` (RCE / bypass / other) becomes `categoryRow` with 8 pills: `RCE / SQLi / bypass / privilege escalation / data leak / XSS / DoS / other`.
- Default active pills: `RCE + bypass` (preserves the current default behavior).
- Pills use a `data-cat` attribute; the existing `toggleMulti` handler sends the `category` param. Pill styling unchanged.

## Tests (TDD)

- `classify_category()` unit tests (`tests/test_score.py` or a new `tests/test_category.py`): one per category, plus the overlap-resolution cases (SQLi dump → SQLi, path traversal → data leak, unauthenticated privesc → privilege escalation, pure RCE → RCE, vuln_type=bypass with no keyword → bypass, no match → other).
- `/api/vulns?category=` filter test (extend `tests/test_api_pending.py`).

## Out of scope

- Reclassifying `vuln_type` (unchanged — still RCE / bypass / other from `score()`).
- Changing push / freshness / scoring logic.
- A category stats/counts panel (can be added later).
