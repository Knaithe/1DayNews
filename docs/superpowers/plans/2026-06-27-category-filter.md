# Dashboard Category Filter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a finer-grained `category` dimension (8 classes) to the vuln-monitor dashboard, stored as a column and exposed as filter pills replacing the current RCE/bypass/other type row.

**Architecture:** A pure `classify_category(vuln_type, text)` function assigns one of 8 labels by keyword priority. The label is stored in a new `category` column, set at ingest + rescore, backfilled once for existing rows, filtered server-side by `/api/vulns`, and shown as pills + card badges in the dashboard.

**Tech Stack:** Python 3 (stdlib `sqlite3`/`re`), Flask (web.py), vanilla JS, pytest.

**Spec:** `docs/superpowers/specs/2026-06-27-category-filter-design.md`

---

## File Structure

- **Create** `tests/test_category.py` — `classify_category()` unit tests + `init_db` migration test.
- **Create** `tests/test_api_category.py` — `/api/vulns?category=` filter test.
- **Create** `scripts/backfill_category.py` — one-off backfill of `category` for all existing rows.
- **Modify** `src/vuln_monitor.py` — add `CATEGORY_KEYWORDS` + `classify_category()`; `init_db` column migration; set `category` at ingest INSERT (`_run`) and rescore UPDATE.
- **Modify** `src/web.py` — `/api/vulns` `category` param + response field; `typeRow` → category pills; JS `activeCats` + `category` param; `CATEGORY_STYLE`; card badge.

---

## Task 1: `classify_category()` function (TDD)

**Files:**
- Create: `tests/test_category.py`
- Modify: `src/vuln_monitor.py` (add after `score()`, ~line 877)

- [ ] **Step 1: Write the failing tests**

Create `tests/test_category.py`:

```python
"""Tests for vuln_monitor.classify_category() and the category column migration."""
import os
import sqlite3
import tempfile
from datetime import datetime, timezone

os.environ.setdefault("VULN_DATA_DIR", "")

import src.vuln_monitor as v


def _cls(vuln_type, text):
    return v.classify_category(vuln_type, text)


def test_rce_by_vuln_type():
    assert _cls("RCE", "anything goes here") == "RCE"


def test_sqli():
    assert _cls("other", "CVE-x FooBar SQL Injection in login") == "SQLi"


def test_bypass_by_keyword():
    assert _cls("other", "CVE-x Authentication Bypass in portal") == "bypass"


def test_bypass_fallback_by_vuln_type():
    # vuln_type=bypass with no specific keyword still maps to bypass
    assert _cls("bypass", "CVE-x some nondescript issue") == "bypass"


def test_privilege_escalation():
    assert _cls("other", "CVE-x Unauthenticated Privilege Escalation in WordPress") == "privilege escalation"


def test_data_leak_file_read():
    assert _cls("other", "CVE-x arbitrary file read via path traversal") == "data leak"


def test_data_leak_info_disclosure():
    assert _cls("other", "CVE-x sensitive information disclosure of user data") == "data leak"


def test_xss():
    assert _cls("other", "CVE-x stored XSS in comment field") == "XSS"


def test_dos():
    assert _cls("other", "CVE-x denial of service via crafted packet") == "DoS"


def test_other_fallback():
    assert _cls("other", "CVE-x some nondescript vuln in a plugin") == "other"


def test_sqli_beats_data_leak():
    # SQLi dump is both SQLi and a data leak -> SQLi wins (priority)
    assert _cls("other", "SQL injection allowing data leak of user table") == "SQLi"


def test_path_traversal_is_data_leak():
    assert _cls("other", "path traversal to read sensitive files") == "data leak"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_category.py -v`
Expected: FAIL — `AttributeError: module 'vuln_monitor' has no attribute 'classify_category'`

- [ ] **Step 3: Implement `classify_category()` + `CATEGORY_KEYWORDS`**

In `src/vuln_monitor.py`, add immediately after the `score()` function (after its `return False, "no hit", None` line, ~line 877):

```python
# ================== CATEGORY (dashboard filter dimension) ==================
# One coarser "category" label per record, derived from vuln_type + keywords.
# Priority order (first match wins): RCE > SQLi > bypass > privilege escalation
# > data leak > XSS > DoS > other. Resolves overlaps (e.g. SQLi-dump -> SQLi,
# path-traversal-read -> data leak). Stored in the `category` column.
CATEGORY_KEYWORDS = [
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
    """Return one dashboard category label for a record.

    Priority: RCE (by vuln_type) > keyword classes > bypass (by vuln_type) > other.
    """
    if vuln_type == "RCE":
        return "RCE"
    low = (text or "").lower()
    for cat, patterns in CATEGORY_KEYWORDS:
        if any(re.search(p, low) for p in patterns):
            return cat
    if vuln_type == "bypass":
        return "bypass"
    return "other"
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_category.py -v`
Expected: 12 passed

- [ ] **Step 5: Commit**

```bash
git add tests/test_category.py src/vuln_monitor.py
git commit -m "feat: 新增 classify_category() 8 类分类函数"
```

---

## Task 2: `category` column migration in `init_db` (TDD)

**Files:**
- Modify: `tests/test_category.py` (append migration test)
- Modify: `src/vuln_monitor.py:611-629` (the `_new_cols` list in `init_db`)

- [ ] **Step 1: Write the failing test**

Append to `tests/test_category.py`:

```python
def test_init_db_adds_category_column(tmp_path):
    db = str(tmp_path / "t.db")
    c = sqlite3.connect(db)
    # a pre-migration DB without category
    c.execute("CREATE TABLE vulns (key TEXT PRIMARY KEY, title TEXT NOT NULL, "
              "created_at REAL NOT NULL, pushed INTEGER DEFAULT 0)")
    v.init_db(c)
    cols = [r[1] for r in c.execute("PRAGMA table_info(vulns)").fetchall()]
    assert "category" in cols
    c.close()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_category.py::test_init_db_adds_category_column -v`
Expected: FAIL — `assert 'category' in cols` is False

- [ ] **Step 3: Add the column to the migration list**

In `src/vuln_monitor.py` `init_db`, add `("category", "TEXT")` to the `_new_cols` loop. Insert it after the `("reproduced", "INTEGER DEFAULT 0"),` line (the last entry, ~line 628):

```python
        ("cvss_ui",       "TEXT"),
        ("reproduced",   "INTEGER DEFAULT 0"),
        ("category",     "TEXT"),
    ]:
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_category.py -v`
Expected: 13 passed

- [ ] **Step 5: Commit**

```bash
git add tests/test_category.py src/vuln_monitor.py
git commit -m "feat: init_db 迁移增加 category 列"
```

---

## Task 3: Set `category` at ingest and rescore

`classify_category` is unit-tested (Task 1); these are one-line wiring changes verified end-to-end by the backfill (Task 6).

**Files:**
- Modify: `src/vuln_monitor.py:2118-2186` (ingest INSERT in `_run`)
- Modify: `src/vuln_monitor.py:2440-2483` (rescore UPDATE in `_cmd_rescore_inner`)

- [ ] **Step 1: Set category in the ingest INSERT**

In `src/vuln_monitor.py`, the ingest block computes `hit, reason, vuln_type = score(it["text"])` at ~line 2118. Immediately after that line, add:

```python
            category = classify_category(vuln_type, it["text"])
```

Then update the INSERT at ~line 2180-2186 to include `category` in the column list, the placeholder count, and the params. Replace:

```python
            conn.execute(
                "INSERT OR IGNORE INTO vulns (key,cve_id,source,title,link,summary,reason,vuln_type,freshness,freshness_reason,pushed,created_at,cve_published,severity,cvss,cvss_vector,cvss_pr,cvss_ui) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (key, cve_id, it["source"], it["title"][:300], it["link"],
                 it["summary"][:500], reason, vuln_type, freshness, fresh_reason,
                 1 if should_push else 0, now, cve_pub, nvd_severity, nvd_cvss,
                 nvd_vector, pr, ui),
            )
```

with:

```python
            conn.execute(
                "INSERT OR IGNORE INTO vulns (key,cve_id,source,title,link,summary,reason,vuln_type,category,freshness,freshness_reason,pushed,created_at,cve_published,severity,cvss,cvss_vector,cvss_pr,cvss_ui) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (key, cve_id, it["source"], it["title"][:300], it["link"],
                 it["summary"][:500], reason, vuln_type, category, freshness, fresh_reason,
                 1 if should_push else 0, now, cve_pub, nvd_severity, nvd_cvss,
                 nvd_vector, pr, ui),
            )
```

- [ ] **Step 2: Set category in the rescore UPDATE**

In `_cmd_rescore_inner` (~line 2440), `text = f"{title or ''}\n{summary or ''}"` is already computed and `hit, reason, vuln_type = score(text)` follows. Immediately after that score call, add:

```python
            category = classify_category(vuln_type, text)
```

Then update the UPDATE at ~line 2482. Replace:

```python
                conn.execute("UPDATE vulns SET reason=?, vuln_type=?, freshness=?, freshness_reason=?, pushed=?, cve_published=COALESCE(?,cve_published) WHERE key=?",
                            (reason, vuln_type, freshness, fresh_reason, new_pushed, cve_pub, key))
```

with:

```python
                conn.execute("UPDATE vulns SET reason=?, vuln_type=?, category=?, freshness=?, freshness_reason=?, pushed=?, cve_published=COALESCE(?,cve_published) WHERE key=?",
                            (reason, vuln_type, category, freshness, fresh_reason, new_pushed, cve_pub, key))
```

- [ ] **Step 3: Smoke-verify the module still imports and tests pass**

Run: `python -m pytest tests/ -v`
Expected: all green (wiring changes don't break existing tests)

- [ ] **Step 4: Commit**

```bash
git add src/vuln_monitor.py
git commit -m "feat: ingest 与 rescore 写入 category 列"
```

---

## Task 4: `/api/vulns` category filter + response field (TDD)

**Files:**
- Create: `tests/test_api_category.py`
- Modify: `src/web.py:185-192` (add `category` param handler), `235` (optional_cols), `245-266` (response)

- [ ] **Step 1: Write the failing test**

Create `tests/test_api_category.py`:

```python
"""Tests for /api/vulns?category= filter."""
import sqlite3
from datetime import datetime, timezone
import pytest

import src.web as web_mod


@pytest.fixture
def client(tmp_path):
    db_path = tmp_path / "vuln_cache.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute("""CREATE TABLE vulns (
        key TEXT, cve_id TEXT, source TEXT, title TEXT, link TEXT,
        summary TEXT, reason TEXT, vuln_type TEXT, category TEXT, freshness TEXT,
        freshness_reason TEXT, pushed INTEGER DEFAULT 0,
        created_at REAL, cve_published TEXT, severity TEXT, cvss REAL,
        llm_verified INTEGER DEFAULT 0, llm_verdict TEXT, llm_notes TEXT,
        tg_sent INTEGER DEFAULT 0, wecom_sent INTEGER DEFAULT 0,
        dingtalk_sent INTEGER DEFAULT 0, feishu_sent INTEGER DEFAULT 0,
        cvss_vector TEXT, cvss_pr TEXT
    )""")
    now = datetime.now(timezone.utc).timestamp()
    rows = [
        ("k1", "CVE-2026-1", "ZDI", "SQL Injection in Foo", "u1", "sqli", "asset+CVE", "other",
         "SQLi", "1day", None, 1, now, "2026-06-20", "high", 9.0, 0, None, None, 1, 0, 0, 0, None, "N"),
        ("k2", "CVE-2026-2", "GHSA", "Path Traversal file read", "u2", "read /etc/passwd", "asset+CVE", "other",
         "data leak", "1day", None, 1, now, "2026-06-19", "critical", 9.8, 0, None, None, 1, 0, 0, 0, None, "N"),
        ("k3", "CVE-2026-3", "CISA_KEV", "RCE in FortiGate", "u3", "RCE", "RCE+asset+CVE", "RCE",
         "RCE", "1day", None, 1, now, "2026-06-18", "critical", 9.8, 0, None, None, 1, 0, 0, 0, None, "N"),
    ]
    conn.executemany("INSERT INTO vulns VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
    conn.commit(); conn.close()

    web_mod.DB_FILE = db_path
    web_mod.TOKEN_FILE = tmp_path / ".web_token"
    web_mod._MAGIC_TOKEN = None
    web_mod.app.config["TESTING"] = True
    yield web_mod.app.test_client()


def test_category_filter_returns_only_matching(client):
    r = client.get("/api/vulns?category=SQLi")
    assert r.status_code == 200
    data = r.get_json()
    assert len(data) == 1
    assert data[0]["id"] == "CVE-2026-1"
    assert data[0]["category"] == "SQLi"


def test_category_filter_multi(client):
    r = client.get("/api/vulns?category=SQLi,data%20leak")  # "data leak" URL-encoded
    data = r.get_json()
    ids = sorted(d["id"] for d in data)
    assert ids == ["CVE-2026-1", "CVE-2026-2"]


def test_response_includes_category(client):
    data = client.get("/api/vulns?category=RCE").get_json()
    assert data[0]["category"] == "RCE"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_api_category.py -v`
Expected: FAIL — `category` not in response / filter not applied

- [ ] **Step 3: Add the `category` param handler**

In `src/web.py`, immediately after the `vuln_type` block (after line 192), add:

```python
        category = request.args.get("category", "").strip()
        if category and "category" in cols_avail:
            cat_list = [c.strip() for c in category.split(",") if c.strip()][:12]
            if len(cat_list) == 1:
                where.append("category = ?"); params.append(cat_list[0])
            elif cat_list:
                where.append(f"category IN ({','.join('?' * len(cat_list))})")
                params.extend(cat_list)
```

- [ ] **Step 4: Add `category` to optional_cols and the response**

In `src/web.py` line 235, change:

```python
        optional_cols = ["vuln_type", "freshness", "cvss_pr", "cvss_ui", "reproduced"]
```

to:

```python
        optional_cols = ["vuln_type", "category", "freshness", "cvss_pr", "cvss_ui", "reproduced"]
```

After line 249 (`has_repro = "reproduced" in cols_avail`), add:

```python
    has_cat = "category" in cols_avail
```

In the response dict (after the `"vuln_type": ...` line, ~line 253), add:

```python
        "category": r["category"] if has_cat else None,
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `python -m pytest tests/test_api_category.py -v`
Expected: 3 passed. Then run the full suite: `python -m pytest tests/ -v` — all green.

- [ ] **Step 6: Commit**

```bash
git add tests/test_api_category.py src/web.py
git commit -m "feat: /api/vulns 支持 category 过滤与返回"
```

---

## Task 5: Dashboard UI — category pills + card badge

No JS test framework; verified manually. The `typeRow` (RCE/bypass/other, `data-vtype`) becomes the category row (`data-cat`).

**Files:**
- Modify: `src/web.py:613-618` (typeRow HTML)
- Modify: `src/web.py:669-673` (TYPE_STYLE → add CATEGORY_STYLE)
- Modify: `src/web.py:676` (activeTypes → activeCats)
- Modify: `src/web.py:711-713` (typeRow click handler)
- Modify: `src/web.py:859` (param builder)
- Modify: `src/web.py:885-889` (card badge)

- [ ] **Step 1: Replace the `typeRow` HTML**

In `src/web.py`, replace the `typeRow` div (lines 613-618):

```html
<div class="filter-row" id="typeRow" role="group" aria-label="Filter by type">
  <button type="button" class="cat-pill" data-vtype="">All</button>
  <button type="button" class="cat-pill active" data-vtype="RCE">RCE</button>
  <button type="button" class="cat-pill active" data-vtype="bypass">bypass</button>
  <button type="button" class="cat-pill" data-vtype="other">other</button>
</div>
```

with the category row:

```html
<div class="filter-row" id="typeRow" role="group" aria-label="Filter by category">
  <button type="button" class="cat-pill" data-cat="">All</button>
  <button type="button" class="cat-pill active" data-cat="RCE">RCE</button>
  <button type="button" class="cat-pill active" data-cat="bypass">bypass</button>
  <button type="button" class="cat-pill" data-cat="SQLi">SQLi</button>
  <button type="button" class="cat-pill" data-cat="privilege escalation">privilege escalation</button>
  <button type="button" class="cat-pill" data-cat="data leak">data leak</button>
  <button type="button" class="cat-pill" data-cat="XSS">XSS</button>
  <button type="button" class="cat-pill" data-cat="DoS">DoS</button>
  <button type="button" class="cat-pill" data-cat="other">other</button>
</div>
```

- [ ] **Step 2: Add `CATEGORY_STYLE` and switch the state set**

Replace the `TYPE_STYLE` block (lines 669-673):

```python
const TYPE_STYLE = {
  "RCE":    {bg:"#FEE2E2",fg:"#991b1b"},
  "bypass": {bg:"#DBEAFE",fg:"#1e40af"},
  "other":  {bg:"#FEF3C7",fg:"#92400e"},
};
```

with:

```python
const CATEGORY_STYLE = {
  "RCE":                   {bg:"#FEE2E2",fg:"#991b1b"},
  "SQLi":                  {bg:"#EDE9FE",fg:"#5b21b6"},
  "bypass":                {bg:"#DBEAFE",fg:"#1e40af"},
  "privilege escalation":  {bg:"#FFEDD5",fg:"#9a3412"},
  "data leak":             {bg:"#FEF3C7",fg:"#92400e"},
  "XSS":                   {bg:"#FCE7F3",fg:"#9d174d"},
  "DoS":                   {bg:"#E5E7EB",fg:"#374151"},
  "other":                 {bg:"#F1F5F9",fg:"#475569"},
};
```

On line 676, change:

```python
const activeTypes = new Set(['RCE','bypass']);
```

to:

```python
const activeCats = new Set(['RCE','bypass']);
```

- [ ] **Step 3: Switch the click handler to `data-cat`**

Replace the typeRow handler (lines 711-713):

```python
document.querySelectorAll('#typeRow .cat-pill').forEach(p => p.addEventListener('click', () => {
  toggleMulti(activeTypes, p.dataset.vtype, '#typeRow', 'vtype');
}));
```

with:

```python
document.querySelectorAll('#typeRow .cat-pill').forEach(p => p.addEventListener('click', () => {
  toggleMulti(activeCats, p.dataset.cat, '#typeRow', 'cat');
}));
```

- [ ] **Step 4: Send `category` param instead of `vuln_type`**

On line 859, change:

```python
  if (activeTypes.size) params.set('vuln_type', [...activeTypes].join(','));
```

to:

```python
  if (activeCats.size) params.set('category', [...activeCats].join(','));
```

- [ ] **Step 5: Show the category badge on cards**

Replace the badge logic (lines 885-889). Change:

```python
      const ts = TYPE_STYLE[v.vuln_type] || {bg:'#F3F4F6',fg:'#6B7280'};
      return `<div class="vcard" style="animation:fadeUp .4s ${i*.03}s both">
        <div class="vcard-top">
          <span class="src-badge" style="background:${ss.bg};color:${ss.fg}">${esc(v.source||'?')}</span>
          ${v.vuln_type&&TYPE_STYLE[v.vuln_type]?`<span class="reason-badge" style="background:${ts.bg};color:${ts.fg}">${esc(v.vuln_type)}</span>`:''}
```

to:

```python
      const cs = CATEGORY_STYLE[v.category] || {bg:'#F3F4F6',fg:'#6B7280'};
      return `<div class="vcard" style="animation:fadeUp .4s ${i*.03}s both">
        <div class="vcard-top">
          <span class="src-badge" style="background:${ss.bg};color:${ss.fg}">${esc(v.source||'?')}</span>
          ${v.category&&CATEGORY_STYLE[v.category]?`<span class="reason-badge" style="background:${cs.bg};color:${cs.fg}">${esc(v.category)}</span>`:''}
```

- [ ] **Step 6: Manual verification**

Run: `python src/web.py` → open `http://127.0.0.1:8001` → confirm:
- The type row shows 8 pills (RCE / bypass / SQLi / privilege escalation / data leak / XSS / DoS / other), RCE + bypass active.
- Clicking a pill filters the list; "All" clears.
- Cards show a colored category badge.

- [ ] **Step 7: Commit**

```bash
git add src/web.py
git commit -m "feat: dashboard 分类药丸 filter（替换 type 行为 category 维度）"
```

---

## Task 6: Backfill `category` for existing records + deploy

**Files:**
- Create: `scripts/backfill_category.py`

- [ ] **Step 1: Write the backfill script**

Create `scripts/backfill_category.py`:

```python
"""One-off: backfill the `category` column for all existing vulns records.

Usage (on prod, as the vuln user):
    /opt/vuln-monitor/venv/bin/python /opt/vuln-monitor/scripts/backfill_category.py
"""
import os
import sqlite3

DB = os.environ.get("VULN_DB", "/opt/vuln-monitor/vuln_cache.db")

def main():
    import sys
    sys.path.insert(0, "/opt/vuln-monitor/src")
    import vuln_monitor as v

    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT key, title, summary, vuln_type FROM vulns").fetchall()
    changed = 0
    from collections import Counter
    dist = Counter()
    for r in rows:
        text = f"{r['title'] or ''}\n{r['summary'] or ''}"
        cat = v.classify_category(r["vuln_type"], text)
        dist[cat] += 1
        conn.execute("UPDATE vulns SET category=? WHERE key=?", (cat, r["key"]))
        changed += 1
    conn.commit()
    print(f"backfilled category on {changed}/{len(rows)} rows")
    for cat, n in dist.most_common():
        print(f"  {cat}: {n}")
    conn.close()

if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Run the full test suite locally**

Run: `python -m pytest tests/ -v`
Expected: all green.

- [ ] **Step 3: Commit + push**

```bash
git add scripts/backfill_category.py
git commit -m "feat: scripts/backfill_category.py 一次性回填 category"
git push origin master
```

- [ ] **Step 4: Deploy + backfill on prod**

On prod (100.107.70.91 as `target`), via the established sshpass/rsync flow:
1. `sudo git -C /opt/vuln-monitor pull --ff-only`
2. `sudo systemctl stop vuln-monitor.service`
3. back up DB: `sudo -u vuln cp /opt/vuln-monitor/vuln_cache.db /opt/vuln-monitor/vuln_cache.db.preCategory`
4. run backfill: `sudo -u vuln /opt/vuln-monitor/venv/bin/python /opt/vuln-monitor/scripts/backfill_category.py`
5. `sudo systemctl start vuln-monitor.service`

Expected: backfill prints a distribution across the 8 categories (RCE largest).

- [ ] **Step 5: Verify on prod**

Query prod: `SELECT category, COUNT(*) FROM vulns GROUP BY category` → 8 categories present, RCE ≈ 1799. Spot-check the two original CVEs: `CVE-2026-56028` → `privilege escalation`, `CVE-2026-56033` → `privilege escalation`. Open the dashboard → category pills filter correctly.

---

## Self-Review (completed)

- **Spec coverage:** classify_category (Task 1), column + migration (Task 2), ingest + rescore (Task 3), API filter + response (Task 4), UI pills + badge (Task 5), backfill + deploy (Task 6) — all spec sections covered.
- **Placeholder scan:** none; every code step has full code.
- **Type consistency:** `classify_category(vuln_type, text)` signature and the 8 label strings are identical across tasks (Task 1 defines, Tasks 3/6 use). `activeCats` / `data-cat` / `category` param name consistent across Task 5 steps. `CATEGORY_STYLE` keys match the 8 labels.
