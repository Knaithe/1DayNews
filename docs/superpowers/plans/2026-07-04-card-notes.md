# Card Notes (备注) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an editable ≤100-char note to each dashboard vulnerability card, saved per-row (effectively per-CVE), edited via a popover anchored to a ✎ icon on the card.

**Architecture:** Mirror the existing `POST /api/reproduced` RW endpoint pattern exactly — idempotent `ALTER TABLE` migration, `get_db_rw()` context, parameterized `UPDATE`, 3× busy-retry → 503. Add a `note TEXT` column. Expose `note` through `GET /api/vulns` (owner-auth-gated) but **never** through `GET /api/pending` (B-side feed). Frontend is a reused popover with a `<textarea maxlength=100>`, all note text rendered through the existing `esc()` helper.

**Tech Stack:** Python 3, Flask + waitress, SQLite (WAL), pytest. Frontend is inline HTML/CSS/JS inside a Python triple-quoted string (`DASHBOARD_HTML`) — no build step, no JS test framework.

## Global Constraints

(Verbatim invariants from `docs/superpowers/specs/2026-07-04-card-notes-design.md`; every task obeys these.)

- Note length ≤ 100 chars, **enforced server-side**; over-length → HTTP 400 (never silent truncation). Count = Python `len()` (== JS `.length` for BMP/CJK).
- SQL is **parameterized only** (`?` placeholders) — no string interpolation into SQL.
- All note text rendered through the existing `esc()` helper; **never** set raw note via `innerHTML`.
- `note` must NOT appear in `GET /api/pending` output (personal notes stay off the B-side feed).
- No new dependencies; match existing patterns (`/api/reproduced`, `get_db_rw`, `_vulns_columns`, `esc`, `cap1`).
- Commits go to `master` (this repo's convention — single-author, all history on master).

---

## File Structure

- **`src/vuln_monitor.py`** — add `note TEXT` to the `init_db()` migration list (monitor-runtime schema).
- **`src/web.py`** — add `POST /api/note` endpoint; expose `note` in `GET /api/vulns`; add ✎ button to the card template; add popover HTML + CSS + JS inside `DASHBOARD_HTML`.
- **`tests/test_api_note.py`** (new) — endpoint behavior, auto-migrate, XSS invariant, length/empty/key validation, `/api/vulns` exposure, `/api/pending` exclusion, dashboard HTML structure.

---

## Task 1: Backend — `POST /api/note` + `note` column migration

**Files:**
- Modify: `src/vuln_monitor.py:648` (init_db migration list — add `note`)
- Modify: `src/web.py:372` (insert `api_note` right after `api_reproduced`)
- Create: `tests/test_api_note.py`

**Interfaces:**
- Consumes: `get_db_rw()`, `_vulns_columns(conn)`, `request`, `jsonify`, `sqlite3`, `time` (all already imported in `web.py`).
- Produces: `POST /api/note` accepting `{"key": str, "note": str}` → `{"ok": true, "key": str, "note": str|null}`; 400 on missing key / over-length; 503 on persistent busy. Auto-migrates the `note` column on first write.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_api_note.py`:

```python
"""Tests for POST /api/note endpoint and note column."""
import sqlite3
from datetime import datetime, timezone
import pytest

import src.web as web_mod


@pytest.fixture
def client(tmp_path):
    db_path = tmp_path / "vuln_cache.db"
    conn = sqlite3.connect(str(db_path))
    # NOTE: no `note` column — exercises the endpoint's auto-migrate path.
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
    conn.execute(
        "INSERT INTO vulns (key, cve_id, source, title, pushed, created_at) "
        "VALUES (?,?,?,?,?,?)",
        ("cve:CVE-2026-1001", "CVE-2026-1001", "CISA_KEV", "RCE in FortiGate", 1, now),
    )
    conn.commit(); conn.close()

    web_mod.DB_FILE = db_path
    web_mod.TOKEN_FILE = tmp_path / ".web_token"
    web_mod._MAGIC_TOKEN = None
    web_mod.app.config["TESTING"] = True
    yield web_mod.app.test_client()


def _note_in_db(db_path, key):
    conn = sqlite3.connect(str(db_path))
    row = conn.execute("SELECT note FROM vulns WHERE key=?", (key,)).fetchone()
    conn.close()
    return row[0] if row else None


def test_save_note_roundtrip_via_db(client, tmp_path):
    resp = client.post("/api/note", json={"key": "cve:CVE-2026-1001", "note": "在野利用确认"})
    assert resp.status_code == 200
    assert resp.get_json() == {"ok": True, "key": "cve:CVE-2026-1001", "note": "在野利用确认"}
    assert _note_in_db(tmp_path / "vuln_cache.db", "cve:CVE-2026-1001") == "在野利用确认"


def test_too_long_note_rejected(client):
    resp = client.post("/api/note", json={"key": "cve:CVE-2026-1001", "note": "x" * 101})
    assert resp.status_code == 400
    assert "max 100" in resp.get_json()["error"]


def test_empty_note_clears_to_null(client, tmp_path):
    db = tmp_path / "vuln_cache.db"
    client.post("/api/note", json={"key": "cve:CVE-2026-1001", "note": "先记一下"})
    assert _note_in_db(db, "cve:CVE-2026-1001") == "先记一下"
    resp = client.post("/api/note", json={"key": "cve:CVE-2026-1001", "note": "   "})
    assert resp.status_code == 200
    assert _note_in_db(db, "cve:CVE-2026-1001") is None


def test_missing_key_rejected(client):
    resp = client.post("/api/note", json={"note": "hello"})
    assert resp.status_code == 400


def test_xss_payload_stored_verbatim(client, tmp_path):
    payload = '<script>alert(1)</script>'
    resp = client.post("/api/note", json={"key": "cve:CVE-2026-1001", "note": payload})
    assert resp.status_code == 200
    # stored raw — proving no execution/interpretation at the storage layer
    assert _note_in_db(tmp_path / "vuln_cache.db", "cve:CVE-2026-1001") == payload


def test_auto_migrates_note_column(client, tmp_path):
    db = tmp_path / "vuln_cache.db"
    conn = sqlite3.connect(str(db))
    cols_before = {r[1] for r in conn.execute("PRAGMA table_info(vulns)")}
    conn.close()
    assert "note" not in cols_before  # precondition: fixture omits the column
    client.post("/api/note", json={"key": "cve:CVE-2026-1001", "note": "after migrate"})
    conn = sqlite3.connect(str(db))
    cols_after = {r[1] for r in conn.execute("PRAGMA table_info(vulns)")}
    conn.close()
    assert "note" in cols_after
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_api_note.py -v`
Expected: FAIL — `404 Not Found` on `POST /api/note` (route doesn't exist yet).

- [ ] **Step 3: Add the `note` column to the monitor-runtime schema**

In `src/vuln_monitor.py`, find the `init_db()` migration list (around line 648, the `for col, typedef in [...]` block ending with `("category", "TEXT"),`). Add `("note", "TEXT"),` as the last entry:

```python
        ("reproduced",   "INTEGER DEFAULT 0"),
        ("category",     "TEXT"),
        ("note",         "TEXT"),
    ]:
```

- [ ] **Step 4: Add the `POST /api/note` endpoint**

In `src/web.py`, find the end of `api_reproduced` (the function at line 351; it ends around line 372 with the `sqlite3.OperationalError` retry block). Insert this new route immediately **after** that function's final blank line and **before** the `# ── Vulnpilot API (for B-side dispatcher) ──` comment:

```python
@app.route("/api/note", methods=["POST"])
def api_note():
    """Set or clear a free-text note (<=100 chars) on a vulnerability by key."""
    data = request.get_json(silent=True) or {}
    key = (data.get("key") or "").strip()
    if not key:
        return jsonify({"error": "key required"}), 400
    note = (data.get("note") or "").strip()
    if len(note) > 100:
        return jsonify({"error": "note too long (max 100)"}), 400
    stored = note if note else None
    for attempt in range(3):
        try:
            with get_db_rw() as conn:
                cols = _vulns_columns(conn)
                if "note" not in cols:
                    conn.execute("ALTER TABLE vulns ADD COLUMN note TEXT")
                conn.execute("UPDATE vulns SET note=? WHERE key=?", (stored, key))
            return jsonify({"ok": True, "key": key, "note": stored})
        except sqlite3.OperationalError:
            if attempt == 2:
                return jsonify({"error": "database busy, try again"}), 503
            time.sleep(1)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `python -m pytest tests/test_api_note.py -v`
Expected: PASS — all 6 tests green.

- [ ] **Step 6: Run the full suite to confirm no regressions**

Run: `python -m pytest -q`
Expected: PASS (all prior tests still green; the new `note` column is absent from the other tests' fixture tables, so `has_note` falls back to `None`).

- [ ] **Step 7: Commit**

```bash
git add tests/test_api_note.py src/web.py src/vuln_monitor.py
git commit -m "feat(api): POST /api/note 写接口 + note 列迁移

照抄 /api/reproduced：参数化 UPDATE、3 次重试、ALTER TABLE 幂等加列；
≤100 字服务端硬限（超长 400 不截断）；空串清成 NULL。

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## Task 2: Expose `note` in `GET /api/vulns`; keep it out of `/api/pending`

**Files:**
- Modify: `src/web.py:292` (`optional_cols`), `src/web.py:307` (add `has_note`), `src/web.py:308-325` (response dict)
- Modify: `tests/test_api_note.py` (append two tests)

**Interfaces:**
- Consumes: `POST /api/note` (Task 1), the `/api/vulns` response builder, the `/api/pending` route (unchanged).
- Produces: each `/api/vulns` object gains a `note` field (string or null). `/api/pending` objects gain nothing.

- [ ] **Step 1: Append the failing read-path tests**

Add to the end of `tests/test_api_note.py`:

```python
def test_vulns_response_includes_note(client):
    client.post("/api/note", json={"key": "cve:CVE-2026-1001", "note": "via vulns"})
    data = client.get("/api/vulns").get_json()
    row = next(d for d in data if d["key"] == "cve:CVE-2026-1001")
    assert row["note"] == "via vulns"


def test_pending_excludes_note(client):
    # /api/pending feeds the B-side dispatcher — personal notes must never leak.
    client.post("/api/note", json={"key": "cve:CVE-2026-1001", "note": "secret"})
    data = client.get("/api/pending").get_json()
    assert data["count"] >= 1
    for v in data["vulns"]:
        assert "note" not in v
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_api_note.py::test_vulns_response_includes_note tests/test_api_note.py::test_pending_excludes_note -v`
Expected: the first FAILs with `KeyError: 'note'` (response lacks the field); the second PASSES already (proving the invariant holds — `/api/pending` is untouched).

- [ ] **Step 3: Expose `note` in `/api/vulns`**

Three edits in `src/web.py` inside `api_vulns` (lines ~288-325):

(a) Add `"note"` to `optional_cols` (line 292):

```python
        optional_cols = ["vuln_type", "category", "freshness", "cvss_pr", "cvss_ui", "reproduced", "note"]
```

(b) Add a `has_note` flag alongside the other `has_*` flags (after line 307, `has_cat = "category" in cols_avail`):

```python
        has_cat = "category" in cols_avail
        has_note = "note" in cols_avail
```

(c) Add the `note` field to the response dict (inside the `jsonify([{...}])` list, e.g. right after the `"category"` line at 312):

```python
        "category": r["category"] if has_cat else None,
        "note": r["note"] if has_note else None,
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_api_note.py -v`
Expected: PASS — all 8 tests green.

- [ ] **Step 5: Run the full suite**

Run: `python -m pytest -q`
Expected: PASS (no regressions; tables without `note` get `"note": None`).

- [ ] **Step 6: Commit**

```bash
git add src/web.py tests/test_api_note.py
git commit -m "feat(api): /api/vulns 暴露 note，/api/pending 不含

note 走 optional_cols + has_note 守卫，缺列回退 None；/api/pending
固定 SELECT 不动，备注永不进 B 机拉取流。

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## Task 3: Frontend — ✎ control + popover editor

**Files:**
- Modify: `src/web.py` — `DASHBOARD_HTML` (CSS in main `<style>` block; ✎ button in card template ~line 1015; popover `<div>` before `</body>` ~line 1058; JS before the `loadSources();…` bootstrap ~line 1051)
- Modify: `tests/test_api_note.py` (append one structural test)

**Interfaces:**
- Consumes: `GET /api/vulns` `note` field (Task 2), `POST /api/note` (Task 1), existing `esc()` helper, existing `.hidden` CSS class, CSS vars (`--cream`, `--ink`, `--violet`, `--red`).
- Produces: a ✎ button on each card; a single reused `#notePopover`; global `openNotePopover(btn)`, `closeNotePopover()`, `saveNote()` functions.

> Note: this repo has **no JS unit-test harness** (frontend is inline JS in a Python string). Task 3 uses a structural smoke test (asserts the served HTML contains the controls + wiring) plus a manual verification step. This matches the repo's existing testing altitude.

- [ ] **Step 1: Write the failing structural test**

Append to `tests/test_api_note.py`:

```python
def test_dashboard_html_has_note_controls(client):
    html = client.get("/").get_data(as_text=True)
    assert 'id="notePopover"' in html
    assert "note-btn" in html
    assert "openNotePopover" in html
    assert "/api/note" in html   # saveNote() posts here
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_api_note.py::test_dashboard_html_has_note_controls -v`
Expected: FAIL — none of the note-control markers exist in the HTML yet.

- [ ] **Step 3: Add the popover CSS**

In `src/web.py`, inside the main `<style>` block (starts at line 419), add these rules (a good spot is right after the existing `.pushed-dot` / card-badge rules — find `.pushed-dot` and append after its rule block):

```css
.note-btn {
  border: none; background: transparent; cursor: pointer;
  font-size: 14px; padding: 2px 4px; border-radius: 8px;
  color: var(--ink); opacity: 0.4; line-height: 1;
}
.note-btn:hover { opacity: 1; background: rgba(0,0,0,0.06); }
.note-btn.has-note { opacity: 1; color: var(--violet); }
.note-btn.has-note::after {
  content: ""; display: inline-block; width: 6px; height: 6px;
  border-radius: 50%; background: var(--violet); margin-left: 3px; vertical-align: top;
}
.note-popover {
  position: fixed; z-index: 1000; width: 280px;
  background: var(--cream); border: 2px solid var(--ink); border-radius: 14px;
  box-shadow: var(--shadow-hard); padding: 10px;
}
.note-popover textarea {
  width: 100%; box-sizing: border-box; min-height: 70px;
  border: 1.5px solid var(--ink); border-radius: 8px; padding: 6px;
  font-family: inherit; font-size: 13px; resize: vertical;
}
.note-popover .np-foot { display: flex; align-items: center; justify-content: space-between; margin-top: 6px; }
.note-popover .np-count { font-size: 11px; opacity: 0.6; font-family: 'JetBrains Mono', monospace; }
.note-popover .np-actions button { border: 1.5px solid var(--ink); border-radius: 8px; padding: 3px 10px; margin-left: 4px; cursor: pointer; background: var(--cream); }
.note-popover .np-save { background: var(--yellow); }
.note-popover .np-err { color: var(--red); font-size: 11px; margin-top: 4px; min-height: 14px; }
```

- [ ] **Step 4: Add the ✎ button to the card template**

In `src/web.py`, find the card render in `loadVulns` (the `vcard-top` block around line 1010-1017). Add the note button inside `.vcard-top`, immediately after the `pushed-dot` span and before the `vcard-date` span:

```js
          <span class="pushed-dot ${v.pushed?'yes':'no'}" title="${v.pushed?(v.tg_sent?'Sent to Telegram':'Selected for push'):'Filtered'}"></span>
          <button type="button" class="note-btn ${v.note?'has-note':''}" data-key="${esc(v.key)}" data-note="${esc(v.note||'')}" title="${esc(v.note?v.note.slice(0,60):'添加备注')}" onclick="openNotePopover(this)">✎</button>
          <span class="vcard-date">${esc(v.date||'-')}</span>
```

(Only the middle `<button>` line is new; the two surrounding lines are shown as anchors — keep them unchanged.)

- [ ] **Step 5: Add the popover HTML**

In `src/web.py`, find `</body>` (line 1058) and insert this block immediately **before** it:

```html
<div id="notePopover" class="note-popover hidden">
  <textarea id="noteTextarea" maxlength="100" placeholder="使用情况说明…（≤100 字）"></textarea>
  <div class="np-foot">
    <span id="noteCount" class="np-count">0/100</span>
    <span class="np-actions">
      <button type="button" class="np-save" onclick="saveNote()">保存</button>
      <button type="button" onclick="closeNotePopover()">✕</button>
    </span>
  </div>
  <div id="noteErr" class="np-err"></div>
</div>
```

- [ ] **Step 6: Add the popover JS**

In `src/web.py`, find the bootstrap line `loadSources(); loadStats(); loadVulns();` (line 1051) and insert this block immediately **before** it (inside the `<script>`):

```js
// ---- per-card note popover (one open at a time) ----
const notePop = document.getElementById('notePopover');
const noteTa = document.getElementById('noteTextarea');
const noteCount = document.getElementById('noteCount');
const noteErr = document.getElementById('noteErr');
let noteBtnEl = null, noteKey = '';

function refreshNoteBtn(btn, note) {
  btn.dataset.note = note || '';
  btn.classList.toggle('has-note', !!note);
  btn.title = note ? note.slice(0, 60) : '添加备注';
}
function openNotePopover(btn) {
  noteBtnEl = btn; noteKey = btn.dataset.key;
  noteTa.value = btn.dataset.note || '';
  noteErr.textContent = '';
  noteCount.textContent = noteTa.value.length + '/100';
  notePop.classList.remove('hidden');
  const r = btn.getBoundingClientRect();
  const pw = notePop.offsetWidth, ph = notePop.offsetHeight;
  let left = r.left + r.width/2 - pw/2;
  let top = r.bottom + 6;
  if (top + ph > window.innerHeight - 8) top = Math.max(8, r.top - ph - 6);
  left = Math.max(8, Math.min(left, window.innerWidth - pw - 8));
  notePop.style.left = left + 'px';
  notePop.style.top = top + 'px';
  noteTa.focus();
}
function closeNotePopover() {
  notePop.classList.add('hidden');
  noteBtnEl = null; noteKey = '';
}
async function saveNote() {
  if (!noteKey) return;
  const note = noteTa.value.slice(0, 100);
  noteErr.textContent = '';
  try {
    const resp = await fetch('/api/note', {
      method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({key: noteKey, note})
    });
    if (!resp.ok) {
      noteErr.textContent = resp.status === 400 ? '超过 100 字上限' : ('保存失败 (' + resp.status + ')');
      return;
    }
    if (noteBtnEl) refreshNoteBtn(noteBtnEl, note);
    closeNotePopover();
  } catch (e) {
    noteErr.textContent = '网络错误';
  }
}
noteTa.addEventListener('input', () => { noteCount.textContent = noteTa.value.length + '/100'; });
document.addEventListener('click', (e) => {
  if (notePop.classList.contains('hidden')) return;
  if (notePop.contains(e.target) || (noteBtnEl && noteBtnEl.contains(e.target))) return;
  closeNotePopover();
});
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && !notePop.classList.contains('hidden')) closeNotePopover();
});

```

- [ ] **Step 7: Run the structural test to verify it passes**

Run: `python -m pytest tests/test_api_note.py::test_dashboard_html_has_note_controls -v`
Expected: PASS.

- [ ] **Step 8: Run the full suite**

Run: `python -m pytest -q`
Expected: PASS — all tests green.

- [ ] **Step 9: Manual verification (real UX check)**

```bash
python src/vuln_monitor.py fetch --no-push   # ensure a DB with rows exists
python src/web.py                             # http://127.0.0.1:8001
```
Open the dashboard, and confirm:
- Each card shows a faint ✎; clicking it opens a popover anchored below (or above, near the bottom) the icon.
- Type a note (try Chinese + the `NN/100` counter), click 保存 → popover closes, ✎ turns violet with a dot, hover shows the text.
- Click ✎ again → popover repopulates with the saved text; clear it + 保存 → ✎ returns to faint (note = NULL).
- Paste >100 chars → 保存 shows "超过 100 字上限" (textarea also blocks at 100 via `maxlength`).
- Press Esc / click outside → popover closes.
- Reload the page → the note persists (read from `/api/vulns`).

- [ ] **Step 10: Commit**

```bash
git add src/web.py tests/test_api_note.py
git commit -m "feat(web): 卡片备注 popover 编辑器

每张卡片 ✎ 控件，点击弹出锚定 popover（textarea + 100 字计数 +
保存/取消）；Esc/点外部关闭；备注文本一律过 esc()，不 innerHTML。

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## Self-Review (completed)

**Spec coverage:** every spec section maps to a task —
- Data model (`note TEXT`, idempotent `ALTER TABLE`) → Task 1 Step 3 (init_db) + Step 4 (endpoint auto-migrate, tested by `test_auto_migrates_note_column`).
- `POST /api/note` (key/no-key, ≤100/400, empty→NULL, parameterized, 3× retry→503, 0-row = 200) → Task 1.
- `GET /api/vulns` exposes `note` (guarded) → Task 2.
- `GET /api/pending` excludes `note` → Task 2 (`test_pending_excludes_note`).
- Frontend ✎ control + popover + `esc()` render + no `innerHTML` raw → Task 3.
- Security tests (XSS stored verbatim) → Task 1 (`test_xss_payload_stored_verbatim`); structural wiring → Task 3.
- Out-of-scope items (has_note filter, timestamp, CLI, markdown) intentionally absent — matches spec YAGNI.

**Placeholder scan:** none — every code step contains complete code; manual-verification step lists concrete actions with expected outcomes.

**Type/name consistency:** endpoint path `/api/note`, request keys `key`/`note`, response `{"ok","key","note"}`, JS ids `notePopover`/`noteTextarea`/`noteCount`/`noteErr`, functions `openNotePopover`/`closeNotePopover`/`saveNote`/`refreshNoteBtn`, CSS class `note-btn`/`has-note`/`note-popover` — identical across all tasks and the structural test. `note` column name consistent in init_db, endpoint, `/api/vulns`, and tests.
