# Per-Card Notes (备注) for vuln-monitor Dashboard

**Date:** 2026-07-04
**Status:** Design — approved, pending implementation

## Goal

Add an editable free-text note (≤100 chars) to each vulnerability card on the web dashboard, so the operator can record per-CVE operational context (e.g. "在野利用确认，配合 Cobalt Strike 使用", patch status, asset exposure). Notes are personal to the dashboard owner and editable in-place.

## Background / decisions (locked in brainstorming)

- **Display model B**: every card shows a persistent ✎ control. Empty = faint "add note"; has-note = solid + indicator dot. The note text is NOT shown as a line on the card (only the icon); content is revealed inside the editor.
- **Editor = popover**, anchored to the ✎ icon (non-disruptive to the card grid; fast for frequent edits).
- **Note attaches to the row `key`** → effectively per-CVE for CVE-bearing records (the same `cve:<CVE>` key collapses cross-source duplicates into one row). Non-CVE records (`adv:` / sha1 keys) get their own note.
- **≤100 chars**, enforced server-side; over-length is rejected (400), not silently truncated.
- An empty note is stored as `NULL` (cleared).
- **Security**: SQLi prevented via parameterized queries; XSS via `esc()` on all render paths + existing CSP as defense-in-depth; notes excluded from `/api/pending` (B-side feed).

## Components

### 1. Data model — `src/vuln_monitor.py` `init_db()`

Add a nullable column via the existing idempotent migration pattern (same as `reproduced`):

```python
if "note" not in cols:
    conn.execute("ALTER TABLE vulns ADD COLUMN note TEXT")
```

No `note_updated_at` in v1 (YAGNI). Empty = `NULL`.

### 2. API — `src/web.py`

**`POST /api/note`** — mirrors `/api/reproduced` (lines 351-372):
- Body: `{"key": "<row key>", "note": "<text>"}`
- Validation:
  - `key` non-empty after `.strip()` → else 400.
  - `note = (data.get("note") or "").strip()`.
  - `len(note) > 100` → 400 `{"error": "note too long (max 100)"}`. Count = Python `len()`, consistent with JS `.length` for BMP/CJK.
  - `note == ""` → store `NULL` (clear); else store the string.
- Auto-migrate the `note` column if missing (via `_vulns_columns`).
- `UPDATE vulns SET note=? WHERE key=?` (parameterized). An UPDATE affecting 0 rows is **not** an error — return 200 (matches `/api/reproduced`'s permissive style; the no-op is idempotent and safe).
- 3× retry on `sqlite3.OperationalError`, 503 on final.
- Response: `{"ok": true, "key": key, "note": <string or null>}`.

**`GET /api/vulns`**: add `"note"` to `optional_cols` (around line 292) and include it in the response object using the existing guarded pattern:
```python
has_note = "note" in cols_avail
...
"note": r["note"] if has_note else None,
```
This endpoint is owner-auth-gated (same token as the dashboard).

**`GET /api/pending`**: UNCHANGED. Its fixed SELECT does not include `note`, so notes never reach the B-side dispatcher. This is an invariant — no code change, but it must be preserved when editing that route.

**Length validation is server-side** (source of truth). The client counter is UX-only.

### 3. Frontend — `src/web.py` (`DASHBOARD_HTML`, inline JS/HTML)

**Card ✎ control** (in `vcard-top`, near the pushed-dot):
- `<button class="note-btn" data-key="...">` showing ✎. Class `has-note` when `v.note` is truthy (solid icon + dot); otherwise faint.
- `title` attribute = first ~60 chars of the note, `esc()`-escaped, for hover preview.

**Popover editor** (at most one open at a time):
- Absolutely positioned, anchored below/above the ✎ icon (flip if near a viewport edge; on narrow widths < threshold, fall back to a centered sheet).
- Contains: `<textarea maxlength="100">`, a live `NN/100` counter, Save + ✕ buttons.
- Open: populate the textarea with the current note. Close: Esc, click-outside, ✕, or Save.
- Save → `fetch('/api/note', {method:'POST', body: JSON.stringify({key, note})})`; on ok → update the card's `v.note`, toggle `has-note`, refresh the `title`, close. On 400/503 → show an inline error, keep the popover open.
- Cancel / ✕ / Esc / click-outside with unsaved changes → discard (no confirm; keep simple).
- All note text rendered through `esc()`. Never set raw note via `innerHTML`. The textarea is a form control populated via `.value`.

**Counter**: `textarea.value.length` / 100, updated live on `input`.

### 4. Security

- **SQL injection**: parameterized `UPDATE vulns SET note=? WHERE key=?`. No string interpolation into SQL (same as `/api/reproduced`).
- **XSS**: note stored raw; rendered exclusively via `esc()` (the `title` attribute and the popover). A `<script>` payload becomes inert escaped text. Defense-in-depth: the existing CSP blocks script execution; no `innerHTML` of raw note anywhere. The textarea value is set via the `.value` property, not parsed as HTML.
- **Auth**: `/api/note` sits behind the existing `@before_request check_token` — open on loopback, token-gated in public mode (same as every other endpoint). Single-user tool; no per-user model.
- **Privacy**: `note` is not added to the `/api/pending` SELECT → never exposed to the B-side dispatcher.
- **Length DoS / abuse**: server-side 100-char cap; over-length → 400 (explicit, not silent truncation).

### 5. Testing — `tests/test_api_note.py` (new)

Mirror the style of `tests/test_api_pending.py`:
- Save + read back round-trip via `/api/vulns`.
- `len(note) > 100` → 400.
- Empty string → note becomes `NULL` (read back null/absent).
- Missing `key` → 400.
- **XSS invariant**: store `<script>alert(1)</script>` → stored verbatim and returned verbatim (assert equality), proving no execution/interpretation at the storage layer.
- `/api/pending` response objects do NOT include a `note` field.
- (If feasible) the concurrent-write retry / 503 path.

Optionally extend `tests/test_web_access.py` with a dedicated auth-gate assertion for `/api/note`; otherwise it inherits the global `check_token` behavior.

## Out of scope (YAGNI for v1)

- "Show only cards with notes" filter (`has_note` pill).
- `note_updated_at` / edit history.
- Notes in the CLI `query` / `brief` output.
- Rich text / markdown rendering (plain text only).
- Per-source note (the note is per-row / per-CVE, not per-source instance).

## Risks / notes

- Popover positioning in the responsive single-column (narrow) layout: anchor + flip must handle a narrow viewport; fall back to a centered sheet below a width threshold.
- `<textarea maxlength=100>` and server `len()` agree for BMP/CJK (1 unit each); rare non-BMP emoji would differ by surrogate pairs — acceptable, out of scope.
