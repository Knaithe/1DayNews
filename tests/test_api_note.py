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
        cvss_vector TEXT, cvss_pr TEXT, reproduced INTEGER DEFAULT 0
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
    web_mod.FETCH_STATE_FILE = tmp_path / "fetch_state.json"
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
    resp = client.post("/api/note", json={"key": "cve:CVE-2026-1001", "note": "x" * 201})
    assert resp.status_code == 400
    assert "max 200" in resp.get_json()["error"]


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


def test_dashboard_html_has_note_controls(client):
    html = client.get("/").get_data(as_text=True)
    assert 'id="noteModal"' in html
    assert "openNoteModal" in html
    assert "dblclick" in html          # double-click a card opens the modal
    assert "/api/note" in html         # saveNote() posts here


def test_save_then_readback_via_api(client):
    # E2E HTTP round-trip: POST /api/note then GET /api/vulns reflects it
    resp = client.post("/api/note", json={"key": "cve:CVE-2026-1001", "note": "E2E round trip"})
    assert resp.status_code == 200
    row = next(d for d in client.get("/api/vulns").get_json() if d["key"] == "cve:CVE-2026-1001")
    assert row["note"] == "E2E round trip"


def test_save_strips_and_returns_server_value(client):
    # server stores the stripped value and returns it (keeps the client aligned)
    resp = client.post("/api/note", json={"key": "cve:CVE-2026-1001", "note": "  hi  "})
    assert resp.status_code == 200
    assert resp.get_json()["note"] == "hi"


def test_save_unknown_key_returns_404(client):
    resp = client.post("/api/note", json={"key": "cve:DOES-NOT-EXIST", "note": "x"})
    assert resp.status_code == 404


def test_note_non_string_rejected_400(client):
    resp = client.post("/api/note", json={"key": "cve:CVE-2026-1001", "note": 123})
    assert resp.status_code == 400
    assert "string" in resp.get_json()["error"]


def test_reproduced_uses_shared_helper(client):
    # /api/reproduced shares _set_vuln_field — write, 404 unknown key, input validation
    assert client.post("/api/reproduced", json={"key": "cve:CVE-2026-1001", "reproduced": 1}).status_code == 200
    assert client.post("/api/reproduced", json={"key": "cve:DOES-NOT-EXIST", "reproduced": 1}).status_code == 404
    assert client.post("/api/reproduced", json={"key": "cve:CVE-2026-1001", "reproduced": "abc"}).status_code == 400
    assert client.post("/api/reproduced", data="[1,2]", content_type="application/json").status_code == 400


class _RaiseOnEnter:
    """Fake get_db_rw() return that raises OperationalError on __enter__."""
    def __init__(self, msg): self.msg = msg
    def __enter__(self): raise sqlite3.OperationalError(self.msg)
    def __exit__(self, *a): return False


def test_note_persistent_lock_returns_503(client, monkeypatch):
    monkeypatch.setattr("time.sleep", lambda s: None)   # don't really wait between retries
    monkeypatch.setattr(web_mod, "get_db_rw", lambda: _RaiseOnEnter("database is locked"))
    assert client.post("/api/note", json={"key": "cve:CVE-2026-1001", "note": "x"}).status_code == 503


def test_note_nonbusy_operational_error_not_swallowed(client, monkeypatch):
    # a non-lock OperationalError must propagate (→500 in prod), not be caught and
    # mislabeled "database busy" 503. Under TESTING it propagates as an exception.
    monkeypatch.setattr(web_mod, "get_db_rw", lambda: _RaiseOnEnter("no such column: bogus"))
    with pytest.raises(sqlite3.OperationalError):
        client.post("/api/note", json={"key": "cve:CVE-2026-1001", "note": "x"})


def test_note_duplicate_column_race_retries_to_success(client, monkeypatch):
    # "duplicate column name" (concurrent first-write ALTER race) is retried, not 500'd
    monkeypatch.setattr("time.sleep", lambda s: None)
    real = web_mod.get_db_rw
    calls = {"n": 0}
    class _DupOnce:
        def __init__(self): self.real = real()
        def __enter__(self):
            calls["n"] += 1
            if calls["n"] == 1:
                raise sqlite3.OperationalError("duplicate column name: note")
            return self.real.__enter__()
        def __exit__(self, *a): return self.real.__exit__(*a)
    monkeypatch.setattr(web_mod, "get_db_rw", _DupOnce)
    assert client.post("/api/note", json={"key": "cve:CVE-2026-1001", "note": "ok"}).status_code == 200


def test_stats_fetch_field_from_state_file(client, tmp_path):
    # daemon writes fetch_state.json → /api/stats surfaces it (collected coerced to int)
    (tmp_path / "fetch_state.json").write_text(
        '{"ts":"2026-07-06T02:17:38+00:00","collected":6046,"new":1,"pushed":0}', encoding="utf-8")
    f = client.get("/api/stats").get_json()["fetch"]
    assert f["collected"] == 6046
    assert f["ts"].startswith("2026-07-06")


def test_stats_fetch_rejects_malformed_state(client, tmp_path):
    # non-dict file → fetch:null (graceful); string collected → coerced to None (XSS hardening)
    (tmp_path / "fetch_state.json").write_text('"not-a-dict"', encoding="utf-8")
    assert client.get("/api/stats").get_json()["fetch"] is None
    (tmp_path / "fetch_state.json").write_text('{"ts":"x","collected":"<img src=x>"}', encoding="utf-8")
    assert client.get("/api/stats").get_json()["fetch"]["collected"] is None
