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
