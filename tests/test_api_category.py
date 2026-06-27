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
    conn.executemany("INSERT INTO vulns VALUES (" + ",".join(["?"] * 25) + ")", rows)
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
