"""Tests for /api/vulns default hiding of reason='excluded' records.

Excluded records (WP ecosystem / noise patterns) are push-pipeline rejects:
they must not clutter the default browse view or the category stats, but stay
auditable via an explicit ?reason=excluded query.
"""
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
        cvss_vector TEXT, cvss_pr TEXT, reproduced INTEGER DEFAULT 0
    )""")
    now = datetime.now(timezone.utc).timestamp()
    rows = [
        ("k1", "CVE-2026-1", "GHSA", "RCE in Foo", "u1", "rce", "RCE+asset+CVE", "RCE",
         "RCE", "1day", None, 0, now, "2026-06-20", "critical", 9.8, 0, None, None, 0, 0, 0, 0, None, "N", 0),
        # excluded WP plugin record, keyword-categorized as RCE by design —
        # must still stay out of the default view
        ("k2", "CVE-2026-59544", "GHSA", "PHP Object Injection in Thrive Quiz Builder", "u2",
         "wp plugin", "excluded", "RCE", "RCE", "1day", None, 0, now, "2026-06-19",
         "critical", 9.8, 1, "confirmed", None, 0, 0, 0, 0, None, "N", 0),
        ("k3", "CVE-2026-3", "GHSA", "no reason yet", "u3", "t", None, None,
         None, "1day", None, 0, now, "2026-06-18", "high", 8.0, 0, None, None, 0, 0, 0, 0, None, "N", 0),
    ]
    conn.executemany("INSERT INTO vulns VALUES (" + ",".join(["?"] * 26) + ")", rows)
    conn.commit(); conn.close()

    web_mod.DB_FILE = db_path
    web_mod.TOKEN_FILE = tmp_path / ".web_token"
    web_mod._MAGIC_TOKEN = "test-token"
    web_mod._LOOPBACK_MODE = True
    web_mod.app.config["TESTING"] = True
    yield web_mod.app.test_client()


def test_default_view_hides_excluded(client):
    data = client.get("/api/vulns").get_json()
    ids = sorted(d["id"] for d in data)
    assert ids == ["CVE-2026-1", "CVE-2026-3"]  # excluded record hidden


def test_excluded_hidden_from_category_view(client):
    data = client.get("/api/vulns?category=RCE").get_json()
    ids = [d["id"] for d in data]
    assert ids == ["CVE-2026-1"]


def test_excluded_auditable_via_explicit_reason(client):
    data = client.get("/api/vulns?reason=excluded").get_json()
    ids = [d["id"] for d in data]
    assert ids == ["CVE-2026-59544"]


def test_stats_categories_skip_excluded(client):
    data = client.get("/api/stats").get_json()
    # k2's RCE category must not inflate the visible count
    assert data["categories"]["RCE"] == 1
    assert data["total"] == 3  # total is a DB-size diagnostic — unfiltered
