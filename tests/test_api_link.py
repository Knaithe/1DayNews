"""Tests for /api/vulns url serialization with space-joined GHSA link fields.

GHSA items deliberately store "advisory-url ref1 ref2 ..." in `link` (WP
detection, sources.fetch_ghsa). The API must serve only the first token as
the clickable url; the full field stays in the DB for pattern matching.
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
        cvss_vector TEXT, cvss_pr TEXT
    )""")
    now = datetime.now(timezone.utc).timestamp()
    blob = ("https://github.com/advisories/GHSA-x https://nvd.nist.gov/vuln/detail/CVE-2026-1 "
            "https://patchstack.com/database/wordpress/vulnerability/x")
    rows = [
        ("k1", "CVE-2026-1", "GHSA", "multi-url link", blob, "s", "RCE+asset+CVE", "RCE",
         "RCE", "1day", None, 0, now, "2026-06-20", "critical", 9.8, 0, None, None, 0, 0, 0, 0, None, "N"),
        ("k2", "CVE-2026-2", "ZDI", "single url", "https://zdi.example/a", "s", "RCE+CVE", "RCE",
         "RCE", "1day", None, 0, now, "2026-06-19", "high", 8.0, 0, None, None, 0, 0, 0, 0, None, "N"),
        ("k3", "CVE-2026-3", "GHSA", "null link", None, "s", "RCE+CVE", "RCE",
         "RCE", "1day", None, 0, now, "2026-06-18", "high", 8.0, 0, None, None, 0, 0, 0, 0, None, "N"),
    ]
    conn.executemany("INSERT INTO vulns VALUES (" + ",".join(["?"] * 25) + ")", rows)
    conn.commit(); conn.close()

    web_mod.DB_FILE = db_path
    web_mod.TOKEN_FILE = tmp_path / ".web_token"
    web_mod._MAGIC_TOKEN = "test-token"
    web_mod._LOOPBACK_MODE = True
    web_mod.app.config["TESTING"] = True
    yield web_mod.app.test_client()


def test_multi_url_link_serves_first_token(client):
    data = client.get("/api/vulns").get_json()
    row = next(d for d in data if d["key"] == "k1")
    assert row["url"] == "https://github.com/advisories/GHSA-x"
    assert " " not in row["url"]


def test_single_url_and_null_link_untouched(client):
    data = client.get("/api/vulns").get_json()
    row2 = next(d for d in data if d["key"] == "k2")
    row3 = next(d for d in data if d["key"] == "k3")
    assert row2["url"] == "https://zdi.example/a"
    assert row3["url"] == ""
