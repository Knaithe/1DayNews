"""Tests for /api/pending endpoint."""
import json
import sqlite3
import tempfile
import os
from datetime import datetime, timezone
import pytest

os.environ.setdefault("VULN_DATA_DIR", "")

import src.web as web_mod


@pytest.fixture
def app(tmp_path):
    db_path = tmp_path / "vuln_cache.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute("""CREATE TABLE vulns (
        key TEXT, cve_id TEXT, source TEXT, title TEXT, link TEXT,
        summary TEXT, reason TEXT, vuln_type TEXT, freshness TEXT,
        freshness_reason TEXT, pushed INTEGER DEFAULT 0,
        created_at REAL, cve_published TEXT, severity TEXT, cvss REAL,
        llm_verified INTEGER DEFAULT 0, llm_verdict TEXT, llm_notes TEXT,
        tg_sent INTEGER DEFAULT 0, wecom_sent INTEGER DEFAULT 0,
        dingtalk_sent INTEGER DEFAULT 0, feishu_sent INTEGER DEFAULT 0,
        cvss_vector TEXT, cvss_pr TEXT
    )""")
    now = datetime.now(timezone.utc).timestamp()
    rows = [
        ("k1", "CVE-2026-1001", "CISA_KEV", "RCE in FortiGate", "https://example.com/1",
         "Critical RCE", "RCE+asset+CVE", "RCE", "1day", None, 1, now, "2026-06-18",
         "critical", 9.8, 0, None, None, 1, 0, 0, 0, None, "N"),
        ("k2", "CVE-2026-1002", "Sploitus_Citrix", "Auth bypass Nezha", "https://example.com/2",
         "Unauth file read", "bypass+CVE", "bypass", "1day", None, 1, now - 86400, "2026-06-17",
         "high", 9.1, 0, None, None, 1, 0, 0, 0, None, "N"),
        ("k3", "CVE-2026-1003", "ZDI", "Info disclosure", "https://example.com/3",
         "Low sev info leak", "no hit", None, None, None, 0, now - 200, "2026-06-16",
         "medium", 5.0, 0, None, None, 0, 0, 0, 0, None, None),
        ("k4", "CVE-2026-1004", "watchTowr", "Another RCE", "https://example.com/4",
         "Pushed RCE", "RCE+CVE", "RCE", "1day", None, 1, now - 50, "2026-06-18",
         "critical", 10.0, 0, None, None, 1, 0, 0, 0, None, "N"),
    ]
    conn.executemany(
        "INSERT INTO vulns VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows
    )
    conn.commit()
    conn.close()

    web_mod.DB_FILE = db_path
    web_mod.TOKEN_FILE = tmp_path / ".web_token"
    web_mod._MAGIC_TOKEN = None
    web_mod.app.config["TESTING"] = True
    yield web_mod.app


@pytest.fixture
def client(app):
    return app.test_client()


class TestAPIPending:
    def test_returns_only_pushed(self, client):
        resp = client.get("/api/pending")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        cve_ids = [v["cve_id"] for v in data["vulns"]]
        assert "CVE-2026-1001" in cve_ids
        assert "CVE-2026-1002" in cve_ids
        assert "CVE-2026-1004" in cve_ids
        # not pushed
        assert "CVE-2026-1003" not in cve_ids

    def test_count_matches_vulns(self, client):
        resp = client.get("/api/pending")
        data = json.loads(resp.data)
        assert data["count"] == len(data["vulns"])

    def test_ordered_by_time_desc(self, client):
        resp = client.get("/api/pending")
        data = json.loads(resp.data)
        times = [v["created_at"] for v in data["vulns"]]
        assert times == sorted(times, reverse=True)

    def test_7day_window(self, client):
        resp = client.get("/api/pending")
        data = json.loads(resp.data)
        cve_ids = [v["cve_id"] for v in data["vulns"]]
        assert "CVE-2026-1001" in cve_ids
        assert "CVE-2026-1002" in cve_ids

    def test_returns_all_pushed(self, client):
        resp = client.get("/api/pending")
        data = json.loads(resp.data)
        assert data["count"] == 3

    def test_response_fields(self, client):
        resp = client.get("/api/pending")
        data = json.loads(resp.data)
        v = data["vulns"][0]
        for field in ("cve_id", "title", "source", "link", "summary",
                       "vuln_type", "cvss", "severity", "reason", "created_at"):
            assert field in v, f"missing field: {field}"


class TestBearerAuth:
    def test_bearer_pending(self, app, tmp_path):
        web_mod._MAGIC_TOKEN = "test-secret-token"
        c = app.test_client()
        resp = c.get("/api/pending")
        assert resp.status_code == 403
        resp = c.get("/api/pending", headers={"Authorization": "Bearer test-secret-token"})
        assert resp.status_code == 200
        resp = c.get("/api/pending", headers={"Authorization": "Bearer wrong"})
        assert resp.status_code == 403

    def test_query_param_still_works(self, app, tmp_path):
        web_mod._MAGIC_TOKEN = "test-secret-token"
        c = app.test_client()
        resp = c.get("/api/pending?token=test-secret-token")
        assert resp.status_code == 200
