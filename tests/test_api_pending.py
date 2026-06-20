"""Tests for /api/pending and /api/ack endpoints."""
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
        cvss_vector TEXT, cvss_pr TEXT, dispatched INTEGER DEFAULT 0
    )""")
    now = datetime.now(timezone.utc).timestamp()
    rows = [
        ("k1", "CVE-2026-1001", "CISA_KEV", "RCE in FortiGate", "https://example.com/1",
         "Critical RCE", "RCE+asset+CVE", "RCE", "1day", None, 1, now, "2026-06-18",
         "critical", 9.8, 0, None, None, 1, 0, 0, 0, None, "N", 0),
        ("k2", "CVE-2026-1002", "Sploitus_Citrix", "Auth bypass Nezha", "https://example.com/2",
         "Unauth file read", "bypass+CVE", "bypass", "1day", None, 1, now - 86400, "2026-06-17",
         "high", 9.1, 0, None, None, 1, 0, 0, 0, None, "N", 0),
        ("k3", "CVE-2026-1003", "ZDI", "Info disclosure", "https://example.com/3",
         "Low sev info leak", "no hit", None, None, None, 0, now - 200, "2026-06-16",
         "medium", 5.0, 0, None, None, 0, 0, 0, 0, None, None, 0),
        ("k4", "CVE-2026-1004", "watchTowr", "Already dispatched", "https://example.com/4",
         "Dispatched RCE", "RCE+CVE", "RCE", "1day", None, 1, now - 50, "2026-06-18",
         "critical", 10.0, 0, None, None, 1, 0, 0, 0, None, "N", 1),
    ]
    conn.executemany(
        "INSERT INTO vulns VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows
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
    def test_returns_only_pushed_undispatched(self, client):
        resp = client.get("/api/pending")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        cve_ids = [v["cve_id"] for v in data["vulns"]]
        assert "CVE-2026-1001" in cve_ids
        assert "CVE-2026-1002" in cve_ids
        # not pushed
        assert "CVE-2026-1003" not in cve_ids
        # already dispatched
        assert "CVE-2026-1004" not in cve_ids

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
        # both CVE-1001 (now) and CVE-1002 (now-1day) within 7 days
        resp = client.get("/api/pending")
        data = json.loads(resp.data)
        cve_ids = [v["cve_id"] for v in data["vulns"]]
        assert "CVE-2026-1001" in cve_ids
        assert "CVE-2026-1002" in cve_ids

    def test_limit(self, client):
        resp = client.get("/api/pending?limit=1")
        data = json.loads(resp.data)
        assert data["count"] == 1
        assert data["vulns"][0]["cvss"] == 9.8

    def test_response_fields(self, client):
        resp = client.get("/api/pending")
        data = json.loads(resp.data)
        v = data["vulns"][0]
        for field in ("cve_id", "title", "source", "link", "summary",
                       "vuln_type", "cvss", "severity", "reason", "created_at"):
            assert field in v, f"missing field: {field}"

    def test_empty_when_no_dispatched_column(self, client, tmp_path):
        """Graceful degradation when DB has no dispatched column."""
        db2 = tmp_path / "vuln_cache_nodispatch.db"
        conn = sqlite3.connect(str(db2))
        conn.execute("""CREATE TABLE vulns (
            key TEXT, cve_id TEXT, source TEXT, title TEXT, link TEXT,
            summary TEXT, reason TEXT, pushed INTEGER DEFAULT 0,
            created_at REAL, cve_published TEXT, severity TEXT, cvss REAL
        )""")
        conn.execute("INSERT INTO vulns VALUES ('k','CVE-X','s','t','l','sum','RCE',1,1750000000,'2026-01-01','high',9.0)")
        conn.commit()
        conn.close()
        web_mod.DB_FILE = db2
        resp = client.get("/api/pending")
        data = json.loads(resp.data)
        assert data["count"] == 0


class TestAPIAck:
    def test_ack_marks_dispatched(self, client, tmp_path):
        resp = client.post("/api/ack", json={"cve_ids": ["CVE-2026-1001"]})
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["acked"] == 1

        # verify it no longer appears in pending
        resp2 = client.get("/api/pending")
        data2 = json.loads(resp2.data)
        cve_ids = [v["cve_id"] for v in data2["vulns"]]
        assert "CVE-2026-1001" not in cve_ids

    def test_ack_multiple(self, client):
        resp = client.post("/api/ack", json={"cve_ids": ["CVE-2026-1001", "CVE-2026-1002"]})
        assert resp.status_code == 200

        resp2 = client.get("/api/pending")
        data2 = json.loads(resp2.data)
        assert data2["count"] == 0

    def test_ack_nonexistent_cve(self, client):
        resp = client.post("/api/ack", json={"cve_ids": ["CVE-0000-0000"]})
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["acked"] == 0

    def test_ack_missing_body(self, client):
        resp = client.post("/api/ack")
        assert resp.status_code == 400

    def test_ack_empty_list(self, client):
        resp = client.post("/api/ack", json={"cve_ids": []})
        assert resp.status_code == 400

    def test_ack_wrong_type(self, client):
        resp = client.post("/api/ack", json={"cve_ids": "not-a-list"})
        assert resp.status_code == 400

    def test_ack_idempotent(self, client):
        resp1 = client.post("/api/ack", json={"cve_ids": ["CVE-2026-1001"]})
        assert json.loads(resp1.data)["acked"] == 1
        resp2 = client.post("/api/ack", json={"cve_ids": ["CVE-2026-1001"]})
        assert json.loads(resp2.data)["acked"] == 0

    def test_ack_returns_actual_rowcount(self, client):
        resp = client.post("/api/ack", json={"cve_ids": ["CVE-2026-1001", "CVE-0000-FAKE"]})
        data = json.loads(resp.data)
        assert data["acked"] == 1

    def test_ack_over_limit(self, client):
        ids = [f"CVE-2026-{i:04d}" for i in range(101)]
        resp = client.post("/api/ack", json={"cve_ids": ids})
        assert resp.status_code == 400


class TestBearerAuth:
    def test_bearer_pending(self, app, tmp_path):
        web_mod._MAGIC_TOKEN = "test-secret-token"
        c = app.test_client()
        # no token → 403
        resp = c.get("/api/pending")
        assert resp.status_code == 403
        # bearer token → 200
        resp = c.get("/api/pending", headers={"Authorization": "Bearer test-secret-token"})
        assert resp.status_code == 200
        # wrong token → 403
        resp = c.get("/api/pending", headers={"Authorization": "Bearer wrong"})
        assert resp.status_code == 403

    def test_bearer_ack(self, app, tmp_path):
        web_mod._MAGIC_TOKEN = "test-secret-token"
        c = app.test_client()
        resp = c.post("/api/ack", json={"cve_ids": ["CVE-2026-1001"]},
                       headers={"Authorization": "Bearer test-secret-token"})
        assert resp.status_code == 200

    def test_query_param_still_works(self, app, tmp_path):
        web_mod._MAGIC_TOKEN = "test-secret-token"
        c = app.test_client()
        resp = c.get("/api/pending?token=test-secret-token")
        assert resp.status_code == 200
