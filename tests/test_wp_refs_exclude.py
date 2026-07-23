"""Tests for WordPress-ecosystem exclusion via NVD/GitHub reference URLs.

Patchstack-sourced WP plugin vulns often never mention "WordPress" in the
description (e.g. CVE-2026-59544 "Unauthenticated PHP Object Injection in
Thrive Quiz Builder"), so the text/link layers in score() miss them. The
tell-tale patchstack/wordfence/wpscan reference URL is checked when NVD
detail is fetched (backfill / freshness) — see nvd._nvd_refs_wp_excluded.
"""
import os
os.environ.setdefault("VULN_DATA_DIR", "")

import src.nvd as nvd
from src.db import init_db


# --- reference extraction in _nvd_detail (NVD path + GitHub fallback) ---

class _Resp:
    def __init__(self, payload, status=200):
        self.status_code = status
        self._payload = payload

    def json(self):
        return self._payload


class _FakeSess:
    """Queue of responses for sequential SESS.get calls."""
    def __init__(self, *resps):
        self._resps = list(resps)

    def get(self, *a, **kw):
        return self._resps.pop(0)


def _patch_common(monkeypatch, *resps):
    monkeypatch.setattr(nvd, "SESS", _FakeSess(*resps))
    monkeypatch.setattr(nvd, "_nvd_cache", {})
    monkeypatch.setattr(nvd, "_nvd_detail_cache", {})
    monkeypatch.setattr("time.sleep", lambda s: None)


def test_nvd_detail_extracts_references(monkeypatch):
    payload = {"vulnerabilities": [{"cve": {
        "published": "2026-07-23T12:18:33.313",
        "descriptions": [{"lang": "en", "value": "d"}],
        "metrics": {"cvssMetricV31": [{"cvssData": {
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
        "references": [
            {"url": "https://patchstack.com/database/wordpress/plugin/thrive-quiz-builder/vulnerability/x"},
            {"url": "https://nvd.nist.gov/vuln/detail/CVE-2026-59544"},
        ],
    }}]}
    _patch_common(monkeypatch, _Resp(payload))
    detail = nvd._nvd_detail("CVE-2026-59544")
    assert "patchstack.com/database/wordpress" in detail["references"]


def test_nvd_detail_github_fallback_extracts_references(monkeypatch):
    # NVD empty → GitHub Advisory fallback (references are plain strings there)
    gh = [{"published_at": "2026-07-22T00:00:00Z", "severity": "critical",
           "cvss": {"score": 9.8, "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
           "description": "d", "summary": "s",
           "references": ["https://patchstack.com/database/wordpress/plugin/x"]}]
    _patch_common(monkeypatch, _Resp({"vulnerabilities": []}), _Resp(gh))
    detail = nvd._nvd_detail("CVE-2026-59544")
    assert "patchstack.com/database/wordpress" in detail["references"]


# --- _nvd_refs_wp_excluded helper (cache-only, no HTTP) ---

def test_refs_helper(monkeypatch):
    monkeypatch.setattr(nvd, "_nvd_detail_cache", {
        "CVE-2026-59544": {"references": "https://patchstack.com/database/wordpress/plugin/x"},
        "CVE-2026-1": {"references": "https://example.com/advisory"},
        "CVE-2026-2": {"published": "2026-01-01"},  # no references key
    })
    assert nvd._nvd_refs_wp_excluded("CVE-2026-59544") is True
    assert nvd._nvd_refs_wp_excluded("cve-2026-59544") is True  # case-insensitive
    assert nvd._nvd_refs_wp_excluded("CVE-2026-1") is False
    assert nvd._nvd_refs_wp_excluded("CVE-2026-2") is False
    assert nvd._nvd_refs_wp_excluded("CVE-2026-99999") is False  # not cached
    assert nvd._nvd_refs_wp_excluded(None) is False
    assert nvd._nvd_refs_wp_excluded("") is False


# --- backfill applies the exclusion ---

def _insert(conn, key, cve, reason, vuln_type, pushed):
    conn.execute(
        "INSERT INTO vulns (key,cve_id,source,title,link,summary,reason,vuln_type,"
        "freshness,pushed,created_at,cvss_pr,llm_verified) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,0)",
        (key, cve, "DailyCVE", "t", "https://dailycve.example/x", "s",
         reason, vuln_type, "1day", pushed, 1000.0, "N"),
    )


def test_backfill_excludes_wp_via_references(tmp_path, monkeypatch):
    import sqlite3
    import src.config as cfg
    monkeypatch.setattr(cfg, "DEEPSEEK_API_KEY", "")
    monkeypatch.setattr(cfg, "OPENAI_API_KEY", "")
    conn = sqlite3.connect(str(tmp_path / "t.db"))
    init_db(conn)
    _insert(conn, "wp", "CVE-2026-59544", "RCE+asset+CVE", "RCE", 1)
    _insert(conn, "ctl", "CVE-2026-11111", "RCE+CVE", "RCE", 0)
    conn.commit()
    fake = {
        "CVE-2026-59544": {"published": "2026-07-23", "cvss": 9.8, "severity": "critical",
                           "description": "Unauthenticated PHP Object Injection in Thrive Quiz Builder",
                           "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                           "references": "https://patchstack.com/database/wordpress/plugin/thrive-quiz-builder/vulnerability/x"},
        "CVE-2026-11111": {"published": "2026-07-20", "cvss": 9.1, "severity": "critical",
                           "description": "RCE in some appliance",
                           "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                           "references": "https://vendor.example.com/advisory/1"},
    }
    monkeypatch.setattr(nvd, "_nvd_detail", lambda c: fake[c])
    nvd._backfill_nvd_severity(conn)

    reason, pushed, severity, cvss = conn.execute(
        "SELECT reason, pushed, severity, cvss FROM vulns WHERE key='wp'").fetchone()
    assert reason == "excluded"
    assert pushed == 0
    assert severity == "critical"   # severity still backfilled for dashboard browse
    assert cvss == 9.8

    # control record: untouched reason, still promotable via regex path (PR=N)
    reason, pushed = conn.execute(
        "SELECT reason, pushed FROM vulns WHERE key='ctl'").fetchone()
    assert reason == "RCE+CVE"
    assert pushed == 1
    conn.close()
