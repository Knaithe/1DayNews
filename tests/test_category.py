"""Tests for vuln_monitor.classify_category() and the category column migration."""
import os
import sqlite3
import tempfile
from datetime import datetime, timezone

os.environ.setdefault("VULN_DATA_DIR", "")

import src.vuln_monitor as v


def _cls(vuln_type, text, reason=None):
    return v.classify_category(vuln_type, text, reason)


def test_rce_by_vuln_type():
    assert _cls("RCE", "anything goes here") == "RCE"


def test_sqli():
    assert _cls("other", "CVE-x FooBar SQL Injection in login") == "SQLi"


def test_bypass_by_keyword():
    assert _cls("other", "CVE-x Authentication Bypass in portal") == "bypass"


def test_bypass_fallback_by_vuln_type():
    # vuln_type=bypass with no specific keyword still maps to bypass
    assert _cls("bypass", "CVE-x some nondescript issue") == "bypass"


def test_privilege_escalation():
    assert _cls("other", "CVE-x Unauthenticated Privilege Escalation in WordPress") == "privilege escalation"


def test_data_leak_file_read():
    assert _cls("other", "CVE-x arbitrary file read via path traversal") == "data leak"


def test_data_leak_info_disclosure():
    assert _cls("other", "CVE-x sensitive information disclosure of user data") == "data leak"


def test_xss():
    assert _cls("other", "CVE-x stored XSS in comment field") == "XSS"


def test_dos():
    assert _cls("other", "CVE-x denial of service via crafted packet") == "DoS"


def test_other_fallback():
    assert _cls("other", "CVE-x some nondescript vuln in a plugin") == "other"


def test_sqli_beats_data_leak():
    # SQLi dump is both SQLi and a data leak -> SQLi wins (priority)
    assert _cls("other", "SQL injection allowing data leak of user table") == "SQLi"


def test_path_traversal_is_data_leak():
    assert _cls("other", "path traversal to read sensitive files") == "data leak"


def test_init_db_adds_category_column(tmp_path):
    db = str(tmp_path / "t.db")
    c = sqlite3.connect(db)
    # a pre-migration DB with the original baseline columns, but no category
    c.execute("CREATE TABLE vulns (key TEXT PRIMARY KEY, cve_id TEXT, source TEXT, "
              "title TEXT NOT NULL, link TEXT, summary TEXT, reason TEXT, vuln_type TEXT, "
              "freshness TEXT, freshness_reason TEXT, pushed INTEGER DEFAULT 0, "
              "created_at REAL NOT NULL, cve_published TEXT, severity TEXT, cvss REAL, "
              "llm_verified INTEGER DEFAULT 0, llm_verdict TEXT, llm_notes TEXT, "
              "tg_sent INTEGER DEFAULT 0, wecom_sent INTEGER DEFAULT 0, "
              "dingtalk_sent INTEGER DEFAULT 0, feishu_sent INTEGER DEFAULT 0, "
              "cvss_vector TEXT, cvss_pr TEXT)")
    v.init_db(c)
    cols = [r[1] for r in c.execute("PRAGMA table_info(vulns)").fetchall()]
    assert "category" in cols
    c.close()


# ── refinement: recall gaps, precision, new SSRF class ──

def test_data_leak_local_file_inclusion_full_phrase():
    # 'local file inclusion' full phrase (not just 'LFI' abbreviation)
    assert _cls("other", "CVE-x Local file inclusion via view parameter") == "data leak"


def test_bypass_idor():
    assert _cls("other", "CVE-x Insecure Direct Object Reference (IDOR) in /api/user") == "bypass"


def test_bypass_account_takeover():
    assert _cls("other", "CVE-x account takeover via password reset poisoning") == "bypass"


def test_ssrf():
    assert _cls("other", "CVE-x Server-Side Request Forgery (SSRF) in webhook") == "SSRF"


def test_excluded_records_are_other():
    # excluded records are noise; never claim a specific category
    assert _cls(None, "SQL Injection in login", reason="excluded") == "other"
    assert _cls("other", "denial of service via crash", reason="excluded") == "other"


def test_dos_not_when_memory_corruption():
    # heap/UAF/OOB is RCE-class, not DoS, even when 'crash'/'denial of service' is mentioned
    assert _cls("other", "heap buffer overflow causing application crash") == "other"
    assert _cls("other", "use-after-free leading to denial of service") == "other"


def test_elevation_of_privilege_is_privesc_even_with_access_control():
    # Microsoft 'Elevation of Privilege' should be privesc even if the summary
    # also mentions access-control language (privesc checked before bypass)
    assert _cls("other", "Azure HorizonDB Elevation of Privilege with access control flaw") == "privilege escalation"


def test_elevation_of_privilege_local_msrc_is_privesc_not_rce():
    # HIGH-3: MSRC 'Elevation of Privilege' reads as RCE via score() (mem corruption)
    # but is really local privilege escalation — category should be privesc.
    assert _cls("RCE", "Azure HorizonDB Elevation of Privilege Vulnerability") == "privilege escalation"


def test_rce_title_privilege_escalation_is_privesc():
    # title-led: a vuln scored RCE whose TITLE says 'privilege escalation' is privesc
    assert _cls("RCE", "Cisco ISE Authenticated Privilege Escalation Vulnerability") == "privilege escalation"


def test_rce_command_injection_title_stays_rce():
    # must NOT downgrade a genuine RCE whose title claims command injection + RCE,
    # even if its summary later mentions elevating privileges
    assert _cls("RCE", "Cisco Command Injection and Remote Code Execution\n"
                       "An attacker could elevate privileges after exploitation.") == "RCE"


def test_rce_memcorruption_elevate_privileges_is_privesc():
    # local memory-corruption + 'elevate privileges' (verb) = local privesc
    assert _cls("RCE", "Use after free in Windows Hyper-V\n"
                       "allows an authorized attacker to elevate privileges locally.") == "privilege escalation"


def test_plain_rce_title_stays_rce():
    assert _cls("RCE", "Remote Code Execution in nginx via crafted request") == "RCE"
