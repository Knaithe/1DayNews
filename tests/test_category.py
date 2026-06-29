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


def test_xss_in_combined_bucket():
    # XSS keywords route into the merged XSS/SSRF bucket
    assert _cls("other", "CVE-x stored XSS in comment field") == "XSS/SSRF"


def test_csrf_in_combined_bucket():
    assert _cls("other", "CVE-x CSRF in admin panel") == "XSS/SSRF"


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


def test_bypass_idor_acronym_alone():
    # 'IDOR' acronym alone (no 'insecure direct object' full phrase) — regression
    # guard for the case-sensitivity bug (uppercase acronym vs lowercased text)
    assert _cls("other", "wger Vulnerable to IDOR: a user can access other users' data") == "bypass"


def test_bypass_account_takeover():
    assert _cls("other", "CVE-x account takeover via password reset poisoning") == "bypass"


def test_ssrf_in_combined_bucket():
    # SSRF keywords route into the merged XSS/SSRF bucket
    assert _cls("other", "CVE-x Server-Side Request Forgery (SSRF) in webhook") == "XSS/SSRF"


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


# ── escape: sandbox / container / VM / hypervisor escape (distinct from privesc) ──

def test_escape_container():
    assert _cls("other", "Docker container escape via privileged mode") == "escape"


def test_escape_container_hardening_bypass():
    # GHSA-8qf9-pc52-j7cm trigger sample (title form)
    assert _cls("other", "Gitea act_runner with Docker backend container hardening bypass") == "escape"


def test_escape_act_runner_full_summary():
    # GHSA-8qf9-pc52-j7cm full advisory text — container appears BEFORE 'escape',
    # so the bidirectional pattern must catch this even though title lacks 'escape'.
    title = "[CRITICAL] CVE-2026-58053 Gitea act_runner with the Docker backend"
    summary = ("Gitea act_runner with the Docker backend (through act 0.262.0) passes a "
               "workflow's container.options string to the Docker job container's HostConfig "
               "and, when configured with privileged: false, forces only the Privileged flag "
               "off while merging options such as --pid=host, --cap-add, and --security-opt "
               "unchanged. A user who can run a workflow on a Docker-backed runner can create "
               "a job container with host namespaces and broad capabilities and escape to the "
               "host as root despite privileged mode being disabled.")
    assert _cls("other", f"{title}\n{summary}") == "escape"


def test_escape_sandbox():
    assert _cls("other", "Chrome Sandbox Escape via Mojo UAF") == "escape"


def test_escape_sandbox_breakout():
    assert _cls("other", "VM2 Sandbox Breakout Through __lookupGetter__") == "escape"


def test_escape_sandbox_bypass_counts_as_escape():
    # sandbox bypass is semantically a sandbox escape
    assert _cls("other", "gVisor sandbox bypass via syscall confusion") == "escape"


def test_escape_vm_hypervisor():
    assert _cls("other", "KVM hypervisor escape via virtio") == "escape"


def test_escape_guest_to_host():
    assert _cls("other", "Hyper-V Guest-to-Host Code Execution") == "escape"


def test_escape_chinese():
    assert _cls("other", "Docker 容器逃逸漏洞 CVE-x") == "escape"
    assert _cls("other", "VirtualBox 虚拟机逃逸") == "escape"


def test_escape_overrides_rce():
    # vuln_type=RCE + sandbox escape language → escape wins over RCE
    assert _cls("RCE", "vm2 has a Sandbox Escape via Promise Constructor") == "escape"


def test_escape_not_lpe_title():
    # title says Local Privilege Escalation → fall back to existing privesc path,
    # NOT escape (user instruction: don't conflate with privesc)
    assert _cls("other",
                "Docker Desktop Enhanced Container Isolation Exposed Dangerous Function "
                "Local Privilege Escalation Vulnerability") != "escape"


def test_escape_not_llm_jailbreak():
    # LLM model jailbreak / prompt injection is a different concept
    assert _cls("other",
                "LLM Jailbreak via Chain-of-Logic Injection in sandbox prompt") != "escape"


def test_escape_overrides_excluded():
    # escape is checked BEFORE the excluded->other gate; an explicit escape
    # signal should not be hidden as noise even when score() marks it excluded
    assert _cls(None, "vm2 has a Sandbox Escape Vulnerability", reason="excluded") == "escape"
