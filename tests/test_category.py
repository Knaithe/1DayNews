"""Tests for vuln_monitor.classify_category() and the category column migration."""
import os
import sqlite3
import tempfile
from datetime import datetime, timezone

os.environ.setdefault("VULN_DATA_DIR", "")

import src.vuln_monitor as v


def _cls(vuln_type, text):
    return v.classify_category(vuln_type, text)


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
