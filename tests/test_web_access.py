"""Access-audit log line formatting (web access.log).

The per-request write is a side effect; these tests lock the line format so the
audit fields (method/path/status/ip/auth/ua) are always present and UA is bounded.
"""
import os
os.environ.setdefault("VULN_DATA_DIR", "")

import src.web as web


def test_access_line_has_all_fields():
    line = web._access_line("GET", "/api/sources", 200, "1.2.3.4", "ok", "Mozilla/5.0")
    assert "GET" in line
    assert "/api/sources" in line
    assert " 200 " in line
    assert "ip=1.2.3.4" in line
    assert "auth=ok" in line
    assert "Mozilla/5.0" in line


def test_access_line_marks_bad_token():
    # a 403 from a missing/wrong token is still auditable
    line = web._access_line("GET", "/", 403, None, "bad", None)
    assert "auth=bad" in line
    assert "403" in line
    assert "ip=-" in line  # missing ip falls back to '-'
    assert 'ua="-"' in line  # missing ua falls back to '-'


def test_access_line_truncates_long_ua():
    line = web._access_line("GET", "/", 200, "1.1.1.1", "loopback", "X" * 500)
    # ua is capped at 160 chars so a pathological UA can't blow up the log line
    assert len(line) < 300


def test_cookie_secure_force_env(monkeypatch):
    monkeypatch.setattr(web, "_FORCE_SECURE_COOKIE", True)
    assert web._cookie_secure() is True


def test_cookie_secure_off_by_default(monkeypatch):
    monkeypatch.setattr(web, "_FORCE_SECURE_COOKIE", False)
    # no request context → False (HTTP/tunnel safe default)
    assert web._cookie_secure() is False


def test_dashboard_html_loaded_from_static():
    # HTML lives in src/static/dashboard.html, not inline in web.py
    assert "vuln-monitor" in web.DASHBOARD_HTML
    assert "vcard" in web.DASHBOARD_HTML
    from pathlib import Path
    assert (Path(web.__file__).parent / "static" / "dashboard.html").is_file()
