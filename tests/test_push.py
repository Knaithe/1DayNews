"""Tests for vuln_monitor._resolve_pushed() — the LLM-era push gate.

Guards the CVE-2026-12569 false-negative: a critical RCE confirmed by the LLM
was never pushed because it had NO CVSS vector (cvss_pr=NULL). The old rule
`pr != "N"` treated a missing vector the same as PR:L/H (authenticated), so
fresh critical RCEs that simply lacked an NVD CVSS were silently dropped.
A missing CVSS vector is a data-availability gap, not evidence of being
authenticated — it must not block an LLM-confirmed push.
"""
import os
os.environ.setdefault("VULN_DATA_DIR", "")

import src.vuln_monitor as vm


# --- the bug: unknown PR must not block an LLM-confirmed 1day vuln ---

def test_confirmed_unknown_pr_pushes():
    # CVE-2026-12569: LLM confirmed, 1day, GHSA (not a github source), no CVSS vector
    assert vm._resolve_pushed("confirmed", "1day", "GHSA", None, None) == 1


def test_confirmed_no_pr_no_ui_pushes():
    # both vectors absent — defer to the LLM verdict, don't hard-block
    assert vm._resolve_pushed("confirmed", "1day", "NVD", None, None) == 1


# --- the gate must still block genuinely authenticated / low-signal vulns ---

def test_authenticated_pr_still_blocked():
    # PR:L (low privileges required = authenticated) stays locked 0 even if LLM says confirmed
    assert vm._resolve_pushed("confirmed", "1day", "GHSA", "L", None) == 0


def test_authenticated_pr_high_still_blocked():
    assert vm._resolve_pushed("confirmed", "1day", "GHSA", "H", None) == 0


def test_user_interaction_required_still_blocked():
    # UI:R (requires user interaction) still locked 0
    assert vm._resolve_pushed("confirmed", "1day", "GHSA", "N", "R") == 0


def test_nday_still_blocked():
    assert vm._resolve_pushed("confirmed", "nday", "GHSA", None, None) == 0


def test_github_source_still_blocked():
    assert vm._resolve_pushed("confirmed", "1day", "GitHub", None, None) == 0


def test_llm_downgrade_still_blocked():
    # LLM can downgrade even when all hard constraints pass
    assert vm._resolve_pushed("not_relevant", "1day", "GHSA", "N", "N") == 0
    assert vm._resolve_pushed("noise", "1day", "GHSA", None, None) == 0


# --- Telegram 429 retry_after parsing (backlog burst must not loop forever) ---

class _FakeResp:
    def __init__(self, payload=None, raise_json=False):
        self.status_code = 429
        self.text = "err"
        self._payload = payload
        self._raise = raise_json

    def json(self):
        if self._raise:
            raise ValueError("no json")
        return self._payload


def test_tg_retry_after_parsed():
    r = _FakeResp({"ok": False, "error_code": 429, "parameters": {"retry_after": 15}})
    assert vm._tg_retry_after(r) == 15


def test_tg_retry_after_missing_parameters():
    # 429 with no parameters block → 0 (caller falls back to its own backoff)
    assert vm._tg_retry_after(_FakeResp({"ok": False, "error_code": 429})) == 0


def test_tg_retry_after_garbage_json():
    # non-JSON / unparseable body → 0, never an exception
    assert vm._tg_retry_after(_FakeResp(raise_json=True)) == 0
