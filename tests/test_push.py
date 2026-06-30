"""Tests for vuln_monitor._resolve_pushed() — the LLM-era push gate.

PR gate: CVSS PR must be 'N' (no privileges required = unauthenticated).
A missing vector (pr=None) is conservatively treated as potentially-authenticated
and blocks the push. NVD backfill in the enrich phase will fill in the real PR
value, at which point confirmed vulns with PR=N will be pushed.
"""
import os
os.environ.setdefault("VULN_DATA_DIR", "")

import src.vuln_monitor as vm


# --- unknown PR blocks push (conservative: missing CVSS ≠ unauthenticated) ---

def test_unknown_pr_blocks_push():
    # pr=None means NVD hasn't provided a CVSS vector yet — block until it does
    assert vm._resolve_pushed("confirmed", "1day", "GHSA", None, None) == 0


def test_confirmed_unauth_pushes():
    # PR=N (explicitly unauthenticated) + LLM confirmed → push
    assert vm._resolve_pushed("confirmed", "1day", "GHSA", "N", None) == 1


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
    assert vm._resolve_pushed("confirmed", "nday", "GHSA", "N", None) == 0


def test_github_source_still_blocked():
    assert vm._resolve_pushed("confirmed", "1day", "GitHub", "N", None) == 0


def test_llm_downgrade_still_blocked():
    # LLM can downgrade even when all hard constraints pass
    assert vm._resolve_pushed("not_relevant", "1day", "GHSA", "N", "N") == 0
    assert vm._resolve_pushed("noise", "1day", "GHSA", "N", None) == 0


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
