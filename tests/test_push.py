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
    assert vm._resolve_pushed("confirmed", "1day", "GHSA", None, None, "RCE") == 0


def test_confirmed_unauth_pushes():
    # PR=N + RCE + LLM confirmed → push
    assert vm._resolve_pushed("confirmed", "1day", "GHSA", "N", None, "RCE") == 1
    assert vm._resolve_pushed("confirmed", "1day", "GHSA", "N", None, "bypass") == 1


def test_other_type_blocked_even_if_llm_confirmed():
    # product scope: SQLi/file-read/credential (vuln_type=other) never push
    assert vm._resolve_pushed("confirmed", "1day", "GHSA", "N", None, "other") == 0
    assert vm._resolve_pushed("confirmed", "1day", "GHSA", "N", None, None) == 0


# --- the gate must still block genuinely authenticated / low-signal vulns ---

def test_authenticated_pr_still_blocked():
    # PR:L (low privileges required = authenticated) stays locked 0 even if LLM says confirmed
    assert vm._resolve_pushed("confirmed", "1day", "GHSA", "L", None, "RCE") == 0


def test_authenticated_pr_high_still_blocked():
    assert vm._resolve_pushed("confirmed", "1day", "GHSA", "H", None, "RCE") == 0


def test_user_interaction_required_still_blocked():
    # UI:R (requires user interaction) still locked 0
    assert vm._resolve_pushed("confirmed", "1day", "GHSA", "N", "R", "RCE") == 0


def test_nday_still_blocked():
    assert vm._resolve_pushed("confirmed", "nday", "GHSA", "N", None, "RCE") == 0


def test_github_source_still_blocked():
    assert vm._resolve_pushed("confirmed", "1day", "GitHub", "N", None, "RCE") == 0


def test_llm_downgrade_still_blocked():
    # LLM can downgrade even when all hard constraints pass
    assert vm._resolve_pushed("not_relevant", "1day", "GHSA", "N", "N", "RCE") == 0
    assert vm._resolve_pushed("noise", "1day", "GHSA", "N", None, "RCE") == 0


# --- fetch vs enrich push-path consistency ---

def test_initial_pushed_zero_when_llm_configured(monkeypatch):
    # With LLM key present, fetch/rescore must NOT mark pushed=1 — enrich owns it.
    # Patch config module (push_gate reads keys at call time).
    import src.config as cfg
    monkeypatch.setattr(cfg, "DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setattr(cfg, "OPENAI_API_KEY", "")
    assert vm._initial_pushed(True, "RCE", "1day", "GHSA", "N", None) == 0
    assert vm._regex_push_candidate(True, "RCE", "1day", "GHSA", "N", None) is True


def test_initial_pushed_regex_when_no_llm(monkeypatch):
    import src.config as cfg
    monkeypatch.setattr(cfg, "DEEPSEEK_API_KEY", "")
    monkeypatch.setattr(cfg, "OPENAI_API_KEY", "")
    assert vm._initial_pushed(True, "RCE", "1day", "GHSA", "N", None) == 1
    assert vm._initial_pushed(True, "other", "1day", "GHSA", "N", None) == 0
    assert vm._initial_pushed(True, "RCE", "nday", "GHSA", "N", None) == 0


# --- enrich fair queue (no starvation under LIMIT) ---

def test_select_enrich_candidates_drains_old_backlog(tmp_path, monkeypatch):
    """Older unverified rows must still be selected when many newer rows exist."""
    import sqlite3
    db = tmp_path / "t.db"
    monkeypatch.setattr(vm, "DB_FILE", db)
    # also patch db module's path used by _get_conn
    import src.db as dbmod
    monkeypatch.setattr(dbmod, "DB_FILE", db)
    conn = sqlite3.connect(str(db))
    vm.init_db(conn)
    # 5 old other + 5 new high-priority RCE 1day
    for i in range(5):
        conn.execute(
            "INSERT INTO vulns (key,cve_id,source,title,reason,vuln_type,freshness,"
            "pushed,created_at,llm_verified) VALUES (?,?,?,?,?,?,?,?,?,0)",
            (f"old{i}", f"CVE-2020-{i}", "GHSA", f"old {i}", "asset+CVE", "other",
             "nday", 0, 1000.0 + i),
        )
    for i in range(5):
        conn.execute(
            "INSERT INTO vulns (key,cve_id,source,title,reason,vuln_type,freshness,"
            "pushed,created_at,llm_verified) VALUES (?,?,?,?,?,?,?,?,?,0)",
            (f"new{i}", f"CVE-2026-{i}", "ZDI", f"rce {i}", "RCE+CVE", "RCE",
             "1day", 0, 9000.0 + i),
        )
    conn.commit()
    rows, backlog = vm._select_enrich_candidates(conn, limit=6)
    keys = [r[0] for r in rows]
    assert backlog == 10
    # should include some new high-priority AND some old backlog
    assert any(k.startswith("new") for k in keys)
    assert any(k.startswith("old") for k in keys)
    assert len(rows) == 6
    conn.close()


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
