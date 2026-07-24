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


# --- hardcoded/default-credential exception: such PR:L is effectively unauthenticated ---

_HARDCODED_TEXT = ("9router 0.4.59 contains a chain of vulnerabilities: a hardcoded "
                   "default password (123456) that authenticates any fresh installation")
_PLAIN_TEXT = "Some product has an authenticated command injection after admin login"


def test_pr_low_hardcoded_password_pushes():
    # PR:L but the only "login" is a hardcoded default password → effectively unauth
    assert vm._resolve_pushed("confirmed", "1day", "GHSA", "L", None, "RCE", _HARDCODED_TEXT) == 1
    assert vm._resolve_pushed("confirmed", "1day", "GHSA", "L", None, "bypass", _HARDCODED_TEXT) == 1


def test_pr_low_without_hardcoded_text_still_blocked():
    assert vm._resolve_pushed("confirmed", "1day", "GHSA", "L", None, "RCE", _PLAIN_TEXT) == 0
    # text omitted → conservative: still blocked
    assert vm._resolve_pushed("confirmed", "1day", "GHSA", "L", None, "RCE") == 0


def test_pr_high_blocked_even_with_hardcoded_text():
    assert vm._resolve_pushed("confirmed", "1day", "GHSA", "H", None, "RCE", _HARDCODED_TEXT) == 0


def test_regex_gate_hardcoded_exception(monkeypatch):
    import src.config as cfg
    monkeypatch.setattr(cfg, "DEEPSEEK_API_KEY", "")
    monkeypatch.setattr(cfg, "OPENAI_API_KEY", "")
    assert vm._regex_push_candidate(True, "RCE", "1day", "GHSA", "L", None, _HARDCODED_TEXT) is True
    assert vm._regex_push_candidate(True, "RCE", "1day", "GHSA", "L", None, _PLAIN_TEXT) is False


def test_init_db_pr_lock_keeps_hardcoded_cred(tmp_path, monkeypatch):
    """startup PR lock must not un-push PR:L records whose only login is a
    hardcoded/default credential — but still un-pushes genuinely authenticated ones."""
    import sqlite3
    db = tmp_path / "t.db"
    monkeypatch.setattr(vm, "DB_FILE", db)
    import src.db as dbmod
    monkeypatch.setattr(dbmod, "DB_FILE", db)
    conn = sqlite3.connect(str(db))
    vm.init_db(conn)
    for key, title, pr in [
        ("keep",  "9router hardcoded default password (123456) allows RCE", "L"),
        ("drop",  "authenticated admin command injection after login", "L"),
        ("dropH", "hardcoded default password but PR:H", "H"),
    ]:
        conn.execute(
            "INSERT INTO vulns (key,cve_id,source,title,reason,vuln_type,freshness,"
            "pushed,created_at,cvss_pr) VALUES (?,?,?,?,?,?,?,1,1000.0,?)",
            (key, f"CVE-2026-{key}", "GHSA", title, "RCE+CVE", "RCE", "1day", pr),
        )
    conn.commit()
    vm.init_db(conn)  # second run applies the locks to the rows above
    rows = dict(conn.execute("SELECT key, pushed FROM vulns").fetchall())
    conn.close()
    assert rows["keep"] == 1
    assert rows["drop"] == 0
    assert rows["dropH"] == 0


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


# --- high-CVSS "no hit" backstop into LLM review ---

def _make_enrich_db(tmp_path, monkeypatch):
    """Fresh temp vulns DB wired into src.db; returns an open connection."""
    import sqlite3
    db = tmp_path / "t.db"
    monkeypatch.setattr(vm, "DB_FILE", db)
    # also patch db module's path used by _get_conn
    import src.db as dbmod
    monkeypatch.setattr(dbmod, "DB_FILE", db)
    conn = sqlite3.connect(str(db))
    vm.init_db(conn)
    return conn


def test_select_enrich_candidates_high_cvss_no_hit_backstop(tmp_path, monkeypatch):
    """regex 'no hit' rows are skipped — unless CVSS>=9.0 and PR=N. Critical
    unauthenticated vulns must not be silently buried by the regex recall layer."""
    conn = _make_enrich_db(tmp_path, monkeypatch)
    for key, reason, cvss, pr in [
        ("rescued",  "no hit",   10.0, "N"),   # the only eligible row
        ("pr_low",   "no hit",   10.0, "L"),   # authenticated → no
        ("low_cvss", "no hit",    8.8, "N"),   # below 9.0 → no
        ("no_cvss",  "no hit",   None, "N"),   # unknown score → no
        ("excluded", "excluded", 10.0, "N"),   # positive noise class stays out
    ]:
        conn.execute(
            "INSERT INTO vulns (key,cve_id,source,title,reason,freshness,"
            "pushed,created_at,cvss,cvss_pr) VALUES (?,?,?,?,?,?,0,?,?,?)",
            (key, f"CVE-2026-{key}", "GHSA", f"t {key}", reason, "1day",
             1000.0, cvss, pr),
        )
    conn.commit()
    selected, backlog = vm._select_enrich_candidates(conn, limit=10)
    assert {r[0] for r in selected} == {"rescued"}
    assert backlog == 1
    conn.close()


def _stub_enrich_io(monkeypatch, llm_result):
    """Stub all network/LLM I/O of _cmd_enrich_inner; returns the enrich module."""
    import src.enrich as en
    monkeypatch.setattr(en, "DEEPSEEK_API_KEY", "sk-test")
    monkeypatch.setattr(en, "OPENAI_API_KEY", "")
    monkeypatch.setattr(en, "_warm_nvd_cache", lambda conn: None)
    monkeypatch.setattr(en, "_backfill_nvd_severity", lambda conn: None)
    monkeypatch.setattr(en, "_enrich_one", lambda rec: llm_result)
    monkeypatch.setattr(en.time, "sleep", lambda s: None)
    return en


def _insert_enrich_row(conn, key, cve, reason, vuln_type, cvss, pr, ui="N"):
    conn.execute(
        "INSERT INTO vulns (key,cve_id,source,title,summary,reason,vuln_type,freshness,"
        "pushed,created_at,severity,cvss,cvss_pr,cvss_ui) "
        "VALUES (?,?,?,?,?,?,?,?,0,?,?,?,?,?)",
        (key, cve, "GHSA", f"title {key}", f"summary {key}", reason, vuln_type,
         "1day", 1000.0, "critical", cvss, pr, ui),
    )
    conn.commit()


def test_enrich_adopts_llm_vuln_type_for_backstop(tmp_path, monkeypatch):
    """A rescued 'no hit' row gets the LLM's vuln_type (+category) so the push
    gate can actually see it — confirmed + bypass + PR=N + 1day → pushed=1."""
    import sqlite3
    en = _stub_enrich_io(monkeypatch, ("confirmed", "OT segmentation bypass", "bypass"))
    conn = _make_enrich_db(tmp_path, monkeypatch)
    _insert_enrich_row(conn, "k1", "CVE-2026-42933", "no hit", None, 10.0, "N")
    conn.close()
    en._cmd_enrich_inner(dry=True)
    conn = sqlite3.connect(str(tmp_path / "t.db"))
    row = conn.execute(
        "SELECT llm_verified, llm_verdict, vuln_type, category, pushed "
        "FROM vulns WHERE key='k1'"
    ).fetchone()
    conn.close()
    assert row == (1, "confirmed", "bypass", "bypass", 1)


def test_enrich_llm_vuln_type_never_overrides_regex(tmp_path, monkeypatch):
    """An existing regex classification is kept — llm vuln_type only fills NULL."""
    import sqlite3
    en = _stub_enrich_io(monkeypatch, ("confirmed", "x", "other"))
    conn = _make_enrich_db(tmp_path, monkeypatch)
    _insert_enrich_row(conn, "k1", "CVE-2026-1", "RCE+CVE", "RCE", 9.8, "N")
    conn.close()
    en._cmd_enrich_inner(dry=True)
    conn = sqlite3.connect(str(tmp_path / "t.db"))
    row = conn.execute(
        "SELECT vuln_type, category, pushed FROM vulns WHERE key='k1'"
    ).fetchone()
    conn.close()
    assert row == ("RCE", None, 1)


def test_enrich_backstop_row_with_other_type_not_pushed(tmp_path, monkeypatch):
    """LLM may classify a rescued row as 'other' (e.g. SQLi) — adopted for the
    record, but product scope (RCE/bypass only) still keeps pushed=0."""
    import sqlite3
    en = _stub_enrich_io(monkeypatch, ("confirmed", "sqli", "other"))
    conn = _make_enrich_db(tmp_path, monkeypatch)
    _insert_enrich_row(conn, "k1", "CVE-2026-2", "no hit", None, 9.5, "N")
    conn.close()
    en._cmd_enrich_inner(dry=True)
    conn = sqlite3.connect(str(tmp_path / "t.db"))
    row = conn.execute(
        "SELECT llm_verdict, vuln_type, pushed FROM vulns WHERE key='k1'"
    ).fetchone()
    conn.close()
    assert row == ("confirmed", "other", 0)


# --- _enrich_one vuln_type parsing ---

class _FakeLLMMsg:
    def __init__(self, content):
        self.content = content
        self.tool_calls = None


class _FakeLLMChoice:
    def __init__(self, msg):
        self.message = msg


class _FakeLLMResp:
    def __init__(self, msg):
        self.choices = [_FakeLLMChoice(msg)]


class _FakeLLMClient:
    """Minimal OpenAI-client stand-in returning one canned content string."""
    def __init__(self, content):
        self.chat = self
        self.completions = self
        self._msg = _FakeLLMMsg(content)

    def create(self, **kwargs):
        return _FakeLLMResp(self._msg)


def _fake_enrich_rec():
    # column order must match enrich._E_* indices
    return ("k", "CVE-2026-1", "GHSA", "title", "", "summary", "no hit",
            "critical", 10.0, "1day", "N", "N", None)


def _run_enrich_one(monkeypatch, payload):
    import src.enrich as en
    monkeypatch.setattr(en, "_llm_client", _FakeLLMClient(payload))
    monkeypatch.setattr(en, "_llm_model", "fake")
    return en._enrich_one(_fake_enrich_rec())


def test_enrich_one_parses_llm_vuln_type(monkeypatch):
    verdict, notes, vt = _run_enrich_one(
        monkeypatch, '{"verdict": "confirmed", "vuln_type": "bypass", "notes": "x"}')
    assert (verdict, notes, vt) == ("confirmed", "x", "bypass")


def test_enrich_one_invalid_vuln_type_becomes_none(monkeypatch):
    verdict, notes, vt = _run_enrich_one(
        monkeypatch, '{"verdict": "confirmed", "vuln_type": "sqli", "notes": "x"}')
    assert (verdict, vt) == ("confirmed", None)


def test_enrich_one_missing_vuln_type_becomes_none(monkeypatch):
    # legacy/custom prompt without the vuln_type field → graceful degradation
    verdict, notes, vt = _run_enrich_one(
        monkeypatch, '{"verdict": "confirmed", "notes": "x"}')
    assert (verdict, vt) == ("confirmed", None)


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
