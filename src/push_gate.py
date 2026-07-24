"""Push decision gates (regex path + LLM verdict path)."""

try:
    from src.scoring import _HARDCODED_CRED_RE
except ImportError:
    from scoring import _HARDCODED_CRED_RE

_VERDICT_PUSH = {"confirmed": 1, "not_relevant": 0, "noise": 0}
_GITHUB_SOURCES = frozenset({"GitHub", "PoC-GitHub"})
# Product scope: only remote code execution + auth/access bypass are push-worthy.
# SQLi / file-read / credential / crypto (vuln_type=other) stay in DB for browse
# but never enter the notify stream — same gate for regex path and LLM path.
_PUSH_VULN_TYPES = frozenset({"RCE", "bypass"})


def _cfg():
    try:
        from src import config as cfg
    except ImportError:
        import config as cfg
    return cfg


def _llm_configured() -> bool:
    """True when an LLM API key is available (enrich owns the final push decision)."""
    cfg = _cfg()
    return bool(cfg.DEEPSEEK_API_KEY or cfg.OPENAI_API_KEY)


def _pr_blocks_push(pr, text=None) -> bool:
    """PR gate: PR=N passes (unauthenticated). PR=L also passes when the only
    "login" is a hardcoded/default credential found in the advisory text — that
    is effectively unauthenticated (e.g. 9router's hardcoded default password
    123456). Unknown PR (None) and PR:H always block.
    """
    if pr == "N":
        return False
    if pr == "L" and text and _HARDCODED_CRED_RE.search(text):
        return False
    return True


def _regex_push_candidate(hit, vuln_type, freshness, source, pr=None, ui=None, text=None) -> bool:
    """Regex-era push gate (shared by fetch / rescore / no-LLM mode)."""
    return bool(
        hit
        and vuln_type in _PUSH_VULN_TYPES
        and freshness == "1day"
        and source not in _GITHUB_SOURCES
        and not _pr_blocks_push(pr, text)
        and ui in (None, "N")
    )


def _initial_pushed(hit, vuln_type, freshness, source, pr=None, ui=None, text=None) -> int:
    """Value written to `pushed` at fetch/rescore time.

    With LLM configured: always 0 — enrich/_resolve_pushed owns the final bit.
    Without LLM: regex gate is the final gate.
    """
    if _llm_configured():
        return 0
    return 1 if _regex_push_candidate(hit, vuln_type, freshness, source, pr, ui, text) else 0


def _resolve_pushed(verdict, freshness, source, pr=None, ui=None, vuln_type=None, text=None):
    """Determine pushed value from LLM verdict, respecting hard constraints.

    Same hard gates as the regex path: 1day, non-GitHub, PR gate (N, or L with
    hardcoded/default credentials), UI≠R, and vuln_type must be RCE or bypass.
    LLM cannot promote SQLi/file-read/etc.
    """
    llm_wants_push = _VERDICT_PUSH.get(verdict, 0)
    if not llm_wants_push:
        return 0
    if vuln_type not in _PUSH_VULN_TYPES:
        return 0
    if freshness != "1day":
        return 0
    if source in _GITHUB_SOURCES:
        return 0
    if _pr_blocks_push(pr, text):
        return 0
    if ui is not None and ui != "N":
        return 0
    return 1
