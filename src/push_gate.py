"""Push decision gates (regex path + LLM verdict path)."""

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


def _regex_push_candidate(hit, vuln_type, freshness, source, pr=None, ui=None) -> bool:
    """Regex-era push gate (shared by fetch / rescore / no-LLM mode)."""
    return bool(
        hit
        and vuln_type in _PUSH_VULN_TYPES
        and freshness == "1day"
        and source not in _GITHUB_SOURCES
        and pr == "N"
        and ui in (None, "N")
    )


def _initial_pushed(hit, vuln_type, freshness, source, pr=None, ui=None) -> int:
    """Value written to `pushed` at fetch/rescore time.

    With LLM configured: always 0 — enrich/_resolve_pushed owns the final bit.
    Without LLM: regex gate is the final gate.
    """
    if _llm_configured():
        return 0
    return 1 if _regex_push_candidate(hit, vuln_type, freshness, source, pr, ui) else 0


def _resolve_pushed(verdict, freshness, source, pr=None, ui=None, vuln_type=None):
    """Determine pushed value from LLM verdict, respecting hard constraints.

    Same hard gates as the regex path: 1day, non-GitHub, PR=N, UI≠R, and
    vuln_type must be RCE or bypass. LLM cannot promote SQLi/file-read/etc.
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
    if pr != "N":
        return 0
    if ui is not None and ui != "N":
        return 0
    return 1
