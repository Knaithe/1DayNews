"""LLM enrichment agent + fair-queue batch processing."""
import json
import re
import time
from datetime import datetime

import requests

try:
    from src.config import (
        DATA_DIR, DEEPSEEK_API_KEY, OPENAI_API_KEY, LLM_MODEL, LLM_BASE_URL,
        LLM_TEMPERATURE, LLM_MAX_TOKENS, LLM_TIMEOUT, LLM_MAX_CONTEXT,
        LLM_REASONING, LLM_TOP_P, GH_TOKEN, CHAITIN_API_URL, HIGH_PRIORITY_SOURCES,
        FRESH_SOURCES, ENRICH_LIMIT, SESS, _get_with_retry, log,
    )
    from src.db import _db, init_db
    from src.nvd import _nvd_detail, _warm_nvd_cache, _backfill_nvd_severity
    from src.push_gate import _resolve_pushed
except ImportError:
    from config import (
        DATA_DIR, DEEPSEEK_API_KEY, OPENAI_API_KEY, LLM_MODEL, LLM_BASE_URL,
        LLM_TEMPERATURE, LLM_MAX_TOKENS, LLM_TIMEOUT, LLM_MAX_CONTEXT,
        LLM_REASONING, LLM_TOP_P, GH_TOKEN, CHAITIN_API_URL, HIGH_PRIORITY_SOURCES,
        FRESH_SOURCES, ENRICH_LIMIT, SESS, _get_with_retry, log,
    )
    from db import _db, init_db
    from nvd import _nvd_detail, _warm_nvd_cache, _backfill_nvd_severity
    from push_gate import _resolve_pushed

# ================== LLM ENRICHMENT ==================
# System prompt: load from DATA_DIR/llm_prompt.txt if exists, else use default.
_LLM_PROMPT_FILE = DATA_DIR / "llm_prompt.txt"
_LLM_SYSTEM_PROMPT_DEFAULT = """You are a vulnerability intelligence analyst. Today is {today}. The current year is {year}. Determine whether a vulnerability is genuine and worth alerting on.

IMPORTANT: CVE-{year}-* are CURRENT-YEAR vulnerabilities, not future-dated or speculative. Do NOT dismiss them based on the year number.

## Verdict categories:
- confirmed: Genuine vulnerability affecting real, widely-deployed products. Worth pushing.
- not_relevant: Real vulnerability but low practical impact — requires authentication + local access, niche product (<1000 deployments), info disclosure only with no escalation path. Not worth pushing.
- noise: Not a real threat — fabricated CVE, personal project with 0 users, CTF/homework, marketing content, automated CVE reservation with no real impact.

## Rules:
1. Vendor PSIRTs (Fortinet/Cisco/PaloAlto/MSRC) confirm the vulnerability is REAL — but real does not mean worth pushing. Still evaluate impact.
2. "confirmed" requires: remotely exploitable OR high blast radius on widely-deployed products. RCE / command injection / SQL injection / auth bypass = confirmed.
3. "not_relevant" for ANY of: DoS-only / crash-only, library-level bugs not directly exploitable in production, info disclosure with no escalation path, authenticated-only local exploits, niche products (<1000 deployments), Linux kernel subsystem patches (staging/ocfs2/fbdev/media/ALSA/i2c/s390).
4. CVSS is a REFERENCE only — a high CVSS DoS is still not_relevant, a low CVSS pre-auth RCE is still confirmed.
5. GitHub repos: check if the repo has actual exploit code vs empty placeholder. 0-star personal forks with no code = noise.
6. Use tools to verify when title/summary is ambiguous or truncated.
7. If you find a public exploit/PoC, mention it in notes — this is valuable intelligence.
8. Do NOT underestimate WordPress plugin deployment — popular plugins (OttoKit, Elementor, WooCommerce addons, etc.) often have 100K+ active installs even if the developer is not well-known.

Output ONLY JSON (no markdown):
{"verdict": "confirmed|not_relevant|noise", "notes": "one-sentence rationale"}
"""

def _get_llm_prompt():
    """Load system prompt from file (if exists) or use default."""
    now = datetime.now()
    today = now.strftime("%Y-%m-%d")
    year = now.strftime("%Y")
    if _LLM_PROMPT_FILE.exists():
        try:
            custom = _LLM_PROMPT_FILE.read_text(encoding="utf-8").strip()
            if custom:
                return custom.replace("{today}", today).replace("{year}", year)
        except Exception:
            pass
    return _LLM_SYSTEM_PROMPT_DEFAULT.replace("{today}", today).replace("{year}", year)

_ENRICH_TOOLS = [
    {"type": "function", "function": {
        "name": "fetch_nvd_detail",
        "description": "Get NVD detail for a CVE: CVSS score, severity, full description, published date.",
        "parameters": {"type": "object", "properties": {"cve_id": {"type": "string"}}, "required": ["cve_id"]},
    }},
    {"type": "function", "function": {
        "name": "fetch_source_page",
        "description": "Fetch text content of a URL (advisory page, blog post). Returns first 2000 chars.",
        "parameters": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]},
    }},
    {"type": "function", "function": {
        "name": "search_github",
        "description": "Search GitHub for PoC/exploit repositories related to a CVE.",
        "parameters": {"type": "object", "properties": {"cve_id": {"type": "string"}}, "required": ["cve_id"]},
    }},
    {"type": "function", "function": {
        "name": "search_chaitin",
        "description": "Search Chaitin Stack vuldb (Chinese vulnerability database) for details.",
        "parameters": {"type": "object", "properties": {"keyword": {"type": "string"}}, "required": ["keyword"]},
    }},
]


_MAX_TOOL_ROUNDS = 5

def _get_llm_client():
    """Create OpenAI-compatible client. Returns (client, model) or (None, None)."""
    try:
        from openai import OpenAI
    except ImportError:
        log.error("openai package not installed. Run: pip install openai")
        return None, None
    api_key = DEEPSEEK_API_KEY or OPENAI_API_KEY
    if not api_key:
        return None, None
    if DEEPSEEK_API_KEY:
        base_url = LLM_BASE_URL or "https://api.deepseek.com"
        model = LLM_MODEL or "deepseek-chat"
    else:
        base_url = LLM_BASE_URL or "https://api.openai.com"
        model = LLM_MODEL or "gpt-4o-mini"
    # avoid double /v1 if user already included it in base_url
    base = base_url.rstrip("/")
    if not base.endswith("/v1"):
        base += "/v1"
    client = OpenAI(api_key=api_key, base_url=base, timeout=LLM_TIMEOUT)
    log.info(f"LLM client: model={model} base_url={base}")
    return client, model

_llm_client = None
_llm_model = None


_TOOL_MAX_OUTPUT = 3000  # truncate tool output to avoid blowing context

def _tool_fetch_nvd_detail(cve_id):
    detail = _nvd_detail(cve_id)
    if not detail:
        return '{"error": "not found in NVD"}'
    # truncate description to avoid huge output
    if detail.get("description"):
        detail["description"] = detail["description"][:1000]
    return json.dumps(detail, ensure_ascii=False)[:_TOOL_MAX_OUTPUT]

def _ssrf_check_url(url):
    """Validate URL scheme and resolved IPs against SSRF. Returns error string or None."""
    from urllib.parse import urlparse
    import socket, ipaddress
    from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return "only http/https allowed"
    host = parsed.hostname or ""
    ex = ThreadPoolExecutor(max_workers=1)
    try:
        infos = ex.submit(socket.getaddrinfo, host, None).result(timeout=5)  # bound the blocking DNS
        for info in infos:
            addr = ipaddress.ip_address(info[4][0])
            if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
                return "internal addresses not allowed"
    except FuturesTimeout:
        return "DNS resolution timed out"
    except (socket.gaierror, ValueError):
        return "DNS resolution failed"
    finally:
        ex.shutdown(wait=False)   # don't let a slow lookup block the caller; thread resolves in background
    return None

def _tool_fetch_source_page(url):
    try:
        from urllib.parse import urljoin
        err = _ssrf_check_url(url)
        if err:
            return json.dumps({"error": err})
        cur_url = url
        for _ in range(5):
            r = SESS.get(cur_url, timeout=15, allow_redirects=False,
                         headers={"User-Agent": "vuln-monitor/1.0"})
            if r.is_redirect and "location" in r.headers:
                cur_url = urljoin(cur_url, r.headers["location"])
                err = _ssrf_check_url(cur_url)
                if err:
                    return json.dumps({"error": f"redirect blocked: {err}"})
                continue
            break
        text = re.sub(r"<[^>]+>", " ", r.text)
        return re.sub(r"\s+", " ", text).strip()[:2000]
    except Exception as ex:
        return json.dumps({"error": str(ex)})

def _tool_search_github(cve_id):
    headers = {"Accept": "application/vnd.github+json"}
    if GH_TOKEN:
        headers["Authorization"] = f"Bearer {GH_TOKEN}"
    try:
        r = _get_with_retry(SESS, "https://api.github.com/search/repositories",
            params={"q": f"{cve_id} in:name,description", "sort": "stars", "per_page": 5},
            headers=headers, timeout=15)
        if r.status_code != 200:
            return json.dumps({"error": f"HTTP {r.status_code}"})
        repos = [{"name": rr["full_name"], "desc": (rr.get("description") or "")[:200],
                  "stars": rr["stargazers_count"], "url": rr["html_url"]}
                 for rr in r.json().get("items", [])]
        return json.dumps(repos, ensure_ascii=False)[:_TOOL_MAX_OUTPUT]
    except Exception as ex:
        return json.dumps({"error": str(ex)})

def _tool_search_chaitin(keyword):
    s = requests.Session()
    try:
        s.headers.update({"User-Agent": "Mozilla/5.0", "Referer": "https://stack.chaitin.com/vuldb/index",
                          "Origin": "https://stack.chaitin.com", "Accept": "application/json"})
        r = s.get(CHAITIN_API_URL, params={"limit": 5, "offset": 0, "search": keyword}, timeout=15)
        if r.status_code != 200:
            return json.dumps({"error": f"HTTP {r.status_code}"})
        items = r.json().get("data", {}).get("list", [])
        return json.dumps([{"cve": v.get("cve_id", ""), "title": v.get("title", ""),
                            "severity": v.get("severity", ""), "summary": (v.get("summary") or "")[:300]}
                           for v in items], ensure_ascii=False)[:_TOOL_MAX_OUTPUT]
    except Exception as ex:
        return json.dumps({"error": str(ex)})
    finally:
        s.close()

_TOOL_DISPATCH = {
    "fetch_nvd_detail": _tool_fetch_nvd_detail,
    "fetch_source_page": _tool_fetch_source_page,
    "search_github": _tool_search_github,
    "search_chaitin": _tool_search_chaitin,
}


# indices into enrich candidate tuples (must match SELECT column order)
_E_KEY, _E_CVE, _E_SRC, _E_TITLE, _E_LINK, _E_SUM, _E_REASON, _E_SEV, _E_CVSS, _E_FRESH, _E_PR, _E_UI, _E_VT = range(13)

def _enrich_one(record):
    """Run LLM agent loop on one vulnerability. Returns (verdict, notes) or (None, None)."""
    global _llm_client, _llm_model
    if _llm_client is None:
        _llm_client, _llm_model = _get_llm_client()
    if _llm_client is None:
        return None, None

    cve_id = record[_E_CVE]
    source = record[_E_SRC]
    title = record[_E_TITLE]
    link = record[_E_LINK]
    summary = record[_E_SUM]
    reason = record[_E_REASON]
    severity = record[_E_SEV]
    cvss = record[_E_CVSS]
    user_msg = (
        f"Assess this vulnerability:\n"
        f"CVE: {cve_id or 'N/A'}\nSource: {source}\nTitle: {title}\n"
        f"URL: {link or 'N/A'}\nSummary: {summary or 'N/A'}\n"
        f"Regex match: {reason}\nCVSS: {cvss or 'unknown'}\nSeverity: {severity or 'unknown'}"
    )
    # skip tools for high-trust sources with sufficient data — direct judgment is faster
    has_enough_context = (source in FRESH_SOURCES and (
        (severity and severity != "unknown") or cvss))
    if has_enough_context:
        user_msg += "\n\nYou have enough context from this PSIRT advisory. Do NOT call tools — respond with JSON verdict directly."
    messages = [{"role": "system", "content": _get_llm_prompt()},
                {"role": "user", "content": user_msg}]
    # rough token estimate: 1 token ≈ 4 chars. Reserve max_tokens for output.
    _ctx_budget = (LLM_MAX_CONTEXT - LLM_MAX_TOKENS) * 4
    use_tools = not has_enough_context
    max_rounds = _MAX_TOOL_ROUNDS if use_tools else 1
    try:
        for round_i in range(max_rounds):
            kwargs = {
                "model": _llm_model, "messages": messages,
                "max_tokens": LLM_MAX_TOKENS,
                "temperature": LLM_TEMPERATURE,
                "top_p": LLM_TOP_P,
            }
            if use_tools:
                kwargs["tools"] = _ENRICH_TOOLS
            if LLM_REASONING:
                kwargs["reasoning_effort"] = LLM_REASONING
            try:
                resp = _llm_client.chat.completions.create(**kwargs)
            except Exception as first_err:
                err_msg = str(first_err).lower()
                # some models don't support certain params — retry without
                for param in ("temperature", "top_p", "reasoning_effort", "tools"):
                    if param in err_msg:
                        kwargs.pop(param, None)
                        break
                else:
                    raise
                resp = _llm_client.chat.completions.create(**kwargs)
            choice = resp.choices[0]
            if choice.message.tool_calls and round_i < max_rounds - 1:
                messages.append(choice.message)
                for tc in choice.message.tool_calls:
                    fn = _TOOL_DISPATCH.get(tc.function.name)
                    try:
                        args = json.loads(tc.function.arguments)
                    except (json.JSONDecodeError, TypeError):
                        args = {}
                    result = fn(**args) if fn else json.dumps({"error": "unknown tool"})
                    # truncate tool result to fit context budget
                    total_chars = sum(len(str(m.get("content", "") if isinstance(m, dict) else getattr(m, "content", ""))) for m in messages)
                    remaining = max(500, _ctx_budget - total_chars)
                    messages.append({"role": "tool", "tool_call_id": tc.id, "content": result[:remaining]})
                continue
            # last round with pending tool_calls: force a verdict
            if choice.message.tool_calls:
                messages.append(choice.message)
                for tc in choice.message.tool_calls:
                    messages.append({"role": "tool", "tool_call_id": tc.id, "content": '{"note":"round limit, give verdict now"}'})
                resp = _llm_client.chat.completions.create(
                    model=_llm_model, messages=messages,
                    max_tokens=LLM_MAX_TOKENS, temperature=LLM_TEMPERATURE)
                choice = resp.choices[0]
            # final response
            content = (choice.message.content or "").strip()
            # strip markdown fences and prose prefix before JSON
            content = re.sub(r"^```json\s*", "", content)
            content = re.sub(r"```\s*$", "", content)
            # extract first JSON object containing "verdict" — brace-balanced
            if not content.startswith("{"):
                start = content.find('{"verdict"')
                if start == -1:
                    start = content.find('{')
                if start != -1 and '"verdict"' in content[start:]:
                    depth = 0
                    for i, ch in enumerate(content[start:], start):
                        if ch == '{': depth += 1
                        elif ch == '}': depth -= 1
                        if depth == 0:
                            content = content[start:i+1]
                            break
            try:
                data = json.loads(content)
                return data.get("verdict"), data.get("notes", "")
            except (json.JSONDecodeError, AttributeError):
                log.warning(f"LLM unparseable for {cve_id}: {content[:200]}")
                return None, None
        log.warning(f"LLM exceeded {max_rounds} rounds for {cve_id}")
    except Exception as ex:
        log.warning(f"LLM err for {cve_id}: {ex}")
    return None, None



def _select_enrich_candidates(conn, limit=None):
    """Pick a fair enrich batch so old backlog is not starved by a flood of new rows.

    Previously: `ORDER BY created_at DESC LIMIT 500` — if more than 500 new
    unverified rows arrived faster than LLM could clear them, older candidates
    never left `llm_verified=0` (queue starvation).

    Now (per cycle, default ENRICH_LIMIT=200, overridable via env):
      1. Newest high-priority (RCE/bypass + 1day) — up to limit//2
      2. Oldest remaining unverified — fill the rest (drains backlog FIFO)
    Returns (rows, backlog_total_before_batch).
    """
    limit = limit if limit is not None else ENRICH_LIMIT
    cols = ("key, cve_id, source, title, link, summary, reason, severity, cvss, "
            "freshness, cvss_pr, cvss_ui, vuln_type")
    where = "llm_verified = 0 AND reason NOT IN ('excluded', 'no hit')"
    backlog = conn.execute(f"SELECT COUNT(*) FROM vulns WHERE {where}").fetchone()[0]
    if backlog == 0:
        return [], 0

    n_high = max(1, limit // 2)
    high = conn.execute(
        f"SELECT {cols} FROM vulns WHERE {where} "
        f"AND vuln_type IN ('RCE','bypass') AND freshness='1day' "
        f"ORDER BY created_at DESC LIMIT ?",
        (n_high,),
    ).fetchall()
    seen = {r[0] for r in high}
    n_old = max(0, limit - len(high))
    old = []
    if n_old:
        # Oldest first among everything not already picked — drains starvation.
        for r in conn.execute(
            f"SELECT {cols} FROM vulns WHERE {where} "
            f"ORDER BY created_at ASC LIMIT ?",
            (limit,),  # over-fetch then filter; limit is small
        ).fetchall():
            if r[0] in seen:
                continue
            old.append(r)
            seen.add(r[0])
            if len(old) >= n_old:
                break
    # Preserve high-priority first (so auto-approve / LLM sees fresh RCE sooner),
    # then oldest backlog filler.
    return list(high) + old, backlog


def _cmd_enrich_inner(dry=False):
    with _db() as conn:
        init_db(conn)
        _warm_nvd_cache(conn)

        # Phase 1: NVD severity/CVSS backfill
        _backfill_nvd_severity(conn)

        # Phase 2: LLM enrichment
        api_key = DEEPSEEK_API_KEY or OPENAI_API_KEY
        if not api_key:
            log.info("enrich: no LLM API key, skipping LLM enrichment")
        else:
            candidates, backlog = _select_enrich_candidates(conn)
            if backlog > len(candidates):
                log.info(
                    f"enrich: backlog={backlog} batch={len(candidates)} "
                    f"(ENRICH_LIMIT={ENRICH_LIMIT}; older rows will drain next cycles)"
                )

            if candidates:
                # group by CVE to avoid duplicate LLM calls
                by_cve = {}
                no_cve = []
                for rec in candidates:
                    cve_id = rec[1]
                    if cve_id and cve_id.startswith("CVE-"):
                        by_cve.setdefault(cve_id, []).append(rec)
                    else:
                        no_cve.append(rec)

                auto_approved = llm_processed = llm_errors = 0

                # auto-approve: any record from high-trust source + critical CVSS
                for cve_id, records in by_cve.items():
                    rep = records[0]
                    any_high_trust = any(r[_E_SRC] in HIGH_PRIORITY_SOURCES for r in records)
                    best_cvss = max((r[_E_CVSS] for r in records if r[_E_CVSS]), default=None)
                    if any_high_trust and best_cvss and best_cvss >= 9.0:
                        for rec in records:
                            pushed_val = _resolve_pushed(
                                "confirmed", rec[_E_FRESH], rec[_E_SRC],
                                rec[_E_PR], rec[_E_UI], rec[_E_VT])
                            conn.execute(
                                "UPDATE vulns SET llm_verified=1, llm_verdict='confirmed', "
                                "llm_notes='auto: high-trust + CVSS>=9.0', pushed=? WHERE key=?",
                                (pushed_val, rec[_E_KEY]))
                        conn.commit()
                        auto_approved += len(records)
                        continue

                    # LLM enrichment
                    verdict, notes = _enrich_one(rep)
                    if verdict is None:
                        llm_errors += 1
                        continue
                    for rec in records:
                        pushed_val = _resolve_pushed(
                            verdict, rec[_E_FRESH], rec[_E_SRC],
                            rec[_E_PR], rec[_E_UI], rec[_E_VT])
                        conn.execute(
                            "UPDATE vulns SET llm_verified=1, llm_verdict=?, llm_notes=?, pushed=? WHERE key=?",
                            (verdict, (notes or "")[:500], pushed_val, rec[_E_KEY]))
                    conn.commit()
                    llm_processed += 1
                    time.sleep(0.5)

                # non-CVE records
                for rec in no_cve:
                    verdict, notes = _enrich_one(rec)
                    if verdict is None:
                        llm_errors += 1
                        continue
                    pushed_val = _resolve_pushed(
                        verdict, rec[_E_FRESH], rec[_E_SRC],
                        rec[_E_PR], rec[_E_UI], rec[_E_VT])
                    conn.execute(
                        "UPDATE vulns SET llm_verified=1, llm_verdict=?, llm_notes=?, pushed=? WHERE key=?",
                        (verdict, (notes or "")[:500], pushed_val, rec[_E_KEY]))
                    conn.commit()
                    llm_processed += 1
                    time.sleep(0.5)
                remaining = conn.execute(
                    "SELECT COUNT(*) FROM vulns WHERE llm_verified=0 "
                    "AND reason NOT IN ('excluded', 'no hit')"
                ).fetchone()[0]
                log.info(
                    f"enrich: auto={auto_approved} llm={llm_processed} "
                    f"errors={llm_errors} backlog_left={remaining}"
                )

                # fallback: too many LLM errors → regex gate for THIS batch's
                # still-unverified rows only (not the entire table — avoids a
                # sudden flood when LLM flakes on a large backlog).
                if llm_errors > 3:
                    batch_keys = [r[0] for r in candidates]
                    placeholders = ",".join("?" * len(batch_keys))
                    fallback = conn.execute(
                        "UPDATE vulns SET llm_verified=1, llm_verdict='confirmed', "
                        "llm_notes='fallback: LLM errors, regex-scored', pushed=1 "
                        f"WHERE key IN ({placeholders}) AND llm_verified=0 "
                        "AND vuln_type IN ('RCE','bypass') "
                        "AND freshness='1day' AND source NOT IN ('GitHub','PoC-GitHub') "
                        "AND cvss_pr='N' AND (cvss_ui IS NULL OR cvss_ui='N')",
                        batch_keys,
                    ).rowcount
                    conn.commit()
                    if fallback:
                        log.warning(
                            f"enrich: LLM errors, fell back to regex for "
                            f"{fallback} records in this batch"
                        )
            else:
                log.info("enrich: no unverified candidates")

        # Phase 3: push pending
        if not dry:
            try:
                from src.pipeline import _push_pending
            except ImportError:
                from pipeline import _push_pending
            _push_pending(conn)


