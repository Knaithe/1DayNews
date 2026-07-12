"""NVD/GitHub advisory lookups, CVSS backfill, and freshness (1day/nday)."""
import re
import time
from datetime import datetime, timedelta, timezone

try:
    from src.config import NVD_API_KEY, GH_TOKEN, FRESH_SOURCES, SESS, log
    from src.scoring import CVE_RE, score
    from src.push_gate import _llm_configured
except ImportError:
    from config import NVD_API_KEY, GH_TOKEN, FRESH_SOURCES, SESS, log
    from scoring import CVE_RE, score
    from push_gate import _llm_configured

def _extract_pr(vector):
    if not vector:
        return None
    m = re.search(r"PR:([NLH])", vector)
    return m.group(1) if m else None


def _extract_ui(vector):
    if not vector:
        return None
    m = re.search(r"UI:([NR])", vector)
    return m.group(1) if m else None


_NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_FRESHNESS_DAYS = 60
_nvd_cache = {}       # cve_id → {"published":"YYYY-MM-DD","cvss":float,"severity":str} or "" or None
_nvd_detail_cache = {}  # full detail cache for LLM tools

def _nvd_detail(cve_id):
    """Query NVD for CVE detail. Returns dict or None.

    Returns: {"published": "YYYY-MM-DD", "cvss": float, "severity": str, "description": str}
    Cache: in-memory dict → NVD API. DB cache handled by caller.
    """
    cve_upper = cve_id.upper()
    # check full detail cache
    if cve_upper in _nvd_detail_cache:
        return _nvd_detail_cache[cve_upper] or None
    # check date-only cache (from _warm_nvd_cache)
    if cve_upper in _nvd_cache:
        cached = _nvd_cache[cve_upper]
        if cached == "":
            return None  # confirmed not in NVD/GitHub, no point retrying
        if cached is None:
            pass  # rate-limited — fall through to query
        elif isinstance(cached, str) and cached:
            # have date in cache but no full detail yet — build partial detail, don't re-query NVD
            _nvd_detail_cache[cve_upper] = {"published": cached, "cvss": None, "severity": None, "description": "", "vector": None}
            return _nvd_detail_cache[cve_upper]
    # query NVD (rate limit: 50 req/30s with key, 5 req/30s without)
    _nvd_sleep = 0.7 if NVD_API_KEY else 6.5
    time.sleep(_nvd_sleep)
    try:
        hdrs = {"User-Agent": "vuln-monitor/1.0 (security research)"}
        if NVD_API_KEY:
            hdrs["apiKey"] = NVD_API_KEY
        r = SESS.get(_NVD_API, params={"cveId": cve_upper}, timeout=10, headers=hdrs)  # Fix #6: use SESS for proxy
        if r.status_code in (403, 429):
            # rate limited — DON'T cache, allow retry next cycle
            log.debug(f"NVD rate limited for {cve_upper}")
            return None
        if r.status_code != 200:
            _nvd_cache[cve_upper] = ""
            return None
        vulns = r.json().get("vulnerabilities", [])
        if vulns:
            cve_data = vulns[0]["cve"]
            pub = cve_data.get("published", "")
            pub_str = None
            if pub:
                dt = datetime.fromisoformat(pub.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                pub_str = dt.strftime("%Y-%m-%d")
            cvss = None
            severity = None
            vector = None
            for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metrics = cve_data.get("metrics", {}).get(metric_key, [])
                if metrics:
                    cvss_data = metrics[0].get("cvssData", {})
                    cvss = cvss_data.get("baseScore")
                    severity = cvss_data.get("baseSeverity", "").lower()
                    vector = cvss_data.get("vectorString", "")
                    break
            if cvss and not severity:
                severity = "critical" if cvss >= 9.0 else "high" if cvss >= 7.0 else "medium" if cvss >= 4.0 else "low"
            descs = cve_data.get("descriptions", [])
            desc_en = next((d["value"] for d in descs if d.get("lang") == "en"), "")
            detail = {"published": pub_str, "cvss": cvss, "severity": severity, "description": desc_en, "vector": vector}
            _nvd_cache[cve_upper] = pub_str or ""
            _nvd_detail_cache[cve_upper] = detail
            return detail
        # NVD has no data — fall through to GitHub Advisory fallback
    except Exception:
        pass
    # fallback: GitHub Advisory Database (often has data before NVD, especially for OSS)
    time.sleep(1)  # Fix #11: rate limit coordination
    try:
        hdrs = {"Accept": "application/vnd.github+json"}
        if GH_TOKEN:
            hdrs["Authorization"] = f"Bearer {GH_TOKEN}"
        r = SESS.get("https://api.github.com/advisories",  # Fix #6: use SESS for proxy
                     params={"cve_id": cve_upper}, headers=hdrs, timeout=10)
        if r.status_code == 200 and r.json():
            adv = r.json()[0]
            pub_raw = adv.get("published_at", "")
            pub_str = pub_raw[:10] if pub_raw else None
            cvss = None
            severity = None
            vector = adv.get("cvss", {}).get("vector_string", "")
            if adv.get("cvss", {}).get("score"):
                cvss = float(adv["cvss"]["score"])
            sev_raw = adv.get("severity", "")
            if sev_raw in ("critical", "high", "medium", "low"):
                severity = sev_raw
            if cvss and not severity:
                severity = "critical" if cvss >= 9.0 else "high" if cvss >= 7.0 else "medium" if cvss >= 4.0 else "low"
            desc = adv.get("description", "") or adv.get("summary", "")
            detail = {"published": pub_str, "cvss": cvss, "severity": severity, "description": desc, "vector": vector}
            _nvd_cache[cve_upper] = pub_str or ""
            _nvd_detail_cache[cve_upper] = detail
            return detail
    except Exception:
        pass
    # both NVD and GitHub failed — mark as empty to stop retrying (Fix #3)
    _nvd_cache[cve_upper] = ""
    _nvd_detail_cache[cve_upper] = None
    return None

def _nvd_published_date(cve_id):
    """Thin wrapper: returns (datetime, "YYYY-MM-DD") or (None, None)."""
    detail = _nvd_detail(cve_id)
    if detail and detail.get("published"):
        pub_str = detail["published"]
        try:
            dt = datetime.fromisoformat(pub_str).replace(tzinfo=timezone.utc)
        except ValueError:
            return None, None
        return dt, pub_str
    return None, None

def _cvss_to_severity(score):
    """Convert CVSS float to severity string."""
    if score >= 9.0: return "critical"
    if score >= 7.0: return "high"
    if score >= 4.0: return "medium"
    return "low"


def _backfill_fortinet(conn):
    """Extract CVSS from Fortinet advisory summary (contains 'CVSSv3 Score: x.x')."""
    rows = conn.execute(
        "SELECT key, summary FROM vulns "
        "WHERE source='Fortinet' AND cvss IS NULL AND summary IS NOT NULL"
    ).fetchall()
    updated = 0
    for key, summary in rows:
        m = re.search(r"CVSSv3\s*Score:\s*(\d+(?:\.\d+)?)", summary)
        if not m:
            continue
        score = float(m.group(1))
        if 0 <= score <= 10:
            conn.execute(
                "UPDATE vulns SET cvss=?, severity=? WHERE key=?",
                (score, _cvss_to_severity(score), key))
            updated += 1
    if updated:
        conn.commit()
        log.info(f"backfill_fortinet: extracted CVSS for {updated} records")


def _backfill_zdi(conn):
    """Fetch CVSS from ZDI advisory page (HTML contains 'CVSS SCORE ... x.x')."""
    rows = conn.execute(
        "SELECT key, link FROM vulns "
        "WHERE source='ZDI' AND cvss IS NULL AND link IS NOT NULL "
        "LIMIT 20"
    ).fetchall()
    updated = 0
    for key, link in rows:
        try:
            r = SESS.get(link, timeout=10, headers={"User-Agent": "vuln-monitor/1.0"})
            if r.status_code != 200:
                continue
            m = re.search(r"CVSS SCORE.*?(\d+\.\d+)", r.text, re.S)
            if not m:
                continue
            score = float(m.group(1))
            if 0 <= score <= 10:
                conn.execute(
                    "UPDATE vulns SET cvss=?, severity=? WHERE key=?",
                    (score, _cvss_to_severity(score), key))
                updated += 1
        except Exception:
            continue
        time.sleep(1)
    if updated:
        conn.commit()
        log.info(f"backfill_zdi: fetched CVSS for {updated} records")


def _backfill_published_fallback(conn):
    """Use created_at as cve_published fallback — only for records older than 7 days.

    Gives NVD/GitHub 7 days to populate real data before falling back.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(days=7)).timestamp()
    rows = conn.execute(
        "SELECT key, created_at FROM vulns "
        "WHERE cve_published IS NULL AND created_at IS NOT NULL AND created_at < ?",
        (cutoff,)
    ).fetchall()
    if not rows:
        return
    for key, created_at in rows:
        pub = datetime.fromtimestamp(created_at, tz=timezone.utc).strftime("%Y-%m-%d")
        conn.execute("UPDATE vulns SET cve_published=? WHERE key=?", (pub, key))
    conn.commit()
    log.info(f"backfill_published: set created_at fallback for {len(rows)} records")


def _backfill_nvd_severity(conn):
    """Backfill severity, CVSS, and cve_published from NVD + GitHub Advisory."""
    batch = 100 if NVD_API_KEY else 20
    rows = conn.execute(
        "SELECT key, cve_id FROM vulns "
        "WHERE cve_id IS NOT NULL AND cve_id LIKE 'CVE-%' "
        "AND (severity IS NULL OR cve_published IS NULL OR cvss_vector IS NULL) "
        f"LIMIT {batch}"
    ).fetchall()
    updated = 0
    for key, cve_id in rows:
        cves = CVE_RE.findall(cve_id)
        detail = None
        for c in (cves or [cve_id]):
            detail = _nvd_detail(c.upper())
            if detail and (detail.get("cvss") or detail.get("published")):
                break
        if detail and not detail.get("vector"):
            for c in (cves or [cve_id]):
                cu = c.upper()
                _nvd_cache.pop(cu, None)
                _nvd_detail_cache.pop(cu, None)
                fresh = _nvd_detail(cu)
                if fresh and fresh.get("vector"):
                    detail = fresh
                    break
        if detail:
            desc = detail.get("description", "")
            vtype_upgrade = None
            if desc:
                hit, _, vt = score(desc)
                if hit and vt in ("RCE", "bypass"):
                    vtype_upgrade = vt
            vec = detail.get("vector") or ""
            sql = ("UPDATE vulns SET severity=COALESCE(severity,?), cvss=COALESCE(cvss,?), "
                   "cve_published=COALESCE(cve_published,?), "
                   "cvss_vector=COALESCE(cvss_vector,?), cvss_pr=COALESCE(cvss_pr,?), cvss_ui=COALESCE(cvss_ui,?)")
            params = [detail.get("severity") or "unknown", detail.get("cvss"),
                      detail.get("published") or "unknown",
                      vec or "N/A", _extract_pr(vec), _extract_ui(vec)]
            if vtype_upgrade:
                sql += ", vuln_type=?"
                params.append(vtype_upgrade)
            sql += " WHERE key=?"
            params.append(key)
            conn.execute(sql, params)
            updated += 1
        else:
            conn.execute(
                "UPDATE vulns SET cvss_vector=COALESCE(cvss_vector,'N/A'), "
                "severity=COALESCE(severity,'unknown'), "
                "cve_published=COALESCE(cve_published,'unknown') WHERE key=?",
                (key,))
            updated += 1
    if updated:
        conn.commit()
        log.info(f"backfill_nvd_severity: updated {updated} records")
    # re-evaluate pushed for records that got PR=N after initial insert.
    # With LLM configured, only promote already-confirmed verdicts (never
    # skip the AI gate by promoting llm_verified=0). Without LLM, regex path.
    if _llm_configured():
        _promo_extra = "llm_verdict='confirmed'"
    else:
        _promo_extra = "llm_verified=0"
    promoted = conn.execute(
        "UPDATE vulns SET pushed=1 WHERE pushed=0 AND cvss_pr='N' "
        "AND (cvss_ui IS NULL OR cvss_ui='N') "
        "AND freshness='1day' AND source NOT IN ('GitHub','PoC-GitHub') "
        f"AND vuln_type IN ('RCE','bypass') AND reason != 'excluded' "
        f"AND ({_promo_extra})"
    ).rowcount
    if promoted:
        conn.commit()
        log.info(f"backfill_nvd_severity: promoted {promoted} records (PR=N arrived after insert)")
    # source-specific backfills
    _backfill_fortinet(conn)
    _backfill_zdi(conn)
    _backfill_published_fallback(conn)



def _warm_nvd_cache(conn):
    """Pre-load DB cve_published values into in-memory cache at startup."""
    _nvd_cache.clear()
    _nvd_detail_cache.clear()  # Fix #9: prevent unbounded memory growth
    try:
        rows = conn.execute("SELECT cve_id, cve_published FROM vulns WHERE cve_published IS NOT NULL").fetchall()
        for cve_id, pub in rows:
            if cve_id and pub:
                _nvd_cache[cve_id] = pub
    except Exception:
        pass

def _is_fresh(source, text):
    """Is this a fresh vulnerability disclosure (1day), not an nday rehash?

    Returns (fresh: bool, pub_date_str: str or None, reason: str).
    reason explains WHY: old_cve / nvd_60d / high_trust_source / nvd_stale /
    no_cve_low_trust.

    ALL sources go through NVD verification — even high-trust vendor PSIRTs.
    An extra layer of checking never hurts: if a vuln is genuinely fresh, NVD
    will confirm it. High-trust sources fall back to CVE-year when NVD has no
    data yet (new CVEs not indexed). Low-trust sources require NVD confirmation.
    """
    cves = CVE_RE.findall(text)
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=_FRESHNESS_DAYS)
    year = now.year
    latest_pub_str = None
    has_nvd_confirmed_recent = False
    has_recent_year = False
    for c in cves:
        pub_dt, pub_str = _nvd_published_date(c.upper())
        if pub_str:
            if latest_pub_str is None or pub_str > latest_pub_str:
                latest_pub_str = pub_str
            if pub_dt and pub_dt >= cutoff:
                has_nvd_confirmed_recent = True
        else:
            try:
                cve_year = int(c.split("-")[1])
                if cve_year >= year - 1:
                    has_recent_year = True
            except (IndexError, ValueError):
                pass
    # hard cutoff: if ALL CVEs are > 1 year old → nday
    if cves:
        all_old = True
        for c in cves:
            try:
                cve_year = int(c.split("-")[1])
                if cve_year >= year - 1:
                    all_old = False
                    break
            except (IndexError, ValueError):
                all_old = False
                break
        if all_old:
            return False, latest_pub_str, "old_cve"
    # high-trust sources: NVD confirmed, or year fallback when NVD unavailable
    if source in FRESH_SOURCES:
        if has_nvd_confirmed_recent:
            return True, latest_pub_str, "high_trust_source"
        if has_recent_year:
            return True, latest_pub_str, "high_trust_source"
        if not cves:
            return True, latest_pub_str, "high_trust_source"
        return False, latest_pub_str, "nvd_stale"
    # low-trust sources: no CVE = can't verify
    if not cves:
        return False, None, "no_cve_low_trust"
    # low-trust with CVE: require actual NVD confirmation, year fallback not trusted
    if has_nvd_confirmed_recent:
        return True, latest_pub_str, "nvd_60d"
    return False, latest_pub_str, "nvd_60d"



