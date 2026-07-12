"""Fetch pipeline, push pending, rescore/rebuild orchestration."""
import hashlib
import os
import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    from src.config import (
        LOCK_FILE, FETCH_STATE, SEED_MARKER, FRESH_SOURCES, STRONG_VULN_TYPES,
        VENDOR_URL_FALLBACK, TG_BOT_TOKEN, TG_CHAT_IDS, WECOM_WEBHOOK_KEY,
        DINGTALK_WEBHOOK_TOKEN, FEISHU_WEBHOOK_URL, PUSH_SLEEP_SEC, log,
    )
    from src.scoring import CVE_RE, score, classify_category
    from src.db import _db, init_db, migrate_json_cache, db_cleanup
    from src.sources import _fetch_all_sources
    from src.nvd import (
        _warm_nvd_cache, _is_fresh, _extract_pr, _extract_ui,
        _nvd_detail_cache, _FRESHNESS_DAYS,
    )
    from src.push_gate import _llm_configured, _regex_push_candidate, _initial_pushed
    from src.notify import (
        _extract_id, format_msg, send_telegram, format_msg_wecom, send_wecom,
        format_msg_dingtalk, send_dingtalk, format_msg_feishu, send_feishu,
    )
except ImportError:
    from config import (
        LOCK_FILE, FETCH_STATE, SEED_MARKER, FRESH_SOURCES, STRONG_VULN_TYPES,
        VENDOR_URL_FALLBACK, TG_BOT_TOKEN, TG_CHAT_IDS, WECOM_WEBHOOK_KEY,
        DINGTALK_WEBHOOK_TOKEN, FEISHU_WEBHOOK_URL, PUSH_SLEEP_SEC, log,
    )
    from scoring import CVE_RE, score, classify_category
    from db import _db, init_db, migrate_json_cache, db_cleanup
    from sources import _fetch_all_sources
    from nvd import (
        _warm_nvd_cache, _is_fresh, _extract_pr, _extract_ui,
        _nvd_detail_cache, _FRESHNESS_DAYS,
    )
    from push_gate import _llm_configured, _regex_push_candidate, _initial_pushed
    from notify import (
        _extract_id, format_msg, send_telegram, format_msg_wecom, send_wecom,
        format_msg_dingtalk, send_dingtalk, format_msg_feishu, send_feishu,
    )

import sys

# ================== LOCK ==================
class SingletonLock:
    """Prevent overlapping runs. fcntl on POSIX, msvcrt on Windows."""

    def __init__(self, path):
        self.path = path
        self.fh = None

    def __enter__(self):
        self.fh = open(self.path, "a+b")
        self.fh.seek(0, 2)
        if self.fh.tell() == 0:
            self.fh.write(b"0")
            self.fh.flush()
        self.fh.seek(0)
        try:
            if sys.platform == "win32":
                import msvcrt
                msvcrt.locking(self.fh.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, BlockingIOError) as ex:
            self.fh.close()
            self.fh = None
            raise RuntimeError(f"another instance is running ({self.path}): {ex}")
        return self

    def __exit__(self, *a):
        if self.fh:
            try:
                if sys.platform == "win32":
                    import msvcrt
                    self.fh.seek(0)
                    msvcrt.locking(self.fh.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self.fh.fileno(), fcntl.LOCK_UN)
            except Exception:
                pass
            try:
                self.fh.close()
            except Exception:
                pass



def _backfill_row(conn, key, it):
    """UPDATE a record's NULL fields with fresh data from a source item."""
    tag = _extract_id(it["text"], it["link"])
    conn.execute(
        "UPDATE vulns SET cve_id=COALESCE(cve_id,?), source=COALESCE(source,?), "
        "title=COALESCE(title,?), link=COALESCE(link,?), summary=COALESCE(summary,?) "
        "WHERE key=?",
        (tag if tag != "N/A" else None, it["source"],
         it["title"][:300], it["link"], it["summary"][:500], key),
    )

def _infer_source_from_title(title):
    """Best-effort vendor inference from title keywords."""
    low = (title or "").lower()
    for kw, src in (
        ("[kev]", "CISA_KEV"),
        ("zdi-", "ZDI"),
        ("fortiweb", "Fortinet"), ("fortigate", "Fortinet"), ("fortios", "Fortinet"),
        ("fortimanager", "Fortinet"), ("fortianalyzer", "Fortinet"), ("forticlient", "Fortinet"),
        ("fortiproxy", "Fortinet"), ("fortisandbox", "Fortinet"), ("fortisiem", "Fortinet"),
        ("fortisoar", "Fortinet"), ("fortiswitch", "Fortinet"), ("fortiadc", "Fortinet"),
        ("fortinac", "Fortinet"), ("fortiportal", "Fortinet"),
        ("pan-os", "PaloAlto"), ("globalprotect", "PaloAlto"), ("cortex xdr", "PaloAlto"),
        ("palo alto", "PaloAlto"), ("prisma access", "PaloAlto"),
        ("cisco", "Cisco"), ("ios-xe", "Cisco"), ("ios-xr", "Cisco"),
        ("webex", "Cisco"), ("anyconnect", "Cisco"), ("firepower", "Cisco"),
        ("vmware", "VMware"), ("vcenter", "VMware"), ("esxi", "VMware"),
    ):
        if kw in low:
            return src
    return None

def _enrich_record(cve_id, source, title, link):
    """Heuristic enrichment for incomplete records.

    Returns (cve_id, source, link) with NULLs filled where possible.
    """
    # --- infer source from advisory ID pattern ---
    if not source and cve_id:
        for pat, src in (
            (r"FG-IR-", "Fortinet"), (r"ZDI-", "ZDI"), (r"cisco-sa-", "Cisco"),
            (r"PAN-SA-", "PaloAlto"), (r"VMSA-", "VMware"),
        ):
            if re.match(pat, cve_id, re.I):
                source = src
                break
    # --- infer source from title keywords ---
    if not source:
        source = _infer_source_from_title(title)
    # --- construct link from advisory ID ---
    if not link and cve_id:
        if re.match(r"CVE-\d{4}-\d+", cve_id, re.I):
            link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        elif re.match(r"FG-IR-\d+-\d+", cve_id, re.I):
            link = f"https://fortiguard.fortinet.com/psirt/{cve_id}"
        elif re.match(r"ZDI-\d+-\d+", cve_id, re.I):
            link = f"https://www.zerodayinitiative.com/advisories/{cve_id}/"
        elif re.match(r"cisco-sa-", cve_id, re.I):
            link = f"https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/{cve_id}"
        elif re.match(r"PAN-SA-", cve_id, re.I):
            link = f"https://security.paloaltonetworks.com/{cve_id}"
    # --- fallback: vendor advisory listing page ---
    if not link and source and source in VENDOR_URL_FALLBACK:
        link = VENDOR_URL_FALLBACK[source]
    return cve_id, source, link

def _auto_enrich():
    """Find incomplete strong-reason records and persist heuristic enrichment.

    Returns number of records updated.
    """
    with _db() as conn:
        init_db(conn)
        # Match strong vuln types
        type_clauses = []
        type_params = []
        for t in STRONG_VULN_TYPES:
            type_clauses.append("vuln_type = ?")
            type_params.append(t)
        candidates = conn.execute(
            f"SELECT key, cve_id, source, title, link FROM vulns "
            f"WHERE (link IS NULL OR link = '') AND ({' OR '.join(type_clauses)})",
            type_params,
        ).fetchall()
        updated = 0
        for key, cve_id, source, title, link in candidates:
            new_cve, new_src, new_link = _enrich_record(cve_id, source, title, link)
            if new_link != link or new_src != source or new_cve != cve_id:
                conn.execute(
                    "UPDATE vulns SET cve_id=COALESCE(cve_id,?), source=COALESCE(source,?), "
                    "link=COALESCE(link,?) WHERE key=?",
                    (new_cve, new_src, new_link, key),
                )
                updated += 1
        conn.commit()
    return updated

_ADVISORY_ID_RE = re.compile(
    r"(XVE-\d{4}-\d+|FG-IR-\d+-\d+|ZDI-\d+-\d+|GHSA-[\w-]+|PAN-SA-\d+-\d+|CT-\d+)", re.I
)

def item_key(title, link, text):
    cves = sorted(set(c.upper() for c in CVE_RE.findall(text)))
    if cves:
        return "cve:" + cves[0]
    # advisory IDs (XVE/FG-IR/ZDI/GHSA/CT) — stable across link/title changes
    adv_ids = sorted(set(m.upper() for m in _ADVISORY_ID_RE.findall(text)))
    if adv_ids:
        return "adv:" + adv_ids[0]
    # fallback: link-only hash
    if link:
        return "u:" + hashlib.sha1(link.encode("utf-8")).hexdigest()[:16]
    return "h:" + hashlib.sha1((title + "|" + (link or "")).encode("utf-8")).hexdigest()[:16]





def _write_fetch_state(collected, pushed, filtered, already_seen, backfilled, db_size):
    """Persist last-fetch stats (timestamp + counts) so the dashboard can show them."""
    try:
        state = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "collected": collected,
            "new": collected - already_seen,
            "pushed": pushed,
            "filtered": filtered,
            "already_seen": already_seen,
            "backfilled": backfilled,
            "db_size": db_size,
        }
        tmp = FETCH_STATE.with_suffix(".tmp")
        tmp.write_text(json.dumps(state), encoding="utf-8")
        os.replace(tmp, FETCH_STATE)
        os.chmod(FETCH_STATE, 0o644)   # readable by the web service even if umask is 077
    except Exception:
        log.warning("failed to write fetch_state.json", exc_info=True)


def _run(no_push=False):
    with _db() as conn:
        init_db(conn)
        migrate_json_cache(conn)
        _warm_nvd_cache(conn)
        now = datetime.now(timezone.utc).timestamp()

        # detect cold start: suppress push only on the first-ever seeding run.
        # Combined condition (no SEED_MARKER yet AND DB empty) so that a later DB
        # reset — marker still present — does NOT silently re-suppress real 0day
        # alerts, and an existing install (non-empty DB) is never treated as cold
        # on deploy.
        _cold_start = (not SEED_MARKER.exists()) and \
            conn.execute("SELECT COUNT(*) FROM vulns").fetchone()[0] == 0

        items = _fetch_all_sources()
        log.info(f"collected {len(items)} items")

        seen_this_run = set()
        pushed = 0
        skipped_seen = 0
        skipped_filter = 0
        backfilled = 0

        for it in items:
            key = item_key(it["title"], it["link"], it["text"])
            if key in seen_this_run:
                skipped_seen += 1
                continue

            row = conn.execute("SELECT source, link FROM vulns WHERE key=?", (key,)).fetchone()
            if row:
                if row[0] is None or row[1] is None:
                    _backfill_row(conn, key, it)
                    backfilled += 1
                skipped_seen += 1
                seen_this_run.add(key)
                continue
            seen_this_run.add(key)

            # ── Exploitability (severity) ──
            hit, reason, vuln_type = score(it["text"])
            category = classify_category(vuln_type, it["text"], reason)

            # ── Freshness — ALL records with CVE get cve_published + freshness ──
            cve_pub = None
            freshness = None
            fresh_reason = None
            if CVE_RE.search(it["text"]):
                fresh, cve_pub, fresh_reason = _is_fresh(it["source"], it["text"])
                freshness = "1day" if fresh else "nday"
                if hit and not fresh:
                    hit = False
            elif it["source"] in FRESH_SOURCES:
                # check source-provided publish date first (e.g. ThreatBook vuln_publish_time)
                src_pub = it.get("_pub_date", "")
                if src_pub:
                    cve_pub = src_pub[:10]
                    try:
                        pub_dt = datetime.fromisoformat(src_pub[:10]).replace(tzinfo=timezone.utc)
                        cutoff = datetime.now(timezone.utc) - timedelta(days=_FRESHNESS_DAYS)
                        if pub_dt >= cutoff:
                            freshness = "1day"
                            fresh_reason = "source_pub_date"
                        else:
                            freshness = "nday"
                            fresh_reason = "source_pub_date"
                            hit = False
                    except ValueError:
                        freshness = "1day"
                        fresh_reason = "high_trust_source"
                else:
                    # fallback: check advisory ID year (XVE-2023, FG-IR-24, etc.)
                    year = datetime.now(timezone.utc).year
                    id_year_m = re.search(r'(?:XVE|FG-IR|ZDI|PAN-SA)-(\d{4})', it["text"])
                    if id_year_m and int(id_year_m.group(1)) < year - 1:
                        freshness = "nday"
                        fresh_reason = "old_advisory_id"
                        hit = False
                    else:
                        freshness = "1day"
                        fresh_reason = "high_trust_source"
            elif hit:
                # low-trust source, no CVE → can't verify freshness
                freshness = "nday"
                fresh_reason = "no_cve_low_trust"
                hit = False

            tag = _extract_id(it["text"], it["link"])
            cve_id = tag if tag != "N/A" else None
            nvd = _nvd_detail_cache.get(cve_id.upper()) if cve_id and cve_id.startswith("CVE-") else None
            nvd_severity = nvd["severity"] if nvd else None
            nvd_cvss = nvd["cvss"] if nvd else None
            nvd_vector = nvd.get("vector") if nvd else None
            # fallback: use source-provided severity/cvss/vector (e.g. GHSA)
            if not nvd_severity:
                nvd_severity = it.get("_severity")
            if not nvd_cvss:
                nvd_cvss = it.get("_cvss")
            if not nvd_vector:
                nvd_vector = it.get("_cvss_vector")
            pr = _extract_pr(nvd_vector)
            ui = _extract_ui(nvd_vector)
            is_candidate = _regex_push_candidate(
                hit, vuln_type, freshness, it["source"], pr, ui)
            pushed_val = _initial_pushed(
                hit, vuln_type, freshness, it["source"], pr, ui)
            conn.execute(
                "INSERT OR IGNORE INTO vulns (key,cve_id,source,title,link,summary,reason,vuln_type,category,freshness,freshness_reason,pushed,created_at,cve_published,severity,cvss,cvss_vector,cvss_pr,cvss_ui) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (key, cve_id, it["source"], it["title"][:300], it["link"],
                 it["summary"][:500], reason, vuln_type, category, freshness, fresh_reason,
                 pushed_val, now, cve_pub, nvd_severity, nvd_cvss,
                 nvd_vector, pr, ui),
            )
            if is_candidate:
                pushed += 1
            else:
                skipped_filter += 1

        conn.commit()

        # cold start: mark all records as already sent to prevent initial flood
        if _cold_start:
            suppressed = conn.execute(
                "UPDATE vulns SET tg_sent=1, wecom_sent=1, dingtalk_sent=1, feishu_sent=1 "
                "WHERE pushed=1 AND (tg_sent=0 OR wecom_sent=0 OR dingtalk_sent=0 OR feishu_sent=0)"
            ).rowcount
            conn.commit()
            if suppressed:
                log.info(f"cold start: suppressed {suppressed} initial notifications (seeding run)")

        # mark this install as seeded once the first run completes — future DB
        # resets (marker present) won't re-trigger cold-start suppression.
        if not SEED_MARKER.exists():
            try:
                SEED_MARKER.touch()
            except OSError:
                log.warning("failed to write seed marker", exc_info=True)

        db_cleanup(conn)
        total = conn.execute("SELECT COUNT(*) FROM vulns").fetchone()[0]
        log.info(
            f"done: pushed={pushed}  filtered={skipped_filter}  already_seen={skipped_seen}  "
            f"backfilled={backfilled}  db_size={total}"
        )
        _write_fetch_state(len(items), pushed, skipped_filter, skipped_seen, backfilled, total)

        # Send pending Telegram notifications (unless --no-push)
        if not no_push:
            _push_pending(conn)


def _push_pending(conn):
    """Send notifications via all configured channels for pushed=1 records.

    When an LLM key is configured, require llm_verified=1 as well so a lone
    `fetch` (or stale regex pushed=1 rows) cannot notify past the AI gate.
    Without LLM, pushed=1 from the regex gate is sufficient.
    """
    llm_gate = " AND llm_verified=1" if _llm_configured() else ""
    pending = conn.execute(
        "SELECT key, cve_id, source, title, link, summary, reason, llm_verdict, llm_notes, "
        "tg_sent, wecom_sent, dingtalk_sent, feishu_sent "
        "FROM vulns WHERE pushed=1" + llm_gate + " AND "
        "(tg_sent=0 OR wecom_sent=0 OR dingtalk_sent=0 OR feishu_sent=0)"
    ).fetchall()
    if not pending:
        return
    counts = {"telegram": 0, "wecom": 0, "dingtalk": 0, "feishu": 0}
    for (key, cve_id, source, title, link, summary, reason, verdict, notes,
         tg_done, wecom_done, dingtalk_done, feishu_done) in pending:
        it = {"source": source or "", "title": title or "", "link": link or "",
              "summary": summary or "", "text": f"{title or ''}\n{summary or ''}"}
        if not tg_done:
            if not (TG_BOT_TOKEN and TG_CHAT_IDS):
                conn.execute("UPDATE vulns SET tg_sent=1 WHERE key=?", (key,))
            elif send_telegram(format_msg(it, reason)):
                conn.execute("UPDATE vulns SET tg_sent=1 WHERE key=?", (key,))
                counts["telegram"] += 1
        if not wecom_done:
            if not WECOM_WEBHOOK_KEY:
                conn.execute("UPDATE vulns SET wecom_sent=1 WHERE key=?", (key,))
            elif send_wecom(format_msg_wecom(it, reason)):
                conn.execute("UPDATE vulns SET wecom_sent=1 WHERE key=?", (key,))
                counts["wecom"] += 1
        if not dingtalk_done:
            if not DINGTALK_WEBHOOK_TOKEN:
                conn.execute("UPDATE vulns SET dingtalk_sent=1 WHERE key=?", (key,))
            else:
                dt_title, dt_text = format_msg_dingtalk(it, reason)
                if send_dingtalk(dt_title, dt_text):
                    conn.execute("UPDATE vulns SET dingtalk_sent=1 WHERE key=?", (key,))
                    counts["dingtalk"] += 1
        if not feishu_done:
            if not FEISHU_WEBHOOK_URL:
                conn.execute("UPDATE vulns SET feishu_sent=1 WHERE key=?", (key,))
            else:
                fs_title, fs_content = format_msg_feishu(it, reason)
                if send_feishu(fs_title, fs_content):
                    conn.execute("UPDATE vulns SET feishu_sent=1 WHERE key=?", (key,))
                    counts["feishu"] += 1
        conn.commit()
        time.sleep(PUSH_SLEEP_SEC)
    active = {k: v for k, v in counts.items() if v > 0}
    if active:
        log.info(f"push: {' '.join(f'{k}={v}' for k, v in active.items())}")



def cmd_rescore(args):
    """Re-evaluate all records with current score() + _is_fresh() rules."""
    with SingletonLock(LOCK_FILE):
        _cmd_rescore_inner()

def _cmd_rescore_inner():
    with _db() as conn:
        init_db(conn)
        _warm_nvd_cache(conn)
        # only rescore records NOT yet verified by LLM — don't override LLM verdicts
        rows = conn.execute("SELECT key, cve_id, source, title, link, summary, reason, pushed, cve_published, cvss_pr, cvss_ui FROM vulns WHERE llm_verified=0").fetchall()
        upgraded = downgraded = unchanged = 0
        for key, cve_id, source, title, link, summary, old_reason, old_pushed, existing_pub, cvss_pr, cvss_ui in rows:
            text = f"{title or ''}\n{summary or ''}"

            hit, reason, vuln_type = score(text)
            category = classify_category(vuln_type, text, reason)
            cve_pub = None
            freshness = None
            fresh_reason = None
            if CVE_RE.search(text):
                fresh, cve_pub, fresh_reason = _is_fresh(source or "", text)
                freshness = "1day" if fresh else "nday"
                if hit and not fresh:
                    hit = False
            elif source in FRESH_SOURCES:
                # use existing cve_published from DB if available (same as _run's _pub_date)
                if existing_pub:
                    try:
                        pub_dt = datetime.fromisoformat(existing_pub[:10]).replace(tzinfo=timezone.utc)
                        cutoff = datetime.now(timezone.utc) - timedelta(days=_FRESHNESS_DAYS)
                        if pub_dt >= cutoff:
                            freshness = "1day"
                            fresh_reason = "source_pub_date"
                        else:
                            freshness = "nday"
                            fresh_reason = "source_pub_date"
                            hit = False
                    except ValueError:
                        freshness = "1day"
                        fresh_reason = "high_trust_source"
                else:
                    year = datetime.now(timezone.utc).year
                    id_year_m = re.search(r'(?:XVE|FG-IR|ZDI|PAN-SA)-(\d{4})', text)
                    if id_year_m and int(id_year_m.group(1)) < year - 1:
                        freshness = "nday"
                        fresh_reason = "old_advisory_id"
                        hit = False
                    else:
                        freshness = "1day"
                        fresh_reason = "high_trust_source"
            elif hit:
                freshness = "nday"
                fresh_reason = "no_cve_low_trust"
                hit = False

            new_pushed = _initial_pushed(
                hit, vuln_type, freshness, source, cvss_pr, cvss_ui)
            if reason != old_reason or new_pushed != old_pushed or cve_pub:
                conn.execute("UPDATE vulns SET reason=?, vuln_type=?, category=?, freshness=?, freshness_reason=?, pushed=?, cve_published=COALESCE(?,cve_published) WHERE key=?",
                            (reason, vuln_type, category, freshness, fresh_reason, new_pushed, cve_pub, key))
                if new_pushed > old_pushed:
                    upgraded += 1
                elif new_pushed < old_pushed:
                    downgraded += 1
                else:
                    unchanged += 1  # reason changed but pushed same

        conn.commit()
        total = len(rows)
        same = total - upgraded - downgraded - unchanged
    print(f"rescored {total} records: {upgraded} upgraded, {downgraded} downgraded, {unchanged} reason-changed, {same} unchanged")



def cmd_rebuild(args):
    """Re-fetch all sources and backfill NULL fields in existing records."""
    with SingletonLock(LOCK_FILE):
        _cmd_rebuild_inner()

def _cmd_rebuild_inner():
    with _db() as conn:
        init_db(conn)

        items = _fetch_all_sources()
        print(f"fetched {len(items)} items from sources")

        updated = 0
        for it in items:
            key = item_key(it["title"], it["link"], it["text"])
            row = conn.execute("SELECT source, link FROM vulns WHERE key=?", (key,)).fetchone()
            if row and (row[0] is None or row[1] is None):
                _backfill_row(conn, key, it)
                updated += 1

        conn.commit()
        # report remaining incomplete records
        incomplete = conn.execute(
            "SELECT COUNT(*) FROM vulns WHERE source IS NULL OR link IS NULL"
        ).fetchone()[0]
    print(f"backfilled {updated} records")
    if incomplete:
        print(f"note: {incomplete} records still have NULL fields (source no longer in feeds)")


