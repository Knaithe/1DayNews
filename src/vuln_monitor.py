#!/usr/bin/env python3
"""
0day/1day RCE vulnerability intelligence aggregator — CLI entrypoint.

Modules:
    config.py / scoring.py / db.py / sources.py / notify.py
    nvd.py / push_gate.py / enrich.py / pipeline.py
    web.py + static/dashboard.html
"""
import os
import sys
import json
import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))
_PARENT = str(_SCRIPT_DIR.parent)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

# Re-exports for tests and external `import src.vuln_monitor as vm`
from src.config import (  # noqa: E402
    DATA_DIR, DB_FILE, LOCK_FILE, ENRICH_LIMIT, DEEPSEEK_API_KEY, OPENAI_API_KEY,
    FRESH_SOURCES, HIGH_PRIORITY_SOURCES, STRONG_VULN_TYPES, log, SESS,
)
from src.scoring import (  # noqa: E402
    score, classify_category, asset_hit, CVE_RE, ADVISORY_RE,
    RCE_PATTERNS, BYPASS_PATTERNS, ASSET_KEYWORDS, EXCLUDE_PATTERNS,
    CATEGORY_KEYWORDS, _ab, _RCE_RE, _BYPASS_RE, _EXCLUDE_RE, _STRONG_RCE_RE,
    _ASSET_KW_SET,
)
from src.db import _get_conn, _db, init_db, migrate_json_cache, db_cleanup  # noqa: E402
from src.sources import (  # noqa: E402
    fetch_rss, fetch_kev_json, fetch_chaitin, fetch_threatbook,
    fetch_poc_in_github, fetch_github_advisories, fetch_repo_advisories,
    fetch_msrc, fetch_fortinet, fetch_watchtowr, fetch_twcert,
    _fetch_all_sources, _parse_msrc_cvrf, _parse_fortinet_psirt,
    _parse_watchtowr_sitemap, _parse_twcert_detail,
)
from src.notify import (  # noqa: E402
    tg_escape, _md_escape, _extract_id, format_msg, _tg_retry_after, _tg_send_one,
    send_telegram, format_msg_wecom, format_msg_dingtalk, format_msg_feishu,
    send_wecom, send_dingtalk, send_feishu, send_failure_alert,
)
from src.push_gate import (  # noqa: E402
    _llm_configured, _regex_push_candidate, _initial_pushed, _resolve_pushed,
    _GITHUB_SOURCES, _VERDICT_PUSH,
)
from src.nvd import (  # noqa: E402
    _extract_pr, _extract_ui, _nvd_detail, _nvd_published_date, _cvss_to_severity,
    _backfill_nvd_severity, _warm_nvd_cache, _is_fresh, _FRESHNESS_DAYS,
    _nvd_cache, _nvd_detail_cache,
)
from src.enrich import (  # noqa: E402
    _select_enrich_candidates, _cmd_enrich_inner, _enrich_one, _get_llm_prompt,
)
from src.pipeline import (  # noqa: E402
    SingletonLock, item_key, _backfill_row, _infer_source_from_title,
    _enrich_record, _auto_enrich, _run, _push_pending, _write_fetch_state,
    cmd_rescore, _cmd_rescore_inner, cmd_rebuild, _cmd_rebuild_inner,
)


def fmt_table(headers, rows):
    if not rows:
        print("(no results)")
        return
    all_rows = [headers] + rows
    widths = [max(len(str(c)) for c in col) for col in zip(*all_rows)]
    def fmt_row(r):
        return "  ".join(str(c).ljust(w) for c, w in zip(r, widths))
    print(fmt_row(headers))
    print("  ".join("─" * w for w in widths))
    for r in rows:
        print(fmt_row(r))


def _query_rows(args, quality_filter=False):
    with _db() as conn:
        init_db(conn)
        where, params = [], []
        if args.cve:
            where.append("cve_id LIKE ?"); params.append(f"%{args.cve}%")
        if args.source:
            where.append("source LIKE ?"); params.append(f"%{args.source}%")
        if args.keyword:
            where.append("(title LIKE ? OR summary LIKE ?)")
            params.extend([f"%{args.keyword}%"] * 2)
        if args.days:
            cutoff = (datetime.now(timezone.utc) - timedelta(days=args.days)).timestamp()
            where.append("created_at > ?"); params.append(cutoff)
        if args.pushed:
            where.append("pushed = 1")
        if args.reason:
            where.append("reason LIKE ?"); params.append(f"%{args.reason}%")
        if quality_filter:
            where.append("link IS NOT NULL AND link != ''")
            where.append("source IS NOT NULL AND source != ''")
            if not args.reason:
                where.append("reason NOT IN ('no hit','excluded') AND freshness != 'nday'")
        sql = "SELECT cve_id,source,title,link,summary,reason,pushed,created_at FROM vulns"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(args.limit)
        rows = conn.execute(sql, params).fetchall()
    return rows


def cmd_query(args):
    rows = _query_rows(args)
    if args.json:
        out = []
        for cve, src, title, link, summary, reason, pushed, ts in rows:
            dt = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat() if ts else None
            out.append({"id": cve, "source": src, "title": title, "url": link,
                        "summary": summary, "reason": reason, "pushed": bool(pushed), "date": dt})
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return
    if args.full:
        for i, (cve, src, title, link, summary, reason, pushed, ts) in enumerate(rows):
            dt = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M") if ts else "-"
            if i > 0:
                print()
            print(f"[{src or '-'}] {cve or 'N/A'}  ({reason or '-'})  {dt}")
            print(f"  {title or '-'}")
            print(f"  {link or '(no url)'}")
            if summary:
                print(f"  {summary[:200]}")
        print(f"\n({len(rows)} rows)")
        return
    headers = ["ID", "Source", "Title", "URL", "Reason", "Date"]
    table = []
    for cve, src, title, link, summary, reason, pushed, ts in rows:
        dt = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d") if ts else "-"
        table.append([cve or "-", src or "-", (title or "")[:45], (link or "-")[:55], reason or "-", dt])
    fmt_table(headers, table)
    print(f"\n({len(rows)} rows)")


def cmd_brief(args):
    enriched = _auto_enrich()
    explain = getattr(args, "explain", False)
    if explain:
        with _db() as conn:
            init_db(conn)
            total = conn.execute("SELECT COUNT(*) FROM vulns").fetchone()[0]
            no_link = conn.execute("SELECT COUNT(*) FROM vulns WHERE link IS NULL OR link=''").fetchone()[0]
            placeholders = ",".join("?" for _ in STRONG_VULN_TYPES)
            strong_no_link = conn.execute(
                f"SELECT COUNT(*) FROM vulns WHERE (link IS NULL OR link='') AND vuln_type IN ({placeholders})",
                tuple(STRONG_VULN_TYPES),
            ).fetchone()[0]
        print(f"[explain] enriched {enriched} records this pass")
        print(f"[explain] db total={total}  still_no_link={no_link}  strong_without_link={strong_no_link}")
        if strong_no_link:
            print(f"[explain] {strong_no_link} strong records could not be enriched (run 'rebuild' to fix from feeds)")
        print(f"[explain] quality filter: link NOT NULL, source NOT NULL, reason NOT IN (no hit, excluded), freshness != nday")
        print()
    rows = _query_rows(args, quality_filter=True)
    if not rows:
        print("(no results matching quality threshold)")
        return
    for i, (cve, src, title, link, summary, reason, pushed, ts) in enumerate(rows):
        dt = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d") if ts else "-"
        tag = cve or "N/A"
        if i > 0:
            print(f"{'─' * 60}")
        print(f"{tag}  [{src}]  {dt}")
        print(f"{title or '-'}")
        print(f"{link}")
        print(f"match: {reason or '-'}")
    print(f"\n({len(rows)} results)")


def cmd_stats(args):
    with _db() as conn:
        init_db(conn)
        total = conn.execute("SELECT COUNT(*) FROM vulns").fetchone()[0]
        pushed = conn.execute("SELECT COUNT(*) FROM vulns WHERE pushed=1").fetchone()[0]
        day_ago = (datetime.now(timezone.utc) - timedelta(days=1)).timestamp()
        recent = conn.execute("SELECT COUNT(*) FROM vulns WHERE created_at>?", (day_ago,)).fetchone()[0]
        last_ts = conn.execute("SELECT MAX(created_at) FROM vulns").fetchone()[0]
        last_dt = datetime.fromtimestamp(last_ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if last_ts else "-"
        print(f"Total: {total}  |  Pushed: {pushed}  |  Last 24h: {recent}  |  Last update: {last_dt}\n")
        sources = conn.execute("SELECT source,COUNT(*) FROM vulns GROUP BY source ORDER BY COUNT(*) DESC").fetchall()
        print("── By Source ──")
        fmt_table(["Source", "Count"], [[s or "(migrated)", str(n)] for s, n in sources])
        print()
        reasons = conn.execute(
            "SELECT reason,COUNT(*) FROM vulns WHERE pushed=1 GROUP BY reason ORDER BY COUNT(*) DESC"
        ).fetchall()
        print("── By Reason (pushed only) ──")
        fmt_table(["Reason", "Count"], [[r, str(n)] for r, n in reasons])


def cmd_enrich(args):
    with SingletonLock(LOCK_FILE):
        _cmd_enrich_inner(getattr(args, "dry", False))


def cmd_daemon(args):
    interval = int(os.getenv("FETCH_INTERVAL", "300"))
    log.info(f"daemon started: interval={interval}s")
    while True:
        try:
            with SingletonLock(LOCK_FILE):
                _run(no_push=True)
                _cmd_enrich_inner()
        except RuntimeError as ex:
            log.warning(f"daemon skip (lock held): {ex}")
        except Exception:
            import traceback
            tb = traceback.format_exc()
            log.exception("daemon error")
            send_failure_alert(f"daemon error:\n{tb[-3500:]}")
        import time
        time.sleep(interval)


def main():
    parser = argparse.ArgumentParser(description="vuln-monitor: 0day/1day RCE intelligence")
    sub = parser.add_subparsers(dest="cmd")
    fp = sub.add_parser("fetch", help="Fetch all sources, dedup, store, push")
    fp.add_argument("--no-push", action="store_true", help="Do not send notifications")

    def _add_filter_args(p):
        p.add_argument("--cve", help="Filter by CVE ID (substring match)")
        p.add_argument("--source", help="Filter by source name")
        p.add_argument("--keyword", "-k", help="Search title and summary")
        p.add_argument("--days", type=int, help="Only last N days")
        p.add_argument("--pushed", action="store_true", help="Only pushed items")
        p.add_argument("--reason", help="Filter by match reason")
        p.add_argument("--limit", type=int, default=50, help="Max rows (default 50)")

    qp = sub.add_parser("query", help="Query stored vulnerabilities")
    _add_filter_args(qp)
    qp.add_argument("--full", action="store_true", help="Detailed multi-line output")
    qp.add_argument("--json", action="store_true", help="JSON output")
    bp = sub.add_parser("brief", help="Notification-friendly output")
    _add_filter_args(bp)
    bp.add_argument("--explain", action="store_true", help="Show enrichment/filter diagnostics")
    sub.add_parser("stats", help="Database statistics")
    sub.add_parser("rebuild", help="Re-fetch sources and backfill NULL fields")
    sub.add_parser("rescore", help="Re-evaluate records with current scoring rules")
    ep = sub.add_parser("enrich", help="NVD + LLM enrichment + push")
    ep.add_argument("--dry", action="store_true", help="Enrich but do not push")
    sub.add_parser("daemon", help="Long-running fetch+enrich loop")

    args = parser.parse_args()
    if args.cmd == "daemon":
        cmd_daemon(args)
    elif args.cmd == "query":
        cmd_query(args)
    elif args.cmd == "brief":
        cmd_brief(args)
    elif args.cmd == "stats":
        cmd_stats(args)
    elif args.cmd == "rebuild":
        cmd_rebuild(args)
    elif args.cmd == "rescore":
        cmd_rescore(args)
    elif args.cmd == "enrich":
        try:
            cmd_enrich(args)
        except RuntimeError as ex:
            log.warning(str(ex))
            sys.exit(0)
        except Exception:
            import traceback
            tb = traceback.format_exc()
            log.exception("enrich error")
            send_failure_alert(f"enrich failed:\n{tb[-3500:]}")
            sys.exit(1)
    else:
        try:
            with SingletonLock(LOCK_FILE):
                _run(no_push=getattr(args, "no_push", False))
        except RuntimeError as ex:
            log.warning(str(ex))
            sys.exit(0)
        except Exception:
            import traceback
            tb = traceback.format_exc()
            log.exception("unhandled error")
            send_failure_alert(tb[-3500:])
            sys.exit(1)


if __name__ == "__main__":
    main()
