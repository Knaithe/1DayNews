#!/usr/bin/env python3
"""Offline quality audit of vuln_cache.db + optional live re-score sample."""
from __future__ import annotations

import os
import sqlite3
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

os.environ.setdefault("VULN_DATA_DIR", str(ROOT))

from src.scoring import score, asset_hit, classify_category  # noqa: E402
from src.vuln_monitor import DB_FILE  # noqa: E402


def main():
    db = Path(os.environ.get("VULN_DATA_DIR", ROOT)) / "vuln_cache.db"
    if not db.exists():
        db = DB_FILE
    print(f"DB: {db}  exists={db.exists()}")
    if not db.exists():
        return 1

    conn = sqlite3.connect(str(db))
    conn.row_factory = sqlite3.Row

    def one(sql, *a):
        return conn.execute(sql, a).fetchone()[0]

    def rows(sql, *a):
        return conn.execute(sql, a).fetchall()

    total = one("SELECT COUNT(*) FROM vulns")
    pushed = one("SELECT COUNT(*) FROM vulns WHERE pushed=1")
    print("\n=== OVERVIEW ===")
    print(f"total={total}  pushed={pushed}  push_rate={pushed/total*100:.1f}%" if total else "empty")

    print("\nfreshness:")
    for r in rows("SELECT freshness, COUNT(*) c FROM vulns GROUP BY freshness ORDER BY c DESC"):
        print(f"  {r['freshness']!r}: {r['c']}")
    print("vuln_type:")
    for r in rows("SELECT vuln_type, COUNT(*) c FROM vulns GROUP BY vuln_type ORDER BY c DESC"):
        print(f"  {r['vuln_type']!r}: {r['c']}")
    print("llm_verdict:")
    for r in rows("SELECT llm_verdict, COUNT(*) c FROM vulns GROUP BY llm_verdict ORDER BY c DESC"):
        print(f"  {r['llm_verdict']!r}: {r['c']}")
    print("reason top:")
    for r in rows(
        "SELECT reason, COUNT(*) c FROM vulns GROUP BY reason ORDER BY c DESC LIMIT 12"
    ):
        print(f"  {r['reason']!r}: {r['c']}")
    print("source top:")
    for r in rows(
        "SELECT source, COUNT(*) c FROM vulns GROUP BY source ORDER BY c DESC LIMIT 12"
    ):
        print(f"  {r['source']!r}: {r['c']}")

    print("\n=== HARD CONSTRAINTS (pushed=1 should all be 0) ===")
    checks = [
        ("pushed+nday", "pushed=1 AND freshness='nday'"),
        ("pushed+null_fresh", "pushed=1 AND freshness IS NULL"),
        ("pushed+github", "pushed=1 AND source IN ('GitHub','PoC-GitHub')"),
        ("pushed+pr_not_N", "pushed=1 AND (cvss_pr IS NULL OR cvss_pr!='N')"),
        ("pushed+ui_R", "pushed=1 AND cvss_ui='R'"),
        ("pushed+excluded", "pushed=1 AND reason='excluded'"),
        ("pushed+no_hit", "pushed=1 AND reason='no hit'"),
        ("pushed+not_relevant", "pushed=1 AND llm_verdict IN ('not_relevant','noise')"),
        ("pushed+other_type", "pushed=1 AND vuln_type='other'"),
    ]
    bad = 0
    for name, where in checks:
        n = one(f"SELECT COUNT(*) FROM vulns WHERE {where}")
        flag = "OK" if n == 0 else "BAD"
        if n:
            bad += n
        print(f"  [{flag}] {name}: {n}")

    print("\n=== COMPLETENESS (pushed) ===")
    for name, where in [
        ("null/empty link", "pushed=1 AND (link IS NULL OR link='')"),
        ("null cve_id", "pushed=1 AND cve_id IS NULL"),
        ("null/unknown severity", "pushed=1 AND (severity IS NULL OR severity='unknown')"),
        ("null cvss", "pushed=1 AND cvss IS NULL"),
        ("null category", "pushed=1 AND (category IS NULL OR category='')"),
        ("llm not verified", "pushed=1 AND llm_verified=0"),
    ]:
        print(f"  {name}: {one(f'SELECT COUNT(*) FROM vulns WHERE {where}')}")

    # Re-score sample: do stored reason/vuln_type/category match current score()?
    print("\n=== RE-SCORE DRIFT (sample up to 2000 recent) ===")
    sample = rows(
        "SELECT key, title, summary, reason, vuln_type, category, source, pushed "
        "FROM vulns ORDER BY created_at DESC LIMIT 2000"
    )
    reason_mismatch = 0
    vt_mismatch = 0
    cat_mismatch = 0
    short_asset_fp = 0  # asset in reason but only short-kw would have matched wrongly
    examples = {"reason": [], "vt": [], "cat": []}
    for r in sample:
        text = f"{(r['title'] or '')}\n{(r['summary'] or '')}"
        hit, reason, vt = score(text)
        cat = classify_category(vt, text, reason)
        if (r["reason"] or "") != (reason or ""):
            reason_mismatch += 1
            if len(examples["reason"]) < 5:
                examples["reason"].append(
                    ((r["title"] or "")[:70], r["reason"], reason)
                )
        if (r["vuln_type"] or "") != (vt or ""):
            vt_mismatch += 1
            if len(examples["vt"]) < 5:
                examples["vt"].append(
                    ((r["title"] or "")[:70], r["vuln_type"], vt)
                )
        if (r["category"] or "") != (cat or ""):
            cat_mismatch += 1
            if len(examples["cat"]) < 5:
                examples["cat"].append(
                    ((r["title"] or "")[:70], r["category"], cat)
                )

    n = len(sample)
    print(f"  sample={n}")
    print(f"  reason drift:   {reason_mismatch} ({reason_mismatch/n*100:.1f}%)" if n else "")
    print(f"  vuln_type drift:{vt_mismatch} ({vt_mismatch/n*100:.1f}%)" if n else "")
    print(f"  category drift: {cat_mismatch} ({cat_mismatch/n*100:.1f}%)" if n else "")
    if examples["reason"]:
        print("  reason examples (title, stored, now):")
        for e in examples["reason"]:
            print(f"    - {e}")
    if examples["vt"]:
        print("  vuln_type examples (title, stored, now):")
        for e in examples["vt"]:
            print(f"    - {e}")

    # Short-asset false positive probe on asset+CVE reasons
    print("\n=== SHORT-ASSET PROBE (asset+CVE rows, re-score) ===")
    asset_rows = rows(
        "SELECT title, summary, reason FROM vulns WHERE reason LIKE '%asset%' "
        "ORDER BY created_at DESC LIMIT 1500"
    )
    still_asset = 0
    lost_asset = 0
    for r in asset_rows:
        text = f"{(r['title'] or '')}\n{(r['summary'] or '')}"
        _, reason, _ = score(text)
        if "asset" in (reason or ""):
            still_asset += 1
        else:
            lost_asset += 1
    print(f"  sampled asset-reason rows: {len(asset_rows)}")
    print(f"  still asset under new rules: {still_asset}")
    print(f"  no longer asset (short-kw fixed / other): {lost_asset}")

    # Pushed sample quality: print 15 most recent pushed
    print("\n=== RECENT PUSHED SAMPLE (15) ===")
    for r in rows(
        "SELECT cve_id, source, title, reason, vuln_type, category, freshness, "
        "cvss_pr, cvss_ui, severity, cvss, llm_verdict, link "
        "FROM vulns WHERE pushed=1 ORDER BY created_at DESC LIMIT 15"
    ):
        print(
            f"  [{r['source']}] {r['cve_id'] or 'N/A'}  "
            f"type={r['vuln_type']} cat={r['category']} pr={r['cvss_pr']} "
            f"fresh={r['freshness']} llm={r['llm_verdict']}  {r['reason']}"
        )
        print(f"    {(r['title'] or '')[:100]}")
        print(f"    {r['link'] or ''}")

    # Suspicious: RCE without RCE language in title+summary (possible mislabel)
    print("\n=== SUSPICIOUS LABELS (pushed, type=RCE, no strong RCE keywords) ===")
    sus = []
    for r in rows(
        "SELECT cve_id, source, title, summary, reason FROM vulns "
        "WHERE pushed=1 AND vuln_type='RCE' ORDER BY created_at DESC LIMIT 400"
    ):
        text = f"{(r['title'] or '')}\n{(r['summary'] or '')}".lower()
        keys = (
            "rce", "remote code", "code execution", "command execution",
            "command injection", "code injection", "deserializ", "webshell",
            "arbitrary code", "任意代码", "命令执行", "远程代码",
        )
        if not any(k in text for k in keys):
            sus.append(r)
    print(f"  count in last 400 RCE-pushed: {len(sus)}")
    for r in sus[:8]:
        print(f"  - [{r['source']}] {r['cve_id']}: {(r['title'] or '')[:90]}  ({r['reason']})")

    print("\n=== SUMMARY ===")
    print(f"  hard_constraint_violations_total: {bad}")
    print(f"  rescore_reason_drift_pct: {reason_mismatch/n*100:.1f}%" if n else "  n/a")
    print(f"  short_asset_rows_lost_on_rescore: {lost_asset}/{len(asset_rows)}")
    print(f"  suspicious_rce_labels: {len(sus)}")
    if bad == 0:
        print("  hard gates: CLEAN")
    else:
        print("  hard gates: HAS VIOLATIONS")
    return 0 if bad == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
