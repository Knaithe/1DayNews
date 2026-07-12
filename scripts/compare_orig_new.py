#!/usr/bin/env python3
"""Compare original prod DB vs same data re-labeled with current scoring/push rules.

Usage:
  python scripts/compare_orig_new.py data_orig_prod.db

Creates data_new_rules.db (copy + offline re-score + re-push gate) and prints
side-by-side quality metrics. No network, no LLM calls.
"""
from __future__ import annotations

import os
import shutil
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from src.scoring import score, classify_category  # noqa: E402
from src.push_gate import (  # noqa: E402
    _resolve_pushed, _regex_push_candidate, _llm_configured, _GITHUB_SOURCES,
)


def metrics(conn: sqlite3.Connection, label: str) -> dict:
    conn.row_factory = sqlite3.Row
    def one(sql):
        return conn.execute(sql).fetchone()[0]

    m = {
        "label": label,
        "total": one("SELECT COUNT(*) FROM vulns"),
        "pushed": one("SELECT COUNT(*) FROM vulns WHERE pushed=1"),
        "pushed_rce": one("SELECT COUNT(*) FROM vulns WHERE pushed=1 AND vuln_type='RCE'"),
        "pushed_bypass": one("SELECT COUNT(*) FROM vulns WHERE pushed=1 AND vuln_type='bypass'"),
        "pushed_other": one("SELECT COUNT(*) FROM vulns WHERE pushed=1 AND vuln_type='other'"),
        "pushed_null_type": one("SELECT COUNT(*) FROM vulns WHERE pushed=1 AND vuln_type IS NULL"),
        "pushed_nday": one("SELECT COUNT(*) FROM vulns WHERE pushed=1 AND freshness='nday'"),
        "pushed_bad_pr": one(
            "SELECT COUNT(*) FROM vulns WHERE pushed=1 AND (cvss_pr IS NULL OR cvss_pr!='N')"
        ),
        "pushed_ui_r": one("SELECT COUNT(*) FROM vulns WHERE pushed=1 AND cvss_ui='R'"),
        "pushed_github": one(
            "SELECT COUNT(*) FROM vulns WHERE pushed=1 AND source IN ('GitHub','PoC-GitHub')"
        ),
        "pushed_no_link": one(
            "SELECT COUNT(*) FROM vulns WHERE pushed=1 AND (link IS NULL OR link='')"
        ),
        "reason_asset_cve": one("SELECT COUNT(*) FROM vulns WHERE reason='asset+CVE'"),
        "reason_rce_any": one("SELECT COUNT(*) FROM vulns WHERE reason LIKE '%RCE%'"),
        "reason_excluded": one("SELECT COUNT(*) FROM vulns WHERE reason='excluded'"),
        "reason_no_hit": one("SELECT COUNT(*) FROM vulns WHERE reason='no hit'"),
        "type_rce": one("SELECT COUNT(*) FROM vulns WHERE vuln_type='RCE'"),
        "type_bypass": one("SELECT COUNT(*) FROM vulns WHERE vuln_type='bypass'"),
        "type_other": one("SELECT COUNT(*) FROM vulns WHERE vuln_type='other'"),
        "llm_confirmed": one("SELECT COUNT(*) FROM vulns WHERE llm_verdict='confirmed'"),
        "llm_not_rel": one("SELECT COUNT(*) FROM vulns WHERE llm_verdict='not_relevant'"),
        "llm_noise": one("SELECT COUNT(*) FROM vulns WHERE llm_verdict='noise'"),
    }
    m["push_rate"] = (m["pushed"] / m["total"] * 100) if m["total"] else 0
    m["pushed_rce_share"] = (m["pushed_rce"] / m["pushed"] * 100) if m["pushed"] else 0
    m["pushed_other_share"] = (m["pushed_other"] / m["pushed"] * 100) if m["pushed"] else 0
    return m


def apply_new_rules(db_path: Path) -> dict:
    """Re-score all rows; recompute pushed with current gates + vuln_type RCE/bypass hard req."""
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT key, title, summary, source, reason, vuln_type, category, "
        "freshness, cvss_pr, cvss_ui, llm_verdict, llm_verified, pushed "
        "FROM vulns"
    ).fetchall()

    reason_chg = vt_chg = cat_chg = push_up = push_down = 0
    # Track what new policy would drop
    drop_other = 0

    for r in rows:
        text = f"{(r['title'] or '')}\n{(r['summary'] or '')}"
        hit, reason, vt = score(text)
        cat = classify_category(vt, text, reason)

        # Push under NEW policy:
        # 1) hard gates via regex candidate base OR llm resolve
        # 2) ALWAYS require vuln_type in (RCE, bypass)  ← quality fix for comparison
        pr, ui = r["cvss_pr"], r["cvss_ui"]
        freshness = r["freshness"]
        source = r["source"]
        if r["llm_verified"] and r["llm_verdict"]:
            new_pushed = _resolve_pushed(r["llm_verdict"], freshness, source, pr, ui)
        else:
            new_pushed = 1 if _regex_push_candidate(hit, vt, freshness, source, pr, ui) else 0
        # tighten: no other/null types
        if new_pushed and vt not in ("RCE", "bypass"):
            new_pushed = 0
            drop_other += 1

        if (r["reason"] or "") != (reason or ""):
            reason_chg += 1
        if (r["vuln_type"] or "") != (vt or ""):
            vt_chg += 1
        if (r["category"] or "") != (cat or ""):
            cat_chg += 1
        old_p = int(r["pushed"] or 0)
        if new_pushed > old_p:
            push_up += 1
        elif new_pushed < old_p:
            push_down += 1

        conn.execute(
            "UPDATE vulns SET reason=?, vuln_type=?, category=?, pushed=? WHERE key=?",
            (reason, vt, cat, new_pushed, r["key"]),
        )

    conn.commit()
    stats = {
        "rows": len(rows),
        "reason_changed": reason_chg,
        "vuln_type_changed": vt_chg,
        "category_changed": cat_chg,
        "push_upgraded": push_up,
        "push_downgraded": push_down,
        "blocked_other_type": drop_other,
    }
    conn.close()
    return stats


def print_pair(a: dict, b: dict, keys: list[tuple[str, str]]):
    print(f"{'metric':<28} {a['label']:>14} {b['label']:>14} {'delta':>10}")
    print("-" * 70)
    for key, title in keys:
        av, bv = a[key], b[key]
        if isinstance(av, float):
            delta = bv - av
            print(f"{title:<28} {av:>13.1f}% {bv:>13.1f}% {delta:>+9.1f}pp")
        else:
            delta = bv - av
            print(f"{title:<28} {av:>14} {bv:>14} {delta:>+10}")


def main():
    orig = Path(sys.argv[1] if len(sys.argv) > 1 else ROOT / "data_orig_prod.db")
    if not orig.exists():
        print(f"missing {orig}")
        return 1
    new = ROOT / "data_new_rules.db"
    print(f"orig: {orig} ({orig.stat().st_size} bytes)")
    print(f"new:  {new} (will rewrite)")
    if new.exists():
        new.unlink()
    shutil.copy2(orig, new)

    conn_o = sqlite3.connect(str(orig))
    m_orig = metrics(conn_o, "ORIG_PROD")
    conn_o.close()

    print("\nApplying current score() + tightened push (RCE/bypass only) ...")
    chg = apply_new_rules(new)
    print(
        f"  rows={chg['rows']}  reasonΔ={chg['reason_changed']}  "
        f"typeΔ={chg['vuln_type_changed']}  catΔ={chg['category_changed']}"
    )
    print(
        f"  push +{chg['push_upgraded']} / -{chg['push_downgraded']}  "
        f"(blocked other-type candidates: {chg['blocked_other_type']})"
    )

    conn_n = sqlite3.connect(str(new))
    m_new = metrics(conn_n, "NEW_RULES")
    conn_n.close()

    print("\n=== SIDE-BY-SIDE ===")
    print_pair(m_orig, m_new, [
        ("total", "total rows"),
        ("pushed", "pushed"),
        ("push_rate", "push rate"),
        ("pushed_rce", "pushed RCE"),
        ("pushed_bypass", "pushed bypass"),
        ("pushed_other", "pushed other (noise)"),
        ("pushed_other_share", "pushed that are other"),
        ("pushed_rce_share", "pushed that are RCE"),
        ("pushed_nday", "viol: pushed+nday"),
        ("pushed_bad_pr", "viol: pushed+pr≠N"),
        ("pushed_github", "viol: pushed+github"),
        ("pushed_no_link", "pushed no link"),
        ("type_rce", "rows type=RCE"),
        ("type_bypass", "rows type=bypass"),
        ("type_other", "rows type=other"),
        ("reason_asset_cve", "reason=asset+CVE"),
        ("reason_rce_any", "reason contains RCE"),
        ("reason_excluded", "reason=excluded"),
        ("reason_no_hit", "reason=no hit"),
        ("llm_confirmed", "llm confirmed"),
        ("llm_not_rel", "llm not_relevant"),
        ("llm_noise", "llm noise"),
    ])

    # Sample: what got demoted from push
    print("\n=== SAMPLE: ORIG pushed → NEW not pushed (first 12) ===")
    conn = sqlite3.connect(str(orig))
    conn.row_factory = sqlite3.Row
    newc = sqlite3.connect(str(new))
    newc.row_factory = sqlite3.Row
    demoted = []
    for r in conn.execute(
        "SELECT key, cve_id, source, title, reason, vuln_type, category, llm_verdict "
        "FROM vulns WHERE pushed=1 ORDER BY created_at DESC LIMIT 500"
    ):
        n = newc.execute(
            "SELECT pushed, reason, vuln_type, category FROM vulns WHERE key=?",
            (r["key"],),
        ).fetchone()
        if n and not n["pushed"]:
            demoted.append((r, n))
        if len(demoted) >= 12:
            break
    for r, n in demoted:
        print(
            f"  - [{r['source']}] {r['cve_id'] or 'N/A'}  "
            f"was type={r['vuln_type']}/{r['reason']} cat={r['category']} llm={r['llm_verdict']}"
        )
        print(f"    now type={n['vuln_type']}/{n['reason']} cat={n['category']}")
        print(f"    {(r['title'] or '')[:100]}")

    # Sample: still pushed RCE under new
    print("\n=== SAMPLE: still pushed under NEW (RCE/bypass, 8) ===")
    for r in newc.execute(
        "SELECT cve_id, source, title, reason, vuln_type, category, llm_verdict "
        "FROM vulns WHERE pushed=1 ORDER BY created_at DESC LIMIT 8"
    ):
        print(
            f"  + [{r['source']}] {r['cve_id']} type={r['vuln_type']} "
            f"cat={r['category']} {r['reason']} llm={r['llm_verdict']}"
        )
        print(f"    {(r['title'] or '')[:100]}")

    conn.close()
    newc.close()
    print(f"\nWrote {new}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
