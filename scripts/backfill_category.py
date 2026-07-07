"""Re-classify existing vulns records with the current classify_category() rules.

By default (CATEGORY-ONLY mode) it recomputes ONLY `category` from each record's
STORED reason/vuln_type — safe for category-rule changes (e.g. the excluded->keyword
fix) and avoids score drift, since score() originally ran on the full ingest text
(title+summary+refs) which is not fully retained.

Use --rescore ONLY when score() rules themselves changed: that re-runs score() on
title+summary and overwrites reason/vuln_type too. NOTE: --rescore can drift records
whose scoring signal lived in non-retained reference text, so prefer category-only.

`pushed` / freshness / cvss / llm_* are NEVER touched.

Run on prod as the vuln user (stop the monitor daemon first to avoid concurrent writes):
    sudo systemctl stop vuln-monitor.service
    /opt/vuln-monitor/venv/bin/python /opt/vuln-monitor/scripts/backfill_category.py
    sudo systemctl start vuln-monitor.service

Override paths with VULN_DB=... / VULN_SRC=... if needed.
"""
import argparse
import os
import sqlite3
import sys
from collections import Counter

DB = os.environ.get("VULN_DB", "/opt/vuln-monitor/vuln_cache.db")
SRC = os.environ.get("VULN_SRC", "/opt/vuln-monitor/src")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rescore", action="store_true",
                    help="ALSO re-run score() on title+summary and overwrite reason/vuln_type "
                         "(for score-rule changes; can drift records — prefer the default category-only mode)")
    args = ap.parse_args()

    sys.path.insert(0, SRC)
    import vuln_monitor as v

    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    v.init_db(conn)  # ensure the `category` column exists
    cols = "key, title, summary, reason, vuln_type, category" if args.rescore else "key, title, summary, reason, vuln_type, category"
    rows = conn.execute(f"SELECT {cols} FROM vulns").fetchall()
    cat_dist = Counter()
    transitions = Counter()
    changed = 0
    for r in rows:
        text = f"{r['title'] or ''}\n{r['summary'] or ''}"
        if args.rescore:
            _hit, reason, vt = v.score(text)            # re-run score() (refreshes reason/vuln_type)
        else:
            reason, vt = r["reason"], r["vuln_type"]    # use STORED reason/vuln_type (no drift)
        cat = v.classify_category(vt, text, reason)
        old_cat = r["category"]
        if cat != old_cat:
            changed += 1
            transitions[(old_cat, cat)] += 1
        cat_dist[cat] += 1
        if args.rescore:
            conn.execute("UPDATE vulns SET reason=?, vuln_type=?, category=? WHERE key=?",
                         (reason, vt, cat, r["key"]))
        else:
            conn.execute("UPDATE vulns SET category=? WHERE key=?", (cat, r["key"]))
    conn.commit()
    mode = "rescore (reason+vuln_type+category)" if args.rescore else "category-only (stored reason/vuln_type)"
    print(f"re-classified {len(rows)} rows [{mode}]; category CHANGED on {changed}. Transitions:")
    for (o, n), c in transitions.most_common():
        print(f"  {o} -> {n}: {c}")
    print("new category distribution:")
    for cat, n in cat_dist.most_common():
        print(f"  {cat}: {n}")
    conn.close()


if __name__ == "__main__":
    main()
