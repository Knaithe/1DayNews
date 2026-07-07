"""Re-classify ALL existing vulns records with the current score() + classify_category().

Re-runs score() to refresh reason/vuln_type, then derives category — so this applies
BOTH score-rule changes and category-rule changes to historical records. The pushed
field (and freshness/cvss/llm_*) are NOT touched — only reason/vuln_type/category.

Reports how many records changed category and the transition breakdown.

Run on prod as the vuln user (stop the monitor daemon first to avoid concurrent writes):
    sudo systemctl stop vuln-monitor.service
    /opt/vuln-monitor/venv/bin/python /opt/vuln-monitor/scripts/backfill_category.py
    sudo systemctl start vuln-monitor.service

Override paths with VULN_DB=... / VULN_SRC=... if needed.
"""
import os
import sqlite3
import sys
from collections import Counter

DB = os.environ.get("VULN_DB", "/opt/vuln-monitor/vuln_cache.db")
SRC = os.environ.get("VULN_SRC", "/opt/vuln-monitor/src")


def main():
    sys.path.insert(0, SRC)
    import vuln_monitor as v

    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    v.init_db(conn)  # ensure the `category` column exists
    rows = conn.execute("SELECT key, title, summary, category FROM vulns").fetchall()
    cat_dist = Counter()
    transitions = Counter()
    changed = 0
    for r in rows:
        text = f"{r['title'] or ''}\n{r['summary'] or ''}"
        hit, reason, vt = v.score(text)              # re-run score() (applies score-rule changes)
        cat = v.classify_category(vt, text, reason)  # then derive category
        old_cat = r["category"]
        if cat != old_cat:
            changed += 1
            transitions[(old_cat, cat)] += 1
        cat_dist[cat] += 1
        conn.execute("UPDATE vulns SET reason=?, vuln_type=?, category=? WHERE key=?",
                     (reason, vt, cat, r["key"]))
    conn.commit()
    print(f"re-classified {len(rows)} rows (reason+vuln_type+category; pushed preserved)")
    print(f"category CHANGED on {changed} rows. Transitions:")
    for (o, n), c in transitions.most_common():
        print(f"  {o} -> {n}: {c}")
    print("new category distribution:")
    for cat, n in cat_dist.most_common():
        print(f"  {cat}: {n}")
    conn.close()


if __name__ == "__main__":
    main()
