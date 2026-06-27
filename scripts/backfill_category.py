"""Re-classify ALL existing vulns records with the current score() + classify_category().

Re-runs score() to refresh reason/vuln_type, then derives category — so this applies
BOTH score-rule changes and category-rule changes to historical records. The pushed
field (and freshness/cvss/llm_*) are NOT touched — only reason/vuln_type/category.

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
    rows = conn.execute("SELECT key, title, summary FROM vulns").fetchall()
    cat_dist = Counter()
    vt_dist = Counter()
    for r in rows:
        text = f"{r['title'] or ''}\n{r['summary'] or ''}"
        hit, reason, vt = v.score(text)              # re-run score() (applies score-rule changes)
        cat = v.classify_category(vt, text, reason)  # then derive category
        cat_dist[cat] += 1
        vt_dist[vt] += 1
        conn.execute("UPDATE vulns SET reason=?, vuln_type=?, category=? WHERE key=?",
                     (reason, vt, cat, r["key"]))
    conn.commit()
    print(f"re-classified {len(rows)} rows (reason+vuln_type+category; pushed preserved)")
    print("vuln_type:", dict(vt_dist.most_common()))
    for cat, n in cat_dist.most_common():
        print(f"  cat {cat}: {n}")
    conn.close()


if __name__ == "__main__":
    main()
