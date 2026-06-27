"""One-off: backfill the `category` column for all existing vulns records.

Run on prod as the vuln user:
    /opt/vuln-monitor/venv/bin/python /opt/vuln-monitor/scripts/backfill_category.py

Override the DB path with VULN_DB=... if needed.
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
    rows = conn.execute("SELECT key, title, summary, vuln_type FROM vulns").fetchall()
    dist = Counter()
    for r in rows:
        text = f"{r['title'] or ''}\n{r['summary'] or ''}"
        cat = v.classify_category(r["vuln_type"], text)
        dist[cat] += 1
        conn.execute("UPDATE vulns SET category=? WHERE key=?", (cat, r["key"]))
    conn.commit()
    print(f"backfilled category on {len(rows)} rows")
    for cat, n in dist.most_common():
        print(f"  {cat}: {n}")
    conn.close()


if __name__ == "__main__":
    main()
