#!/usr/bin/env python3
"""One-shot: fetch full GHSA descriptions and re-score all GHSA records."""
import sys, os, re, time, sqlite3, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from vuln_monitor import score, _extract_pr, DATA_DIR, GH_TOKEN, SESS

DB = DATA_DIR / "vuln_cache.db"

def main():
    conn = sqlite3.connect(DB, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")

    # 1) Load all GHSA keys from DB
    rows = conn.execute(
        "SELECT key, cve_id, summary, vuln_type, reason FROM vulns WHERE source='GHSA'"
    ).fetchall()
    db_map = {r[1]: {"key": r[0], "old_summary": r[2], "old_vt": r[3], "old_reason": r[4]}
              for r in rows if r[1]}
    print(f"DB has {len(db_map)} GHSA records with cve_id")

    # 2) Bulk fetch from GHSA API (100 per page, all severities)
    headers = {"Accept": "application/vnd.github+json"}
    if GH_TOKEN:
        headers["Authorization"] = f"Bearer {GH_TOKEN}"

    fetched = {}
    for severity in ("critical", "high"):
        page = 1
        while True:
            r = SESS.get("https://api.github.com/advisories",
                         params={"severity": severity, "type": "reviewed",
                                 "per_page": 100, "page": page},
                         headers=headers, timeout=15)
            if r.status_code != 200:
                print(f"  API {r.status_code} at {severity} p{page}, stopping")
                break
            advs = r.json()
            if not advs:
                break
            for a in advs:
                cve = a.get("cve_id")
                if cve and cve in db_map:
                    desc = a.get("description", "") or a.get("summary", "")
                    fetched[cve] = desc
            print(f"  {severity} p{page}: {len(advs)} advisories, matched {len(fetched)} so far")
            if len(advs) < 100:
                break
            page += 1
            time.sleep(0.3)
        time.sleep(0.5)

    print(f"\nFetched descriptions for {len(fetched)}/{len(db_map)} GHSA records")

    # 3) Re-score and update
    updated_summary = 0
    upgraded_rce = 0
    reason_changed = 0
    for cve_id, desc in fetched.items():
        rec = db_map[cve_id]
        key = rec["key"]
        old_summary = rec["old_summary"] or ""
        old_vt = rec["old_vt"]
        old_reason = rec["old_reason"]

        new_summary = desc[:500] if len(desc) > len(old_summary) else old_summary
        hit, new_reason, new_vt = score(desc)

        changes = []
        sets = []
        params = []

        if len(new_summary) > len(old_summary):
            sets.append("summary=?")
            params.append(new_summary)
            changes.append("summary")

        if new_vt == "RCE" and old_vt != "RCE":
            sets.append("vuln_type='RCE'")
            sets.append("reason=?")
            params.append(new_reason)
            changes.append(f"vuln_type: {old_vt}->RCE, reason: {old_reason}->{new_reason}")
            upgraded_rce += 1
        elif hit and new_reason != old_reason and old_reason not in ("excluded",):
            sets.append("reason=?")
            params.append(new_reason)
            changes.append(f"reason: {old_reason}->{new_reason}")
            reason_changed += 1

        if sets:
            sql = f"UPDATE vulns SET {', '.join(sets)} WHERE key=?"
            params.append(key)
            conn.execute(sql, params)
            updated_summary += 1

    conn.execute("INSERT OR IGNORE INTO _ghsa_checked SELECT key FROM vulns WHERE source='GHSA'")
    conn.commit()
    conn.close()

    print(f"\nDone: {updated_summary} records updated")
    print(f"  vuln_type upgraded to RCE: {upgraded_rce}")
    print(f"  reason changed: {reason_changed}")
    print(f"  _ghsa_checked: marked all as checked")

if __name__ == "__main__":
    main()
