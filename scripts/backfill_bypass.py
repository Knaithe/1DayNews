"""Backfill Sploitus_Citrix records: enrich from NVD, re-score, insert into DB.

Usage:
    python backfill_bypass.py --dry          # dry run (no DB writes)
    python backfill_bypass.py                # insert into DB
    VULN_DB=path python backfill_bypass.py   # override DB path
"""
import sqlite3, sys, os, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from vuln_monitor import score, SESS, NVD_API_KEY

DB = os.environ.get("VULN_DB", os.path.join(os.path.dirname(__file__), '..', 'vuln_cache_remote.db'))
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DRY_RUN = "--dry" in sys.argv


def nvd_lookup(cve_id):
    delay = 0.7 if NVD_API_KEY else 6.5
    time.sleep(delay)
    hdrs = {"User-Agent": "vuln-monitor/1.0"}
    if NVD_API_KEY:
        hdrs["apiKey"] = NVD_API_KEY
    try:
        r = SESS.get(NVD_API, params={"cveId": cve_id}, timeout=15, headers=hdrs)
        if r.status_code != 200:
            return None
        data = r.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None
        cve_obj = vulns[0]["cve"]
        desc = ""
        for d in cve_obj.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d["value"]
                break
        cvss = None
        severity = None
        vector = None
        for ver in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metrics = cve_obj.get("metrics", {}).get(ver, [])
            if metrics:
                cd = metrics[0].get("cvssData", {})
                cvss = cd.get("baseScore")
                severity = cd.get("baseSeverity", "").lower()
                vector = cd.get("vectorString")
                break
        return {"description": desc, "cvss": cvss, "severity": severity, "vector": vector}
    except Exception as e:
        print(f"  NVD error for {cve_id}: {e}", flush=True)
        return None


def main():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row

    rows = conn.execute(
        "SELECT * FROM vulns WHERE source='Sploitus_Citrix' AND cve_id IS NOT NULL AND cve_id != ''"
    ).fetchall()
    print(f"Sploitus_Citrix records with CVE: {len(rows)}", flush=True)

    covered = set()
    for r in conn.execute(
        "SELECT DISTINCT cve_id FROM vulns WHERE source != 'Sploitus_Citrix' AND cve_id IS NOT NULL"
    ):
        covered.add(r[0])

    unique = [r for r in rows if r["cve_id"] not in covered]
    print(f"Already covered by other sources: {len(rows) - len(unique)}", flush=True)
    print(f"Sploitus-only CVEs to evaluate: {len(unique)}", flush=True)

    need_nvd = [r for r in unique if not (r["summary"] or "").strip()]
    print(f"Need NVD enrichment: {len(need_nvd)}", flush=True)

    nvd_results = {}
    for i, r in enumerate(need_nvd, 1):
        cid = r["cve_id"]
        result = nvd_lookup(cid)
        if result and result["description"]:
            nvd_results[cid] = result
            print(f"  [{i}/{len(need_nvd)}] {cid}: {result['description'][:80]}...", flush=True)
        else:
            print(f"  [{i}/{len(need_nvd)}] {cid}: no NVD data", flush=True)

    candidates = []
    for r in unique:
        cve_id = r["cve_id"]
        title = r["title"] or ""
        summary = r["summary"] or ""
        cvss = r["cvss"]
        severity = r["severity"]
        vector = r["cvss_vector"]

        nvd = nvd_results.get(cve_id)
        if nvd:
            if not summary.strip():
                summary = nvd["description"]
            if nvd["cvss"] and (not cvss or nvd["cvss"] > cvss):
                cvss = nvd["cvss"]
                severity = nvd["severity"]
                vector = nvd.get("vector")

        text = title + " " + summary
        hit, reason, vtype = score(text)
        if hit:
            candidates.append({
                "key": r["key"], "cve_id": cve_id, "source": r["source"],
                "title": title, "link": r["link"], "summary": summary,
                "reason": reason, "vuln_type": vtype,
                "cvss": cvss, "severity": severity, "cvss_vector": vector,
            })

    conn.close()

    print(f"\n{'='*60}", flush=True)
    print(f"Total candidates to backfill: {len(candidates)}", flush=True)
    by_type = {}
    for c in candidates:
        t = c["vuln_type"] or "null"
        by_type[t] = by_type.get(t, 0) + 1
    print(f"By type: {by_type}")
    for c in candidates:
        print(f"  {c['cve_id']:20s} type={c['vuln_type']:8s} CVSS={str(c['cvss'] or '?'):5s} {c['reason']:20s} {c['title'][:55]}")

    if DRY_RUN:
        print(f"\n[DRY RUN] Would insert {len(candidates)} records.", flush=True)
        return

    if not candidates:
        print("Nothing to backfill.")
        return

    print(f"\nInserting into {DB}...", flush=True)
    conn = sqlite3.connect(DB)
    inserted = 0
    skipped = 0
    for c in candidates:
        exists = conn.execute("SELECT 1 FROM vulns WHERE cve_id=?", (c["cve_id"],)).fetchone()
        if exists:
            skipped += 1
            continue
        conn.execute(
            """INSERT INTO vulns (key, cve_id, source, title, link, summary, reason, vuln_type,
               cvss, severity, cvss_vector, pushed, freshness, freshness_reason, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 'fresh', 'backfill', datetime('now'))""",
            (c["key"], c["cve_id"], c["source"], c["title"], c["link"], c["summary"],
             c["reason"], c["vuln_type"], c["cvss"], c["severity"], c["cvss_vector"]),
        )
        inserted += 1
    conn.commit()
    conn.close()
    print(f"Done: inserted={inserted}, skipped={skipped}", flush=True)


if __name__ == "__main__":
    main()
