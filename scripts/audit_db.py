#!/usr/bin/env python3
"""Audit vuln_cache.db quality. Run locally against a copy of the DB.

Usage:
    python scripts/audit_db.py D:/Code/tmp/vuln_cache.db
    python scripts/audit_db.py /opt/vuln-monitor/vuln_cache.db
"""
import sqlite3
import sys
from pathlib import Path

def pct(n, total):
    return f"{100*n/total:.1f}%" if total else "N/A"

def run(db_path):
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row

    # ── 1. 总览 ──
    total = conn.execute("SELECT COUNT(*) FROM vulns").fetchone()[0]
    pushed = conn.execute("SELECT COUNT(*) FROM vulns WHERE pushed=1").fetchone()[0]
    print(f"{'='*60}")
    print(f"  DB 审计: {db_path}")
    print(f"  总记录: {total}  |  推送: {pushed} ({pct(pushed, total)})")
    print(f"{'='*60}\n")

    # ── 2. 字段覆盖率 ──
    cols = {}
    for col in ["cve_id", "cve_published", "cvss", "severity", "freshness",
                 "freshness_reason", "vuln_type", "llm_verdict", "llm_notes"]:
        try:
            n = conn.execute(f"SELECT COUNT(*) FROM vulns WHERE {col} IS NOT NULL AND {col} != ''").fetchone()[0]
            cols[col] = n
        except Exception:
            cols[col] = -1  # column doesn't exist

    print("── 字段覆盖率 ──")
    for col, n in cols.items():
        if n == -1:
            print(f"  {col:20s}  列不存在")
        else:
            print(f"  {col:20s}  {n:4d} / {total}  ({pct(n, total)})")

    # ── 3. 多 CVE 拼接 ──
    multi = conn.execute("SELECT COUNT(*) FROM vulns WHERE cve_id LIKE '%CVE-% CVE-%'").fetchone()[0]
    has_cve = cols.get("cve_id", 0)
    cve_no_nvd = conn.execute(
        "SELECT COUNT(*) FROM vulns WHERE cve_id LIKE 'CVE-%' AND cve_published IS NULL"
    ).fetchone()[0]
    print(f"\n── CVE 数据 ──")
    print(f"  有 CVE 编号:       {has_cve}")
    print(f"  多 CVE 拼接:       {multi}  (NVD 查询需拆分)")
    print(f"  有 CVE 无 NVD:     {cve_no_nvd}")

    # ── 4. 各源统计 ──
    print(f"\n── 各源数据质量 ──")
    print(f"  {'源':17s} {'总数':>5s} {'有CVE':>5s} {'有NVD':>5s} {'有CVSS':>5s} {'推送':>5s} {'1day':>5s} {'nday':>5s}")
    print(f"  {'-'*17} {'-'*5} {'-'*5} {'-'*5} {'-'*5} {'-'*5} {'-'*5} {'-'*5}")
    rows = conn.execute("""
        SELECT source, COUNT(*) as t,
            SUM(cve_id LIKE 'CVE-%%') as c,
            SUM(cve_published IS NOT NULL) as p,
            SUM(cvss IS NOT NULL) as cv,
            SUM(pushed=1) as pu,
            SUM(freshness='1day') as f1,
            SUM(freshness='nday') as fn
        FROM vulns GROUP BY source ORDER BY t DESC
    """).fetchall()
    for r in rows:
        print(f"  {r[0] or '(null)':17s} {r[1]:5d} {r[2] or 0:5d} {r[3] or 0:5d} {r[4] or 0:5d} {r[5] or 0:5d} {r[6] or 0:5d} {r[7] or 0:5d}")

    # ── 5. freshness 分布 ──
    print(f"\n── freshness 分布 ──")
    rows = conn.execute("""
        SELECT freshness, freshness_reason, COUNT(*) as n
        FROM vulns WHERE freshness IS NOT NULL
        GROUP BY freshness, freshness_reason ORDER BY freshness, n DESC
    """).fetchall()
    for r in rows:
        print(f"  {r[0] or 'NULL':6s}  {r[1] or '':20s}  {r[2]}")

    # ── 6. LLM verdict 分布 ──
    print(f"\n── LLM verdict 分布 ──")
    rows = conn.execute("""
        SELECT llm_verdict, COUNT(*) as n, SUM(pushed=1) as p
        FROM vulns WHERE llm_verdict IS NOT NULL
        GROUP BY llm_verdict ORDER BY n DESC
    """).fetchall()
    for r in rows:
        print(f"  {r[0]:15s}  {r[1]:4d} 条  (推送 {r[2] or 0})")

    # ── 7. 约束违反检测 ──
    print(f"\n── 约束违反检测 ──")
    issues = []

    # pushed 但不是 1day
    n = conn.execute("SELECT COUNT(*) FROM vulns WHERE pushed=1 AND freshness != '1day'").fetchone()[0]
    if n: issues.append(f"  [FAIL] {n} 条 pushed=1 但 freshness≠1day")

    # pushed 但是 GitHub
    n = conn.execute("SELECT COUNT(*) FROM vulns WHERE pushed=1 AND source IN ('GitHub','PoC-GitHub')").fetchone()[0]
    if n: issues.append(f"  [FAIL] {n} 条 GitHub/PoC-GitHub 被推送")

    # pushed 但没有 llm_verdict
    n = conn.execute("SELECT COUNT(*) FROM vulns WHERE pushed=1 AND llm_verdict IS NULL").fetchone()[0]
    if n: issues.append(f"  [WARN] {n} 条 pushed=1 但无 LLM verdict")

    # freshness=1day 但 CVE 年份明显过老
    n = conn.execute("""
        SELECT COUNT(*) FROM vulns
        WHERE freshness='1day' AND cve_id LIKE 'CVE-%%'
        AND CAST(SUBSTR(cve_id, 5, 4) AS INTEGER) < 2024
        AND cve_id NOT LIKE '%% CVE-%%'
    """).fetchone()[0]
    if n: issues.append(f"  [WARN] {n} 条 freshness=1day 但 CVE 年份 < 2024")

    # tg_sent 但 pushed=0
    n = conn.execute("SELECT COUNT(*) FROM vulns WHERE tg_sent=1 AND pushed=0").fetchone()[0]
    if n: issues.append(f"  [WARN] {n} 条 tg_sent=1 但 pushed=0 (历史遗留)")

    if issues:
        for i in issues:
            print(i)
    else:
        print("  [PASS] 所有约束检查通过")

    # ── 8. 垃圾内容检测 ──
    print(f"\n── 垃圾内容抽样 ──")
    # 非漏洞内容
    rows = conn.execute("""
        SELECT source, substr(title,1,60) FROM vulns
        WHERE freshness='1day' AND vuln_type IS NULL AND pushed=0
        AND reason NOT IN ('excluded','no hit')
        LIMIT 5
    """).fetchall()
    if rows:
        print("  1day 但无 vuln_type (可能是非漏洞内容):")
        for r in rows:
            print(f"    [{r[0]}] {r[1]}")

    # Rapid7 博客
    rows = conn.execute("""
        SELECT substr(title,1,60) FROM vulns
        WHERE source='Rapid7' AND cve_id IS NULL AND freshness='1day'
        LIMIT 5
    """).fetchall()
    if rows:
        print("  Rapid7 无 CVE 但标记 1day (博客/营销):")
        for r in rows:
            print(f"    {r[0]}")

    print(f"\n{'='*60}")
    print(f"  审计完成")
    print(f"{'='*60}")
    conn.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <path-to-vuln_cache.db>")
        sys.exit(1)
    db = Path(sys.argv[1])
    if not db.exists():
        print(f"ERROR: {db} not found")
        sys.exit(1)
    run(str(db))
