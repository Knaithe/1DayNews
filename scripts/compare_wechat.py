"""
Compare vuln-monitor coverage with WeChat 网络安全日报.
Navigates from album page into articles (avoids captcha),
extracts CVE IDs, then cross-references with local DB.
"""
import asyncio
import re
import json
import sys

import cloakbrowser

ALBUM_URL = (
    "https://mp.weixin.qq.com/mp/appmsgalbum"
    "?__biz=MzA5OTU0ODQ3MA=="
    "&action=getalbum"
    "&album_id=4531202795517083653"
    "&scene=126"
)

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")


async def scrape_articles(max_articles=10):
    browser = await cloakbrowser.launch_async(headless=True)
    page = await browser.new_page()

    print("[1] Loading album page...")
    await page.goto(ALBUM_URL, wait_until="networkidle", timeout=30000)

    items = await page.query_selector_all(".album__list-item")
    print(f"    Found {len(items)} article entries")

    articles = []
    for item in items[:max_articles]:
        title = await item.evaluate("el => el.querySelector('.album__item-title-wrp')?.innerText || ''")
        link = await item.get_attribute("data-link")
        if link:
            articles.append({"title": title.strip(), "link": link})

    all_cves = {}  # cve_id -> {articles, details}

    for i, art in enumerate(articles):
        print(f"\n[{i+2}] {art['title'][:60]}...")
        detail_page = await browser.new_page()
        try:
            await detail_page.goto(art["link"], wait_until="networkidle", timeout=30000)
            await detail_page.wait_for_timeout(1500)

            body_text = await detail_page.evaluate("""() => {
                const c = document.getElementById('js_content')
                    || document.querySelector('.rich_media_content');
                return c ? c.innerText : document.body.innerText.substring(0, 15000);
            }""")

            if "环境异常" in body_text or len(body_text) < 100:
                print("    ⚠ Captcha or empty page, skipping")
                continue

            cves = set(CVE_RE.findall(body_text))
            print(f"    Found {len(cves)} CVEs: {', '.join(sorted(cves)[:8])}{'...' if len(cves)>8 else ''}")

            for cve in cves:
                if cve not in all_cves:
                    all_cves[cve] = {"articles": [], "snippet": ""}
                all_cves[cve]["articles"].append(art["title"][:40])

                if not all_cves[cve]["snippet"]:
                    for line in body_text.split("\n"):
                        if cve in line and len(line) > 20:
                            all_cves[cve]["snippet"] = line[:200]
                            break

        except Exception as e:
            print(f"    ✗ Error: {e}")
        finally:
            await detail_page.close()

    await browser.close()
    return all_cves


def compare_with_db(wechat_cves):
    import sqlite3
    from pathlib import Path

    db_path = Path(__file__).resolve().parent.parent / "vuln_cache.db"
    if not db_path.exists():
        print(f"\n⚠ Local DB not found at {db_path}")
        print("  Outputting all WeChat CVEs for manual comparison")
        return wechat_cves, {}

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row

    existing = {}
    for cve_id in wechat_cves:
        row = conn.execute(
            "SELECT cve_id, title, vuln_type, severity, cvss, reason, source "
            "FROM vulns WHERE cve_id = ?", (cve_id,)
        ).fetchone()
        if row:
            existing[cve_id] = dict(row)

    conn.close()

    missing = {k: v for k, v in wechat_cves.items() if k not in existing}
    return missing, existing


def main():
    max_art = int(sys.argv[1]) if len(sys.argv) > 1 else 8
    print(f"=== WeChat 网络安全日报 Coverage Comparison ===")
    print(f"    Scraping up to {max_art} articles\n")

    wechat_cves = asyncio.run(scrape_articles(max_articles=max_art))
    print(f"\n{'='*60}")
    print(f"Total unique CVEs from WeChat daily: {len(wechat_cves)}")

    missing, existing = compare_with_db(wechat_cves)

    print(f"\n✓ Already in vuln-monitor: {len(existing)}")
    print(f"✗ MISSING from vuln-monitor: {len(missing)}")

    if missing:
        print(f"\n{'='*60}")
        print("MISSING CVEs (blind spots):\n")
        for cve_id in sorted(missing):
            info = missing[cve_id]
            snippet = info.get("snippet", "")[:120]
            print(f"  {cve_id}")
            if snippet:
                print(f"    {snippet}")
            print()

    if existing:
        print(f"\n{'='*60}")
        print("Already covered:\n")
        for cve_id in sorted(existing):
            row = existing[cve_id]
            print(f"  {cve_id}  [{row.get('vuln_type','?')}] [{row.get('severity','?')}] src={row.get('source','?')}")

    result = {
        "total_wechat_cves": len(wechat_cves),
        "already_covered": len(existing),
        "missing": len(missing),
        "missing_cves": sorted(missing.keys()),
        "covered_cves": sorted(existing.keys()),
    }
    out_path = Path(__file__).resolve().parent.parent / "wechat_comparison.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"\nResults saved to {out_path}")


if __name__ == "__main__":
    from pathlib import Path
    main()
