"""Probe replacement URLs for all broken feeds."""
import feedparser
import requests

CANDIDATES = {
    "VMware": [
        "https://www.vmware.com/security/advisories.xml",
        "https://www.broadcom.com/support/vmware-security-advisories/rss",
        "https://support.broadcom.com/security-advisory/rss",
        "https://www.vmware.com/content/dam/digitalmarketing/vmware/en/pdf/security/rss.xml",
        "https://blogs.vmware.com/security/feed",
    ],
    "F5": [
        "https://my.f5.com/manage/s/feed/security-advisories",
        "https://my.f5.com/manage/s/article/K000148074?feedType=rss",
        "https://support.f5.com/rss/security.xml",
        "https://www.f5.com/company/blog/rss.xml",
    ],
    "Assetnote": [
        "https://www.assetnote.io/resources/rss.xml",
        "https://www.assetnote.io/resources/feed.xml",
        "https://www.assetnote.io/rss.xml",
        "https://www.assetnote.io/feed",
        "https://www.assetnote.io/rss",
        "https://blog.assetnote.io/feed",
    ],
    "Horizon3": [
        "https://www.horizon3.ai/attack-research/feed/",
        "https://www.horizon3.ai/feed/",
        "https://www.horizon3.ai/blog/feed/",
        "https://www.horizon3.ai/rss",
        "https://horizon3.ai/feed/",
    ],
    "CISA_KEV": [
        "https://www.cisa.gov/cybersecurity-advisories/known-exploited-vulnerabilities.xml",
        "https://www.cisa.gov/known-exploited-vulnerabilities.xml",
        "https://www.cisa.gov/news.xml",
        "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    ],
    "Cisco": [
        "https://tools.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml",
        "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml",
        "https://sec.cloudapps.cisco.com/security/center/publicationListing.x",
    ],
}

UA = {"User-Agent": "Mozilla/5.0"}

for vendor, urls in CANDIDATES.items():
    print(f"\n=== {vendor} ===")
    for u in urls:
        try:
            r = requests.get(u, headers=UA, timeout=15, allow_redirects=True)
            ct = r.headers.get("Content-Type", "")[:30]
            if "json" in ct.lower():
                tag = "JSON" if r.status_code == 200 else "NO "
                print(f"  [{tag}] {r.status_code} json ct={ct}")
                print(f"       {u}")
                if r.status_code == 200:
                    try:
                        data = r.json()
                        n = len(data.get("vulnerabilities", []) or data.get("items", []) or [])
                        print(f"       json entries={n}")
                    except Exception:
                        pass
                continue
            d = feedparser.parse(r.content)
            entries = len(d.entries)
            title = getattr(d.feed, "title", "") if entries else ""
            tag = "OK " if entries > 0 and not d.bozo else ("BOZ" if entries > 0 else "NO ")
            print(f"  [{tag}] {r.status_code} entries={entries} ct={ct}")
            print(f"       {u}")
            if entries:
                print(f"       title: {title!r}")
                print(f"       first: {d.entries[0].get('title','')[:90]!r}")
        except Exception as ex:
            print(f"  [ERR] {u}: {str(ex)[:80]}")
