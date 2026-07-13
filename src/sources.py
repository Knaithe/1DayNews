"""Vulnerability data-source fetchers."""
import json
import os
import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import defusedxml.ElementTree as ET
import feedparser
import requests
# TWCERT's cert carries a non-standard 32-byte SKI (RFC 5280 mandates 20); we
# fetch it with verify=False, so suppress the per-request InsecureRequestWarning
# (otherwise ~51 warnings per TWCERT cycle spam the log).
try:
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except Exception:
    pass

try:
    from src.config import (
        SESS, _get_with_retry, GH_TOKEN, ITEM_PER_FEED, REQUEST_TIMEOUT,
        CACHE_TTL_DAYS, RSS_FEEDS, KEV_JSON_URL, CHAITIN_API_URL, THREATBOOK_API_URL,
        TWCERT_RSS_URL, MSRC_CVRF_API, _MONTH_ABBR, FORTINET_PSIRT_URL, WATCHTOWR_SITEMAP,
        REPO_ADVISORY_SOURCES, SOURCE_HEALTH, log,
    )
    from src.scoring import CVE_RE
except ImportError:
    from config import (
        SESS, _get_with_retry, GH_TOKEN, ITEM_PER_FEED, REQUEST_TIMEOUT,
        CACHE_TTL_DAYS, RSS_FEEDS, KEV_JSON_URL, CHAITIN_API_URL, THREATBOOK_API_URL,
        TWCERT_RSS_URL, MSRC_CVRF_API, _MONTH_ABBR, FORTINET_PSIRT_URL, WATCHTOWR_SITEMAP,
        REPO_ADVISORY_SOURCES, SOURCE_HEALTH, log,
    )
    from scoring import CVE_RE

def fetch_rss(name, url):
    """Fetch with our own timeout (feedparser.parse(url) has no timeout control)."""
    out = []
    try:
        r = _get_with_retry(SESS, url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        if r.status_code != 200:
            log.warning(f"RSS {name} HTTP {r.status_code}")
            return out
        d = feedparser.parse(r.content)
        if getattr(d, "bozo", False) and not d.entries:
            log.warning(f"RSS {name} parse error: {getattr(d, 'bozo_exception', '')}")
            return out
        for e in d.entries[:ITEM_PER_FEED]:
            title   = (e.get("title") or "").strip()
            link    = (e.get("link") or "").strip()
            summary = re.sub(r"<[^>]+>", " ", e.get("summary", "") or "").strip()
            out.append({
                "source": name,
                "title": title,
                "link": link,
                "summary": summary[:500],
                "text": f"{title}\n{summary}",
            })
    except Exception as ex:
        log.warning(f"RSS {name} err: {ex}")
    return out

def fetch_kev_json():
    """CISA KEV: gold-standard in-the-wild exploited list. JSON with 1500+ entries."""
    out = []
    try:
        r = _get_with_retry(SESS, KEV_JSON_URL, timeout=REQUEST_TIMEOUT)
        if r.status_code != 200:
            log.warning(f"KEV HTTP {r.status_code}")
            return out
        data = r.json()
        kev_cutoff = (datetime.now(timezone.utc) - timedelta(days=CACHE_TTL_DAYS)).strftime("%Y-%m-%d")
        for v in data.get("vulnerabilities", []):
            if v.get("dateAdded", "") < kev_cutoff:
                continue
            cve = v.get("cveID", "")
            vendor = v.get("vendorProject", "")
            product = v.get("product", "")
            name = v.get("vulnerabilityName", "")
            short = v.get("shortDescription", "")
            ransomware = v.get("knownRansomwareCampaignUse", "")
            due = v.get("dueDate", "")
            title = f"[KEV] {cve} {vendor} {product}: {name}"
            summary = f"{short} (due {due}, ransomware={ransomware})"
            out.append({
                "source": "CISA_KEV",
                "title": title[:300],
                "link": f"https://nvd.nist.gov/vuln/detail/{cve}",
                "summary": summary[:500],
                "text": f"{title}\n{summary}",
            })
    except Exception as ex:
        log.warning(f"KEV err: {ex}")
    return out


def fetch_chaitin():
    """Chaitin Stack vuldb — Chinese vuln database (350k+ total, ~184 curated).

    Uses a hidden JSON API; fresh session + Referer header to pass SafeLine WAF.
    Default list returns curated high-risk items (~184), not the full database.
    API limited to ~15 results per call; used as supplementary source.
    """
    out = []
    s = requests.Session()
    try:
        s.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Referer": "https://stack.chaitin.com/vuldb/index",
            "Origin": "https://stack.chaitin.com",
            "Accept": "application/json",
        })
        r = _get_with_retry(s, CHAITIN_API_URL,
                  params={"limit": ITEM_PER_FEED, "offset": 0},
                  timeout=REQUEST_TIMEOUT)
        if r.status_code != 200:
            log.warning(f"Chaitin HTTP {r.status_code}")
            return out
        data = r.json()
        for v in data.get("data", {}).get("list", []):
            ct_id = v.get("ct_id", "")
            cve = v.get("cve_id", "")
            title = v.get("title", "")
            severity = v.get("severity", "")
            summary = v.get("summary", "")
            refs = v.get("references", "")
            link = f"https://stack.chaitin.com/vuldb/detail/{v['id']}" if v.get("id") else ""
            full_title = f"[{severity.upper()}] {cve or ct_id} {title}"
            out.append({
                "source": "Chaitin",
                "title": full_title[:300],
                "link": link,
                "summary": summary[:500],
                "text": f"{full_title}\n{summary}\n{refs}",
            })
    except Exception as ex:
        log.warning(f"Chaitin err: {ex}")
    finally:
        s.close()
    return out


def fetch_threatbook():
    """微步在线 ThreatBook — premium + highrisk vuln listings."""
    out = []
    s = requests.Session()
    try:
        s.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Referer": "https://x.threatbook.com/v5/vul",
            "Origin": "https://x.threatbook.com",
            "Accept": "application/json",
        })
        r = _get_with_retry(s, THREATBOOK_API_URL, timeout=REQUEST_TIMEOUT)
        if r.status_code != 200:
            log.warning(f"ThreatBook HTTP {r.status_code}")
            return out
        data = r.json().get("data", {})
        for section in ("premium", "highrisk"):
            for v in data.get(section, []):
                xve = v.get("id", "")
                name = v.get("vuln_name_zh", "")
                risk = v.get("riskLevel", "")
                poc = v.get("pocExist", False)
                affects = ", ".join(v.get("affects", []))
                pub_date = v.get("vuln_publish_time", "")
                link = f"https://x.threatbook.com/v5/vul/{xve}" if xve else ""
                title = f"[{risk}] {xve} {name}"
                summary = f"affects: {affects}" if affects else ""
                if poc:
                    summary = f"PoC available. {summary}"
                if pub_date:
                    summary = f"published: {pub_date}. {summary}"
                out.append({
                    "source": "ThreatBook",
                    "title": title[:300],
                    "link": link,
                    "summary": summary[:500],
                    "text": f"{title}\n{summary}\n{affects}",
                    "_pub_date": pub_date,  # used by _run() to set cve_published
                })
    except Exception as ex:
        log.warning(f"ThreatBook err: {ex}")
    finally:
        s.close()
    return out


# NVD API is used only for cve_published date lookup (_nvd_published_date),
# NOT as an intelligence source. Raw NVD data is too noisy (kernel patches,
# personal project CVEs, etc.) and has no editorial curation.


def fetch_poc_in_github():
    """nomi-sec/PoC-in-GitHub: latest commit diff → new PoC repos for recent CVEs."""
    out = []
    year = datetime.now().year
    headers = {"Accept": "application/vnd.github+json"}
    if GH_TOKEN:
        headers["Authorization"] = f"Bearer {GH_TOKEN}"
    try:
        r = _get_with_retry(SESS,
            "https://api.github.com/repos/nomi-sec/PoC-in-GitHub/commits/master",
            headers=headers, timeout=REQUEST_TIMEOUT)
        if r.status_code != 200:
            log.warning(f"PoC-in-GitHub HTTP {r.status_code}")
            return out
        files = r.json().get("files", [])
        for f in files:
            fname = f.get("filename", "")
            # only current/previous year CVEs (path: "2026/CVE-2026-xxxx.json")
            if not (fname.startswith(f"{year}/") or fname.startswith(f"{year-1}/")):
                continue
            cves = CVE_RE.findall(fname)
            if not cves:
                continue
            cve = cves[0].upper()
            raw_url = f.get("raw_url", "")
            # fetch the JSON to get PoC repo URLs
            if raw_url:
                try:
                    jr = SESS.get(raw_url, headers=headers, timeout=10)
                    if jr.status_code == 200:
                        repos = jr.json() if isinstance(jr.json(), list) else []
                        for repo in repos[:3]:
                            name = repo.get("full_name", "")
                            desc = repo.get("description") or ""
                            html_url = repo.get("html_url", "")
                            out.append({
                                "source": "PoC-GitHub",
                                "title": f"{cve} PoC: {name}",
                                "link": html_url,
                                "summary": desc[:500],
                                "text": f"{cve} {name}\n{desc}",
                            })
                except Exception:
                    pass
    except Exception as ex:
        log.warning(f"PoC-in-GitHub err: {ex}")
    return out


def fetch_github_advisories():
    """Fetch recent advisories from GitHub Advisory Database.

    Uses date-range windowing to cover the last 30 days, avoiding pagination limits.
    Pulls critical + high severity in weekly windows.
    """
    out = []
    headers = {"Accept": "application/vnd.github+json"}
    if GH_TOKEN:
        headers["Authorization"] = f"Bearer {GH_TOKEN}"
    now = datetime.now(timezone.utc)
    for severity in ("critical", "high"):
        # slide 7-day windows over last 30 days
        for weeks_ago in range(5):
            end = now - timedelta(days=weeks_ago * 7)
            start = end - timedelta(days=7)
            date_range = f"{start.strftime('%Y-%m-%d')}..{end.strftime('%Y-%m-%d')}"
            for page in range(1, 5):
                try:
                    r = _get_with_retry(SESS, "https://api.github.com/advisories",
                                 params={"severity": severity, "published": date_range,
                                         "sort": "published", "direction": "desc",
                                         "per_page": 100, "page": page},
                                 headers=headers, timeout=15)
                    if r.status_code != 200:
                        break
                    advs = r.json()
                    if not isinstance(advs, list) or not advs:
                        break
                    for adv in advs:
                        cve = adv.get("cve_id") or adv.get("ghsa_id", "")
                        summary = adv.get("summary", "")
                        desc = adv.get("description", "")
                        cvss_obj = adv.get("cvss", {})
                        cvss = cvss_obj.get("score")
                        vec = cvss_obj.get("vector_string", "")
                        sev = adv.get("severity", "")
                        cvss_str = f" (CVSS {cvss})" if cvss else ""
                        sev_str = f" [{sev.upper()}]" if sev else ""
                        full_text = desc or summary
                        display_summary = (desc or summary)[:500] + cvss_str
                        out.append({
                            "source": "GHSA",
                            "title": f"{sev_str} {cve} {summary[:200]}".strip(),
                            "link": adv.get("html_url", ""),
                            "summary": display_summary,
                            "text": f"{cve} {full_text}",
                            "_severity": sev.lower() if sev else None,
                            "_cvss": cvss,
                            "_cvss_vector": vec or None,
                        })
                    if len(advs) < 100:
                        break  # no more pages for this window
                except Exception as ex:
                    log.warning(f"GHSA {severity} {date_range} p{page}: {ex}")
                    break
                time.sleep(0.5)
            time.sleep(0.5)
    return out


def fetch_repo_advisories():
    """Fetch repo-level GitHub Security Advisories for independent software products.

    The global /advisories endpoint (fetch_github_advisories) only indexes advisories
    bound to a package ecosystem (npm/pip/maven...). Software shipped outside any
    package manager — firewalls (OPNsense), web servers (nginx/Apache), runtimes
    (PHP/Node/OpenSSL) — publishes advisories to their own repo via the
    repos/{owner}/{repo}/security-advisories endpoint, which never reach the global
    database. This fetcher closes that gap (e.g. OPNsense CVE-2026-57155 Root RCE).

    Source is labelled "GHSA-Repo" so the dashboard can distinguish it from global
    GHSA. Dedup is by CVE id (item_key → "cve:CVE-...") so overlap with global GHSA
    is harmless: whichever source arrives first claims the record.
    """
    out = []
    headers = {"Accept": "application/vnd.github+json"}
    if GH_TOKEN:
        headers["Authorization"] = f"Bearer {GH_TOKEN}"
    else:
        # Without a token GitHub allows only 60 req/hr (shared with GHSA + PoC-GitHub);
        # this fetcher alone needs ~14 req/cycle. Warn once so operators know GHSA-Repo
        # will be starved until GH_TOKEN is set in .env.
        log.warning("GHSA-Repo: no GH_TOKEN — unauthenticated rate limit (60/hr) will "
                    "starve this source; set GH_TOKEN for reliable coverage")
    for repo in REPO_ADVISORY_SOURCES:
        try:
            r = _get_with_retry(
                SESS, f"https://api.github.com/repos/{repo}/security-advisories",
                params={"per_page": 100, "sort": "published", "direction": "desc"},
                headers=headers, timeout=15)
            if r.status_code != 200:
                # Rate-limited? Stop early — remaining repos will also 403.
                if r.status_code in (403, 429):
                    rem = r.headers.get("X-RateLimit-Remaining")
                    if rem == "0" or r.status_code == 429:
                        log.warning(f"GHSA-Repo {repo}: rate-limited "
                                    f"(remaining={rem}), aborting remaining repos")
                        break
                # 404 = repo hasn't enabled advisories; skip to next repo
                continue
            advs = r.json()
            if not isinstance(advs, list):
                continue
            for adv in advs:
                sev = (adv.get("severity") or "").lower()
                if sev not in ("critical", "high"):
                    continue
                cve = adv.get("cve_id") or adv.get("ghsa_id", "")
                summary = adv.get("summary", "")
                desc = adv.get("description", "")
                cvss_obj = adv.get("cvss", {})
                cvss = cvss_obj.get("score")
                vec = cvss_obj.get("vector_string", "")
                cvss_str = f" (CVSS {cvss})" if cvss else ""
                sev_str = f"[{sev.upper()}]" if sev else ""
                full_text = desc or summary
                out.append({
                    "source": "GHSA-Repo",
                    "title": f"[GHSA-Repo] {sev_str} {cve} {summary[:200]}".strip(),
                    "link": adv.get("html_url", ""),
                    "summary": (desc or summary)[:500] + cvss_str,
                    "text": f"{cve} {full_text}",
                    "_severity": sev or None,
                    "_cvss": cvss,
                    "_cvss_vector": vec or None,
                })
        except Exception as ex:
            log.warning(f"GHSA-Repo {repo}: {ex}")
        time.sleep(0.5)
    return out


def _parse_msrc_cvrf(xml_bytes):
    """Parse a MSRC CVRF security bundle (XML) into CVE-level items."""
    out = []
    try:
        root = ET.fromstring(xml_bytes)
    except Exception:
        return out
    for vuln in root.findall(".//{*}Vulnerability"):
        cve_el = vuln.find("{*}CVE")
        cve = (cve_el.text or "").strip() if cve_el is not None else ""
        if not re.match(r"^CVE-\d{4}-\d+$", cve):
            continue
        title_el = vuln.find("{*}Title")
        title = (title_el.text or "").strip() if title_el is not None else ""
        full = f"[MSRC] {cve} {title}".strip()
        out.append({
            "source": "MSRC",
            "title": full[:300],
            "link": f"https://msrc.microsoft.com/update-guide/vulnerability/{cve}",
            "summary": title[:500],
            "text": f"{full}\n{title}",
        })
    return out


def fetch_msrc():
    """Microsoft MSRC — CVRF XML API. The RSS feed was deprecated in 2026 (it now
    serves a frozen April snapshot). The /updates list is unsorted and polluted
    with Mariner notes, so we fetch the last 2 real monthly bundles by constructed
    alias (YYYY-Mon) and parse the CVRF XML. Each bundle carries 1000+ CVEs;
    score() filters the noise.
    """
    out = []
    now = datetime.now(timezone.utc)
    aliases = []
    for back in range(0, 2):  # current + previous month
        y, m = now.year, now.month - back
        while m <= 0:
            m += 12
            y -= 1
        aliases.append(f"{y}-{_MONTH_ABBR[m - 1]}")
    for alias in aliases:
        try:
            r = _get_with_retry(SESS, MSRC_CVRF_API.format(alias=alias),
                                timeout=90, headers={"User-Agent": "vuln-monitor/1.0"})
            if r.status_code != 200:
                continue
            out.extend(_parse_msrc_cvrf(r.content))
        except Exception as ex:
            log.warning(f"MSRC {alias} err: {ex}")
    seen, deduped = set(), []
    for it in out:
        if it["title"] in seen:
            continue
        seen.add(it["title"])
        deduped.append(it)
    return deduped


_FORTINET_ROW_RE = re.compile(
    r"<div class=\"row\" onclick=\"location\.href\s*=\s*'/psirt/(FG-IR-\d+-\d+)'\">"
    r".*?<b>FG-IR-\d+-\d+\s*(.*?)</b>"
    r".*?<b class=\"cve\">(CVE-\d{4}-\d{4,})</b>"
    r"(?:.*?<small>(.*?)</small>)?",
    re.S)


def _parse_fortinet_psirt(html):
    """Parse the Fortinet PSIRT portal HTML into FG-IR advisory items.

    Only advisories that carry a CVE are returned (about half of them); the rest
    have no CVE to track and are skipped.
    """
    out = []
    for m in _FORTINET_ROW_RE.finditer(html):
        fgir, title, cve, desc = (m.group(1), m.group(2).strip(), m.group(3),
                                  (m.group(4) or ""))
        desc = re.sub(r"<[^>]+>", " ", desc).strip()
        full = f"[Fortinet] {fgir} {cve} {title}".strip()
        out.append({
            "source": "Fortinet",
            "title": full[:300],
            "link": f"https://www.fortiguard.com/psirt/{fgir}",
            "summary": desc[:500],
            "text": f"{full}\n{desc}",
        })
    return out


def fetch_fortinet():
    """Fortinet PSIRT — the ir.xml RSS froze in 2026-Q2 (serves an April snapshot).
    Scrape the live portal HTML for FG-IR-* advisories instead.
    """
    out = []
    try:
        r = _get_with_retry(SESS, FORTINET_PSIRT_URL, timeout=REQUEST_TIMEOUT,
                            headers={"User-Agent": "Mozilla/5.0"}, allow_redirects=True)
        if r.status_code != 200:
            log.warning(f"Fortinet HTTP {r.status_code}")
            return out
        out = _parse_fortinet_psirt(r.text)
        if not out:
            log.warning("Fortinet parsed 0 advisories — portal HTML layout may have changed")
    except Exception as ex:
        log.warning(f"Fortinet err: {ex}")
    return out


_WATCHTOWR_ENTRY_RE = re.compile(
    r"<url>\s*<loc>([^<]+)</loc>\s*<lastmod>([^<]+)</lastmod>", re.S)


def _parse_watchtowr_sitemap(xml):
    """Parse watchTowr's posts sitemap into items, keeping only CVE-tagged posts."""
    out = []
    for loc, lastmod in _WATCHTOWR_ENTRY_RE.findall(xml):
        m = re.search(r"cve-(\d{4}-\d+)", loc, re.I)
        if not m:
            continue  # non-vulnerability blog post
        cve = "CVE-" + m.group(1)
        slug = loc.rstrip("/").split("/")[-1]
        slug = re.sub(r"-cve-\d+-\d+", "", slug, flags=re.I).replace("-", " ").strip()
        pub = lastmod[:10]
        full = f"[watchTowr] {cve} {slug}"
        out.append({
            "source": "watchTowr",
            "title": full[:300],
            "link": loc,
            "summary": f"published: {pub}. {slug}",
            "text": f"{full}\n{slug}",
            "_pub_date": pub,
        })
    return out


def fetch_watchtowr():
    """watchTowr labs — RSS froze in 2026-Q2; the posts sitemap is live and each
    vulnerability writeup's URL slug carries its CVE-Id (e.g. ...-cve-2026-8037/).
    """
    out = []
    try:
        r = _get_with_retry(SESS, WATCHTOWR_SITEMAP, timeout=REQUEST_TIMEOUT,
                            headers={"User-Agent": "Mozilla/5.0"})
        if r.status_code != 200:
            log.warning(f"watchTowr HTTP {r.status_code}")
            return out
        out = _parse_watchtowr_sitemap(r.text)
    except Exception as ex:
        log.warning(f"watchTowr err: {ex}")
    return out


# Matches "9.8 (Critical) CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
_TWCERT_CVSS_RE = re.compile(
    r"(\d+\.\d+)\s*\((Critical|High|Medium|Low)\)\s*(CVSS:[\d.]+/[^\s<]+)", re.I)
_TWCERT_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.I)


def _parse_twcert_detail(html, link):
    """Parse a TWCERT/CC detail page into one item per CVE.

    Each advisory page lists 1+ CVEs, each with its own CVSS score+vector, a
    product name, and a description block. We split per-CVE so item_key dedups
    by CVE id (cve:CVE-...), matching the rest of the pipeline.
    """
    out = []
    plain = re.sub(r"<[^>]+>", "\n", html)
    plain = re.sub(r"\n\s*\n", "\n", plain).strip()

    # Product name(s) — the 影響產品 section lists per-CVE affected products:
    #   【CVE-2026-7489】\n CTMS培訓大師 所有版本\n【CVE-2026-7490】\n CTMS...\n CAPS...
    # (single-product pages just have the bare name without 【CVE-】 markers)
    product_section = ""
    m = re.search(r"影響產品\s*\n(.+?)(?:問題描述|解決方法|公開日期|$)", plain, re.S)
    if m:
        product_section = m.group(1)
    per_cve_product = {}
    for pm in re.finditer(r"【\s*(CVE-\d{4}-\d+)\s*】(.+?)(?=【\s*CVE-\d|$)",
                          product_section, re.S):
        per_cve_product[pm.group(1).upper()] = re.sub(r"\s+", " ", pm.group(2)).strip()
    # fallback: bare product name (no per-CVE markers)
    fallback_product = re.sub(r"\s+", " ", product_section).strip() if product_section else ""

    # Publication date: "公開日期  2026-07-06"
    pub_date = ""
    m = re.search(r"公開日期\s*\n\s*(\d{4}-\d{2}-\d{2})", plain)
    if m:
        pub_date = m.group(1)

    # Per-CVE descriptions in the 問題描述 section:
    #   【CVE-2026-14808(Exposure of Sensitive Information)】 描述...
    #   【CVE-2026-14809(SQL Injection)】 描述...
    desc_section = ""
    m = re.search(r"問題描述\s*\n(.+?)(?:解決方法|漏洞通報者|公開日期)", plain, re.S)
    if m:
        desc_section = m.group(1)
    # map each CVE → its own description (the text up to the next 【CVE- marker)
    per_cve_desc = {}
    for dm in re.finditer(r"【\s*(CVE-\d{4}-\d+)\s*\(([^)]*)\)\s*】(.+?)(?=【\s*CVE-\d|$)",
                          desc_section, re.S):
        cve_id, vuln_type, body = dm.group(1).upper(), dm.group(2), dm.group(3)
        body_clean = re.sub(r"\s+", " ", body).strip()
        per_cve_desc[cve_id] = f"{vuln_type}. {body_clean}"

    # CVSS scores — the CVSS section lists per-CVE blocks (multi-CVE pages):
    #   【CVE-2026-7489】\n8.8 (High) CVSS:3.1/...
    # Single-CVE pages have a bare score with no 【CVE-】 marker:
    #   9.8 (Critical) \nCVSS:3.1/...
    cvss_section = ""
    m = re.search(r"CVSS\s*\n(.+?)(?:影響產品|問題描述)", plain, re.S)
    if m:
        cvss_section = m.group(1)
    per_cve_cvss = {}
    for cm in re.finditer(r"【\s*(CVE-\d{4}-\d+)\s*】\s*\n(.+?)(?=【\s*CVE-\d|$)",
                          cvss_section, re.S):
        cve_id = cm.group(1).upper()
        cvm = _TWCERT_CVSS_RE.search(cm.group(2))
        if cvm:
            per_cve_cvss[cve_id] = (cvm.group(1), cvm.group(2).lower(), cvm.group(3))
    # fallback: bare score (single-CVE page, no per-CVE markers)
    fallback_cvss = None
    if not per_cve_cvss:
        fm = _TWCERT_CVSS_RE.search(cvss_section)
        if fm:
            fallback_cvss = (fm.group(1), fm.group(2).lower(), fm.group(3))

    cves = list(dict.fromkeys(c.upper() for c in _TWCERT_CVE_RE.findall(plain)))
    if not cves:
        # TVN-only advisory (no CVE assigned) — can't dedup/track without a CVE id
        log.debug(f"TWCERT {link}: no CVE, skipped")
        return out

    for cve in cves:
        score, severity, vector = (None, None, None)
        cv = per_cve_cvss.get(cve) or fallback_cvss
        if cv:
            score, severity, vector = cv
        product = per_cve_product.get(cve) or fallback_product
        desc = per_cve_desc.get(cve, "")[:500]
        # Strip any cross-referenced CVE IDs from the description so item_key (which
        # picks the alphabetically-smallest CVE in text) keys on THIS cve only.
        desc_sanitized = _TWCERT_CVE_RE.sub("", desc).strip()
        full = f"[TWCERT] {cve} {product}".strip()
        text = f"{full}\n{product}. {desc_sanitized}"
        out.append({
            "source": "TWCERT",
            "title": full[:300],
            "link": link,
            "summary": f"{product}. {desc}"[:500],
            "text": text,
            "_pub_date": pub_date or None,
            "_severity": severity,
            "_cvss": float(score) if score else None,
            "_cvss_vector": vector,
        })
    return out


def fetch_twcert():
    """TWCERT/CC — Taiwan Vulnerability Notes (TVN).

    The RSS (rss-132-1.xml) lists advisory titles/links but no CVE/CVSS. We pull
    the RSS for the link list, then fetch each detail page (cp-132-*) to extract
    structured fields (CVE ID, CVSS score+vector, product, vuln type). Each CVE
    becomes a separate item so item_key dedups by CVE id.

    TWCERT's TLS cert carries a non-standard 32-byte Subject Key Identifier
    (RFC 5280 mandates 20); strict verifiers (Windows Schannel, newer OpenSSL)
    reject it. verify=False is a deliberate trade-off for this official CERT source.

    Detail-page fetches use a short timeout (8s) and circuit-break after 3
    consecutive failures: some networks interfere with twcert.org.tw TLS handshakes
    (connections establish but stall, leaking into the shared connection pool);
    so we use a dedicated session, close every response explicitly, and bail early
    rather than stall the fetch cycle.
    """
    _TWCERT_TIMEOUT = 8          # per-request — twcert is slow / TLS-interfered
    _TWCERT_MAX_FAILS = 3        # circuit-break threshold for consecutive failures
    _twcert_headers = {"User-Agent": "Mozilla/5.0"}
    # Dedicated session: twcert's stalling connections leak CLOSE-WAIT sockets that
    # can exhaust the shared SESS pool and block other sources. Isolate them here.
    twsess = requests.Session()
    out = []
    try:
        # Single-shot (no _get_with_retry): on TLS-interfered networks twcert.org.tw
        # handshakes hang until timeout; retrying multiplies the stall.
        r = twsess.get(TWCERT_RSS_URL, timeout=_TWCERT_TIMEOUT,
                       headers=_twcert_headers, verify=False)
        if r.status_code != 200:
            log.warning(f"TWCERT RSS HTTP {r.status_code}")
            r.close()
            return out
        rss_text = r.text
        r.close()
        links = []
        for m in re.finditer(r"<link>(https://www\.twcert\.org\.tw/tw/cp-132-[^<]+)</link>",
                             rss_text):
            links.append(m.group(1))
        links = list(dict.fromkeys(links))[:ITEM_PER_FEED]
        consecutive_fails = 0
        for link in links:
            if consecutive_fails >= _TWCERT_MAX_FAILS:
                log.warning(f"TWCERT: circuit-break after {consecutive_fails} consecutive "
                            f"detail failures (network interference?), skipping remaining")
                break
            try:
                pr = twsess.get(link, timeout=_TWCERT_TIMEOUT,
                                headers=_twcert_headers, verify=False)
                if pr.status_code != 200:
                    consecutive_fails += 1
                    pr.close()
                    continue
                parsed = _parse_twcert_detail(pr.text, link)
                pr.close()
                if parsed:
                    out.extend(parsed)
                    consecutive_fails = 0
                else:
                    consecutive_fails += 1
            except Exception as ex:
                consecutive_fails += 1
                log.debug(f"TWCERT detail {link}: {ex}")
            time.sleep(0.5)
    except Exception as ex:
        log.warning(f"TWCERT err: {ex}")
    finally:
        twsess.close()
    return out


def _fetch_all_sources():
    """Collect items from all configured sources. Used by _run() and cmd_rebuild()."""
    items = []
    counts = {}
    for name, url in RSS_FEEDS:
        batch = fetch_rss(name, url)
        counts[name] = len(batch)
        items.extend(batch)
    for name, func in [("CISA_KEV", fetch_kev_json), ("Chaitin", fetch_chaitin),
                        ("ThreatBook", fetch_threatbook),
                        ("PoC-GitHub", fetch_poc_in_github),
                        ("GHSA", fetch_github_advisories),
                        ("GHSA-Repo", fetch_repo_advisories),
                        ("MSRC", fetch_msrc), ("Fortinet", fetch_fortinet),
                        ("watchTowr", fetch_watchtowr), ("TWCERT", fetch_twcert)]:
        batch = func()
        counts[name] = len(batch)
        items.extend(batch)
    log.info("source counts: " + "  ".join(f"{k}={v}" for k, v in counts.items()))
    _update_source_health(counts)
    return items


# Sources whose fetch legitimately returns 0 items on a healthy cycle, so 0 must NOT be
# treated as a failure. PoC-in-GitHub diffs only the latest commit — no new commit ⇒ 0
# items, even though the source is working fine.
_LEGIT_EMPTY_SOURCES = frozenset(["PoC-GitHub"])


def _update_source_health(counts):
    """Record per-source item counts over the last 3 fetch cycles → source_health.json.

    The web dashboard colors each source pill: green (healthy) or red (the source has
    returned 0 items for 3 consecutive cycles — i.e. it is timing out / dead). A source
    that can legitimately return 0 (see _LEGIT_EMPTY_SOURCES) is never flagged red.
    """
    state = {"ts": datetime.now(timezone.utc).isoformat(), "sources": {}}
    try:
        if SOURCE_HEALTH.exists():
            raw = json.loads(SOURCE_HEALTH.read_text(encoding="utf-8"))
            if isinstance(raw, dict) and isinstance(raw.get("sources"), dict):
                state["sources"] = raw["sources"]
    except Exception:
        pass
    hist = state["sources"]
    for name, cnt in counts.items():
        prev = hist.get(name)
        prev_recent = prev.get("recent") if isinstance(prev, dict) else None
        recent = (prev_recent if isinstance(prev_recent, list) else []) + [int(cnt or 0)]
        recent = recent[-3:]
        bad = (name not in _LEGIT_EMPTY_SOURCES
               and len(recent) >= 3 and all(c == 0 for c in recent))
        hist[name] = {"recent": recent, "healthy": not bad}
    for stale in [n for n in hist if n not in counts]:   # drop decommissioned sources
        del hist[stale]
    try:
        tmp = SOURCE_HEALTH.with_suffix(".tmp")
        tmp.write_text(json.dumps(state), encoding="utf-8")
        os.replace(tmp, SOURCE_HEALTH)
    except Exception:
        log.warning("failed to write source_health.json", exc_info=True)


