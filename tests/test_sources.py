"""Tests for the replacement source fetchers' parsers.

The original vendor RSS feeds (MSRC / Fortinet ir.xml / watchTowr) froze in
2026-Q2 — they still return 200 but serve month-old snapshots. The new fetchers
pull from CVRF XML / portal HTML / posts-sitemap instead. The network layer is
exercised on the server; these tests lock down the parsing against representative
samples so a layout change is caught before deploy.
"""
import os
os.environ.setdefault("VULN_DATA_DIR", "")

import src.vuln_monitor as v


# ── MSRC: CVRF XML (RSS deprecated) ──

MSRC_SAMPLE = b"""<?xml version="1.0" encoding="utf-8"?>
<cvrf:cvrfdoc xmlns:cvrf="http://www.icasi.org/CVRF/schema/cvrf/1.1"
              xmlns:vuln="http://www.icasi.org/CVRF/schema/vuln/1.1">
  <vuln:Vulnerability Ordinal="1">
    <vuln:CVE>CVE-2026-99999</vuln:CVE>
    <vuln:Title>Remote Code Execution in TestProduct</vuln:Title>
  </vuln:Vulnerability>
  <vuln:Vulnerability Ordinal="2">
    <vuln:CVE>CVE-2026-99998</vuln:CVE>
    <vuln:Title>Elevation of Privilege</vuln:Title>
  </vuln:Vulnerability>
</cvrf:cvrfdoc>"""


def test_msrc_cvrf_parse():
    items = v._parse_msrc_cvrf(MSRC_SAMPLE)
    assert len(items) == 2
    assert items[0]["source"] == "MSRC"
    assert "CVE-2026-99999" in items[0]["title"]
    assert "Remote Code Execution" in items[0]["title"]
    assert items[0]["link"].endswith("/CVE-2026-99999")


def test_msrc_cvrf_bad_xml_returns_empty():
    assert v._parse_msrc_cvrf(b"not xml") == []


# ── Fortinet: /psirt portal HTML (ir.xml RSS frozen) ──

FORTINET_SAMPLE = """
<div class="row" onclick="location.href = '/psirt/FG-IR-26-143'">
    <div class="col-md-3">
        <b>FG-IR-26-143 Restricted CLI escape using Lua</b>
        <br>
        <b class="cve">CVE-2025-67862</b>
    </div>
    <div class="col-md-2">
        <small>An Internal Asset Exposed to Unsafe Debug Access Level</small>
    </div>
</div>
<div class="row" onclick="location.href = '/psirt/FG-IR-26-140'">
    <div class="col-md-3">
        <b>FG-IR-26-140 Advisory without a CVE</b>
    </div>
</div>
"""


def test_fortinet_psirt_parse():
    items = v._parse_fortinet_psirt(FORTINET_SAMPLE)
    assert len(items) == 1  # the no-CVE row is skipped
    it = items[0]
    assert it["source"] == "Fortinet"
    assert "FG-IR-26-143" in it["title"]
    assert "CVE-2025-67862" in it["title"]
    assert "Restricted CLI escape using Lua" in it["title"]
    assert it["link"].endswith("/FG-IR-26-143")
    assert "Unsafe Debug Access" in it["summary"]


# ── watchTowr: posts sitemap (RSS frozen) ──

WATCHTOWR_SAMPLE = """<?xml version="1.0" encoding="UTF-8"?>
<urlset>
  <url><loc>https://labs.watchtowr.com/we-hack-kemp-loadmaster-pre-auth-rce-cve-2026-8037/</loc><lastmod>2026-06-29T19:24:54.000Z</lastmod></url>
  <url><loc>https://labs.watchtowr.com/some-non-vuln-thought-leadership-post/</loc><lastmod>2026-06-01T00:00:00Z</lastmod></url>
  <url><loc>https://labs.watchtowr.com/splunk-enterprise-cve-2026-20253/</loc><lastmod>2026-06-18T18:54:15Z</lastmod></url>
</urlset>"""


def test_watchtowr_sitemap_parse():
    items = v._parse_watchtowr_sitemap(WATCHTOWR_SAMPLE)
    assert len(items) == 2  # the non-vuln post is dropped
    assert items[0]["source"] == "watchTowr"
    assert "CVE-2026-8037" in items[0]["title"]
    assert items[0]["link"].startswith("https://labs.watchtowr.com/")
    assert items[0]["_pub_date"] == "2026-06-29"
    assert "CVE-2026-20253" in items[1]["title"]
