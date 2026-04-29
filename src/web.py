#!/usr/bin/env python3
"""
vuln-monitor web dashboard. Read-only SQLite viewer.

Usage:
    python src/web.py                          # localhost only
    python src/web.py --public                 # 0.0.0.0 + magic token
    python src/web.py --public --token MY_SEC  # custom token
    ssh -L 8001:127.0.0.1:8001 user@srv       # SSH tunnel (no token needed)
"""
import argparse
import hmac
import secrets
import sqlite3
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import Flask, jsonify, request, abort
from waitress import serve

# ── Magic token auth ──
_MAGIC_TOKEN = None  # set at startup if --public

# ── Locate database ──
SCRIPT_DIR = Path(__file__).resolve().parent
if os.getenv("VULN_DATA_DIR"):
    DATA_DIR = Path(os.getenv("VULN_DATA_DIR")).resolve()
elif SCRIPT_DIR.name == "src":
    DATA_DIR = SCRIPT_DIR.parent
else:
    DATA_DIR = SCRIPT_DIR
DB_FILE = DATA_DIR / "vuln_cache.db"
TOKEN_FILE = DATA_DIR / ".web_token"


def _save_token(token):
    """Persist token to file with restricted permissions."""
    TOKEN_FILE.write_text(token, encoding="utf-8")
    try:
        os.chmod(TOKEN_FILE, 0o600)
    except OSError:
        pass


def _load_or_create_token():
    """Load token from file, or generate and persist a new one."""
    if TOKEN_FILE.exists():
        token = TOKEN_FILE.read_text(encoding="utf-8").strip()
        if token:
            return token
    token = secrets.token_hex(8)
    _save_token(token)
    return token


def _token_match(candidate):
    """Constant-time token comparison to prevent timing attacks."""
    if not _MAGIC_TOKEN or not candidate:
        return False
    return hmac.compare_digest(candidate, _MAGIC_TOKEN)

app = Flask(__name__)

@app.before_request
def check_token():
    if _MAGIC_TOKEN is None:
        return  # localhost mode, no auth
    # Allow token via: /TOKEN/path, ?token=TOKEN, or cookie
    path_parts = request.path.strip("/").split("/", 1)
    if _token_match(path_parts[0]):
        # Strip token prefix, redirect to real path + set cookie
        tail = path_parts[1] if len(path_parts) > 1 else ""
        real_path = "/" + tail.lstrip("/")  # prevent //evil.com open redirect
        from flask import redirect, make_response
        resp = make_response(redirect(real_path))
        resp.set_cookie("_vmt", _MAGIC_TOKEN, httponly=True, samesite="Strict", max_age=86400*30)
        return resp
    if _token_match(request.args.get("token", "")):
        return
    if _token_match(request.cookies.get("_vmt", "")):
        return
    abort(403)

@app.after_request
def no_cache(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; "
        "script-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'none'; "
        "form-action 'self'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return response

SOURCE_COLORS = {
    "CISA_KEV": "#ef4444", "Fortinet": "#f97316", "PaloAlto": "#f59e0b",
    "Cisco": "#3b82f6", "MSRC": "#6366f1", "ZDI": "#8b5cf6",
    "watchTowr": "#ec4899", "Horizon3": "#14b8a6", "Rapid7": "#06b6d4",
    "Chaitin": "#10b981", "ThreatBook": "#22d3ee", "GitHub": "#a78bfa",
    "Sploitus_Citrix": "#fb923c", "Sploitus_Ivanti": "#fb923c", "Sploitus_F5": "#fb923c",
}
REASON_COLORS = {
    "RCE+asset/CVE": "#ef4444", "asset+CVE": "#f97316",
    "RCE+exploit": "#f43f5e", "excluded": "#4b5563", "no hit": "#374151",
}


def get_db():
    conn = sqlite3.connect(f"file:{DB_FILE}?mode=ro", uri=True, timeout=5)
    conn.row_factory = sqlite3.Row
    return conn


def _int_arg(name, default, lo, hi):
    try:
        return max(lo, min(hi, int(request.args.get(name, default))))
    except (ValueError, TypeError):
        return default


# ── API ──
@app.route("/api/vulns")
def api_vulns():
    conn = get_db()
    where, params = [], []
    q = request.args.get("q", "").strip()
    if q:
        where.append("(cve_id LIKE ? OR title LIKE ? OR summary LIKE ?)")
        params.extend([f"%{q}%"] * 3)
    source = request.args.get("source", "").strip()
    if source:
        where.append("source = ?"); params.append(source)
    reason = request.args.get("reason", "").strip()
    if reason:
        where.append("reason = ?"); params.append(reason)
    pushed = request.args.get("pushed", "").strip()
    if pushed == "1":
        where.append("pushed = 1")
    days = _int_arg("days", 0, 0, 3650)
    if days > 0:
        cutoff_date = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
        cutoff_ts = (datetime.now(timezone.utc) - timedelta(days=days)).timestamp()
        where.append("(cve_published >= ? OR (cve_published IS NULL AND created_at > ?))")
        params.extend([cutoff_date, cutoff_ts])

    sql = "SELECT cve_id,source,title,link,summary,reason,pushed,created_at,cve_published,severity,cvss,llm_verdict,llm_notes,tg_sent FROM vulns"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY COALESCE(cve_published, strftime('%Y-%m-%d', created_at, 'unixepoch')) DESC, created_at DESC LIMIT ?"
    limit = _int_arg("limit", 100, 1, 500)
    params.append(limit)

    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return jsonify([{
        "id": r["cve_id"], "source": r["source"], "title": r["title"],
        "url": r["link"], "summary": r["summary"], "reason": r["reason"],
        "pushed": bool(r["pushed"]),
        "tg_sent": bool(r["tg_sent"]) if r["tg_sent"] is not None else None,
        "cve_published": r["cve_published"],
        "severity": r["severity"],
        "cvss": r["cvss"],
        "llm_verdict": r["llm_verdict"],
        "llm_notes": r["llm_notes"],
        "date": r["cve_published"] or (datetime.fromtimestamp(r["created_at"], tz=timezone.utc).strftime("%Y-%m-%d") if r["created_at"] else None),
    } for r in rows])


@app.route("/api/stats")
def api_stats():
    conn = get_db()
    total = conn.execute("SELECT COUNT(*) FROM vulns").fetchone()[0]
    pushed = conn.execute("SELECT COUNT(*) FROM vulns WHERE pushed=1").fetchone()[0]
    sources = conn.execute("SELECT source, COUNT(*) as n FROM vulns WHERE source IS NOT NULL GROUP BY source ORDER BY n DESC").fetchall()
    reasons = conn.execute("SELECT reason, COUNT(*) as n FROM vulns WHERE pushed=1 GROUP BY reason ORDER BY n DESC").fetchall()
    conn.close()
    return jsonify({
        "total": total, "pushed": pushed,
        "sources": {r["source"]: r["n"] for r in sources},
        "reasons": {r["reason"]: r["n"] for r in reasons},
    })


@app.route("/api/sources")
def api_sources():
    conn = get_db()
    rows = conn.execute("SELECT DISTINCT source FROM vulns WHERE source IS NOT NULL ORDER BY source").fetchall()
    conn.close()
    return jsonify([r["source"] for r in rows])


# ── Frontend ──
@app.route("/")
def index():
    return DASHBOARD_HTML


DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>vuln-monitor</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><rect width='100' height='100' rx='20' fill='%23111013'/><path d='M29 8L29 54L42 54L42 92L71 42L54 42L71 8Z' fill='%23FFFF78'/></svg>">
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
:root {
  --cream: #FDF2D4; --sand: #E9DAAD; --peach: #FFB89F;
  --white: #FFFFFF; --card: #FFFFFF;
  --ink: #111013; --body: #2a2a2a; --muted: #6b6b6b;
  --yellow: #FFFF78; --orange: #FA673A; --red: #EB2010;
  --mint: #39BF97; --violet: #7C5CFC;
  --radius: 20px; --pill: 100px;
  --spring: cubic-bezier(.5, 2.5, .7, .7);
  --shadow-hard: 4px 4px 0 var(--ink);
  --shadow-soft: 2px 2px 0 var(--ink);
}
body {
  background: var(--cream);
  background-image:
    radial-gradient(ellipse 80% 60% at 15% 10%, rgba(250,103,58,.10), transparent),
    radial-gradient(ellipse 60% 50% at 85% 80%, rgba(255,255,120,.18), transparent);
  color: var(--body); font-family: 'Poppins', -apple-system, sans-serif;
  font-weight: 400; line-height: 1.5; min-height: 100vh;
}
a { color: var(--violet); text-decoration: none; }
a:hover { text-decoration: underline; }

/* ── Navbar (cream, slim: logo + search only) ── */
.nav { background: var(--cream); padding: 0 40px; position: sticky; top: 0; z-index: 20; border-bottom: 1px solid var(--ink); backdrop-filter: blur(6px); }
.nav-inner { max-width: 1260px; margin: 0 auto; display: grid; grid-template-columns: auto 1fr auto; align-items: center; height: 60px; gap: 18px; }
.nav-left { display: flex; align-items: center; gap: 18px; min-width: 0; }
.nav-tagline { font-size: 12px; color: var(--muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.nav-logo {
  font-family: 'Unbounded', sans-serif; font-weight: 800; font-size: 15px;
  color: var(--ink); background: var(--yellow); padding: 6px 16px;
  border-radius: var(--pill); letter-spacing: -.2px; white-space: nowrap;
  border: 1px solid var(--ink); box-shadow: var(--shadow-soft);
}
.nav-search { width: 100%; max-width: 560px; justify-self: center; position: relative; }
.nav-search input {
  width: 100%; padding: 8px 18px 8px 42px; background: var(--white);
  border: 1px solid var(--ink); border-radius: var(--pill);
  color: var(--ink); font-family: inherit; font-size: 14px; outline: none;
  transition: box-shadow .25s var(--spring);
}
.nav-search input:focus { box-shadow: var(--shadow-soft); }
.nav-search input::placeholder { color: var(--muted); }
.nav-search::before {
  content: "\1F50D"; position: absolute; left: 16px; top: 50%;
  transform: translateY(-50%); font-size: 14px; opacity: .5;
}
.nav-filters { display: flex; gap: 6px; align-items: center; }

/* ── Pill-row filters (each filter its own row) ── */
.filter-row { max-width: 1260px; margin: 10px auto 0; padding: 0 40px; display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
#timeRow { margin-top: 36px; }
.group-label { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; font-weight: 600; min-width: 64px; }

/* ── Hero / Stats ── */
.hero { max-width: 1260px; margin: 0 auto; padding: 48px 40px 8px; }
.hero-title {
  font-family: 'Unbounded', sans-serif; font-weight: 800;
  font-size: clamp(2rem, 4.5vw, 4.5rem);
  color: var(--ink); letter-spacing: -.02em; line-height: 1.1;
}
.hero-title span { color: var(--red); }
.hero-sub { color: var(--muted); font-size: 15px; margin-top: 10px; font-weight: 400; }

.meta-row { max-width: 1260px; margin: 18px auto 0; padding: 0 40px; display: flex; align-items: baseline; justify-content: center; gap: 18px 28px; flex-wrap: wrap; }
.stats { display: flex; gap: 28px; align-items: baseline; flex-wrap: wrap; }
.stat-item { display: inline-flex; align-items: baseline; gap: 8px; }
.stat-item + .stat-item { padding-left: 28px; border-left: 1px solid var(--ink); }
.stat-num { font-family: 'Unbounded', sans-serif; font-size: 28px; font-weight: 800; color: var(--ink); line-height: 1; letter-spacing: -.02em; }
.stat-label { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; font-weight: 600; white-space: nowrap; }
@media (max-width: 900px) { .nav-tagline { display: none; } }

/* ── Severity legend (sits below filter rows, above grid) ── */
.legend-row { max-width: 1260px; margin: 14px auto 0; padding: 0 40px; display: flex; gap: 14px; flex-wrap: wrap; align-items: center; }
.legend-inline { display: flex; align-items: center; gap: 14px; flex-wrap: wrap; }
.legend-inline-label { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; font-weight: 600; }
.legend-item { display: inline-flex; align-items: center; gap: 6px; font-size: 12px; font-weight: 600; color: var(--ink); }
.legend-pill { width: 8px; height: 14px; border-radius: 0 var(--pill) var(--pill) 0; border: 1px solid var(--ink); border-left: none; flex-shrink: 0; }

/* ── Pushed toggle (switch) ── */
.pushed-toggle { display: inline-flex; align-items: center; gap: 8px; font-size: 12px; font-weight: 600; color: var(--ink); cursor: pointer; user-select: none; }
.pushed-toggle input { position: absolute; opacity: 0; width: 0; height: 0; pointer-events: none; }
.pushed-toggle .switch {
  width: 36px; height: 20px; background: var(--white); border: 1px solid var(--ink);
  border-radius: var(--pill); position: relative; transition: background .25s var(--spring);
}
.pushed-toggle input:focus-visible + .switch { outline: 2px solid var(--ink); outline-offset: 3px; }
.pushed-toggle .switch::after {
  content: ''; position: absolute; top: 2px; left: 2px;
  width: 14px; height: 14px; background: var(--ink); border-radius: 50%;
  transition: transform .25s var(--spring);
}
.pushed-toggle input:checked + .switch { background: var(--mint); }
.pushed-toggle input:checked + .switch::after { transform: translateX(16px); }

/* ── Category pills ── */
.cat-row { max-width: 1260px; margin: 10px auto 0; padding: 0 40px; display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
.cat-pill {
  font-family: inherit; line-height: 1.5;
  padding: 6px 18px; border-radius: var(--pill); border: 1px solid var(--ink);
  background: var(--white); font-size: 12px; font-weight: 600; color: var(--ink);
  cursor: pointer; transition: all .25s var(--spring); user-select: none;
}
.cat-pill:hover { background: var(--yellow); transform: translateY(-2px); box-shadow: var(--shadow-soft); }
.cat-pill:focus-visible { outline: 2px solid var(--ink); outline-offset: 3px; }
.cat-pill.active { background: var(--ink); color: var(--yellow); }

/* ── Vuln cards ── */
.grid { max-width: 1260px; margin: 24px auto 0; padding: 0 40px 60px; display: grid; grid-template-columns: repeat(auto-fill, minmax(380px, 1fr)); gap: 20px; }
.vcard {
  background: var(--card); border: 1px solid var(--ink); border-radius: var(--radius);
  padding: 22px 24px 20px; display: flex; flex-direction: column; gap: 10px;
  transition: transform .25s var(--spring), box-shadow .25s var(--spring);
  position: relative;
}
.vcard::before {
  content: ''; position: absolute; top: 18px; left: -1px;
  width: 8px; height: 24px;
  border-radius: 0 var(--pill) var(--pill) 0;
  border: 1px solid var(--ink); border-left: none;
}
.vcard:hover { transform: translateY(-4px); box-shadow: var(--shadow-hard); }
.vcard-top { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; padding-left: 4px; }
.vcard-date { margin-left: auto; font-size: 12px; color: var(--muted); font-family: 'JetBrains Mono', monospace; font-weight: 500; }
.src-badge {
  display: inline-flex; align-items: center; padding: 3px 12px; border-radius: var(--pill);
  border: 1px solid var(--ink);
  font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: .4px;
}
.reason-badge {
  padding: 2px 10px; border-radius: var(--pill); border: 1px solid var(--ink);
  font-size: 10px; font-weight: 700;
  text-transform: uppercase; letter-spacing: .3px;
}
.sev-badge {
  padding: 2px 10px; border-radius: var(--pill); border: 1px solid var(--ink);
  font-size: 10px; font-weight: 700; letter-spacing: .3px;
  font-family: 'JetBrains Mono', monospace; color: var(--ink);
}
.sev-badge.sev-critical { background: #9B1C1C; color: var(--white); font-weight: 800; }
.sev-badge.sev-high { background: var(--orange); color: var(--ink); }
.sev-badge.sev-medium { background: var(--yellow); color: var(--ink); }
.sev-badge.sev-low { background: var(--mint); color: var(--ink); }
.pushed-dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
.pushed-dot.yes { background: var(--mint); box-shadow: 0 0 0 2px rgba(57,191,151,.25); }
.pushed-dot.no { background: var(--muted); }
.vcard-id {
  display: inline-block; align-self: flex-start;
  font-family: 'JetBrains Mono', monospace; font-size: 12px; font-weight: 600;
  color: var(--ink); background: var(--sand);
  padding: 3px 10px; border-radius: 8px; letter-spacing: .2px;
}
.vcard-title { font-size: 15px; font-weight: 700; color: var(--ink); line-height: 1.4; letter-spacing: -.005em; }
.vcard-summary { font-size: 13px; color: var(--muted); line-height: 1.55; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; }
.vcard-llm {
  display: inline-flex; align-items: baseline; gap: 6px; max-width: 100%;
  font-size: 12px; color: var(--body); line-height: 1.4;
  border-left: 2px solid var(--violet); padding-left: 8px; cursor: help;
}
.vcard-llm .llm-prefix {
  font-family: 'JetBrains Mono', monospace; font-size: 10px; font-weight: 700;
  color: var(--violet); letter-spacing: .5px;
}
.vcard-link { font-size: 12px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.vcard-link a { color: var(--ink); font-weight: 500; border-bottom: 1px solid var(--ink); }
.vcard-link a:hover { background: var(--yellow); text-decoration: none; }

/* severity stripe colors (CVSS-standard: CRITICAL=red, HIGH=orange) */
.sev-critical::before { background: var(--red); }
.sev-high::before { background: var(--orange); }
.sev-medium::before { background: var(--yellow); }
.sev-low::before { background: var(--mint); }

/* ── Load more ── */
.load-more-row { max-width: 1260px; margin: 8px auto 32px; padding: 0 40px; display: flex; justify-content: center; }
.load-more-btn {
  font-family: inherit; font-size: 13px; font-weight: 700; color: var(--ink);
  background: var(--white); border: 1px solid var(--ink); border-radius: var(--pill);
  padding: 10px 28px; cursor: pointer; text-transform: uppercase; letter-spacing: .5px;
  transition: all .25s var(--spring);
}
.load-more-btn:hover { background: var(--yellow); transform: translateY(-2px); box-shadow: var(--shadow-hard); }
.load-more-btn:disabled { opacity: .5; cursor: default; transform: none; box-shadow: none; background: var(--white); }
.load-more-row.hidden { display: none; }

/* ── Skip link (a11y) ── */
.skip-link {
  position: absolute; top: -50px; left: 8px;
  background: var(--ink); color: var(--yellow);
  padding: 8px 18px; border-radius: var(--pill);
  font-weight: 700; font-size: 13px; z-index: 100;
  text-decoration: none; transition: top .15s;
}
.skip-link:focus { top: 8px; outline: 2px solid var(--yellow); outline-offset: 2px; }

/* ── Empty / Loading ── */
.empty { grid-column: 1/-1; text-align: center; padding: 80px 20px; color: var(--muted); }
.loading { grid-column: 1/-1; text-align: center; padding: 60px; color: var(--muted); }
.spinner { display: inline-block; width: 28px; height: 28px; border: 3px solid var(--sand); border-top-color: var(--orange); border-radius: 50%; animation: spin .7s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }

/* ── Footer ── */
.footer { max-width: 1260px; margin: 0 auto; padding: 24px 40px; text-align: center; color: var(--muted); font-size: 12px; border-top: 1px solid var(--ink); }

@media (max-width: 860px) {
  .nav-inner { display: flex; flex-direction: column; align-items: stretch; height: auto; padding: 12px 0; gap: 10px; }
  .nav-search { max-width: none; width: 100%; }
  .nav-filters { align-self: flex-end; margin-left: 0; }
  .hero-title { font-size: 28px; }
  .grid { grid-template-columns: 1fr; }
  .hero, .meta-row, .filter-row, .legend-row, .grid, .footer { padding-left: 16px; padding-right: 16px; }
  .nav { padding: 0 16px; }
}
</style>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&family=Unbounded:wght@400;600;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
</head>
<body>
<a class="skip-link" href="#cardList">Skip to results</a>

<nav class="nav">
  <div class="nav-inner">
    <div class="nav-left">
      <div class="nav-logo">VULN-MONITOR</div>
      <div class="nav-tagline">Real-time 1day/0day RCE tracking across <span id="srcCount">—</span> sources</div>
    </div>
    <div class="nav-search">
      <input type="text" id="searchInput" placeholder="Search CVE, title, keyword..." aria-label="Search vulnerabilities by CVE, title, or keyword" autofocus>
    </div>
    <div class="nav-filters">
      <label class="pushed-toggle" title="Show only items pushed to Telegram">
        <input type="checkbox" id="pushedFilter" checked>
        <span class="switch"></span>
        <span>Telegram pushed</span>
      </label>
    </div>
  </div>
</nav>

<main id="main">
<div class="hero">
  <h1 class="hero-title">Vulnerability <span>Intelligence</span></h1>
</div>

<div class="meta-row">
  <div class="stats" id="statsBar"></div>
</div>

<div class="filter-row" id="timeRow" role="group" aria-label="Filter by time range">
  <button type="button" class="cat-pill" data-days="">All Time</button>
  <button type="button" class="cat-pill" data-days="1">24h</button>
  <button type="button" class="cat-pill active" data-days="7">7 days</button>
  <button type="button" class="cat-pill" data-days="30">30 days</button>
  <button type="button" class="cat-pill" data-days="60">60 days</button>
</div>

<div class="filter-row" id="reasonRow" role="group" aria-label="Filter by reason">
  <button type="button" class="cat-pill active" data-reason="">All</button>
  <button type="button" class="cat-pill" data-reason="RCE+asset/CVE">RCE+asset/CVE</button>
  <button type="button" class="cat-pill" data-reason="asset+CVE">asset+CVE</button>
  <button type="button" class="cat-pill" data-reason="RCE+exploit">RCE+exploit</button>
</div>

<div class="filter-row cat-row" id="catRow" role="group" aria-label="Filter by source"></div>

<div class="legend-row" aria-label="Severity legend">
  <span class="legend-item"><span class="legend-pill" style="background:var(--red)"></span>Critical / KEV</span>
  <span class="legend-item"><span class="legend-pill" style="background:var(--orange)"></span>RCE / Pre-auth</span>
  <span class="legend-item"><span class="legend-pill" style="background:var(--yellow)"></span>Overflow / Inject</span>
  <span class="legend-item"><span class="legend-pill" style="background:var(--mint)"></span>Other</span>
</div>

<div class="grid" id="cardList"><div class="loading"><div class="spinner"></div><p style="margin-top:12px">Loading...</p></div></div>
<div class="load-more-row hidden" id="loadMoreRow">
  <button class="load-more-btn" id="loadMoreBtn" type="button">Load more</button>
</div>
</main>
<div class="footer">vuln-monitor &middot; read-only &middot; bound to 127.0.0.1</div>

<script>
const SRC_STYLE = {
  CISA_KEV:  {bg:"#FFE0E0",fg:"#b91c1c"}, Fortinet: {bg:"#FFF3E0",fg:"#c2410c"},
  PaloAlto:  {bg:"#FFFDE7",fg:"#92400e"}, Cisco:    {bg:"#E0F2FE",fg:"#0369a1"},
  MSRC:      {bg:"#EDE9FE",fg:"#6d28d9"}, ZDI:      {bg:"#F3E8FF",fg:"#7c3aed"},
  watchTowr: {bg:"#FCE7F3",fg:"#be185d"}, Horizon3: {bg:"#D1FAE5",fg:"#047857"},
  Rapid7:    {bg:"#CFFAFE",fg:"#0e7490"}, Chaitin:  {bg:"#D1FAE5",fg:"#065f46"},
  ThreatBook:{bg:"#E0F2FE",fg:"#0c4a6e"}, GitHub:   {bg:"#EDE9FE",fg:"#5b21b6"},
  Sploitus_Citrix:{bg:"#FED7AA",fg:"#9a3412"}, Sploitus_Ivanti:{bg:"#FED7AA",fg:"#9a3412"},
  Sploitus_F5:{bg:"#FED7AA",fg:"#9a3412"},
};
const REASON_STYLE = {
  "RCE+asset/CVE": {bg:"#FEE2E2",fg:"#991b1b"},
  "asset+CVE":     {bg:"#FEF3C7",fg:"#92400e"},
  "RCE+exploit":   {bg:"#FCE7F3",fg:"#9d174d"},
};

let debounceTimer, activeCat = '', activeReason = '', activeDays = '7';
let currentLimit = 100;
const MAX_LIMIT = 500;
document.getElementById('loadMoreBtn').addEventListener('click', () => {
  currentLimit = Math.min(currentLimit + 100, MAX_LIMIT);
  loadVulns(true);
});
document.getElementById('searchInput').addEventListener('input', () => {
  clearTimeout(debounceTimer); debounceTimer = setTimeout(loadVulns, 300);
});
document.getElementById('pushedFilter').addEventListener('change', () => loadVulns());

function setActive(rowSelector, attr, val) {
  document.querySelectorAll(rowSelector + ' .cat-pill').forEach(p => p.classList.toggle('active', p.dataset[attr] === val));
}
function updateCatPills() { setActive('#catRow', 'src', activeCat); }

document.querySelectorAll('#timeRow .cat-pill').forEach(p => p.addEventListener('click', () => {
  activeDays = p.dataset.days; setActive('#timeRow', 'days', activeDays); loadVulns();
}));
document.querySelectorAll('#reasonRow .cat-pill').forEach(p => p.addEventListener('click', () => {
  activeReason = p.dataset.reason; setActive('#reasonRow', 'reason', activeReason); loadVulns();
}));

async function loadSources() {
  try {
    const sources = await (await fetch('/api/sources')).json();
    const row = document.getElementById('catRow');
    row.innerHTML = `<button type="button" class="cat-pill active" data-src="">All</button>` +
      sources.map(s => `<button type="button" class="cat-pill" data-src="${esc(s)}">${esc(s)}</button>`).join('');
    row.querySelectorAll('.cat-pill[data-src]').forEach(p => p.addEventListener('click', () => {
      activeCat = p.dataset.src;
      updateCatPills(); loadVulns();
    }));
  } catch(e) {}
}

async function loadStats() {
  try {
    const d = await (await fetch('/api/stats')).json();
    const srcCount = Object.keys(d.sources).length;
    document.getElementById('statsBar').innerHTML = `
      <span class="stat-item"><span class="stat-num">${d.total}</span><span class="stat-label">Total Vulns</span></span>
      <span class="stat-item"><span class="stat-num">${d.pushed}</span><span class="stat-label">Pushed</span></span>
      <span class="stat-item"><span class="stat-num">${srcCount}</span><span class="stat-label">Active Sources</span></span>
    `;
    document.getElementById('srcCount').textContent = srcCount;
  } catch(e) {}
}

function esc(s) {
  return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
                .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}
function safeUrl(u) {
  if (!u) return '#';
  try {
    const p = new URL(u, 'http://x/');
    if (p.protocol !== 'http:' && p.protocol !== 'https:') return '#';
    return u.replace(/&/g,'&amp;').replace(/"/g,'&quot;');
  } catch(e) { return '#'; }
}
function sevClass(v) {
  // Prefer real DB severity field; fall back to title-keyword heuristic for legacy rows
  if (v && v.severity) {
    const s = String(v.severity).toLowerCase();
    if (s === 'critical' || s === 'high' || s === 'medium' || s === 'low') return 'sev-' + s;
  }
  const t = ((v && v.title) || '').toLowerCase();
  if (t.includes('critical') || t.includes('[kev]')) return 'sev-critical';
  if (t.includes('rce') || t.includes('pre-auth') || t.includes('remote code')) return 'sev-high';
  if (t.includes('overflow') || t.includes('injection')) return 'sev-medium';
  return 'sev-low';
}
function sevBadge(v) {
  const sev = v.severity ? String(v.severity).toUpperCase() : '';
  const cvss = (typeof v.cvss === 'number') ? v.cvss.toFixed(1) : '';
  if (!sev && !cvss) return '';
  const cls = sevClass(v);
  const prefix = sev === 'CRITICAL' ? '▲&nbsp;' : '';  // ▲ warning triangle for CRITICAL
  return `<span class="sev-badge ${cls}">${prefix}${esc(sev || '?')}${cvss ? ` &middot; ${cvss}` : ''}</span>`;
}

async function loadVulns(append=false) {
  if (!append) currentLimit = 100;
  const params = new URLSearchParams();
  const q = document.getElementById('searchInput').value.trim();
  if (q) params.set('q', q);
  if (activeCat) params.set('source', activeCat);
  if (activeReason) params.set('reason', activeReason);
  if (activeDays) params.set('days', activeDays);
  if (document.getElementById('pushedFilter').checked) params.set('pushed', '1');
  params.set('limit', String(currentLimit));

  const container = document.getElementById('cardList');
  const moreRow = document.getElementById('loadMoreRow');
  const moreBtn = document.getElementById('loadMoreBtn');
  if (append) { moreBtn.disabled = true; moreBtn.textContent = 'Loading…'; }
  try {
    const vulns = await (await fetch('/api/vulns?' + params)).json();
    if (!vulns.length) {
      container.innerHTML = '<div class="empty"><p style="font-size:32px">&#128270;</p><p>No vulnerabilities found</p></div>';
      moreRow.classList.add('hidden');
      return;
    }
    moreRow.classList.toggle('hidden', vulns.length < currentLimit || currentLimit >= MAX_LIMIT);
    moreBtn.disabled = false;
    moreBtn.textContent = currentLimit >= MAX_LIMIT ? 'Reached display cap (500)' : 'Load more';
    container.innerHTML = vulns.map((v,i) => {
      const ss = SRC_STYLE[v.source] || {bg:'#F3F4F6',fg:'#374151'};
      const rs = REASON_STYLE[v.reason] || {bg:'#F3F4F6',fg:'#6B7280'};
      return `<div class="vcard ${sevClass(v)}" style="animation:fadeUp .4s ${i*.03}s both">
        <div class="vcard-top">
          <span class="src-badge" style="background:${ss.bg};color:${ss.fg}">${esc(v.source||'?')}</span>
          <span class="reason-badge" style="background:${rs.bg};color:${rs.fg}">${esc(v.reason||'-')}</span>
          ${sevBadge(v)}
          <span class="pushed-dot ${v.pushed?'yes':'no'}" title="${v.pushed?(v.tg_sent?'Sent to Telegram':'Selected for push'):'Filtered'}"></span>
          <span class="vcard-date">${esc(v.date||'-')}</span>
        </div>
        <div class="vcard-id">${esc(v.id||'N/A')}</div>
        <div class="vcard-title">${esc(v.title)}</div>
        ${v.summary?`<div class="vcard-summary">${esc(v.summary)}</div>`:''}
        ${v.llm_verdict?`<div class="vcard-llm" title="${esc(v.llm_notes||'')}"><span class="llm-prefix">AI</span> ${esc(v.llm_verdict)}</div>`:''}
        ${v.url?`<div class="vcard-link"><a href="${safeUrl(v.url)}" target="_blank" rel="noopener noreferrer">${esc(v.url)}</a></div>`:''}
      </div>`;
    }).join('');
  } catch(e) {
    container.innerHTML = '<div class="empty"><p>Failed to load</p></div>';
    moreRow.classList.add('hidden');
    moreBtn.disabled = false; moreBtn.textContent = 'Load more';
  }
}

loadSources(); loadStats(); loadVulns();
</script>
<style>
@keyframes fadeUp { from { opacity:0; transform:translateY(16px); } to { opacity:1; transform:translateY(0); } }
::selection { background: var(--peach); color: var(--ink); }
</style>
</body>
</html>"""


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="vuln-monitor web dashboard")
    p.add_argument("--port", type=int, default=8001)
    p.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1 only)")
    p.add_argument("--public", action="store_true",
                   help="Bind 0.0.0.0 and require magic token for access")
    p.add_argument("--token", default=None,
                   help="Manually set token (overrides saved token)")
    p.add_argument("--rotate-token", action="store_true",
                   help="Generate a new token (invalidates old one)")
    p.add_argument("--show-token", action="store_true",
                   help="Print current token and exit")
    args = p.parse_args()

    # Token management commands (work without --public)
    if args.show_token:
        if TOKEN_FILE.exists():
            print(TOKEN_FILE.read_text(encoding="utf-8").strip())
        else:
            print("(no token file, run with --public to generate)")
        raise SystemExit(0)

    if args.rotate_token:
        new_token = secrets.token_hex(8)
        _save_token(new_token)
        print(f"new token: {new_token}")
        print(f"saved to:  {TOKEN_FILE}")
        if not args.public:
            print("restart vuln-web.service to apply")
            raise SystemExit(0)

    if args.token:
        _save_token(args.token)
        if not args.public:
            print(f"token saved to {TOKEN_FILE}, restart vuln-web.service to apply")
            raise SystemExit(0)

    if not DB_FILE.exists():
        print(f"ERROR: database not found at {DB_FILE}")
        print("Run 'python src/vuln_monitor.py fetch' first to create it.")
        raise SystemExit(1)

    if args.public:
        args.host = "0.0.0.0"
        _MAGIC_TOKEN = args.token or (new_token if args.rotate_token else _load_or_create_token())
        print(f"vuln-monitor dashboard (PUBLIC mode)")
        print(f"  magic URL:  http://<your-ip>:{args.port}/{_MAGIC_TOKEN}/")
        print(f"  token:      {_MAGIC_TOKEN}")
        print(f"  token file: {TOKEN_FILE}")
        print(f"  database:   {DB_FILE}")
    else:
        print(f"vuln-monitor dashboard: http://{args.host}:{args.port}")
        print(f"database: {DB_FILE}")
        if args.host == "127.0.0.1":
            print(f"localhost only (use --public for external access, or SSH tunnel)")

    serve(app, host=args.host, port=args.port)
