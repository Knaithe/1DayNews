#!/usr/bin/env python3
"""
vuln-monitor web dashboard. Read-only SQLite viewer, binds 127.0.0.1 only.

Usage:
    python src/web.py                     # http://127.0.0.1:8001
    python src/web.py --port 9000         # custom port
    ssh -L 8001:127.0.0.1:8001 user@srv  # remote access via SSH tunnel
"""
import argparse
import sqlite3
import os
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, request

# ── Locate database ──
SCRIPT_DIR = Path(__file__).resolve().parent
if os.getenv("VULN_DATA_DIR"):
    DATA_DIR = Path(os.getenv("VULN_DATA_DIR")).resolve()
elif SCRIPT_DIR.name == "src":
    DATA_DIR = SCRIPT_DIR.parent
else:
    DATA_DIR = SCRIPT_DIR
DB_FILE = DATA_DIR / "vuln_cache.db"

app = Flask(__name__)

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
    days = request.args.get("days", "").strip()
    if days and days.isdigit():
        from datetime import timedelta
        cutoff = (datetime.now(timezone.utc) - timedelta(days=int(days))).timestamp()
        where.append("created_at > ?"); params.append(cutoff)

    sql = "SELECT cve_id,source,title,link,summary,reason,pushed,created_at FROM vulns"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY created_at DESC LIMIT ?"
    limit = min(int(request.args.get("limit", 100)), 500)
    params.append(limit)

    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return jsonify([{
        "id": r["cve_id"], "source": r["source"], "title": r["title"],
        "url": r["link"], "summary": r["summary"], "reason": r["reason"],
        "pushed": bool(r["pushed"]),
        "date": datetime.fromtimestamp(r["created_at"], tz=timezone.utc).strftime("%Y-%m-%d %H:%M") if r["created_at"] else None,
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
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
:root {
  --cream: #FBF0DF; --peach: #F5D9B0; --sand: #EDE3D3;
  --white: #FFFFFF; --card: #FFFEFA;
  --ink: #111013; --body: #3a3636; --muted: #9a918a;
  --yellow: #FFFF78; --coral: #FF6B6B; --mint: #39BF97;
  --orange: #F4845F; --violet: #7C5CFC; --sky: #38BDF8;
  --radius: 22px;
}
body {
  background: var(--cream);
  background-image:
    radial-gradient(ellipse 80% 60% at 15% 10%, rgba(255,180,130,.22), transparent),
    radial-gradient(ellipse 60% 50% at 85% 80%, rgba(255,255,120,.15), transparent);
  color: var(--body); font-family: 'DM Sans', -apple-system, sans-serif;
  line-height: 1.6; min-height: 100vh;
}
a { color: var(--violet); text-decoration: none; }
a:hover { text-decoration: underline; }

/* ── Navbar ── */
.nav { background: var(--ink); padding: 0 40px; position: sticky; top: 0; z-index: 20; }
.nav-inner { max-width: 1260px; margin: 0 auto; display: flex; align-items: center; height: 64px; gap: 28px; }
.nav-logo {
  font-family: 'Syne', sans-serif; font-weight: 800; font-size: 18px;
  color: var(--ink); background: var(--yellow); padding: 5px 18px;
  border-radius: 40px; letter-spacing: -.3px; white-space: nowrap;
  box-shadow: 0 0 0 2px var(--ink), 0 0 0 4px var(--yellow);
}
.nav-search { flex: 1; position: relative; }
.nav-search input {
  width: 100%; padding: 9px 18px 9px 42px; background: rgba(255,255,255,.08);
  border: 1.5px solid rgba(255,255,255,.12); border-radius: 40px;
  color: #fff; font-family: inherit; font-size: 14px; outline: none; transition: all .25s;
}
.nav-search input:focus { background: rgba(255,255,255,.14); border-color: var(--yellow); }
.nav-search input::placeholder { color: rgba(255,255,255,.35); }
.nav-search::before {
  content: "\1F50D"; position: absolute; left: 16px; top: 50%;
  transform: translateY(-50%); font-size: 14px; opacity: .4;
}
.nav-filters { display: flex; gap: 6px; align-items: center; }
.pill-select {
  padding: 7px 28px 7px 12px; background: rgba(255,255,255,.07);
  border: 1.5px solid rgba(255,255,255,.12); border-radius: 40px;
  color: rgba(255,255,255,.75); font-family: inherit; font-size: 12px;
  cursor: pointer; appearance: none; -webkit-appearance: none;
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='10' fill='rgba(255,255,255,.4)'%3E%3Cpath d='M1 3l4 4 4-4'/%3E%3C/svg%3E");
  background-repeat: no-repeat; background-position: right 10px center;
}
.pill-select:focus { border-color: var(--yellow); outline: none; }
.btn-refresh {
  padding: 7px 18px; background: var(--yellow); color: var(--ink);
  border: none; border-radius: 40px; font-family: inherit; font-size: 12px;
  font-weight: 700; cursor: pointer; transition: transform .1s;
}
.btn-refresh:hover { transform: scale(1.05); }

/* ── Hero / Stats ── */
.hero { max-width: 1260px; margin: 0 auto; padding: 40px 40px 8px; }
.hero-title {
  font-family: 'Syne', sans-serif; font-weight: 800; font-size: 42px;
  color: var(--ink); letter-spacing: -1.5px; line-height: 1.1;
}
.hero-title span { color: var(--coral); }
.hero-sub { color: var(--muted); font-size: 15px; margin-top: 6px; }

.stats { max-width: 1260px; margin: 24px auto 0; padding: 0 40px; display: flex; gap: 14px; flex-wrap: wrap; }
.stat-card {
  background: var(--white); border: 2px solid var(--sand);
  border-radius: var(--radius); padding: 18px 26px; min-width: 150px;
  transition: transform .2s, border-color .2s, box-shadow .2s;
}
.stat-card:hover { transform: translateY(-3px); border-color: var(--peach); box-shadow: 0 8px 20px rgba(0,0,0,.06); }
.stat-num { font-family: 'Syne', sans-serif; font-size: 34px; font-weight: 800; color: var(--ink); line-height: 1; }
.stat-label { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 1.2px; margin-top: 4px; font-weight: 600; }

/* ── Category pills ── */
.cat-row { max-width: 1260px; margin: 28px auto 0; padding: 0 40px; display: flex; gap: 8px; flex-wrap: wrap; }
.cat-pill {
  padding: 6px 18px; border-radius: 40px; border: 2px solid var(--sand);
  background: var(--white); font-size: 12px; font-weight: 600; color: var(--body);
  cursor: pointer; transition: all .2s; user-select: none;
}
.cat-pill:hover, .cat-pill.active { background: var(--ink); color: var(--yellow); border-color: var(--ink); }

/* ── Vuln cards ── */
.grid { max-width: 1260px; margin: 20px auto 0; padding: 0 40px 60px; display: grid; grid-template-columns: repeat(auto-fill, minmax(380px, 1fr)); gap: 16px; }
.vcard {
  background: var(--card); border: 2px solid var(--sand); border-radius: var(--radius);
  padding: 22px 24px; display: flex; flex-direction: column; gap: 10px;
  transition: transform .2s, border-color .2s, box-shadow .2s;
  position: relative; overflow: hidden;
}
.vcard::before {
  content: ''; position: absolute; top: 0; left: 0; width: 5px; height: 100%;
  border-radius: var(--radius) 0 0 var(--radius);
}
.vcard:hover { transform: translateY(-4px); border-color: var(--peach); box-shadow: 0 12px 32px rgba(0,0,0,.07); }
.vcard-top { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.vcard-date { margin-left: auto; font-size: 12px; color: var(--muted); font-family: 'JetBrains Mono', monospace; font-weight: 500; }
.src-badge {
  display: inline-flex; align-items: center; padding: 3px 12px; border-radius: 40px;
  font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: .4px;
}
.reason-badge {
  padding: 2px 10px; border-radius: 40px; font-size: 10px; font-weight: 700;
  text-transform: uppercase; letter-spacing: .3px;
}
.pushed-dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
.pushed-dot.yes { background: var(--mint); box-shadow: 0 0 6px var(--mint); }
.pushed-dot.no { background: var(--muted); }
.vcard-id {
  font-family: 'JetBrains Mono', monospace; font-size: 13px; font-weight: 600;
  color: var(--violet); letter-spacing: .2px;
}
.vcard-title { font-size: 15px; font-weight: 700; color: var(--ink); line-height: 1.45; }
.vcard-summary { font-size: 13px; color: var(--muted); line-height: 1.5; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; }
.vcard-link { font-size: 12px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.vcard-link a { color: var(--mint); font-weight: 500; }

/* severity stripe colors */
.sev-critical::before { background: var(--coral); }
.sev-high::before { background: var(--orange); }
.sev-medium::before { background: var(--yellow); }
.sev-low::before { background: var(--sand); }

/* ── Empty / Loading ── */
.empty { grid-column: 1/-1; text-align: center; padding: 80px 20px; color: var(--muted); }
.loading { grid-column: 1/-1; text-align: center; padding: 60px; color: var(--muted); }
.spinner { display: inline-block; width: 28px; height: 28px; border: 3px solid var(--sand); border-top-color: var(--coral); border-radius: 50%; animation: spin .7s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }

/* ── Footer ── */
.footer { max-width: 1260px; margin: 0 auto; padding: 24px 40px; text-align: center; color: var(--muted); font-size: 12px; border-top: 2px solid var(--sand); }

@media (max-width: 860px) {
  .nav-inner { flex-wrap: wrap; height: auto; padding: 12px 0; gap: 10px; }
  .hero-title { font-size: 28px; }
  .grid { grid-template-columns: 1fr; }
  .hero, .stats, .cat-row, .grid, .footer { padding-left: 16px; padding-right: 16px; }
  .nav { padding: 0 16px; }
}
</style>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Syne:wght@600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
</head>
<body>

<nav class="nav">
  <div class="nav-inner">
    <div class="nav-logo">VULN-MONITOR</div>
    <div class="nav-search">
      <input type="text" id="searchInput" placeholder="Search CVE, title, keyword..." autofocus>
    </div>
    <div class="nav-filters">
      <select class="pill-select" id="sourceFilter"><option value="">All Sources</option></select>
      <select class="pill-select" id="reasonFilter">
        <option value="">Reason</option>
        <option value="RCE+asset/CVE">RCE+asset/CVE</option>
        <option value="asset+CVE">asset+CVE</option>
        <option value="RCE+exploit">RCE+exploit</option>
      </select>
      <select class="pill-select" id="daysFilter">
        <option value="">All Time</option>
        <option value="1">24h</option>
        <option value="7" selected>7 days</option>
        <option value="30">30 days</option>
        <option value="60">60 days</option>
      </select>
      <select class="pill-select" id="pushedFilter">
        <option value="">All</option>
        <option value="1">Pushed</option>
      </select>
      <button class="btn-refresh" onclick="loadVulns()">Refresh</button>
    </div>
  </div>
</nav>

<div class="hero">
  <div class="hero-title">Vulnerability <span>Intelligence</span></div>
  <div class="hero-sub">Real-time 1day/0day RCE tracking across 17 sources</div>
</div>

<div class="stats" id="statsBar"></div>
<div class="cat-row" id="catRow"></div>
<div class="grid" id="cardList"><div class="loading"><div class="spinner"></div><p style="margin-top:12px">Loading...</p></div></div>
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

let debounceTimer, activeCat = '';
document.getElementById('searchInput').addEventListener('input', () => {
  clearTimeout(debounceTimer); debounceTimer = setTimeout(loadVulns, 300);
});
['sourceFilter','reasonFilter','daysFilter','pushedFilter'].forEach(id =>
  document.getElementById(id).addEventListener('change', () => { activeCat=''; updateCatPills(); loadVulns(); }));

function updateCatPills() {
  document.querySelectorAll('.cat-pill').forEach(p => p.classList.toggle('active', p.dataset.src === activeCat));
}

async function loadSources() {
  try {
    const sources = await (await fetch('/api/sources')).json();
    const sel = document.getElementById('sourceFilter');
    sources.forEach(s => { const o = document.createElement('option'); o.value=s; o.textContent=s; sel.appendChild(o); });
    const row = document.getElementById('catRow');
    row.innerHTML = `<div class="cat-pill active" data-src="">All</div>` +
      sources.map(s => `<div class="cat-pill" data-src="${s}">${s}</div>`).join('');
    row.querySelectorAll('.cat-pill').forEach(p => p.addEventListener('click', () => {
      activeCat = p.dataset.src;
      document.getElementById('sourceFilter').value = activeCat;
      updateCatPills(); loadVulns();
    }));
  } catch(e) {}
}

async function loadStats() {
  try {
    const d = await (await fetch('/api/stats')).json();
    document.getElementById('statsBar').innerHTML = `
      <div class="stat-card"><div class="stat-num">${d.total}</div><div class="stat-label">Total Vulns</div></div>
      <div class="stat-card"><div class="stat-num">${d.pushed}</div><div class="stat-label">Pushed</div></div>
      <div class="stat-card"><div class="stat-num">${Object.keys(d.sources).length}</div><div class="stat-label">Active Sources</div></div>
    `;
  } catch(e) {}
}

function esc(s) { return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function sevClass(title) {
  const t = (title||'').toLowerCase();
  if (t.includes('critical') || t.includes('[kev]')) return 'sev-critical';
  if (t.includes('rce') || t.includes('pre-auth') || t.includes('remote code')) return 'sev-high';
  if (t.includes('overflow') || t.includes('injection')) return 'sev-medium';
  return 'sev-low';
}

async function loadVulns() {
  const params = new URLSearchParams();
  const q = document.getElementById('searchInput').value.trim();
  if (q) params.set('q', q);
  const source = document.getElementById('sourceFilter').value;
  if (source) params.set('source', source);
  const reason = document.getElementById('reasonFilter').value;
  if (reason) params.set('reason', reason);
  const days = document.getElementById('daysFilter').value;
  if (days) params.set('days', days);
  const pushed = document.getElementById('pushedFilter').value;
  if (pushed) params.set('pushed', pushed);

  const container = document.getElementById('cardList');
  try {
    const vulns = await (await fetch('/api/vulns?' + params)).json();
    if (!vulns.length) { container.innerHTML = '<div class="empty"><p style="font-size:32px">&#128270;</p><p>No vulnerabilities found</p></div>'; return; }
    container.innerHTML = vulns.map((v,i) => {
      const ss = SRC_STYLE[v.source] || {bg:'#F3F4F6',fg:'#374151'};
      const rs = REASON_STYLE[v.reason] || {bg:'#F3F4F6',fg:'#6B7280'};
      return `<div class="vcard ${sevClass(v.title)}" style="animation:fadeUp .4s ${i*.03}s both">
        <div class="vcard-top">
          <span class="src-badge" style="background:${ss.bg};color:${ss.fg}">${esc(v.source||'?')}</span>
          <span class="reason-badge" style="background:${rs.bg};color:${rs.fg}">${esc(v.reason||'-')}</span>
          <span class="pushed-dot ${v.pushed?'yes':'no'}" title="${v.pushed?'Pushed to Telegram':'Filtered'}"></span>
          <span class="vcard-date">${v.date||'-'}</span>
        </div>
        <div class="vcard-id">${esc(v.id||'N/A')}</div>
        <div class="vcard-title">${esc(v.title)}</div>
        ${v.summary?`<div class="vcard-summary">${esc(v.summary)}</div>`:''}
        ${v.url?`<div class="vcard-link"><a href="${v.url}" target="_blank" rel="noopener">${esc(v.url)}</a></div>`:''}
      </div>`;
    }).join('');
  } catch(e) { container.innerHTML = '<div class="empty"><p>Failed to load</p></div>'; }
}

loadSources(); loadStats(); loadVulns();
</script>
<style>@keyframes fadeUp { from { opacity:0; transform:translateY(16px); } to { opacity:1; transform:translateY(0); } }</style>
</body>
</html>"""


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="vuln-monitor web dashboard")
    p.add_argument("--port", type=int, default=8001)
    p.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1 only)")
    args = p.parse_args()

    if not DB_FILE.exists():
        print(f"ERROR: database not found at {DB_FILE}")
        print("Run 'python src/vuln_monitor.py fetch' first to create it.")
        raise SystemExit(1)

    print(f"vuln-monitor dashboard: http://{args.host}:{args.port}")
    print(f"database: {DB_FILE}")
    print(f"WARNING: only accessible from localhost (use SSH tunnel for remote access)")
    app.run(host=args.host, port=args.port, debug=False)
