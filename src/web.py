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
  --bg: #111013; --surface: #1c1b22; --surface2: #26252d;
  --border: #33323a; --text: #f0efe8; --muted: #8e8d96;
  --yellow: #FFFF78; --cream: #FDF2D4; --green: #39bf97;
  --red: #ff6b6b; --orange: #ffad5c;
}
body { background: var(--bg); color: var(--text); font-family: 'Poppins', -apple-system, sans-serif; line-height: 1.6; min-height: 100vh; }
a { color: var(--yellow); text-decoration: none; transition: opacity .2s; }
a:hover { opacity: .8; }

/* Header */
.header { background: #000; padding: 18px 32px; position: sticky; top: 0; z-index: 10; border-bottom: 2px solid var(--yellow); }
.header-inner { max-width: 1200px; margin: 0 auto; display: flex; align-items: center; gap: 24px; flex-wrap: wrap; }
.logo { font-family: 'Unbounded', sans-serif; font-size: 22px; font-weight: 700; color: #000; background: var(--yellow); padding: 4px 16px; border-radius: 24px; white-space: nowrap; }
.search { flex: 1; min-width: 200px; }
.search input { width: 100%; padding: 10px 18px; background: var(--surface); border: 2px solid var(--border); border-radius: 24px; color: var(--text); font-family: inherit; font-size: 14px; outline: none; transition: border .2s; }
.search input:focus { border-color: var(--yellow); }
.search input::placeholder { color: var(--muted); }
.filters { display: flex; gap: 8px; flex-wrap: wrap; }
.filters select { padding: 9px 14px; background: var(--surface); border: 2px solid var(--border); border-radius: 20px; color: var(--text); font-family: inherit; font-size: 13px; cursor: pointer; appearance: none; -webkit-appearance: none; padding-right: 28px; background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' fill='%238e8d96'%3E%3Cpath d='M2 4l4 4 4-4'/%3E%3C/svg%3E"); background-repeat: no-repeat; background-position: right 10px center; }
.filters select:focus { border-color: var(--yellow); outline: none; }
.btn { padding: 9px 20px; background: var(--yellow); color: #000; border: none; border-radius: 20px; font-family: inherit; font-size: 13px; font-weight: 600; cursor: pointer; transition: transform .1s, opacity .2s; }
.btn:hover { opacity: .9; transform: scale(1.02); }

/* Stats bar */
.stats-bar { max-width: 1200px; margin: 28px auto 20px; padding: 0 32px; display: flex; gap: 16px; flex-wrap: wrap; }
.stat { background: var(--surface); border: 2px solid var(--border); border-radius: 20px; padding: 16px 24px; min-width: 140px; transition: border-color .2s; }
.stat:hover { border-color: var(--yellow); }
.stat-value { font-family: 'Unbounded', sans-serif; font-size: 28px; font-weight: 700; color: var(--yellow); }
.stat-label { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; margin-top: 2px; }

/* Cards */
.cards { max-width: 1200px; margin: 0 auto; padding: 0 32px 48px; display: grid; grid-template-columns: 1fr; gap: 12px; }
.card { background: var(--surface); border: 2px solid var(--border); border-radius: 20px; padding: 20px 24px; transition: border-color .2s, transform .15s, box-shadow .2s; display: grid; grid-template-columns: auto 1fr auto; gap: 16px; align-items: start; }
.card:hover { border-color: var(--yellow); transform: translateY(-2px); box-shadow: 0 8px 24px rgba(255,255,120,.06); }
.card-left { display: flex; flex-direction: column; gap: 8px; min-width: 100px; }
.badge { display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: .5px; }
.badge-source { color: #000; }
.badge-reason { background: var(--surface2); border: 1px solid var(--border); color: var(--muted); font-size: 10px; }
.card-body { min-width: 0; }
.card-id { font-family: 'JetBrains Mono', monospace; font-size: 13px; color: var(--yellow); margin-bottom: 4px; letter-spacing: .3px; }
.card-title { font-size: 15px; font-weight: 600; margin-bottom: 6px; line-height: 1.4; }
.card-summary { font-size: 13px; color: var(--muted); line-height: 1.5; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.card-url { font-size: 12px; margin-top: 6px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.card-url a { color: var(--green); }
.card-right { text-align: right; white-space: nowrap; padding-top: 2px; }
.card-date { font-size: 12px; color: var(--muted); font-family: 'JetBrains Mono', monospace; }
.card-pushed { font-size: 11px; margin-top: 4px; font-weight: 600; }
.pushed-yes { color: var(--green); }
.pushed-no { color: var(--muted); }

/* Empty / Loading */
.empty { text-align: center; padding: 80px 20px; color: var(--muted); }
.empty-icon { font-size: 48px; margin-bottom: 12px; }
.loading { text-align: center; padding: 60px; color: var(--muted); }
.spinner { display: inline-block; width: 28px; height: 28px; border: 3px solid var(--border); border-top-color: var(--yellow); border-radius: 50%; animation: spin .7s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }

/* Footer */
.footer { text-align: center; padding: 24px; color: var(--muted); font-size: 12px; border-top: 1px solid var(--border); letter-spacing: .5px; }

@media (max-width: 768px) {
  .header-inner { gap: 12px; }
  .card { grid-template-columns: 1fr; gap: 10px; }
  .card-left { flex-direction: row; flex-wrap: wrap; }
  .card-right { text-align: left; }
  .stats-bar, .cards { padding: 0 16px; }
}
</style>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&family=Unbounded:wght@400;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
</head>
<body>

<div class="header">
  <div class="header-inner">
    <div class="logo">VULN-MONITOR</div>
    <div class="search">
      <input type="text" id="searchInput" placeholder="Search CVE, title, keyword..." autofocus>
    </div>
    <div class="filters">
      <select id="sourceFilter"><option value="">All Sources</option></select>
      <select id="reasonFilter">
        <option value="">All Reasons</option>
        <option value="RCE+asset/CVE">RCE+asset/CVE</option>
        <option value="asset+CVE">asset+CVE</option>
        <option value="RCE+exploit">RCE+exploit</option>
      </select>
      <select id="daysFilter">
        <option value="">All Time</option>
        <option value="1">Last 24h</option>
        <option value="7" selected>Last 7 days</option>
        <option value="30">Last 30 days</option>
        <option value="60">Last 60 days</option>
      </select>
      <select id="pushedFilter">
        <option value="">All</option>
        <option value="1">Pushed only</option>
      </select>
      <button class="btn" onclick="loadVulns()">Refresh</button>
    </div>
  </div>
</div>

<div class="stats-bar" id="statsBar"></div>
<div class="cards" id="cardList"><div class="loading"><div class="spinner"></div><p style="margin-top:12px">Loading...</p></div></div>
<div class="footer">vuln-monitor &middot; read-only &middot; 127.0.0.1</div>

<script>
const SOURCE_COLORS = {
  "CISA_KEV":"#ff6b6b","Fortinet":"#ffad5c","PaloAlto":"#FFFF78","Cisco":"#7dd3fc",
  "MSRC":"#c4b5fd","ZDI":"#d8b4fe","watchTowr":"#f9a8d4","Horizon3":"#5eead4",
  "Rapid7":"#67e8f9","Chaitin":"#6ee7b7","ThreatBook":"#a5f3fc","GitHub":"#c4b5fd",
  "Sploitus_Citrix":"#fdba74","Sploitus_Ivanti":"#fdba74","Sploitus_F5":"#fdba74",
};
const REASON_STYLES = {
  "RCE+asset/CVE":"background:var(--red);color:#fff",
  "asset+CVE":"background:var(--orange);color:#000",
  "RCE+exploit":"background:#f472b6;color:#000",
};

let debounceTimer;
document.getElementById('searchInput').addEventListener('input', () => {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(loadVulns, 300);
});
['sourceFilter','reasonFilter','daysFilter','pushedFilter'].forEach(id =>
  document.getElementById(id).addEventListener('change', loadVulns));

async function loadSources() {
  try {
    const sources = await (await fetch('/api/sources')).json();
    const sel = document.getElementById('sourceFilter');
    sources.forEach(s => { const o = document.createElement('option'); o.value = s; o.textContent = s; sel.appendChild(o); });
  } catch(e) {}
}

async function loadStats() {
  try {
    const d = await (await fetch('/api/stats')).json();
    document.getElementById('statsBar').innerHTML = `
      <div class="stat"><div class="stat-value">${d.total}</div><div class="stat-label">Total Vulns</div></div>
      <div class="stat"><div class="stat-value">${d.pushed}</div><div class="stat-label">Pushed</div></div>
      <div class="stat"><div class="stat-value">${Object.keys(d.sources).length}</div><div class="stat-label">Sources</div></div>
    `;
  } catch(e) {}
}

function esc(s) { return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

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
    if (!vulns.length) {
      container.innerHTML = '<div class="empty"><div class="empty-icon">&#128270;</div><p>No vulnerabilities found</p></div>';
      return;
    }
    container.innerHTML = vulns.map(v => {
      const srcColor = SOURCE_COLORS[v.source] || '#a1a1aa';
      const reasonStyle = REASON_STYLES[v.reason] || '';
      return `<div class="card">
        <div class="card-left">
          <span class="badge badge-source" style="background:${srcColor}">${esc(v.source||'?')}</span>
          <span class="badge badge-reason" ${reasonStyle?`style="${reasonStyle}"`:``}>${esc(v.reason||'-')}</span>
        </div>
        <div class="card-body">
          <div class="card-id">${esc(v.id||'N/A')}</div>
          <div class="card-title">${esc(v.title)}</div>
          ${v.summary?`<div class="card-summary">${esc(v.summary)}</div>`:''}
          ${v.url?`<div class="card-url"><a href="${v.url}" target="_blank" rel="noopener">${esc(v.url)}</a></div>`:''}
        </div>
        <div class="card-right">
          <div class="card-date">${v.date||'-'}</div>
          <div class="card-pushed ${v.pushed?'pushed-yes':'pushed-no'}">${v.pushed?'PUSHED':'filtered'}</div>
        </div>
      </div>`;
    }).join('');
  } catch(e) {
    container.innerHTML = '<div class="empty"><div class="empty-icon">&#9888;</div><p>Failed to load</p></div>';
  }
}

loadSources();
loadStats();
loadVulns();
</script>
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
