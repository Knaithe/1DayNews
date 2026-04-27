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
  --bg: #0a0a0f; --surface: #13131a; --surface2: #1a1a24;
  --border: #2a2a3a; --text: #e4e4e7; --muted: #71717a;
  --accent: #39bf97; --danger: #ef4444; --warn: #f59e0b;
}
body { background: var(--bg); color: var(--text); font-family: 'Inter', -apple-system, sans-serif; line-height: 1.5; min-height: 100vh; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }

/* Header */
.header { background: var(--surface); border-bottom: 1px solid var(--border); padding: 16px 24px; position: sticky; top: 0; z-index: 10; }
.header-inner { max-width: 1400px; margin: 0 auto; display: flex; align-items: center; gap: 20px; flex-wrap: wrap; }
.logo { font-size: 20px; font-weight: 700; letter-spacing: -0.5px; white-space: nowrap; }
.logo span { color: var(--accent); }
.search { flex: 1; min-width: 200px; }
.search input { width: 100%; padding: 8px 14px; background: var(--bg); border: 1px solid var(--border); border-radius: 8px; color: var(--text); font-size: 14px; outline: none; transition: border 0.2s; }
.search input:focus { border-color: var(--accent); }
.filters { display: flex; gap: 8px; flex-wrap: wrap; }
.filters select, .filters button { padding: 7px 12px; background: var(--bg); border: 1px solid var(--border); border-radius: 8px; color: var(--text); font-size: 13px; cursor: pointer; }
.filters button { background: var(--accent); color: #000; border: none; font-weight: 600; }
.filters button:hover { opacity: 0.9; }

/* Stats bar */
.stats-bar { max-width: 1400px; margin: 16px auto; padding: 0 24px; display: flex; gap: 16px; flex-wrap: wrap; }
.stat { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 12px 18px; min-width: 120px; }
.stat-value { font-size: 24px; font-weight: 700; color: var(--accent); }
.stat-label { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; }

/* Cards */
.cards { max-width: 1400px; margin: 8px auto; padding: 0 24px 40px; display: grid; grid-template-columns: 1fr; gap: 8px; }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 16px 20px; transition: border-color 0.2s, transform 0.1s; display: grid; grid-template-columns: auto 1fr auto; gap: 12px; align-items: start; }
.card:hover { border-color: var(--accent); transform: translateY(-1px); }
.card-left { display: flex; flex-direction: column; gap: 6px; min-width: 90px; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.3px; }
.badge-source { color: #fff; }
.badge-reason { background: var(--surface2); color: var(--muted); font-size: 10px; }
.card-body { min-width: 0; }
.card-id { font-family: 'JetBrains Mono', monospace; font-size: 13px; color: var(--accent); margin-bottom: 2px; }
.card-title { font-size: 15px; font-weight: 500; margin-bottom: 4px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.card-summary { font-size: 13px; color: var(--muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.card-url { font-size: 12px; color: var(--muted); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.card-url a { color: #5eead4; }
.card-right { text-align: right; white-space: nowrap; }
.card-date { font-size: 12px; color: var(--muted); }
.card-pushed { font-size: 11px; }
.pushed-yes { color: var(--accent); }
.pushed-no { color: var(--muted); }

/* Empty state */
.empty { text-align: center; padding: 80px 20px; color: var(--muted); }
.empty-icon { font-size: 48px; margin-bottom: 12px; }

/* Loading */
.loading { text-align: center; padding: 40px; color: var(--muted); }
.spinner { display: inline-block; width: 24px; height: 24px; border: 3px solid var(--border); border-top-color: var(--accent); border-radius: 50%; animation: spin 0.8s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }

/* Footer */
.footer { text-align: center; padding: 20px; color: var(--muted); font-size: 12px; border-top: 1px solid var(--border); }

@media (max-width: 768px) {
  .card { grid-template-columns: 1fr; }
  .card-left { flex-direction: row; }
  .card-right { text-align: left; }
}
</style>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
</head>
<body>

<div class="header">
  <div class="header-inner">
    <div class="logo">vuln<span>-monitor</span></div>
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
      <button onclick="loadVulns()">Refresh</button>
    </div>
  </div>
</div>

<div class="stats-bar" id="statsBar"></div>
<div class="cards" id="cardList"><div class="loading"><div class="spinner"></div><p>Loading...</p></div></div>
<div class="footer">vuln-monitor dashboard &middot; read-only &middot; bound to 127.0.0.1</div>

<script>
const SOURCE_COLORS = """ + str(SOURCE_COLORS).replace("'", '"') + """;
const REASON_COLORS = """ + str(REASON_COLORS).replace("'", '"') + """;

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
      <div class="stat"><div class="stat-value">${d.total}</div><div class="stat-label">Total</div></div>
      <div class="stat"><div class="stat-value">${d.pushed}</div><div class="stat-label">Pushed</div></div>
      <div class="stat"><div class="stat-value">${Object.keys(d.sources).length}</div><div class="stat-label">Sources</div></div>
    `;
  } catch(e) {}
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
    if (!vulns.length) {
      container.innerHTML = '<div class="empty"><div class="empty-icon">&#128270;</div><p>No vulnerabilities found</p></div>';
      return;
    }
    container.innerHTML = vulns.map(v => {
      const srcColor = SOURCE_COLORS[v.source] || '#6b7280';
      const reasonColor = REASON_COLORS[v.reason] || '#374151';
      const escapedTitle = (v.title || '').replace(/</g, '&lt;').replace(/>/g, '&gt;');
      const escapedSummary = (v.summary || '').replace(/</g, '&lt;').replace(/>/g, '&gt;');
      return `<div class="card">
        <div class="card-left">
          <span class="badge badge-source" style="background:${srcColor}">${v.source || '?'}</span>
          <span class="badge badge-reason" style="background:${reasonColor};color:#fff">${v.reason || '-'}</span>
        </div>
        <div class="card-body">
          <div class="card-id">${v.id || 'N/A'}</div>
          <div class="card-title">${escapedTitle}</div>
          ${v.summary ? `<div class="card-summary">${escapedSummary}</div>` : ''}
          ${v.url ? `<div class="card-url"><a href="${v.url}" target="_blank" rel="noopener">${v.url}</a></div>` : ''}
        </div>
        <div class="card-right">
          <div class="card-date">${v.date || '-'}</div>
          <div class="card-pushed ${v.pushed ? 'pushed-yes' : 'pushed-no'}">${v.pushed ? 'PUSHED' : 'filtered'}</div>
        </div>
      </div>`;
    }).join('');
  } catch(e) {
    container.innerHTML = '<div class="empty"><div class="empty-icon">&#9888;</div><p>Failed to load data</p></div>';
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
