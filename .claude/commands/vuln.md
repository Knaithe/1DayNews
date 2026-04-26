You are operating vuln-monitor, a 0day/1day RCE vulnerability intelligence system.

## Locate the script

```bash
SCRIPT="/opt/vuln-monitor/src/vuln_monitor.py"
# fallback: find the script relative to this repo
[ -f "$SCRIPT" ] || SCRIPT="$(git rev-parse --show-toplevel 2>/dev/null)/src/vuln_monitor.py"
```

Use the venv Python when on the server:
```bash
PY="/opt/vuln-monitor/venv/bin/python"
[ -x "$PY" ] || PY="python3"
```

## Subcommands

### fetch — Pull all sources, dedup, store, push new items to Telegram
```bash
$PY $SCRIPT fetch
```
Run this periodically (every 5 minutes) to keep the database current.

### query — Search stored vulnerabilities
```bash
$PY $SCRIPT query [flags]
```

Default output is a compact table with URL. Add `--full` for detailed multi-line view, `--json` for machine-readable output.

Filter flags (also work with `brief`):
| Flag | Example | Description |
|---|---|---|
| `--cve` | `--cve CVE-2026-1340` | Filter by CVE or advisory ID (substring) |
| `--source` | `--source CISA_KEV` | Filter by source name |
| `--keyword` / `-k` | `-k "FortiWeb RCE"` | Search in title and summary |
| `--days` | `--days 7` | Only last N days |
| `--pushed` | `--pushed` | Only items pushed to Telegram |
| `--reason` | `--reason "RCE+asset"` | Filter by match reason |
| `--limit` | `--limit 20` | Max rows (default 50) |
| `--full` | `--full` | Detailed multi-line (query only) |
| `--json` | `--json` | JSON output (query only) |

### brief — Notification-friendly output (human readable, with URL)
```bash
$PY $SCRIPT brief --pushed --days 1
```
Each record shows: ID, source, date, title, URL, match reason. Designed for copy-paste and forwarding.

### stats — Database overview
```bash
$PY $SCRIPT stats
```

## How to interpret user requests

Map natural language to the right subcommand:

| User says | Command |
|---|---|
| "fetch" / "update" / "pull" / "抓取" / "更新" | `fetch` |
| "最近有什么新漏洞" / "what's new" | `brief --pushed --days 1` |
| "Fortinet 相关的" | `brief --source Fortinet` |
| "查一下 CVE-2026-1340" | `query --full --cve CVE-2026-1340` |
| "CISA KEV 最近一周" | `brief --source CISA_KEV --days 7` |
| "有没有 RCE" | `brief --reason RCE --days 7` |
| "导出最近漏洞" / "export" | `query --json --pushed --days 7` |
| "统计" / "status" / "overview" | `stats` |

## Available sources

S-tier: CISA_KEV, watchTowr, Fortinet, PaloAlto
A-tier: ZDI, MSRC, ProjectDisc, Horizon3, Cisco
B-tier: Sploitus_Citrix, Sploitus_Ivanti, Sploitus_F5, Rapid7, VMware
C-tier: GreyNoise
Other: GitHub

## Data location

- Database: `/opt/vuln-monitor/vuln_cache.db`
- Log: `/opt/vuln-monitor/vuln_monitor.log`
