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
import json
import secrets
import sqlite3
import os
import time
import logging
import urllib.parse
from datetime import datetime, timedelta, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path

# NOTE: keep in sync with JS const MAX_LIMIT in DASHBOARD_HTML (substituted at module load)
LIMIT_MAX = 500
NOTE_MAX = 200   # per-card note char cap (api_note); injected into dashboard JS as __NOTE_MAX__

from flask import Flask, jsonify, request, abort, g
from waitress import serve

# ── Magic token auth ──
_MAGIC_TOKEN = None  # set at startup (always loaded; public mode enforces on all methods)
# True when bound to loopback without --public: GET is open, mutating methods need token.
_LOOPBACK_MODE = True
# Force Secure cookies (or auto when request is HTTPS / X-Forwarded-Proto=https).
# Set VULN_WEB_SECURE=1 behind an HTTPS reverse proxy that terminates TLS.
_FORCE_SECURE_COOKIE = os.getenv("VULN_WEB_SECURE", "").strip().lower() in (
    "1", "true", "yes", "on",
)


def _cookie_secure() -> bool:
    """Whether Set-Cookie should include Secure.

    - Explicit VULN_WEB_SECURE=1 (recommended behind HTTPS reverse proxy)
    - Or the current request is already HTTPS / X-Forwarded-Proto: https
    Plain HTTP / SSH tunnel keeps Secure off so the browser still stores the cookie.
    """
    if _FORCE_SECURE_COOKIE:
        return True
    try:
        if request.is_secure:
            return True
        if request.headers.get("X-Forwarded-Proto", "").split(",")[0].strip().lower() == "https":
            return True
    except RuntimeError:
        pass  # no request context
    return False


def _set_auth_cookie(resp):
    """Attach the magic-token cookie with httponly + SameSite=Strict (+ Secure when HTTPS)."""
    resp.set_cookie(
        "_vmt",
        _MAGIC_TOKEN,
        httponly=True,
        samesite="Strict",
        secure=_cookie_secure(),
        max_age=86400 * 30,
    )
    return resp

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
ACCESS_LOG = DATA_DIR / "access.log"
FETCH_STATE_FILE = DATA_DIR / "fetch_state.json"
SOURCE_HEALTH_FILE = DATA_DIR / "source_health.json"

# Stealthy access audit — one line per request into access.log, never shown in
# the UI. The file handler is attached lazily so importing the module (e.g. in
# tests) never creates the file; only a real served request does.
_access_log = logging.getLogger("vuln_access")
_access_log.setLevel(logging.INFO)
_access_log.propagate = False


def _ensure_access_handler():
    if _access_log.handlers:
        return
    try:
        _h = RotatingFileHandler(ACCESS_LOG, maxBytes=5 * 1024 * 1024,
                                 backupCount=5, encoding="utf-8")
        _h.setFormatter(logging.Formatter("%(message)s"))
        _access_log.addHandler(_h)
    except Exception:
        pass  # best-effort: never break serving over logging


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

def _request_has_valid_token():
    """True if the request carries a valid magic token (path/query/cookie/Bearer)."""
    if not _MAGIC_TOKEN:
        return False
    path_parts = request.path.strip("/").split("/", 1)
    if _token_match(path_parts[0]):
        return True
    if _token_match(request.args.get("token", "")):
        return True
    if _token_match(request.cookies.get("_vmt", "")):
        return True
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer ") and _token_match(auth[7:]):
        return True
    return False


@app.before_request
def check_token():
    """Auth gate.

    - Public / non-loopback: every request needs the magic token.
    - Loopback (default): GET/HEAD/OPTIONS open for local browsing; POST/PUT/PATCH/
      DELETE (note / tags / reproduced writes) still require the magic token so a
      mis-bound port or CSRF-ish local page cannot mutate the DB silently.
    """
    is_write = request.method in ("POST", "PUT", "PATCH", "DELETE")

    # No token configured at all (tests may leave it None) — only allow non-writes
    # on loopback; writes hard-require a token once one exists, and in production
    # startup always loads/creates one.
    if _MAGIC_TOKEN is None:
        if _LOOPBACK_MODE and not is_write:
            g.auth = "loopback"
            return
        g.auth = "bad"
        abort(403)

    # Path-prefix token → redirect to clean URL + set cookie
    path_parts = request.path.strip("/").split("/", 1)
    if _token_match(path_parts[0]):
        g.auth = "ok"
        tail = path_parts[1] if len(path_parts) > 1 else ""
        real_path = "/" + tail.lstrip("/")  # prevent //evil.com open redirect
        from flask import redirect, make_response
        resp = make_response(redirect(real_path))
        return _set_auth_cookie(resp)

    if _request_has_valid_token():
        g.auth = "ok"
        return

    # Loopback reads stay open (SSH tunnel / local dashboard without pasting token)
    if _LOOPBACK_MODE and not is_write:
        g.auth = "loopback"
        return

    g.auth = "bad"
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


def _access_line(method, path, status, ip, auth, ua):
    """Format one audit line (the caller prepends the timestamp)."""
    ua = (ua or "-")[:160]
    return (f"{method} {path} {status} ip={ip or '-'} "
            f'auth={auth} ua="{ua}"')


@app.after_request
def _log_access(response):
    """Append a stealthy per-request audit line to access.log (never in the UI)."""
    _ensure_access_handler()
    try:
        ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        path = request.path
        if _MAGIC_TOKEN and path.startswith("/" + _MAGIC_TOKEN):
            path = "/<token>" + path[len("/" + _MAGIC_TOKEN):]   # don't log the secret
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        _access_log.info(
            ts + " " + _access_line(
                request.method, path, response.status_code, ip,
                getattr(g, "auth", "none"), request.headers.get("User-Agent"))
        )
    except Exception:
        pass
    return response

import contextlib

@contextlib.contextmanager
def get_db():
    """Context manager for read-only DB access — guarantees close on exception."""
    db_uri = f"file:{urllib.parse.quote(str(DB_FILE), safe='/:')}?mode=ro"
    try:
        conn = sqlite3.connect(db_uri, uri=True, timeout=5)
    except sqlite3.OperationalError:
        conn = sqlite3.connect(str(DB_FILE), timeout=5)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


@contextlib.contextmanager
def get_db_rw():
    """Context manager for read-write DB access (only for user-facing toggles)."""
    conn = sqlite3.connect(str(DB_FILE), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()



def _vulns_columns(conn):
    """Set of column names in vulns table (for pre-migration DB compat)."""
    return {row[1] for row in conn.execute("PRAGMA table_info(vulns)")}


def _int_arg(name, default, lo, hi):
    try:
        return max(lo, min(hi, int(request.args.get(name, default))))
    except (ValueError, TypeError):
        return default


# ── API ──
def _parse_tags(s):
    """Parse the stored tags JSON; return [] on any malformation (non-JSON / non-list).

    Guards /api/vulns so one corrupt `tags` cell degrades that one card to
    'no tags' instead of 500-ing the whole endpoint.
    """
    if not s:
        return []
    try:
        v = json.loads(s)
        return v if isinstance(v, list) else []
    except Exception:
        return []


@app.route("/api/vulns")
def api_vulns():
    with get_db() as conn:
        cols_avail = _vulns_columns(conn)
        where, params = [], []
        q = request.args.get("q", "").strip()
        if q:
            esc_q = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            where.append("(cve_id LIKE ? ESCAPE '\\' OR title LIKE ? ESCAPE '\\' OR summary LIKE ? ESCAPE '\\')")
            params.extend([f"%{esc_q}%"] * 3)
        exclude = request.args.get("exclude", "").strip()
        if exclude:
            for kw in exclude.split(",")[:10]:
                kw = kw.strip()
                if kw:
                    esc_kw = kw.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
                    where.append("(COALESCE(title,'') NOT LIKE ? ESCAPE '\\' AND COALESCE(summary,'') NOT LIKE ? ESCAPE '\\')")
                    params.extend([f"%{esc_kw}%"] * 2)
        source = request.args.get("source", "").strip()
        if source:
            src_list = [s.strip() for s in source.split(",") if s.strip()][:15]
            if len(src_list) == 1:
                where.append("source = ?"); params.append(src_list[0])
            elif src_list:
                where.append(f"source IN ({','.join('?' * len(src_list))})")
                params.extend(src_list)
        vuln_type = request.args.get("vuln_type", "").strip()
        if vuln_type and "vuln_type" in cols_avail:
            vt_list = [v.strip() for v in vuln_type.split(",") if v.strip()][:10]
            if len(vt_list) == 1:
                where.append("vuln_type = ?"); params.append(vt_list[0])
            elif vt_list:
                where.append(f"vuln_type IN ({','.join('?' * len(vt_list))})")
                params.extend(vt_list)
        category = request.args.get("category", "").strip()
        if category and "category" in cols_avail:
            cat_list = [c.strip() for c in category.split(",") if c.strip()][:12]
            if len(cat_list) == 1:
                where.append("category = ?"); params.append(cat_list[0])
            elif cat_list:
                where.append(f"category IN ({','.join('?' * len(cat_list))})")
                params.extend(cat_list)
        severity = request.args.get("severity", "").strip().lower()
        if severity:
            sev_valid = {"critical", "high", "medium", "low"}
            sev_list = [s.strip() for s in severity.split(",") if s.strip() in sev_valid][:4]
            if len(sev_list) == 1:
                where.append("LOWER(severity) = ?"); params.append(sev_list[0])
            elif sev_list:
                where.append(f"LOWER(severity) IN ({','.join('?' * len(sev_list))})")
                params.extend(sev_list)
        pr = request.args.get("pr", "").strip()
        if pr and "cvss_pr" in cols_avail:
            if pr.upper() in ("N", "L", "H"):
                where.append("cvss_pr = ?"); params.append(pr.upper())
            elif pr == "!N":
                where.append("cvss_pr IS NOT NULL AND cvss_pr != 'N'")
        ui = request.args.get("ui", "").strip()
        if ui and "cvss_ui" in cols_avail:
            if ui.upper() in ("N", "R"):
                where.append("cvss_ui = ?"); params.append(ui.upper())
        repro = request.args.get("reproduced", "").strip()
        if repro and "reproduced" in cols_avail:
            if repro in ("1", "-1", "2"):
                where.append("reproduced = ?"); params.append(int(repro))
            elif repro == "0":
                where.append("(reproduced IS NULL OR reproduced = 0)")
        reason = request.args.get("reason", "").strip()
        if reason:
            where.append("reason = ?"); params.append(reason)
        else:
            # excluded records (WP ecosystem / noise patterns) are push-pipeline
            # rejects — keep them out of the default browse view; audit them
            # explicitly via ?reason=excluded
            where.append("(reason IS NULL OR reason != 'excluded')")
        pushed = request.args.get("pushed", "").strip()
        if pushed == "1":
            where.append("pushed = 1")
        days = _int_arg("days", 0, 0, 3650)
        if days > 0:
            cutoff_date = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
            cutoff_ts = (datetime.now(timezone.utc) - timedelta(days=days)).timestamp()
            where.append("(NULLIF(cve_published,'unknown') >= ? OR (NULLIF(cve_published,'unknown') IS NULL AND created_at > ?))")
            params.extend([cutoff_date, cutoff_ts])

        # column list — drop optional ones missing in pre-migration DBs
        base_cols = ["key", "cve_id", "source", "title", "link", "summary", "reason", "pushed",
                     "created_at", "cve_published", "severity", "cvss", "llm_verdict",
                     "llm_notes", "tg_sent"]
        optional_cols = ["vuln_type", "category", "freshness", "cvss_pr", "cvss_ui", "reproduced", "note", "tags"]
        cols = base_cols + [c for c in optional_cols if c in cols_avail]
        sql = f"SELECT {','.join(cols)} FROM vulns"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY COALESCE(NULLIF(cve_published,'unknown'), strftime('%Y-%m-%d', created_at, 'unixepoch')) DESC, created_at DESC LIMIT ?"
        limit = _int_arg("limit", 100, 1, LIMIT_MAX)
        params.append(limit)

        rows = conn.execute(sql, params).fetchall()
    has_vt = "vuln_type" in cols_avail
    has_fr = "freshness" in cols_avail
    has_pr = "cvss_pr" in cols_avail
    has_ui = "cvss_ui" in cols_avail
    has_repro = "reproduced" in cols_avail
    has_cat = "category" in cols_avail
    has_note = "note" in cols_avail
    has_tags = "tags" in cols_avail
    return jsonify([{
        "key": r["key"], "id": r["cve_id"], "source": r["source"], "title": r["title"],
        "url": r["link"], "summary": r["summary"], "reason": r["reason"],
        "vuln_type": r["vuln_type"] if has_vt else None,
        "category": r["category"] if has_cat else None,
        "note": r["note"] if has_note else None,
        "tags": (_parse_tags(r["tags"]) if has_tags else []),
        "freshness": r["freshness"] if has_fr else None,
        "pr": r["cvss_pr"] if has_pr else None,
        "ui": r["cvss_ui"] if has_ui else None,
        "reproduced": r["reproduced"] if has_repro and r["reproduced"] is not None else 0,
        "pushed": bool(r["pushed"]),
        "tg_sent": bool(r["tg_sent"]) if r["tg_sent"] is not None else None,
        "cve_published": r["cve_published"] if r["cve_published"] != "unknown" else None,
        "severity": r["severity"] if r["severity"] != "unknown" else None,
        "cvss": r["cvss"],
        "llm_verdict": r["llm_verdict"],
        "llm_notes": r["llm_notes"],
        "date": (r["cve_published"] if r["cve_published"] != "unknown" else None) or (datetime.fromtimestamp(r["created_at"], tz=timezone.utc).strftime("%Y-%m-%d") if r["created_at"] else None),
    } for r in rows])


@app.route("/api/stats")
def api_stats():
    with get_db() as conn:
        total = conn.execute("SELECT COUNT(*) FROM vulns").fetchone()[0]
        pushed = conn.execute("SELECT COUNT(*) FROM vulns WHERE pushed=1").fetchone()[0]
        sources = conn.execute("SELECT source, COUNT(*) as n FROM vulns WHERE source IS NOT NULL AND created_at > strftime('%%s','now') - 7*86400 GROUP BY source ORDER BY n DESC").fetchall()
        cat_rows = conn.execute("SELECT COALESCE(category,'(none)') c, COUNT(*) n FROM vulns WHERE reason IS NULL OR reason != 'excluded' GROUP BY category").fetchall()
        repro_rows = conn.execute("SELECT reproduced, COUNT(*) n FROM vulns GROUP BY reproduced").fetchall()
    fetch_state = None
    try:
        if FETCH_STATE_FILE.exists():
            raw = json.loads(FETCH_STATE_FILE.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                c = raw.get("collected")
                raw["collected"] = int(c) if isinstance(c, (int, float)) and not isinstance(c, bool) else None
                fetch_state = raw
    except Exception:
        pass
    source_health = {}
    try:
        if SOURCE_HEALTH_FILE.exists():
            raw = json.loads(SOURCE_HEALTH_FILE.read_text(encoding="utf-8"))
            srcs = raw.get("sources") if isinstance(raw, dict) else None
            if isinstance(srcs, dict):
                for name, v in srcs.items():
                    if isinstance(v, dict) and "healthy" in v:
                        source_health[name] = bool(v["healthy"])
    except Exception:
        pass
    return jsonify({
        "total": total, "pushed": pushed,
        "sources": {r["source"]: r["n"] for r in sources},
        "categories": {r["c"]: r["n"] for r in cat_rows},
        "reproduced": {str(r["reproduced"]): r["n"] for r in repro_rows},
        "fetch": fetch_state,
        "source_health": source_health,
    })


@app.route("/api/sources")
def api_sources():
    with get_db() as conn:
        rows = conn.execute("SELECT DISTINCT source FROM vulns WHERE source IS NOT NULL ORDER BY source").fetchall()
    return jsonify([r["source"] for r in rows])


# allowlist for _set_vuln_field: col -> SQL typedef. Defense-in-depth so the
# f-string identifier interpolation can never ingest caller-supplied input.
_ALLOWED_VULN_COLS = {"note": "TEXT", "reproduced": "INTEGER DEFAULT 0", "tags": "TEXT"}


def _set_vuln_field(key, col, value):
    """Shared writer for a per-row column on `vulns` (`col` must be allowlisted).

    Auto-migrates the column if missing; retries on lock/contention OR a benign
    concurrent-migration "duplicate column name" race (re-raising other
    OperationalErrors so a schema/IO bug surfaces as a 500 traceback instead of
    a misleading "database busy" 503); returns 404 when no row matches the key.
    `value`/`key` are parameterized; `col` is validated against _ALLOWED_VULN_COLS.
    Returns (status_code, body_dict).
    """
    if col not in _ALLOWED_VULN_COLS:
        raise ValueError(f"_set_vuln_field: column {col!r} not in allowlist")
    typedef = _ALLOWED_VULN_COLS[col]
    for attempt in range(3):
        try:
            with get_db_rw() as conn:
                if col not in _vulns_columns(conn):
                    conn.execute(f"ALTER TABLE vulns ADD COLUMN {col} {typedef}")
                cur = conn.execute(f"UPDATE vulns SET {col}=? WHERE key=?", (value, key))
                if cur.rowcount == 0:
                    return 404, {"error": "no such vulnerability"}
            return 200, {"ok": True, "key": key, col: value}
        except sqlite3.OperationalError as e:
            msg = str(e).lower()
            if "locked" in msg or "busy" in msg or "duplicate column name" in msg:
                if attempt == 2:
                    return 503, {"error": "database busy, try again"}
                time.sleep(1)
            else:
                raise


@app.route("/api/reproduced", methods=["POST"])
def api_reproduced():
    """Toggle reproduced flag for a vulnerability by internal key."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "JSON object body required"}), 400
    key = (data.get("key") or "").strip()
    if not key:
        return jsonify({"error": "key required"}), 400
    try:
        val = int(data.get("reproduced", 0))
    except (TypeError, ValueError):
        return jsonify({"error": "reproduced must be an integer"}), 400
    if val not in (-1, 0, 1, 2):
        return jsonify({"error": "reproduced must be -1, 0, 1, or 2"}), 400
    code, body = _set_vuln_field(key, "reproduced", val)
    return jsonify(body), code


@app.route("/api/note", methods=["POST"])
def api_note():
    """Set or clear a free-text note (<= NOTE_MAX chars) on a vulnerability by key."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "JSON object body required"}), 400
    key = (data.get("key") or "").strip()
    if not key:
        return jsonify({"error": "key required"}), 400
    raw = data.get("note")
    if raw is None:
        note = ""
    elif isinstance(raw, str):
        note = raw.strip()
    else:
        return jsonify({"error": "note must be a string"}), 400
    if len(note) > NOTE_MAX:
        return jsonify({"error": f"note too long (max {NOTE_MAX})"}), 400
    stored = note if note else None
    code, body = _set_vuln_field(key, "note", stored)
    return jsonify(body), code


@app.route("/api/tags", methods=["POST"])
def api_tags():
    """Set the tag list on a vulnerability (e.g. 内网目标/重点关注/已处理/误报)."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "JSON object body required"}), 400
    key = (data.get("key") or "").strip()
    if not key:
        return jsonify({"error": "key required"}), 400
    raw = data.get("tags")
    if raw is None:
        tags = []
    elif isinstance(raw, list) and all(isinstance(t, str) for t in raw):
        tags = [t.strip() for t in raw if t.strip()]
    else:
        return jsonify({"error": "tags must be a list of strings"}), 400
    if len(tags) > 8:
        return jsonify({"error": "too many tags (max 8)"}), 400
    if any(len(t) > 16 for t in tags):
        return jsonify({"error": "tag too long (max 16 chars)"}), 400
    stored = json.dumps(tags, ensure_ascii=False) if tags else None
    code, body = _set_vuln_field(key, "tags", stored)
    if code == 200:
        body["tags"] = tags   # return the parsed list, not the JSON string
    return jsonify(body), code


# ── Vulnpilot API (for B-side dispatcher) ──

@app.route("/api/pending")
def api_pending():
    """Return pushed vulns from last 7 days for B-side dispatcher."""
    with get_db() as conn:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=7)).timestamp()
        rows = conn.execute(
            """SELECT cve_id, source, title, link, summary, vuln_type, cvss,
                      severity, reason, created_at
               FROM vulns WHERE pushed = 1 AND created_at > ?
               ORDER BY created_at DESC LIMIT 1000""",
            (cutoff,),
        ).fetchall()
    return jsonify({
        "vulns": [{
            "cve_id": r["cve_id"],
            "title": r["title"],
            "source": r["source"],
            "link": r["link"],
            "summary": r["summary"],
            "vuln_type": r["vuln_type"],
            "cvss": r["cvss"],
            "severity": r["severity"],
            "reason": r["reason"],
            "created_at": datetime.fromtimestamp(r["created_at"], tz=timezone.utc).isoformat() if r["created_at"] else None,
        } for r in rows],
        "count": len(rows),
    })


# ── Frontend ──
def _load_dashboard_html():
    """Load dashboard template from static/dashboard.html."""
    path = Path(__file__).resolve().parent / "static" / "dashboard.html"
    html = path.read_text(encoding="utf-8")
    # substitute server-side constants (single source of truth)
    html = html.replace("__LIMIT_MAX__", str(LIMIT_MAX))
    html = html.replace("__NOTE_MAX__", str(NOTE_MAX))
    return html


DASHBOARD_HTML = _load_dashboard_html()


@app.route("/")
def index():
    from flask import make_response
    resp = make_response(DASHBOARD_HTML)
    # Loopback: drop the auth cookie on page load so dashboard write APIs
    # (note/tags/reproduced) succeed without the user pasting a token URL.
    # SameSite=Strict blocks cross-site CSRF from carrying the cookie.
    # Secure is set automatically on HTTPS / when VULN_WEB_SECURE=1.
    if _LOOPBACK_MODE and _MAGIC_TOKEN:
        _set_auth_cookie(resp)
    return resp


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

    # Always load/create a token so write APIs can require it even on loopback.
    _MAGIC_TOKEN = args.token or (new_token if args.rotate_token else _load_or_create_token())

    if args.public:
        args.host = "0.0.0.0"
        _LOOPBACK_MODE = False
        print(f"vuln-monitor dashboard (PUBLIC mode — all requests need token)")
        print(f"  magic URL:  http://<your-ip>:{args.port}/{_MAGIC_TOKEN}/")
        print(f"  token:      {_MAGIC_TOKEN}")
        print(f"  token file: {TOKEN_FILE}")
        print(f"  database:   {DB_FILE}")
    elif args.host not in ("127.0.0.1", "localhost", "::1"):
        _LOOPBACK_MODE = False
        print(f"vuln-monitor dashboard (non-loopback, token enforced)")
        print(f"  bind:       {args.host}:{args.port}")
        print(f"  token:      {_MAGIC_TOKEN}")
        print(f"  database:   {DB_FILE}")
    else:
        _LOOPBACK_MODE = True
        print(f"vuln-monitor dashboard: http://{args.host}:{args.port}")
        print(f"  database:   {DB_FILE}")
        print(f"  token:      {_MAGIC_TOKEN}  (required for write APIs; set on first page load)")
        print(f"  localhost reads open; POST note/tags/reproduced need magic token")
        print(f"  (use --public for external access, or SSH tunnel)")

    serve(app, host=args.host, port=args.port)
