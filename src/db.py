"""SQLite helpers for vuln-monitor."""
import contextlib
import json
import sqlite3
from datetime import datetime, timedelta, timezone

try:
    from src.config import DB_FILE, CACHE_TTL_DAYS, _JSON_LEGACY, log
    from src.scoring import _HARDCODED_CRED_RE
except ImportError:
    from config import DB_FILE, CACHE_TTL_DAYS, _JSON_LEGACY, log
    from scoring import _HARDCODED_CRED_RE

def _get_conn():
    conn = sqlite3.connect(DB_FILE, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn

import contextlib

@contextlib.contextmanager
def _db():
    """Context manager for DB connections — guarantees close on exception."""
    conn = _get_conn()
    try:
        yield conn
    finally:
        conn.close()

def init_db(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS vulns (
            key        TEXT PRIMARY KEY,
            cve_id     TEXT,
            source     TEXT,
            title      TEXT NOT NULL,
            link       TEXT,
            summary    TEXT,
            reason     TEXT,
            vuln_type  TEXT,
            freshness  TEXT,
            freshness_reason TEXT,
            pushed     INTEGER DEFAULT 0,
            created_at REAL NOT NULL,
            cve_published TEXT,
            severity      TEXT,
            cvss          REAL,
            llm_verified  INTEGER DEFAULT 0,
            llm_verdict   TEXT,
            llm_notes     TEXT,
            tg_sent       INTEGER DEFAULT 0,
            wecom_sent    INTEGER DEFAULT 0,
            dingtalk_sent INTEGER DEFAULT 0,
            feishu_sent   INTEGER DEFAULT 0,
            cvss_vector   TEXT,
            cvss_pr       TEXT
        )
    """)
    # migrate: add columns if missing (existing databases)
    _new_cols = []
    for col, typedef in [
        ("cve_published", "TEXT"),
        ("severity",      "TEXT"),
        ("cvss",          "REAL"),
        ("llm_verified",  "INTEGER DEFAULT 0"),
        ("llm_verdict",   "TEXT"),
        ("llm_notes",     "TEXT"),
        ("tg_sent",       "INTEGER DEFAULT 0"),
        ("wecom_sent",    "INTEGER DEFAULT 0"),
        ("dingtalk_sent", "INTEGER DEFAULT 0"),
        ("feishu_sent",   "INTEGER DEFAULT 0"),
        ("freshness",     "TEXT"),
        ("freshness_reason", "TEXT"),
        ("vuln_type",     "TEXT"),
        ("cvss_vector",   "TEXT"),
        ("cvss_pr",       "TEXT"),
        ("cvss_ui",       "TEXT"),
        ("reproduced",   "INTEGER DEFAULT 0"),
        ("category",     "TEXT"),
        ("note",         "TEXT"),
        ("tags",         "TEXT"),
    ]:
        try:
            conn.execute(f"ALTER TABLE vulns ADD COLUMN {col} {typedef}")
            _new_cols.append(col)
        except sqlite3.OperationalError:
            pass
    # backfill sent columns: mark already-pushed records as sent (only on first migration)
    if "tg_sent" in _new_cols:
        conn.execute("UPDATE vulns SET tg_sent = 1 WHERE pushed = 1")
    if "wecom_sent" in _new_cols:
        conn.execute("UPDATE vulns SET wecom_sent = 1 WHERE pushed = 1")
    if "dingtalk_sent" in _new_cols:
        conn.execute("UPDATE vulns SET dingtalk_sent = 1 WHERE pushed = 1")
    if "feishu_sent" in _new_cols:
        conn.execute("UPDATE vulns SET feishu_sent = 1 WHERE pushed = 1")
    # backfill freshness + vuln_type + migrate legacy values (only on first migration)
    if "freshness" in _new_cols:
        conn.execute("UPDATE vulns SET freshness='nday', reason=SUBSTR(reason,6) WHERE reason LIKE 'nday:%'")
        conn.execute("UPDATE vulns SET freshness='1day' WHERE freshness IS NULL AND reason NOT IN ('excluded','no hit')")
        # migrate legacy llm_verdict values
        conn.execute("UPDATE vulns SET llm_verdict='confirmed' WHERE llm_verdict IN ('1day_rce','1day_high','fallback_regex')")
        conn.execute("UPDATE vulns SET llm_verdict='not_relevant' WHERE llm_verdict='1day_low'")
        conn.execute("UPDATE vulns SET llm_verdict='not_relevant' WHERE llm_verdict='nday'")
    # backfill vuln_type from reason (only on first migration)
    if "vuln_type" in _new_cols:
        conn.execute("UPDATE vulns SET vuln_type='RCE' WHERE reason LIKE '%RCE%'")
        conn.execute("UPDATE vulns SET vuln_type='other' WHERE vuln_type IS NULL AND reason NOT IN ('excluded','no hit')")
    # enforce hard locks on existing data: GitHub/nday/excluded must not remain pushed
    conn.execute("UPDATE vulns SET pushed=0 WHERE source IN ('GitHub','PoC-GitHub') AND pushed=1")
    conn.execute("UPDATE vulns SET pushed=0 WHERE freshness='nday' AND pushed=1")
    # PR lock: unknown PR / PR:H always un-push. PR:L un-pushes too — unless the
    # only "login" is a hardcoded/default credential (effectively unauthenticated,
    # same exception as push_gate._pr_blocks_push).
    conn.execute("UPDATE vulns SET pushed=0 WHERE pushed=1 AND (cvss_pr IS NULL OR cvss_pr NOT IN ('N','L'))")
    for _k, _t, _s in conn.execute(
            "SELECT key, title, summary FROM vulns WHERE pushed=1 AND cvss_pr='L'").fetchall():
        if not _HARDCODED_CRED_RE.search(f"{_t or ''}\n{_s or ''}"):
            conn.execute("UPDATE vulns SET pushed=0 WHERE key=?", (_k,))
    if "cvss_ui" in _new_cols:
        conn.execute("""UPDATE vulns SET cvss_ui =
            CASE WHEN cvss_vector LIKE '%/UI:N/%' OR cvss_vector LIKE '%/UI:N' THEN 'N'
                 WHEN cvss_vector LIKE '%/UI:R/%' OR cvss_vector LIKE '%/UI:R' THEN 'R'
                 ELSE NULL END
            WHERE cvss_vector IS NOT NULL AND cvss_ui IS NULL""")
    conn.execute("UPDATE vulns SET pushed=0 WHERE pushed=1 AND cvss_ui IS NOT NULL AND cvss_ui != 'N'")
    conn.execute("UPDATE vulns SET pushed=0 WHERE pushed=1 AND reason='excluded'")
    # product scope: only RCE + bypass are push-worthy (un-push SQLi/file-read/etc.)
    conn.execute(
        "UPDATE vulns SET pushed=0 WHERE pushed=1 "
        "AND (vuln_type IS NULL OR vuln_type NOT IN ('RCE','bypass'))"
    )
    conn.commit()
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cve_id     ON vulns(cve_id)     WHERE cve_id IS NOT NULL")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_source     ON vulns(source)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_created_at ON vulns(created_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_pushed     ON vulns(pushed)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_llm_verified ON vulns(llm_verified) WHERE llm_verified=0")
    conn.commit()

def migrate_json_cache(conn):
    """One-time migration from vuln_cache.json → SQLite."""
    if not _JSON_LEGACY.exists():
        return
    if conn.execute("SELECT COUNT(*) FROM vulns").fetchone()[0] > 0:
        return
    try:
        old = json.loads(_JSON_LEGACY.read_text(encoding="utf-8"))
    except Exception:
        return
    for key, val in old.items():
        cve_id = key.split(":", 1)[1] if key.startswith("cve:") else None
        conn.execute(
            "INSERT OR IGNORE INTO vulns (key,cve_id,title,reason,pushed,created_at) "
            "VALUES (?,?,?,?,?,?)",
            (key, cve_id, val.get("title", "")[:300], val.get("reason", ""),
             1 if val.get("pushed") else 0, val.get("ts", 0)),
        )
    conn.commit()
    _JSON_LEGACY.rename(_JSON_LEGACY.with_suffix(".json.migrated"))
    log.info(f"migrated {len(old)} entries from JSON to SQLite")

def db_cleanup(conn):
    cutoff = (datetime.now(timezone.utc) - timedelta(days=CACHE_TTL_DAYS)).timestamp()
    conn.execute("DELETE FROM vulns WHERE created_at < ?", (cutoff,))
    conn.commit()

