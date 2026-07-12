"""Shared runtime config for vuln-monitor.

Paths, credentials, HTTP session, logging. Imported by db/notify/sources/vuln_monitor.
"""
import os
import sys
import json
import time
import logging
import platform
from logging.handlers import RotatingFileHandler
from pathlib import Path

import requests

def _user_config_path() -> Path:
    """XDG-compliant per-user config path. Cross-platform.

    Linux / macOS: $XDG_CONFIG_HOME/vuln-monitor/config.json  (default ~/.config/...)
    Windows:       %APPDATA%\\vuln-monitor\\config.json
    """
    if platform.system() == "Windows":
        base = os.getenv("APPDATA") or str(Path.home())
    else:
        base = os.getenv("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "vuln-monitor" / "config.json"


USER_CONFIG_FILE = _user_config_path()


def _load_user_config() -> dict:
    """Load persisted local config. Returns {} if missing or unreadable."""
    if not USER_CONFIG_FILE.exists():
        return {}
    try:
        return json.loads(USER_CONFIG_FILE.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"WARN: failed to parse {USER_CONFIG_FILE}: {e}", file=sys.stderr)
        return {}


# Resolution order for credentials:
#   1. environment variable   (CI / systemd / one-off override)
#   2. user config file       (persisted via `scripts/configure.py`)
#   3. empty string           (TG_* empty -> dry mode, no push)
_user_cfg = _load_user_config()
TG_BOT_TOKEN = os.getenv("TG_BOT_TOKEN") or _user_cfg.get("tg_bot_token", "")
_raw_chat_id = os.getenv("TG_CHAT_ID")   or _user_cfg.get("tg_chat_id", "")
TG_CHAT_IDS  = [c.strip() for c in _raw_chat_id.split(",") if c.strip()]
GH_TOKEN     = os.getenv("GH_TOKEN")     or _user_cfg.get("gh_token", "")
NVD_API_KEY  = os.getenv("NVD_API_KEY") or _user_cfg.get("nvd_api_key", "")
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY") or _user_cfg.get("deepseek_api_key", "")
OPENAI_API_KEY   = os.getenv("OPENAI_API_KEY")   or _user_cfg.get("openai_api_key", "")
LLM_MODEL    = os.getenv("LLM_MODEL")       or _user_cfg.get("llm_model", "")
LLM_BASE_URL = os.getenv("LLM_BASE_URL")   or _user_cfg.get("llm_base_url", "")
def _safe_num(raw, cast, default):
    try:
        return cast(raw)
    except (ValueError, TypeError):
        return default

LLM_TEMPERATURE = _safe_num(os.getenv("LLM_TEMPERATURE") or _user_cfg.get("llm_temperature", "0.1"), float, 0.1)
LLM_MAX_TOKENS  = _safe_num(os.getenv("LLM_MAX_TOKENS")  or _user_cfg.get("llm_max_tokens", "1024"), int, 1024)
LLM_TIMEOUT     = _safe_num(os.getenv("LLM_TIMEOUT")      or _user_cfg.get("llm_timeout", "60"), int, 60)
LLM_MAX_CONTEXT = _safe_num(os.getenv("LLM_MAX_CONTEXT")  or _user_cfg.get("llm_max_context", "1048576"), int, 1048576)
LLM_REASONING   = os.getenv("LLM_REASONING_EFFORT")   or _user_cfg.get("llm_reasoning_effort", "high")
LLM_TOP_P       = _safe_num(os.getenv("LLM_TOP_P")    or _user_cfg.get("llm_top_p", "0.9"), float, 0.9)
PROXY        = os.getenv("HTTPS_PROXY")  or _user_cfg.get("https_proxy", "")

WECOM_WEBHOOK_KEY      = os.getenv("WECOM_WEBHOOK_KEY")      or _user_cfg.get("wecom_webhook_key", "")
DINGTALK_WEBHOOK_TOKEN  = os.getenv("DINGTALK_WEBHOOK_TOKEN")  or _user_cfg.get("dingtalk_webhook_token", "")
DINGTALK_WEBHOOK_SECRET = os.getenv("DINGTALK_WEBHOOK_SECRET") or _user_cfg.get("dingtalk_webhook_secret", "")
FEISHU_WEBHOOK_URL      = os.getenv("FEISHU_WEBHOOK_URL")      or _user_cfg.get("feishu_webhook_url", "")

SCRIPT_DIR     = Path(__file__).resolve().parent
# Runtime state (cache / lock / alert-state / log) lives in DATA_DIR.
# Resolution order:
#   1. $VULN_DATA_DIR env var (systemd / deploy.sh set this explicitly)
#   2. SCRIPT_DIR.parent if SCRIPT_DIR is named "src" (repo layout: src/vuln_monitor.py)
#   3. SCRIPT_DIR (script sits at data root)
if os.getenv("VULN_DATA_DIR"):
    DATA_DIR = Path(os.getenv("VULN_DATA_DIR")).resolve()
elif SCRIPT_DIR.name == "src":
    DATA_DIR = SCRIPT_DIR.parent
else:
    DATA_DIR = SCRIPT_DIR
DATA_DIR.mkdir(parents=True, exist_ok=True)

DB_FILE        = DATA_DIR / "vuln_cache.db"
_JSON_LEGACY   = DATA_DIR / "vuln_cache.json"   # migration source
LOCK_FILE      = DATA_DIR / "vuln_monitor.lock"
ALERT_STATE    = DATA_DIR / "vuln_alert_state.json"
FETCH_STATE    = DATA_DIR / "fetch_state.json"
SEED_MARKER    = DATA_DIR / ".seeded"     # written after the first run — a later DB reset
                                       # (marker present) won't re-trigger cold-start suppression
SOURCE_HEALTH  = DATA_DIR / "source_health.json"   # per-source last-3 fetch counts → web health dots
LOG_FILE       = DATA_DIR / "vuln_monitor.log"
CACHE_TTL_DAYS = 60
ITEM_PER_FEED  = 50
PUSH_SLEEP_SEC = 1.5
REQUEST_TIMEOUT = 20
LOG_MAX_BYTES  = 5 * 1024 * 1024
LOG_BACKUPS    = 5
ALERT_COOLDOWN_SEC = 3600
# Max LLM candidates processed per enrich cycle. Fair queue (see
# _select_enrich_candidates): half newest high-priority, half oldest backlog —
# avoids the old "ORDER BY created_at DESC LIMIT 500" starvation of older rows.
ENRICH_LIMIT = max(1, int(os.getenv("ENRICH_LIMIT", "200")))

RSS_FEEDS = [
    # ---- vendor PSIRT ----
    # Citrix/F5/Assetnote: no working RSS as of 2026.
    # Fortinet/MSRC/watchTowr: their RSS froze in 2026-Q2 (still 200 but serves a
    #   months-old snapshot) — moved to dedicated fetchers below
    #   (fetch_fortinet / fetch_msrc / fetch_watchtowr).
    ("PaloAlto",    "https://security.paloaltonetworks.com/rss.xml"),
    ("Cisco",       "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml"),
    # ---- exploit aggregator (low quality but unique CVE coverage, enriched via NVD backfill) ----
    ("Sploitus_Citrix",   "https://sploitus.com/rss?query=citrix"),
    # ---- research teams (vuln-focused, not blogs/marketing) ----
    # watchTowr moved to fetch_watchtowr (posts sitemap) — its RSS froze in 2026-Q2.
    ("ZDI",         "https://www.zerodayinitiative.com/rss/published/"),
    ("Horizon3",    "https://www.horizon3.ai/feed/"),
    ("Rapid7",      "https://www.rapid7.com/blog/rss/"),
    ("DailyCVE",    "https://dailycve.com/feed"),
    # ---- CERT (structured advisories, high CVE density) ----
    ("CERT_CC",     "https://www.kb.cert.org/vuls/atomfeed/"),
    # VMware (blog/marketing, 0% CVE) — removed
    # ProjectDisc (product marketing, 0% CVE) — removed
    # GreyNoise (trend analysis, 10% CVE) — removed
    # SentinelLabs (research blog, 0% CVE) — removed
    # XuanwuLab (academic/research, low CVE density) — removed
]

# CISA KEV uses a JSON endpoint (1500+ entries with structured fields, not RSS).
KEV_JSON_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Chaitin Stack vuldb — hidden JSON API behind SafeLine WAF.
# Requires Referer/Origin headers; rate-limited (one call per fetch cycle is fine).
CHAITIN_API_URL = "https://stack.chaitin.com/api/v2/vuln/list/"

# ThreatBook (微步在线) — public homePage endpoint, returns premium + highrisk vulns.
THREATBOOK_API_URL = "https://x.threatbook.com/v5/node/vul_module/homePage"

# TWCERT/CC (台灣電腦網路危機處理暨協調中心) — Taiwan Vulnerability Notes (TVN).
# The RSS lists advisory titles only (no CVE/CVSS); each detail page (cp-132-*)
# carries the structured fields (CVE ID, CVSS score+vector, product, vuln type).
TWCERT_RSS_URL = "https://www.twcert.org.tw/tw/rss-132-1.xml"

# Microsoft MSRC — CVRF XML API (the RSS feed was deprecated in 2026 and now
# serves a frozen months-old snapshot).
MSRC_CVRF_API      = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{alias}"
_MONTH_ABBR        = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
                      "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
# Fortinet PSIRT — ir.xml RSS froze in 2026-Q2 (serves an April snapshot);
# scrape the live portal HTML for FG-IR-* advisories instead.
FORTINET_PSIRT_URL = "https://www.fortiguard.com/psirt"
# watchTowr labs — RSS froze in 2026-Q2; the posts sitemap is live and each
# vulnerability writeup's URL slug carries its CVE-Id (e.g. ...-cve-2026-8037/).
WATCHTOWR_SITEMAP  = "https://labs.watchtowr.com/sitemap-posts.xml"

# GitHub repo-level Security Advisories — independent software products (firewall/
# VPN/web server/runtime) whose vulns are NOT published to any package ecosystem,
# so they never appear in the global /advisories endpoint (fetch_github_advisories).
# Each is a boundary device or core infra component in ASSET_KEYWORDS. The repo
# endpoint repos/{owner}/{repo}/security-advisories exposes advisories that GitHub's
# global Advisory Database doesn't index (e.g. OPNsense CVE-2026-57155 Root RCE).
REPO_ADVISORY_SOURCES = [
    "opnsense/core",               # OPNsense firewall
    "vyos/vyos",                   # VyOS router
    "FreeRDP/FreeRDP",             # RDP client
    "nginx/nginx",                 # nginx
    "apache/httpd",                # Apache httpd
    "apache/tomcat",               # Tomcat
    "haproxy/haproxy",             # HAProxy
    "envoyproxy/envoy",            # Envoy
    "caddyserver/caddy",           # Caddy
    "openssl/openssl",             # OpenSSL
    "libressl-portable/portable",  # LibreSSL
    "php/php-src",                 # PHP
    "nodejs/node",                 # Node.js
    "python/cpython",              # CPython
]




# Sources whose advisories are high-value even when DB fields are incomplete.
HIGH_PRIORITY_SOURCES = frozenset({
    "Fortinet", "PaloAlto", "Cisco", "CISA_KEV", "ZDI",
    "watchTowr", "MSRC", "Horizon3", "Chaitin", "ThreatBook",
})
# Reasons that indicate a genuinely interesting finding.
STRONG_VULN_TYPES = frozenset({"RCE", "bypass", "other"})

# ── Freshness (1day vs nday) ──
# 1day = 漏洞本体新近公开且处于可利用窗口期，值得立刻关注和防御的新鲜攻击面。
# 不是"任意新内容"：老洞新 PoC / 聚合站重新收录 / 老洞重炒 都不算 1day。
# Sources where publication inherently means the vulnerability is fresh.
FRESH_SOURCES = frozenset({
    "Fortinet", "PaloAlto", "Cisco", "MSRC",        # Vendor PSIRT
    "CISA_KEV",                                       # In-the-wild confirmation
    "ZDI", "watchTowr", "Horizon3", "Rapid7",        # Research teams
    "Chaitin",                                            # Curated vuln database
    # ThreatBook: NOT in FRESH_SOURCES — premium section lacks vuln_publish_time,
    # mixes old vulns (XVE-2025 with 2025-04 pub date) into current listings.
    "DailyCVE",                                        # Aggregator, but entries are day-of CVEs (not old rehash)
    "GHSA",                                            # GitHub Advisory Database (reviewed by GitHub security team)
})
# Sources that aggregate/republish old vulns — need CVE year validation.
# PoC-GitHub is implicitly NOT in FRESH_SOURCES.

# Fallback advisory page per vendor (used when we know the source but have no
# item-level URL).
VENDOR_URL_FALLBACK = {
    "Fortinet":     "https://www.fortiguard.com/psirt",
    "PaloAlto":     "https://security.paloaltonetworks.com",
    "Cisco":        "https://sec.cloudapps.cisco.com/security/center/publicationListing.x",
    "CISA_KEV":     "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    "MSRC":         "https://msrc.microsoft.com/update-guide",
    "ZDI":          "https://www.zerodayinitiative.com/advisories/published/",
    "watchTowr":    "https://labs.watchtowr.com",
    "Horizon3":     "https://www.horizon3.ai/attack-research/",
    "Rapid7":       "https://www.rapid7.com/blog/",
    "Chaitin":      "https://stack.chaitin.com/vuldb/index",
    "ThreatBook":   "https://x.threatbook.com/v5/vul",
    "GitHub":       "https://github.com",
}



# ================== LOG / HTTP ==================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        RotatingFileHandler(LOG_FILE, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUPS, encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger("vuln")

SESS = requests.Session()
SESS.headers["User-Agent"] = "vuln-intel/1.0"
if PROXY:
    SESS.proxies = {"http": PROXY, "https": PROXY}

_RETRY_ATTEMPTS = 3
_RETRY_DELAY = 3

def _get_with_retry(session, url, **kwargs):
    """GET with retry on transient failures."""
    for attempt in range(1, _RETRY_ATTEMPTS + 1):
        try:
            r = session.get(url, **kwargs)
            return r
        except (requests.ConnectionError, requests.Timeout) as ex:
            if attempt == _RETRY_ATTEMPTS:
                raise
            log.debug(f"retry {attempt}/{_RETRY_ATTEMPTS} for {url}: {ex}")
            time.sleep(_RETRY_DELAY)
    return None  # unreachable


