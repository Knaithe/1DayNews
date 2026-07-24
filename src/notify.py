"""Multi-channel push (Telegram / WeCom / DingTalk / Feishu) + failure alerts."""
import base64
import hashlib
import hmac
import json
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

import requests

try:
    from src.config import (
        TG_BOT_TOKEN, TG_CHAT_IDS, WECOM_WEBHOOK_KEY,
        DINGTALK_WEBHOOK_TOKEN, DINGTALK_WEBHOOK_SECRET, FEISHU_WEBHOOK_URL,
        ALERT_STATE, ALERT_COOLDOWN_SEC, PUSH_SLEEP_SEC, REQUEST_TIMEOUT,
        log, SESS,
    )
    from src.scoring import CVE_RE, ADVISORY_RE, first_url
except ImportError:
    from config import (
        TG_BOT_TOKEN, TG_CHAT_IDS, WECOM_WEBHOOK_KEY,
        DINGTALK_WEBHOOK_TOKEN, DINGTALK_WEBHOOK_SECRET, FEISHU_WEBHOOK_URL,
        ALERT_STATE, ALERT_COOLDOWN_SEC, PUSH_SLEEP_SEC, REQUEST_TIMEOUT,
        log, SESS,
    )
    from scoring import CVE_RE, ADVISORY_RE, first_url

def tg_escape(s):
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def _md_escape(s):
    """Escape markdown metacharacters for WeCom/DingTalk webhook messages."""
    s = (s or "").replace("\n", " ")
    for ch in ("\\", "*", "_", "[", "]", "(", ")", ">", "#", "`"):
        s = s.replace(ch, f"\\{ch}")
    return s

def _extract_id(text, link):
    """Extract CVE or vendor advisory ID from text+link."""
    cves = sorted(set(c.upper() for c in CVE_RE.findall(text)))
    if cves:
        return " ".join(cves)
    # fallback: vendor advisory ID from text or link
    for src in (text, link or ""):
        m = ADVISORY_RE.search(src)
        if m:
            return m.group()
    return "N/A"

def format_msg(it, reason):
    tag = _extract_id(it["text"], it["link"])
    return (
        f"<b>[{tg_escape(it['source'])}]</b> <code>{tg_escape(tag)}</code>\n"
        f"<b>{tg_escape(it['title'][:220])}</b>\n"
        f"{tg_escape(first_url(it['link']))}\n"
        f"{tg_escape(it['summary'][:400])}\n"
        f"<i>match: {tg_escape(reason)}</i>"
    )[:4000]

def _tg_retry_after(response):
    """Seconds Telegram told us to wait on a 429, or 0 if not parseable.

    Telegram returns {"parameters": {"retry_after": <sec>}} on 429. We must
    honour it — ignoring it turns a burst (e.g. a backfilled backlog) into a
    permanent 429 loop that never delivers.
    """
    try:
        return int((response.json() or {}).get("parameters", {}).get("retry_after") or 0)
    except Exception:
        return 0


def _tg_send_one(chat_id, msg, _retried=False):
    """Send one Telegram message. On 429, sleep retry_after and retry once."""
    try:
        r = SESS.post(
            f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage",
            json={
                "chat_id": chat_id,
                "text": msg,
                "parse_mode": "HTML",
                "disable_web_page_preview": False,
            },
            timeout=REQUEST_TIMEOUT,
        )
    except Exception as ex:
        log.warning(f"TG err {chat_id}: {type(ex).__name__}")
        return False
    if r.status_code == 429 and not _retried:
        wait = _tg_retry_after(r) or 1
        log.warning(f"TG push {chat_id} 429: rate-limited, sleeping {wait}s then retrying")
        time.sleep(wait)
        return _tg_send_one(chat_id, msg, _retried=True)
    if r.status_code != 200:
        log.warning(f"TG push {chat_id} {r.status_code}: {r.text[:200]}")
        return False
    return True


def send_telegram(msg):
    if not (TG_BOT_TOKEN and TG_CHAT_IDS):
        log.info(f"[DRY] {msg[:500]}")
        return True
    ok = True
    for chat_id in TG_CHAT_IDS:
        if not _tg_send_one(chat_id, msg):
            ok = False
    return ok


def format_msg_wecom(it, reason):
    tag = _md_escape(_extract_id(it["text"], it["link"]))
    src = _md_escape(it["source"])
    title = _md_escape(it["title"][:220])
    summary = _md_escape(it["summary"][:400])
    link = first_url(it["link"])
    msg = (
        f"**{src}** {tag}\n"
        f"**{title}**\n"
        f"[链接]({link})\n"
        f"{summary}\n"
        f"> match: {_md_escape(reason)}"
    )
    return msg.encode("utf-8")[:4096].decode("utf-8", "ignore")

def format_msg_dingtalk(it, reason):
    tag = _md_escape(_extract_id(it["text"], it["link"]))
    src = _md_escape(it["source"])
    dt_title = f"{it['source']} {_extract_id(it['text'], it['link'])}"
    title_esc = _md_escape(it["title"][:220])
    summary = _md_escape(it["summary"][:400])
    link = first_url(it["link"])
    text = (
        f"**{src}** {tag}\n\n"
        f"**{title_esc}**\n\n"
        f"[链接]({link})\n\n"
        f"{summary}\n\n"
        f"match: {_md_escape(reason)}"
    )[:4096]
    return dt_title, text

def format_msg_feishu(it, reason):
    tag = _extract_id(it["text"], it["link"])
    title = f"[{it['source']}] {tag}"
    link = first_url(it["link"])
    content = [[
        {"tag": "text", "text": f"{it['title'][:220]}\n"},
        {"tag": "a", "text": link or "N/A", "href": link},
        {"tag": "text", "text": f"\n{it['summary'][:400]}\nmatch: {reason}"},
    ]]
    return title, content


def send_wecom(msg_markdown):
    if not WECOM_WEBHOOK_KEY:
        return True
    try:
        r = SESS.post(
            f"https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key={WECOM_WEBHOOK_KEY}",
            json={"msgtype": "markdown", "markdown": {"content": msg_markdown}},
            timeout=REQUEST_TIMEOUT,
        )
        if r.status_code != 200 or r.json().get("errcode", 0) != 0:
            log.warning(f"WeCom push {r.status_code}: {r.text[:200]}")
            return False
    except Exception as ex:
        log.warning(f"WeCom err: {type(ex).__name__}")
        return False
    return True

def _dingtalk_sign():
    if not DINGTALK_WEBHOOK_SECRET:
        return ""
    import hmac, hashlib, base64
    from urllib.parse import quote_plus
    ts = str(int(time.time() * 1000))
    string_to_sign = f"{ts}\n{DINGTALK_WEBHOOK_SECRET}"
    hmac_code = hmac.new(DINGTALK_WEBHOOK_SECRET.encode("utf-8"),
                         string_to_sign.encode("utf-8"), digestmod=hashlib.sha256).digest()
    sign = quote_plus(base64.b64encode(hmac_code))
    return f"&timestamp={ts}&sign={sign}"

def send_dingtalk(title, msg_markdown):
    if not DINGTALK_WEBHOOK_TOKEN:
        return True
    try:
        url = f"https://oapi.dingtalk.com/robot/send?access_token={DINGTALK_WEBHOOK_TOKEN}{_dingtalk_sign()}"
        r = SESS.post(
            url,
            json={"msgtype": "markdown", "markdown": {"title": title, "text": msg_markdown}},
            timeout=REQUEST_TIMEOUT,
        )
        if r.status_code != 200 or r.json().get("errcode", 0) != 0:
            log.warning(f"DingTalk push {r.status_code}: {r.text[:200]}")
            return False
    except Exception as ex:
        log.warning(f"DingTalk err: {type(ex).__name__}")
        return False
    return True

def send_feishu(title, content):
    if not FEISHU_WEBHOOK_URL:
        return True
    try:
        r = SESS.post(
            FEISHU_WEBHOOK_URL,
            json={"msg_type": "post", "content": {"post": {"zh_cn": {"title": title, "content": content}}}},
            timeout=REQUEST_TIMEOUT,
        )
        if r.status_code != 200 or r.json().get("code", 0) != 0:
            log.warning(f"Feishu push {r.status_code}: {r.text[:200]}")
            return False
    except Exception as ex:
        log.warning(f"Feishu err: {type(ex).__name__}")
        return False
    return True


def send_failure_alert(msg):
    """Rate-limited error notification so silent cron breakage is noticed."""
    now = time.time()
    state = {}
    if ALERT_STATE.exists():
        try:
            state = json.loads(ALERT_STATE.read_text(encoding="utf-8"))
        except Exception:
            pass
    if now - state.get("last_alert_ts", 0) < ALERT_COOLDOWN_SEC:
        log.warning(f"alert suppressed (cooldown): {msg[:150]}")
        return
    alert_text = f"vuln-monitor error\n\n{msg[:3800]}"
    any_configured = False
    if TG_BOT_TOKEN and TG_CHAT_IDS:
        any_configured = True
        for chat_id in TG_CHAT_IDS:
            try:
                SESS.post(
                    f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage",
                    json={"chat_id": chat_id, "text": alert_text, "disable_web_page_preview": True},
                    timeout=REQUEST_TIMEOUT,
                )
            except Exception as ex:
                log.error(f"alert push TG {chat_id} failed: {type(ex).__name__}")
    if WECOM_WEBHOOK_KEY:
        any_configured = True
        try:
            SESS.post(
                f"https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key={WECOM_WEBHOOK_KEY}",
                json={"msgtype": "text", "text": {"content": alert_text}},
                timeout=REQUEST_TIMEOUT,
            )
        except Exception as ex:
            log.error(f"alert push WeCom failed: {type(ex).__name__}")
    if DINGTALK_WEBHOOK_TOKEN:
        any_configured = True
        try:
            url = f"https://oapi.dingtalk.com/robot/send?access_token={DINGTALK_WEBHOOK_TOKEN}{_dingtalk_sign()}"
            SESS.post(url, json={"msgtype": "text", "text": {"content": alert_text}}, timeout=REQUEST_TIMEOUT)
        except Exception as ex:
            log.error(f"alert push DingTalk failed: {type(ex).__name__}")
    if FEISHU_WEBHOOK_URL:
        any_configured = True
        send_feishu("vuln-monitor error", [[{"tag": "text", "text": alert_text}]])
    if not any_configured:
        log.error(f"[ALERT-DRY] {msg[:500]}")
    state["last_alert_ts"] = now
    try:
        tmp = ALERT_STATE.with_suffix(".tmp")
        tmp.write_text(json.dumps(state), encoding="utf-8")
        os.replace(tmp, ALERT_STATE)
    except Exception as ex:
        log.warning(f"alert state save failed: {ex}")


