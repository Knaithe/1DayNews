#!/usr/bin/env bash
# Uninstall vuln-monitor. Reverses deploy.sh. Run as root.
#
# Usage:
#   sudo bash uninstall.sh              # keep data (db/log/env)
#   sudo bash uninstall.sh --purge      # delete everything
#
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/vuln-monitor}"
APP_USER="${APP_USER:-vuln}"
SYSTEMD_DIR=/etc/systemd/system
PURGE=false
[ "${1:-}" = "--purge" ] && PURGE=true

if [ "$EUID" -ne 0 ]; then
    echo "run as root (sudo bash uninstall.sh)" >&2
    exit 1
fi

# ---------- 1. stop & disable systemd ----------
echo ">>> [1/4] stopping systemd units ..."
systemctl disable --now vuln-monitor.timer   2>/dev/null || true
systemctl disable --now vuln-monitor.service 2>/dev/null || true
systemctl disable --now vuln-web.service     2>/dev/null || true
rm -f "$SYSTEMD_DIR/vuln-monitor.service" "$SYSTEMD_DIR/vuln-monitor.timer" "$SYSTEMD_DIR/vuln-web.service"
systemctl daemon-reload

# ---------- 2. remove app directory ----------
if $PURGE; then
    echo ">>> [2/4] purging $APP_DIR (all data) ..."
    rm -rf "$APP_DIR"
else
    echo ">>> [2/4] removing code, keeping data ..."
    # keep: .env, vuln_cache.db*, vuln_monitor.log*, vuln_alert_state.json
    find "$APP_DIR" -mindepth 1 \
        ! -name '.env' \
        ! -name 'vuln_cache.db*' \
        ! -name 'vuln_cache.json*' \
        ! -name 'vuln_monitor.log*' \
        ! -name 'vuln_alert_state.json*' \
        -delete 2>/dev/null || true
    echo "    data kept at $APP_DIR (use --purge to delete)"
fi

# ---------- 3. remove system user ----------
if id "$APP_USER" &>/dev/null; then
    echo ">>> [3/4] removing system user '$APP_USER' ..."
    userdel "$APP_USER" 2>/dev/null || true
else
    echo ">>> [3/4] user '$APP_USER' not found, skipping"
fi

# ---------- 4. done ----------
echo ">>> [4/4] done."
if $PURGE; then
    echo "  fully purged."
else
    echo "  uninstalled. data preserved at $APP_DIR"
    echo "  to fully remove: sudo rm -rf $APP_DIR"
fi
