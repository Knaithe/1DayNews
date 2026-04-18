#!/usr/bin/env bash
# One-shot deploy for Debian/Ubuntu/RHEL. Run as root.
set -euo pipefail

APP_DIR=/opt/vuln-monitor
APP_USER=vuln
SYSTEMD_DIR=/etc/systemd/system
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ "$EUID" -ne 0 ]; then
    echo "run as root" >&2
    exit 1
fi

# 1. user + dir
id "$APP_USER" &>/dev/null || useradd --system --home-dir "$APP_DIR" --shell /usr/sbin/nologin "$APP_USER"
mkdir -p "$APP_DIR"

# 2. code
install -o "$APP_USER" -g "$APP_USER" -m 644 "$SRC_DIR/vuln_monitor.py" "$APP_DIR/vuln_monitor.py"
install -o "$APP_USER" -g "$APP_USER" -m 644 "$SRC_DIR/requirements.txt" "$APP_DIR/requirements.txt"

if [ ! -f "$APP_DIR/.env" ]; then
    install -o "$APP_USER" -g "$APP_USER" -m 600 "$SRC_DIR/env.example" "$APP_DIR/.env"
    echo ">>> created $APP_DIR/.env from template — EDIT IT NOW and re-run."
    exit 2
fi
chmod 600 "$APP_DIR/.env"
chown "$APP_USER:$APP_USER" "$APP_DIR/.env"

# 3. venv + deps
if [ ! -d "$APP_DIR/venv" ]; then
    python3 -m venv "$APP_DIR/venv"
fi
"$APP_DIR/venv/bin/pip" install --quiet --upgrade pip
"$APP_DIR/venv/bin/pip" install --quiet -r "$APP_DIR/requirements.txt"
chown -R "$APP_USER:$APP_USER" "$APP_DIR"

# 4. systemd
install -m 644 "$SRC_DIR/vuln-monitor.service" "$SYSTEMD_DIR/vuln-monitor.service"
install -m 644 "$SRC_DIR/vuln-monitor.timer"   "$SYSTEMD_DIR/vuln-monitor.timer"
systemctl daemon-reload
systemctl enable --now vuln-monitor.timer

# 5. one immediate cache-warm run (dry vs real decided by .env)
echo ">>> first run (warm cache)..."
sudo -u "$APP_USER" "$APP_DIR/venv/bin/python" "$APP_DIR/vuln_monitor.py" || true

echo ">>> deployed."
echo "    status: systemctl status vuln-monitor.timer"
echo "    logs:   journalctl -u vuln-monitor.service -f"
echo "    next:   systemctl list-timers vuln-monitor.timer"
