#!/usr/bin/env python3
"""Interactive setup for vuln-monitor's local config file.

Writes tokens to an XDG-compliant path (cross-platform):
    Linux / macOS: $XDG_CONFIG_HOME/vuln-monitor/config.json
                   (default: ~/.config/vuln-monitor/config.json)
    Windows:       %APPDATA%\\vuln-monitor\\config.json

Priority at runtime: env var > this config file > empty (dry mode).

For server (systemd) deployment, deploy.sh writes /opt/vuln-monitor/.env
instead — do NOT use this script on the server.

Usage:
    python scripts/configure.py          # interactive, prompts for each field
    python scripts/configure.py --show   # print current config (tokens masked)
    python scripts/configure.py --path   # print config file path and exit
"""
import argparse
import json
import os
import platform
import sys
from pathlib import Path


def config_path() -> Path:
    if platform.system() == "Windows":
        base = os.getenv("APPDATA") or str(Path.home())
    else:
        base = os.getenv("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "vuln-monitor" / "config.json"


def mask(val: str) -> str:
    if not val:
        return "(empty)"
    if len(val) <= 10:
        return "***"
    return f"{val[:6]}...{val[-4:]}"


def load(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"WARN: cannot parse existing config ({e}); starting fresh", file=sys.stderr)
        return {}


def save(path: Path, cfg: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(cfg, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)
    # chmod 600 on POSIX; no-op on Windows (ACLs differ, but APPDATA is per-user already)
    if platform.system() != "Windows":
        try:
            os.chmod(path, 0o600)
        except Exception as e:
            print(f"WARN: could not chmod 600 {path}: {e}", file=sys.stderr)


def prompt(label: str, current: str, required: bool = False) -> str:
    hint = f" [current: {mask(current)}]" if current else ""
    req = " (required)" if required and not current else " (optional)" if not required else ""
    while True:
        try:
            raw = input(f"  {label}{req}{hint}: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\ncancelled."); sys.exit(1)
        if raw:
            return raw
        if current or not required:
            return current
        print("    value required; try again or Ctrl+C to abort")


def do_interactive(path: Path) -> None:
    existing = load(path)
    if existing:
        print(f"editing existing config: {path}\n")
    else:
        print(f"creating new config:     {path}\n")

    cfg = {
        "tg_bot_token": prompt("Telegram Bot Token",       existing.get("tg_bot_token", ""),  required=True),
        "tg_chat_id":   prompt("Telegram Chat/Channel ID", existing.get("tg_chat_id", ""),    required=True),
        "gh_token":     prompt("GitHub PAT",               existing.get("gh_token", ""),      required=False),
        "https_proxy":  prompt("HTTPS proxy",              existing.get("https_proxy", ""),   required=False),
    }

    save(path, cfg)
    mode_note = "" if platform.system() == "Windows" else " (mode 600)"
    print(f"\nsaved to {path}{mode_note}")
    print("\nnext: python src/vuln_monitor.py")


def do_show(path: Path) -> None:
    if not path.exists():
        print(f"no config at {path}")
        return
    cfg = load(path)
    print(f"path: {path}\n")
    for k in ("tg_bot_token", "tg_chat_id", "gh_token", "https_proxy"):
        v = cfg.get(k, "")
        # chat_id and proxy are not secrets — show them in full
        if k in ("tg_chat_id", "https_proxy"):
            print(f"  {k:15s} = {v or '(empty)'}")
        else:
            print(f"  {k:15s} = {mask(v)}")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--show", action="store_true", help="print current config (tokens masked)")
    p.add_argument("--path", action="store_true", help="print config file path and exit")
    args = p.parse_args()

    path = config_path()

    if args.path:
        print(path)
        return
    if args.show:
        do_show(path)
        return
    do_interactive(path)


if __name__ == "__main__":
    main()
