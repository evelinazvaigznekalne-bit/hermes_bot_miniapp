#!/usr/bin/env python3
"""Refuse to start a second Telegram poller on the Hermes gateway's own bot.

Two `getUpdates` consumers on one token steal each other's updates. If this
project's `TELEGRAM_BOT_TOKEN` happens to be the same bot the Hermes gateway is
already polling, starting the bot would silently break the user's existing
Hermes Telegram integration.

The token is compared by SHA-256 digest, so neither value is ever printed or
logged — only whether the digests match.

Exit codes (consumed by scripts/run_bot.sh):
    0  safe to poll
    2  no token configured
    3  token belongs to the running Hermes gateway  (refuse)
    4  token rejected by Telegram (invalid/revoked) (refuse)
    5  could not verify (network/API unreachable)

Usage:
    python3 scripts/check_bot_token.py
    python3 scripts/check_bot_token.py --json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

PROJECT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_DIR))

OK, NO_TOKEN, GATEWAY_CLASH, REJECTED, UNVERIFIED = 0, 2, 3, 4, 5

#: Where the Hermes gateway keeps its own Telegram credentials.
#: Override with HERMES_GATEWAY_ENV_FILES (colon-separated) for testing.
def _gateway_env_files() -> tuple:
    override = os.environ.get("HERMES_GATEWAY_ENV_FILES")
    if override:
        return tuple(Path(p) for p in override.split(os.pathsep) if p)
    return (
        Path.home() / ".hermes" / ".env",
        Path.home() / ".hermes" / "secrets.env",
    )

TOKEN_KEYS = ("TELEGRAM_BOT_TOKEN", "TELEGRAM_TOKEN", "BOT_TOKEN")

#: Backwards-compatible alias for tests that monkeypatch this name.
GATEWAY_ENV_FILES = _gateway_env_files()


def digest(value: str) -> str:
    return hashlib.sha256(value.strip().encode()).hexdigest()


def _parse_env_file(path: Path) -> Dict[str, str]:
    out: Dict[str, str] = {}
    try:
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            out[key.strip()] = value.strip().strip("'\"")
    except OSError:
        pass
    return out


def gateway_token_digests() -> Dict[str, str]:
    """SHA-256 digests of any Telegram tokens the Hermes gateway owns."""
    found: Dict[str, str] = {}
    # prefer the module-level alias if a test has monkeypatched it
    for path in GATEWAY_ENV_FILES:
        env = _parse_env_file(path)
        for key in TOKEN_KEYS:
            value = env.get(key, "")
            if value and not value.startswith("YOUR_"):
                found.setdefault(digest(value), str(path))
    return found


def gateway_running() -> Optional[int]:
    """PID of a running `hermes gateway run` process, if any."""
    try:
        out = subprocess.run(
            ["ps", "aux"], capture_output=True, text=True, timeout=10,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    for line in out.splitlines():
        if "hermes" in line and "gateway" in line and "run" in line \
                and "grep" not in line:
            parts = line.split()
            if len(parts) > 1 and parts[1].isdigit():
                return int(parts[1])
    return None


def get_me(token: str) -> Tuple[Optional[dict], Optional[str]]:
    """Call getMe. Returns (result, error_string)."""
    import urllib.error
    import urllib.request

    url = f"https://api.telegram.org/bot{token}/getMe"
    try:
        with urllib.request.urlopen(url, timeout=15) as resp:
            payload = json.loads(resp.read())
        if payload.get("ok"):
            return payload.get("result") or {}, None
        return None, payload.get("description", "getMe returned ok=false")
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode()[:200]
        except Exception:  # pragma: no cover
            pass
        return None, f"HTTP {exc.code}: {body or exc.reason}"
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"


def check(*, token: Optional[str] = None, me: Optional[dict] = None,
          me_error: Optional[str] = None,
          gateway_digests: Optional[Dict[str, str]] = None,
          gateway_pid: Optional[int] = -1) -> dict:
    """Pure decision logic, injectable for tests."""
    if gateway_digests is None:
        gateway_digests = gateway_token_digests()
    if gateway_pid == -1:
        gateway_pid = gateway_running()

    if token is None:
        try:
            from app.config import get_settings, load_dotenv
            load_dotenv()
            token = get_settings().telegram_bot_token or ""
        except Exception:
            token = os.environ.get("TELEGRAM_BOT_TOKEN", "")

    report = {
        "token_present": bool(token),
        "gateway_pid": gateway_pid,
        "gateway_token_sources": len(gateway_digests),
        "same_as_gateway": False,
        "bot": None,
        "code": OK,
        "message": "",
    }

    if not token:
        report.update(code=NO_TOKEN,
                      message="TELEGRAM_BOT_TOKEN is not configured (or is a placeholder).")
        return report

    report["same_as_gateway"] = digest(token) in gateway_digests

    if report["same_as_gateway"]:
        where = gateway_digests.get(digest(token), "the Hermes gateway config")
        report.update(
            code=GATEWAY_CLASH,
            message=(
                "This token is the Hermes gateway's OWN bot (also present in "
                f"{where}). The gateway is already polling it"
                + (f" (pid {gateway_pid})" if gateway_pid else "")
                + ". Starting a second poller would steal its updates and break "
                "your existing Hermes Telegram. Create a NEW bot with @BotFather."
            ),
        )
        return report

    if me is None and me_error is None:
        me, me_error = get_me(token)

    if me_error is not None:
        # A 401/404 means the token itself is bad; anything else is transient.
        rejected = "401" in me_error or "404" in me_error or "Unauthorized" in me_error
        report.update(
            code=REJECTED if rejected else UNVERIFIED,
            message=(f"Telegram rejected this token: {me_error}" if rejected
                     else f"Could not verify the token: {me_error}"),
        )
        return report

    report["bot"] = {
        "id": me.get("id"),
        "username": me.get("username"),
        "first_name": me.get("first_name"),
    }
    report.update(code=OK,
                  message=f"Token is valid and unused elsewhere: @{me.get('username')} "
                          f"(id {me.get('id')})")
    return report


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    report = check()

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        mark = {OK: "✓", NO_TOKEN: "✗", GATEWAY_CLASH: "✗", REJECTED: "✗",
                UNVERIFIED: "⚠"}.get(report["code"], "?")
        print(f"{mark} {report['message']}")
        if report["gateway_pid"]:
            print(f"  · hermes gateway running (pid {report['gateway_pid']})")

    return report["code"]


if __name__ == "__main__":
    raise SystemExit(main())
