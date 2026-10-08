#!/usr/bin/env python3
"""Run the Telegram bot backend (long polling).

Usage:
    python3 -m app.bot_main            # poll forever
    python3 -m app.bot_main --once     # process one batch of updates, then exit
    python3 -m app.bot_main --selftest # render command replies without a token
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Optional

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import get_settings  # noqa: E402
from app.errors import ConfigError  # noqa: E402
from app.logging_setup import get_logger, setup_logging  # noqa: E402
from app.service import WalletService  # noqa: E402
from app.telegram.bot import TelegramBot  # noqa: E402

log = get_logger()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Hermes Wallet Inspector bot")
    parser.add_argument("--once", action="store_true",
                        help="process a single batch of updates and exit")
    parser.add_argument("--selftest", action="store_true",
                        help="render replies locally without contacting Telegram")
    parser.add_argument("--address", default=None,
                        help="address to use for the local self-test")
    return parser


def assert_safe_to_poll(settings) -> Optional[str]:
    """Return an error string if starting a poller would be unsafe.

    Two `getUpdates` consumers on one token steal each other's updates. The
    Hermes gateway polls its own bot continuously, so reusing that token here
    would silently break the user's existing Hermes Telegram. Tokens are
    compared by SHA-256 digest — no secret is read out or logged.
    """
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        from scripts.check_bot_token import GATEWAY_CLASH, check

        report = check(token=settings.telegram_bot_token or "")
    except Exception as exc:  # pragma: no cover - never block on our own bug
        log.warning("token safety check unavailable: %s", exc,
                    extra={"component": "telegram.bot", "status": "⏳"})
        return None

    if report["code"] == GATEWAY_CLASH:
        return report["message"]
    return None


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    settings = get_settings()
    setup_logging(settings.log_dir)
    service = WalletService(settings)
    bot = TelegramBot(service, settings=settings)

    if args.selftest:
        print(bot.handle_command(0, "/start"))
        print()
        print(bot.handle_command(0, "/status"))
        print()
        print(bot.handle_command(0, "/chains"))
        if args.address:
            print()
            print(bot.handle_command(0, f"/inspect {args.address}"))
        return 0

    # Guard every path into polling, including a direct `python3 -m app.bot_main`
    # that bypasses scripts/run_bot.sh.
    if os.environ.get("SKIP_TOKEN_CHECK") != "1":
        unsafe = assert_safe_to_poll(settings)
        if unsafe:
            log.error("refusing to poll: %s", unsafe,
                      extra={"component": "telegram.bot", "status": "✗"})
            print(f"✗ {unsafe}", file=sys.stderr)
            print("Create a NEW bot with @BotFather; do not reuse the gateway's.",
                  file=sys.stderr)
            return 3

    try:
        bot.poll_forever(max_iterations=1 if args.once else None)
    except ConfigError as exc:
        log.error("bot cannot start: %s", exc.message,
                  extra={"component": "telegram.bot", "status": "✗"})
        print(f"✗ {exc.message}", file=sys.stderr)
        print("Set TELEGRAM_BOT_TOKEN in .env, then re-run.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
