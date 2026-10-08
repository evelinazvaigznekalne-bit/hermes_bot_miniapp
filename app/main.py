#!/usr/bin/env python3
"""Run the Mini App backend server.

Usage:
    python3 -m app.main server [--host H] [--port P]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

if __package__ in (None, ""):  # allow `python3 app/main.py`
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import get_settings  # noqa: E402
from app.logging_setup import get_logger, setup_logging  # noqa: E402
from app.service import WalletService  # noqa: E402
from app.webapp.server import run_server  # noqa: E402

log = get_logger()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Hermes Wallet Inspector server")
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    settings = get_settings()
    setup_logging(settings.log_dir)
    host = args.host or settings.host
    port = args.port or settings.port

    log.info("starting mini app server",
             extra={"component": "web", "status": "⏳",
                    "detail": f"{host}:{port}"})
    if not settings.telegram_configured:
        log.warning("TELEGRAM_BOT_TOKEN not set - Mini App initData "
                    "validation will fail closed",
                    extra={"component": "config", "status": "✗"})
    if not settings.memepol_configured:
        log.warning("MEMEPOL_API_KEY not set - puzzle analysis will report "
                    "an ERROR state, not a match",
                    extra={"component": "config", "status": "✗"})

    service = WalletService(settings)
    try:
        run_server(service, host, port, settings=settings)
    except OSError as exc:
        log.error("could not bind %s:%s (%s)", host, port, exc,
                  extra={"component": "web", "status": "✗"})
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
