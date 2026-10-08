"""Structured JSON logging with mandatory secret redaction.

Every log record passes through :class:`RedactingFilter`, which scrubs any
value registered via :func:`register_secret`. This makes it structurally hard
to leak a token into ``logs/``.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional

_SECRETS: set = set()


def register_secret(value: Optional[str]) -> None:
    """Register a literal secret so it is replaced anywhere it appears."""
    if value and len(value) >= 6:
        _SECRETS.add(value)


class RedactingFilter(logging.Filter):
    """Replaces registered secret literals with ``<redacted>``."""

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        try:
            message = record.getMessage()
        except Exception:  # pragma: no cover - defensive
            return True
        scrubbed = message
        for secret in _SECRETS:
            if secret in scrubbed:
                scrubbed = scrubbed.replace(secret, "<redacted>")
        if scrubbed != message:
            record.msg = scrubbed
            record.args = ()
        return True


class JsonFormatter(logging.Formatter):
    """One JSON object per line."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key in ("status", "component", "detail", "address", "chain", "provider"):
            value = getattr(record, key, None)
            if value is not None:
                payload[key] = value
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def setup_logging(log_dir: Path, *, level: int = logging.INFO,
                  stream: bool = True) -> logging.Logger:
    """Configure the root logger to write JSON lines to ``logs/app.log``.

    The log directory is created automatically (requirement 8).
    """
    log_dir = Path(log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("hermes_miniapp")
    logger.setLevel(level)
    logger.handlers.clear()
    logger.propagate = False

    formatter = JsonFormatter()
    redactor = RedactingFilter()

    file_handler = logging.FileHandler(log_dir / "app.log", encoding="utf-8")
    file_handler.setFormatter(formatter)
    file_handler.addFilter(redactor)
    logger.addHandler(file_handler)

    if stream:
        stream_handler = logging.StreamHandler(sys.stderr)
        stream_handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
        stream_handler.addFilter(redactor)
        logger.addHandler(stream_handler)

    return logger


def get_logger() -> logging.Logger:
    return logging.getLogger("hermes_miniapp")


def redact_secrets_from_env(vars_: Iterable[str]) -> None:
    """Register the current values of the given env vars as secrets."""
    import os

    for name in vars_:
        register_secret(os.environ.get(name))
