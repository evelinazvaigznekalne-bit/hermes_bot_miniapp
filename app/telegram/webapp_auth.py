"""Validation of Telegram Mini App ``initData``.

Implements the documented HMAC-SHA256 scheme:

    secret_key = HMAC_SHA256(key="WebAppData", msg=bot_token)
    hash       = HMAC_SHA256(key=secret_key,  msg=data_check_string)

where ``data_check_string`` is the alphabetically sorted ``key=value`` pairs
(excluding ``hash``) joined by newlines.

The bot token is never logged. An empty/placeholder token makes validation
fail closed rather than silently accepting data.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from urllib.parse import parse_qsl

from ..config import is_placeholder
from ..errors import SignatureError

#: Telegram recommends rejecting initData older than this (seconds).
MAX_AUTH_AGE_SECONDS = 24 * 60 * 60


@dataclass
class TelegramUser:
    id: int
    first_name: str = ""
    last_name: str = ""
    username: Optional[str] = None
    language_code: Optional[str] = None
    is_premium: bool = False
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def display_name(self) -> str:
        name = " ".join(p for p in (self.first_name, self.last_name) if p).strip()
        return name or (self.username or str(self.id))

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "TelegramUser":
        return cls(
            id=int(payload.get("id", 0)),
            first_name=payload.get("first_name") or "",
            last_name=payload.get("last_name") or "",
            username=payload.get("username"),
            language_code=payload.get("language_code"),
            is_premium=bool(payload.get("is_premium")),
            raw=payload,
        )


def _data_check_string(pairs) -> str:
    return "\n".join(f"{k}={v}" for k, v in sorted(pairs) if k != "hash")


def compute_init_data_hash(init_data: str, bot_token: str) -> str:
    """Return the expected ``hash`` for the given initData string."""
    pairs = parse_qsl(init_data, keep_blank_values=True, strict_parsing=False)
    check_string = _data_check_string(pairs)
    secret_key = hmac.new(b"WebAppData", bot_token.encode("utf-8"),
                          hashlib.sha256).digest()
    return hmac.new(secret_key, check_string.encode("utf-8"),
                    hashlib.sha256).hexdigest()


def validate_init_data(init_data: str, bot_token: Optional[str], *,
                       max_age: int = MAX_AUTH_AGE_SECONDS,
                       now: Optional[int] = None) -> TelegramUser:
    """Validate Mini App initData and return the authenticated user.

    Raises :class:`SignatureError` when the token is missing/placeholder, the
    hash does not match, or the payload is stale.
    """
    if not init_data or not isinstance(init_data, str):
        raise SignatureError("missing Telegram initData")
    if is_placeholder(bot_token):
        raise SignatureError(
            "TELEGRAM_BOT_TOKEN is not configured; cannot validate initData"
        )

    pairs = dict(parse_qsl(init_data, keep_blank_values=True))
    provided_hash = pairs.get("hash")
    if not provided_hash:
        raise SignatureError("initData is missing the 'hash' field")

    expected = compute_init_data_hash(init_data, bot_token)
    if not hmac.compare_digest(expected, provided_hash):
        raise SignatureError("initData hash mismatch")

    auth_date = pairs.get("auth_date")
    if auth_date:
        try:
            age = (now if now is not None else int(time.time())) - int(auth_date)
        except ValueError as exc:
            raise SignatureError("invalid auth_date in initData") from exc
        if age > max_age:
            raise SignatureError("initData has expired; reopen the Mini App")
        if age < -300:
            raise SignatureError("initData auth_date is in the future")

    user_raw = pairs.get("user")
    if not user_raw:
        raise SignatureError("initData does not contain a user object")
    try:
        user_payload = json.loads(user_raw)
    except ValueError as exc:
        raise SignatureError("initData user object is not valid JSON") from exc
    if not isinstance(user_payload, dict) or "id" not in user_payload:
        raise SignatureError("initData user object is malformed")
    return TelegramUser.from_dict(user_payload)


def build_init_data(user: Dict[str, Any], bot_token: str, *,
                    auth_date: Optional[int] = None,
                    extra: Optional[Dict[str, str]] = None) -> str:
    """Construct a signed initData string (used by tests and local dev)."""
    from urllib.parse import urlencode

    params: Dict[str, str] = {
        "auth_date": str(auth_date if auth_date is not None else int(time.time())),
        "user": json.dumps(user, separators=(",", ":")),
    }
    if extra:
        params.update(extra)
    check_string = "\n".join(f"{k}={v}" for k, v in sorted(params.items()))
    secret_key = hmac.new(b"WebAppData", bot_token.encode("utf-8"),
                          hashlib.sha256).digest()
    digest = hmac.new(secret_key, check_string.encode("utf-8"),
                      hashlib.sha256).hexdigest()
    params["hash"] = digest
    return urlencode(params)
