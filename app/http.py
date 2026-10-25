"""Small HTTP client with retries, backoff, and redaction-safe errors.

Only read-only GET/POST calls are made. No authentication material is ever
placed in a URL - API keys travel in headers so they cannot leak through
proxy logs or error strings.

Uses urllib.request (stdlib) instead of requests — requests has DNS and
connection issues on Termux/Android that urllib/curl don't have.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any, Optional

from .errors import HttpError
from .logging_setup import get_logger
from .errors import _safe_exception

log = get_logger()

RETRYABLE_STATUS = {408, 425, 429, 500, 502, 503, 504}


class HttpClient:
    """Thin wrapper over :mod:`urllib.request` with bounded retries."""

    def __init__(self, *, timeout: float = 12.0, max_retries: int = 2,
                 backoff: float = 0.5, session: Optional[Any] = None):
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff = backoff
        # session parameter kept for API compatibility but ignored
        self._headers = {
            "User-Agent": "hermes-bot-miniapp/1.0",
            "Connection": "close",
        }

    # -- internals --------------------------------------------------------
    def _sleep(self, attempt: int, retry_after: Optional[str]) -> None:
        delay = self.backoff * (2 ** attempt)
        if retry_after:
            try:
                delay = max(delay, float(retry_after))
            except (TypeError, ValueError):
                pass
        time.sleep(min(delay, 30.0))

    def _request(self, method: str, url: str, *, provider: str,
                 params=None, headers=None, json_body=None) -> Any:
        last_error: Optional[str] = None
        for attempt in range(self.max_retries + 1):
            try:
                # Build request
                req_headers = dict(self._headers)
                if headers:
                    req_headers.update(headers)

                data = None
                if json_body is not None:
                    data = json.dumps(json_body).encode("utf-8")
                    req_headers["Content-Type"] = "application/json"

                req = urllib.request.Request(
                    url, data=data, headers=req_headers, method=method
                )

                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    status = resp.getcode()
                    body = resp.read().decode("utf-8", errors="replace")

            except urllib.error.HTTPError as exc:
                status = exc.code
                body = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
                last_error = _safe_exception(exc)
                log.warning(
                    "http transport error",
                    extra={"provider": provider, "status": "⏳", "detail": last_error},
                )
                if attempt < self.max_retries and status in RETRYABLE_STATUS:
                    self._sleep(attempt, None)
                    continue
                raise HttpError(
                    f"{provider} request failed after {attempt + 1} attempts",
                    status_code=status,
                    detail=last_error,
                ) from exc

            except (urllib.error.URLError, OSError) as exc:
                last_error = _safe_exception(exc)
                log.warning(
                    "http transport error",
                    extra={"provider": provider, "status": "⏳", "detail": last_error},
                )
                if attempt < self.max_retries:
                    self._sleep(attempt, None)
                    continue
                raise HttpError(
                    f"{provider} request failed after {attempt + 1} attempts",
                    detail=last_error,
                ) from exc

            if status in RETRYABLE_STATUS and attempt < self.max_retries:
                log.warning(
                    "http retryable status",
                    extra={"provider": provider, "status": "⏳",
                           "detail": f"HTTP {status}"},
                )
                self._sleep(attempt, None)
                continue

            if status >= 400:
                raise HttpError(
                    f"{provider} returned HTTP {status}",
                    status_code=status,
                    detail=body[:300] if body else None,
                )

            try:
                return json.loads(body) if body else {}
            except json.JSONDecodeError as exc:
                raise HttpError(
                    f"{provider} returned non-JSON response",
                    status_code=status,
                    detail=body[:200] if body else None,
                ) from exc

        raise HttpError(f"{provider} request failed", detail=last_error)

    # -- public API -------------------------------------------------------
    def get_json(self, url: str, *, provider: str, params=None, headers=None) -> Any:
        return self._request("GET", url, provider=provider, params=params,
                             headers=headers)

    def post_json(self, url: str, *, provider: str, json_body=None,
                  headers=None) -> Any:
        return self._request("POST", url, provider=provider, json_body=json_body,
                             headers=headers)
