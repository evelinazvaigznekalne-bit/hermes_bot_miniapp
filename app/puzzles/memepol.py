"""MemePol API client abstraction.

The API key is read exclusively from the environment (``MEMEPOL_API_KEY``)
and sent in an ``Authorization`` header - never in a URL, never logged,
never echoed in an error message. When no key is configured the client
reports ``configured = False`` and callers degrade to an explicit
``UNCONFIGURED`` state rather than guessing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..config import Settings, is_placeholder
from ..errors import PuzzleAPIError
from ..http import HttpClient
from ..logging_setup import get_logger, register_secret

log = get_logger()


@dataclass
class PuzzleEntry:
    """A single authorized puzzle record from MemePol."""

    id: str
    title: str = ""
    chain: Optional[str] = None
    criteria: Dict[str, Any] = field(default_factory=dict)
    hints: List[str] = field(default_factory=list)
    images: List[str] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)
    note: Optional[str] = None

    @classmethod
    def from_api(cls, payload: Dict[str, Any]) -> "PuzzleEntry":
        pid = str(payload.get("id") or payload.get("puzzle_id") or "unknown")
        hints = payload.get("hints") or []
        images = payload.get("images") or payload.get("image_refs") or []
        if isinstance(hints, str):
            hints = [hints]
        if isinstance(images, str):
            images = [images]
        criteria = payload.get("criteria")
        if not isinstance(criteria, dict):
            criteria = {}
            # tolerate a flat shape
            for key in ("address", "min_balance", "balance", "symbol",
                        "chain", "token"):
                if key in payload:
                    criteria[key] = payload[key]
        return cls(
            id=pid,
            title=str(payload.get("title") or payload.get("name") or ""),
            chain=payload.get("chain") or criteria.get("chain"),
            criteria=criteria,
            hints=[str(h) for h in hints],
            images=[str(i) for i in images],
            raw=payload,
            note=payload.get("note"),
        )


class MemePolClient:
    """Read-only client for the MemePol puzzle dataset."""

    def __init__(self, settings: Settings, *, http: Optional[HttpClient] = None):
        self.settings = settings
        self.base_url = (settings.memepol_base_url or "").rstrip("/")
        self._api_key = settings.memepol_api_key
        self.http = http or HttpClient(timeout=settings.http_timeout)
        if self._api_key and not is_placeholder(self._api_key):
            register_secret(self._api_key)

    # -- capability -------------------------------------------------------
    @property
    def configured(self) -> bool:
        return bool(self.base_url) and not is_placeholder(self._api_key)

    def _headers(self) -> Dict[str, str]:
        """Build auth headers.

        The header name and prefix are configurable because providers differ:
        generic REST APIs want ``Authorization: Bearer <key>`` while some
        catalogs (e.g. apis.io) want a bare ``X-API-Key: <key>``.
        """
        if not self.configured:
            raise PuzzleAPIError(
                "MemePol API is not configured; set MEMEPOL_API_KEY "
                "(and MEMEPOL_BASE_URL) in the environment"
            )
        prefix = (self.settings.memepol_auth_prefix or "").strip()
        value = f"{prefix} {self._api_key}".strip() if prefix else self._api_key
        return {
            self.settings.memepol_auth_header or "Authorization": value,
            "Accept": "application/json",
        }

    def ping(self) -> Dict[str, Any]:
        """Probe the configured endpoint and report whether the key is accepted.

        Never returns the key. Useful for verifying credentials without
        guessing at the puzzle payload shape.
        """
        if not self.configured:
            raise PuzzleAPIError("MemePol API is not configured")
        url = f"{self.base_url}/puzzles"
        try:
            data = self.http.get_json(
                url, provider="memepol", params={"limit": 1},
                headers=self._headers(),
            )
        except Exception as exc:
            return {"ok": False, "endpoint": url,
                    "detail": f"{type(exc).__name__}: {exc}"}
        return {"ok": True, "endpoint": url,
                "detail": "endpoint reachable and key accepted",
                "payload_keys": sorted(data)[:10] if isinstance(data, dict) else None}

    # -- calls ------------------------------------------------------------
    def list_puzzles(self, *, limit: int = 200) -> List[PuzzleEntry]:
        """Fetch the authorized puzzle dataset."""
        if not self.configured:
            raise PuzzleAPIError("MemePol API is not configured")
        url = f"{self.base_url}/puzzles"
        data = self.http.get_json(
            url, provider="memepol", params={"limit": limit},
            headers=self._headers(),
        )
        if isinstance(data, dict):
            items = data.get("puzzles") or data.get("data") or data.get("items") or []
        elif isinstance(data, list):
            items = data
        else:
            raise PuzzleAPIError("unexpected MemePol payload shape")
        entries = []
        for item in items:
            if isinstance(item, dict):
                entries.append(PuzzleEntry.from_api(item))
        log.info(
            "memepol puzzles fetched",
            extra={"component": "puzzles.memepol", "status": "✓",
                   "provider": "memepol", "detail": f"{len(entries)} entries"},
        )
        return entries

    def get_puzzle(self, puzzle_id: str) -> PuzzleEntry:
        if not self.configured:
            raise PuzzleAPIError("MemePol API is not configured")
        url = f"{self.base_url}/puzzles/{puzzle_id}"
        data = self.http.get_json(url, provider="memepol", headers=self._headers())
        if not isinstance(data, dict):
            raise PuzzleAPIError("unexpected MemePol puzzle payload")
        return PuzzleEntry.from_api(data)
