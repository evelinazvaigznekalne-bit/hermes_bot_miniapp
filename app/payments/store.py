"""Idempotency ledger for captured PayPal orders.

An order id may only ever produce ONE entitlement grant. Without this, a
replayed capture request (or a retry after a network timeout) would push the
entitlement's ``granted_at`` forward and, for a time-limited tier, silently
extend it for free.

The ledger is a small JSON file next to the entitlement store. It is not
authoritative for access control -- :class:`app.access.EntitlementStore` is --
it only answers "have I already credited this order?".
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, Optional

from ..logging_setup import get_logger

log = get_logger()


class ProcessedOrderStore:
    """Records which PayPal order ids have already been credited."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._cache: Optional[Dict[str, Dict[str, Any]]] = None

    # -- io ---------------------------------------------------------------
    def _load(self) -> Dict[str, Dict[str, Any]]:
        if self._cache is not None:
            return self._cache
        data: Dict[str, Dict[str, Any]] = {}
        if self.path.exists():
            try:
                raw = json.loads(self.path.read_text(encoding="utf-8"))
                entries = raw.get("orders") or {}
                if isinstance(entries, dict):
                    data = entries
            except (OSError, json.JSONDecodeError) as exc:
                log.warning("processed-order ledger unreadable: %s", exc,
                            extra={"component": "payments", "status": "✗"})
        self._cache = data
        return data

    def _save(self, data: Dict[str, Dict[str, Any]]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"orders": data}
        self.path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        try:
            self.path.chmod(0o600)
        except OSError:  # pragma: no cover - best effort on odd filesystems
            pass
        self._cache = data

    # -- api --------------------------------------------------------------
    def seen(self, order_id: str) -> bool:
        return (order_id or "") in self._load()

    def get(self, order_id: str) -> Optional[Dict[str, Any]]:
        return self._load().get(order_id or "")

    def record(self, order_id: str, *, address: str, amount: str,
               currency: str, tier: str, days: Optional[int]) -> None:
        data = dict(self._load())
        data[order_id] = {
            "address": address,
            "amount": amount,
            "currency": currency,
            "tier": tier,
            "days": days,
            "credited_at": time.time(),
        }
        self._save(data)

    def all(self) -> Dict[str, Dict[str, Any]]:
        return dict(self._load())
