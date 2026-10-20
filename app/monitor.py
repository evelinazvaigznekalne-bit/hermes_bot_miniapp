"""Puzzle monitoring daemon.

Watches puzzle transactions and logs status changes:
  • Address balance changes
  • New puzzle transactions
  • Puzzle solved events

This is a READ-ONLY monitor. It never broadcasts transactions or moves funds.
Run with: python3 -m app.monitor
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .logging_setup import get_logger
from .puzzles.bitcoin_puzzle import KNOWN_PUZZLES, identify_puzzle_address

log = get_logger()

__all__ = ["Monitor", "MonitorEvent", "run_monitor"]


class MonitorEvent:
    """A single monitoring event."""

    def __init__(self, kind: str, puzzle_number: int, address: str,
                 detail: str = "", timestamp: Optional[str] = None):
        self.kind = kind
        self.puzzle_number = puzzle_number
        self.address = address
        self.detail = detail
        self.timestamp = timestamp or datetime.now(timezone.utc).isoformat()

    def as_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "puzzle_number": self.puzzle_number,
            "address": self.address,
            "detail": self.detail,
            "timestamp": self.timestamp,
        }


class Monitor:
    """Watches puzzle transactions for changes."""

    def __init__(self, log_path: Optional[Path] = None,
                 interval_sec: int = 900):
        self.log_path = log_path or Path("logs/monitor.log")
        self.interval_sec = interval_sec
        self.events: List[MonitorEvent] = []
        self._last_state: Dict[str, Dict[str, Any]] = {}

    def check_all(self) -> List[MonitorEvent]:
        """Check all known puzzle addresses for changes."""
        events = []
        for addr, puzzle in KNOWN_PUZZLES.items():
            event = self._check_address(addr, puzzle)
            if event:
                events.append(event)
        self.events.extend(events)
        if events:
            self._persist(events)
        return events

    def _check_address(self, addr: str, puzzle) -> Optional[MonitorEvent]:
        """Check a single puzzle address."""
        # In production, this would query mempool.space or similar
        # For now, we just log that we checked
        state_key = addr
        last = self._last_state.get(state_key, {})

        # Placeholder: in production, fetch balance and compare
        current_balance = 0  # Would be fetched from API

        if last.get("balance") != current_balance:
            event = MonitorEvent(
                kind="balance_change",
                puzzle_number=puzzle.puzzle_number,
                address=addr,
                detail=f"Balance changed: {last.get('balance', 0)} -> {current_balance}",
            )
            self._last_state[state_key] = {"balance": current_balance}
            return event

        self._last_state[state_key] = {"balance": current_balance}
        return None

    def _persist(self, events: List[MonitorEvent]) -> None:
        """Append events to the monitor log."""
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.log_path, "a") as f:
            for event in events:
                f.write(json.dumps(event.as_dict()) + "\n")

    def status(self) -> Dict[str, Any]:
        """Get current monitoring status."""
        return {
            "watching": len(KNOWN_PUZZLES),
            "interval_sec": self.interval_sec,
            "events_logged": len(self.events),
            "last_check": datetime.now(timezone.utc).isoformat(),
            "log_path": str(self.log_path),
            "puzzles": [
                {
                    "puzzle_number": p.puzzle_number,
                    "address": addr[:16] + "…" + addr[-8:],
                    "amount_btc": p.amount_btc,
                }
                for addr, p in KNOWN_PUZZLES.items()
            ],
        }


def run_monitor(interval_sec: int = 900) -> None:
    """Run the monitor in a loop."""
    monitor = Monitor(interval_sec=interval_sec)
    log.info("monitor started", extra={"component": "monitor"})
    while True:
        events = monitor.check_all()
        if events:
            for event in events:
                log.info("monitor event",
                         extra={"component": "monitor", **event.as_dict()})
        time.sleep(interval_sec)


if __name__ == "__main__":
    run_monitor()
