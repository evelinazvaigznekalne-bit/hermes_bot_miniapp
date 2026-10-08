"""✓ / ✗ / ⏳ status tracking for every subsystem."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

OK = "✓"
FAIL = "✗"
PENDING = "⏳"

VALID_STATUSES = (OK, FAIL, PENDING)

#: Canonical subsystem keys, mirroring ``config.yaml``.
SUBSYSTEMS = (
    "wallet_data",
    "assets_chains",
    "memepol_comparison",
    "puzzle_hints",
    "puzzle_images",
)


@dataclass
class StatusEntry:
    status: str = PENDING
    detail: Optional[str] = None
    updated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def as_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"status": self.status}
        if self.detail:
            out["detail"] = self.detail
        out["updated_at"] = self.updated_at
        return out


class StatusTracker:
    """Tracks and persists subsystem status.

    Errors are recorded in ``detail``; callers must pass already-redacted text.
    """

    def __init__(self, log_path: Optional[Path] = None):
        self.entries: Dict[str, StatusEntry] = {
            name: StatusEntry() for name in SUBSYSTEMS
        }
        self.log_path = Path(log_path) if log_path else None
        if self.log_path:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            self._replay()

    def _replay(self) -> None:
        """Restore the last-known status of each subsystem from ``log_path``.

        The log is append-only, so the last record for a key is its current
        state. Without this, ``compact()`` on a freshly built tracker returns
        the constructor default (PENDING) for every subsystem, and a status
        report cannot distinguish "never ran" from "ran and failed".

        A missing, empty, unreadable or malformed log leaves the default
        PENDING state in place; unparseable lines are skipped individually.
        """
        if not self.log_path.is_file():
            return
        try:
            lines = self.log_path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if not isinstance(record, dict):
                continue
            key = record.get("key")
            status = record.get("status")
            if key not in SUBSYSTEMS or status not in VALID_STATUSES:
                continue
            self.entries[key] = StatusEntry(
                status=status,
                detail=record.get("detail"),
                updated_at=record.get("updated_at") or StatusEntry().updated_at,
            )

    def set(self, key: str, status: str, detail: Optional[str] = None) -> StatusEntry:
        if status not in VALID_STATUSES:
            raise ValueError(f"invalid status {status!r}; expected one of {VALID_STATUSES}")
        entry = StatusEntry(status=status, detail=detail)
        self.entries[key] = entry
        self._persist(key, entry)
        return entry

    def pending(self, key: str, detail: Optional[str] = None) -> StatusEntry:
        return self.set(key, PENDING, detail)

    def ok(self, key: str, detail: Optional[str] = None) -> StatusEntry:
        return self.set(key, OK, detail)

    def fail(self, key: str, detail: Optional[str] = None) -> StatusEntry:
        return self.set(key, FAIL, detail)

    def _persist(self, key: str, entry: StatusEntry) -> None:
        if not self.log_path:
            return
        record = {"key": key, **entry.as_dict()}
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")

    def snapshot(self) -> Dict[str, Dict[str, Any]]:
        return {k: v.as_dict() for k, v in self.entries.items()}

    def compact(self) -> Dict[str, str]:
        """``{subsystem: ✓|✗|⏳}`` - the form used in reports."""
        return {k: v.status for k, v in self.entries.items()}


def summarize(tracker: StatusTracker) -> str:
    """Human-readable one-line summary of all subsystems."""
    return "  ".join(f"{k}={v}" for k, v in tracker.compact().items())
