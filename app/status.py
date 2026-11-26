"""✓ / ✗ / ⏳ status tracking for every subsystem.

The legacy ✓/✗/⏳ vocabulary (OK, FAIL, PENDING) is preserved for backward
compatibility with existing API consumers and the status.log replay format.

A richer, evidence-based vocabulary is also supported:

* UNTESTED   - the tool/subsystem has never been executed
* RUNNING    - an execution is in progress
* VERIFIED   - the tool/subsystem executed successfully with real evidence
* FAILED     - the tool/subsystem executed and failed
* DEGRADED   - partially available or running in a reduced mode
* UNCONFIGURED - required configuration is absent (e.g. missing API key)

Each entry records last_test_time, latency_ms, source, result_classification
and a sanitized error so that statuses are always backed by execution
evidence, never by assumption.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from .errors import _safe_detail

# -- legacy vocabulary (backward compatible) ------------------------------
OK = "✓"
FAIL = "✗"
PENDING = "⏳"

# -- evidence-based vocabulary -------------------------------------------
UNTESTED = "UNTESTED"
RUNNING = "RUNNING"
VERIFIED = "VERIFIED"
FAILED = "FAILED"
DEGRADED = "DEGRADED"
UNCONFIGURED = "UNCONFIGURED"

#: Full set of statuses accepted by the tracker.
VALID_STATUSES = (OK, FAIL, PENDING, UNTESTED, RUNNING, VERIFIED, FAILED,
                  DEGRADED, UNCONFIGURED)

#: Legacy aliases accepted on write (mapped to the evidence vocabulary).
LEGACY_ALIASES = {
    OK: VERIFIED,
    FAIL: FAILED,
    PENDING: UNTESTED,
}

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
    last_test_time: Optional[str] = None
    latency_ms: Optional[float] = None
    source: Optional[str] = None
    result_classification: Optional[str] = None
    error: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"status": self.status}
        if self.detail:
            out["detail"] = self.detail
        out["updated_at"] = self.updated_at
        if self.last_test_time:
            out["last_test_time"] = self.last_test_time
        if self.latency_ms is not None:
            out["latency_ms"] = self.latency_ms
        if self.source:
            out["source"] = self.source
        if self.result_classification:
            out["result_classification"] = self.result_classification
        if self.error:
            out["error"] = self.error
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
                last_test_time=record.get("last_test_time"),
                latency_ms=record.get("latency_ms"),
                source=record.get("source"),
                result_classification=record.get("result_classification"),
                error=record.get("error"),
            )

    def set(self, key: str, status: str, detail: Optional[str] = None,
            *, last_test_time: Optional[str] = None, latency_ms: Optional[float] = None,
            source: Optional[str] = None, result_classification: Optional[str] = None,
            error: Optional[str] = None) -> StatusEntry:
        if status not in VALID_STATUSES:
            raise ValueError(f"invalid status {status!r}; expected one of {VALID_STATUSES}")
        entry = StatusEntry(
            status=status, detail=detail,
            last_test_time=last_test_time,
            latency_ms=latency_ms,
            source=source,
            result_classification=result_classification,
            error=error,
        )
        self.entries[key] = entry
        self._persist(key, entry)
        return entry

    def untested(self, key: str, detail: Optional[str] = None) -> StatusEntry:
        return self.set(key, UNTESTED, detail)

    def running(self, key: str, detail: Optional[str] = None) -> StatusEntry:
        return self.set(key, RUNNING, detail)

    def verified(self, key: str, detail: Optional[str] = None, *,
                 latency_ms: Optional[float] = None,
                 source: Optional[str] = None,
                 result_classification: Optional[str] = None) -> StatusEntry:
        return self.set(key, VERIFIED, detail, latency_ms=latency_ms,
                        source=source, result_classification=result_classification)

    def failed(self, key: str, detail: Optional[str] = None, *,
               error: Optional[str] = None,
               source: Optional[str] = None) -> StatusEntry:
        return self.set(key, FAILED, detail, error=error, source=source)

    def degraded(self, key: str, detail: Optional[str] = None, *,
                 error: Optional[str] = None) -> StatusEntry:
        return self.set(key, DEGRADED, detail, error=error)

    def unconfigured(self, key: str, detail: Optional[str] = None) -> StatusEntry:
        return self.set(key, UNCONFIGURED, detail)

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
        # Sanitize detail before persisting
        detail = record.get("detail")
        if detail and _safe_detail(detail) != detail:
            record["detail"] = "internal"
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
