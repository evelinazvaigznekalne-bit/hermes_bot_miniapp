"""Per-user state: history and puzzle progress.

Keeps a small, bounded record of what each Telegram user has looked at, so the
bot can answer "/history" and "/progress" without re-querying chains.

Deliberate limits:

  * **No wallet material, ever.** Only public addresses, command names, and
    timestamps. There is no field that could hold a key or a seed.
  * **Bounded.** Each user keeps at most ``MAX_HISTORY`` entries; the oldest
    are dropped. The whole file is capped at ``MAX_USERS`` users.
  * **Local.** A JSON file next to the other state, mode 600. No external
    service, no analytics endpoint.
  * **No cross-user reads.** Every accessor is keyed by the caller's own
    Telegram id.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from .logging_setup import get_logger

log = get_logger()

MAX_HISTORY = 50
MAX_USERS = 5000
MAX_PROGRESS = 200

#: Commands worth recording. Read-only lookups only.
TRACKED = frozenset({"inspect", "puzzles", "assets", "catalog", "item"})


@dataclass
class HistoryEntry:
    at: float
    command: str
    address: str = ""
    detail: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "at": self.at,
            "when": time.strftime("%Y-%m-%d %H:%M", time.localtime(self.at)),
            "command": self.command,
            "address": self.address,
            "detail": self.detail,
        }


@dataclass
class ProgressEntry:
    sku: str
    title: str = ""
    status: str = "open"
    note: str = ""
    updated_at: float = field(default_factory=time.time)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "sku": self.sku,
            "title": self.title,
            "status": self.status,
            "note": self.note,
            "when": time.strftime("%Y-%m-%d %H:%M",
                                  time.localtime(self.updated_at)),
        }


@dataclass
class UserRecord:
    user_id: str
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    history: List[HistoryEntry] = field(default_factory=list)
    progress: Dict[str, ProgressEntry] = field(default_factory=dict)
    scan_count: int = 0
    inspect_count: int = 0
    puzzle_count: int = 0

    def as_dict(self) -> Dict[str, Any]:
        return {
            "user_id": self.user_id,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "history": [h.as_dict() for h in self.history],
            "progress": [p.as_dict() for p in self.progress.values()],
            "scan_count": self.scan_count,
            "inspect_count": self.inspect_count,
            "puzzle_count": self.puzzle_count,
        }


class UserStore:
    """Local JSON store of per-user history and puzzle progress."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._cache: Optional[Dict[str, UserRecord]] = None

    # -- io ---------------------------------------------------------------
    def _load(self) -> Dict[str, UserRecord]:
        if self._cache is not None:
            return self._cache
        out: Dict[str, UserRecord] = {}
        if self.path.exists():
            try:
                raw = json.loads(self.path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                log.warning("user store unreadable: %s", exc,
                            extra={"component": "users", "status": "✗"})
                self._cache = out
                return out

            # Per-entry parsing: one malformed row must not discard the whole
            # record, or a single bad timestamp would wipe a user's history.
            for uid, rec in (raw.get("users") or {}).items():
                rec = rec or {}
                history: List[HistoryEntry] = []
                for h in (rec.get("history") or []):
                    try:
                        history.append(HistoryEntry(
                            at=float(h.get("at") or 0),
                            command=str(h.get("command") or ""),
                            address=str(h.get("address") or ""),
                            detail=str(h.get("detail") or ""),
                        ))
                    except (AttributeError, TypeError, ValueError):
                        continue  # skip the bad row, keep the rest

                progress: Dict[str, ProgressEntry] = {}
                for p in (rec.get("progress") or []):
                    try:
                        sku = str(p.get("sku") or "")
                        if not sku:
                            continue
                        progress[sku] = ProgressEntry(
                            sku=sku,
                            title=str(p.get("title") or ""),
                            status=str(p.get("status") or "open"),
                            note=str(p.get("note") or ""),
                            updated_at=float(p.get("updated_at") or 0),
                        )
                    except (AttributeError, TypeError, ValueError):
                        continue

                try:
                    first = float(rec.get("first_seen") or 0)
                    last = float(rec.get("last_seen") or 0)
                except (TypeError, ValueError):
                    first = last = 0.0

                out[str(uid)] = UserRecord(
                    user_id=str(uid), first_seen=first, last_seen=last,
                    history=history, progress=progress,
                    scan_count=int(rec.get("scan_count") or 0),
                    inspect_count=int(rec.get("inspect_count") or 0),
                    puzzle_count=int(rec.get("puzzle_count") or 0),
                )
        self._cache = out
        return out

    def _save(self, data: Dict[str, UserRecord]) -> None:
        # Cap the number of users, keeping the most recently active.
        if len(data) > MAX_USERS:
            keep = sorted(data.values(), key=lambda r: r.last_seen,
                          reverse=True)[:MAX_USERS]
            data = {r.user_id: r for r in keep}
        payload = {"users": {uid: r.as_dict() for uid, r in data.items()}}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        try:
            self.path.chmod(0o600)
        except OSError:  # pragma: no cover
            pass
        self._cache = data

    # -- api --------------------------------------------------------------
    def touch(self, user_id: Any) -> UserRecord:
        """Mark the user as seen, creating the record if needed."""
        uid = str(user_id)
        data = dict(self._load())
        rec = data.get(uid) or UserRecord(user_id=uid)
        rec.last_seen = time.time()
        if not rec.first_seen:
            rec.first_seen = rec.last_seen
        data[uid] = rec
        self._save(data)
        return rec

    def record(self, user_id: Any, *, command: str, address: str = "",
               detail: str = "") -> None:
        """Append a history entry. Only TRACKED commands are stored."""
        cmd = str(command or "").lstrip("/").lower()
        if cmd not in TRACKED:
            return
        uid = str(user_id)
        data = dict(self._load())
        rec = data.get(uid) or UserRecord(user_id=uid)
        rec.last_seen = time.time()
        rec.history.append(HistoryEntry(at=time.time(), command=cmd,
                                        address=str(address or ""),
                                        detail=str(detail or "")[:120]))
        if len(rec.history) > MAX_HISTORY:
            rec.history = rec.history[-MAX_HISTORY:]
        data[uid] = rec
        self._save(data)

    def history(self, user_id: Any, *, limit: int = 10) -> List[HistoryEntry]:
        rec = self._load().get(str(user_id))
        if not rec:
            return []
        return list(reversed(rec.history))[:max(1, limit)]

    def set_progress(self, user_id: Any, *, sku: str, title: str = "",
                     status: str = "open", note: str = "") -> ProgressEntry:
        uid = str(user_id)
        data = dict(self._load())
        rec = data.get(uid) or UserRecord(user_id=uid)
        rec.last_seen = time.time()
        entry = ProgressEntry(sku=str(sku), title=str(title),
                              status=str(status), note=str(note)[:200])
        rec.progress[str(sku)] = entry
        if len(rec.progress) > MAX_PROGRESS:
            oldest = sorted(rec.progress.values(),
                            key=lambda p: p.updated_at)[:len(rec.progress) - MAX_PROGRESS]
            for old in oldest:
                rec.progress.pop(old.sku, None)
        data[uid] = rec
        self._save(data)
        return entry

    def progress(self, user_id: Any) -> List[ProgressEntry]:
        rec = self._load().get(str(user_id))
        if not rec:
            return []
        return sorted(rec.progress.values(), key=lambda p: p.updated_at,
                      reverse=True)

    def increment(self, user_id: Any, *, field: str) -> int:
        """Increment a counter and return the new value."""
        uid = str(user_id)
        data = dict(self._load())
        rec = data.get(uid) or UserRecord(user_id=uid)
        rec.last_seen = time.time()
        if not rec.first_seen:
            rec.first_seen = rec.last_seen
        current = getattr(rec, field, 0)
        setattr(rec, field, current + 1)
        data[uid] = rec
        self._save(data)
        return current + 1

    def stats(self, user_id: Any) -> Dict[str, Any]:
        rec = self._load().get(str(user_id))
        if not rec:
            return {"history": 0, "progress": 0, "scan_count": 0,
                    "inspect_count": 0, "puzzle_count": 0,
                    "first_seen": None, "last_seen": None}
        return {
            "history": len(rec.history),
            "progress": len(rec.progress),
            "scan_count": rec.scan_count,
            "inspect_count": rec.inspect_count,
            "puzzle_count": rec.puzzle_count,
            "first_seen": time.strftime("%Y-%m-%d",
                                        time.localtime(rec.first_seen)),
            "last_seen": time.strftime("%Y-%m-%d %H:%M",
                                       time.localtime(rec.last_seen)),
        }


# ------------------------------------------------------- wallet storage ----

WALLET_FILE = Path(__file__).parent.parent / "data" / "wallets.json"


def _load_wallets() -> Dict[str, List[Dict[str, Any]]]:
    """Load all wallets from disk."""
    if not WALLET_FILE.is_file():
        return {}
    try:
        return json.loads(WALLET_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save_wallets(data: Dict[str, List[Dict[str, Any]]]) -> None:
    """Save wallets to disk."""
    WALLET_FILE.parent.mkdir(parents=True, exist_ok=True)
    WALLET_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def add_wallet(address: str, label: str, session_token: str) -> Dict[str, Any]:
    """Add a wallet to the user's account."""
    if not address:
        raise ValueError("address is required")
    if not session_token:
        raise ValueError("session_token is required")

    wallets = _load_wallets()
    user_wallets = wallets.setdefault(session_token, [])

    for w in user_wallets:
        if w["address"].lower() == address.lower():
            raise ValueError("wallet already exists")

    user_wallets.append({
        "address": address,
        "label": label or "Wallet",
        "added_at": time.time(),
    })
    _save_wallets(wallets)

    return {"wallets": user_wallets}


def list_wallets(session_token: str) -> Dict[str, Any]:
    """List user's wallets."""
    if not session_token:
        raise ValueError("session_token is required")

    wallets = _load_wallets()
    user_wallets = wallets.get(session_token, [])
    return {"wallets": user_wallets}
