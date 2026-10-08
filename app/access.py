"""Access tiers and entitlements.

Four tiers, resolved from the verified session:

    ANONYMOUS  no signature — public chain data only, no puzzle data at all
    VERIFIED   wallet ownership proven — free tier, limited puzzle preview
    PAID       entitlement granted — full public puzzle corpus
    OWNER      the operator — everything, including the private corpus

The private corpus is a **separate file** that is never merged into the public
one, so it cannot leak through a bug in the public filtering path. Non-owner
responses contain no trace of it: not titles, not counts, not existence.

Entitlements are stored locally as a JSON map of address -> record. Granting is
an explicit operator action (`app.cli grant`), so no payment processor is
required to run this — sell however you like, then grant.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from .errors import ValidationError
from .logging_setup import get_logger

log = get_logger()


class Tier(str, Enum):
    ANONYMOUS = "anonymous"
    VERIFIED = "verified"
    PAID = "paid"
    OWNER = "owner"

    @property
    def rank(self) -> int:
        return {
            Tier.ANONYMOUS: 0, Tier.VERIFIED: 1, Tier.PAID: 2, Tier.OWNER: 3,
        }[self]


@dataclass(frozen=True)
class Limits:
    """What a tier may see."""

    puzzles_visible: int          # 0 = none; -1 = all
    hints_per_puzzle: int         # -1 = all
    include_images: bool
    include_private: bool         # the owner-only corpus
    bulk_lookup: bool
    history: bool

    def allows_all_puzzles(self) -> bool:
        return self.puzzles_visible < 0


#: Tier -> limits. Tune in one place.
TIER_LIMITS: Dict[Tier, Limits] = {
    Tier.ANONYMOUS: Limits(
        puzzles_visible=0, hints_per_puzzle=0, include_images=False,
        include_private=False, bulk_lookup=False, history=False,
    ),
    Tier.VERIFIED: Limits(
        puzzles_visible=3, hints_per_puzzle=1, include_images=False,
        include_private=False, bulk_lookup=False, history=False,
    ),
    Tier.PAID: Limits(
        puzzles_visible=-1, hints_per_puzzle=-1, include_images=True,
        include_private=False, bulk_lookup=True, history=True,
    ),
    Tier.OWNER: Limits(
        puzzles_visible=-1, hints_per_puzzle=-1, include_images=True,
        include_private=True, bulk_lookup=True, history=True,
    ),
}


@dataclass
class Entitlement:
    address: str
    tier: str = "paid"
    granted_at: float = 0.0
    expires_at: Optional[float] = None
    note: str = ""

    def is_active(self, now: Optional[float] = None) -> bool:
        if self.expires_at is None:
            return True
        return (now if now is not None else time.time()) < self.expires_at

    def as_dict(self) -> Dict[str, Any]:
        return {
            "address": self.address, "tier": self.tier,
            "granted_at": self.granted_at, "expires_at": self.expires_at,
            "note": self.note, "active": self.is_active(),
        }


class EntitlementStore:
    """Local JSON map of address -> entitlement. No external service.

    Always reads from disk. Deliberately uncached: this file decides who gets
    paid access, and it is written by a *different process* (``app.cli grant``)
    while the server runs. An mtime-based cache is not reliable here — this
    filesystem has one-second timestamp granularity, so a grant and a revoke
    inside the same second are indistinguishable by mtime, and the server would
    keep serving stale access. The file is a few KB; re-reading it per request
    costs nothing and cannot go stale.
    """

    def __init__(self, path: Path):
        self.path = Path(path)

    # -- io ---------------------------------------------------------------
    def _load(self) -> Dict[str, Entitlement]:
        out: Dict[str, Entitlement] = {}
        if self.path.exists():
            try:
                raw = json.loads(self.path.read_text())
                for addr, rec in (raw.get("entitlements") or {}).items():
                    out[addr.lower()] = Entitlement(
                        address=addr.lower(),
                        tier=rec.get("tier", "paid"),
                        granted_at=rec.get("granted_at", 0.0),
                        expires_at=rec.get("expires_at"),
                        note=rec.get("note", ""),
                    )
            except (OSError, json.JSONDecodeError) as exc:
                log.warning("entitlement store unreadable: %s", exc,
                            extra={"component": "access", "status": "✗"})
        return out

    def _save(self, data: Dict[str, Entitlement]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"entitlements": {a: e.as_dict() for a, e in data.items()}}
        self.path.write_text(json.dumps(payload, indent=2))
        try:
            self.path.chmod(0o600)
        except OSError:  # pragma: no cover
            pass

    # -- api --------------------------------------------------------------
    def get(self, address: str) -> Optional[Entitlement]:
        rec = self._load().get((address or "").lower())
        if rec and rec.is_active():
            return rec
        return None

    def grant(self, address: str, *, tier: str = "paid",
              days: Optional[int] = None, note: str = "") -> Entitlement:
        addr = (address or "").strip()
        if not addr:
            raise ValidationError("address is required")
        if tier not in ("paid", "owner", "verified"):
            raise ValidationError("tier must be one of: paid, owner, verified")
        now = time.time()
        rec = Entitlement(
            address=addr.lower(), tier=tier, granted_at=now,
            expires_at=(now + days * 86400) if days else None, note=note,
        )
        data = dict(self._load())
        data[addr.lower()] = rec
        self._save(data)
        return rec

    def revoke(self, address: str) -> bool:
        data = dict(self._load())
        removed = data.pop((address or "").lower(), None) is not None
        if removed:
            self._save(data)
        return removed

    def all(self) -> List[Entitlement]:
        return sorted(self._load().values(), key=lambda e: e.granted_at)


def resolve_tier(*, verified_address: Optional[str],
                 owner_addresses: List[str],
                 store: Optional[EntitlementStore] = None) -> Tier:
    """Resolve the caller's tier.

    OWNER wins over any entitlement. An address in the owner list is the
    operator, so it never depends on the store being present.
    """
    if not verified_address:
        return Tier.ANONYMOUS

    addr = verified_address.lower()
    owners = {a.strip().lower() for a in owner_addresses if a and a.strip()}
    if addr in owners:
        return Tier.OWNER

    if store is not None:
        rec = store.get(addr)
        if rec is not None:
            if rec.tier == "owner":
                return Tier.OWNER
            if rec.tier == "paid":
                return Tier.PAID
            if rec.tier == "verified":
                return Tier.VERIFIED

    return Tier.VERIFIED


def apply_limits(analysis: Dict[str, Any], tier: Tier) -> Dict[str, Any]:
    """Filter a puzzle-analysis payload down to what ``tier`` may see.

    Operates on the serialized analysis dict. Returns a new dict; the input is
    not mutated. Non-permitted data is removed, not merely hidden, and a
    ``locked`` block tells the client what a higher tier would add — without
    revealing any of the actual content.
    """
    limits = TIER_LIMITS[tier]
    out = dict(analysis)

    # Only real matches belong in `matches`. The analyzer records EVERY
    # evaluated entry (with verdict NONE for non-matches) so callers can audit
    # what was checked — but exposing that list enumerates the corpus, and a
    # free user could read out puzzle titles one page at a time. Keep the
    # evaluated COUNT, drop the non-matching records.
    real = [m for m in (out.get("matches") or [])
            if str(m.get("verdict", "")).lower() in ("exact_match", "possible_match")]
    evaluated = out.get("evaluated")
    if evaluated is None:
        evaluated = len(out.get("matches") or [])

    matches = list(real)
    hints = list(out.get("hints") or [])
    images = list(out.get("images") or [])
    notes = list(out.get("notes") or [])

    total_matches = len(matches)

    if limits.puzzles_visible == 0:
        out["matches"] = []
        out["hints"] = []
        out["images"] = []
        out["notes"] = []
    else:
        if not limits.allows_all_puzzles():
            matches = matches[:limits.puzzles_visible]
        if limits.hints_per_puzzle >= 0:
            # truncate each match's own hint list as well as the aggregate
            trimmed = []
            for m in matches:
                m = dict(m)
                mh = list(m.get("hints") or [])
                if len(mh) > limits.hints_per_puzzle:
                    m["hints"] = mh[:limits.hints_per_puzzle]
                    m["hints_truncated"] = True
                trimmed.append(m)
            matches = trimmed
            hints = hints[:limits.hints_per_puzzle]
        if not limits.include_images:
            images = []
        out["matches"] = matches
        out["hints"] = hints
        out["images"] = images
        out["notes"] = notes if limits.allows_all_puzzles() else []

    # never leak the existence of the private corpus to a non-owner
    if not limits.include_private:
        out.pop("private_count", None)

    out["evaluated"] = evaluated

    locked: Dict[str, Any] = {}
    # only advertise a locked capability when there is actually content to lock
    if total_matches:
        if total_matches > len(out["matches"]):
            locked["hidden_matches"] = total_matches - len(out["matches"])
        if not limits.allows_all_puzzles():
            locked["full_corpus"] = "available on a paid tier"
        if not limits.include_images and images:
            locked["images"] = "available on a paid tier"
        if limits.hints_per_puzzle >= 0 and hints:
            locked["full_hints"] = "available on a paid tier"

    out["tier"] = tier.value
    out["locked"] = locked
    out["redacted"] = bool(locked)
    return out


def tier_summary(tier: Tier) -> Dict[str, Any]:
    lim = TIER_LIMITS[tier]
    return {
        "tier": tier.value,
        "puzzles_visible": lim.puzzles_visible,
        "hints_per_puzzle": lim.hints_per_puzzle,
        "images": lim.include_images,
        "private_corpus": lim.include_private,
        "bulk_lookup": lim.bulk_lookup,
        "history": lim.history,
    }
