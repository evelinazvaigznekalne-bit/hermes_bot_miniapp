"""Catalog API — the marketplace surface, over the real puzzle corpus.

Mirrors the *shape* of a marketplace backend (categories, tabs, config, item
listings, item detail) without any of the inventory problems: the catalog is
the authorized open-crypto-puzzles corpus plus your own private corpus, both of
which you already hold.

Design rules:

  * **Tier-gated.** Every listing path runs through :mod:`app.access`, so a
    free user sees the same 3-item preview the rest of the app gives them, and
    an anonymous caller sees counts but no titles.
  * **The private corpus never leaks.** It is a separate source, merged only
    for OWNER, and non-owner responses contain no trace of it — not titles, not
    counts, not existence.
  * **No enumeration by paging.** The visible-item cap is enforced on the whole
    result set, not per page, so a free user cannot walk the corpus one page at
    a time.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from .access import TIER_LIMITS, Tier, tier_summary
from .logging_setup import get_logger

log = get_logger()

#: Status buckets exposed as catalog tabs. Order matters — it is display order.
TAB_ORDER = ("open", "watch", "solved", "dead-end")

TAB_LABELS = {
    "open": "Open",
    "watch": "Watch",
    "solved": "Solved",
    "dead-end": "Dead ends",
    "all": "All",
}

#: Category labels for chains seen in the corpus.
CHAIN_LABELS = {
    "bitcoin": "Bitcoin",
    "ethereum": "Ethereum",
    "arweave": "Arweave",
    "base": "Base",
    "litecoin": "Litecoin",
    "solana": "Solana",
    "unknown": "Other",
}


def _status_of(entry) -> str:
    raw = getattr(entry, "raw", None) or {}
    status = str(raw.get("status") or "open").strip().lower()
    return status if status in TAB_ORDER else "open"


def _chain_of(entry) -> str:
    criteria = getattr(entry, "criteria", None) or {}
    chain = criteria.get("chain") if isinstance(criteria, dict) else None
    return str(chain or "unknown").strip().lower()


@dataclass
class CatalogItem:
    """One listing in the catalog."""

    sku: str
    title: str
    category: str
    status: str
    hint_count: int
    image_count: int
    address_count: int
    private: bool = False

    def as_dict(self, *, tier: Tier, detail: bool = False,
                entry=None) -> Dict[str, Any]:
        """Serialize for ``tier``. Higher tiers get strictly more fields."""
        limits = TIER_LIMITS[tier]
        out: Dict[str, Any] = {
            "sku": self.sku,
            "title": self.title,
            "category": self.category,
            "category_label": CHAIN_LABELS.get(self.category, self.category),
            "status": self.status,
        }
        if not detail:
            out["hint_count"] = self.hint_count
            out["image_count"] = self.image_count if limits.include_images else None
            out["locked"] = {} if limits.allows_all_puzzles() else {
                "full_detail": "available on a paid tier"
            }
            return out

        # -- detail view: apply the per-item hint/image caps -----------------
        out["address_count"] = self.address_count
        hints: List[str] = list(getattr(entry, "hints", None) or [])
        images: List[str] = list(getattr(entry, "images", None) or [])
        locked: Dict[str, Any] = {}

        if limits.puzzles_visible == 0:
            hints, images = [], []
            out["locked"] = {"detail": "sign in with a wallet to view"}
            out["hints"] = []
            out["images"] = []
            out["hint_count"] = self.hint_count
            return out

        if limits.hints_per_puzzle >= 0 and len(hints) > limits.hints_per_puzzle:
            locked["hidden_hints"] = len(hints) - limits.hints_per_puzzle
            hints = hints[:limits.hints_per_puzzle]
        if not limits.include_images and images:
            locked["images"] = "available on a paid tier"
            images = []

        out["hints"] = hints
        out["images"] = images
        out["hint_count"] = self.hint_count
        out["locked"] = locked
        return out


@dataclass
class Catalog:
    """Builds catalog views over one or more puzzle sources."""

    public_entries: Sequence[Any] = field(default_factory=tuple)
    private_entries: Sequence[Any] = field(default_factory=tuple)

    # -- selection --------------------------------------------------------
    def _entries_for(self, tier: Tier) -> List[Any]:
        """Public corpus always; private corpus only for OWNER."""
        entries = list(self.public_entries)
        if TIER_LIMITS[tier].include_private:
            entries = entries + list(self.private_entries)
        return entries

    @staticmethod
    def _item(entry, *, private: bool = False) -> CatalogItem:
        raw = getattr(entry, "raw", None) or {}
        criteria = getattr(entry, "criteria", None) or {}
        addresses = criteria.get("addresses") if isinstance(criteria, dict) else None
        if not addresses:
            addresses = raw.get("addresses") or []
            if isinstance(addresses, str):
                addresses = [addresses]
        return CatalogItem(
            sku=str(getattr(entry, "id", "") or "unknown"),
            title=str(getattr(entry, "title", "") or getattr(entry, "id", "")),
            category=_chain_of(entry),
            status=_status_of(entry),
            hint_count=len(getattr(entry, "hints", None) or []),
            image_count=len(getattr(entry, "images", None) or []),
            address_count=len(addresses or []),
            private=private,
        )

    # -- config -----------------------------------------------------------
    def config(self, *, settings=None) -> Dict[str, Any]:
        """Feature flags — the shape a marketplace frontend expects."""
        paypal = getattr(settings, "paypal_configured", False) if settings else False
        return {
            "config": {
                "marketEnabled": True,
                "marketAdminOnly": False,
                "catalogEnabled": True,
                "catalogAdminOnly": False,
                "cartEnabled": False,
                "purchasesEnabled": bool(paypal),
                "favoritesEnabled": True,
                "maintenanceEnabled": False,
                "requireSecretCode": False,
                "tiersEnabled": True,
            },
            "seo": {
                "siteName": "hermes",
                "title": "hermes - wallet inspector and puzzle catalog",
                "description": (
                    "Read-only wallet inspection, secret-shape detection, and an "
                    "authorized open-crypto-puzzles catalog."
                ),
                "allowIndexing": False,
            },
        }

    # -- facets -----------------------------------------------------------
    def categories(self, tier: Tier) -> Dict[str, Any]:
        """Chain categories with counts. Anonymous callers get counts only."""
        counts: Dict[str, int] = {}
        for entry in self._entries_for(tier):
            cat = _chain_of(entry)
            counts[cat] = counts.get(cat, 0) + 1
        limits = TIER_LIMITS[tier]
        cats = [
            {
                "id": cat,
                "label": CHAIN_LABELS.get(cat, cat),
                "count": n if limits.puzzles_visible != 0 else None,
            }
            for cat, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
        ]
        return {"categories": cats, "tier": tier.value}

    def tabs(self, tier: Tier) -> Dict[str, Any]:
        """Status tabs with counts."""
        counts: Dict[str, int] = {}
        for entry in self._entries_for(tier):
            st = _status_of(entry)
            counts[st] = counts.get(st, 0) + 1
        limits = TIER_LIMITS[tier]
        tabs = [{
            "id": "all",
            "label": TAB_LABELS["all"],
            "count": (sum(counts.values())
                      if limits.puzzles_visible != 0 else None),
        }]
        for st in TAB_ORDER:
            tabs.append({
                "id": st,
                "label": TAB_LABELS[st],
                "count": counts.get(st, 0) if limits.puzzles_visible != 0 else None,
            })
        return {"tabs": tabs, "tier": tier.value}

    # -- listings ---------------------------------------------------------
    def items(self, tier: Tier, *, category: Optional[str] = None,
              tab: Optional[str] = None, limit: int = 20,
              offset: int = 0) -> Dict[str, Any]:
        """Tier-gated listing.

        The visibility cap is applied to the FILTERED SET before paging, so a
        free user cannot enumerate the corpus by walking offsets.
        """
        limits = TIER_LIMITS[tier]
        entries = self._entries_for(tier)

        if category:
            want = str(category).strip().lower()
            entries = [e for e in entries if _chain_of(e) == want]
        if tab and str(tab).strip().lower() not in ("all", ""):
            want_tab = str(tab).strip().lower()
            entries = [e for e in entries if _status_of(e) == want_tab]

        total_matching = len(entries)

        # Cap BEFORE paging — this is the anti-enumeration property.
        if not limits.allows_all_puzzles():
            entries = entries[:max(0, limits.puzzles_visible)]

        visible_total = len(entries)
        limit = max(1, min(int(limit), 100))
        offset = max(0, int(offset))
        page = entries[offset:offset + limit]

        items = [self._item(e).as_dict(tier=tier) for e in page]

        locked: Dict[str, Any] = {}
        if limits.puzzles_visible == 0:
            locked["catalog"] = "sign in with a wallet to view listings"
        elif not limits.allows_all_puzzles() and total_matching > visible_total:
            locked["hidden_items"] = total_matching - visible_total
            locked["full_corpus"] = "available on a paid tier"

        return {
            "items": items,
            "count": len(items),
            "visible_total": visible_total,
            "matched_total": (total_matching if limits.puzzles_visible != 0
                              else None),
            "offset": offset,
            "limit": limit,
            "tier": tier.value,
            "entitlements": tier_summary(tier),
            "locked": locked,
        }

    def item_detail(self, tier: Tier, sku: str) -> Optional[Dict[str, Any]]:
        """Single listing with hints/images, capped per tier."""
        want = str(sku or "").strip()
        if not want:
            return None
        for entry in self._entries_for(tier):
            if str(getattr(entry, "id", "")) == want:
                item = self._item(entry)
                out = item.as_dict(tier=tier, detail=True, entry=entry)
                out["tier"] = tier.value
                out["entitlements"] = tier_summary(tier)
                return out
        return None

    # -- summary ----------------------------------------------------------
    def summary(self, tier: Tier) -> Dict[str, Any]:
        entries = self._entries_for(tier)
        limits = TIER_LIMITS[tier]
        return {
            "tier": tier.value,
            "corpus": len(self.public_entries),
            "private_corpus": (len(self.private_entries)
                               if limits.include_private else None),
            "visible": (len(entries) if limits.puzzles_visible != 0 else 0),
            "entitlements": tier_summary(tier),
        }
