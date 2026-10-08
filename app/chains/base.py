"""Chain provider abstraction.

A provider is responsible for exactly one address family. Adding a new chain
means subclassing :class:`ChainProvider`, implementing ``validate`` and
``fetch_assets``, and registering it - no call site changes required.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..addresses import detect_address_kind


@dataclass
class Asset:
    """A single asset balance held by an address."""

    symbol: str
    amount: float
    raw: str
    decimals: int
    kind: str = "native"          # native | token
    contract: Optional[str] = None
    name: Optional[str] = None
    usd_value: Optional[float] = None

    def as_dict(self) -> Dict[str, Any]:
        out = {
            "symbol": self.symbol,
            "amount": self.amount,
            "raw": self.raw,
            "decimals": self.decimals,
            "kind": self.kind,
        }
        if self.contract:
            out["contract"] = self.contract
        if self.name:
            out["name"] = self.name
        if self.usd_value is not None:
            out["usd_value"] = round(self.usd_value, 2)
        return out


@dataclass
class AssetReport:
    """Result of querying one address on one chain."""

    address: str
    chain: str
    family: str
    status: str = "⏳"
    assets: List[Asset] = field(default_factory=list)
    balance_native: Optional[float] = None
    native_symbol: str = ""
    explorer_url: Optional[str] = None
    meta: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    detail: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "address": self.address,
            "chain": self.chain,
            "family": self.family,
            "status": self.status,
            "native_symbol": self.native_symbol,
            "assets": [a.as_dict() for a in self.assets],
        }
        if self.balance_native is not None:
            out["balance_native"] = self.balance_native
        if self.explorer_url:
            out["explorer_url"] = self.explorer_url
        if self.meta:
            out["meta"] = self.meta
        if self.errors:
            out["errors"] = self.errors
        if self.detail:
            out["detail"] = self.detail
        return out


class ChainProvider(abc.ABC):
    """Base class for a chain/address-family provider."""

    #: canonical chain id, e.g. ``ethereum`` or ``bitcoin``
    chain: str = ""
    #: address family handled, e.g. ``evm`` or ``bitcoin``
    family: str = ""
    #: human-readable label
    label: str = ""
    #: symbol of the native asset
    native_symbol: str = ""
    #: number of decimals of the native asset
    native_decimals: int = 18

    @abc.abstractmethod
    def validate(self, address: str) -> str:
        """Return the normalised address or raise AddressValidationError."""

    def accepts(self, address: str) -> bool:
        """True when this provider can handle the given address."""
        try:
            self.validate(address)
            return True
        except Exception:
            return False

    @abc.abstractmethod
    def fetch_assets(self, address: str, *, limit: int = 50) -> AssetReport:
        """Read-only fetch of native + token balances."""

    def explorer_url(self, address: str) -> Optional[str]:
        return None


class ChainRegistry:
    """Ordered registry of providers keyed by chain id and family."""

    def __init__(self) -> None:
        self._by_chain: Dict[str, ChainProvider] = {}
        self._by_family: Dict[str, ChainProvider] = {}
        self._order: List[str] = []

    def register(self, provider: ChainProvider) -> ChainProvider:
        self._by_chain[provider.chain] = provider
        if provider.family not in self._by_family:
            self._by_family[provider.family] = provider
        if provider.chain not in self._order:
            self._order.append(provider.chain)
        return provider

    def get(self, chain: str) -> Optional[ChainProvider]:
        return self._by_chain.get(chain)

    def for_family(self, family: str) -> Optional[ChainProvider]:
        return self._by_family.get(family)

    def resolve(self, address: str) -> Optional[ChainProvider]:
        """Pick a provider based on the address format alone."""
        kind = detect_address_kind(address)
        if kind is None:
            return None
        return self._by_family.get(kind)

    def chains(self) -> List[str]:
        return list(self._order)

    def describe(self) -> List[Dict[str, Any]]:
        return [
            {
                "chain": p.chain,
                "label": p.label,
                "family": p.family,
                "native_symbol": p.native_symbol,
            }
            for p in (self._by_chain[c] for c in self._order)
        ]
