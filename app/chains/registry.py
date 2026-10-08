"""Provider registry wiring.

Adding a chain = subclass a provider + register it here (or call
``register`` at runtime). Call sites resolve by address format, so they never
need to change.
"""

from __future__ import annotations

from typing import Optional

from .base import Asset, AssetReport, ChainProvider, ChainRegistry
from .bitcoin import BitcoinProvider
from .evm import BLOCKSCOUT_BASES, EvmProvider

__all__ = [
    "Asset",
    "AssetReport",
    "ChainProvider",
    "ChainRegistry",
    "EvmProvider",
    "BitcoinProvider",
    "build_registry",
]


def build_registry(*, rpc_urls: Optional[tuple] = None, http=None,
                   btc_api_base: str = "https://mempool.space/api") -> ChainRegistry:
    """Construct the default registry (EVM chains + Bitcoin)."""
    registry = ChainRegistry()
    for chain, symbol in (
        ("ethereum", "ETH"),
        ("polygon", "POL"),
        ("base", "ETH"),
        ("optimism", "ETH"),
        ("arbitrum", "ETH"),
        ("gnosis", "xDAI"),
    ):
        registry.register(
            EvmProvider(
                chain=chain,
                http=http,
                # only Ethereum mainnet uses the public RPC fallback list
                rpc_urls=rpc_urls if chain == "ethereum" else (),
                native_symbol=symbol,
                blockscout_base=BLOCKSCOUT_BASES.get(chain),
            )
        )
    registry.register(BitcoinProvider(http=http, api_base=btc_api_base))
    return registry
