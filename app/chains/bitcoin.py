"""Bitcoin provider (public addresses only).

Deliberately separate from the EVM provider: a Bitcoin address is validated
with base58check/bech32 rules and queried through mempool.space. An EVM
address is rejected here and vice-versa (requirement 6).
"""

from __future__ import annotations

from typing import Optional

from ..addresses import validate_bitcoin_address
from ..errors import ChainAPIError
from ..http import HttpClient
from ..logging_setup import get_logger
from .base import Asset, AssetReport, ChainProvider

log = get_logger()

SATOSHIS_PER_BTC = 100_000_000


class BitcoinProvider(ChainProvider):
    family = "bitcoin"
    chain = "bitcoin"
    label = "Bitcoin"
    native_symbol = "BTC"
    native_decimals = 8

    def __init__(self, *, http: Optional[HttpClient] = None,
                 api_base: str = "https://mempool.space/api"):
        self.http = http or HttpClient()
        self.api_base = api_base.rstrip("/")

    def validate(self, address: str) -> str:
        return validate_bitcoin_address(address).address

    def explorer_url(self, address: str) -> str:
        return f"https://mempool.space/address/{address}"

    def fetch_assets(self, address: str, *, limit: int = 50) -> AssetReport:
        info = validate_bitcoin_address(address)
        address = info.address
        report = AssetReport(
            address=address,
            chain=self.chain,
            family=self.family,
            native_symbol=self.native_symbol,
            explorer_url=self.explorer_url(address),
        )
        report.status = "⏳"
        report.meta.update(
            {"address_type": info.kind, "network": info.network,
             "encoding": info.encoding}
        )

        url = f"{self.api_base}/address/{address}"
        try:
            data = self.http.get_json(url, provider="mempool.space")
        except Exception as exc:
            report.status = "✗"
            report.errors.append(f"mempool.space: {exc}")
            report.detail = "Bitcoin balance lookup failed"
            return report

        if not isinstance(data, dict) or "chain_stats" not in data:
            report.status = "✗"
            report.detail = "unexpected mempool.space payload"
            return report

        chain_stats = data.get("chain_stats") or {}
        mempool_stats = data.get("mempool_stats") or {}
        confirmed = int(chain_stats.get("funded_txo_sum", 0)) - int(
            chain_stats.get("spent_txo_sum", 0)
        )
        pending = int(mempool_stats.get("funded_txo_sum", 0)) - int(
            mempool_stats.get("spent_txo_sum", 0)
        )
        total = confirmed + pending

        report.balance_native = total / SATOSHIS_PER_BTC
        report.assets.append(
            Asset(
                symbol="BTC",
                amount=report.balance_native,
                raw=str(total),
                decimals=8,
                kind="native",
                name="Bitcoin",
            )
        )
        report.meta.update(
            {
                "confirmed_sats": confirmed,
                "pending_sats": pending,
                "tx_count": int(chain_stats.get("tx_count", 0)),
                "funded_txo_count": int(chain_stats.get("funded_txo_count", 0)),
                "spent_txo_count": int(chain_stats.get("spent_txo_count", 0)),
            }
        )
        report.status = "✓"
        log.info(
            "bitcoin assets fetched",
            extra={"component": "chains.bitcoin", "status": "✓",
                   "address": address, "provider": "mempool.space"},
        )
        return report
