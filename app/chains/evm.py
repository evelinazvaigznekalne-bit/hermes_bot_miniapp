"""Ethereum / EVM-compatible provider.

Read-only. Uses Blockscout's public REST API for native balance, token
balances and account metadata, falling back to a public JSON-RPC endpoint
when Blockscout is unavailable. A user-supplied ``ETH_RPC_URL`` takes
priority over the built-in public endpoints.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..addresses import validate_evm_address
from ..errors import ChainAPIError, _safe_exception
from ..http import HttpClient
from ..logging_setup import get_logger
from .base import Asset, AssetReport, ChainProvider

log = get_logger()

#: Blockscout instance per chain id. Add entries to support more EVM chains.
BLOCKSCOUT_BASES = {
    "ethereum": "https://eth.blockscout.com",
    "gnosis": "https://gnosis.blockscout.com",
    "polygon": "https://polygon.blockscout.com",
    "base": "https://base.blockscout.com",
    "optimism": "https://optimism.blockscout.com",
    "arbitrum": "https://arbitrum.blockscout.com",
}

EXPLORERS = {
    "ethereum": "https://etherscan.io/address/{address}",
    "gnosis": "https://gnosisscan.io/address/{address}",
    "polygon": "https://polygonscan.com/address/{address}",
    "base": "https://basescan.org/address/{address}",
    "optimism": "https://optimistic.etherscan.io/address/{address}",
    "arbitrum": "https://arbiscan.io/address/{address}",
}

CHAIN_IDS = {
    "ethereum": 1,
    "gnosis": 100,
    "polygon": 137,
    "base": 8453,
    "optimism": 10,
    "arbitrum": 42161,
}

MAX_UINT = (1 << 256) - 1


def format_units(raw: int, decimals: int) -> float:
    if decimals <= 0:
        return float(raw)
    return raw / (10 ** decimals)


class EvmProvider(ChainProvider):
    """EVM address provider (default: Ethereum mainnet)."""

    family = "evm"
    native_symbol = "ETH"
    native_decimals = 18

    def __init__(self, chain: str = "ethereum", *, http: Optional[HttpClient] = None,
                 rpc_urls: Optional[tuple] = None, label: Optional[str] = None,
                 native_symbol: Optional[str] = None, decimals: int = 18,
                 blockscout_base: Optional[str] = None, token_limit: int = 50):
        self.chain = chain
        self.label = label or chain.capitalize()
        self.native_symbol = native_symbol or "ETH"
        self.native_decimals = decimals
        self.http = http or HttpClient()
        self.rpc_urls = tuple(rpc_urls or ())
        self.blockscout_base = blockscout_base or BLOCKSCOUT_BASES.get(chain)
        self.token_limit = token_limit

    # -- validation -------------------------------------------------------
    def validate(self, address: str) -> str:
        return validate_evm_address(address)

    def explorer_url(self, address: str) -> Optional[str]:
        tmpl = EXPLORERS.get(self.chain)
        return tmpl.format(address=address) if tmpl else None

    # -- blockscout -------------------------------------------------------
    def _blockscout_address(self, address: str) -> Dict[str, Any]:
        if not self.blockscout_base:
            raise ChainAPIError("no Blockscout endpoint for this chain",
                                provider="blockscout")
        url = f"{self.blockscout_base}/api/v2/addresses/{address}"
        return self.http.get_json(url, provider="blockscout")

    def _blockscout_tokens(self, address: str) -> List[Dict[str, Any]]:
        if not self.blockscout_base:
            return []
        url = f"{self.blockscout_base}/api/v2/addresses/{address}/token-balances"
        data = self.http.get_json(url, provider="blockscout")
        return data if isinstance(data, list) else []

    # -- json-rpc ---------------------------------------------------------
    def _rpc_call(self, method: str, params: list) -> Any:
        payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        last_error: Optional[str] = None
        for url in self.rpc_urls:
            try:
                data = self.http.post_json(url, provider="eth-rpc", json_body=payload)
            except Exception as exc:  # try the next endpoint
                last_error = _safe_exception(exc)
                continue
            if isinstance(data, dict) and "result" in data:
                return data["result"]
            if isinstance(data, dict) and "error" in data:
                last_error = str(data["error"])[:200]
                continue
            last_error = "malformed JSON-RPC response"
        raise ChainAPIError(
            "all configured Ethereum RPC endpoints failed",
            provider="eth-rpc", detail=last_error,
        )

    def _rpc_balance(self, address: str) -> int:
        result = self._rpc_call("eth_getBalance", [address, "latest"])
        if not isinstance(result, str):
            raise ChainAPIError("unexpected eth_getBalance result",
                                provider="eth-rpc")
        return int(result, 16)

    # -- main -------------------------------------------------------------
    def fetch_assets(self, address: str, *, limit: int = 50) -> AssetReport:
        address = self.validate(address)
        report = AssetReport(
            address=address, chain=self.chain, family=self.family,
            native_symbol=self.native_symbol,
            explorer_url=self.explorer_url(address),
        )
        report.status = "⏳"

        raw_balance: Optional[int] = None
        exchange_rate: Optional[float] = None
        source = None

        # 1. Preferred: Blockscout (balance + tokens + metadata in 2 calls)
        try:
            info = self._blockscout_address(address)
            coin_balance = info.get("coin_balance")
            if coin_balance is not None:
                raw_balance = int(coin_balance)
            rate = info.get("exchange_rate")
            if rate is not None:
                try:
                    exchange_rate = float(rate)
                except (TypeError, ValueError):
                    exchange_rate = None
            report.meta["blockscout"] = {
                "has_tokens": info.get("has_tokens"),
                "has_token_transfers": info.get("has_token_transfers"),
                "is_contract": bool(info.get("is_contract")),
                "creation_status": info.get("creation_status"),
            }
            source = "blockscout"
        except Exception as exc:
            report.errors.append(f"blockscout: {exc}")

        # 2. Fallback: public JSON-RPC for the native balance
        if raw_balance is None and self.rpc_urls:
            try:
                raw_balance = self._rpc_balance(address)
                source = "json-rpc"
            except Exception as exc:
                report.errors.append(f"json-rpc: {exc}")

        if raw_balance is None:
            report.status = "✗"
            report.detail = "native balance unavailable from all providers"
            return report

        report.balance_native = format_units(raw_balance, self.native_decimals)
        usd = None
        if exchange_rate is not None:
            usd = report.balance_native * exchange_rate
        report.assets.append(
            Asset(
                symbol=self.native_symbol,
                amount=report.balance_native,
                raw=str(raw_balance),
                decimals=self.native_decimals,
                kind="native",
                name=self.label,
                usd_value=usd,
            )
        )
        report.meta["source"] = source
        if exchange_rate is not None:
            report.meta["native_usd_rate"] = exchange_rate

        # 3. ERC-20 balances (best-effort; failure is non-fatal)
        if source == "blockscout":
            try:
                for token in self._blockscout_tokens(address)[:min(limit, self.token_limit)]:
                    asset = self._parse_token(token)
                    if asset is not None:
                        report.assets.append(asset)
            except Exception as exc:
                report.errors.append(f"tokens: {exc}")

        report.status = "✓"
        log.info(
            "evm assets fetched",
            extra={"component": "chains.evm", "status": "✓", "chain": self.chain,
                   "address": address, "provider": source},
        )
        return report

    def _parse_token(self, token: Dict[str, Any]) -> Optional[Asset]:
        try:
            meta = token.get("token") or {}
            decimals = int(meta.get("decimals") or 0)
            raw = int(token.get("value") or 0)
            if raw == 0:
                return None
            symbol = meta.get("symbol") or "?"
            name = meta.get("name")
            rate = meta.get("exchange_rate")
            usd = None
            if rate is not None:
                try:
                    usd = format_units(raw, decimals) * float(rate)
                except (TypeError, ValueError):
                    usd = None
            return Asset(
                symbol=symbol,
                amount=format_units(raw, decimals),
                raw=str(raw),
                decimals=decimals,
                kind="token",
                contract=meta.get("address_hash"),
                name=name,
                usd_value=usd,
            )
        except Exception:
            return None
