"""Chain provider tests, including upstream API failure handling."""

from __future__ import annotations

import pytest

from app.chains.bitcoin import BitcoinProvider
from app.chains.evm import EvmProvider, format_units
from app.chains.registry import build_registry
from app.errors import AddressValidationError, HttpError

SAMPLE_EVM = "0xDe0DAFC80d487b8aE652bBF906ac6c6007aE3A5e"
SAMPLE_BTC = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"

BS_ADDRESS = {
    "coin_balance": "786571611000",
    "exchange_rate": "2725.71",
    "has_tokens": True,
    "has_token_transfers": True,
    "is_contract": False,
    "creation_status": "success",
}

BS_TOKENS = [
    {
        "token": {
            "address_hash": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
            "decimals": "6",
            "symbol": "USDT",
            "name": "Tether USD",
            "exchange_rate": "0.999871",
        },
        "value": "256000",
    },
    {
        # zero balance -> filtered out
        "token": {"address_hash": "0x0", "decimals": "18", "symbol": "ZERO"},
        "value": "0",
    },
]


class FakeHttp:
    """Routes URLs to canned payloads; raises for keys mapped to exceptions."""

    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def _resolve(self, url):
        self.calls.append(url)
        for key, value in self.routes.items():
            if key in url:
                if isinstance(value, Exception):
                    raise value
                return value
        raise HttpError(f"no route for {url}", provider="fake")

    def get_json(self, url, *, provider, params=None, headers=None):
        return self._resolve(url)

    def post_json(self, url, *, provider, json_body=None, headers=None):
        return self._resolve(url)


class TestFormatUnits:
    def test_18_decimals(self):
        assert format_units(786571611000, 18) == pytest.approx(7.86571611e-7)

    def test_zero_decimals(self):
        assert format_units(42, 0) == 42.0

    def test_one_eth(self):
        assert format_units(10**18, 18) == 1.0


class TestEvmProviderHappyPath:
    def _provider(self, routes):
        return EvmProvider(chain="ethereum", http=FakeHttp(routes),
                           rpc_urls=("https://rpc.test",))

    def test_blockscout_success(self):
        provider = self._provider({
            "token-balances": BS_TOKENS,
            "api/v2/addresses/": BS_ADDRESS,
        })
        report = provider.fetch_assets(SAMPLE_EVM)
        assert report.status == "✓"
        assert report.balance_native == pytest.approx(7.86571611e-07)
        assert report.meta["source"] == "blockscout"
        symbols = [a.symbol for a in report.assets]
        assert "ETH" in symbols and "USDT" in symbols
        # zero-balance token filtered out
        assert "ZERO" not in symbols
        usdt = next(a for a in report.assets if a.symbol == "USDT")
        assert usdt.amount == pytest.approx(0.256)
        assert usdt.kind == "token"
        assert report.explorer_url.endswith(SAMPLE_EVM)

    def test_token_failure_is_non_fatal(self):
        provider = self._provider({
            "token-balances": HttpError("blockscout 500", provider="blockscout"),
            "api/v2/addresses/": BS_ADDRESS,
        })
        report = provider.fetch_assets(SAMPLE_EVM)
        assert report.status == "✓"
        assert report.balance_native == pytest.approx(7.86571611e-07)
        assert any("tokens" in e for e in report.errors)


class TestEvmProviderFailures:
    def test_rpc_fallback_when_blockscout_down(self):
        provider = EvmProvider(
            chain="ethereum",
            http=FakeHttp({
                "api/v2/addresses/": HttpError("blockscout 503", provider="blockscout"),
                "rpc.test": {"jsonrpc": "2.0", "id": 1, "result": "0xb723524b78"},
            }),
            rpc_urls=("https://rpc.test",),
        )
        report = provider.fetch_assets(SAMPLE_EVM)
        assert report.status == "✓"
        assert report.meta["source"] == "json-rpc"
        assert report.balance_native == pytest.approx(7.86571611e-07)

    def test_all_providers_down_returns_fail(self):
        provider = EvmProvider(
            chain="ethereum",
            http=FakeHttp({
                "api/v2/addresses/": HttpError("blockscout down", provider="blockscout"),
                "rpc.test": HttpError("rpc down", provider="eth-rpc"),
            }),
            rpc_urls=("https://rpc.test",),
        )
        report = provider.fetch_assets(SAMPLE_EVM)
        assert report.status == "✗"
        assert report.detail is not None
        assert len(report.errors) >= 2

    def test_rpc_json_error_object_handled(self):
        provider = EvmProvider(
            chain="ethereum",
            http=FakeHttp({
                "api/v2/addresses/": HttpError("nope", provider="blockscout"),
                "rpc.test": {"jsonrpc": "2.0", "id": 1,
                             "error": {"code": -32000, "message": "rate limited"}},
            }),
            rpc_urls=("https://rpc.test",),
        )
        report = provider.fetch_assets(SAMPLE_EVM)
        assert report.status == "✗"

    def test_rpc_urls_exhausted_then_second_succeeds(self):
        class FlakyHttp(FakeHttp):
            def _resolve(self, url):
                if "bad-rpc" in url:
                    raise HttpError("connection refused", provider="eth-rpc")
                return super()._resolve(url)

        provider = EvmProvider(
            chain="ethereum",
            http=FlakyHttp({
                "api/v2/addresses/": HttpError("blockscout down", provider="blockscout"),
                "good-rpc": {"jsonrpc": "2.0", "id": 1, "result": "0xde0b6b3a7640000"},
            }),
            rpc_urls=("https://bad-rpc", "https://good-rpc"),
        )
        report = provider.fetch_assets(SAMPLE_EVM)
        assert report.status == "✓"
        assert report.balance_native == pytest.approx(1.0)

    def test_rejects_bitcoin_address(self):
        provider = EvmProvider(chain="ethereum", http=FakeHttp({}))
        with pytest.raises(AddressValidationError):
            provider.fetch_assets(SAMPLE_BTC)


class TestBitcoinProvider:
    def test_success(self):
        payload = {
            "address": SAMPLE_BTC,
            "chain_stats": {"funded_txo_count": 80209, "funded_txo_sum": 5757247662,
                            "spent_txo_count": 0, "spent_txo_sum": 0,
                            "tx_count": 66779},
            "mempool_stats": {"funded_txo_count": 14, "funded_txo_sum": 16661,
                              "spent_txo_count": 0, "spent_txo_sum": 0,
                              "tx_count": 14},
        }
        provider = BitcoinProvider(http=FakeHttp({"mempool.space": payload}))
        report = provider.fetch_assets(SAMPLE_BTC)
        assert report.status == "✓"
        assert report.balance_native == pytest.approx((5757247662 + 16661) / 1e8)
        assert report.meta["address_type"] == "p2pkh"
        assert report.meta["network"] == "mainnet"
        assert report.assets[0].symbol == "BTC"

    def test_api_failure_returns_fail(self):
        provider = BitcoinProvider(
            http=FakeHttp({"mempool.space": HttpError("503", provider="mempool.space")})
        )
        report = provider.fetch_assets(SAMPLE_BTC)
        assert report.status == "✗"
        assert report.errors
        assert report.detail == "Bitcoin balance lookup failed"

    def test_unexpected_payload_returns_fail(self):
        provider = BitcoinProvider(http=FakeHttp({"mempool.space": {"weird": True}}))
        report = provider.fetch_assets(SAMPLE_BTC)
        assert report.status == "✗"

    def test_rejects_evm_address(self):
        provider = BitcoinProvider(http=FakeHttp({}))
        with pytest.raises(AddressValidationError):
            provider.fetch_assets(SAMPLE_EVM)


class TestRegistry:
    def test_resolves_by_address_format(self):
        registry = build_registry()
        assert registry.resolve(SAMPLE_EVM).family == "evm"
        assert registry.resolve(SAMPLE_BTC).family == "bitcoin"

    def test_unknown_address_returns_none(self):
        assert build_registry().resolve("garbage") is None

    def test_evm_family_chain(self):
        registry = build_registry()
        assert registry.get("ethereum").chain == "ethereum"
        assert registry.resolve(SAMPLE_EVM).chain == "ethereum"

    def test_describe_lists_chains(self):
        chains = [c["chain"] for c in build_registry().describe()]
        assert "ethereum" in chains and "bitcoin" in chains

    def test_custom_chain_registration(self):
        from app.chains.base import ChainProvider, ChainRegistry

        class Dummy(ChainProvider):
            chain, family, label, native_symbol = "dummy", "evm", "Dummy", "DUM"

            def validate(self, address):
                return address

            def fetch_assets(self, address, *, limit=50):
                raise NotImplementedError

        registry = ChainRegistry()
        registry.register(Dummy())
        assert registry.get("dummy") is not None
        assert "dummy" in registry.chains()
