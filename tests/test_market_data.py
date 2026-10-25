"""Tests for market_data.py with mocked HTTP."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.market_data import MarketData


class FakeHttp:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def get_json(self, url, provider=None):
        self.calls.append((url, provider))
        key = (url, provider)
        if key in self.responses:
            return self.responses[key]
        raise RuntimeError(f"unexpected URL: {url}")


class TestMarketData:
    def test_price_returns_source(self):
        md = MarketData(http=FakeHttp({
            ("https://api.coingecko.com/api/v3/simple/price?ids=btc&vs_currencies=usd&include_24hr_change=true", "coingecko"): {
                "btc": {"usd": 50000.0, "usd_24h_change": 2.5},
            },
        }))
        data = md.price("btc")
        assert data["symbol"] == "btc"
        assert data["source"] == "coingecko"
        assert data["usd"] == 50000.0

    def test_price_binance_fallback(self):
        md = MarketData(http=FakeHttp({
            ("https://api.coingecko.com/api/v3/simple/price?ids=btc&vs_currencies=usd&include_24hr_change=true", "coingecko"): None,
            ("https://api.binance.com/api/v3/ticker/24hr?symbol=BTCUSDT", "binance"): {
                "lastPrice": "50000", "priceChangePercent": "1.5", "volume": "1000",
            },
        }))
        data = md.price("btc")
        assert data["source"] == "binance"
        assert data["price"] == 50000.0

    def test_price_no_data(self):
        md = MarketData(http=FakeHttp({}))
        data = md.price("unknown_symbol")
        assert "error" in data

    def test_overview_aggregates(self):
        md = MarketData(http=FakeHttp({
            ("https://api.coingecko.com/api/v3/global", "coingecko"): {
                "data": {"market_cap_percentage": {"btc": 50.0, "eth": 18.0},
                         "total_market_cap": {"usd": 2000000000000},
                         "total_volume": {"usd": 50000000000}},
            },
            ("https://api.binance.com/api/v3/ticker/24hr?symbol=BTCUSDT", "binance"): {
                "lastPrice": "50000", "priceChangePercent": "2.0", "volume": "1000",
            },
            ("https://gamma-api.polymarket.com/markets?limit=5&order=volume24hr&ascending=false", "polymarket"): [],
        }))
        data = md.overview()
        assert "coingecko" in data["sources"]
        assert "binance" in data["sources"]
        assert data["coingecko"]["btc_dominance"] == 50.0

    def test_overview_polymarket(self):
        md = MarketData(http=FakeHttp({
            ("https://api.coingecko.com/api/v3/global", "coingecko"): None,
            ("https://api.binance.com/api/v3/ticker/24hr?symbol=BTCUSDT", "binance"): None,
            ("https://gamma-api.polymarket.com/markets?limit=5&order=volume24hr&ascending=false", "polymarket"): [
                {"question": "Will BTC hit 100k?", "volume24hr": 100000, "bestBid": 0.6, "bestAsk": 0.65},
            ],
        }))
        data = md.overview()
        assert "polymarket" in data["sources"]
        assert len(data["polymarket"]["top_markets"]) == 1

    def test_overview_all_fail(self):
        md = MarketData(http=FakeHttp({}))
        data = md.overview()
        assert data["sources"] == []

    def test_price_timeout_returns_none(self):
        md = MarketData(http=FakeHttp({
            ("https://api.coingecko.com/api/v3/simple/price?ids=btc&vs_currencies=usd&include_24hr_change=true", "coingecko"): None,
        }))
        data = md.price("btc")
        assert "error" in data
