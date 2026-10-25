"""Market data and prediction-market intelligence.

Public APIs used:
- CoinGecko (free, no key for basic endpoints)
- Binance public market data
- Polymarket Gamma API (public markets)
- Kalshi public API (where documented)
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from .logging_setup import get_logger
from .http import HttpClient

log = get_logger()


class MarketData:
    def __init__(self, http: Optional[HttpClient] = None):
        self.http = http or HttpClient(timeout=20.0, max_retries=2)

    def overview(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"timestamp": time.time(), "sources": []}
        cg = self._coingecko_overview()
        if cg:
            out["coingecko"] = cg
            out["sources"].append("coingecko")
        bn = self._binance_overview()
        if bn:
            out["binance"] = bn
            out["sources"].append("binance")
        pm = self._polymarket_overview()
        if pm:
            out["polymarket"] = pm
            out["sources"].append("polymarket")
        return out

    def price(self, symbol: str) -> Dict[str, Any]:
        s = symbol.lower().strip()
        cg = self._coingecko_price(s)
        if cg:
            return cg
        bn = self._binance_price(s.upper())
        if bn:
            return bn
        return {"error": "no data", "symbol": symbol}

    def _coingecko_overview(self) -> Optional[Dict[str, Any]]:
        try:
            data = self.http.get_json(
                "https://api.coingecko.com/api/v3/global",
                provider="coingecko",
            )
            gd = data.get("data", {}) if isinstance(data, dict) else {}
            mkt = gd.get("market_cap_percentage", {})
            return {
                "btc_dominance": mkt.get("btc"),
                "eth_dominance": mkt.get("eth"),
                "market_cap_usd": gd.get("total_market_cap", {}).get("usd"),
                "volume_usd": gd.get("total_volume", {}).get("usd"),
            }
        except Exception as exc:
            log.debug("coingecko global failed: %s", exc)
            return None

    def _coingecko_price(self, symbol: str) -> Optional[Dict[str, Any]]:
        try:
            data = self.http.get_json(
                f"https://api.coingecko.com/api/v3/simple/price?"
                f"ids={symbol}&vs_currencies=usd&include_24hr_change=true",
                provider="coingecko",
            )
            if symbol in data:
                return {"symbol": symbol, "source": "coingecko", **data[symbol]}
        except Exception as exc:
            log.debug("coingecko price failed: %s", exc)
        return None

    def _binance_overview(self) -> Optional[Dict[str, Any]]:
        try:
            data = self.http.get_json(
                "https://api.binance.com/api/v3/ticker/24hr?symbol=BTCUSDT",
                provider="binance",
            )
            return {
                "btc_usdt_price": float(data.get("lastPrice", 0)),
                "btc_change_pct": float(data.get("priceChangePercent", 0)),
                "btc_volume": float(data.get("volume", 0)),
            }
        except Exception as exc:
            log.debug("binance overview failed: %s", exc)
            return None

    def _binance_price(self, symbol: str) -> Optional[Dict[str, Any]]:
        try:
            data = self.http.get_json(
                f"https://api.binance.com/api/v3/ticker/24hr?symbol={symbol}USDT",
                provider="binance",
            )
            return {
                "symbol": symbol,
                "source": "binance",
                "price": float(data.get("lastPrice", 0)),
                "change_pct": float(data.get("priceChangePercent", 0)),
            }
        except Exception as exc:
            log.debug("binance price failed: %s", exc)
            return None

    def _polymarket_overview(self) -> Optional[Dict[str, Any]]:
        try:
            data = self.http.get_json(
                "https://gamma-api.polymarket.com/markets?limit=5&order=volume24hr&ascending=false",
                provider="polymarket",
            )
            if not isinstance(data, list):
                return None
            return {
                "top_markets": [
                    {
                        "question": m.get("question", "")[:80],
                        "volume_24h": m.get("volume24hr", 0),
                        "best_bid": m.get("bestBid"),
                        "best_ask": m.get("bestAsk"),
                    }
                    for m in data[:5]
                ]
            }
        except Exception as exc:
            log.debug("polymarket failed: %s", exc)
            return None
