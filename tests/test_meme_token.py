"""Tests for meme_token.py with mocked HTTP responses."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.meme_token import MemeTokenAnalyzer, TokenRiskCheck, MemeTokenReport


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


class TestMemeTokenAnalyzer:
    def test_invalid_address_raises(self):
        with pytest.raises(Exception):
            MemeTokenAnalyzer().analyze("not-an-address")

    def test_empty_address_raises(self):
        with pytest.raises(Exception):
            MemeTokenAnalyzer().analyze("")

    def test_short_address_raises(self):
        with pytest.raises(Exception):
            MemeTokenAnalyzer().analyze("0x1234")

    def test_honeypot_flag_high_risk(self):
        addr = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
        responses = {
            (f"https://api.honeypot.is/v2/IsHoneypot?address={addr}&chainID=1", "honeypot.is"): {
                "riskLevel": "HIGH",
                "isHoneypot": True,
                "simulation": {"buyTax": "15%", "sellTax": "25%"},
                "liquidityAmount": 1000,
            },
            (f"https://api.gopluslabs.io/api/v1/token_security/1/{addr}", "goplus"): {
                "code": 1,
                "result": {"is_honeypot": "1", "is_mintable": "0"},
            },
            (f"https://api.dexscreener.com/latest/dex/tokens/{addr}", "dexscreener"): {
                "pairs": [{"priceUsd": "0.0001", "liquidity": {"usd": "5000"}, "dexId": "uniswap", "pairAddress": "0xabc"}],
            },
        }
        analyzer = MemeTokenAnalyzer(http=FakeHttp(responses))
        report = analyzer.analyze(addr)
        assert report.risk_level == "high"
        assert report.liquidity_usd == 1000.0
        assert any(c.name == "honeypot_is" for c in report.checks)
        assert any("high buy tax" in w.lower() for w in report.warnings)

    def test_safe_token_low_risk(self):
        addr = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
        responses = {
            (f"https://api.honeypot.is/v2/IsHoneypot?address={addr}&chainID=1", "honeypot.is"): {
                "riskLevel": "LOW",
                "isHoneypot": False,
                "simulation": {"buyTax": "1%", "sellTax": "1%"},
            },
            (f"https://api.gopluslabs.io/api/v1/token_security/1/{addr}", "goplus"): {
                "code": 1,
                "result": {},
            },
            (f"https://api.dexscreener.com/latest/dex/tokens/{addr}", "dexscreener"): {
                "pairs": [{"priceUsd": "1.0", "liquidity": {"usd": "50000"}, "dexId": "uniswap"}],
            },
        }
        analyzer = MemeTokenAnalyzer(http=FakeHttp(responses))
        report = analyzer.analyze(addr)
        assert report.risk_level in ("low", "unknown")
        assert report.price_usd == 1.0

    def test_api_timeout_degrades(self):
        addr = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"

        def fail(*args, **kwargs):
            raise TimeoutError("timed out")

        analyzer = MemeTokenAnalyzer(http=FakeHttp({}))
        analyzer.http.get_json = fail  # type: ignore[assignment]
        report = analyzer.analyze(addr)
        assert report.risk_level in ("unknown", "low", "medium", "high")
        assert report.risk_score >= 0

    def test_goplus_unexpected_response(self):
        addr = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
        responses = {
            (f"https://api.honeypot.is/v2/IsHoneypot?address={addr}&chainID=1", "honeypot.is"): {
                "riskLevel": "LOW", "isHoneypot": False, "simulation": {},
            },
            (f"https://api.gopluslabs.io/api/v1/token_security/1/{addr}", "goplus"): "not-a-dict",
            (f"https://api.dexscreener.com/latest/dex/tokens/{addr}", "dexscreener"): {
                "pairs": [{"priceUsd": "0.5", "liquidity": {"usd": "1000"}}],
            },
        }
        analyzer = MemeTokenAnalyzer(http=FakeHttp(responses))
        report = analyzer.analyze(addr)
        assert any(c.name == "goplus" for c in report.checks)

    def test_dexscreener_no_pairs(self):
        addr = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
        responses = {
            (f"https://api.honeypot.is/v2/IsHoneypot?address={addr}&chainID=1", "honeypot.is"): {
                "riskLevel": "LOW", "isHoneypot": False, "simulation": {},
            },
            (f"https://api.gopluslabs.io/api/v1/token_security/1/{addr}", "goplus"): {"code": 1, "result": {}},
            (f"https://api.dexscreener.com/latest/dex/tokens/{addr}", "dexscreener"): {"pairs": []},
        }
        analyzer = MemeTokenAnalyzer(http=FakeHttp(responses))
        report = analyzer.analyze(addr)
        assert any(c.name == "dexscreener" for c in report.checks)

    def test_report_as_dict_roundtrip(self):
        addr = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
        responses = {
            (f"https://api.honeypot.is/v2/IsHoneypot?address={addr}&chainID=1", "honeypot.is"): {
                "riskLevel": "LOW", "isHoneypot": False, "simulation": {},
            },
            (f"https://api.gopluslabs.io/api/v1/token_security/1/{addr}", "goplus"): {"code": 1, "result": {}},
            (f"https://api.dexscreener.com/latest/dex/tokens/{addr}", "dexscreener"): {"pairs": []},
        }
        analyzer = MemeTokenAnalyzer(http=FakeHttp(responses))
        report = analyzer.analyze(addr)
        data = report.as_dict()
        assert "address" in data
        assert "checks" in data
        assert "risk_level" in data
        assert data["address"] == addr
