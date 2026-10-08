"""Tests for market scan, market overview, and user stats endpoints."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request

import pytest

from app.chains.base import Asset, AssetReport
from app.chains.registry import ChainRegistry
from app.market import TokenScanner, RiskLevel
from app.service import WalletService
from app.webapp.server import MiniAppAPI, create_server


SAMPLE_TOKEN = "0xDe0DAFC80d487b8aE652bBF906ac6c6007aE3A5e"


class StubProvider:
    family = "evm"
    chain = "ethereum"
    label = "Ethereum"
    native_symbol = "ETH"

    def accepts(self, address):
        return address.startswith("0x") and len(address) == 42

    def validate(self, address):
        return address

    def explorer_url(self, address):
        return None

    def fetch_assets(self, address, *, limit=50):
        report = AssetReport(address=address, chain=self.chain, family=self.family,
                             native_symbol="ETH", status="✓")
        report.balance_native = 2.0
        report.assets.append(Asset(symbol="ETH", amount=2.0, raw="2", decimals=18))
        return report


@pytest.fixture
def service(settings, tracker):
    registry = ChainRegistry()
    registry.register(StubProvider())
    return WalletService(settings, tracker=tracker, registry=registry)


@pytest.fixture
def live_server(service, settings):
    httpd = create_server(service, "127.0.0.1", 0, settings=settings)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    host, port = httpd.server_address[:2]
    yield f"http://{host}:{port}"
    httpd.shutdown()
    httpd.server_close()


def post(url, payload):
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(), method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def get(url):
    with urllib.request.urlopen(url, timeout=10) as resp:
        return resp.status, json.loads(resp.read())


class TestMarketScan:
    """Tests for /api/market/scan endpoint."""

    def test_scan_valid_token(self, live_server):
        status, body = post(live_server + "/api/market/scan",
                            {"address": SAMPLE_TOKEN})
        assert status == 200
        assert body["address"] == SAMPLE_TOKEN
        assert body["chain"] == "ethereum"
        assert "risk_level" in body
        assert "risk_score" in body
        assert "checks" in body
        assert isinstance(body["checks"], list)
        assert len(body["checks"]) > 0
        assert body["status"] == "✓"

    def test_scan_requires_address(self, live_server):
        status, body = post(live_server + "/api/market/scan", {})
        assert status == 400
        assert "error" in body

    def test_scan_invalid_address(self, live_server):
        status, body = post(live_server + "/api/market/scan",
                            {"address": "not-an-address"})
        assert status == 400
        assert "error" in body

    def test_scan_with_chain(self, live_server):
        status, body = post(live_server + "/api/market/scan",
                            {"address": SAMPLE_TOKEN, "chain": "ethereum"})
        assert status == 200
        assert body["chain"] == "ethereum"

    def test_scan_returns_risk_levels(self, live_server):
        status, body = post(live_server + "/api/market/scan",
                            {"address": SAMPLE_TOKEN})
        assert status == 200
        assert body["risk_level"] in ("low", "medium", "high", "unknown")
        assert 0 <= body["risk_score"] <= 100


class TestMarketOverview:
    """Tests for /api/market/overview endpoint."""

    def test_overview_returns_stats(self, live_server):
        status, body = get(live_server + "/api/market/overview")
        assert status == 200
        assert "total_tracked" in body
        assert "total_scans" in body
        assert "risk_distribution" in body
        assert body["status"] == "✓"

    def test_overview_risk_distribution(self, live_server):
        status, body = get(live_server + "/api/market/overview")
        assert status == 200
        dist = body["risk_distribution"]
        assert "low" in dist
        assert "medium" in dist
        assert "high" in dist
        assert "unknown" in dist


class TestUserStats:
    """Tests for /api/user/stats endpoint."""

    def test_stats_requires_session(self, live_server):
        status, body = post(live_server + "/api/user/stats", {})
        assert status == 400
        assert "error" in body

    def test_stats_with_invalid_session(self, live_server):
        status, body = post(live_server + "/api/user/stats",
                            {"session_token": "invalid-token"})
        assert status == 400
        assert "error" in body


class TestTokenScannerUnit:
    """Direct unit tests for TokenScanner."""

    def test_scan_valid_address(self):
        scanner = TokenScanner()
        result = scanner.scan(SAMPLE_TOKEN)
        assert result.address == SAMPLE_TOKEN
        assert result.chain == "ethereum"
        assert result.risk_level in (
            RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.UNKNOWN
        )
        assert 0 <= result.risk_score <= 100
        assert len(result.checks) > 0

    def test_scan_invalid_address_raises(self):
        scanner = TokenScanner()
        with pytest.raises(Exception):
            scanner.scan("invalid")

    def test_scan_empty_address_raises(self):
        scanner = TokenScanner()
        with pytest.raises(Exception):
            scanner.scan("")

    def test_overview_empty(self):
        scanner = TokenScanner()
        overview = scanner.overview()
        assert overview["total_tracked"] == 0
        assert overview["total_scans"] == 0

    def test_overview_after_scan(self):
        scanner = TokenScanner()
        scanner.scan(SAMPLE_TOKEN)
        overview = scanner.overview()
        assert overview["total_tracked"] == 1
        assert overview["total_scans"] == 1

    def test_risk_levels_exist(self):
        assert RiskLevel.LOW.value == "low"
        assert RiskLevel.MEDIUM.value == "medium"
        assert RiskLevel.HIGH.value == "high"
        assert RiskLevel.UNKNOWN.value == "unknown"
