"""Rate limiter tests, including a real-socket 429 check."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from app.chains.base import Asset, AssetReport
from app.chains.registry import ChainRegistry
from app.service import WalletService
from app.webapp.ratelimit import RateLimiter
from app.webapp.server import create_server

SAMPLE_EVM = "0xDe0DAFC80d487b8aE652bBF906ac6c6007aE3A5e"


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


class TestRateLimiterUnit:
    def test_allows_up_to_limit(self):
        limiter = RateLimiter(limit=3, window=60, clock=Clock())
        assert [limiter.check("1.2.3.4", "/health").allowed for _ in range(3)] == \
            [True, True, True]

    def test_blocks_over_limit(self):
        limiter = RateLimiter(limit=3, window=60, clock=Clock())
        for _ in range(3):
            limiter.check("1.2.3.4", "/health")
        d = limiter.check("1.2.3.4", "/health")
        assert d.allowed is False
        assert d.retry_after >= 1

    def test_remaining_counts_down(self):
        limiter = RateLimiter(limit=5, window=60, clock=Clock())
        assert limiter.check("ip", "/health").remaining == 4
        assert limiter.check("ip", "/health").remaining == 3

    def test_window_rolls_over(self):
        clock = Clock()
        limiter = RateLimiter(limit=2, window=60, clock=clock)
        limiter.check("ip", "/x")
        limiter.check("ip", "/x")
        assert limiter.check("ip", "/x").allowed is False
        clock.advance(61)
        assert limiter.check("ip", "/x").allowed is True

    def test_clients_are_isolated(self):
        limiter = RateLimiter(limit=1, window=60, clock=Clock())
        assert limiter.check("a", "/x").allowed is True
        assert limiter.check("b", "/x").allowed is True
        assert limiter.check("a", "/x").allowed is False

    def test_expensive_paths_have_their_own_budget(self):
        limiter = RateLimiter(limit=100, window=60, expensive_limit=2,
                              clock=Clock())
        assert limiter.check("ip", "/api/wallet/assets").allowed is True
        assert limiter.check("ip", "/api/wallet/assets").allowed is True
        assert limiter.check("ip", "/api/wallet/assets").allowed is False
        # the cheap budget is untouched
        assert limiter.check("ip", "/health").allowed is True

    def test_expensive_detection_covers_network_paths(self):
        limiter = RateLimiter(limit=100, expensive_limit=1, clock=Clock())
        for path in ("/api/wallet/assets", "/api/auth/challenge",
                     "/api/auth/verify"):
            limiter.reset()
            limiter.check("ip", path)
            assert limiter.check("ip", path).allowed is False, path

    def test_headers_advertise_the_budget(self):
        limiter = RateLimiter(limit=10, window=60, clock=Clock())
        headers = limiter.check("ip", "/x").headers()
        assert headers["X-RateLimit-Limit"] == "10"
        assert headers["X-RateLimit-Remaining"] == "9"

    def test_blocked_headers_include_retry_after(self):
        limiter = RateLimiter(limit=1, window=60, clock=Clock())
        limiter.check("ip", "/x")
        headers = limiter.check("ip", "/x").headers()
        assert "Retry-After" in headers

    def test_buckets_are_pruned(self):
        clock = Clock()
        limiter = RateLimiter(limit=5, window=1, clock=clock, max_buckets=10)
        for i in range(50):
            limiter.check(f"ip{i}", "/x")
            clock.advance(2)
        assert len(limiter._buckets) <= 10

    def test_thread_safety(self):
        limiter = RateLimiter(limit=1000, window=60)
        errors = []

        def hammer():
            try:
                for _ in range(100):
                    limiter.check("shared", "/x")
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=hammer) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors
        assert limiter._buckets[("shared", "normal")].count == 800


class StubProvider:
    family = "evm"
    chain = "ethereum"
    label = "Ethereum"
    native_symbol = "ETH"

    def accepts(self, address):
        return address.startswith("0x")

    def validate(self, address):
        return address

    def explorer_url(self, address):
        return None

    def fetch_assets(self, address, *, limit=50):
        r = AssetReport(address=address, chain="ethereum", family="evm",
                        native_symbol="ETH", status="✓")
        r.balance_native = 1.0
        r.assets.append(Asset(symbol="ETH", amount=1.0, raw="1", decimals=18))
        return r


class TestRateLimitOverHttp:
    @pytest.fixture
    def server(self, settings, tracker):
        registry = ChainRegistry()
        registry.register(StubProvider())
        service = WalletService(settings, tracker=tracker, registry=registry)
        limiter = RateLimiter(limit=5, window=60, expensive_limit=2)
        httpd = create_server(service, "127.0.0.1", 0, settings=settings,
                              limiter=limiter)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
        httpd.shutdown()
        httpd.server_close()

    @staticmethod
    def _get(url):
        try:
            with urllib.request.urlopen(url, timeout=10) as r:
                return r.status, dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers)

    @staticmethod
    def _post(url, payload):
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode(), method="POST",
            headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status
        except urllib.error.HTTPError as e:
            return e.code

    def test_cheap_endpoint_eventually_429s(self, server):
        codes = [self._get(server + "/health")[0] for _ in range(8)]
        assert 200 in codes
        assert codes[-1] == 429

    def test_429_body_is_json(self, server):
        for _ in range(6):
            self._get(server + "/health")
        req = urllib.request.Request(server + "/health")
        try:
            urllib.request.urlopen(req, timeout=10)
            raise AssertionError("expected 429")
        except urllib.error.HTTPError as e:
            body = json.loads(e.read())
            assert body["error"] == "rate_limited"
            assert "Retry-After" in e.headers

    def test_success_carries_ratelimit_headers(self, server):
        status, headers = self._get(server + "/health")
        assert status == 200
        assert headers.get("X-RateLimit-Limit") == "5"
        assert headers.get("X-RateLimit-Remaining") == "4"

    def test_expensive_endpoint_has_stricter_budget(self, server):
        codes = [self._post(server + "/api/wallet/assets",
                            {"address": SAMPLE_EVM}) for _ in range(4)]
        assert codes[:2] == [200, 200]
        assert codes[2] == 429

    def test_forwards_client_ip_from_header(self, server):
        """X-Forwarded-For must not collapse all callers into one bucket."""
        def get_with_ip(ip):
            req = urllib.request.Request(server + "/health",
                                         headers={"X-Forwarded-For": ip})
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status
        for _ in range(5):
            get_with_ip("10.0.0.1")
        # a different client still gets service
        assert get_with_ip("10.0.0.2") == 200
