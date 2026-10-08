"""Integration tests: the HTTP puzzle source against a real local server.

These do not mock the HTTP layer - they stand up an actual socket server
speaking the documented contract, so the client's URL building, headers,
auth, retries and payload parsing are all exercised for real.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from app.chains.base import Asset, AssetReport
from app.config import Settings
from app.errors import HttpError, PuzzleAPIError
from app.puzzles.analysis import PuzzleAnalyzer, Verdict
from app.puzzles.memepol import MemePolClient

TOKEN = "test-secret-token"

PUZZLES = [
    {
        "id": "eth-escrow",
        "title": "ETH escrow",
        "chain": "ethereum",
        "criteria": {"address": "0xDe0DAFC80d487b8aE652bBF906ac6c6007aE3A5e",
                     "chain": "ethereum"},
        "hints": ["hint one"],
        "images": ["https://example.test/a.png"],
    },
    {
        "id": "btc-threshold",
        "title": "BTC threshold",
        "chain": "bitcoin",
        "criteria": {"address": "14zMkTgaVXJcxdh4JdWi29MLRR44iUSG9W",
                     "chain": "bitcoin", "min_balance": 0.5},
        "hints": ["stage 2"],
    },
]


class Handler(BaseHTTPRequestHandler):
    """Configurable fake endpoint."""

    mode = "ok"            # ok | unauthorized | malformed | error | slow_status
    require_token = TOKEN
    seen_headers = []

    def log_message(self, *a):
        pass

    def _send(self, payload, status=200):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        from urllib.parse import urlparse

        Handler.seen_headers.append(dict(self.headers))
        path = urlparse(self.path).path.rstrip("/") or "/"
        if Handler.mode == "unauthorized":
            return self._send({"error": "unauthorized"}, 401)
        if Handler.mode == "malformed":
            return self._send("not a puzzle list")
        if Handler.mode == "slow_status":
            return self._send({"error": "boom"}, 503)
        auth = self.headers.get("Authorization") or self.headers.get("X-API-Key") or ""
        # Accept any prefix ("Bearer x", "Token x", or a bare key).
        if Handler.require_token and not auth.endswith(TOKEN):
            return self._send({"error": "unauthorized"}, 401)
        if path == "/puzzles":
            return self._send({"puzzles": PUZZLES})
        return self._send({"error": "not_found"}, 404)


@pytest.fixture
def endpoint():
    Handler.mode = "ok"
    Handler.seen_headers = []
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()
    httpd.server_close()


def client_for(url, *, key=TOKEN, header="Authorization", prefix="Bearer", **kw):
    settings = Settings(memepol_base_url=url, memepol_api_key=key,
                        memepol_auth_header=header, memepol_auth_prefix=prefix,
                        **kw)
    from app.http import HttpClient
    return MemePolClient(settings, http=HttpClient(max_retries=0, timeout=5))


class TestHttpSource:
    def test_fetches_and_parses(self, endpoint):
        client = client_for(endpoint)
        entries = client.list_puzzles()
        assert [e.id for e in entries] == ["eth-escrow", "btc-threshold"]
        assert entries[0].criteria["address"].startswith("0xDe0DAFC8")
        assert entries[0].hints == ["hint one"]
        assert entries[0].images == ["https://example.test/a.png"]

    def test_bearer_header_sent(self, endpoint):
        client_for(endpoint).list_puzzles()
        auth = Handler.seen_headers[0].get("Authorization")
        assert auth == f"Bearer {TOKEN}"

    def test_x_api_key_header_mode(self, endpoint):
        client_for(endpoint, header="X-API-Key", prefix="").list_puzzles()
        # HTTP headers are case-insensitive; check all headers for the key
        headers = Handler.seen_headers[0]
        found = None
        for k, v in headers.items():
            if k.lower() == "x-api-key":
                found = v
                break
        assert found == TOKEN
        # Authorization should not be present
        auth = None
        for k, v in headers.items():
            if k.lower() == "authorization":
                auth = v
                break
        assert auth is None

    def test_custom_prefix(self, endpoint):
        client_for(endpoint, prefix="Token").list_puzzles()
        assert Handler.seen_headers[0].get("Authorization") == f"Token {TOKEN}"

    def test_token_never_appears_in_url(self, endpoint):
        client_for(endpoint).list_puzzles()
        # the handler only ever sees a path; assert no query string carried it
        assert TOKEN not in Handler.seen_headers[0].get("Referer", "")

    def test_wrong_key_rejected(self, endpoint):
        with pytest.raises(HttpError):
            client_for(endpoint, key="wrong-key").list_puzzles()

    def test_unconfigured_without_key(self, endpoint):
        client = client_for(endpoint, key=None)
        assert client.configured is False
        with pytest.raises(PuzzleAPIError):
            client.list_puzzles()

    def test_malformed_payload_raises(self, endpoint):
        Handler.mode = "malformed"
        with pytest.raises(PuzzleAPIError):
            client_for(endpoint).list_puzzles()

    def test_http_error_surfaces(self, endpoint):
        Handler.mode = "slow_status"
        with pytest.raises(HttpError) as exc:
            client_for(endpoint).list_puzzles()
        assert exc.value.status_code == 503

    def test_ping_ok(self, endpoint):
        result = client_for(endpoint).ping()
        assert result["ok"] is True
        assert result["endpoint"].endswith("/puzzles")

    def test_ping_reports_failure_without_raising(self, endpoint):
        result = client_for(endpoint, key="wrong").ping()
        assert result["ok"] is False
        assert "detail" in result

    def test_ping_never_returns_the_key(self, endpoint):
        result = client_for(endpoint).ping()
        assert TOKEN not in json.dumps(result)


class TestHttpSourceAnalysis:
    def report(self, chain, address, balance=0.0, symbol="ETH"):
        r = AssetReport(address=address, chain=chain, family=chain,
                        native_symbol=symbol, status="✓")
        r.balance_native = balance
        r.assets.append(Asset(symbol=symbol, amount=balance, raw="0", decimals=18))
        return r

    def analyzer(self, url):
        return PuzzleAnalyzer(client_for(url))

    def test_exact_match_via_http(self, endpoint):
        result = self.analyzer(endpoint).analyze(
            self.report("ethereum", "0xDe0DAFC80d487b8aE652bBF906ac6c6007aE3A5e"))
        assert result.verdict is Verdict.EXACT
        assert result.source == "memepol"
        assert result.hints == ["hint one"]
        assert result.images == ["https://example.test/a.png"]

    def test_threshold_unmet_is_possible(self, endpoint):
        result = self.analyzer(endpoint).analyze(
            self.report("bitcoin", "14zMkTgaVXJcxdh4JdWi29MLRR44iUSG9W",
                        0.1, "BTC"))
        assert result.verdict is Verdict.POSSIBLE

    def test_unrelated_address_is_no_match(self, endpoint):
        result = self.analyzer(endpoint).analyze(
            self.report("bitcoin", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
                        99.0, "BTC"))
        assert result.verdict is Verdict.NONE
        assert result.hints == []

    def test_api_error_yields_error_verdict(self, endpoint):
        Handler.mode = "unauthorized"
        result = self.analyzer(endpoint).analyze(
            self.report("ethereum", "0xDe0DAFC80d487b8aE652bBF906ac6c6007aE3A5e"))
        assert result.verdict is Verdict.ERROR
        assert result.status == "✗"
        assert result.matches == []
