"""HTTP API tests using the standard-library server on an ephemeral port."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request

import pytest

from app.auth import personal_sign_hash
from app.chains.base import Asset, AssetReport
from app.chains.registry import ChainRegistry
from app.service import WalletService
from app.webapp.server import MiniAppAPI, create_server

SAMPLE_EVM = "0xDe0DAFC80d487b8aE652bBF906ac6c6007aE3A5e"
PRIV = "11" * 32


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


class TestHttpEndpoints:
    def test_health(self, live_server):
        status, body = get(live_server + "/health")
        assert status == 200
        assert body["ok"] is True
        assert body["read_only"] is True
        assert body["secrets_requested"] is False

    def test_status_endpoint(self, live_server):
        status, body = get(live_server + "/api/status")
        assert status == 200
        assert "wallet_data" in body["statuses"]

    def test_chains_endpoint(self, live_server):
        status, body = get(live_server + "/api/chains")
        assert status == 200
        assert body["chains"][0]["chain"] == "ethereum"

    def test_challenge_and_verify_roundtrip(self, live_server):
        from eth_keys import keys

        priv = keys.PrivateKey(bytes.fromhex(PRIV))
        address = priv.public_key.to_checksum_address()

        status, challenge = post(live_server + "/api/auth/challenge",
                                 {"address": address})
        assert status == 200
        assert challenge["status"] == "⏳"

        sig = priv.sign_msg_hash(personal_sign_hash(challenge["message"]))
        status, result = post(live_server + "/api/auth/verify", {
            "address": address, "signature": "0x" + sig.to_bytes().hex(),
            "nonce": challenge["nonce"],
        })
        assert status == 200
        assert result["verified"] is True

    def test_verify_rejects_bad_signature(self, live_server):
        status, challenge = post(live_server + "/api/auth/challenge",
                                 {"address": SAMPLE_EVM})
        assert status == 200
        status, result = post(live_server + "/api/auth/verify", {
            "address": SAMPLE_EVM, "signature": "0x" + "00" * 65,
            "nonce": challenge["nonce"],
        })
        assert status == 200
        assert result["verified"] is False

    def test_assets_endpoint(self, live_server):
        status, body = post(live_server + "/api/wallet/assets",
                            {"address": SAMPLE_EVM})
        assert status == 200
        assert body["wallet"]["balance_native"] == 2.0
        assert body["wallet"]["chain"] == "ethereum"

    def test_assets_requires_address(self, live_server):
        status, body = post(live_server + "/api/wallet/assets", {})
        assert status == 400
        assert "error" in body

    def test_bad_json_body(self, live_server):
        req = urllib.request.Request(
            live_server + "/api/wallet/assets", data=b"{not json",
            method="POST", headers={"Content-Type": "application/json"},
        )
        try:
            urllib.request.urlopen(req, timeout=10)
            assert False, "expected 400"
        except urllib.error.HTTPError as exc:
            assert exc.code == 400

    def test_unknown_post_route(self, live_server):
        status, body = post(live_server + "/api/nope", {})
        assert status == 404

    def test_invalid_address_rejected(self, live_server):
        status, body = post(live_server + "/api/wallet/assets",
                            {"address": "garbage"})
        assert status == 400

    def test_no_transaction_endpoint_exists(self, live_server):
        """Requirement 16: nothing can move funds."""
        for path in ("/api/send", "/api/sign", "/api/broadcast",
                     "/api/wallet/sweep", "/api/transaction"):
            status, _ = post(live_server + path, {})
            assert status == 404

    def test_static_index_served(self, live_server):
        with urllib.request.urlopen(live_server + "/", timeout=10) as resp:
            body = resp.read().decode()
        assert "Hermes Wallet Inspector" in body
        assert "never asks for your seed phrase" in body.lower()

    def test_static_traversal_blocked(self, live_server):
        try:
            with urllib.request.urlopen(live_server + "/../config.py", timeout=10) as resp:
                body = resp.read().decode()
            assert "SECRET_ENV_VARS" not in body
        except urllib.error.HTTPError as exc:
            assert exc.code in (403, 404)


class TestApiUnit:
    """Direct calls to MiniAppAPI (no socket needed)."""

    def test_health_flags(self, service, settings):
        api = MiniAppAPI(service, settings=settings)
        health = api.health()
        assert health["memepol_configured"] is False
        assert health["telegram_configured"] is False

    def test_telegram_validate_reports_unconfigured_without_raising(
            self, service, settings):
        """No bot token is a server-config gap, not a bad request.

        It degrades gracefully with an explicit reason rather than throwing,
        so the Mini App can show "cannot verify" instead of an error page.
        """
        api = MiniAppAPI(service, settings=settings)
        result = api.telegram_validate(
            {"init_data": "user=%7B%22id%22%3A1%7D&hash=x"})
        assert result["valid"] is False
        assert "not configured" in result["detail"]
        assert result["status"] == "⏳"

    def test_telegram_validate_requires_init_data(self, service, settings):
        """Missing init_data IS a bad request and must raise."""
        api = MiniAppAPI(service, settings=settings)
        with pytest.raises(Exception):
            api.telegram_validate({})
