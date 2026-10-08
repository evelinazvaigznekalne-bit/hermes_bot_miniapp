"""API tests for the secret-scan endpoint.

Two properties matter:
  1. It detects secrets.
  2. The response body and the server log never contain the raw value.
"""

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
from app.webapp.server import MiniAppAPI, create_server

EVM_KEY = "0x" + "a3f1" * 16
BOT_TOKEN = "8881860201:AAHfakeTokenValuexxxxxxxxxxxxxxxxxxxx"
MNEMONIC = ("legal winner thank year wave sausage worth useful legal winner "
            "thank yellow")
CARD = "4111111111111111"


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


class TestScanApiUnit:
    @pytest.fixture
    def api(self, settings, tracker):
        registry = ChainRegistry()
        registry.register(StubProvider())
        service = WalletService(settings, tracker=tracker, registry=registry)
        return MiniAppAPI(service, settings=settings)

    def test_clean_text(self, api):
        r = api.scan_secrets({"text": "nothing sensitive here"})
        assert r["clean"] is True
        assert r["count"] == 0
        assert r["findings"] == []
        assert r["status"] == "✓"

    def test_detects_private_key(self, api):
        r = api.scan_secrets({"text": f"key {EVM_KEY}"})
        assert r["clean"] is False
        assert r["count"] == 1
        assert r["findings"][0]["kind"] == "evm_private_key"
        assert r["status"] == "✗"

    def test_detects_several(self, api):
        r = api.scan_secrets({"text": f"{EVM_KEY} {BOT_TOKEN} {MNEMONIC}"})
        assert r["count"] >= 3

    def test_empty_body_is_clean(self, api):
        assert api.scan_secrets({})["clean"] is True

    def test_rejects_non_string(self, api):
        with pytest.raises(Exception):
            api.scan_secrets({"text": 12345})

    def test_rejects_oversized_input(self, api):
        with pytest.raises(Exception):
            api.scan_secrets({"text": "a" * 200_001})

    def test_response_carries_no_raw_secret(self, api):
        for secret in (EVM_KEY, BOT_TOKEN, MNEMONIC, CARD):
            r = api.scan_secrets({"text": f"x {secret} y"})
            assert secret not in json.dumps(r), "raw secret leaked in response"

    def test_notice_states_no_storage(self, api):
        r = api.scan_secrets({"text": EVM_KEY})
        assert "never stores" in r["notice"]


class TestScanApiOverHttp:
    @pytest.fixture
    def base_url(self, settings, tracker):
        registry = ChainRegistry()
        registry.register(StubProvider())
        service = WalletService(settings, tracker=tracker, registry=registry)
        httpd = create_server(service, "127.0.0.1", 0, settings=settings)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
        httpd.shutdown()
        httpd.server_close()

    @staticmethod
    def _post(url, payload):
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode(), method="POST",
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read())

    def test_endpoint_detects_and_redacts(self, base_url):
        status, body = self._post(base_url + "/api/security/scan",
                                  {"text": f"key {EVM_KEY}"})
        assert status == 200
        assert body["count"] == 1
        assert EVM_KEY not in json.dumps(body)
        assert "•" in body["findings"][0]["redacted"]

    def test_clean_input_over_http(self, base_url):
        status, body = self._post(base_url + "/api/security/scan",
                                  {"text": "hello"})
        assert status == 200
        assert body["clean"] is True

    def test_bad_payload_is_400(self, base_url):
        req = urllib.request.Request(
            base_url + "/api/security/scan",
            data=json.dumps({"text": 12345}).encode(), method="POST",
            headers={"Content-Type": "application/json"})
        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(req, timeout=15)
        assert e.value.code == 400

    def test_secret_not_written_to_log(self, base_url, settings, tmp_path):
        """The scanned secret must not reach any log file."""
        secret = "0x" + "deadbeef" * 8
        self._post(base_url + "/api/security/scan", {"text": f"k {secret}"})
        import time
        time.sleep(0.3)
        hits = []
        for path in tmp_path.rglob("*"):
            if path.is_file():
                try:
                    if secret in path.read_text(errors="ignore"):
                        hits.append(str(path))
                except OSError:
                    pass
        assert not hits, f"secret written to {hits}"
