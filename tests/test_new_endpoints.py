"""HTTP endpoint tests for the crypto reverse-engineering and puzzle-strategy surfaces.

These exercise the real request router, not just the handler functions, so a route that
was never wired is a failing test rather than a silently missing feature.
"""

from __future__ import annotations

import base64
import json
import struct
import threading
import urllib.error
import urllib.request

import pytest

from app.webapp.server import MiniAppAPI, create_server

try:
    from app.chains.base import Asset, AssetReport
    from app.chains.registry import ChainRegistry
    from app.service import WalletService
    _HAS_CHAINS = True
except ImportError:      # pragma: no cover - environment guard
    _HAS_CHAINS = False

LEGACY_ETH_TX = (
    "0xf86c098504a817c80082520894353535353535353535353535353535353535353588"
    "0de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1"
    "590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1"
    "966a3b6d83"
)

BTC_LEGACY = ("01000000" "01" + "11" * 32 + "00000000" + "00" + "ffffffff"
              "01" + (100000000).to_bytes(8, "little").hex()
              + "19" + "76a914" + "ab" * 20 + "88ac" + "00000000")


class _StubProvider:
    """Minimal EVM provider so the catalog/service build without network access."""

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
        report.balance_native = 1.0
        report.assets.append(Asset(symbol="ETH", amount=1.0, raw="1", decimals=18))
        return report


@pytest.fixture
def service(settings, tracker):
    if not _HAS_CHAINS:      # pragma: no cover - environment guard
        pytest.skip("chain modules unavailable")
    registry = ChainRegistry()
    registry.register(_StubProvider())
    return WalletService(settings, tracker=tracker, registry=registry)


@pytest.fixture
def api(service, settings):
    return MiniAppAPI(service, settings=settings)


@pytest.fixture
def live(service, settings):
    httpd = create_server(service, "127.0.0.1", 0, settings=settings)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    host, port = httpd.server_address[:2]
    yield f"http://{host}:{port}"
    httpd.shutdown()
    httpd.server_close()


def _post(base, path, body):
    req = urllib.request.Request(
        base + path, data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode())


# ---------------------------------------------------------------------------
# Transaction decoder
# ---------------------------------------------------------------------------

class TestDecodeTransactionEndpoint:
    def test_decodes_a_bitcoin_transaction(self, api):
        r = api.tools_decode_transaction({"raw": BTC_LEGACY})
        assert r["decoded_as"] == "btc"
        assert r["outputs"][0]["value_btc"] == 1.0
        assert r["status"] == "✓"

    def test_decodes_an_ethereum_transaction(self, api):
        r = api.tools_decode_transaction({"raw": LEGACY_ETH_TX})
        assert r["decoded_as"] == "eth"
        assert r["value_eth"] == pytest.approx(1.0)
        assert r["chain_id"] == 1

    def test_missing_input_is_a_validation_error(self, api):
        from app.errors import ValidationError
        with pytest.raises(ValidationError):
            api.tools_decode_transaction({})

    def test_bad_hex_is_a_validation_error(self, api):
        from app.errors import ValidationError
        with pytest.raises(ValidationError):
            api.tools_decode_transaction({"raw": "zz"})

    def test_route_is_wired(self, live):
        status, body = _post(live, "/api/tools/decode-transaction", {"raw": BTC_LEGACY})
        assert status == 200
        assert body["decoded_as"] == "btc"


# ---------------------------------------------------------------------------
# Transaction decoder serialization (v, r, s as hex strings)
# ---------------------------------------------------------------------------

class TestDecodeTransactionSerialization:
    """Ensure byte-valued v, r, s fields are serialized as hex strings."""

    def test_eth_v_r_s_are_strings(self, api):
        r = api.tools_decode_transaction({"raw": LEGACY_ETH_TX})
        assert r["decoded_as"] == "eth"
        for key in ("v", "r", "s"):
            assert key in r, f"missing {key}"
            assert isinstance(r[key], str), f"{key} must be string, got {type(r[key])}"
            # v should be a hex string like "25", r and s should be 64-char hex
            if key == "v":
                assert len(r[key]) == 2, f"v should be 2-char hex, got {r[key]}"
                int(r[key], 16)  # valid hex
            else:
                assert len(r[key]) == 64, f"{key} should be 64-char hex, got {r[key]}"
                int(r[key], 16)  # valid hex

    def test_btc_has_no_v_r_s(self, api):
        r = api.tools_decode_transaction({"raw": BTC_LEGACY})
        assert r["decoded_as"] == "btc"
        for key in ("v", "r", "s"):
            assert key not in r, f"BTC tx should not have {key}"

    def test_eth_result_is_json_serializable(self, live):
        """The full ETH result must survive ``json.dumps`` -- this is the 500.

        ``decode_transaction`` returns ``v``/``r``/``s`` as raw bytes.  The
        handler converts them to hex; if that conversion is missing, the
        stdlib JSON encoder raises ``TypeError`` and the router answers 500.
        """
        status, body = _post(live, "/api/tools/decode-transaction",
                             {"raw": LEGACY_ETH_TX, "chain": "ethereum"})
        assert status == 200, f"expected 200, got {status}: {body}"
        assert body["decoded_as"] == "eth"
        # Round-trip through JSON exactly as the HTTP layer does.
        json.dumps(body)
        for key in ("v", "r", "s"):
            assert isinstance(body[key], str), f"{key} must be hex, got {body[key]!r}"

    def test_eth_sender_is_recovered(self, api):
        r = api.tools_decode_transaction({"raw": LEGACY_ETH_TX, "chain": "ethereum"})
        assert r["decoded_as"] == "eth"
        assert r["sender"] == "0xe75f08b448ce1176b3b7cd2be43181c9e752dfd5"

    def test_eth_route_is_wired(self, live):
        status, body = _post(live, "/api/tools/decode-transaction",
                             {"raw": LEGACY_ETH_TX, "chain": "ethereum"})
        assert status == 200
        assert body["decoded_as"] == "eth"
        assert body["value_eth"] == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# Mnemonic
# ---------------------------------------------------------------------------

class TestMnemonicEndpoint:
    def test_valid_phrase(self, api):
        r = api.tools_convert_mnemonic(
            {"phrase": "legal winner thank year wave sausage worth useful legal "
                       "winner thank yellow"})
        assert r["valid"] is True
        assert r["status"] == "✓"

    def test_invalid_checksum_is_not_an_error(self, api):
        r = api.tools_convert_mnemonic(
            {"phrase": "legal winner thank year wave sausage worth useful legal "
                       "winner thank thank"})
        assert r["valid"] is False
        assert r["status"] == "✗"

    def test_missing_phrase_is_a_validation_error(self, api):
        from app.errors import ValidationError
        with pytest.raises(ValidationError):
            api.tools_convert_mnemonic({})

    def test_route_is_wired(self, live):
        status, body = _post(live, "/api/tools/mnemonic",
                             {"phrase": "legal winner thank year wave sausage worth "
                                        "useful legal winner thank yellow"})
        assert status == 200
        assert body["valid"] is True


# ---------------------------------------------------------------------------
# Key calculator
# ---------------------------------------------------------------------------

class TestCalculatorEndpoint:
    def test_derives_known_addresses(self, api):
        r = api.tools_crypto_calculator({"key": "0" * 63 + "1"})
        assert r["chains"]["bitcoin"]["p2pkh_compressed"] == \
            "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"

    def test_out_of_range_key_is_reported_not_raised(self, api):
        r = api.tools_crypto_calculator({"key": "00" * 32})
        assert r["in_range"] is False
        assert r["chains"] == {}

    def test_missing_key_is_a_validation_error(self, api):
        from app.errors import ValidationError
        with pytest.raises(ValidationError):
            api.tools_crypto_calculator({})

    def test_route_is_wired(self, live):
        status, body = _post(live, "/api/tools/calculator", {"key": "0" * 63 + "1"})
        assert status == 200
        assert body["in_range"] is True


# ---------------------------------------------------------------------------
# wallet.dat
# ---------------------------------------------------------------------------

def _wallet_dat() -> bytes:
    out = bytearray(b"\x62\x31\x05\x00" + b"\x00" * 60)
    for raw_type, payload in (
            (b"version", struct.pack("<I", 169900)),
            (b"mkey", b"\x11" * 32 + b"\x00" + struct.pack("<Q", 25000) + b"\x22" * 48),
            (b"minversion", struct.pack("<I", 169900)),
            (b"bestblock", b"\x33" * 80)):
        out += bytes([len(raw_type)]) + raw_type + payload
    if len(out) < 2048:
        out += b"\x00" * (2048 - len(out))
    return bytes(out)


class TestWalletDatEndpoint:
    def test_accepts_base64_upload(self, api):
        r = api.tools_parse_wallet_dat(
            {"base64_data": base64.b64encode(_wallet_dat()).decode()})
        assert r["encrypted"] is True
        assert r["version"] == 169900
        assert "wallet version" in r["records"]

    def test_accepts_a_server_side_path(self, api, tmp_path):
        p = tmp_path / "wallet.dat"
        p.write_bytes(_wallet_dat())
        r = api.tools_parse_wallet_dat({"path": str(p)})
        assert r["source"] == str(p)

    def test_missing_file_is_a_validation_error(self, api):
        from app.errors import ValidationError
        with pytest.raises(ValidationError):
            api.tools_parse_wallet_dat({"path": "/nonexistent/wallet.dat"})

    def test_neither_source_is_a_validation_error(self, api):
        from app.errors import ValidationError
        with pytest.raises(ValidationError):
            api.tools_parse_wallet_dat({})

    def test_bad_base64_is_a_validation_error(self, api):
        from app.errors import ValidationError
        with pytest.raises(ValidationError):
            api.tools_parse_wallet_dat({"base64_data": "!!!not-base64!!!"})

    def test_route_is_wired(self, live):
        status, body = _post(live, "/api/tools/wallet-dat",
                             {"base64_data": base64.b64encode(_wallet_dat()).decode()})
        assert status == 200
        assert body["encrypted"] is True


# ---------------------------------------------------------------------------
# Puzzle strategy identification
# ---------------------------------------------------------------------------

class TestClassifyEndpoint:
    def test_classifies_a_catalog_slug(self, api):
        r = api.puzzles_classify({"slug": "peter-todd-hash-collision-bounties-0-59btc"})
        assert r["family"] == "math"
        assert r["status"] == "✓"

    def test_classifies_free_text(self, api):
        r = api.puzzles_classify({"text": "find the private key hidden in this image"})
        assert r["family"]
        assert r["inferred"] is True

    def test_unknown_slug_is_a_validation_error(self, api):
        from app.errors import ValidationError
        with pytest.raises(ValidationError):
            api.puzzles_classify({"slug": "no-such-puzzle-xyz"})

    def test_neither_input_is_a_validation_error(self, api):
        from app.errors import ValidationError
        with pytest.raises(ValidationError):
            api.puzzles_classify({})

    def test_catalog_distribution(self, api):
        r = api.puzzles_classify_catalog()
        assert r["count"] > 0
        assert sum(r["distribution"].values()) == r["count"]

    def test_route_is_wired(self, live):
        status, body = _post(live, "/api/puzzles/classify",
                             {"slug": "peter-todd-hash-collision-bounties-0-59btc"})
        assert status == 200
        assert body["family"] == "math"

    def test_catalog_route_is_wired(self, live):
        status, body = _post(live, "/api/puzzles/classify-catalog", {})
        assert status == 200
        assert body["count"] > 0


class TestPlanAndAttackEndpoints:
    def test_plan_returns_a_first_move(self, api):
        r = api.puzzles_plan({"slug": "gsmg-io-5btc-puzzle"})
        assert r["family"] == "brute_force"
        assert r["first_move"]

    def test_attack_reports_outcome_vocabulary(self, api):
        r = api.puzzles_attack({"slug": "peter-todd-hash-collision-bounties-0-59btc"})
        assert r["outcome"] in ("match", "infeasible", "uncertified",
                                "needs_input", "skipped")
        assert "status" in r

    def test_attack_capacity_path(self, api):
        r = api.puzzles_attack({"slug": "wares-wallets-solana",
                                "extra": {"symbols": 59, "bits_per_symbol": 1}})
        assert r["outcome"] == "infeasible"

    def test_missing_slug_is_a_validation_error(self, api):
        from app.errors import ValidationError
        with pytest.raises(ValidationError):
            api.puzzles_plan({})

    def test_plan_route_is_wired(self, live):
        status, body = _post(live, "/api/puzzles/plan",
                             {"slug": "gsmg-io-5btc-puzzle"})
        assert status == 200
        assert body["family"] == "brute_force"

    def test_attack_route_is_wired(self, live):
        status, body = _post(live, "/api/puzzles/attack",
                             {"slug": "peter-todd-hash-collision-bounties-0-59btc"})
        assert status == 200
        assert body["outcome"] in ("match", "infeasible", "uncertified",
                                   "needs_input", "skipped")


# ---------------------------------------------------------------------------
# Seed validation
# ---------------------------------------------------------------------------

class TestSeedValidateEndpoint:
    def test_valid_phrase(self, api):
        r = api.tools_seed_validate(
            {"phrase": "legal winner thank year wave sausage worth useful legal "
                       "winner thank yellow"})
        assert r["valid"] is True
        assert r["word_count"] == 12
        assert "error" not in r or r.get("error") is None

    def test_invalid_checksum(self, api):
        r = api.tools_seed_validate(
            {"phrase": "legal winner thank year wave sausage worth useful legal "
                       "winner thank thank"})
        assert r["valid"] is False
        assert r["word_count"] == 12
        assert "error" in r and r["error"] is not None

    def test_invalid_word_count(self, api):
        r = api.tools_seed_validate({"phrase": "legal winner thank"})
        assert r["valid"] is False
        assert r["word_count"] == 3
        assert "error" in r and r["error"] is not None

    def test_missing_phrase(self, api):
        r = api.tools_seed_validate({})
        assert r["valid"] is False
        assert r["word_count"] == 0
        assert "error" in r and r["error"] is not None

    def test_route_is_wired(self, live):
        status, body = _post(live, "/api/tools/seed-validate",
                             {"phrase": "legal winner thank year wave sausage worth useful legal "
                                        "winner thank yellow"})
        assert status == 200
        assert body["valid"] is True
        assert body["word_count"] == 12


# ---------------------------------------------------------------------------
# Address derivation
# ---------------------------------------------------------------------------

class TestDeriveAddressesEndpoint:
    def test_valid_phrase(self, api):
        r = api.tools_derive_addresses(
            {"phrase": "legal winner thank year wave sausage worth useful legal "
                       "winner thank yellow", "count": 3})
        assert "btc" in r and "eth" in r
        assert len(r["btc"]) == 3
        assert len(r["eth"]) == 3
        assert "error" not in r or r.get("error") is None
        # Check structure
        assert r["btc"][0]["path"] == "m/44'/0'/0'/0/0"
        assert "p2pkh" in r["btc"][0]
        assert "p2wpkh" in r["btc"][0]
        assert r["eth"][0]["path"] == "m/44'/60'/0'/0/0"
        assert "address" in r["eth"][0]
        assert r["eth"][0]["address"].startswith("0x")

    def test_invalid_phrase(self, api):
        r = api.tools_derive_addresses({"phrase": "invalid phrase", "count": 1})
        assert r["btc"] == []
        assert r["eth"] == []
        assert "error" in r and r["error"] is not None

    def test_missing_phrase(self, api):
        r = api.tools_derive_addresses({})
        assert r["btc"] == []
        assert r["eth"] == []
        assert "error" in r and r["error"] is not None

    def test_route_is_wired(self, live):
        status, body = _post(live, "/api/tools/derive-addresses",
                             {"phrase": "legal winner thank year wave sausage worth useful legal "
                                        "winner thank yellow", "count": 2})
        assert status == 200
        assert len(body["btc"]) == 2
        assert len(body["eth"]) == 2
        assert "error" not in body or body.get("error") is None
