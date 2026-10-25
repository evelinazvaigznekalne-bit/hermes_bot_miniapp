"""Regression tests for P0 bugs in app/crypto_extras.py."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.crypto_extras import (
    DecodeError,
    _btc_balance,
    _bip32_xpub,
    _bip39_master,
    address_balance,
)


class TestBtcBalanceAccounting:
    @staticmethod
    def _make_mempool_response(*, chain_funded=1000, chain_spent=400,
                               mempool_funded=0, mempool_spent=0,
                               unconfirmed_balance=None, tx_count=5, **kwargs):
        resp = {
            "chain_stats": {
                "funded_txo_sum": chain_funded,
                "spent_txo_sum": chain_spent,
                "tx_count": tx_count,
            },
            "mempool_stats": {
                "funded_txo_sum": mempool_funded,
                "spent_txo_sum": mempool_spent,
                "tx_count": 0,
            },
        }
        if unconfirmed_balance is not None:
            resp["unconfirmed_balance"] = unconfirmed_balance
        resp.update(kwargs)
        return resp

    def test_confirmed_only(self, monkeypatch):
        response = self._make_mempool_response(chain_funded=1000, chain_spent=400)
        monkeypatch.setattr("app.crypto_extras._get_json", lambda url, **kw: response)
        result = _btc_balance("bc1qtest")
        assert result["confirmed"] == pytest.approx(0.00000600)
        assert result["unconfirmed"] == 0.0
        assert result["balance"] == pytest.approx(0.00000600)

    def test_pending_incoming(self, monkeypatch):
        response = self._make_mempool_response(
            chain_funded=1000, chain_spent=400,
            mempool_funded=200, mempool_spent=0,
        )
        monkeypatch.setattr("app.crypto_extras._get_json", lambda url, **kw: response)
        result = _btc_balance("bc1qtest")
        assert result["confirmed"] == pytest.approx(0.00000600)
        assert result["unconfirmed"] == pytest.approx(0.00000200)
        assert result["balance"] == pytest.approx(0.00000800)

    def test_pending_outgoing(self, monkeypatch):
        response = self._make_mempool_response(
            chain_funded=1000, chain_spent=400,
            mempool_funded=0, mempool_spent=300,
        )
        monkeypatch.setattr("app.crypto_extras._get_json", lambda url, **kw: response)
        result = _btc_balance("bc1qtest")
        assert result["confirmed"] == pytest.approx(0.00000600)
        # Net outgoing mempool change is negative, clamped to 0 for display.
        assert result["unconfirmed"] == 0.0
        assert result["balance"] == pytest.approx(0.00000600)

    def test_both_pending_directions(self, monkeypatch):
        response = self._make_mempool_response(
            chain_funded=1000, chain_spent=400,
            mempool_funded=200, mempool_spent=300,
        )
        monkeypatch.setattr("app.crypto_extras._get_json", lambda url, **kw: response)
        result = _btc_balance("bc1qtest")
        assert result["confirmed"] == pytest.approx(0.00000600)
        # Net outgoing (300 > 200) → unconfirmed clamped to 0.
        assert result["unconfirmed"] == 0.0
        assert result["balance"] == pytest.approx(0.00000600)

    def test_missing_fields_default_to_zero(self, monkeypatch):
        response = {}
        monkeypatch.setattr("app.crypto_extras._get_json", lambda url, **kw: response)
        result = _btc_balance("bc1qtest")
        assert result["confirmed"] == 0.0
        assert result["unconfirmed"] == 0.0
        assert result["balance"] == 0.0
        assert result["tx_count"] == 0

    def test_api_error_raises(self, monkeypatch):
        import urllib.error
        monkeypatch.setattr("app.crypto_extras._get_json",
                            lambda url, **kw: (_ for _ in ()).throw(
                                urllib.error.HTTPError(url, 500, "server error", {}, None)))
        with pytest.raises(DecodeError, match="mempool.space fetch failed"):
            _btc_balance("bc1qtest")

    def test_malformed_response_raises(self, monkeypatch):
        monkeypatch.setattr("app.crypto_extras._get_json", lambda url, **kw: "not a dict")
        with pytest.raises(DecodeError):
            _btc_balance("bc1qtest")

    def test_negative_confirmed_clamped_to_zero(self, monkeypatch):
        response = self._make_mempool_response(chain_funded=100, chain_spent=500)
        monkeypatch.setattr("app.crypto_extras._get_json", lambda url, **kw: response)
        result = _btc_balance("bc1qtest")
        assert result["confirmed"] == 0.0
        assert result["balance"] >= 0.0


class TestBip32RootPath:
    def test_root_path_m_does_not_crash(self):
        phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        mk, cc = _bip39_master(phrase)
        result = _bip32_xpub(mk, cc, "m")
        assert "xpub" in result
        assert result["depth"] == 0
        assert result["child_index"] == 0

    def test_master_xpub_has_valid_format(self):
        phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        mk, cc = _bip39_master(phrase)
        result = _bip32_xpub(mk, cc, "m")
        assert result["xpub"].startswith("xpub")
        assert result["depth"] == 0
        assert result["child_index"] == 0

    def test_depth1_parent_fingerprint_not_zero(self):
        phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        mk, cc = _bip39_master(phrase)
        result = _bip32_xpub(mk, cc, "m/44'")
        assert result["depth"] == 1
        assert result["child_index"] == 0x8000002C
        import base58
        xpub_bytes = base58.b58decode_check(result["xpub"])
        parent_fp = xpub_bytes[5:9]
        assert parent_fp != b"\x00\x00\x00\x00"


class TestBip32MultiLevelDerivation:
    def test_hardened_derivation_depth3(self):
        phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        mk, cc = _bip39_master(phrase)
        result = _bip32_xpub(mk, cc, "m/44'/0'/0'")
        assert result["depth"] == 3
        assert result["child_index"] == 0x80000000

    def test_non_hardened_derivation(self):
        phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        mk, cc = _bip39_master(phrase)
        result = _bip32_xpub(mk, cc, "m/44'/0'/0'/0/0")
        assert result["depth"] == 5
        assert result["child_index"] == 0

    def test_invalid_path_raises(self):
        phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        mk, cc = _bip39_master(phrase)
        with pytest.raises(ValueError):
            _bip32_xpub(mk, cc, "m/not-a-number'")


class TestBip32ParentFingerprintChain:
    def test_depth2_fingerprint_not_master(self):
        phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        mk, cc = _bip39_master(phrase)
        result = _bip32_xpub(mk, cc, "m/44'/0'")
        assert result["depth"] == 2
        assert result["child_index"] == 0x80000000
        import base58, hashlib
        from coincurve import PrivateKey
        xpub_bytes = base58.b58decode_check(result["xpub"])
        parent_fp = xpub_bytes[5:9]
        master_fp = hashlib.new(
            "ripemd160",
            hashlib.sha256(PrivateKey(mk).public_key.format(compressed=True)).digest(),
        ).digest()[:4]
        assert parent_fp != master_fp
        assert parent_fp != b"\x00\x00\x00\x00"

    def test_depth3_fingerprint_matches_depth2_key(self):
        phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        mk, cc = _bip39_master(phrase)
        result = _bip32_xpub(mk, cc, "m/44'/0'/0'")
        assert result["depth"] == 3
        assert result["child_index"] == 0x80000000
        import base58, hashlib, hmac
        from coincurve import PrivateKey
        from ecdsa import SECP256k1
        xpub_bytes = base58.b58decode_check(result["xpub"])
        parent_fp = xpub_bytes[5:9]
        # Re-derive depth-2 key to compute expected fingerprint
        key = mk
        ccode = cc
        for part in ["44'", "0'"]:
            idx = 0x8000002C if part == "44'" else 0x80000000
            data = b"\x00" + key + idx.to_bytes(4, "big")
            h = hmac.new(ccode, data, hashlib.sha512).digest()
            child_key = h[:32]
            child_cc = h[32:]
            priv_int = int.from_bytes(key, "big")
            child_int = int.from_bytes(child_key, "big")
            new_int = (priv_int + child_int) % SECP256k1.order
            key = new_int.to_bytes(32, "big")
            ccode = child_cc
        expected_fp = hashlib.new(
            "ripemd160",
            hashlib.sha256(PrivateKey(key).public_key.format(compressed=True)).digest(),
        ).digest()[:4]
        assert parent_fp == expected_fp


class TestBip32KnownVectors:
    @staticmethod
    def _trusted_xpub(master_key, chain_code, path):
        import hashlib, hmac, base58
        from coincurve import PrivateKey
        from ecdsa import SECP256k1
        parts = [p for p in path.split("/") if p != "m"]
        key = master_key
        cc = chain_code
        depth = 0
        parent_fingerprint = b"\x00\x00\x00\x00"
        last_idx = 0
        for part in parts:
            hardened = part.endswith("'")
            idx = int(part.rstrip("'"))
            if hardened:
                idx |= 0x80000000
            depth += 1
            # BIP32: xpub at depth d stores fingerprint of key at depth d-1.
            # The key at the START of this iteration IS the parent key.
            parent_fingerprint = hashlib.new(
                "ripemd160",
                hashlib.sha256(PrivateKey(key).public_key.format(compressed=True)).digest(),
            ).digest()[:4]
            data = b"\x00" + key + idx.to_bytes(4, "big")
            h = hmac.new(cc, data, hashlib.sha512).digest()
            child_key = h[:32]
            child_cc = h[32:]
            priv_int = int.from_bytes(key, "big")
            child_int = int.from_bytes(child_key, "big")
            new_int = (priv_int + child_int) % SECP256k1.order
            key = new_int.to_bytes(32, "big")
            cc = child_cc
            last_idx = idx
        version = b"\x04\x88\xb2\x1e"
        xpub = (
            version
            + bytes([depth])
            + parent_fingerprint
            + last_idx.to_bytes(4, "big")
            + cc
            + PrivateKey(key).public_key.format(compressed=True)
        )
        return base58.b58encode_check(xpub).decode()

    def test_known_vector_m0(self):
        phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        mk, cc = _bip39_master(phrase)
        trusted = self._trusted_xpub(mk, cc, "m/0'")
        impl = _bip32_xpub(mk, cc, "m/0'")
        assert impl["xpub"] == trusted
        assert impl["depth"] == 1
        assert impl["child_index"] == 0x80000000

    def test_known_vector_m0_0(self):
        phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        mk, cc = _bip39_master(phrase)
        trusted = self._trusted_xpub(mk, cc, "m/0'/0'")
        impl = _bip32_xpub(mk, cc, "m/0'/0'")
        assert impl["xpub"] == trusted
        assert impl["depth"] == 2
        assert impl["child_index"] == 0x80000000


class TestBip32KeyMaterialSafety:
    def test_xpub_contains_no_private_key_bytes(self):
        phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        mk, cc = _bip39_master(phrase)
        result = _bip32_xpub(mk, cc, "m/44'/0'/0'/0/0")
        import base58
        data = base58.b58decode_check(result["xpub"])
        key_data = data[45:]
        assert len(key_data) == 33
        assert key_data[0] in (0x02, 0x03)


class TestAddressBalancePublicApi:
    def test_btc_dispatch(self, monkeypatch):
        captured = {}
        def fake_btc(addr, **kw):
            captured["addr"] = addr
            return {"balance": 1.0, "source": "btc"}
        monkeypatch.setattr("app.crypto_extras._btc_balance", fake_btc)
        result = address_balance("bc1qtest")
        assert captured["addr"] == "bc1qtest"
        assert result["balance"] == 1.0

    def test_evm_dispatch(self, monkeypatch):
        captured = {}
        def fake_evm(addr, **kw):
            captured["addr"] = addr
            return {"balance": 2.0, "source": "evm"}
        monkeypatch.setattr("app.crypto_extras._evm_balance", fake_evm)
        result = address_balance("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045")
        assert captured["addr"] == "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
        assert result["balance"] == 2.0
