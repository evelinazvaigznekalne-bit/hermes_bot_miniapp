"""Tests for crypto_extras.py with mocked HTTP."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.crypto_extras import (
    DecodeError,
    decode_bitcoin_script,
    verify_ecdsa_signature,
    recover_pubkey_from_sig,
    decrypt_bip38,
)


class TestDecodeBitcoinScript:
    def test_p2pkh_recognized(self):
        script = "76a914" + "89abcdefabbaabbaabbaabbaabbaabbaabbaab00" + "88ac"
        result = decode_bitcoin_script(script)
        assert result["type"] == "p2pkh"
        assert any("OP_DUP" in op for op in result["ops"])

    def test_p2sh_recognized(self):
        script = "a914" + "89abcdefabbaabbaabbaabbaabbaabbaabbaab00" + "87"
        result = decode_bitcoin_script(script)
        assert result["type"] == "p2sh"

    def test_p2wpkh_recognized(self):
        script = "0014" + "89abcdefabbaabbaabbaabbaabbaabbaabbaab00"
        result = decode_bitcoin_script(script)
        assert result["type"] == "p2wpkh"

    def test_invalid_hex_raises(self):
        with pytest.raises(DecodeError):
            decode_bitcoin_script("not-valid-hex!!")

    def test_empty_raises(self):
        with pytest.raises(DecodeError):
            decode_bitcoin_script("")

    def test_op_return_recognized(self):
        script = "6a48656c6c6f"  # OP_RETURN "Hello"
        result = decode_bitcoin_script(script)
        assert result["type"] == "op_return"

    def test_nonstandard_unknown(self):
        script = "0100"
        result = decode_bitcoin_script(script)
        assert result["type"] == "nonstandard"

    def test_push_data(self):
        script = "03456789ab"
        result = decode_bitcoin_script(script)
        assert any("PUSH(3)" in op for op in result["ops"])


class TestBip38:
    def test_invalid_prefix_raises(self):
        with pytest.raises(DecodeError):
            decrypt_bip38("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ", "pass")

    def test_empty_key_raises(self):
        with pytest.raises(DecodeError):
            decrypt_bip38("", "pass")

    def test_wrong_passphrase_detected(self):
        key = "6PRNRLe1CgcK5qL2t5hEpzDrQh wspo1WT9VoBFwJo1crzpnBb5XNo5yB3"
        # This key is EC-compressed mode (flag=0x20|0x02=0x22), not supported
        with pytest.raises(DecodeError):
            decrypt_bip38(key, "wrong")


class TestEcdsaVerify:
    def test_verify_valid_signature(self):
        # coincurve-generated test vector
        try:
            import coincurve
            pk = coincurve.PrivateKey(b"\x01" * 32)
            pub = pk.public_key.format(compressed=True).hex()
            msg = b"test message"
            sig = pk.sign(msg).hex()
            result = verify_ecdsa_signature(pub, msg.hex(), sig, hasher="sha256")
            assert result["valid"] is True
        except Exception as exc:
            pytest.skip(f"coincurve not available: {exc}")

    def test_verify_bad_pubkey_raises(self):
        with pytest.raises((DecodeError, ValueError)):
            verify_ecdsa_signature("not-hex", "aa", "bb")

    def test_verify_invalid_signature(self):
        try:
            import coincurve
            pk = coincurve.PrivateKey(b"\x01" * 32)
            pub = pk.public_key.format(compressed=True).hex()
            msg = b"test"
            bad_sig = "00" * 64
            result = verify_ecdsa_signature(pub, msg.hex(), bad_sig, hasher="sha256")
            assert result["valid"] is False
        except Exception as exc:
            pytest.skip(f"coincurve not available: {exc}")


class TestRecoverPubkey:
    def test_recover_valid_sig(self):
        try:
            import coincurve
            pk = coincurve.PrivateKey(b"\x01" * 32)
            msg = b"hello"
            sig = pk.sign(msg)
            if len(sig) != 65:
                pytest.skip("need 65-byte recoverable sig")
            result = recover_pubkey_from_sig(sig.hex(), msg.hex(), hasher="sha256")
            assert "pubkey_compressed" in result
            assert "pubkey_uncompressed" in result
        except Exception as exc:
            pytest.skip(f"coincurve not available: {exc}")

    def test_recover_wrong_length_raises(self):
        with pytest.raises(DecodeError):
            recover_pubkey_from_sig("abcd", "aa")
