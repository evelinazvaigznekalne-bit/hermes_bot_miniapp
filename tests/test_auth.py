"""Signature verification + nonce/session tests."""

from __future__ import annotations

import pytest

from app.auth import (
    NonceStore,
    SessionIssuer,
    personal_sign_hash,
    recover_evm_address,
    verify_evm_signature,
)
from app.errors import NonceError, SignatureError

PRIV_A = "11" * 32
PRIV_B = "22" * 32


def _signer(private_hex: str):
    from eth_keys import keys

    return keys.PrivateKey(bytes.fromhex(private_hex))


def sign(private_hex: str, message: str) -> str:
    from eth_keys import keys

    priv = keys.PrivateKey(bytes.fromhex(private_hex))
    sig = priv.sign_msg_hash(personal_sign_hash(message))
    return "0x" + sig.to_bytes().hex()


class TestSignatureRecovery:
    def test_recover_matches_signer(self):
        priv = _signer(PRIV_A)
        addr = priv.public_key.to_checksum_address()
        message = f"hermes-bot-miniapp authentication\nAddress: {addr}\nNonce: abc"
        assert recover_evm_address(message, sign(PRIV_A, message)) == addr

    def test_verify_accepts_correct_signer(self):
        priv = _signer(PRIV_A)
        addr = priv.public_key.to_checksum_address()
        message = f"hermes-bot-miniapp authentication\nAddress: {addr}\nNonce: 1"
        assert verify_evm_signature(message, sign(PRIV_A, message), addr) == addr

    def test_verify_rejects_wrong_signer(self):
        priv_a = _signer(PRIV_A)
        addr_a = priv_a.public_key.to_checksum_address()
        message = f"hermes-bot-miniapp authentication\nAddress: {addr_a}\nNonce: 1"
        other = _signer(PRIV_B).public_key.to_checksum_address()
        with pytest.raises(SignatureError):
            verify_evm_signature(message, sign(PRIV_B, message), addr_a)
        assert other != addr_a

    def test_verify_rejects_tampered_message(self):
        priv = _signer(PRIV_A)
        addr = priv.public_key.to_checksum_address()
        message = f"hermes-bot-miniapp authentication\nAddress: {addr}\nNonce: 1"
        sig = sign(PRIV_A, message)
        tampered = message.replace("Nonce: 1", "Nonce: 2")
        with pytest.raises(SignatureError):
            verify_evm_signature(tampered, sig, addr)

    def test_verify_rejects_foreign_domain(self):
        priv = _signer(PRIV_A)
        addr = priv.public_key.to_checksum_address()
        message = f"evil-domain authentication\nAddress: {addr}\nNonce: 1"
        with pytest.raises(SignatureError):
            verify_evm_signature(message, sign(PRIV_A, message), addr)

    def test_verify_rejects_address_not_in_message(self):
        priv = _signer(PRIV_A)
        addr = priv.public_key.to_checksum_address()
        other = _signer(PRIV_B).public_key.to_checksum_address()
        message = f"hermes-bot-miniapp authentication\nAddress: {other}\nNonce: 1"
        with pytest.raises(SignatureError):
            verify_evm_signature(message, sign(PRIV_A, message), addr)

    @pytest.mark.parametrize("bad", [
        "", "0x", "0xdeadbeef", "zz" * 65, "0x" + "11" * 64,
    ])
    def test_malformed_signatures_rejected(self, bad):
        with pytest.raises(SignatureError):
            recover_evm_address("msg", bad)


class TestNonceStore:
    def test_issue_and_consume(self):
        store = NonceStore(ttl_seconds=60)
        nonce, message, ttl = store.issue("0xDe0DAFC80d487b8aE652bBF906ac6c6007aE3A5e")
        assert nonce in message
        assert ttl == 60
        record = store.consume(nonce)
        assert record.address.lower().startswith("0xde0dafc8")

    def test_single_use(self):
        store = NonceStore()
        nonce, _, _ = store.issue("0xDe0DAFC80d487b8aE652bBF906ac6c6007aE3A5e")
        store.consume(nonce)
        with pytest.raises(NonceError):
            store.consume(nonce)

    def test_unknown_nonce(self):
        with pytest.raises(NonceError):
            NonceStore().consume("nope")

    def test_expiry(self):
        clock = {"t": 1000.0}
        store = NonceStore(ttl_seconds=10, clock=lambda: clock["t"])
        nonce, _, _ = store.issue("0xDe0DAFC80d487b8aE652bBF906ac6c6007aE3A5e")
        clock["t"] += 11
        with pytest.raises(NonceError):
            store.consume(nonce)

    def test_invalid_address_rejected(self):
        from app.errors import AddressValidationError

        with pytest.raises(AddressValidationError):
            NonceStore().issue("not-an-address")


class TestSessionIssuer:
    def test_roundtrip(self):
        issuer = SessionIssuer(secret="test-secret")
        token, expires = issuer.issue("0xDe0DAFC80d487b8aE652bBF906ac6c6007aE3A5e")
        assert issuer.verify(token).lower() == "0xde0dafc80d487b8ae652bbf906ac6c6007ae3a5e"
        assert expires > 0

    def test_tampered_token_rejected(self):
        issuer = SessionIssuer(secret="test-secret")
        token, _ = issuer.issue("0xDe0DAFC80d487b8aE652bBF906ac6c6007aE3A5e")
        with pytest.raises(SignatureError):
            issuer.verify(token[:-1] + ("0" if token[-1] != "0" else "1"))

    def test_wrong_secret_rejected(self):
        token, _ = SessionIssuer(secret="a").issue("0xDe0DAFC80d487b8aE652bBF906ac6c6007aE3A5e")
        with pytest.raises(SignatureError):
            SessionIssuer(secret="b").verify(token)

    def test_expired_rejected(self):
        issuer = SessionIssuer(secret="s", ttl_seconds=-1)
        token, _ = issuer.issue("0xDe0DAFC80d487b8aE652bBF906ac6c6007aE3A5e")
        with pytest.raises(SignatureError):
            issuer.verify(token)
