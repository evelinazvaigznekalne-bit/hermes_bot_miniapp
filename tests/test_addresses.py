"""Address validation tests (EVM vs Bitcoin separation)."""

from __future__ import annotations

import pytest

from app.addresses import (
    detect_address_kind,
    eip55_checksum,
    is_bitcoin_address,
    is_evm_address,
    validate_bitcoin_address,
    validate_evm_address,
)
from app.errors import AddressValidationError

SAMPLE_EVM = "0xDe0DAFC80d487b8aE652bBF906ac6c6007aE3A5e"
SAMPLE_BTC = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
SAMPLE_BTC_BECH32 = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
SAMPLE_BTC_TAPROOT = (
    "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
)


class TestEvmValidation:
    def test_valid_checksummed(self):
        assert validate_evm_address(SAMPLE_EVM) == SAMPLE_EVM

    def test_all_lowercase_accepted(self):
        assert validate_evm_address(SAMPLE_EVM.lower()).lower() == SAMPLE_EVM.lower()

    def test_all_uppercase_accepted(self):
        out = validate_evm_address("0x" + SAMPLE_EVM[2:].upper())
        assert out.lower() == SAMPLE_EVM.lower()

    def test_bad_checksum_rejected(self):
        broken = SAMPLE_EVM[:-1] + ("A" if SAMPLE_EVM[-1] != "A" else "B")
        with pytest.raises(AddressValidationError):
            validate_evm_address(broken)

    def test_checksum_computation(self):
        assert eip55_checksum(SAMPLE_EVM.lower()) == SAMPLE_EVM

    @pytest.mark.parametrize("bad", [
        "",
        "0x",
        "0x123",
        "De0DAFC80d487b8aE652bBF906ac6c6007aE3A5e",   # missing 0x
        "0xZZZDAFC80d487b8aE652bBF906ac6c6007aE3A5e",  # non-hex
        "0xDe0DAFC80d487b8aE652bBF906ac6c6007aE3A5",   # 39 chars
        "0xDe0DAFC80d487b8aE652bBF906ac6c6007aE3A5eF",  # 41 chars
    ])
    def test_invalid_rejected(self, bad):
        with pytest.raises(AddressValidationError):
            validate_evm_address(bad)
        assert is_evm_address(bad) is False


class TestBitcoinValidation:
    def test_base58_p2pkh(self):
        info = validate_bitcoin_address(SAMPLE_BTC)
        assert info.kind == "p2pkh"
        assert info.network == "mainnet"
        assert info.encoding == "base58check"

    def test_bech32_p2wpkh(self):
        info = validate_bitcoin_address(SAMPLE_BTC_BECH32)
        assert info.kind == "p2wpkh"
        assert info.encoding == "bech32"

    def test_taproot_bech32m(self):
        info = validate_bitcoin_address(SAMPLE_BTC_TAPROOT)
        assert info.kind == "p2tr"
        assert info.encoding == "bech32m"

    def test_checksum_failure_rejected(self):
        broken = SAMPLE_BTC[:-1] + ("a" if SAMPLE_BTC[-1] != "a" else "b")
        with pytest.raises(AddressValidationError):
            validate_bitcoin_address(broken)

    def test_bech32_checksum_failure_rejected(self):
        broken = SAMPLE_BTC_BECH32[:-1] + ("q" if SAMPLE_BTC_BECH32[-1] != "q" else "p")
        with pytest.raises(AddressValidationError):
            validate_bitcoin_address(broken)

    @pytest.mark.parametrize("bad", [
        "",
        "not-an-address",
        "0xDe0DAFC80d487b8aE652bBF906ac6c6007aE3A5e",
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb",  # bad checksum
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",  # bad bech32 checksum
    ])
    def test_invalid_rejected(self, bad):
        with pytest.raises(AddressValidationError):
            validate_bitcoin_address(bad)
        assert is_bitcoin_address(bad) is False


class TestFamilySeparation:
    """Requirement 6: never treat one family as the other."""

    def test_evm_not_bitcoin(self):
        assert is_evm_address(SAMPLE_EVM) is True
        assert is_bitcoin_address(SAMPLE_EVM) is False

    def test_bitcoin_not_evm(self):
        assert is_bitcoin_address(SAMPLE_BTC) is True
        assert is_evm_address(SAMPLE_BTC) is False

    def test_detect_kind(self):
        assert detect_address_kind(SAMPLE_EVM) == "evm"
        assert detect_address_kind(SAMPLE_BTC) == "bitcoin"
        assert detect_address_kind(SAMPLE_BTC_BECH32) == "bitcoin"
        assert detect_address_kind("garbage") is None
        assert detect_address_kind(None) is None
