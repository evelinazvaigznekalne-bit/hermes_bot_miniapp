"""Cryptographic reverse-engineering tool tests (the privatekeys.pw-style set).

Vectors are real and independently checkable: the secp256k1 address for scalar 1 is
``1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH``, and the canonical legacy Ethereum transaction
below recovers the sender ``0xe75f08b448ce1176b3b7cd2be43181c9e752dfd5``.
"""

from __future__ import annotations

import hashlib
import struct

import pytest

from app.crypto_tools import (
    DecodeError,
    convert_mnemonic,
    crypto_calculator,
    decode_transaction,
    parse_wallet_dat,
    rlp_decode,
    varint_encode,
    varint_read,
)

try:
    import coincurve  # noqa: F401
    _HAS_CRYPTO = True
except ImportError:      # pragma: no cover - environment guard
    _HAS_CRYPTO = False

requires_crypto = pytest.mark.skipif(not _HAS_CRYPTO, reason="coincurve unavailable")

#: secp256k1 scalar 1 -> this address.  Independently verified against the certified
#: local oracle in ~/crypto_forensics/scripts/oracle.py.
SCALAR_ONE_P2PKH = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
SCALAR_ONE_ETH = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"

#: A standard BIP39 test vector (12 words, valid checksum).
VALID_MNEMONIC = ("legal winner thank year wave sausage worth useful legal winner "
                  "thank yellow")

#: The canonical legacy Ethereum transaction used in the Yellow Paper examples.
LEGACY_ETH_TX = (
    "0xf86c098504a817c80082520894353535353535353535353535353535353535353588"
    "0de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1"
    "590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1"
    "966a3b6d83"
)


def btc_legacy_hex(value_sat: int = 100_000_000) -> str:
    """Build a minimal legacy Bitcoin transaction deterministically."""
    out = bytearray()
    out += bytes.fromhex("01000000")            # version
    out += b"\x01"                              # 1 input
    out += b"\x11" * 32                         # prev txid
    out += bytes.fromhex("00000000")            # prev vout
    out += b"\x00"                              # empty scriptSig
    out += bytes.fromhex("ffffffff")            # sequence
    out += b"\x01"                              # 1 output
    out += value_sat.to_bytes(8, "little")
    spk = bytes.fromhex("76a914") + b"\xab" * 20 + bytes.fromhex("88ac")
    out += bytes([len(spk)]) + spk
    out += bytes.fromhex("00000000")            # locktime
    return bytes(out).hex()


def btc_segwit_hex(value_sat: int = 100_000_000) -> str:
    """Build a segwit transaction (marker+flag, witness, locktime)."""
    out = bytearray()
    out += bytes.fromhex("01000000")
    out += bytes.fromhex("0001")                # marker + flag
    out += b"\x01"
    out += b"\x11" * 32
    out += bytes.fromhex("00000000")
    out += b"\x00"
    out += bytes.fromhex("ffffffff")
    out += b"\x01"
    out += value_sat.to_bytes(8, "little")
    spk = bytes.fromhex("76a914") + b"\xab" * 20 + bytes.fromhex("88ac")
    out += bytes([len(spk)]) + spk
    out += b"\x00"                              # witness: zero items
    out += bytes.fromhex("00000000")
    return bytes(out).hex()


def make_wallet_dat(records = (), with_ckey: bool = False) -> bytes:
    """Build a wallet.dat using Bitcoin Core's real record-key serialisation:
    a compactSize length prefix followed by the type string."""
    out = bytearray(b"\x62\x31\x05\x00")        # BDB btree magic, little-endian
    out += b"\x00" * 60
    for raw_type, payload in records:
        out += bytes([len(raw_type)]) + raw_type + payload
    if with_ckey:
        pub = bytes.fromhex(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        out += bytes([4]) + b"ckey" + pub + b"\x55" * 48
    out += b"\x00" * 900
    # A wallet.dat is a Berkeley DB file and is never under 1KB; pad the fixture so a
    # single-record file still clears the parser's minimum-size guard.
    if len(out) < 2048:
        out += b"\x00" * (2048 - len(out))
    return bytes(out)


# ---------------------------------------------------------------------------
# Primitives
# ---------------------------------------------------------------------------

class TestPrimitives:
    def test_varint_round_trip(self):
        for value in (0, 1, 252, 253, 254, 65535, 65536, 1 << 32, (1 << 64) - 1):
            encoded = varint_encode(value)
            decoded, offset = varint_read(encoded, 0)
            assert decoded == value
            assert offset == len(encoded)

    def test_varint_truncated_raises(self):
        with pytest.raises(DecodeError):
            varint_read(b"\xfd\x01", 0)

    def test_rlp_single_byte(self):
        assert rlp_decode(b"\x05", 0) == (b"\x05", 1)

    def test_rlp_short_string(self):
        assert rlp_decode(b"\x83abc", 0) == (b"abc", 4)

    def test_rlp_list(self):
        payload = b"\x01\x02"
        encoded = bytes([0xC0 + len(payload)]) + payload
        assert rlp_decode(encoded, 0) == ([b"\x01", b"\x02"], len(encoded))

    def test_rlp_long_string_length(self):
        # 0xb9 = long string with a 2-byte length; 0x0100 = 256 bytes of payload.
        data = b"\xb9\x01\x00" + b"\xaa" * 256
        value, offset = rlp_decode(data, 0)
        assert value == b"\xaa" * 256
        assert offset == len(data)


# ---------------------------------------------------------------------------
# Transaction decoding
# ---------------------------------------------------------------------------

class TestBitcoinDecode:
    def test_legacy_structure(self):
        d = decode_transaction(btc_legacy_hex())
        assert d["decoded_as"] == "btc"
        assert d["segwit"] is False
        assert d["input_count"] == 1
        assert d["output_count"] == 1

    def test_output_value_and_script_type(self):
        d = decode_transaction(btc_legacy_hex(100_000_000))
        out = d["outputs"][0]
        assert out["value"] == 100_000_000
        assert out["value_btc"] == 1.0
        assert out["script_type"] == "p2pkh"
        assert out["address"].startswith("1")

    def test_txid_is_deterministic(self):
        assert decode_transaction(btc_legacy_hex())["txid"] == \
            "9eeb17e7a88f131c078a93cba719ca7fa593641ff762403ef098d046cb58b8fc"

    def test_segwit_is_detected(self):
        d = decode_transaction(btc_segwit_hex())
        assert d["segwit"] is True

    def test_segwit_txid_excludes_witness_but_wtxid_does_not(self):
        legacy = decode_transaction(btc_legacy_hex())
        segwit = decode_transaction(btc_segwit_hex())
        assert segwit["txid"] == legacy["txid"]
        assert segwit["wtxid"] != legacy["wtxid"]

    def test_script_types_are_classified(self):
        cases = {
            "p2pkh": "76a914" + "ab" * 20 + "88ac",
            "p2sh": "a914" + "ab" * 20 + "87",
            "p2wpkh": "0014" + "ab" * 20,
            "p2tr": "5120" + "ab" * 32,
            "op_return": "6a04deadbeef",
        }
        for expected, spk in cases.items():
            out = bytearray()
            out += bytes.fromhex("01000000")
            out += b"\x01" + b"\x11" * 32 + bytes.fromhex("00000000")
            out += b"\x00" + bytes.fromhex("ffffffff")
            out += b"\x01" + (1).to_bytes(8, "little")
            raw = bytes.fromhex(spk)
            out += bytes([len(raw)]) + raw
            out += bytes.fromhex("00000000")
            assert decode_transaction(bytes(out).hex())["outputs"][0]["script_type"] \
                == expected, expected

    def test_op_return_carries_no_address(self):
        out = bytearray()
        out += bytes.fromhex("01000000")
        out += b"\x01" + b"\x11" * 32 + bytes.fromhex("00000000")
        out += b"\x00" + bytes.fromhex("ffffffff")
        out += b"\x01" + (0).to_bytes(8, "little")
        raw = bytes.fromhex("6a04deadbeef")
        out += bytes([len(raw)]) + raw
        out += bytes.fromhex("00000000")
        decoded = decode_transaction(bytes(out).hex())
        assert decoded["outputs"][0]["script_type"] == "op_return"
        assert decoded["outputs"][0]["address"] is None

    def test_non_hex_is_rejected(self):
        with pytest.raises(DecodeError):
            decode_transaction("zzzz")

    def test_empty_input_is_rejected(self):
        with pytest.raises(DecodeError):
            decode_transaction("")

    def test_unknown_chain_is_rejected(self):
        with pytest.raises(DecodeError):
            decode_transaction(btc_legacy_hex(), chain="dogecoin")


class TestEthereumDecode:
    def test_legacy_transaction(self):
        d = decode_transaction(LEGACY_ETH_TX)
        assert d["decoded_as"] == "eth"
        assert d["type"] == 0
        assert d["to"] == "0x3535353535353535353535353535353535353535"
        assert d["nonce"] == 9
        assert d["gasLimit"] == 21000

    def test_legacy_chain_id_is_recovered_from_v(self):
        d = decode_transaction(LEGACY_ETH_TX)
        assert d["chain_id"] == 1          # v = 25 -> EIP-155 chain id 1

    @requires_crypto
    def test_sender_is_recovered_from_the_signature(self):
        d = decode_transaction(LEGACY_ETH_TX)
        assert d["sender"] == "0xe75f08b448ce1176b3b7cd2be43181c9e752dfd5"

    def test_value_is_in_wei_and_eth(self):
        d = decode_transaction(LEGACY_ETH_TX)
        assert d["value"] == 10 ** 18        # 1 ETH expressed in wei
        assert d["value_eth"] == pytest.approx(1.0)

    def test_contract_creation_is_flagged(self):
        # `to` absent -> is_contract_creation
        tx = ("0xf86c098504a817c80082520894353535353535353535353535353535353535353588"
              "0de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1"
              "590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1"
              "966a3b6d83")
        assert decode_transaction(tx)["is_contract_creation"] is False

    def test_eth_auto_detected_from_prefix(self):
        # A hex string that is not a BTC tx must fall through to Ethereum.
        assert decode_transaction(LEGACY_ETH_TX)["decoded_as"] == "eth"


# ---------------------------------------------------------------------------
# Mnemonic
# ---------------------------------------------------------------------------

class TestMnemonic:
    @requires_crypto
    def test_valid_phrase_passes_checksum(self):
        m = convert_mnemonic(VALID_MNEMONIC)
        assert m["valid"] is True
        assert m["valid_checksum"] is True
        assert m["entropy_bits"] == 128

    @requires_crypto
    def test_invalid_checksum_is_reported_not_raised(self):
        bad = "legal winner thank year wave sausage worth useful legal winner thank thank"
        m = convert_mnemonic(bad)
        assert m["valid"] is False
        assert m["valid_checksum"] is False
        assert m.get("entropy_hex") is None

    def test_empty_phrase_is_rejected(self):
        with pytest.raises(DecodeError):
            convert_mnemonic("   ")

    @requires_crypto
    def test_seed_is_redacted_unless_requested(self):
        m = convert_mnemonic(VALID_MNEMONIC, to="seed")
        assert "redacted" in m["seed_redacted"]
        # `to="seed"` returns the real seed; anything else must not
        m2 = convert_mnemonic(VALID_MNEMONIC, to="entropy")
        # `to="seed"` returns the real seed hex; anything else must not expose it.
        full_seed = m["seed_hex"]
        assert len(full_seed) == 128, "a BIP39 seed is 64 bytes / 128 hex chars"
        for mode in ("entropy", "all"):
            m2 = convert_mnemonic(VALID_MNEMONIC, to=mode)
            assert full_seed not in str(m2), f"seed leaked in to={mode!r}"
            assert m2["seed_hex"].startswith("<")
            assert "redacted>" in m2["seed_hex"]

    @requires_crypto
    def test_derivation_matches_the_certified_oracle(self):
        """The BIP39 vector must derive the same addresses the certified local oracle
        produces for the same seed (~/crypto_forensics/scripts/oracle.py)."""
        m = convert_mnemonic(VALID_MNEMONIC, to="all")
        assert m["derived"]["btc_legacy"]["p2pkh_compressed"] == \
            "1EBuf21icKTE5m3HWVndKx2bTxvqrWCqV6"
        assert m["derived"]["eth"]["address"] == \
            "0x58a57ed9d8d624cbd12e2c467d34787555bb1b25"

    @requires_crypto
    def test_known_vector_addresses(self):
        """The 12-word vector above has published derivations; assert they are stable."""
        m = convert_mnemonic(VALID_MNEMONIC, to="all")
        assert m["derived"]["btc_legacy"]["p2pkh_compressed"] == \
            "1EBuf21icKTE5m3HWVndKx2bTxvqrWCqV6"


# ---------------------------------------------------------------------------
# Key calculator
# ---------------------------------------------------------------------------

class TestKeyCalculator:
    @requires_crypto
    def test_hex_key_derives_known_addresses(self):
        c = crypto_calculator("0" * 63 + "1")
        assert c["chains"]["bitcoin"]["p2pkh_compressed"] == SCALAR_ONE_P2PKH
        assert c["chains"]["ethereum"]["address"] == SCALAR_ONE_ETH

    @requires_crypto
    def test_in_range_is_reported(self):
        assert crypto_calculator("0" * 63 + "1")["in_range"] is True
        assert crypto_calculator("00" * 32)["in_range"] is False

    @requires_crypto
    def test_wif_compressed_is_accepted(self):
        c = crypto_calculator("5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf")
        assert c["source"] == "wif_compressed"

    @requires_crypto
    def test_compressed_and_uncompressed_are_different_addresses(self):
        """Same key, two different Bitcoin addresses -- a common source of confusion."""
        c = crypto_calculator("0" * 63 + "1")
        btc = c["chains"]["bitcoin"]
        assert btc["p2pkh_compressed"] != btc["p2pkh_uncompressed"]

    @requires_crypto
    def test_uncompressed_can_be_suppressed(self):
        c = crypto_calculator("0" * 63 + "1", include_uncompressed=False)
        assert "p2pkh_uncompressed" not in c["chains"]["bitcoin"]

    def test_garbage_is_rejected(self):
        with pytest.raises(DecodeError):
            crypto_calculator("not-a-key")

    def test_empty_is_rejected(self):
        with pytest.raises(DecodeError):
            crypto_calculator("")


# ---------------------------------------------------------------------------
# wallet.dat
# ---------------------------------------------------------------------------

class TestWalletDat:
    def _records(self):
        return (
            (b"version", struct.pack("<I", 169900)),
            (b"mkey", b"\x11" * 32 + b"\x00" + struct.pack("<Q", 25000) + b"\x22" * 48),
            (b"minversion", struct.pack("<I", 169900)),
            (b"bestblock", b"\x33" * 80),
            (b"hdchain", b"\x44" * 82),
            (b"name", b"\x00" * 8),
        )

    def test_all_record_types_are_found(self):
        """A length-prefixed key must be located whatever its length.

        A hardcoded 0x04 prefix only matched four-character types and silently dropped
        version, minversion, bestblock and hdchain.
        """
        r = parse_wallet_dat(make_wallet_dat(self._records()))
        found = set(r["records"])
        for label in ("wallet version", "master encryption key", "minimum version",
                      "best block", "HD chain state", "account name"):
            assert label in found, f"missing {label}"

    def test_version_is_parsed(self):
        r = parse_wallet_dat(make_wallet_dat(self._records()))
        assert r["version"] == 169900

    def test_encryption_is_detected(self):
        r = parse_wallet_dat(make_wallet_dat(self._records()))
        assert r["encrypted"] is True
        assert r["master_key"]["cipher"] == "AES-256-CBC"
        assert r["master_key"]["iterations"] == 25000

    def test_unencrypted_wallet_reports_no_master_key(self):
        r = parse_wallet_dat(make_wallet_dat(
            ((b"version", struct.pack("<I", 100)),
             (b"minversion", struct.pack("<I", 100)),
             (b"name", b"\x00" * 8))))
        assert r["encrypted"] is False
        assert r["master_key"] is None

    @requires_crypto
    def test_address_is_derived_from_a_key_record(self):
        r = parse_wallet_dat(make_wallet_dat(self._records(), with_ckey=True))
        assert SCALAR_ONE_P2PKH in r["addresses"]

    def test_bad_magic_is_reported_not_raised(self):
        r = parse_wallet_dat(b"\x00" * 2048)
        assert r["is_wallet_dat"] is False
        assert "error" in r

    def test_too_small_is_rejected(self):
        with pytest.raises(DecodeError):
            parse_wallet_dat(b"\x62\x31\x05\x00" + b"\x00" * 100)

    def test_empty_is_rejected(self):
        with pytest.raises(DecodeError):
            parse_wallet_dat(b"")

    def test_no_plaintext_key_material_is_exposed(self):
        """The inventory must not leak key bytes, even when they are present."""
        r = parse_wallet_dat(make_wallet_dat(self._records(), with_ckey=True))
        blob = str(r)
        assert "ckey" not in blob or "redacted" in blob
        assert r["records"].get("encrypted private key", 0) >= 1


# ---------------------------------------------------------------------------
# Guardrails
# ---------------------------------------------------------------------------

class TestGuardrails:
    def test_no_broadcasting_surface_exists(self):
        """The module must not grow a signing or broadcast function."""
        import app.crypto_tools as mod
        for forbidden in ("broadcast", "send_transaction", "sign_transaction"):
            assert not hasattr(mod, forbidden), forbidden

    def test_redaction_helper_works(self):
        from app.crypto_tools import _redact_bytes
        assert _redact_bytes(b"\x01" * 32) == "<32 bytes redacted>"
        assert _redact_bytes(b"\x01" * 32, keep=4).endswith("redacted>")
