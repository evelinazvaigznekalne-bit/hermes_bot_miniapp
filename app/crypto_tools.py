"""Offline cryptographic reverse-engineering tools.

Every tool here is read-only, local, and needs no network and no API key.  They exist to
answer the questions a puzzle or a wallet file actually asks:

* ``decode_transaction`` -- what does this raw signed transaction contain?  Covers Bitcoin
  (legacy and segwit) and Ethereum (legacy plus types 1-4), and recovers the sender from the
  signature when the curve library is available.
* ``convert_mnemonic`` -- is this BIP39 phrase valid, and what seed and addresses does it
  produce?  Exposes the checksum so a near-miss phrase can be distinguished from a wrong one.
* ``crypto_calculator`` -- given a key, what addresses does it control across chains?  The
  multi-chain answer matters because the same key is often reused, and compressed vs
  uncompressed Bitcoin keys give *different* addresses.
* ``parse_wallet_dat`` -- what is inside a Bitcoin Core wallet file?  Reports structure and
  metadata, and **redacts key material by default** -- the tool is for inventory, not for
  printing secrets.

Deliberate omissions, and why: no tool here sweeps a keyspace, and none of them moves funds.
A whole-keyspace scan is 2^256 work and no amount of hardware changes that; and a tool that
broadcasts is not a research tool.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from typing import Any, Dict, List, Optional, Tuple

from .logging_setup import get_logger

log = get_logger()

__all__ = [
    "decode_transaction",
    "convert_mnemonic",
    "crypto_calculator",
    "parse_wallet_dat",
    "rlp_decode",
    "varint_read",
    "redact",
]


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


class DecodeError(ValueError):
    """The input is not a parseable transaction / mnemonic / wallet file."""


def _hex(b: bytes) -> str:
    return b.hex()


def _reverse_hex(b: bytes) -> str:
    """Bitcoin displays txids and hashes little-endian."""
    return b[::-1].hex()


def _redact_bytes(b: bytes, keep: int = 0) -> str:
    if keep <= 0:
        return f"<{len(b)} bytes redacted>"
    return b[:keep].hex() + f"…<{len(b) - keep} bytes redacted>"


def varint_read(data: bytes, offset: int) -> Tuple[int, int]:
    """Read a Bitcoin compactSize varint.  Returns ``(value, next_offset)``."""
    if offset >= len(data):
        raise DecodeError("truncated varint")
    first = data[offset]
    if first < 0xFD:
        return first, offset + 1
    if first == 0xFD:
        if offset + 3 > len(data):
            raise DecodeError("truncated varint (0xfd)")
        return struct.unpack_from("<H", data, offset + 1)[0], offset + 3
    if first == 0xFE:
        if offset + 5 > len(data):
            raise DecodeError("truncated varint (0xfe)")
        return struct.unpack_from("<I", data, offset + 1)[0], offset + 5
    if offset + 9 > len(data):
        raise DecodeError("truncated varint (0xff)")
    return struct.unpack_from("<Q", data, offset + 1)[0], offset + 9


def varint_encode(value: int) -> bytes:
    if value < 0xFD:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", value)
    if value <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", value)
    return b"\xff" + struct.pack("<Q", value)


def _script_type(script: bytes) -> str:
    """Classify a Bitcoin output script by its template.

    Templates (Bitcoin script pushes are explicit, so these are exact byte matches):
      p2pkh  76 a9 14 <20> 88 ac          (25 bytes)
      p2sh   a9 14 <20> 87                (23 bytes)
      p2wpkh 00 14 <20>                   (22 bytes)
      p2wsh  00 20 <32>                   (34 bytes)
      p2tr   51 20 <32>                   (34 bytes)
    """
    if not script:
        return "empty"
    if len(script) == 25 and script[:3] == b"\x76\xa9\x14" and script[-2:] == b"\x88\xac":
        return "p2pkh"
    if len(script) == 23 and script[:2] == b"\xa9\x14" and script[-1:] == b"\x87":
        return "p2sh"
    if len(script) == 22 and script[:2] == b"\x00\x14":
        return "p2wpkh"
    if len(script) == 34 and script[:2] == b"\x00\x20":
        return "p2wsh"
    if len(script) == 34 and script[:2] == b"\x51\x20":
        return "p2tr"
    if script[0] == 0x6A:
        return "op_return"
    return "nonstandard"


def _script_address(script: bytes) -> Optional[str]:
    """Render a script as an address when it is a standard output."""
    try:
        import base58
        stype = _script_type(script)
        if stype == "p2pkh":
            return base58.b58encode_check(b"\x00" + script[3:23]).decode()
        if stype == "p2sh":
            return base58.b58encode_check(b"\x05" + script[2:22]).decode()
        if stype == "p2wpkh":
            import bech32
            return bech32.encode("bc", 0, script[2:22])
        if stype == "p2wsh":
            import bech32
            return bech32.encode("bc", 0, script[2:34])
        if stype == "p2tr":
            import bech32
            return bech32.encode("bc", 1, script[2:34])
    except Exception:
        return None
    return None


# ---------------------------------------------------------------------------
# Transaction decoding
# ---------------------------------------------------------------------------


def _decode_btc(raw: bytes) -> Dict[str, Any]:
    offset = 0
    if len(raw) < 10:
        raise DecodeError("too short for a Bitcoin transaction")

    # The txid is computed over the transaction *without* witness data, so the legacy
    # serialisation is rebuilt alongside the parse.
    legacy = bytearray()

    segwit = False
    if raw[4] == 0x00 and raw[5] == 0x01:
        segwit = True
        version = struct.unpack_from("<i", raw, 0)[0]
        legacy += raw[0:4]
        offset = 6
    else:
        version = struct.unpack_from("<i", raw, 0)[0]
        legacy += raw[0:4]
        offset = 4

    vin_count, offset = varint_read(raw, offset)
    legacy += varint_encode(vin_count)
    inputs: List[Dict[str, Any]] = []
    for _ in range(vin_count):
        if offset + 36 > len(raw):
            raise DecodeError("truncated input")
        prev_txid = raw[offset:offset + 32]
        vout = struct.unpack_from("<I", raw, offset + 32)[0]
        offset += 36
        script_len, offset = varint_read(raw, offset)
        if offset + script_len + 4 > len(raw):
            raise DecodeError("truncated scriptSig")
        script_sig = raw[offset:offset + script_len]
        offset += script_len
        sequence = struct.unpack_from("<I", raw, offset)[0]
        offset += 4
        legacy += prev_txid + struct.pack("<I", vout)
        legacy += varint_encode(script_len) + script_sig + struct.pack("<I", sequence)
        inputs.append({
            "txid": _reverse_hex(prev_txid),
            "vout": vout,
            "scriptSig": _hex(script_sig),
            "scriptSig_len": script_len,
            "sequence": sequence,
        })

    vout_count, offset = varint_read(raw, offset)
    legacy += varint_encode(vout_count)
    outputs: List[Dict[str, Any]] = []
    for _ in range(vout_count):
        if offset + 8 > len(raw):
            raise DecodeError("truncated output")
        value = struct.unpack_from("<q", raw, offset)[0]
        offset += 8
        script_len, offset = varint_read(raw, offset)
        if offset + script_len > len(raw):
            raise DecodeError("truncated scriptPubKey")
        script = raw[offset:offset + script_len]
        offset += script_len
        legacy += struct.pack("<q", value) + varint_encode(script_len) + script
        outputs.append({
            "value": value,
            "value_btc": value / 1e8,
            "script": _hex(script),
            "script_type": _script_type(script),
            "address": _script_address(script),
        })

    witnesses: List[List[str]] = []
    if segwit:
        for _ in range(vin_count):
            count, offset = varint_read(raw, offset)
            items = []
            for _ in range(count):
                item_len, offset = varint_read(raw, offset)
                if offset + item_len > len(raw):
                    raise DecodeError("truncated witness item")
                items.append(_hex(raw[offset:offset + item_len]))
                offset += item_len
            witnesses.append(items)

    if offset + 4 > len(raw):
        raise DecodeError("truncated locktime")
    locktime = struct.unpack_from("<I", raw, offset)[0]
    legacy += struct.pack("<I", locktime)

    total_in = None  # inputs reference prior outputs, so the sum is unknowable here
    total_out = sum(o["value"] for o in outputs)
    fee_note = ("input total unknown from the raw transaction alone; "
                "fetch the referenced outputs to compute the fee")

    txid = _reverse_hex(hashlib.sha256(hashlib.sha256(bytes(legacy)).digest()).digest())
    wtxid = _reverse_hex(hashlib.sha256(hashlib.sha256(raw).digest()).digest())

    return {
        "chain": "bitcoin",
        "segwit": segwit,
        "version": version,
        "locktime": locktime,
        "inputs": inputs,
        "outputs": outputs,
        "witnesses": witnesses,
        "input_count": vin_count,
        "output_count": vout_count,
        "total_input": total_in,
        "total_output": total_out,
        "total_output_btc": total_out / 1e8,
        "fee_note": fee_note,
        "size_bytes": len(raw),
        "stripped_size_bytes": len(legacy),
        "txid": txid,
        "wtxid": wtxid,
        "consumed": len(raw),
    }


# --- RLP ------------------------------------------------------------------


def rlp_decode(data: bytes, offset: int = 0) -> Tuple[Any, int]:
    """Minimal RLP decoder.  Returns ``(value, next_offset)``."""
    if offset >= len(data):
        raise DecodeError("truncated RLP")
    prefix = data[offset]

    if prefix < 0x80:
        return bytes([prefix]), offset + 1
    if prefix < 0xB8:
        length = prefix - 0x80
        start = offset + 1
        if start + length > len(data):
            raise DecodeError("truncated RLP string")
        return data[start:start + length], start + length
    if prefix < 0xC0:
        len_of_len = prefix - 0xB7
        if offset + 1 + len_of_len > len(data):
            raise DecodeError("truncated RLP length")
        length = int.from_bytes(data[offset + 1:offset + 1 + len_of_len], "big")
        start = offset + 1 + len_of_len
        if start + length > len(data):
            raise DecodeError("truncated RLP long string")
        return data[start:start + length], start + length
    if prefix < 0xF8:
        length = prefix - 0xC0
        start = offset + 1
        if start + length > len(data):
            raise DecodeError("truncated RLP list")
        return _rlp_decode_list(data, start, length)
    len_of_len = prefix - 0xF7
    if offset + 1 + len_of_len > len(data):
        raise DecodeError("truncated RLP long list")
    length = int.from_bytes(data[offset + 1:offset + 1 + len_of_len], "big")
    start = offset + 1 + len_of_len
    if start + length > len(data):
        raise DecodeError("truncated RLP long list")
    return _rlp_decode_list(data, start, length)


def _rlp_decode_list(data: bytes, start: int, length: int) -> Tuple[List[Any], int]:
    out: List[Any] = []
    end = start + length
    cursor = start
    while cursor < end:
        value, cursor = rlp_decode(data, cursor)
        out.append(value)
    if cursor != end:
        raise DecodeError("RLP list length mismatch")
    return out, end


def _rlp_to_int(value: bytes) -> int:
    return int.from_bytes(value, "big") if value else 0


def _legacy_chain_id(v: int) -> Optional[int]:
    """EIP-155 chain id encoded in a legacy signature's ``v``; ``None`` for 27/28.

    ``v = 35 + 2 * chain_id + parity`` for a replay-protected signature.  A bare 27 or 28
    is a pre-EIP-155 signature, which carries no chain id at all.
    """
    if v in (27, 28):
        return None
    if v < 35:
        return None
    return (v - 35) // 2


def _decode_eth(raw: bytes) -> Dict[str, Any]:
    if not raw:
        raise DecodeError("empty transaction")

    tx_type = None
    body = raw
    if raw[0] >= 0xC0:          # legacy: an RLP list
        tx_type = 0
    else:
        tx_type = raw[0]
        body = raw[1:]

    try:
        fields, end = rlp_decode(body, 0)
    except DecodeError:
        raise
    if not isinstance(fields, list):
        raise DecodeError("Ethereum transaction is not an RLP list")
    if end != len(body):
        raise DecodeError("trailing bytes after Ethereum transaction")

    def _addr(v: bytes) -> Optional[str]:
        if not v:
            return None
        return "0x" + v.hex()

    if tx_type == 0:
        names = ["nonce", "gasPrice", "gasLimit", "to", "value", "data", "v", "r", "s"]
        if len(fields) < 9:
            raise DecodeError(f"legacy transaction needs 9 fields, got {len(fields)}")
        d = {n: _rlp_to_int(f) if i not in (3, 5, 6, 7, 8) else f
             for i, (n, f) in enumerate(zip(names, fields))}
        d["to"] = _addr(fields[3])
        d["data"] = _hex(fields[5])
        # v carries the EIP-155 chain id for a replay-protected legacy signature
        # (v = 35 + 2*chain_id + parity); a bare 27/28 is a pre-EIP-155 signature with
        # no chain id.  Reporting None unconditionally here contradicted the value the
        # sender-recovery path computes from the same field.
        d["chain_id"] = _legacy_chain_id(_rlp_to_int(fields[6]))
    elif tx_type == 1:
        names = ["chainId", "nonce", "gasPrice", "gasLimit", "to", "value", "data",
                 "accessList", "v", "r", "s"]
        if len(fields) < 11:
            raise DecodeError(f"type-1 transaction needs 11 fields, got {len(fields)}")
        d = {n: (fields[i] if i in (4, 6, 7, 8, 9, 10) else _rlp_to_int(fields[i]))
             for i, n in enumerate(names)}
        d["to"] = _addr(fields[4])
        d["data"] = _hex(fields[6])
        d["chain_id"] = d["chainId"]
    elif tx_type == 2:
        names = ["chainId", "nonce", "maxPriorityFeePerGas", "maxFeePerGas", "gasLimit",
                 "to", "value", "data", "accessList", "yParity", "r", "s"]
        if len(fields) < 12:
            raise DecodeError(f"type-2 transaction needs 12 fields, got {len(fields)}")
        d = {n: (fields[i] if i in (5, 7, 8, 9, 10, 11) else _rlp_to_int(fields[i]))
             for i, n in enumerate(names)}
        d["to"] = _addr(fields[5])
        d["data"] = _hex(fields[7])
        d["chain_id"] = d["chainId"]
    elif tx_type == 3:
        names = ["chainId", "nonce", "maxPriorityFeePerGas", "maxFeePerGas", "gasLimit",
                 "to", "value", "data", "accessList", "yParity", "r", "s"]
        if len(fields) < 12:
            raise DecodeError(f"type-3 transaction needs 12 fields, got {len(fields)}")
        d = {n: (fields[i] if i in (5, 7, 8, 9, 10, 11) else _rlp_to_int(fields[i]))
             for i, n in enumerate(names)}
        d["to"] = _addr(fields[5])
        d["data"] = _hex(fields[7])
        d["chain_id"] = d["chainId"]
        d["blob_hashes"] = [_hex(x) if isinstance(x, bytes) else x for x in fields[12:]]
    else:
        raise DecodeError(f"unsupported Ethereum transaction type {tx_type}")

    d["type"] = tx_type
    d["chain"] = "ethereum"
    d["size_bytes"] = len(raw)
    d["is_contract_creation"] = d.get("to") is None
    # `d["value"]` is already an int for every transaction type (legacy index 4, typed
    # index 6).  The previous expression divided fields[6] for legacy transactions, which
    # is the `v` field -- so value_eth reported 3.7e-17 for a transfer of 1 ETH.
    d["value_eth"] = d.get("value", 0) / 1e18
    d["sender"] = _recover_eth_sender(raw, tx_type)
    return d


def _recover_eth_sender(raw: bytes, tx_type: int) -> Optional[str]:
    """Recover the sender address from the signature.  Requires eth-keys + coincurve."""
    try:
        import coincurve
        from Crypto.Hash import keccak
    except Exception:
        return None

    body = raw[1:] if tx_type else raw
    try:
        fields, _ = rlp_decode(body, 0)
    except DecodeError:
        return None

    def _b(i: int) -> bytes:
        return fields[i] if isinstance(fields[i], bytes) else b""

    try:
        if tx_type == 0:
            nonce, gas_price, gas, to, value, data, v, r, s = (_rlp_to_int(_b(i)) for i in range(9))
            to_b, data_b = _b(3), _b(5)
            if v in (27, 28):
                chain_id = None
            else:
                chain_id = (v - 35) // 2
        elif tx_type == 1:
            chain_id, nonce, gas_price, gas, to_b, value, data_b = (
                _rlp_to_int(_b(0)), _rlp_to_int(_b(1)), _rlp_to_int(_b(2)),
                _rlp_to_int(_b(3)), _b(4), _rlp_to_int(_b(5)), _b(6))
            v, r, s = _rlp_to_int(_b(8)), _rlp_to_int(_b(9)), _rlp_to_int(_b(10))
            r = r + 1 if False else r  # type-1 keeps v as 0/1
        elif tx_type == 2:
            chain_id, nonce = _rlp_to_int(_b(0)), _rlp_to_int(_b(1))
            gas_price, gas = _rlp_to_int(_b(3)), _rlp_to_int(_b(4))
            to_b, value, data_b = _b(5), _rlp_to_int(_b(6)), _b(7)
            v, r, s = _rlp_to_int(_b(9)), _rlp_to_int(_b(10)), _rlp_to_int(_b(11))
        else:
            return None
    except Exception:
        return None

    try:
        if tx_type == 0 and chain_id is not None:
            sig_hash = _keccak(_rlp_encode_list([
                varint_encode(nonce) if nonce < 0x80 else _rlp_str(nonce),
                _rlp_str(gas_price), _rlp_str(gas), to_b, _rlp_str(value), data_b,
                _rlp_str(chain_id), b"\x80", b"\x80"]))
        else:
            sig_hash = _keccak(_rlp_encode_list([
                _rlp_str(nonce), _rlp_str(gas_price), _rlp_str(gas), to_b,
                _rlp_str(value), data_b]))
    except Exception:
        return None

    try:
        pub = coincurve.PublicKey.from_signature_and_message(
            _pad32(r) + _pad32(s) + bytes([v & 1]), sig_hash, hasher=None)
        pub_bytes = pub.format(compressed=False)[1:]
        k = keccak.new(digest_bits=256)
        k.update(pub_bytes)
        return "0x" + k.hexdigest()[-40:]
    except Exception:
        return None


def _pad32(value: int) -> bytes:
    return value.to_bytes(32, "big")


def _rlp_str(value: int) -> bytes:
    """RLP-encode an integer as a minimal big-endian byte string."""
    if value == 0:
        return b"\x80"
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    if len(raw) == 1 and raw[0] < 0x80:
        return raw
    return bytes([0x80 + len(raw)]) + raw


def _rlp_bytes(raw: bytes) -> bytes:
    """RLP-encode raw bytes as a string."""
    if len(raw) == 1 and raw[0] < 0x80:
        return raw
    if len(raw) < 56:
        return bytes([0x80 + len(raw)]) + raw
    length_bytes = len(raw).to_bytes((len(raw).bit_length() + 7) // 8, "big")
    return bytes([0xB7 + len(length_bytes)]) + length_bytes + raw


def _rlp_encode_list(items: List[bytes]) -> bytes:
    payload = b"".join(items)
    if len(payload) < 56:
        return bytes([0xC0 + len(payload)]) + payload
    length_bytes = len(payload).to_bytes((len(payload).bit_length() + 7) // 8, "big")
    return bytes([0xF7 + len(length_bytes)]) + length_bytes + payload


def _keccak(data: bytes) -> bytes:
    from Crypto.Hash import keccak
    h = keccak.new(digest_bits=256)
    h.update(data)
    return h.digest()


def decode_transaction(raw: str, chain: str = "auto") -> Dict[str, Any]:
    """Decode a raw signed transaction into structured fields.

    ``chain`` may be ``auto``, ``btc``/``bitcoin``, or ``eth``/``ethereum``.  ``auto`` tries
    Bitcoin first and falls back to Ethereum.
    """
    cleaned = (raw or "").strip().replace(" ", "").replace("\n", "")
    if not cleaned:
        raise DecodeError("no transaction supplied")
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]
    try:
        data = bytes.fromhex(cleaned)
    except ValueError as exc:
        raise DecodeError(f"not hexadecimal: {exc}")

    wanted = chain.lower()
    attempts = []
    if wanted in ("auto", "btc", "bitcoin"):
        attempts.append(("btc", _decode_btc))
    if wanted in ("auto", "eth", "ethereum", "evm"):
        attempts.append(("eth", _decode_eth))
    if not attempts:
        raise DecodeError(f"unknown chain {chain!r}")

    errors = []
    for name, fn in attempts:
        try:
            result = fn(data)
            result["decoded_as"] = name
            return result
        except DecodeError as exc:
            errors.append(f"{name}: {exc}")
    raise DecodeError("could not decode as any chain: " + "; ".join(errors))


# ---------------------------------------------------------------------------
# BIP32 / BIP39
# ---------------------------------------------------------------------------

_CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_BIP32_HARDENED = 0x80000000


def _secp_pubkey(priv: bytes, compressed: bool = True) -> bytes:
    import coincurve
    pk = coincurve.PrivateKey(priv)
    return pk.public_key.format(compressed=compressed)


def _bip32_master(seed: bytes) -> Tuple[bytes, bytes]:
    digest = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    return digest[:32], digest[32:]


def _bip32_ckd_priv(key: bytes, chain: bytes, index: int) -> Tuple[bytes, bytes]:
    import coincurve
    if index & _BIP32_HARDENED:
        data = b"\x00" + key + struct.pack(">I", index)
    else:
        data = coincurve.PrivateKey(key).public_key.format(compressed=True) \
            + struct.pack(">I", index)
    digest = hmac.new(chain, data, hashlib.sha512).digest()
    left = int.from_bytes(digest[:32], "big")
    if left >= _CURVE_ORDER:
        raise DecodeError("invalid child key (left >= n)")
    child = (left + int.from_bytes(key, "big")) % _CURVE_ORDER
    if child == 0:
        raise DecodeError("invalid child key (zero)")
    return child.to_bytes(32, "big"), digest[32:]


def _parse_bip32_path(path: str) -> List[int]:
    if not path.startswith("m") and not path.startswith("M"):
        raise DecodeError(f"path must start with m or M: {path!r}")
    out: List[int] = []
    for part in path.split("/")[1:]:
        if not part:
            continue
        hardened = part[-1] in ("'", "h", "H")
        num = part[:-1] if hardened else part
        if not num.isdigit():
            raise DecodeError(f"bad path component {part!r}")
        idx = int(num)
        if idx >= _BIP32_HARDENED:
            raise DecodeError(f"path index too large: {idx}")
        out.append(idx + _BIP32_HARDENED if hardened else idx)
    return out


def _derive_priv(seed: bytes, path: str) -> Tuple[bytes, bytes, bytes]:
    key, chain = _bip32_master(seed)
    for index in _parse_bip32_path(path):
        key, chain = _bip32_ckd_priv(key, chain, index)
    return key, chain, chain


def _btc_addresses(priv: bytes) -> Dict[str, str]:
    import base58
    import bech32
    out: Dict[str, str] = {}
    comp = _secp_pubkey(priv, compressed=True)
    uncomp = _secp_pubkey(priv, compressed=False)
    h160_c = hashlib.new("ripemd160", hashlib.sha256(comp).digest()).digest()
    h160_u = hashlib.new("ripemd160", hashlib.sha256(uncomp).digest()).digest()
    out["p2pkh_compressed"] = base58.b58encode_check(b"\x00" + h160_c).decode()
    out["p2pkh_uncompressed"] = base58.b58encode_check(b"\x00" + h160_u).decode()
    out["p2wpkh"] = bech32.encode("bc", 0, h160_c)
    out["p2tr"] = bech32.encode("bc", 1, h160_c)
    return out


def _eth_address(priv: bytes) -> str:
    pub = _secp_pubkey(priv, compressed=False)[1:]
    return "0x" + _keccak(pub)[-20:].hex()


def convert_mnemonic(phrase: str, to: str = "seed", passphrase: str = "",
                     language: str = "english") -> Dict[str, Any]:
    """BIP39 phrase -> entropy and/or seed, with checksum validation.

    ``to`` selects what is returned: ``entropy``, ``seed``, or ``all``.
    """
    from mnemonic import Mnemonic

    cleaned = " ".join((phrase or "").strip().split()).lower()
    if not cleaned:
        raise DecodeError("no mnemonic supplied")

    words = cleaned.split()
    try:
        entropy = Mnemonic(language).to_entropy(words)
        valid_checksum = True
    except Exception:
        valid_checksum = False
        entropy = None

    result: Dict[str, Any] = {
        "word_count": len(words),
        "valid_checksum": valid_checksum,
        "language": language,
        "valid": valid_checksum,
    }
    if entropy is not None:
        result["entropy_hex"] = entropy.hex()
        result["entropy_bits"] = len(entropy) * 8

    seed = None
    if valid_checksum:
        try:
            seed = Mnemonic.to_seed(cleaned, passphrase)
        except Exception:
            seed = None
    if seed is not None:
        result["seed_hex"] = _redact_bytes(seed, keep=0) if to != "seed" else seed.hex()
        result["seed_redacted"] = _redact_bytes(seed, keep=0)
        result["passphrase"] = passphrase or None

    if valid_checksum and to == "all" and seed is not None:
        result["derived"] = derive_seed(seed)

    return result


def derive_seed(seed: bytes) -> Dict[str, Any]:
    """Derive the standard first addresses for a seed, across chains."""
    import base58
    paths = {
        "btc_legacy": "m/44'/0'/0'/0/0",
        "btc_segwit": "m/84'/0'/0'/0/0",
        "btc_change": "m/44'/0'/0'/1/0",
        "eth": "m/44'/60'/0'/0/0",
        "ltc": "m/44'/2'/0'/0/0",
        "doge": "m/44'/3'/0'/0/0",
    }
    out: Dict[str, Any] = {}
    for name, path in paths.items():
        try:
            key, _, _ = _derive_priv(seed, path)
        except DecodeError:
            continue
        entry: Dict[str, Any] = {"path": path}
        if name == "eth":
            entry["address"] = _eth_address(key)
        else:
            entry.update(_btc_addresses(key))
            entry["address"] = entry.get("p2pkh_compressed")
        out[name] = entry
    return out


def crypto_calculator(private_key: str, include_uncompressed: bool = True) -> Dict[str, Any]:
    """Derive every address a private key controls.

    The compressed/uncompressed distinction matters: they are *different* Bitcoin addresses
    for the same key, and a key that controls one controls the other only if you derive it.
    """
    cleaned = (private_key or "").strip()
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]

    source = "hex"
    priv: Optional[bytes] = None

    if len(cleaned) == 64:
        try:
            candidate = bytes.fromhex(cleaned)
            if len(candidate) == 32:
                priv = candidate
        except ValueError:
            priv = None

    if priv is None:
        # Not 64 hex chars: try WIF.
        #
        # WIF is version-prefixed: b58decode_check yields
        #   0x80 || <32-byte key>            -> uncompressed  (33 bytes)
        #   0x80 || <32-byte key> || 0x01    -> compressed    (34 bytes)
        # The 0x80 prefix must be stripped in *both* cases; matching on the raw
        # payload length conflated the two (a 33-byte payload was read as a
        # compressed key with the 0x80 still attached, and a real 34-byte
        # compressed key was rejected outright as an "unrecognised length").
        try:
            import base58
            decoded = base58.b58decode_check(cleaned)
            if len(decoded) in (33, 34) and decoded[0] == 0x80:
                body = decoded[1:]
                if len(body) == 33 and body[-1] == 0x01:
                    priv = body[:-1]
                    source = "wif_compressed"
                elif len(body) == 32:
                    priv = body
                    source = "wif_uncompressed"
                else:
                    raise DecodeError(
                        f"unrecognised WIF payload length {len(decoded)}")
            else:
                raise DecodeError(
                    f"unrecognised WIF payload length {len(decoded)}")
        except DecodeError:
            raise
        except Exception as exc:
            raise DecodeError(f"could not parse as hex or WIF: {exc}")

    assert priv is not None  # guaranteed by the branches above

    # Validate the scalar before handing it to coincurve: coincurve rejects an
    # out-of-range secret with a bare ValueError, which surfaced as an unhandled crash.
    # Reporting the condition keeps the tool total -- an invalid key is an answer, not an
    # exception -- and `in_range` stays meaningful instead of always being True.
    scalar = int.from_bytes(priv, "big")
    in_range = 0 < scalar < _CURVE_ORDER

    result: Dict[str, Any] = {
        "source": source,
        "key_hex_prefix": priv.hex()[:8] + "…",
        "key_length_bytes": len(priv),
        "in_range": in_range,
        "chains": {},
    }
    if not in_range:
        result["note"] = (
            "private key is out of range for secp256k1: it must satisfy 0 < key < n, "
            "so it controls no addresses")
        return result

    result["chains"]["bitcoin"] = _btc_addresses(priv)
    result["chains"]["ethereum"] = {"address": _eth_address(priv)}
    if not include_uncompressed:
        for v in result["chains"].values():
            if isinstance(v, dict):
                v.pop("p2pkh_uncompressed", None)
    return result


# ---------------------------------------------------------------------------
# wallet.dat (Berkeley DB)
# ---------------------------------------------------------------------------

# Bitcoin Core serialises wallet records with a 4-byte type prefix.  These are the ones that
# carry key material or wallet structure.
WALLET_RECORD_TYPES = {
    b"name": "account name",
    b"version": "wallet version",
    b"minversion": "minimum version",
    b"mkey": "master encryption key",
    b"ckey": "encrypted private key",
    b"wkey": "unencrypted private key (deprecated)",
    b"key": "unencrypted private key",
    b"pool": "key pool",
    b"acc": "account",
    b"bestblock": "best block",
    b"defaultkey": "default key",
    b"cscript": "watched script",
    b"watchs": "watched script (legacy)",
    b"hdchain": "HD chain state",
    b"destdata": "destination data",
    b"tx": "transaction",
    b"vtx": "transaction (legacy)",
    b"keymeta": "key metadata",
    b"watchmeta": "watch metadata",
    b"poolmeta": "pool metadata",
    b"acentry": "account entry",
    b"fordered": "flag",
    b"zkey": "z-addr key",
    b"cscript2": "watched script",
    b"walletflag": "wallet flag",
}

_BDB_MAGIC = {
    0x053162: "btree",
    0x061561: "hash",
    0x042253: "queue",
    0x00053162: "btree (v2)",
    0x00061561: "hash (v2)",
    0x00042253: "queue (v2)",
}


def parse_wallet_dat(data: bytes, include_key_bytes: bool = False) -> Dict[str, Any]:
    """Inventory a Bitcoin Core ``wallet.dat`` without exposing key material.

    Reports file structure, the records present, whether the wallet is encrypted, and any
    addresses found.  Key bytes are **redacted by default** -- pass ``include_key_bytes``
    only on a file you own and in a context where that output is not logged.
    """
    if not data:
        raise DecodeError("no wallet data supplied")
    if len(data) < 1024:
        raise DecodeError(f"file too small to be a wallet ({len(data)} bytes)")

    magic_raw = data[:4]
    magic = struct.unpack("<I", magic_raw)[0]
    detected = _BDB_MAGIC.get(magic)
    if detected is None:
        # BDB stores the magic big-endian in some versions.
        magic_be = struct.unpack(">I", magic_raw)[0]
        detected = _BDB_MAGIC.get(magic_be)

    result: Dict[str, Any] = {
        "size_bytes": len(data),
        "format": detected or "unknown",
        "magic_hex": magic_raw.hex(),
        "is_wallet_dat": detected is not None,
        "encrypted": False,
        "master_key": None,
        "version": None,
        "records": {},
        "record_count": 0,
        "addresses": [],
        "note": ("key material redacted; pass include_key_bytes only on a wallet you own "
                 "and never paste the result into a chat or a log"),
    }
    if detected is None:
        result["error"] = "unrecognised Berkeley DB magic; not a Bitcoin Core wallet.dat"
        return result

    counts: Dict[str, int] = {}
    addresses: List[str] = []
    master = None
    version = None

    # Scan for record keys.  Bitcoin Core serialises each record's key as a length-prefixed
    # string: a compactSize varint holding the type's length, then the type bytes.  So the
    # needle for "version" is b"\x07version", not b"\x04version" -- a hardcoded 0x04 prefix
    # matches only the four-character types (mkey, ckey, name, pool, ...) and silently
    # misses the rest, which is most of a real wallet.  Observed on a correctly-built
    # file: version, minversion, bestblock and hdchain were all absent from the inventory.
    for raw_type, label in WALLET_RECORD_TYPES.items():
        needle = varint_encode(len(raw_type)) + raw_type
        payload_at = len(needle)
        start = 0
        while True:
            idx = data.find(needle, start)
            if idx == -1:
                break
            counts[label] = counts.get(label, 0) + 1
            start = idx + 1
            payload_start = idx + payload_at

            if raw_type == b"mkey" and master is None:
                # mkey payload: 32-byte salt + 1-byte method + 8-byte iterations + key
                payload = data[payload_start:payload_start + 64]
                if len(payload) >= 41:
                    salt = payload[:32]
                    method = payload[32]
                    iters = struct.unpack("<Q", payload[33:41])[0]
                    master = {
                        "salt_hex": salt.hex(),
                        "method": method,
                        "iterations": iters,
                        "cipher": "AES-256-CBC" if method == 0 else f"method {method}",
                    }
            elif raw_type == b"version" and version is None:
                payload = data[payload_start:payload_start + 4]
                if len(payload) == 4:
                    version = struct.unpack("<I", payload)[0]
            elif raw_type in (b"ckey", b"key"):
                # The record carries a public key; derive its address where it parses.
                addr = _address_from_key_record(data, payload_start, raw_type)
                if addr:
                    addresses.append(addr)

    result["records"] = dict(sorted(counts.items(), key=lambda kv: -kv[1]))
    result["record_count"] = sum(counts.values())
    result["encrypted"] = master is not None
    result["master_key"] = master
    result["version"] = version
    result["addresses"] = sorted(set(addresses))
    return result


def _address_from_key_record(data: bytes, offset: int, raw_type: bytes) -> Optional[str]:
    """Best-effort: read a compressed public key from a key record and render its address."""
    import base58
    try:
        if raw_type == b"ckey":
            # ckey: pubkey (compressed) + encrypted privkey
            if offset + 33 > len(data):
                return None
            pub = data[offset:offset + 33]
        elif raw_type == b"key":
            # key: <len><pubkey> ... old format with a length byte first
            if offset >= len(data):
                return None
            length = data[offset]
            pub = data[offset + 1:offset + 1 + length]
            if len(pub) != length:
                return None
        else:
            return None
        if len(pub) == 33 and pub[0] in (0x02, 0x03):
            h160 = hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest()
            return base58.b58encode_check(b"\x00" + h160).decode()
    except Exception:
        return None
    return None
