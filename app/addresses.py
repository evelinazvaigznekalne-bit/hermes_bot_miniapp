"""Chain-agnostic address validation and normalisation.

Two families are supported and kept strictly separate:

* **EVM** (``0x`` + 40 hex chars, optional EIP-55 checksum)
* **Bitcoin** (base58check P2PKH/P2SH, and bech32/bech32m segwit)

An EVM address is never treated as a Bitcoin address and vice-versa
(requirement 6). The bech32 verifier is implemented here rather than relying
on a third-party package API, so validation behaviour is fully testable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from .errors import AddressValidationError

EVM_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")

# ---------------------------------------------------------------- EVM ----

_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_GENERATORS = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
_BECH32M_CONST = 0x2BC830A3


def _keccak256(data: bytes) -> bytes:
    try:
        from Crypto.Hash import keccak  # pycryptodome

        k = keccak.new(digest_bits=256)
        k.update(data)
        return k.digest()
    except Exception:  # pragma: no cover - fallback path
        from eth_keys import keys  # type: ignore

        return keys.PublicKey._keccak256(data)  # type: ignore[attr-defined]


def eip55_checksum(address: str) -> str:
    """Return the EIP-55 mixed-case form of a 40-hex EVM address."""
    body = address[2:] if address.startswith("0x") else address
    body = body.lower()
    if not re.fullmatch(r"[0-9a-f]{40}", body):
        raise AddressValidationError(f"not a 40-hex EVM address: {address!r}")
    digest = _keccak256(body.encode("ascii")).hex()
    out = []
    for i, ch in enumerate(body):
        if ch in "0123456789":
            out.append(ch)
        else:
            out.append(ch.upper() if int(digest[i], 16) >= 8 else ch)
    return "0x" + "".join(out)


def is_evm_address(address: Optional[str]) -> bool:
    return bool(address) and bool(EVM_ADDRESS_RE.match(address.strip()))


def validate_evm_address(address: str, *, strict_checksum: bool = True) -> str:
    """Validate and normalise an EVM address.

    All-lowercase and all-uppercase inputs are accepted (no checksum present).
    Mixed-case inputs must satisfy EIP-55 when ``strict_checksum`` is set.
    Returns the EIP-55 checksummed address.
    """
    if not isinstance(address, str) or not EVM_ADDRESS_RE.match(address.strip()):
        raise AddressValidationError(
            "invalid EVM address: expected '0x' followed by 40 hex characters"
        )
    addr = address.strip()
    body = addr[2:]
    checksummed = eip55_checksum(addr)
    if strict_checksum and body != body.lower() and body != body.upper():
        if addr != checksummed:
            raise AddressValidationError(
                "invalid EIP-55 checksum for EVM address"
            )
    return checksummed


# ------------------------------------------------------------ Bitcoin ----

def _bech32_polymod(values) -> int:
    chk = 1
    for value in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ value
        for i in range(5):
            chk ^= _BECH32_GENERATORS[i] if ((top >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp: str):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _bech32_decode(bech: str):
    """Return ``(hrp, data, spec)`` or ``(None, None, None)`` when invalid."""
    if any(ord(c) < 33 or ord(c) > 126 for c in bech):
        return None, None, None
    if bech.lower() != bech and bech.upper() != bech:
        return None, None, None
    bech = bech.lower()
    pos = bech.rfind("1")
    if pos < 1 or pos + 7 > len(bech) or len(bech) > 90:
        return None, None, None
    if not all(c in _BECH32_CHARSET for c in bech[pos + 1:]):
        return None, None, None
    hrp = bech[:pos]
    data = [_BECH32_CHARSET.find(c) for c in bech[pos + 1:]]
    check = _bech32_polymod(_bech32_hrp_expand(hrp) + data)
    if check == 1:
        spec = "bech32"
    elif check == _BECH32M_CONST:
        spec = "bech32m"
    else:
        return None, None, None
    return hrp, data[:-6], spec


def _convertbits(data, frombits: int, tobits: int, pad: bool = True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


@dataclass(frozen=True)
class BitcoinAddressInfo:
    address: str
    kind: str          # p2pkh | p2sh | p2wpkh | p2wsh | p2tr
    network: str       # mainnet | testnet
    encoding: str      # base58check | bech32 | bech32m


_BTC_BASE58_VERSIONS = {
    0x00: ("p2pkh", "mainnet"),
    0x05: ("p2sh", "mainnet"),
    0x6F: ("p2pkh", "testnet"),
    0xC4: ("p2sh", "testnet"),
}

_BTC_BECH32_HRP = {"bc": "mainnet", "tb": "testnet"}


def _base58check_decode(address: str) -> bytes:
    import base58

    try:
        raw = base58.b58decode_check(address)
    except Exception as exc:  # invalid checksum / charset
        raise AddressValidationError(
            "invalid base58check Bitcoin address (checksum failed)"
        ) from exc
    return raw


def validate_bitcoin_address(address: str) -> BitcoinAddressInfo:
    """Validate a Bitcoin address and classify its script type + network."""
    if not isinstance(address, str) or not address:
        raise AddressValidationError("invalid Bitcoin address: empty input")
    addr = address.strip()
    if " " in addr or len(addr) < 14 or len(addr) > 90:
        raise AddressValidationError("invalid Bitcoin address: bad length")

    # segwit
    if addr.lower().startswith(("bc1", "tb1")):
        hrp, data, spec = _bech32_decode(addr)
        if hrp is None or not data:
            raise AddressValidationError("invalid bech32/bech32m Bitcoin address")
        network = _BTC_BECH32_HRP.get(hrp)
        if network is None:
            raise AddressValidationError(f"unsupported bech32 HRP {hrp!r}")
        version = data[0]
        program = _convertbits(data[1:], 5, 8, pad=False)
        if program is None or not (2 <= len(program) <= 40):
            raise AddressValidationError("invalid segwit witness program")
        if version == 0:
            if spec != "bech32":
                raise AddressValidationError("segwit v0 must use bech32 encoding")
            if len(program) not in (20, 32):
                raise AddressValidationError("invalid segwit v0 program length")
            kind = "p2wpkh" if len(program) == 20 else "p2wsh"
        elif version == 1 and len(program) == 32:
            if spec != "bech32m":
                raise AddressValidationError("taproot must use bech32m encoding")
            kind = "p2tr"
        else:
            if spec != "bech32m":
                raise AddressValidationError("segwit v1+ must use bech32m encoding")
            kind = "p2wsh" if len(program) == 32 else "p2wpkh"
        return BitcoinAddressInfo(addr, kind, network, spec)

    # legacy / P2SH
    raw = _base58check_decode(addr)
    if len(raw) != 21:
        raise AddressValidationError("invalid base58check payload length")
    version = raw[0]
    if version not in _BTC_BASE58_VERSIONS:
        raise AddressValidationError(f"unsupported base58 version byte 0x{version:02x}")
    kind, network = _BTC_BASE58_VERSIONS[version]
    return BitcoinAddressInfo(addr, kind, network, "base58check")


def is_bitcoin_address(address: Optional[str]) -> bool:
    if not address:
        return False
    try:
        validate_bitcoin_address(address)
        return True
    except AddressValidationError:
        return False


# ----------------------------------------------------------- dispatch ----

def detect_address_kind(address: str) -> Optional[str]:
    """Return ``'evm'``, ``'bitcoin'``, or ``None`` for unknown input."""
    if not isinstance(address, str):
        return None
    if is_evm_address(address):
        return "evm"
    if is_bitcoin_address(address):
        return "bitcoin"
    return None
