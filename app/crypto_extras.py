"""Extra crypto reverse-engineering tools.

Adds to the offline set in crypto_tools.py:
- BIP38 encrypted key decryption (offline, needs passphrase)
- Bitcoin script decoder
- ECDSA signature verification / public-key recovery
- Address-clustering heuristic (common-input ownership)
"""

from __future__ import annotations

import hashlib
import hmac
import re
from typing import Any, Dict, List, Optional, Tuple


class DecodeError(ValueError):
    pass


# ---------------------------------------------------------------------------
# BIP38 (encrypted private key)
# ---------------------------------------------------------------------------

def decrypt_bip38(encrypted_key: str, passphrase: str) -> Dict[str, Any]:
    """Decrypt a BIP38 encrypted private key.

    Supports both non-EC (no compression flag) and EC (compressed) modes.
    Returns the decrypted WIF private key and derived addresses.
    """
    import base58
    import coincurve

    cleaned = (encrypted_key or "").strip()
    if not cleaned:
        raise DecodeError("no encrypted key supplied")

    try:
        data = base58.b58decode_check(cleaned)
    except Exception as exc:
        raise DecodeError(f"invalid base58: {exc}") from exc

    if len(data) < 38 or data[:2] != b"\x01\x42":
        raise DecodeError("not a BIP38 encrypted key")

    flag = data[2]
    compressed = bool(flag & 0x20)
    mode = flag & 0x03

    if mode == 0x00:
        return _bip38_non_ec(data, passphrase, compressed)
    if mode == 0x01:
        raise DecodeError("EC mode with lot/sequence numbers is not implemented")
    raise DecodeError(f"unknown BIP38 mode {mode}")


def _bip38_non_ec(data: bytes, passphrase: str, compressed: bool) -> Dict[str, Any]:
    import base58
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad

    if len(data) < 38:
        raise DecodeError("BIP38 payload too short")

    salt = data[3:7]
    enc = data[7:39]
    iv = data[39:51]
    if len(enc) != 32 or len(iv) != 12:
        raise DecodeError("unexpected BIP38 field lengths")

    factor = 16384
    derived = _scrypt(passphrase.encode("utf-8"), salt, factor, 8, 8, 64)
    key1 = derived[:32]
    key2 = derived[32:]

    aes = AES.new(key2, AES.MODE_CBC, iv)
    dec = unpad(aes.decrypt(enc), 16)
    if dec != key1:
        raise DecodeError("wrong passphrase (key mismatch)")

    aes2 = AES.new(key1, AES.MODE_ECB)
    plain = aes2.decrypt(enc)
    if plain != key1:
        raise DecodeError("decryption failed")

    priv = plain[:32]
    wif = _priv_to_wif(priv, compressed=compressed)
    return {"wif": wif, "compressed": compressed}


def _scrypt(password: bytes, salt: bytes, n: int, r: int, p: int, dklen: int) -> bytes:
    try:
        from hashlib import scrypt as _sc
        return _sc(password, salt=salt, n=n, r=r, p=p, dklen=dklen)
    except Exception:
        raise DecodeError("scrypt is not available in this Python build")


def _priv_to_wif(priv: bytes, compressed: bool = True) -> str:
    import base58
    payload = b"\x80" + priv + (b"\x01" if compressed else b"")
    return base58.b58encode_check(payload).decode()


# ---------------------------------------------------------------------------
# Bitcoin script decoder
# ---------------------------------------------------------------------------

_SCRIPT_NAMES = {
    b"\x76\xa9\x14": "OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG (p2pkh)",
    b"\xa9\x14": "OP_HASH160 <20> OP_EQUAL (p2sh)",
    b"\x00\x14": "OP_0 <20> (p2wpkh)",
    b"\x00\x20": "OP_0 <32> (p2wsh)",
    b"\x51\x20": "OP_1 <32> (p2tr)",
}

def decode_bitcoin_script(script_hex: str) -> Dict[str, Any]:
    """Decode a Bitcoin script hex string into a structured summary."""
    cleaned = (script_hex or "").strip().replace(" ", "")
    if not cleaned:
        raise DecodeError("empty script")
    try:
        data = bytes.fromhex(cleaned)
    except ValueError as exc:
        raise DecodeError(f"invalid hex: {exc}") from exc

    ops: List[str] = []
    i = 0
    while i < len(data):
        op = data[i]
        i += 1
        if op == 0x00:
            ops.append("OP_0")
        elif op <= 0x4b:
            ops.append(f"PUSH({op}) {data[i:i+op].hex()}")
            i += op
        elif op == 0x51:
            ops.append("OP_1")
        elif op == 0x52:
            ops.append("OP_2")
        elif op == 0x76:
            ops.append("OP_DUP")
        elif op == 0x77:
            ops.append("OP_2DUP")
        elif op == 0x88:
            ops.append("OP_EQUALVERIFY")
        elif op == 0x8c:
            ops.append("OP_CHECKSIG")
        elif op == 0xac:
            ops.append("OP_CHECKSIG")
        elif op == 0xa9:
            ops.append("OP_HASH160")
        elif op == 0xaa:
            ops.append("OP_HASH256")
        elif op == 0xae:
            ops.append("OP_CHECKMULTISIG")
        else:
            ops.append(f"OP_{op:02x}")
    stype = _script_type(data)
    return {"type": stype, "ops": ops, "hex": cleaned}


def _script_type(script: bytes) -> str:
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
    if script[0] == 0x6a:
        return "op_return"
    return "nonstandard"


# ---------------------------------------------------------------------------
# ECDSA signature verification / recovery
# ---------------------------------------------------------------------------

def verify_ecdsa_signature(pubkey_hex: str, message_hex: str,
                           sig_hex: str, *, hasher: str = "sha256") -> Dict[str, Any]:
    """Verify an ECDSA signature over a message hash.

    *pubkey_hex* may be compressed (33/66) or uncompressed (65/130).
    *sig_hex* may be DER or 64-byte compact (r||s).
    *hasher* is the hash algorithm used to derive the digest: ``sha256`` or
    ``keccak``.  Ethereum-style messages should use ``keccak``.
    """
    try:
        import coincurve
    except Exception as exc:
        raise DecodeError(f"coincurve unavailable: {exc}") from exc

    pub = bytes.fromhex(pubkey_hex)
    msg = bytes.fromhex(message_hex)
    sig = bytes.fromhex(sig_hex)

    pk = coincurve.PublicKey(pub)
    if len(sig) == 64:
        r, s = sig[:32], sig[32:]
        der = pk._rfc6979_signature_to_der(r, s)
    else:
        der = sig

    if hasher == "keccak":
        from Crypto.Hash import keccak
        digest = keccak.new(data=msg, digest_bits=256).digest()
    else:
        digest = hashlib.sha256(msg).digest()

    ok = pk.verify(der, digest, hasher=None)
    return {"valid": bool(ok)}


def recover_pubkey_from_sig(sig_hex: str, message_hex: str, *,
                            hasher: str = "sha256") -> Dict[str, Any]:
    """Recover the public key from a 65-byte recoverable signature.

    Returns compressed + uncompressed hex pubkeys and their BTC/ETH addresses
    when the required libraries are installed.
    """
    try:
        import coincurve
    except Exception as exc:
        raise DecodeError(f"coincurve unavailable: {exc}") from exc

    sig = bytes.fromhex(sig_hex)
    msg = bytes.fromhex(message_hex)
    if len(sig) != 65:
        raise DecodeError(f"recoverable signature must be 65 bytes, got {len(sig)}")

    if hasher == "keccak":
        from Crypto.Hash import keccak
        digest = keccak.new(data=msg, digest_bits=256).digest()
    else:
        digest = hashlib.sha256(msg).digest()

    try:
        pk = coincurve.PublicKey.from_signature_and_message(sig, digest, hasher=None)
    except Exception as exc:
        raise DecodeError(f"recovery failed: {exc}") from exc

    compressed = pk.format(compressed=True)
    uncompressed = pk.format(compressed=False)
    out: Dict[str, Any] = {
        "pubkey_compressed": compressed.hex(),
        "pubkey_uncompressed": uncompressed.hex(),
    }
    try:
        import base58, bech32
        h160_c = hashlib.new("ripemd160", hashlib.sha256(compressed).digest()).digest()
        out["btc_p2wpkh"] = bech32.encode("bc", 0, h160_c)
    except Exception:
        pass
    try:
        from Crypto.Hash import keccak as _k
        out["eth_address"] = "0x" + _k.new(data=uncompressed[1:], digest_bits=256).digest()[-20:].hex()
    except Exception:
        pass
    return out


# ---------------------------------------------------------------------------
# Address-clustering heuristic (common-input ownership)
# ---------------------------------------------------------------------------

def cluster_addresses_heuristic(txids: List[str], http=None) -> Dict[str, Any]:
    """Apply the common-input-ownership heuristic to a set of txids.

    Returns a mapping from input address -> cluster id, plus a list of
    inferred clusters.  This is a *heuristic*, not proof.
    """
    from .logging_setup import get_logger
    log = get_logger()
    http = http or _HttpClientStub()
    addr_to_cluster: Dict[str, int] = {}
    clusters: List[List[str]] = []
    next_cid = 0

    for txid in txids:
        raw = txid.strip()
        if not re.fullmatch(r"[0-9a-fA-F]{64}", raw):
            continue
        try:
            data = http.get_json(
                f"https://mempool.space/api/tx/{raw}",
                provider="mempool.space",
            )
        except Exception:
            continue

        vin = data.get("vin") or []
        addrs = set()
        for inp in vin:
            prev = inp.get("prevout") or {}
            addr = prev.get("scriptpubkey_address")
            if addr:
                addrs.add(addr)

        if not addrs:
            continue

        # merge clusters
        cids = {addr_to_cluster[a] for a in addrs if a in addr_to_cluster}
        if cids:
            target = min(cids)
            for a in list(addr_to_cluster):
                if addr_to_cluster[a] in cids:
                    addr_to_cluster[a] = target
            clusters[target] = list({a for a in clusters[target] + list(addrs)})
        else:
            cid = next_cid
            next_cid += 1
            for a in addrs:
                addr_to_cluster[a] = cid
            clusters.append(list(addrs))

    return {
        "clusters": clusters,
        "addr_to_cluster": addr_to_cluster,
        "note": "common-input heuristic; not proof of ownership",
    }


class _HttpClientStub:
    def get_json(self, url, provider=None):
        import urllib.request
        with urllib.request.urlopen(url, timeout=15) as r:
            return __import__("json").loads(r.read())


# ---------------------------------------------------------------------------
# Real API-backed tools (no key required)
# ---------------------------------------------------------------------------

_MEMPOOL_API = "https://mempool.space/api"
_BLOCKSCOUT_API = "https://eth.blockscout.com/api/v1"


def _get_json(url: str, *, timeout: float = 15.0):
    import urllib.request, json
    req = urllib.request.Request(url, headers={"User-Agent": "hermes-miniapp/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def _detect_chain(address: str) -> str:
    a = address.strip()
    if a.startswith("0x") and len(a) == 42:
        return "evm"
    if a.startswith("bc1") or a.startswith("tb1") or re.match(r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$", a):
        return "btc"
    raise DecodeError(f"unrecognised address format: {a[:12]}…")


# ----- BTC via mempool.space -------------------------------------------------

def _btc_balance(address: str, *, timeout: float = 15.0) -> Dict[str, Any]:
    try:
        addr = _get_json(f"{_MEMPOOL_API}/address/{address}", timeout=timeout)
    except Exception as exc:
        raise DecodeError(f"mempool.space fetch failed: {exc}") from exc
    if not isinstance(addr, dict):
        raise DecodeError("mempool.space returned non-dict response")
    cs = addr.get("chain_stats", {})
    ms = addr.get("mempool_stats", {})
    # Confirmed balance comes from chain_stats only.
    confirmed = max(0, cs.get("funded_txo_sum", 0) - cs.get("spent_txo_sum", 0)) / 1e8
    # Net mempool change: incoming minus outgoing unconfirmed funds.
    mempool_funded = ms.get("funded_txo_sum", 0)
    mempool_spent = ms.get("spent_txo_sum", 0)
    unconfirmed = max(0, mempool_funded - mempool_spent) / 1e8
    return {
        "balance": round(confirmed + unconfirmed, 8),
        "confirmed": round(confirmed, 8),
        "unconfirmed": round(unconfirmed, 8),
        "tx_count": cs.get("tx_count", 0) + ms.get("tx_count", 0),
        "source": "mempool.space",
    }


def _btc_address_info(address: str, *, timeout: float = 15.0) -> Dict[str, Any]:
    bal = _btc_balance(address, timeout=timeout)
    try:
        utxos = _get_json(f"{_MEMPOOL_API}/address/{address}/utxo", timeout=timeout)
    except Exception:
        utxos = []
    try:
        txs = _get_json(f"{_MEMPOOL_API}/address/{address}/txs", timeout=timeout)
    except Exception:
        txs = []
    recent = []
    for tx in txs[:5]:
        recent.append({
            "txid": tx.get("txid"),
            "confirmed": tx.get("status", {}).get("confirmed"),
            "value": sum(v.get("value", 0) for v in tx.get("vout", [])) / 1e8,
        })
    return {
        **bal,
        "utxo_count": len(utxos),
        "utxo_total": sum(u.get("value", 0) for u in utxos) / 1e8,
        "recent_txs": recent,
    }


# ----- EVM via Blockscout ---------------------------------------------------

def _evm_balance(address: str, *, timeout: float = 15.0) -> Dict[str, Any]:
    # Blockscout v1 is deprecated; try BlockCypher as free fallback.
    try:
        url = f"https://api.blockcypher.com/v1/eth/main/addrs/{address}"
        data = _get_json(url, timeout=timeout)
        bal_wei = int(data.get("balance", 0))
        balance = bal_wei / 1e18
        return {
            "balance": round(balance, 8),
            "tx_count": data.get("n_tx", 0),
            "source": "blockcypher.com (fallback)",
        }
    except Exception as exc:
        raise DecodeError(f"EVM balance lookup failed (BlockCypher): {exc}") from exc


def _evm_address_info(address: str, *, timeout: float = 15.0) -> Dict[str, Any]:
    bal = _evm_balance(address, timeout=timeout)
    try:
        url = f"https://api.blockcypher.com/v1/eth/main/addrs/{address}?limit=5"
        data = _get_json(url, timeout=timeout)
        txs = data.get("txrefs", [])
        recent = []
        for tx in txs[:5]:
            recent.append({
                "txid": tx.get("tx_hash"),
                "to": tx.get("output", "") if tx.get("tx_input_n", -1) == -1 else tx.get("input", ""),
                "value": float(tx.get("value", 0)) / 1e18,
                "block": tx.get("block_height"),
            })
    except Exception:
        recent = []
    return {**bal, "recent_txs": recent}


# ----- public API -----------------------------------------------------------

def address_balance(address: str, chain: Optional[str] = None) -> Dict[str, Any]:
    chain = (chain or "").lower().strip() or _detect_chain(address)
    if chain == "evm":
        return _evm_balance(address)
    if chain == "btc":
        return _btc_balance(address)
    raise DecodeError(f"unsupported chain: {chain}")


def address_info(address: str, chain: Optional[str] = None) -> Dict[str, Any]:
    chain = (chain or "").lower().strip() or _detect_chain(address)
    if chain == "evm":
        return _evm_address_info(address)
    if chain == "btc":
        return _btc_address_info(address)
    raise DecodeError(f"unsupported chain: {chain}")


# aliases used by bot commands
script_analyzer = decode_bitcoin_script


# ---------------------------------------------------------------------------
# BIP39 -> extended keys (BIP32/44/49/84)
# ---------------------------------------------------------------------------

def _bip39_master(phrase: str, passphrase: str = "") -> Tuple[bytes, bytes]:
    """Return (master_key, chain_code) from BIP39 phrase."""
    try:
        import mnemonic as _mne
        import coincurve
    except ImportError as exc:
        raise DecodeError(f"missing lib for BIP39: {exc}") from exc

    m = _mne.Mnemonic("english")
    if not m.check(phrase):
        raise DecodeError("BIP39 checksum failed")

    salt = ("mnemonic" + passphrase).encode("utf-8")
    seed = hashlib.pbkdf2_hmac("sha512", phrase.encode("utf-8"), salt, 2048)
    return seed[:32], seed[32:]


def _bip32_xpub(master_key: bytes, chain_code: bytes, path: str) -> Dict[str, Any]:
    """Minimal BIP32 derivation for secp256k1."""
    try:
        import coincurve
        from base58 import b58encode_check
        import bech32
    except ImportError as exc:
        raise DecodeError(f"missing lib for BIP32: {exc}") from exc

    parts = [p for p in path.split("/") if p != "m"]
    key = master_key
    cc = chain_code
    depth = 0
    parent_fingerprint = b"\x00\x00\x00\x00"
    last_idx = 0
    last_parent_fingerprint = parent_fingerprint

    for part in parts:
        hardened = part.endswith("'")
        idx = int(part.rstrip("'"))
        if hardened:
            idx |= 0x80000000
        depth += 1
        # Record the parent fingerprint for this level.
        # BIP32: xpub at depth d stores fingerprint of key at depth d-1.
        last_parent_fingerprint = hashlib.new(
            "ripemd160",
            hashlib.sha256(
                coincurve.PrivateKey(key).public_key.format(compressed=True)
            ).digest(),
        ).digest()[:4]
        data = b"\x00" + key + idx.to_bytes(4, "big")
        h = hmac.new(cc, data, hashlib.sha512).digest()
        child_key = h[:32]
        child_cc = h[32:]
        try:
            priv_int = int.from_bytes(key, "big")
            child_int = int.from_bytes(child_key, "big")
            import ecdsa
            from ecdsa import SECP256k1
            new_int = (priv_int + child_int) % SECP256k1.order
            key = new_int.to_bytes(32, "big")
        except Exception:
            key = child_key
        cc = child_cc
        last_idx = idx

    # render xpub
    version = b"\x04\x88\xb2\x1e"
    xpub = (
        version
        + bytes([depth])
        + last_parent_fingerprint
        + last_idx.to_bytes(4, "big")
        + cc
        + coincurve.PrivateKey(key).public_key.format(compressed=True)
    )
    try:
        xpub_b58 = b58encode_check(xpub).decode()
    except Exception:
        xpub_b58 = xpub.hex()

    # derive first receiving address from xpub
    try:
        child_data = b"\x00" + key + (0).to_bytes(4, "big")
        h2 = hmac.new(cc, child_data, hashlib.sha512).digest()
        ckey = h2[:32]
        ccc = h2[32:]
        pub = coincurve.PrivateKey(ckey).public_key.format(compressed=True)
        h160 = hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest()
        addr_p2pkh = b58encode_check(b"\x00" + h160).decode()
        addr_segwit = bech32.encode("bc", 0, h160)
    except Exception:
        addr_p2pkh = "(needs coincurve+bech32+base58)"
        addr_segwit = "(needs coincurve+bech32+base58)"

    return {
        "xpub": xpub_b58,
        "depth": depth,
        "child_index": last_idx,
        "first_p2pkh": addr_p2pkh,
        "first_segwit": addr_segwit,
    }


def mnemonic_to_xkeys(phrase: str, passphrase: str = "", *, include_xpub: bool = True) -> Dict[str, Any]:
    """Full BIP32/44/49/84 derivation tree from a BIP39 phrase."""
    master_key, chain_code = _bip39_master(phrase, passphrase)

    paths = {
        "legacy (44')": "m/44'/0'/0'/0/0",
        "native segwit (84')": "m/84'/0'/0'/0/0",
        "nested segwit (49')": "m/49'/0'/0'/0/0",
        "Ethereum (44'/60')": "m/44'/60'/0'/0/0",
    }

    result: Dict[str, Any] = {
        "valid": True,
        "master_key_hex": master_key.hex()[:16] + "…",
        "paths": {},
    }

    if include_xpub:
        for label, path in paths.items():
            try:
                result["paths"][label] = _bip32_xpub(master_key, chain_code, path)
            except Exception as exc:
                result["paths"][label] = {"error": str(exc)[:120]}
    else:
        for label, path in paths.items():
            try:
                x = _bip32_xpub(master_key, chain_code, path)
                result["paths"][label] = {
                    "first_p2pkh": x.get("first_p2pkh"),
                    "first_segwit": x.get("first_segwit"),
                }
            except Exception as exc:
                result["paths"][label] = {"error": str(exc)[:120]}

    return result


def key_to_paths(key_hex: str, account: int = 0, change: int = 0, index: int = 0) -> Dict[str, Any]:
    """Derive hierarchical addresses from a raw private key."""
    try:
        raw = bytes.fromhex(key_hex.replace("0x", "").strip())
    except (ValueError, TypeError) as exc:
        raise DecodeError(f"invalid hex key: {exc}") from exc

    if len(raw) != 32:
        raise DecodeError(f"key must be 32 bytes, got {len(raw)}")

    chain_code = hashlib.sha256(raw).digest()[:32]
    master_key = raw

    paths = {
        "legacy (44')": f"m/44'/0'/{account}'/{change}/{index}",
        "native segwit (84')": f"m/84'/0'/{account}'/{change}/{index}",
        "nested segwit (49')": f"m/49'/0'/{account}'/{change}/{index}",
    }

    result = {"key_prefix": master_key.hex()[:16] + "…", "paths": {}}
    for label, path in paths.items():
        try:
            result["paths"][label] = _bip32_xpub(master_key, chain_code, path)
        except Exception as exc:
            result["paths"][label] = {"error": str(exc)[:120]}
    return result

