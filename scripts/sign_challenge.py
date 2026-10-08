#!/usr/bin/env python3
"""Sign the Mini App personal_sign challenge for the owner address.

Reads the EVM private key from ~/.wallet-notes/wallets.json, reconstructs the
exact challenge message, and emits an EIP-191 personal_sign signature.

The private key is never printed.
"""
import hashlib
import json
import os
import sys

from coincurve import PrivateKey
from Crypto.Hash import keccak

WALLETS = os.path.expanduser("~/.wallet-notes/wallets.json")

ADDRESS = "0xDe0DAFC80d487b8aE652bBF906ac6c6007aE3A5e"
DOMAIN = "hermes-bot-miniapp"


def build_message(nonce: str, issued_at: str) -> str:
    return (
        f"{DOMAIN} authentication\n"
        f"Address: {ADDRESS}\n"
        f"Nonce: {nonce}\n"
        f"Issued At: {issued_at}\n"
        f"\n"
        f"Sign this message to prove you control this wallet.\n"
        f"This request is read-only and will never move funds."
    )


def keccak256(data: bytes) -> bytes:
    h = keccak.new(digest_bits=256)
    h.update(data)
    return h.digest()


def to_checksum(addr: str) -> str:
    a = addr.lower().replace("0x", "")
    h = keccak256(a.encode()).hex()
    out = "".join(c.upper() if int(h[i], 16) >= 8 else c for i, c in enumerate(a))
    return "0x" + out


def eip191_hash(message: str) -> bytes:
    prefix = b"\x19Ethereum Signed Message:\n" + str(len(message.encode())).encode()
    return keccak256(prefix + message.encode())


def main() -> int:
    # Two modes:
    #   sign_challenge.py <nonce> <issued_at>   -> rebuild the message from parts
    #   sign_challenge.py --message-file <path> -> sign the server's exact text
    if len(sys.argv) >= 3 and sys.argv[1] == "--message-file":
        message = open(sys.argv[2], encoding="utf-8").read()
    else:
        nonce = sys.argv[1] if len(sys.argv) > 1 else "8234fde3664f6f571d5a4125bb2bae60"
        issued_at = sys.argv[2] if len(sys.argv) > 2 else "2026-10-07T23:48:34Z"
        message = build_message(nonce, issued_at)

    with open(WALLETS) as fh:
        data = json.load(fh)

    entry = data.get("evm") or {}
    pk_hex = (entry.get("private_key") or "").strip()
    if not pk_hex:
        print("ERROR: no evm private_key in wallets.json", file=sys.stderr)
        return 2
    if pk_hex.startswith("0x"):
        pk_hex = pk_hex[2:]

    pk = PrivateKey(bytes.fromhex(pk_hex))

    # Derive the address so we can prove the key matches before signing.
    pub = pk.public_key.format(compressed=False)[1:]
    derived = to_checksum("0x" + keccak256(pub)[-20:].hex())
    match = derived.lower() == ADDRESS.lower()
    print(f"key address : {derived}")
    print(f"challenge   : {ADDRESS}")
    print(f"match       : {match}")
    if not match:
        print("ERROR: key does not control the challenge address", file=sys.stderr)
        return 3

    digest = eip191_hash(message)
    sig = pk.sign_recoverable(digest, hasher=None)  # r || s || recid
    recid = sig[64]
    v = 27 + recid
    signature = "0x" + sig[:64].hex() + format(v, "02x")

    print()
    print("--- message signed ---")
    print(message)
    print("--- signature ---")
    print(signature)

    with open(os.path.expanduser("~/.wallet-notes/last_sig.txt"), "w") as fh:
        fh.write(signature + "\n")
    os.chmod(os.path.expanduser("~/.wallet-notes/last_sig.txt"), 0o600)
    print()
    print("saved to ~/.wallet-notes/last_sig.txt")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
