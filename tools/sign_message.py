#!/usr/bin/env python3
"""TEST HELPER ONLY - signs a message with a throwaway key.

Used by tests/frontend_harness.mjs to stand in for a user's wallet so the
Mini App frontend can be exercised end-to-end. The key is a hard-coded test
vector; it must never hold funds.

Reads the message on stdin, prints {"address", "signature"} on stdout.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.auth import personal_sign_hash  # noqa: E402

#: Test-only vector. Deterministic so the harness can predict the address.
TEST_PRIVATE_KEY = os.environ.get("TEST_PRIVATE_KEY", "11" * 32)


def main() -> int:
    from eth_keys import keys

    message = sys.stdin.read()
    priv = keys.PrivateKey(bytes.fromhex(TEST_PRIVATE_KEY))
    sig = priv.sign_msg_hash(personal_sign_hash(message))
    print(json.dumps({
        "address": priv.public_key.to_checksum_address(),
        "signature": "0x" + sig.to_bytes().hex(),
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
