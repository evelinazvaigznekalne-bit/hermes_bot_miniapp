#!/usr/bin/env python3
"""Minimal reference implementation of the puzzle-endpoint contract.

Serves the JSON shape the client expects, so you can:

  1. see exactly what your own endpoint must return, and
  2. test the HTTP path end-to-end without a real provider.

Usage:
    python3 tools/mock_puzzle_server.py --port 9099
    python3 tools/mock_puzzle_server.py --port 9099 --token secret123

Then point the app at it:

    MEMEPOL_BASE_URL=http://127.0.0.1:9099
    MEMEPOL_API_KEY=secret123
    MEMEPOL_AUTH_HEADER=Authorization
    MEMEPOL_AUTH_PREFIX=Bearer
    PUZZLE_SOURCE=memepol

Endpoints:
    GET /puzzles          -> {"puzzles": [...]}
    GET /puzzles/{id}     -> one puzzle object
    GET /health           -> {"ok": true}
"""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

PUZZLES = [
    {
        "id": "demo-eth-escrow",
        "title": "Demo Ethereum escrow puzzle",
        "chain": "ethereum",
        "criteria": {
            "address": "0xDe0DAFC80d487b8aE652bBF906ac6c6007aE3A5e",
            "chain": "ethereum",
        },
        "hints": ["check the calldata", "the nonce is not what it seems"],
        "images": ["https://example.test/demo/eth-clue.png"],
        "note": "status=open",
    },
    {
        "id": "demo-btc-threshold",
        "title": "Demo Bitcoin threshold puzzle",
        "chain": "bitcoin",
        "criteria": {
            "address": "14zMkTgaVXJcxdh4JdWi29MLRR44iUSG9W",
            "chain": "bitcoin",
            "min_balance": 0.5,
        },
        "hints": ["stage 2 is unsolved"],
        "images": [],
    },
    {
        "id": "demo-btc-any",
        "title": "Demo puzzle with no address (should never exact-match)",
        "chain": "bitcoin",
        "criteria": {"chain": "bitcoin", "min_balance": 0.01},
        "hints": ["generic"],
    },
]


class Handler(BaseHTTPRequestHandler):
    server_version = "MockPuzzle/1.0"
    token: str = ""

    def log_message(self, fmt, *args):
        print(f"  {self.address_string()} {fmt % args}")

    def _auth_ok(self) -> bool:
        if not self.token:
            return True
        supplied = self.headers.get("Authorization") or self.headers.get("X-API-Key") or ""
        expected = f"Bearer {self.token}"
        return supplied in (expected, self.token)

    def _send(self, payload, status=200):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        path = urlparse(self.path).path.rstrip("/") or "/"
        if path == "/health":
            return self._send({"ok": True})
        if not self._auth_ok():
            return self._send({"error": "unauthorized"}, 401)
        if path == "/puzzles":
            return self._send({"puzzles": PUZZLES})
        if path.startswith("/puzzles/"):
            pid = path.split("/", 2)[2]
            for p in PUZZLES:
                if p["id"] == pid:
                    return self._send(p)
            return self._send({"error": "not_found"}, 404)
        return self._send({"error": "not_found"}, 404)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=9099)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--token", default="", help="require this bearer token")
    args = ap.parse_args()

    Handler.token = args.token
    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"mock puzzle endpoint on http://{args.host}:{args.port}")
    print(f"  auth: {'Bearer <token>' if args.token else 'none'}")
    print(f"  GET /puzzles  ({len(PUZZLES)} records)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
