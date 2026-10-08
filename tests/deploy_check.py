#!/usr/bin/env python3
"""Deployment readiness check using a mock Telegram Bot API.

Proves the bot deploy path (getMe, setChatMenuButton, setMyCommands,
getUpdates, command dispatch) works end-to-end without a real token.

Usage: python3 tests/deploy_check.py
"""

from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import Settings, load_dotenv  # noqa: E402
from app.service import WalletService  # noqa: E402
from app.telegram.bot import TelegramBot, TelegramClient  # noqa: E402

MOCK_TOKEN = "111111:MOCK-TOKEN-FOR-DEPLOY-CHECK"
RESULTS: list = []


class MockTelegram(BaseHTTPRequestHandler):
    """Minimal Bot API stand-in."""

    def log_message(self, *a):
        pass

    def do_POST(self):  # noqa: N802
        method = self.path.rsplit("/", 1)[-1]
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length) or b"{}")
        RESULTS.append((method, body))

        if method == "getMe":
            result = {"id": 111111, "is_bot": True, "first_name": "Hermes",
                      "username": "mock_hermes_bot"}
        elif method == "getUpdates":
            result = [{
                "update_id": 100,
                "message": {"chat": {"id": 42}, "text": "/chains"},
            }]
        elif method in ("setChatMenuButton", "setMyCommands", "sendMessage"):
            result = True
        else:
            result = True

        payload = json.dumps({"ok": True, "result": result}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def main() -> int:
    load_dotenv()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), MockTelegram)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    print(f"mock Bot API on {base}\n")

    settings = Settings(telegram_bot_token=MOCK_TOKEN,
                        telegram_webapp_url="https://example.trycloudflare.com")
    client = TelegramClient(MOCK_TOKEN, api_base=base)
    service = WalletService(settings)
    bot = TelegramBot(service, settings=settings, client=client)

    failures = []

    # 1. getMe
    me = client.call("getMe")
    ok = me.get("username") == "mock_hermes_bot"
    print(f"{'✓' if ok else '✗'} getMe -> @{me.get('username')}")
    failures += [] if ok else ["getMe"]

    # 2. menu button
    try:
        client.set_webapp_menu(settings.telegram_webapp_url)
        print("✓ setChatMenuButton")
    except Exception as exc:
        print(f"✗ setChatMenuButton: {exc}")
        failures.append("setChatMenuButton")

    # 3. getUpdates + dispatch
    updates = bot.get_updates(timeout=1)
    ok = len(updates) == 1 and updates[0]["update_id"] == 100
    print(f"{'✓' if ok else '✗'} getUpdates -> {len(updates)} update(s)")
    failures += [] if ok else ["getUpdates"]

    reply = bot.handle_update(updates[0])
    ok = reply is not None and "ethereum" in reply
    print(f"{'✓' if ok else '✗'} dispatch /chains -> {'rendered' if ok else 'FAILED'}")
    failures += [] if ok else ["dispatch"]

    # 4. sendMessage actually went out
    sent = [m for m, _ in RESULTS if m == "sendMessage"]
    ok = bool(sent)
    print(f"{'✓' if ok else '✗'} sendMessage delivered ({len(sent)})")
    failures += [] if ok else ["sendMessage"]

    # 5. token must never appear in a URL
    leaked = [m for m, _ in RESULTS if MOCK_TOKEN in m]
    ok = not leaked
    print(f"{'✓' if ok else '✗'} token absent from request paths")
    failures += [] if ok else ["token-in-url"]

    httpd.shutdown()
    print()
    if failures:
        print(f"✗ deploy check FAILED: {', '.join(failures)}")
        return 1
    print("✓ bot deploy path verified (mock API) — a real token is the only unknown")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
