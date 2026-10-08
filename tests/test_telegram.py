"""Telegram Mini App initData validation + bot command tests."""

from __future__ import annotations

import time

import pytest

from app.config import is_placeholder, redact
from app.errors import SignatureError
from app.telegram.bot import TelegramBot
from app.telegram.webapp_auth import (
    build_init_data,
    compute_init_data_hash,
    validate_init_data,
)

BOT_TOKEN = "123456789:AAHtest-token-value-not-real-xyz"
USER = {"id": 42, "first_name": "Soulles", "username": "soulles"}


class TestInitDataValidation:
    def test_valid_init_data_accepted(self):
        init_data = build_init_data(USER, BOT_TOKEN)
        user = validate_init_data(init_data, BOT_TOKEN)
        assert user.id == 42
        assert user.username == "soulles"
        assert user.display_name == "Soulles"

    def test_tampered_user_rejected(self):
        init_data = build_init_data(USER, BOT_TOKEN)
        tampered = init_data.replace("%22id%22%3A42", "%22id%22%3A43")
        with pytest.raises(SignatureError):
            validate_init_data(tampered, BOT_TOKEN)

    def test_wrong_token_rejected(self):
        init_data = build_init_data(USER, BOT_TOKEN)
        with pytest.raises(SignatureError):
            validate_init_data(init_data, "999:different-token")

    def test_missing_hash_rejected(self):
        with pytest.raises(SignatureError):
            validate_init_data("user=%7B%22id%22%3A1%7D&auth_date=1", BOT_TOKEN)

    def test_empty_token_fails_closed(self):
        init_data = build_init_data(USER, BOT_TOKEN)
        with pytest.raises(SignatureError):
            validate_init_data(init_data, None)
        with pytest.raises(SignatureError):
            validate_init_data(init_data, "")

    def test_placeholder_token_fails_closed(self):
        init_data = build_init_data(USER, BOT_TOKEN)
        with pytest.raises(SignatureError):
            validate_init_data(init_data, "YOUR_TELEGRAM_BOT_TOKEN")

    def test_expired_init_data_rejected(self):
        old = int(time.time()) - 60 * 60 * 48
        init_data = build_init_data(USER, BOT_TOKEN, auth_date=old)
        with pytest.raises(SignatureError):
            validate_init_data(init_data, BOT_TOKEN)

    def test_fresh_init_data_with_explicit_now(self):
        init_data = build_init_data(USER, BOT_TOKEN, auth_date=1000)
        user = validate_init_data(init_data, BOT_TOKEN, now=1005)
        assert user.id == 42

    def test_hash_is_deterministic(self):
        init_data = build_init_data(USER, BOT_TOKEN, auth_date=1000)
        assert compute_init_data_hash(init_data, BOT_TOKEN) == \
            compute_init_data_hash(init_data, BOT_TOKEN)

    def test_missing_user_rejected(self):
        from urllib.parse import urlencode

        params = {"auth_date": str(int(time.time()))}
        import hashlib
        import hmac

        check = "\n".join(f"{k}={v}" for k, v in sorted(params.items()))
        secret = hmac.new(b"WebAppData", BOT_TOKEN.encode(), hashlib.sha256).digest()
        params["hash"] = hmac.new(secret, check.encode(), hashlib.sha256).hexdigest()
        with pytest.raises(SignatureError):
            validate_init_data(urlencode(params), BOT_TOKEN)


class TestSecretRedaction:
    def test_placeholder_detection(self):
        assert is_placeholder(None) is True
        assert is_placeholder("") is True
        assert is_placeholder("YOUR_TELEGRAM_BOT_TOKEN") is True
        assert is_placeholder("changeme") is True
        assert is_placeholder("123456:real-looking-token") is False

    def test_redact_hides_value(self):
        secret = "123456789:AAHsupersecrettokenvalue"
        out = redact(secret)
        assert secret not in out
        assert "redacted" in out

    def test_redact_unset(self):
        assert redact(None) == "<unset>"
        assert redact("YOUR_KEY") == "<placeholder>"


class TestBotCommands:
    @pytest.fixture
    def bot(self, settings, tracker):
        from app.service import WalletService

        service = WalletService(settings, tracker=tracker)
        return TelegramBot(service, settings=settings)

    def test_start_mentions_no_secrets(self, bot):
        text = bot.handle_command(0, "/start")
        assert "never" in text.lower()
        assert "seed" in text.lower()

    def test_help_lists_commands(self, bot):
        text = bot.handle_command(0, "/help")
        assert "/status" in text
        assert "/inspect" in text

    def test_status_shows_all_subsystems(self, bot):
        text = bot.handle_command(0, "/status")
        for key in ("wallet_data", "assets_chains", "memepol_comparison"):
            assert key in text

    def test_status_shows_credential_flags(self, bot):
        text = bot.handle_command(0, "/status")
        assert "TELEGRAM_BOT_TOKEN" in text
        assert "MEMEPOL_API_KEY" in text

    def test_chains_command(self, bot):
        text = bot.handle_command(0, "/chains")
        assert "ethereum" in text
        assert "bitcoin" in text

    def test_inspect_without_args_shows_usage(self, bot):
        assert "Usage" in bot.handle_command(0, "/inspect")

    def test_unknown_command(self, bot):
        assert "Unknown command" in bot.handle_command(0, "/nope")

    def test_handle_update_extracts_message(self, bot):
        update = {"update_id": 1, "message": {"chat": {"id": 5}, "text": "/help"}}
        assert bot.handle_update(update) is not None

    def test_handle_update_ignores_non_text(self, bot):
        update = {"update_id": 1, "message": {"chat": {"id": 5}}}
        assert bot.handle_update(update) is None

    def test_command_with_bot_suffix(self, bot):
        assert bot.handle_command(0, "/help@HermesBot") is not None

    def test_poll_requires_token(self, bot):
        from app.errors import ConfigError

        with pytest.raises(ConfigError):
            bot.poll_forever(max_iterations=1)


class TestBotNaming:
    def test_help_uses_configured_name(self, settings, tracker):
        from dataclasses import replace

        from app.service import WalletService

        named = replace(settings, bot_display_name="hermesgotdat")
        service = WalletService(named, tracker=tracker)
        bot = TelegramBot(service, settings=named)
        text = bot.handle_command(0, "/start")
        assert "hermesgotdat" in text

    def test_default_name_when_unset(self, settings, tracker):
        from app.service import WalletService

        service = WalletService(settings, tracker=tracker)
        bot = TelegramBot(service, settings=settings)
        assert "Hermes Wallet Inspector" in bot.handle_command(0, "/help")

    def test_setname_without_args_shows_usage(self, settings, tracker):
        from app.service import WalletService

        service = WalletService(settings, tracker=tracker)
        bot = TelegramBot(service, settings=settings)
        text = bot.handle_command(0, "/setname")
        assert "Usage" in text

    def test_setname_calls_bot_api(self, settings, tracker):
        from app.service import WalletService
        from app.telegram.bot import TelegramClient

        calls = []

        class FakeClient(TelegramClient):
            def __init__(self):
                super().__init__("123456:fake-token-for-test")

            def call(self, method, payload=None):
                calls.append((method, payload))
                return True

        service = WalletService(settings, tracker=tracker)
        bot = TelegramBot(service, settings=settings, client=FakeClient())
        reply = bot.handle_command(0, "/setname hermesgotdat")
        assert "✓" in reply
        assert calls and calls[0][0] == "setMyName"
        assert calls[0][1]["name"] == "hermesgotdat"

    def test_setname_reports_api_failure(self, settings, tracker):
        from app.service import WalletService
        from app.telegram.bot import TelegramClient

        class FailingClient(TelegramClient):
            def __init__(self):
                super().__init__("123456:fake-token-for-test")

            def call(self, method, payload=None):
                raise RuntimeError("api down")

        service = WalletService(settings, tracker=tracker)
        bot = TelegramBot(service, settings=settings, client=FailingClient())
        assert "✗" in bot.handle_command(0, "/setname whatever")
