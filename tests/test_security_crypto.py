"""Security regression tests for Phase 1 crypto tools.

Verifies that sensitive material (mnemonics, seeds, private keys, xpubs,
addresses, passphrases) is never persisted to the tool log, that access
control blocks unauthorized users, and that exceptions are sanitized.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.config import Settings
from app.telegram.bot import TelegramBot
from app.tool_logger import ToolLogger, _redact, log_tool_result, recent_tool_logs
from app.errors import _safe_exception


# ---------------------------------------------------------------------------
# Synthetic, non-functional test data
# ---------------------------------------------------------------------------

SYNTHETIC_MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
SYNTHETIC_SEED_HEX = "a" * 64
SYNTHETIC_WIF = "5Kb8kLf9zgWQnogidDA76MzPL6TsZZY36hWXMssSzNydYXYB9KF"
SYNTHETIC_XPUB = "xpub" + "A" * 108
SYNTHETIC_ADDRESS = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
SYNTHETIC_PASSPHRASE = "super secret passphrase"


class TestToolLoggerRedaction:
    """Central redaction in tool_logger.py."""

    def test_mnemonic_redacted(self):
        assert _redact(SYNTHETIC_MNEMONIC) == "<redacted>"

    def test_seed_hex_redacted(self):
        assert _redact(SYNTHETIC_SEED_HEX) == "<redacted>"

    def test_wif_redacted(self):
        assert _redact(SYNTHETIC_WIF) == "<redacted>"

    def test_xpub_redacted(self):
        assert _redact(SYNTHETIC_XPUB) == "<redacted>"

    def test_address_redacted(self):
        assert _redact(SYNTHETIC_ADDRESS) == "<redacted>"

    def test_passphrase_redacted(self):
        assert _redact(SYNTHETIC_PASSPHRASE) == "<redacted>"

    def test_safe_text_unchanged(self):
        assert _redact("balance is 1.5 btc") == "balance is 1.5 btc"

    def test_empty_unchanged(self):
        assert _redact("") == ""

    def test_error_label_never_exposes_message(self):
        class LeakyExc(Exception):
            def __str__(self):
                return f"bad seed {SYNTHETIC_SEED_HEX}"

        exc = LeakyExc("detail")
        from app.tool_logger import _safe_error
        # Non-allowed exception classes map to InternalError
        assert _safe_error(exc) == "InternalError"
        assert SYNTHETIC_SEED_HEX not in _safe_error(exc)

    def test_allowed_error_category_preserved(self):
        exc = ValueError("some detail")
        from app.tool_logger import _safe_error
        assert _safe_error(exc) == "ValueError"


class TestToolLoggerPersistence:
    """SQLite must not contain raw sensitive strings."""

    def test_log_does_not_persist_raw_mnemonic(self, tmp_path):
        db = tmp_path / "logs.db"
        logger = ToolLogger(db_path=str(db))
        logger.log(
            tool="mnemonic_to_xkeys",
            input_summary=SYNTHETIC_MNEMONIC,
            output_summary=SYNTHETIC_XPUB,
            success=True,
        )
        rows = logger.recent(limit=1)
        assert len(rows) == 1
        row = rows[0]
        # Sensitive tools get fixed summaries; raw values are discarded.
        assert row["input_summary"] == "<redacted>"
        assert row["output_summary"] == "success; output redacted"
        assert SYNTHETIC_MNEMONIC not in row["input_summary"]
        assert SYNTHETIC_XPUB not in row["output_summary"]

    def test_failed_call_logs_safely(self, tmp_path):
        db = tmp_path / "logs.db"
        logger = ToolLogger(db_path=str(db))

        class SensitiveError(Exception):
            def __str__(self):
                return f"invalid mnemonic {SYNTHETIC_MNEMONIC}"

        logger.log(
            tool="mnemonic_to_xkeys",
            input_summary="<redacted>",
            output_summary="failed",
            success=False,
            error=SensitiveError("boom"),
        )
        rows = logger.recent(limit=1)
        assert len(rows) == 1
        row = rows[0]
        assert row["success"] == 0
        # Non-allowed error class maps to InternalError
        assert row["error"] == "InternalError"
        assert SYNTHETIC_MNEMONIC not in row["error"]

    def test_prune_removes_old_rows(self, tmp_path):
        db = tmp_path / "logs.db"
        logger = ToolLogger(db_path=str(db))
        logger.log(tool="price", input_summary="old", output_summary="old", success=True)
        logger.log(tool="price", input_summary="new", output_summary="new", success=True)
        before = logger.recent(limit=10)[0]["ts"]
        removed = logger.prune(before=before)
        assert removed >= 1
        assert len(logger.recent(limit=10)) == 1


class TestTelegramAccessControl:
    """Sensitive commands must reject unauthorized users."""

    @pytest.fixture
    def settings(self, tmp_path):
        return Settings(
            telegram_bot_token="123456:TOKEN",
            telegram_authorized_user_ids=(100, 200),
            log_dir=tmp_path / "logs",
        )

    @pytest.fixture
    def bot(self, settings, tmp_path):
        from app.service import WalletService
        from app.status import StatusTracker
        tracker = StatusTracker(tmp_path / "logs" / "status.log")
        return TelegramBot(
            service=WalletService(settings, tracker=tracker),
            settings=settings,
        )

    def test_authorized_user_allowed(self, bot):
        # Pass sender_id explicitly; authorization now uses from.id, not chat_id.
        reply = bot.handle_command(100, "/xkeys " + SYNTHETIC_MNEMONIC,
                                   sender_id=100)
        assert "🔑" in reply or "Valid" in reply or "xpub" in reply

    def test_unauthorized_user_denied(self, bot):
        reply = bot.handle_command(999, "/xkeys " + SYNTHETIC_MNEMONIC,
                                   sender_id=999)
        assert "Access denied" in reply

    def test_missing_allowlist_denies(self, tmp_path):
        settings = Settings(
            telegram_bot_token="123456:TOKEN",
            telegram_authorized_user_ids=(),
            log_dir=tmp_path / "logs",
        )
        from app.service import WalletService
        from app.status import StatusTracker
        tracker = StatusTracker(tmp_path / "logs" / "status.log")
        bot = TelegramBot(
            service=WalletService(settings, tracker=tracker),
            settings=settings,
        )
        reply = bot.handle_command(100, "/xkeys " + SYNTHETIC_MNEMONIC,
                                   sender_id=100)
        assert "Authorized users only" in reply

    def test_all_four_sensitive_commands_blocked(self, bot):
        for cmd in ("/xkeys", "/mnemonic", "/keycalc", "/bip38"):
            reply = bot.handle_command(999, f"{cmd} test", sender_id=999)
            assert "Access denied" in reply

    def test_group_chat_denied(self, bot):
        for cmd in ("/xkeys", "/mnemonic", "/keycalc", "/bip38"):
            reply = bot.handle_command(999, f"{cmd} test",
                                       sender_id=999, chat_type="group")
            assert "private only" in reply.lower()

    def test_missing_sender_identity_denied(self, bot):
        reply = bot.handle_command(999, "/xkeys test", sender_id=None)
        assert "Access denied" in reply

    def test_non_integer_sender_denied(self, bot):
        reply = bot.handle_command(999, "/xkeys test", sender_id="not-an-int")
        assert "Access denied" in reply


class TestExceptionSanitization:
    """Exception messages returned to Telegram must not leak secrets."""

    @pytest.fixture
    def bot(self, tmp_path):
        settings = Settings(
            telegram_bot_token="123456:TOKEN",
            telegram_authorized_user_ids=(),
            log_dir=tmp_path / "logs",
        )
        from app.service import WalletService
        from app.status import StatusTracker
        tracker = StatusTracker(tmp_path / "logs" / "status.log")
        return TelegramBot(
            service=WalletService(settings, tracker=tracker),
            settings=settings,
        )

    def test_safe_exception_sanitizes_sensitive_keywords(self):
        class LeakyExc(Exception):
            def __str__(self):
                return f"bad mnemonic {SYNTHETIC_MNEMONIC}"

        result = _safe_exception(LeakyExc("boom"))
        # Non-allowed exception classes map to InternalError
        assert result == "InternalError: operation failed"
        assert SYNTHETIC_MNEMONIC not in result

    def test_safe_exception_preserves_non_sensitive(self):
        exc = ValueError("network timeout")
        result = _safe_exception(exc)
        # Allowed classes keep their name, but message is never exposed
        assert "ValueError" in result
        assert "operation failed" in result
        assert "timeout" not in result
