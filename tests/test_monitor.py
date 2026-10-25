"""Tests for the puzzle monitor."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from app.monitor import Monitor, MonitorEvent


class TestFetchBalance:
    def test_confirmed_zero_balance(self, tmp_path):
        log_path = tmp_path / "monitor.log"
        mon = Monitor(log_path=log_path)

        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "chain_stats": {
                "funded_txo_sum": 0,
                "spent_txo_sum": 0,
            }
        }).encode()
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_response):
            balance = mon._fetch_balance("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")

        assert balance == 0

    def test_positive_balance(self, tmp_path):
        log_path = tmp_path / "monitor.log"
        mon = Monitor(log_path=log_path)

        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "chain_stats": {
                "funded_txo_sum": 50000,
                "spent_txo_sum": 10000,
            }
        }).encode()
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_response):
            balance = mon._fetch_balance("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")

        assert balance == 40000

    def test_http_failure_returns_none(self, tmp_path):
        log_path = tmp_path / "monitor.log"
        mon = Monitor(log_path=log_path)

        with patch("urllib.request.urlopen", side_effect=Exception("HTTP 400")):
            balance = mon._fetch_balance("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")

        assert balance is None

    def test_network_timeout_returns_none(self, tmp_path):
        log_path = tmp_path / "monitor.log"
        mon = Monitor(log_path=log_path)

        with patch("urllib.request.urlopen", side_effect=Exception("timed out")):
            balance = mon._fetch_balance("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")

        assert balance is None

    def test_invalid_address_returns_none(self, tmp_path):
        log_path = tmp_path / "monitor.log"
        mon = Monitor(log_path=log_path)

        with patch("urllib.request.urlopen", side_effect=Exception("HTTP 400 Bad Request")):
            balance = mon._fetch_balance("1Invalid")

        assert balance is None

    def test_malformed_json_returns_none(self, tmp_path):
        log_path = tmp_path / "monitor.log"
        mon = Monitor(log_path=log_path)

        mock_response = MagicMock()
        mock_response.read.return_value = b"not json"
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_response):
            balance = mon._fetch_balance("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")

        assert balance is None


class TestCheckAddress:
    def test_failure_does_not_overwrite_state(self, tmp_path):
        log_path = tmp_path / "monitor.log"
        mon = Monitor(log_path=log_path)
        mon._last_state = {"addr1": {"balance": 100}}

        mock_puzzle = MagicMock(puzzle_number=1)
        with patch.object(mon, "_fetch_balance", return_value=None):
            event = mon._check_address("addr1", mock_puzzle)

        assert event is None
        assert mon._last_state["addr1"]["balance"] == 100

    def test_restart_does_not_emit_fake_event(self, tmp_path):
        log_path = tmp_path / "monitor.log"
        mon = Monitor(log_path=log_path)

        mock_puzzle = MagicMock(puzzle_number=1)
        with patch.object(mon, "_fetch_balance", return_value=0):
            event = mon._check_address("addr1", mock_puzzle)

        assert event is None
        assert mon._last_state["addr1"]["balance"] == 0

    def test_balance_change_emits_event(self, tmp_path):
        log_path = tmp_path / "monitor.log"
        mon = Monitor(log_path=log_path)
        mon._last_state = {"addr1": {"balance": 100}}

        mock_puzzle = MagicMock(puzzle_number=1)
        with patch.object(mon, "_fetch_balance", return_value=200):
            event = mon._check_address("addr1", mock_puzzle)

        assert event is not None
        assert event.kind == "balance_change"
        assert event.detail == "Balance changed: 100 -> 200"
        assert mon._last_state["addr1"]["balance"] == 200


class TestStatus:
    def test_event_count_from_log(self, tmp_path):
        log_path = tmp_path / "monitor.log"
        log_path.write_text(
            '{"kind": "balance_change"}\n{"kind": "balance_change"}\n'
        )

        mon = Monitor(log_path=log_path)
        status = mon.status()

        assert status["events_logged"] == 2

    def test_last_check_from_log(self, tmp_path):
        log_path = tmp_path / "monitor.log"
        log_path.write_text(
            '{"kind": "balance_change", "timestamp": "2026-10-24T14:25:39+00:00"}\n'
        )

        mon = Monitor(log_path=log_path)
        status = mon.status()

        assert status["last_check"] == "2026-10-24T14:25:39+00:00"

    def test_daemon_status_returns_string(self, tmp_path):
        log_path = tmp_path / "monitor.log"
        mon = Monitor(log_path=log_path)
        status = mon.status()

        assert isinstance(status["daemon_status"], str)
        assert status["daemon_status"] in ("running", "stopped")


class TestMonitorText:
    def test_monitor_text_includes_daemon_status(self):
        from app.telegram.bot import TelegramBot
        from app.service import WalletService
        from app.config import get_settings

        settings = get_settings()
        service = WalletService(settings)
        bot = TelegramBot(service=service, selftest=True)

        with patch("app.monitor.Monitor") as MockMonitor:
            mock_mon = MockMonitor.return_value
            mock_mon.status.return_value = {
                "watching": 3,
                "interval_sec": 900,
                "events_logged": 12,
                "last_check": "2026-10-24T15:00:33+00:00",
                "daemon_status": "stopped",
                "log_path": "logs/monitor.log",
                "puzzles": [
                    {
                        "puzzle_number": 1,
                        "address": "1PpyGsfXz1TJdYxRBEEGgsat37ZDmLsyWw",
                        "amount_btc": 1.0,
                    },
                ],
            }
            reply = bot._monitor_text([])

        assert "Puzzle Monitoring" in reply
        assert "Daemon: <b>stopped</b>" in reply
        assert "Watching: <b>3</b>" in reply
        assert "Interval: <b>900s</b>" in reply
        assert "Events logged: <b>12</b>" in reply
        assert "Last check: <b>2026-10-24T15:00:33+00:00</b>" in reply
        assert "Start:" in reply
