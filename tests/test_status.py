"""Status tracking tests (✓ / ✗ / ⏳)."""

from __future__ import annotations

import json

import pytest

from app.status import FAIL, OK, PENDING, SUBSYSTEMS, StatusTracker


class TestStatusTracker:
    def test_initial_state_is_pending(self, tracker):
        assert set(tracker.compact().values()) == {PENDING}
        assert set(tracker.compact().keys()) == set(SUBSYSTEMS)

    def test_transitions(self, tracker):
        tracker.ok("wallet_data")
        tracker.fail("assets_chains", "boom")
        tracker.pending("puzzle_hints")
        compact = tracker.compact()
        assert compact["wallet_data"] == OK
        assert compact["assets_chains"] == FAIL
        assert compact["puzzle_hints"] == PENDING

    def test_error_detail_retained(self, tracker):
        tracker.fail("assets_chains", "HTTP 503 from blockscout")
        snapshot = tracker.snapshot()
        assert snapshot["assets_chains"]["detail"] == "HTTP 503 from blockscout"
        assert snapshot["assets_chains"]["status"] == FAIL

    def test_persists_json_lines(self, tmp_path):
        path = tmp_path / "logs" / "status.log"
        tracker = StatusTracker(path)
        tracker.ok("wallet_data", "verified")
        tracker.fail("memepol_comparison", "not configured")
        lines = path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 2
        records = [json.loads(line) for line in lines]
        assert records[0]["key"] == "wallet_data"
        assert records[0]["status"] == OK
        assert records[1]["detail"] == "not configured"

    def test_directory_created_automatically(self, tmp_path):
        nested = tmp_path / "a" / "b" / "c" / "status.log"
        StatusTracker(nested)
        assert nested.parent.is_dir()

    def test_invalid_status_rejected(self, tracker):
        with pytest.raises(ValueError):
            tracker.set("wallet_data", "maybe")

    def test_snapshot_has_timestamps(self, tracker):
        tracker.ok("wallet_data")
        assert "updated_at" in tracker.snapshot()["wallet_data"]

    # --- replay on init (persistence) -----------------------------------

    def test_fresh_tracker_loads_last_known_state(self, tmp_path):
        """A new tracker over an existing log restores the LAST event per key."""
        path = tmp_path / "logs" / "status.log"
        writer = StatusTracker(path)
        writer.fail("assets_chains", "HTTP 503 from blockscout")
        writer.ok("assets_chains", "4 asset(s) on ethereum")   # last wins
        writer.ok("wallet_data", "ownership verified via signature")

        fresh = StatusTracker(path)
        compact = fresh.compact()
        assert compact["assets_chains"] == OK
        assert compact["wallet_data"] == OK
        # a subsystem with no record keeps the default
        assert compact["memepol_comparison"] == PENDING
        assert set(compact.keys()) == set(SUBSYSTEMS)

        snapshot = fresh.snapshot()
        assert snapshot["assets_chains"]["detail"] == "4 asset(s) on ethereum"
        assert snapshot["assets_chains"]["status"] == OK

    def test_replay_preserves_updated_at(self, tmp_path):
        path = tmp_path / "logs" / "status.log"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps({
                "key": "puzzle_hints", "status": OK,
                "detail": "2 hint(s)", "updated_at": "2026-01-02T03:04:05+00:00",
            }) + "\n",
            encoding="utf-8",
        )
        entry = StatusTracker(path).snapshot()["puzzle_hints"]
        assert entry["status"] == OK
        assert entry["detail"] == "2 hint(s)"
        assert entry["updated_at"] == "2026-01-02T03:04:05+00:00"

    def test_missing_log_keeps_defaults(self, tmp_path):
        tracker = StatusTracker(tmp_path / "nope" / "status.log")
        assert set(tracker.compact().values()) == {PENDING}

    def test_empty_log_keeps_defaults(self, tmp_path):
        path = tmp_path / "logs" / "status.log"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")
        assert set(StatusTracker(path).compact().values()) == {PENDING}

    def test_malformed_lines_are_skipped_individually(self, tmp_path):
        path = tmp_path / "logs" / "status.log"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "not json at all\n"
            '{"key": "wallet_data", "status": "✓", "detail": "ok"}\n'
            '{"key": "assets_chains", "status": "bogus"}\n'      # invalid status
            '{"key": "not_a_subsystem", "status": "✓"}\n'        # unknown key
            '{"key": "puzzle_images", "status": "✗"}\n'
            '{"key": "assets_chains", "status": "✗", "detail": "torn\n',  # truncated
            encoding="utf-8",
        )
        compact = StatusTracker(path).compact()
        assert compact["wallet_data"] == OK
        assert compact["puzzle_images"] == FAIL
        # invalid-status and unknown-key records are ignored, not applied
        assert compact["assets_chains"] == PENDING
        assert set(compact.keys()) == set(SUBSYSTEMS)

    def test_replay_does_not_write_to_the_log(self, tmp_path):
        """Replaying must not append — the log stays append-only history."""
        path = tmp_path / "logs" / "status.log"
        writer = StatusTracker(path)
        writer.ok("wallet_data", "verified")
        before = path.read_text(encoding="utf-8")

        StatusTracker(path)                     # replay only
        assert path.read_text(encoding="utf-8") == before


class TestLoggingSetup:
    def test_log_dir_and_redaction(self, tmp_path):
        import logging

        from app.logging_setup import register_secret, setup_logging

        logger = setup_logging(tmp_path / "logs", stream=False)
        assert (tmp_path / "logs").is_dir()

        secret = "123456:SUPERSECRETTOKENVALUE"
        register_secret(secret)
        logger.info("token is %s", secret)
        for handler in logger.handlers:
            handler.flush()

        content = (tmp_path / "logs" / "app.log").read_text(encoding="utf-8")
        assert secret not in content
        assert "<redacted>" in content
        logging.getLogger("hermes_miniapp").handlers.clear()


class TestStatusTrackerSanitization:
    """StatusTracker must not persist raw exception details."""

    def test_raw_exception_detail_is_sanitized(self, tmp_path):
        from app.errors import _safe_detail
        path = tmp_path / "logs" / "status.log"
        tracker = StatusTracker(path)
        tracker.fail("assets_chains", "ChainAPIError: blockscout returned HTTP 503 with body ...")
        lines = path.read_text(encoding="utf-8").strip().splitlines()
        record = json.loads(lines[-1])
        assert record["detail"] == "internal"

    def test_safe_non_exception_detail_preserved(self, tmp_path):
        path = tmp_path / "logs" / "status.log"
        tracker = StatusTracker(path)
        tracker.ok("wallet_data", "verified via signature")
        lines = path.read_text(encoding="utf-8").strip().splitlines()
        record = json.loads(lines[-1])
        assert record["detail"] == "verified via signature"

    def test_detail_with_credentials_is_sanitized(self, tmp_path):
        path = tmp_path / "logs" / "status.log"
        tracker = StatusTracker(path)
        tracker.fail("assets_chains", "error calling https://rpc.example.com?key=secret123")
        lines = path.read_text(encoding="utf-8").strip().splitlines()
        record = json.loads(lines[-1])
        assert record["detail"] == "internal"

    def test_detail_with_mnemonic_keyword_is_sanitized(self, tmp_path):
        path = tmp_path / "logs" / "status.log"
        tracker = StatusTracker(path)
        tracker.fail("assets_chains", "invalid mnemonic phrase supplied")
        lines = path.read_text(encoding="utf-8").strip().splitlines()
        record = json.loads(lines[-1])
        assert record["detail"] == "internal"
