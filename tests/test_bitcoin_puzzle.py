"""Tests for the Bitcoin Puzzle Transaction solver."""

from __future__ import annotations

import pytest

from app.puzzles.bitcoin_puzzle import (
    PuzzleTransaction,
    PuzzleAttempt,
    KNOWN_PUZZLES,
    identify_puzzle_address,
    estimate_keyspace,
    brute_force_puzzle,
    run_puzzle_witness,
    _format_duration,
)


class TestKnownPuzzles:
    def test_known_puzzles_not_empty(self):
        assert len(KNOWN_PUZZLES) > 0

    def test_puzzle_1_exists(self):
        puzzle = identify_puzzle_address("1PpyGsfXz1TJdYxRBEEGgsat37ZDmLsyWw")
        assert puzzle is not None
        assert puzzle.puzzle_number == 1

    def test_puzzle_32_exists(self):
        puzzle = identify_puzzle_address("1LxELwZvgDyjXruDxBzWBdUXBCBbRCr2h3")
        assert puzzle is not None
        assert puzzle.puzzle_number == 32

    def test_unknown_address_returns_none(self):
        result = identify_puzzle_address("1UnknownAddressHere123456789")
        assert result is None

    def test_puzzle_metadata_complete(self):
        for addr, puzzle in KNOWN_PUZZLES.items():
            assert puzzle.address == addr
            assert puzzle.txid
            assert puzzle.block_height > 0
            assert puzzle.keyspace_range[0] <= puzzle.keyspace_range[1]


class TestEstimateKeyspace:
    def test_small_range(self):
        est = estimate_keyspace(0x01, 0x10)
        assert est["space_size"] == 16
        assert est["feasible"] is True

    def test_large_range_infeasible(self):
        est = estimate_keyspace(0x1, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
        assert est["space_size"] > 0
        assert est["feasible"] is False

    def test_invalid_range(self):
        est = estimate_keyspace(0x10, 0x01)
        assert est["space_size"] == 0
        assert est["feasible"] is False
        assert "message" in est

    def test_estimates_present(self):
        est = estimate_keyspace(0x100, 0xFFFF)
        assert "estimates" in est
        assert "cpu_1M_s" in est["estimates"]
        assert "gpu_100M_s" in est["estimates"]
        assert "asic_1B_s" in est["estimates"]


class TestBruteForcePuzzle:
    def test_match_found(self):
        puzzle = PuzzleTransaction(
            txid="test",
            address="1Test",
            amount_btc=0.1,
            block_height=500000,
            puzzle_number=99,
            keyspace_range=(1, 100),
        )
        # Oracle that matches key 42
        def oracle(key):
            return key == 42

        result = brute_force_puzzle(puzzle, oracle)
        assert result.outcome == "MATCH"
        assert result.tested == 41
        assert "0x2a" in result.message

    def test_no_match(self):
        puzzle = PuzzleTransaction(
            txid="test",
            address="1Test",
            amount_btc=0.1,
            block_height=500000,
            puzzle_number=99,
            keyspace_range=(1, 50),
        )
        def oracle(key):
            return False

        result = brute_force_puzzle(puzzle, oracle)
        assert result.outcome == "UNCERTIFIED"
        assert result.tested == 50

    def test_max_test_limit(self):
        puzzle = PuzzleTransaction(
            txid="test",
            address="1Test",
            amount_btc=0.1,
            block_height=500000,
            puzzle_number=99,
            keyspace_range=(1, 1000),
        )
        def oracle(key):
            return False

        result = brute_force_puzzle(puzzle, oracle, max_test=10)
        assert result.tested == 10
        assert result.outcome == "UNCERTIFIED"

    def test_witness_run(self):
        puzzle = PuzzleTransaction(
            txid="test",
            address="1Test",
            amount_btc=0.1,
            block_height=500000,
            puzzle_number=99,
            keyspace_range=(1, 100),
        )
        def oracle(key):
            return key == 42

        assert run_puzzle_witness(puzzle, oracle, 42) is True
        assert run_puzzle_witness(puzzle, oracle, 43) is False


class TestFormatDuration:
    def test_milliseconds(self):
        assert "ms" in _format_duration(0.5)

    def test_seconds(self):
        assert "s" in _format_duration(30)

    def test_minutes(self):
        assert "min" in _format_duration(300)

    def test_hours(self):
        assert "hours" in _format_duration(7200)

    def test_days(self):
        assert "days" in _format_duration(172800)

    def test_years(self):
        assert "years" in _format_duration(63072000)

    def test_infinite(self):
        assert "infinite" in _format_duration(1e30)
