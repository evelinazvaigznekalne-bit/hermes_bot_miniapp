"""Tests for the file-backed open-crypto-puzzles source."""

from __future__ import annotations

import json

import pytest

from app.puzzles.analysis import PuzzleAnalyzer, Verdict
from app.puzzles.ocp import OcpSource

SAMPLE_INDEX = {
    "schema_version": 1,
    "counts": {"big": 1, "mid": 1},
    "puzzles": [
        {
            "slug": "demo-btc",
            "title": "Demo Bitcoin Puzzle",
            "chain": "bitcoin",
            "status": "open",
            "puzzle_type": ["bip39-seed"],
            "addresses": [
                {"address": "14zMkTgaVXJcxdh4JdWi29MLRR44iUSG9W", "chain": "bitcoin",
                 "role": "escrow", "label": "stage 1",
                 "verified_state": "funded-unspent"},
                {"address": "13Cv6SXUnzGDT8JHqzzJ8xMPtsSdhJA4wd", "chain": "bitcoin",
                 "role": "payout", "verified_state": "spent"},
            ],
            "leads": [
                {"rank": 1, "title": "ask the solver for the convention",
                 "cost": "needs-a-person", "status": "open"},
                {"rank": 2, "title": "bounded edit sweep", "cost": "gpu"},
            ],
            "artifacts": [
                {"path": "clues/x.jpg", "source": "https://example.test/x.jpg"},
            ],
        },
        {
            "slug": "demo-eth",
            "title": "Demo Ethereum Puzzle",
            "chain": "ethereum",
            "status": "solved",
            "addresses": [
                {"address": "0xDe0DAFC80d487b8aE652bBF906ac6c6007aE3A5e",
                 "chain": "ethereum", "role": "escrow"},
            ],
        },
        {
            "slug": "demo-nochain",
            "title": "No chain puzzle",
            "chain": "none",
            "addresses": [],
        },
    ],
}


@pytest.fixture
def index_file(tmp_path):
    path = tmp_path / "puzzles.json"
    path.write_text(json.dumps(SAMPLE_INDEX), encoding="utf-8")
    return path


class TestOcpSource:
    def test_loads_and_converts(self, index_file):
        src = OcpSource(index_file)
        assert src.configured is True
        entries = src.list_puzzles()
        assert len(entries) == 3
        assert {e.id for e in entries} == {"demo-btc", "demo-eth", "demo-nochain"}

    def test_prefers_escrow_address_over_payout(self, index_file):
        entry = next(e for e in OcpSource(index_file).list_puzzles()
                     if e.id == "demo-btc")
        assert entry.criteria["address"] == "14zMkTgaVXJcxdh4JdWi29MLRR44iUSG9W"
        assert entry.criteria["escrow_state"] == "funded-unspent"

    def test_leads_become_hints(self, index_file):
        entry = next(e for e in OcpSource(index_file).list_puzzles()
                     if e.id == "demo-btc")
        assert len(entry.hints) == 2
        assert entry.hints[0].startswith("#1")
        assert "needs-a-person" in entry.hints[0]

    def test_artifacts_become_images(self, index_file):
        entry = next(e for e in OcpSource(index_file).list_puzzles()
                     if e.id == "demo-btc")
        assert entry.images == ["https://example.test/x.jpg"]

    def test_chain_none_is_dropped_from_criteria(self, index_file):
        entry = next(e for e in OcpSource(index_file).list_puzzles()
                     if e.id == "demo-nochain")
        assert "chain" not in entry.criteria

    def test_note_summarises_status(self, index_file):
        entry = next(e for e in OcpSource(index_file).list_puzzles()
                     if e.id == "demo-btc")
        assert "status=open" in entry.note
        assert "escrow=funded-unspent" in entry.note

    def test_missing_file_is_unconfigured(self, tmp_path):
        src = OcpSource(tmp_path / "nope.json")
        assert src.configured is False
        with pytest.raises(FileNotFoundError):
            src.list_puzzles()

    def test_describe_reports_no_api_key_needed(self, index_file):
        d = OcpSource(index_file).describe()
        assert d["requires_api_key"] is False
        assert d["configured"] is True

    def test_malformed_json_raises_value_error(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("{not json", encoding="utf-8")
        with pytest.raises(ValueError):
            OcpSource(bad).list_puzzles()

    def test_missing_puzzles_key_raises(self, tmp_path):
        p = tmp_path / "empty.json"
        p.write_text(json.dumps({"schema_version": 1}), encoding="utf-8")
        with pytest.raises(ValueError):
            OcpSource(p).list_puzzles()

    def test_caching(self, index_file):
        src = OcpSource(index_file)
        first = src.list_puzzles()
        index_file.write_text(json.dumps({"puzzles": []}), encoding="utf-8")
        assert len(src.list_puzzles()) == len(first)      # cached
        assert src.list_puzzles(refresh=True) == []       # forced reload


class TestOcpIntegration:
    """The analyzer driving the file source end-to-end."""

    def analyzer(self, index_file):
        from app.config import Settings
        from app.puzzles.memepol import MemePolClient

        client = MemePolClient(Settings(memepol_api_key=None))
        return PuzzleAnalyzer(client, source=OcpSource(index_file))

    def report(self, chain, address, balance=0.0, symbol="BTC"):
        from app.chains.base import Asset, AssetReport

        r = AssetReport(address=address, chain=chain, family=chain,
                        native_symbol=symbol, status="✓")
        r.balance_native = balance
        r.assets.append(Asset(symbol=symbol, amount=balance, raw="0", decimals=8))
        return r

    def test_exact_match_on_escrow_address(self, index_file):
        result = self.analyzer(index_file).analyze(
            self.report("bitcoin", "14zMkTgaVXJcxdh4JdWi29MLRR44iUSG9W", 0.777))
        assert result.verdict is Verdict.EXACT
        assert result.source == "ocp"
        assert result.evaluated == 3
        assert result.hints

    def test_unrelated_bitcoin_address_is_no_match(self, index_file):
        result = self.analyzer(index_file).analyze(
            self.report("bitcoin", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", 57.5))
        assert result.verdict is Verdict.NONE
        assert result.hints == []

    def test_eth_wallet_does_not_match_bitcoin_puzzles(self, index_file):
        result = self.analyzer(index_file).analyze(
            self.report("ethereum", "0x1111111111111111111111111111111111111111",
                        1.0, "ETH"))
        assert result.verdict is Verdict.NONE

    def test_eth_escrow_address_matches_its_puzzle(self, index_file):
        result = self.analyzer(index_file).analyze(
            self.report("ethereum", "0xDe0DAFC80d487b8aE652bBF906ac6c6007aE3A5e",
                        0.0, "ETH"))
        assert result.verdict is Verdict.EXACT
