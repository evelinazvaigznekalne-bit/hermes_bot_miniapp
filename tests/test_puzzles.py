"""MemePol client + puzzle-analysis verdict tests."""

from __future__ import annotations

import pytest

from app.chains.base import Asset, AssetReport
from app.config import Settings
from app.errors import PuzzleAPIError
from app.puzzles.analysis import PuzzleAnalyzer, Verdict
from app.puzzles.memepol import MemePolClient, PuzzleEntry

SAMPLE_EVM = "0xDe0DAFC80d487b8aE652bBF906ac6c6007aE3A5e"


def make_settings(*, api_key=None, base_url="https://api.memepol.test/v1"):
    return Settings(memepol_base_url=base_url, memepol_api_key=api_key)


def make_report(*, address=SAMPLE_EVM, chain="ethereum", balance=1.0, symbol="ETH"):
    report = AssetReport(address=address, chain=chain, family="evm",
                         native_symbol=symbol, status="✓")
    report.balance_native = balance
    report.assets.append(Asset(symbol=symbol, amount=balance, raw="1", decimals=18))
    return report


class FakeHttp:
    def __init__(self, payload=None, error=None):
        self.payload = payload
        self.error = error
        self.calls = []

    def get_json(self, url, *, provider, params=None, headers=None):
        self.calls.append((url, headers))
        if self.error:
            raise self.error
        return self.payload

    def post_json(self, url, *, provider, json_body=None, headers=None):
        return self.get_json(url, provider=provider)


class TestMemePolClient:
    def test_unconfigured_without_key(self):
        client = MemePolClient(make_settings(api_key=None))
        assert client.configured is False
        with pytest.raises(PuzzleAPIError):
            client.list_puzzles()

    def test_placeholder_key_treated_as_unconfigured(self):
        client = MemePolClient(make_settings(api_key="YOUR_MEMEPOL_API_KEY"))
        assert client.configured is False

    def test_configured_with_key(self):
        client = MemePolClient(make_settings(api_key="sk_live_abc123"))
        assert client.configured is True

    def test_api_key_sent_in_header_not_url(self):
        http = FakeHttp(payload={"puzzles": []})
        client = MemePolClient(make_settings(api_key="sk_live_abc123"), http=http)
        client.list_puzzles()
        url, headers = http.calls[0]
        assert "sk_live_abc123" not in url
        assert headers["Authorization"] == "Bearer sk_live_abc123"

    def test_parses_list_payload(self):
        http = FakeHttp(payload={"puzzles": [
            {"id": "p1", "title": "Puzzle One", "chain": "ethereum",
             "criteria": {"address": SAMPLE_EVM, "min_balance": 1},
             "hints": ["look closer"], "images": ["ipfs://abc"]},
        ]})
        client = MemePolClient(make_settings(api_key="k"), http=http)
        entries = client.list_puzzles()
        assert len(entries) == 1
        assert entries[0].id == "p1"
        assert entries[0].criteria["min_balance"] == 1
        assert entries[0].hints == ["look closer"]

    def test_parses_flat_shape(self):
        entry = PuzzleEntry.from_api({"id": "x", "address": SAMPLE_EVM,
                                      "min_balance": 2, "symbol": "ETH"})
        assert entry.criteria["address"] == SAMPLE_EVM
        assert entry.criteria["symbol"] == "ETH"

    def test_tolerates_bare_list(self):
        http = FakeHttp(payload=[{"id": "a"}, {"id": "b"}])
        client = MemePolClient(make_settings(api_key="k"), http=http)
        assert [e.id for e in client.list_puzzles()] == ["a", "b"]

    def test_bad_shape_raises(self):
        http = FakeHttp(payload="nonsense")
        client = MemePolClient(make_settings(api_key="k"), http=http)
        with pytest.raises(PuzzleAPIError):
            client.list_puzzles()


class TestVerdictDecision:
    """Requirement 11: an address/balance alone is never an exact match."""

    def analyzer(self, configured=True):
        settings = make_settings(api_key="k" if configured else None)
        return PuzzleAnalyzer(MemePolClient(settings))

    def test_unconfigured_yields_error_not_match(self):
        result = self.analyzer(configured=False).analyze(make_report())
        assert result.verdict is Verdict.ERROR
        assert result.status == "✗"
        assert result.matches == []
        assert "configured" in result.detail

    def test_api_error_yields_error_state(self):
        settings = make_settings(api_key="k")
        client = MemePolClient(settings, http=FakeHttp(error=PuzzleAPIError("boom")))
        result = PuzzleAnalyzer(client).analyze(make_report())
        assert result.verdict is Verdict.ERROR
        assert result.status == "✗"

    def test_exact_match_requires_address_and_threshold(self):
        entry = PuzzleEntry(id="p1", title="Exact", criteria={
            "address": SAMPLE_EVM, "chain": "ethereum", "min_balance": 0.5,
        }, hints=["h1"], images=["img1"])
        result = self.analyzer().analyze(make_report(balance=1.0), [entry])
        assert result.verdict is Verdict.EXACT
        assert result.status == "✓"
        assert result.hints == ["h1"]
        assert result.images == ["img1"]

    def test_address_match_but_balance_below_threshold_is_possible(self):
        entry = PuzzleEntry(id="p2", criteria={
            "address": SAMPLE_EVM, "min_balance": 100.0,
        })
        result = self.analyzer().analyze(make_report(balance=1.0), [entry])
        assert result.verdict is Verdict.POSSIBLE
        assert result.status == "⏳"

    def test_threshold_met_without_address_is_no_match(self):
        """A puzzle's min_balance describes the ESCROW, not the visitor.

        Matching a stranger's balance against it would flag every funded
        wallet as a possible match, so address confirmation is required.
        """
        entry = PuzzleEntry(id="p3", criteria={"min_balance": 0.5})
        result = self.analyzer().analyze(make_report(balance=1.0), [entry])
        assert result.verdict is Verdict.NONE
        assert result.hints == []

    def test_no_criteria_is_no_match(self):
        entry = PuzzleEntry(id="p4", criteria={})
        result = self.analyzer().analyze(make_report(), [entry])
        assert result.verdict is Verdict.NONE
        assert result.status == "✗"

    def test_address_mismatch_and_balance_unmet_is_no_match(self):
        entry = PuzzleEntry(id="p5", criteria={
            "address": "0x0000000000000000000000000000000000000001",
            "min_balance": 500.0,
        })
        result = self.analyzer().analyze(make_report(balance=1.0), [entry])
        assert result.verdict is Verdict.NONE

    def test_chain_mismatch_is_not_exact(self):
        entry = PuzzleEntry(id="p6", criteria={
            "address": SAMPLE_EVM, "chain": "bitcoin", "min_balance": 0.1,
        })
        result = self.analyzer().analyze(make_report(chain="ethereum"), [entry])
        assert result.verdict is not Verdict.EXACT

    def test_chain_mismatch_is_not_even_possible(self):
        """Chain is a filter: a differing chain excludes the record entirely."""
        entry = PuzzleEntry(id="p6b", criteria={"chain": "bitcoin"})
        result = self.analyzer().analyze(make_report(chain="ethereum"), [entry])
        assert result.verdict is Verdict.NONE
        assert result.matches[0].score == 0.0

    def test_shared_chain_alone_is_never_a_match(self):
        """REGRESSION: 31 BTC puzzles share a chain with any BTC address.

        Merely sharing a chain must not produce a possible_match.
        """
        entry = PuzzleEntry(id="p6c", title="Some BTC puzzle",
                            criteria={"chain": "bitcoin"})
        report = make_report(chain="bitcoin", address="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
                             balance=0.0, symbol="BTC")
        result = self.analyzer().analyze(report, [entry])
        assert result.verdict is Verdict.NONE
        assert result.hints == []
        assert result.images == []

    def test_unrelated_bitcoin_address_scores_no_matches(self):
        """A real-world control: an address that matches no escrow."""
        entries = [
            PuzzleEntry(id="a", criteria={"chain": "bitcoin",
                                          "address": "14zMkTgaVXJcxdh4JdWi29MLRR44iUSG9W"}),
            PuzzleEntry(id="b", criteria={"chain": "bitcoin",
                                          "address": "1JxWyNrkgYvgsHu8hVQZqTXEB9RftRGP5m"}),
        ]
        report = make_report(chain="bitcoin",
                             address="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
                             balance=0.0, symbol="BTC")
        result = self.analyzer().analyze(report, entries)
        assert result.verdict is Verdict.NONE
        assert result.matches == [] or all(m.verdict is Verdict.NONE
                                           for m in result.matches)

    def test_eth_wallet_matches_no_bitcoin_puzzle(self):
        """REGRESSION: a funded ETH wallet must not 'match' BTC puzzles."""
        entries = [PuzzleEntry(id=f"btc{i}", criteria={"chain": "bitcoin",
                                                       "address": f"1addr{i}"})
                   for i in range(5)]
        report = make_report(chain="ethereum", balance=5.0, symbol="ETH")
        result = self.analyzer().analyze(report, entries)
        assert result.verdict is Verdict.NONE

    def test_address_match_alone_is_exact_when_no_threshold(self):
        """Address confirmation with no value criteria is still exact."""
        entry = PuzzleEntry(id="p8", criteria={"address": SAMPLE_EVM})
        result = self.analyzer().analyze(make_report(), [entry])
        assert result.verdict is Verdict.EXACT

    def test_zero_balance_wallet_matches_nothing(self):
        entry = PuzzleEntry(id="p7", criteria={"min_balance": 0.0001})
        result = self.analyzer().analyze(make_report(balance=0.0), [entry])
        assert result.verdict is Verdict.NONE

    def test_overall_verdict_is_best_of_all(self):
        entries = [
            PuzzleEntry(id="n1", criteria={"min_balance": 9999}),
            PuzzleEntry(id="n2", criteria={"address": SAMPLE_EVM,
                                           "min_balance": 0.1}),
        ]
        result = self.analyzer().analyze(make_report(balance=1.0), entries)
        assert result.verdict is Verdict.EXACT
        assert result.evaluated == 2

    def test_matches_sorted_by_score(self):
        entries = [
            PuzzleEntry(id="low", criteria={"min_balance": 1000}),
            PuzzleEntry(id="high", criteria={"address": SAMPLE_EVM,
                                             "min_balance": 0.1}),
        ]
        result = self.analyzer().analyze(make_report(balance=1.0), entries)
        assert result.matches[0].puzzle_id == "high"
