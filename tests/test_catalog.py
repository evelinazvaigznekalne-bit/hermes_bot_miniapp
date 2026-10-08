"""Catalog API tests.

The properties that matter are non-disclosure and non-enumeration:

  * a lower tier must not receive hidden items, nor be able to reconstruct
    them by paging or filtering;
  * the private corpus must be invisible to every non-owner tier — including
    its count;
  * hint/image caps must be enforced per item, not just in aggregate.

Several tests below assert on the ABSENCE of data, which is deliberate.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.access import Tier  # noqa: E402
from app.catalog import Catalog  # noqa: E402


class FakeEntry:
    """Minimal stand-in for a PuzzleEntry."""

    def __init__(self, pid, *, chain="bitcoin", status="open", hints=0,
                 images=0, addresses=1, title=None):
        self.id = pid
        self.title = title or f"Puzzle {pid}"
        self.chain = chain
        self.criteria = {"chain": chain, "addresses": ["addr"] * addresses}
        self.hints = [f"hint {pid}-{i}" for i in range(hints)]
        self.images = [f"https://img.test/{pid}-{i}.png" for i in range(images)]
        self.raw = {"status": status, "addresses": ["addr"] * addresses}
        self.note = None


def make_catalog(n=49, private=12):
    public = []
    for i in range(n):
        chain = ["bitcoin", "ethereum", "arweave", "base", "litecoin",
                 "solana"][i % 6]
        status = ["open", "open", "solved", "dead-end"][i % 4]
        public.append(FakeEntry(f"pub-{i:02d}", chain=chain, status=status,
                                hints=(i % 7), images=(i % 3)))
    priv = [FakeEntry(f"priv-{i:02d}", hints=9, images=2)
            for i in range(private)]
    return Catalog(public_entries=public, private_entries=priv)


# --- tier resolution --------------------------------------------------------

class TestTierVisibility:
    def test_anonymous_sees_no_items(self):
        r = make_catalog().items(Tier.ANONYMOUS)
        assert r["count"] == 0
        assert r["items"] == []
        assert "catalog" in r["locked"]

    def test_verified_sees_only_the_free_preview(self):
        r = make_catalog().items(Tier.VERIFIED)
        assert r["count"] == 3
        assert r["visible_total"] == 3
        assert r["matched_total"] == 49
        assert r["locked"]["hidden_items"] == 46

    def test_paid_sees_everything(self):
        r = make_catalog().items(Tier.PAID, limit=100)
        assert r["count"] == 49
        assert r["locked"] == {}

    def test_owner_sees_public_plus_private(self):
        c = make_catalog()
        r = c.items(Tier.OWNER, limit=100)
        assert r["count"] == 61


# --- the important ones: can a free user get more than 3? -------------------

class TestNoEnumeration:
    def test_paging_cannot_harvest_more_than_the_cap(self):
        """The cap is applied BEFORE paging, so offsets cannot walk the corpus."""
        c = make_catalog()
        seen = set()
        for offset in range(0, 200, 3):
            r = c.items(Tier.VERIFIED, limit=3, offset=offset)
            for item in r["items"]:
                seen.add(item["sku"])
        assert len(seen) == 3, f"free user harvested {len(seen)} items"

    def test_filtering_cannot_reveal_hidden_items(self):
        """Filtering to a category must not bypass the global cap."""
        c = make_catalog()
        for cat in ("bitcoin", "ethereum", "arweave", "base", "litecoin",
                    "solana"):
            r = c.items(Tier.VERIFIED, category=cat, limit=100)
            assert len(r["items"]) <= 3, cat

    def test_tab_filter_cannot_reveal_hidden_items(self):
        c = make_catalog()
        for tab in ("open", "solved", "dead-end", "all"):
            r = c.items(Tier.VERIFIED, tab=tab, limit=100)
            assert len(r["items"]) <= 3, tab

    def test_combined_filters_cannot_reveal_hidden_items(self):
        c = make_catalog()
        r = c.items(Tier.VERIFIED, category="bitcoin", tab="open", limit=100)
        assert len(r["items"]) <= 3

    def test_large_limit_does_not_overflow_the_cap(self):
        c = make_catalog()
        r = c.items(Tier.VERIFIED, limit=10000)
        assert len(r["items"]) == 3

    def test_negative_offset_is_clamped(self):
        c = make_catalog()
        r = c.items(Tier.PAID, offset=-50, limit=10)
        assert r["offset"] == 0
        assert len(r["items"]) == 10


# --- private corpus isolation ----------------------------------------------

class TestPrivateCorpusIsolation:
    def test_non_owners_never_see_the_private_count(self):
        c = make_catalog()
        for tier in (Tier.ANONYMOUS, Tier.VERIFIED, Tier.PAID):
            summary = c.summary(tier)
            assert summary["private_corpus"] is None, tier

    def test_owner_sees_the_private_count(self):
        assert make_catalog().summary(Tier.OWNER)["private_corpus"] == 12

    def test_private_skus_never_appear_for_non_owners(self):
        c = make_catalog()
        for tier in (Tier.ANONYMOUS, Tier.VERIFIED, Tier.PAID):
            blob = json.dumps(c.items(tier, limit=1000))
            assert "priv-" not in blob, tier

    def test_private_skus_absent_from_facets_too(self):
        c = make_catalog()
        for tier in (Tier.ANONYMOUS, Tier.VERIFIED, Tier.PAID):
            blob = (json.dumps(c.categories(tier)) + json.dumps(c.tabs(tier)))
            assert "priv-" not in blob, tier

    def test_item_detail_refuses_private_sku_for_non_owner(self):
        c = make_catalog()
        for tier in (Tier.ANONYMOUS, Tier.VERIFIED, Tier.PAID):
            assert c.item_detail(tier, "priv-00") is None, tier

    def test_item_detail_serves_private_sku_to_owner(self):
        assert make_catalog().item_detail(Tier.OWNER, "priv-00") is not None


# --- hint / image caps ------------------------------------------------------

class TestDetailCaps:
    def test_anonymous_detail_is_empty(self):
        d = make_catalog().item_detail(Tier.ANONYMOUS, "pub-05")
        assert d["hints"] == []
        assert d["images"] == []
        assert "detail" in d["locked"]

    def test_verified_detail_is_capped_to_one_hint(self):
        d = make_catalog().item_detail(Tier.VERIFIED, "pub-05")
        assert len(d["hints"]) == 1
        # pub-05 carries 5 hints (index 5 % 7); 1 shown leaves 4 hidden.
        assert d["locked"]["hidden_hints"] == 4
        assert d["images"] == []

    def test_paid_detail_is_uncapped(self):
        d = make_catalog().item_detail(Tier.PAID, "pub-05")
        assert len(d["hints"]) == 5
        assert d["locked"] == {}

    def test_detail_does_not_mutate_the_source_entry(self):
        c = make_catalog()
        before = len(c.public_entries[5].hints)
        c.item_detail(Tier.VERIFIED, "pub-05")
        assert len(c.public_entries[5].hints) == before

    def test_unknown_sku_returns_none(self):
        assert make_catalog().item_detail(Tier.PAID, "nope") is None

    def test_empty_sku_returns_none(self):
        assert make_catalog().item_detail(Tier.PAID, "") is None


# --- facets -----------------------------------------------------------------

class TestFacets:
    def test_anonymous_counts_are_hidden(self):
        c = make_catalog()
        for cat in c.categories(Tier.ANONYMOUS)["categories"]:
            assert cat["count"] is None
        for tab in c.tabs(Tier.ANONYMOUS)["tabs"]:
            assert tab["count"] is None

    def test_paid_counts_are_exact(self):
        c = make_catalog()
        total = sum(cat["count"] for cat in c.categories(Tier.PAID)["categories"])
        assert total == 49

    def test_tab_counts_sum_to_corpus_size(self):
        c = make_catalog()
        tabs = c.tabs(Tier.PAID)["tabs"]
        non_all = sum(t["count"] for t in tabs if t["id"] != "all")
        assert non_all == 49


# --- config -----------------------------------------------------------------

class TestConfig:
    def test_config_shape_matches_a_marketplace(self):
        cfg = make_catalog().config()
        assert "config" in cfg and "seo" in cfg
        assert cfg["config"]["catalogEnabled"] is True

    def test_purchases_disabled_without_paypal(self):
        class S:
            paypal_configured = False
        assert make_catalog().config(settings=S())["config"]["purchasesEnabled"] is False

    def test_purchases_enabled_with_paypal(self):
        class S:
            paypal_configured = True
        assert make_catalog().config(settings=S())["config"]["purchasesEnabled"] is True


# --- robustness -------------------------------------------------------------

class TestRobustness:
    def test_empty_corpus_does_not_crash(self):
        c = Catalog()
        for tier in Tier:
            c.items(tier)
            c.categories(tier)
            c.tabs(tier)
            c.summary(tier)

    def test_entry_without_criteria_is_tolerated(self):
        class Bare:
            id = "bare"
            title = "Bare"
            hints = []
            images = []
            raw = {}
            criteria = {}
        c = Catalog(public_entries=[Bare()])
        r = c.items(Tier.PAID)
        assert r["count"] == 1
        assert r["items"][0]["category"] == "unknown"

    def test_status_is_normalised(self):
        class Weird:
            id = "w"
            title = "W"
            hints = []
            images = []
            criteria = {"chain": "bitcoin"}
            raw = {"status": "SOMETHING-ELSE"}
        c = Catalog(public_entries=[Weird()])
        assert c.items(Tier.PAID)["items"][0]["status"] == "open"
