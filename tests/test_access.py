"""Access-tier tests.

The critical property is NON-DISCLOSURE: a lower tier must not receive, or be
able to infer, the contents of the private corpus. Several tests below assert on
the ABSENCE of data rather than its presence.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.access import (  # noqa: E402
    TIER_LIMITS,
    EntitlementStore,
    Tier,
    apply_limits,
    resolve_tier,
    tier_summary,
)

OWNER = "0xOwner0000000000000000000000000000000001"
BUYER = "0xBuyer0000000000000000000000000000000002"
STRANGER = "0xStranger00000000000000000000000000000003"


def make_analysis(n_matches=5, hints_each=3, with_private=True):
    """Build an analysis payload shaped like the real analyzer output.

    The analyzer emits a record for EVERY evaluated entry (verdict NONE for
    non-matches), so include some of those to exercise the filtering.
    """
    real = [
        {
            "puzzle_id": f"p{i}",
            "title": f"Secret Puzzle {i}",
            "chain": "bitcoin",
            "verdict": "exact_match",
            "score": 1.0,
            "hints": [f"hint {i}-{j}" for j in range(hints_each)],
        }
        for i in range(n_matches)
    ]
    non_matches = [
        {
            "puzzle_id": f"n{i}",
            "title": f"Unrelated Puzzle {i}",
            "chain": "bitcoin",
            "verdict": "no_match",
            "score": 0.0,
            "hints": [],
        }
        for i in range(3)
    ]
    analysis = {
        "verdict": "exact_match",
        "status": "✓",
        "matches": real + non_matches,
        "hints": [f"hint {i}" for i in range(n_matches)],
        "images": ["https://example.test/img1.png"],
        "notes": ["status=open"],
        "evaluated": len(real) + len(non_matches),
    }
    if with_private:
        analysis["private_count"] = 12
    return analysis


class TestTierResolution:
    def test_no_session_is_anonymous(self):
        assert resolve_tier(verified_address=None, owner_addresses=[]) \
            is Tier.ANONYMOUS

    def test_verified_wallet_is_free_tier(self):
        assert resolve_tier(verified_address=STRANGER, owner_addresses=[]) \
            is Tier.VERIFIED

    def test_owner_list_wins(self):
        assert resolve_tier(verified_address=OWNER, owner_addresses=[OWNER]) \
            is Tier.OWNER

    def test_owner_match_is_case_insensitive(self):
        assert resolve_tier(verified_address=OWNER.upper(),
                            owner_addresses=[OWNER.lower()]) is Tier.OWNER

    def test_granted_address_is_paid(self, tmp_path):
        store = EntitlementStore(tmp_path / "e.json")
        store.grant(BUYER, tier="paid")
        assert resolve_tier(verified_address=BUYER, owner_addresses=[],
                            store=store) is Tier.PAID

    def test_ungranted_address_stays_verified(self, tmp_path):
        store = EntitlementStore(tmp_path / "e.json")
        store.grant(BUYER, tier="paid")
        assert resolve_tier(verified_address=STRANGER, owner_addresses=[],
                            store=store) is Tier.VERIFIED

    def test_expired_grant_falls_back_to_verified(self, tmp_path):
        store = EntitlementStore(tmp_path / "e.json")
        rec = store.grant(BUYER, tier="paid", days=1)
        rec.expires_at = time.time() - 10
        store._save({BUYER.lower(): rec})
        assert resolve_tier(verified_address=BUYER, owner_addresses=[],
                            store=store) is Tier.VERIFIED

    def test_granted_owner_tier_is_owner(self, tmp_path):
        store = EntitlementStore(tmp_path / "e.json")
        store.grant(STRANGER, tier="owner")
        assert resolve_tier(verified_address=STRANGER, owner_addresses=[],
                            store=store) is Tier.OWNER


class TestEntitlementStore:
    def test_grant_persists(self, tmp_path):
        path = tmp_path / "e.json"
        EntitlementStore(path).grant(BUYER, tier="paid", note="paid via paypal")
        reopened = EntitlementStore(path).get(BUYER)
        assert reopened is not None and reopened.tier == "paid"
        assert reopened.note == "paid via paypal"

    def test_store_file_is_0600(self, tmp_path):
        path = tmp_path / "e.json"
        EntitlementStore(path).grant(BUYER)
        assert oct(path.stat().st_mode)[-3:] == "600"

    def test_revoke(self, tmp_path):
        store = EntitlementStore(tmp_path / "e.json")
        store.grant(BUYER)
        assert store.revoke(BUYER) is True
        assert store.get(BUYER) is None
        assert store.revoke(BUYER) is False

    def test_rejects_unknown_tier(self, tmp_path):
        with pytest.raises(Exception):
            EntitlementStore(tmp_path / "e.json").grant(BUYER, tier="superuser")

    def test_rejects_empty_address(self, tmp_path):
        with pytest.raises(Exception):
            EntitlementStore(tmp_path / "e.json").grant("")

    def test_corrupt_store_does_not_crash(self, tmp_path):
        path = tmp_path / "e.json"
        path.write_text("{not json")
        assert EntitlementStore(path).get(BUYER) is None


class TestAnonymousSeesNothing:
    def test_no_puzzles_at_all(self):
        out = apply_limits(make_analysis(), Tier.ANONYMOUS)
        assert out["matches"] == []
        assert out["hints"] == []
        assert out["images"] == []
        assert out["notes"] == []

    def test_private_count_removed(self):
        out = apply_limits(make_analysis(), Tier.ANONYMOUS)
        assert "private_count" not in out

    def test_does_not_leak_puzzle_titles(self):
        out = apply_limits(make_analysis(), Tier.ANONYMOUS)
        assert "Secret Puzzle" not in json.dumps(out)

    def test_does_not_leak_hint_text(self):
        out = apply_limits(make_analysis(), Tier.ANONYMOUS)
        assert "hint 0-0" not in json.dumps(out)

    def test_reports_that_content_is_locked(self):
        out = apply_limits(make_analysis(), Tier.ANONYMOUS)
        assert out["redacted"] is True
        assert out["locked"]


class TestVerifiedFreeTier:
    def test_sees_a_limited_preview(self):
        out = apply_limits(make_analysis(n_matches=5), Tier.VERIFIED)
        assert len(out["matches"]) == TIER_LIMITS[Tier.VERIFIED].puzzles_visible

    def test_hints_truncated_per_match(self):
        out = apply_limits(make_analysis(hints_each=3), Tier.VERIFIED)
        for m in out["matches"]:
            assert len(m["hints"]) == 1
            assert m.get("hints_truncated") is True

    def test_images_withheld(self):
        out = apply_limits(make_analysis(), Tier.VERIFIED)
        assert out["images"] == []

    def test_private_corpus_not_visible(self):
        out = apply_limits(make_analysis(), Tier.VERIFIED)
        assert "private_count" not in out

    def test_reports_hidden_count(self):
        out = apply_limits(make_analysis(n_matches=5), Tier.VERIFIED)
        assert out["locked"]["hidden_matches"] == 5 - 3

    def test_cannot_see_the_rest(self):
        """The 4th puzzle onward must not appear anywhere in the payload."""
        out = apply_limits(make_analysis(n_matches=5), Tier.VERIFIED)
        blob = json.dumps(out)
        assert "Secret Puzzle 3" not in blob
        assert "Secret Puzzle 4" not in blob


class TestPaidTier:
    def test_sees_everything_public(self):
        out = apply_limits(make_analysis(n_matches=5), Tier.PAID)
        assert len(out["matches"]) == 5
        assert out["images"]

    def test_full_hints(self):
        out = apply_limits(make_analysis(hints_each=3), Tier.PAID)
        assert all(len(m["hints"]) == 3 for m in out["matches"])

    def test_still_cannot_see_private_corpus(self):
        """Paying does not grant the owner's private corpus."""
        out = apply_limits(make_analysis(), Tier.PAID)
        assert "private_count" not in out
        assert TIER_LIMITS[Tier.PAID].include_private is False


class TestOwnerTier:
    def test_sees_private_count(self):
        out = apply_limits(make_analysis(), Tier.OWNER)
        assert out["private_count"] == 12

    def test_sees_all_public(self):
        out = apply_limits(make_analysis(n_matches=5), Tier.OWNER)
        assert len(out["matches"]) == 5


class TestApplyLimitsIsPure:
    def test_input_not_mutated(self):
        src = make_analysis(n_matches=5)
        snapshot = json.dumps(src, sort_keys=True)
        apply_limits(src, Tier.ANONYMOUS)
        assert json.dumps(src, sort_keys=True) == snapshot

    def test_returns_new_object(self):
        src = make_analysis()
        assert apply_limits(src, Tier.PAID) is not src

    def test_handles_missing_keys(self):
        assert apply_limits({}, Tier.VERIFIED)["matches"] == []

    def test_handles_empty_matches(self):
        out = apply_limits({"matches": [], "hints": []}, Tier.VERIFIED)
        assert out["matches"] == []
        assert out["locked"] == {}


class TestNoMatchRecordsAreDropped:
    """The analyzer emits a record per evaluated entry; only real matches ship."""

    def test_non_matches_removed_for_every_tier(self):
        for tier in Tier:
            out = apply_limits(make_analysis(n_matches=5), tier)
            ids = [m["puzzle_id"] for m in out["matches"]]
            assert not any(i.startswith("n") for i in ids), tier

    def test_unrelated_titles_never_leak(self):
        """A free user must not be able to enumerate the corpus."""
        for tier in (Tier.ANONYMOUS, Tier.VERIFIED, Tier.PAID):
            blob = json.dumps(apply_limits(make_analysis(), tier))
            assert "Unrelated Puzzle" not in blob, tier

    def test_evaluated_count_is_preserved(self):
        out = apply_limits(make_analysis(n_matches=5), Tier.PAID)
        assert out["evaluated"] == 8          # 5 real + 3 non-matching

    def test_locked_count_reflects_real_matches_only(self):
        out = apply_limits(make_analysis(n_matches=5), Tier.VERIFIED)
        assert out["locked"]["hidden_matches"] == 5 - 3


class TestLiveReload:
    """A grant made by another process must be visible without a restart.

    This is the bug where ``app.cli grant`` wrote the file but a long-running
    server kept serving its stale in-memory cache, so a freshly granted owner
    was still refused.
    """

    def test_grant_by_another_process_is_picked_up(self, tmp_path):
        path = tmp_path / "e.json"
        server_view = EntitlementStore(path)      # simulates the long-running server
        assert server_view.get(BUYER) is None

        # a separate process grants access
        other = EntitlementStore(path)
        other.grant(BUYER, tier="paid")

        assert server_view.get(BUYER) is not None

    def test_revoke_by_another_process_is_picked_up(self, tmp_path):
        path = tmp_path / "e.json"
        server_view = EntitlementStore(path)
        server_view.grant(BUYER, tier="paid")
        assert server_view.get(BUYER) is not None

        EntitlementStore(path).revoke(BUYER)
        assert server_view.get(BUYER) is None

    def test_owner_grant_by_another_process_resolves_to_owner(self, tmp_path):
        path = tmp_path / "e.json"
        server_view = EntitlementStore(path)
        EntitlementStore(path).grant(BUYER, tier="owner")
        assert resolve_tier(verified_address=BUYER, owner_addresses=[],
                            store=server_view) is Tier.OWNER

    def test_unchanged_file_still_serves_from_cache(self, tmp_path):
        path = tmp_path / "e.json"
        s = EntitlementStore(path)
        s.grant(BUYER, tier="paid")
        first = s.get(BUYER)
        assert s.get(BUYER).granted_at == first.granted_at


class TestTierSummary:
    def test_summary_exposes_no_secrets(self):
        for t in Tier:
            blob = json.dumps(tier_summary(t))
            assert "Secret" not in blob

    def test_owner_is_only_private_tier(self):
        assert tier_summary(Tier.OWNER)["private_corpus"] is True
        for t in (Tier.ANONYMOUS, Tier.VERIFIED, Tier.PAID):
            assert tier_summary(t)["private_corpus"] is False

    def test_anonymous_sees_no_puzzles(self):
        assert tier_summary(Tier.ANONYMOUS)["puzzles_visible"] == 0
