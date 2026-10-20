"""Strategy-driven attack engine tests.

Every test runs against a LOCAL oracle (coincurve) -- no network, no external service.
The point of this suite is the reporting discipline: a negative is only a negative when
the harness was proven on a known-good input.
"""

from __future__ import annotations

import hashlib
import hmac

import pytest

from app.puzzles.attack import (
    SECP256K1_N,
    Outcome,
    analyze_curve,
    assess_nonce_leak,
    brute_force_range,
    channel_capacity_bits,
    guess_candidates,
    plan_attack,
    run_attack,
    run_witness,
    search_candidates,
    size_and_rate,
)

# ---------------------------------------------------------------------------
# Local oracle
# ---------------------------------------------------------------------------

try:
    import coincurve
except ImportError:      # pragma: no cover - environment guard
    coincurve = None

pytestmark = pytest.mark.skipif(coincurve is None, reason="coincurve unavailable")


def _priv_to_p2pkh(key: int) -> str:
    """Derive the compressed P2PKH address a scalar controls (local, no network)."""
    import base58
    pk = coincurve.PrivateKey(key.to_bytes(32, "big"))
    comp = pk.public_key.format(compressed=True)
    h160 = hashlib.new("ripemd160", hashlib.sha256(comp).digest()).digest()
    return base58.b58encode_check(b"\x00" + h160).decode()


def oracle(key: int):
    if not (0 < key < SECP256K1_N):
        return None
    return _priv_to_p2pkh(key)


def phrase_oracle(phrase: str) -> str:
    """BIP39 phrase -> first legacy address, through the same local path."""
    from mnemonic import Mnemonic
    seed = Mnemonic.to_seed(phrase, "")
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    return oracle(int.from_bytes(I[:32], "big"))


# ---------------------------------------------------------------------------
# N / D / t arithmetic
# ---------------------------------------------------------------------------

class TestSizeAndRate:
    def test_small_space_is_feasible(self):
        r = size_and_rate(1000, 500, budget_seconds=10)
        assert r["feasible"] is True
        assert r["t_seconds"] == pytest.approx(2.0)

    def test_large_space_is_infeasible(self):
        r = size_and_rate(1 << 128, 1e9, budget_seconds=3600)
        assert r["feasible"] is False
        assert r["orders_over_budget"] > 20

    def test_zero_rate_cannot_size_the_search(self):
        r = size_and_rate(1000, 0, budget_seconds=10)
        assert r["feasible"] is None
        assert "measure D" in r["note"]

    def test_negative_space_is_rejected(self):
        assert size_and_rate(-5, 10)["feasible"] is None

    def test_non_integer_space_is_rejected(self):
        assert size_and_rate("many", 10)["feasible"] is None

    def test_human_readable_time_is_scaled(self):
        assert "s" in size_and_rate(100, 100)["t_human"]
        assert "years" in size_and_rate(1 << 60, 1)["t_human"]


# ---------------------------------------------------------------------------
# The witness
# ---------------------------------------------------------------------------

class TestWitness:
    def test_witness_passes_on_a_working_oracle(self):
        w = run_witness(oracle, 1, oracle(1))
        assert w["witnessed"] is True
        assert w["reason"] is None

    def test_witness_fails_on_a_broken_oracle(self):
        broken = lambda k: "1NotARealAddressAtAll000000000000000000000"
        w = run_witness(broken, 1, oracle(1))
        assert w["witnessed"] is False
        assert "harness failed its own witness" in w["reason"]

    def test_witness_without_oracle_is_not_witnessed(self):
        assert run_witness(None, 1, oracle(1))["witnessed"] is False

    def test_witness_without_address_is_not_witnessed(self):
        assert run_witness(oracle, 1, None)["witnessed"] is False


# ---------------------------------------------------------------------------
# Brute force
# ---------------------------------------------------------------------------

class TestBruteForce:
    def test_finds_a_planted_key(self):
        target = oracle(0xBEEF)
        out = brute_force_range(oracle, target, 1, 0xBEEF + 1, budget_seconds=120,
                                witness_key=1, witness_address=oracle(1))
        assert out.outcome is Outcome.MATCH
        assert out.match_key == hex(0xBEEF)
        assert out.witness["witnessed"] is True

    def test_miss_with_passing_witness_is_uncertified(self):
        target = oracle(2 ** 200)          # far outside the swept range
        out = brute_force_range(oracle, target, 1, 5000, budget_seconds=60,
                                witness_key=1, witness_address=oracle(1))
        assert out.outcome is Outcome.UNCERTIFIED
        assert out.witness["witnessed"] is True
        assert out.tried > 0

    def test_miss_with_failing_witness_is_not_a_result(self):
        broken = lambda k: "1NotARealAddressAtAll000000000000000000000"
        target = oracle(2 ** 200)
        out = brute_force_range(broken, target, 1, 2000, budget_seconds=30,
                                witness_key=1, witness_address=oracle(1))
        assert out.outcome is not Outcome.UNCERTIFIED
        assert out.witness["witnessed"] is False

    def test_infeasible_space_never_enters_the_loop(self):
        target = oracle(2 ** 200)
        out = brute_force_range(oracle, target, 1, 1 << 128, budget_seconds=1.0,
                                witness_key=1, witness_address=oracle(1))
        assert out.outcome is Outcome.INFEASIBLE
        assert out.tried == 0
        assert "arithmetic" in out.notes[0]

    def test_empty_range_is_skipped(self):
        out = brute_force_range(oracle, "x", 100, 100, budget_seconds=1.0)
        assert out.outcome is Outcome.SKIPPED

    def test_result_is_serialisable(self):
        target = oracle(7)
        out = brute_force_range(oracle, target, 1, 8, budget_seconds=60,
                                witness_key=1, witness_address=oracle(1))
        d = out.as_dict()
        assert d["outcome"] == "match"
        assert d["status"] == "✓"
        assert "t_human" in d


# ---------------------------------------------------------------------------
# Guessing
# ---------------------------------------------------------------------------

class TestGuessing:
    def test_candidates_include_the_full_theme(self):
        """A themed passphrase is the most likely human choice and a 2-word joiner
        never produces it."""
        cands = guess_candidates(["tarot", "soulles", "hermes"])
        assert "tarot soulles hermes" in cands

    def test_candidates_are_deduplicated(self):
        cands = guess_candidates(["alpha", "alpha", "beta"])
        assert len(cands) == len(set(cands))

    def test_empty_input_yields_no_candidates(self):
        assert guess_candidates([]) == []

    def test_search_finds_a_planted_phrase(self):
        planted = "tarot soulles hermes"
        cands = guess_candidates(["tarot", "soulles", "hermes"])
        out = search_candidates(phrase_oracle, phrase_oracle(planted), cands,
                                budget_seconds=60,
                                witness_phrase=planted,
                                witness_address=phrase_oracle(planted))
        assert out.outcome is Outcome.MATCH
        assert out.match_key == planted

    def test_search_miss_without_witness_is_not_a_result(self):
        cands = guess_candidates(["alpha", "beta"])
        out = search_candidates(phrase_oracle, phrase_oracle("zzz-unrelated"),
                                cands, budget_seconds=60)
        assert out.outcome is not Outcome.UNCERTIFIED

    def test_no_candidates_is_skipped(self):
        out = search_candidates(phrase_oracle, "x", [], budget_seconds=1)
        assert out.outcome is Outcome.SKIPPED


# ---------------------------------------------------------------------------
# Mathematics
# ---------------------------------------------------------------------------

class TestMath:
    def test_secp256k1_order_is_prime(self):
        facts = analyze_curve(SECP256K1_N)
        assert facts["prime"] is True
        assert facts["order_bits"] == 256

    def test_pohlig_hellman_is_ruled_out_on_secp256k1(self):
        """The order is prime, so there is no subgroup structure to reduce to."""
        facts = analyze_curve(SECP256K1_N)
        assert "inapplicable" in facts["pohlig_hellman"]

    def test_smooth_order_is_flagged_applicable(self):
        smooth = 2 * 3 * 5 * 7 * 11 * 13 * 17 * 19 * 23 * 29 * 31 * 37 * 41 * 43 * 47
        facts = analyze_curve(smooth)
        assert facts["smooth"] is True
        assert "APPLICABLE" in facts["pohlig_hellman"]

    def test_nonce_leak_needs_enough_total_bits(self):
        assert assess_nonce_leak(8, 6)["applicable"] is False     # 48 < 256
        assert assess_nonce_leak(8, 40)["applicable"] is True     # 320 >= 256
        assert assess_nonce_leak(128, 2)["applicable"] is True

    def test_nonce_leak_rejects_nonsense(self):
        assert assess_nonce_leak(0, 5)["applicable"] is False
        assert assess_nonce_leak(8, 0)["applicable"] is False

    def test_capacity_check(self):
        assert channel_capacity_bits(59, 1)["holds_256bit_key"] is False
        assert channel_capacity_bits(256, 1)["holds_256bit_key"] is True


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

class TestDispatch:
    def test_plan_for_a_brute_force_puzzle(self):
        plan = plan_attack({"slug": "x", "puzzle_type": ["raw-private-key"]})
        assert plan.family == "brute_force"
        assert plan.compute == "cpu"
        assert plan.first_move

    def test_plan_for_a_math_puzzle(self):
        plan = plan_attack({"slug": "x", "puzzle_type": ["hash-collision"]})
        assert plan.family == "math"

    def test_run_attack_needs_input_without_an_oracle(self):
        out = run_attack({"slug": "x", "puzzle_type": ["raw-private-key"]})
        assert out.outcome is Outcome.NEEDS_INPUT

    def test_run_attack_math_reports_structural_facts(self):
        out = run_attack({"slug": "x", "puzzle_type": ["hash-collision"]})
        assert out.family == "math"
        assert any("prime" in r for r in out.reasons)

    def test_run_attack_steganography_capacity(self):
        out = run_attack({"slug": "x", "puzzle_type": ["image-stego"]},
                         extra={"symbols": 59, "bits_per_symbol": 1})
        assert out.outcome is Outcome.INFEASIBLE

    def test_text_classification_needs_no_catalog_entry(self):
        out = run_attack({"slug": "free text",
                          "description": "find the private key in this image"})
        assert out.family in ("steganography", "guessing", "external")


# ---------------------------------------------------------------------------
# Determinism / no-network guard
# ---------------------------------------------------------------------------

class TestPurity:
    def test_oracle_is_local_and_deterministic(self):
        """The engine must be reproducible: same key, same address, no network."""
        assert oracle(1) == oracle(1)
        assert oracle(1) == "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
