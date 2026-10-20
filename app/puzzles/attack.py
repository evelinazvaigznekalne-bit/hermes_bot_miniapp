"""Strategy-driven puzzle attack engine.

A puzzle classification (see :mod:`app.puzzle_types`) says *what kind of problem* a puzzle
is.  This module turns that into *work*: it picks the concrete attack the family implies,
runs it against an oracle, and reports the result in a form that cannot flatter itself.

The reporting discipline is the point.  Every run returns ``N`` (size of the space),
``D`` (measured rate) and ``t = N / D``, and it separates four outcomes that are routinely
confused:

* ``MATCH``       -- the oracle reported an exact match.
* ``INFEASIBLE``  -- arithmetic already settled it: ``t`` exceeds the budget by orders of
  magnitude.  No compute was spent.
* ``UNCERTIFIED`` -- the space was searched and nothing matched, **but the harness was not
  proven on a known-good input**, so the negative means nothing yet.
* ``NEEDS_INPUT`` -- the missing piece is information, not compute (a physical object, an
  unpublished document, a person).

A negative without a witness is not a negative.  :func:`run_witness` plants a known key and
requires the harness to find it before any negative is reported as a real negative.

Nothing here broadcasts a transaction or writes to a chain.  The engine is a reader: it
derives addresses locally and compares them.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from ..logging_setup import get_logger
from ..puzzle_types import FAMILIES, classify_puzzle

log = get_logger()

__all__ = [
    "Outcome",
    "AttackOutcome",
    "AttackPlan",
    "size_and_rate",
    "run_witness",
    "brute_force_range",
    "guess_candidates",
    "search_candidates",
    "analyze_curve",
    "assess_nonce_leak",
    "plan_attack",
    "run_attack",
    "channel_capacity_bits",
]


class Outcome(str, Enum):
    """What a run actually established."""

    MATCH = "match"
    INFEASIBLE = "infeasible"
    UNCERTIFIED = "uncertified"
    NEEDS_INPUT = "needs_input"
    SKIPPED = "skipped"

    @property
    def status(self) -> str:
        return {
            Outcome.MATCH: "✓",
            Outcome.INFEASIBLE: "✗",
            Outcome.UNCERTIFIED: "⏳",
            Outcome.NEEDS_INPUT: "⏳",
            Outcome.SKIPPED: "⏳",
        }[self]


#: An oracle derives the address a key controls.  ``int -> str | None``.
DeriveFn = Callable[[int], Optional[str]]
#: A phrase oracle derives the address a passphrase controls.
PhraseFn = Callable[[str], Optional[str]]


# ---------------------------------------------------------------------------
# Space / rate arithmetic
# ---------------------------------------------------------------------------


def size_and_rate(space_size: int, rate_per_sec: float,
                  budget_seconds: float = 3600.0) -> Dict[str, Any]:
    """Decide feasibility from N, D and t before spending any compute.

    ``t`` is the wall-clock time to exhaust the space.  The verdict is arithmetic, not an
    opinion: a space that needs 10^40 seconds is not "hard", it is not happening, and
    saying so in one line is worth more than a week of GPU time.
    """
    try:
        n = int(space_size)
    except (TypeError, ValueError):
        return {"space_size": None, "rate_per_sec": rate_per_sec,
                "t_seconds": None, "feasible": None,
                "note": "space size is not an integer; cannot size the search"}
    if n < 0:
        return {"space_size": n, "rate_per_sec": rate_per_sec, "t_seconds": None,
                "feasible": None, "note": "negative space size"}

    if rate_per_sec <= 0:
        return {"space_size": n, "rate_per_sec": rate_per_sec, "t_seconds": None,
                "feasible": None,
                "note": "rate is zero or negative; measure D before trusting t"}

    t = n / rate_per_sec
    return {
        "space_size": n,
        "rate_per_sec": round(rate_per_sec, 2),
        "t_seconds": round(t, 3),
        "t_human": _human_seconds(t),
        "budget_seconds": budget_seconds,
        "feasible": t <= budget_seconds,
        "orders_over_budget": round(_log10(t / budget_seconds), 2) if t > 0 else None,
        "note": None if t <= budget_seconds else
                f"exceeds budget by {abs(_log10(t / budget_seconds)):.1f} orders of magnitude",
    }


def _log10(x: float) -> float:
    import math
    return math.log10(x) if x > 0 else float("-inf")


def _human_seconds(t: float) -> str:
    if t < 1:
        return f"{t * 1000:.0f} ms"
    if t < 90:
        return f"{t:.1f} s"
    if t < 5400:
        return f"{t / 60:.1f} min"
    if t < 172800:
        return f"{t / 3600:.1f} h"
    if t < 31557600 * 2:
        return f"{t / 86400:.1f} days"
    if t < 31557600 * 1000:
        return f"{t / 31557600:.1f} years"
    return f"{t / 31557600:.3g} years"


# ---------------------------------------------------------------------------
# The witness
# ---------------------------------------------------------------------------


def run_witness(derive: Optional[DeriveFn], known_key: int,
                known_address: Optional[str]) -> Dict[str, Any]:
    """Prove the harness works before trusting any negative.

    Plants a key whose address is already known, pushes it through the *same* derivation
    path the search uses, and requires the match.  Without this, "searched 10^9 keys, no
    hit" is indistinguishable from "the harness is broken".
    """
    if derive is None:
        return {"witnessed": False, "reason": "no oracle supplied"}
    if known_address is None:
        return {"witnessed": False, "reason": "no witness address supplied"}
    try:
        got = derive(known_key)
    except Exception as exc:                       # pragma: no cover - defensive
        return {"witnessed": False,
                "reason": f"oracle raised {type(exc).__name__}: {exc}"}
    if got is None:
        return {"witnessed": False, "reason": "oracle returned nothing for a valid key"}
    ok = str(got).lower() == str(known_address).lower()
    return {
        "witnessed": ok,
        "reason": None if ok else
                  f"harness failed its own witness (expected {known_address}, got {got})",
    }


# ---------------------------------------------------------------------------
# Attacks
# ---------------------------------------------------------------------------


@dataclass
class AttackOutcome:
    """The result of one attack run."""

    family: str
    outcome: Outcome
    space_size: Optional[int] = None
    rate_per_sec: Optional[float] = None
    t_seconds: Optional[float] = None
    budget_seconds: Optional[float] = None
    tried: int = 0
    elapsed_seconds: float = 0.0
    match_key: Optional[str] = None
    witness: Optional[Dict[str, Any]] = None
    reasons: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "family": self.family,
            "outcome": self.outcome.value,
            "status": self.outcome.status,
            "space_size": self.space_size,
            "rate_per_sec": self.rate_per_sec,
            "t_seconds": self.t_seconds,
            "t_human": _human_seconds(self.t_seconds) if self.t_seconds else None,
            "budget_seconds": self.budget_seconds,
            "tried": self.tried,
            "elapsed_seconds": round(self.elapsed_seconds, 3),
            "match_key": self.match_key,
            "witnessed": bool(self.witness and self.witness.get("witnessed")),
            "reasons": self.reasons,
            "notes": self.notes,
        }


def brute_force_range(derive: DeriveFn, target: str, start: int, end: int, *,
                      budget_seconds: float = 5.0,
                      witness_key: Optional[int] = None,
                      witness_address: Optional[str] = None,
                      progress_every: int = 0) -> AttackOutcome:
    """Enumerate scalar keys in ``[start, end)`` and compare each derived address.

    The space is sized against the budget *before* the first derivation.  A space that
    cannot be exhausted inside the budget is reported ``INFEASIBLE`` and the loop is never
    entered -- spending five seconds to discover you needed five centuries is not a result.
    """
    size = end - start
    if size <= 0:
        return AttackOutcome(family="brute_force", outcome=Outcome.SKIPPED,
                             reasons=["empty range"], notes=["start >= end"])

    # Measure D on a short sample so the size decision uses a real rate, not a guess.
    sample_end = min(end, start + max(1, min(256, size)))
    t0 = time.perf_counter()
    sample_hits = 0
    for k in range(start, sample_end):
        if str(derive(k) or "").lower() == target.lower():
            sample_hits += 1
    sample_dt = max(time.perf_counter() - t0, 1e-9)
    rate = (sample_end - start) / sample_dt

    sized = size_and_rate(size, rate, budget_seconds)
    witness = run_witness(derive, witness_key, witness_address) \
        if witness_key is not None else {"witnessed": False,
                                         "reason": "no witness key supplied"}

    if sized["feasible"] is False:
        return AttackOutcome(
            family="brute_force", outcome=Outcome.INFEASIBLE,
            space_size=size, rate_per_sec=rate,
            t_seconds=sized.get("t_seconds"),
            budget_seconds=budget_seconds, witness=witness,
            reasons=[sized.get("note") or "space exceeds budget"],
            notes=["no keys were tried; the decision was arithmetic"],
        )

    t0 = time.perf_counter()
    tried = 0
    match_key: Optional[str] = None
    deadline = t0 + budget_seconds
    k = start
    while k < end:
        if time.perf_counter() >= deadline:
            break
        if str(derive(k) or "").lower() == target.lower():
            match_key = hex(k)
            break
        tried += 1
        if progress_every and tried % progress_every == 0:
            log.info(
                "brute force progress",
                extra={"component": "puzzles.attack", "status": "⏳",
                       "detail": f"{tried}/{size} keys"},
            )
        k += 1
    elapsed = time.perf_counter() - t0

    if match_key is not None:
        return AttackOutcome(
            family="brute_force", outcome=Outcome.MATCH, space_size=size,
            rate_per_sec=rate, t_seconds=sized.get("t_seconds"),
            budget_seconds=budget_seconds, tried=tried, elapsed_seconds=elapsed,
            match_key=match_key, witness=witness,
            reasons=[f"exact match at key {match_key}"],
        )

    reasons = [f"no match in {tried} keys over {elapsed:.2f}s"]
    notes = []
    if not witness.get("witnessed"):
        notes.append("UNCERTIFIED: witness did not pass, so this negative is not a result")
    if tried < size:
        notes.append(f"range truncated by budget ({tried}/{size} keys)")
    return AttackOutcome(
        family="brute_force",
        outcome=Outcome.UNCERTIFIED if witness.get("witnessed") else Outcome.SKIPPED,
        space_size=size, rate_per_sec=rate, t_seconds=sized.get("t_seconds"),
        budget_seconds=budget_seconds, tried=tried, elapsed_seconds=elapsed,
        witness=witness, reasons=reasons, notes=notes,
    )


# --- passphrase / dictionary ------------------------------------------------


_MUTATIONS: Sequence[Tuple[str, Callable[[str], str]]] = (
    ("identity", lambda s: s),
    ("lower", lambda s: s.lower()),
    ("upper", lambda s: s.upper()),
    ("title", lambda s: s.title()),
    ("reverse", lambda s: s[::-1]),
    ("no_space", lambda s: s.replace(" ", "")),
    ("underscore", lambda s: s.replace(" ", "_")),
    ("hyphen", lambda s: s.replace(" ", "-")),
    ("dot", lambda s: s.replace(" ", ".")),
    ("camel", lambda s: s.title().replace(" ", "")),
    ("leetspeak", lambda s: (s.replace("a", "4").replace("e", "3")
                             .replace("i", "1").replace("o", "0"))),
)

_SEPARATORS = ("", " ", "_", "-", ".", "123", "2024", "2025")


def guess_candidates(base_words: Iterable[str],
                     extra_words: Iterable[str] = (),
                     max_mutations: int = 0) -> List[str]:
    """Generate passphrase candidates from the puzzle's own theme.

    Puzzle authors reuse their own material: the title, the author's name, the domain,
    the date.  Candidates are ordered plausibility-first -- exact theme words, then
    mutations, then date-style suffixes -- so a wide shallow pass beats a deep narrow one
    when a hit is expected soon.
    """
    words: List[str] = []
    for w in list(base_words) + list(extra_words):
        cleaned = str(w).strip()
        if cleaned and cleaned.lower() not in {x.lower() for x in words}:
            words.append(cleaned)
    if not words:
        return []

    candidates: List[str] = []
    seen = set()

    def add(candidate: str) -> None:
        if candidate and candidate not in seen:
            seen.add(candidate)
            candidates.append(candidate)

    # 1. exact theme words and short joins
    for w in words:
        add(w)
    for a in words:
        for b in words:
            if a is b:
                continue
            add(f"{a}{b}")
            add(f"{a} {b}")

    # 1b. the whole theme as one phrase -- the single most likely human choice when a
    # puzzle is themed, and the one a 2-word joiner never produces.
    if len(words) >= 2:
        add(" ".join(words))
        add("".join(words))

    # 2. mutations of the strongest single-word candidate
    if max_mutations > 0:
        for w in words[:max_mutations]:
            for _name, fn in _MUTATIONS:
                add(fn(w))

    # 3. date-style suffixes, the most common human padding
    for w in words[:3]:
        for sep in _SEPARATORS:
            add(f"{w}{sep}")

    return candidates


def search_candidates(derive_phrase: PhraseFn, target: str,
                      candidates: Iterable[str], *,
                      budget_seconds: float = 5.0,
                      witness_phrase: Optional[str] = None,
                      witness_address: Optional[str] = None) -> AttackOutcome:
    """Push candidates through the phrase oracle under the same N/D/t discipline."""
    pool = list(candidates)
    if not pool:
        return AttackOutcome(family="guessing", outcome=Outcome.SKIPPED,
                             reasons=["no candidates generated"],
                             notes=["supply base words or a wordlist"])

    witness = run_witness(None, 0, "")
    if witness_phrase is not None:
        # The witness must go through the SAME oracle the search uses, so bind it to the
        # phrase oracle rather than the scalar one.
        witness = run_witness(lambda _k: derive_phrase(witness_phrase), 0,
                              witness_address)
    else:
        witness = {"witnessed": False, "reason": "no witness phrase supplied"}

    t0 = time.perf_counter()
    tried = 0
    match_phrase: Optional[str] = None
    deadline = t0 + budget_seconds
    for cand in pool:
        if time.perf_counter() >= deadline:
            break
        if str(derive_phrase(cand) or "").lower() == target.lower():
            match_phrase = cand
            break
        tried += 1
    elapsed = max(time.perf_counter() - t0, 1e-9)

    if match_phrase is not None:
        return AttackOutcome(
            family="guessing", outcome=Outcome.MATCH, space_size=len(pool),
            rate_per_sec=tried / elapsed if tried else None,
            t_seconds=(len(pool) / (tried / elapsed)) if tried else None,
            tried=tried, elapsed_seconds=elapsed, match_key=match_phrase,
            witness=witness, reasons=[f"exact match on candidate {match_phrase!r}"],
        )

    reasons = [f"no match in {tried}/{len(pool)} candidates over {elapsed:.2f}s"]
    notes = []
    if not witness.get("witnessed"):
        notes.append("UNCERTIFIED: witness did not pass, so this negative is not a result")
    if tried < len(pool):
        notes.append(f"candidate list truncated by budget ({tried}/{len(pool)})")
    return AttackOutcome(
        family="guessing",
        outcome=Outcome.UNCERTIFIED if witness.get("witnessed") else Outcome.SKIPPED,
        space_size=len(pool), rate_per_sec=(tried / elapsed) if tried else None,
        t_seconds=(len(pool) / (tried / elapsed)) if tried else None,
        tried=tried, elapsed_seconds=elapsed, witness=witness,
        reasons=reasons, notes=notes,
    )


# ---------------------------------------------------------------------------
# Mathematics
# ---------------------------------------------------------------------------

#: secp256k1 group order n.  Prime -- which is exactly why Pohlig-Hellman is worthless here.
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def _is_probable_prime(n: int, rounds: int = 12) -> bool:
    """Deterministic Miller-Rabin for the ranges this module deals with."""
    if n < 2:
        return False
    small = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    for p in small:
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    import random
    rng = random.Random(0x5EED)
    for _ in range(rounds):
        a = rng.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _smoothness_bound(n: int, limit: int = 10 ** 6) -> Tuple[bool, List[int]]:
    """Trial-divide n by primes below ``limit``.  Returns (is_smooth, remaining_factors)."""
    factors: List[int] = []
    m = n
    d = 2
    while d * d <= m and d <= limit:
        while m % d == 0:
            factors.append(d)
            m //= d
        d += 1 if d == 2 else 2
    if m > 1:
        factors.append(m)
    is_smooth = all(f <= limit for f in factors)
    return is_smooth, factors


def analyze_curve(n: int = SECP256K1_N, smoothness_limit: int = 10 ** 6) -> Dict[str, Any]:
    """Structural facts about a curve order, stated as provable propositions.

    This is the step that decides whether a *named* attack applies at all.  Reaching for
    Pohlig-Hellman on secp256k1 is not slow, it is a category error: the order is prime, so
    there is no subgroup structure to exploit.
    """
    prime = _is_probable_prime(n)
    smooth, factors = _smoothness_bound(n, smoothness_limit) if not prime else (False, [])
    smallest = factors[0] if factors else None

    if prime:
        pohlig = ("inapplicable: the group order is prime, so the discrete log lives in "
                  "one cyclic group of prime order and there is no subgroup structure to "
                  "reduce it to")
    elif smooth:
        pohlig = (f"APPLICABLE: order is {smoothness_limit}-smooth "
                  f"(smallest factor {smallest}); discrete log reduces to subgroups and "
                  "Pohlig-Hellman solves it")
    else:
        pohlig = (f"not useful: smallest factor above {smoothness_limit} is {smallest}, "
                  "so no small-subgroup reduction exists")

    return {
        "order_hex": hex(n),
        "order_bits": n.bit_length(),
        "prime": prime,
        "smooth": smooth,
        "smallest_factor": smallest,
        "factors_under_limit": factors if not prime else [],
        "pohlig_hellman": pohlig,
        "ecdlp_best_known": (
            "Pollard rho, O(sqrt(n)) group operations"
        ),
        "ecdlp_cost_256bit": size_and_rate(1 << 128, 1e9, 3600.0)["t_human"],
        "note": ("a named attack is only worth running once its precondition holds; "
                 "verify the precondition here before spending compute"),
    }


def assess_nonce_leak(leaked_bits: int, signatures: int, key_bits: int = 256) -> Dict[str, Any]:
    """Assess whether an ECDSA nonce-bias (HNP/lattice) attack can apply.

    The lattice attack recovers the key from signatures whose nonces leak ``leaked_bits``
    each.  The standard heuristic is that the attack succeeds once the total leaked
    information covers the key: ``signatures * leaked_bits >= key_bits``.  The exact
    threshold is empirical -- it depends on the leak position (MSB leaks are friendlier
    than LSB), the lattice implementation, and the reduction quality -- so this is a
    precondition to check, not a guarantee.  Always validate against a witness instance
    before trusting a negative.
    """
    try:
        t, m, bits = int(leaked_bits), int(signatures), int(key_bits)
    except (TypeError, ValueError):
        return {"applicable": None, "reason": "leaked_bits/signatures/key_bits must be ints"}

    total = t * m
    margin = total - bits
    if t <= 0 or m <= 0:
        return {"applicable": False, "reason": "no leaked bits or no signatures"}
    if bits <= 0:
        return {"applicable": None, "reason": "key_bits must be positive"}

    applicable = total >= bits
    return {
        "applicable": applicable,
        "leaked_bits_per_signature": t,
        "signatures": m,
        "total_leaked_bits": total,
        "key_bits": bits,
        "margin_bits": margin,
        "reason": (
            f"{total} leaked bits vs {bits}-bit key: "
            + ("covers the key" if applicable else
               f"short by {abs(margin)} bits -- add signatures or recover more bits each")
        ),
        "caveat": ("threshold is empirical; validate on a witness instance with the same "
                   "leak pattern before trusting a negative"),
        "needs_witness": True,
    }


def channel_capacity_bits(symbols: int, bits_per_symbol: int = 1) -> Dict[str, Any]:
    """Information capacity of a steganographic or visual channel, in bits.

    A channel that cannot physically carry the payload is not a candidate; it is a dead
    end, and saying so costs nothing.  This is the check that stops a 1-bit-per-symbol
    59-symbol channel from being mined for a 256-bit key.
    """
    total = symbols * bits_per_symbol
    return {
        "symbols": symbols,
        "bits_per_symbol": bits_per_symbol,
        "capacity_bits": total,
        "holds_256bit_key": total >= 256,
        "holds_160bit_key": total >= 160,
        "verdict": ("sufficient" if total >= 256 else
                    "short -- the missing piece is a reading rule, not more symbols"),
    }


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


@dataclass
class AttackPlan:
    """What the engine decided to do, before doing it."""

    slug: str
    family: str
    label: str
    confidence: float
    compute: str
    approach: Tuple[str, ...]
    tools: Tuple[str, ...]
    first_move: str
    reasons: Tuple[str, ...] = ()
    secondary_families: Tuple[str, ...] = ()

    def as_dict(self) -> Dict[str, Any]:
        return {
            "slug": self.slug,
            "family": self.family,
            "label": self.label,
            "confidence": round(self.confidence, 3),
            "compute": self.compute,
            "approach": list(self.approach),
            "tools": list(self.tools),
            "first_move": self.first_move,
            "reasons": list(self.reasons),
            "secondary_families": list(self.secondary_families),
        }


#: The first concrete action each family implies.
_FIRST_MOVE: Dict[str, str] = {
    "guessing": "Generate candidates from the puzzle's own theme (title, author, domain, "
                "date) and push each through the oracle, ordered plausibility-first.",
    "brute_force": "Write down N and measure D, then compute t = N/D. If t exceeds your "
                   "budget, stop and look for a constraint that shrinks N.",
    "steganography": "Enumerate carrier properties (bit planes, channels, DCT, metadata, "
                     "trailing bytes) and compute the channel's capacity in bits first.",
    "encoding": "Find the author's worked example and calibrate the tokenizer against it; "
                "exact reproduction of the demo pins the rule.",
    "geometry": "Measure the property two independent ways and require agreement; compute "
                "the channel capacity before reading anything.",
    "math": "Identify the exact problem (ECDLP, DLP, factoring, collision, preimage) and "
            "check its structural preconditions before computing.",
    "reverse_engineering": "Establish what the artifact is and which parts are in scope, "
                           "then find the invariant that makes the input reachable.",
    "blockchain": "Read the escrow's full history (funding tx, OP_RETURN, change, "
                  "notarization) -- on-chain state outranks any secondary description.",
    "external": "Write down exactly what information is missing, then ask the author. "
                "Rank this last for compute and first for outreach.",
}

#: What is needed before the family's attack can run.
_REQUIRED_INPUT: Dict[str, str] = {
    "guessing": "a candidate source (wordlist, theme words) and an oracle",
    "brute_force": "a key range and an oracle",
    "steganography": "the carrier file",
    "encoding": "the puzzle text plus the author's worked example",
    "geometry": "the image or diagram",
    "math": "the curve parameters or the numerical instance",
    "reverse_engineering": "the artifact (bytecode, binary, file)",
    "blockchain": "the escrow address or txid",
    "external": "a contact for the author or a second copy of the artifact",
}


def plan_attack(puzzle: Dict[str, Any]) -> AttackPlan:
    """Classify a puzzle record and return the attack plan it implies."""
    classification = classify_puzzle(puzzle)
    fam = FAMILIES[classification.family]
    return AttackPlan(
        slug=classification.slug,
        family=fam.key,
        label=fam.label,
        confidence=classification.confidence,
        compute=fam.compute,
        approach=fam.approach,
        tools=fam.tools,
        first_move=_FIRST_MOVE.get(fam.key, "classify first"),
        reasons=classification.reasons,
        secondary_families=classification.secondary_families,
    )


def run_attack(puzzle: Dict[str, Any], *, oracle: Optional[DeriveFn] = None,
               target: Optional[str] = None, budget_seconds: float = 5.0,
               extra: Optional[Dict[str, Any]] = None) -> AttackOutcome:
    """Run the attack the puzzle's family implies.

    ``extra`` carries family-specific inputs: ``start``/``end`` for ``brute_force``,
    ``candidates`` or ``base_words`` for ``guessing``, ``n`` for ``math``,
    ``leaked_bits``/``signatures`` for a nonce-bias assessment, ``symbols``/
    ``bits_per_symbol`` for a capacity check.
    """
    extra = extra or {}
    plan = plan_attack(puzzle)
    opts = dict(extra)

    if plan.family == "brute_force":
        if oracle is None or target is None:
            return AttackOutcome(
                family=plan.family, outcome=Outcome.NEEDS_INPUT,
                reasons=["brute force needs an oracle and a target address"],
                notes=[f"missing: {_REQUIRED_INPUT['brute_force']}"],
            )
        start = int(opts.get("start", 1))
        end = int(opts.get("end", start + 1000))
        return brute_force_range(
            oracle, target, start, end,
            budget_seconds=budget_seconds,
            witness_key=opts.get("witness_key"),
            witness_address=opts.get("witness_address"),
        )

    if plan.family == "guessing":
        derive_phrase = opts.get("derive_phrase")
        if derive_phrase is None or target is None:
            return AttackOutcome(
                family=plan.family, outcome=Outcome.NEEDS_INPUT,
                reasons=["guessing needs a phrase oracle and a target address"],
                notes=[f"missing: {_REQUIRED_INPUT['guessing']}"],
            )
        candidates = opts.get("candidates")
        if candidates is None:
            candidates = guess_candidates(
                opts.get("base_words") or _theme_words(puzzle),
                opts.get("extra_words") or (),
                max_mutations=int(opts.get("max_mutations") or 0),
            )
        return search_candidates(
            derive_phrase, target, candidates,
            budget_seconds=budget_seconds,
            witness_phrase=opts.get("witness_phrase"),
            witness_address=opts.get("witness_address"),
        )

    if plan.family == "math":
        n = int(opts.get("n") or SECP256K1_N)
        facts = analyze_curve(n)
        notes = [facts["pohlig_hellman"], f"best known ECDLP attack: {facts['ecdlp_best_known']}"]
        if opts.get("leaked_bits") and opts.get("signatures"):
            leak = assess_nonce_leak(int(opts["leaked_bits"]), int(opts["signatures"]),
                                     int(opts.get("key_bits") or 256))
            facts["nonce_leak"] = leak
            notes.append(leak["reason"])
        return AttackOutcome(
            family=plan.family,
            outcome=Outcome.MATCH if facts.get("smooth") else Outcome.INFEASIBLE,
            space_size=None, reasons=[f"order is prime: {facts['prime']}",
                                      f"Pollard rho cost: {facts['ecdlp_cost_256bit']}"],
            notes=notes,
        )

    if plan.family == "steganography":
        symbols = opts.get("symbols")
        if symbols is None:
            return AttackOutcome(
                family=plan.family, outcome=Outcome.NEEDS_INPUT,
                reasons=["steganography needs the carrier to measure a channel"],
                notes=[f"missing: {_REQUIRED_INPUT['steganography']}"],
            )
        cap = channel_capacity_bits(int(symbols),
                                    int(opts.get("bits_per_symbol") or 1))
        return AttackOutcome(
            family=plan.family,
            outcome=Outcome.INFEASIBLE if not cap["holds_256bit_key"] else Outcome.SKIPPED,
            reasons=[f"channel capacity {cap['capacity_bits']} bits"],
            notes=[cap["verdict"]],
        )

    if plan.family == "encoding":
        return AttackOutcome(
            family=plan.family, outcome=Outcome.NEEDS_INPUT,
            reasons=["encoding needs the puzzle text and the author's worked example"],
            notes=[f"missing: {_REQUIRED_INPUT['encoding']}",
                   "calibrate the tokenizer against the demo, never against the narrative"],
        )

    if plan.family == "geometry":
        symbols = opts.get("symbols")
        if symbols is None:
            return AttackOutcome(
                family=plan.family, outcome=Outcome.NEEDS_INPUT,
                reasons=["geometry needs the image or diagram"],
                notes=[f"missing: {_REQUIRED_INPUT['geometry']}"],
            )
        cap = channel_capacity_bits(int(symbols),
                                    int(opts.get("bits_per_symbol") or 1))
        return AttackOutcome(
            family=plan.family,
            outcome=Outcome.INFEASIBLE if not cap["holds_256bit_key"] else Outcome.SKIPPED,
            reasons=[f"measured channel capacity {cap['capacity_bits']} bits"],
            notes=[cap["verdict"],
                   "re-extract on an independent copy to separate a real channel from an "
                   "extraction artifact"],
        )

    if plan.family == "reverse_engineering":
        return AttackOutcome(
            family=plan.family, outcome=Outcome.NEEDS_INPUT,
            reasons=["reverse engineering needs the artifact itself"],
            notes=[f"missing: {_REQUIRED_INPUT['reverse_engineering']}",
                   "prove a finding by execution on a local harness, not by inspection"],
        )

    if plan.family == "blockchain":
        address = opts.get("address") or (puzzle.get("criteria") or {}).get("address")
        if not address:
            return AttackOutcome(
                family=plan.family, outcome=Outcome.NEEDS_INPUT,
                reasons=["blockchain reading needs the escrow address or txid"],
                notes=[f"missing: {_REQUIRED_INPUT['blockchain']}"],
            )
        return AttackOutcome(
            family=plan.family, outcome=Outcome.SKIPPED,
            reasons=[f"target escrow {address}"],
            notes=["read the full history (funding tx, OP_RETURN, change, notarization)",
                   "check for an author notarization transaction",
                   "verify the author's convention reproduces before relying on it"],
        )

    # external, and anything unmatched
    return AttackOutcome(
        family=plan.family, outcome=Outcome.NEEDS_INPUT,
        reasons=["the missing piece is information, not compute"],
        notes=[f"missing: {_REQUIRED_INPUT.get(plan.family, 'the required input')}",
               "write down the question precisely, then ask the author"],
    )


def _theme_words(puzzle: Dict[str, Any]) -> List[str]:
    """Pull theme words out of a puzzle record -- what an author is likely to reuse."""
    words: List[str] = []
    for key in ("title", "slug", "author", "series"):
        value = puzzle.get(key)
        if not value:
            continue
        for token in str(value).replace("-", " ").replace("_", " ").split():
            cleaned = "".join(ch for ch in token if ch.isalnum())
            if len(cleaned) >= 3 and cleaned.lower() not in {w.lower() for w in words}:
                words.append(cleaned)
    return words
