"""Puzzle strategy taxonomy and classifier for the open-crypto-puzzles catalog.

The catalog already records a fine-grained ``puzzle_type`` per entry (``bip39-seed``,
``image-stego``, ``text-cipher``, ...).  That vocabulary is *mechanism*, not *method*: it
says how the answer is stored, not what you actually have to do.  This module maps those
mechanisms onto **strategy families** -- the handful of fundamentally different ways a
puzzle can be attacked -- and classifies entries that carry no type at all from their text.

Why this matters: two puzzles can share a mechanism and need opposite methods.  ``bip39-seed``
and ``brainwallet`` both store a key behind words, but one is a constrained wordlist search
and the other is a hash-preimage hunt over an unbounded phrase space.  Picking the wrong
family wastes days; the repo's own history records a 500-million-derivation sweep spent on a
reading that was never going to yield a 256-bit key.

The taxonomy is deliberately small.  Every family is a *method*, and every method has a
concrete first move.  Families that cannot be expressed as a sequence of actions are not
families -- they are just labels.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

__all__ = [
    "StrategyFamily",
    "Classification",
    "FAMILIES",
    "TYPE_TO_FAMILY",
    "classify_puzzle",
    "classify_text",
    "classify_catalog",
    "family_for_type",
    "TYPE_TO_FAMILY",
]


# ---------------------------------------------------------------------------
# Strategy families
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StrategyFamily:
    """A fundamentally different *way of attacking* a puzzle.

    ``mechanisms`` are the catalog ``puzzle_type`` values that belong to this family.
    ``signals`` are substrings that, found in a puzzle's title/description, are evidence for
    it -- used only for entries that carry no explicit type.
    """

    key: str
    label: str
    description: str
    approach: Tuple[str, ...]
    tools: Tuple[str, ...]
    compute: str                      # "none" | "cpu" | "gpu"
    mechanisms: Tuple[str, ...] = ()
    signals: Tuple[str, ...] = ()


FAMILIES: Dict[str, StrategyFamily] = {}


def _family(f: StrategyFamily) -> StrategyFamily:
    FAMILIES[f.key] = f
    return f


_family(StrategyFamily(
    key="guessing",
    label="Guessing / passphrase",
    description=(
        "The key is derived from a human-chosen secret: a word, a phrase, a date, a name, a "
        "password. The space is unbounded in principle but strongly biased in practice, so the "
        "attack is dictionary + rules, not brute force."
    ),
    approach=(
        "Build a candidate generator around the puzzle's own theme (author, date, domain, "
        "title words) -- puzzle authors reuse their own material.",
        "Order candidates by plausibility: exact theme words, then mutations (case, leetspeak, "
        "separators), then dates in every common format.",
        "Push each candidate through the oracle's own derivation (never a reimplementation).",
        "If a hit is expected soon, prefer a wide shallow pass over a deep narrow one.",
    ),
    tools=("wordlist + rule engine", "hashcat", "the oracle as the verifier"),
    compute="cpu",
    mechanisms=("bip39-seed", "word-selection", "brainwallet", "password-pages", "bip38"),
    signals=("password", "passphrase", "word", "phrase", "mnemonic", "seed", "brainwallet",
             "guess", "name of", "date of", "favourite", "favorite"),
))

_family(StrategyFamily(
    key="brute_force",
    label="Brute force / small keyspace",
    description=(
        "The key lives in a range small enough to enumerate: a truncated key, a low-entropy "
        "seed, a sequential counter. Success is arithmetic -- size the space, measure your "
        "rate, and decide before you start."
    ),
    approach=(
        "Write down N (space size) and D (your measured rate) and compute t = N/D first.",
        "If t exceeds a few hours, look for a constraint that shrinks N rather than asking for "
        "more compute.",
        "Always run a witness: plant a known key in the space and confirm the harness finds it.",
        "A negative without a witness does not count.",
    ),
    tools=("multiprocessing oracle", "coincurve", "a known-answer test vector"),
    compute="cpu",
    mechanisms=("raw-private-key", "timelock"),
    signals=("brute", "range", "sequential", "counter", "truncated", "low entropy",
             "small key", "2^", "bit range"),
))

_family(StrategyFamily(
    key="steganography",
    label="Steganography / hidden data",
    description=(
        "The payload is concealed inside a carrier -- an image, audio, video, or document. "
        "The work is *finding the channel*, not computing harder: once the channel is known "
        "the read is usually trivial."
    ),
    approach=(
        "Inventory every carrier property before extracting anything: bit planes, colour "
        "channels, DCT coefficients, metadata chunks, trailing bytes, EXIF.",
        "Run an existing scanner (zsteg, steghide, binwalk) to enumerate candidates cheaply.",
        "Only sweep a channel if it can plausibly carry the payload size -- a 1-bit-per-pixel "
        "channel in a 950x950 image cannot hold a 256-bit key unless something expands it.",
        "Read the image yourself; 'needs a person' usually means a recognition task, not math.",
    ),
    tools=("zsteg", "steghide", "binwalk", "PIL/numpy", "the image itself"),
    compute="none",
    mechanisms=("image-stego", "audio", "video-series"),
    signals=("image", "png", "jpg", "hidden", "stego", "steganograph", "picture", "photo",
             "audio", "wav", "mp3", "video", "gif", "lsb"),
))

_family(StrategyFamily(
    key="encoding",
    label="Encoding / cipher",
    description=(
        "The answer is a transformation: a substitution cipher, a base conversion, a book "
        "cipher, a null cipher, an acrostic. The puzzle is to recover the *rule*, and the rule "
        "is usually demonstrated somewhere in the puzzle's own text."
    ),
    approach=(
        "Look for the author's worked example first -- position-select puzzles almost always "
        "ship one, and it pins the tokenizer and indexing convention at once.",
        "Calibrate the tokenizer against the demo (exact reproduction), never against the "
        "narrative, which is the wrong text.",
        "Rule out the cheap encodings in minutes (acrostic, word-length, a1z26) and log each "
        "negative before theorising.",
        "When a length does not match the expected key size, the encoding is wrong -- do not "
        "pad your way around it.",
    ),
    tools=("the author's own example", "a tokenizer you can prove", "frequency analysis"),
    compute="none",
    mechanisms=("text-cipher", "book", "pixel-code"),
    signals=("cipher", "encode", "decode", "base64", "hex", "acrostic", "substitut", "book",
             "novel", "poem", "verse", "chapter", "page", "letter"),
))

_family(StrategyFamily(
    key="geometry",
    label="Geometry / visual reading",
    description=(
        "The key is a measurable property of a drawing: a shape, a spacing, an area, a count. "
        "The trap is that the measurement is only meaningful if it is *stable* -- a reading "
        "that changes with threshold is noise, not a channel."
    ),
    approach=(
        "Measure the property two or three independent ways and require agreement before "
        "treating it as a channel.",
        "Compute the channel's information capacity in bits and compare it to what the key "
        "needs -- a 59-symbol 1-bit channel cannot hold a 256-bit key.",
        "If capacity is short, the missing piece is a reading rule, not more pixels.",
        "Re-extract on an independent copy of the image to separate a real channel from an "
        "extraction artifact.",
    ),
    tools=("PIL/numpy", "a stable extractor", "an information-capacity calculation"),
    compute="none",
    mechanisms=("geometry",),
    signals=("grid", "rectangle", "circle", "shape", "pattern", "count", "measure",
             "coordinate", "diagram", "pixel"),
))

_family(StrategyFamily(
    key="math",
    label="Mathematics / number theory",
    description=(
        "The key falls to a mathematical result: a discrete log, a factorisation, a smooth "
        "order, a hash collision. These are the puzzles where the answer is *provable* and "
        "where a wrong method is not merely slow but impossible."
    ),
    approach=(
        "Identify the exact problem first: ECDLP, DLP, factoring, collision, preimage. The "
        "applicable attack depends entirely on which one it is.",
        "Check the structural conditions before computing: is the group order smooth? are the "
        "primes close? is the curve anomalous or singular?",
        "Reach for a named attack only when its precondition holds -- Pohlig-Hellman is "
        "worthless on secp256k1 because n is prime.",
        "Prefer a small worked instance to validate the implementation before the real target.",
    ),
    tools=("SageMath/sympy", "a published reference implementation", "the curve parameters"),
    compute="cpu",
    mechanisms=("hash-collision", "smart-contract"),
    signals=("discrete log", "ecdlp", "factor", "prime", "curve", "collision", "hash",
             "modular", "lattice", "coppersmith", "smooth"),
))

_family(StrategyFamily(
    key="reverse_engineering",
    label="Reverse engineering / protocol",
    description=(
        "The answer is inside an artifact: a binary, a smart contract, a file format, a "
        "protocol trace. The work is understanding the artifact, and the payoff is a precise "
        "reading rather than a search."
    ),
    approach=(
        "Establish what the artifact is and which parts are in scope before reading anything.",
        "Find the invariant that makes the malformed input reachable -- an unreachable bug is "
        "not a result.",
        "Prove the finding by execution on a local harness, not by inspection alone.",
        "Distinguish 'confirmed but unreachable' from 'not a finding' and record both.",
    ),
    tools=("a local chain / disassembler", "execution, not inspection", "the spec"),
    compute="none",
    mechanisms=("smart-contract", "multisig", "shamir"),
    signals=("contract", "solidity", "evm", "bytecode", "binary", "revers", "protocol",
             "decompil", "disassembl", "abi"),
))

_family(StrategyFamily(
    key="blockchain",
    label="On-chain data reading",
    description=(
        "The key is derived from blockchain state: an address, a transaction, an opcode, an "
        "event log, a notarization. Everything needed is public; the work is reading it "
        "correctly and noticing the structure."
    ),
    approach=(
        "Read the escrow's full history first -- funding transaction, OP_RETURN outputs, "
        "change addresses, notarization transactions.",
        "Check for a notarization or provenance transaction the author may have published.",
        "Look for the convention the author used on sibling puzzles; verify it reproduces "
        "before relying on it.",
        "Treat on-chain state as the ground truth over any secondary description.",
    ),
    tools=("a block explorer API", "raw transaction decoding", "the author's own posts"),
    compute="none",
    mechanisms=("timelock", "multisig", "web-tree"),
    signals=("transaction", "txid", "on-chain", "notariz", "block", "escrow", "address",
             "script", "opcode", "utxo"),
))

_family(StrategyFamily(
    key="external",
    label="External information required",
    description=(
        "The key is not derivable from the published material at all: it needs a physical "
        "object, a person, an unpublished document, or a research breakthrough. No amount of "
        "compute closes this gap -- only information does."
    ),
    approach=(
        "Establish precisely what is missing and write it down as a question.",
        "Ask the author directly; every long-open puzzle in a series eventually gets a hint.",
        "Look for an independent copy of the artifact (an archive, a mirror, a print edition).",
        "Rank this puzzle last for compute and first for outreach.",
    ),
    tools=("the author's contact", "the Internet Archive", "a second copy of the artifact"),
    compute="none",
    mechanisms=("physical-object", "web-tree"),
    signals=("physical", "printed", "isbn", "signed", "contact", "email", "ask", "hint",
             "unpublished", "only the author"),
))


# Fine-grained catalog mechanism -> strategy family.
TYPE_TO_FAMILY: Dict[str, str] = {
    "bip39-seed": "guessing",
    "word-selection": "guessing",
    "brainwallet": "guessing",
    "password-pages": "guessing",
    "bip38": "guessing",
    "raw-private-key": "brute_force",
    "timelock": "blockchain",
    "image-stego": "steganography",
    "audio": "steganography",
    "video-series": "steganography",
    "text-cipher": "encoding",
    "book": "encoding",
    "pixel-code": "encoding",
    "geometry": "geometry",
    "hash-collision": "math",
    "smart-contract": "reverse_engineering",
    "multisig": "reverse_engineering",
    "shamir": "reverse_engineering",
    "web-tree": "external",
    "physical-object": "external",
}

# Normalisation for catalog values that arrive hyphenated, spaced, or cased differently.
_TYPE_ALIASES: Dict[str, str] = {
    "bip39": "bip39-seed",
    "bip39 seed": "bip39-seed",
    "stego": "image-stego",
    "image stego": "image-stego",
    "steganography": "image-stego",
    "raw private key": "raw-private-key",
    "private key": "raw-private-key",
    "text cipher": "text-cipher",
    "cipher": "text-cipher",
    "smart contract": "smart-contract",
    "contract": "smart-contract",
    "hash collision": "hash-collision",
    "collision": "hash-collision",
}


def _normalise_type(value: str) -> str:
    key = re.sub(r"[\s_]+", "-", value.strip().lower())
    key = _TYPE_ALIASES.get(key, key)
    key = _TYPE_ALIASES.get(value.strip().lower(), key)
    return key


def family_for_type(puzzle_type: str) -> Optional[str]:
    """Map a catalog ``puzzle_type`` value to a strategy-family key."""
    if not puzzle_type:
        return None
    norm = _normalise_type(puzzle_type)
    if norm in TYPE_TO_FAMILY:
        return TYPE_TO_FAMILY[norm]
    if norm in FAMILIES:
        return norm
    for known, fam in TYPE_TO_FAMILY.items():
        if norm in known or known in norm:
            return fam
    return None


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Classification:
    """The result of classifying one puzzle.

    ``family`` is the highest-scoring family; ``families`` is every family that scored, ranked.
    A puzzle can legitimately need more than one method (``ballet-bobby-lee`` is both a BIP38
    passphrase search and a physical-object hunt), so the ranked list is the useful output and
    ``family`` is only the first entry.
    """

    slug: str
    family: str
    label: str
    confidence: float
    reasons: Tuple[str, ...]
    approach: Tuple[str, ...]
    tools: Tuple[str, ...]
    compute: str
    matched_types: Tuple[str, ...] = ()
    families: Tuple[Tuple[str, float], ...] = ()

    @property
    def is_inferred(self) -> bool:
        """True when the family came from text signals rather than an explicit type."""
        return not self.matched_types

    @property
    def secondary_families(self) -> Tuple[str, ...]:
        return tuple(k for k, _ in self.families[1:])

    def as_dict(self) -> Dict[str, Any]:
        return {
            "slug": self.slug,
            "family": self.family,
            "label": self.label,
            "confidence": round(self.confidence, 3),
            "inferred": self.is_inferred,
            "families": [[k, round(v, 3)] for k, v in self.families],
            "secondary_families": list(self.secondary_families),
            "reasons": list(self.reasons),
            "matched_types": list(self.matched_types),
            "approach": list(self.approach),
            "tools": list(self.tools),
            "compute": self.compute,
        }


_EXPLICIT_WEIGHT = 1.0
_SIGNAL_WEIGHT = 0.45


def _score_signals(text: str) -> Dict[str, float]:
    lowered = text.lower()
    scores: Dict[str, float] = {}
    for key, fam in FAMILIES.items():
        hits = [s for s in fam.signals if s in lowered]
        if hits:
            scores[key] = _SIGNAL_WEIGHT * min(len(hits), 3) / 3.0
    return scores


def _classify(slug: str, scores: Dict[str, float], reasons: List[str],
               matched: Sequence[str]) -> Classification:
    ranked = tuple(sorted(scores.items(), key=lambda kv: (-kv[1], kv[0])))
    if not ranked:
        fam = FAMILIES["external"]
        return Classification(
            slug=slug, family=fam.key, label=fam.label, confidence=0.0,
            reasons=tuple(reasons) or ("no mechanism recorded and no signal matched",),
            approach=fam.approach, tools=fam.tools, compute=fam.compute,
            matched_types=tuple(matched), families=(),
        )
    best_key, best_score = ranked[0]
    fam = FAMILIES[best_key]
    return Classification(
        slug=slug, family=best_key, label=fam.label, confidence=round(best_score, 3),
        reasons=tuple(reasons), approach=fam.approach, tools=fam.tools, compute=fam.compute,
        matched_types=tuple(matched), families=ranked,
    )


def classify_puzzle(puzzle: Mapping[str, Any]) -> Classification:
    """Classify one catalog entry.

    An explicit ``puzzle_type`` is authoritative: it fixes the family outright.  When it is
    absent the entry's title and description are scored against each family's signals.
    """
    slug = str(puzzle.get("slug") or puzzle.get("id") or "<unknown>")
    reasons: List[str] = []
    scores: Dict[str, float] = {}
    matched: List[str] = []

    raw_types = puzzle.get("puzzle_type") or []
    if isinstance(raw_types, str):
        raw_types = [raw_types]
    for raw in raw_types:
        fam = family_for_type(str(raw))
        matched.append(str(raw))
        if fam:
            scores[fam] = max(scores.get(fam, 0.0), _EXPLICIT_WEIGHT)
            reasons.append(f"recorded type {raw!r} -> {fam}")

    blob = " ".join(str(puzzle.get(k) or "") for k in
                    ("title", "description", "summary", "series", "author"))
    if not scores:
        for fam_key, s in _score_signals(blob).items():
            scores[fam_key] = max(scores.get(fam_key, 0.0), s)
        for fam_key in scores:
            fam = FAMILIES[fam_key]
            hits = [sig for sig in fam.signals if sig in blob.lower()]
            if hits:
                reasons.append(f"text signals {hits[:4]} -> {fam_key}")

    c = _classify(slug, scores, reasons, matched)
    return _post_classify(c, puzzle)


# ---------------------------------------------------------------------------
# Post-classification adjustments for documented puzzle mechanics
# ---------------------------------------------------------------------------

# Signals that a smart-contract puzzle is actually a small-keyspace brute force
# (e.g. ZK Guess: number-guessing game with maxNumber <= 65535).
_ZKGUESS_SIGNALS = ("65535", "maxnumber", "max number", "number range", "secret number")

# Signals that a puzzle requires information that is not available
# (e.g. Teikhos: public keys never published by the author).
_NEEDS_INPUT_SIGNALS = (
    "never published by the author",
    "not recoverable from any",
    "only the author",
    "no trace of the key",
    "no trace of the public key",
    "cannot be recovered",
    "key is not recoverable",
    "information is not available",
    "required key is missing",
)


def _post_classify(c: Classification, puzzle: Mapping[str, Any]) -> Classification:
    """Adjust classification based on documented puzzle mechanics.

    Some puzzles have an explicit ``puzzle_type`` that misleads the family mapping.
    ZK Guess is recorded as ``smart-contract`` (→ reverse_engineering) but the actual
    attack is brute-forcing a small number range (maxNumber <= 65535).  Teikhos is
    recorded as ``smart-contract`` but the required public keys were never published,
    making it NEEDS_INPUT.  This function corrects those cases.
    """
    blob = " ".join(str(puzzle.get(k) or "") for k in (
        "title", "description", "summary", "difficulty_note", "series", "author",
        "difficulty_note",
    )).lower()

    # ZK-guess style: number guessing + small search space.
    # The signals "max"/"65535"/"secret number" + "guess" are specific enough
    # to identify a number-guessing game without needing an explicit type.
    if ("guess" in blob
            and any(s in blob for s in _ZKGUESS_SIGNALS)):
        fam = FAMILIES["brute_force"]
        reasons = c.reasons + (
            "zk-guess: number-guessing with small search space -> brute_force",
        )
        families = (("brute_force", 0.9),) + tuple(
            (k, v) for k, v in c.families if k != "brute_force"
        )
        return Classification(
            slug=c.slug, family=fam.key, label=fam.label, confidence=0.9,
            reasons=reasons, approach=fam.approach, tools=fam.tools,
            compute=fam.compute, matched_types=c.matched_types, families=families,
        )

    # NEEDS_INPUT: required information not available
    if any(s in blob for s in _NEEDS_INPUT_SIGNALS):
        fam = FAMILIES["external"]
        reasons = c.reasons + (
            "NEEDS_INPUT: required information not available -> external",
        )
        families = (("external", 0.85),) + tuple(
            (k, v) for k, v in c.families if k != "external"
        )
        return Classification(
            slug=c.slug, family=fam.key, label=fam.label, confidence=0.85,
            reasons=reasons, approach=fam.approach, tools=fam.tools,
            compute=fam.compute, matched_types=c.matched_types, families=families,
        )

    return c


def classify_text(text: str, slug: str = "<text>") -> Classification:
    """Classify free text (a puzzle description with no catalog entry)."""
    scores = _score_signals(text)
    reasons = []
    for fam_key in scores:
        fam = FAMILIES[fam_key]
        hits = [sig for sig in fam.signals if sig in text.lower()]
        if hits:
            reasons.append(f"text signals {hits[:4]} -> {fam_key}")
    return _classify(slug, scores, reasons, [])


def classify_catalog(puzzles: Iterable[Mapping[str, Any]]) -> Dict[str, Any]:
    """Classify a whole catalog and return per-entry results plus a distribution."""
    results: List[Dict[str, Any]] = []
    dist: Dict[str, int] = {}
    for p in puzzles:
        c = classify_puzzle(p)
        results.append(c.as_dict())
        dist[c.family] = dist.get(c.family, 0) + 1
    return {
        "status": "✓",
        "count": len(results),
        "families": {k: FAMILIES[k].label for k in FAMILIES},
        "distribution": dict(sorted(dist.items(), key=lambda kv: -kv[1])),
        "inferred": sum(1 for r in results if r["inferred"]),
        "results": results,
    }
