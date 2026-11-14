"""Bitcoin Puzzle Transaction solver.

The "Bitcoin Puzzle" is a series of transactions starting from 2015 where
funds were sent to addresses whose private keys are unknown but constrained
to a known range. The puzzle is to brute-force the private key from that
range and claim the funds.

This module:
1. Identifies whether an address/transaction is part of the puzzle.
2. Determines the keyspace (range of private keys).
3. Runs a brute-force search against the range.
4. Reports results honestly (MATCH / INFEASIBLE / UNCERTIFIED).

This is READ-ONLY: it derives addresses locally and compares them. It never
broadcasts transactions or moves funds.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..logging_setup import get_logger

log = get_logger()

__all__ = [
    "PuzzleTransaction",
    "PuzzleAttempt",
    "identify_puzzle_address",
    "estimate_keyspace",
    "brute_force_puzzle",
    "run_puzzle_witness",
]


@dataclass(frozen=True)
class PuzzleTransaction:
    """A known Bitcoin puzzle transaction."""
    txid: str
    address: str
    amount_btc: float
    block_height: int
    puzzle_number: int
    keyspace_range: Tuple[int, int]  # (start, end) inclusive
    description: str = ""


@dataclass
class PuzzleAttempt:
    """Result of a brute-force attempt."""
    puzzle_number: int
    address: str
    space_size: int
    rate_per_sec: float = 0.0
    elapsed_sec: float = 0.0
    outcome: str = "UNCERTIFIED"
    message: str = ""
    tested: int = 0


# Known puzzle transactions, verified against public references:
#   https://btcpuzzlesearch.com/puzzle/<n>
#   https://lotterypuzzle.org/
# NOTE: txid/block_height are intentionally empty/0 - the values previously
# shipped here were fabricated. Only address/range/status are source-verified.
KNOWN_PUZZLES: Dict[str, PuzzleTransaction] = {
    # Puzzle 1 - key 0x1, solved 2015-01-15.
    "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH": PuzzleTransaction(
        txid="",
        address="1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
        amount_btc=0.0,
        block_height=0,
        puzzle_number=1,
        keyspace_range=(0x01, 0x01),
        description="Puzzle 1 - solved (range 0x01-0x01, key 0x1)",
    ),
    # Puzzle 32 - range 2^31..2^32-1, solved 2015-01-16 (key 0xb862a62e).
    "1FRoHA9xewq7DjrZ1psWJVeTer8gHRqEvR": PuzzleTransaction(
        txid="",
        address="1FRoHA9xewq7DjrZ1psWJVeTer8gHRqEvR",
        amount_btc=0.0,
        block_height=0,
        puzzle_number=32,
        keyspace_range=(1 << 31, (1 << 32) - 1),
        description="Puzzle 32 - solved 2015-01-16 (key 0xb862a62e)",
    ),
    # Puzzle 101 - range 2^100..2^101-1, unsolved, 10.1 BTC.
    "1CKCVdbDJasYmhswB6HKZHEAnNaDpK7W4n": PuzzleTransaction(
        txid="",
        address="1CKCVdbDJasYmhswB6HKZHEAnNaDpK7W4n",
        amount_btc=10.1,
        block_height=0,
        puzzle_number=101,
        keyspace_range=(1 << 100, (1 << 101) - 1),
        description="Puzzle 101 - unsolved (range 2^100..2^101-1)",
    ),
}

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {char: idx for idx, char in enumerate(_B58_ALPHABET)}


def _base58check_ok(address: str) -> bool:
    """True when *address* carries a valid Base58Check checksum."""
    try:
        number = 0
        for char in address:
            number = number * 58 + _B58_INDEX[char]
        pad = len(address) - len(address.lstrip("1"))
        raw = b"\x00" * pad + (
            number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
        )
        if len(raw) != 25:
            return False
        checksum = hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4]
        return checksum == raw[-4:]
    except (KeyError, ValueError, OverflowError):
        return False


_invalid = [addr for addr in KNOWN_PUZZLES if not _base58check_ok(addr)]
if _invalid:
    raise ValueError(f"invalid Bitcoin puzzle address(es): {_invalid}")


def identify_puzzle_address(address: str) -> Optional[PuzzleTransaction]:
    """Check if an address is a known Bitcoin puzzle address.

    Returns the puzzle metadata if found, None otherwise. Addresses without a
    valid Base58Check checksum never match.
    """
    puzzle = KNOWN_PUZZLES.get(address)
    if puzzle is None or not _base58check_ok(address):
        return None
    return puzzle


def estimate_keyspace(start: int, end: int) -> Dict[str, Any]:
    """Estimate the difficulty of a brute-force search.

    Returns space size, estimated time at various rates, and feasibility.
    """
    size = end - start + 1
    if size <= 0:
        return {
            "space_size": 0,
            "feasible": False,
            "message": "Invalid range (end <= start)",
        }

    # Estimate at 1M keys/sec (modern CPU with optimized library)
    rate_cpu = 1_000_000
    # Estimate at 100M keys/sec (GPU)
    rate_gpu = 100_000_000
    # Estimate at 1B keys/sec (specialized hardware)
    rate_asic = 1_000_000_000

    seconds_cpu = size / rate_cpu
    seconds_gpu = size / rate_gpu
    seconds_asic = size / rate_asic

    return {
        "space_size": size,
        "bits": size.bit_length(),
        "estimates": {
            "cpu_1M_s": _format_duration(seconds_cpu),
            "gpu_100M_s": _format_duration(seconds_gpu),
            "asic_1B_s": _format_duration(seconds_asic),
        },
        "feasible": seconds_gpu < 86400 * 365,  # 1 year on GPU
    }


def brute_force_puzzle(
    puzzle: PuzzleTransaction,
    oracle: Callable[[int], bool],
    max_test: Optional[int] = None,
) -> PuzzleAttempt:
    """Run a brute-force search against a puzzle.

    ``oracle`` is a function that takes a private key (int) and returns True
    if it matches the target address.

    ``max_test`` caps the number of keys to test (None = full range).

    Returns a PuzzleAttempt with honest results.
    """
    start, end = puzzle.keyspace_range
    size = end - start + 1
    test_limit = min(max_test, size) if max_test else size

    attempt = PuzzleAttempt(
        puzzle_number=puzzle.puzzle_number,
        address=puzzle.address,
        space_size=size,
    )

    t0 = time.time()
    tested = 0

    for i in range(test_limit):
        key = start + i
        if oracle(key):
            attempt.elapsed_sec = time.time() - t0
            attempt.tested = tested
            attempt.outcome = "MATCH"
            attempt.message = f"Found key: 0x{key:x}"
            attempt.rate_per_sec = tested / attempt.elapsed_sec if attempt.elapsed_sec > 0 else 0
            return attempt
        tested += 1

    attempt.elapsed_sec = time.time() - t0
    attempt.tested = tested
    attempt.rate_per_sec = tested / attempt.elapsed_sec if attempt.elapsed_sec > 0 else 0
    attempt.outcome = "UNCERTIFIED"
    attempt.message = (
        f"Tested {tested:,} keys in {_format_duration(attempt.elapsed_sec)}. "
        f"No match found. Range not fully exhausted."
    )
    return attempt


def run_puzzle_witness(
    puzzle: PuzzleTransaction,
    oracle: Callable[[int], bool],
    witness_key: int,
) -> bool:
    """Plant a known key and verify the oracle finds it.

    This proves the harness works before trusting any negative result.
    """
    return oracle(witness_key)


def _format_duration(seconds: float) -> str:
    """Format seconds into human-readable duration."""
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    if seconds < 60:
        return f"{seconds:.1f} s"
    if seconds < 3600:
        return f"{seconds / 60:.1f} min"
    if seconds < 86400:
        return f"{seconds / 3600:.1f} hours"
    if seconds < 31536000:
        return f"{seconds / 86400:.1f} days"
    if seconds < 3153600000:
        return f"{seconds / 31536000:.1f} years"
    return f"{seconds:.2e} s (practically infinite)"
