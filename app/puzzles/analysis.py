"""Puzzle analysis: compare public wallet data against authorized MemePol data.

Verdicts are deliberately four-valued (requirement 11). Merely having an
address or a non-zero balance is never enough for a match:

* ``EXACT``    - every required criterion is satisfied (address *and* value
                 thresholds where specified).
* ``POSSIBLE`` - partial evidence (e.g. address matches but a threshold is
                 unmet, or a balance-range criterion is satisfied without an
                 address confirmation). Requires human review.
* ``NONE``     - the record was evaluated and no criterion matched.
* ``ERROR``    - the dataset could not be evaluated (unconfigured, API error,
                 malformed record). Never reported as a match.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from ..chains.base import AssetReport
from ..errors import AppError, PuzzleAPIError
from ..logging_setup import get_logger
from .memepol import MemePolClient, PuzzleEntry

log = get_logger()


class Verdict(str, Enum):
    EXACT = "exact_match"
    POSSIBLE = "possible_match"
    NONE = "no_match"
    ERROR = "error"

    @property
    def status(self) -> str:
        """Map a verdict onto the ✓/✗/⏳ status vocabulary."""
        return {
            Verdict.EXACT: "✓",
            Verdict.POSSIBLE: "⏳",
            Verdict.NONE: "✗",
            Verdict.ERROR: "✗",
        }[self]


@dataclass
class PuzzleMatch:
    puzzle_id: str
    title: str
    verdict: Verdict
    score: float
    reasons: List[str] = field(default_factory=list)
    hints: List[str] = field(default_factory=list)
    images: List[str] = field(default_factory=list)
    note: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        out = {
            "puzzle_id": self.puzzle_id,
            "title": self.title,
            "verdict": self.verdict.value,
            "status": self.verdict.status,
            "score": round(self.score, 3),
            "reasons": self.reasons,
            "hints": self.hints,
            "images": self.images,
        }
        if self.note:
            out["note"] = self.note
        return out


@dataclass
class AnalysisResult:
    verdict: Verdict
    status: str
    matches: List[PuzzleMatch] = field(default_factory=list)
    hints: List[str] = field(default_factory=list)
    images: List[str] = field(default_factory=list)
    evaluated: int = 0
    detail: Optional[str] = None
    source: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "verdict": self.verdict.value,
            "status": self.status,
            "evaluated": self.evaluated,
            "matches": [m.as_dict() for m in self.matches],
            "hints": self.hints,
            "images": self.images,
        }
        if self.source:
            out["source"] = self.source
        if self.detail:
            out["detail"] = self.detail
        return out


def _as_float(value: Any) -> Optional[float]:
    try:
        if value is None or value == "":
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


class PuzzleAnalyzer:
    """Evaluates wallet data against MemePol puzzle records."""

    def __init__(self, client: MemePolClient, *, source=None):
        self.client = client
        self.source = source

    @property
    def configured(self) -> bool:
        if self.source is not None:
            return bool(getattr(self.source, "configured", False))
        return self.client.configured

    # -- public -----------------------------------------------------------
    def analyze(self, report: AssetReport,
                puzzles: Optional[List[PuzzleEntry]] = None) -> AnalysisResult:
        """Analyse one asset report against the dataset."""
        if not self.configured:
            detail = ("no puzzle dataset configured; set OCP_DATASET_PATH or "
                      "MEMEPOL_API_KEY")
            return AnalysisResult(
                verdict=Verdict.ERROR, status="✗", detail=detail,
            )
        try:
            if puzzles is not None:
                entries = puzzles
            elif self.source is not None:
                entries = self.source.list_puzzles()
            else:
                entries = self.client.list_puzzles()
        except AppError as exc:
            log.warning(
                "puzzle evaluation failed",
                extra={"component": "puzzles.analysis", "status": "✗",
                       "detail": str(exc)},
            )
            return AnalysisResult(
                verdict=Verdict.ERROR, status="✗",
                detail=f"dataset error: {type(exc).__name__}: {exc}",
            )
        except (FileNotFoundError, ValueError, OSError) as exc:
            log.warning(
                "puzzle dataset unavailable",
                extra={"component": "puzzles.analysis", "status": "✗",
                       "detail": str(exc)},
            )
            return AnalysisResult(
                verdict=Verdict.ERROR, status="✗",
                detail=f"dataset error: {exc}",
            )

        matches: List[PuzzleMatch] = []
        for entry in entries:
            match = self._evaluate_entry(report, entry)
            if match is not None:
                matches.append(match)

        matches.sort(key=lambda m: m.score, reverse=True)
        if any(m.verdict is Verdict.EXACT for m in matches):
            overall = Verdict.EXACT
        elif any(m.verdict is Verdict.POSSIBLE for m in matches):
            overall = Verdict.POSSIBLE
        else:
            overall = Verdict.NONE

        hints: List[str] = []
        images: List[str] = []
        for m in matches:
            if m.verdict in (Verdict.EXACT, Verdict.POSSIBLE):
                hints.extend(h for h in m.hints if h not in hints)
                images.extend(i for i in m.images if i not in images)

        result = AnalysisResult(
            verdict=overall,
            status=overall.status,
            matches=matches,
            hints=hints,
            images=images,
            evaluated=len(entries),
            source=getattr(self.source, "name", None) or "memepol",
        )
        log.info(
            "puzzle analysis complete",
            extra={"component": "puzzles.analysis", "status": overall.status,
                   "detail": f"verdict={overall.value} evaluated={len(entries)}"},
        )
        return result

    # -- scoring ----------------------------------------------------------
    def _evaluate_entry(self, report: AssetReport,
                        entry: PuzzleEntry) -> Optional[PuzzleMatch]:
        criteria = entry.criteria or {}
        if not criteria:
            # Nothing to compare against - record it but never as a match.
            return PuzzleMatch(
                puzzle_id=entry.id, title=entry.title, verdict=Verdict.NONE,
                score=0.0,
                reasons=["puzzle record has no comparable criteria"],
            )

        reasons: List[str] = []

        # ---- chain is a FILTER, not evidence ----------------------------
        # Sharing a chain with 31 bitcoin puzzles is not a signal. If the
        # record names a chain and it differs, this record is out.
        c_chain = criteria.get("chain")
        if c_chain and str(c_chain).lower() != report.chain.lower():
            return PuzzleMatch(
                puzzle_id=entry.id, title=entry.title, verdict=Verdict.NONE,
                score=0.0,
                reasons=[f"chain mismatch (record={c_chain}, wallet={report.chain})"],
            )
        if c_chain:
            reasons.append(f"chain matches ({report.chain})")

        # ---- evidence criteria ------------------------------------------
        satisfied = 0
        required = 0
        address_confirmed = False
        threshold_met = True
        threshold_specified = False

        # address: the only criterion that confirms ownership
        c_address = criteria.get("address")
        if c_address:
            required += 1
            if str(c_address).lower() == report.address.lower():
                satisfied += 1
                address_confirmed = True
                reasons.append("address matches exactly")
            else:
                reasons.append("address does not match")

        # symbol: weak evidence (many wallets hold ETH)
        c_symbol = criteria.get("symbol") or criteria.get("asset")
        if c_symbol:
            required += 1
            symbols = {a.symbol.upper() for a in report.assets}
            if str(c_symbol).upper() in symbols:
                satisfied += 1
                reasons.append(f"asset {c_symbol} present")
            else:
                reasons.append(f"asset {c_symbol} not held")

        # balance thresholds: moderate evidence
        c_min = _as_float(criteria.get("min_balance"))
        c_exact_bal = _as_float(criteria.get("balance"))
        wallet_balance = report.balance_native
        if c_min is not None:
            threshold_specified = True
            required += 1
            if wallet_balance is not None and wallet_balance >= c_min:
                satisfied += 1
                reasons.append(f"balance {wallet_balance} >= min {c_min}")
            else:
                threshold_met = False
                reasons.append(f"balance {wallet_balance} below min {c_min}")
        if c_exact_bal is not None:
            threshold_specified = True
            required += 1
            if wallet_balance is not None and abs(wallet_balance - c_exact_bal) < 1e-12:
                satisfied += 1
                reasons.append(f"balance equals {c_exact_bal}")
            else:
                threshold_met = False
                reasons.append(f"balance {wallet_balance} != {c_exact_bal}")

        # ---- no evidence criteria at all -> nothing comparable ----------
        if required == 0:
            return PuzzleMatch(
                puzzle_id=entry.id, title=entry.title, verdict=Verdict.NONE,
                score=0.0,
                reasons=reasons + ["no address/asset/balance criteria to compare"],
            )

        score = satisfied / required

        # ---- verdict (evidence-based, four-valued) ----------------------
        # Address confirmation is REQUIRED for any match.
        #
        # A puzzle's `min_balance` / `balance` describes the ESCROW's expected
        # balance, not a filter on the visiting wallet. Comparing an arbitrary
        # wallet's balance against it is a category error: it would flag every
        # funded address as a "possible match" for any puzzle with a threshold.
        # So value criteria only refine a match once the address is proven.
        if address_confirmed and threshold_met and satisfied == required:
            verdict = Verdict.EXACT
            reasons.append("all criteria satisfied")
        elif address_confirmed:
            # The escrow address is proven; only value criteria differ, which is
            # worth a human look (balance may have changed since verification).
            verdict = Verdict.POSSIBLE
            reasons.append("address confirmed; value criteria unmet")
        else:
            verdict = Verdict.NONE
            reasons.append("address not confirmed; not a match")

        return PuzzleMatch(
            puzzle_id=entry.id, title=entry.title, verdict=verdict, score=score,
            reasons=reasons,
            hints=entry.hints if verdict in (Verdict.EXACT, Verdict.POSSIBLE) else [],
            images=entry.images if verdict in (Verdict.EXACT, Verdict.POSSIBLE) else [],
            note=entry.note,
        )
