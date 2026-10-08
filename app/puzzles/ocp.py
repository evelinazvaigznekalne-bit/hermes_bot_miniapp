"""File-backed puzzle source for the local open-crypto-puzzles corpus.

The ``open-crypto-puzzles`` repository ships a machine-readable
``puzzles.json`` index (see its ``AGENTS.md``). That corpus is the authorized
dataset this project compares against, so no API key is involved: it is read
straight off disk.

Record shape consumed (one entry per puzzle):

    {
      "slug": "...", "title": "...", "chain": "bitcoin", "status": "open",
      "addresses": [{"address": "...", "chain": "...", "role": "escrow",
                     "label": "...", "verified_state": "funded-unspent"}],
      "leads":     [{"rank": 1, "title": "...", "cost": "...", "status": "..."}],
      "artifacts": [{"path": "clues/x.jpg", "source": "https://..."}]
    }

Mapping onto :class:`PuzzleEntry`:

* ``criteria.address``  <- first escrow address (the only ownership-confirming key)
* ``criteria.chain``    <- puzzle chain
* ``hints``             <- ``leads[].title``
* ``images``            <- ``artifacts[].source`` (falling back to ``path``)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..logging_setup import get_logger
from .memepol import PuzzleEntry

log = get_logger()

#: Default locations to probe, in order.
DEFAULT_PATHS = (
    Path.home() / "ocp" / "puzzles.json",
    Path.home() / "open-crypto-puzzles" / "puzzles.json",
)


class OcpSource:
    """Reads the local open-crypto-puzzles index as a puzzle source."""

    name = "ocp"

    def __init__(self, path: Optional[Path] = None):
        self.path = self._resolve(path)
        self._cache: Optional[List[PuzzleEntry]] = None

    # -- discovery --------------------------------------------------------
    @staticmethod
    def _resolve(path: Optional[Path]) -> Optional[Path]:
        if path:
            p = Path(path).expanduser()
            return p if p.is_file() else None
        for candidate in DEFAULT_PATHS:
            if candidate.is_file():
                return candidate
        return None

    @property
    def configured(self) -> bool:
        return self.path is not None and self.path.is_file()

    def describe(self) -> Dict[str, Any]:
        return {
            "source": self.name,
            "configured": self.configured,
            "path": str(self.path) if self.path else None,
            "requires_api_key": False,
        }

    # -- loading ----------------------------------------------------------
    def list_puzzles(self, *, limit: int = 1000,
                     refresh: bool = False) -> List[PuzzleEntry]:
        if self._cache is not None and not refresh:
            return self._cache[:limit]
        if not self.configured:
            raise FileNotFoundError(
                "open-crypto-puzzles index not found; expected "
                f"{DEFAULT_PATHS[0]} (set OCP_DATASET_PATH to override)"
            )
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ValueError(f"could not read {self.path}: {exc}") from exc

        records = data.get("puzzles") if isinstance(data, dict) else data
        if not isinstance(records, list):
            raise ValueError("puzzles.json has no 'puzzles' list")

        entries = [e for e in (self._convert(r) for r in records) if e is not None]
        self._cache = entries
        log.info(
            "ocp dataset loaded",
            extra={"component": "puzzles.ocp", "status": "✓",
                   "detail": f"{len(entries)} puzzles from {self.path.name}"},
        )
        return entries[:limit]

    # -- conversion -------------------------------------------------------
    @staticmethod
    def _convert(record: Dict[str, Any]) -> Optional[PuzzleEntry]:
        if not isinstance(record, dict):
            return None
        slug = record.get("slug") or record.get("title")
        if not slug:
            return None

        addresses = record.get("addresses") or []
        escrow = None
        if isinstance(addresses, list):
            for entry in addresses:
                if isinstance(entry, dict) and entry.get("role") == "escrow":
                    escrow = entry
                    break
            if escrow is None and addresses and isinstance(addresses[0], dict):
                escrow = addresses[0]

        chain = record.get("chain")
        criteria: Dict[str, Any] = {}
        if escrow:
            criteria["address"] = escrow.get("address")
            if escrow.get("verified_state"):
                criteria["escrow_state"] = escrow["verified_state"]
        if chain and chain != "none":
            criteria["chain"] = chain

        hints: List[str] = []
        for lead in (record.get("leads") or []):
            if isinstance(lead, dict) and lead.get("title"):
                rank = lead.get("rank")
                cost = lead.get("cost")
                suffix = f" [{cost}]" if cost else ""
                hints.append(f"#{rank} {lead['title']}{suffix}" if rank
                             else f"{lead['title']}{suffix}")
            elif isinstance(lead, str):
                hints.append(lead)

        images: List[str] = []
        for art in (record.get("artifacts") or []):
            if isinstance(art, dict):
                ref = art.get("source") or art.get("path")
                if ref:
                    images.append(str(ref))
            elif isinstance(art, str):
                images.append(art)

        note_bits = []
        if record.get("status"):
            note_bits.append(f"status={record['status']}")
        if record.get("puzzle_type"):
            pt = record["puzzle_type"]
            note_bits.append(f"type={','.join(pt) if isinstance(pt, list) else pt}")
        if escrow and escrow.get("verified_state"):
            note_bits.append(f"escrow={escrow['verified_state']}")

        return PuzzleEntry(
            id=str(slug),
            title=str(record.get("title") or slug),
            chain=chain,
            criteria=criteria,
            hints=hints,
            images=images,
            raw=record,
            note="; ".join(note_bits) if note_bits else None,
        )
