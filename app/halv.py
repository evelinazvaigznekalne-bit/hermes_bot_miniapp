"""HALV puzzle research data loader.

Read-only module that surfaces the local HALV research files
(checkpoint, README, tested.md, leads.md) as structured data for the bot.
No secrets, no keys, no wallet material.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional


HALV_DIR = Path.home() / "ocp/2-mid-prizes/zden-haluska-halv-312ksats"
CHECKPOINT = Path.home() / ".hermes/cache/scratch/HALV-CHECKPOINT.md"


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except Exception:
        return ""


def _parse_frontmatter(text: str) -> Dict[str, Any]:
    """Extract YAML-ish frontmatter from a markdown file."""
    out: Dict[str, Any] = {}
    if not text.startswith("---"):
        return out
    end = text.find("---", 3)
    if end == -1:
        return out
    block = text[3:end]
    for line in block.splitlines():
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        key = key.strip()
        val = val.strip()
        if not key:
            continue
        if val.startswith("[") and val.endswith("]"):
            val = [v.strip().strip('"').strip("'") for v in val[1:-1].split(",") if v.strip()]
        out[key] = val
    return out


def _parse_table(text: str, header: str) -> List[Dict[str, str]]:
    """Parse Markdown table rows, tolerating trailing extra cells."""
    rows: List[Dict[str, str]] = []
    lines = text.splitlines()

    expected = [
        c.strip().lower()
        for c in header.strip().strip("|").split("|")
    ]

    header_index = None

    for i, line in enumerate(lines):
        if not line.strip().startswith("|"):
            continue
        cells = [
            c.strip().lower()
            for c in line.strip().strip("|").split("|")
        ]
        if cells == expected:
            header_index = i
            break

    if header_index is None:
        return rows

    for line in lines[header_index + 1:]:
        stripped = line.strip()

        if not stripped:
            if rows:
                break
            continue

        if not stripped.startswith("|"):
            break

        cells = [
            c.strip()
            for c in stripped.strip("|").split("|")
        ]

        # Ignore Markdown separator rows.
        if cells and all(
            re.fullmatch(r":?-{3,}:?", c) for c in cells
        ):
            continue

        # Some evidence rows have an extra status/note cell.
        if len(cells) < len(expected):
            continue

        row = dict(zip(expected, cells[:len(expected)]))
        hypothesis = row.get("hypothesis", "").strip()

        if not hypothesis:
            continue

        rows.append({
            "hypothesis": hypothesis,
            "volume": row.get("volume", "").strip(),
            "result": row.get("result", "").strip(),
            "date": row.get("date", "").strip(),
        })

    return rows

def get_halv_summary() -> Dict[str, Any]:
    """Return a structured summary of the HALV puzzle research."""
    readme = _read(HALV_DIR / "README.md")
    tested = _read(HALV_DIR / "analysis/tested.md")
    leads = _read(HALV_DIR / "analysis/leads.md")
    puzzle = _read(HALV_DIR / "puzzle.json")
    checkpoint = _read(CHECKPOINT)

    # Try JSON first
    if puzzle.strip().startswith("{"):
        try:
            pdata = __import__("json").loads(puzzle)
        except Exception:
            pdata = {}
    else:
        pdata = {}

    fm = _parse_frontmatter(readme) if readme.startswith("---") else {}

    # Escrow from README body or puzzle.json
    escrow_match = re.search(r"`(1[a-km-zA-HJ-NP-Z1-9]{25,34})`", readme)
    escrow = escrow_match.group(1) if escrow_match else pdata.get("escrow", "")
    if not escrow and pdata.get("addresses"):
        escrow = pdata["addresses"][0].get("address", "")

    # Verified on-chain check
    verified_on = pdata.get("last_updated", "")
    verified_state = ""
    if pdata.get("addresses"):
        verified_state = pdata["addresses"][0].get("verified_state", "")

    # Negative hypotheses
    negs = _parse_table(tested, "| Hypothesis | Volume | Result | Date |") if tested else []

    # Leads
    # Only numbered headings are actual leads.
    # Editorial headings such as "Not recommended" are excluded.
    lead_titles = [
        match.group(1).strip()
        for line in leads.splitlines()
        if (match := re.match(
            r"^##\s+\d+\.\s+(.+?)\s*$", line.strip()
        ))
    ]

    return {
        "slug": "zden-haluska-halv-312ksats",
        "title": pdata.get("title", fm.get("title", "Zden Level HALV")),
        "author": pdata.get("author", {}).get("name", fm.get("author", "Zden")),
        "status": pdata.get("status", fm.get("status", "OPEN")),
        "prize_sats": pdata.get("prize", {}).get("amount", 312500),
        "chain": pdata.get("chain", "bitcoin"),
        "escrow": escrow,
        "verified_on": verified_on,
        "verified_state": verified_state,
        "puzzle_type": pdata.get("puzzle_type", ["geometry", "raw-private-key"]),
        "target_format": pdata.get("target_format", "256-bit private key as direct hex, P2PKH"),
        "oracle_certified": pdata.get("derivation", {}).get("oracle_certified", False),
        "tested_total": pdata.get("tested_total", {}),
        "negatives_count": len(negs),
        "leads": lead_titles,
        "checkpoint_exists": CHECKPOINT.exists(),
        "checkpoint_updated": CHECKPOINT.stat().st_mtime if CHECKPOINT.exists() else 0,
    }


def get_halv_negatives() -> List[Dict[str, str]]:
    tested = _read(HALV_DIR / "analysis/tested.md")
    return _parse_table(tested, "| Hypothesis | Volume | Result | Date |") if tested else []


def get_halv_leads() -> List[str]:
    """Return only numbered, actionable lead headings."""
    leads = _read(HALV_DIR / "analysis/leads.md")
    result = []

    for line in leads.splitlines():
        match = re.match(
            r"^##\s+\d+\.\s+(.+?)\s*$",
            line.strip(),
        )
        if match:
            result.append(match.group(1).strip())

    return result

def get_halv_next_steps() -> List[str]:
    """Extract recommended next steps from README."""
    readme = _read(HALV_DIR / "README.md")
    steps: List[str] = []
    in_section = False
    for line in readme.splitlines():
        if "## Recommended next steps" in line or "## Open leads" in line:
            in_section = True
            continue
        if in_section:
            if line.startswith("## "):
                break
            if line.strip().startswith("-"):
                steps.append(line.strip().lstrip("-").strip())
    return steps
