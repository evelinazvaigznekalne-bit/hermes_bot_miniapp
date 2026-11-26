#!/usr/bin/env python3
"""Generate a sanitized public puzzle catalog from ~/ocp/puzzles.json.

Uses an explicit field allowlist. Excludes private keys, seed phrases,
candidate secrets, credentials, private filesystem paths, private research
artifacts, and personal data (author handles, published URLs, etc.).

Output: ~/hermes_bot_miniapp/app/data/public_catalog.json
"""

from __future__ import annotations

import json
from pathlib import Path

SRC = Path.home() / "ocp" / "puzzles.json"
OUT = Path(__file__).resolve().parent.parent / "app" / "data" / "public_catalog.json"

#: Explicit field allowlist — only these fields are copied into the public
#: catalog. Everything else (author, published, leads, artifacts,
#: dead_end_reason, series, etc.) is dropped.
ALLOWLIST = (
    "slug",
    "title",
    "chain",
    "status",
    "tier",
    "puzzle_type",
    "addresses",
    "prize",
)


def _sanitize_address(addr: dict) -> dict:
    """Keep only public on-chain address fields. Drop explorer URLs."""
    out = {}
    for key in ("address", "chain", "role", "label", "verified_state"):
        if key in addr:
            out[key] = addr[key]
    # Drop 'expected' if it contains candidate-secret-like content; keep
    # verified_state as the historical funded/unspent indicator.
    return out


def _sanitize_prize(prize: dict) -> dict:
    """Keep only public prize metadata."""
    out = {}
    for key in ("amount", "asset", "usd_estimate", "usd_snapshot", "note"):
        if key in prize:
            out[key] = prize[key]
    return out


def build_catalog(records: list[dict]) -> list[dict]:
    catalog = []
    for rec in records:
        entry = {}
        for field in ALLOWLIST:
            if field not in rec:
                continue
            value = rec[field]
            if field == "addresses" and isinstance(value, list):
                entry[field] = [_sanitize_address(a) for a in value if isinstance(a, dict)]
            elif field == "prize" and isinstance(value, dict):
                entry[field] = _sanitize_prize(value)
            else:
                entry[field] = value
        catalog.append(entry)
    return catalog


def main() -> int:
    if not SRC.is_file():
        print(f"Source dataset not found: {SRC}")
        return 1

    with SRC.open(encoding="utf-8") as fh:
        data = json.load(fh)

    records = data.get("puzzles", [])
    if not isinstance(records, list):
        print("puzzles.json has no 'puzzles' list")
        return 1

    catalog = build_catalog(records)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": 1,
        "source": "open-crypto-puzzles (sanitized public catalog)",
        "record_count": len(catalog),
        "puzzles": catalog,
    }
    OUT.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Wrote {len(catalog)} records to {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
