#!/usr/bin/env python3
"""Local dry-run: inspect a public address without any signing.

Usage:
    python3 -m app.cli inspect 0xDe0DAFC80d487b8aE652bBF906ac6c6007aE3A5e
    python3 -m app.cli inspect <address> --chain ethereum --puzzles
    python3 -m app.cli status
    python3 -m app.cli demo            # offline demo using a synthetic signer
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import get_settings  # noqa: E402
from app.logging_setup import get_logger, setup_logging  # noqa: E402
from app.service import WalletService  # noqa: E402
from app.status import summarize  # noqa: E402

log = get_logger()


def _print(payload) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=False))


def cmd_inspect(args) -> int:
    settings = get_settings()
    setup_logging(settings.log_dir)
    service = WalletService(settings)
    result = service.inspect_public(
        args.address, chain=args.chain, include_puzzles=args.puzzles
    )
    _print(result)
    print("\nstatus:", summarize(service.tracker))
    return 0 if result["wallet"]["status"] == "✓" else 1


def cmd_status(args) -> int:
    settings = get_settings()
    setup_logging(settings.log_dir)
    service = WalletService(settings)
    _print({"capabilities": service.capabilities(),
            "statuses": service.tracker.compact()})
    return 0


def cmd_demo(args) -> int:
    """Offline end-to-end demo of the challenge/verify flow.

    Generates an ephemeral key **in-process only** to simulate a client-side
    wallet. No real wallet material is read from disk or the environment, and
    nothing is transmitted anywhere.
    """
    settings = get_settings()
    setup_logging(settings.log_dir)
    service = WalletService(settings)

    from eth_keys import keys

    private = keys.PrivateKey(bytes.fromhex("11" * 32))
    address = private.public_key.to_checksum_address()
    print(f"synthetic signer address: {address}")

    challenge = service.issue_challenge(address)
    print("⏳ challenge issued")

    from app.auth import personal_sign_hash

    signature = private.sign_msg_hash(personal_sign_hash(challenge["message"]))
    sig_hex = "0x" + signature.to_bytes().hex()

    result = service.verify(address, sig_hex, challenge["nonce"])
    print(f"{result.status} verification: verified={result.verified}")
    if result.verified:
        print(f"✓ session token issued for {result.address} "
              f"(expires {result.expires_at})")

    print("\nstatus:", summarize(service.tracker))
    return 0 if result.verified else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Hermes Wallet Inspector CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p_inspect = sub.add_parser("inspect", help="read-only public address lookup")
    p_inspect.add_argument("address")
    p_inspect.add_argument("--chain", default=None)
    p_inspect.add_argument("--puzzles", action="store_true",
                           help="also run MemePol puzzle comparison")
    p_inspect.set_defaults(func=cmd_inspect)

    p_status = sub.add_parser("status", help="show capability + status table")
    p_status.set_defaults(func=cmd_status)

    p_demo = sub.add_parser("demo", help="offline signature-flow self-test")
    p_demo.set_defaults(func=cmd_demo)

    p_scan = sub.add_parser(
        "scan", help="detect secret-shaped text (warn only, never stores)")
    p_scan.add_argument("text", nargs="?", default=None,
                        help="text to scan; omit to read stdin")
    p_scan.add_argument("--file", default=None, help="scan a file instead")
    p_scan.add_argument("--json", action="store_true",
                        help="machine-readable output")
    p_scan.set_defaults(func=cmd_scan)

    p_grant = sub.add_parser(
        "grant", help="manage paid/owner access (operator-only, local store)")
    p_grant.add_argument("action", choices=["grant", "revoke", "list", "tiers"])
    p_grant.add_argument("address", nargs="?", default="",
                         help="wallet address (for grant/revoke)")
    p_grant.add_argument("--tier", default="paid",
                         choices=["paid", "owner", "verified"])
    p_grant.add_argument("--days", type=int, default=None,
                         help="expire after N days (default: never)")
    p_grant.add_argument("--note", default="", help="free-text note")
    p_grant.add_argument("--json", action="store_true")
    p_grant.set_defaults(func=cmd_grant)

    p_inv = sub.add_parser(
        "inventory", help="print a metadata-only file listing (redacted)")
    p_inv.add_argument("roots", nargs="*", default=None,
                       help="roots to walk (default: INVENTORY_ROOTS or ~)")
    p_inv.add_argument("--depth", type=int, default=None)
    p_inv.add_argument("--max-files", type=int, default=None)
    p_inv.add_argument("--no-redact", action="store_true",
                       help="show real filenames (identifiers NOT masked)")
    p_inv.add_argument("--json", action="store_true")
    p_inv.add_argument("--hashes", action="store_true",
                       help="include sha256 for small files")
    p_inv.add_argument("--out", default=None, help="write listing to a file")
    p_inv.set_defaults(func=cmd_inventory)
    return parser


def cmd_scan(args) -> int:
    """Scan text (or a file) for secret-shaped strings. Never stores anything."""
    from .security import scan as _scan, warning_text

    if args.file:
        text = Path(args.file).read_text(errors="replace")
        source = args.file
    elif args.text is not None:
        text = args.text
        source = "<argument>"
    else:
        import sys as _sys
        text = _sys.stdin.read()
        source = "<stdin>"

    findings = _scan(text)

    if args.json:
        print(json.dumps({
            "source": source,
            "clean": not findings,
            "count": len(findings),
            "findings": [f.as_dict() for f in findings],
        }, indent=2))
    else:
        if not findings:
            print(f"✓ no secrets detected in {source}")
        else:
            print(warning_text(findings, app_name="hermes_bot_miniapp"))
            print()
            print(f"scanned: {source}  ({len(findings)} finding(s))")

    # Exit 1 when secrets are present so this is usable in shell pipelines.
    return 0 if not findings else 1


def cmd_grant(args) -> int:
    """Grant, revoke, or list paid access. Operator-only, local store."""
    from .access import EntitlementStore, tier_summary, TIER_LIMITS
    from .access import Tier

    settings = get_settings()
    store = EntitlementStore(
        settings.entitlements_path
        or (Path(settings.log_dir).parent / ".run" / "entitlements.json"))

    if args.action == "list":
        records = store.all()
        if args.json:
            print(json.dumps([r.as_dict() for r in records], indent=2))
        elif not records:
            print("· no entitlements granted")
        else:
            for r in records:
                state = "active" if r.is_active() else "expired"
                exp = "" if r.expires_at is None else f"  expires={int(r.expires_at)}"
                print(f"  {r.address}  tier={r.tier}  {state}{exp}"
                      f"{('  # ' + r.note) if r.note else ''}")
        return 0

    if args.action == "revoke":
        ok = store.revoke(args.address)
        print(f"{'✓ revoked' if ok else '· not found'}: {args.address}")
        return 0 if ok else 1

    if args.action == "tiers":
        for t in Tier:
            print(f"  {t.value:10} {json.dumps(tier_summary(t))}")
        return 0

    rec = store.grant(args.address, tier=args.tier, days=args.days,
                      note=args.note or "")
    print(f"✓ granted {rec.tier} to {rec.address}")
    if rec.expires_at:
        import datetime as _dt
        print(f"  expires {_dt.datetime.fromtimestamp(rec.expires_at):%Y-%m-%d}")
    print(f"  store: {store.path}")
    return 0


def cmd_inventory(args) -> int:
    """Print a metadata-only, redacted inventory of the configured roots."""
    from .inventory import build_inventory, render_listing, summarize

    settings = get_settings()
    roots = args.roots or list(settings.inventory_roots)
    redact = not args.no_redact

    result = build_inventory(
        roots,
        max_depth=args.depth or settings.inventory_max_depth,
        max_files=args.max_files or settings.inventory_max_files,
        hashes=args.hashes,
    )

    if args.json:
        print(json.dumps(summarize(result, redact=redact), indent=2))
        return 0

    text = render_listing(result, redact=redact)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"✓ wrote {args.out}  ({len(result.entries)} files)")
        if redact:
            print("  identifiers masked; pass --no-redact for real names")
    else:
        print(text)
    return 0


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
