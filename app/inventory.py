"""Printable inventory of the files this project works with.

Answers one question: *what is actually on this device?* It walks a set of
configured roots, classifies each file, and emits a listing that is safe to
print, paste, or hand to someone else.

Two hard rules:

  * **No file contents are ever read into the listing.** Metadata only —
    name, size, mtime, kind. For small files an optional SHA-256 is computed
    by streaming, and only the digest is kept.
  * **Names are redacted by default.** Wallet addresses, key-shaped tokens,
    and long hex strings embedded in filenames are masked, because a filename
    like ``1F654t1HxrZtg7uhcXyZeFvRsyB8HCnBXJ.dat`` leaks the target address.
    Redaction can be turned off explicitly, but it is on unless asked
    otherwise.

The walk is bounded (depth, file count, skipped directories) so it cannot hang
on a Termux home directory full of ``node_modules``.
"""

from __future__ import annotations

import hashlib
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .logging_setup import get_logger

log = get_logger()

#: Directories that are never worth listing and can be huge.
SKIP_DIRS = frozenset({
    ".git", "node_modules", "__pycache__", ".pytest_cache", "site-packages",
    ".npm", ".npmcache", ".npmtmp", ".cargo", ".cache", "dist", "build",
    ".venv", "venv", ".mypy_cache", ".ruff_cache", ".hermes",
})

#: Wallet-shaped extensions.
WALLET_EXTS = frozenset({".dat", ".data", ".wallet", ".key", ".keys"})

#: Document extensions.
DOC_EXTS = frozenset({".pdf", ".docx", ".doc", ".xlsx", ".csv", ".md", ".rtf",
                      ".txt"})

#: Executable/source extensions.
CODE_EXTS = frozenset({".py", ".sh", ".js", ".mjs", ".ts", ".json", ".yaml",
                       ".yml", ".toml", ".ini", ".cfg"})

#: Categories, in display order.
CATEGORIES = (
    "wallet", "wordlist", "puzzle", "osint", "log", "document", "code",
    "archive", "image", "other",
)

ARCHIVE_EXTS = frozenset({".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar"})
IMAGE_EXTS = frozenset({".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"})

#: Default roots: the places this project actually cares about.
DEFAULT_ROOTS = (
    "~",
)

#: How long a single inventory run may take before it stops early.
DEFAULT_TIME_BUDGET = 20.0
DEFAULT_MAX_FILES = 4000
DEFAULT_MAX_DEPTH = 3


# --- redaction --------------------------------------------------------------

_BASE58_RE = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,39}\b")
_BECH32_RE = re.compile(r"\b(?:bc1|tb1)[02-9ac-hj-np-z]{11,71}\b")
_EVM_ADDR_RE = re.compile(r"\b0x[0-9a-fA-F]{40}\b")
_HEX32_RE = re.compile(r"\b[0-9a-fA-F]{32,}\b")
_ONION_RE = re.compile(r"\b[a-z2-7]{16,56}\.onion\b")
_IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")


def redact_name(name: str) -> str:
    """Mask identifiers embedded in a filename.

    ``1F654t1HxrZtg7uhcXyZeFvRsyB8HCnBXJ.dat`` becomes
    ``1F654…CnBXJ.dat`` — enough to recognise the file, not enough to reuse
    the address as a lookup key.
    """
    def _mask(match: re.Match) -> str:
        v = match.group(0)
        if len(v) <= 10:
            return "•" * len(v)
        return f"{v[:6]}…{v[-5:]}"

    out = name
    for rx in (_EVM_ADDR_RE, _BECH32_RE, _BASE58_RE, _ONION_RE, _HEX32_RE):
        out = rx.sub(_mask, out)
    out = _IPV4_RE.sub(_mask, out)
    out = _EMAIL_RE.sub(_mask, out)
    return out


def redact_value(value: str, *, keep: int = 6) -> str:
    """Mask a standalone identifier (used for addresses in summaries)."""
    v = (value or "").strip()
    if not v:
        return ""
    if len(v) <= keep + 4:
        return "•" * len(v)
    return f"{v[:keep]}…{v[-4:]}"


# --- model ------------------------------------------------------------------

@dataclass
class FileEntry:
    """One file. Metadata only — never contents."""

    path: str            # relative to the root it was found under
    root: str            # which root produced it
    name: str            # redacted basename
    raw_name: str        # original basename (only returned when redaction off)
    category: str
    size: int
    mtime: float
    sha256: Optional[str] = None
    note: str = ""

    def as_dict(self, *, redact: bool = True) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "name": self.name if redact else self.raw_name,
            "category": self.category,
            "size": self.size,
            "size_human": human_size(self.size),
            "modified": time.strftime("%Y-%m-%d %H:%M",
                                      time.localtime(self.mtime)),
            "sha256": self.sha256,
        }
        if not redact:
            out["path"] = self.path
            out["root"] = self.root
        if self.note:
            out["note"] = self.note
        return out


def human_size(n: int) -> str:
    step = 1024.0
    value = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < step or unit == "TB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= step
    return f"{value:.1f} TB"


def classify(path: Path, name: str) -> Tuple[str, str]:
    """Return ``(category, note)`` for a file."""
    ext = path.suffix.lower()
    low = name.lower()

    if ext in WALLET_EXTS:
        return "wallet", "wallet-shaped file (encrypted Berkeley DB or unknown)"
    if "wordlist" in low or "rockyou" in low or "pwd" in low or "password" in low:
        return "wordlist", "password/word list"
    if "puzzle" in low or "ocp" in low or "bounty" in low or "treasure" in low:
        return "puzzle", "puzzle corpus data"
    if "sweep" in low or "chunk" in low or "seed_variation" in low:
        return "wordlist", "sweep input list"
    if ext == ".log" or low.endswith(".out") or "log" in low:
        return "log", "run log"
    if low.startswith("@") or "telegram" in low or "keyhunters" in low:
        return "osint", "Telegram OSINT export"
    # Notes ABOUT wallets/escrows are OSINT, but only when they are documents —
    # the explicit parens matter: without them the `and` binds to the last
    # clause only, and "allinfo"/"escrow" would match any extension.
    if ext in DOC_EXTS and (
        "allinfo" in low or "escrow" in low or "wallet" in low
    ):
        return "osint", "wallet/infrastructure notes"
    if ext in ARCHIVE_EXTS:
        return "archive", "archive"
    if ext in IMAGE_EXTS:
        return "image", "image"
    if ext in DOC_EXTS:
        return "document", "document"
    if ext in CODE_EXTS:
        return "code", "source/config"
    return "other", ""


def _sha256(path: Path, limit: int = 8 * 1024 * 1024) -> Optional[str]:
    """Streaming digest for files up to ``limit`` bytes."""
    try:
        if path.stat().st_size > limit:
            return None
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for block in iter(lambda: fh.read(65536), b""):
                h.update(block)
        return h.hexdigest()
    except OSError:
        return None


# --- walk -------------------------------------------------------------------

@dataclass
class InventoryResult:
    entries: List[FileEntry] = field(default_factory=list)
    roots: List[str] = field(default_factory=list)
    truncated: bool = False
    elapsed: float = 0.0
    scanned: int = 0
    errors: List[str] = field(default_factory=list)

    # -- aggregation ------------------------------------------------------
    def by_category(self) -> Dict[str, int]:
        out: Dict[str, int] = {c: 0 for c in CATEGORIES}
        for e in self.entries:
            out[e.category] = out.get(e.category, 0) + 1
        return {k: v for k, v in out.items() if v}

    def total_bytes(self) -> int:
        return sum(e.size for e in self.entries)

    def as_dict(self, *, redact: bool = True) -> Dict[str, Any]:
        return {
            "roots": [redact_value(r) if redact else r for r in self.roots],
            "count": len(self.entries),
            "scanned": self.scanned,
            "total_bytes": self.total_bytes(),
            "total_human": human_size(self.total_bytes()),
            "truncated": self.truncated,
            "elapsed_seconds": round(self.elapsed, 2),
            "by_category": self.by_category(),
            "errors": self.errors[:5],
            "entries": [e.as_dict(redact=redact) for e in self.entries],
        }


def _expand(root: str) -> Path:
    return Path(os.path.expanduser(root)).resolve()


def build_inventory(roots: Sequence[str] = DEFAULT_ROOTS, *,
                    max_depth: int = DEFAULT_MAX_DEPTH,
                    max_files: int = DEFAULT_MAX_FILES,
                    time_budget: float = DEFAULT_TIME_BUDGET,
                    hashes: bool = True,
                    include_hidden: bool = False) -> InventoryResult:
    """Walk ``roots`` and build a metadata-only inventory.

    Bounded in three ways (depth, file count, wall clock) so it always
    returns, even on a pathological directory tree.
    """
    started = time.time()
    result = InventoryResult(roots=[str(_expand(r)) for r in roots])
    resolved_roots = [_expand(r) for r in roots]

    for root in resolved_roots:
        if not root.exists():
            result.errors.append(f"root not found: {redact_value(str(root))}")
            continue

        base_depth = len(root.parts)
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            if time.time() - started > time_budget:
                result.truncated = True
                result.errors.append("time budget exceeded; listing is partial")
                break
            if len(result.entries) >= max_files:
                result.truncated = True
                result.errors.append("file limit reached; listing is partial")
                break

            here = Path(dirpath)
            depth = len(here.parts) - base_depth
            if depth >= max_depth:
                dirnames[:] = []
            else:
                dirnames[:] = sorted(
                    d for d in dirnames
                    if d not in SKIP_DIRS and (include_hidden or not d.startswith("."))
                )

            for fn in sorted(filenames):
                if len(result.entries) >= max_files:
                    result.truncated = True
                    break
                if not include_hidden and fn.startswith("."):
                    continue
                full = here / fn
                try:
                    st = full.stat()
                except OSError:
                    continue
                if not full.is_file():
                    continue

                result.scanned += 1
                rel = str(full.relative_to(root)) if root in full.parents or full != root else fn
                category, note = classify(full, fn)
                entry = FileEntry(
                    path=rel,
                    root=str(root),
                    name=redact_name(fn),
                    raw_name=fn,
                    category=category,
                    size=st.st_size,
                    mtime=st.st_mtime,
                    note=note,
                )
                if hashes and st.st_size <= 8 * 1024 * 1024:
                    entry.sha256 = _sha256(full)
                result.entries.append(entry)

        if result.truncated:
            break

    result.entries.sort(key=lambda e: (CATEGORIES.index(e.category)
                                       if e.category in CATEGORIES else 99,
                                       -e.size))
    result.elapsed = time.time() - started
    log.info("inventory built",
             extra={"component": "inventory", "status": "✓",
                    "detail": f"{len(result.entries)} files in "
                              f"{result.elapsed:.1f}s"})
    return result


# --- printable rendering ----------------------------------------------------

def render_listing(result: InventoryResult, *, redact: bool = True,
                   max_rows: int = 400) -> str:
    """Render a plain-text listing suitable for printing or pasting.

    Contains no file contents and no unredacted identifiers unless
    ``redact=False`` was explicitly requested.
    """
    lines: List[str] = []
    lines.append("HERMES FILE INVENTORY")
    lines.append("=" * 62)
    lines.append(f"generated   {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"redaction   {'ON (identifiers masked)' if redact else 'OFF'}")
    lines.append(f"files       {len(result.entries)} listed, "
                 f"{result.scanned} scanned")
    lines.append(f"size        {human_size(result.total_bytes())} total")
    lines.append(f"elapsed     {result.elapsed:.1f}s"
                 + ("   [PARTIAL]" if result.truncated else ""))
    lines.append("")

    counts = result.by_category()
    lines.append("BY CATEGORY")
    lines.append("-" * 62)
    for cat in CATEGORIES:
        if cat in counts:
            lines.append(f"  {cat:<10} {counts[cat]:>5}")
    lines.append("")

    current = None
    shown = 0
    for entry in result.entries:
        if entry.category != current:
            current = entry.category
            lines.append("")
            lines.append(f"{current.upper()}")
            lines.append("-" * 62)
        if shown >= max_rows:
            lines.append(f"  … {len(result.entries) - shown} more "
                         f"(raise max_rows to see them)")
            break
        name = entry.name if redact else entry.raw_name
        digest = f"  sha256:{entry.sha256[:12]}…" if entry.sha256 else ""
        lines.append(f"  {name:<44} {human_size(entry.size):>9}  "
                     f"{time.strftime('%Y-%m-%d', time.localtime(entry.mtime))}"
                     f"{digest}")
        shown += 1

    if result.errors:
        lines.append("")
        lines.append("NOTES")
        lines.append("-" * 62)
        for err in result.errors:
            lines.append(f"  ! {err}")

    lines.append("")
    lines.append("Metadata only — no file contents were read into this listing.")
    return "\n".join(lines)


def summarize(result: InventoryResult, *, redact: bool = True) -> Dict[str, Any]:
    """Compact summary for an API response or a chat message."""
    counts = result.by_category()
    return {
        "count": len(result.entries),
        "total_human": human_size(result.total_bytes()),
        "truncated": result.truncated,
        "by_category": counts,
        "redacted": redact,
        "headline": ", ".join(f"{k}: {v}" for k, v in counts.items()),
    }
