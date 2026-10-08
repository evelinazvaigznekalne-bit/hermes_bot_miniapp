"""Secret-shape detection — warn, never store.

This is the *inverse* of a harvesting feature. Where a credential-harvesting
implementation would capture what a user pastes and keep it, this module:

  * detects secret-shaped input (private keys, seed phrases, WIF, API keys),
  * returns a warning and a redacted preview,
  * and never persists, logs, or transmits the matched value.

Nothing here writes to disk, a database, or a log. The matched secret is
replaced with a masked placeholder before it can leave this function.

Design rule: `scan()` is pure. It takes text, returns a finding. Callers decide
what to do, and the only supported action is to show the warning.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

#: BIP-39 English wordlist size and the standard mnemonic lengths.
_BIP39_SIZES = (12, 15, 18, 21, 24)


def _load_bip39() -> frozenset:
    """Load the official BIP-39 English wordlist shipped alongside this module."""
    path = Path(__file__).resolve().parent / "data" / "bip39_english.txt"
    try:
        return frozenset(
            w.strip().lower() for w in path.read_text().splitlines() if w.strip()
        )
    except OSError:  # pragma: no cover - fall back to shape-only detection
        return frozenset()


_BIP39_WORDS = _load_bip39()


@dataclass
class SecretFinding:
    """A detected secret-shaped string. The value is NEVER stored."""

    kind: str
    label: str
    severity: str          # "critical" | "high" | "medium"
    redacted: str          # masked preview, safe to display/log
    advice: str
    span: Optional[tuple] = None   # (start, end) in the scanned text
    meta: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "kind": self.kind,
            "label": self.label,
            "severity": self.severity,
            "redacted": self.redacted,
            "advice": self.advice,
        }


def mask(value: str, *, keep: int = 4) -> str:
    """Mask a secret for display. Never returns enough to reconstruct it."""
    v = value.strip()
    if len(v) <= keep * 2:
        return "•" * len(v)
    return f"{v[:keep]}{'•' * 8}{v[-keep:]}  ({len(v)} chars)"


# --- patterns ---------------------------------------------------------------
# Each entry: (kind, label, severity, compiled regex, advice)
_PATTERNS = [
    (
        "evm_private_key", "Ethereum / EVM private key", "critical",
        re.compile(r"\b(?:0x)?(?=[0-9a-fA-F]{64}\b)([0-9a-fA-F]{64})\b"),
        "This is a raw EVM private key. Anyone holding it controls the wallet "
        "completely. Never share it. If you pasted it anywhere, move the funds to a "
        "new wallet immediately and treat the old one as burned.",
    ),
    (
        "bitcoin_wif", "Bitcoin WIF private key", "critical",
        re.compile(r"\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b"),
        "This is a Bitcoin private key in WIF format. It grants full control of the "
        "address. Never share it; move funds to a new wallet if it was exposed.",
    ),
    (
        "bip39_mnemonic", "Seed phrase (BIP-39)", "critical",
        re.compile(r"\b(?:\w{3,8}[ \t]+){11,23}\w{3,8}\b"),
        "This looks like a seed phrase. It restores your entire wallet and all "
        "derived addresses. No legitimate app ever needs it. If exposed, move funds "
        "to a freshly generated wallet.",
    ),
    (
        "telegram_bot_token", "Telegram bot token", "critical",
        re.compile(r"\b\d{8,12}:[A-Za-z0-9_-]{30,40}\b"),
        "This is a Telegram bot token. Anyone with it controls your bot, can read "
        "its messages, and can impersonate it. Revoke it in @BotFather "
        "(/mybots -> API Token -> Revoke) and issue a new one.",
    ),
    (
        "xprv", "Extended private key (xprv/yprv/zprv)", "critical",
        re.compile(r"\b[xyzYZ]prv[1-9A-HJ-NP-Za-km-z]{100,120}\b"),
        "This is an extended private key (BIP-32). It derives every key in the "
        "account hierarchy. Never share it.",
    ),
    (
        "openai_key", "OpenAI API key", "high",
        re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
        "API key detected. Revoke it in the provider dashboard and rotate. Treat as "
        "compromised if it was pasted anywhere.",
    ),
    (
        "stripe_key", "Stripe secret key", "high",
        re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b"),
        "Stripe secret key. Grants payment access on your account. Roll it "
        "immediately in the Stripe dashboard.",
    ),
    (
        "generic_api_key", "API key (vendor-prefixed)", "high",
        re.compile(r"\b(?:apisio|pre77|pk|api)[_-](?:live|sk|key)[_-][A-Za-z0-9_-]{16,}\b"),
        "Vendor API key detected. Rotate it and avoid pasting keys into chats or "
        "logs.",
    ),
    (
        "aws_key", "AWS access key ID", "high",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        "AWS access key ID. Rotate the corresponding secret in IAM immediately.",
    ),
    (
        "jwt", "JSON Web Token", "medium",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        "A JWT was detected. It may grant session access until it expires. Do not "
        "paste tokens into chats or issue trackers.",
    ),
    (
        "pem_private_key", "PEM private key block", "critical",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
        "A PEM private key block was detected. Never share it; regenerate the key "
        "pair if exposed.",
    ),
    (
        "card_number", "Payment card number (Luhn-valid)", "high",
        re.compile(r"\b(?:\d[ -]?){13,19}\b"),
        "A number matching payment-card format was detected. Do not enter card "
        "details into unofficial tools. If this is your own card and it was exposed, "
        "contact your bank.",
    ),
]


def _luhn_ok(digits: str) -> bool:
    d = [int(c) for c in digits if c.isdigit()]
    if not 13 <= len(d) <= 19:
        return False
    total, parity = 0, len(d) % 2
    for i, n in enumerate(d):
        if i % 2 == parity:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _mnemonic_plausible(text: str, span: tuple) -> bool:
    """Check word count AND membership in the real BIP-39 wordlist.

    Shape alone is far too weak: "the quick brown fox jumps over the lazy dog
    again and again" is 12 short words but is plainly not a mnemonic. Requiring
    every word to be in the 2048-word list removes almost all false positives.
    """
    words = re.findall(r"[a-z]+", text[span[0]:span[1]].lower())
    if len(words) not in _BIP39_SIZES:
        return False
    if not _BIP39_WORDS:  # wordlist unavailable: fall back to shape only
        return True
    return all(w in _BIP39_WORDS for w in words)


def scan(text: str, *, max_findings: int = 10) -> List[SecretFinding]:
    """Detect secret-shaped strings. Pure function — stores nothing.

    The returned findings contain only masked previews. The original matched
    value is deliberately discarded.
    """
    if not text:
        return []

    findings: List[SecretFinding] = []
    seen_spans: List[tuple] = []

    for kind, label, severity, rx, advice in _PATTERNS:
        for m in rx.finditer(text):
            span = m.span()
            # skip overlaps with an earlier, more specific match
            if any(s < span[1] and span[0] < e for s, e in seen_spans):
                continue

            raw = m.group(0)

            if kind == "card_number" and not _luhn_ok(raw):
                continue
            if kind == "bip39_mnemonic" and not _mnemonic_plausible(text, span):
                continue
            # a 64-hex string is more likely a tx hash than a key; still flag,
            # but only when it is NOT part of a longer hex run.
            # NOTE: guard against the empty string - `"" in "0123abc"` is True
            # in Python, which would skip a key sitting at the very start.
            if kind == "evm_private_key":
                before = text[span[0] - 1:span[0]] if span[0] > 0 else ""
                after = text[span[1]:span[1] + 1]
                hexdigits = "0123456789abcdefABCDEF"
                if before and before in hexdigits:
                    continue
                if after and after in hexdigits:
                    continue

            seen_spans.append(span)
            findings.append(SecretFinding(
                kind=kind, label=label, severity=severity,
                redacted=mask(raw), advice=advice, span=span,
            ))
            if len(findings) >= max_findings:
                return findings

    order = {"critical": 0, "high": 1, "medium": 2}
    findings.sort(key=lambda f: order.get(f.severity, 3))
    return findings


def warning_text(findings: List[SecretFinding], *, app_name: str = "this app") -> str:
    """Human-readable warning. Contains only masked values."""
    if not findings:
        return ""
    lines = [
        "⚠️  SECRET DETECTED — NOT STORED",
        "",
        f"{app_name} does not need this and has not saved it.",
        "",
    ]
    for f in findings:
        lines.append(f"  [{f.severity.upper()}] {f.label}")
        lines.append(f"      {f.redacted}")
        lines.append(f"      {f.advice}")
        lines.append("")
    lines.append("This app never asks for seed phrases or private keys.")
    return "\n".join(lines)
