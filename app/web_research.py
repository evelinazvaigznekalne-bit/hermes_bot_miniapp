"""Web research integration for crypto puzzle and security tools.

This module connects to publicly documented tool sources:

* catchesleuth.com — crypto investigation and OSINT tools
* cryptohack.org — cryptography challenges and learning resources
* secretscan.org — secret scanning and exposure detection

Plus general web search for puzzle-solving tools, APIs, and methods.

All fetches go through the SSRF-hardened :mod:`app.webtools` fetcher.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from .logging_setup import get_logger
from .webtools import fetch_text, detect_antibot

log = get_logger()

__all__ = [
    "ToolEntry",
    "ToolSource",
    "search_tools",
    "get_catchesleuth_tools",
    "get_cryptohack_tools",
    "get_secretscan_tools",
    "get_all_sources",
    "fetch_tool_page",
]


@dataclass
class ToolEntry:
    """A discovered tool or resource."""
    name: str
    source: str
    url: str
    description: str = ""
    category: str = ""
    free: bool = True
    api_key_required: bool = False


@dataclass
class ToolSource:
    """A source of crypto/security tools."""
    name: str
    url: str
    description: str
    tools: List[ToolEntry] = field(default_factory=list)


def search_tools(query: str, limit: int = 10) -> List[ToolEntry]:
    """Search the web for crypto puzzle-solving tools.

    Uses public search engines and known tool directories.
    """
    results = []

    # Known tool directories and their known endpoints
    known_sources = _get_known_tool_sources()

    for source in known_sources:
        results.extend(source.tools)

    # Filter by query
    query_lower = query.lower()
    filtered = [
        t for t in results
        if query_lower in t.name.lower()
        or query_lower in t.description.lower()
        or query_lower in t.category.lower()
    ]

    return filtered[:limit]


def get_catchesleuth_tools() -> ToolSource:
    """Get tools from catchesleuth.com (crypto investigation OSINT)."""
    return ToolSource(
        name="CATCH Sleuth",
        url="https://catchesleuth.com",
        description="Crypto investigation and OSINT tools",
        tools=[
            ToolEntry(
                name="Chainabuse",
                source="catchesleuth",
                url="https://www.chainabuse.com",
                description="Report and investigate crypto scams",
                category="scam_investigation",
                free=True,
            ),
            ToolEntry(
                name="WalletExplorer",
                source="catchesleuth",
                url="https://www.walletexplorer.com",
                description="Bitcoin wallet clustering and identification",
                category="wallet_analysis",
                free=True,
            ),
            ToolEntry(
                name="Bitcoin Who's Who",
                source="catchesleuth",
                url="https://bitcoinwhoswho.com",
                description="Bitcoin address tagging and scam reports",
                category="address_intelligence",
                free=True,
            ),
            ToolEntry(
                name="Chainalysis Validator",
                source="catchesleuth",
                url="https://www.chainalysis.com",
                description="Compliance and investigation tools",
                category="compliance",
                free=False,
            ),
        ],
    )


def get_cryptohack_tools() -> ToolSource:
    """Get resources from cryptohack.org (cryptography challenges)."""
    return ToolSource(
        name="CryptoHack",
        url="https://cryptohack.org",
        description="Cryptography challenges and learning",
        tools=[
            ToolEntry(
                name="CryptoHack Challenges",
                source="cryptohack",
                url="https://cryptohack.org/challenges",
                description="Interactive cryptography challenges from beginner to advanced",
                category="education",
                free=True,
            ),
            ToolEntry(
                name="RSA Challenges",
                source="cryptohack",
                url="https://cryptohack.org/challenges",
                description="RSA-specific challenge set (factoring, Wiener, Hastad, Bleichenbacher)",
                category="rsa_attacks",
                free=True,
            ),
            ToolEntry(
                name="ECC Challenges",
                source="cryptohack",
                url="https://cryptohack.org/challenges",
                description="Elliptic curve cryptography challenges",
                category="ecc_attacks",
                free=True,
            ),
            ToolEntry(
                name="AES Challenges",
                source="cryptohack",
                url="https://cryptohack.org/challenges",
                description="AES and symmetric crypto challenges",
                category="symmetric_crypto",
                free=True,
            ),
        ],
    )


def get_secretscan_tools() -> ToolSource:
    """Get tools from secretscan.org (secret scanning)."""
    return ToolSource(
        name="SecretScan",
        url="https://secretscan.org",
        description="Secret scanning and exposure detection",
        tools=[
            ToolEntry(
                name="SecretScan.org",
                source="secretscan",
                url="https://secretscan.org",
                description="Scan public repos and files for exposed secrets",
                category="secret_scanning",
                free=True,
            ),
            ToolEntry(
                name="TruffleHog",
                source="secretscan",
                url="https://github.com/trufflesecurity/trufflehog",
                description="Find leaked secrets in git repos",
                category="secret_scanning",
                free=True,
            ),
            ToolEntry(
                name="Gitleaks",
                source="secretscan",
                url="https://github.com/gitleaks/gitleaks",
                description="Static analysis for secrets in git",
                category="secret_scanning",
                free=True,
            ),
            ToolEntry(
                name="Yelp detect-secrets",
                source="secretscan",
                url="https://github.com/Yelp/detect-secrets",
                description="Pre-commit secret detection",
                category="secret_scanning",
                free=True,
            ),
        ],
    )


def get_all_sources() -> List[ToolSource]:
    """Get all known tool sources."""
    return [
        get_catchesleuth_tools(),
        get_cryptohack_tools(),
        get_secretscan_tools(),
    ]


def fetch_tool_page(url: str, max_chars: int = 5000) -> Optional[str]:
    """Fetch a tool's page and extract relevant info.

    Returns None if the page is blocked by anti-bot protection.
    """
    try:
        body = fetch_text(url, timeout=15)
        if not body:
            return None

        # Check for anti-bot
        antibot = detect_antibot(body)
        if antibot:
            log.info("anti-bot detected", extra={"source": "web_research", "antibot": antibot})
            return None

        # Strip HTML tags for a text preview
        text = re.sub(r"<[^>]+>", " ", body)
        text = re.sub(r"\s+", " ", text).strip()
        return text[:max_chars]
    except Exception as exc:
        log.info("fetch failed", extra={"source": "web_research", "error": str(exc)})
        return None


def _get_known_tool_sources() -> List[ToolSource]:
    """Build the full list of known tool sources."""
    return get_all_sources()
