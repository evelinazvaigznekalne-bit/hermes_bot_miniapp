"""Security Research module — bug bounty methodology + opportunity scanner.

Provides the structured workflow for security research:
1. Define target
2. Surface mapping (OSINT)
3. Data collection
4. Analysis & matching
5. Report + submit to bounty
"""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class ResearchStep:
    """One step in the security research workflow."""
    id: str
    title: str
    description: str
    tools: List[str] = field(default_factory=list)
    tips: List[str] = field(default_factory=list)
    example: str = ""


@dataclass
class ResearchTarget:
    """A target for security research."""
    name: str
    target_type: str  # "contract", "protocol", "api", "web"
    url: str = ""
    repo: str = ""
    max_bounty: str = ""
    kyc_required: bool = False
    scope: List[str] = field(default_factory=list)
    notes: str = ""


# ------------------------------------------------------------- workflow ----

RESEARCH_WORKFLOW: List[ResearchStep] = [
    ResearchStep(
        id="define",
        title="1. Define Target",
        description=(
            "Identify what you are auditing and what is in scope. "
            "Read the documentation, understand the protocol's purpose, "
            "and map the attack surface."
        ),
        tools=["Documentation", "Source code", "Previous audits"],
        tips=[
            "Check if the protocol has been audited before — prior findings are learning material",
            "Identify the invariant: what must ALWAYS be true for the system to be secure",
            "Note the chains, token standards, and external dependencies",
        ],
        example=(
            "Target: ENS DNSRegistrar\n"
            "Invariant: Only the owner of a DNS name can claim the corresponding ENS record\n"
            "Scope: DNSSECImpl, DNSClaimChecker, OffchainDNSResolver"
        ),
    ),
    ResearchStep(
        id="surface",
        title="2. Surface Mapping (OSINT)",
        description=(
            "Map the attack surface: entry points, external calls, "
            "privileged roles, and data flows. Build a mental model of "
            "where trust boundaries are crossed."
        ),
        tools=["Source code review", "Function call graphs", "Access control analysis"],
        tips=[
            "List every external entry point (public/external functions)",
            "Identify who can call each function (access control)",
            "Trace data flow: where does untrusted input enter?",
            "Look for oracle dependencies, upgrade patterns, and proxy patterns",
        ],
        example=(
            "Entry points: verifyRRSet(), claim(), resolveCallback()\n"
            "Privileged: owner-only functions, admin setters\n"
            "External calls: ENS registry, DNS resolvers"
        ),
    ),
    ResearchStep(
        id="collect",
        title="3. Data Collection",
        description=(
            "Gather on-chain data, transaction histories, and deployment "
            "parameters. Build a dataset of normal vs. anomalous behavior."
        ),
        tools=["eth.blockscout.com", "mempool.space", "Tenderly", "Dune Analytics"],
        tips=[
            "Check contract verification status on the block explorer",
            "Analyze recent transactions for unusual patterns",
            "Compare with similar protocols — what invariants do they enforce?",
            "Look for edge cases: empty inputs, zero values, max values, reentrancy",
        ],
        example=(
            "Deployed at: 0x164af34fAF9879394370C7f09064127C043A35E9\n"
            "Verified: Yes\n"
            "Transactions analyzed: 1,247\n"
            "Anomalies: 3 failed claims with malformed DNS data"
        ),
    ),
    ResearchStep(
        id="analyze",
        title="4. Analysis & Matching",
        description=(
            "Systematically test each entry point against the invariant. "
            "Prove reachability before claiming a finding. "
            "A confirmed-but-unreachable bug is NOT a finding."
        ),
        tools=["Foundry (forge)", "Ganache", "Manual reasoning", "Proof of concept"],
        tips=[
            "For every candidate bug, ask: is it reachable from a permissionless entry point?",
            "Check upstream guards — does a parent function block the vulnerable path?",
            "Verify the algebra: a comment claiming a guarantee is not proof",
            "Test on a local fork before submitting",
        ],
        example=(
            "Candidate: ecrecover returns address(0) for invalid sigs\n"
            "Reachable? NO — the only path requires a valid ERC-6492 suffix\n"
            "Verdict: NOT reportable (unreachable via real entry points)"
        ),
    ),
    ResearchStep(
        id="report",
        title="5. Report & Submit",
        description=(
            "Write a clear, reproducible report. Include: "
            "summary, impact, proof of concept, affected code, "
            "and recommended fix. Submit to the bounty platform."
        ),
        tools=["Code4rena", "Cantina", "Immunefi", "Sherlock"],
        tips=[
            "A report without a PoC is a hypothesis, not a finding",
            "Show the exact transaction that triggers the bug",
            "Quantify impact: what can an attacker steal or break?",
            "Suggest a concrete fix, not just 'add validation'",
            "Check submission deposits — some platforms charge per report",
        ],
        example=(
            "Severity: High\n"
            "Impact: Attacker can claim any ENS name without DNS ownership\n"
            "PoC: Transaction 0xabc...123 calls claim() with forged DNS data\n"
            "Fix: require(input.length > 0) in verifyRRSet()"
        ),
    ),
]


# ---------------------------------------------------- opportunity scan ----

def scan_opportunities() -> Dict[str, Any]:
    """Run the opportunity scanner and return parsed results."""
    script_path = Path.home() / ".hermes" / "scripts" / "scan_opportunities.py"
    if not script_path.exists():
        return {
            "status": "unavailable",
            "detail": "Scanner script not found at ~/.hermes/scripts/scan_opportunities.py",
            "opportunities": [],
        }

    try:
        result = subprocess.run(
            ["python3", str(script_path), "--json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            return {
                "status": "ok",
                "detail": f"Found {len(data.get('opportunities', []))} open opportunities",
                "opportunities": data.get("opportunities", []),
            }
    except Exception as exc:
        return {
            "status": "error",
            "detail": str(exc),
            "opportunities": [],
        }

    return {
        "status": "error",
        "detail": "Scanner returned non-zero exit code",
        "opportunities": [],
    }


# --------------------------------------------------------- API handlers ----

def get_workflow() -> Dict[str, Any]:
    """Return the full research workflow."""
    return {
        "status": "ok",
        "workflow": [
            {
                "id": step.id,
                "title": step.title,
                "description": step.description,
                "tools": step.tools,
                "tips": step.tips,
                "example": step.example,
            }
            for step in RESEARCH_WORKFLOW
        ],
    }


def get_opportunities() -> Dict[str, Any]:
    """Return current bounty opportunities."""
    return scan_opportunities()


def get_methodology() -> Dict[str, Any]:
    """Return the complete methodology for the Security Research module."""
    return {
        "status": "ok",
        "workflow": get_workflow(),
        "opportunities": get_opportunities(),
        "pitfalls": [
            "A confirmed-but-unreachable bug is NOT a finding",
            "bytes4(v) on short revert data zero-pads in solc >=0.8 — can never equal a real selector",
            "A comment claiming a guarantee is not proof — verify the algebra",
            "Check upstream guards before reporting — the vulnerable path may be blocked",
            "Submission deposits are real per-report costs — a $100 deposit per attempt adds up",
            "Headline bounty figures are CAPS, not prize pools",
        ],
        "data_sources": {
            "superteam": "https://earn.superteam.fun/api/listings?status=open",
            "sherlock": "https://mainnet-contest.sherlock.xyz/contests",
            "cantina": "https://cantina.xyz/opportunities/{competitions,bounties}",
            "immunefi": "https://immunefi.com/bug-bounty/",
            "code4rena": "https://code4rena.com/audits",
        },
    }
