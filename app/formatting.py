"""Telegram message formatter — box-drawing, tool calls, diffs, and structured output.

Builds Telegram HTML messages with box-drawing characters inside <pre> tags.
Telegram supports <pre> for monospace blocks, which renders box characters cleanly.
"""

from __future__ import annotations

import html
from typing import Any, Dict, List, Optional, Tuple


def esc(text: Any) -> str:
    """Escape HTML special characters for Telegram HTML parsing."""
    return html.escape(str(text)) if text is not None else ""


def box(title: str, lines: List[str], width: int = 42) -> str:
    """Build a box-drawing block for Telegram <pre>."""
    bar = "─" * width
    out = [f"┌─ {esc(title)} {bar[:max(1, width - len(title) - 1)]}┐"]
    for line in lines:
        padded = line.ljust(width)[:width]
        out.append(f"│ {padded}│")
    out.append(f"└{'─' * (width + 2)}┘")
    return "\n".join(out)


def tool_call(name: str, status: str = "✓", detail: str = "") -> str:
    """Render a single tool call line."""
    icon = "●" if status == "✓" else "○" if status == "⏳" else "✗"
    line = f" {icon} {name}  {status}"
    if detail:
        line += f" {detail}"
    return line


def tool_block(calls: List[Tuple[str, str, str]], title: str = "Data Sources") -> str:
    """Render a block of tool calls."""
    lines = [tool_call(name, status, detail) for name, status, detail in calls]
    return box(title, lines)


def diff_line(kind: str, text: str) -> str:
    """Render a diff-style line: + added, - removed, ? info."""
    prefix = {"+": "  + ", "-": "  - ", "?": "  ? "}.get(kind, "  ? ")
    return f"{prefix}{esc(text)}"


def diff_block(changes: List[Tuple[str, str]], title: str = "Analysis") -> str:
    """Render a diff-style block."""
    lines = [diff_line(kind, text) for kind, text in changes]
    return box(title, lines)


def verdict(positive: bool, title: str, reason: str, next_steps: List[str]) -> str:
    """Render a verdict block with explanation and next steps."""
    icon = "✓" if positive else "❌"
    lines = [
        "",
        f" {icon} {title}",
        "",
        f" Why: {reason}",
        "",
    ]
    for step in next_steps:
        lines.append(f"  → {step}")
    lines.append("")
    return box("Result", lines)


def asset_table(assets: List[Dict[str, Any]]) -> str:
    """Render asset balances as a table."""
    if not assets:
        return box("Assets", ["", " No assets found", ""])
    lines = []
    for a in assets:
        sym = a.get("symbol", "?")
        amt = a.get("amount", "0")
        kind = a.get("kind", "")
        lines.append(f" {sym:<12} {amt:>18} {kind}")
    return box("Assets", lines)


def puzzle_verdict(matches: List[Dict[str, Any]], evaluated: int) -> str:
    """Render puzzle match results."""
    if not matches:
        return box("Puzzle Analysis", [
            "",
            f" Evaluated {evaluated} records",
            "",
            "  ❌ No match found",
            "",
            " Why? This wallet has no interaction",
            " with known puzzle contracts.",
            "",
            " Next: Try /catalog to browse",
            " the puzzle list manually.",
            "",
        ])
    lines = ["", f" Evaluated {evaluated} records", ""]
    for m in matches[:5]:
        title = m.get("title") or m.get("puzzle_id", "Unknown")
        status = m.get("verdict", "?")
        score = m.get("score", "?")
        lines.append(f"  ✓ {title}  ({status}, score {score})")
    return box("Puzzle Analysis", lines)


def scan_result(address: str, chain: str, assets: List[Dict[str, Any]],
                 tool_calls: List[Tuple[str, str, str]],
                 puzzle_matches: List[Dict[str, Any]],
                 puzzle_evaluated: int) -> str:
    """Build a complete scan result message."""
    blocks = [
        box("🔍 Deep Scan", [
            "",
            f" Target: {address[:20]}...{address[-8:]}",
            f" Chain: {chain}",
            "",
        ]),
        tool_block(tool_calls),
        asset_table(assets),
        puzzle_verdict(puzzle_matches, puzzle_evaluated),
    ]
    return "\n".join(blocks)


def welcome_message(name: str) -> str:
    """Build the welcome message."""
    return box(f"🛡️ {name}", [
        "",
        " Read-only public wallet data.",
        " I will never ask for a seed phrase",
        " or private key.",
        "",
        " ━━━━━━━━━━━━━━━━━━",
        " 🔍 Commands:",
        "   /scan <address>  — deep scan",
        "   /inspect <addr> — assets only",
        "   /catalog         — browse puzzles",
        "   /market          — market overview",
        "   /research        — bounty workflow",
        "   /help            — full help",
        "",
    ])


def research_workflow_summary() -> str:
    """Build a compact research workflow summary."""
    steps = [
        ("1. Define Target", "Identify scope + invariants"),
        ("2. Surface Map", "Entry points, trust boundaries"),
        ("3. Collect Data", "On-chain + historical"),
        ("4. Analyze", "Prove reachability before claiming"),
        ("5. Report", "PoC + impact + fix → submit"),
    ]
    lines = [""]
    for title, desc in steps:
        lines.append(f"  ├─ {title}")
        lines.append(f"  │  {desc}")
    lines.append("  └─ Submit to bounty platform")
    return box("Research Workflow", lines)


def opportunity_list(opportunities: List[Dict[str, Any]]) -> str:
    """Build a compact opportunity listing."""
    if not opportunities:
        return box("Opportunities", ["", " No open opportunities found", ""])
    lines = [""]
    for o in opportunities[:10]:
        platform = o.get("platform", "?")
        target = o.get("target") or o.get("title", "Unknown")
        bounty = o.get("max_bounty") or o.get("payout", "?")
        lines.append(f"  [{platform}] {target}")
        lines.append(f"    → {bounty}")
    return box("Open Bounties", lines)


def file_analysis_result(filename: str, file_type: str, size: str,
                          classification: str, details: str = "") -> str:
    """Render file analysis results."""
    lines = [
        "",
        f" File: {filename}",
        f" Type: {file_type}",
        f" Size: {size}",
        f" Class: {classification}",
    ]
    if details:
        lines.extend(["", f" Details:", f" {details}"])
    return box("File Analysis", lines)


def goal_prompt() -> str:
    """Render a prompt asking the user for their goal."""
    return box("🎯 What's your goal?", [
        "",
        " Tell me what you want to achieve:",
        "",
        " • Analyze a wallet for activity",
        " • Find puzzle matches",
        " • Research a bounty target",
        " • Check token safety",
        " • Recover wallet data",
        " • Something else",
        "",
        "Type your goal below and I'll",
        "suggest the best approach.",
        "",
    ])


def ai_suggestion(goal: str, steps: List[str]) -> str:
    """Render an AI-generated suggestion for a user goal."""
    lines = ["", f" Goal: {goal}", "", " Steps:"]
    for i, step in enumerate(steps, 1):
        lines.append(f"  {i}. {step}")
    return box("AI Helper", lines)
