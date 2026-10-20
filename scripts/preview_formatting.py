#!/usr/bin/env python3
"""Preview script — shows how bot messages will look in Telegram.

Run: python3 scripts/preview_formatting.py
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.formatting import (
    ai_suggestion, box, diff_block, file_analysis_result, goal_prompt,
    opportunity_list, puzzle_verdict, research_workflow_summary,
    scan_result, tool_block, verdict, welcome_message,
)


def main():
    print("=" * 60)
    print("TELEGRAM BOT MESSAGE PREVIEW")
    print("=" * 60)
    print()

    # 1. Welcome message
    print("1. WELCOME MESSAGE")
    print("-" * 40)
    print(welcome_message("Hermes Wallet Inspector"))
    print()

    # 2. Scan result
    print("2. SCAN RESULT")
    print("-" * 40)
    print(scan_result(
        address="0x3a5bd13b47d646fa941ee04b06ff0d5733f91653",
        chain="Ethereum Mainnet",
        assets=[
            {"symbol": "USDT", "amount": "0.256040", "kind": "token"},
            {"symbol": "ETH", "amount": "0.001900", "kind": "native"},
        ],
        tool_calls=[
            ("eth.blockscout.com", "✓", "0.8s"),
            ("mempool.space", "✓", "0.3s"),
            ("puzzle corpus", "✓", "0 matches"),
        ],
        puzzle_matches=[],
        puzzle_evaluated=49,
    ))
    print()

    # 3. Puzzle match
    print("3. PUZZLE MATCH")
    print("-" * 40)
    print(puzzle_verdict(
        matches=[
            {"title": "ENS DNSRegistrar", "verdict": "High", "score": "0.85"},
            {"title": "DNSSEC Oracle", "verdict": "Medium", "score": "0.62"},
        ],
        evaluated=49,
    ))
    print()

    # 4. Research workflow
    print("4. RESEARCH WORKFLOW")
    print("-" * 40)
    print(research_workflow_summary())
    print()

    # 5. Opportunities
    print("5. OPPORTUNITIES")
    print("-" * 40)
    print(opportunity_list([
        {"platform": "cantina", "target": "Revert v4lend", "max_bounty": "$50,000"},
        {"platform": "immunefi", "target": "Sky", "max_bounty": "$10M"},
        {"platform": "superteam", "target": "Solana Mobile", "max_bounty": "$1,600"},
    ]))
    print()

    # 6. File analysis
    print("6. FILE ANALYSIS")
    print("-" * 40)
    print(file_analysis_result(
        filename="wallet_backup.dat",
        file_type="SQLite database",
        size="2.4 MB",
        classification="Wallet data (encrypted)",
        details="Contains 3 wallet entries. Encrypted with AES-256-CCM.",
    ))
    print()

    # 7. Goal prompt
    print("7. GOAL PROMPT")
    print("-" * 40)
    print(goal_prompt())
    print()

    # 8. AI suggestion
    print("8. AI SUGGESTION")
    print("-" * 40)
    print(ai_suggestion(
        goal="Analyze a wallet for puzzle matches",
        steps=[
            "Connect your wallet or paste an address",
            "Run /scan to check assets + puzzle corpus",
            "If no match, try /catalog to browse manually",
            "Track puzzles with /progress to get notified",
        ],
    ))
    print()

    # 9. Verdict with next steps
    print("9. VERDICT WITH NEXT STEPS")
    print("-" * 40)
    print(verdict(
        positive=False,
        title="No puzzle match found",
        reason="This wallet has no transaction history with known puzzle contracts",
        next_steps=[
            "Try a different wallet (one with older history)",
            "Browse the catalog manually with /catalog",
            "Track a puzzle to get notified when new hints drop",
        ],
    ))
    print()

    # 10. Diff block
    print("10. DIFF BLOCK")
    print("-" * 40)
    print(diff_block([
        ("+", "Wallet interacts with DNSSEC oracle"),
        ("-", "No direct puzzle contract interaction found"),
        ("?", "Check tx 0xabc...123 for full trace"),
    ]))
    print()

    print("=" * 60)
    print("END OF PREVIEW")
    print("=" * 60)


if __name__ == "__main__":
    main()
