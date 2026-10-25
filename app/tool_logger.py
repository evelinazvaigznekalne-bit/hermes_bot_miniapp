"""Tool result logger for self-improvement.

Records every tool call, its inputs, outputs, success/failure, timing,
and any user feedback.  Data is stored in a local SQLite database
under ``~/.hermes/tool_logs.db``.  Callers use ``log_tool_result()``
and can query aggregated stats via ``tool_stats()``.
"""

from __future__ import annotations

import os
import re
import sqlite3
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


_DB_PATH = os.path.expanduser("~/.hermes/tool_logs.db")
_SCHEMA = """
CREATE TABLE IF NOT EXISTS tool_logs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            TEXT NOT NULL,
    tool          TEXT NOT NULL,
    input_summary TEXT,
    output_summary TEXT,
    success       INTEGER NOT NULL,
    duration_ms   INTEGER,
    error         TEXT,
    session       TEXT
);
CREATE INDEX IF NOT EXISTS idx_tool_ts ON tool_logs(tool, ts);
"""

# ---------------------------------------------------------------------------
# Strict schema for permitted telemetry fields
# ---------------------------------------------------------------------------

#: Approved tool identifiers.  Anything else is rejected before it reaches
#: the database.  This is the primary protection, not regex redaction.
_ALLOWED_TOOLS = frozenset({
    "address_balance",
    "address_info",
    "mnemonic_to_xkeys",
    "crypto_calculator",
    "decode_transaction",
    "parse_wallet_dat",
    "verify_ecdsa_signature",
    "decrypt_bip38",
    "address_balance",
    "address_info",
    "multi_decode",
    "crack_caesar",
    "crack_xor",
    "estimate_keyspace",
    "plan_attack",
    "classify_puzzle",
    "classify_text",
    "fetch_text",
    "wayback_available",
    "fetch_wayback",
    "summarize_page",
    "describe_antibot",
    "extract_og_image",
    "price",
    "overview",
    "analyze",
    "analyze_contract",
    "analyze_token_symbol",
    "cluster_addresses_heuristic",
    "decode_bitcoin_script",
    "inspect_public",
    "token_scan",
    "walletdat_inspect",
    "btc_puzzle_identify",
    "btc_puzzle_estimate",
    "proofofsolve_verify",
    "proofofsolve_clues",
    "halv_summary",
})

#: Safe error categories.  Anything else maps to "InternalError".
_SAFE_ERROR_CATEGORIES = frozenset({
    "DecodeError", "ValueError", "TypeError", "KeyError", "IndexError",
    "AttributeError", "RuntimeError", "OSError", "IOError",
    "ImportError", "ModuleNotFoundError", "MemoryError",
    "OverflowError", "ZeroDivisionError", "AssertionError",
    "LookupError", "NameError", "ReferenceError",
    "BlockingIOError", "ChildProcessError", "ConnectionError",
    "BrokenPipeError", "ConnectionAbortedError",
    "ConnectionRefusedError", "ConnectionResetError",
    "FileExistsError", "FileNotFoundError", "InterruptedError",
    "IsADirectoryError", "NotADirectoryError", "PermissionError",
    "ProcessLookupError", "TimeoutError",
    "UnboundLocalError", "RecursionError",
    "ConfigError", "SignatureError", "NonceError",
    "ValidationError", "AddressValidationError",
    "UnsafeUrlError", "HttpError", "RateLimitError",
    "InternalError",
})

#: Fixed summaries for sensitive tools — arbitrary input/output is discarded.
_SENSITIVE_TOOL_SUMMARIES = frozenset({
    "mnemonic_to_xkeys",
    "crypto_calculator",
    "decrypt_bip38",
    "convert_mnemonic",
    "parse_wallet_dat",
    "verify_ecdsa_signature",
    "decode_transaction",
})


def _redact(text: str) -> str:
    """Redact free-text that may contain sensitive material.

    This is a defence-in-depth layer, not the primary protection.
    The primary protection is the strict schema in ``log()``.
    """
    if not text:
        return text
    t = text.strip()
    # Mnemonic phrase: 12-24 words
    words = t.split()
    if 12 <= len(words) <= 24:
        return "<redacted>"
    # Hex seed / private key: 64 hex chars
    if re.fullmatch(r"[0-9a-fA-F]{64}", t):
        return "<redacted>"
    # WIF: base58 starting with 5, K, or L, length 51-52
    if re.fullmatch(r"[5KL][1-9A-HJ-NP-Za-km-z]{50,51}", t):
        return "<redacted>"
    # Extended key: xpub, xprv, zpub, zprv, etc.
    if re.match(r"^(xpub|xprv|zpub|zprv|ypub|yprv)", t, re.I):
        return "<redacted>"
    # Blockchain address: bc1, 1, 3, 0x
    if re.match(r"^(bc1[a-zA-Z0-9]{20,}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40})$", t):
        return "<redacted>"
    # Sensitive keywords
    if re.search(r"(?i)(mnemonic|seed|phrase|private|key|wif|xpub|address|passphrase|secret)", t):
        return "<redacted>"
    return text


def _safe_error(exc: Exception) -> str:
    """Return a non-sensitive error label for logging."""
    name = type(exc).__name__
    if name not in _SAFE_ERROR_CATEGORIES:
        return "InternalError"
    return name


class ToolLogger:
    def __init__(self, db_path: str = _DB_PATH):
        self.db_path = db_path
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def log(
        self,
        tool: str,
        input_summary: str = "",
        output_summary: str = "",
        success: bool = True,
        duration_ms: Optional[int] = None,
        error: Optional[Exception] = None,
        session: Optional[str] = None,
    ) -> int:
        # Primary protection: strict schema validation.
        # Reject unknown tool names outright.
        if tool not in _ALLOWED_TOOLS:
            raise ValueError(f"tool '{tool}' is not in the allowed telemetry schema")

        # For sensitive tools, discard arbitrary input/output and use fixed
        # summaries.  This prevents caller-side injection of secrets.
        if tool in _SENSITIVE_TOOL_SUMMARIES:
            input_summary = "<redacted>"
            if success:
                output_summary = "success; output redacted"
            else:
                output_summary = "failed"

        now = datetime.now(timezone.utc).isoformat()
        error_label = _safe_error(error) if error else ""
        cur = self._conn.execute(
            """INSERT INTO tool_logs
               (ts, tool, input_summary, output_summary, success, duration_ms, error, session)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                now,
                tool,
                _redact(str(input_summary))[:512],
                _redact(str(output_summary))[:1024],
                int(success),
                duration_ms,
                error_label[:512],
                session,
            ),
        )
        self._conn.commit()
        return cur.lastrowid

    def recent(self, tool: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM tool_logs"
        params: tuple = ()
        if tool:
            sql += " WHERE tool = ?"
            params = (tool,)
        sql += " ORDER BY id DESC LIMIT ?"
        rows = self._conn.execute(sql, params + (limit,)).fetchall()
        cols = [d[1] for d in self._conn.execute("PRAGMA table_info(tool_logs)").fetchall()]
        return [dict(zip(cols, r)) for r in rows]

    def stats(self, tool: Optional[str] = None, limit: int = 20) -> Dict[str, Any]:
        sql = (
            "SELECT tool, COUNT(*) as calls, SUM(success) as successes, "
            "AVG(duration_ms) as avg_ms FROM tool_logs"
        )
        params: tuple = ()
        if tool:
            sql += " WHERE tool = ?"
            params = (tool,)
        sql += " GROUP BY tool ORDER BY calls DESC LIMIT ?"
        rows = self._conn.execute(sql, params + (limit,)).fetchall()
        by_tool = {
            r[0]: {
                "calls": r[1],
                "successes": r[2] or 0,
                "failure_rate": round((r[1] - (r[2] or 0)) / max(r[1], 1), 4),
                "avg_duration_ms": round(r[3], 1) if r[3] is not None else None,
            }
            for r in rows
        }
        return {"by_tool": by_tool, "total_calls": sum(v["calls"] for v in by_tool.values())}

    def prune(self, before: Optional[str] = None) -> int:
        """Delete rows older than ``before`` (ISO timestamp). Returns rows removed."""
        if not before:
            return 0
        cur = self._conn.execute("DELETE FROM tool_logs WHERE ts < ?", (before,))
        self._conn.commit()
        return cur.rowcount


# module-level singleton
_tool_logger: Optional[ToolLogger] = None


def get_tool_logger() -> ToolLogger:
    global _tool_logger
    if _tool_logger is None:
        _tool_logger = ToolLogger()
    return _tool_logger


def log_tool_result(
    tool: str,
    input_summary: str = "",
    output_summary: str = "",
    success: bool = True,
    duration_ms: Optional[int] = None,
    error: Optional[Exception] = None,
    session: Optional[str] = None,
) -> int:
    return get_tool_logger().log(
        tool=tool,
        input_summary=input_summary,
        output_summary=output_summary,
        success=success,
        duration_ms=duration_ms,
        error=error,
        session=session,
    )


def tool_stats(tool: Optional[str] = None, limit: int = 20) -> Dict[str, Any]:
    return get_tool_logger().stats(tool=tool, limit=limit)


def recent_tool_logs(tool: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
    return get_tool_logger().recent(tool=tool, limit=limit)
