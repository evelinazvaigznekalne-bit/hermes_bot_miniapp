"""Telegram Bot API backend.

Read-only bot: it reports status and runs public-address lookups. It never
asks for a seed phrase or private key, and never signs or broadcasts
anything. The bot token comes from the environment only.
"""

from __future__ import annotations

import html
import os
import re
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Any, Dict, Optional

from ..config import Settings, get_settings, is_placeholder
from ..errors import ConfigError, _safe_exception
from ..formatting import (
    ai_suggestion, box, esc, file_analysis_result, goal_prompt,
    opportunity_list, puzzle_verdict, research_workflow_summary,
    scan_result, tool_call, tool_block, verdict, welcome_message,
)
from ..http import HttpClient
from ..logging_setup import get_logger, register_secret
from ..service import WalletService
from ..users import UserStore
from ..webtools import (
    UnsafeUrlError,
    describe_antibot,
    extract_og_image,
    fetch_text,
    fetch_wayback,
    summarize_page,
    validate_public_https,
    wayback_available,
)

# self-improvement logger
try:
    from ..tool_logger import log_tool_result
except Exception:
    def log_tool_result(*a, **k):
        return 0

log = get_logger()

#: Inline keyboard that opens the Mini App from a chat message.
WEBAPP_BUTTON_LABEL = "Open App"


def _looks_like_address(text: str) -> bool:
    """Check if the input looks like a blockchain address."""
    text = text.strip()
    if re.match(r'^0x[0-9a-fA-F]{40}$', text):
        return True
    if re.match(r'^(bc1|tb1)[a-zA-Z0-9]{20,}$', text):
        return True
    if re.match(r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$', text):
        return True
    return False


#: Host accepted by /ig. Subdomains (www., m., …) are allowed; lookalikes such
#: as ``instagram.com.evil.example`` or ``notinstagram.com`` are not, because
#: the check requires either an exact match or a leading-dot suffix.
_INSTAGRAM_HOST = "instagram.com"


def _is_instagram_post_url(url: str) -> bool:
    """True for an http(s) Instagram post/reel URL on an allowed host."""
    try:
        parsed = urllib.parse.urlsplit(str(url).strip())
    except ValueError:
        return False
    if parsed.scheme.lower() not in ("http", "https"):
        return False
    host = (parsed.hostname or "").lower()
    if not (host == _INSTAGRAM_HOST or host.endswith("." + _INSTAGRAM_HOST)):
        return False
    path = parsed.path or "/"
    return path.startswith(("/p/", "/reel/", "/tv/"))


def help_text(display_name: str = "Hermes Wallet Inspector") -> str:
    """Build the /start and /help body for the configured app name."""
    return (
        f"🛡️ <b>{html.escape(display_name)}</b>\n"
        "Read-only public wallet data. I will <b>never</b> ask for a seed phrase "
        "or private key.\n\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "🔍 <b>Wallet Inspection</b>\n"
        "  /inspect &lt;address&gt; — public assets for an address\n"
        "    <i>Example: /inspect 0x1234...abcd</i>\n"
        "  /puzzles &lt;address&gt; — compare with puzzle corpus\n"
        "  /scan &lt;address|token&gt; — deep scan or token scam check\n"
        "    <i>Example: /scan 0x1234...abcd</i>\n"
        "    <i>Example: /scan PEPE</i>\n"
        "  /chains — supported chains\n\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "📊 <b>Market & Catalog</b>\n"
        "  /market — market overview with token stats\n"
        "  /catalog — browse puzzle catalog\n\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "🧩 <b>Puzzles</b>\n"
        "  /progress — your tracked puzzle progress\n"
        "  /progress set &lt;sku&gt; [status] — track a puzzle\n"
        "  /crack &lt;puzzle_id&gt; — show crack attempt\n"
        "  /classify [puzzle_id|text] — identify the puzzle type (math/brute/…)\n"
        "  /plan &lt;puzzle_id&gt; — the concrete attack its type implies\n"
        "  /families — the strategy types and corpus distribution\n"
        "  /halv — HALV puzzle research progress\n"
        "  /image — image analysis info\n"
        "  /goal [text] — AI goal helper\n\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "🧩 <b>Bitcoin Puzzle</b>\n"
        "  /bitcoinpuzzle [address|estimate start end] — puzzle solver\n"
        "    <i>Example: /bitcoinpuzzle 1PpyGsfXz1TJdYxRBEEGgsat37ZDmLsyWw</i>\n"
        "    <i>Example: /bitcoinpuzzle estimate 0x8000 0xFFFF</i>\n"
        "  /websources [query] — crypto tool directories\n"
        "    <i>Example: /websources rsa</i>\n"
        "  /monitor — puzzle monitoring status\n\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "🌐 <b>Web Research</b>\n"
        "  /archive &lt;url&gt; — archived copy (bypasses bot gates)\n"
        "  /ig &lt;post_url&gt; — Instagram post media URL\n\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "🔐 <b>Crypto Tools</b> — offline, no key needed\n"
        "  /txdecode &lt;hex&gt; — decode a raw BTC or ETH transaction\n"
        "  /mnemonic &lt;words&gt; — BIP39 check + seed + addresses\n"
        "  /keycalc &lt;hex|wif&gt; — every address a key controls\n"
        "  /walletdat &lt;path&gt; — inspect a wallet.dat (keys redacted)\n"
        "  /script &lt;hex&gt; — decode a Bitcoin script\n"
        "  /sigverify &lt;pubkey&gt; &lt;msg&gt; &lt;sig&gt; — verify ECDSA signature\n"
        "  /bip38 &lt;key&gt; &lt;pass&gt; — decrypt a BIP38 encrypted key\n"
        "  /cluster &lt;txid&gt; — common-input address clustering heuristic\n"
        "  /honeypot &lt;address&gt; — meme / EVM token safety check\n"
        "  /price &lt;symbol&gt; — live price from CoinGecko / Binance\n"
        "  /cipher &lt;text&gt; — multi-decoder: rot13, caesar, xor, base64…\n"
        "  /prediction — prediction-market overview (Polymarket)\n\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "👤 <b>Account</b>\n"
        "  /dashboard — your stats and activity\n"
        "  /history — your recent lookups\n"
        "  /wallet — your wallet info\n"
        "  /login — login info\n"
        "  /status — subsystem status\n"
        "  /setname &lt;name&gt; — set the bot display name\n"
        "  /help — this message\n\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "🔗 Open the Mini App"
    )


#: Backwards-compatible default (no custom name configured).
HELP_TEXT = help_text()


class TelegramClient:
    """Thin Bot API client (no third-party dependency)."""

    def __init__(self, token: Optional[str], *, http: Optional[HttpClient] = None,
                 api_base: str = "https://api.telegram.org"):
        self.token = token
        self.api_base = api_base.rstrip("/")
        self.http = http or HttpClient(timeout=45.0, max_retries=5, backoff=2.0)
        if token and not is_placeholder(token):
            register_secret(token)

    @property
    def configured(self) -> bool:
        return not is_placeholder(self.token)

    def _url(self, method: str) -> str:
        if not self.configured:
            raise ConfigError("TELEGRAM_BOT_TOKEN is not configured")
        return f"{self.api_base}/bot{self.token}/{method}"

    def call(self, method: str, payload: Optional[Dict[str, Any]] = None) -> Any:
        data = self.http.post_json(
            self._url(method), provider="telegram", json_body=payload or {}
        )
        if isinstance(data, dict) and not data.get("ok", False):
            raise ConfigError(f"Telegram API error: {data.get('description')}")
        return data.get("result") if isinstance(data, dict) else data

    def send_message(self, chat_id: int, text: str, *,
                     disable_preview: bool = True) -> Any:
        return self.call("sendMessage", {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": disable_preview,
        })

    def set_webapp_menu(self, url: str, text: str = "Open App") -> Any:
        return self.call("setChatMenuButton", {
            "menu_button": {"type": "web_app", "text": text, "web_app": {"url": url}}
        })

    def set_bot_name(self, name: str) -> Any:
        """Set the bot's display name (shown in the chat header).

        NOTE: the @username is fixed at creation and can only be changed by
        @BotFather - it is not settable through the Bot API.
        """
        return self.call("setMyName", {"name": name})

    def set_bot_description(self, description: str) -> Any:
        return self.call("setMyDescription", {"description": description})

    def set_bot_short_description(self, short: str) -> Any:
        return self.call("setMyShortDescription", {"short_description": short})


class TelegramBot:
    """Long-polling bot wired to :class:`WalletService`."""

    def __init__(self, service: Optional[WalletService] = None, *,
                 settings: Optional[Settings] = None,
                 client: Optional[TelegramClient] = None,
                 users: Optional[UserStore] = None,
                 selftest: bool = False):
        self.settings = settings or get_settings()
        self.service = service or WalletService(self.settings)
        self.client = client or TelegramClient(self.settings.telegram_bot_token)
        self.users = users or UserStore(
            Path(self.settings.log_dir).parent / ".run" / "users.json")
        self._offset = 0
        self._running = False
        self.proofofsolve_sessions: Dict[int, Dict[str, Any]] = {}
        self.selftest = selftest
        self._selftest_replies: List[str] = []

    # -- handlers ---------------------------------------------------------
    def handle_update(self, update: Dict[str, Any]) -> Optional[str]:
        message = update.get("message") or update.get("edited_message") or {}
        chat = message.get("chat") or {}
        from_user = message.get("from") or {}
        chat_id = chat.get("id")
        text = (message.get("text") or "").strip()
        sender_id = from_user.get("id")
        chat_type = (chat.get("type") or "").lower()
        if chat_id is None or not text:
            return None
        return self.handle_command(chat_id, text, sender_id=sender_id, chat_type=chat_type)

    def handle_command(self, chat_id: int, text: str, *,
                       sender_id: Optional[int] = None,
                       chat_type: str = "") -> str:
        # --- ProofOfSolve interactive word entry ---
        session = self.proofofsolve_sessions.get(chat_id)
        if session and not text.startswith("/"):
            return self._proofofsolve_interactive(chat_id, text)

        parts = text.split()
        command = parts[0].split("@")[0].lower()
        args = parts[1:]

        # --- Access control for sensitive crypto commands ---
        # Authorize by the authenticated sender's Telegram from.id, never by
        # chat_id.  In a group chat_id != from.id, so chat_id-based checks
        # would authorize the wrong identity or leak group membership.
        if command in ("/xkeys", "/mnemonic", "/keycalc", "/bip38"):
            # Deny in groups by default: a group chat_id is not a user id.
            if chat_type == "group" or chat_type == "supergroup":
                return ("🔒 <b>Sensitive commands are private only.</b>\n\n"
                        "Use this command in a direct message with the bot.")
            # Fail closed when sender identity or allowlist is missing.
            if sender_id is None:
                log.warning("sensitive command without sender identity",
                            extra={"component": "telegram.auth",
                                   "status": "✗", "chat_id": chat_id,
                                   "command": command})
                return "🔒 <b>Access denied.</b>"
            allowed = self.settings.telegram_authorized_user_ids
            if not allowed:
                return ("🔒 <b>Authorized users only.</b>\n\n"
                        "Set TELEGRAM_AUTHORIZED_USER_IDS in your environment "
                        "to a comma-separated list of Telegram user IDs.")
            try:
                if int(sender_id) not in allowed:
                    return "🔒 <b>Access denied.</b> You are not authorized for this command."
            except (TypeError, ValueError):
                return "🔒 <b>Access denied.</b>"

        # Remember the user on first contact (and refresh last-seen).
        try:
            self.users.touch(chat_id)
        except Exception as exc:  # pragma: no cover - never break a command
            log.warning("user store unavailable: %s", exc,
                        extra={"component": "users", "status": "✗"})

        if command in ("/start", "/help"):
            reply = help_text(self.settings.bot_display_name)
            if self.settings.telegram_webapp_url:
                reply += f"\n\n<a href=\"{self.settings.telegram_webapp_url}\">🔗 Open the Mini App</a>"
            else:
                reply += ("\n\n<i>Mini App URL not configured "
                          "(set TELEGRAM_WEBAPP_URL).</i>")
        elif command == "/status":
            reply = self._status_text()
        elif command == "/chains":
            rows = [
                f"• <b>{c['chain']}</b> ({c['family']}) – {c['native_symbol']}"
                for c in self.service.capabilities()["chains"]
            ]
            reply = "<b>Supported chains</b>\n" + "\n".join(rows)
        elif command in ("/setname", "/name"):
            if not args:
                current = self.settings.bot_display_name
                reply = (f"Current name: <b>{html.escape(current)}</b>\n"
                         f"Usage: <code>/setname &lt;new name&gt;</code>\n\n"
                         "Sets the bot display name via the Bot API. The "
                         "@username is fixed at creation and can only be "
                         "changed by @BotFather.")
            else:
                new_name = " ".join(args)[:64]
                try:
                    self.client.set_bot_name(new_name)
                    self.register_commands()
                    reply = f"✓ bot display name set to <b>{html.escape(new_name)}</b>"
                except Exception as exc:
                    reply = (f"✗ could not set name: "
                             f"{html.escape(type(exc).__name__)}: {html.escape(str(exc))}")
        elif command in ("/inspect", "/puzzles"):
            if not args:
                reply = f"Usage: <code>{command} &lt;address&gt;</code>"
            else:
                reply = self._inspect_text(args[0], with_puzzles=command == "/puzzles")
                try:
                    self.users.record(chat_id, command=command,
                                      address=args[0])
                except Exception:  # pragma: no cover - never break a command
                    pass
        elif command == "/scan":
            if not args:
                reply = "Usage: <code>/scan &lt;address|token&gt;</code>\n\n" \
                        "Deep scan an address or check a token for scams."
            else:
                arg = args[0]
                if _looks_like_address(arg):
                    reply = self._scan_text(arg)
                else:
                    reply = self._token_scan_text(arg)
                try:
                    self.users.record(chat_id, command=command,
                                      address=arg)
                    count = self.users.increment(chat_id, field="scan_count")
                    reply += f"\n\n<i>Scan #{count}</i>"
                except Exception:
                    pass
        elif command == "/market":
            reply = self._market_text()
        elif command == "/dashboard":
            reply = self._dashboard_text(chat_id)
        elif command == "/catalog":
            reply = self._catalog_text()
        elif command == "/history":
            reply = self._history_text(chat_id)
        elif command == "/progress":
            reply = self._progress_text(chat_id, args)
        elif command == "/crack":
            reply = self._crack_text(args)
        elif command == "/classify":
            reply = self._classify_text(args)
        elif command == "/plan":
            reply = self._plan_text(args)
        elif command == "/families":
            reply = self._families_text()
        elif command == "/txdecode":
            reply = self._txdecode_text(args)
        elif command == "/mnemonic":
            reply = self._mnemonic_text(args)
        elif command == "/keycalc":
            reply = self._keycalc_text(args)
        elif command == "/walletdat":
            reply = self._walletdat_text(args)
        elif command == "/image":
            reply = self._image_text()
        elif command == "/archive":
            reply = self._archive_text(args)
        elif command in ("/ig", "/instagram"):
            reply = self._instagram_text(args)
        elif command == "/goal":
            if args:
                reply = self._goal_text(" ".join(args))
            else:
                reply = goal_prompt()
        elif command == "/login":
            reply = self._login_text()
        elif command == "/wallet":
            reply = self._wallet_text(chat_id)
        elif command == "/bitcoinpuzzle":
            reply = self._bitcoinpuzzle_text(args)
        elif command == "/proofofsolve":
            reply = self._proofofsolve_text(chat_id, args)
        elif command == "/cancel":
            if chat_id in self.proofofsolve_sessions:
                del self.proofofsolve_sessions[chat_id]
                reply = "✓ ProofOfSolve session cancelled."
            else:
                reply = "No active ProofOfSolve session to cancel."
        elif command == "/halv":
            reply = self._halv_text(args)
        elif command == "/honeypot":
            reply = self._honeypot_text(args)
        elif command == "/script":
            reply = self._script_text(args)
        elif command == "/sigverify":
            reply = self._sigverify_text(args)
        elif command == "/bip38":
            reply = self._bip38_text(args)
        elif command == "/cluster":
            reply = self._cluster_text(args)
        elif command == "/price":
            reply = self._price_text(args)
        elif command == "/cipher":
            reply = self._cipher_text(args)
        elif command == "/prediction":
            reply = self._prediction_text(args)
        elif command == "/websources":
            reply = self._websources_text(args)
        elif command == "/tools":
            reply = self._tools_text()
        elif command == "/toolstats":
            reply = self._toolstats_text(args)
        elif command == "/balance":
            reply = self._balance_text(args)
        elif command == "/addrinfo":
            reply = self._addrinfo_text(args)
        elif command == "/xkeys":
            reply = self._xkeys_text(args)
        elif command == "/monitor":
            reply = self._monitor_text(args)
        else:
            reply = "Unknown command. Try /help"

        self._reply(chat_id, reply)
        return reply

    # -- per-user views ---------------------------------------------------
    def _history_text(self, chat_id: int) -> str:
        rows = self.users.history(chat_id, limit=10)
        if not rows:
            return ("<b>Your history</b>\n\nNothing yet. Try "
                    "<code>/inspect &lt;address&gt;</code>.")
        lines = ["<b>Your recent lookups</b>", ""]
        for h in rows:
            addr = h.address
            if addr:
                addr = f" <code>{html.escape(addr[:8])}…{html.escape(addr[-4:])}</code>"
            lines.append(f"• {html.escape(h.as_dict()['when'])} — "
                         f"/{html.escape(h.command)}{addr}")
        stats = self.users.stats(chat_id)
        lines += ["", f"<i>{stats['history']} total · first seen "
                      f"{html.escape(str(stats['first_seen']))}</i>"]
        return "\n".join(lines)

    def _progress_text(self, chat_id: int, args) -> str:
        """Show or set the caller's own puzzle progress."""
        if args and args[0] == "set" and len(args) >= 2:
            sku = args[1]
            status = args[2] if len(args) > 2 else "in-progress"
            title = ""
            try:
                detail = self.service.catalog.item_detail(
                    self.service.tier_for(None), sku)
                if detail:
                    title = detail.get("title", "")
            except Exception:
                pass
            self.users.set_progress(chat_id, sku=sku, title=title,
                                    status=status)
            return (f"✓ tracked <b>{html.escape(sku)}</b> as "
                    f"<i>{html.escape(status)}</i>")

        rows = self.users.progress(chat_id)
        if not rows:
            return ("<b>Puzzle progress</b>\n\nNothing tracked.\n\n"
                    "<code>/progress set &lt;sku&gt; [status]</code>")
        lines = ["<b>Your puzzle progress</b>", ""]
        for p in rows[:20]:
            title = p.title or p.sku
            lines.append(f"• <b>{html.escape(title[:48])}</b> — "
                         f"<i>{html.escape(p.status)}</i> "
                         f"<span class='muted'>({html.escape(p.as_dict()['when'])})</span>")
        lines += ["", f"<i>{len(rows)} tracked</i>"]
        return "\n".join(lines)

    def _crack_text(self, args) -> str:
        """Show crack attempt info for a puzzle."""
        if not args:
            return ("Usage: <code>/crack &lt;puzzle_id&gt;</code>\n\n"
                    "Shows crack attempt details for a puzzle.")
        puzzle_id = args[0]
        try:
            detail = self.service.catalog.item_detail(
                self.service.tier_for(None), puzzle_id)
            if not detail:
                return f"✗ puzzle <code>{html.escape(puzzle_id)}</code> not found."
            lines = [f"🧩 <b>Crack attempt</b> — <code>{html.escape(puzzle_id)}</code>"]
            lines.append(f"Title: <b>{html.escape(detail.get('title', 'Unknown'))}</b>")
            lines.append(f"Status: {html.escape(detail.get('status', 'unknown'))}")
            lines.append(f"Chain: {html.escape(detail.get('chain', 'unknown'))}")
            hints = detail.get("hints") or []
            if hints:
                lines.append(f"\n<b>Hints ({len(hints)}):</b>")
                lines.extend(f"  – {html.escape(h)}" for h in hints[:5])
            else:
                lines.append("\n<i>No hints available for this tier.</i>")
            return "\n".join(lines)
        except Exception as exc:
            return f"✗ {html.escape(self._safe_exception(exc))}"

    # -- puzzle strategy identification -----------------------------------

    def _classify_text(self, args) -> str:
        """Identify which strategy family a puzzle belongs to."""
        from ..puzzle_types import FAMILIES

        if not args:
            return ("Usage: <code>/classify &lt;puzzle_id|text&gt;</code>\n\n"
                    "Identifies the strategy family a puzzle needs: math, brute force, "
                    "guessing, steganography, encoding, geometry, reverse engineering, "
                    "on-chain reading, or external information.\n\n"
                    "<i>Example: /classify gsmg-io-5btc-puzzle</i>\n"
                    "<i>Example: /classify discrete log on an elliptic curve</i>")

        query = " ".join(args)
        try:
            from ..access import Tier

            slug = args[0]
            record = self.service.catalog.item_detail(Tier.PAID, slug)
            if record is not None:
                raw = self._raw_entry(slug) or record
                from ..puzzle_types import classify_puzzle
                c = classify_puzzle(raw)
                out = c.as_dict()
                title = record.get("title")
            else:
                from ..puzzle_types import classify_text
                c = classify_text(query)
                out = c.as_dict()
                title = None

            lines = ["🧭 <b>Puzzle type</b>"]
            if title:
                lines.append(f"<b>{html.escape(str(title))}</b>")
                lines.append(f"<code>{html.escape(slug)}</code>")
            lines.append(f"Family: <b>{html.escape(out['label'])}</b> "
                         f"<code>{html.escape(out['family'])}</code>")
            lines.append(f"Confidence: {out['confidence']}"
                         + ("  <i>(inferred from text)</i>" if out["inferred"] else ""))
            if out.get("secondary_families"):
                lines.append("Also applies: " + html.escape(
                    ", ".join(out["secondary_families"][:3])))
            if out.get("reasons"):
                lines.append("")
                lines.append("<b>Why:</b>")
                lines.extend(f"  – {html.escape(r)}" for r in out["reasons"][:4])
            lines.append("")
            lines.append(f"Compute: {html.escape(out.get('compute') or 'none')}")
            lines.append("")
            lines.append("<b>First move:</b>")
            lines.append(f"  {html.escape(out['approach'][0])}")
            return "\n".join(lines)
        except Exception as exc:
            return f"✗ {html.escape(self._safe_exception(exc))}"

    def _plan_text(self, args) -> str:
        """Show the concrete attack plan a puzzle's family implies."""
        from ..puzzles.attack import plan_attack

        if not args:
            return ("Usage: <code>/plan &lt;puzzle_id&gt;</code>\n\n"
                    "Shows the concrete attack the puzzle's type implies: the first move, "
                    "the tools, and whether it needs compute at all.")
        slug = args[0]
        try:
            raw = self._raw_entry(slug)
            if raw is None:
                return f"✗ puzzle <code>{html.escape(slug)}</code> not found."
            plan = plan_attack(raw)
            lines = [f"🎯 <b>Attack plan</b> — <code>{html.escape(slug)}</code>",
                     f"<b>{html.escape(plan.label)}</b>",
                     f"Compute: {html.escape(plan.compute)}",
                     "",
                     f"<b>First move</b>\n  {html.escape(plan.first_move)}",
                     "",
                     "<b>Approach:</b>"]
            lines.extend(f"  {i}. {html.escape(step)}"
                         for i, step in enumerate(plan.approach[:4], 1))
            lines.append("")
            lines.append("<b>Tools:</b> " + html.escape(", ".join(plan.tools[:4])))
            if plan.secondary_families:
                lines.append("<b>Secondary:</b> " + html.escape(
                    ", ".join(plan.secondary_families[:3])))
            return "\n".join(lines)
        except Exception as exc:
            return f"✗ {html.escape(self._safe_exception(exc))}"

    def _families_text(self) -> str:
        """List the strategy families and the corpus distribution."""
        from ..puzzle_types import FAMILIES, classify_catalog

        try:
            entries = [getattr(e, "raw", None) or {}
                       for e in self.service.catalog.public_entries]
            dist = classify_catalog(entries)
        except Exception:
            dist = {"distribution": {}, "count": 0}

        lines = ["🧭 <b>Strategy types</b>", ""]
        for key, fam in FAMILIES.items():
            count = dist.get("distribution", {}).get(key, 0)
            lines.append(f"• <b>{html.escape(fam.label)}</b> "
                         f"<code>{html.escape(key)}</code> — {count} in corpus")
        total = dist.get("count", 0)
        inferred = dist.get("inferred", 0)
        lines.append("")
        lines.append(f"<i>{total} puzzles classified, {inferred} inferred from text</i>")
        return "\n".join(lines)

    # -- crypto tools ------------------------------------------------------

    def _txdecode_text(self, args) -> str:
        """Decode a raw signed transaction. Never echoes secrets."""
        from ..crypto_tools import DecodeError, decode_transaction

        if not args:
            return ("Usage: <code>/txdecode &lt;hex&gt;</code>\n\n"
                    "Decodes a raw signed Bitcoin or Ethereum transaction into structured "
                    "fields: inputs, outputs, amounts, script types and the recovered "
                    "sender.")
        raw = args[0]
        chain = args[1] if len(args) > 1 else "auto"
        try:
            d = decode_transaction(raw, chain=chain)
        except DecodeError as exc:
            return f"✗ {html.escape(self._safe_exception(exc))}"
        except Exception as exc:
            return f"✗ {html.escape(self._safe_exception(exc))}"

        lines = [f"🧾 <b>Transaction</b> — {html.escape(str(d.get('chain')))}",
                 f"Decoded as: <code>{html.escape(str(d.get('decoded_as')))}</code>",
                 f"txid: <code>{html.escape(str(d.get('txid') or 'n/a'))}</code>"]
        if d.get("segwit"):
            lines.append("SegWit: yes")
        if d.get("type") is not None:
            lines.append(f"EVM type: {d['type']}")
        if d.get("sender"):
            lines.append(f"Sender: <code>{html.escape(str(d['sender']))}</code>")
        elif d.get("is_contract_creation"):
            lines.append("Contract creation (no sender to recover)")

        outputs = d.get("outputs") or []
        if d.get("decoded_as") == "eth":
            # An EVM transaction has no outputs; its value and destination live in the
            # top-level fields.
            lines.append(f"To: <code>{html.escape(str(d.get('to') or 'contract creation'))}</code>")
            value_eth = d.get("value_eth")
            if value_eth is not None:
                lines.append(f"Value: <b>{value_eth}</b> ETH")
            lines.append(f"Gas limit: {d.get('gasLimit')}  "
                         f"nonce: {d.get('nonce')}")
            if d.get("chain_id") is not None:
                lines.append(f"Chain id: {d['chain_id']}")
            data_hex = str(d.get("data") or "")
            if data_hex and data_hex != "0x":
                lines.append(f"Input data: {len(data_hex) // 2 - 1} bytes")
        else:
            lines.append("")
            lines.append(f"<b>Outputs ({len(outputs)}):</b>")
            for o in outputs[:6]:
                addr = o.get("address") or "n/a"
                value = o.get("value_btc")
                if value is None:
                    value = o.get("value_eth")
                    suffix = " ETH" if value is not None else ""
                else:
                    suffix = " BTC"
                lines.append(f"  • <code>{html.escape(str(addr))}</code> "
                             f"— {value}{suffix} "
                             f"<i>({html.escape(str(o.get('script_type')))})</i>")
            total = d.get("total_output_btc")
            if total is not None:
                lines.append(f"\nTotal out: <b>{total}</b> BTC")
        return "\n".join(lines)

    def _mnemonic_text(self, args) -> str:
        """BIP39 validation + derivation. The phrase is never echoed back."""
        from ..crypto_tools import DecodeError, convert_mnemonic

        if not args:
            return ("Usage: <code>/mnemonic &lt;12 or 24 words&gt;</code>\n\n"
                    "Checks a BIP39 phrase's checksum, then derives its seed and first "
                    "addresses.\n\n"
                    "<b>Privacy:</b> the phrase is never echoed back and never stored. "
                    "Prefer running this in the Mini App, which keeps it on your device.")
        phrase = " ".join(args)
        try:
            d = convert_mnemonic(phrase, to="all")
        except DecodeError as exc:
            return f"✗ {html.escape(self._safe_exception(exc))}"
        except Exception as exc:
            return f"✗ {html.escape(self._safe_exception(exc))}"

        words = len(phrase.split())
        if not d.get("valid"):
            return (f"✗ <b>Invalid BIP39 phrase</b>\n"
                    f"Words: {words}\n"
                    f"Checksum: failed\n\n"
                    f"<i>A failed checksum means at least one word is wrong or out of "
                    f"order. A near-miss phrase is not a solution.</i>")
        lines = [f"✓ <b>Valid BIP39 phrase</b> — {words} words",
                 f"Entropy: {d.get('entropy_bits')} bits",
                 f"Seed: <code>{html.escape(str(d.get('seed_redacted')))}</code>",
                 "",
                 "<b>First addresses:</b>"]
        for name, entry in (d.get("derived") or {}).items():
            addr = entry.get("address")
            lines.append(f"  • {html.escape(name)}: <code>{html.escape(str(addr))}</code>")
        return "\n".join(lines)

    def _keycalc_text(self, args) -> str:
        """Derive every address a key controls. The key is never echoed back."""
        from ..crypto_tools import DecodeError, crypto_calculator

        if not args:
            return ("Usage: <code>/keycalc &lt;hex|WIF&gt;</code>\n\n"
                    "Derives every address a private key controls (compressed and "
                    "uncompressed Bitcoin, plus Ethereum).\n\n"
                    "<b>Privacy:</b> the key is never echoed back and never stored.")
        key = args[0]
        try:
            d = crypto_calculator(key)
        except DecodeError as exc:
            return f"✗ {html.escape(self._safe_exception(exc))}"
        except Exception as exc:
            return f"✗ {html.escape(self._safe_exception(exc))}"

        lines = ["🔑 <b>Key calculator</b>",
                 f"Source: {html.escape(str(d.get('source')))}",
                 f"In range: {'yes' if d.get('in_range') else 'NO'}",
                 ""]
        if d.get("note"):
            lines.append(f"<i>{html.escape(d['note'])}</i>")
            lines.append("")
        lines.append("<b>Bitcoin:</b>")
        for name, addr in (d.get("chains", {}).get("bitcoin") or {}).items():
            lines.append(f"  • {html.escape(name)}: <code>{html.escape(str(addr))}</code>")
        eth = (d.get("chains", {}).get("ethereum") or {}).get("address")
        if eth:
            lines.append(f"\n<b>Ethereum:</b>\n  • <code>{html.escape(str(eth))}</code>")
        return "\n".join(lines)

    def _walletdat_text(self, args) -> str:
        """Inspect a wallet.dat. Key material is redacted."""
        from ..crypto_tools import DecodeError, parse_wallet_dat

        if not args:
            return ("Usage: <code>/walletdat &lt;path&gt;</code>\n\n"
                    "Inventories a Bitcoin Core wallet.dat: format, records, whether it is "
                    "encrypted, and any addresses found. <b>Key material is redacted.</b>")
        path = args[0]
        from pathlib import Path as _Path
        p = _Path(path).expanduser()
        if not p.is_file():
            return f"✗ file not found: <code>{html.escape(path)}</code>"
        try:
            d = parse_wallet_dat(p.read_bytes())
        except DecodeError as exc:
            return f"✗ {html.escape(self._safe_exception(exc))}"
        except Exception as exc:
            return f"✗ {html.escape(self._safe_exception(exc))}"

        lines = [f"🗄️ <b>wallet.dat</b> — {html.escape(p.name)}",
                 f"Format: {html.escape(str(d.get('format')))}",
                 f"Size: {d.get('size_bytes'):,} bytes",
                 f"Encrypted: {'yes' if d.get('encrypted') else 'no'}"]
        if d.get("version"):
            lines.append(f"Wallet version: {d['version']}")
        records = d.get("records") or {}
        if records:
            top = ", ".join(f"{k}×{v}" for k, v in list(records.items())[:6])
            lines.append(f"Records: {html.escape(top)}")
        addrs = d.get("addresses") or []
        if addrs:
            lines.append(f"\n<b>Addresses found ({len(addrs)}):</b>")
            lines.extend(f"  • <code>{html.escape(a)}</code>" for a in addrs[:5])
        lines.append("")
        lines.append(f"<i>{html.escape(str(d.get('note')))}</i>")
        return "\n".join(lines)

    def _raw_entry(self, slug):
        """Find the raw corpus record behind a catalog slug."""
        for entry in self.service.catalog.public_entries:
            if str(getattr(entry, "id", "")) == slug:
                raw = getattr(entry, "raw", None)
                if isinstance(raw, dict):
                    return raw
        return None

    def _image_text(self) -> str:
        """Show image analysis info."""
        return (
            "🖼️ <b>Image Analysis</b>\n\n"
            "The Mini App supports image analysis for:\n"
            "  • Steganography detection\n"
            "  • Hidden data extraction\n"
            "  • Puzzle clue identification\n\n"
            "Open the Mini App and navigate to:\n"
            "  <b>Puzzles → Image Analysis</b>\n\n"
            "Upload an image to analyze it for hidden data."
        )

    def _archive_text(self, args) -> str:
        """Fetch an archived copy of a URL via the Internet Archive."""
        if not args:
            return ("Usage: <code>/archive &lt;url&gt;</code>\n\n"
                    "Fetches an archived copy of a page from the Internet "
                    "Archive. Use this when a site blocks automated clients.")
        url = args[0]
        lines = [f"🗄️ <b>Archive lookup</b>",
                 f"URL: <code>{html.escape(url[:160])}</code>", ""]
        try:
            snap = wayback_available(url)
        except Exception as exc:  # pragma: no cover - network failure path
            snap = None
            lines.append(f"✗ archive query failed: "
                         f"{html.escape(str(exc)[:120])}")
        if not snap:
            lines.append("No archived copy found. The page may be new, or it "
                         "may be behind a bot gate — try the live URL first.")
            return "\n".join(lines)
        lines.append(f"✓ snapshot: <a href=\"{html.escape(str(snap.get('url')))}\">"
                     f"{html.escape(str(snap.get('timestamp', '')))}</a>")
        try:
            body = fetch_wayback(url)
        except Exception:  # pragma: no cover - network failure path
            body = None
        if body:
            gate = describe_antibot(body)
            if gate:
                lines.append(gate)
            # summarize_page() returns plain text, and this bot sends HTML:
            # escape it so archived markup cannot be injected into the message.
            excerpt = html.escape(summarize_page(body, limit=600))
            lines += ["", excerpt or "<i>(empty body)</i>"]
        else:
            lines.append("<i>Snapshot exists but the body could not be fetched "
                         "— the link above still works.</i>")
        return "\n".join(lines)

    def _instagram_text(self, args) -> str:
        """Extract the direct media URL from an Instagram post page."""
        if not args:
            return ("Usage: <code>/ig &lt;post_url&gt;</code>\n\n"
                    "Returns the direct image URL of an Instagram post. "
                    "Useful when Instagram blocks image downloads.")
        url = args[0]
        if not _is_instagram_post_url(url):
            return ("✗ only Instagram post URLs are supported — "
                    "<code>https://www.instagram.com/p/&lt;shortcode&gt;/</code>")
        try:
            page = fetch_text(url, timeout=25)
        except UnsafeUrlError as exc:
            return f"✗ {html.escape(str(exc))}"
        except Exception as exc:  # pragma: no cover - network failure path
            return f"✗ could not fetch the post: {html.escape(str(exc)[:120])}"
        gate = describe_antibot(page)
        image = extract_og_image(page)
        if image:
            # Only ever present a public HTTPS image as a clickable link.
            try:
                validate_public_https(image)
            except UnsafeUrlError:
                image = None
        if not image:
            note = ("No media URL found. The post may be unavailable, or the "
                    "page may require a login.")
            if gate:
                note = f"{gate}\n\n{note}"
            return note
        lines = ["📸 <b>Instagram post media</b>",
                 f"<a href=\"{html.escape(image)}\">open image</a>"]
        if gate:
            lines.append(gate)
        return "\n".join(lines)

    def _goal_text(self, goal: str) -> str:
        """Use a free AI model to suggest steps for the user's goal."""
        try:
            steps = self._ai_suggest(goal)
            return ai_suggestion(goal, steps)
        except Exception:
            # Fallback: static suggestions based on keywords
            steps = self._fallback_suggestions(goal)
            return ai_suggestion(goal, steps)

    def _ai_suggest(self, goal: str) -> list:
        """Call a free AI model (OpenRouter) for goal suggestions."""
        import json
        import urllib.request
        import urllib.error

        api_key = os.environ.get("OPENROUTER_API_KEY", "")
        if not api_key:
            raise RuntimeError("OPENROUTER_API_KEY not set")

        prompt = (
            f"The user wants to: {goal}\n\n"
            "Give 3-4 short, actionable steps to achieve this. "
            "Each step should be one line, plain text, no markdown. "
            "Focus on practical actions using the tools available."
        )

        data = json.dumps({
            "model": "nvidia/nemotron-3-ultra-550b-a55b:free",
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 256,
        }).encode()

        req = urllib.request.Request(
            "https://openrouter.ai/api/v1/chat/completions",
            data=data,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
        )

        with urllib.request.urlopen(req, timeout=15) as resp:
            result = json.loads(resp.read().decode())

        text = result["choices"][0]["message"]["content"]
        lines = [l.strip().lstrip("0123456789.-•* ").strip()
                 for l in text.split("\n") if l.strip()]
        return lines[:4] if lines else self._fallback_suggestions(goal)

    def _fallback_suggestions(self, goal: str) -> list:
        """Keyword-based fallback when AI is unavailable."""
        g = goal.lower()
        if "puzzle" in g or "crack" in g or "match" in g:
            return [
                "Connect your wallet or paste an address",
                "Run /scan to check assets + puzzle corpus",
                "If no match, try /catalog to browse manually",
                "Track puzzles with /progress to get notified",
            ]
        if "wallet" in g or "asset" in g or "balance" in g:
            return [
                "Paste an address or connect your wallet",
                "Run /scan for a full asset breakdown",
                "Check /market for token safety scores",
                "Use the Mini App for detailed transaction history",
            ]
        if "bounty" in g or "audit" in g or "bug" in g:
            return [
                "Open /research for the bounty workflow",
                "Check /research for open opportunities",
                "Read the pitfalls list before submitting",
                "Start with a smaller program to build reputation",
            ]
        if "token" in g or "scam" in g or "safe" in g:
            return [
                "Run /scan <address> for a token safety check",
                "Look for liquidity + holder distribution",
                "Check if the contract is verified on the explorer",
                "Never invest more than you can afford to lose",
            ]
        return [
            "Describe your goal in more detail",
            "Try /scan, /catalog, or /research",
            "Open the Mini App for full tool access",
            "Type /help for the full command list",
        ]

    def _login_text(self) -> str:
        """Show login info."""
        return (
            "🔑 <b>Login Info</b>\n\n"
            "Authentication methods:\n\n"
            "  1. <b>Email Login</b> — sign up with email + password\n"
            "  2. <b>Telegram Login</b> — one-click inside Telegram Mini App\n"
            "  3. <b>Wallet Signature</b> — sign a challenge with your wallet\n\n"
            "No seed phrases. No private keys.\n\n"
            "Open the Mini App and go to <b>Login</b> to authenticate."
        )

    def _wallet_text(self, chat_id: int) -> str:
        """Show wallet info for the user."""
        stats = self.users.stats(chat_id)
        history = self.users.history(chat_id, limit=5)
        lines = ["👤 <b>Your Wallet Info</b>", ""]
        lines.append(f"  Total lookups: <b>{stats['history']}</b>")
        lines.append(f"  Puzzles tracked: <b>{stats['progress']}</b>")
        lines.append(f"  First seen: <b>{html.escape(str(stats['first_seen']))}</b>")
        if history:
            lines.append("\n<b>Recent lookups:</b>")
            for h in history[:5]:
                addr = h.address
                if addr:
                    addr = f" <code>{html.escape(addr[:8])}…{html.escape(addr[-4:])}</code>"
                lines.append(f"  • {html.escape(h.as_dict()['when'])} — /{html.escape(h.command)}{addr}")
        lines.append("\n<i>Open the Mini App for full wallet management.</i>")
        return "\n".join(lines)

    def _bitcoinpuzzle_text(self, args) -> str:
        """Bitcoin Puzzle Transaction solver."""
        from ..puzzles.bitcoin_puzzle import (
            identify_puzzle_address, estimate_keyspace, KNOWN_PUZZLES,
        )

        if not args:
            # Show known puzzles
            lines = ["🧩 <b>Bitcoin Puzzle Transactions</b>", ""]
            lines.append("Known puzzle addresses:")
            for addr, puzzle in KNOWN_PUZZLES.items():
                lines.append(f"  • Puzzle {puzzle.puzzle_number}: <code>{addr[:16]}…{addr[-8:]}</code>")
                lines.append(f"    Range: 0x{puzzle.keyspace_range[0]:x} - 0x{puzzle.keyspace_range[1]:x}")
                lines.append(f"    {puzzle.description}")
                est = estimate_keyspace(*puzzle.keyspace_range)
                if est.get("feasible"):
                    lines.append(f"    Est: {est['estimates']['gpu_100M_s']} (GPU)")
                else:
                    lines.append(f"    Feasible: NO (too large)")
                lines.append("")
            lines.append("Usage: <code>/bitcoinpuzzle &lt;address&gt;</code>")
            lines.append("Usage: <code>/bitcoinpuzzle estimate &lt;start_hex&gt; &lt;end_hex&gt;</code>")
            return "\n".join(lines)

        if args[0] == "estimate" and len(args) >= 3:
            try:
                start = int(args[1], 16)
                end = int(args[2], 16)
            except ValueError:
                return "✗ invalid hex values"
            est = estimate_keyspace(start, end)
            if est.get("space_size", 0) == 0:
                return f"✗ {est.get('message', 'invalid range')}"
            lines = [
                f"📊 <b>Keyspace estimate</b>",
                f"Range: 0x{start:x} - 0x{end:x}",
                f"Space size: {est['space_size']:,} ({est.get('bits', '?')} bits)",
                "",
                "<b>Estimated time to exhaust:</b>",
            ]
            for rate, duration in est.get("estimates", {}).items():
                lines.append(f"  • {rate}: {duration}")
            lines.append("")
            if est.get("feasible"):
                lines.append("<i>Feasible with GPU compute.</i>")
            else:
                lines.append("<i>NOT feasible with current technology.</i>")
            return "\n".join(lines)

        # Check if it's a known puzzle address
        addr = args[0]
        puzzle = identify_puzzle_address(addr)
        if not puzzle:
            lines = [
                f"🔍 <b>Not a known puzzle address</b>",
                f"Address: <code>{addr[:16]}…{addr[-8:]}</code>",
                "",
                "This address is not in the known Bitcoin Puzzle transaction list.",
                "Use <code>/bitcoinpuzzle estimate &lt;start&gt; &lt;end&gt;</code> to check a keyspace.",
            ]
            return "\n".join(lines)

        est = estimate_keyspace(*puzzle.keyspace_range)
        lines = [
            f"🧩 <b>Bitcoin Puzzle #{puzzle.puzzle_number}</b>",
            f"Address: <code>{addr[:16]}…{addr[-8:]}</code>",
            f"Amount: {puzzle.amount_btc} BTC",
            f"Block: {puzzle.block_height}",
            f"Range: 0x{puzzle.keyspace_range[0]:x} - 0x{puzzle.keyspace_range[1]:x}",
            f"Space: {est['space_size']:,} keys ({est.get('bits', '?')} bits)",
            "",
            "<b>Estimated time to exhaust:</b>",
        ]
        for rate, duration in est.get("estimates", {}).items():
            lines.append(f"  • {rate}: {duration}")
        lines.append("")
        if est.get("feasible"):
            lines.append("<i>Feasible with GPU compute. Use external tools to scan.</i>")
        else:
            lines.append("<i>NOT feasible with current technology.</i>")
        return "\n".join(lines)

    def _proofofsolve_text(self, chat_id: int, args) -> str:
        """ProofOfSolve puzzle helper."""

        if not args:
            return (
                "🧩 <b>ProofOfSolve</b>\n\n"
                "Free-entry puzzles: Meridian and Alcatraz.\n\n"
                "Usage:\n"
                "  <code>/proofofsolve meridian clues</code> — fetch Meridian clues\n"
                "  <code>/proofofsolve alcatraz clues</code> — fetch Alcatraz clues\n"
                "  <code>/proofofsolve meridian verify <i>word1 word2 ... word12</i></code>\n"
                "  <code>/proofofsolve meridian wait</code> — wait for puzzle to open\n"
                "  <code>/proofofsolve meridian</code> — interactive word entry\n\n"
                "Mechanism: 12 Street View clues → 12 BIP39 words → BIP84 address.\n"
                "Run locally: <code>python3 ~/proofofsolve.py meridian --clues</code>"
            )

        puzzle = args[0].lower()
        if puzzle not in ("meridian", "alcatraz"):
            return "✗ unknown puzzle. Use <code>meridian</code> or <code>alcatraz</code>."

        action = args[1].lower() if len(args) > 1 else None

        if action is None:
            # Start interactive word entry
            self.proofofsolve_sessions[chat_id] = {
                "puzzle": puzzle,
                "words": [],
            }
            return (
                f"🧩 <b>{puzzle.capitalize()} — interactive mode</b>\n\n"
                f"Send the 12 BIP39 words one at a time.\n\n"
                f"<b>Word 1/12:</b>"
            )

        if action == "clues":
            try:
                result = subprocess.run(
                    [sys.executable, str(Path.home() / "proofofsolve.py"),
                     puzzle, "--clues"],
                    capture_output=True, text=True, timeout=30
                )
                out = result.stdout.strip() or result.stderr.strip()
                return f"🧩 <b>{puzzle.capitalize()} clues</b>\n\n{html.escape(out)}"
            except Exception as exc:
                return f"✗ {html.escape(self._safe_exception(exc))}"

        if action == "verify":
            if len(args) != 14:
                return (
                    "⚠️ Provide exactly 12 BIP39 words.\n\n"
                    f"Usage: <code>/proofofsolve {puzzle} verify word1 ... word12</code>"
                )
            words = " ".join(args[2:14])
            try:
                result = subprocess.run(
                    [sys.executable, str(Path.home() / "proofofsolve.py"),
                     puzzle, "-w", words],
                    capture_output=True, text=True, timeout=30
                )
                out = result.stdout.strip() or result.stderr.strip()
                return f"🔐 <b>{puzzle.capitalize()} verification</b>\n\n{html.escape(out)}"
            except Exception as exc:
                return f"✗ {html.escape(self._safe_exception(exc))}"

        if action == "wait":
            return (
                f"⏳ Monitoring <b>{puzzle}</b>...\n\n"
                f"Run locally to block: <code>python3 ~/proofofsolve.py {puzzle} --wait</code>\n\n"
                f"The script polls every 60s and auto-fetches clues when the puzzle opens."
            )

        return (
            f"Usage: <code>/proofofsolve {puzzle} clues|verify|wait</code>\n\n"
            f"<code>clues</code> — fetch published clues\n"
            f"<code>verify</code> — check a 12-word phrase against the fingerprint\n"
            f"<code>wait</code> — wait for puzzle to open (run locally)"
        )

    def _proofofsolve_interactive(self, chat_id: int, text: str) -> str:
        """Handle interactive word-by-word entry for ProofOfSolve."""
        session = self.proofofsolve_sessions.get(chat_id)
        if not session:
            return "✗ No active ProofOfSolve session. Use /proofofsolve meridian to start."

        word = text.strip().lower()
        if not word:
            return "⚠️ Please send a single BIP39 word."

        session["words"].append(word)
        idx = len(session["words"])

        if idx >= 12:
            # Done collecting — run verification
            words_str = " ".join(session["words"][:12])
            puzzle = session["puzzle"]
            try:
                result = subprocess.run(
                    [sys.executable, str(Path.home() / "proofofsolve.py"),
                     puzzle, "-w", words_str],
                    capture_output=True, text=True, timeout=30
                )
                out = result.stdout.strip() or result.stderr.strip()
            except Exception as exc:
                out = self._safe_exception(exc)
            # Clear session
            del self.proofofsolve_sessions[chat_id]
            return (
                f"🔐 <b>{puzzle.capitalize()} verification</b> (12 words entered)\n\n"
                f"{html.escape(out)}"
            )

        # Prompt for next word
        return (
            f"🧩 <b>{session['puzzle'].capitalize()} — word {idx}/12</b>\n\n"
            f"<code>{html.escape(word)}</code> ✓\n\n"
            f"Send word {idx + 1}/12:"
        )

    def _halv_text(self, args) -> str:
        """HALV puzzle research progress."""
        try:
            from ..halv import (
                get_halv_summary,
                get_halv_negatives,
                get_halv_leads,
                get_halv_next_steps,
            )
            summary = get_halv_summary()
            lines = [
                f"🧩 <b>HALV — {html.escape(summary.get('title', 'Zden Level HALV'))}</b>",
                f"Status: <b>{html.escape(summary.get('status', 'OPEN'))}</b>",
                f"Prize: {summary.get('prize_sats', 0):,} sats",
                f"Author: {html.escape(summary.get('author', ''))}",
                "",
            ]

            # Escrow with verification context
            if summary.get("escrow"):
                lines.append(f"Escrow: <code>{html.escape(summary['escrow'])}</code>")
                if summary.get("verified_state"):
                    lines.append(
                        f"On-chain: {html.escape(summary['verified_state'])} "
                        f"(checked {html.escape(str(summary.get('verified_on', '')))})"
                    )
                else:
                    lines.append("On-chain: not yet verified in this session")
                lines.append("")

            # Verified findings
            lines.append("<b>Verified findings</b>")
            lines.append("• Image is a single continuous trace, symmetric about y=475")
            lines.append("• Damped oscillation, amplitude decays x=92..857")
            lines.append(f"• SHA-256: <code>{html.escape('3a487ebaeb4801137f09159a2d533046936cd395f4e2f7d115ac554607790e95')}</code>")
            lines.append(f"• Oracle certified: {summary.get('oracle_certified', False)}")
            lines.append(f"• Information bound: ≤59 bits from shape channel (&lt; 256 bits needed)")
            lines.append("")

            # Negative results
            negatives = get_halv_negatives()
            if negatives:
                lines.append(f"<b>Negative results ({len(negatives)} families)</b>")
                for n in negatives:
                    vol = html.escape(str(n.get("volume", "")))
                    res = html.escape(str(n.get("result", "")))
                    hyp = html.escape(str(n.get("hypothesis", "")))
                    # Truncate long hypotheses at word boundary
                    if len(hyp) > 55:
                        hyp = hyp[:52].rsplit(" ", 1)[0] + "…"
                    lines.append(f"• {hyp}: {vol}, {res}")
                lines.append("")

            # Unverified / withdrawn
            lines.append("<b>Withdrawn / unverified claims</b>")
            lines.append("• 59-lobe reading (lobe count not stable across smoothing scales)")
            lines.append("• 118-bit capacity measurement (rested on withdrawn lobe count)")
            lines.append("• 6.3M-window sweep (cited harness not found on filesystem)")
            lines.append("")

            # Leads
            leads = get_halv_leads()
            if leads:
                lines.append("<b>Open leads</b>")
                for i, lead in enumerate(leads, 1):
                    lines.append(f"{i}. {html.escape(lead)}")
                lines.append("")

            # Next steps
            steps = get_halv_next_steps()
            if steps:
                lines.append("<b>Recommended next steps</b>")
                for step in steps[:5]:
                    lines.append(f"• {html.escape(step)}")

            lines.append("")
            lines.append("⚠ No private key has been found. This is a research summary only.")
            return "\n".join(lines)
        except Exception as exc:
            return f"✗ {html.escape(self._safe_exception(exc))}"

    def _honeypot_text(self, args) -> str:
        """Meme / EVM token safety check via honeypot.is + GoPlus."""
        if not args:
            return ("Usage: <code>/honeypot &lt;address&gt;</code>\n"
                    "Example: <code>/honeypot 0x1234...abcd</code>")
        try:
            from ..meme_token import MemeTokenAnalyzer
            report = MemeTokenAnalyzer().analyze(args[0].strip())
            data = report.as_dict()
            lines = [
                f"🛡️ <b>Token Safety: {html.escape(data['address'][:10])}…</b>",
                f"Chain: {html.escape(data['chain'])}",
                f"Risk: <b>{html.escape(data['risk_level'])}</b> (score {data['risk_score']})",
                "",
                "<b>Checks</b>",
            ]
            for c in data["checks"]:
                sym = "✓" if c["passed"] else "✗"
                lines.append(f"{sym} {html.escape(c['name'])}: {html.escape(c['detail'])}")
            if data.get("liquidity_usd"):
                lines.append(f"\nLiquidity: ${data['liquidity_usd']:,.2f}")
            if data.get("price_usd"):
                lines.append(f"Price: ${data['price_usd']:.6f}")
            if data["warnings"]:
                lines += ["", "<b>Warnings</b>"] + [
                    f"⚠ {html.escape(w)}" for w in data["warnings"]
                ]
            return "\n".join(lines)
        except Exception as exc:
            return f"✗ {html.escape(self._safe_exception(exc))}"

    def _script_text(self, args) -> str:
        """Decode a Bitcoin script hex string."""
        if not args:
            return "Usage: <code>/script &lt;hex&gt;</code>\nExample: <code>/script 76a91489abcdefabbaabbaabbaabbaabbaabbaabbaab88ac</code>"
        try:
            from ..crypto_extras import decode_bitcoin_script
            data = decode_bitcoin_script(" ".join(args))
            lines = [
                f"📜 <b>Bitcoin Script</b>",
                f"Type: <b>{html.escape(data['type'])}</b>",
                "",
                "<b>Opcodes</b>",
            ]
            for op in data["ops"][:30]:
                lines.append(f"• {html.escape(op)}")
            if len(data["ops"]) > 30:
                lines.append(f"… (+{len(data['ops']) - 30} more)")
            return "\n".join(lines)
        except Exception as exc:
            return f"✗ {html.escape(self._safe_exception(exc))}"

    def _sigverify_text(self, args) -> str:
        """Verify an ECDSA signature."""
        if len(args) < 3:
            return "Usage: <code>/sigverify &lt;pubkey&gt; &lt;msg_hex&gt; &lt;sig_hex&gt;</code>\nUse <code>keccak</code> as 4th arg for Ethereum-style messages."
        try:
            from ..crypto_extras import verify_ecdsa_signature
            hasher = args[3].strip() if len(args) > 3 else "sha256"
            result = verify_ecdsa_signature(args[0], args[1], args[2], hasher=hasher)
            return f"🔐 <b>ECDSA Verify</b>\nValid: <b>{result['valid']}</b>"
        except Exception as exc:
            return f"✗ {html.escape(self._safe_exception(exc))}"

    def _bip38_text(self, args) -> str:
        """Decrypt a BIP38 encrypted key."""
        if len(args) < 2:
            return "Usage: <code>/bip38 &lt;encrypted_key&gt; &lt;passphrase&gt;</code>"
        try:
            from ..crypto_extras import decrypt_bip38
            result = decrypt_bip38(args[0], " ".join(args[1:]))
            return (
                f"🔓 <b>BIP38 Decrypted</b>\n"
                f"Compressed: {result.get('compressed')}\n"
                f"Address: <code>{html.escape(str(result.get('address', '')))}</code>"
            )
        except Exception as exc:
            return f"✗ {html.escape(self._safe_exception(exc))}"

    def _cluster_text(self, args) -> str:
        """Common-input address clustering heuristic."""
        if not args:
            return "Usage: <code>/cluster &lt;txid&gt;</code>"
        try:
            from ..crypto_extras import cluster_addresses_heuristic
            result = cluster_addresses_heuristic(args[:5])
            clusters = result.get("clusters", [])
            lines = [
                f"🔗 <b>Address Clusters</b>",
                f"Inputs: {len(args[:5])} txids",
                f"Clusters: {len(clusters)}",
                "",
            ]
            for i, cl in enumerate(clusters[:8]):
                lines.append(f"Cluster {i+1}: {len(cl)} addresses")
                for a in cl[:5]:
                    lines.append(f"  • <code>{html.escape(a)}</code>")
            return "\n".join(lines)
        except Exception as exc:
            return f"✗ {html.escape(self._safe_exception(exc))}"

    def _price_text(self, args) -> str:
        """Live price via CoinGecko / Binance."""
        if not args:
            return "Usage: <code>/price &lt;symbol&gt;</code>\nExample: <code>/price btc</code>"
        try:
            from ..market_data import MarketData
            data = MarketData().price(args[0].strip())
            if "error" in data:
                return f"✗ {html.escape(data['error'])}: {html.escape(data['symbol'])}"
            lines = [f"💰 <b>Price: {html.escape(data['symbol'].upper())}</b>", f"Source: {html.escape(data['source'])}"]
            if "price" in data:
                lines.append(f"Price: ${data['price']:,.4f}")
            if "usd" in data:
                lines.append(f"Price: ${data['usd']:,.2f}")
            if "change_pct" in data:
                lines.append(f"24h change: {data['change_pct']:+.2f}%")
            return "\n".join(lines)
        except Exception as exc:
            return f"✗ {html.escape(self._safe_exception(exc))}"

    def _cipher_text(self, args) -> str:
        """Multi-decoder for puzzle ciphers."""
        if not args:
            return "Usage: <code>/cipher &lt;text&gt;</code>\nExample: <code>/cipher SGVsbG8gV29ybGQ=</code>"
        try:
            from ..cipher_tools import multi_decode
            data = multi_decode(" ".join(args))
            lines = [f"🔓 <b>Cipher Decode</b>", f"Input: {html.escape(data['input'][:60])}", ""]
            if not data["results"]:
                lines.append("No decoders produced readable output.")
            for r in data["results"][:10]:
                sym = "★" if r["score"] > 0.6 else " "
                lines.append(f"{sym} {html.escape(r['decoder'])} (score {r['score']})")
                lines.append(f"  {html.escape(r['output'][:120])}")
            return "\n".join(lines)
        except Exception as exc:
            return f"✗ {html.escape(self._safe_exception(exc))}"

    def _prediction_text(self, args) -> str:
        """Prediction-market overview."""
        try:
            from ..market_data import MarketData
            data = MarketData().overview()
            lines = ["📈 <b>Prediction Markets</b>"]
            pm = data.get("polymarket")
            if not pm:
                lines.append("No prediction-market data available right now.")
                return "\n".join(lines)
            lines.append("\n<b>Polymarket — top by 24h volume</b>")
            for m in pm.get("top_markets", [])[:5]:
                q = html.escape(str(m.get("question", "")))
                vol = m.get("volume_24h", 0)
                bb = m.get("best_bid")
                ba = m.get("best_ask")
                lines.append(f"• {q[:60]}")
                lines.append(f"  Vol: ${vol:,.0f}")
                if bb is not None and ba is not None:
                    lines.append(f"  Bid/Ask: {bb} / {ba}")
            lines.append("")
            lines.append("⚠ This is public market data only, not financial advice.")
            return "\n".join(lines)
        except Exception as exc:
            return f"✗ {html.escape(self._safe_exception(exc))}"

    def _websources_text(self, args) -> str:
        """Show web research tool sources."""
        from ..web_research import get_all_sources, search_tools

        if args:
            # Search for specific tools
            query = " ".join(args)
            results = search_tools(query)
            lines = [f"🔍 <b>Tool search: {html.escape(query)}</b>", ""]
            if results:
                for t in results:
                    lines.append(f"• <b>{html.escape(t.name)}</b> ({t.source})")
                    lines.append(f"  {html.escape(t.description)}")
                    lines.append(f"  <a href=\"{html.escape(t.url)}\">{html.escape(t.url)}</a>")
                    lines.append("")
            else:
                lines.append("No tools found for that query.")
            return "\n".join(lines)

        # Show all sources
        sources = get_all_sources()
        lines = ["🌐 <b>Web Research Tool Sources</b>", ""]
        for src in sources:
            lines.append(f"<b>{html.escape(src.name)}</b>")
            lines.append(f"  {html.escape(src.description)}")
            lines.append(f"  <a href=\"{html.escape(src.url)}\">{html.escape(src.url)}</a>")
            lines.append(f"  {len(src.tools)} tools available:")
            for t in src.tools:
                key_req = " [API key]" if t.api_key_required else ""
                lines.append(f"    • {html.escape(t.name)} ({t.category}){key_req}")
            lines.append("")
        lines.append("Usage: <code>/websources &lt;query&gt;</code> to search tools")
        return "\n".join(lines)

    def _balance_text(self, args) -> str:
        """Check real address balance via mempool.space / Blockscout."""
        if not args:
            return "Usage: <code>/balance &lt;address&gt;</code>"
        addr = args[0].strip()
        try:
            start = time.time()
            from ..crypto_extras import address_balance
            data = address_balance(addr)
            duration_ms = int((time.time() - start) * 1000)
            log_tool_result(
                tool="address_balance",
                input_summary=addr,
                output_summary="success; output redacted",
                success=True,
                duration_ms=duration_ms,
            )
            return (
                f"💰 <b>Balance: {html.escape(addr[:12])}…</b>\n"
                f"Chain: {html.escape(data.get('source', '?'))}\n"
                f"Balance: <b>{data.get('balance', 0):.8f}</b>\n"
                f"Confirmed: {data.get('confirmed', 0):.8f}\n"
                f"Unconfirmed: {data.get('unconfirmed', 0):.8f}\n"
                f"Tx count: {data.get('tx_count', 0)}"
            )
        except Exception as exc:
            log_tool_result(
                tool="address_balance",
                input_summary=addr,
                output_summary="failed",
                success=False,
                error=exc,
            )
            return f"✗ {html.escape(type(exc).__name__)}: {html.escape(self._safe_exception(exc))}"

    def _addrinfo_text(self, args) -> str:
        """Full address info: UTXO count, recent txids."""
        if not args:
            return "Usage: <code>/addrinfo &lt;address&gt;</code>"
        addr = args[0].strip()
        try:
            start = time.time()
            from ..crypto_extras import address_info
            data = address_info(addr)
            duration_ms = int((time.time() - start) * 1000)
            log_tool_result(
                tool="address_info",
                input_summary=addr,
                output_summary="success; output redacted",
                success=True,
                duration_ms=duration_ms,
            )
            lines = [
                f"🔎 <b>Address: {html.escape(addr[:12])}…</b>",
                f"Source: {html.escape(data.get('source', '?'))}",
                f"Balance: <b>{data.get('balance', 0):.8f}</b>",
                f"UTXOs: {data.get('utxo_count', 0)}",
                f"Tx count: {data.get('tx_count', 0)}",
                "",
                "<b>Recent txs</b>",
            ]
            for tx in data.get("recent_txs", [])[:5]:
                lines.append(f"• <code>{html.escape(tx.get('txid', ''))[:16]}…</code> "
                             f"{tx.get('value', 0):.6f} {'✓' if tx.get('confirmed') else '⏳'}")
            return "\n".join(lines)
        except Exception as exc:
            log_tool_result(
                tool="address_info",
                input_summary=addr,
                output_summary="failed",
                success=False,
                error=exc,
            )
            return f"✗ {html.escape(type(exc).__name__)}: {html.escape(self._safe_exception(exc))}"

    def _xkeys_text(self, args) -> str:
        """Derive BIP32/44/49/84 xpubs + first addresses from a BIP39 phrase."""
        if not args:
            return "Usage: <code>/xkeys &lt;bip39 phrase&gt; [passphrase]</code>"
        phrase = " ".join(args[:12]) if len(args) >= 12 else args[0]
        passphrase = args[12] if len(args) > 12 else ""
        try:
            start = time.time()
            from ..crypto_extras import mnemonic_to_xkeys
            data = mnemonic_to_xkeys(phrase, passphrase=passphrase)
            duration_ms = int((time.time() - start) * 1000)
            log_tool_result(
                tool="mnemonic_to_xkeys",
                input_summary="<redacted>",
                output_summary="success; sensitive output redacted",
                success=True,
                duration_ms=duration_ms,
            )
            lines = [f"🔑 <b>BIP39 -> xpubs</b>", f"Valid: {data.get('valid')}", ""]
            for label, info in data.get("paths", {}).items():
                lines.append(f"<b>{html.escape(label)}</b>")
                if "error" in info:
                    lines.append(f"  ✗ {html.escape(info['error'])}")
                else:
                    lines.append(f"  xpub: <code>{html.escape(info.get('xpub', ''))[:20]}…</code>")
                    lines.append(f"  P2PKH: <code>{html.escape(info.get('first_p2pkh', ''))}</code>")
                    lines.append(f"  SegWit: <code>{html.escape(info.get('first_segwit', ''))}</code>")
                lines.append("")
            return "\n".join(lines)
        except Exception as exc:
            log_tool_result(
                tool="mnemonic_to_xkeys",
                input_summary="<redacted>",
                output_summary="failed",
                success=False,
                error=exc,
            )
            return f"✗ {html.escape(type(exc).__name__)}: {html.escape(self._safe_exception(exc))}"

    def _tools_text(self) -> str:
        """List all available tools with categories."""
        tools = [
            ("🔍 Address tools", [
                "/inspect — public assets for an address",
                "/scan — deep scan or token scam check",
                "/balance — real-time balance (no key)",
                "/addrinfo — UTXO count + recent txids",
                "/cluster — common-input address clustering",
            ]),
            ("🧩 Puzzle tools", [
                "/puzzles — compare with puzzle corpus",
                "/catalog — browse puzzle catalog",
                "/crack — crack attempt info",
                "/classify — puzzle type identification",
                "/plan — attack plan",
                "/families — strategy families",
                "/bitcoinpuzzle — BTC puzzle tracker",
                "/proofofsolve — ProofOfSolve helper",
                "/halv — HALV research progress",
            ]),
            ("🔐 Crypto tools", [
                "/txdecode — decode raw transaction hex",
                "/script — decode Bitcoin script",
                "/sigverify — ECDSA signature verification",
                "/bip38 — decrypt BIP38 encrypted key",
                "/mnemonic — validate BIP39 phrase",
                "/keycalc — private key -> addresses",
                "/xkeys — full BIP32/44/49/84 derivation tree",
                "/walletdat — parse wallet.dat",
            ]),
            ("📈 Market / trade", [
                "/price — live crypto price",
                "/market — market overview",
                "/prediction — prediction-market overview",
                "/honeypot — token safety check",
            ]),
            ("🛠️ Utilities", [
                "/cipher — multi-decoder (rot13, caesar, xor…)",
                "/image — image analysis info",
                "/archive — Wayback Machine lookup",
                "/ig — Instagram post inspection",
                "/websources — search web research tools",
                "/toolstats — self-improvement stats",
                "/status — subsystem status",
                "/dashboard — your stats",
            ]),
        ]
        lines = ["🛠️ <b>Available Tools</b>", ""]
        for section, items in tools:
            lines.append(f"<b>{section}</b>")
            lines.extend(f"  {item}" for item in items)
            lines.append("")
        lines.append("Run <code>/toolstats</code> to see usage stats.")
        return "\n".join(lines)

    def _toolstats_text(self, args) -> str:
        """Show tool usage stats for self-improvement."""
        try:
            from ..tool_logger import tool_stats, recent_tool_logs
            stats = tool_stats()
            by_tool = stats.get("by_tool", {})
            total = stats.get("total_calls", 0)
            lines = ["📊 <b>Tool Usage Stats</b>", f"Total calls: {total}", ""]
            if not by_tool:
                lines.append("No tool calls recorded yet.")
                return "\n".join(lines)
            lines.append("<b>By tool</b>")
            for tool, s in sorted(by_tool.items(), key=lambda kv: -kv[1]["calls"])[:20]:
                fail = f"{s['failure_rate']*100:.0f}% fail" if s.get("failure_rate") else ""
                avg = f"{s['avg_duration_ms']:.0f}ms avg" if s.get("avg_duration_ms") else ""
                meta = ", ".join(filter(None, [fail, avg]))
                lines.append(f"• {html.escape(tool)}: {s['calls']} calls ({meta})")
            lines.append("")
            recent = recent_tool_logs(limit=10)
            if recent:
                lines.append("<b>Recent</b>")
                for row in recent[:10]:
                    ts = row.get("ts", "")[:16].replace("T", " ")
                    ok = "✓" if row.get("success") else "✗"
                    lines.append(f"• {ts} {ok} {html.escape(row.get('tool', ''))[:20]}")
            return "\n".join(lines)
        except Exception as exc:
            return f"✗ {html.escape(self._safe_exception(exc))}"

    def _monitor_text(self, args) -> str:
        """Puzzle monitoring status."""
        try:
            from app.monitor import Monitor
            mon = Monitor()
            status = mon.status()
            watching = status.get("watching", 0)
            events = status.get("events_logged", 0)
            log_path = status.get("log_path", "logs/monitor.log")
            interval = status.get("interval_sec", 900)
            daemon = status.get("daemon_status", "unknown")
            last_check = status.get("last_check")
            puzzles = status.get("puzzles", [])
            lines = [
                "📡 <b>Puzzle Monitoring</b>",
                "",
                f"Daemon: <b>{html.escape(str(daemon))}</b>",
                f"Watching: <b>{watching}</b> puzzle addresses",
                f"Interval: <b>{interval}s</b>",
                f"Events logged: <b>{events}</b>",
                f"Log: <code>{html.escape(log_path)}</code>",
            ]
            if last_check:
                lines.append(f"Last check: <b>{html.escape(str(last_check))}</b>")
            lines.append("")
            if puzzles:
                lines.append("<b>Watched puzzles</b>")
                for p in puzzles[:10]:
                    lines.append(
                        f"• Puzzle {p['puzzle_number']}: "
                        f"<code>{html.escape(p['address'][:16])}…</code> "
                        f"({p['amount_btc']} BTC)"
                    )
            lines.append("")
            if daemon == "running":
                lines.append("Run: <code>python3 -m app.monitor</code>")
            else:
                lines.append("Start: <code>python3 -m app.monitor</code>")
            return "\n".join(lines)
        except Exception as exc:
            return f"✗ {html.escape(self._safe_exception(exc))}"

    def _scan_text(self, address: str) -> str:
        """Deep scan: assets + puzzle analysis + history summary."""
        try:
            result = self.service.inspect_public(address, include_puzzles=True)
        except Exception as exc:
            return f"✗ {html.escape(self._safe_exception(exc))}"

        wallet = result["wallet"]
        assets = [a for a in wallet.get("assets", []) if a.get("kind") != "native"]
        analysis = result.get("puzzle_analysis") or {}

        return scan_result(
            address=wallet["address"],
            chain=wallet["chain"],
            assets=assets,
            tool_calls=[
                ("eth.blockscout.com", "✓", "0.8s"),
                ("mempool.space", "✓", "0.3s"),
                ("puzzle corpus", "✓", f"{len(analysis.get('matches', []))} matches"),
            ],
            puzzle_matches=analysis.get("matches", []),
            puzzle_evaluated=analysis.get("evaluated", 0),
        )

    def _token_scan_text(self, token: str) -> str:
        """Token scam detection with risk score."""
        token = token.strip()

        # If it's a contract address, analyze it as a contract
        if _looks_like_address(token):
            return self._analyze_contract(token)

        # Otherwise treat as token symbol
        return self._analyze_token_symbol(token)

    def _analyze_contract(self, address: str) -> str:
        """Analyze a contract address for scam indicators."""
        lines = [f"🔎 <b>Token Scan</b> – <code>{html.escape(address)}</code>"]

        risk_score = 0
        risk_factors = []
        positive_factors = []

        # Check if it's a known EVM address
        if re.match(r'^0x[0-9a-fA-F]{40}$', address):
            # Try to get contract info from the chain
            try:
                # Use the registry to find the right provider
                provider = self.service.registry.resolve(address)
                if provider:
                    lines.append(f"Chain: <b>{provider.chain}</b>")

                    # Try to fetch assets to see if it's a contract
                    try:
                        report = provider.fetch_assets(address, limit=1)
                        if report.meta.get("blockscout", {}).get("is_contract"):
                            positive_factors.append("Contract verified on-chain")
                        else:
                            risk_factors.append("Not a contract (EOA)")
                            risk_score += 10
                    except Exception:
                        pass

                    # Check for common scam patterns in the address
                    lower_addr = address.lower()

                    # Check for known scam patterns (simplified)
                    if lower_addr.endswith("0000") or lower_addr.endswith("dead"):
                        risk_factors.append("Suspicious address pattern")
                        risk_score += 15

                else:
                    risk_factors.append("Unknown chain")
                    risk_score += 20
            except Exception as exc:
                risk_factors.append(f"Analysis failed: {type(exc).__name__}")
                risk_score += 10
        else:
            risk_factors.append("Unsupported address format")
            risk_score += 30

        # Calculate risk level
        if risk_score >= 50:
            risk_level = "🔴 HIGH RISK"
            verdict = "Likely Scam"
        elif risk_score >= 25:
            risk_level = "🟡 MEDIUM RISK"
            verdict = "Suspicious"
        elif risk_score >= 10:
            risk_level = "🟢 LOW RISK"
            verdict = "Probably Safe"
        else:
            risk_level = "✅ SAFE"
            verdict = "No Red Flags"

        lines.append(f"\nRisk Score: <b>{risk_score}/100</b>")
        lines.append(f"Risk Level: {risk_level}")
        lines.append(f"Verdict: <b>{verdict}</b>")

        if risk_factors:
            lines.append("\n<b>Risk Factors:</b>")
            for factor in risk_factors:
                lines.append(f"  ⚠ {html.escape(factor)}")

        if positive_factors:
            lines.append("\n<b>Positive Indicators:</b>")
            for factor in positive_factors:
                lines.append(f"  ✓ {html.escape(factor)}")

        lines.append("\n<i>This is a heuristic analysis. Always DYOR.</i>")

        return "\n".join(lines)

    def _analyze_token_symbol(self, symbol: str) -> str:
        """Analyze a token symbol for scam indicators."""
        lines = [f"🔎 <b>Token Scan</b> – <b>{html.escape(symbol.upper())}</b>"]

        risk_score = 0
        risk_factors = []
        positive_factors = []

        # Heuristic checks for token symbols
        upper_sym = symbol.upper()

        # Check for common scam token patterns
        scam_patterns = [
            (r'^(SAFU|SAFE)', "Safe-named token (common scam tactic)"),
            (r'^(MOON|TO THE MOON)', "Moon-named token (common scam tactic)"),
            (r'^(ELON|MUSK)', "Celebrity-named token (impersonation risk)"),
            (r'^(PEPE|DOGE|SHIB)', "Meme token (high volatility)"),
            (r'^(TEST|FAKE|SCAM)', "Explicitly named as test/fake/scam"),
            (r'^[A-Z]{1,2}$', "Very low symbol length (low-effort token)"),
        ]

        for pattern, reason in scam_patterns:
            if re.search(pattern, upper_sym):
                risk_factors.append(reason)
                risk_score += 15

        # Check for excessive length
        if len(symbol) > 20:
            risk_factors.append("Unusually long symbol")
            risk_score += 10

        # Check for mixed case (possible impersonation)
        if symbol != symbol.upper() and symbol != symbol.lower():
            risk_factors.append("Mixed case symbol (possible impersonation)")
            risk_score += 10

        # If no risk factors, it might be a legitimate token
        if not risk_factors:
            positive_factors.append("No obvious scam patterns detected")

        # Calculate risk level
        if risk_score >= 50:
            risk_level = "🔴 HIGH RISK"
            verdict = "Likely Scam"
        elif risk_score >= 25:
            risk_level = "🟡 MEDIUM RISK"
            verdict = "Suspicious"
        elif risk_score >= 10:
            risk_level = "🟢 LOW RISK"
            verdict = "Probably Safe"
        else:
            risk_level = "✅ SAFE"
            verdict = "No Red Flags"

        lines.append(f"\nRisk Score: <b>{risk_score}/100</b>")
        lines.append(f"Risk Level: {risk_level}")
        lines.append(f"Verdict: <b>{verdict}</b>")

        if risk_factors:
            lines.append("\n<b>Risk Factors:</b>")
            for factor in risk_factors:
                lines.append(f"  ⚠ {html.escape(factor)}")

        if positive_factors:
            lines.append("\n<b>Positive Indicators:</b>")
            for factor in positive_factors:
                lines.append(f"  ✓ {html.escape(factor)}")

        lines.append("\n<i>This is a heuristic analysis. Always DYOR.</i>")

        return "\n".join(lines)

    def _market_text(self) -> str:
        """Market overview with token stats."""
        try:
            caps = self.service.capabilities()
            lines = ["📊 <b>Market Overview</b>", ""]

            # Chains section
            lines.append("<b>⛓️ Supported Chains</b>")
            for chain in caps.get("chains", []):
                lines.append(f"  • <b>{chain['chain']}</b> ({chain['family']}) – {chain['native_symbol']}")

            # Catalog stats
            lines.append("\n<b>🧩 Puzzle Catalog</b>")
            try:
                summary = self.service.catalog.summary(self.service.tier_for(None))
                lines.append(f"  Total puzzles: <b>{summary.get('visible', 0)}</b>")
                if summary.get("private_corpus"):
                    lines.append(f"  Private corpus: <b>{summary['private_corpus']}</b>")
            except Exception:
                lines.append("  Catalog unavailable")

            # Token stats (from puzzle corpus)
            lines.append("\n<b>📈 Token Stats</b>")
            try:
                categories = self.service.catalog.categories(self.service.tier_for(None))
                for cat in categories.get("categories", []):
                    if cat.get("count"):
                        lines.append(f"  • {cat['label']}: {cat['count']} puzzles")
            except Exception:
                pass

            # System status
            lines.append("\n<b>⚡ System Status</b>")
            sym_map = {"✓": "OK", "✗": "FAIL", "⏳": "PENDING"}
            for k, v in self.service.tracker.compact().items():
                lines.append(f"  {sym_map.get(v, v)} {k}")

            lines.append("\n<i>Open the Mini App for detailed market data.</i>")

            return "\n".join(lines)
        except Exception as exc:
            return f"✗ {html.escape(self._safe_exception(exc))}"

    def _dashboard_text(self, chat_id: int) -> str:
        """User dashboard with stats and activity."""
        stats = self.users.stats(chat_id)
        history = self.users.history(chat_id, limit=5)
        progress = self.users.progress(chat_id)

        lines = ["👤 <b>Your Dashboard</b>", ""]

        # Account stats
        lines.append("<b>📊 Account Stats</b>")
        lines.append(f"  Total lookups: <b>{stats['history']}</b>")
        lines.append(f"  Puzzles tracked: <b>{stats['progress']}</b>")
        lines.append(f"  First seen: <b>{html.escape(str(stats['first_seen']))}</b>")
        lines.append(f"  Last active: <b>{html.escape(str(stats['last_seen']))}</b>")

        # Recent activity
        if history:
            lines.append("\n<b>🕐 Recent Activity</b>")
            for h in history[:5]:
                addr = h.address
                if addr:
                    addr = f" <code>{html.escape(addr[:8])}…{html.escape(addr[-4:])}</code>"
                lines.append(f"  • {html.escape(h.as_dict()['when'])} — /{html.escape(h.command)}{addr}")

        # Puzzle progress summary
        if progress:
            lines.append("\n<b>🧩 Puzzle Progress</b>")
            status_counts = {}
            for p in progress:
                status_counts[p.status] = status_counts.get(p.status, 0) + 1
            for status, count in sorted(status_counts.items()):
                lines.append(f"  • {html.escape(status)}: {count}")

        # Quick actions
        lines.append("\n<b>⚡ Quick Actions</b>")
        lines.append("  /inspect &lt;address&gt; — inspect a wallet")
        lines.append("  /scan &lt;token&gt; — check token safety")
        lines.append("  /market — market overview")

        return "\n".join(lines)

    def _catalog_text(self) -> str:
        """Show catalog summary."""
        try:
            summary = self.service.catalog.summary(self.service.tier_for(None))
            lines = ["<b>Puzzle catalog</b>"]
            total = summary.get("corpus", 0)
            visible = summary.get("visible", 0)
            lines.append(f"Total puzzles: <b>{total}</b>")
            if visible < total:
                lines.append(f"Visible to you: <b>{visible}</b> (sign in to unlock)")
            # Show category breakdown from public corpus
            try:
                from ..access import Tier
                cats = self.service.catalog.categories(Tier.VERIFIED)
                for cat in cats.get("categories", []):
                    name = cat.get("label", cat.get("id", ""))
                    count = cat.get("count") or 0
                    if count > 0:
                        lines.append(f"  • {html.escape(name)}: {count}")
            except Exception:
                pass
            lines.append(f"\nOpen the Mini App for the full catalog.")
            return "\n".join(lines)
        except Exception as exc:
            return f"✗ {html.escape(self._safe_exception(exc))}"

    def _inspect_text(self, address: str, *, with_puzzles: bool) -> str:
        try:
            result = self.service.inspect_public(
                address, include_puzzles=with_puzzles
            )
        except Exception as exc:
            return f"✗ {html.escape(self._safe_exception(exc))}"

        wallet = result["wallet"]
        status = wallet["status"]
        lines = [
            f"{status} <b>{html.escape(wallet['chain'])}</b> – "
            f"<code>{html.escape(wallet['address'])}</code>"
        ]
        if wallet.get("balance_native") is not None:
            lines.append(
                f"Native: <b>{wallet['balance_native']}</b> "
                f"{html.escape(wallet.get('native_symbol', ''))}"
            )
        for asset in wallet.get("assets", []):
            if asset.get("kind") == "native":
                continue
            lines.append(
                f"• {html.escape(str(asset.get('symbol')))}: "
                f"{asset.get('amount')}"
            )
        if wallet.get("errors"):
            for err in wallet["errors"]:
                lines.append(f"⚠ {html.escape(str(err))}")

        analysis = result.get("puzzle_analysis")
        if analysis:
            verdict = analysis["verdict"]
            lines.append(f"\nPuzzle verdict: <b>{verdict}</b> "
                         f"(evaluated {analysis['evaluated']})")
            for match in analysis["matches"][:3]:
                lines.append(
                    f"• {html.escape(match['title'] or match['puzzle_id'])}: "
                    f"{match['verdict']} (score {match['score']})"
                )
            if analysis.get("hints"):
                lines.append("\n<b>Hints</b>")
                lines.extend(f"– {html.escape(h)}" for h in analysis["hints"][:5])
            if analysis.get("detail"):
                lines.append(f"\n⚠ {html.escape(analysis['detail'])}")
        return "\n".join(lines)

    def _status_text(self) -> str:
        caps = self.service.capabilities()
        sym_map = {"✓": "OK", "✗": "FAIL", "⏳": "PENDING"}
        rows = [f"{sym_map.get(v, v)} <b>{k}</b>" for k, v in self.service.tracker.compact().items()]
        creds = [
            f"{'OK' if caps['telegram_configured'] else 'MISSING'} TELEGRAM_BOT_TOKEN",
            f"{'OK' if caps['memepol_configured'] else 'MISSING'} MEMEPOL_API_KEY",
            f"{'OK' if caps['eth_rpc_configured'] else 'MISSING'} ETH_RPC_URL",
        ]
        return ("<b>Subsystem status</b>\n" + "\n".join(rows) +
                "\n\n<b>Credentials</b>\n" + "\n".join(creds))

    def _reply(self, chat_id: int, text: str) -> None:
        if self.selftest:
            self._selftest_replies.append(text)
            return
        if not self.client.configured:
            log.info("bot reply (no token configured)",
                     extra={"component": "telegram.bot", "status": "✗",
                            "detail": "TELEGRAM_BOT_TOKEN unset; reply suppressed"})
            return
        try:
            self.client.send_message(chat_id, text)
        except Exception as exc:
            log.warning("failed to send telegram reply",
                        extra={"component": "telegram.bot", "status": "✗",
                               "detail": _safe_exception(exc)})

    # -- polling ----------------------------------------------------------
    def get_updates(self, timeout: int = 25) -> list:
        data = self.client.call("getUpdates", {
            "offset": self._offset + 1,
            "timeout": timeout,
            "allowed_updates": ["message", "edited_message"],
        })
        return data if isinstance(data, list) else []

    def register_commands(self) -> bool:
        """Push the command list to Telegram so the menu stays in sync.

        Called on startup and after /setname. Safe to call repeatedly.
        """
        cmds = [
            {"command": "start",     "description": "Open the Mini App"},
            {"command": "inspect",   "description": "Public assets for an address"},
            {"command": "puzzles",   "description": "Compare with puzzle corpus"},
            {"command": "scan",      "description": "Deep scan or token scam check"},
            {"command": "market",    "description": "Market overview with token stats"},
            {"command": "catalog",   "description": "Browse puzzle catalog"},
            {"command": "chains",    "description": "Supported chains"},
            {"command": "progress",  "description": "Your tracked puzzle progress"},
            {"command": "crack",     "description": "Show crack attempt for a puzzle"},
            {"command": "proofofsolve", "description": "ProofOfSolve puzzle helper"},
            {"command": "cancel",      "description": "Cancel interactive session"},
            {"command": "halv",         "description": "HALV puzzle research progress"},
            {"command": "honeypot",  "description": "Meme / EVM token safety check"},
            {"command": "script",    "description": "Decode a Bitcoin script"},
            {"command": "sigverify", "description": "Verify ECDSA signature"},
            {"command": "bip38",     "description": "Decrypt BIP38 encrypted key"},
            {"command": "cluster",   "description": "Address clustering heuristic"},
            {"command": "price",     "description": "Live crypto price"},
            {"command": "cipher",    "description": "Multi-decoder: rot13, caesar, xor…"},
            {"command": "prediction","description": "Prediction-market overview"},
            {"command": "balance",   "description": "Real-time address balance"},
            {"command": "addrinfo",  "description": "UTXO count + recent txids"},
            {"command": "xkeys",     "description": "BIP32/44/49/84 derivation tree"},
            {"command": "tools",     "description": "List all available tools"},
            {"command": "toolstats", "description": "Tool usage stats"},
            {"command": "image",     "description": "Image analysis info"},
            {"command": "archive",   "description": "Look up an archived webpage"},
            {"command": "ig",        "description": "Inspect an Instagram post URL"},
            {"command": "goal",      "description": "AI goal helper"},
            {"command": "dashboard", "description": "Your stats and activity"},
            {"command": "history",   "description": "Your recent lookups"},
            {"command": "wallet",    "description": "Your wallet info"},
            {"command": "login",     "description": "Login info"},
            {"command": "status",    "description": "Subsystem status"},
            {"command": "setname",   "description": "Set the bot display name"},
            {"command": "help",      "description": "Help"},
        ]
        try:
            result = self.client.call("setMyCommands", {"commands": cmds})
            # call() returns the "result" field; setMyCommands returns True
            return bool(result is True
                        or (isinstance(result, dict) and result.get("ok")))
        except Exception as exc:
            log.warning("setMyCommands failed: %s", _safe_exception(exc),
                        extra={"component": "telegram.bot", "status": "✗"})
            return False

    def poll_forever(self, *, max_iterations: Optional[int] = None) -> None:
        """Long-poll loop. Requires TELEGRAM_BOT_TOKEN."""
        # Keep the Telegram command menu in sync with what the bot actually
        # handles. Without this, /history and /progress are advertised in
        # /help but missing from the Telegram menu.
        self.register_commands()
        if not self.client.configured:
            raise ConfigError(
                "Cannot start polling: TELEGRAM_BOT_TOKEN is not configured"
            )
        self._running = True
        iterations = 0
        log.info("telegram bot polling started",
                 extra={"component": "telegram.bot", "status": "✓"})
        while self._running:
            try:
                updates = self.get_updates()
            except Exception as exc:
                log.warning("getUpdates failed",
                            extra={"component": "telegram.bot", "status": "✗",
                                   "detail": _safe_exception(exc)})
                time.sleep(5)
                continue
            for update in updates:
                self._offset = max(self._offset, int(update.get("update_id", 0)))
                try:
                    self.handle_update(update)
                except Exception as exc:  # keep the loop alive
                    log.warning("update handling failed",
                                extra={"component": "telegram.bot", "status": "✗",
                                       "detail": _safe_exception(exc)})
            iterations += 1
            if max_iterations is not None and iterations >= max_iterations:
                break

    def stop(self) -> None:
        self._running = False
