"""Telegram Bot API backend.

Read-only bot: it reports status and runs public-address lookups. It never
asks for a seed phrase or private key, and never signs or broadcasts
anything. The bot token comes from the environment only.
"""

from __future__ import annotations

import html
import re
import time
from pathlib import Path
from typing import Any, Dict, Optional

from ..config import Settings, get_settings, is_placeholder
from ..errors import ConfigError
from ..http import HttpClient
from ..logging_setup import get_logger, register_secret
from ..service import WalletService
from ..users import UserStore

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
        "  /image — image analysis info\n\n"
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
        self.http = http or HttpClient(timeout=35.0, max_retries=4, backoff=1.0)
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
                 users: Optional[UserStore] = None):
        self.settings = settings or get_settings()
        self.service = service or WalletService(self.settings)
        self.client = client or TelegramClient(self.settings.telegram_bot_token)
        self.users = users or UserStore(
            Path(self.settings.log_dir).parent / ".run" / "users.json")
        self._offset = 0
        self._running = False

    # -- handlers ---------------------------------------------------------
    def handle_update(self, update: Dict[str, Any]) -> Optional[str]:
        message = update.get("message") or update.get("edited_message") or {}
        chat = message.get("chat") or {}
        chat_id = chat.get("id")
        text = (message.get("text") or "").strip()
        if chat_id is None or not text:
            return None
        return self.handle_command(chat_id, text)

    def handle_command(self, chat_id: int, text: str) -> str:
        parts = text.split()
        command = parts[0].split("@")[0].lower()
        args = parts[1:]

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
        elif command == "/image":
            reply = self._image_text()
        elif command == "/login":
            reply = self._login_text()
        elif command == "/wallet":
            reply = self._wallet_text(chat_id)
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
            return f"✗ {html.escape(type(exc).__name__)}: {html.escape(str(exc))}"

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

    def _scan_text(self, address: str) -> str:
        """Deep scan: assets + puzzle analysis + history summary."""
        try:
            result = self.service.inspect_public(address, include_puzzles=True)
        except Exception as exc:
            return f"✗ {html.escape(type(exc).__name__)}: {html.escape(str(exc))}"

        wallet = result["wallet"]
        lines = [f"<b>Deep scan</b> – <code>{html.escape(wallet['address'])}</code>"]
        lines.append(f"Chain: <b>{html.escape(wallet['chain'])}</b> – {wallet['status']}")

        if wallet.get("balance_native") is not None:
            lines.append(f"Native: <b>{wallet['balance_native']} {html.escape(wallet.get('native_symbol', ''))}</b>")

        for asset in wallet.get("assets", []):
            if asset.get("kind") == "native":
                continue
            lines.append(f"  • {html.escape(str(asset.get('symbol')))}: {asset.get('amount')}")

        analysis = result.get("puzzle_analysis")
        if analysis:
            lines.append(f"\nPuzzle verdict: <b>{analysis['verdict']}</b>")
            for match in analysis.get("matches", [])[:3]:
                lines.append(f"  • {html.escape(match.get('title') or match.get('puzzle_id', ''))}: {match['verdict']}")
            if analysis.get("hints"):
                lines.append("<b>Hints</b>")
                lines.extend(f"  – {html.escape(h)}" for h in analysis["hints"][:5])

        if wallet.get("errors"):
            for err in wallet["errors"]:
                lines.append(f"⚠ {html.escape(str(err))}")

        return "\n".join(lines)

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
            return f"✗ {html.escape(type(exc).__name__)}: {html.escape(str(exc))}"

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
                from .access import Tier
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
            return f"✗ {html.escape(type(exc).__name__)}: {html.escape(str(exc))}"

    def _inspect_text(self, address: str, *, with_puzzles: bool) -> str:
        try:
            result = self.service.inspect_public(
                address, include_puzzles=with_puzzles
            )
        except Exception as exc:
            return f"✗ {html.escape(type(exc).__name__)}: {html.escape(str(exc))}"

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
                               "detail": f"{type(exc).__name__}: {exc}"})

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
            {"command": "image",     "description": "Image analysis info"},
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
            return result is True or (isinstance(result, dict) and result.get("ok"))
        except Exception as exc:
            log.warning("setMyCommands failed: %s", exc,
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
                                   "detail": f"{type(exc).__name__}: {exc}"})
                time.sleep(5)
                continue
            for update in updates:
                self._offset = max(self._offset, int(update.get("update_id", 0)))
                try:
                    self.handle_update(update)
                except Exception as exc:  # keep the loop alive
                    log.warning("update handling failed",
                                extra={"component": "telegram.bot", "status": "✗",
                                       "detail": f"{type(exc).__name__}: {exc}"})
            iterations += 1
            if max_iterations is not None and iterations >= max_iterations:
                break

    def stop(self) -> None:
        self._running = False
