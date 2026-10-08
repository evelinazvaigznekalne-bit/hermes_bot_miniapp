"""Mini App backend HTTP server (standard library only).

Serves the static Mini App frontend plus a small JSON API:

  GET  /health                     liveness + capability flags
  GET  /api/status                 subsystem ✓/✗/⏳ status
  GET  /api/chains                 registered chains
  GET  /api/paypal/config          pricing + browser-safe PayPal client id
  GET  /api/catalog/config         catalog feature flags
  POST /api/catalog/categories     chain categories (tier-gated counts)
  POST /api/catalog/tabs           status tabs (tier-gated counts)
  POST /api/catalog/items          tier-gated listing
  POST /api/catalog/item           single listing detail
  POST /api/catalog/summary        corpus summary for the caller's tier
  POST /api/auth/challenge         issue a signing challenge
  POST /api/auth/verify            verify signature -> session token
  POST /api/wallet/assets          read-only public asset lookup
  POST /api/telegram/validate      validate Mini App initData
  POST /api/security/scan          detect secret-shaped text (never stores)
  POST /api/paypal/orders          create a PayPal order (session required)
  POST /api/paypal/capture         capture + grant the tier (session required)
  POST /api/paypal/entitlement     report the caller's own entitlement
  POST /api/inventory              metadata-only file listing (owner only)
  POST /api/inventory/listing      printable file listing (owner only)

No transaction endpoint exists. Nothing here can move funds. The payment
endpoints only ever *grant access*; they cannot send money anywhere.
"""

from __future__ import annotations

import json
import mimetypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple
from urllib.parse import urlparse

from ..errors import AppError, SignatureError
from ..logging_setup import get_logger
from ..payments.paypal import PayPalError
from ..service import WalletService
from ..telegram.webapp_auth import validate_init_data
from ..errors import ValidationError
from ..access import Tier, tier_summary
from ..market import TokenScanner
from ..tools import analyze_file, decode_data, analyze_data, simulate_sweep, crack_list
from ..users import UserStore
from .ratelimit import RateLimiter

log = get_logger()

MAX_BODY_BYTES = 64 * 1024

STATIC_DIR = Path(__file__).resolve().parent / "static"

Route = Tuple[str, Callable[..., Any]]


class MiniAppAPI:
    """Transport-independent API surface (directly unit-testable)."""

    def __init__(self, service: WalletService, settings=None, *,
                 limiter: Optional[RateLimiter] = None):
        self.service = service
        self.settings = settings or service.settings
        self.limiter = limiter

    # -- GET --------------------------------------------------------------
    def health(self) -> Dict[str, Any]:
        return {
            "ok": True,
            "read_only": True,
            "secrets_requested": False,
            **self.service.capabilities(),
        }

    def status(self) -> Dict[str, Any]:
        return {
            "statuses": self.service.tracker.compact(),
            "details": self.service.tracker.snapshot(),
        }

    def chains(self) -> Dict[str, Any]:
        return {"chains": self.service.registry.describe()}

    # -- POST -------------------------------------------------------------
    def challenge(self, body: Dict[str, Any]) -> Dict[str, Any]:
        address = body.get("address")
        if not address:
            raise SignatureError("'address' is required")
        return self.service.issue_challenge(address)

    def verify(self, body: Dict[str, Any]) -> Dict[str, Any]:
        for field in ("address", "signature", "nonce"):
            if not body.get(field):
                raise SignatureError(f"'{field}' is required")
        result = self.service.verify(
            body["address"], body["signature"], body["nonce"],
            message=body.get("message"),
        )
        return result.as_dict()

    def assets(self, body: Dict[str, Any]) -> Dict[str, Any]:
        address = body.get("address")
        if not address:
            raise SignatureError("'address' is required")
        token = body.get("session_token")
        verified_address = None
        if token:
            verified_address = self.service.require_session(token)

        # The caller may only see their OWN tier's data. An unverified caller is
        # anonymous even if they ask for a different address.
        owns_address = bool(
            verified_address and verified_address.lower() == str(address).lower()
        )
        tier = (self.service.tier_for(verified_address) if owns_address
                else Tier.ANONYMOUS)

        payload = self.service.inspect_public(
            address,
            chain=body.get("chain"),
            include_puzzles=bool(body.get("include_puzzles")),
            tier=tier,
        )
        payload["verified"] = owns_address
        payload["entitlements"] = tier_summary(tier)
        return payload

    def telegram_validate(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Validate Telegram WebApp initData (HMAC) without a bot token in dev."""
        init_data = body.get("init_data") or ""
        if not init_data:
            raise SignatureError("init_data is required")
        if not self.settings.telegram_configured:
            return {
                "valid": False,
                "detail": "TELEGRAM_BOT_TOKEN not configured; cannot verify HMAC",
                "status": "⏳",
            }
        result = validate_init_data(init_data, self.settings.telegram_bot_token)
        result["status"] = "✓" if result.get("valid") else "✗"
        return result

    def telegram_auth(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Validate Telegram initData and issue a session token.

        Flow:
        1. Client sends Telegram.WebApp.initData
        2. Server validates HMAC signature using bot token
        3. Server creates/retrieves user record
        4. Server issues HMAC-signed session token
        5. Client uses token for all subsequent API calls
        """
        init_data = body.get("init_data") or ""
        if not init_data:
            raise SignatureError("init_data is required")
        if not self.settings.telegram_configured:
            raise SignatureError("TELEGRAM_BOT_TOKEN not configured")

        user = validate_init_data(init_data, self.settings.telegram_bot_token)
        user_id = str(user.id)

        # Create or update user record
        self.users.record(user_id, command="telegram_auth")

        # Issue session token (reuse SessionIssuer from auth module)
        from ..auth import SessionIssuer
        issuer = SessionIssuer(secret=self.settings.session_secret)
        token, expires = issuer.issue(user_id)

        return {
            "valid": True,
            "user": {
                "id": user.id,
                "name": user.display_name,
                "username": user.username,
                "is_premium": user.is_premium,
            },
            "session_token": token,
            "expires_at": expires,
            "tier": "verified",
        }

    # -- secret-shape detection (warn, never store) -----------------------
    def scan_secrets(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Detect secret-shaped input and return a warning.

        The matched value is never echoed, stored, or logged. Only a masked
        preview and remediation advice are returned. `span` offsets are included
        so a caller can redact in place without ever holding the raw string.
        """
        from ..security import scan as _scan

        text = body.get("text") or ""
        if not isinstance(text, str):
            raise ValidationError("text must be a string")
        if len(text) > 200_000:
            raise ValidationError("text too large to scan (max 200000 chars)")

        findings = _scan(text)
        return {
            "clean": not findings,
            "count": len(findings),
            "findings": [f.as_dict() for f in findings],
            "notice": "This service never stores or transmits matched secrets.",
            "status": "✓" if not findings else "✗",
        }

    # -- payments ---------------------------------------------------------
    def paypal_config(self) -> Dict[str, Any]:
        """Public pricing + browser-safe client id. Never returns the secret."""
        checkout = self.service.checkout
        cfg = checkout.describe()
        cfg["status"] = "✓" if cfg["configured"] else "⏳"
        if cfg["configured"]:
            # The client id is designed to be public in PayPal's Web SDK; the
            # secret stays server-side.
            cfg["client_id"] = self.settings.paypal_client_id
        else:
            cfg["detail"] = (
                "PayPal not configured: set PAYPAL_CLIENT_ID and "
                "PAYPAL_CLIENT_SECRET in .env"
            )
        return cfg

    def paypal_create_order(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Create an order bound to the session-verified address.

        A verified session is required so an entitlement can never be granted
        to an address the caller did not prove they control.
        """
        token = body.get("session_token")
        if not token:
            raise SignatureError("session_token is required to start a purchase")
        address = self.service.require_session(token)
        sku = str(body.get("sku") or "").strip()
        if not sku:
            raise ValidationError("'sku' is required")
        return self.service.checkout.create_order(sku=sku, address=address)

    def paypal_capture_order(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Capture an approved order and grant the tier."""
        token = body.get("session_token")
        if not token:
            raise SignatureError("session_token is required to capture")
        address = self.service.require_session(token)
        order_id = str(body.get("order_id") or "").strip()
        if not order_id:
            raise ValidationError("'order_id' is required")
        return self.service.checkout.capture_order(order_id=order_id,
                                                   address=address)

    def paypal_entitlement(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Report the caller's own entitlement (session-bound, read-only)."""
        token = body.get("session_token")
        if not token:
            raise SignatureError("session_token is required")
        address = self.service.require_session(token)
        return {
            "address": address,
            "entitlement": self.service.checkout.entitlement_for(address),
            "tier": self.service.tier_for(address).value,
        }

    # -- catalog (public reads; tier from the session) ---------------------
    def _caller_tier(self, body: Dict[str, Any]) -> Tier:
        """Resolve the caller's tier, or ANONYMOUS when no session is given."""
        token = body.get("session_token")
        if not token:
            return Tier.ANONYMOUS
        try:
            return self.service.tier_for(self.service.require_session(token))
        except Exception:
            # A bad/expired token is not an error for a public read — it just
            # means the caller is anonymous.
            return Tier.ANONYMOUS

    def catalog_config(self) -> Dict[str, Any]:
        return self.service.catalog.config(settings=self.settings)

    def catalog_categories(self, body: Dict[str, Any]) -> Dict[str, Any]:
        return self.service.catalog.categories(self._caller_tier(body))

    def catalog_tabs(self, body: Dict[str, Any]) -> Dict[str, Any]:
        return self.service.catalog.tabs(self._caller_tier(body))

    def catalog_items(self, body: Dict[str, Any]) -> Dict[str, Any]:
        tier = self._caller_tier(body)
        payload = self.service.catalog.items(
            tier,
            category=body.get("category"),
            tab=body.get("tab"),
            limit=int(body.get("limit") or 20),
            offset=int(body.get("offset") or 0),
        )
        payload["status"] = "✓"
        return payload

    def catalog_item(self, body: Dict[str, Any]) -> Dict[str, Any]:
        tier = self._caller_tier(body)
        sku = str(body.get("sku") or "").strip()
        if not sku:
            raise ValidationError("'sku' is required")
        detail = self.service.catalog.item_detail(tier, sku)
        if detail is None:
            raise ValidationError(f"unknown sku {sku!r}")
        detail["status"] = "✓"
        return detail

    def catalog_summary(self, body: Dict[str, Any]) -> Dict[str, Any]:
        return self.service.catalog.summary(self._caller_tier(body))

    # -- inventory (operator-only) ----------------------------------------
    def _require_owner(self, body: Dict[str, Any]) -> str:
        """Inventory lists this device's files — owner session only."""
        token = body.get("session_token")
        if not token:
            raise SignatureError("session_token is required")
        address = self.service.require_session(token)
        if self.service.tier_for(address) is not Tier.OWNER:
            # Same response whether the session is invalid or merely unpaid, so
            # a paid user cannot probe for the existence of the feature.
            raise SignatureError("this endpoint requires the owner tier")
        return address

    def inventory(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Metadata-only file listing. Contents are never read."""
        self._require_owner(body)
        redact = body.get("redact")
        redact = True if redact is None else bool(redact)

        roots = body.get("roots")
        if roots is not None:
            if not isinstance(roots, list) or not roots:
                raise ValidationError("'roots' must be a non-empty list")
            roots = [str(r) for r in roots]
        else:
            roots = list(self.settings.inventory_roots)

        from ..inventory import build_inventory, summarize

        result = build_inventory(
            roots,
            max_depth=int(body.get("max_depth")
                          or self.settings.inventory_max_depth),
            max_files=int(body.get("max_files")
                          or self.settings.inventory_max_files),
            hashes=bool(body.get("hashes", True)),
        )
        payload = summarize(result, redact=redact)
        if body.get("include_entries"):
            payload["entries"] = [e.as_dict(redact=redact)
                                  for e in result.entries[:500]]
        payload["status"] = "✓"
        return payload

    def inventory_listing(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Printable plain-text listing (what you'd paste into chat)."""
        self._require_owner(body)
        redact = body.get("redact")
        redact = True if redact is None else bool(redact)
        roots = body.get("roots") or list(self.settings.inventory_roots)

        from ..inventory import build_inventory, render_listing

        result = build_inventory(
            [str(r) for r in roots],
            max_depth=int(body.get("max_depth")
                          or self.settings.inventory_max_depth),
            max_files=int(body.get("max_files")
                          or self.settings.inventory_max_files),
            hashes=bool(body.get("hashes", False)),
        )
        text = render_listing(result, redact=redact,
                              max_rows=int(body.get("max_rows") or 400))
        return {"listing": text, "count": len(result.entries),
                "truncated": result.truncated, "redacted": redact,
                "status": "✓"}

    # -- market (token scam detection) ------------------------------------
    def market_scan(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Scan a token address for scam indicators."""
        address = body.get("address")
        if not address:
            raise ValidationError("'address' is required")
        chain = str(body.get("chain") or "ethereum").strip().lower()

        scanner = TokenScanner()
        result = scanner.scan(address, chain=chain)
        return result.as_dict()

    def tools_file(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a file from local storage."""
        return analyze_file(body.get("path", ""))

    def tools_decode(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Decode hex/base64/plain text."""
        return decode_data(body.get("data", ""))

    def tools_analyze(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze data for patterns and secrets."""
        return analyze_data(body.get("data", ""))

    def tools_sweep(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate a sweep transaction."""
        return simulate_sweep(body.get("from", ""), body.get("to", ""))

    def tools_crack(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Attempt to crack a puzzle with a password."""
        from ..tools import crack_puzzle
        return crack_puzzle(body.get("puzzle", ""), body.get("password", ""),
                           catalog=self.service.catalog)

    def tools_image(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze an image for hidden data."""
        from ..tools import analyze_image
        return analyze_image(filename=body.get("filename", ""),
                            base64_data=body.get("base64_data", ""))

    def tools_seed_validate(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Validate a BIP39 seed phrase."""
        from ..tools import validate_seed_phrase
        return validate_seed_phrase(body.get("phrase", ""))

    def tools_derive_addresses(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Derive BTC and ETH addresses from a BIP39 seed phrase."""
        from ..tools import derive_addresses
        return derive_addresses(
            body.get("phrase", ""),
            passphrase=body.get("passphrase", ""),
            count=int(body.get("count") or 5),
        )

    def crack_list(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """List puzzles from the catalog with filtering and search."""
        result = crack_list(
            self.service.catalog,
            chain=body.get("chain"),
            status=body.get("status"),
            search=body.get("search"),
            limit=int(body.get("limit") or 100),
            offset=int(body.get("offset") or 0),
        )
        result["status"] = "✓"
        return result

    def crack_item(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Get a single puzzle's details from the crack list."""
        sku = str(body.get("sku") or "").strip()
        if not sku:
            raise ValidationError("'sku' is required")
        from ..access import Tier
        detail = self.service.catalog.item_detail(Tier.PAID, sku)
        if detail is None:
            raise ValidationError(f"unknown sku {sku!r}")
        detail["status"] = "✓"
        return detail

    def auth_login(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Login with email/password."""
        from ..auth import authenticate_user
        return authenticate_user(body.get("email", ""), body.get("password", ""))

    def auth_signup(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new account."""
        from ..auth import create_user
        return create_user(body.get("email", ""), body.get("password", ""))

    def auth_session(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Validate a session token."""
        from ..auth import validate_session
        token = body.get("session_token", "")
        if not token:
            raise SignatureError("session_token is required")
        session = validate_session(token)
        if session is None:
            raise SignatureError("invalid or expired session")
        return {
            "valid": True,
            "user_id": session.get("user_id"),
            "email": session.get("email"),
            "expires_at": session.get("expires_at"),
        }

    def auth_logout(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Revoke a session token."""
        from ..auth import revoke_session
        token = body.get("session_token", "")
        if not token:
            raise SignatureError("session_token is required")
        revoked = revoke_session(token)
        return {"valid": True, "revoked": revoked}

    def wallet_add(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Add a wallet to the user's account."""
        from ..users import add_wallet
        return add_wallet(body.get("address", ""), body.get("label", ""),
                         body.get("session_token", ""))

    def wallet_list(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """List user's wallets."""
        from ..users import list_wallets
        return list_wallets(body.get("session_token", ""))

    def market_overview(self) -> Dict[str, Any]:
        """Return market overview stats for tracked tokens."""
        scanner = TokenScanner()
        return scanner.overview()

    # -- user stats ---------------------------------------------------------
    def user_stats(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """Return user dashboard stats (scan count, puzzles found, etc.)."""
        token = body.get("session_token")
        if not token:
            raise SignatureError("session_token is required")
        address = self.service.require_session(token)

        # Get user stats from the user store
        user_store = UserStore(
            self.settings.log_dir.parent / ".run" / "users.json"
        )
        stats = user_store.stats(address)

        # Add scan count from the service tracker
        stats["scans"] = self.service.tracker.snapshot().get("wallet_data", {})
        stats["address"] = address
        stats["tier"] = self.service.tier_for(address).value
        stats["status"] = "✓"
        return stats


def make_handler(api: MiniAppAPI):
    """Build a request handler bound to ``api``."""

    class Handler(BaseHTTPRequestHandler):
        server_version = "HermesMiniApp/1.0"

        # -- helpers ------------------------------------------------------
        def _send_json(self, payload: Any, status: int = 200,
                       extra_headers: Optional[Dict[str, str]] = None) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            for key, value in (extra_headers or {}).items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)

        def _client_ip(self) -> str:
            """Best-effort client identity.

            The tunnel terminates TLS, so the socket peer is always loopback;
            prefer the forwarded headers when present.
            """
            for header in ("CF-Connecting-IP", "X-Forwarded-For",
                           "X-Real-IP"):
                value = self.headers.get(header)
                if value:
                    return value.split(",")[0].strip()
            return self.client_address[0] if self.client_address else "unknown"

        def _rate_limited(self, path: str) -> bool:
            """Return True (and send 429) when the caller is over budget."""
            self._rl_headers = {}
            if api.limiter is None:
                return False
            decision = api.limiter.check(self._client_ip(), path)
            if decision.allowed:
                self._rl_headers = decision.headers()
                return False
            log.warning("rate limit exceeded",
                        extra={"component": "web", "status": "✗",
                               "detail": f"{self._client_ip()} {path}"})
            self._send_json({"error": "rate_limited",
                             "detail": "too many requests; slow down"},
                            429, extra_headers=decision.headers())
            return True

        def _read_body(self) -> Dict[str, Any]:
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0:
                return {}
            if length > MAX_BODY_BYTES:
                raise AppError("request body too large")
            raw = self.rfile.read(length)
            try:
                data = json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError) as exc:
                raise AppError("request body is not valid JSON") from exc
            if not isinstance(data, dict):
                raise AppError("request body must be a JSON object")
            return data

        def _static(self, path: str) -> None:
            rel = "index.html" if path in ("/", "") else path.lstrip("/")
            candidate = (STATIC_DIR / rel).resolve()
            if not str(candidate).startswith(str(STATIC_DIR.resolve())):
                self._send_json({"error": "forbidden"}, 403)
                return
            if not candidate.is_file():
                self._send_json({"error": "not found"}, 404)
                return
            content_type, _ = mimetypes.guess_type(str(candidate))
            body = candidate.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", content_type or "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        # -- routes -------------------------------------------------------
        def do_GET(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            if self._rate_limited(path):
                return
            try:
                if path == "/health":
                    return self._send_json(api.health(),
                                           extra_headers=self._rl_headers)
                if path == "/api/status":
                    return self._send_json(api.status(),
                                           extra_headers=self._rl_headers)
                if path == "/api/chains":
                    return self._send_json(api.chains(),
                                           extra_headers=self._rl_headers)
                if path == "/api/paypal/config":
                    return self._send_json(api.paypal_config(),
                                           extra_headers=self._rl_headers)
                if path == "/api/catalog/config":
                    return self._send_json(api.catalog_config(),
                                           extra_headers=self._rl_headers)
                if path == "/api/market/overview":
                    return self._send_json(api.market_overview(),
                                           extra_headers=self._rl_headers)
                if path == "/api/crack/list":
                    return self._send_json(api.crack_list({}),
                                           extra_headers=self._rl_headers)
                if path.startswith("/api/crack/item/"):
                    sku = path[len("/api/crack/item/"):]
                    return self._send_json(api.crack_item({"sku": sku}),
                                           extra_headers=self._rl_headers)
                return self._static(path)
            except AppError as exc:
                return self._send_json(exc.as_dict(), 400)
            except Exception as exc:  # pragma: no cover - defensive
                log.warning("GET failed", extra={"component": "web",
                                                 "detail": str(exc)})
                return self._send_json({"error": "internal_error"}, 500)

        def do_POST(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            if self._rate_limited(path):
                return
            try:
                body = self._read_body()
                if path == "/api/auth/challenge":
                    return self._send_json(api.challenge(body),
                                           extra_headers=self._rl_headers)
                if path == "/api/auth/verify":
                    return self._send_json(api.verify(body),
                                           extra_headers=self._rl_headers)
                if path == "/api/auth/telegram":
                    return self._send_json(api.telegram_auth(body),
                                           extra_headers=self._rl_headers)
                if path == "/api/wallet/assets":
                    return self._send_json(api.assets(body),
                                           extra_headers=self._rl_headers)
                if path == "/api/telegram/validate":
                    return self._send_json(api.telegram_validate(body),
                                           extra_headers=self._rl_headers)
                if path == "/api/security/scan":
                    return self._send_json(api.scan_secrets(body),
                                           extra_headers=self._rl_headers)
                if path == "/api/paypal/orders":
                    return self._send_json(api.paypal_create_order(body),
                                           extra_headers=self._rl_headers)
                if path == "/api/paypal/capture":
                    return self._send_json(api.paypal_capture_order(body),
                                           extra_headers=self._rl_headers)
                if path == "/api/paypal/entitlement":
                    return self._send_json(api.paypal_entitlement(body),
                                           extra_headers=self._rl_headers)
                if path == "/api/inventory":
                    return self._send_json(api.inventory(body),
                                           extra_headers=self._rl_headers)
                if path == "/api/inventory/listing":
                    return self._send_json(api.inventory_listing(body),
                                           extra_headers=self._rl_headers)
                if path == "/api/catalog/categories":
                    return self._send_json(api.catalog_categories(body),
                                           extra_headers=self._rl_headers)
                if path == "/api/catalog/tabs":
                    return self._send_json(api.catalog_tabs(body),
                                           extra_headers=self._rl_headers)
                if path == "/api/catalog/items":
                    return self._send_json(api.catalog_items(body),
                                           extra_headers=self._rl_headers)
                if path == "/api/catalog/item":
                    return self._send_json(api.catalog_item(body),
                                           extra_headers=self._rl_headers)
                if path == "/api/catalog/summary":
                    return self._send_json(api.catalog_summary(body),
                                           extra_headers=self._rl_headers)
                if path == "/api/market/scan":
                    return self._send_json(api.market_scan(body),
                                           extra_headers=self._rl_headers)
                if path == "/api/tools/file":
                    return self._send_json(api.tools_file(body),
                                           extra_headers=self._rl_headers)
                if path == "/api/tools/decode":
                    return self._send_json(api.tools_decode(body),
                                           extra_headers=self._rl_headers)
                if path == "/api/tools/analyze":
                    return self._send_json(api.tools_analyze(body),
                                           extra_headers=self._rl_headers)
                if path == "/api/tools/sweep":
                    return self._send_json(api.tools_sweep(body),
                                           extra_headers=self._rl_headers)
                if path == "/api/tools/crack":
                    return self._send_json(api.tools_crack(body),
                                           extra_headers=self._rl_headers)
                if path == "/api/tools/image":
                    return self._send_json(api.tools_image(body),
                                           extra_headers=self._rl_headers)
                if path == "/api/tools/seed-validate":
                    return self._send_json(api.tools_seed_validate(body),
                                           extra_headers=self._rl_headers)
                if path == "/api/tools/derive-addresses":
                    return self._send_json(api.tools_derive_addresses(body),
                                           extra_headers=self._rl_headers)
                if path == "/api/auth/login":
                    return self._send_json(api.auth_login(body),
                                           extra_headers=self._rl_headers)
                if path == "/api/auth/signup":
                    return self._send_json(api.auth_signup(body),
                                           extra_headers=self._rl_headers)
                if path == "/api/auth/session":
                    return self._send_json(api.auth_session(body),
                                           extra_headers=self._rl_headers)
                if path == "/api/auth/logout":
                    return self._send_json(api.auth_logout(body),
                                           extra_headers=self._rl_headers)
                if path == "/api/wallet/add":
                    return self._send_json(api.wallet_add(body),
                                           extra_headers=self._rl_headers)
                if path == "/api/wallet/list":
                    return self._send_json(api.wallet_list(body),
                                           extra_headers=self._rl_headers)
                if path == "/api/user/stats":
                    return self._send_json(api.user_stats(body),
                                           extra_headers=self._rl_headers)
                return self._send_json({"error": "not_found"}, 404)
            except AppError as exc:
                return self._send_json(exc.as_dict(), 400)
            except PayPalError as exc:
                return self._send_json(exc.as_dict(), 502)
            except Exception as exc:  # pragma: no cover - defensive
                log.warning("POST failed", extra={"component": "web",
                                                  "detail": str(exc)})
                return self._send_json({"error": "internal_error"}, 500)

        def log_message(self, fmt: str, *args) -> None:  # quieter default log
            log.debug("%s - %s", self.address_string(), fmt % args)

    return Handler


def create_server(service: WalletService, host: str, port: int,
                  *, settings=None,
                  limiter: Optional[RateLimiter] = None) -> ThreadingHTTPServer:
    if limiter is None:
        settings = settings or service.settings
        limiter = RateLimiter(
            limit=settings.rate_limit_per_minute,
            window=60.0,
            expensive_limit=settings.rate_limit_expensive_per_minute,
        )
    api = MiniAppAPI(service, settings=settings, limiter=limiter)
    return ThreadingHTTPServer((host, port), make_handler(api))


def run_server(service: WalletService, host: str = "127.0.0.1",
               port: int = 8080, *, settings=None) -> None:
    httpd = create_server(service, host, port, settings=settings)
    log.info("mini app server listening",
             extra={"component": "web", "status": "✓",
                    "detail": f"http://{host}:{port}"})
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
