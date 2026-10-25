"""Application service layer.

Wires auth, chains and puzzle analysis together and keeps the status tracker
in sync. This is the only place that mutates subsystem status, so the
✓/✗/⏳ contract stays consistent across the HTTP API, the Telegram bot and the
CLI dry-run.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from .addresses import detect_address_kind
from .auth import NonceStore, SessionIssuer, verify_evm_signature
from .chains.base import AssetReport
from .chains.registry import build_registry
from .config import Settings, get_settings
from .errors import AddressValidationError, ConfigError, NonceError, SignatureError
from .logging_setup import get_logger, setup_logging
from .errors import _safe_detail
from .puzzles.analysis import PuzzleAnalyzer
from .puzzles.memepol import MemePolClient
from .puzzles.ocp import OcpSource
from .access import EntitlementStore, Tier, resolve_tier
from .status import StatusTracker

log = get_logger()


@dataclass
class VerificationResult:
    verified: bool
    address: Optional[str]
    token: Optional[str]
    expires_at: Optional[int]
    status: str
    detail: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        out = {
            "verified": self.verified,
            "address": self.address,
            "status": self.status,
        }
        if self.token:
            out["session_token"] = self.token
            out["expires_at"] = self.expires_at
        if self.detail:
            out["detail"] = self.detail
        return out


class WalletService:
    """Read-only wallet inspection + ownership verification."""

    def __init__(self, settings: Optional[Settings] = None, *,
                 http=None, tracker: Optional[StatusTracker] = None,
                 registry=None, session_issuer: Optional[SessionIssuer] = None):
        self.settings = settings or get_settings()
        self.tracker = tracker or StatusTracker(self.settings.log_dir / "status.log")
        self.nonces = NonceStore(ttl_seconds=self.settings.nonce_ttl_seconds)
        self.sessions = session_issuer or SessionIssuer()
        self.registry = registry or build_registry(
            rpc_urls=self.settings.eth_rpc_urls, http=http,
            btc_api_base=self.settings.btc_api_base,
        )
        self.memepol = MemePolClient(self.settings, http=http)
        self.ocp = OcpSource(self.settings.ocp_dataset_path)
        self.private = OcpSource(self.settings.private_dataset_path)
        self.entitlements = EntitlementStore(
            self.settings.entitlements_path
            or (Path(self.settings.log_dir).parent / ".run" / "entitlements.json"))
        self.checkout = self._build_checkout()
        self.puzzle_source = self._select_puzzle_source()
        self.analyzer = PuzzleAnalyzer(self.memepol, source=self.puzzle_source)
        self.catalog = self._build_catalog()

    def _build_catalog(self):
        """Build the catalog over the public + private corpora."""
        from .catalog import Catalog

        public = []
        private = []
        try:
            public = self.ocp.list_puzzles() if self.ocp.configured else []
        except Exception as exc:  # pragma: no cover - defensive
            log.warning("public corpus unavailable: %s", exc,
                        extra={"component": "catalog", "status": "✗"})
        try:
            private = (self.private.list_puzzles()
                       if self.private.configured else [])
        except Exception as exc:  # pragma: no cover - defensive
            log.warning("private corpus unavailable: %s", exc,
                        extra={"component": "catalog", "status": "✗"})
        return Catalog(public_entries=public, private_entries=private)

    def _build_checkout(self):
        """Wire the PayPal checkout service (unconfigured is a valid state)."""
        from .payments.checkout import CheckoutService
        from .payments.paypal import PayPalClient
        from .payments.store import ProcessedOrderStore

        run_dir = Path(self.settings.log_dir).parent / ".run"
        client = PayPalClient(
            client_id=self.settings.paypal_client_id,
            client_secret=self.settings.paypal_client_secret,
            sandbox=self.settings.paypal_sandbox,
        )
        processed = ProcessedOrderStore(
            self.settings.processed_orders_path
            or (run_dir / "processed_orders.json"))
        return CheckoutService(
            paypal=client,
            entitlements=self.entitlements,
            processed=processed,
            public_url=self.settings.paypal_public_url,
        )

    def _select_puzzle_source(self):
        """Pick the puzzle source according to PUZZLE_SOURCE.

        ``auto``    - local corpus if present, else the HTTP API
        ``ocp``     - local corpus only (error if absent)
        ``memepol`` - HTTP API only (for a real remote endpoint)
        """
        pref = self.settings.puzzle_source_pref
        if pref == "memepol":
            return None                      # force the HTTP client
        if pref == "ocp":
            return self.ocp if self.ocp.configured else None
        return self.ocp if self.ocp.configured else None

    # -- capabilities -----------------------------------------------------
    def capabilities(self) -> Dict[str, Any]:
        return {
            "chains": self.registry.describe(),
            "families": ["evm", "bitcoin"],
            "telegram_configured": self.settings.telegram_configured,
            "memepol_configured": self.memepol.configured,
            "puzzle_source": (
                self.puzzle_source.describe() if self.puzzle_source
                else {"source": "memepol", "configured": self.memepol.configured,
                      "base_url": self.settings.memepol_base_url,
                      "auth_header": self.settings.memepol_auth_header,
                      "requires_api_key": True}
            ),
            "puzzle_source_pref": self.settings.puzzle_source_pref,
            "eth_rpc_configured": self.settings.eth_rpc_configured,
            "paypal_configured": self.settings.paypal_configured,
            "paypal_environment": self.checkout.paypal.environment,
            "catalog_items": len(self.catalog.public_entries),
            "read_only": True,
            "secrets_requested": False,
        }

    # -- auth -------------------------------------------------------------
    def issue_challenge(self, address: str) -> Dict[str, Any]:
        """Start the sign-in flow (requirement 2/3)."""
        self.tracker.pending("wallet_data", "challenge issued, awaiting signature")
        try:
            nonce, message, ttl = self.nonces.issue(address)
        except AddressValidationError as exc:
            self.tracker.fail("wallet_data", str(exc))
            raise
        log.info(
            "challenge issued",
            extra={"component": "auth", "status": "⏳", "address": address},
        )
        return {
            "address": address,
            "nonce": nonce,
            "message": message,
            "expires_in": ttl,
            "status": "⏳",
            "instructions": (
                "Sign `message` client-side with personal_sign (EIP-191). "
                "Send the resulting signature back. Your private key must "
                "never leave your device."
            ),
        }

    def verify(self, address: str, signature: str, nonce: str,
               *, message: Optional[str] = None) -> VerificationResult:
        """Verify the signature and open a session."""
        try:
            record = self.nonces.consume(nonce)
        except NonceError as exc:
            self.tracker.fail("wallet_data", exc.message)
            return VerificationResult(False, None, None, None, "✗", exc.message)

        challenge = message or record.message
        if record.address.lower() != str(address).lower():
            self.tracker.fail("wallet_data", "nonce was issued for a different address")
            return VerificationResult(
                False, None, None, None, "✗",
                "nonce was issued for a different address",
            )
        try:
            recovered = verify_evm_signature(challenge, signature, record.address)
        except SignatureError as exc:
            self.tracker.fail("wallet_data", exc.message)
            log.warning(
                "signature verification failed",
                extra={"component": "auth", "status": "✗", "address": record.address,
                       "detail": exc.message},
            )
            return VerificationResult(False, None, None, None, "✗", exc.message)

        token, expires = self.sessions.issue(recovered)
        self.tracker.ok("wallet_data", "ownership verified via signature")
        log.info(
            "wallet verified",
            extra={"component": "auth", "status": "✓", "address": recovered},
        )
        return VerificationResult(True, recovered, token, expires, "✓")

    # -- data -------------------------------------------------------------
    def fetch_assets(self, address: str, *, chain: Optional[str] = None,
                     include_puzzles: bool = False,
                     limit: int = 50) -> Dict[str, Any]:
        """Collect public asset data (requirement 4/5/6)."""
        self.tracker.pending("assets_chains", "fetching public chain data")

        provider = None
        if chain:
            provider = self.registry.get(chain)
            if provider is None:
                self.tracker.fail("assets_chains", f"unknown chain {chain!r}")
                raise AddressValidationError(f"unknown chain {chain!r}")
            if not provider.accepts(address):
                self.tracker.fail(
                    "assets_chains",
                    f"address is not valid for chain {chain!r}",
                )
                raise AddressValidationError(
                    f"address {address!r} is not valid for chain {chain!r}"
                )
        else:
            provider = self.registry.resolve(address)
            if provider is None:
                self.tracker.fail("assets_chains", "unrecognised address format")
                raise AddressValidationError(
                    "unrecognised address format: expected an EVM (0x…) or "
                    "Bitcoin address"
                )

        try:
            report: AssetReport = provider.fetch_assets(address, limit=limit)
        except Exception as exc:
            self.tracker.fail("assets_chains", _safe_detail(f"{type(exc).__name__}: {exc}"))
            raise

        if report.status == "✓":
            self.tracker.ok(
                "assets_chains",
                f"{len(report.assets)} asset(s) on {report.chain}",
            )
        else:
            self.tracker.fail("assets_chains", report.detail or "fetch failed")

        payload: Dict[str, Any] = {
            "wallet": report.as_dict(),
            "status": report.status,
        }

        if include_puzzles:
            analysis = self.analyzer.analyze(report)
            self.tracker.set(
                "memepol_comparison", analysis.status,
                analysis.detail or f"verdict={analysis.verdict.value}",
            )
            self.tracker.set(
                "puzzle_hints",
                "✓" if analysis.hints else ("⏳" if analysis.status == "✓" else "✗"),
                f"{len(analysis.hints)} hint(s)",
            )
            self.tracker.set(
                "puzzle_images",
                "✓" if analysis.images else ("⏳" if analysis.status == "✓" else "✗"),
                f"{len(analysis.images)} image ref(s)",
            )
            payload["puzzle_analysis"] = analysis.as_dict()

        payload["statuses"] = self.tracker.compact()
        return payload

    # -- orchestration ----------------------------------------------------
    def inspect_public(self, address: str, *, chain: Optional[str] = None,
                       include_puzzles: bool = False,
                       tier: Optional[Tier] = None) -> Dict[str, Any]:
        """Read-only inspection of a public address (no signing required).

        When ``tier`` is supplied the puzzle analysis is filtered to what that
        tier may see. When it is omitted the caller gets ANONYMOUS limits, so a
        forgotten argument fails closed rather than leaking the corpus.
        """
        from .access import TIER_LIMITS, apply_limits

        payload = self.fetch_assets(address, chain=chain,
                                    include_puzzles=include_puzzles)
        effective = tier if tier is not None else Tier.ANONYMOUS

        analysis = payload.get("puzzle_analysis")
        if isinstance(analysis, dict):
            payload["puzzle_analysis"] = apply_limits(analysis, effective)

        # owner-only corpus: only loaded and attached for OWNER
        if TIER_LIMITS[effective].include_private:
            try:
                private_entries = self.private.list_puzzles()
                if private_entries:
                    report = payload.get("report")
                    if isinstance(report, AssetReport):
                        owner_analysis = self.analyzer.analyze(report, private_entries)
                    else:
                        # no report available: surface the corpus inventory only
                        owner_analysis = None
                    if owner_analysis is not None:
                        payload["private_analysis"] = apply_limits(
                            owner_analysis.as_dict(), Tier.OWNER)
                    payload["private_count"] = len(private_entries)
            except Exception as exc:  # pragma: no cover - defensive
                log.warning("private corpus unavailable: %s", exc,
                            extra={"component": "service", "status": "✗"})

        payload["tier"] = effective.value
        return payload

    def tier_for(self, verified_address: Optional[str]) -> Tier:
        return resolve_tier(
            verified_address=verified_address,
            owner_addresses=list(self.settings.owner_addresses),
            store=self.entitlements,
        )

    def require_session(self, token: str) -> str:
        """Validate a bearer token and return the bound address."""
        return self.sessions.verify(token)


def build_service(settings: Optional[Settings] = None, **kwargs) -> WalletService:
    settings = settings or get_settings()
    setup_logging(settings.log_dir)
    from .config import SECRET_ENV_VARS
    from .logging_setup import redact_secrets_from_env

    redact_secrets_from_env(SECRET_ENV_VARS)
    # Bind the service's session issuer to the configured SESSION_SECRET so that
    # tokens minted by the login/signup/Telegram auth paths (which use the same
    # secret) actually validate here. Without this the service falls back to a
    # random per-process secret and every authenticated request silently
    # degrades to ANONYMOUS.
    if "session_issuer" not in kwargs:
        kwargs["session_issuer"] = SessionIssuer(secret=settings.session_secret)
    return WalletService(settings, **kwargs)


def assert_configured(settings: Settings, *, need_telegram: bool = False) -> None:
    """Raise :class:`ConfigError` when required credentials are absent."""
    if need_telegram and not settings.telegram_configured:
        raise ConfigError(
            "TELEGRAM_BOT_TOKEN is not set (or is still a placeholder). "
            "Put it in .env - never in source."
        )
