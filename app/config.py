"""Configuration loading from environment variables.

Rules:
  * No credential is ever hard-coded. Everything sensitive comes from the
    environment (or a local ``.env`` that is git-ignored).
  * :func:`redact` is the single choke point used before anything is logged.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent

#: Env vars whose values must never appear in logs or API responses.
SECRET_ENV_VARS = (
    "TELEGRAM_BOT_TOKEN",
    "MEMEPOL_API_KEY",
    "MEMEPOL_API_SECRET",
    "ETH_RPC_URL",
    "BTC_API_KEY",
    "PAYPAL_CLIENT_SECRET",
)

_PLACEHOLDER_MARKERS = (
    "your_",
    "changeme",
    "replace_me",
    "xxx",
    "<",
    "example",
)


def load_dotenv(path: Optional[Path] = None) -> Dict[str, str]:
    """Minimal ``.env`` parser (no external dependency).

    Existing environment variables always win over file values. Returns the
    mapping of keys that were parsed (values are NOT printed by this module).
    """
    path = path or PROJECT_ROOT / ".env"
    parsed: Dict[str, str] = {}
    if not path.is_file():
        return parsed
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if not key:
            continue
        parsed[key] = value
        # Do not clobber a real environment variable with a .env value.
        os.environ.setdefault(key, value)
    return parsed


def is_placeholder(value: Optional[str]) -> bool:
    """True when a credential looks like an unfilled ``.env.example`` value."""
    if value is None:
        return True
    v = value.strip()
    if not v:
        return True
    low = v.lower()
    return any(marker in low for marker in _PLACEHOLDER_MARKERS)


def redact(value: Optional[str], keep: int = 4) -> str:
    """Return a safe representation of a secret for logging."""
    if not value:
        return "<unset>"
    if is_placeholder(value):
        return "<placeholder>"
    if len(value) <= keep:
        return "*" * len(value)
    return f"{value[:keep]}…<redacted:{len(value)} chars>"


@dataclass(frozen=True)
class Settings:
    """Resolved application settings."""

    telegram_bot_token: Optional[str] = None
    telegram_webapp_url: Optional[str] = None
    telegram_authorized_user_ids: tuple = ()
    bot_display_name: str = "Hermes Wallet Inspector"
    memepol_base_url: str = "https://api.memepol.example/v1"
    memepol_api_key: Optional[str] = None
    memepol_auth_header: str = "Authorization"
    memepol_auth_prefix: str = "Bearer"
    ocp_dataset_path: Optional[Path] = None
    puzzle_source_pref: str = "auto"
    rate_limit_per_minute: int = 60
    rate_limit_expensive_per_minute: int = 20
    # --- access control -------------------------------------------------
    entitlements_path: Optional[Path] = None
    private_dataset_path: Optional[Path] = None
    # --- payments (PayPal) ------------------------------------------------
    paypal_client_id: Optional[str] = None
    paypal_client_secret: Optional[str] = None
    paypal_sandbox: bool = True
    paypal_public_url: Optional[str] = None
    processed_orders_path: Optional[Path] = None
    # --- inventory --------------------------------------------------------
    inventory_roots: tuple = ("~",)
    inventory_max_files: int = 4000
    inventory_max_depth: int = 3
    owner_addresses: tuple = ()
    eth_rpc_urls: tuple = ()
    btc_api_base: str = "https://mempool.space/api"
    http_timeout: float = 12.0
    nonce_ttl_seconds: int = 300
    session_secret: Optional[str] = None
    host: str = "127.0.0.1"
    port: int = 8080
    log_dir: Path = field(default_factory=lambda: PROJECT_ROOT / "logs")
    request_timeout: float = 12.0

    # -- capability flags -------------------------------------------------
    @property
    def telegram_configured(self) -> bool:
        return not is_placeholder(self.telegram_bot_token)

    @property
    def memepol_configured(self) -> bool:
        return not is_placeholder(self.memepol_api_key)

    @property
    def eth_rpc_configured(self) -> bool:
        return bool(self.eth_rpc_urls)

    @property
    def paypal_configured(self) -> bool:
        return not (
            is_placeholder(self.paypal_client_id)
            or is_placeholder(self.paypal_client_secret)
        )


#: Public, key-less Ethereum JSON-RPC endpoints used as a fallback chain.
#: These are read-only public nodes; a user-supplied ETH_RPC_URL takes priority.
DEFAULT_ETH_RPC_URLS = (
    "https://ethereum-rpc.publicnode.com",
    "https://eth.drpc.org",
    "https://1rpc.io/eth",
)


def _split_urls(raw: Optional[str]) -> tuple:
    if not raw:
        return ()
    return tuple(u.strip() for u in raw.split(",") if u.strip())


def get_settings(env: Optional[Dict[str, str]] = None) -> Settings:
    """Build :class:`Settings` from the environment.

    ``env`` may be supplied in tests to avoid touching the real environment.
    """
    if env is None:
        load_dotenv()
        src = os.environ
    else:
        src = env

    rpc_urls = _split_urls(src.get("ETH_RPC_URL")) + tuple(
        u for u in DEFAULT_ETH_RPC_URLS if u not in _split_urls(src.get("ETH_RPC_URL"))
    )

    log_dir = Path(src.get("LOG_DIR") or (PROJECT_ROOT / "logs"))
    log_dir.mkdir(parents=True, exist_ok=True)

    return Settings(
        telegram_bot_token=src.get("TELEGRAM_BOT_TOKEN"),
        telegram_webapp_url=src.get("TELEGRAM_WEBAPP_URL"),
        telegram_authorized_user_ids=tuple(
            int(u.strip()) for u in (src.get("TELEGRAM_AUTHORIZED_USER_IDS") or "").split(",")
            if u.strip().isdigit()
        ),
        bot_display_name=src.get("BOT_DISPLAY_NAME") or "Hermes Wallet Inspector",
        memepol_base_url=src.get("MEMEPOL_BASE_URL") or "https://api.memepol.example/v1",
        memepol_api_key=src.get("MEMEPOL_API_KEY"),
        memepol_auth_header=src.get("MEMEPOL_AUTH_HEADER") or "Authorization",
        memepol_auth_prefix=src.get("MEMEPOL_AUTH_PREFIX") or "Bearer",
        ocp_dataset_path=(Path(src["OCP_DATASET_PATH"]) if src.get("OCP_DATASET_PATH") else None),
        puzzle_source_pref=(src.get("PUZZLE_SOURCE") or "auto").strip().lower(),
        rate_limit_per_minute=int(src.get("RATE_LIMIT_PER_MINUTE") or 60),
        rate_limit_expensive_per_minute=int(
            src.get("RATE_LIMIT_EXPENSIVE_PER_MINUTE") or 20),
        entitlements_path=(Path(src["ENTITLEMENTS_PATH"]) if src.get("ENTITLEMENTS_PATH")
                           else None),
        private_dataset_path=(Path(src["PRIVATE_DATASET_PATH"])
                              if src.get("PRIVATE_DATASET_PATH") else None),
        paypal_client_id=src.get("PAYPAL_CLIENT_ID"),
        paypal_client_secret=src.get("PAYPAL_CLIENT_SECRET"),
        paypal_sandbox=(src.get("PAYPAL_SANDBOX") or "true").strip().lower()
                       not in ("0", "false", "no", "off"),
        paypal_public_url=src.get("PAYPAL_PUBLIC_URL") or src.get("TELEGRAM_WEBAPP_URL"),
        processed_orders_path=(Path(src["PROCESSED_ORDERS_PATH"])
                               if src.get("PROCESSED_ORDERS_PATH") else None),
        inventory_roots=tuple(
            r.strip() for r in (src.get("INVENTORY_ROOTS") or "~").split(",")
            if r.strip()) or ("~",),
        inventory_max_files=int(src.get("INVENTORY_MAX_FILES") or 4000),
        inventory_max_depth=int(src.get("INVENTORY_MAX_DEPTH") or 3),
        owner_addresses=tuple(
            a.strip().lower() for a in (src.get("OWNER_ADDRESSES") or "").split(",")
            if a.strip()),
        eth_rpc_urls=rpc_urls,
        btc_api_base=src.get("BTC_API_BASE") or "https://mempool.space/api",
        http_timeout=float(src.get("HTTP_TIMEOUT") or 12.0),
        nonce_ttl_seconds=int(src.get("NONCE_TTL_SECONDS") or 300),
        session_secret=src.get("SESSION_SECRET"),
        host=src.get("HOST") or "127.0.0.1",
        port=int(src.get("PORT") or 8080),
        log_dir=log_dir,
    )
