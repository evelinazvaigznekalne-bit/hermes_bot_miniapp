"""Nonce/challenge-based ownership verification (EIP-191 ``personal_sign``).

Flow
----
1. Client asks for a challenge for its address.
2. Server issues a single-use nonce and the exact human-readable message.
3. The wallet signs that message **client-side**; the private key never moves.
4. Client returns the signature; the server recovers the signer address from
   the signature and compares it to the claimed address.

The backend therefore proves ownership while only ever handling a public
address plus a signature (requirement 3).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple

from .addresses import validate_evm_address
from .errors import NonceError, SignatureError

DOMAIN = "hermes-bot-miniapp"

CHALLENGE_TEMPLATE = (
    "{domain} authentication\n"
    "Address: {address}\n"
    "Nonce: {nonce}\n"
    "Issued At: {issued_at}\n"
    "\n"
    "Sign this message to prove you control this wallet.\n"
    "This request is read-only and will never move funds."
)


# ------------------------------------------------------------- nonces ----

@dataclass
class NonceRecord:
    address: str
    message: str
    issued_at: float
    expires_at: float
    used: bool = False


class NonceStore:
    """In-memory, single-use, TTL-bounded nonce store."""

    def __init__(self, ttl_seconds: int = 300, clock=time.time):
        self.ttl = ttl_seconds
        self._clock = clock
        self._records: Dict[str, NonceRecord] = {}

    def issue(self, address: str, *, domain: str = DOMAIN) -> Tuple[str, str, int]:
        """Create a challenge. Returns ``(nonce, message, expires_in)``."""
        normalized = validate_evm_address(address)
        nonce = secrets.token_hex(16)
        now = self._clock()
        issued_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
        message = CHALLENGE_TEMPLATE.format(
            domain=domain, address=normalized, nonce=nonce, issued_at=issued_at
        )
        self._records[nonce] = NonceRecord(
            address=normalized,
            message=message,
            issued_at=now,
            expires_at=now + self.ttl,
        )
        self._prune()
        return nonce, message, self.ttl

    def consume(self, nonce: str) -> NonceRecord:
        """Validate and burn a nonce."""
        record = self._records.get(nonce)
        if record is None:
            raise NonceError("unknown or already-used nonce")
        if record.used:
            raise NonceError("nonce has already been used")
        if self._clock() > record.expires_at:
            raise NonceError("nonce has expired; request a new challenge")
        record.used = True
        return record

    def _prune(self) -> None:
        now = self._clock()
        stale = [k for k, v in self._records.items() if v.expires_at < now - 60]
        for key in stale:
            self._records.pop(key, None)


# ------------------------------------------------------- signature -----

def personal_sign_hash(message: str) -> bytes:
    """EIP-191 personal-message hash."""
    from Crypto.Hash import keccak

    payload = message.encode("utf-8")
    prefix = b"\x19Ethereum Signed Message:\n" + str(len(payload)).encode("ascii")
    k = keccak.new(digest_bits=256)
    k.update(prefix + payload)
    return k.digest()


def _normalize_v(v: int) -> int:
    """Normalise any recovery-id encoding to ``0`` or ``1``.

    Accepts raw ``0/1``, legacy ``27/28``, and EIP-155 ``35+`` encodings.
    ``eth_keys`` requires the raw ``0/1`` form.
    """
    if v in (0, 1):
        return v
    if v in (27, 28):
        return v - 27
    if v >= 35:  # EIP-155 style
        return (v - 35) % 2
    return -1


def recover_evm_address(message: str, signature: str) -> str:
    """Recover the checksummed signer address from a 65-byte hex signature."""
    from eth_keys import keys
    from eth_keys.exceptions import BadSignature, ValidationError as EthValidationError

    if not isinstance(signature, str):
        raise SignatureError("signature must be a hex string")
    sig = signature.strip()
    if sig.startswith("0x"):
        sig = sig[2:]
    try:
        raw = bytes.fromhex(sig)
    except ValueError as exc:
        raise SignatureError("signature is not valid hex") from exc
    if len(raw) != 65:
        raise SignatureError(f"signature must be 65 bytes, got {len(raw)}")

    r = int.from_bytes(raw[0:32], "big")
    s = int.from_bytes(raw[32:64], "big")
    v = _normalize_v(raw[64])
    if v not in (0, 1):
        raise SignatureError(f"unrecoverable signature recovery id v={raw[64]}")

    msg_hash = personal_sign_hash(message)
    try:
        sig_obj = keys.Signature(vrs=(v, r, s))
        pub = sig_obj.recover_public_key_from_msg_hash(msg_hash)
    except (BadSignature, EthValidationError, ValueError, AssertionError) as exc:
        raise SignatureError("could not recover signer from signature") from exc
    return pub.to_checksum_address()


def verify_evm_signature(message: str, signature: str, expected_address: str,
                         *, domain: str = DOMAIN) -> str:
    """Verify a signature matches ``expected_address``; returns the address.

    Raises :class:`SignatureError` on mismatch or malformed input.
    """
    expected = validate_evm_address(expected_address)
    if domain not in message:
        raise SignatureError("challenge message is not for this application")
    if expected.lower() not in message.lower():
        raise SignatureError("challenge message does not reference this address")
    recovered = recover_evm_address(message, signature)
    if recovered.lower() != expected.lower():
        raise SignatureError(
            "signature does not match the claimed address",
            detail=f"recovered={recovered}",
        )
    return recovered


# -------------------------------------------------- email/password auth ----

SESSION_STORE_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "sessions.json")
SESSION_TTL_SECONDS = 86400  # 24 hours


def _hash_password(password: str, salt: str = "") -> str:
    """Hash a password with SHA-256 (salted with domain + user salt)."""
    salted = f"{DOMAIN}:{salt}:{password}"
    return hashlib.sha256(salted.encode("utf-8")).hexdigest()


def _load_users() -> Dict[str, Any]:
    """Load users from persistent storage."""
    path = os.path.join(os.path.dirname(__file__), "..", "data", "users.json")
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}


def _save_users(users: Dict[str, Any]) -> None:
    """Save users to persistent storage."""
    path = os.path.join(os.path.dirname(__file__), "..", "data", "users.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(users, f, indent=2)
    os.chmod(path, 0o600)


def _load_sessions() -> Dict[str, Any]:
    """Load sessions from persistent storage."""
    if not os.path.exists(SESSION_STORE_PATH):
        return {}
    try:
        with open(SESSION_STORE_PATH, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}


def _save_sessions(sessions: Dict[str, Any]) -> None:
    """Save sessions to persistent storage."""
    os.makedirs(os.path.dirname(SESSION_STORE_PATH), exist_ok=True)
    with open(SESSION_STORE_PATH, "w") as f:
        json.dump(sessions, f, indent=2)
    os.chmod(SESSION_STORE_PATH, 0o600)


def validate_session(token: str) -> Optional[Dict[str, Any]]:
    """Validate a session token. Returns session info or None if invalid/expired."""
    if not token:
        return None
    sessions = _load_sessions()
    session = sessions.get(token)
    if session is None:
        return None
    if time.time() > session.get("expires_at", 0):
        sessions.pop(token, None)
        _save_sessions(sessions)
        return None
    return session


def revoke_session(token: str) -> bool:
    """Revoke a session token. Returns True if it existed."""
    sessions = _load_sessions()
    if token in sessions:
        sessions.pop(token, None)
        _save_sessions(sessions)
        return True
    return False


def create_user(email: str, password: str) -> Dict[str, Any]:
    """Create a new user account. Returns user info + session token."""
    if not email or not password:
        raise SignatureError("email and password are required")
    if len(password) < 8:
        raise SignatureError("password must be at least 8 characters")
    if not any(c.isalpha() for c in password) or not any(c.isdigit() for c in password):
        raise SignatureError("password must contain both letters and numbers")

    users = _load_users()
    user_id = hashlib.sha256(email.encode()).hexdigest()[:16]

    if user_id in users:
        raise SignatureError("email already registered")

    salt = hashlib.sha256(os.urandom(32)).hexdigest()[:16]
    password_hash = _hash_password(password, salt)

    user = {
        "id": user_id,
        "name": email.split("@")[0],
        "email": email,
        "salt": salt,
        "password_hash": password_hash,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    users[user_id] = user
    _save_users(users)

    issuer = SessionIssuer()
    token, expires = issuer.issue(user_id)

    # Persist session
    sessions = _load_sessions()
    sessions[token] = {
        "user_id": user_id,
        "email": email,
        "created_at": time.time(),
        "expires_at": expires,
    }
    _save_sessions(sessions)

    return {
        "valid": True,
        "user": {"id": user_id, "name": user["name"], "email": email},
        "session_token": token,
        "expires_at": expires,
        "tier": "verified",
    }


def authenticate_user(email: str, password: str) -> Dict[str, Any]:
    """Authenticate with email/password. Returns user info + session token."""
    if not email or not password:
        raise SignatureError("email and password are required")

    users = _load_users()
    user_id = hashlib.sha256(email.encode()).hexdigest()[:16]

    if user_id not in users:
        raise SignatureError("invalid email or password")

    user = users[user_id]
    salt = user.get("salt", "")
    stored_hash = user.get("password_hash", "")

    if _hash_password(password, salt) != stored_hash:
        raise SignatureError("invalid email or password")

    issuer = SessionIssuer()
    token, expires = issuer.issue(user_id)

    # Persist session
    sessions = _load_sessions()
    sessions[token] = {
        "user_id": user_id,
        "email": email,
        "created_at": time.time(),
        "expires_at": expires,
    }
    _save_sessions(sessions)

    return {
        "valid": True,
        "user": {"id": user_id, "name": user["name"], "email": email},
        "session_token": token,
        "expires_at": expires,
        "tier": "verified",
    }


# -------------------------------------------------- session tokens ----

class SessionIssuer:
    """Minimal HMAC-signed, expiring bearer tokens for verified sessions."""

    def __init__(self, secret: Optional[str] = None, ttl_seconds: int = SESSION_TTL_SECONDS):
        if secret is None:
            # Fall back to the configured SESSION_SECRET so every issuer in the
            # process (service layer, email login, Telegram auth) shares one
            # signing key. A random per-instance secret silently invalidated
            # tokens across components.
            try:
                from .config import get_settings
                secret = get_settings().session_secret
            except Exception:
                secret = None
        self.secret = (secret or secrets.token_hex(32)).encode("utf-8")
        self.ttl = ttl_seconds

    def issue(self, address: str) -> Tuple[str, int]:
        expires = int(time.time()) + self.ttl
        payload = f"{address.lower()}:{expires}"
        mac = hmac.new(self.secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()
        return f"{payload}:{mac}", expires

    def verify(self, token: str) -> str:
        """Return the checksummed address for a valid token, else raise."""
        if not isinstance(token, str) or token.count(":") < 2:
            raise SignatureError("malformed session token")
        address, expires, mac = token.rsplit(":", 2)
        payload = f"{address}:{expires}"
        expected = hmac.new(
            self.secret, payload.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(mac, expected):
            raise SignatureError("invalid session token signature")
        try:
            if int(expires) < int(time.time()):
                raise SignatureError("session token expired")
        except ValueError as exc:
            raise SignatureError("malformed session token expiry") from exc
        try:
            from .addresses import validate_evm_address

            return validate_evm_address(address)
        except Exception:
            return address
