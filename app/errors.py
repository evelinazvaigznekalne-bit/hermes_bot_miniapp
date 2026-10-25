"""Typed errors used across the application."""

from __future__ import annotations

from typing import Optional


class AppError(Exception):
    """Base class for all application errors."""

    status = "✗"

    def __init__(self, message: str, *, detail: Optional[str] = None):
        super().__init__(message)
        self.message = message
        self.detail = detail

    def as_dict(self) -> dict:
        out = {"error": type(self).__name__, "message": self.message}
        if self.detail:
            out["detail"] = self.detail
        return out


class ConfigError(AppError):
    """Raised when required configuration (usually a credential) is missing."""


class ValidationError(AppError):
    """Raised when user-supplied input is malformed."""


class AddressValidationError(ValidationError):
    """Raised when an address fails chain-specific validation."""


class SignatureError(AppError):
    """Raised when a wallet signature cannot be verified."""


class NonceError(AppError):
    """Raised when a nonce is unknown, expired, or already consumed."""


class ChainAPIError(AppError):
    """Raised when an upstream chain API fails or returns bad data."""

    def __init__(self, message: str, *, provider: Optional[str] = None,
                 status_code: Optional[int] = None, detail: Optional[str] = None):
        super().__init__(message, detail=detail)
        self.provider = provider
        self.status_code = status_code

    def as_dict(self) -> dict:
        out = super().as_dict()
        if self.provider:
            out["provider"] = self.provider
        if self.status_code is not None:
            out["status_code"] = self.status_code
        return out


class PuzzleAPIError(AppError):
    """Raised when the MemePol API is unreachable, unconfigured, or errors."""


class HttpError(AppError):
    """Raised by :class:`app.http.HttpClient` for transport/status failures."""

    def __init__(self, message: str, *, provider: Optional[str] = None,
                 status_code: Optional[int] = None, detail: Optional[str] = None):
        super().__init__(message, detail=detail)
        self.provider = provider
        self.status_code = status_code

    def as_dict(self) -> dict:
        out = super().as_dict()
        if self.provider:
            out["provider"] = self.provider
        if self.status_code is not None:
            out["status_code"] = self.status_code
        # Never echo raw exception text or response bodies to the client.
        if out.get("detail") and not _is_safe_detail(out["detail"]):
            out["detail"] = "internal"
        return out


# ---------------------------------------------------------------------------
# Safe exception helpers
# ---------------------------------------------------------------------------

#: Allowlisted exception class names.  Anything outside this set maps to
#: "InternalError".  Only broad categories are exposed — never raw messages.
_SAFE_CATEGORIES = frozenset({
    "ValueError", "TypeError", "KeyError", "IndexError",
    "AttributeError", "RuntimeError", "OSError", "IOError",
    "ImportError", "ModuleNotFoundError", "MemoryError",
    "OverflowError", "ZeroDivisionError", "AssertionError",
    "LookupError", "NameError", "ReferenceError",
    "BlockingIOError", "ChildProcessError", "ConnectionError",
    "BrokenPipeError", "ConnectionAbortedError", "ConnectionRefusedError",
    "ConnectionResetError", "FileExistsError", "FileNotFoundError",
    "InterruptedError", "IsADirectoryError", "NotADirectoryError",
    "PermissionError", "ProcessLookupError", "TimeoutError",
    "UnboundLocalError", "RecursionError",
    "DecodeError", "ConfigError", "SignatureError", "NonceError",
    "ValidationError", "AddressValidationError", "UnsafeUrlError",
    "HttpError", "RateLimitError", "ChainAPIError", "PuzzleAPIError",
})


def _safe_exception(exc: Exception) -> str:
    """Return a generic, non-leaky error string for logs and status records.

    Never inspects the exception message, arguments, or traceback.
    Only the exception class name is exposed, from the safe allowlist.
    """
    name = type(exc).__name__
    if name not in _SAFE_CATEGORIES:
        name = "InternalError"
    return f"{name}: operation failed"


def _safe_detail(text: Optional[str]) -> Optional[str]:
    """Return a sanitized detail string safe for logs, status records, and HTTP responses.

    If the text looks like it might contain raw exception info or sensitive
    material, return a generic placeholder.  Otherwise pass it through.
    """
    if not text:
        return text
    # Detect raw exception shape: "TypeName: ..." — these come from
    # f"{type(exc).__name__}: {exc}" patterns and must be stripped.
    stripped = text.strip()
    if ":" in stripped:
        prefix = stripped.split(":", 1)[0].strip()
        if prefix in _SAFE_CATEGORIES:
            return "internal"
    # Detect URLs that may embed credentials
    if "://" in stripped and ("@" in stripped or "key=" in stripped.lower()
                              or "token=" in stripped.lower()
                              or "secret=" in stripped.lower()):
        return "internal"
    # Detect known sensitive keywords
    import re
    if re.search(
        r"(?i)(mnemonic|seed|phrase|private[\s_-]?key|wif|xpub|xprv|passphrase|secret)",
        stripped,
    ):
        return "internal"
    return text


def _is_safe_detail(text: str) -> bool:
    """True when text is safe to expose in an HTTP response body."""
    return _safe_detail(text) == text
