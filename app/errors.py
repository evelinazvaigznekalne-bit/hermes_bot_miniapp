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
        return out
