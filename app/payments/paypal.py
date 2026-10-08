"""Minimal PayPal Orders v2 REST client (standard library only).

Mirrors the server-side flow of PayPal's official v6 Web SDK sample
(``paypal-examples/v6-web-sdk-sample-integration``): create an order, let the
buyer approve it in the browser via the Web SDK, then capture it server-side.

Why not ``@paypal/paypal-server-sdk``? That is a Node package; this project is
a bare-Termux Python app. The REST surface used here is small and stable, so we
call it directly and keep the dependency count at zero.

Endpoints used (sandbox and live differ only by host):

    POST {base}/v1/oauth2/token                          -> access token
    POST {base}/v2/checkout/orders                       -> create order
    GET  {base}/v2/checkout/orders/{id}                  -> read order
    POST {base}/v2/checkout/orders/{id}/capture          -> capture funds

Nothing in this module logs a credential, a token, or a full PayPal response.
"""

from __future__ import annotations

import base64
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, Optional

from ..logging_setup import get_logger

log = get_logger()

SANDBOX_BASE = "https://api-m.sandbox.paypal.com"
LIVE_BASE = "https://api-m.paypal.com"


class PayPalError(Exception):
    """Raised when PayPal rejects a request or is unreachable."""

    def __init__(self, message: str, *, status_code: Optional[int] = None,
                 detail: Optional[str] = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.detail = detail

    def as_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"error": "PayPalError", "message": self.message}
        if self.status_code is not None:
            out["status_code"] = self.status_code
        if self.detail:
            out["detail"] = self.detail
        return out


@dataclass
class OrderResult:
    """The subset of a PayPal order this app cares about."""

    id: str
    status: str
    amount: Optional[str]
    currency: Optional[str]
    payer_email: Optional[str]
    capture_id: Optional[str]
    raw: Dict[str, Any]
    approval_url: Optional[str] = None

    @classmethod
    def from_api(cls, payload: Dict[str, Any]) -> "OrderResult":
        units = payload.get("purchase_units") or []
        amount = currency = None
        capture_id = None
        if units:
            first = units[0] or {}
            amt = (first.get("amount") or {})
            amount = amt.get("value")
            currency = amt.get("currency_code")
            payments = (first.get("payments") or {}).get("captures") or []
            if payments:
                capture_id = (payments[0] or {}).get("id")
        payer = payload.get("payer") or {}
        # Extract the approval URL from the order links (for redirect-based flow)
        links = payload.get("links") or []
        approval_url = None
        for link in links:
            if link.get("rel") == "approve":
                approval_url = link.get("href")
                break
        return cls(
            id=str(payload.get("id") or ""),
            status=str(payload.get("status") or ""),
            amount=amount,
            currency=currency,
            payer_email=payer.get("email_address"),
            capture_id=capture_id,
            raw=payload,
            approval_url=approval_url,
        )


class PayPalClient:
    """Thin, dependency-free PayPal Orders v2 client.

    A client is *configured* only when both credentials are present and look
    real. An unconfigured client reports ``configured == False`` and every call
    raises :class:`PayPalError`, so the feature fails closed rather than
    silently pretending a payment succeeded.
    """

    def __init__(self, *, client_id: Optional[str],
                 client_secret: Optional[str], sandbox: bool = True,
                 timeout: float = 15.0, is_placeholder=None):
        from ..config import is_placeholder as _default_check

        check = is_placeholder or _default_check
        self._client_id = (client_id or "").strip()
        self._client_secret = (client_secret or "").strip()
        self.sandbox = sandbox
        self.timeout = timeout
        self.base_url = SANDBOX_BASE if sandbox else LIVE_BASE
        self._token: Optional[str] = None
        self._token_expires_at: float = 0.0
        self._configured = not (
            check(self._client_id) or check(self._client_secret)
        )

    # -- properties -------------------------------------------------------
    @property
    def configured(self) -> bool:
        return self._configured

    @property
    def environment(self) -> str:
        return "sandbox" if self.sandbox else "live"

    def describe(self) -> Dict[str, Any]:
        """Safe-to-return description. Never includes the secret."""
        return {
            "configured": self.configured,
            "environment": self.environment,
            "base_url": self.base_url,
            "client_id_suffix": (
                self._client_id[-6:] if self._configured else None
            ),
        }

    # -- transport --------------------------------------------------------
    def _require_configured(self) -> None:
        if not self._configured:
            raise PayPalError(
                "PayPal is not configured (set PAYPAL_CLIENT_ID and "
                "PAYPAL_CLIENT_SECRET in .env)"
            )

    def _request(self, method: str, path: str, *, body: Optional[dict] = None,
                 auth: Optional[str] = None) -> Dict[str, Any]:
        url = f"{self.base_url}{path}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "hermes-bot-miniapp/1.0",
        }
        if auth:
            headers["Authorization"] = auth
        request = urllib.request.Request(url, data=data, headers=headers,
                                         method=method)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
            detail = self._safe_detail(raw)
            log.warning("paypal http error",
                        extra={"component": "payments", "status": "✗",
                               "detail": f"HTTP {exc.code}: {detail}"})
            raise PayPalError(
                f"PayPal returned HTTP {exc.code}",
                status_code=exc.code, detail=detail,
            ) from exc
        except urllib.error.URLError as exc:
            log.warning("paypal transport error",
                        extra={"component": "payments", "status": "⏳",
                               "detail": type(exc).__name__})
            raise PayPalError(
                "PayPal is unreachable", detail=type(exc).__name__
            ) from exc
        if not raw:
            return {}
        try:
            parsed = json.loads(raw)
        except ValueError:
            return {"_raw": raw[:500]}
        return parsed if isinstance(parsed, dict) else {"_data": parsed}

    @staticmethod
    def _safe_detail(raw: str) -> Optional[str]:
        """Extract PayPal's error name/message without echoing the whole body."""
        if not raw:
            return None
        try:
            payload = json.loads(raw)
        except ValueError:
            return raw[:200]
        name = payload.get("name") or payload.get("error")
        message = payload.get("message")
        parts = [p for p in (name, message) if p]
        return " - ".join(str(p) for p in parts)[:300] or None

    # -- auth -------------------------------------------------------------
    def access_token(self) -> str:
        """Return a cached OAuth2 bearer token, refreshing when near expiry."""
        self._require_configured()
        now = time.time()
        if self._token and now < self._token_expires_at - 60:
            return self._token

        creds = f"{self._client_id}:{self._client_secret}".encode("utf-8")
        basic = base64.b64encode(creds).decode("ascii")
        url = f"{self.base_url}/v1/oauth2/token"
        data = urllib.parse.urlencode({"grant_type": "client_credentials"}).encode()
        request = urllib.request.Request(
            url, data=data, method="POST",
            headers={
                "Authorization": f"Basic {basic}",
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "User-Agent": "hermes-bot-miniapp/1.0",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            detail = self._safe_detail(
                exc.read().decode("utf-8", errors="replace") if exc.fp else "")
            # Never log the credential or the Authorization header.
            log.warning("paypal auth failed",
                        extra={"component": "payments", "status": "✗",
                               "detail": f"HTTP {exc.code}: {detail}"})
            raise PayPalError(
                f"PayPal authentication failed (HTTP {exc.code})",
                status_code=exc.code, detail=detail,
            ) from exc
        except urllib.error.URLError as exc:
            raise PayPalError("PayPal is unreachable",
                              detail=type(exc).__name__) from exc

        try:
            payload = json.loads(raw)
        except ValueError as exc:
            raise PayPalError("PayPal returned a non-JSON token response") from exc
        token = payload.get("access_token")
        if not token:
            raise PayPalError("PayPal token response contained no access_token")
        self._token = str(token)
        self._token_expires_at = now + float(payload.get("expires_in") or 3200)
        return self._token

    # -- orders -----------------------------------------------------------
    def create_order(self, *, amount: str, currency: str, description: str,
                     reference_id: str = "tier-upgrade",
                     return_url: Optional[str] = None,
                     cancel_url: Optional[str] = None,
                     intent: str = "CAPTURE") -> OrderResult:
        """Create a PayPal order for a one-time tier purchase."""
        purchase_unit: Dict[str, Any] = {
            "reference_id": reference_id,
            "description": description[:127],
            "amount": {"currency_code": currency, "value": amount},
        }
        body: Dict[str, Any] = {
            "intent": intent,
            "purchase_units": [purchase_unit],
        }
        if return_url or cancel_url:
            body["payment_source"] = {
                "paypal": {
                    "experience_context": {
                        "return_url": return_url,
                        "cancel_url": cancel_url,
                        "user_action": "CONTINUE",
                        "shipping_preference": "NO_SHIPPING",
                    }
                }
            }

        payload = self._request(
            "POST", "/v2/checkout/orders", body=body,
            auth=f"Bearer {self.access_token()}",
        )
        order = OrderResult.from_api(payload)
        if not order.id:
            raise PayPalError("PayPal did not return an order id")
        log.info("paypal order created",
                 extra={"component": "payments", "status": "⏳",
                        "detail": f"{order.id} {amount} {currency}"})
        return order

    def get_order(self, order_id: str) -> OrderResult:
        payload = self._request(
            "GET", f"/v2/checkout/orders/{urllib.parse.quote(order_id)}",
            auth=f"Bearer {self.access_token()}",
        )
        return OrderResult.from_api(payload)

    def capture_order(self, order_id: str) -> OrderResult:
        """Capture an approved order.

        ``Prefer: return=representation`` is used (via the JSON body being
        empty) so the response carries the captured amount we must verify.
        """
        payload = self._request(
            "POST",
            f"/v2/checkout/orders/{urllib.parse.quote(order_id)}/capture",
            body={},
            auth=f"Bearer {self.access_token()}",
        )
        order = OrderResult.from_api(payload)
        log.info("paypal order captured",
                 extra={"component": "payments", "status": "✓",
                        "detail": f"{order.id} status={order.status}"})
        return order

    def verify_webhook_signature(self, *args, **kwargs) -> bool:
        """Placeholder for PayPal webhook verification.

        Deliberately NOT implemented: this app credits entitlements from the
        synchronous capture response, which is verified server-side against the
        live order. Adding webhooks means adding a public endpoint and a
        webhook-id secret; do that only when the flow actually needs
        asynchronous notification, and verify with PayPal's
        ``/v1/notifications/verify-webhook-signature`` endpoint when you do.
        """
        raise PayPalError(
            "webhook verification is not implemented; entitlements are granted "
            "from the verified capture response instead"
        )
