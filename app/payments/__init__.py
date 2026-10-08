"""Payment integration.

Payments exist to do exactly one thing: turn a completed PayPal order into a
:class:`app.access.Entitlement` for the wallet address that paid. Nothing here
touches wallet material, and nothing here can move funds.

Flow:

    1. GET  /api/paypal/config          -> browser-safe client id + price
    2. POST /api/paypal/orders          -> server creates a PayPal order
    3. (buyer approves in the PayPal JS SDK)
    4. POST /api/paypal/orders/<id>/capture -> server captures, verifies the
       captured amount, then grants the tier to the session's address.

Security invariants:

  * Order creation requires a verified session token, so the entitlement is
    always bound to an address the caller proved they control.
  * Capture re-reads the order from PayPal and checks status + amount before
    granting. A client cannot claim a tier by lying about the amount.
  * Every processed order id is recorded, so replaying a capture cannot extend
    or duplicate an entitlement.
  * Credentials live in the environment only and are never logged or returned.
"""

from .paypal import PayPalClient, PayPalError, OrderResult
from .store import ProcessedOrderStore

__all__ = [
    "PayPalClient",
    "PayPalError",
    "OrderResult",
    "ProcessedOrderStore",
]
