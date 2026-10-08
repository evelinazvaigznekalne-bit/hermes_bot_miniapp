"""Turns a captured PayPal order into a tier entitlement.

This is the only place that grants access as a result of a payment. It is
intentionally paranoid:

  * the order must exist on PayPal's side and be ``COMPLETED`` (or ``APPROVED``
    before capture, then ``COMPLETED`` after);
  * the captured amount and currency must match the configured price exactly;
  * the order id must not have been credited before;
  * the entitlement is bound to the *session-verified* address, never to an
    address supplied in the request body.

Anything else raises :class:`PayPalError` and grants nothing.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from ..access import EntitlementStore
from ..logging_setup import get_logger
from .paypal import PayPalClient, PayPalError
from .store import ProcessedOrderStore

log = get_logger()

#: PayPal order states that may be credited.
CREDITABLE_STATUSES = ("COMPLETED", "APPROVED")


@dataclass(frozen=True)
class PricePlan:
    """A purchasable tier."""

    sku: str
    label: str
    amount: str          # decimal string, e.g. "19.00"
    currency: str        # ISO-4217, e.g. "USD"
    tier: str            # app.access tier to grant
    days: Optional[int]  # None = perpetual

    def as_dict(self) -> Dict[str, Any]:
        return {
            "sku": self.sku, "label": self.label, "amount": self.amount,
            "currency": self.currency, "tier": self.tier, "days": self.days,
        }


#: Default catalogue. Override amounts via the environment if you like; the
#: tier/days mapping is what the access layer consumes.
DEFAULT_PLANS = (
    PricePlan("tier-30d", "Full corpus - 30 days", "19.00", "USD", "paid", 30),
    PricePlan("tier-365d", "Full corpus - 1 year", "149.00", "USD", "paid", 365),
    PricePlan("tier-lifetime", "Full corpus - lifetime", "399.00", "USD",
              "paid", None),
)


class CheckoutService:
    """Order creation + capture + entitlement granting."""

    def __init__(self, *, paypal: PayPalClient,
                 entitlements: EntitlementStore,
                 processed: ProcessedOrderStore,
                 plans=DEFAULT_PLANS,
                 public_url: Optional[str] = None):
        self.paypal = paypal
        self.entitlements = entitlements
        self.processed = processed
        self.plans = {p.sku: p for p in plans}
        self.public_url = public_url

    # -- catalogue --------------------------------------------------------
    def plans_public(self) -> list:
        return [p.as_dict() for p in self.plans.values()]

    def get_plan(self, sku: str) -> PricePlan:
        plan = self.plans.get(sku)
        if plan is None:
            raise PayPalError(f"unknown plan {sku!r}")
        return plan

    def describe(self) -> Dict[str, Any]:
        return {
            "configured": self.paypal.configured,
            "environment": self.paypal.environment,
            "plans": self.plans_public(),
        }

    # -- order lifecycle --------------------------------------------------
    def create_order(self, *, sku: str, address: str) -> Dict[str, Any]:
        """Create a PayPal order for ``sku`` bound to a verified address."""
        plan = self.get_plan(sku)
        return_url = f"{self.public_url}/?paid=1" if self.public_url else None
        cancel_url = f"{self.public_url}/?cancelled=1" if self.public_url else None

        order = self.paypal.create_order(
            amount=plan.amount,
            currency=plan.currency,
            description=f"{plan.label} ({address[:10]}…)",
            reference_id=plan.sku,
            return_url=return_url,
            cancel_url=cancel_url,
        )
        return {
            "order_id": order.id,
            "status": order.status,
            "amount": plan.amount,
            "currency": plan.currency,
            "sku": plan.sku,
            "plan": plan.as_dict(),
            "approval_url": order.approval_url,
        }

    def capture_order(self, *, order_id: str, address: str) -> Dict[str, Any]:
        """Capture ``order_id`` and grant the matching tier to ``address``.

        ``address`` MUST come from a verified session. This method re-reads the
        order from PayPal and validates amount/currency/status before granting.
        """
        if self.processed.seen(order_id):
            prior = self.processed.get(order_id) or {}
            # Idempotent: return the original grant instead of double-crediting.
            return {
                "already_processed": True,
                "order_id": order_id,
                "granted_to": prior.get("address"),
                "tier": prior.get("tier"),
                "entitlement": (
                    self.entitlements.get(prior.get("address") or "").as_dict()
                    if prior.get("address") else None
                ),
            }

        order = self.paypal.capture_order(order_id)

        if order.status not in CREDITABLE_STATUSES:
            raise PayPalError(
                f"order {order_id} is {order.status!r}; not creditable",
                detail=f"expected one of {', '.join(CREDITABLE_STATUSES)}",
            )

        plan = self._plan_for_order(order, order_id)

        if order.amount is None or order.currency is None:
            raise PayPalError(
                f"order {order_id} returned no captured amount; refusing to grant"
            )
        if str(order.amount) != plan.amount or str(order.currency).upper() != plan.currency:
            # A mismatch means the order was tampered with or priced differently
            # than the plan says. Never grant on a mismatch.
            log.warning(
                "paypal amount mismatch; refusing grant",
                extra={"component": "payments", "status": "✗",
                       "detail": f"{order.id} got {order.amount} {order.currency} "
                                 f"expected {plan.amount} {plan.currency}"},
            )
            raise PayPalError(
                "captured amount does not match the plan price",
                detail=f"got {order.amount} {order.currency}, "
                       f"expected {plan.amount} {plan.currency}",
            )

        record = self.entitlements.grant(
            address, tier=plan.tier, days=plan.days,
            note=f"paypal {order.id} {order.amount} {order.currency}",
        )
        self.processed.record(
            order.id, address=address, amount=str(order.amount),
            currency=str(order.currency), tier=plan.tier, days=plan.days,
        )
        log.info("entitlement granted from payment",
                 extra={"component": "payments", "status": "✓",
                        "detail": f"{plan.tier} -> {address} via {order.id}"})
        return {
            "already_processed": False,
            "order_id": order.id,
            "status": order.status,
            "amount": order.amount,
            "currency": order.currency,
            "granted_to": record.address,
            "tier": record.tier,
            "expires_at": record.expires_at,
            "entitlement": record.as_dict(),
        }

    def _plan_for_order(self, order, order_id: str) -> PricePlan:
        """Recover the plan for a captured order.

        Prefers the ``reference_id`` PayPal echoes back. Falls back to matching
        the amount, which is safe because the amount is then re-verified above.
        """
        ref = None
        units = order.raw.get("purchase_units") or []
        if units:
            ref = (units[0] or {}).get("reference_id")
        if ref and ref in self.plans:
            return self.plans[ref]
        for plan in self.plans.values():
            if str(order.amount) == plan.amount and \
                    str(order.currency).upper() == plan.currency:
                return plan
        raise PayPalError(
            f"cannot match order {order_id} to a plan",
            detail=f"reference_id={ref!r} amount={order.amount} {order.currency}",
        )

    # -- status -----------------------------------------------------------
    def entitlement_for(self, address: str) -> Optional[Dict[str, Any]]:
        rec = self.entitlements.get(address)
        return rec.as_dict() if rec else None
