"""Payment tests — the invariants that protect money and access.

The failure modes worth testing are all about granting access that wasn't paid
for:

  * a capture whose amount does not match the plan must NOT grant;
  * a replayed capture must NOT double-credit (or extend) a tier;
  * a capture with no session must fail;
  * the entitlement must bind to the SESSION address, never a body field;
  * credentials must never appear in a response, a log, or an exception.

Every test uses a fake PayPal transport, so nothing here touches the network
and no real credential is involved.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.access import EntitlementStore, Tier, resolve_tier  # noqa: E402
from app.payments.checkout import (  # noqa: E402
    DEFAULT_PLANS,
    CheckoutService,
    PricePlan,
)
from app.payments.paypal import OrderResult, PayPalClient, PayPalError  # noqa: E402
from app.payments.store import ProcessedOrderStore  # noqa: E402

BUYER = "0xBuyer0000000000000000000000000000000002"
OTHER = "0xOther0000000000000000000000000000000009"
SECRET = "EK-secret-value-do-not-leak-1234567890"
CLIENT_ID = "Afakeclientid1234567890"


def order_payload(*, oid="ORDER-1", status="COMPLETED", value="19.00",
                  currency="USD", reference="tier-30d"):
    return {
        "id": oid,
        "status": status,
        "purchase_units": [{
            "reference_id": reference,
            "amount": {"currency_code": currency, "value": value},
            "payments": {"captures": [{"id": f"CAP-{oid}"}]},
        }],
        "payer": {"email_address": "buyer@example.test"},
    }


class FakePayPal(PayPalClient):
    """PayPalClient with the transport replaced by a scripted response."""

    def __init__(self, *, payload=None, configured=True, raises=None):
        super().__init__(
            client_id=CLIENT_ID if configured else None,
            client_secret=SECRET if configured else None,
            sandbox=True,
        )
        self._payload = payload if payload is not None else order_payload()
        self._raises = raises
        self.calls = []

    def access_token(self):
        return "fake-token"

    def create_order(self, **kwargs):
        self.calls.append(("create", kwargs))
        if self._raises:
            raise self._raises
        return OrderResult.from_api(self._payload)

    def capture_order(self, order_id):
        self.calls.append(("capture", order_id))
        if self._raises:
            raise self._raises
        return OrderResult.from_api(self._payload)

    def get_order(self, order_id):
        self.calls.append(("get", order_id))
        return OrderResult.from_api(self._payload)


@pytest.fixture
def checkout(tmp_path):
    """A CheckoutService wired to fake PayPal + temp stores."""
    def _make(**kwargs):
        paypal = kwargs.pop("paypal", None) or FakePayPal()
        entitlements = kwargs.pop("entitlements", None) or EntitlementStore(
            tmp_path / "entitlements.json")
        processed = kwargs.pop("processed", None) or ProcessedOrderStore(
            tmp_path / "processed.json")
        return CheckoutService(paypal=paypal, entitlements=entitlements,
                               processed=processed, **kwargs)
    return _make


# --- configuration ----------------------------------------------------------

class TestConfiguration:
    def test_unconfigured_client_is_not_configured(self):
        c = PayPalClient(client_id=None, client_secret=None)
        assert c.configured is False

    def test_placeholder_credentials_are_not_configured(self):
        c = PayPalClient(client_id="your_client_id",
                         client_secret="YOUR_PAYPAL_SECRET")
        assert c.configured is False

    def test_real_looking_credentials_are_configured(self):
        assert FakePayPal().configured is True

    def test_unconfigured_client_refuses_to_create(self):
        c = PayPalClient(client_id=None, client_secret=None)
        with pytest.raises(PayPalError):
            c.create_order(amount="1.00", currency="USD", description="x")

    def test_describe_never_includes_the_secret(self):
        blob = json.dumps(FakePayPal().describe())
        assert SECRET not in blob

    def test_describe_includes_only_a_client_id_suffix(self):
        d = FakePayPal().describe()
        assert d["client_id_suffix"] == CLIENT_ID[-6:]
        assert CLIENT_ID not in json.dumps(d)


# --- order creation ---------------------------------------------------------

class TestCreateOrder:
    def test_create_returns_the_order_id(self, checkout):
        r = checkout().create_order(sku="tier-30d", address=BUYER)
        assert r["order_id"] == "ORDER-1"
        assert r["amount"] == "19.00"
        assert r["currency"] == "USD"

    def test_create_returns_approval_url(self, checkout):
        payload = order_payload()
        payload["links"] = [
            {"rel": "approve", "href": "https://sandbox.paypal.com/checkoutnow?token=ORDER-1"},
            {"rel": "self", "href": "https://sandbox.paypal.com/v2/checkout/orders/ORDER-1"},
        ]
        c = checkout(paypal=FakePayPal(payload=payload))
        r = c.create_order(sku="tier-30d", address=BUYER)
        assert r["approval_url"] == "https://sandbox.paypal.com/checkoutnow?token=ORDER-1"

    def test_create_without_links_has_no_approval_url(self, checkout):
        r = checkout().create_order(sku="tier-30d", address=BUYER)
        assert r["approval_url"] is None

    def test_unknown_sku_is_rejected(self, checkout):
        with pytest.raises(PayPalError):
            checkout().create_order(sku="nope", address=BUYER)

    def test_create_uses_the_plan_price_not_a_client_value(self, checkout):
        c = checkout()
        c.create_order(sku="tier-30d", address=BUYER)
        _, kwargs = c.paypal.calls[-1]
        assert kwargs["amount"] == "19.00"
        assert kwargs["currency"] == "USD"

    def test_address_is_not_echoed_in_the_description(self, checkout):
        c = checkout()
        c.create_order(sku="tier-30d", address=BUYER)
        _, kwargs = c.paypal.calls[-1]
        # only a truncated prefix may appear
        assert BUYER not in kwargs["description"]


# --- the important invariants ----------------------------------------------

class TestCaptureInvariants:
    def test_capture_grants_the_tier(self, checkout):
        r = checkout().capture_order(order_id="ORDER-1", address=BUYER)
        assert r["already_processed"] is False
        assert r["granted_to"] == BUYER.lower()
        assert r["tier"] == "paid"

    def test_capture_records_the_order(self, checkout):
        c = checkout()
        c.capture_order(order_id="ORDER-1", address=BUYER)
        assert c.processed.seen("ORDER-1") is True

    def test_amount_mismatch_refuses_to_grant(self, checkout):
        """A tampered/incorrect order must never produce access."""
        paypal = FakePayPal(payload=order_payload(value="0.01"))
        c = checkout(paypal=paypal)
        with pytest.raises(PayPalError) as exc:
            c.capture_order(order_id="ORDER-1", address=BUYER)
        assert "amount" in str(exc.value).lower()
        assert c.entitlements.get(BUYER) is None

    def test_currency_mismatch_refuses_to_grant(self, checkout):
        paypal = FakePayPal(payload=order_payload(currency="EUR"))
        c = checkout(paypal=paypal)
        with pytest.raises(PayPalError):
            c.capture_order(order_id="ORDER-1", address=BUYER)
        assert c.entitlements.get(BUYER) is None

    def test_non_creditable_status_refuses_to_grant(self, checkout):
        paypal = FakePayPal(payload=order_payload(status="VOIDED"))
        c = checkout(paypal=paypal)
        with pytest.raises(PayPalError):
            c.capture_order(order_id="ORDER-1", address=BUYER)
        assert c.entitlements.get(BUYER) is None

    def test_missing_amount_refuses_to_grant(self, checkout):
        payload = order_payload()
        payload["purchase_units"][0]["amount"] = {}
        c = checkout(paypal=FakePayPal(payload=payload))
        with pytest.raises(PayPalError):
            c.capture_order(order_id="ORDER-1", address=BUYER)
        assert c.entitlements.get(BUYER) is None

    def test_replayed_capture_does_not_double_credit(self, checkout):
        """Replay must be idempotent — no second grant, no extended expiry."""
        c = checkout()
        first = c.capture_order(order_id="ORDER-1", address=BUYER)
        granted_at = first["entitlement"]["granted_at"]
        second = c.capture_order(order_id="ORDER-1", address=BUYER)
        assert second["already_processed"] is True
        again = c.entitlements.get(BUYER)
        assert again.granted_at == granted_at

    def test_replay_does_not_extend_a_time_limited_tier(self, checkout):
        c = checkout()
        c.capture_order(order_id="ORDER-1", address=BUYER)
        exp1 = c.entitlements.get(BUYER).expires_at
        c.capture_order(order_id="ORDER-1", address=BUYER)
        assert c.entitlements.get(BUYER).expires_at == exp1

    def test_capture_failure_does_not_record_the_order(self, checkout):
        c = checkout(paypal=FakePayPal(payload=order_payload(value="0.01")))
        with pytest.raises(PayPalError):
            c.capture_order(order_id="ORDER-1", address=BUYER)
        assert c.processed.seen("ORDER-1") is False

    def test_entitlement_binds_to_the_given_address(self, checkout):
        """The address argument is what gets the tier — callers must pass the
        session address, and this asserts the binding is not sourced elsewhere."""
        c = checkout()
        c.capture_order(order_id="ORDER-1", address=OTHER)
        assert c.entitlements.get(OTHER) is not None
        assert c.entitlements.get(BUYER) is None

    def test_granted_address_resolves_to_paid(self, checkout):
        c = checkout()
        c.capture_order(order_id="ORDER-1", address=BUYER)
        assert resolve_tier(verified_address=BUYER, owner_addresses=[],
                            store=c.entitlements) is Tier.PAID

    def test_paypal_transport_error_propagates_without_granting(self, checkout):
        c = checkout(paypal=FakePayPal(raises=PayPalError("network down")))
        with pytest.raises(PayPalError):
            c.capture_order(order_id="ORDER-1", address=BUYER)
        assert c.entitlements.get(BUYER) is None


# --- plan matching ----------------------------------------------------------

class TestPlanMatching:
    def test_reference_id_selects_the_plan(self, checkout):
        paypal = FakePayPal(payload=order_payload(value="5.00",
                                                  reference="a"))
        c = checkout(paypal=paypal, plans=(
            PricePlan("a", "A", "5.00", "USD", "paid", 30),
            PricePlan("b", "B", "9.00", "USD", "paid", 365),
        ))
        c.capture_order(order_id="ORDER-1", address=BUYER)
        assert c.entitlements.get(BUYER) is not None

    def test_unknown_reference_falls_back_to_amount_match(self, checkout):
        paypal = FakePayPal(payload=order_payload(reference="unknown-ref"))
        c = checkout(paypal=paypal)
        r = c.capture_order(order_id="ORDER-1", address=BUYER)
        assert r["tier"] == "paid"

    def test_unmatchable_order_is_refused(self, checkout):
        paypal = FakePayPal(payload=order_payload(value="77.77",
                                                  reference="nope"))
        c = checkout(paypal=paypal)
        with pytest.raises(PayPalError):
            c.capture_order(order_id="ORDER-1", address=BUYER)
        assert c.entitlements.get(BUYER) is None

    def test_default_plans_are_all_paid_tier(self):
        assert all(p.tier == "paid" for p in DEFAULT_PLANS)

    def test_default_plans_have_distinct_skus(self):
        skus = [p.sku for p in DEFAULT_PLANS]
        assert len(skus) == len(set(skus))


# --- secrets -----------------------------------------------------------------

class TestNoSecretLeakage:
    def test_error_dict_has_no_secret(self):
        c = PayPalClient(client_id=CLIENT_ID, client_secret=SECRET)
        err = PayPalError("failed", detail="upstream")
        assert SECRET not in json.dumps(err.as_dict())

    def test_describe_has_no_secret_after_use(self):
        c = FakePayPal()
        c.access_token()
        assert SECRET not in json.dumps(c.describe())

    def test_entitlement_note_carries_no_secret(self, checkout):
        c = checkout()
        c.capture_order(order_id="ORDER-1", address=BUYER)
        note = c.entitlements.get(BUYER).note
        assert SECRET not in note
        assert CLIENT_ID not in note


# --- store ------------------------------------------------------------------

class TestProcessedOrderStore:
    def test_unknown_order_is_not_seen(self, tmp_path):
        s = ProcessedOrderStore(tmp_path / "p.json")
        assert s.seen("nope") is False

    def test_record_then_seen(self, tmp_path):
        s = ProcessedOrderStore(tmp_path / "p.json")
        s.record("O1", address=BUYER, amount="19.00", currency="USD",
                 tier="paid", days=30)
        assert s.seen("O1") is True
        assert s.get("O1")["address"] == BUYER

    def test_persists_across_instances(self, tmp_path):
        p = tmp_path / "p.json"
        ProcessedOrderStore(p).record("O1", address=BUYER, amount="19.00",
                                      currency="USD", tier="paid", days=30)
        assert ProcessedOrderStore(p).seen("O1") is True

    def test_corrupt_ledger_does_not_crash(self, tmp_path):
        p = tmp_path / "p.json"
        p.write_text("{not json")
        assert ProcessedOrderStore(p).seen("O1") is False

    def test_ledger_file_is_owner_only(self, tmp_path):
        p = tmp_path / "p.json"
        ProcessedOrderStore(p).record("O1", address=BUYER, amount="19.00",
                                      currency="USD", tier="paid", days=30)
        assert (p.stat().st_mode & 0o777) == 0o600
