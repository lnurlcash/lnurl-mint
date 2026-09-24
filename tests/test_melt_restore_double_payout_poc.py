"""Regression tests for S1 (melt restore vs late-settling payment - double
payout, CWE-367/372), ported from a security review's PoC
(lnurl-mint-security-review-2026-08-12.md). The original PoC's HodlNode fake
modeled the *pre-fix* is_payment_complete backends, which mapped a still
in-flight/pending payment straight to False - exactly the bug. It asserted
that behavior to prove the vulnerability; every test PASSED against the
vulnerable code.

Since the fix (router.py's _melt_pay + node.py's _is_payment_complete_lnd/
_cln), that mapping is gone: a payment that's still genuinely in flight (a
malicious payee holding a hodl invoice open rather than settling or failing
it) must raise - "can't confirm either way" - never resolve to False. HodlNode
below models that corrected contract, and the assertions are inverted
accordingly: melting into a hodl invoice must leave the note pending, never
restore it while the underlying payment might still resolve.

What HodlNode encodes (standard, documented LN behavior this fix must
survive even though it isn't exercised against a real node here):

- lnd: a terminal FAILED status marks the payment failed LOCALLY; it cannot
  claw back a live downstream HTLC. A hodl-invoice recipient knows the
  preimage and can settle a held HTLC any time before CLTV expiry - after
  the payer's node has given up.
- cln: an xpay non-2xx means xpay gave up waiting, not that no HTLC remains
  claimable - true for honest failures, not for a counterparty deliberately
  holding the HTLC (see node.py's _pay_invoice_cln docstring).
"""

import time
from hashlib import sha256
from os import urandom

import bolt11
import pytest
from bolt11.models.tags import TagChar, Tags
from bolt11.types import Bolt11
from fastapi.testclient import TestClient

import lnurl_mint.router as router_module
from lnurl_mint.config import settings
from lnurl_mint.db import notes
from lnurl_mint.node import PaymentFailed, PaymentResult
from lnurl_mint.server import app
from tests.conftest import fresh_secret, k1_id

VALUE = 100_000


def fake_invoice(amount_msat: int, payment_hash: str | None = None) -> str:
    tags = Tags()
    tags.add(TagChar.payment_hash, payment_hash or urandom(32).hex())
    tags.add(TagChar.payment_secret, urandom(32).hex())
    tags.add(TagChar.description, "poc")
    return bolt11.encode(
        Bolt11(currency="bc", amount_msat=amount_msat, date=int(time.time()), tags=tags), urandom(32).hex()
    )


class HodlNode:
    """A funding source whose API answers and reality can diverge - the
    defining property of paying a hodl invoice: our client gives up, the
    HTLC stays live, the recipient settles it whenever they choose.

    is_payment_complete models the FIXED backend contract: while any HTLC
    is still held open (pending_hodl non-empty), it raises rather than
    reporting False - "can't confirm either way", never "confirmed not
    paid". Only once reality has caught up (settle_hodl_payments, or the
    HTLC never existed to begin with) does it resolve definitively."""

    def __init__(self) -> None:
        self.settled: set[str] = set()  # settled MINT invoices (for minting notes)
        self.last_preimage = b""
        self.preimages: dict[str, bytes] = {}
        self.paid_out: list[str] = []  # reality ledger: invoices funds actually left for
        self.pay_mode = "ok"  # "ok" | "ambiguous" | "failed"
        self.pending_hodl: list[str] = []  # raised against, but destined to settle (or clear) late
        self.is_payment_complete_calls = 0

    async def create_invoice(self, amount_msat, config, memo=""):
        preimage = urandom(32)
        self.last_preimage = preimage
        ph = sha256(preimage).hexdigest()
        self.preimages[ph] = preimage
        return fake_invoice(amount_msat, ph), preimage

    async def is_invoice_settled(self, ph, config):
        return ph in self.settled

    async def invoice_preimage(self, ph, config):
        return self.preimages.get(ph) if ph in self.settled else None

    async def pay_invoice(self, invoice, config, fee_limit_msat):
        if self.pay_mode == "ambiguous":
            # lnd: stream ends without terminal status -> ValueError.
            # Reality: the HTLC stays in flight.
            self.pending_hodl.append(invoice)
            raise ValueError("lnd did not report a terminal payment status.")
        if self.pay_mode == "failed":
            # lnd terminal FAILED / cln xpay non-2xx -> PaymentFailed. Reality
            # for a hodl invoice: the HTLC was never failed back and can
            # still settle until CLTV expiry.
            self.pending_hodl.append(invoice)
            raise PaymentFailed("Timed out trying to find a route to pay this invoice.")
        if self.pay_mode == "benign_failed":
            # a genuine no-route failure: no HTLC was ever sent anywhere,
            # unlike "failed" above where one is (deliberately) held open
            raise PaymentFailed("Could not find a route to pay this invoice.")
        self.paid_out.append(invoice)
        return PaymentResult(urandom(32), None)

    async def is_payment_complete(self, payment_hash, config):
        self.is_payment_complete_calls += 1
        if self.pending_hodl:
            raise ConnectionError("payment still pending - not a terminal outcome (hodl HTLC live)")
        return bool(self.paid_out)

    def settle_hodl_payments(self):
        """Reality catches up: every hodl HTLC we gave up on gets settled by
        its recipient - funds actually leave the node now, and a fresh
        confirmation check would report True."""
        self.paid_out.extend(self.pending_hodl)
        self.pending_hodl.clear()


@pytest.fixture
def hodl(monkeypatch: pytest.MonkeyPatch) -> HodlNode:
    node = HodlNode()
    monkeypatch.setattr(settings, "fundingsource_backend", "lnd")
    monkeypatch.setattr(router_module, "create_invoice", node.create_invoice)
    monkeypatch.setattr(router_module, "is_invoice_settled", node.is_invoice_settled)
    monkeypatch.setattr(router_module, "invoice_preimage", node.invoice_preimage)
    monkeypatch.setattr(router_module, "pay_invoice", node.pay_invoice)
    monkeypatch.setattr(router_module, "is_payment_complete", node.is_payment_complete)
    # no real backoff in tests - see conftest.py's node fixture
    monkeypatch.setattr(router_module, "_CONFIRMATION_RETRY_DELAYS_SECONDS", ())
    return node


@pytest.fixture
def hodl_client(hodl: HodlNode) -> TestClient:
    return TestClient(app)


def mint_note(client: TestClient, node: HodlNode, amount_msat: int = VALUE) -> str:
    secret, comment = fresh_secret()
    res = client.get(f"/p/cb?amount={amount_msat}&comment={comment}")
    assert res.status_code == 200, res.text
    preimage = node.last_preimage
    node.settled.add(sha256(preimage).hexdigest())
    return secret


def outstanding(k1: str) -> int | None:
    return notes.note_amount(k1_id(k1))


def test_variant_a_ambiguous_failure_leaves_the_note_pending_not_restored(hodl_client, hodl):
    """pay_invoice raises ambiguously; the HTLC stays genuinely live at the
    hodl-invoice attacker. Confirmation can no longer confirm "not paid" for
    a still-pending payment, so the note must stay pending - not be restored
    out from under a payment that might still resolve."""
    k1 = mint_note(hodl_client, hodl)

    hodl.pay_mode = "ambiguous"
    res = hodl_client.get(f"/w/cb?k1={k1}&pr={fake_invoice(VALUE)}")
    assert res.json() == {"status": "OK"}  # per spec, OK before the payment attempt
    assert hodl.is_payment_complete_calls == 1  # confirmation consulted...
    assert outstanding(k1) == VALUE  # ...still outstanding, but frozen:
    _, h = fresh_secret()
    assert hodl_client.get(f"/w/cb?k1={k1}&p1={h}").json() == {"status": "ERROR", "reason": "pending"}

    hodl.settle_hodl_payments()  # reality: funds leave the node now

    # the note is NOT auto-recovered just because reality caught up (S3: no
    # reconcile loop yet) - but critically, it can never be spent twice:
    hodl.pay_mode = "ok"
    res = hodl_client.get(f"/w/cb?k1={k1}&pr={fake_invoice(VALUE)}")
    assert res.json() == {"status": "ERROR", "reason": "pending"}

    # exactly one payout ever left the node for this one note
    assert len(hodl.paid_out) == 1


def test_variant_b_payment_failed_is_still_confirmed_before_restoring(hodl_client, hodl):
    """PaymentFailed is no longer trusted on its own - is_payment_complete is
    always consulted, and a hodl HTLC still held (pending_hodl non-empty)
    means it can't confirm "not paid" either, so the note stays pending
    rather than being restored and later double-spent."""
    k1 = mint_note(hodl_client, hodl)

    hodl.pay_mode = "failed"
    res = hodl_client.get(f"/w/cb?k1={k1}&pr={fake_invoice(VALUE)}")
    assert res.json() == {"status": "OK"}
    assert hodl.is_payment_complete_calls == 1  # confirmation is no longer skipped
    assert outstanding(k1) == VALUE  # still outstanding, but frozen:
    _, h = fresh_secret()
    assert hodl_client.get(f"/w/cb?k1={k1}&p1={h}").json() == {"status": "ERROR", "reason": "pending"}

    hodl.settle_hodl_payments()  # the "definitively failed" payment settles late

    hodl.pay_mode = "ok"
    res = hodl_client.get(f"/w/cb?k1={k1}&pr={fake_invoice(VALUE)}")
    assert res.json() == {"status": "ERROR", "reason": "pending"}

    assert len(hodl.paid_out) == 1


def test_control_benign_failure_restores_and_retry_pays_exactly_once(hodl_client, hodl):
    """The restore path's intended case: a genuine no-route failure (no HTLC
    ever held) must still restore normally - isolating the fix to
    restore-vs-in-flight, not restore itself."""
    k1 = mint_note(hodl_client, hodl)

    hodl.pay_mode = "benign_failed"
    res = hodl_client.get(f"/w/cb?k1={k1}&pr={fake_invoice(VALUE)}")
    assert res.json() == {"status": "OK"}
    assert outstanding(k1) == VALUE  # restored - correct for a benign failure

    hodl.pay_mode = "ok"
    res = hodl_client.get(f"/w/cb?k1={k1}&pr={fake_invoice(VALUE)}")
    assert res.json() == {"status": "OK"}
    assert outstanding(k1) is None

    assert len(hodl.paid_out) == 1  # exactly one payout for one note
