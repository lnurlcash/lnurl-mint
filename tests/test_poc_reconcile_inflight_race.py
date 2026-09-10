"""Regression tests for the reconcile-vs-in-flight-melt double spend
(CWE-367 time-of-check/time-of-use). The original PoC asserted the
*vulnerable* behavior - and PASSED against the unfixed code, proving it:
a reconcile_pending_melts call landing in the window between
mark_pending and the payment attempt reaching the funding source
restored the note out from under its own in-flight payment, and the
holder rotated the value out before the payment settled. Funds gone AND
the value still outstanding.

The window existed because server.py's _monitor_funding_source runs
reconcile_pending_melts on every healthy tick, and NoteStore.pending_melts
could not tell a cross-restart leftover apart from a melt whose _melt_pay
is running right now in this same process: before pay_invoice's RPC lands,
lnd's TrackPaymentV2 404s and cln's listpays is empty for the payment hash
- both truthfully "not paid", per node state alone.

The fix (router.py's _in_flight_melts registry): get_withdraw_callback
registers the melt's payment hash the moment mark_pending succeeds -
before the response goes out and the background task starts - and
_melt_pay drops it in a finally. reconcile_pending_melts skips any hash
with a live attempt entirely (it never even consults the funding source
for one), so the restore-vs-in-flight interleaving can no longer occur.
Across a restart the registry is empty by construction - background tasks
don't survive - so boot/time reconcile still picks up genuine leftovers.

HodlNode here models the same "API answers and reality can diverge"
funding source as test_melt_restore_double_payout_poc.py: pay_invoice is
entered but parked BEFORE any RPC registers the attempt node-side, and
is_payment_complete reports what lnd (404) / cln (empty listpays) both
report for an unregistered payment: "confirmed not paid".
"""

import asyncio
from hashlib import sha256
from os import urandom

import bolt11
import httpx
import pytest
from fastapi.testclient import TestClient

import lnurl_mint.router as router_module
from lnurl_mint.config import settings
from lnurl_mint.db import notes
from lnurl_mint.node import PaymentResult
from lnurl_mint.server import app
from tests.conftest import fake_invoice, fresh_secret

VALUE = 100_000


class InFlightNode:
    """A funding source whose pay_invoice is entered but parked BEFORE the
    payment attempt is registered node-side - the exact window in which
    lnd's TrackPaymentV2 still 404s and cln's listpays is still empty for
    the melt's payment hash, so is_payment_complete (truthfully, from the
    node's perspective) reports "confirmed not paid"."""

    def __init__(self) -> None:
        self.settled: set[str] = set()  # settled MINT invoices (for minting notes)
        self.last_preimage = b""
        self.preimages: dict[str, bytes] = {}
        self.paid_out: list[str] = []  # reality ledger: invoices funds actually left for
        self.pay_started = asyncio.Event()  # pay_invoice entered (mark_pending already landed)
        self.pay_release = asyncio.Event()  # the test lets the payment through
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
        # entered, but parked before any RPC reaches the funding source -
        # the node has no record of this attempt yet
        self.pay_started.set()
        await self.pay_release.wait()
        self.paid_out.append(invoice)
        return PaymentResult(urandom(32), None)

    async def is_payment_complete(self, payment_hash, config):
        # what lnd (TrackPaymentV2 404) and cln (empty listpays) both report
        # for a payment the node has not registered yet: "confirmed not paid"
        self.is_payment_complete_calls += 1
        return False


@pytest.fixture
def inflight(monkeypatch: pytest.MonkeyPatch) -> InFlightNode:
    node = InFlightNode()
    monkeypatch.setattr(settings, "fundingsource_backend", "lnd")
    monkeypatch.setattr(router_module, "create_invoice", node.create_invoice)
    monkeypatch.setattr(router_module, "is_invoice_settled", node.is_invoice_settled)
    monkeypatch.setattr(router_module, "invoice_preimage", node.invoice_preimage)
    monkeypatch.setattr(router_module, "pay_invoice", node.pay_invoice)
    monkeypatch.setattr(router_module, "is_payment_complete", node.is_payment_complete)
    # no real backoff in tests - see conftest.py's node fixture
    monkeypatch.setattr(router_module, "_CONFIRMATION_RETRY_DELAYS_SECONDS", ())
    return node


def _mint_and_materialize(client: TestClient, node: InFlightNode) -> tuple[str, str]:
    """A settled, materialized note - returns (k1, note_id)."""
    secret = urandom(32).hex()
    comment = sha256(bytes.fromhex(secret)).hexdigest()
    res = client.get(f"/p/cb?amount={VALUE}&comment={comment}")
    assert res.json().get("pr"), res.text
    preimage = node.last_preimage
    node.settled.add(sha256(preimage).hexdigest())
    k1 = secret
    assert client.get(f"/w?k1={k1}").json().get("tag") == "withdrawRequest"
    note_id = comment
    assert notes.note_amount(note_id) == VALUE
    return k1, note_id


def test_reconcile_skips_a_note_whose_melt_is_in_flight(inflight: InFlightNode):
    """The original PoC's exact interleaving, now safe: with the melt's
    payment hash registered as in-flight, reconcile skips it without even
    consulting the funding source - the note stays pending, the rotate
    keeps failing, and exactly one payout ever leaves the node."""
    client = TestClient(app)  # sync setup only - no lifespan, no monitor task
    k1, note_id = _mint_and_materialize(client, inflight)
    melt_pr = fake_invoice(VALUE)
    attacker_secret, attacker_h = fresh_secret()

    async def scenario() -> None:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as ac:
            # the melt: mark_pending lands synchronously in the handler, the
            # payment is attempted by a background task after the response
            melt_task = asyncio.create_task(ac.get(f"/w/cb?k1={k1}&pr={melt_pr}"))
            # wait until _melt_pay is INSIDE pay_invoice, parked before any
            # RPC registers the attempt at the funding source
            await asyncio.wait_for(inflight.pay_started.wait(), timeout=5)
            assert notes.note_pending(note_id) is True

            # one monitor tick, exactly as server._monitor_funding_source
            # issues it on every healthy interval
            await router_module.reconcile_pending_melts(settings.funding_source())

            # FIXED: the hash has a live in-process attempt, so reconcile
            # skips it outright - no RPC, no restore
            assert inflight.is_payment_complete_calls == 0
            assert notes.note_pending(note_id) is True

            # the holder's rotate still fails - the value was never freed
            res = await ac.get(f"/w/cb?k1={k1}&p1={attacker_h}")
            assert res.json() == {"status": "ERROR", "reason": "pending"}

            # only now does the melt's payment actually go out
            inflight.pay_release.set()
            melt_res = await melt_task
            assert melt_res.json()["status"] == "OK", melt_res.text

    asyncio.run(scenario())

    # exactly one payout, the note is burned, and no value ever moved to h
    assert inflight.paid_out == [melt_pr]
    assert notes.note_spent(note_id) is True
    assert notes.note_amount(attacker_h) is None
    assert attacker_secret  # unused - the rotate never succeeded


def test_leftover_pending_note_is_still_reconciled(inflight: InFlightNode):
    """The skip must be scoped to LIVE attempts: a note pending with no
    in-process melt (a crash/restart leftover - indistinguishable in the
    database except for the registry entry) is still restored exactly as
    before when the payment is confirmed not to have gone out."""
    client = TestClient(app)
    _k1, note_id = _mint_and_materialize(client, inflight)
    # a leftover: marked pending for a payment hash no _melt_pay exists for
    leftover_ph = bolt11.decode(fake_invoice(VALUE)).payment_hash
    notes.mark_pending([note_id], leftover_ph)

    asyncio.run(router_module.reconcile_pending_melts(settings.funding_source()))

    assert inflight.is_payment_complete_calls == 1  # consulted - not skipped
    assert notes.note_amount(note_id) == VALUE  # restored to circulation


def test_in_flight_registry_refcounts_duplicate_payment_hashes():
    """Two melts of different notes into the same invoice share one payment
    hash: the hash stays skipped until BOTH attempts finish, and a stray
    extra _track_melt_end is a harmless no-op."""
    ph = sha256(b"dup-hash").hexdigest()
    router_module._track_melt_start(ph)
    router_module._track_melt_start(ph)
    assert router_module._melt_in_flight(ph) is True
    router_module._track_melt_end(ph)
    assert router_module._melt_in_flight(ph) is True  # one attempt still live
    router_module._track_melt_end(ph)
    assert router_module._melt_in_flight(ph) is False
    router_module._track_melt_end(ph)  # no-op, never negative
    assert router_module._melt_in_flight(ph) is False
