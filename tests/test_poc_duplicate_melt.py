"""Regression tests for the duplicate-melt guard (2026-08-17 review, second
finding): a melt into an invoice whose payment hash an earlier melt already
used is rejected outright, instead of burning its note without moving funds.

The original problem: funding sources dedupe outgoing payments by payment
hash - cln's xpay rejects with 219 "This invoice has already been paid."
(node.py's _CLN_PAY_FAILURE_REASONS) and lnd replays the prior payment's
status for a repeated hash - so a second melt into the same `pr` was
confirmed against the FIRST payment (is_payment_complete True) and
finalize_melt burned the second note with no new funds leaving the node:
the melter's value destroyed, silently captured by the mint. Typical
trigger: a merchant (or broken merchant software) handing the same invoice
to two buyers.

The fix (router.py's melt branch): any `pr` whose payment hash is already
in the melts table (NoteStore.record_melt writes it unconditionally, even
for a melt that later fails) is rejected synchronously, before any
reservation. Trade-off, pinned below: retrying a genuinely FAILED melt
also needs a fresh invoice - BOLT-11 invoices are single-use anyway.
"""

from fastapi.testclient import TestClient

from tests.conftest import FakeNode, fake_invoice, fresh_secret

VALUE = 50_000


def test_second_melt_into_the_same_invoice_is_rejected(client: TestClient, node: FakeNode, mint_note):
    k1_a, k1_b = mint_note(VALUE), mint_note(VALUE)
    pr = fake_invoice(VALUE)

    # the first melt pays the invoice normally
    res = client.get(f"/w/cb?k1={k1_a}&pr={pr}")
    assert res.json()["status"] == "OK", res.text
    assert node.paid == [pr]

    # a second melt into the SAME invoice: previously this burned k1_b's
    # note against the first payment without any funds moving - now
    # rejected before anything is reserved
    res = client.get(f"/w/cb?k1={k1_b}&pr={pr}")
    assert res.json()["status"] == "ERROR"
    assert "already used" in res.json()["reason"]
    assert node.paid == [pr]  # no second payment attempt at all

    # note B is untouched - still fully spendable
    _, h = fresh_secret()
    res = client.get(f"/w/cb?k1={k1_b}&p1={h}")
    assert res.json()["status"] == "OK", res.text


def test_failed_melt_retry_needs_a_fresh_invoice(client: TestClient, node: FakeNode, mint_note):
    """The guard's trade-off, pinned honestly: a melt that failed cleanly
    (no route - note restored) CAN be retried, but only with a fresh
    invoice, since the melts row recorded for LUD-25 verify stays."""
    k1 = mint_note(VALUE)
    stale_pr, fresh_pr = fake_invoice(VALUE), fake_invoice(VALUE)

    node.fail_reason = "Could not find a route to pay this invoice."
    res = client.get(f"/w/cb?k1={k1}&pr={stale_pr}")
    assert res.json()["status"] == "OK", res.text  # OK per spec, then fails async
    node.fail_reason = None
    # restored after the confirmed failure - the note itself is fine
    assert client.get(f"/w?k1={k1}").json().get("tag") == "withdrawRequest"

    # same invoice again: rejected - the payment hash is already recorded
    res = client.get(f"/w/cb?k1={k1}&pr={stale_pr}")
    assert res.json()["status"] == "ERROR"
    assert "already used" in res.json()["reason"]

    # a fresh invoice for the same amount: melts normally
    res = client.get(f"/w/cb?k1={k1}&pr={fresh_pr}")
    assert res.json()["status"] == "OK", res.text
    assert node.paid == [fresh_pr]
