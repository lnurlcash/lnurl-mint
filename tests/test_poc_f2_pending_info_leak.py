"""Regression tests for the pending-note information leak (2026-08-17
review, F-2 - originally a cross-check PoC).

Pre-fix, `note_amount` filtered `spent = 0` but not `pending = 0`, and
get_withdraw never consulted the pending flag - so while a melt held its
note reserved (mark_pending, up to the whole background payment attempt),
/w answered a valid LUD-03 withdrawRequest with min=max=full value,
byte-for-byte indistinguishable from a freely spendable note, while every
mutating callback correctly rejected with reason "pending". That gap was
the sell-during-melt scam: seller melts, shows the buyer the healthy-looking
/w, buyer pays out-of-band, rotate fails "pending", the melt settles and
the note is gone.

The fix: get_withdraw checks NoteStore.note_pending and rejects with the
same spec-shaped reason "pending" /w/cb uses. These tests pin: (1) during
the pending window /w tells the truth, (2) after a FAILED melt (restore)
/w shows the note as withdrawable again - pending is a state, not a
one-way flag.

The pending window is exercised for real: the fake node's pay_invoice
sleeps inside the background melt task while probe requests interleave on
the same event loop (production's own concurrency shape).
"""

import asyncio
from hashlib import sha256

import httpx
from fastapi.testclient import TestClient

from lnurl_mint.db import notes
from lnurl_mint.server import app
from tests.conftest import fake_invoice, fresh_secret

VALUE = 10_000


def test_w_reports_pending_during_melt_window(client: TestClient, node, mint_note):
    k1 = mint_note(VALUE)
    # materialize it once so /w is a pure read of note state
    assert client.get(f"/w?k1={k1}").json()["maxWithdrawable"] == VALUE

    node.pay_delay = 0.5  # the background melt stays in flight long enough to probe
    probes: dict[str, dict] = {}

    async def gather():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as ac:

            async def melt():
                return (await ac.get(f"/w/cb?k1={k1}&pr={fake_invoice(VALUE)}")).json()

            async def probe():
                await asyncio.sleep(0.05)  # let the melt reach mark_pending + background pay
                probes["w"] = (await ac.get(f"/w?k1={k1}")).json()
                _, h = fresh_secret()
                probes["rotate"] = (await ac.get(f"/w/cb?k1={k1}&p1={h}")).json()

            return await asyncio.gather(melt(), probe())

    melt_body, _ = asyncio.run(gather())
    assert melt_body["status"] == "OK", melt_body  # melt accepted, paid in background

    # DURING the pending window the row said pending=1 - and now BOTH
    # endpoints tell the same truth, /w with the spec's own reason:
    assert probes["w"] == {"status": "ERROR", "reason": "pending"}, probes["w"]
    assert probes["rotate"] == {"status": "ERROR", "reason": "pending"}, probes["rotate"]

    # AFTER the melt settles, the note is spent for good - the third,
    # distinct state (unknown vs pending vs spent all report separately)
    assert client.get(f"/w?k1={k1}").json() == {"status": "ERROR", "reason": "Note already spent."}


def test_w_shows_the_note_again_after_a_failed_melt_restores_it(client: TestClient, node, mint_note):
    """Pending is transient: a melt whose payment fails cleanly (FakeNode's
    fail_reason = definitive failure, restored immediately) releases the
    note, and /w must advertise it as withdrawable again - the fix must not
    turn into a one-way 'tainted' flag."""
    k1 = mint_note(VALUE)
    note_id = sha256(bytes.fromhex(k1)).hexdigest()

    node.fail_reason = "no route"
    melt = client.get(f"/w/cb?k1={k1}&pr={fake_invoice(VALUE)}")
    assert melt.json()["status"] == "OK", melt.text
    # TestClient runs background tasks before returning, so by here the
    # failed melt has already restored the note
    assert notes.note_pending(note_id) is False

    w = client.get(f"/w?k1={k1}").json()
    assert w.get("tag") == "withdrawRequest", w
    assert w["maxWithdrawable"] == VALUE, w
