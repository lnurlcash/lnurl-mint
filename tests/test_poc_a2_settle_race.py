"""PoC for A2 (auth-data lane): can a settle_mint race double-credit one paid
invoice? **FALSIFIED** - one settled invoice can only ever materialize one
note, no matter how many requests race the materialization window.

The window: `_mint_settled` (router.py:200-223) reads `mint_settled` (False)
and `pending_mint` (amount) *before* awaiting the funding source's
is_invoice_settled - so N concurrent first-resolvers (any mix of /w and
/verify, the two paths that lazily materialize) can all observe "not settled
yet" and all proceed into `settle_mint` for the same payment_hash.

What saves it (the point this PoC hammers and proves):

1. db.py:137-142 - `settle_mint` runs under NoteStore._lock and its first
   statement is an atomic compare-and-set:
   `UPDATE mints SET minted = 1 WHERE payment_hash = ? AND minted = 0`.
   Exactly one racer sees rowcount == 1; every other gets rowcount 0 and
   returns None, having written nothing.
2. router.py:217-223 - a None return is explicitly the "a concurrent request
   already settled this same invoice first" case: no second note, and only
   the winner logs the mint.
3. db.py:46 backstop - `notes.id` is a PRIMARY KEY, so even a hypothetical
   second INSERT would raise and roll back rather than create a second note
   (see A1, which exploits exactly that collision against *unrelated* rows).

Concurrency model: production runs every DB-touching handler on uvicorn's
single event loop, so the race is await-interleaving on ONE loop - reproduced
here with httpx.AsyncClient + ASGITransport and asyncio.gather inside one
loop (not threads: a thread-per-request client would give each request its
own loop and its own concurrent sqlite connection use, an artifact no real
deployment of this app has). The DB layer itself is additionally hammered
with real OS threads below to prove the lock + compare-and-set on their own.
"""

import asyncio
import threading
from hashlib import sha256
from os import urandom

import httpx
import pytest
from fastapi.testclient import TestClient

import lnurl_mint.router as router_module
from lnurl_mint.config import settings
from lnurl_mint.db import notes
from lnurl_mint.server import app
from tests.conftest import fake_invoice, k1_id

AMOUNT = 21_000
W_RACERS = 8
VERIFY_RACERS = 4


def _fresh_settled_pending_mint(client: TestClient, node, comment_secret: str | None = None) -> tuple[str, str]:
    """An invoice the payer has settled but no request has materialized yet:
    (payment_hash, k1). The fake node reports it settled; the mints row is
    still minted=0 until the first /w or /verify resolves it.

    LUD-25 comment protection is mandatory (see router.get_pay_callback), so
    a WALLET-generated secret is always used - `comment_secret` lets a
    caller pin a specific one (needed by callers that want to race on a
    predetermined k1), otherwise a fresh one is generated. The returned k1
    is that secret, not the payment preimage - the note ends up keyed by
    the comment hash instead (see settle_mint)."""
    if comment_secret is None:
        comment_secret = urandom(32).hex()
    url = f"/p/cb?amount={AMOUNT}&comment={sha256(bytes.fromhex(comment_secret)).hexdigest()}"
    resp = client.get(url)
    assert resp.json().get("pr"), resp.text
    preimage = node.last_preimage
    ph = sha256(preimage).hexdigest()
    node.settled.add(ph)
    assert notes.pending_mint(ph) == AMOUNT
    return ph, comment_secret


def _race_http(ph: str, k1: str, w_racers: int, verify_racers: int) -> list[dict]:
    """Fire w_racers x /w and verify_racers x /verify concurrently on ONE
    event loop - exactly how uvicorn interleaves them in production."""

    async def gather() -> list[dict]:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as ac:

            async def hit_w() -> dict:
                return (await ac.get(f"/w?k1={k1}")).json()

            async def hit_verify() -> dict:
                return (await ac.get(f"/verify/{ph}")).json()

            return await asyncio.gather(
                *(hit_w() for _ in range(w_racers)), *(hit_verify() for _ in range(verify_racers))
            )

    return asyncio.run(gather())


def test_a2_http_race_materializes_exactly_one_note(client: TestClient, node, monkeypatch):
    # /verify racers need the endpoint served - VERIFY_ENABLED=false (the
    # test-env default) 404s it since the review, and (since LUD-25 comment
    # protection) so does a no-comment mint regardless - so this mint uses
    # one, which also means the note ends up keyed by the comment hash
    # (note_id below), not the payment hash `ph` /verify racers poll by:
    # the two now race two genuinely different lazy-settle entry points
    # (_mint_settled vs _mint_settled_by_note_id) against the same
    # underlying settle_mint call, a strictly harder version of the
    # original single-entry-point race.
    monkeypatch.setattr(settings, "verify_enabled", True)
    secret = urandom(32).hex()
    ph, k1 = _fresh_settled_pending_mint(client, node, comment_secret=secret)
    note_id = k1_id(secret)

    # widen the race window: every is_invoice_settled call parks here long
    # enough for all racers to pass the not-yet-settled checks together
    rpc_calls = 0
    orig_settled = router_module.is_invoice_settled

    async def delayed_settled(payment_hash, config):
        nonlocal rpc_calls
        rpc_calls += 1
        await asyncio.sleep(0.25)
        return await orig_settled(payment_hash, config)

    monkeypatch.setattr(router_module, "is_invoice_settled", delayed_settled)

    # count mint log entries (router.py:217-223: only the rowcount==1 winner)
    log_calls: list[tuple[str, int]] = []
    orig_log = router_module._log_mint_settled
    monkeypatch.setattr(router_module, "_log_mint_settled", lambda p, a: (log_calls.append((p, a)), orig_log(p, a))[1])

    results = _race_http(ph, k1, W_RACERS, VERIFY_RACERS)

    # the window was genuinely shared: several requests passed the not-yet-
    # settled checks and hit the node before settle_mint serialized them
    assert rpc_calls >= 2, f"race window not exercised (rpc_calls={rpc_calls})"

    # every /w racer got a valid withdrawRequest for the SAME single amount
    for body in results[:W_RACERS]:
        assert body.get("tag") == "withdrawRequest", body
        assert body["maxWithdrawable"] == AMOUNT, body
    # every /verify racer reports settled
    for body in results[W_RACERS:]:
        assert body["settled"] is True, body

    # ...and exactly one note ever came into existence: one row, one log line
    assert notes.note_amount(note_id) == AMOUNT
    assert notes.mint_settled(ph) is True
    assert log_calls == [(ph, AMOUNT)], log_calls

    # total outstanding value for this payment hash can never exceed one mint
    row = notes.conn.execute("SELECT COUNT(*), SUM(amount_msat) FROM notes WHERE id = ?", (note_id,)).fetchone()
    assert row == (1, AMOUNT), row


@pytest.mark.parametrize("rounds", [5])
def test_a2_repeated_races_never_double_credit(client: TestClient, node, rounds: int):
    """The same /w-only hammer, repeated with fresh mints - a falsified race
    should survive repetition, not just one lucky interleaving."""
    for _ in range(rounds):
        ph, k1 = _fresh_settled_pending_mint(client, node)
        note_id = k1_id(k1)
        bodies = _race_http(ph, k1, W_RACERS, 0)
        for body in bodies:
            assert body.get("tag") == "withdrawRequest", body
            assert body["maxWithdrawable"] == AMOUNT, body
        assert notes.note_amount(note_id) == AMOUNT
        assert notes.conn.execute("SELECT COUNT(*) FROM notes WHERE id = ?", (note_id,)).fetchone() == (1,)


def test_a2_db_layer_settle_mint_race_returns_amount_to_exactly_one_caller():
    """Two barrier-synced OS threads calling settle_mint directly: the lock +
    atomic compare-and-set hand the value to exactly one of them."""
    ph = sha256(urandom(32)).hexdigest()
    notes.create_mint(ph, fake_invoice(AMOUNT, ph), AMOUNT, ph)

    barrier = threading.Barrier(2)
    outcomes: list[int | None] = [None, None]

    def race(i):
        barrier.wait()
        outcomes[i] = notes.settle_mint(ph)

    threads = [threading.Thread(target=race, args=(i,)) for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    assert sorted(o for o in outcomes if o is not None) == [AMOUNT], outcomes
    assert outcomes.count(None) == 1, outcomes
    # a later call - concurrent or not - always loses once minted
    assert notes.settle_mint(ph) is None
    assert notes.note_amount(ph) == AMOUNT
