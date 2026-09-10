import asyncio
import logging
import time

from fastapi.testclient import TestClient

import lnurl_mint.errors as errors_module
import lnurl_mint.router as router_module
import lnurl_mint.server as server_module
from lnurl_mint.config import settings
from lnurl_mint.server import app
from tests.conftest import FakeNode, fake_invoice, fresh_secret


def _leave_a_note_pending(client: TestClient, node: FakeNode, mint_note, amount_msat: int = 5000) -> str:
    """Mints a note, then melts it into a payment outcome that can't be
    confirmed either way - see router._melt_pay's left-pending fallback -
    leaving it reserved (pending=1) rather than burned or restored."""
    k1 = mint_note(amount_msat)
    node.fail_payments = True
    node.is_payment_complete_raises = True
    pr = fake_invoice(amount_msat)
    assert client.get(f"/w/cb?k1={k1}&pr={pr}").json() == {"status": "OK"}
    _, h = fresh_secret()
    assert client.get(f"/w/cb?k1={k1}&p1={h}").json() == {"status": "ERROR", "reason": "pending"}
    return k1


def test_reconcile_finalizes_a_pending_note_once_confirmed_paid(client: TestClient, node: FakeNode, mint_note):
    k1 = _leave_a_note_pending(client, node, mint_note)

    node.is_payment_complete_raises = False
    node.payment_actually_completed = True
    asyncio.run(router_module.reconcile_pending_melts(settings.funding_source()))

    # burned for good, not just still-pending
    assert client.get(f"/w?k1={k1}").json()["status"] == "ERROR"


def test_reconcile_restores_a_pending_note_once_confirmed_not_paid(client: TestClient, node: FakeNode, mint_note):
    k1 = _leave_a_note_pending(client, node, mint_note)

    node.is_payment_complete_raises = False
    node.payment_actually_completed = False
    asyncio.run(router_module.reconcile_pending_melts(settings.funding_source()))

    assert client.get(f"/w?k1={k1}").json()["maxWithdrawable"] == 5000
    # no longer pending - a fresh melt is accepted again
    _, h = fresh_secret()
    assert client.get(f"/w/cb?k1={k1}&p1={h}").json()["status"] == "OK"


def test_reconcile_leaves_still_unconfirmable_notes_pending_without_retrying(
    client: TestClient, node: FakeNode, mint_note
):
    # a single attempt per note, not the melt-time retry/backoff schedule -
    # otherwise a boot with several stuck notes could take minutes (see
    # _confirm_payment's delays=() from reconcile_pending_melts)
    k1 = _leave_a_note_pending(client, node, mint_note)

    node.is_payment_complete_calls = 0
    asyncio.run(router_module.reconcile_pending_melts(settings.funding_source()))

    assert node.is_payment_complete_calls == 1
    _, h = fresh_secret()
    assert client.get(f"/w/cb?k1={k1}&p1={h}").json() == {"status": "ERROR", "reason": "pending"}


def test_reconcile_writes_still_unconfirmed_notes_to_error_log(
    client: TestClient, node: FakeNode, mint_note, monkeypatch, tmp_path
):
    # regression: this used to be a plain logging.warning (stdout only). A
    # note interrupted mid-melt by a restart never gets a chance to reach
    # _melt_pay's own log_internal_error call - every later boot's
    # reconcile attempt hits this same still-unconfirmed outcome, so
    # without this, such a note leaves no durable record anywhere, ever,
    # only ephemeral warnings that scroll out of `docker logs`.
    log_path = tmp_path / "error.log"
    test_logger = logging.getLogger("lnurl_mint.errors.test_reconcile")
    test_logger.setLevel(logging.ERROR)
    test_logger.propagate = False
    test_logger.addHandler(logging.FileHandler(str(log_path), delay=True))
    monkeypatch.setattr(errors_module, "_logger", test_logger)

    k1 = _leave_a_note_pending(client, node, mint_note)
    asyncio.run(router_module.reconcile_pending_melts(settings.funding_source()))

    logged = log_path.read_text()
    assert "still unconfirmed at boot" in logged
    assert k1 not in logged  # the note's own secret must never land in a log file


def test_app_boot_reconciles_a_note_left_pending_by_a_previous_process(
    client: TestClient, node: FakeNode, mint_note, monkeypatch
):
    # end-to-end wiring check: server.py's lifespan actually calls
    # reconcile_pending_melts once the funding source is confirmed
    # reachable, not just the function in isolation. The `node` fixture
    # patches fetch_node_info for frontend.py/signing.py, but a fresh
    # TestClient's own lifespan reads server.py's own imported reference -
    # patched here too, so this second boot also sees a reachable node.
    monkeypatch.setattr(server_module, "fetch_node_info", node.fetch_node_info)
    k1 = _leave_a_note_pending(client, node, mint_note)

    node.is_payment_complete_raises = False
    node.payment_actually_completed = True
    with TestClient(app):
        pass  # boot runs and shuts down here

    assert client.get(f"/w?k1={k1}").json()["status"] == "ERROR"  # burned during that boot


def test_periodic_monitor_reconciles_a_note_that_resolves_after_boot(
    client: TestClient, node: FakeNode, mint_note, monkeypatch
):
    # a note whose payment outcome only becomes confirmable *after* boot
    # (not just at the exact moment the funding source flips from
    # unreachable to reachable) used to require an operator to notice and
    # restart the process by hand - server._monitor_funding_source now
    # retries reconcile_pending_melts on every healthy tick, not just once
    monkeypatch.setattr(server_module, "fetch_node_info", node.fetch_node_info)
    monkeypatch.setattr(settings, "funding_source_health_check_interval_seconds", 0.01)
    k1 = _leave_a_note_pending(client, node, mint_note)

    with TestClient(app):
        # still unresolvable when this process boots - matches the state
        # the note was left in
        _, h = fresh_secret()
        assert client.get(f"/w/cb?k1={k1}&p1={h}").json() == {"status": "ERROR", "reason": "pending"}

        # only now does the underlying payment become confirmable - no
        # further boot happens, only the periodic monitor's own later tick
        # can pick this up
        node.is_payment_complete_raises = False
        node.payment_actually_completed = True
        time.sleep(0.1)  # let a few ticks run

    assert client.get(f"/w?k1={k1}").json()["status"] == "ERROR"  # burned by then


def test_periodic_monitor_survives_a_reconcile_failure(client: TestClient, node: FakeNode, monkeypatch):
    # an uncaught exception from reconcile_pending_melts must not kill the
    # whole background loop for the rest of the process's life - that
    # would silently end both future reconciliation *and* health-check
    # logging, the same silent-failure shape issue #2 was about to begin with
    monkeypatch.setattr(server_module, "fetch_node_info", node.fetch_node_info)
    monkeypatch.setattr(settings, "funding_source_health_check_interval_seconds", 0.01)

    calls = {"n": 0}
    real_reconcile = server_module.reconcile_pending_melts

    async def _flaky_reconcile(funding_source):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("boom")
        return await real_reconcile(funding_source)

    monkeypatch.setattr(server_module, "reconcile_pending_melts", _flaky_reconcile)
    with TestClient(app):
        time.sleep(0.1)  # several ticks worth

    assert calls["n"] > 1  # the loop kept going past the first failure
