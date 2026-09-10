import asyncio
import logging

from fastapi.testclient import TestClient

import lnurl_mint.mint_log as mint_log_module
import lnurl_mint.router as router_module
from lnurl_mint.config import settings
from tests.conftest import FakeNode, fake_invoice, fresh_secret


def _capture(monkeypatch, tmp_path):
    """Redirects mint_log's own logger to a throwaway file, mirroring
    test_errors.py's pattern for error.log - lets these tests read exactly
    what would have been written to mint.log without touching the real,
    session-wide one."""
    log_path = tmp_path / "mint.log"
    logger = logging.getLogger(f"lnurl_mint.mint_log.test.{tmp_path.name}")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger.addHandler(logging.FileHandler(str(log_path), delay=True))
    monkeypatch.setattr(mint_log_module, "_logger", logger)
    return log_path


def test_mint_logs_gross_fee_and_net(client: TestClient, node: FakeNode, mint_note, monkeypatch, tmp_path):
    log_path = _capture(monkeypatch, tmp_path)
    monkeypatch.setattr(settings, "base_fee_msat", 1000)

    k1 = mint_note(100_000)
    client.get(f"/w?k1={k1}")  # first lookup materializes + logs the mint

    logged = log_path.read_text()
    assert "MINT" in logged
    assert "gross_msat=100000" in logged
    assert "fee_msat=1000" in logged
    assert "net_msat=99000" in logged


def test_mint_is_logged_exactly_once_even_when_checked_repeatedly(
    client: TestClient, node: FakeNode, mint_note, monkeypatch, tmp_path
):
    log_path = _capture(monkeypatch, tmp_path)

    k1 = mint_note(5000)
    client.get(f"/w?k1={k1}")
    client.get(f"/w?k1={k1}")
    client.get(f"/w?k1={k1}")

    assert log_path.read_text().count("MINT") == 1


def test_melt_logs_amount_and_routing_fee_on_the_happy_path(
    client: TestClient, node: FakeNode, mint_note, monkeypatch, tmp_path
):
    log_path = _capture(monkeypatch, tmp_path)
    node.pay_fee_msat = 15

    k1 = mint_note(5000)
    pr = fake_invoice(5000)
    assert client.get(f"/w/cb?k1={k1}&pr={pr}").json() == {"status": "OK"}

    logged = log_path.read_text()
    assert "MELT" in logged
    assert "amount_msat=5000" in logged
    assert "routing_fee_msat=15" in logged


def test_melt_logs_amount_with_unknown_fee_when_confirmed_via_status_check(
    client: TestClient, node: FakeNode, mint_note, monkeypatch, tmp_path
):
    # pay_invoice itself raised (ambiguously), so its response never
    # reported a fee - only is_payment_complete confirmed this actually
    # went through, and a bare status check carries no fee information
    log_path = _capture(monkeypatch, tmp_path)
    node.fail_payments = True
    node.payment_actually_completed = True

    k1 = mint_note(5000)
    pr = fake_invoice(5000)
    assert client.get(f"/w/cb?k1={k1}&pr={pr}").json() == {"status": "OK"}

    logged = log_path.read_text()
    assert "MELT" in logged
    assert "amount_msat=5000" in logged
    assert "routing_fee_msat=None" in logged


def test_reconcile_logs_amount_when_confirming_a_stuck_melt(
    client: TestClient, node: FakeNode, mint_note, monkeypatch, tmp_path
):
    log_path = _capture(monkeypatch, tmp_path)
    node.fail_payments = True
    node.is_payment_complete_raises = True
    k1 = mint_note(5000)
    pr = fake_invoice(5000)
    client.get(f"/w/cb?k1={k1}&pr={pr}")
    _, h = fresh_secret()
    assert client.get(f"/w/cb?k1={k1}&p1={h}").json() == {"status": "ERROR", "reason": "pending"}

    node.is_payment_complete_raises = False
    node.payment_actually_completed = True
    asyncio.run(router_module.reconcile_pending_melts(settings.funding_source()))

    logged = log_path.read_text()
    assert "MELT" in logged
    assert "amount_msat=5000" in logged
    assert "routing_fee_msat=None" in logged


def test_mint_log_write_failure_does_not_crash_the_mint(
    client: TestClient, node: FakeNode, mint_note, monkeypatch, tmp_path
):
    unwritable_dir = tmp_path / "unwritable"
    unwritable_dir.mkdir(mode=0o500)
    broken_logger = logging.getLogger(f"lnurl_mint.mint_log.test_unwritable.{tmp_path.name}")
    broken_logger.setLevel(logging.INFO)
    broken_logger.propagate = False
    broken_logger.addHandler(logging.FileHandler(str(unwritable_dir / "mint.log"), delay=True))
    monkeypatch.setattr(mint_log_module, "_logger", broken_logger)

    k1 = mint_note(5000)
    # must not raise, and the note must still materialize normally
    assert client.get(f"/w?k1={k1}").json()["maxWithdrawable"] == 5000
