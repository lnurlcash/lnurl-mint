import logging

from fastapi.testclient import TestClient

from lnurl_mint.config import settings
from lnurl_mint.signing import verify_note
from tests.conftest import fresh_secret


def test_mint_pubkey_absent_without_a_funding_source(client: TestClient, mint_note, monkeypatch):
    k1 = mint_note(5000)
    # settle the pending mint into a real outstanding note *before* removing
    # the funding source - resolving a not-yet-settled one also depends on
    # it (to check the invoice), which would fail this test for an unrelated
    # reason (an unresolvable k1) rather than the one it's meant to check
    assert client.get(f"/w?k1={k1}").json()["maxWithdrawable"] == 5000
    monkeypatch.setattr(settings, "fundingsource_backend", None)
    data = client.get(f"/w?k1={k1}").json()
    assert data["maxWithdrawable"] == 5000
    assert "mintPubkey" not in data


def test_signature_absent_without_a_funding_source(client: TestClient, mint_note, monkeypatch):
    k1 = mint_note(5000)
    assert client.get(f"/w?k1={k1}").json()["maxWithdrawable"] == 5000
    monkeypatch.setattr(settings, "fundingsource_backend", None)
    _, h = fresh_secret()
    data = client.get(f"/w/cb?k1={k1}&p1={h}").json()
    assert data["status"] == "OK"
    assert "sig" not in data


def test_mint_pubkey_is_the_funding_source_nodes_own_identity(client: TestClient, mint_note, node):
    k1 = mint_note(5000)
    data = client.get(f"/w?k1={k1}").json()
    assert data["mintPubkey"] == node.pubkey


def test_rotate_returns_a_valid_signature(client: TestClient, mint_note, node):
    k1 = mint_note(5000)
    _, h = fresh_secret()
    data = client.get(f"/w/cb?k1={k1}&p1={h}").json()
    assert verify_note(node.pubkey, h, 5000, data["sig"])
    assert "sig2" not in data


def test_split_returns_valid_signatures_for_both_notes(client: TestClient, mint_note, node):
    k1 = mint_note(5000)
    _, h = fresh_secret()
    _, h2 = fresh_secret()
    data = client.get(f"/w/cb?k1={k1}&amount=2000&p1={h}&p2={h2}").json()
    assert verify_note(node.pubkey, h, 2000, data["sig"])
    assert verify_note(node.pubkey, h2, 3000, data["sig2"])


def test_merge_returns_a_valid_signature(client: TestClient, mint_note, node):
    a, b = mint_note(2000), mint_note(3000)
    _, h = fresh_secret()
    data = client.get(f"/w/cb?k1={a}&k1={b}&p1={h}").json()
    assert verify_note(node.pubkey, h, 5000, data["sig"])


def test_melt_carries_no_signature(client: TestClient, node, mint_note):
    from tests.conftest import fake_invoice

    k1 = mint_note(5000)
    pr = fake_invoice(5000)
    data = client.get(f"/w/cb?k1={k1}&pr={pr}").json()
    assert data == {"status": "OK"}


def test_signature_does_not_verify_against_wrong_amount(client: TestClient, mint_note, node):
    k1 = mint_note(5000)
    _, h = fresh_secret()
    data = client.get(f"/w/cb?k1={k1}&p1={h}").json()
    assert not verify_note(node.pubkey, h, 5001, data["sig"])


def test_signature_does_not_verify_against_wrong_k1(client: TestClient, mint_note, node):
    k1 = mint_note(5000)
    _, h = fresh_secret()
    _, other_h = fresh_secret()  # a different note's hash, never disclosed here
    data = client.get(f"/w/cb?k1={k1}&p1={h}").json()
    assert not verify_note(node.pubkey, other_h, 5000, data["sig"])


def test_signature_does_not_verify_against_wrong_pubkey(client: TestClient, mint_note, node):
    from coincurve import PrivateKey

    k1 = mint_note(5000)
    _, h = fresh_secret()
    data = client.get(f"/w/cb?k1={k1}&p1={h}").json()
    wrong_pubkey = PrivateKey().public_key.format(compressed=True).hex()
    assert not verify_note(wrong_pubkey, h, 5000, data["sig"])


def test_signing_failure_is_swallowed_not_raised(client: TestClient, mint_note, node, monkeypatch):
    # a rotate/split/merge must still succeed even if the node is
    # unreachable when asked to sign - offline verification is optional
    async def _broken_sign_message(message, config):
        raise ConnectionError("node unreachable")

    monkeypatch.setattr("lnurl_mint.signing.sign_message", _broken_sign_message)
    k1 = mint_note(5000)
    _, h = fresh_secret()
    data = client.get(f"/w/cb?k1={k1}&p1={h}").json()
    assert data["status"] == "OK"
    assert "sig" not in data


def test_signing_failure_is_still_logged(client: TestClient, mint_note, node, monkeypatch, caplog):
    # regression: sign_note used to swallow every exception with zero
    # trace anywhere - a persistently broken signing RPC (e.g. a macaroon/
    # rune scoped without signmessage permission) was then indistinguishable
    # from "offline verification just isn't configured", from the logs alone
    async def _broken_sign_message(message, config):
        raise ConnectionError("Not permitted: missing signmessage permission")

    monkeypatch.setattr("lnurl_mint.signing.sign_message", _broken_sign_message)
    k1 = mint_note(5000)
    _, h = fresh_secret()
    with caplog.at_level(logging.WARNING):
        client.get(f"/w/cb?k1={k1}&p1={h}")
    assert any("sign_note" in r.message and "missing signmessage permission" in r.message for r in caplog.records)


def test_mint_pubkey_failure_is_logged(client: TestClient, mint_note, node, monkeypatch, caplog):
    async def _broken_fetch_node_info(config):
        raise ConnectionError("connection refused")

    monkeypatch.setattr("lnurl_mint.signing.fetch_node_info", _broken_fetch_node_info)
    k1 = mint_note(5000)
    with caplog.at_level(logging.WARNING):
        client.get(f"/w?k1={k1}")
    assert any("mint_pubkey" in r.message and "connection refused" in r.message for r in caplog.records)
