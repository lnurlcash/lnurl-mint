"""NIP-57 zaps, publish-only (see nostr.py): a registered username's
payRequest says it can be zapped, /p/{username} takes the kind 9734 and
binds the invoice to it, and once the invoice settles the mint publishes
a kind 9735 receipt signed with its own Nostr key."""

import asyncio
import json
import time
from hashlib import sha256
from os import urandom
from typing import Any

import pytest
from coincurve import PrivateKey
from fastapi.testclient import TestClient
from pydantic import SecretStr

from lnurl_mint import bech32m, derivation, nostr
from lnurl_mint import router as router_module
from lnurl_mint.config import settings
from lnurl_mint.db import notes
from tests.conftest import FakeNode, sign_schnorr_message

MINT_KEY = urandom(32).hex()
RELAYS = ["wss://relay.example", "wss://nos.example"]

# secp256k1 group order - see test_username_registration.py's own copy of
# this constant/helper for the full rationale (BIP-340 x-only tweak).
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def _ownership_sig(p: PrivateKey, branch_point: bytes, chain_code: bytes, action: str, username: str) -> str:
    d = p.to_int()
    if p.public_key.format(compressed=True)[0] == 0x03:
        d = _N - d
    tweak = int.from_bytes(
        derivation.tagged_hash(b"LNURLcash/derive", branch_point + chain_code + (0).to_bytes(4, "big")), "big"
    )
    sk0 = PrivateKey.from_int((d + tweak) % _N)
    message = f"LNURLcash:{action}:{username}".encode()
    return sign_schnorr_message(sk0, message).hex()


def _branch() -> tuple[PrivateKey, bytes, bytes, str]:
    p = PrivateKey()
    branch_point = p.public_key.format(compressed=True)[1:]
    chain_code = urandom(32)
    return p, branch_point, chain_code, bech32m.encode_cx1(branch_point + chain_code)


def _zap_request(amount_msat: int | None = 21_000, recipient: str | None = None, **overrides: Any) -> dict[str, Any]:
    sender = urandom(32).hex()
    tags: list[list[str]] = [
        ["p", recipient or urandom(32).hex()],
        ["relays", *RELAYS],
    ]
    if amount_msat is not None:
        tags.append(["amount", str(amount_msat)])
    tags.extend(overrides.pop("extra_tags", []))
    event = nostr.sign_event(nostr.ZAP_REQUEST_KIND, tags, "gm", sender)
    event.update(overrides)
    return event


@pytest.fixture
def zaps(monkeypatch: pytest.MonkeyPatch, client: TestClient) -> list[tuple[list[str], dict[str, Any]]]:
    """A mint with zaps on, whose relay publishes are captured here
    instead of dialled: (relays asked, event) per receipt."""
    monkeypatch.setattr(settings, "nostr_key", SecretStr(MINT_KEY))
    monkeypatch.setattr(settings, "nostr_relays", "wss://mint.example")
    sent: list[tuple[list[str], dict[str, Any]]] = []

    async def fake_publish(relays: list[str], event: dict[str, Any]) -> list[str]:
        sent.append((relays, event))
        return relays

    monkeypatch.setattr(nostr, "publish", fake_publish)
    return sent


def _register(client: TestClient) -> str:
    """A fresh username each time: the store outlives one test."""
    username = f"zap{urandom(4).hex()}"  # .hex() is always lowercase already
    p, branch_point, chain_code, cx1 = _branch()
    sig = _ownership_sig(p, branch_point, chain_code, "register", username)
    assert client.post(f"/p/{username}?cx1={cx1}&sig={sig}").json() == {"status": "OK"}
    return username


def _receipts(node: FakeNode) -> int:
    return asyncio.run(router_module.publish_zap_receipts(settings.funding_source()))


def _receipt_for(zaps: list[tuple[list[str], dict[str, Any]]], pr: str) -> tuple[list[str], dict[str, Any]] | None:
    """The published receipt for invoice `pr`, if any - the store outlives
    a test, so a round may also publish another test's leftovers."""
    for relays, event in zaps:
        if ["bolt11", pr] in event["tags"]:
            return relays, event
    return None


def test_a_registered_username_advertises_zaps(client: TestClient, zaps):
    username = _register(client)
    data = client.get(f"/.well-known/lnurlp/{username}").json()
    assert data["allowsNostr"] is True
    assert data["nostrPubkey"] == nostr.pubkey_of(MINT_KEY)


def test_the_fixed_identity_does_not(client: TestClient, zaps):
    data = client.get(f"/.well-known/lnurlp/{settings.username}").json()
    assert "allowsNostr" not in data and "nostrPubkey" not in data


def test_without_a_key_nothing_is_advertised_and_a_zap_is_refused(client: TestClient):
    username = _register(client)
    assert "allowsNostr" not in client.get(f"/.well-known/lnurlp/{username}").json()
    resp = client.get(f"/p/{username}", params={"amount": 21_000, "nostr": json.dumps(_zap_request())})
    assert resp.json() == {"status": "ERROR", "reason": "Zaps are not offered for this address."}


def test_a_zap_binds_the_invoice_to_the_request_and_publishes_a_receipt(client: TestClient, node: FakeNode, zaps):
    username = _register(client)
    request = _zap_request()
    raw = json.dumps(request)
    resp = client.get(f"/p/{username}", params={"amount": 21_000, "nostr": raw}).json()
    assert "pr" in resp, resp
    payment_hash = sha256(node.last_preimage).hexdigest()
    # the invoice carries sha256(zap request), which is what clients check the receipt against
    assert node.description_hashes[payment_hash] == raw
    # unpaid: no receipt
    _receipts(node)
    assert _receipt_for(zaps, resp["pr"]) is None

    node.settled.add(payment_hash)
    _receipts(node)
    relays, receipt = _receipt_for(zaps, resp["pr"])
    assert set(relays) == {*RELAYS, "wss://mint.example"}
    assert receipt["kind"] == 9735
    assert receipt["pubkey"] == nostr.pubkey_of(MINT_KEY)
    assert nostr.verify_event(receipt)
    tags = {t[0]: t[1:] for t in receipt["tags"]}
    assert tags["p"] == [request["tags"][0][1]]
    assert tags["P"] == [request["pubkey"]]
    assert tags["bolt11"] == [resp["pr"]]
    assert tags["description"] == [raw]
    assert tags["preimage"] == [node.last_preimage.hex()]
    # the note landed on the username's branch as any address payment does
    assert notes.mint_settled(payment_hash)
    # published once, never again
    assert notes.zap_receipt_id(payment_hash) == receipt["id"]
    _receipts(node)
    assert sum(1 for _, e in zaps if e["id"] == receipt["id"]) == 1


def test_a_receipt_no_relay_takes_is_retried(client: TestClient, node: FakeNode, zaps, monkeypatch):
    username = _register(client)
    pr = client.get(f"/p/{username}", params={"amount": 21_000, "nostr": json.dumps(_zap_request())}).json()["pr"]
    payment_hash = sha256(node.last_preimage).hexdigest()
    node.settled.add(payment_hash)

    async def nobody(relays: list[str], event: dict[str, Any]) -> list[str]:
        return []

    monkeypatch.setattr(nostr, "publish", nobody)
    _receipts(node)
    assert notes.zap_receipt_id(payment_hash) is None

    async def everybody(relays: list[str], event: dict[str, Any]) -> list[str]:
        zaps.append((relays, event))
        return relays

    monkeypatch.setattr(nostr, "publish", everybody)
    _receipts(node)
    assert _receipt_for(zaps, pr) is not None
    assert notes.zap_receipt_id(payment_hash) is not None


def test_an_ordinary_address_payment_publishes_nothing(client: TestClient, node: FakeNode, zaps, monkeypatch):
    monkeypatch.setattr(settings, "verify_enabled", True)
    username = _register(client)
    pr = client.get(f"/p/{username}", params={"amount": 21_000}).json()["pr"]
    payment_hash = sha256(node.last_preimage).hexdigest()
    node.settled.add(payment_hash)
    # not a zap, so the poll leaves it to settle lazily as ever; verify settles it here
    _receipts(node)
    assert not notes.mint_settled(payment_hash)
    assert client.get(f"/verify/{payment_hash}").json()["settled"] is True
    _receipts(node)
    assert _receipt_for(zaps, pr) is None and notes.zap_receipt_id(payment_hash) is None


@pytest.mark.parametrize(
    "request_json, reason",
    [
        ("not json", "Zap request is not JSON."),
        (json.dumps({**_zap_request(), "kind": 1}), "Zap request is not a kind 9734 event."),
        (json.dumps({**_zap_request(), "sig": "00" * 64}), "Zap request signature is invalid."),
        (json.dumps({**_zap_request(), "content": "tampered"}), "Zap request signature is invalid."),
        (json.dumps(_zap_request(amount_msat=20_000)), "Zap request amount does not match the invoice."),
        (
            json.dumps(_zap_request(extra_tags=[["p", "ab" * 32]])),
            "Zap request needs exactly one p tag naming a pubkey.",
        ),
        (json.dumps(_zap_request(extra_tags=[["e", "nothex"]])), "Zap request e tag is malformed."),
    ],
)
def test_a_bad_zap_request_is_refused_before_any_invoice(
    client: TestClient, node: FakeNode, zaps, request_json: str, reason: str
):
    username = _register(client)
    resp = client.get(f"/p/{username}", params={"amount": 21_000, "nostr": request_json})
    assert resp.json() == {"status": "ERROR", "reason": reason}
    assert node.last_preimage == b""


def test_a_zap_request_without_relays_is_refused(client: TestClient, zaps):
    username = _register(client)
    request = _zap_request()
    request["tags"] = [t for t in request["tags"] if t[0] != "relays"]
    resp = client.get(f"/p/{username}", params={"amount": 21_000, "nostr": json.dumps(request)})
    # re-signed by nobody: the id no longer matches, which is the first thing checked
    assert resp.json()["status"] == "ERROR"


def test_the_fixed_identity_refuses_a_zap(client: TestClient, zaps):
    resp = client.get("/p/cb", params={"amount": 21_000, "nostr": json.dumps(_zap_request())})
    assert resp.json() == {"status": "ERROR", "reason": "Zaps are not offered for this address."}


def test_the_request_cannot_point_the_mint_at_arbitrary_sockets():
    request = _zap_request()
    request["tags"] = [
        ["p", "ab" * 32],
        ["relays", "ws://127.0.0.1:9735", "http://relay.example", "wss://one.example", " wss://one.example"]
        + [f"wss://r{i}.example" for i in range(20)],
    ]
    relays = nostr.relays_of(request)
    assert relays[:1] == ["wss://one.example"]
    assert len(relays) == 8
    assert all(r.startswith("wss://") for r in relays)


def test_the_settlement_poll_is_bounded(client: TestClient, node: FakeNode, zaps, monkeypatch):
    username = _register(client)
    for _ in range(3):
        client.get(f"/p/{username}", params={"amount": 21_000, "nostr": json.dumps(_zap_request())})
    monkeypatch.setattr(router_module, "_ZAP_POLL_LIMIT", 2)
    assert len(notes.pending_zap_mints(0, router_module._ZAP_POLL_LIMIT)) == 2
    # an invoice older than the window is not polled, however new the rest are
    assert notes.pending_zap_mints(int(time.time()) + 10**9, 100) == []


def test_zaps_stay_off_on_spark(client: TestClient, zaps, monkeypatch):
    username = _register(client)
    monkeypatch.setattr(settings, "fundingsource_backend", "spark")
    assert "allowsNostr" not in client.get(f"/.well-known/lnurlp/{username}").json()


def test_a_zap_with_an_empty_lud12_comment_still_gets_a_receipt(client: TestClient, node: FakeNode, zaps):
    """A zapping client may also send the empty LUD-12 comment advertised by
    the address. It must not block the zap or its receipt."""
    username = _register(client)
    raw = json.dumps(_zap_request())
    response = client.get(f"/p/{username}", params={"amount": 21_000, "nostr": raw, "comment": ""}).json()
    assert "pr" in response, response
    payment_hash = sha256(node.last_preimage).hexdigest()
    assert node.description_hashes[payment_hash] == raw

    node.settled.add(payment_hash)
    _receipts(node)
    assert _receipt_for(zaps, response["pr"]) is not None
