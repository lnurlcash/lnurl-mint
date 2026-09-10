"""LUD-25 Part 2, Seed & derivation's cx1 registration (router.py's
/register): a WALLET claims a Lightning Address username against its own
watch-only branch, and this mint auto-mints cp1 notes off it directly."""

from hashlib import sha256
from os import urandom

from coincurve import PrivateKey
from fastapi.testclient import TestClient

from lnurl_mint import bech32m, derivation
from lnurl_mint.config import settings
from lnurl_mint.db import notes
from tests.conftest import FakeNode


def _branch() -> tuple[bytes, bytes, str]:
    """A fresh (P, chain_code, cx1) triple - a WALLET's watch-only branch
    export, standing in for a real BIP-340-tweakable point without needing
    a full derivation from a BIP32 seed (see derivation.derive_pubkey,
    which only needs a valid x-only P, not how it was produced)."""
    p = PrivateKey()
    branch_point = p.public_key.format(compressed=True)[1:]
    chain_code = urandom(32)
    return branch_point, chain_code, bech32m.encode_cx1(branch_point + chain_code)


def _payment_hash(node: FakeNode) -> str:
    return sha256(node.last_preimage).hexdigest()


def _note_value(client: TestClient, note_id_hex: str) -> int | None:
    """Value of the outstanding note with id `note_id_hex` - via the
    informational GET's `p` lookup (LUD-25's "Checking a note without
    exposing it"), which also triggers this mint's lazy
    settle-on-first-lookup materialization (see NoteStore.settle_mint) -
    unlike poking NoteStore.note_amount directly, this is what actually
    makes a freshly settled mint invoice become a queryable note."""
    data = client.get(f"/w?p={note_id_hex}").json()
    return data.get("maxWithdrawable")


def test_register_claims_a_username(client: TestClient):
    _, _, cx1 = _branch()
    resp = client.get(f"/register?username=alice&cx1={cx1}")
    assert resp.json() == {"status": "OK"}
    assert notes.username_branch("alice") == bech32m.decode_cx1(cx1).hex()


def test_register_rejects_duplicate_username(client: TestClient):
    _, _, cx1 = _branch()
    assert client.get(f"/register?username=bob&cx1={cx1}").json()["status"] == "OK"
    _, _, cx1_2 = _branch()
    resp = client.get(f"/register?username=bob&cx1={cx1_2}")
    assert resp.json()["status"] == "ERROR"


def test_register_rejects_reserved_username(client: TestClient):
    _, _, cx1 = _branch()
    assert client.get(f"/register?username={settings.username}&cx1={cx1}").json()["status"] == "ERROR"
    assert client.get(f"/register?username=_&cx1={cx1}").json()["status"] == "ERROR"


def test_register_rejects_malformed_cx1(client: TestClient):
    resp = client.get("/register?username=carol&cx1=notbech32m")
    assert resp.json()["status"] == "ERROR"


def test_unregistered_username_404s(client: TestClient):
    resp = client.get("/.well-known/lnurlp/nobody")
    assert resp.json() == {"status": "ERROR", "reason": "Unknown user."}


def test_registered_lnaddress_callback_carries_username(client: TestClient):
    _, _, cx1 = _branch()
    client.get(f"/register?username=dave&cx1={cx1}")
    data = client.get("/.well-known/lnurlp/dave").json()
    assert data["callback"] == "http://testserver/p/cb?username=dave"
    assert data["tag"] == "payRequest"


def test_paying_registered_address_with_no_comment_automints(client: TestClient, node: FakeNode):
    branch_point, chain_code, cx1 = _branch()
    client.get(f"/register?username=erin&cx1={cx1}")

    lnaddress = client.get("/.well-known/lnurlp/erin").json()
    pay_response = client.get(f"{lnaddress['callback']}&amount=5000")
    assert pay_response.json().get("pr"), pay_response.text
    node.settled.add(_payment_hash(node))

    expected_id = derivation.derive_pubkey(branch_point, chain_code, 0).hex()
    assert _note_value(client, expected_id) == 5000


def test_second_automint_payment_uses_the_next_index(client: TestClient, node: FakeNode):
    branch_point, chain_code, cx1 = _branch()
    client.get(f"/register?username=frank&cx1={cx1}")
    lnaddress = client.get("/.well-known/lnurlp/frank").json()

    for _ in range(2):
        pay_response = client.get(f"{lnaddress['callback']}&amount=5000")
        assert pay_response.json().get("pr")
        node.settled.add(_payment_hash(node))

    pk0 = derivation.derive_pubkey(branch_point, chain_code, 0).hex()
    pk1 = derivation.derive_pubkey(branch_point, chain_code, 1).hex()
    assert _note_value(client, pk0) == 5000
    assert _note_value(client, pk1) == 5000


def test_automint_skips_an_index_already_taken_by_a_manual_mint(client: TestClient, node: FakeNode):
    """LUD-25 Seed & derivation's own race-avoidance paragraph: if index 0
    is already outstanding (e.g. a WALLET's own pending rotate got there
    first), the auto-mint path must skip to the next free index rather
    than double-credit or collide."""
    branch_point, chain_code, cx1 = _branch()
    client.get(f"/register?username=grace&cx1={cx1}")

    pk0 = derivation.derive_pubkey(branch_point, chain_code, 0)
    manual = client.get(f"/p/cb?amount=1000&comment={bech32m.encode_cp1(pk0)}")
    assert manual.json().get("pr")
    node.settled.add(_payment_hash(node))
    assert _note_value(client, pk0.hex()) == 1000

    lnaddress = client.get("/.well-known/lnurlp/grace").json()
    pay_response = client.get(f"{lnaddress['callback']}&amount=5000")
    assert pay_response.json().get("pr")
    node.settled.add(_payment_hash(node))

    pk1 = derivation.derive_pubkey(branch_point, chain_code, 1)
    assert _note_value(client, pk1.hex()) == 5000


def test_comment_is_still_honored_for_registered_username(client: TestClient, node: FakeNode):
    """The address owner minting for themselves with a specific key already
    in hand overrides auto-derivation."""
    _, _, cx1 = _branch()
    client.get(f"/register?username=henry&cx1={cx1}")
    sk = PrivateKey()
    cp1 = bech32m.encode_cp1(sk.public_key.format(compressed=True)[1:])

    pay_response = client.get(f"/p/cb?amount=5000&username=henry&comment={cp1}")
    assert pay_response.json().get("pr")
    node.settled.add(_payment_hash(node))
    assert _note_value(client, bech32m.decode_cp1(cp1).hex()) == 5000


def test_username_registration_disabled_404s_register(client: TestClient, monkeypatch):
    monkeypatch.setattr(settings, "username_registration_enabled", False)
    _, _, cx1 = _branch()
    resp = client.get(f"/register?username=iris&cx1={cx1}")
    assert resp.json() == {"status": "ERROR", "reason": "Not found"}


def test_username_registration_disabled_hides_registered_address(client: TestClient, monkeypatch):
    _, _, cx1 = _branch()
    client.get(f"/register?username=jill&cx1={cx1}")
    monkeypatch.setattr(settings, "username_registration_enabled", False)
    resp = client.get("/.well-known/lnurlp/jill")
    assert resp.json() == {"status": "ERROR", "reason": "Unknown user."}
