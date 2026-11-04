"""LUD-26's address fee (ADDRESS_FEE_MSAT): a registration is answered with
an invoice and its username held until that is paid - over Lightning, or
by melting a note here - and released if it expires unpaid. Advertised as
the third `Mint fees` value on the mint's own payRequest."""

import asyncio
import json
import os
from hashlib import sha256

import bolt11
import pytest
from fastapi.testclient import TestClient

from lnurl_mint import router as router_module
from lnurl_mint.config import Settings, settings
from lnurl_mint.db import notes
from tests.conftest import FakeNode, address_proof, fake_invoice, fresh_username, k1_id, make_share

FEE = 21_000


@pytest.fixture
def address_fee(monkeypatch: pytest.MonkeyPatch) -> int:
    monkeypatch.setattr(settings, "address_fee_msat", FEE)
    return FEE


def _register(client: TestClient, username: str) -> dict:
    p, cx1 = make_share()
    sig = address_proof(p, "register", username, cx1)
    return client.post(f"/.well-known/lnurlp/{username}", data={"cx1": cx1, "sig": sig}).json()


def _hash(pr: str) -> str:
    return bolt11.decode(pr).payment_hash


def _fees_entry(client: TestClient, username: str) -> str | None:
    metadata = json.loads(client.get(f"/.well-known/lnurlp/{username}").json()["metadata"])
    entries = [text for kind, text in metadata if kind == "text/plain" and text.startswith("Mint fees: ")]
    return entries[0] if entries else None


def _published(client: TestClient, username: str) -> bool:
    return client.get(f"/.well-known/lnurlp/{username}").json().get("status") != "ERROR"


# ---- configuration ----


def test_fee_ppm_still_reads_its_old_name(monkeypatch: pytest.MonkeyPatch):
    """FEE_PERCENT_PPM, from before the rename, must not silently become 0."""
    monkeypatch.delenv("FEE_PPM", raising=False)
    monkeypatch.setenv("FEE_PERCENT_PPM", "2000")
    assert Settings().fee_ppm == 2000
    monkeypatch.setenv("FEE_PPM", "3000")
    assert Settings().fee_ppm == 3000


def test_address_fee_is_never_negative():
    with pytest.raises(ValueError):
        Settings(address_fee_msat=-1)


# ---- advertising ----


def test_mint_payrequest_advertises_the_address_fee_as_a_third_value(client: TestClient, address_fee, monkeypatch):
    monkeypatch.setattr(settings, "base_fee_msat", 1000)
    monkeypatch.setattr(settings, "fee_ppm", 10)
    assert _fees_entry(client, "mint") == f"Mint fees: 1000,10,{FEE}"
    assert _fees_entry(client, "_") == f"Mint fees: 1000,10,{FEE}"


def test_an_address_fee_alone_is_still_advertised(client: TestClient, address_fee):
    assert _fees_entry(client, "mint") == f"Mint fees: 0,0,{FEE}"


def test_a_registered_address_carries_no_address_fee(client: TestClient, node: FakeNode, address_fee, monkeypatch):
    """Only the mint's own payRequest - a registered address only mints."""
    name = fresh_username("adv")
    resp = _register(client, name)
    node.settled.add(_hash(resp["pr"]))
    asyncio.run(router_module.settle_polled_mints())
    assert _fees_entry(client, name) is None
    monkeypatch.setattr(settings, "base_fee_msat", 1000)
    assert _fees_entry(client, name) == "Mint fees: 1000,0"


def test_no_address_fee_while_registration_is_off(client: TestClient, address_fee, monkeypatch):
    monkeypatch.setattr(settings, "username_registration_enabled", False)
    assert _fees_entry(client, "mint") is None


def test_without_an_address_fee_registering_stays_free(client: TestClient):
    assert _register(client, fresh_username("free")) == {"status": "OK"}
    assert _fees_entry(client, "mint") is None


# ---- holding and settling ----


def test_registration_answers_an_invoice_and_holds_the_username(client: TestClient, node: FakeNode, address_fee):
    name = fresh_username("held")
    resp = _register(client, name)
    assert resp["status"] == "OK"
    assert bolt11.decode(resp["pr"]).amount_msat == FEE
    # held: not published, no auto-mint, no internal transfer
    assert not _published(client, name)
    assert client.get(f"/p/{name}?amount=21000").json()["reason"] == "unknown user"
    assert notes.username_branch(name) is None
    # and nobody else can take it meanwhile
    assert _register(client, name) == {"status": "ERROR", "reason": "already registered"}


def test_the_fee_invoice_and_its_hold_expire_in_an_hour(client: TestClient, node: FakeNode, address_fee):
    resp = _register(client, fresh_username("hour"))
    payment_hash = _hash(resp["pr"])
    assert node.expiries[payment_hash] == 3600
    decoded = bolt11.decode(resp["pr"])
    assert decoded.expiry == 3600
    assert notes.address_fee(payment_hash)[3] == decoded.date + 3600


def test_a_mint_invoice_keeps_the_backend_default_expiry(client: TestClient, node: FakeNode, mint_note):
    mint_note(5000)
    assert node.expiries[sha256(node.last_preimage).hexdigest()] is None


def test_paying_the_fee_registers_the_username(client: TestClient, node: FakeNode, address_fee):
    name = fresh_username("paid")
    resp = _register(client, name)
    node.settled.add(_hash(resp["pr"]))
    asyncio.run(router_module.settle_polled_mints())
    assert notes.username_branch(name) is not None
    assert _published(client, name)
    assert _register(client, name) == {"status": "ERROR", "reason": "already registered"}


def test_looking_up_a_held_address_settles_a_fee_the_poll_no_longer_asks_about(
    client: TestClient, node: FakeNode, address_fee
):
    name = fresh_username("late")
    resp = _register(client, name)
    payment_hash = _hash(resp["pr"])
    with notes._lock, notes.conn:
        notes.conn.execute("UPDATE address_fees SET created_at = 0 WHERE payment_hash = ?", (payment_hash,))
    node.settled.add(payment_hash)
    asyncio.run(router_module.settle_polled_mints())
    assert notes.username_branch(name) is None  # outside the poll window
    assert _published(client, name)
    assert notes.username_branch(name) is not None


def test_an_expired_hold_releases_the_username(client: TestClient, node: FakeNode, address_fee):
    name = fresh_username("lapse")
    first = _register(client, name)
    with notes._lock, notes.conn:
        notes.conn.execute("UPDATE address_fees SET expires_at = 1 WHERE payment_hash = ?", (_hash(first["pr"]),))
    second = _register(client, name)
    assert second["status"] == "OK" and second["pr"] != first["pr"]
    node.settled.add(_hash(second["pr"]))
    asyncio.run(router_module.settle_polled_mints())
    registered = notes.username_branch(name)
    # the lapsed invoice paid late anyway: kept, but never overwrites
    node.settled.add(_hash(first["pr"]))
    assert notes.settle_address_fee(_hash(first["pr"])) == (name, False)
    assert notes.username_branch(name) == registered


def test_a_held_share_is_never_accepted_again(client: TestClient, node: FakeNode, address_fee):
    """The share key is taken at hold time, so a captured proof never
    applies again even after its invoice lapses unpaid."""
    name = fresh_username("once")
    p, cx1 = make_share()
    sig = address_proof(p, "register", name, cx1)
    first = client.post(f"/.well-known/lnurlp/{name}", data={"cx1": cx1, "sig": sig}).json()
    with notes._lock, notes.conn:
        notes.conn.execute("UPDATE address_fees SET expires_at = 1 WHERE payment_hash = ?", (_hash(first["pr"]),))
    again = client.post(f"/.well-known/lnurlp/{name}", data={"cx1": cx1, "sig": sig}).json()
    assert again == {"status": "ERROR", "reason": "cx1 already used"}


def test_an_update_charges_no_address_fee(client: TestClient, node: FakeNode, address_fee):
    name = fresh_username("move")
    p, cx1 = make_share()
    resp = client.post(
        f"/.well-known/lnurlp/{name}", data={"cx1": cx1, "sig": address_proof(p, "register", name, cx1)}
    ).json()
    node.settled.add(_hash(resp["pr"]))
    asyncio.run(router_module.settle_polled_mints())
    q, new_cx1 = make_share()
    moved = client.put(
        f"/.well-known/lnurlp/{name}",
        data={
            "cx1": new_cx1,
            "sig": address_proof(p, "update", name, new_cx1),
            "newsig": address_proof(q, "register", name, new_cx1),
        },
    ).json()
    assert moved == {"status": "OK"}


def test_verify_reports_an_address_fee(client: TestClient, node: FakeNode, address_fee, monkeypatch):
    monkeypatch.setattr(settings, "verify_enabled", True)
    resp = _register(client, fresh_username("ver"))
    payment_hash = _hash(resp["pr"])
    assert client.get(f"/verify/{payment_hash}").json() == {"status": "OK", "settled": False, "pr": resp["pr"]}
    node.settled.add(payment_hash)
    data = client.get(f"/verify/{payment_hash}").json()
    assert data["settled"] is True
    assert sha256(bytes.fromhex(data["preimage"])).hexdigest() == payment_hash


# ---- melting a note into the fee ----


def test_melting_a_note_into_the_fee_registers_without_routing(
    client: TestClient, node: FakeNode, mint_note, address_fee
):
    name = fresh_username("melt")
    resp = _register(client, name)
    k1 = mint_note(FEE)
    assert client.get(f"/w/cb?k1={k1}&pr={resp['pr']}").json() == {"status": "OK"}
    assert node.paid == []
    assert notes.note_spent(k1_id(k1))
    assert notes.username_branch(name) is not None
    # paid: a second note melted into it is refused, and survives
    other = mint_note(FEE)
    assert client.get(f"/w/cb?k1={other}&pr={resp['pr']}").json()["status"] == "ERROR"
    assert notes.note_amount(k1_id(other)) == FEE


def test_melting_into_an_expired_fee_burns_nothing(client: TestClient, node: FakeNode, mint_note, address_fee):
    name = fresh_username("gone")
    resp = _register(client, name)
    with notes._lock, notes.conn:
        notes.conn.execute("UPDATE address_fees SET expires_at = 1 WHERE payment_hash = ?", (_hash(resp["pr"]),))
    k1 = mint_note(FEE)
    data = client.get(f"/w/cb?k1={k1}&pr={resp['pr']}").json()
    assert data == {"status": "ERROR", "reason": "This address fee invoice is no longer payable."}
    assert notes.note_amount(k1_id(k1)) == FEE
    assert notes.username_branch(name) is None
    assert node.paid == []


def test_melting_into_a_fee_whose_username_was_taken_burns_nothing(
    client: TestClient, node: FakeNode, mint_note, address_fee
):
    name = fresh_username("race")
    first = _register(client, name)
    with notes._lock, notes.conn:
        notes.conn.execute("UPDATE address_fees SET expires_at = 1 WHERE payment_hash = ?", (_hash(first["pr"]),))
    second = _register(client, name)
    node.settled.add(_hash(second["pr"]))
    asyncio.run(router_module.settle_polled_mints())
    # the first hold's invoice is expired now, but make it look payable to
    # reach the taken-username guard itself
    with notes._lock, notes.conn:
        notes.conn.execute(
            "UPDATE address_fees SET expires_at = 4102444800 WHERE payment_hash = ?", (_hash(first["pr"]),)
        )
    k1 = mint_note(FEE)
    assert client.get(f"/w/cb?k1={k1}&pr={first['pr']}").json() == {"status": "ERROR", "reason": "already registered"}
    assert notes.note_amount(k1_id(k1)) == FEE
    assert notes.address_fee(_hash(first["pr"]))[4] is False  # rolled back with it


def test_melting_a_wrong_amount_into_the_fee_is_refused(client: TestClient, node: FakeNode, mint_note, address_fee):
    resp = _register(client, fresh_username("amt"))
    k1 = mint_note(FEE + 1000)
    assert client.get(f"/w/cb?k1={k1}&pr={resp['pr']}").json()["status"] == "ERROR"
    assert notes.note_amount(k1_id(k1)) == FEE + 1000


def test_a_forged_invoice_under_the_fee_hash_is_never_paid(client: TestClient, node: FakeNode, mint_note, address_fee):
    """Another invoice reusing the fee's payment hash is neither settled
    here nor routed back to this mint's own node."""
    name = fresh_username("forge")
    resp = _register(client, name)
    forged = fake_invoice(FEE, _hash(resp["pr"]))
    k1 = mint_note(FEE)
    assert client.get(f"/w/cb?k1={k1}&pr={forged}").json()["status"] == "ERROR"
    assert node.paid == []
    assert notes.note_amount(k1_id(k1)) == FEE
    assert notes.username_branch(name) is None


@pytest.fixture(autouse=True)
def _no_stale_env(monkeypatch: pytest.MonkeyPatch):
    for name in ("FEE_PPM", "FEE_PERCENT_PPM", "ADDRESS_FEE_MSAT"):
        if name in os.environ:
            monkeypatch.delenv(name)
