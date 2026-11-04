"""LUD-26 Lightning Addresses (router.py's POST/PUT/DELETE
/.well-known/lnurlp/{username}): a WALLET registers one of its shares - an
extended public key, cx1 = chain_code || P - at the very address it
claims, and this mint auto-mints a note on the share's next unused key for
every payment there. Every registration, update and unregistration is
proven by a share's own key; a registration is never overwritten, and a
share is never accepted twice."""

import json
from hashlib import sha256
from os import urandom
from pathlib import Path

import bech32 as bech32_pkg
from coincurve import PrivateKey
from fastapi.testclient import TestClient

from lnurl_mint import bech32m, derivation
from lnurl_mint import router as router_module
from lnurl_mint.config import settings
from lnurl_mint.db import NoteStore, notes
from lnurl_mint.signing import verify_register_signature
from tests.conftest import (
    FakeNode,
    address_proof,
    fresh_username,
    make_share,
    register_share,
    settle_polled,
    share_note,
)

VECTORS = Path(__file__).parent / "vectors"


def _address(username: str) -> str:
    return f"/.well-known/lnurlp/{username}"


def _post(client: TestClient, username: str, **form: str) -> dict:
    return client.post(_address(username), data=form).json()


def _put(client: TestClient, username: str, **form: str) -> dict:
    return client.put(_address(username), data=form).json()


def _delete(client: TestClient, username: str, **form: str) -> dict:
    return client.request("DELETE", _address(username), data=form).json()


def _reason(response: dict) -> str:
    assert response["status"] == "ERROR", response
    return response["reason"]


def _npub() -> tuple[bytes, str]:
    """A fresh (pubkey, npub) pair - NIP-19's classic (non-bech32m) bech32."""
    pubkey = PrivateKey().public_key.format(compressed=True)[1:]
    data = bech32_pkg.convertbits(pubkey, 8, 5, True)
    assert data is not None
    return pubkey, bech32_pkg.bech32_encode("npub", data)


def _note_value(client: TestClient, note_id_hex: str) -> int | None:
    """Value of the outstanding note `note_id_hex`, via the informational
    GET's `p` lookup."""
    data = client.get(f"/w?p={bech32m.encode_cp1(bytes.fromhex(note_id_hex))}").json()
    return data.get("maxWithdrawable")


def _net(amount_msat: int) -> int:
    return amount_msat - router_module._mint_fee_msat(amount_msat)


def _pay(client: TestClient, node: FakeNode, username: str, amount_msat: int = 21_000) -> str:
    """Request an invoice from `username`'s address; its payment hash."""
    callback = client.get(_address(username)).json()["callback"]
    resp = client.get(f"{callback}?amount={amount_msat}").json()
    assert resp.get("pr"), resp
    return sha256(node.last_preimage).hexdigest()


# ---- registering ----


def test_register_claims_a_username(client: TestClient):
    name = fresh_username("alice")
    _, cx1 = register_share(client, name)
    share = bech32m.decode_cx1(cx1)
    assert share is not None
    assert notes.username_branch(name) == share.hex()


def test_a_proof_proves_one_action_name_cx1_and_domain_only(client: TestClient):
    """A proof binds the action, the domain (so another mint cannot replay
    it here), the lowercased username and the cx1 being put on file."""
    name = fresh_username("zoe")
    p, cx1 = make_share()
    _, other_cx1 = make_share()
    for sig in [
        address_proof(p, "register", name, cx1, domain="other-mint.example"),
        address_proof(p, "unregister", name),
        address_proof(p, "update", name, cx1),
        address_proof(p, "register", fresh_username("bob"), cx1),
        address_proof(p, "register", name, other_cx1),
        address_proof(PrivateKey(), "register", name, cx1),
        "00" * 64,
        "not hex",
    ]:
        assert _reason(_post(client, name, cx1=cx1, sig=sig)) == "Invalid ownership signature."
    assert notes.username_branch(name) is None


def test_register_needs_a_cx1_and_a_signature(client: TestClient):
    name = fresh_username("amy")
    _, cx1 = make_share()
    assert _reason(_post(client, name, cx1=cx1)) == "Missing sig."
    assert _reason(_post(client, name, sig="00" * 64)) == "Missing cx1."


def test_register_reads_its_parameters_from_the_form_body(client: TestClient):
    """LUD-26 sends them form-encoded, so a browser WALLET's POST needs no
    CORS preflight, and they stay out of a query string a log might keep."""
    name = fresh_username("form")
    p, cx1 = make_share()
    body = f"cx1={cx1}&sig={address_proof(p, 'register', name, cx1)}"
    resp = client.post(_address(name), content=body, headers={"content-type": "application/x-www-form-urlencoded"})
    assert resp.json() == {"status": "OK"}


def test_register_rejects_reserved_and_malformed_usernames(client: TestClient):
    """The mint's own names - its configured username, `_` and always
    `mint`, where LUD-26 has a WALLET find the mint payRequest - and any
    name with a `+`, which is a tag of another address."""
    for name in [settings.username, "_", "mint", "MINT", "a+b", "x" * 33]:
        p, cx1 = make_share()
        resp = _post(client, name, cx1=cx1, sig=address_proof(p, "register", name.lower(), cx1))
        assert _reason(resp) == "Invalid or reserved username.", name


def test_register_rejects_a_malformed_or_superseded_cx1(client: TestClient):
    name = fresh_username("cy")
    p = PrivateKey()
    point = p.public_key.format(compressed=True)
    for cx1 in [
        "notacx1",
        bech32m.encode_cp1(point[1:]),
        # the 64-byte x(P) || chain_code from before LUD-26
        bech32m.encode_legacy_cx1(point[1:] + urandom(32)),
        # a 65-byte payload whose P is no compressed point
        bech32m.encode_cx1(urandom(32) + b"\x04" + point[1:]),
    ]:
        resp = _post(client, name, cx1=cx1, sig=address_proof(p, "register", name, cx1))
        assert _reason(resp) == "Invalid cx1.", cx1


def test_registration_lowercases_a_mixed_case_username(client: TestClient):
    name = fresh_username("mixed")
    p, cx1 = make_share()
    resp = _post(client, name.upper(), cx1=cx1, sig=address_proof(p, "register", name, cx1))
    assert resp == {"status": "OK"}
    assert notes.username_branch(name) is not None


def test_a_registration_is_never_overwritten(client: TestClient):
    name = fresh_username("once")
    _, cx1 = register_share(client, name)
    p2, cx1_2 = make_share()
    for queried in [name, name.upper()]:
        resp = _post(client, queried, cx1=cx1_2, sig=address_proof(p2, "register", name, cx1_2))
        assert _reason(resp) == "already registered"
    share = bech32m.decode_cx1(cx1)
    assert share is not None
    assert notes.username_branch(name) == share.hex()


def test_a_share_registered_once_is_refused_under_another_name(client: TestClient):
    name, other = fresh_username("first"), fresh_username("second")
    p, cx1 = make_share()
    assert _post(client, name, cx1=cx1, sig=address_proof(p, "register", name, cx1)) == {"status": "OK"}
    resp = _post(client, other, cx1=cx1, sig=address_proof(p, "register", other, cx1))
    assert _reason(resp) == "cx1 already used"


# ---- NIP-05 ----


def test_register_with_npub_serves_nip05(client: TestClient):
    name = fresh_username("nip")
    pubkey, npub = _npub()
    p, cx1 = make_share()
    assert _post(client, name, cx1=cx1, sig=address_proof(p, "register", name, cx1), npub=npub) == {"status": "OK"}
    assert client.get(f"/.well-known/nostr.json?name={name}").json() == {"names": {name: pubkey.hex()}}
    # case-insensitive, but the queried name is echoed back
    upper = name.upper()
    assert client.get(f"/.well-known/nostr.json?name={upper}").json() == {"names": {upper: pubkey.hex()}}


def test_register_without_npub_has_no_nip05_name(client: TestClient):
    name = fresh_username("nonip")
    register_share(client, name)
    assert client.get(f"/.well-known/nostr.json?name={name}").json() == {"names": {}}
    assert client.get("/.well-known/nostr.json").json() == {"names": {}}


def test_register_rejects_a_malformed_npub(client: TestClient):
    name = fresh_username("badnpub")
    p, cx1 = make_share()
    resp = _post(client, name, cx1=cx1, sig=address_proof(p, "register", name, cx1), npub="npub1nope")
    assert _reason(resp) == "Invalid npub."


def test_npub_registration_follows_the_nip05_switch(client: TestClient, monkeypatch):
    monkeypatch.setattr(settings, "nip05_enabled", False)
    name = fresh_username("off")
    p, cx1 = make_share()
    _, npub = _npub()
    resp = _post(client, name, cx1=cx1, sig=address_proof(p, "register", name, cx1), npub=npub)
    assert _reason(resp) == "npub registration (NIP-05) is disabled on this mint."
    # without one it still registers, and the endpoint itself is gone
    assert _post(client, name, cx1=cx1, sig=address_proof(p, "register", name, cx1)) == {"status": "OK"}
    assert _reason(client.get(f"/.well-known/nostr.json?name={name}").json()) == "Not found"


def test_registration_disabled_hides_everything(client: TestClient, monkeypatch):
    name = fresh_username("hidden")
    _, npub = _npub()
    p, cx1 = make_share()
    assert _post(client, name, cx1=cx1, sig=address_proof(p, "register", name, cx1), npub=npub) == {"status": "OK"}
    monkeypatch.setattr(settings, "username_registration_enabled", False)
    assert _reason(client.get(_address(name)).json()) == "unknown user"
    assert client.get(f"/.well-known/nostr.json?name={name}").json() == {"names": {}}
    assert _reason(_post(client, fresh_username("new"), cx1=cx1, sig="00" * 64)) == "Not found"
    assert _reason(_delete(client, name, sig="00" * 64)) == "Not found"


# ---- the address ----


def test_a_registered_address_is_an_ordinary_lightning_address(client: TestClient):
    """No comment (it could never reach the holder), no key of the share
    (LUD-26 dropped text/cpub), the same withdrawLink and fees as the mint,
    and a +tag lands on the same share."""
    name = fresh_username("addr")
    _, cx1 = register_share(client, name)
    for queried in [name, name.upper(), f"{name}+coffee"]:
        resp = client.get(_address(queried)).json()
        assert resp["callback"] == f"http://testserver/p/{name}", queried
        assert resp["withdrawLink"] == "http://testserver/w"
        assert resp.get("commentAllowed") is None
        assert "text/cpub" not in resp["metadata"] and cx1 not in resp["metadata"]
        metadata = json.loads(resp["metadata"])
        assert ["text/identifier", f"{name}@testserver"] in metadata


def test_mint_is_always_the_mints_own_address(client: TestClient):
    resp = client.get(_address("mint")).json()
    assert resp["callback"] == "http://testserver/p/cb"
    assert resp["commentAllowed"] == 64


def test_an_unregistered_username_is_unknown(client: TestClient):
    assert _reason(client.get(_address(fresh_username("nobody"))).json()) == "unknown user"


# ---- update ----


def test_a_put_moves_the_address_to_a_new_share(client: TestClient, node: FakeNode):
    name = fresh_username("mover")
    p0, cx1_0 = register_share(client, name)
    p1, cx1_1 = make_share()
    newsig = address_proof(p1, "register", name, cx1_1)

    # the key on file must sign the update, over the new cx1
    for sig in [
        address_proof(p1, "update", name, cx1_1),
        address_proof(p0, "update", name, make_share()[1]),
        address_proof(p0, "register", name, cx1_1),
    ]:
        assert _reason(_put(client, name, cx1=cx1_1, sig=sig, newsig=newsig)) == "Invalid ownership signature."
    sig = address_proof(p0, "update", name, cx1_1)
    # and the new share its own register message
    assert _reason(_put(client, name, cx1=cx1_1, sig=sig, newsig=sig)) == "Invalid ownership signature."
    assert _put(client, name, cx1=cx1_1, sig=sig, newsig=newsig) == {"status": "OK"}
    share = bech32m.decode_cx1(cx1_1)
    assert share is not None
    assert notes.username_branch(name) == share.hex()

    # auto-mint now lands on the new share, from its index 0
    payment_hash = _pay(client, node, name)
    settle_polled(node, payment_hash)
    assert _note_value(client, share_note(cx1_1, 0)) == _net(21_000)
    assert _note_value(client, share_note(cx1_0, 0)) is None

    # the old share is never accepted again
    other = fresh_username("taker")
    resp = _post(client, other, cx1=cx1_0, sig=address_proof(p0, "register", other, cx1_0))
    assert _reason(resp) == "cx1 already used"


def test_a_put_for_an_unregistered_username_is_unknown(client: TestClient):
    name = fresh_username("ghost")
    p, cx1 = make_share()
    resp = _put(
        client,
        name,
        cx1=cx1,
        sig=address_proof(p, "update", name, cx1),
        newsig=address_proof(p, "register", name, cx1),
    )
    assert _reason(resp) == "unknown user"


def test_a_put_never_moves_to_a_share_accepted_before(client: TestClient):
    first, second = fresh_username("one"), fresh_username("two")
    p0, _ = register_share(client, first)
    p1, cx1_1 = register_share(client, second)
    resp = _put(
        client,
        first,
        cx1=cx1_1,
        sig=address_proof(p0, "update", first, cx1_1),
        newsig=address_proof(p1, "register", first, cx1_1),
    )
    assert _reason(resp) == "cx1 already used"


# ---- unregister ----


def test_delete_with_the_key_on_file_frees_the_username(client: TestClient):
    name = fresh_username("bye")
    p, cx1 = register_share(client, name)
    for sig in [address_proof(PrivateKey(), "unregister", name), address_proof(p, "register", name, cx1)]:
        assert _reason(_delete(client, name, sig=sig)) == "Invalid ownership signature."
    assert _reason(_delete(client, name)) == "Missing sig."
    assert _delete(client, name, sig=address_proof(p, "unregister", name)) == {"status": "OK"}
    assert _reason(client.get(_address(name)).json()) == "unknown user"
    # free for a fresh share, never for the old one
    assert _reason(_post(client, name, cx1=cx1, sig=address_proof(p, "register", name, cx1))) == "cx1 already used"
    register_share(client, name)


def test_delete_of_an_unregistered_username_is_unknown(client: TestClient):
    assert _reason(_delete(client, fresh_username("none"), sig="00" * 64)) == "unknown user"


# ---- auto-mint ----


def test_an_address_payment_credits_the_shares_next_note_when_it_settles(client: TestClient, node: FakeNode):
    """LUD-26's Crediting: the note is picked when the payment settles,
    never when the invoice is issued, so unpaid invoices leave no unused
    index behind - here the second invoice, paid first, takes index 0."""
    name = fresh_username("erin")
    _, cx1 = register_share(client, name)
    first = _pay(client, node, name, 21_000)
    second = _pay(client, node, name, 30_000)
    # nothing is named, let alone credited, before a payment settles
    assert _note_value(client, share_note(cx1, 0)) is None
    settle_polled(node, second)
    assert _note_value(client, share_note(cx1, 0)) == _net(30_000)
    settle_polled(node, first)
    assert _note_value(client, share_note(cx1, 1)) == _net(21_000)
    # settling again credits nothing more
    settle_polled(node, first)
    assert _note_value(client, share_note(cx1, 2)) is None


def test_auto_mint_skips_a_share_note_somebody_already_holds(client: TestClient, node: FakeNode):
    name = fresh_username("skip")
    _, cx1 = register_share(client, name)
    # a note minted the ordinary way onto the share's index 0
    taken = bech32m.encode_cp1(bytes.fromhex(share_note(cx1, 0)))
    assert client.get(f"/p/cb?amount=21000&comment={taken}").json().get("pr")
    node.settled.add(sha256(node.last_preimage).hexdigest())
    assert _note_value(client, share_note(cx1, 0)) == _net(21_000)

    payment_hash = _pay(client, node, name, 30_000)
    settle_polled(node, payment_hash)
    assert _note_value(client, share_note(cx1, 1)) == _net(30_000)


def test_a_comment_is_ignored_for_a_registered_address(client: TestClient, node: FakeNode):
    """It names no output there: the payment always lands on the share."""
    name = fresh_username("nocomment")
    _, cx1 = register_share(client, name)
    _, decoy = make_share()
    decoy_note = bech32m.encode_cp1(bytes.fromhex(share_note(decoy, 0)))
    resp = client.get(f"/p/{name.upper()}?amount=21000&comment={decoy_note}").json()
    assert resp.get("pr"), resp
    settle_polled(node, sha256(node.last_preimage).hexdigest())
    assert _note_value(client, share_note(cx1, 0)) == _net(21_000)
    assert _note_value(client, share_note(decoy, 0)) is None


def test_verify_settles_an_address_mint_too(client: TestClient, node: FakeNode, monkeypatch):
    """LUD-21: an address mint's preimage redeems nothing, so verify is
    offered, and asking it settles the mint as the poll does."""
    monkeypatch.setattr(settings, "verify_enabled", True)
    name = fresh_username("verify")
    _, cx1 = register_share(client, name)
    payment_hash = _pay(client, node, name)
    node.settled.add(payment_hash)
    assert client.get(f"/verify/{payment_hash}").json()["settled"] is True
    assert _note_value(client, share_note(cx1, 0)) == _net(21_000)


# ---- internal transfer ----


def test_an_internal_transfer_credits_the_payees_next_note(client: TestClient, mint_note):
    """LUD-26: a payer holding a note on this mint sends the note itself to
    the address's callback. Its full value lands, free of fees, on the
    share's next unused note, which the payer never learns."""
    name = fresh_username("ivan")
    _, cx1 = register_share(client, name)
    k1 = mint_note(20_000)
    value = client.get(f"/w?k1={k1}").json()["maxWithdrawable"]

    # the whole note, never part of it
    part = client.get(f"/p/{name}?amount={value - 1000}&k1={k1}").json()
    assert "full value" in _reason(part)
    uri = f"/p/{name}+tip?amount={value}&k1={k1}"
    assert client.get(uri).json() == {"status": "OK"}
    assert _note_value(client, share_note(cx1, 0)) == value
    assert _reason(client.get(f"/w?k1={k1}").json()) == "already in use"
    # a retry is answered as the first and credits nothing more
    assert client.get(uri).json() == {"status": "OK"}
    assert _note_value(client, share_note(cx1, 1)) is None


def test_an_internal_transfer_needs_a_registered_address(client: TestClient, mint_note):
    k1 = mint_note(20_000)
    value = client.get(f"/w?k1={k1}").json()["maxWithdrawable"]
    for name in [fresh_username("nobody"), "mint"]:
        assert _reason(client.get(f"/p/{name}?amount={value}&k1={k1}").json()) == "unknown user"
    assert client.get(f"/w?k1={k1}").json()["maxWithdrawable"] == value


def test_an_internal_transfer_stays_within_the_addresses_range(client: TestClient, mint_note):
    name = fresh_username("small")
    register_share(client, name)
    k1 = mint_note(20_000)
    for amount in [router_module._min_sendable_msat() - 1, settings.max_sendable_msat + 1]:
        resp = client.get(f"/p/{name}?amount={amount}&k1={k1}").json()
        assert _reason(resp) == "Amount outside what this address accepts."


# ---- registered before LUD-26 ----


def test_a_pre_lud26_address_keeps_working_until_it_is_moved(client: TestClient, node: FakeNode, mint_note):
    """A username registered before LUD-26 holds the superseded 64-byte cx1
    = x(P) || chain_code. It keeps auto-minting under the old purpose-2
    tweak, so it does not stop working the day this mint upgrades, and its
    owner moves it to a share with an update signed by the old branch key."""
    name = fresh_username("legacy")
    branch_key = PrivateKey()
    point, chain_code = branch_key.public_key.format(compressed=True)[1:], urandom(32)
    notes.register_username(name, (point + chain_code).hex(), point.hex())

    payment_hash = _pay(client, node, name)
    settle_polled(node, payment_hash)
    old_note = derivation.legacy_derive_pubkey(point, chain_code, derivation.PURPOSE_LIGHTNING_ADDRESS, 0)
    assert _note_value(client, old_note.hex()) == _net(21_000)

    p1, cx1_1 = make_share()
    resp = _put(
        client,
        name,
        cx1=cx1_1,
        sig=address_proof(branch_key, "update", name, cx1_1),
        newsig=address_proof(p1, "register", name, cx1_1),
    )
    assert resp == {"status": "OK"}
    k1 = mint_note(20_000)
    value = client.get(f"/w?k1={k1}").json()["maxWithdrawable"]
    assert client.get(f"/p/{name}?amount={value}&k1={k1}").json() == {"status": "OK"}
    assert _note_value(client, share_note(cx1_1, 0)) == value


def test_shares_on_file_are_accepted_keys_once_the_store_opens(tmp_path):
    """Every share registered before accepted_keys existed is in it, in
    either cx1 shape, so none is registered a second time."""
    path = str(tmp_path / "old.db")
    store = NoteStore(path)
    legacy = (b"\xaa" * 32 + b"\xcc" * 32).hex()
    current = (b"\xcc" * 32 + b"\x02" + b"\xbb" * 32).hex()
    store.conn.execute("DROP TABLE accepted_keys")
    store.conn.execute("INSERT INTO usernames (username, cx1) VALUES ('old', ?), ('new', ?)", (legacy, current))
    store.conn.commit()
    reopened = NoteStore(path)
    for xp in ["aa" * 32, "bb" * 32]:
        try:
            reopened.register_username(fresh_username("carol"), "ff", xp)
        except ValueError as exc:
            assert str(exc) == "cx1 already used"
        else:
            raise AssertionError(f"{xp} was accepted twice")


# ---- the spec's own vectors ----


def test_registration_proofs_match_the_lud26_vectors():
    """lnurl/luds 26-vectors.json: register account 0 share 0, update to
    share 1, unregister with share 1 - each verified against its share's
    x(P), and against no other."""
    registration = json.loads((VECTORS / "26-vectors.json").read_text())["registration"]
    domain, username = registration["domain"], registration["username"]
    old, new = (bech32m.decode_cx1(registration[key]) for key in ("cx1", "new_cx1"))
    assert old is not None and new is not None
    for proof, action, cx1, signer in [
        (registration["register"], "register", registration["cx1"], old[33:]),
        (registration["update"]["sig"], "update", registration["new_cx1"], old[33:]),
        (registration["update"]["newsig"], "register", registration["new_cx1"], new[33:]),
        (registration["unregister"], "unregister", None, new[33:]),
    ]:
        assert sha256(proof["message"].encode()).hexdigest() == proof["digest"]
        assert verify_register_signature(signer, proof["sig"], action, domain, username, cx1), action
        other = new[33:] if signer == old[33:] else old[33:]
        assert not verify_register_signature(other, proof["sig"], action, domain, username, cx1), action
