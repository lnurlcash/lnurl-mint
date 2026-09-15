"""LUD-25 Part 2, Seed & derivation's cx1 registration (router.py's
POST/DELETE /p/{username}): a WALLET claims a Lightning Address username
against its own watch-only branch, and this mint auto-mints cp1 notes off
it directly. Overwriting or deleting an existing claim needs an
ownership-proof signature over the branch's own index-0 secret."""

from hashlib import sha256
from os import urandom

import bech32 as bech32_pkg
from coincurve import PrivateKey
from fastapi.testclient import TestClient

from lnurl_mint import bech32m, derivation
from lnurl_mint.config import settings
from lnurl_mint.db import notes
from lnurl_mint.signing import lightning_signed_message_digest
from tests.conftest import FakeNode

# secp256k1 group order - needed to mirror derive_pubkey's BIP-340 x-only
# tweak on the PRIVATE key side (see _ownership_sig).
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def _branch() -> tuple[PrivateKey, bytes, bytes, str]:
    """A fresh (p, P, chain_code, cx1) - a WALLET's watch-only branch
    export, standing in for a real BIP32 seed derivation without needing
    one (see derivation.derive_pubkey, which only needs a valid x-only P,
    not how it was produced). `p`, the private scalar behind P, is kept
    too - _ownership_sig needs it to derive the branch's own index-0
    secret."""
    p = PrivateKey()
    branch_point = p.public_key.format(compressed=True)[1:]
    chain_code = urandom(32)
    return p, branch_point, chain_code, bech32m.encode_cx1(branch_point + chain_code)


def _ownership_sig(p: PrivateKey, branch_point: bytes, chain_code: bytes, action: str, username: str) -> str:
    """A valid ownership-proof signature (router._owns_branch) for the
    branch (branch_point, chain_code): derive_pubkey tweaks the PUBLIC key
    assuming the even-y (lift_x) representation of `branch_point`, so the
    private-key side must first negate `p`'s scalar whenever `p`'s own
    full pubkey has odd y (PublicKeyXOnly always represents the even-y
    point), then add the same tweak - this recovers sk_0, the branch's
    own index-0 secret. Signed over
    "LNURLcash:<action>:<username>" (25.md's Seed & derivation; a
    different message than a note's own ck1 - see signing.py),
    recoverable. `action` is "register" (an overwrite, matching
    upsert_registered_username) or "unregister" (matching
    delete_registered_username) - the two are never interchangeable."""
    d = p.to_int()
    if p.public_key.format(compressed=True)[0] == 0x03:
        d = _N - d
    tweak = int.from_bytes(
        derivation.tagged_hash(b"LNURLcash/derive", branch_point + chain_code + (0).to_bytes(4, "big")), "big"
    )
    sk0 = PrivateKey.from_int((d + tweak) % _N)
    digest = lightning_signed_message_digest(f"LNURLcash:{action}:{username}")
    return sk0.sign_recoverable(digest, hasher=None).hex()


def _npub() -> tuple[bytes, str]:
    """A fresh (pubkey, npub) pair - NIP-19's classic (non-bech32m) bech32
    encoding, built straight off the `bech32` package rather than
    lnurl_mint.bech32m (whose encode() is bech32m-only, wrong checksum for
    an npub - see bech32m.decode_npub)."""
    pubkey = PrivateKey().public_key.format(compressed=True)[1:]
    data = bech32_pkg.convertbits(pubkey, 8, 5, True)
    assert data is not None
    return pubkey, bech32_pkg.bech32_encode("npub", data)


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
    _, _, _, cx1 = _branch()
    resp = client.post(f"/p/alice?cx1={cx1}")
    assert resp.json() == {"status": "OK"}
    assert notes.username_branch("alice") == bech32m.decode_cx1(cx1).hex()


def test_overwrite_without_ownership_proof_rejected(client: TestClient):
    _, _, _, cx1 = _branch()
    assert client.post(f"/p/bob?cx1={cx1}").json()["status"] == "OK"
    _, _, _, cx1_2 = _branch()
    resp = client.post(f"/p/bob?cx1={cx1_2}")
    assert resp.json()["status"] == "ERROR"
    # rejected outright: the original branch is untouched
    assert notes.username_branch("bob") == bech32m.decode_cx1(cx1).hex()


def test_overwrite_with_wrong_signature_rejected(client: TestClient):
    p, branch_point, chain_code, cx1 = _branch()
    client.post(f"/p/carol?cx1={cx1}")
    wrong_p, _, _, _ = _branch()
    sig = _ownership_sig(wrong_p, wrong_p.public_key.format(compressed=True)[1:], urandom(32), "register", "carol")
    _, _, _, cx1_2 = _branch()
    resp = client.post(f"/p/carol?cx1={cx1_2}&sig={sig}")
    assert resp.json()["status"] == "ERROR"
    assert notes.username_branch("carol") == bech32m.decode_cx1(cx1).hex()


def test_overwrite_with_valid_ownership_proof_replaces_the_branch(client: TestClient):
    p, branch_point, chain_code, cx1 = _branch()
    client.post(f"/p/dana?cx1={cx1}")
    sig = _ownership_sig(p, branch_point, chain_code, "register", "dana")
    _, _, _, cx1_2 = _branch()
    resp = client.post(f"/p/dana?cx1={cx1_2}&sig={sig}")
    assert resp.json() == {"status": "OK"}
    assert notes.username_branch("dana") == bech32m.decode_cx1(cx1_2).hex()


def test_overwrite_omitting_npub_clears_it(client: TestClient):
    p, branch_point, chain_code, cx1 = _branch()
    _, npub = _npub()
    client.post(f"/p/edna?cx1={cx1}&npub={npub}")
    assert client.get("/.well-known/nostr.json?name=edna").json()["names"]

    sig = _ownership_sig(p, branch_point, chain_code, "register", "edna")
    resp = client.post(f"/p/edna?cx1={cx1}&sig={sig}")
    assert resp.json() == {"status": "OK"}
    assert client.get("/.well-known/nostr.json?name=edna").json() == {"names": {}}


def test_register_rejects_reserved_username(client: TestClient):
    _, _, _, cx1 = _branch()
    assert client.post(f"/p/{settings.username}?cx1={cx1}").json()["status"] == "ERROR"
    assert client.post(f"/p/_?cx1={cx1}").json()["status"] == "ERROR"


def test_register_rejects_malformed_cx1(client: TestClient):
    resp = client.post("/p/finn?cx1=notbech32m")
    assert resp.json()["status"] == "ERROR"


def test_register_with_npub_serves_nip05(client: TestClient):
    _, _, _, cx1 = _branch()
    pubkey, npub = _npub()
    resp = client.post(f"/p/mallory?cx1={cx1}&npub={npub}")
    assert resp.json() == {"status": "OK"}

    nip05 = client.get("/.well-known/nostr.json?name=mallory").json()
    assert nip05 == {"names": {"mallory": pubkey.hex()}}


def test_register_without_npub_has_no_nip05_name(client: TestClient):
    _, _, _, cx1 = _branch()
    client.post(f"/p/nora?cx1={cx1}")
    nip05 = client.get("/.well-known/nostr.json?name=nora").json()
    assert nip05 == {"names": {}}


def test_register_rejects_malformed_npub(client: TestClient):
    _, _, _, cx1 = _branch()
    resp = client.post(f"/p/oscarnpub?cx1={cx1}&npub=notanpub")
    assert resp.json()["status"] == "ERROR"
    assert notes.username_branch("oscarnpub") is None


def test_nip05_unknown_name_returns_empty_names(client: TestClient):
    assert client.get("/.well-known/nostr.json?name=nobody").json() == {"names": {}}


def test_nip05_with_no_name_returns_empty_names(client: TestClient):
    """Never dumps the whole directory - only the one name asked about,
    and no `name` at all asks about none."""
    _, _, _, cx1 = _branch()
    _, npub = _npub()
    client.post(f"/p/petra?cx1={cx1}&npub={npub}")
    assert client.get("/.well-known/nostr.json").json() == {"names": {}}


def test_nip05_lookup_is_case_insensitive_but_echoes_the_queried_name(client: TestClient):
    _, _, _, cx1 = _branch()
    pubkey, npub = _npub()
    client.post(f"/p/Quinn?cx1={cx1}&npub={npub}")
    nip05 = client.get("/.well-known/nostr.json?name=QUINN").json()
    assert nip05 == {"names": {"QUINN": pubkey.hex()}}


def test_nip05_hidden_while_username_registration_disabled(client: TestClient, monkeypatch):
    _, _, _, cx1 = _branch()
    _, npub = _npub()
    client.post(f"/p/ray?cx1={cx1}&npub={npub}")
    monkeypatch.setattr(settings, "username_registration_enabled", False)
    assert client.get("/.well-known/nostr.json?name=ray").json() == {"names": {}}


def test_unregistered_username_404s(client: TestClient):
    resp = client.get("/.well-known/lnurlp/nobody")
    assert resp.json() == {"status": "ERROR", "reason": "Unknown user."}


def test_registered_lnaddress_callback_carries_username(client: TestClient):
    _, _, _, cx1 = _branch()
    client.post(f"/p/dave?cx1={cx1}")
    data = client.get("/.well-known/lnurlp/dave").json()
    assert data["callback"] == "http://testserver/p/dave"
    assert data["tag"] == "payRequest"


def test_paying_registered_address_with_no_comment_automints(client: TestClient, node: FakeNode):
    p, branch_point, chain_code, cx1 = _branch()
    client.post(f"/p/erin?cx1={cx1}")

    lnaddress = client.get("/.well-known/lnurlp/erin").json()
    pay_response = client.get(f"{lnaddress['callback']}?amount=5000")
    assert pay_response.json().get("pr"), pay_response.text
    node.settled.add(_payment_hash(node))

    expected_id = derivation.derive_pubkey(branch_point, chain_code, 0).hex()
    assert _note_value(client, expected_id) == 5000


def test_second_automint_payment_uses_the_next_index(client: TestClient, node: FakeNode):
    p, branch_point, chain_code, cx1 = _branch()
    client.post(f"/p/frank?cx1={cx1}")
    lnaddress = client.get("/.well-known/lnurlp/frank").json()

    for _ in range(2):
        pay_response = client.get(f"{lnaddress['callback']}?amount=5000")
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
    p, branch_point, chain_code, cx1 = _branch()
    client.post(f"/p/grace?cx1={cx1}")

    pk0 = derivation.derive_pubkey(branch_point, chain_code, 0)
    manual = client.get(f"/p/cb?amount=1000&comment={bech32m.encode_cp1(pk0)}")
    assert manual.json().get("pr")
    node.settled.add(_payment_hash(node))
    assert _note_value(client, pk0.hex()) == 1000

    lnaddress = client.get("/.well-known/lnurlp/grace").json()
    pay_response = client.get(f"{lnaddress['callback']}?amount=5000")
    assert pay_response.json().get("pr")
    node.settled.add(_payment_hash(node))

    pk1 = derivation.derive_pubkey(branch_point, chain_code, 1)
    assert _note_value(client, pk1.hex()) == 5000


def test_comment_is_still_honored_for_registered_username(client: TestClient, node: FakeNode):
    """The address owner minting for themselves with a specific key already
    in hand overrides auto-derivation."""
    _, _, _, cx1 = _branch()
    client.post(f"/p/henry?cx1={cx1}")
    sk = PrivateKey()
    cp1 = bech32m.encode_cp1(sk.public_key.format(compressed=True)[1:])

    pay_response = client.get(f"/p/henry?amount=5000&comment={cp1}")
    assert pay_response.json().get("pr")
    node.settled.add(_payment_hash(node))
    assert _note_value(client, bech32m.decode_cp1(cp1).hex()) == 5000


def test_ordinary_lud12_comment_automints_for_registered_username(client: TestClient, node: FakeNode):
    """A payer's WALLET sending a plain human LUD-12 message (not a note
    ref) must not block minting - it's ignored and the payment still
    auto-mints on the username's own branch, same as no comment at all."""
    p, branch_point, chain_code, cx1 = _branch()
    client.post(f"/p/lenny?cx1={cx1}")
    lnaddress = client.get("/.well-known/lnurlp/lenny").json()

    pay_response = client.get(f"{lnaddress['callback']}?amount=5000&comment=gm!")
    assert pay_response.json().get("pr"), pay_response.text
    node.settled.add(_payment_hash(node))

    expected_id = derivation.derive_pubkey(branch_point, chain_code, 0).hex()
    assert _note_value(client, expected_id) == 5000


def test_username_registration_disabled_404s_register(client: TestClient, monkeypatch):
    monkeypatch.setattr(settings, "username_registration_enabled", False)
    _, _, _, cx1 = _branch()
    resp = client.post(f"/p/iris?cx1={cx1}")
    assert resp.json() == {"status": "ERROR", "reason": "Not found"}


def test_username_registration_disabled_hides_registered_address(client: TestClient, monkeypatch):
    _, _, _, cx1 = _branch()
    client.post(f"/p/jill?cx1={cx1}")
    monkeypatch.setattr(settings, "username_registration_enabled", False)
    resp = client.get("/.well-known/lnurlp/jill")
    assert resp.json() == {"status": "ERROR", "reason": "Unknown user."}


def test_registration_lowercases_a_mixed_case_username(client: TestClient):
    """A registered username is always stored normalized - 'Kevin'
    registers as 'kevin', so every lookup site (which also lowercases its
    own input) resolves it the same way regardless of how a client
    capitalized either side."""
    _, _, _, cx1 = _branch()
    resp = client.post(f"/p/Kevin?cx1={cx1}")
    assert resp.json() == {"status": "OK"}
    assert notes.username_branch("kevin") == bech32m.decode_cx1(cx1).hex()
    assert notes.username_branch("Kevin") is None  # stored lowercase, not as typed


def test_lnaddress_lookup_is_case_insensitive(client: TestClient):
    """A payer's client capitalizing the local-part differently than how
    it was registered (e.g. Alice@host vs alice@host) must still resolve -
    LUD-16 local-parts are conventionally case-insensitive."""
    _, _, _, cx1 = _branch()
    client.post(f"/p/liam?cx1={cx1}")
    lower = client.get("/.well-known/lnurlp/liam").json()
    mixed = client.get("/.well-known/lnurlp/Liam").json()
    upper = client.get("/.well-known/lnurlp/LIAM").json()
    assert lower["tag"] == mixed["tag"] == upper["tag"] == "payRequest"


def test_registered_lnaddress_case_insensitive_duplicate_rejected(client: TestClient):
    """Registering 'Noah' after 'noah' is already taken normalizes to the
    same row, so it hits the overwrite path - and without an ownership
    proof for the branch already on file, that's rejected, not a silent
    second, differently-cased identity for the same logical username."""
    _, _, _, cx1 = _branch()
    assert client.post(f"/p/noah?cx1={cx1}").json()["status"] == "OK"
    _, _, _, cx1_2 = _branch()
    resp = client.post(f"/p/Noah?cx1={cx1_2}")
    assert resp.json()["status"] == "ERROR"
    assert notes.username_branch("noah") == bech32m.decode_cx1(cx1).hex()


def test_mint_username_config_is_case_insensitive(client: TestClient):
    """This mint's own fixed identity (settings.username) resolves the
    same way regardless of how a payer's client capitalized it."""
    assert client.get(f"/.well-known/lnurlp/{settings.username.upper()}").json()["tag"] == "payRequest"
    assert client.get(f"/.well-known/lnurlp/{settings.username.capitalize()}").json()["tag"] == "payRequest"


def test_automint_works_with_mixed_case_username_in_callback(client: TestClient, node: FakeNode):
    """The exact bug this test guards: the callback URL carries whatever
    case the lnaddress lookup was queried with, and the auto-mint path
    (NoteStore.claim_next_index) must still find the registered branch's
    row even though it was stored lowercase - previously this raised
    'Unknown username.' internally for any non-lowercase query."""
    p, branch_point, chain_code, cx1 = _branch()
    client.post(f"/p/oscar?cx1={cx1}")

    lnaddress = client.get("/.well-known/lnurlp/Oscar").json()
    assert lnaddress["callback"] == "http://testserver/p/Oscar"

    pay_response = client.get(f"{lnaddress['callback']}?amount=5000")
    assert pay_response.json().get("pr"), pay_response.text
    node.settled.add(_payment_hash(node))

    expected_id = derivation.derive_pubkey(branch_point, chain_code, 0).hex()
    data = client.get(f"/w?p={expected_id}").json()
    assert data.get("maxWithdrawable") == 5000, data


def test_delete_requires_ownership_proof(client: TestClient):
    _, _, _, cx1 = _branch()
    client.post(f"/p/percy?cx1={cx1}")
    resp = client.delete("/p/percy?sig=" + "00" * 65)
    assert resp.json()["status"] == "ERROR"
    assert notes.username_branch("percy") is not None


def test_delete_with_valid_signature_frees_the_username(client: TestClient):
    p, branch_point, chain_code, cx1 = _branch()
    client.post(f"/p/quincy?cx1={cx1}")
    sig = _ownership_sig(p, branch_point, chain_code, "unregister", "quincy")
    resp = client.delete(f"/p/quincy?sig={sig}")
    assert resp.json() == {"status": "OK"}
    assert notes.username_branch("quincy") is None

    # freed: anyone can claim it again, no proof needed for a fresh claim
    _, _, _, cx1_2 = _branch()
    assert client.post(f"/p/quincy?cx1={cx1_2}").json()["status"] == "OK"


def test_delete_unknown_username_404s(client: TestClient):
    resp = client.delete("/p/nobody?sig=" + "00" * 65)
    assert resp.json() == {"status": "ERROR", "reason": "Unknown user."}


def test_register_signature_cannot_be_replayed_as_unregister(client: TestClient):
    """25.md requires the ownership proof to bind the action
    ("register:" vs "unregister:") into the signed message, not just the
    branch - otherwise a signature published to authorize an overwrite
    (e.g. visible in a GET request log) could be replayed to delete the
    same username outright."""
    p, branch_point, chain_code, cx1 = _branch()
    client.post(f"/p/sybil?cx1={cx1}")
    register_sig = _ownership_sig(p, branch_point, chain_code, "register", "sybil")
    resp = client.delete(f"/p/sybil?sig={register_sig}")
    assert resp.json()["status"] == "ERROR"
    assert notes.username_branch("sybil") is not None


def test_ownership_signature_cannot_be_replayed_across_usernames(client: TestClient):
    """A signature proving ownership of one username registered on a
    branch must not authorize an overwrite/delete of a DIFFERENT username
    that happens to share that same branch - 25.md binds `username` into
    the signed message specifically to prevent this."""
    p, branch_point, chain_code, cx1 = _branch()
    client.post(f"/p/tanya?cx1={cx1}")
    client.post(f"/p/ursula?cx1={cx1}")
    sig_for_tanya = _ownership_sig(p, branch_point, chain_code, "unregister", "tanya")
    resp = client.delete(f"/p/ursula?sig={sig_for_tanya}")
    assert resp.json()["status"] == "ERROR"
    assert notes.username_branch("ursula") is not None


def test_delete_disabled_while_username_registration_disabled(client: TestClient, monkeypatch):
    p, branch_point, chain_code, cx1 = _branch()
    client.post(f"/p/river?cx1={cx1}")
    sig = _ownership_sig(p, branch_point, chain_code, "unregister", "river")
    monkeypatch.setattr(settings, "username_registration_enabled", False)
    resp = client.delete(f"/p/river?sig={sig}")
    assert resp.json() == {"status": "ERROR", "reason": "Not found"}
