"""LUD-25 Part 2, Seed & derivation's cx1 registration (router.py's
POST/DELETE /p/{username}): a WALLET claims a Lightning Address username
against its own watch-only branch, and this mint auto-mints cp1 notes off
it directly. Every register/unregister call needs an ownership-proof
signature - a fresh claim over the branch being submitted right now, an
overwrite or delete over whichever branch is already on file (see
router._owns_branch and upsert_registered_username's own docstring for why
those differ) - there is no proof-free case."""

import json
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

# a well-formed-length but cryptographically meaningless signature - used
# wherever a test needs *some* sig value present (sig is a required query
# param on every register/unregister call now) but wants the ownership
# check itself to fail, not FastAPI's own missing-parameter validation.
_BOGUS_SIG = "00" * 65


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
    recoverable. `action` is "register" (a fresh claim OR an overwrite -
    upsert_registered_username checks it against a different branch
    depending on which) or "unregister" (matching
    delete_registered_username) - the two are never interchangeable.
    `username` must already be lowercase: the endpoint lowercases it
    before ever checking a signature, so a sig signed over a mixed-case
    username would simply never match."""
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
    p, branch_point, chain_code, cx1 = _branch()
    sig = _ownership_sig(p, branch_point, chain_code, "register", "alice")
    resp = client.post(f"/p/alice?cx1={cx1}&sig={sig}")
    assert resp.json() == {"status": "OK"}
    assert notes.username_branch("alice") == bech32m.decode_cx1(cx1).hex()


def test_register_without_a_signature_rejected(client: TestClient):
    """`sig` is a required parameter now - even a fresh, unclaimed
    username is never proof-free (25.md's Seed & derivation)."""
    _, _, _, cx1 = _branch()
    resp = client.post(f"/p/quentin?cx1={cx1}")
    assert resp.json()["status"] == "ERROR"
    assert notes.username_branch("quentin") is None


def test_register_fresh_claim_with_wrong_signature_rejected(client: TestClient):
    """A fresh claim's proof must be over the NEW cx1 being submitted -
    signed by any OTHER key, it's rejected outright, exactly like an
    overwrite's own wrong-signature case."""
    _, _, _, cx1 = _branch()
    wrong_p, wrong_branch_point, wrong_chain_code, _ = _branch()
    sig = _ownership_sig(wrong_p, wrong_branch_point, wrong_chain_code, "register", "walter")
    resp = client.post(f"/p/walter?cx1={cx1}&sig={sig}")
    assert resp.json()["status"] == "ERROR"
    assert notes.username_branch("walter") is None


def test_overwrite_without_ownership_proof_rejected(client: TestClient):
    p, branch_point, chain_code, cx1 = _branch()
    sig = _ownership_sig(p, branch_point, chain_code, "register", "bob")
    assert client.post(f"/p/bob?cx1={cx1}&sig={sig}").json()["status"] == "OK"
    _, _, _, cx1_2 = _branch()
    resp = client.post(f"/p/bob?cx1={cx1_2}&sig={_BOGUS_SIG}")
    assert resp.json()["status"] == "ERROR"
    # rejected outright: the original branch is untouched
    assert notes.username_branch("bob") == bech32m.decode_cx1(cx1).hex()


def test_overwrite_with_wrong_signature_rejected(client: TestClient):
    p, branch_point, chain_code, cx1 = _branch()
    sig0 = _ownership_sig(p, branch_point, chain_code, "register", "carol")
    client.post(f"/p/carol?cx1={cx1}&sig={sig0}")
    wrong_p, _, _, _ = _branch()
    sig = _ownership_sig(wrong_p, wrong_p.public_key.format(compressed=True)[1:], urandom(32), "register", "carol")
    _, _, _, cx1_2 = _branch()
    resp = client.post(f"/p/carol?cx1={cx1_2}&sig={sig}")
    assert resp.json()["status"] == "ERROR"
    assert notes.username_branch("carol") == bech32m.decode_cx1(cx1).hex()


def test_overwrite_with_valid_ownership_proof_replaces_the_branch(client: TestClient):
    p, branch_point, chain_code, cx1 = _branch()
    sig = _ownership_sig(p, branch_point, chain_code, "register", "dana")
    client.post(f"/p/dana?cx1={cx1}&sig={sig}")
    # same key both times: the fresh claim above proved control of `cx1`
    # itself, this overwrite proves continued control of that SAME branch
    # (still on file), a different check that happens to need an
    # identical signature only because nothing about the branch changed
    _, _, _, cx1_2 = _branch()
    resp = client.post(f"/p/dana?cx1={cx1_2}&sig={sig}")
    assert resp.json() == {"status": "OK"}
    assert notes.username_branch("dana") == bech32m.decode_cx1(cx1_2).hex()


def test_overwrite_omitting_npub_clears_it(client: TestClient):
    p, branch_point, chain_code, cx1 = _branch()
    _, npub = _npub()
    sig = _ownership_sig(p, branch_point, chain_code, "register", "edna")
    client.post(f"/p/edna?cx1={cx1}&npub={npub}&sig={sig}")
    assert client.get("/.well-known/nostr.json?name=edna").json()["names"]

    resp = client.post(f"/p/edna?cx1={cx1}&sig={sig}")
    assert resp.json() == {"status": "OK"}
    assert client.get("/.well-known/nostr.json?name=edna").json() == {"names": {}}


def test_register_rejects_reserved_username(client: TestClient):
    _, _, _, cx1 = _branch()
    assert client.post(f"/p/{settings.username}?cx1={cx1}&sig={_BOGUS_SIG}").json()["status"] == "ERROR"
    assert client.post(f"/p/_?cx1={cx1}&sig={_BOGUS_SIG}").json()["status"] == "ERROR"


def test_register_rejects_malformed_cx1(client: TestClient):
    resp = client.post(f"/p/finn?cx1=notbech32m&sig={_BOGUS_SIG}")
    assert resp.json()["status"] == "ERROR"


def test_register_with_npub_serves_nip05(client: TestClient):
    p, branch_point, chain_code, cx1 = _branch()
    pubkey, npub = _npub()
    sig = _ownership_sig(p, branch_point, chain_code, "register", "mallory")
    resp = client.post(f"/p/mallory?cx1={cx1}&npub={npub}&sig={sig}")
    assert resp.json() == {"status": "OK"}

    nip05 = client.get("/.well-known/nostr.json?name=mallory").json()
    assert nip05 == {"names": {"mallory": pubkey.hex()}}


def test_register_without_npub_has_no_nip05_name(client: TestClient):
    p, branch_point, chain_code, cx1 = _branch()
    sig = _ownership_sig(p, branch_point, chain_code, "register", "nora")
    client.post(f"/p/nora?cx1={cx1}&sig={sig}")
    nip05 = client.get("/.well-known/nostr.json?name=nora").json()
    assert nip05 == {"names": {}}


def test_register_rejects_malformed_npub(client: TestClient):
    p, branch_point, chain_code, cx1 = _branch()
    sig = _ownership_sig(p, branch_point, chain_code, "register", "oscarnpub")
    resp = client.post(f"/p/oscarnpub?cx1={cx1}&npub=notanpub&sig={sig}")
    assert resp.json()["status"] == "ERROR"
    assert notes.username_branch("oscarnpub") is None


def test_nip05_unknown_name_returns_empty_names(client: TestClient):
    assert client.get("/.well-known/nostr.json?name=nobody").json() == {"names": {}}


def test_nip05_with_no_name_returns_empty_names(client: TestClient):
    """Never dumps the whole directory - only the one name asked about,
    and no `name` at all asks about none."""
    p, branch_point, chain_code, cx1 = _branch()
    _, npub = _npub()
    sig = _ownership_sig(p, branch_point, chain_code, "register", "petra")
    client.post(f"/p/petra?cx1={cx1}&npub={npub}&sig={sig}")
    assert client.get("/.well-known/nostr.json").json() == {"names": {}}


def test_nip05_lookup_is_case_insensitive_but_echoes_the_queried_name(client: TestClient):
    p, branch_point, chain_code, cx1 = _branch()
    pubkey, npub = _npub()
    sig = _ownership_sig(p, branch_point, chain_code, "register", "quinn")
    client.post(f"/p/Quinn?cx1={cx1}&npub={npub}&sig={sig}")
    nip05 = client.get("/.well-known/nostr.json?name=QUINN").json()
    assert nip05 == {"names": {"QUINN": pubkey.hex()}}


def test_nip05_hidden_while_username_registration_disabled(client: TestClient, monkeypatch):
    p, branch_point, chain_code, cx1 = _branch()
    _, npub = _npub()
    sig = _ownership_sig(p, branch_point, chain_code, "register", "ray")
    client.post(f"/p/ray?cx1={cx1}&npub={npub}&sig={sig}")
    monkeypatch.setattr(settings, "username_registration_enabled", False)
    assert client.get("/.well-known/nostr.json?name=ray").json() == {"names": {}}


def test_nip05_404s_while_nip05_disabled(client: TestClient, monkeypatch):
    p, branch_point, chain_code, cx1 = _branch()
    _, npub = _npub()
    sig = _ownership_sig(p, branch_point, chain_code, "register", "sam")
    client.post(f"/p/sam?cx1={cx1}&npub={npub}&sig={sig}")
    monkeypatch.setattr(settings, "nip05_enabled", False)
    resp = client.get("/.well-known/nostr.json?name=sam")
    assert resp.json() == {"status": "ERROR", "reason": "Not found"}


def test_registration_rejects_npub_while_nip05_disabled(client: TestClient, monkeypatch):
    monkeypatch.setattr(settings, "nip05_enabled", False)
    p, branch_point, chain_code, cx1 = _branch()
    _, npub = _npub()
    sig = _ownership_sig(p, branch_point, chain_code, "register", "tina")
    resp = client.post(f"/p/tina?cx1={cx1}&npub={npub}&sig={sig}")
    assert resp.json() == {"status": "ERROR", "reason": "npub registration (NIP-05) is disabled on this mint."}
    assert notes.username_branch("tina") is None


def test_registration_without_npub_still_works_while_nip05_disabled(client: TestClient, monkeypatch):
    monkeypatch.setattr(settings, "nip05_enabled", False)
    p, branch_point, chain_code, cx1 = _branch()
    sig = _ownership_sig(p, branch_point, chain_code, "register", "uma")
    resp = client.post(f"/p/uma?cx1={cx1}&sig={sig}")
    assert resp.json() == {"status": "OK"}
    assert notes.username_branch("uma") is not None


def test_unregistered_username_404s(client: TestClient):
    resp = client.get("/.well-known/lnurlp/nobody")
    assert resp.json() == {"status": "ERROR", "reason": "Unknown user."}


def test_registered_lnaddress_callback_carries_username(client: TestClient):
    p, branch_point, chain_code, cx1 = _branch()
    sig = _ownership_sig(p, branch_point, chain_code, "register", "dave")
    client.post(f"/p/dave?cx1={cx1}&sig={sig}")
    data = client.get("/.well-known/lnurlp/dave").json()
    assert data["callback"] == "http://testserver/p/dave"
    assert data["tag"] == "payRequest"


def test_registered_lnaddress_metadata_advertises_xpub_for_internal_transfers(client: TestClient):
    """25.md's Internal mint transfers: a registered username's payRequest
    metadata carries its own `cx1`, so a payer's WALLET already holding a
    note on this mint can skip Lightning entirely - deriving the next note
    key itself rather than paying an invoice."""
    p, branch_point, chain_code, cx1 = _branch()
    sig = _ownership_sig(p, branch_point, chain_code, "register", "gina")
    client.post(f"/p/gina?cx1={cx1}&sig={sig}")
    metadata = json.loads(client.get("/.well-known/lnurlp/gina").json()["metadata"])
    assert ["text/xpub", f"{cx1}:0"] in metadata


def test_fixed_identity_lnaddress_metadata_has_no_xpub(client: TestClient):
    """This mint's own fixed identity has no watch-only branch to advertise
    - only a registered (cx1-backed) username does."""
    metadata = json.loads(client.get(f"/.well-known/lnurlp/{settings.username}").json()["metadata"])
    assert not any(entry[0] == "text/xpub" for entry in metadata)


def test_xpub_index_hint_advances_after_an_automint(client: TestClient, node: FakeNode):
    """claim_next_index reserves and persists past the index it hands out
    at callback (invoice-creation) time, not at settlement - so the
    advertised hint must already reflect that on the very next lookup,
    even before this particular invoice is paid."""
    p, branch_point, chain_code, cx1 = _branch()
    sig = _ownership_sig(p, branch_point, chain_code, "register", "hana")
    client.post(f"/p/hana?cx1={cx1}&sig={sig}")
    lnaddress = client.get("/.well-known/lnurlp/hana").json()
    metadata = json.loads(lnaddress["metadata"])
    assert ["text/xpub", f"{cx1}:0"] in metadata

    pay_response = client.get(f"{lnaddress['callback']}?amount=5000")
    assert pay_response.json().get("pr")

    metadata = json.loads(client.get("/.well-known/lnurlp/hana").json()["metadata"])
    assert ["text/xpub", f"{cx1}:1"] in metadata


def test_internal_transfer_skips_lightning_via_rotate(client: TestClient, node: FakeNode, mint_note):
    """The whole point of Internal mint transfers: a payer already holding
    a note on this mint reads `ivan`'s `cx1`/index hint off his payRequest
    metadata and lands a note directly on his branch via an ordinary
    rotate - never paying a Lightning invoice to `ivan`'s address at all."""
    p, branch_point, chain_code, cx1 = _branch()
    sig = _ownership_sig(p, branch_point, chain_code, "register", "ivan")
    client.post(f"/p/ivan?cx1={cx1}&sig={sig}")
    metadata = json.loads(client.get("/.well-known/lnurlp/ivan").json()["metadata"])
    xpub_entry = next(entry for entry in metadata if entry[0] == "text/xpub")
    advertised_cx1, index_hint = xpub_entry[1].rsplit(":", 1)
    assert advertised_cx1 == cx1
    decoded_branch = bech32m.decode_cx1(advertised_cx1)
    assert decoded_branch == branch_point + chain_code

    pk_i = derivation.derive_pubkey(branch_point, chain_code, int(index_hint))
    cp1 = bech32m.encode_cp1(pk_i)

    # the sender already holds an ordinary (legacy) note on this mint -
    # rotating it directly onto ivan's derived key moves the value without
    # ever touching ivan's own payRequest/invoice
    k1 = mint_note(5000)
    resp = client.get(f"/w/cb?k1={k1}&p1={cp1}")
    assert resp.json()["status"] == "OK"
    assert _note_value(client, pk_i.hex()) == 5000

    # ivan's own advertised next_index is untouched by this - it's only a
    # hint, never reserved by anything other than his own auto-mint path
    metadata = json.loads(client.get("/.well-known/lnurlp/ivan").json()["metadata"])
    assert ["text/xpub", f"{cx1}:{index_hint}"] in metadata


def test_internal_transfer_to_a_stale_index_is_rejected_like_any_collision(
    client: TestClient, node: FakeNode, mint_note
):
    """`i` is only a hint (25.md): if two senders race for the same
    advertised index, the second one must fail cleanly, exactly like any
    other already-in-use p1, never double-credit or overwrite."""
    p, branch_point, chain_code, cx1 = _branch()
    sig = _ownership_sig(p, branch_point, chain_code, "register", "jack")
    client.post(f"/p/jack?cx1={cx1}&sig={sig}")
    pk0 = derivation.derive_pubkey(branch_point, chain_code, 0)
    cp1 = bech32m.encode_cp1(pk0)

    first_k1 = mint_note(3000)
    assert client.get(f"/w/cb?k1={first_k1}&p1={cp1}").json()["status"] == "OK"

    second_k1 = mint_note(2000)
    resp = client.get(f"/w/cb?k1={second_k1}&p1={cp1}")
    assert resp.json()["status"] == "ERROR"
    # the first transfer's note is untouched, the second sender's note
    # was never burned
    assert _note_value(client, pk0.hex()) == 3000
    assert client.get(f"/w?k1={second_k1}").json()["maxWithdrawable"] == 2000


def test_paying_registered_address_with_no_comment_automints(client: TestClient, node: FakeNode):
    p, branch_point, chain_code, cx1 = _branch()
    sig = _ownership_sig(p, branch_point, chain_code, "register", "erin")
    client.post(f"/p/erin?cx1={cx1}&sig={sig}")

    lnaddress = client.get("/.well-known/lnurlp/erin").json()
    pay_response = client.get(f"{lnaddress['callback']}?amount=5000")
    assert pay_response.json().get("pr"), pay_response.text
    node.settled.add(_payment_hash(node))

    expected_id = derivation.derive_pubkey(branch_point, chain_code, 0).hex()
    assert _note_value(client, expected_id) == 5000


def test_second_automint_payment_uses_the_next_index(client: TestClient, node: FakeNode):
    p, branch_point, chain_code, cx1 = _branch()
    sig = _ownership_sig(p, branch_point, chain_code, "register", "frank")
    client.post(f"/p/frank?cx1={cx1}&sig={sig}")
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
    sig = _ownership_sig(p, branch_point, chain_code, "register", "grace")
    client.post(f"/p/grace?cx1={cx1}&sig={sig}")

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
    p, branch_point, chain_code, cx1 = _branch()
    sig = _ownership_sig(p, branch_point, chain_code, "register", "henry")
    client.post(f"/p/henry?cx1={cx1}&sig={sig}")
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
    sig = _ownership_sig(p, branch_point, chain_code, "register", "lenny")
    client.post(f"/p/lenny?cx1={cx1}&sig={sig}")
    lnaddress = client.get("/.well-known/lnurlp/lenny").json()

    pay_response = client.get(f"{lnaddress['callback']}?amount=5000&comment=gm!")
    assert pay_response.json().get("pr"), pay_response.text
    node.settled.add(_payment_hash(node))

    expected_id = derivation.derive_pubkey(branch_point, chain_code, 0).hex()
    assert _note_value(client, expected_id) == 5000


def test_username_registration_disabled_404s_register(client: TestClient, monkeypatch):
    monkeypatch.setattr(settings, "username_registration_enabled", False)
    _, _, _, cx1 = _branch()
    resp = client.post(f"/p/iris?cx1={cx1}&sig={_BOGUS_SIG}")
    assert resp.json() == {"status": "ERROR", "reason": "Not found"}


def test_username_registration_disabled_hides_registered_address(client: TestClient, monkeypatch):
    p, branch_point, chain_code, cx1 = _branch()
    sig = _ownership_sig(p, branch_point, chain_code, "register", "jill")
    client.post(f"/p/jill?cx1={cx1}&sig={sig}")
    monkeypatch.setattr(settings, "username_registration_enabled", False)
    resp = client.get("/.well-known/lnurlp/jill")
    assert resp.json() == {"status": "ERROR", "reason": "Unknown user."}


def test_registration_lowercases_a_mixed_case_username(client: TestClient):
    """A registered username is always stored normalized - 'Kevin'
    registers as 'kevin', so every lookup site (which also lowercases its
    own input) resolves it the same way regardless of how a client
    capitalized either side."""
    p, branch_point, chain_code, cx1 = _branch()
    sig = _ownership_sig(p, branch_point, chain_code, "register", "kevin")
    resp = client.post(f"/p/Kevin?cx1={cx1}&sig={sig}")
    assert resp.json() == {"status": "OK"}
    assert notes.username_branch("kevin") == bech32m.decode_cx1(cx1).hex()
    assert notes.username_branch("Kevin") is None  # stored lowercase, not as typed


def test_lnaddress_lookup_is_case_insensitive(client: TestClient):
    """A payer's client capitalizing the local-part differently than how
    it was registered (e.g. Alice@host vs alice@host) must still resolve -
    LUD-16 local-parts are conventionally case-insensitive."""
    p, branch_point, chain_code, cx1 = _branch()
    sig = _ownership_sig(p, branch_point, chain_code, "register", "liam")
    client.post(f"/p/liam?cx1={cx1}&sig={sig}")
    lower = client.get("/.well-known/lnurlp/liam").json()
    mixed = client.get("/.well-known/lnurlp/Liam").json()
    upper = client.get("/.well-known/lnurlp/LIAM").json()
    assert lower["tag"] == mixed["tag"] == upper["tag"] == "payRequest"


def test_registered_lnaddress_case_insensitive_duplicate_rejected(client: TestClient):
    """Registering 'Noah' after 'noah' is already taken normalizes to the
    same row, so it hits the overwrite path - and without an ownership
    proof for the branch already on file, that's rejected, not a silent
    second, differently-cased identity for the same logical username."""
    p, branch_point, chain_code, cx1 = _branch()
    sig = _ownership_sig(p, branch_point, chain_code, "register", "noah")
    assert client.post(f"/p/noah?cx1={cx1}&sig={sig}").json()["status"] == "OK"
    _, _, _, cx1_2 = _branch()
    resp = client.post(f"/p/Noah?cx1={cx1_2}&sig={_BOGUS_SIG}")
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
    sig = _ownership_sig(p, branch_point, chain_code, "register", "oscar")
    client.post(f"/p/oscar?cx1={cx1}&sig={sig}")

    lnaddress = client.get("/.well-known/lnurlp/Oscar").json()
    assert lnaddress["callback"] == "http://testserver/p/Oscar"

    pay_response = client.get(f"{lnaddress['callback']}?amount=5000")
    assert pay_response.json().get("pr"), pay_response.text
    node.settled.add(_payment_hash(node))

    expected_id = derivation.derive_pubkey(branch_point, chain_code, 0).hex()
    data = client.get(f"/w?p={expected_id}").json()
    assert data.get("maxWithdrawable") == 5000, data


def test_delete_requires_ownership_proof(client: TestClient):
    p, branch_point, chain_code, cx1 = _branch()
    sig = _ownership_sig(p, branch_point, chain_code, "register", "percy")
    client.post(f"/p/percy?cx1={cx1}&sig={sig}")
    resp = client.delete(f"/p/percy?sig={_BOGUS_SIG}")
    assert resp.json()["status"] == "ERROR"
    assert notes.username_branch("percy") is not None


def test_delete_with_valid_signature_frees_the_username(client: TestClient):
    p, branch_point, chain_code, cx1 = _branch()
    sig0 = _ownership_sig(p, branch_point, chain_code, "register", "quincy")
    client.post(f"/p/quincy?cx1={cx1}&sig={sig0}")
    sig = _ownership_sig(p, branch_point, chain_code, "unregister", "quincy")
    resp = client.delete(f"/p/quincy?sig={sig}")
    assert resp.json() == {"status": "OK"}
    assert notes.username_branch("quincy") is None

    # freed: anyone can claim it again - still needs to prove it controls
    # the NEW branch being submitted, same as any other fresh claim
    # (register is never proof-free, not even right after a delete)
    p2, branch_point2, chain_code2, cx1_2 = _branch()
    sig2 = _ownership_sig(p2, branch_point2, chain_code2, "register", "quincy")
    assert client.post(f"/p/quincy?cx1={cx1_2}&sig={sig2}").json()["status"] == "OK"


def test_delete_unknown_username_404s(client: TestClient):
    resp = client.delete(f"/p/nobody?sig={_BOGUS_SIG}")
    assert resp.json() == {"status": "ERROR", "reason": "Unknown user."}


def test_register_signature_cannot_be_replayed_as_unregister(client: TestClient):
    """25.md requires the ownership proof to bind the action
    ("register:" vs "unregister:") into the signed message, not just the
    branch - otherwise a signature published to authorize an overwrite
    (e.g. visible in a GET request log) could be replayed to delete the
    same username outright."""
    p, branch_point, chain_code, cx1 = _branch()
    sig = _ownership_sig(p, branch_point, chain_code, "register", "sybil")
    client.post(f"/p/sybil?cx1={cx1}&sig={sig}")
    resp = client.delete(f"/p/sybil?sig={sig}")
    assert resp.json()["status"] == "ERROR"
    assert notes.username_branch("sybil") is not None


def test_ownership_signature_cannot_be_replayed_across_usernames(client: TestClient):
    """A signature proving ownership of one username registered on a
    branch must not authorize an overwrite/delete of a DIFFERENT username
    that happens to share that same branch - 25.md binds `username` into
    the signed message specifically to prevent this."""
    p, branch_point, chain_code, cx1 = _branch()
    sig_tanya = _ownership_sig(p, branch_point, chain_code, "register", "tanya")
    sig_ursula = _ownership_sig(p, branch_point, chain_code, "register", "ursula")
    client.post(f"/p/tanya?cx1={cx1}&sig={sig_tanya}")
    client.post(f"/p/ursula?cx1={cx1}&sig={sig_ursula}")
    sig_for_tanya = _ownership_sig(p, branch_point, chain_code, "unregister", "tanya")
    resp = client.delete(f"/p/ursula?sig={sig_for_tanya}")
    assert resp.json()["status"] == "ERROR"
    assert notes.username_branch("ursula") is not None


def test_delete_disabled_while_username_registration_disabled(client: TestClient, monkeypatch):
    p, branch_point, chain_code, cx1 = _branch()
    sig0 = _ownership_sig(p, branch_point, chain_code, "register", "river")
    client.post(f"/p/river?cx1={cx1}&sig={sig0}")
    sig = _ownership_sig(p, branch_point, chain_code, "unregister", "river")
    monkeypatch.setattr(settings, "username_registration_enabled", False)
    resp = client.delete(f"/p/river?sig={sig}")
    assert resp.json() == {"status": "ERROR", "reason": "Not found"}
