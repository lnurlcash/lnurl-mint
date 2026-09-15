"""LUD-25 Part 2 (25.md): Wallet-side ownership proofs + Offline verification
for `cp1` notes - mint via comment=cp1<pk>, redeem via k1=ck1<pk><sig>, and
the cs1 certificates issued alongside rotate/split/merge and the
informational GET."""

from hashlib import sha256
from os import urandom

from coincurve import PrivateKey, PublicKey
from fastapi.testclient import TestClient

from lnurl_mint import bech32m
from lnurl_mint.signing import lightning_signed_message_digest
from tests.conftest import FakeNode

_CK1_MESSAGE = sha256(b"LNURLcash").digest()


def _note_keypair() -> tuple[PrivateKey, str]:
    """A fresh (sk, cp1<pk>) pair for a Part 2 note, the way a real WALLET
    would generate one (see 25.md's Wallet-side ownership proofs)."""
    sk = PrivateKey()
    pk_xonly = sk.public_key.format(compressed=True)[1:]
    return sk, bech32m.encode_cp1(pk_xonly)


def _ck1(sk: PrivateKey) -> str:
    """The bearer secret for a note owned by `sk` - a BIP-340 Schnorr
    signature over the one fixed message every ck1 signs, per Encoding,
    with `sk`'s own x-only pubkey travelling alongside it."""
    pk_xonly = sk.public_key.format(compressed=True)[1:]
    sig = sk.sign_schnorr(_CK1_MESSAGE)
    return bech32m.encode_ck1(pk_xonly, sig)


def _mint_cp1_note(client: TestClient, node: FakeNode, amount_msat: int) -> tuple[PrivateKey, str]:
    sk, cp1 = _note_keypair()
    response = client.get(f"/p/cb?amount={amount_msat}&comment={cp1}")
    assert response.json().get("pr"), response.text
    node.settled.add(node_payment_hash(node))
    return sk, cp1


def node_payment_hash(node: FakeNode) -> str:
    from hashlib import sha256

    return sha256(node.last_preimage).hexdigest()


def test_mint_cp1_note_and_check_value(client: TestClient, node: FakeNode):
    sk, cp1 = _mint_cp1_note(client, node, 5000)
    k1 = _ck1(sk)
    data = client.get(f"/w?k1={k1}").json()
    assert data["minWithdrawable"] == data["maxWithdrawable"] == 5000


def test_informational_get_includes_cs1_certificate(client: TestClient, node: FakeNode):
    sk, cp1 = _mint_cp1_note(client, node, 5000)
    k1 = _ck1(sk)
    data = client.get(f"/w?k1={k1}").json()
    assert "sig" in data
    amount_msat, sig = bech32m.decode_cs1(data["sig"])
    assert amount_msat == 5000
    digest = lightning_signed_message_digest(f"LNURLcash:{amount_msat}:{bech32m.decode_cp1(cp1).hex()}")
    recovered = PublicKey.from_signature_and_message(sig, digest, hasher=None)
    assert recovered.format(compressed=True).hex() == node.pubkey


def test_legacy_note_informational_get_has_no_sig(client: TestClient, mint_note):
    k1 = mint_note(5000)
    data = client.get(f"/w?k1={k1}").json()
    assert "sig" not in data


def test_recovery_scan_finds_a_note_via_p_equals_cp1(client: TestClient, node: FakeNode):
    """25.md's Seed & derivation: a WALLET recovering on a fresh install
    re-derives pk_0, pk_1, ... and GETs the withdraw LNURL with
    `?p=cp1<pk_i>` for each - this must find an outstanding cp1 note the
    same way `?p=<raw hex>` already does for a legacy one, not 404 just
    because the id happens to be bech32m-encoded on the wire."""
    sk, cp1 = _mint_cp1_note(client, node, 5000)
    data = client.get(f"/w?p={cp1}").json()
    assert data.get("maxWithdrawable") == 5000, data


def test_recovery_scan_via_p_equals_cp1_also_includes_cs1_certificate(client: TestClient, node: FakeNode):
    """A `cs1` certificate is just this mint's signature over (pubkey,
    amount) - not a spend authorization - so a `?p=cp1<pk>` lookup (which
    names a cp1 note just as unambiguously as a `ck1`, but proves no
    ownership) is exactly as safe a place to hand one out. Without this, a
    WALLET's recovery scan (which only ever has `p`, never `k1`, until it
    finds the note) would need a second round trip - or to force a rotate -
    just to obtain a certificate it could already prove it's entitled to."""
    sk, cp1 = _mint_cp1_note(client, node, 5000)
    data = client.get(f"/w?p={cp1}").json()
    assert "sig" in data
    amount_msat, sig = bech32m.decode_cs1(data["sig"])
    assert amount_msat == 5000
    digest = lightning_signed_message_digest(f"LNURLcash:{amount_msat}:{bech32m.decode_cp1(cp1).hex()}")
    recovered = PublicKey.from_signature_and_message(sig, digest, hasher=None)
    assert recovered.format(compressed=True).hex() == node.pubkey


def test_recovery_scan_reports_a_spent_cp1_note_as_spent_not_unknown(client: TestClient, node: FakeNode):
    sk, cp1 = _mint_cp1_note(client, node, 5000)
    k1 = _ck1(sk)
    new_sk, new_cp1 = _note_keypair()
    assert client.get(f"/w/cb?k1={k1}&p1={new_cp1}").json()["status"] == "OK"

    data = client.get(f"/w?p={cp1}").json()
    assert data == {"status": "ERROR", "reason": "Note already spent."}


def test_rotate_cp1_note_produces_cp1_output_with_certificate(client: TestClient, node: FakeNode):
    sk, cp1 = _mint_cp1_note(client, node, 5000)
    k1 = _ck1(sk)
    new_sk, new_cp1 = _note_keypair()
    data = client.get(f"/w/cb?k1={k1}&p1={new_cp1}").json()
    assert data["status"] == "OK"
    amount_msat, sig = bech32m.decode_cs1(data["sig"])
    assert amount_msat == 5000
    new_pk = bech32m.decode_cp1(new_cp1)
    digest = lightning_signed_message_digest(f"LNURLcash:{amount_msat}:{new_pk.hex()}")
    recovered = PublicKey.from_signature_and_message(sig, digest, hasher=None)
    assert recovered.format(compressed=True).hex() == node.pubkey

    # old note is burned, new one is spendable under the new key
    assert client.get(f"/w?k1={k1}").json()["reason"] == "Note already spent."
    new_k1 = _ck1(new_sk)
    assert client.get(f"/w?k1={new_k1}").json()["maxWithdrawable"] == 5000


def test_split_cp1_note_produces_two_cp1_outputs(client: TestClient, node: FakeNode):
    sk, cp1 = _mint_cp1_note(client, node, 5000)
    k1 = _ck1(sk)
    out_sk, out_cp1 = _note_keypair()
    change_sk, change_cp1 = _note_keypair()
    data = client.get(f"/w/cb?k1={k1}&amount=2000&p1={out_cp1}&p2={change_cp1}").json()
    assert data["status"] == "OK"
    assert bech32m.decode_cs1(data["sig"])[0] == 2000
    assert bech32m.decode_cs1(data["sig2"])[0] == 3000

    out_k1 = _ck1(out_sk)
    change_k1 = _ck1(change_sk)
    assert client.get(f"/w?k1={out_k1}").json()["maxWithdrawable"] == 2000
    assert client.get(f"/w?k1={change_k1}").json()["maxWithdrawable"] == 3000


def test_merge_mixes_legacy_and_cp1_notes(client: TestClient, node: FakeNode, mint_note):
    legacy_k1 = mint_note(3000)
    sk, cp1 = _mint_cp1_note(client, node, 2000)
    ck1 = _ck1(sk)
    out_sk, out_cp1 = _note_keypair()

    data = client.get(f"/w/cb?k1={legacy_k1}&k1={ck1}&p1={out_cp1}").json()
    assert data["status"] == "OK"
    assert bech32m.decode_cs1(data["sig"])[0] == 5000

    out_k1 = _ck1(out_sk)
    assert client.get(f"/w?k1={out_k1}").json()["maxWithdrawable"] == 5000


def test_bare_pubkey_cannot_redeem_a_cp1_note(client: TestClient, node: FakeNode):
    """A cp1 pubkey alone (no ck1 signature) must never be accepted as a
    spend-capable k1 - pk is public information (it travels in the open,
    e.g. handed to a recipient, or used as the mint `comment`), so
    accepting it as k1 would let anyone burn any cp1 note they've merely
    seen, breaking the entire bearer-secret model Part 2 relies on."""
    sk, cp1 = _mint_cp1_note(client, node, 5000)
    _, new_cp1 = _note_keypair()
    data = client.get(f"/w/cb?k1={cp1}&p1={new_cp1}").json()
    assert data == {"status": "ERROR", "reason": "Invalid or already spent k1."}


def test_forged_ck1_signature_rejected(client: TestClient, node: FakeNode):
    sk, cp1 = _mint_cp1_note(client, node, 5000)
    other_sk = PrivateKey()
    forged = _ck1(other_sk)  # a signature valid for a note that was never minted
    _, new_cp1 = _note_keypair()
    data = client.get(f"/w/cb?k1={forged}&p1={new_cp1}").json()
    assert data == {"status": "ERROR", "reason": "Invalid or already spent k1."}


def test_malformed_ck1_rejected(client: TestClient):
    """A ck1 string with a bad checksum, wrong HRP, or wrong length must
    fail the same way a malformed legacy k1 does, never a 500."""
    _, new_cp1 = _note_keypair()
    bad = "ck1" + "q" * 110
    data = client.get(f"/w/cb?k1={bad}&p1={new_cp1}").json()
    assert data["status"] == "ERROR"


def test_comment_rejects_wrong_length_cp1_lookalike(client: TestClient):
    # a cp1-shaped string but wrong payload length must still be rejected,
    # not silently truncated/padded
    bogus = bech32m.encode("cp", urandom(31))
    response = client.get(f"/p/cb?amount=5000&comment={bogus}")
    assert response.json()["status"] == "ERROR"


def _legacy_ck1(sk: PrivateKey) -> str:
    """TODO(deprecated): the pre-schnorr ck1 shape - a bare 65-byte
    recoverable signature, no embedded pk - built the way an un-upgraded
    WALLET still would, so tests can confirm the mint still honors it
    during the transition (see bech32m.decode_ck1_legacy,
    signing.recover_note_pubkey)."""
    sig = sk.sign_recoverable(lightning_signed_message_digest("LNURLcash"), hasher=None)
    return bech32m.encode("ck", sig)


def test_legacy_ck1_still_redeems_a_cp1_note(client: TestClient, node: FakeNode):
    """TODO(deprecated): a note redeemed with the old bare-signature ck1
    shape must still work while the mint stays backwards compatible with
    un-upgraded WALLETs."""
    sk, cp1 = _mint_cp1_note(client, node, 5000)
    legacy_k1 = _legacy_ck1(sk)
    data = client.get(f"/w?k1={legacy_k1}").json()
    assert data["minWithdrawable"] == data["maxWithdrawable"] == 5000

    new_sk, new_cp1 = _note_keypair()
    cb = client.get(f"/w/cb?k1={legacy_k1}&p1={new_cp1}").json()
    assert cb["status"] == "OK"
    new_k1 = _ck1(new_sk)
    assert client.get(f"/w?k1={new_k1}").json()["maxWithdrawable"] == 5000
