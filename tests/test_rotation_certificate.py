import logging

import pytest
from coincurve import PrivateKey
from fastapi.testclient import TestClient

from lnurl_mint import bech32m
from lnurl_mint.config import settings
from lnurl_mint.signing import lightning_signed_message_digest, verify_note, verify_rotation
from tests.conftest import bearer_id, ck1_for, fresh_secret, k1_id


def _certifies_rotation(pubkey: str, spent_id: str, h: str, amount_msat: int, cr1: str) -> bool:
    """Whether `cr1` is `pubkey`'s certificate that the note `spent_id` (hex
    Q) was burned into the bearer note named by its hex `h`, worth
    `amount_msat` - checked against the claimed amount, not the one the
    certificate's own HRP carries, so a wrong claim fails."""
    decoded = bech32m.decode_cr1(cr1)
    return decoded is not None and verify_rotation(pubkey, spent_id, bearer_id(h), amount_msat, decoded[1].hex())


def test_cr1_test_vector():
    """A fixed vector other implementations can reproduce: the SERVICE key
    is sha256("LNURLcash rotation certificate test vector"). The two notes
    are keys this suite's spec vectors already use: the burned one is the
    pk_0 of test_ck1_matches_lud25_spec_test_vector_3, the credited one the
    pk_0 of test_username_registration's registration-proof vector. Signed
    with RFC6979, like a node's signmessage."""
    mint_pubkey = "0305299ebc7d5301da5ff64350c558d2daf9933445e611574474024d10d30f826a"
    spent = "aad3a0e36c083eb0d2d92ec0860977dc46d10c952f31830e6443b1faa1997634"
    note = "01fee34e378bf66de6afa1bfa6e30f5c89551fd92bc1b089dca93c52b7ab61bc"

    digest_1000 = lightning_signed_message_digest(f"LNURLcash:rotate:1000:{spent}:{note}")
    assert digest_1000.hex() == "0d60b3e73e340395bccbd3b87a2210dc6c949df3cd6f0c74d256349b2b989cc1"
    sig_1000 = (
        "3ef03201d14594c51de4d5372f57036b29c0fed94f88c804fc6b69198a40155d4d2969bfef7a9226f1fbcb15246a1be0"
        "c2f8c3cc2d0983e0c3e67e422c7c807001"
    )
    assert verify_rotation(mint_pubkey, spent, note, 1000, sig_1000)
    assert bech32m.encode_cr1(1000, bytes.fromhex(sig_1000)) == (
        "cr10n18mcryqw3gk2v280y65mj74crdv5uplkef7yvsp8udd53nzjqz4w562tfhlhh4y3x78auk9fydgd7pshcc0xz6zvrurp7vljz937gquqp09cjwz"
    )

    digest_21m = lightning_signed_message_digest(f"LNURLcash:rotate:21000000:{spent}:{note}")
    assert digest_21m.hex() == "2ee0ec8c1361fd0e1613d62575dd3e790cd4480ac699af7c852eb9819a29db05"
    sig_21m = (
        "6c329cc404f152e5d59d3b737ea9a347e718b676475679d13db0b9112bdfe4064bae7416c87918ad030423c9dcf49139"
        "94e83eb278c6ca9e955292220cc109ac01"
    )
    assert verify_rotation(mint_pubkey, spent, note, 21000000, sig_21m)
    assert bech32m.encode_cr1(21000000, bytes.fromhex(sig_21m)) == (
        "cr210u1dsefe3qy79fwt4va8deha2drgln33dnkgat8n5fakzu3z27lusryhtn5zmy8jx9dqvzz8jwu7jgnn98g86e833k2n6249y3zpnqsntqpu0dlaz"
    )

    # the amount, the direction and the notes themselves are all signed
    assert not verify_rotation(mint_pubkey, spent, note, 21000000, sig_1000)
    assert not verify_rotation(mint_pubkey, note, spent, 1000, sig_1000)
    assert not verify_rotation(mint_pubkey, spent, spent, 1000, sig_1000)
    # and a rotation certificate is never a note's own certificate, for
    # either of the two notes it names
    assert not verify_note(mint_pubkey, note, 1000, sig_1000)
    assert not verify_note(mint_pubkey, spent, 1000, sig_1000)


def test_what_a_cr1_says_that_a_cs1_cannot(client: TestClient, mint_note, node):
    """The question a rotation certificate answers. A seal's history says
    its note Q0 became Q1. Anyone who has seen that history can put a note
    of their own on a made-up Q1': this mint certifies it like any note, and
    Q0 really is spent. A buyer shown "Q0 became Q1'" has nothing to tell it
    from the truth - every cs1 involved is genuine. Only the rotation itself
    has a certificate, and this mint cannot issue a second one for Q0."""
    from tests.test_wallet_ownership_proofs import _mint_cp1_note

    # the real transfer: Q0 is burned into Q1
    k1 = mint_note(5000)
    q0 = k1_id(k1)
    _, h = fresh_secret()
    real = client.get(f"/w/cb?k1={k1}&p1={h}").json()
    q1 = bearer_id(h)

    # the look-alike: a fresh note, paid for by anyone, on a key they chose
    _, cp1 = _mint_cp1_note(client, node, 5000)
    q1_fake = bech32m.decode_cp1(cp1).hex()
    fake = client.get(f"/w?p={cp1}").json()

    # everything a cs1 can say is true of both: each note exists, each is
    # worth 5000 - and Q0 is gone, whichever of the two one is shown
    for note, cs1 in ((q1, real["c"]), (q1_fake, fake["c"])):
        assert verify_note(node.pubkey, note, 5000, bech32m.decode_cs1(cs1)[1].hex())
    assert client.get(f"/w?k1={k1}").json() == {"status": "ERROR", "reason": "Note already spent."}

    # what tells them apart: this mint signed "Q0 became Q1" ...
    rotation = bech32m.decode_cr1(real["r"])[1].hex()
    assert verify_rotation(node.pubkey, q0, q1, 5000, rotation)
    assert not verify_rotation(node.pubkey, q0, q1_fake, 5000, rotation)
    # ... and nothing gets it to sign "Q0 became Q1'": not minting that note,
    # not asking for the rotate again with it
    assert "r" not in fake
    again = client.get(f"/w/cb?k1={k1}&p1={cp1}").json()
    assert again["status"] == "ERROR"
    assert "r" not in again


def test_rotate_returns_a_valid_rotation_certificate(client: TestClient, mint_note, node):
    k1 = mint_note(5000)
    _, h = fresh_secret()
    data = client.get(f"/w/cb?k1={k1}&p1={h}").json()
    assert data["r"].startswith("cr50n1")
    assert _certifies_rotation(node.pubkey, k1_id(k1), h, 5000, data["r"])
    # the amount the certificate carries is the amount it signs, and the
    # same one the note's own certificate carries
    assert bech32m.decode_cr1(data["r"])[0] == bech32m.decode_cs1(data["c"])[0] == 5000


def test_rotation_certificates_chain_note_to_note(client: TestClient, mint_note, node):
    # what a consignment carries: one certificate per transfer, each one's
    # credited note the next one's burned note
    k1 = mint_note(5000)
    chain = [k1_id(k1)]
    certificates = []
    for _ in range(3):
        new_k1, h = fresh_secret()
        certificates.append(client.get(f"/w/cb?k1={k1}&p1={h}").json()["r"])
        chain.append(bearer_id(h))
        k1 = new_k1
    for index, cr1 in enumerate(certificates):
        signature = bech32m.decode_cr1(cr1)[1].hex()
        assert verify_rotation(node.pubkey, chain[index], chain[index + 1], 5000, signature)
        # never for a step it doesn't describe: not backwards, not the next
        # one, and not a shortcut past a note in between
        assert not verify_rotation(node.pubkey, chain[index + 1], chain[index], 5000, signature)
        if index + 2 < len(chain):
            assert not verify_rotation(node.pubkey, chain[index + 1], chain[index + 2], 5000, signature)
            assert not verify_rotation(node.pubkey, chain[index], chain[index + 2], 5000, signature)


def test_rotation_certificate_does_not_verify_against_another_note(client: TestClient, mint_note, node):
    k1, other_k1 = mint_note(5000), mint_note(5000)
    _, h = fresh_secret()
    _, other_h = fresh_secret()
    data = client.get(f"/w/cb?k1={k1}&p1={h}").json()
    # a look-alike: a note minted on the side, not the one this note became
    assert not _certifies_rotation(node.pubkey, k1_id(k1), other_h, 5000, data["r"])
    # nor from a note that was never burned for it
    assert not _certifies_rotation(node.pubkey, k1_id(other_k1), h, 5000, data["r"])
    assert not _certifies_rotation(node.pubkey, k1_id(k1), h, 5001, data["r"])


def test_rotation_certificate_does_not_verify_against_wrong_pubkey(client: TestClient, mint_note, node):
    k1 = mint_note(5000)
    _, h = fresh_secret()
    data = client.get(f"/w/cb?k1={k1}&p1={h}").json()
    wrong_pubkey = PrivateKey().public_key.format(compressed=True).hex()
    assert not _certifies_rotation(wrong_pubkey, k1_id(k1), h, 5000, data["r"])


def test_rotation_certificate_is_not_a_note_certificate(client: TestClient, mint_note, node):
    # the two certificates of one rotate are never interchangeable: a cr1's
    # signature is not a cs1's over either note, and their prefixes differ
    k1 = mint_note(5000)
    _, h = fresh_secret()
    data = client.get(f"/w/cb?k1={k1}&p1={h}").json()
    rotation = bech32m.decode_cr1(data["r"])[1].hex()
    assert not verify_note(node.pubkey, bearer_id(h), 5000, rotation)
    assert not verify_note(node.pubkey, k1_id(k1), 5000, rotation)
    assert bech32m.decode_cs1(data["r"]) is None
    assert bech32m.decode_cr1(data["c"]) is None


def test_split_carries_no_rotation_certificate(client: TestClient, mint_note, node):
    # two notes came out of one: neither is "the" note it became, and a
    # holder of either must not be able to pass it off as such
    k1 = mint_note(5000)
    _, h = fresh_secret()
    _, h2 = fresh_secret()
    data = client.get(f"/w/cb?k1={k1}&amount=2000&p1={h}&p2={h2}").json()
    assert data["status"] == "OK"
    # signing works - both notes are certified - and still no rotation is
    assert "c" in data and "c2" in data
    assert "r" not in data


def test_merge_carries_no_rotation_certificate(client: TestClient, mint_note, node):
    a, b = mint_note(2000), mint_note(3000)
    _, h = fresh_secret()
    data = client.get(f"/w/cb?k1={a}&k1={b}&p1={h}").json()
    assert data["status"] == "OK"
    assert "c" in data
    assert "r" not in data


def test_melt_carries_no_rotation_certificate(client: TestClient, node, mint_note):
    from tests.conftest import fake_invoice

    k1 = mint_note(5000)
    data = client.get(f"/w/cb?k1={k1}&pr={fake_invoice(5000)}").json()
    assert data == {"status": "OK"}


def test_informational_request_carries_no_rotation_certificate(client: TestClient, mint_note, node):
    k1 = mint_note(5000)
    assert "r" not in client.get(f"/w?k1={k1}").json()


def test_retried_rotate_replays_the_same_rotation_certificate(client: TestClient, mint_note, node):
    # how whoever made a rotation gets its certificate again later: an
    # exact retry, LUD-25's Retrying a mutation - nothing is stored for it
    k1 = mint_note(5000)
    _, h = fresh_secret()
    first = client.get(f"/w/cb?k1={k1}&p1={h}").json()
    second = client.get(f"/w/cb?k1={k1}&p1={h}").json()
    assert second["r"] == first["r"]
    assert _certifies_rotation(node.pubkey, k1_id(k1), h, 5000, second["r"])


@pytest.mark.parametrize("split", [True, False])
def test_retried_split_and_merge_replay_without_a_rotation_certificate(client: TestClient, mint_note, node, split):
    _, h = fresh_secret()
    _, h2 = fresh_secret()
    if split:
        query = f"/w/cb?k1={mint_note(5000)}&amount=2000&p1={h}&p2={h2}"
    else:
        query = f"/w/cb?k1={mint_note(2000)}&k1={mint_note(3000)}&p1={h}"
    first = client.get(query).json()
    second = client.get(query).json()
    assert second == first
    assert "c" in second
    assert "r" not in second


def test_rotation_certificate_is_unaffected_by_mint_fees(client: TestClient, mint_note, node, monkeypatch):
    # a rotate moves a note's whole value: the amount certified is the
    # amount that was burned
    monkeypatch.setattr(settings, "base_fee_msat", 1000)
    k1 = mint_note(5000)
    value = client.get(f"/w?k1={k1}").json()["maxWithdrawable"]
    _, h = fresh_secret()
    data = client.get(f"/w/cb?k1={k1}&p1={h}").json()
    assert _certifies_rotation(node.pubkey, k1_id(k1), h, value, data["r"])


def test_rotation_certificate_absent_without_a_funding_source(client: TestClient, mint_note, monkeypatch):
    k1 = mint_note(5000)
    assert client.get(f"/w?k1={k1}").json()["maxWithdrawable"] == 5000
    monkeypatch.setattr(settings, "fundingsource_backend", None)
    _, h = fresh_secret()
    data = client.get(f"/w/cb?k1={k1}&p1={h}").json()
    assert data["status"] == "OK"
    assert "r" not in data


def test_rotation_signing_failure_is_swallowed_and_logged(client: TestClient, mint_note, node, monkeypatch, caplog):
    # the rotate itself already happened: an unreachable node must cost the
    # holder a certificate they can ask for again, never the note
    async def _broken_sign_message(message, config):
        raise ConnectionError("node unreachable")

    k1 = mint_note(5000)
    new_k1, h = fresh_secret()
    assert client.get(f"/w?k1={k1}").json()["maxWithdrawable"] == 5000
    monkeypatch.setattr("lnurl_mint.signing.sign_message", _broken_sign_message)
    with caplog.at_level(logging.WARNING):
        data = client.get(f"/w/cb?k1={k1}&p1={h}").json()
    assert data == {"status": "OK"}
    assert any("sign_rotation" in r.message and "node unreachable" in r.message for r in caplog.records)
    assert client.get(f"/w?k1={new_k1}").json()["maxWithdrawable"] == 5000


# ---- what must never be certified ----
#
# A rotation certificate says "this note became that one, and nothing else
# did". Each test below asks for one that would not be true.


def test_a_split_cannot_be_replayed_as_a_rotate(client: TestClient, mint_note, node):
    # the note became TWO notes; naming it again with either of them alone
    # is no retry of that split, and must not come back as "it became this"
    k1 = mint_note(5000)
    _, h = fresh_secret()
    _, h2 = fresh_secret()
    assert client.get(f"/w/cb?k1={k1}&amount=2000&p1={h}&p2={h2}").json()["status"] == "OK"
    for output in (h, h2):
        data = client.get(f"/w/cb?k1={k1}&p1={output}").json()
        assert data["status"] == "ERROR"
        assert "r" not in data
    # the split itself still replays, without one
    assert "r" not in client.get(f"/w/cb?k1={k1}&amount=2000&p1={h}&p2={h2}").json()


def test_a_merge_cannot_be_replayed_as_a_rotate_of_one_of_its_notes(client: TestClient, mint_note, node):
    a, b = mint_note(2000), mint_note(3000)
    _, h = fresh_secret()
    assert client.get(f"/w/cb?k1={a}&k1={b}&p1={h}").json()["status"] == "OK"
    for k1 in (a, b):
        data = client.get(f"/w/cb?k1={k1}&p1={h}").json()
        assert data["status"] == "ERROR"
        assert "r" not in data


def test_a_note_is_certified_into_one_successor_only(client: TestClient, mint_note, node):
    # the whole point: after "k1 became h", nothing can make this mint sign
    # "k1 became other"
    k1 = mint_note(5000)
    _, h = fresh_secret()
    _, other = fresh_secret()
    first = client.get(f"/w/cb?k1={k1}&p1={h}").json()
    assert _certifies_rotation(node.pubkey, k1_id(k1), h, 5000, first["r"])
    data = client.get(f"/w/cb?k1={k1}&p1={other}").json()
    assert data["status"] == "ERROR"
    assert "r" not in data
    # and the first answer is still the only one a retry gets
    assert client.get(f"/w/cb?k1={k1}&p1={h}").json()["r"] == first["r"]


def test_the_same_note_named_twice_is_no_rotate(client: TestClient, mint_note, node):
    k1 = mint_note(5000)
    _, h = fresh_secret()
    data = client.get(f"/w/cb?k1={k1}&k1={k1}&p1={h}").json()
    assert data["status"] == "ERROR"
    assert "r" not in data
    # nothing burned
    assert client.get(f"/w?k1={k1}").json()["maxWithdrawable"] == 5000


def test_concurrent_rotates_of_one_note_certify_one_successor(client: TestClient, mint_note, node):
    from concurrent.futures import ThreadPoolExecutor

    k1 = mint_note(5000)
    outputs = [fresh_secret()[1] for _ in range(5)]
    with ThreadPoolExecutor(max_workers=5) as pool:
        answers = list(pool.map(lambda h: client.get(f"/w/cb?k1={k1}&p1={h}").json(), outputs))
    certified = [h for h, data in zip(outputs, answers) if "r" in data]
    assert len(certified) == 1
    assert [data["status"] for data in answers].count("OK") == 1


# ---- every kind of note ----


def test_a_key_path_note_is_certified_like_any_other(client: TestClient, mint_note, node):
    # what a seal's note is spent by is a signature, not a preimage: the
    # certificate names the notes by their Q either way
    from tests.test_wallet_ownership_proofs import _mint_cp1_note, _note_keypair

    sk, cp1 = _mint_cp1_note(client, node, 5000)
    spent = bech32m.decode_cp1(cp1).hex()
    next_sk, next_cp1 = _note_keypair()
    note = bech32m.decode_cp1(next_cp1).hex()
    data = client.get(f"/w/cb?k1={ck1_for(sk)}&p1={next_cp1}").json()
    signature = bech32m.decode_cr1(data["r"])[1].hex()
    assert verify_rotation(node.pubkey, spent, note, 5000, signature)
    # and on from there
    _, h = fresh_secret()
    data = client.get(f"/w/cb?k1={ck1_for(next_sk)}&p1={h}").json()
    assert _certifies_rotation(node.pubkey, note, h, 5000, data["r"])


# ---- a certificate that went missing ----


def test_a_rotation_certificate_lost_to_a_signing_failure_comes_back_on_retry(
    client: TestClient, mint_note, node, monkeypatch
):
    # only the rotation's own signature fails: the rotate stands, the note
    # is certified, and asking again - the same request - gets the rest
    real_sign_message = node.sign_message

    async def _rotation_signing_is_down(message, config):
        if message.startswith("LNURLcash:rotate:"):
            raise ConnectionError("node unreachable")
        return await real_sign_message(message, config)

    k1 = mint_note(5000)
    assert client.get(f"/w?k1={k1}").json()["maxWithdrawable"] == 5000
    _, h = fresh_secret()
    monkeypatch.setattr("lnurl_mint.signing.sign_message", _rotation_signing_is_down)
    first = client.get(f"/w/cb?k1={k1}&p1={h}").json()
    assert first["status"] == "OK"
    assert "c" in first and "r" not in first

    monkeypatch.setattr("lnurl_mint.signing.sign_message", real_sign_message)
    retried = client.get(f"/w/cb?k1={k1}&p1={h}").json()
    assert retried["c"] == first["c"]
    assert _certifies_rotation(node.pubkey, k1_id(k1), h, 5000, retried["r"])
