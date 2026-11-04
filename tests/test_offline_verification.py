import logging

from fastapi.testclient import TestClient

from lnurl_mint import bech32m
from lnurl_mint.config import settings
from lnurl_mint.signing import lightning_signed_message_digest, verify_note
from tests.conftest import bearer_id, fresh_secret


def _certifies(pubkey: str, h: str, amount_msat: int, cs1: str) -> bool:
    """Whether `cs1` is `pubkey`'s certificate that the bearer note named by
    its hex `h` (stored at, and certified over, its Q) is worth
    `amount_msat` - checked against the claimed amount, not the one the
    certificate's own HRP carries, so a wrong claim fails."""
    decoded = bech32m.decode_cs1(cs1)
    return decoded is not None and verify_note(pubkey, bearer_id(h), "testserver", amount_msat, decoded[1].hex())


def test_cs1_matches_lud25_spec_test_vector_4():
    """Cross-implementation check against 25.md's own published "Test
    vector 4: Offline verification (mint's cs1 certificate)" - an
    arbitrary SERVICE signing key (unrelated to any WALLET seed, per the
    vector's own intro) and pk_0 from test vector 1
    (test_ck1_matches_lud25_spec_test_vector_3 already confirms that pk_0),
    certified for two different amounts. Everything else in this file only
    self-checks sign_note/verify_note by round-tripping against randomly
    generated keys via a FakeNode - deterministic, but never against a
    value anything outside this file could reproduce."""
    mint_pubkey = "035acdbd57663f858be6d61ec4bfcbc99492699010f1451e30a6550f26295e813d"
    pk = "690ac33892c64aa53874b0066ab1332f0ef45cb7c0e017eae0828916f52aa99f"
    domain = "mint.example"

    digest_1000 = lightning_signed_message_digest(f"LNURLcash:{domain}:1000:{pk}")
    assert digest_1000.hex() == "084dbb1bf4c84e6bb08da9c283208f07c546305855e74f06834adc7257c3644b"
    sig_1000 = (
        "8863e702d6a676cde369439645104dc793106eec12d1bde8f13a7d95d3079c560fe39eff7edf0b7b4ccee16a7273b737"
        "3b04c813b0cfd1e297e2d7a9ba0bce9901"
    )
    assert verify_note(mint_pubkey, pk, domain, 1000, sig_1000)
    assert bech32m.encode_cs1(1000, bytes.fromhex(sig_1000)) == (
        "cs10n13p37wqkk5emvmcmfgwty2yzdc7f3qmhvztgmm6838f7et5c8n3tqlcu7lald7zmmfn8wz6njwwmnwwcyeqfmpn73u2t794afhg9uaxgpyam087"
    )

    digest_21m = lightning_signed_message_digest(f"LNURLcash:{domain}:21000000:{pk}")
    assert digest_21m.hex() == "cdda839535b2705e17d5587c1cfde7ae50df8afaeba822a9ea898cc7fdc86049"
    sig_21m = (
        "2b3b440e3befbf3632f006b497d0a57fcb23eca47bc33531b7baf74f4d922cc863fff6a9cd1c5deda86751509b57c68d"
        "a6a51a92e1d3ab6acb5a3eca369f365000"
    )
    assert verify_note(mint_pubkey, pk, domain, 21000000, sig_21m)
    assert bech32m.encode_cs1(21000000, bytes.fromhex(sig_21m)) == (
        "cs210u19va5gr3ma7lnvvhsq66f05990l9j8m9y00pn2vdhhtm57nvj9nyx8llk48x3ch0d4pn4z5ym2lrgmf49r2fwr5atdt9450k2x60nv5qqt2u5km"
    )

    # cross-amount replay must fail - amount is folded into the signed
    # message itself, not carried alongside it as an unverified label
    assert not verify_note(mint_pubkey, pk, domain, 21000000, sig_1000)
    assert not verify_note(mint_pubkey, pk, domain, 1000, sig_21m)
    # and so is the domain: a certificate never vouches for the note at
    # another mint (luds 92abbb3)
    assert not verify_note(mint_pubkey, pk, "other.example", 1000, sig_1000)


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
    assert "c" not in data


def test_mint_pubkey_is_the_funding_source_nodes_own_identity(client: TestClient, mint_note, node):
    k1 = mint_note(5000)
    data = client.get(f"/w?k1={k1}").json()
    assert data["mintPubkey"] == node.pubkey


def test_rotate_returns_a_valid_signature(client: TestClient, mint_note, node):
    k1 = mint_note(5000)
    _, h = fresh_secret()
    data = client.get(f"/w/cb?k1={k1}&p1={h}").json()
    assert _certifies(node.pubkey, h, 5000, data["c"])
    assert "c2" not in data


def test_split_returns_valid_signatures_for_both_notes(client: TestClient, mint_note, node):
    k1 = mint_note(5000)
    _, h = fresh_secret()
    _, h2 = fresh_secret()
    data = client.get(f"/w/cb?k1={k1}&amount=2000&p1={h}&p2={h2}").json()
    assert _certifies(node.pubkey, h, 2000, data["c"])
    assert _certifies(node.pubkey, h2, 3000, data["c2"])


def test_merge_returns_a_valid_signature(client: TestClient, mint_note, node):
    a, b = mint_note(2000), mint_note(3000)
    _, h = fresh_secret()
    data = client.get(f"/w/cb?k1={a}&k1={b}&p1={h}").json()
    assert _certifies(node.pubkey, h, 5000, data["c"])


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
    assert not _certifies(node.pubkey, h, 5001, data["c"])


def test_signature_does_not_verify_against_wrong_k1(client: TestClient, mint_note, node):
    k1 = mint_note(5000)
    _, h = fresh_secret()
    _, other_h = fresh_secret()  # a different note's hash, never disclosed here
    data = client.get(f"/w/cb?k1={k1}&p1={h}").json()
    assert not _certifies(node.pubkey, other_h, 5000, data["c"])


def test_signature_does_not_verify_against_wrong_pubkey(client: TestClient, mint_note, node):
    from coincurve import PrivateKey

    k1 = mint_note(5000)
    _, h = fresh_secret()
    data = client.get(f"/w/cb?k1={k1}&p1={h}").json()
    wrong_pubkey = PrivateKey().public_key.format(compressed=True).hex()
    assert not _certifies(wrong_pubkey, h, 5000, data["c"])


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
    assert "c" not in data


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
