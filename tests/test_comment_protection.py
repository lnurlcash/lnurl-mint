"""LUD-25 comment protection (Protecting a freshly minted note from a
preimage race - see luds@cec741b): a WALLET attaches
`comment = hex(sha256(secret))` to a mint payment, and once it settles the
resulting note is credited as `k1=<secret>` instead of the payment preimage
`P` - closing the routing-node preimage race (see
test_bearer_threat_suite_poc.py's T2/T2b) and, since `P` no longer redeems
anything, making it safe for SERVICE to serve LUD-21 verify on that
invoice too (see test_verify.py, test_poc_verify_race.py,
test_surface_hunter_verification.py for the verify-gating side of this).

This file covers the mint-side mechanics themselves: what a valid/invalid/
absent comment does to the resulting note, informational-GET resolution by
secret alone (no prior verify or rotate needed), the commentAllowed
advertisement, and comment-hash collisions."""

from hashlib import sha256

from fastapi.testclient import TestClient

from lnurl_mint.config import settings
from lnurl_mint.db import notes
from tests.conftest import FakeNode, bearer_id, fresh_secret, k1_hash, k1_id

VALUE = 21_000


def test_pay_response_advertises_comment_allowed(client: TestClient):
    data = client.get(f"/.well-known/lnurlp/{settings.username}").json()
    # 64 hex chars - exactly a sha256 digest, the only shape this mint's
    # comment protection recognizes (see router.HEX32_PATTERN)
    assert data["commentAllowed"] >= 64


def test_valid_comment_credits_the_note_under_the_secret_not_the_preimage(client: TestClient, node: FakeNode):
    secret, comment = fresh_secret()
    resp = client.get(f"/p/cb?amount={VALUE}&comment={comment}")
    assert resp.json()["pr"]
    preimage = node.last_preimage.hex()
    node.settled.add(sha256(node.last_preimage).hexdigest())

    # the note resolves under the secret...
    data = client.get(f"/w?k1={secret}").json()
    assert data["tag"] == "withdrawRequest"
    assert data["maxWithdrawable"] == VALUE

    # ...never under the raw preimage, which played no further role
    assert client.get(f"/w?k1={preimage}").json() == {"status": "ERROR", "reason": "Unknown note."}
    _, h = fresh_secret()
    r = client.get(f"/w/cb?k1={preimage}&p1={h}").json()
    assert r == {"status": "ERROR", "reason": "Invalid or already spent k1."}


def test_valid_comment_note_redeems_normally_by_secret(client: TestClient, node: FakeNode):
    secret, comment = fresh_secret()
    client.get(f"/p/cb?amount={VALUE}&comment={comment}")
    node.settled.add(sha256(node.last_preimage).hexdigest())

    _, h = fresh_secret()
    r = client.get(f"/w/cb?k1={secret}&p1={h}").json()
    assert r["status"] == "OK", r
    assert notes.note_amount(bearer_id(h)) == VALUE


def test_missing_comment_is_rejected(client: TestClient, node: FakeNode):
    # comment protection is now mandatory (see get_pay_callback) - a
    # preimage-keyed fallback note is no longer offered to new mints, since
    # the preimage can leak to a route hop before settlement
    resp = client.get(f"/p/cb?amount={VALUE}").json()
    assert resp["status"] == "ERROR"
    assert "comment" in resp["reason"].lower()


def test_malformed_comment_is_rejected(client: TestClient, node: FakeNode):
    # not a bare hex-encoded 32-byte hash - now a hard error rather than a
    # silent fallback to the no-comment path
    resp = client.get(f"/p/cb?amount={VALUE}&comment=not-a-hash").json()
    assert resp["status"] == "ERROR"
    assert "comment" in resp["reason"].lower()


def test_verify_advertised_whenever_verify_is_enabled(client: TestClient, node: FakeNode, monkeypatch):
    monkeypatch.setattr(settings, "verify_enabled", True)

    _, comment = fresh_secret()
    with_comment = client.get(f"/p/cb?amount={VALUE}&comment={comment}").json()
    assert with_comment.get("verify")

    # comment is mandatory now, so both of these are rejected outright
    # rather than falling back to a no-comment mint without verify
    assert client.get(f"/p/cb?amount={VALUE}").json()["status"] == "ERROR"
    assert client.get(f"/p/cb?amount={VALUE}&comment=nope").json()["status"] == "ERROR"


def test_informational_get_lazily_settles_a_comment_protected_mint_without_verify(client: TestClient, node: FakeNode):
    """A WALLET need not touch /verify at all to claim a comment-protected
    note - plain GET /w?k1=<secret> (the ordinary LUD-03 informational
    query) must lazily materialize it too, exactly like the no-comment
    fallback already does for a preimage (see _mint_settled_by_comment)."""
    secret, comment = fresh_secret()
    client.get(f"/p/cb?amount={VALUE}&comment={comment}")
    node.settled.add(sha256(node.last_preimage).hexdigest())

    assert notes.note_amount(bearer_id(comment)) is None  # not yet materialized
    data = client.get(f"/w?k1={secret}").json()
    assert data["maxWithdrawable"] == VALUE
    assert notes.note_amount(bearer_id(comment)) == VALUE  # now it is


def test_unsettled_comment_protected_mint_is_not_yet_a_note(client: TestClient, node: FakeNode):
    secret, comment = fresh_secret()
    client.get(f"/p/cb?amount={VALUE}&comment={comment}")
    # not settled - the fake node hasn't been told this payment_hash paid
    assert client.get(f"/w?k1={secret}").json() == {"status": "ERROR", "reason": "Unknown note."}


def test_comment_colliding_with_an_outstanding_note_is_rejected(client: TestClient, node: FakeNode, mint_note):
    # attacker (or an unlucky WALLET) picks a comment hash that's already
    # in use as an outstanding note's id - create_mint must refuse rather
    # than let a later settle silently shadow or fail against that note
    existing_k1 = mint_note(VALUE)
    existing_note_id = k1_id(existing_k1)
    # mint_note only settles the invoice - materialize the note itself
    # (lazy, via the informational GET) before the collision can be hit
    assert client.get(f"/w?k1={existing_k1}").json()["maxWithdrawable"] == VALUE
    resp = client.get(f"/p/cb?amount={VALUE}&comment={k1_hash(existing_k1)}")
    assert resp.json() == {"status": "ERROR", "reason": "comment already in use"}
    # the existing note is completely unaffected
    assert notes.note_amount(existing_note_id) == VALUE


def test_comment_colliding_with_another_pending_mint_is_rejected(client: TestClient, node: FakeNode):
    _, comment = fresh_secret()
    first = client.get(f"/p/cb?amount={VALUE}&comment={comment}")
    assert first.json()["pr"]

    second = client.get(f"/p/cb?amount={VALUE}&comment={comment}")
    assert second.json() == {"status": "ERROR", "reason": "comment already in use"}


def test_comment_protected_note_can_split_rotate_and_merge_like_any_other(client: TestClient, node: FakeNode):
    secret, comment = fresh_secret()
    client.get(f"/p/cb?amount={VALUE}&comment={comment}")
    node.settled.add(sha256(node.last_preimage).hexdigest())

    _, h = fresh_secret()
    _, h2 = fresh_secret()
    r = client.get(f"/w/cb?k1={secret}&p1={h}&p2={h2}&amount=5000").json()
    assert r["status"] == "OK", r
    assert notes.note_amount(bearer_id(h)) == 5000
    assert notes.note_amount(bearer_id(h2)) == VALUE - 5000
