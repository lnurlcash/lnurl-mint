"""Regression tests for the /verify preimage observer race (2026-08-17
review, F-3/P1 - originally PoC B3).

Originally: the race was spec-shaped and remained BY DESIGN whenever verify
was on, since /verify handed a settled mint's preimage (= the no-comment
fallback note's entire spend secret) to ANYONE who knew the payment_hash
(embedded in the invoice itself), letting the first rotater win the note
regardless of who paid for it.

FIXED, now in two layers: LUD-25 comment protection (router.get_pay_callback)
is mandatory, so a no-comment mint - the case where the preimage IS the
note's whole spend secret - is rejected at /p/cb outright, before an invoice
or a verify URL ever exists (see
test_theft_chain_closed_at_the_door_comment_is_now_mandatory below). And even
setting that aside, a mint that DOES use `comment` gets verify served, but
its disclosed preimage is no longer the note's secret (the WALLET-held
`secret` behind `comment` is), so the same theft chain fails there too, for
a different reason (test_theft_chain_closed_because_comment_makes_the_preimage_harmless).

What the earlier review changed, still true and unaffected by the above:
VERIFY_ENABLED=false is a real off switch - the endpoint 404s entirely (not
just its advertisement) - see test_verify_disabled_closes_the_hole.
"""

from hashlib import sha256

import bolt11
from fastapi.testclient import TestClient

from lnurl_mint.config import settings
from lnurl_mint.db import notes
from tests.conftest import FakeNode, fake_invoice, fresh_secret


def test_theft_chain_closed_at_the_door_comment_is_now_mandatory(client: TestClient, node: FakeNode, monkeypatch):
    """The original theft chain (attacker scrapes a no-comment mint's
    preimage from /verify, since there it IS the note's whole spend secret)
    is now closed one step earlier than the verify-refusal fix below: a
    mint that skips `comment` (LUD-25 comment protection) is rejected
    outright at /p/cb, so no preimage-keyed fallback note - and no invoice
    to scrape a preimage from in the first place - ever comes into
    existence."""
    monkeypatch.setattr(settings, "verify_enabled", True)

    # victim tries to mint WITHOUT comment protection (a legacy or
    # LNURLcash-aware-but-opted-out wallet) - refused before an invoice is
    # even created
    resp = client.get("/p/cb?amount=50000").json()
    assert resp["status"] == "ERROR"
    assert "comment" in resp["reason"].lower()


def test_theft_chain_closed_because_comment_makes_the_preimage_harmless(
    client: TestClient, node: FakeNode, monkeypatch
):
    """The complementary fix: a WALLET that DOES use LUD-25 comment
    protection gets verify served normally, but the disclosed preimage is
    no longer the note's spend secret (the WALLET-held `secret` behind
    `comment` is) - so an attacker stealing it from /verify gets nothing to
    rotate, and the theft chain fails at its second step instead."""
    monkeypatch.setattr(settings, "verify_enabled", True)
    victim_secret, comment = fresh_secret()
    resp = client.get(f"/p/cb?amount=50000&comment={comment}")
    assert resp.json().get("verify")
    victim_pr = resp.json()["pr"]
    victim_ph = bolt11.decode(victim_pr).payment_hash
    node.settled.add(victim_ph)

    # ATTACKER: verify is served (comment protection was used) and does
    # disclose the preimage...
    r = client.get(f"/verify/{victim_ph}")
    body = r.json()
    assert body["settled"] is True
    stolen_preimage = body["preimage"]
    assert stolen_preimage is not None

    # ...but it redeems nothing - it was never the note's k1 to begin with
    _, attacker_h = fresh_secret()
    r = client.get(f"/w/cb?k1={stolen_preimage}&p1={attacker_h}")
    assert r.json() == {"status": "ERROR", "reason": "Invalid or already spent k1."}
    assert notes.note_amount(attacker_h) is None

    # only the victim's own held secret redeems the note, at their leisure -
    # no race to win, since nobody else ever had anything that worked
    _, victim_h = fresh_secret()
    r = client.get(f"/w/cb?k1={victim_secret}&p1={victim_h}")
    assert r.json()["status"] == "OK", r.text
    assert notes.note_amount(victim_h) == 50_000


def test_no_comment_mint_never_gets_far_enough_to_have_a_verify_url(client: TestClient, node: FakeNode, monkeypatch):
    """The old exposure window in one picture, now closed even earlier than
    the verify-refusal fix: a no-comment mint request is rejected outright,
    so there's no payment_hash, no invoice, and nothing for /verify/{ph} to
    ever answer about - at any point in time."""
    monkeypatch.setattr(settings, "verify_enabled", True)
    resp = client.get("/p/cb?amount=50000").json()
    assert resp["status"] == "ERROR"
    assert "pr" not in resp


def test_melt_direction_verify_is_harmless(client: TestClient, node: FakeNode, mint_note, monkeypatch):
    """The melt-direction analog: /verify on a melt's payment_hash returns
    the OUTGOING payment's own preimage. Harmless, as the code claims: the
    notes that funded the melt are burned by the time the preimage appears,
    and the melt preimage keys no note - rotating with it fails as
    unknown."""
    monkeypatch.setattr(settings, "verify_enabled", True)
    k1 = mint_note(50_000)
    note_id = sha256(bytes.fromhex(k1)).hexdigest()

    # victim melts their note into an external invoice
    melt_invoice = fake_invoice(50_000)
    melt_ph = bolt11.decode(melt_invoice).payment_hash
    r = client.get(f"/w/cb?k1={k1}&pr={melt_invoice}")
    assert r.json()["status"] == "OK", r.text
    # note burned (background payment succeeded in FakeNode)
    assert notes.note_amount(note_id) is None
    assert notes.note_spent(note_id) is True

    # attacker polls the melt's verify once it completes
    node.payment_actually_completed = True
    r = client.get(f"/verify/{melt_ph}")
    body = r.json()
    assert body["settled"] is True
    melt_preimage = body["preimage"]
    assert melt_preimage is not None
    assert body["pr"] == melt_invoice  # proof-of-payment bundle, per LUD-25

    # the melt preimage is NOT a bearer secret. (FakeNode.pay_invoice
    # returns a random preimage uncommitted to melt_ph; on a real node
    # sha256(preimage) == melt_ph by the BOLT-11 commitment - the
    # conclusion below is identical either way, because melt_ph keys no
    # note and no mint ever used it as a payment hash.)
    assert notes.note_amount(melt_ph) is None
    assert notes.mint_pr(melt_ph) is None
    _, attacker_h = fresh_secret()
    r = client.get(f"/w/cb?k1={melt_preimage}&p1={attacker_h}")
    assert r.json() == {"status": "ERROR", "reason": "Invalid or already spent k1."}
    assert notes.note_amount(attacker_h) is None
    # and the original note's secret is equally dead (already burned)
    r = client.get(f"/w/cb?k1={k1}&p1={attacker_h}")
    assert r.json() == {"status": "ERROR", "reason": "Invalid or already spent k1."}


def test_verify_disabled_closes_the_hole(client: TestClient, node: FakeNode):
    """The review's fix: with VERIFY_ENABLED=false (the test-env default,
    and now a REAL off switch), the endpoint 404s even for a settled mint
    whose preimage is there for the taking - an observer holding the
    payment_hash learns nothing, and the victim's slow manual rotate
    succeeds untouched."""
    assert settings.verify_enabled is False
    victim_secret, comment = fresh_secret()
    resp = client.get(f"/p/cb?amount=50000&comment={comment}")
    victim_ph = bolt11.decode(resp.json()["pr"]).payment_hash
    node.settled.add(victim_ph)

    # the attacker polls verify exactly as in the theft chain above...
    assert client.get(f"/verify/{victim_ph}").json() == {"status": "ERROR", "reason": "Not found"}

    # ...and the victim rotates at human speed, unhurried and unrobbed
    _, victim_h = fresh_secret()
    r = client.get(f"/w/cb?k1={victim_secret}&p1={victim_h}")
    assert r.json()["status"] == "OK", r.text
    assert notes.note_amount(victim_h) == 50_000
