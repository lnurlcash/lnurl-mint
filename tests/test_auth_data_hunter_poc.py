"""Regression tests from the auth-data lane of the 2026-08-17 security
review (originally PoCs, flipped to pin the fixed behavior).

- F1/F-3: /verify discloses a settled mint's preimage (= the bearer note's
  spend secret) to anyone holding only the payment_hash - embedded in the
  invoice itself. Post-fix this requires VERIFY_ENABLED=true; false 404s
  the endpoint entirely (see also test_poc_verify_race.py, which pins the
  by-design race for the enabled case).
- F3/F-2: GET /w on a note reserved by an in-flight melt (pending=1) now
  rejects with the spec's reason "pending" instead of reporting it fully
  withdrawable - the sell-during-melt scam's one lie.
- F4/F-1: rotating ONTO a pending mint's payment_hash is rejected by the
  swap guard (ids may never collide with `mints` rows), so the victim's
  settled mint materializes normally - the attack costs the attacker their
  attempted squat and buys nothing.
"""

from hashlib import sha256

from fastapi.testclient import TestClient

from lnurl_mint.config import settings
from lnurl_mint.db import notes
from tests.conftest import FakeNode, bearer_id, fresh_secret, k1_id


def test_f1_verify_disclosure_requires_verify_enabled(client: TestClient, node: FakeNode):
    # VERIFY_ENABLED pinned false by conftest; /p/cb does not advertise verify
    assert settings.verify_enabled is False
    victim_secret, comment = fresh_secret()
    resp = client.get(f"/p/cb?amount=50000&comment={comment}")
    assert "verify" not in resp.json()

    preimage = node.last_preimage
    payment_hash = sha256(preimage).hexdigest()  # embedded in pr, not secret
    node.settled.add(payment_hash)

    # an attacker holding only the pr (and thus the payment_hash) gets
    # nothing from the unadvertised endpoint - not even after settlement
    verify = client.get(f"/verify/{payment_hash}")
    assert verify.json() == {"status": "ERROR", "reason": "Not found"}
    assert preimage.hex() not in verify.text

    # the note is the victim's to rotate, at whatever speed they like
    _, victim_h = fresh_secret()
    rotate = client.get(f"/w/cb?k1={victim_secret}&p1={victim_h}")
    assert rotate.json()["status"] == "OK", rotate.text
    assert notes.note_amount(bearer_id(victim_h)) == 50_000


def test_f3_withdraw_rejects_pending_note_with_spec_reason(client: TestClient, node: FakeNode, mint_note):
    import threading

    from tests.conftest import fake_invoice

    k1 = mint_note(10_000)
    node.pay_delay = 2.0  # hold the melt in-flight

    # TestClient runs background tasks before returning, so drive the melt
    # from a thread to observe the pending window from the main one
    melt_resp = {}
    t = threading.Thread(
        target=lambda: melt_resp.setdefault("r", client.get(f"/w/cb?k1={k1}&pr={fake_invoice(10_000)}"))
    )
    t.start()
    while notes.pending_melts() == {}:
        pass  # spin until mark_pending lands (pay_delay holds it there)
    try:
        # note is reserved (pending=1) by the in-flight melt
        assert notes.pending_melts() != {}

        # the informational endpoint now tells the same truth as the
        # mutating one, with the spec's own distinct reason
        info = client.get(f"/w?k1={k1}").json()
        assert info == {"status": "ERROR", "reason": "pending"}, info

        _, h = fresh_secret()
        rotate = client.get(f"/w/cb?k1={k1}&p1={h}").json()
        assert rotate["reason"] == "pending"
    finally:
        node.pay_delay = 0.0
        t.join()
    assert melt_resp["r"].json()["status"] == "OK"


def test_f4_rotate_onto_pending_mint_rejected_victim_unharmed(client: TestClient, node: FakeNode, mint_note):
    attacker_k1 = mint_note(10_000)

    # victim requests a mint invoice (unpaid); its pr embeds the payment_hash
    victim_secret, victim_comment = fresh_secret()
    client.get(f"/p/cb?amount=50000&comment={victim_comment}")
    victim_preimage = node.last_preimage
    victim_ph = sha256(victim_preimage).hexdigest()

    # the squat on the note the victim's mint will credit fails atomically
    # - nothing planted, nothing burned
    r1 = client.get(f"/w/cb?k1={attacker_k1}&p1={victim_comment}")
    assert r1.json() == {"status": "ERROR", "reason": "already in use"}, r1.text
    assert notes.note_amount(bearer_id(victim_comment)) is None  # no squatter row
    attacker_id = k1_id(attacker_k1)
    assert notes.note_amount(attacker_id) == 10_000  # attacker's note intact

    # victim pays: the mint materializes for its full value, exactly as if
    # the attack never happened
    node.settled.add(victim_ph)
    victim_info = client.get(f"/w?k1={victim_secret}").json()
    assert victim_info.get("tag") == "withdrawRequest", victim_info
    assert victim_info["maxWithdrawable"] == 50_000
    assert notes.mint_settled(victim_ph) is True
