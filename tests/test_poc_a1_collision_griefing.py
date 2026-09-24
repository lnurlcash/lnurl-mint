"""Regression tests for the pending-mint note-id squat (2026-08-17 review,
F-1 - the review's one HIGH finding, originally PoC A1).

Pre-fix, NoteStore.swap's INSERT collision-checked only the `notes` table,
never `mints` - so a rotate/split/merge with h/h2 = a victim's PENDING mint
invoice payment_hash (visible in the victim's BOLT11 pr) planted a squatter
note under that id. The victim's /w then returned a valid, mint-SIGNED
withdrawRequest for the squatter's dust amount (silent value substitution),
and once the squatter was spent, settle_mint's INSERT PK-collided with the
kept row and rolled back forever - the paid mint could never materialize,
/verify 500d permanently, all for the price of one dust note.

The fix: swap rejects any new note id some `mints` row will credit as
"already in use" (LUD-25), in the same transaction - so the squat fails
atomically (nothing burned), and the legitimate mint materializes normally
once paid. These tests pin exactly that, across all three swap paths
(rotate p1, split p1/p2, merge p1), plus the settled-mint variant.

Since LUD-25 keys every note by its output key Q, a pending mint's future
id is the note its `comment` named, never its payment hash - so that is
what a squat has to target now, and squatting the payment hash (the
original PoC's target) plants a note nobody's mint will ever credit.
"""

from hashlib import sha256

import pytest
from fastapi.testclient import TestClient

from lnurl_mint.db import notes
from tests.conftest import bearer_id, fresh_secret, k1_id

VICTIM_AMOUNT = 50_000
PLANT_AMOUNT = 10_000


def _pending_victim_mint(client: TestClient, node) -> tuple[str, str, str]:
    """A victim mint invoice, requested but not yet paid: (payment_hash,
    secret, comment). The squat targets `comment` - the note this invoice
    will credit once paid."""
    secret, comment = fresh_secret()
    resp = client.get(f"/p/cb?amount={VICTIM_AMOUNT}&comment={comment}")
    assert resp.json().get("pr"), resp.text
    preimage = node.last_preimage
    return sha256(preimage).hexdigest(), secret, comment


def _assert_squat_rejected(resp, attacker_k1: str, reason: str = "Output already in use.") -> None:
    """The squat fails, atomically - the attacker's own note is NOT burned
    (the whole swap rolls back)."""
    assert resp.json() == {"status": "ERROR", "reason": reason}, resp.text
    attacker_id = k1_id(attacker_k1)
    assert notes.note_amount(attacker_id) == PLANT_AMOUNT


def _assert_victim_mint_materializes(client: TestClient, node, victim_ph: str, victim_k1: str) -> None:
    """After the rejected squat, the victim pays and their mint works
    exactly as if nothing happened."""
    node.settled.add(victim_ph)
    w = client.get(f"/w?k1={victim_k1}")
    assert w.status_code == 200
    body = w.json()
    assert body.get("tag") == "withdrawRequest", body
    assert body["maxWithdrawable"] == VICTIM_AMOUNT, body
    assert notes.mint_settled(victim_ph) is True
    assert notes.note_amount(k1_id(victim_k1)) == VICTIM_AMOUNT


def test_rotate_squat_is_rejected_and_victim_mint_survives(client: TestClient, node, mint_note):
    attacker_k1 = mint_note(PLANT_AMOUNT)
    victim_ph, victim_k1, victim_comment = _pending_victim_mint(client, node)
    assert notes.pending_mint(victim_ph) == VICTIM_AMOUNT

    resp = client.get(f"/w/cb?k1={attacker_k1}&p1={victim_comment}")
    _assert_squat_rejected(resp, attacker_k1, "Output already in use.")
    # no squatter note exists under the victim's future id
    assert notes.note_amount(bearer_id(victim_comment)) is None

    _assert_victim_mint_materializes(client, node, victim_ph, victim_k1)


def test_squatting_the_payment_hash_is_harmless(client: TestClient, node, mint_note):
    """The original PoC's target: a note credited under the payment hash's
    own bearer note sits beside the victim's, which still materializes."""
    attacker_k1 = mint_note(PLANT_AMOUNT)
    victim_ph, victim_k1, _ = _pending_victim_mint(client, node)
    assert client.get(f"/w/cb?k1={attacker_k1}&p1={victim_ph}").json()["status"] == "OK"
    _assert_victim_mint_materializes(client, node, victim_ph, victim_k1)


@pytest.mark.parametrize("variant", ["split_h", "split_h2", "merge"])
def test_split_and_merge_squats_are_rejected_identically(client: TestClient, node, mint_note, variant: str):
    """Split (h and h2) and merge (h) all reach the same swap guard."""
    victim_ph, victim_k1, victim_comment = _pending_victim_mint(client, node)

    if variant == "split_h":
        k1 = mint_note(PLANT_AMOUNT)
        _, h2 = fresh_secret()
        resp = client.get(f"/w/cb?k1={k1}&amount=4000&p1={victim_comment}&p2={h2}")
    elif variant == "split_h2":
        k1 = mint_note(PLANT_AMOUNT)
        _, h = fresh_secret()
        resp = client.get(f"/w/cb?k1={k1}&amount=4000&p1={h}&p2={victim_comment}")
    else:  # merge
        k1a, k1b = mint_note(6000), mint_note(4000)
        resp = client.get(f"/w/cb?k1={k1a}&k1={k1b}&p1={victim_comment}")
        k1 = k1a  # for the atomicity check below (both must survive)
    assert resp.json() == {"status": "ERROR", "reason": "Output already in use."}, resp.text
    assert notes.note_amount(bearer_id(victim_comment)) is None  # no squatter planted

    # atomic: nothing was burned - every input note is still outstanding
    if variant == "merge":
        assert notes.note_amount(k1_id(k1a)) == 6000
        assert notes.note_amount(k1_id(k1b)) == 4000
    else:
        assert notes.note_amount(k1_id(k1)) == PLANT_AMOUNT

    _assert_victim_mint_materializes(client, node, victim_ph, victim_k1)


def test_squat_on_an_already_settled_mints_id_is_also_rejected(client: TestClient, node, mint_note):
    """A settled mint's note already exists, so a WALLET-chosen id colliding
    with it must reject as "already in use" (LUD-25), rather than dying on
    the notes-table PK constraint with an ugly internal-error 500."""
    victim_k1 = mint_note(VICTIM_AMOUNT)
    victim_note_id = k1_id(victim_k1)  # the note the comment named
    victim_ph = sha256(node.last_preimage).hexdigest()  # the underlying invoice's payment_hash
    # materialize the note (mints settle lazily, on first resolution)
    assert client.get(f"/w?k1={victim_k1}").json()["maxWithdrawable"] == VICTIM_AMOUNT
    assert notes.mint_settled(victim_ph) is True

    attacker_k1 = mint_note(PLANT_AMOUNT)
    resp = client.get(f"/w/cb?k1={attacker_k1}&p1={sha256(bytes.fromhex(victim_k1)).hexdigest()}")
    _assert_squat_rejected(resp, attacker_k1, "Output already in use.")
    # the victim's real note is untouched
    assert notes.note_amount(victim_note_id) == VICTIM_AMOUNT


def test_legitimate_ids_still_pass_the_guard(client: TestClient, node, mint_note):
    """No false positives: fresh WALLET-generated h/h2 (the honest flow)
    rotate, split and merge exactly as before the guard existed."""
    k1 = mint_note(PLANT_AMOUNT)
    _, h = fresh_secret()
    assert client.get(f"/w/cb?k1={k1}&p1={h}").json()["status"] == "OK"
    assert notes.note_amount(bearer_id(h)) == PLANT_AMOUNT

    k1b, k1c = mint_note(6000), mint_note(4000)
    _, hm = fresh_secret()
    assert client.get(f"/w/cb?k1={k1b}&k1={k1c}&p1={hm}").json()["status"] == "OK"
    assert notes.note_amount(bearer_id(hm)) == 10_000

    k1d = mint_note(PLANT_AMOUNT)
    _, hs, _, hs2 = *fresh_secret(), *fresh_secret()
    assert client.get(f"/w/cb?k1={k1d}&amount=4000&p1={hs}&p2={hs2}").json()["status"] == "OK"
    assert notes.note_amount(bearer_id(hs)) == 4000
    assert notes.note_amount(bearer_id(hs2)) == PLANT_AMOUNT - 4000
