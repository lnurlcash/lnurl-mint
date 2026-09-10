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

The fix: swap rejects any new note id present in `mints` (pending OR
settled) with the generic safe reason, in the same transaction - so the
squat fails atomically (nothing burned), and the legitimate mint
materializes normally once paid. These tests pin exactly that, across all
three swap paths (rotate h, split h/h2, merge h), plus the settled-mint
variant (an already-settled invoice's payment_hash stays in `mints`
forever, so it must reject too).
"""

from hashlib import sha256

import pytest
from fastapi.testclient import TestClient

from lnurl_mint.db import notes
from tests.conftest import fresh_secret

VICTIM_AMOUNT = 50_000
PLANT_AMOUNT = 10_000


def _pending_victim_mint(client: TestClient, node) -> tuple[str, str]:
    """A victim mint invoice, requested but not yet paid: (payment_hash,
    secret). The squat targets `payment_hash` - visible in the victim's
    BOLT11 pr before settlement, unrelated to comment protection (which
    only changes what the resulting note's k1 will be: the WALLET's
    secret, not the preimage)."""
    secret, comment = fresh_secret()
    resp = client.get(f"/p/cb?amount={VICTIM_AMOUNT}&comment={comment}")
    assert resp.json().get("pr"), resp.text
    preimage = node.last_preimage
    return sha256(preimage).hexdigest(), secret


def _assert_squat_rejected(resp, attacker_k1: str) -> None:
    """The squat fails with the generic safe reason, atomically - the
    attacker's own note is NOT burned (the whole swap rolls back)."""
    assert resp.json() == {"status": "ERROR", "reason": "Invalid or already spent k1."}, resp.text
    attacker_id = sha256(bytes.fromhex(attacker_k1)).hexdigest()
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
    assert notes.note_amount(sha256(bytes.fromhex(victim_k1)).hexdigest()) == VICTIM_AMOUNT


def test_rotate_squat_is_rejected_and_victim_mint_survives(client: TestClient, node, mint_note):
    attacker_k1 = mint_note(PLANT_AMOUNT)
    victim_ph, victim_k1 = _pending_victim_mint(client, node)
    assert notes.pending_mint(victim_ph) == VICTIM_AMOUNT

    resp = client.get(f"/w/cb?k1={attacker_k1}&p1={victim_ph}")
    _assert_squat_rejected(resp, attacker_k1)
    # no squatter note exists under the victim's future id
    assert notes.note_amount(victim_ph) is None

    _assert_victim_mint_materializes(client, node, victim_ph, victim_k1)


@pytest.mark.parametrize("variant", ["split_h", "split_h2", "merge"])
def test_split_and_merge_squats_are_rejected_identically(client: TestClient, node, mint_note, variant: str):
    """Split (h and h2) and merge (h) all reach the same swap guard."""
    victim_ph, victim_k1 = _pending_victim_mint(client, node)

    if variant == "split_h":
        k1 = mint_note(PLANT_AMOUNT)
        _, h2 = fresh_secret()
        resp = client.get(f"/w/cb?k1={k1}&amount=4000&p1={victim_ph}&p2={h2}")
    elif variant == "split_h2":
        k1 = mint_note(PLANT_AMOUNT)
        _, h = fresh_secret()
        resp = client.get(f"/w/cb?k1={k1}&amount=4000&p1={h}&p2={victim_ph}")
    else:  # merge
        k1a, k1b = mint_note(6000), mint_note(4000)
        resp = client.get(f"/w/cb?k1={k1a}&k1={k1b}&p1={victim_ph}")
        k1 = k1a  # for the atomicity check below (both must survive)
    assert resp.json() == {"status": "ERROR", "reason": "Invalid or already spent k1."}, resp.text
    assert notes.note_amount(victim_ph) is None  # no squatter planted

    # atomic: nothing was burned - every input note is still outstanding
    if variant == "merge":
        assert notes.note_amount(sha256(bytes.fromhex(k1a)).hexdigest()) == 6000
        assert notes.note_amount(sha256(bytes.fromhex(k1b)).hexdigest()) == 4000
    else:
        assert notes.note_amount(sha256(bytes.fromhex(k1)).hexdigest()) == PLANT_AMOUNT

    _assert_victim_mint_materializes(client, node, victim_ph, victim_k1)


def test_squat_on_an_already_settled_mints_id_is_also_rejected(client: TestClient, node, mint_note):
    """The guard consults `mints` rows regardless of minted state: a settled
    mint's payment_hash row stays in `mints` forever (even though, with
    comment protection mandatory, the note it actually produced is keyed by
    comment_hash instead - see settle_mint), so a WALLET-chosen id colliding
    with that payment_hash must still reject, generically, rather than dying
    on the notes-table PK constraint with an ugly internal-error 500."""
    victim_k1 = mint_note(VICTIM_AMOUNT)
    victim_note_id = sha256(bytes.fromhex(victim_k1)).hexdigest()  # = comment_hash, the note's real id
    victim_ph = sha256(node.last_preimage).hexdigest()  # the underlying invoice's payment_hash
    # materialize the note (mints settle lazily, on first resolution)
    assert client.get(f"/w?k1={victim_k1}").json()["maxWithdrawable"] == VICTIM_AMOUNT
    assert notes.mint_settled(victim_ph) is True

    attacker_k1 = mint_note(PLANT_AMOUNT)
    resp = client.get(f"/w/cb?k1={attacker_k1}&p1={victim_ph}")
    _assert_squat_rejected(resp, attacker_k1)
    # the victim's real note is untouched
    assert notes.note_amount(victim_note_id) == VICTIM_AMOUNT


def test_legitimate_ids_still_pass_the_guard(client: TestClient, node, mint_note):
    """No false positives: fresh WALLET-generated h/h2 (the honest flow)
    rotate, split and merge exactly as before the guard existed."""
    k1 = mint_note(PLANT_AMOUNT)
    _, h = fresh_secret()
    assert client.get(f"/w/cb?k1={k1}&p1={h}").json()["status"] == "OK"
    assert notes.note_amount(h) == PLANT_AMOUNT

    k1b, k1c = mint_note(6000), mint_note(4000)
    _, hm = fresh_secret()
    assert client.get(f"/w/cb?k1={k1b}&k1={k1c}&p1={hm}").json()["status"] == "OK"
    assert notes.note_amount(hm) == 10_000

    k1d = mint_note(PLANT_AMOUNT)
    _, hs, _, hs2 = *fresh_secret(), *fresh_secret()
    assert client.get(f"/w/cb?k1={k1d}&amount=4000&p1={hs}&p2={hs2}").json()["status"] == "OK"
    assert notes.note_amount(hs) == 4000
    assert notes.note_amount(hs2) == PLANT_AMOUNT - 4000
