"""PoC for A3 (auth-data lane): "NoteStore.mark_pending validates only
k1s[0]; later k1s go unvalidated, so restore()/finalize_melt() can hit ids
that were never outstanding." **FALSIFIED** on two independent grounds.

1. The premise does not match the code. mark_pending (db.py:214-235) is two
   loops: the FIRST validates every note_id (each must exist, be unspent, and
   not be pending - db.py:226-231) before the SECOND writes anything
   (db.py:232-235). A garbage id at ANY position aborts the whole
   reservation; nothing is marked. (No revision of db.py in git history ever
   had the single-id `WHERE id IN (...)` shape the candidate describes.)
2. Unreachable via HTTP anyway: the only caller is the melt path
   (router.py:607), and melts reject multiple k1s outright
   (router.py:562-565) - note_ids is always a 1-element list.

The residual sharp edge is real but not a vulnerability: finalize_melt and
restore are blind UPDATEs with no rowcount check (db.py:237-255) - they trust
their caller. The control test below shows finalize_melt WILL silently burn a
never-reserved outstanding note if handed one directly, i.e. mark_pending's
validation is the only line of defense. It holds today, and both _melt_pay
(router.py:87-149) and reconcile_pending_melts (router.py:152-190) only ever
pass ids that mark_pending accepted.
"""

from hashlib import sha256

import pytest
from fastapi.testclient import TestClient

from lnurl_mint.db import PendingNoteError, notes
from tests.conftest import fake_invoice, fresh_secret

GARBAGE_ID = "ff" * 32  # well-formed note id that was never minted


def _note_id(k1: str) -> str:
    return sha256(bytes.fromhex(k1)).hexdigest()


def _materialize(client: TestClient, k1: str) -> str:
    """mint_note only settles the invoice at the fake node - the notes row
    itself materializes lazily on first resolution (router._mint_settled), so
    resolve it once to give mark_pending a real outstanding row to validate."""
    body = client.get(f"/w?k1={k1}").json()
    assert body.get("tag") == "withdrawRequest", body
    return _note_id(k1)


def _is_pending(note_id: str) -> bool:
    row = notes.conn.execute("SELECT pending FROM notes WHERE id = ?", (note_id,)).fetchone()
    return bool(row and row[0])


def test_a3_http_melt_rejects_multiple_k1s_before_any_reservation(client: TestClient, node, mint_note):
    """Ground 2: a melt can never even reach mark_pending with >1 k1."""
    k1a, k1b = mint_note(10_000), mint_note(10_000)
    pr = fake_invoice(20_000)
    resp = client.get(f"/w/cb?k1={k1a}&k1={k1b}&pr={pr}")
    assert resp.json()["status"] == "ERROR", resp.text
    assert "cannot be combined" in resp.json()["reason"]
    # both notes remain fully spendable - nothing was reserved
    assert _is_pending(_note_id(k1a)) is False
    assert _is_pending(_note_id(k1b)) is False
    _, h = fresh_secret()
    assert client.get(f"/w/cb?k1={k1a}&p1={h}").json()["status"] == "OK"


def test_a3_mark_pending_validates_every_id_at_any_position(client: TestClient, node, mint_note):
    """Ground 1: a garbage id anywhere in the list aborts the whole
    reservation - and marks nothing, not even the valid ids."""
    real_k1 = mint_note(10_000)
    real_id = _materialize(client, real_k1)
    ph = sha256(b"a3-test-payment").hexdigest()

    # garbage LAST: the described bug shape would reserve real_id and skip
    # validating the rest - instead the whole call aborts
    with pytest.raises(ValueError, match="Invalid or already spent k1"):
        notes.mark_pending([real_id, GARBAGE_ID], ph)
    assert _is_pending(real_id) is False  # NOT silently reserved

    # garbage FIRST: same abort
    with pytest.raises(ValueError, match="Invalid or already spent k1"):
        notes.mark_pending([GARBAGE_ID, real_id], ph)
    assert _is_pending(real_id) is False

    # a SPENT id anywhere also aborts (rotate a note away, then try it)
    spent_k1 = mint_note(10_000)
    spent_id = _materialize(client, spent_k1)
    _, h = fresh_secret()
    assert client.get(f"/w/cb?k1={spent_k1}&p1={h}").json()["status"] == "OK"
    with pytest.raises(ValueError, match="Invalid or already spent k1"):
        notes.mark_pending([real_id, spent_id], ph)
    assert _is_pending(real_id) is False

    # and an already-pending id anywhere aborts with PendingNoteError,
    # leaving the earlier ids untouched
    other_id = _materialize(client, mint_note(10_000))
    notes.mark_pending([other_id], ph)  # valid single reservation
    with pytest.raises(PendingNoteError):
        notes.mark_pending([real_id, other_id], ph)
    assert _is_pending(real_id) is False
    notes.restore([other_id])  # cleanup: release the valid reservation

    # sanity: the real note still rotates fine - nothing above reserved it
    _, h2 = fresh_secret()
    assert client.get(f"/w/cb?k1={real_k1}&p1={h2}").json()["status"] == "OK"


def test_a3_finalize_and_restore_on_never_reserved_ids_are_noops_for_unknown_ids():
    """The blind-UPDATE tail of the candidate: finalize/restore don't verify
    prior state - shown here to be harmless for unknown ids (0 rows match),
    with the control that proves WHY mark_pending's validation matters."""
    # unknown ids: both are silent no-ops, no row appears, nothing is spent
    notes.finalize_melt([GARBAGE_ID])
    assert notes.note_spent(GARBAGE_ID) is False
    notes.restore([GARBAGE_ID])
    assert notes.note_amount(GARBAGE_ID) is None

    # control: finalize_melt WILL burn a never-reserved *outstanding* note if
    # handed one directly - it has no defense of its own. Unreachable today
    # (every caller passes ids mark_pending accepted; every id there was
    # validated), so this is a code-fragility note, not a vulnerability.
    k1_secret, _ = fresh_secret()
    outstanding_id = _note_id(k1_secret)
    notes.conn.execute("INSERT INTO notes (id, amount_msat) VALUES (?, ?)", (outstanding_id, 10_000))
    notes.conn.commit()
    notes.finalize_melt([outstanding_id])
    assert notes.note_spent(outstanding_id) is True  # burned without ever being pending
