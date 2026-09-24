import sqlite3
from hashlib import sha256

import bolt11
from fastapi.testclient import TestClient

from lnurl_mint.config import settings
from lnurl_mint.db import NoteStore, notes
from tests.conftest import fake_invoice, fresh_secret, k1_id, melt_in_background


def test_verify_url_absent_by_default(client: TestClient):
    data = client.get("/p/cb?amount=5000").json()
    assert "verify" not in data


def test_verify_url_advertised_when_enabled(client: TestClient, node, monkeypatch):
    monkeypatch.setattr(settings, "verify_enabled", True)
    # verify is only advertised for a mint that used LUD-25 comment
    # protection - see test_verify_url_absent_without_comment below
    _, comment = fresh_secret()
    data = client.get(f"/p/cb?amount=5000&comment={comment}").json()
    payment_hash = sha256(node.last_preimage).hexdigest()
    assert data["verify"] == f"http://testserver/verify/{payment_hash}"


def test_verify_url_absent_without_comment(client: TestClient, node, monkeypatch):
    # per LUD-25's Security considerations, SERVICE MUST NOT offer verify
    # in the no-comment fallback: there the preimage IS the note's entire
    # bearer secret, and verify would hand it to anyone holding the URL
    monkeypatch.setattr(settings, "verify_enabled", True)
    data = client.get("/p/cb?amount=5000").json()
    assert "verify" not in data
    payment_hash = sha256(node.last_preimage).hexdigest()
    assert client.get(f"/verify/{payment_hash}").json() == {"status": "ERROR", "reason": "Not found"}
    node.settled.add(payment_hash)
    # ...even after settlement, when the preimage would otherwise be served
    assert client.get(f"/verify/{payment_hash}").json() == {"status": "ERROR", "reason": "Not found"}


def test_verify_reports_unsettled_before_payment(client: TestClient, node, monkeypatch):
    monkeypatch.setattr(settings, "verify_enabled", True)
    _, comment = fresh_secret()
    data = client.get(f"/p/cb?amount=5000&comment={comment}").json()
    payment_hash = sha256(node.last_preimage).hexdigest()

    result = client.get(f"/verify/{payment_hash}").json()
    assert result == {"status": "OK", "settled": False, "pr": data["pr"]}
    assert "preimage" not in result


def test_verify_reports_settled_after_payment(client: TestClient, node, monkeypatch):
    monkeypatch.setattr(settings, "verify_enabled", True)
    _, comment = fresh_secret()
    data = client.get(f"/p/cb?amount=5000&comment={comment}").json()
    payment_hash = sha256(node.last_preimage).hexdigest()
    node.settled.add(payment_hash)

    result = client.get(f"/verify/{payment_hash}").json()
    assert result == {"status": "OK", "settled": True, "pr": data["pr"], "preimage": node.last_preimage.hex()}


def test_verify_withholds_the_preimage_before_settlement(client: TestClient, node, monkeypatch):
    monkeypatch.setattr(settings, "verify_enabled", True)
    # plain LUD-21 behavior, orthogonal to comment protection: the
    # preimage is only handed over once settled, so an unsettled invoice's
    # verify response must not leak it even though the node already knows it
    _, comment = fresh_secret()
    client.get(f"/p/cb?amount=5000&comment={comment}")
    payment_hash = sha256(node.last_preimage).hexdigest()

    body = client.get(f"/verify/{payment_hash}").text
    assert node.last_preimage.hex() not in body
    assert "preimage" not in body


def test_verify_unknown_payment_hash_is_not_found(client: TestClient, monkeypatch):
    monkeypatch.setattr(settings, "verify_enabled", True)
    bogus = "00" * 32
    result = client.get(f"/verify/{bogus}").json()
    assert result == {"status": "ERROR", "reason": "Not found"}


def test_verify_stays_settled_after_the_note_is_spent(client: TestClient, node, monkeypatch):
    monkeypatch.setattr(settings, "verify_enabled", True)
    # LUD-21 verify answers "was this invoice ever paid", not "is there a
    # spendable note right now" - those diverge once the note is rotated,
    # but the preimage - fetched live from the node, never cached - is
    # still handed back regardless, since the node retains it indefinitely.
    # Comment protection (LUD-25) is what gets verify served here at all
    # (see get_pay_callback) - the note's actual k1 is `secret`, not the
    # preimage this test checks verify keeps reporting.
    secret, comment = fresh_secret()
    resp = client.get(f"/p/cb?amount=5000&comment={comment}")
    assert resp.json()["pr"]
    preimage = node.last_preimage.hex()
    payment_hash = sha256(node.last_preimage).hexdigest()
    node.settled.add(payment_hash)

    result = client.get(f"/verify/{payment_hash}").json()
    assert result["settled"] is True
    assert result["preimage"] == preimage

    _, h = fresh_secret()
    rotated = client.get(f"/w/cb?k1={secret}&p1={h}").json()
    assert rotated["status"] == "OK"

    result = client.get(f"/verify/{payment_hash}").json()
    assert result["settled"] is True
    assert result["preimage"] == preimage


def test_verify_endpoint_is_disabled_entirely_when_verify_enabled_is_false(client: TestClient, node):
    # VERIFY_ENABLED=false is a real off switch, not just a hidden URL:
    # the endpoint 404s even when hit directly with a known payment_hash -
    # deliberately unlike the usual LUD-21 convention, because for a mint
    # the settled response's preimage IS the bearer note's spend secret
    # (see router.verify_invoice), so an operator unwilling to serve it to
    # any invoice holder can turn it off for good
    assert settings.verify_enabled is False
    data = client.get("/p/cb?amount=5000").json()
    assert "verify" not in data
    payment_hash = sha256(node.last_preimage).hexdigest()
    assert client.get(f"/verify/{payment_hash}").json() == {"status": "ERROR", "reason": "Not found"}
    # ...even after settlement, when the preimage would be served
    node.settled.add(payment_hash)
    assert client.get(f"/verify/{payment_hash}").json() == {"status": "ERROR", "reason": "Not found"}


def test_melt_response_carries_no_verify_by_default(client: TestClient, node, mint_note):
    # verify_enabled is False in the test env (see conftest) - a melt's
    # response must stay a bare {"status": "OK"}, same as before LUD-25's
    # melt verify existed
    k1 = mint_note(5000)
    pr = fake_invoice(5000)
    assert client.get(f"/w/cb?k1={k1}&pr={pr}").json() == {"status": "OK"}


def test_melt_response_carries_pr_and_verify_url_when_enabled(client: TestClient, node, mint_note, monkeypatch):
    monkeypatch.setattr(settings, "verify_enabled", True)
    k1 = mint_note(5000)
    pr = fake_invoice(5000)
    payment_hash = bolt11.decode(pr).payment_hash
    data = client.get(f"/w/cb?k1={k1}&pr={pr}").json()
    assert data["pr"] == pr
    assert data["verify"] == f"http://testserver/verify/{payment_hash}"


def test_melt_verify_reports_settled_and_a_matching_preimage_once_paid(
    client: TestClient, node, mint_note, monkeypatch
):
    # the preimage handed back here is proof of the *outgoing* payment's own
    # settlement, not a bearer secret - the note(s) that funded the melt are
    # already burned by the time anyone could use it
    monkeypatch.setattr(settings, "verify_enabled", True)
    k1 = mint_note(5000)
    pr = fake_invoice(5000)
    node.payment_actually_completed = True  # the node's own view: this payment settled
    data = client.get(f"/w/cb?k1={k1}&pr={pr}").json()

    payment_hash = bolt11.decode(pr).payment_hash
    result = client.get(data["verify"]).json()
    assert result["status"] == "OK"
    assert result["settled"] is True
    assert result["pr"] == pr
    assert result["preimage"] == node.melt_preimages[payment_hash].hex()


def test_melt_verify_reports_unsettled_while_genuinely_pending(client: TestClient, node, mint_note, monkeypatch):
    """Real in-flight state (not just an artificial FakeNode flag): the
    melt has been accepted and its note marked pending, but pay_invoice
    hasn't returned yet - see conftest.melt_in_background, since a single
    TestClient call otherwise blocks until the whole request (background
    task included) is done, leaving no other way to observe this window."""
    monkeypatch.setattr(settings, "verify_enabled", True)
    k1 = mint_note(5000)
    pr = fake_invoice(5000)
    payment_hash = bolt11.decode(pr).payment_hash
    node.pay_delay = 0.3

    thread = melt_in_background(client, k1, pr, monkeypatch)
    result = client.get(f"/verify/{payment_hash}").json()
    assert result == {"status": "OK", "settled": False, "pr": pr}
    assert "preimage" not in result
    thread.join()
    assert thread.result["melt"]["status"] == "OK"  # type: ignore[attr-defined]


def test_melt_verify_reports_settled_immediately_once_finalized_even_if_the_node_lags(
    client: TestClient, node, mint_note, monkeypatch
):
    """The bug this closes: once _melt_pay finalizes a melt (pay_invoice
    itself already succeeded), verify must report settled right away via
    NoteStore.mark_melt_settled - not by re-asking the funding source,
    which right after a payment lands can still lag or answer
    inconsistently. Pinned here by leaving node.payment_actually_completed
    at its default False: a live is_payment_complete call would report
    unsettled, but the melt already completed and the note is spent."""
    monkeypatch.setattr(settings, "verify_enabled", True)
    k1 = mint_note(5000)
    pr = fake_invoice(5000)
    payment_hash = bolt11.decode(pr).payment_hash
    data = client.get(f"/w/cb?k1={k1}&pr={pr}").json()
    assert data["status"] == "OK"
    assert notes.note_spent(k1_id(k1)) is True

    assert node.payment_actually_completed is False  # the node's own live view lags
    result = client.get(f"/verify/{payment_hash}").json()
    assert result["settled"] is True


def test_melt_verify_is_also_disabled_when_verify_enabled_is_false(client: TestClient, node, mint_note):
    # the same off switch covers the melt direction: the melts row is still
    # recorded (cheap, and the endpoint simply serves recordings while on),
    # but /verify 404s regardless
    assert settings.verify_enabled is False
    k1 = mint_note(5000)
    pr = fake_invoice(5000)
    node.payment_actually_completed = True
    data = client.get(f"/w/cb?k1={k1}&pr={pr}").json()
    assert "verify" not in data

    payment_hash = bolt11.decode(pr).payment_hash
    assert client.get(f"/verify/{payment_hash}").json() == {"status": "ERROR", "reason": "Not found"}


def test_mints_table_migrates_from_before_lud21(tmp_path):
    # a database from before this feature has a `mints` table with no `pr`
    # column - this mint has no migration framework, and telling an
    # operator to just delete their database isn't acceptable when it
    # holds real outstanding notes, so the column must be added by hand
    db_path = str(tmp_path / "pre-lud21.db")
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE mints (payment_hash TEXT PRIMARY KEY, amount_msat INTEGER NOT NULL,"
        " minted INTEGER NOT NULL DEFAULT 0)"
    )
    conn.execute("INSERT INTO mints (payment_hash, amount_msat) VALUES ('deadbeef', 5000)")
    conn.commit()
    conn.close()

    store = NoteStore(db_path)
    assert store.pending_mint("deadbeef") == 5000
    assert store.mint_pr("deadbeef") == ""
    store.create_mint("newhash", "lnbcrt1...", 3000, "note-new")
    assert store.mint_pr("newhash") == "lnbcrt1..."


def test_melts_table_migrates_from_before_mark_melt_settled(tmp_path):
    # a database from before mark_melt_settled has a `melts` table with no
    # `settled` column - existing rows predate it entirely, and must default
    # to 0 (router._melt_settled then falls back to a live check for them,
    # same as it always did)
    db_path = str(tmp_path / "pre-settled.db")
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE melts (payment_hash TEXT PRIMARY KEY, pr TEXT NOT NULL)")
    conn.execute("INSERT INTO melts (payment_hash, pr) VALUES ('deadbeef', 'lnbcrt1...')")
    conn.commit()
    conn.close()

    store = NoteStore(db_path)
    assert store.melt_pr("deadbeef") == "lnbcrt1..."
    assert store.melt_settled("deadbeef") is False
    store.mark_melt_settled("deadbeef")
    assert store.melt_settled("deadbeef") is True


def test_note_columns_are_renamed(tmp_path):
    # a database from before these columns were renamed kept a mint's note
    # in `comment_hash` and a burn's outputs in `h`/`h2` -
    # the same hex(Q) values, carried over by a plain column rename
    db_path = str(tmp_path / "pre-cp1.db")
    q, q2, q3 = "aa" * 32, "bb" * 32, "cc" * 32
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE notes (id TEXT PRIMARY KEY, amount_msat INTEGER NOT NULL,"
        " spent INTEGER NOT NULL DEFAULT 0, pending INTEGER NOT NULL DEFAULT 0, pending_payment_hash TEXT)"
    )
    conn.execute(
        "CREATE TABLE mints (payment_hash TEXT PRIMARY KEY, pr TEXT NOT NULL, amount_msat INTEGER NOT NULL,"
        " minted INTEGER NOT NULL DEFAULT 0, comment_hash TEXT)"
    )
    conn.execute(
        "CREATE TABLE burns (burn_key TEXT PRIMARY KEY, h TEXT NOT NULL, h2 TEXT,"
        " amount1_msat INTEGER NOT NULL, amount2_msat INTEGER)"
    )
    conn.execute("INSERT INTO notes (id, amount_msat) VALUES (?, 2000)", (q,))
    conn.execute(
        "INSERT INTO mints (payment_hash, pr, amount_msat, comment_hash) VALUES ('ph', 'lnbcrt1...', 3000, ?)", (q2,)
    )
    conn.execute("INSERT INTO burns (burn_key, h, h2, amount1_msat, amount2_msat) VALUES ('old', ?, ?, 1, 2)", (q3, q))
    conn.commit()
    conn.close()

    store = NoteStore(db_path)
    columns = {t: {r[1] for r in store.conn.execute(f"PRAGMA table_info({t})")} for t in ("notes", "mints", "burns")}
    assert "id" in columns["notes"] and "cp1" not in columns["notes"]
    assert "note_id" in columns["mints"] and "comment_hash" not in columns["mints"]
    assert {"id", "id2"} <= columns["burns"] and not {"h", "h2"} & columns["burns"]
    assert store.note_amount(q) == 2000
    assert store.pending_mint_by_note_id(q2) == ("ph", 3000)
    assert store.find_burn(["old"]) == (q3, q, 1, 2)
    # and opening it again is a no-op
    assert NoteStore(db_path).note_amount(q) == 2000


def test_outstanding_msat_is_zero_for_a_fresh_store(tmp_path):
    store = NoteStore(str(tmp_path / "notes.db"))
    assert store.outstanding_msat() == 0


def test_outstanding_msat_sums_every_materialized_note(tmp_path):
    store = NoteStore(str(tmp_path / "notes.db"))
    store.create_mint("hash-a", "lnbcrt1...", 2000, "note-a")
    store.settle_mint("hash-a")
    store.create_mint("hash-b", "lnbcrt1...", 3000, "note-b")
    store.settle_mint("hash-b")
    assert store.outstanding_msat() == 5000


def test_outstanding_msat_ignores_a_settled_mint_never_materialized(tmp_path):
    # only counts notes actually looked up at least once (settle_mint is
    # what materializes the `mints` row into a `notes` row - see
    # NoteStore.outstanding_msat's own docstring for why)
    store = NoteStore(str(tmp_path / "notes.db"))
    store.create_mint("hash-a", "lnbcrt1...", 2000, "note-a")
    assert store.outstanding_msat() == 0


def test_outstanding_msat_includes_a_pending_note(tmp_path):
    # a note reserved by an in-flight melt (mark_pending) is still
    # outstanding until its melt actually settles - per LUD-25, SERVICE
    # MUST NOT burn it until then
    store = NoteStore(str(tmp_path / "notes.db"))
    store.create_mint("hash-a", "lnbcrt1...", 2000, "note-a")
    store.settle_mint("hash-a")
    store.mark_pending(["note-a"], "melt-payment-hash")
    assert store.outstanding_msat() == 2000


def test_outstanding_msat_survives_a_swap(tmp_path):
    # a rotate/split/merge (NoteStore.swap) burns one set of notes and
    # mints another - the total should reflect the new note(s), not the
    # burned one(s), and stay the same when their combined value doesn't
    # change (a plain rotate)
    store = NoteStore(str(tmp_path / "notes.db"))
    store.create_mint("hash-a", "lnbcrt1...", 2000, "note-a")
    store.settle_mint("hash-a")
    store.swap(["note-a"], ["new-hash"], [2000])
    assert store.outstanding_msat() == 2000


def test_outstanding_msat_drops_after_finalize_melt(tmp_path):
    # unlike a swap, a melt (finalize_melt) burns a note with no
    # replacement - the total must actually go down
    store = NoteStore(str(tmp_path / "notes.db"))
    store.create_mint("hash-a", "lnbcrt1...", 2000, "note-a")
    store.settle_mint("hash-a")
    store.create_mint("hash-b", "lnbcrt1...", 3000, "note-b")
    store.settle_mint("hash-b")
    store.finalize_melt(["note-a"])
    assert store.outstanding_msat() == 3000
