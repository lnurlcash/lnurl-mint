"""Backwards compatibility for a WALLET built against a pre-rename mint:
`h`/`h2` (the callback's replacement-note hashes) and `h` (the
informational GET's hash-lookup) are the spec's old names for what is now
`p1`/`p2`/`p` - still accepted, equivalent in every way, just an older
spelling. See router.get_withdraw/get_withdraw_callback."""

from fastapi.testclient import TestClient

from tests.conftest import fresh_secret, k1_id


def test_informational_get_accepts_legacy_h(client: TestClient, mint_note):
    k1 = mint_note(5000)
    note_id = k1_id(k1)
    by_p = client.get(f"/w?p={note_id}").json()
    by_h = client.get(f"/w?h={note_id}").json()
    assert by_h == by_p
    assert by_h["maxWithdrawable"] == 5000


def test_informational_get_prefers_p_when_both_given(client: TestClient, mint_note):
    k1 = mint_note(5000)
    note_id = k1_id(k1)
    # a bogus h alongside a valid p: p must win, not error or use h
    data = client.get(f"/w?p={note_id}&h={'0' * 64}").json()
    assert data["maxWithdrawable"] == 5000


def test_rotate_accepts_legacy_h(client: TestClient, mint_note):
    k1 = mint_note(5000)
    new_k1, h = fresh_secret()
    data = client.get(f"/w/cb?k1={k1}&h={h}").json()
    assert data["status"] == "OK"
    assert client.get(f"/w?k1={new_k1}").json()["maxWithdrawable"] == 5000


def test_split_accepts_legacy_h_and_h2(client: TestClient, mint_note):
    k1 = mint_note(5000)
    out_k1, h = fresh_secret()
    change_k1, h2 = fresh_secret()
    data = client.get(f"/w/cb?k1={k1}&amount=2000&h={h}&h2={h2}").json()
    assert data["status"] == "OK"
    assert client.get(f"/w?k1={out_k1}").json()["maxWithdrawable"] == 2000
    assert client.get(f"/w?k1={change_k1}").json()["maxWithdrawable"] == 3000


def test_merge_accepts_legacy_h(client: TestClient, mint_note):
    k1a = mint_note(2000)
    k1b = mint_note(3000)
    out_k1, h = fresh_secret()
    data = client.get(f"/w/cb?k1={k1a}&k1={k1b}&h={h}").json()
    assert data["status"] == "OK"
    assert client.get(f"/w?k1={out_k1}").json()["maxWithdrawable"] == 5000


def test_callback_prefers_p1_when_both_given(client: TestClient, mint_note):
    k1 = mint_note(5000)
    new_k1, p1_hash = fresh_secret()
    _, bogus_h = fresh_secret()
    data = client.get(f"/w/cb?k1={k1}&p1={p1_hash}&h={bogus_h}").json()
    assert data["status"] == "OK"
    # the note landed under p1, not the bogus h
    assert client.get(f"/w?k1={new_k1}").json()["maxWithdrawable"] == 5000


def test_retry_replay_matches_regardless_of_which_spelling_was_used(client: TestClient, mint_note):
    """LUD-25's Retrying a mutation must still recognize a retried request
    as the same burn whether it arrives spelled as p1 or the legacy h."""
    k1 = mint_note(5000)
    new_k1, h = fresh_secret()
    first = client.get(f"/w/cb?k1={k1}&h={h}").json()
    assert first["status"] == "OK"
    retry = client.get(f"/w/cb?k1={k1}&p1={h}").json()
    assert retry == first
