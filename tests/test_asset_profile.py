from fastapi.testclient import TestClient

from lnurl_mint.config import Settings, settings
from tests.conftest import fake_invoice, fresh_secret


def note_value(client: TestClient, k1: str) -> int | None:
    data = client.get(f"/w?k1={k1}").json()
    return data.get("maxWithdrawable") if data.get("status") != "ERROR" else None


# --- MELT_ENABLED -----------------------------------------------------------


def test_melt_allowed_by_default(client: TestClient, mint_note):
    k1 = mint_note(5000)
    assert client.get(f"/w/cb?k1={k1}&pr={fake_invoice(5000)}").json()["status"] == "OK"


def test_melt_disabled_rejects_before_decoding_the_invoice(client: TestClient, mint_note, monkeypatch):
    monkeypatch.setattr(settings, "melt_enabled", False)
    k1 = mint_note(5000)
    # an unparseable pr would otherwise fail with "Invalid invoice" - the
    # switch answers first, so no invoice is ever decoded, reserved or paid
    assert client.get(f"/w/cb?k1={k1}&pr=not-an-invoice").json() == {"status": "ERROR", "reason": "melt disabled"}
    assert client.get(f"/w/cb?k1={k1}&pr={fake_invoice(5000)}").json() == {
        "status": "ERROR",
        "reason": "melt disabled",
    }
    # nothing was reserved: the note is still outstanding and rotates fine
    assert note_value(client, k1) == 5000
    new_k1, h = fresh_secret()
    assert client.get(f"/w/cb?k1={k1}&p1={h}").json()["status"] == "OK"
    assert note_value(client, new_k1) == 5000


# --- MUTATIONS --------------------------------------------------------------


def test_mutations_default_allows_all_three(client: TestClient, mint_note):
    a, b = mint_note(3000), mint_note(2000)
    _, h = fresh_secret()
    assert client.get(f"/w/cb?k1={a}&k1={b}&p1={h}").json()["status"] == "OK"


def test_mutations_rotate_only_refuses_split_and_merge(client: TestClient, mint_note, monkeypatch):
    monkeypatch.setattr(settings, "mutations", "rotate")
    a, b = mint_note(3000), mint_note(2000)
    _, h = fresh_secret()
    _, h2 = fresh_secret()
    assert client.get(f"/w/cb?k1={a}&amount=1000&p1={h}&p2={h2}").json() == {
        "status": "ERROR",
        "reason": "split disabled",
    }
    assert client.get(f"/w/cb?k1={a}&k1={b}&p1={h}").json() == {"status": "ERROR", "reason": "merge disabled"}
    # a multi-k1 split is a split, not a merge, per the spec's own table
    assert client.get(f"/w/cb?k1={a}&k1={b}&amount=1000&p1={h}&p2={h2}").json() == {
        "status": "ERROR",
        "reason": "split disabled",
    }
    # nothing above touched the store
    assert note_value(client, a) == 3000
    assert note_value(client, b) == 2000
    new_a, h = fresh_secret()
    assert client.get(f"/w/cb?k1={a}&p1={h}").json()["status"] == "OK"
    assert note_value(client, new_a) == 3000


def test_mutations_can_refuse_rotate(client: TestClient, mint_note, monkeypatch):
    monkeypatch.setattr(settings, "mutations", "split,merge")
    k1 = mint_note(5000)
    _, h = fresh_secret()
    assert client.get(f"/w/cb?k1={k1}&p1={h}").json() == {"status": "ERROR", "reason": "rotate disabled"}


def test_mutations_setting_rejects_unknown_entries():
    try:
        Settings(base_url="http://testserver", mutations="rotate,burn")
    except ValueError as exc:
        assert "burn" in str(exc)
    else:
        raise AssertionError("an unknown mutation should not validate")
    assert Settings(base_url="http://testserver", mutations=" merge , rotate ").allowed_mutations() == {
        "rotate",
        "merge",
    }
    assert Settings(base_url="http://testserver", mutations="").allowed_mutations() == set()
