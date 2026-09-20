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


# --- GET /nft/{id} ----------------------------------------------------------


def test_nft_lookup_is_off_by_default(client: TestClient, mint_note):
    k1 = mint_note(5000)
    assert note_value(client, k1) == 5000
    from hashlib import sha256

    genesis = sha256(bytes.fromhex(k1)).hexdigest()
    assert client.get(f"/nft/{genesis}").json() == {"status": "ERROR", "reason": "Not found"}


def test_nft_lookup_rejects_a_malformed_id(client: TestClient, monkeypatch):
    monkeypatch.setattr(settings, "nft_lookup_enabled", True)
    assert client.get("/nft/zzz").json()["status"] == "ERROR"
    assert client.get(f"/nft/{'00' * 32}").json() == {"status": "ERROR", "reason": "Not found"}


def test_nft_lookup_follows_rotates_to_the_current_holder(client: TestClient, mint_note, monkeypatch):
    monkeypatch.setattr(settings, "nft_lookup_enabled", True)
    monkeypatch.setattr(settings, "mutations", "rotate")
    from hashlib import sha256

    k1 = mint_note(1_000_000)
    genesis = sha256(bytes.fromhex(k1)).hexdigest()
    # straight after settlement, before any lookup materialized the note
    assert client.get(f"/nft/{genesis}").json() == {
        "status": "OK",
        "holder": genesis,
        "hops": 0,
        "outstanding": True,
    }
    current = k1
    holders = [genesis]
    for _ in range(3):
        new_k1, h = fresh_secret()
        assert client.get(f"/w/cb?k1={current}&p1={h}").json()["status"] == "OK"
        current = new_k1
        holders.append(h)
    assert client.get(f"/nft/{genesis}").json() == {
        "status": "OK",
        "holder": holders[-1],
        "hops": 3,
        "outstanding": True,
    }
    # any id on the chain is a valid starting point, not only the genesis
    assert client.get(f"/nft/{holders[1]}").json()["hops"] == 2
    # a cp1-shaped id decodes to the same 32 bytes and walks the same chain
    from lnurl_mint.bech32m import encode_cp1

    assert client.get(f"/nft/{encode_cp1(bytes.fromhex(genesis))}").json()["holder"] == holders[-1]


def test_nft_lookup_reports_a_melted_descendant_as_not_outstanding(client: TestClient, mint_note, node, monkeypatch):
    monkeypatch.setattr(settings, "nft_lookup_enabled", True)
    from hashlib import sha256

    k1 = mint_note(5000)
    genesis = sha256(bytes.fromhex(k1)).hexdigest()
    new_k1, h = fresh_secret()
    assert client.get(f"/w/cb?k1={k1}&p1={h}").json()["status"] == "OK"
    assert client.get(f"/w/cb?k1={new_k1}&pr={fake_invoice(5000)}").json()["status"] == "OK"
    assert client.get(f"/nft/{genesis}").json() == {"status": "OK", "holder": h, "hops": 1, "outstanding": False}


def test_nft_lookup_stops_at_a_split_or_merge(client: TestClient, mint_note, monkeypatch):
    monkeypatch.setattr(settings, "nft_lookup_enabled", True)
    from hashlib import sha256

    k1 = mint_note(5000)
    genesis = sha256(bytes.fromhex(k1)).hexdigest()
    _, h = fresh_secret()
    _, h2 = fresh_secret()
    assert client.get(f"/w/cb?k1={k1}&amount=2000&p1={h}&p2={h2}").json()["status"] == "OK"
    # None fields are excluded on the wire (see error_handler's route class)
    assert client.get(f"/nft/{genesis}").json() == {
        "status": "OK",
        "hops": 0,
        "outstanding": False,
        "reason": "diverged",
    }

    a, b = mint_note(3000), mint_note(2000)
    genesis_a = sha256(bytes.fromhex(a)).hexdigest()
    _, merged = fresh_secret()
    assert client.get(f"/w/cb?k1={a}&k1={b}&p1={merged}").json()["status"] == "OK"
    assert client.get(f"/nft/{genesis_a}").json()["reason"] == "diverged"
