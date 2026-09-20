from fastapi.testclient import TestClient

from lnurl_mint.config import settings
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
