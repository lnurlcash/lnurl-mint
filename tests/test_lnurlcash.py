import json
from hashlib import sha256
from os import urandom

from fastapi.testclient import TestClient

import lnurl_mint.router as router_module
from lnurl_mint.config import settings
from lnurl_mint.db import notes
from tests.conftest import FakeNode, bearer_id, fake_invoice, fresh_secret, k1_hash, k1_id
from tests.conftest import melt_in_background as _melt_in_background


def note_value(client: TestClient, k1: str) -> int | None:
    """Read a note's value the authoritative way: a (repeatable,
    non-consuming) GET on its LNURL, per the spec."""
    data = client.get(f"/w?k1={k1}").json()
    if data.get("status") == "ERROR":
        return None
    assert data["minWithdrawable"] == data["maxWithdrawable"]
    return data["maxWithdrawable"]


def test_pay_request_advertises_withdraw_link(client: TestClient):
    data = client.get(f"/.well-known/lnurlp/{settings.username}").json()
    assert data["tag"] == "payRequest"
    assert data["withdrawLink"] == "http://testserver/w"
    assert data["minSendable"] <= data["maxSendable"]


def test_paid_invoice_secret_becomes_a_bearer_note(client: TestClient, node: FakeNode):
    secret, comment = fresh_secret()
    response = client.get(f"/p/cb?amount=5000&comment={comment}")
    assert response.json()["pr"]

    # not settled yet - not a note
    assert note_value(client, secret) is None

    node.settled.add(sha256(node.last_preimage).hexdigest())
    assert note_value(client, secret) == 5000
    # the informational GET never consumes the note
    assert note_value(client, secret) == 5000


def test_pay_callback_advertises_the_lnaddress_as_not_disposable(client: TestClient, node: FakeNode):
    # LUD-11: this mint's payRequest/lightning address is a permanent,
    # repeatable way to mint fresh notes, not a one-shot link - a WALLET
    # that doesn't recognize `disposable` at all must otherwise assume
    # `true` and may discard it, so this has to be sent explicitly
    _, comment = fresh_secret()
    response = client.get(f"/p/cb?amount=5000&comment={comment}")
    assert response.json()["disposable"] is False


def test_pay_callback_enforces_sendable_bounds(client: TestClient):
    assert client.get("/p/cb?amount=1").json()["status"] == "ERROR"
    assert client.get("/p/cb?amount=999999999999").json()["status"] == "ERROR"


def test_pay_callback_rejects_while_sunsetting(client: TestClient, monkeypatch):
    monkeypatch.setattr(settings, "sunset_mint", True)
    assert client.get("/p/cb?amount=5000").json()["status"] == "ERROR"


def test_pay_response_omits_mint_fee_when_free(client: TestClient):
    metadata = client.get(f"/.well-known/lnurlp/{settings.username}").json()["metadata"]
    assert "Mint fees:" not in metadata


def test_pay_response_advertises_mint_fee_when_configured(client: TestClient, monkeypatch):
    monkeypatch.setattr(settings, "base_fee_msat", 1000)
    monkeypatch.setattr(settings, "fee_percent_ppm", 2000)
    metadata = client.get(f"/.well-known/lnurlp/{settings.username}").json()["metadata"]
    assert ["text/plain", "Mint fees: 1000,2000"] in json.loads(metadata)


def test_pay_response_advertises_fee_inclusive_min_sendable(client: TestClient, node: FakeNode, monkeypatch):
    # regression: minSendable used to be settings.min_sendable_msat as-is,
    # gross - but _mint_fee_msat is withheld before /p/cb's min_mint_msat
    # check, so paying that advertised minimum bounced whenever the fee ate
    # into it. minSendable must be raised enough that paying exactly that
    # amount nets at least min_mint_msat.
    monkeypatch.setattr(settings, "base_fee_msat", 1000)
    monkeypatch.setattr(settings, "min_mint_msat", 10_000)
    monkeypatch.setattr(settings, "min_sendable_msat", 10_000)

    min_sendable = client.get(f"/.well-known/lnurlp/{settings.username}").json()["minSendable"]
    assert min_sendable == 11000  # 10000 (min_mint_msat) + 1000 (fee)

    secret, comment = fresh_secret()
    response = client.get(f"/p/cb?amount={min_sendable}&comment={comment}")
    assert response.json()["pr"]
    node.settled.add(sha256(node.last_preimage).hexdigest())
    assert note_value(client, secret) == 10000


def test_mint_credits_note_net_of_configured_fee(client: TestClient, node: FakeNode, monkeypatch):
    monkeypatch.setattr(settings, "base_fee_msat", 1000)
    monkeypatch.setattr(settings, "fee_percent_ppm", 2000)  # 0.2%

    secret, comment = fresh_secret()
    client.get(f"/p/cb?amount=100000&comment={comment}")
    node.settled.add(sha256(node.last_preimage).hexdigest())

    # 1000 flat + 0.2% of 100000 = 1000 + 200 = 1200, rounded up to the
    # nearest whole sat (2000) - see test_mint_fee_rounds_up_to_the_nearest_sat
    assert note_value(client, secret) == 100000 - 2000


def test_mint_fee_rounds_up_to_the_nearest_sat(client: TestClient, node: FakeNode, monkeypatch):
    monkeypatch.setattr(settings, "base_fee_msat", 0)
    monkeypatch.setattr(settings, "fee_percent_ppm", 1)  # 0.0001%

    secret, comment = fresh_secret()
    client.get(f"/p/cb?amount=100000000&comment={comment}")
    node.settled.add(sha256(node.last_preimage).hexdigest())

    # 0.0001% of 100000000 = 100 msat (0.1 sat) - rounded up to a full sat
    # (1000 msat) rather than left fractional, so the mint is never short
    assert note_value(client, secret) == 100000000 - 1000


def test_pay_callback_rejects_amount_that_cannot_cover_the_fee(client: TestClient, monkeypatch):
    monkeypatch.setattr(settings, "base_fee_msat", settings.min_sendable_msat + 1)
    result = client.get(f"/p/cb?amount={settings.min_sendable_msat}").json()
    assert result == {
        "status": "ERROR",
        "reason": "Amount too low to mint a note (min 0 msat net of fees).",
    }


def test_pay_callback_rejects_amount_below_min_mint(client: TestClient, monkeypatch):
    # amount clears MIN_SENDABLE_MSAT (the gross, pre-fee bound) but still
    # can't net a note worth MIN_MINT_MSAT once fee-free amount == net
    monkeypatch.setattr(settings, "min_mint_msat", 10_000)
    result = client.get(f"/p/cb?amount={settings.min_sendable_msat}").json()
    assert result == {
        "status": "ERROR",
        "reason": "Amount too low to mint a note (min 10000 msat net of fees).",
    }


def test_mint_succeeds_at_exactly_min_mint(client: TestClient, node: FakeNode, monkeypatch):
    monkeypatch.setattr(settings, "min_mint_msat", 10_000)
    secret, comment = fresh_secret()
    client.get(f"/p/cb?amount=10000&comment={comment}")
    node.settled.add(sha256(node.last_preimage).hexdigest())
    assert note_value(client, secret) == 10000


def test_withdraw_callback_url_ignores_a_spoofed_host_header(client: TestClient, mint_note):
    # regression: callback/verify URLs must come from settings.base_url,
    # never req.url_for (Host-header-derived) - a spoofed Host must not be
    # able to redirect a wallet's mutating callback to an attacker's host
    k1 = mint_note(5000)
    data = client.get(f"/w?k1={k1}", headers={"Host": "evil.example"}).json()
    assert data["callback"] == "http://testserver/w/cb"
    assert "evil.example" not in data["callback"]
    assert "evil.example" not in data["defaultDescription"]


def test_verify_url_ignores_a_spoofed_host_header(client: TestClient, monkeypatch):
    monkeypatch.setattr(settings, "verify_enabled", True)
    # verify is only advertised for a comment-protected mint (LUD-25) - see
    # test_verify.py
    _, comment = fresh_secret()
    data = client.get(f"/p/cb?amount=5000&comment={comment}", headers={"Host": "evil.example"}).json()
    assert data["verify"].startswith("http://testserver/verify/")
    assert "evil.example" not in data["verify"]


def test_rotate_burns_and_replaces_the_note(client: TestClient, mint_note):
    k1 = mint_note(5000)
    new_k1, h = fresh_secret()
    data = client.get(f"/w/cb?k1={k1}&p1={h}").json()
    assert data["status"] == "OK"
    # LUD-25: WALLET generates the replacement itself - this mint has
    # nothing further to hand back for it, just status (+ sig, untested here)
    assert "k1" not in data
    assert note_value(client, k1) is None
    assert note_value(client, new_k1) == 5000


def test_split_mints_amount_and_change(client: TestClient, mint_note):
    k1 = mint_note(5000)
    new_k1, h = fresh_secret()
    change_k1, h2 = fresh_secret()
    data = client.get(f"/w/cb?k1={k1}&amount=2000&p1={h}&p2={h2}").json()
    assert data["status"] == "OK"
    assert note_value(client, k1) is None
    assert note_value(client, new_k1) == 2000
    assert note_value(client, change_k1) == 3000


def test_split_merges_multiple_k1s_first(client: TestClient, mint_note):
    # a split may now name several k1s at once - merge them, then split off
    # `amount`, same as merging first and splitting the result separately
    a, b = mint_note(2000), mint_note(3000)
    new_k1, h = fresh_secret()
    change_k1, h2 = fresh_secret()
    data = client.get(f"/w/cb?k1={a}&k1={b}&amount=1000&p1={h}&p2={h2}").json()
    assert data["status"] == "OK"
    assert note_value(client, a) is None
    assert note_value(client, b) is None
    assert note_value(client, new_k1) == 1000
    assert note_value(client, change_k1) == 4000


def test_split_rejects_amount_out_of_range(client: TestClient, mint_note):
    k1 = mint_note(5000)
    _, h = fresh_secret()
    _, h2 = fresh_secret()
    for amount in (0, 5000, 6000):
        assert client.get(f"/w/cb?k1={k1}&amount={amount}&p1={h}&p2={h2}").json()["status"] == "ERROR"
    assert note_value(client, k1) == 5000


def test_split_rejects_while_sunsetting(client: TestClient, mint_note, monkeypatch):
    k1 = mint_note(5000)
    monkeypatch.setattr(settings, "sunset_mint", True)
    _, h = fresh_secret()
    _, h2 = fresh_secret()
    assert client.get(f"/w/cb?k1={k1}&amount=2000&p1={h}&p2={h2}").json()["status"] == "ERROR"
    assert note_value(client, k1) == 5000  # rejected before anything was burned


def test_rotate_merge_and_melt_are_unaffected_by_sunsetting(client: TestClient, node: FakeNode, mint_note, monkeypatch):
    a, b = mint_note(2000), mint_note(3000)
    c = mint_note(4000)
    monkeypatch.setattr(settings, "sunset_mint", True)

    new_a, h_a = fresh_secret()
    assert client.get(f"/w/cb?k1={a}&p1={h_a}").json()["status"] == "OK"  # rotate
    assert note_value(client, new_a) == 2000

    new_bc, h_bc = fresh_secret()
    assert client.get(f"/w/cb?k1={b}&k1={c}&p1={h_bc}").json()["status"] == "OK"  # merge
    assert note_value(client, new_bc) == 7000

    pr = fake_invoice(7000)
    assert client.get(f"/w/cb?k1={new_bc}&pr={pr}").json()["status"] == "OK"  # melt
    assert node.paid == [pr]


def test_merge_burns_all_and_mints_the_sum(client: TestClient, mint_note):
    a, b = mint_note(2000), mint_note(3000)
    new_k1, h = fresh_secret()
    data = client.get(f"/w/cb?k1={a}&k1={b}&p1={h}").json()
    assert data["status"] == "OK"
    assert note_value(client, a) is None
    assert note_value(client, b) is None
    assert note_value(client, new_k1) == 5000


def test_split_deducts_base_fee_from_change_when_mint_charges_fees(client: TestClient, mint_note, monkeypatch):
    # LUD-25: base_fee_msat comes out of change, never the requested
    # amount - minted fee-free first so the note's own value stays a clean
    # 5000, then the fee is turned on only for the split itself
    k1 = mint_note(5000)
    monkeypatch.setattr(settings, "base_fee_msat", 1000)
    new_k1, h = fresh_secret()
    change_k1, h2 = fresh_secret()
    data = client.get(f"/w/cb?k1={k1}&amount=2000&p1={h}&p2={h2}").json()
    assert data["status"] == "OK"
    assert note_value(client, new_k1) == 2000
    assert note_value(client, change_k1) == 3000 - 1000


def test_split_does_not_reapply_fee_percent_ppm(client: TestClient, mint_note, monkeypatch):
    # per LUD-25, fee_percent_ppm was already withheld once at mint time -
    # only the flat base_fee_msat is charged again on split
    k1 = mint_note(5000)
    monkeypatch.setattr(settings, "base_fee_msat", 0)
    monkeypatch.setattr(settings, "fee_percent_ppm", 500_000)  # 50%, if it were (wrongly) reapplied
    _, h = fresh_secret()
    change_k1, h2 = fresh_secret()
    data = client.get(f"/w/cb?k1={k1}&amount=2000&p1={h}&p2={h2}").json()
    assert data["status"] == "OK"
    assert note_value(client, change_k1) == 3000


def test_split_rejects_when_change_cannot_cover_the_base_fee(client: TestClient, mint_note, monkeypatch):
    k1 = mint_note(5000)
    monkeypatch.setattr(settings, "base_fee_msat", 2000)
    _, h = fresh_secret()
    _, h2 = fresh_secret()
    # amount=4500 leaves change worth 500 before the fee - can't cover it
    result = client.get(f"/w/cb?k1={k1}&amount=4500&p1={h}&p2={h2}").json()
    assert result == {"status": "ERROR", "reason": "insufficient value"}
    # rejected outright - the note is untouched, not partially burned
    assert note_value(client, k1) == 5000


def test_split_rejects_a_zero_value_change_note(client: TestClient, mint_note, monkeypatch):
    # regression: change_before_fee == base_fee_msat exactly used to pass
    # the old strict "<" check and mint a 0 msat change note - a bearer
    # note for nothing must never be mintable, independent of the fee-free
    # min_mint_msat=0 configured here. Minted fee-free first so the note's
    # own value stays a clean 5000 - the fee only needs to apply to the
    # split itself.
    k1 = mint_note(5000)
    monkeypatch.setattr(settings, "min_mint_msat", 0)
    monkeypatch.setattr(settings, "base_fee_msat", 2000)
    _, h = fresh_secret()
    _, h2 = fresh_secret()
    # amount=3000 leaves change worth exactly 2000 before the fee -
    # base_fee_msat (2000) would consume all of it, leaving 0
    result = client.get(f"/w/cb?k1={k1}&amount=3000&p1={h}&p2={h2}").json()
    assert result == {"status": "ERROR", "reason": "insufficient value"}
    assert note_value(client, k1) == 5000


def test_split_ignores_min_mint_msat_on_both_sides(client: TestClient, mint_note, monkeypatch):
    # min_mint_msat is /p/cb's own dust floor for a *fresh* mint - it MUST
    # NOT leak into split: neither side of a split is a new mint, both come
    # from value the wallet already holds, and LUD-25 defines no minimum
    # for either. A high min_mint_msat here must not reject an otherwise
    # tiny, but positive, amount or change.
    monkeypatch.setattr(settings, "base_fee_msat", 0)
    k1 = mint_note(5000)  # minted before raising the floor - /p/cb is still bound by it
    monkeypatch.setattr(settings, "min_mint_msat", 10_000)
    new_k1, h = fresh_secret()
    change_k1, h2 = fresh_secret()
    data = client.get(f"/w/cb?k1={k1}&amount=1&p1={h}&p2={h2}").json()
    assert data["status"] == "OK"
    assert note_value(client, new_k1) == 1
    assert note_value(client, change_k1) == 4999


def test_merge_refunds_base_fee_for_every_extra_note(client: TestClient, mint_note, monkeypatch):
    # LUD-25: merging n notes refunds (n - 1) * base_fee_msat, giving back
    # every base fee already collected beyond the single one this now-one
    # note should have cost
    a, b, c = mint_note(2000), mint_note(3000), mint_note(1000)
    monkeypatch.setattr(settings, "base_fee_msat", 500)
    new_k1, h = fresh_secret()
    data = client.get(f"/w/cb?k1={a}&k1={b}&k1={c}&p1={h}").json()
    assert data["status"] == "OK"
    assert note_value(client, new_k1) == 2000 + 3000 + 1000 + 2 * 500


def test_rotate_is_unaffected_by_mint_fees(client: TestClient, mint_note, monkeypatch):
    # rotate is a merge of one - (1 - 1) * base_fee_msat refunds nothing,
    # so a fee-charging mint still returns exactly the note's own value
    k1 = mint_note(5000)
    monkeypatch.setattr(settings, "base_fee_msat", 1000)
    new_k1, h = fresh_secret()
    data = client.get(f"/w/cb?k1={k1}&p1={h}").json()
    assert data["status"] == "OK"
    assert note_value(client, new_k1) == 5000


def test_retried_rotate_replays_the_original_result(client: TestClient, mint_note):
    # LUD-25 "Retrying a mutation": an exact repeat of a completed rotate
    # (same k1, same h) must get the same {"status": "OK", "c": ...} back,
    # not "already spent" - a GET can get retried by transports that never
    # ask WALLET first
    k1 = mint_note(5000)
    new_k1, h = fresh_secret()
    first = client.get(f"/w/cb?k1={k1}&p1={h}").json()
    second = client.get(f"/w/cb?k1={k1}&p1={h}").json()
    assert first["status"] == "OK"
    assert second == first
    # still exactly one outstanding note from this rotate, not a second one
    assert note_value(client, new_k1) == 5000


def test_retried_split_replays_the_original_result(client: TestClient, mint_note):
    k1 = mint_note(5000)
    new_k1, h = fresh_secret()
    change_k1, h2 = fresh_secret()
    first = client.get(f"/w/cb?k1={k1}&amount=2000&p1={h}&p2={h2}").json()
    second = client.get(f"/w/cb?k1={k1}&amount=2000&p1={h}&p2={h2}").json()
    assert first["status"] == "OK"
    assert second == first
    assert note_value(client, new_k1) == 2000
    assert note_value(client, change_k1) == 3000


def test_retried_merge_replays_the_original_result(client: TestClient, mint_note):
    a, b = mint_note(2000), mint_note(3000)
    new_k1, h = fresh_secret()
    first = client.get(f"/w/cb?k1={a}&k1={b}&p1={h}").json()
    second = client.get(f"/w/cb?k1={a}&k1={b}&p1={h}").json()
    # order of the repeated k1s must not matter either - same burn, same set
    third = client.get(f"/w/cb?k1={b}&k1={a}&p1={h}").json()
    assert first["status"] == "OK"
    assert second == first
    assert third == first
    assert note_value(client, new_k1) == 5000


def test_retry_with_a_different_h_is_a_conflict_not_a_replay(client: TestClient, mint_note):
    # same k1, but a different h than what was actually burned under - a
    # genuine conflict (e.g. a buggy or malicious wallet), not a replay, and
    # must still get the plain already-spent error
    k1 = mint_note(5000)
    _, h = fresh_secret()
    _, other_h = fresh_secret()
    first = client.get(f"/w/cb?k1={k1}&p1={h}").json()
    assert first["status"] == "OK"
    conflict = client.get(f"/w/cb?k1={k1}&p1={other_h}").json()
    assert conflict == {"status": "ERROR", "reason": "Invalid or already spent k1."}


def test_melt_pays_invoice_of_exactly_the_notes_value(client: TestClient, node: FakeNode, mint_note):
    k1 = mint_note(5000)
    pr = fake_invoice(5000)
    data = client.get(f"/w/cb?k1={k1}&pr={pr}").json()
    assert data == {"status": "OK"}  # no new note on a melt
    assert node.paid == [pr]
    assert note_value(client, k1) is None


def test_melt_fee_limit_defaults_to_the_baseline_when_mint_fee_is_low(client: TestClient, node: FakeNode, mint_note):
    # base_fee_msat is 0 in tests by default (see conftest.py) - the
    # baseline (max(0.5%, 5000msat)) must still apply, not a 0 msat cap
    # that would make melting fail to find almost any real route
    k1 = mint_note(2_000_000)
    pr = fake_invoice(2_000_000)
    client.get(f"/w/cb?k1={k1}&pr={pr}")
    assert node.last_fee_limit_msat == max(round(2_000_000 * 0.005), 5000)


def test_melt_fee_limit_follows_a_higher_configured_mint_fee(
    client: TestClient, node: FakeNode, mint_note, monkeypatch
):
    # LUD-25: the mint fee "is meant to cover whatever routing cost
    # SERVICE incurs paying out this note when it is eventually melted" -
    # an operator charging more than the baseline should get a
    # correspondingly higher routing-fee budget for this melt. Minted
    # fee-free first so the note's own value stays a clean 2_000_000 (see
    # test_split_deducts_base_fee_from_change_when_mint_charges_fees for
    # this same pattern) - the fee only needs to apply at melt time.
    k1 = mint_note(2_000_000)
    monkeypatch.setattr(settings, "base_fee_msat", 50_000)  # well above the 5000msat/0.5% baseline for this amount
    pr = fake_invoice(2_000_000)
    client.get(f"/w/cb?k1={k1}&pr={pr}")
    assert node.last_fee_limit_msat == 50_000


def test_melt_rejects_multiple_k1s(client: TestClient, node: FakeNode, mint_note):
    # pr MUST NOT be combined with multiple k1s - merge first
    a, b = mint_note(2000), mint_note(3000)
    pr = fake_invoice(5000)
    assert client.get(f"/w/cb?k1={a}&k1={b}&pr={pr}").json()["status"] == "ERROR"
    assert node.paid == []
    assert note_value(client, a) == 2000
    assert note_value(client, b) == 3000


def test_melt_rejects_invoice_of_wrong_amount(client: TestClient, node: FakeNode, mint_note):
    k1 = mint_note(5000)
    pr = fake_invoice(4000)
    assert client.get(f"/w/cb?k1={k1}&pr={pr}").json()["status"] == "ERROR"
    assert node.paid == []
    assert note_value(client, k1) == 5000


def test_failed_payment_restores_the_notes(client: TestClient, node: FakeNode, mint_note):
    k1 = mint_note(5000)
    node.fail_payments = True
    pr = fake_invoice(5000)
    # per LUD-03 step 6, the callback replies OK immediately and pays
    # asynchronously - a payment failure is only ever observable via the
    # note becoming spendable again, never via this response
    assert client.get(f"/w/cb?k1={k1}&pr={pr}").json() == {"status": "OK"}
    assert note_value(client, k1) == 5000


def test_pending_note_rejects_concurrent_operations(client: TestClient, node: FakeNode, mint_note, monkeypatch):
    # while a melt's outgoing payment is in flight, its k1 is reserved but
    # not yet burned - any other callback naming it must be rejected with
    # reason "pending", not treated as merely invalid/spent
    k1 = mint_note(5000)
    pr = fake_invoice(5000)
    node.pay_delay = 0.3

    _, h = fresh_secret()
    thread = _melt_in_background(client, k1, pr, monkeypatch)
    concurrent = client.get(f"/w/cb?k1={k1}&p1={h}").json()
    thread.join()
    result = thread.result  # type: ignore[attr-defined]

    assert concurrent == {"status": "ERROR", "reason": "pending"}
    assert result["melt"]["status"] == "OK"
    assert node.paid == [pr]
    assert note_value(client, k1) is None


def test_pending_note_is_released_if_the_payment_fails(client: TestClient, node: FakeNode, mint_note, monkeypatch):
    k1 = mint_note(5000)
    pr = fake_invoice(5000)
    node.pay_delay = 0.3
    node.fail_payments = True

    _, h = fresh_secret()
    thread = _melt_in_background(client, k1, pr, monkeypatch)
    concurrent = client.get(f"/w/cb?k1={k1}&p1={h}").json()
    thread.join()
    result = thread.result  # type: ignore[attr-defined]

    assert concurrent == {"status": "ERROR", "reason": "pending"}
    # the callback itself already replied OK (per LUD-03, before the
    # payment was even attempted) - the failure only shows up as the note
    # being outstanding again
    assert result["melt"]["status"] == "OK"
    assert note_value(client, k1) == 5000


def test_payment_failed_still_confirms_before_restoring(client: TestClient, node: FakeNode, mint_note):
    # PaymentFailed (a clean routing/RPC failure response) is NOT proof no
    # HTLC remains outstanding - a malicious payee holding a hodl invoice
    # can make the funding source report exactly this while still holding
    # an already-sent HTLC open. So even this "definitive" failure must
    # still be confirmed independently before the note is restored.
    k1 = mint_note(5000)
    node.fail_reason = "Could not find a route to pay this invoice."
    pr = fake_invoice(5000)

    assert client.get(f"/w/cb?k1={k1}&pr={pr}").json() == {"status": "OK"}

    assert note_value(client, k1) == 5000
    assert node.is_payment_complete_called is True


def test_pending_note_is_released_if_funding_source_becomes_unavailable(
    client: TestClient, node: FakeNode, mint_note, monkeypatch
):
    # regression: a note must not get stuck "pending" forever if something
    # goes wrong *after* it's reserved but *before* any payment is even
    # attempted - e.g. the funding source becomes unconfigured between
    # requests. Previously the reservation was never released in this case,
    # permanently stranding the note despite no payment ever being tried.
    k1 = mint_note(5000)
    pr = fake_invoice(5000)
    assert note_value(client, k1) == 5000  # materialize the note before the funding source disappears
    monkeypatch.setattr(settings, "fundingsource_backend", None)

    assert client.get(f"/w/cb?k1={k1}&pr={pr}").json()["status"] == "ERROR"
    assert node.paid == []

    monkeypatch.setattr(settings, "fundingsource_backend", "lnd")
    # the note must still be usable, not stuck pending forever
    assert note_value(client, k1) == 5000
    _, h = fresh_secret()
    assert client.get(f"/w/cb?k1={k1}&p1={h}").json()["status"] == "OK"


def test_melt_rejects_own_pending_invoice(client: TestClient, node: FakeNode, mint_note):
    # melting straight into an invoice this same mint issued (and hasn't
    # settled yet) is rejected outright - it must not be paid over
    # Lightning (a self-payment to our own node) nor settled as a shortcut
    k1 = mint_note(5000)
    new_secret, new_comment = fresh_secret()
    response = client.get(f"/p/cb?amount=5000&comment={new_comment}")
    pr = response.json()["pr"]

    assert client.get(f"/w/cb?k1={k1}&pr={pr}").json()["status"] == "ERROR"

    assert node.paid == []
    assert note_value(client, k1) == 5000  # note untouched, still spendable
    assert note_value(client, new_secret) is None  # the own invoice never got settled


def test_melt_rejects_already_settled_own_invoice(client: TestClient, node: FakeNode, mint_note):
    # same rejection applies once the invoice is already settled/minted -
    # this mint issued it either way, so it's still "an invoice we created
    # ourselves"
    k1 = mint_note(5000)
    settled_k1 = mint_note(5000)
    settled_payment_hash = sha256(node.last_preimage).hexdigest()
    # mint_note only settles at the (fake) node - force this mint to
    # actually observe and record that settlement (minted=1)
    assert note_value(client, settled_k1) == 5000
    pr = fake_invoice(5000, settled_payment_hash)

    assert client.get(f"/w/cb?k1={k1}&pr={pr}").json()["status"] == "ERROR"

    assert node.paid == []
    assert note_value(client, k1) == 5000


def test_ambiguously_failed_payment_that_actually_succeeded_does_not_restore(
    client: TestClient, node: FakeNode, mint_note
):
    # pay_invoice raised (e.g. the response was lost), but the funding
    # source confirms the payment actually completed - the melt genuinely
    # succeeded despite the local error, so this reports OK (not an error)
    # and, crucially, does NOT restore the note: doing so would let a
    # retry with a *different* invoice pay the same value out twice
    k1 = mint_note(5000)
    node.fail_payments = True
    node.payment_actually_completed = True
    pr = fake_invoice(5000)
    assert client.get(f"/w/cb?k1={k1}&pr={pr}").json() == {"status": "OK"}
    assert note_value(client, k1) is None


def test_undeterminable_payment_status_leaves_the_note_pending(client: TestClient, node: FakeNode, mint_note):
    # if pay_invoice fails AND the confirmation check itself can't tell
    # whether the payment went through (even after _confirm_payment's
    # retries), the mint must not guess: burning would risk destroying a
    # bearer that was in fact never paid for, restoring would risk a
    # double payout if it secretly was. It's left pending instead - still
    # outstanding (so its value isn't lost), but unusable until an operator
    # resolves it by hand once they've confirmed the true outcome.
    k1 = mint_note(5000)
    node.fail_payments = True
    node.is_payment_complete_raises = True
    pr = fake_invoice(5000)
    assert client.get(f"/w/cb?k1={k1}&pr={pr}").json() == {"status": "OK"}
    # still outstanding (its value isn't lost) - probed at the store, since
    # /w truthfully rejects a pending note with the spec's reason instead of
    # advertising a value for it (see test_poc_f2_pending_info_leak.py)
    assert notes.note_amount(k1_id(k1)) == 5000
    assert client.get(f"/w?k1={k1}").json() == {"status": "ERROR", "reason": "pending"}
    _, h = fresh_secret()
    assert client.get(f"/w/cb?k1={k1}&p1={h}").json() == {"status": "ERROR", "reason": "pending"}


def test_hodl_invoice_attack_leaves_the_note_pending_instead_of_restoring(
    client: TestClient, node: FakeNode, mint_note
):
    # regression for the double-spend this whole confirm/pending mechanism
    # exists to close: attacker melts into their own hodl invoice, holds
    # the HTLC open rather than settling or failing it. The funding source
    # gives up and reports a clean PaymentFailed (xpay's retry_for expiring,
    # or lnd's own send timeout) even though the HTLC is still claimable -
    # and the confirmation check can't positively rule that out either
    # (see _is_payment_complete_lnd/_cln raising rather than returning
    # False for a non-terminal/pending status). Previously PaymentFailed
    # skipped confirmation and restored immediately, letting the attacker
    # both settle the held HTLC *and* re-melt the restored note - a double
    # payout. Now it must stay pending: not restored (the note must not be
    # spendable again while its value might still be claimed), not
    # finalized (never confirmed paid either).
    k1 = mint_note(5000)
    node.fail_reason = "Could not find a route to pay this invoice."
    node.is_payment_complete_raises = True
    pr = fake_invoice(5000)
    assert client.get(f"/w/cb?k1={k1}&pr={pr}").json() == {"status": "OK"}
    # same as above: outstanding at the store, "pending" on the wire
    assert notes.note_amount(k1_id(k1)) == 5000
    assert client.get(f"/w?k1={k1}").json() == {"status": "ERROR", "reason": "pending"}
    _, h = fresh_secret()
    assert client.get(f"/w/cb?k1={k1}&p1={h}").json() == {"status": "ERROR", "reason": "pending"}


def test_undeterminable_payment_status_retries_before_giving_up(
    client: TestClient, node: FakeNode, mint_note, monkeypatch
):
    # a transient funding-source hiccup (is_payment_complete raising once)
    # must not be enough to strand the note - _confirm_payment retries and,
    # once the funding source recovers, the melt resolves normally instead
    # of falling back to "pending"
    monkeypatch.setattr(router_module, "_CONFIRMATION_RETRY_DELAYS_SECONDS", (0, 0))
    k1 = mint_note(5000)
    node.fail_payments = True
    node.payment_actually_completed = True

    attempts = {"n": 0}
    real_is_payment_complete = node.is_payment_complete

    async def flaky_is_payment_complete(payment_hash: str, config):
        attempts["n"] += 1
        if attempts["n"] < 2:
            raise ConnectionError("funding source unreachable")
        return await real_is_payment_complete(payment_hash, config)

    monkeypatch.setattr(router_module, "is_payment_complete", flaky_is_payment_complete)
    pr = fake_invoice(5000)
    assert client.get(f"/w/cb?k1={k1}&pr={pr}").json() == {"status": "OK"}
    assert note_value(client, k1) is None  # confirmed paid on retry - finalized as burned, not left pending


def test_any_invalid_k1_fails_the_whole_request(client: TestClient, mint_note):
    k1 = mint_note(5000)
    bogus = urandom(32).hex()
    _, h = fresh_secret()
    result = client.get(f"/w/cb?k1={k1}&k1={bogus}&p1={h}").json()
    assert result == {"status": "ERROR", "reason": "Invalid or already spent k1."}
    # the valid note was not burned
    assert note_value(client, k1) == 5000


def test_duplicate_k1_cannot_be_double_counted(client: TestClient, mint_note):
    k1 = mint_note(5000)
    _, h = fresh_secret()
    result = client.get(f"/w/cb?k1={k1}&k1={k1}&p1={h}").json()
    assert result == {"status": "ERROR", "reason": "Invalid or already spent k1."}
    assert note_value(client, k1) == 5000


def test_too_many_k1s_is_rejected(client: TestClient):
    query = "&".join(f"k1={urandom(32).hex()}" for _ in range(settings.max_k1s + 1))
    result = client.get(f"/w/cb?{query}").json()
    assert result == {"status": "ERROR", "reason": f"Too many k1s (max {settings.max_k1s})."}


def test_amount_cannot_be_combined_with_pr(client: TestClient, mint_note):
    k1 = mint_note(5000)
    pr = fake_invoice(2000)
    assert client.get(f"/w/cb?k1={k1}&pr={pr}&amount=2000").json()["status"] == "ERROR"
    assert note_value(client, k1) == 5000


def test_withdraw_response_echoes_the_literal_secret(client: TestClient, mint_note):
    # the k1 in a withdrawRequest response MUST be the actual bearer secret,
    # never a derived or opaque identifier - a wallet relies on copying it
    # verbatim into the callback or a new note URL
    k1 = mint_note(5000)
    assert client.get(f"/w?k1={k1}").json()["k1"] == k1


def test_withdraw_requires_k1(client: TestClient):
    assert client.get("/w").json()["status"] == "ERROR"


def test_withdraw_by_hash_reports_the_same_note_without_the_secret(client: TestClient, mint_note):
    # LUD-25 "Checking a note without exposing it": ?p= is a second way in
    # for the same lookup - here the bearer note's hex `h`, its short form
    k1 = mint_note(5000)
    by_k1 = client.get(f"/w?k1={k1}").json()
    by_h = client.get(f"/w?p={k1_hash(k1)}").json()
    assert by_h["minWithdrawable"] == by_h["maxWithdrawable"] == 5000
    assert by_h["callback"] == by_k1["callback"]
    # unlike the k1 lookup, the response never echoes a secret it wasn't
    # given - a caller who queried by hash already holds the raw k1
    assert "k1" not in by_h
    assert by_k1["k1"] == k1


def test_withdraw_by_hash_never_burns_the_note(client: TestClient, mint_note):
    k1 = mint_note(5000)
    client.get(f"/w?p={k1_hash(k1)}")
    assert note_value(client, k1) == 5000


def test_withdraw_by_hash_rejects_an_unknown_hash(client: TestClient):
    result = client.get(f"/w?p={urandom(32).hex()}").json()
    assert result == {"status": "ERROR", "reason": "Unknown note."}


def test_withdraw_by_hash_reports_a_retained_spent_note(client: TestClient, mint_note):
    k1 = mint_note(5000)
    note_id = k1_id(k1)
    new_k1, h = fresh_secret()
    assert client.get(f"/w/cb?k1={k1}&p1={h}").json()["status"] == "OK"  # rotate, burns k1
    # Both lookup forms report the retained spent record, while a never
    # registered hash remains unknown. These reads do not reissue the note.
    for lookup in (f"p={k1_hash(k1)}", f"k1={k1}"):
        assert client.get(f"/w?{lookup}").json() == {"status": "ERROR", "reason": "Note already spent."}
    assert notes.note_spent(note_id)
    assert client.get(f"/w?p={urandom(32).hex()}").json() == {"status": "ERROR", "reason": "Unknown note."}


def test_withdraw_requires_exactly_one_of_k1_or_p(client: TestClient, mint_note):
    k1 = mint_note(5000)
    assert client.get("/w").json()["status"] == "ERROR"
    assert client.get(f"/w?k1={k1}&p={k1_hash(k1)}").json()["status"] == "ERROR"


def test_withdraw_by_hash_reports_pending_the_same_way_k1_would(
    client: TestClient, node: FakeNode, mint_note, monkeypatch
):
    k1 = mint_note(5000)
    note_id = k1_id(k1)
    pr = fake_invoice(5000)
    node.pay_delay = 0.3

    thread = _melt_in_background(client, k1, pr, monkeypatch)
    pending = client.get(f"/w?p={k1_hash(k1)}").json()
    thread.join()

    assert pending == {"status": "ERROR", "reason": "pending"}
    assert client.get(f"/w?p={k1_hash(k1)}").json() == {"status": "ERROR", "reason": "Note already spent."}
    assert notes.note_spent(note_id)


def test_failed_melt_restores_hash_lookup_value(client: TestClient, node: FakeNode, mint_note, monkeypatch):
    k1 = mint_note(5000)
    note_id = k1_id(k1)
    node.pay_delay = 0.3
    node.fail_payments = True
    thread = _melt_in_background(client, k1, fake_invoice(5000), monkeypatch)
    pending = client.get(f"/w?p={k1_hash(k1)}").json()
    thread.join()

    assert pending == {"status": "ERROR", "reason": "pending"}
    restored = client.get(f"/w?p={k1_hash(k1)}").json()
    assert restored["maxWithdrawable"] == 5000
    assert "k1" not in restored
    assert not notes.note_spent(note_id)


def test_withdraw_reports_unknown_k1_distinctly_from_spent(client: TestClient, mint_note):
    # a k1 this mint never issued at all gets a different reason than one
    # it issued and has since burned - both fail the same GET /w lookup,
    # but only the store can tell them apart (see NoteStore.note_spent)
    bogus, _ = fresh_secret()
    unknown = client.get(f"/w?k1={bogus}").json()
    assert unknown == {"status": "ERROR", "reason": "Unknown note."}

    k1 = mint_note(5000)
    _, h = fresh_secret()
    assert client.get(f"/w/cb?k1={k1}&p1={h}").json()["status"] == "OK"
    spent = client.get(f"/w?k1={k1}").json()
    assert spent == {"status": "ERROR", "reason": "Note already spent."}


def test_withdraw_ignores_the_declared_amount(client: TestClient, mint_note):
    # a note's URL may carry a wallet-declared &amount=, which the
    # informational endpoint MUST ignore - maxWithdrawable stays authoritative
    k1 = mint_note(5000)
    data = client.get(f"/w?k1={k1}&amount=1").json()
    assert data["maxWithdrawable"] == 5000


def test_no_bearer_secret_is_ever_persisted(client: TestClient, mint_note):
    k1 = mint_note(5000)
    new_k1, h = fresh_secret()
    change_k1, h2 = fresh_secret()
    client.get(f"/w/cb?k1={k1}&amount=2000&p1={h}&p2={h2}")
    stored = str(notes.conn.execute("SELECT * FROM notes").fetchall())
    stored += str(notes.conn.execute("SELECT * FROM mints").fetchall())
    # per LUD-25 neither of these secrets ever crossed the wire to begin
    # with - this mint only ever saw their hashes (h/h2), the short form of
    # the bearer notes they spend
    for secret in (k1, new_k1, change_k1):
        assert secret not in stored
    # notes are stored under their output key Q (LUD-25), never the secret
    assert k1_id(k1) in stored
    assert bearer_id(h) in stored
    assert bearer_id(h2) in stored


def test_spent_k1_cannot_be_replayed(client: TestClient, mint_note):
    k1 = mint_note(5000)
    new_k1, h = fresh_secret()
    first = client.get(f"/w/cb?k1={k1}&p1={h}").json()
    assert first["status"] == "OK"
    _, other_h = fresh_secret()
    second = client.get(f"/w/cb?k1={k1}&p1={other_h}").json()
    assert second["status"] == "ERROR"
    # the replacement from the first rotate is untouched by the replay
    assert note_value(client, new_k1) == 5000
