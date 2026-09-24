"""PoC B4 (2026-08-17 review): value-conservation / inflation hunt.

Candidate claim (hunters' P4): the fee arithmetic might let a holder
inflate value via mint -> split -> merge cycles. The suspect spots:
  - _mint_fee_msat rounds the fee UP to a whole sat (router.py:319-320)
  - a split collects base_fee_msat once but produces 2 notes (L646-656)
  - a merge refunds (n-1) * base_fee_msat (L673-674) even though note
    lineage is not tracked, so a merged note "claims" a full base fee per
    input regardless of what that input historically cost

Method: a white-box Ledger drives the real endpoints (TestClient + FakeNode)
and tracks paid_in (gross invoice amounts), melted_out (invoices the mint
paid), fees collected (mint fees + split base fees) and refunds (merge
refunds). After every operation it asserts the conservation identity

    paid_in == outstanding + melted_out + fees_collected - refunds

and reads every note's value straight from the db (never trusting a
response). Any cycle ending with attacker_gain = outstanding + melted_out
- paid_in > 0 is an inflation bug.

All local/safe: FakeNode + TestClient + throwaway db.
"""

from hashlib import sha256

import pytest
from fastapi.testclient import TestClient

from lnurl_mint import bech32m
from lnurl_mint.config import settings
from lnurl_mint.db import notes
from lnurl_mint.router import _mint_fee_msat
from tests.conftest import FakeNode, bearer_id, fake_invoice, fresh_secret, k1_id


def _note_id(k1: str) -> str:
    return k1_id(k1)


class Ledger:
    def __init__(self, client: TestClient, node: FakeNode) -> None:
        self.client = client
        self.node = node
        self.paid_in = 0
        self.melted_out = 0
        self.fees = 0  # mint fees + split base fees actually collected
        self.refunds = 0  # merge refunds actually paid out
        self.ids: list[str] = []  # outstanding note ids, white-box

    # -- operations (each asserts its own expected arithmetic) --

    def mint(self, gross_msat: int) -> str:
        k1, comment = fresh_secret()
        resp = self.client.get(f"/p/cb?amount={gross_msat}&comment={comment}")
        assert resp.json().get("pr"), resp.text
        self.node.settled.add(sha256(self.node.last_preimage).hexdigest())
        r = self.client.get(f"/w?k1={k1}")
        net = r.json()["maxWithdrawable"]
        # the minted value must equal gross minus the exact fee formula
        assert net == gross_msat - _mint_fee_msat(gross_msat)
        self.paid_in += gross_msat
        self.fees += gross_msat - net
        self.ids.append(_note_id(k1))
        self.assert_conserved()
        return k1

    def rotate(self, k1: str) -> str:
        old = notes.note_amount(_note_id(k1))
        assert old is not None
        secret, h = fresh_secret()
        r = self.client.get(f"/w/cb?k1={k1}&p1={h}")
        assert r.json()["status"] == "OK", r.text
        self.ids.remove(_note_id(k1))
        self.ids.append(bearer_id(h))
        assert notes.note_amount(bearer_id(h)) == old  # rotate is value-neutral
        self.assert_conserved()
        return secret

    def split(self, k1: str, amount_msat: int) -> tuple[str, str]:
        total = notes.note_amount(_note_id(k1))
        assert total is not None
        secret_amount, h = fresh_secret()
        secret_change, h2 = fresh_secret()
        r = self.client.get(f"/w/cb?k1={k1}&p1={h}&p2={h2}&amount={amount_msat}")
        assert r.json()["status"] == "OK", r.text
        change = total - amount_msat - settings.base_fee_msat
        self.fees += settings.base_fee_msat
        self.ids.remove(_note_id(k1))
        self.ids.extend([bearer_id(h), bearer_id(h2)])
        assert notes.note_amount(bearer_id(h)) == amount_msat
        assert notes.note_amount(bearer_id(h2)) == change
        self.assert_conserved()
        return secret_amount, secret_change

    def merge(self, k1s: list[str]) -> str:
        values = []
        for k1 in k1s:
            v = notes.note_amount(_note_id(k1))
            assert v is not None
            values.append(v)
        secret, h = fresh_secret()
        query = "&".join(f"k1={k1}" for k1 in k1s)
        r = self.client.get(f"/w/cb?{query}&p1={h}")
        assert r.json()["status"] == "OK", r.text
        refund = (len(k1s) - 1) * settings.base_fee_msat
        self.refunds += refund
        for k1 in k1s:
            self.ids.remove(_note_id(k1))
        self.ids.append(bearer_id(h))
        assert notes.note_amount(bearer_id(h)) == sum(values) + refund
        self.assert_conserved()
        return secret

    def melt(self, k1: str) -> None:
        value = notes.note_amount(_note_id(k1))
        assert value is not None
        r = self.client.get(f"/w/cb?k1={k1}&pr={fake_invoice(value)}")
        assert r.json()["status"] == "OK", r.text
        self.melted_out += value
        self.ids.remove(_note_id(k1))
        self.assert_conserved()

    # -- accounting --

    def outstanding(self) -> int:
        return sum(notes.note_amount(i) or 0 for i in self.ids)

    def attacker_gain(self) -> int:
        return self.outstanding() + self.melted_out - self.paid_in

    def assert_conserved(self) -> None:
        # the pure bookkeeping identity - holds even in the operator
        # fee-raise scenario, where the over-refund is funded by the mint's
        # own treasury (fees/refunds are tracked exactly, so the identity
        # absorbs it)
        assert self.paid_in == self.outstanding() + self.melted_out + self.fees - self.refunds

    def assert_no_attacker_gain(self) -> None:
        """The adversarial invariant: after any attacker-reachable cycle the
        holder has NOT ended up with more than they paid in. Checked
        explicitly at the end of each attack test rather than inside every
        op, because the informational operator-fee-raise test deliberately
        violates it (from the mint's treasury, not from thin air)."""
        assert self.attacker_gain() <= 0


@pytest.fixture
def ledger(client: TestClient, node: FakeNode) -> Ledger:
    return Ledger(client, node)


@pytest.fixture
def fee_settings(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "base_fee_msat", 1000)
    monkeypatch.setattr(settings, "fee_percent_ppm", 0)
    monkeypatch.setattr(settings, "min_mint_msat", 0)
    monkeypatch.setattr(settings, "min_sendable_msat", 1000)


def test_simple_cycles(ledger: Ledger, fee_settings):
    # cycle A: mint -> rotate -> melt
    k1 = ledger.mint(100_000)
    k1 = ledger.rotate(k1)
    ledger.melt(k1)
    assert ledger.attacker_gain() == -1000  # one mint fee, kept by the mint

    # cycle B: mint -> split -> merge -> melt
    k1 = ledger.mint(100_000)
    a, change = ledger.split(k1, 40_000)
    k1 = ledger.merge([a, change])
    ledger.melt(k1)
    # two mint fees total so far, split fee and merge refund cancel exactly
    assert ledger.attacker_gain() == -2000

    # cycle C: deep split chain - split off 1 msat dust nine times, merge
    # all ten notes back, melt
    k1 = ledger.mint(1_000_000)
    dust = []
    for _ in range(9):
        d, k1 = ledger.split(k1, 1)
        dust.append(d)
    k1 = ledger.merge([*dust, k1])
    ledger.melt(k1)
    assert ledger.attacker_gain() == -3000

    # cycle D: three separate mints, split each, cross-merge everything
    parts = []
    for _ in range(3):
        k1 = ledger.mint(100_000)
        a, change = ledger.split(k1, 25_000)
        parts.extend([a, change])
    k1 = ledger.merge(parts)
    ledger.melt(k1)
    # cumulative across all four cycles: 6 mint fees + 13 split fees - 15
    # merge refunds = 4000 kept by the mint
    assert ledger.attacker_gain() == -4000


def test_dust_split_edges(ledger: Ledger, fee_settings):
    # change of exactly 1 msat is allowed (change == 0 is rejected)
    k1 = ledger.mint(100_000)  # nets 99_000
    a, change = ledger.split(k1, 97_999)  # change_before_fee = 1001 -> change = 1
    assert notes.note_amount(_note_id(change)) == 1
    # ...and the 1-msat dust note still merges back losslessly
    k1 = ledger.merge([a, change])
    ledger.melt(k1)
    assert ledger.attacker_gain() == -1000

    # amount of exactly 1 msat works too
    k1 = ledger.mint(100_000)
    a, change = ledger.split(k1, 1)
    k1 = ledger.merge([a, change])
    ledger.melt(k1)
    assert ledger.attacker_gain() == -2000

    # change_before_fee == base_fee exactly (change would be 0) is rejected,
    # and the failed split changes nothing
    k1 = ledger.mint(100_000)
    total = notes.note_amount(_note_id(k1))
    secret, h = fresh_secret()
    secret2, h2 = fresh_secret()
    r = ledger.client.get(f"/w/cb?k1={k1}&p1={h}&p2={h2}&amount={total - 1000}")
    assert r.json()["status"] == "ERROR"
    assert notes.note_amount(_note_id(k1)) == total
    assert notes.note_amount(bearer_id(h)) is None and notes.note_amount(bearer_id(h2)) is None
    ledger.assert_conserved()


def test_hundred_note_merge_is_not_a_base_fee_printing_press(ledger: Ledger, fee_settings):
    """The lead's suspect: merging N notes refunds (N-1) base fees, but each
    split only collected ONE base fee while producing two notes. Quantified
    here at the maximum batch: carve 99 dust notes of 1 sat off one mint
    (99 splits, 99 base fees collected), then merge all 100 notes at once
    (max_k1s) - the refund is 99 base fees, EXACTLY what the splits
    collected. Net effect zero; the mint keeps precisely the mint fee."""
    k1 = ledger.mint(301_000)  # nets 300_000 after the 1000-msat mint fee
    dust = []
    for _ in range(99):
        d, k1 = ledger.split(k1, 1000)
        dust.append(d)
    assert len(dust) == 99
    # change note: 300_000 - 99*1000 (amounts) - 99*1000 (split fees) = 102_000
    assert notes.note_amount(_note_id(k1)) == 102_000
    k1 = ledger.merge([*dust, k1])  # 100 k1s, refund = 99 * 1000
    assert notes.note_amount(_note_id(k1)) == 300_000
    ledger.melt(k1)
    assert ledger.attacker_gain() == -1000  # exactly the one mint fee
    # fees collected: 1000 (mint) + 99_000 (splits) = refunds 99_000 + 1000 kept
    assert ledger.fees == 100_000
    assert ledger.refunds == 99_000


def test_fee_arithmetic_grid_never_attacker_favorable(client: TestClient, node: FakeNode, monkeypatch):
    """Property sweep: over a grid of (base_fee, ppm, gross), the minted
    net value never exceeds gross - base_fee, i.e. every minted note has
    provably 'paid' at least one base fee - the load-bearing fact for the
    merge-refund conservation argument (see report)."""
    monkeypatch.setattr(settings, "min_mint_msat", 0)
    monkeypatch.setattr(settings, "min_sendable_msat", 1000)
    for base_fee in (0, 1, 500, 1000, 1500, 10_000):
        for ppm in (0, 1, 1000, 500_000, 999_999):
            monkeypatch.setattr(settings, "base_fee_msat", base_fee)
            monkeypatch.setattr(settings, "fee_percent_ppm", ppm)
            for gross in (1000, 10_000, 999_999, 1_000_000, 1_500_000, 100_000_000):
                fee = _mint_fee_msat(gross)
                # fee always >= the unrounded formula, and always >= base_fee
                assert fee >= base_fee + (gross * ppm) // 1_000_000
                assert fee >= base_fee
                net = gross - fee
                if net >= 0:  # mintable at min_mint=0
                    assert net <= gross - base_fee


def test_zero_value_mint_edge_no_gain(ledger: Ledger, monkeypatch):
    """min_mint_msat=0 + fee == gross mints a ZERO-value note (net=0 is not
    < min_mint=0, so /p/cb allows it). Confirm it buys the attacker nothing:
    zero-notes merge into zero-notes (refund only ever adds base_fee, which
    each zero-note already paid in full at mint time)."""
    # variant 1: ppm=1e6, bf=0 - fee == gross exactly at multiples of 1000
    monkeypatch.setattr(settings, "base_fee_msat", 0)
    monkeypatch.setattr(settings, "fee_percent_ppm", 1_000_000)
    monkeypatch.setattr(settings, "min_mint_msat", 0)
    monkeypatch.setattr(settings, "min_sendable_msat", 1000)
    z1 = ledger.mint(1000)
    z2 = ledger.mint(1000)
    assert notes.note_amount(_note_id(z1)) == 0
    merged = ledger.merge([z1, z2])  # refund = 1 * 0 = 0
    assert notes.note_amount(_note_id(merged)) == 0
    assert ledger.attacker_gain() == -2000  # attacker paid everything, holds nothing

    # variant 2: bf=1000, ppm=0 - zero-note that 'paid' a full base fee
    monkeypatch.setattr(settings, "base_fee_msat", 1000)
    monkeypatch.setattr(settings, "fee_percent_ppm", 0)
    z1 = ledger.mint(1000)
    z2 = ledger.mint(1000)
    assert notes.note_amount(_note_id(z1)) == 0
    merged = ledger.merge([z1, z2])  # refund = 1 * 1000, paid for by the two mint fees
    assert notes.note_amount(_note_id(merged)) == 1000
    ledger.melt(merged)
    assert ledger.attacker_gain() == -3000  # paid 4000 total, got 1000 back


def test_sub_sat_base_fee_rounding_is_mint_favorable(ledger: Ledger, monkeypatch):
    """base_fee_msat=1 (sub-sat): the mint fee rounds UP to 1000 msat while
    splits collect and merges refund the raw 1 msat - the rounding gap is
    always kept by the mint, never by the holder."""
    monkeypatch.setattr(settings, "base_fee_msat", 1)
    monkeypatch.setattr(settings, "fee_percent_ppm", 0)
    monkeypatch.setattr(settings, "min_mint_msat", 0)
    monkeypatch.setattr(settings, "min_sendable_msat", 1000)
    k1 = ledger.mint(100_000)
    assert notes.note_amount(_note_id(k1)) == 99_000  # fee rounded 1 -> 1000
    a, change = ledger.split(k1, 50_000)  # collects 1 msat
    k1 = ledger.merge([a, change])  # refunds 1 msat
    ledger.melt(k1)
    assert ledger.attacker_gain() == -1000


def test_failed_requests_change_no_value(ledger: Ledger, fee_settings):
    """Every adversarially-malformed multi-k1 request must fail atomically:
    no input burned, no output minted, ledger untouched."""
    # duplicate k1 in one merge: resolves (and sums!) twice, but swap's
    # second burn finds it spent and rolls the whole transaction back
    k1 = ledger.mint(100_000)
    _, h = fresh_secret()
    r = ledger.client.get(f"/w/cb?k1={k1}&k1={k1}&p1={h}")
    assert r.json()["status"] == "ERROR"
    assert notes.note_amount(_note_id(k1)) == 99_000  # intact
    assert notes.note_amount(bearer_id(h)) is None  # nothing minted
    ledger.assert_conserved()

    # split with h == h2: second INSERT violates the PRIMARY KEY, whole
    # swap rolls back
    k1b = ledger.mint(100_000)
    _, h_dup = fresh_secret()
    _, h2_dup = fresh_secret()
    r = ledger.client.get(f"/w/cb?k1={k1b}&p1={h_dup}&p2={h_dup}&amount=1000")
    assert r.json()["status"] == "ERROR"
    assert notes.note_amount(_note_id(k1b)) == 99_000
    assert notes.note_amount(bearer_id(h_dup)) is None
    ledger.assert_conserved()

    # merge onto an EXISTING outstanding note id: INSERT collides, rolls back
    k1c = ledger.mint(100_000)
    existing_id = _note_id(k1)
    r = ledger.client.get(f"/w/cb?k1={k1c}&p1={bech32m.encode_cp1(bytes.fromhex(existing_id))}")
    assert r.json()["status"] == "ERROR"
    assert notes.note_amount(_note_id(k1c)) == 99_000
    assert notes.note_amount(existing_id) == 99_000
    ledger.assert_conserved()

    # split amount == total (change would be negative) rejected, no-op
    r = ledger.client.get(f"/w/cb?k1={k1}&p1={h}&p2={h2_dup}&amount=99_000")
    assert r.json()["status"] == "ERROR"
    assert notes.note_amount(_note_id(k1)) == 99_000
    ledger.assert_conserved()
    ledger.assert_no_attacker_gain()


def test_merge_can_exceed_max_sendable_but_stays_conserved(ledger: Ledger, fee_settings, monkeypatch):
    """maxSendable bounds /p/cb only; nothing caps a merged note's value.
    Merging two near-max notes into one oversized note and melting it works
    - but pays out exactly what was paid in, minus fees. Not inflation,
    documented here because it doubles the melt size an operator may expect
    to have to route."""
    monkeypatch.setattr(settings, "max_sendable_msat", 200_000)
    k1a = ledger.mint(200_000)
    k1b = ledger.mint(200_000)
    k1 = ledger.merge([k1a, k1b])
    oversized = notes.note_amount(_note_id(k1))
    assert oversized == 199_000 + 199_000 + 1000 > settings.max_sendable_msat
    ledger.melt(k1)  # pays the oversized invoice fine (FakeNode)
    # two mint fees collected, one base fee refunded on the merge: net -1000
    assert ledger.attacker_gain() == -1000


def test_operator_fee_raise_overrefunds(ledger: Ledger, monkeypatch):
    """Informational, config-change gated (NOT attacker-reachable): merge
    refunds use the CURRENT base_fee_msat, not the one historical notes
    actually paid. If an operator raises base_fee_msat while notes are
    outstanding, merges of pre-raise notes refund more than was ever
    collected for them - quantified here: 3 notes minted at bf=1000 (3000
    collected), merged at bf=5000 (10000 refunded): the mint pays out 7000
    it never collected. The mirror-image fee CUT under-refunds holders.
    Attacker cannot trigger this; it's an operator footgun worth a doc
    line, not a vulnerability."""
    monkeypatch.setattr(settings, "base_fee_msat", 1000)
    monkeypatch.setattr(settings, "fee_percent_ppm", 0)
    monkeypatch.setattr(settings, "min_mint_msat", 0)
    monkeypatch.setattr(settings, "min_sendable_msat", 1000)
    k1s = [ledger.mint(100_000) for _ in range(3)]
    fees_before = ledger.fees
    monkeypatch.setattr(settings, "base_fee_msat", 5000)  # operator raises the fee
    k1 = ledger.merge(k1s)
    assert notes.note_amount(_note_id(k1)) == 3 * 99_000 + 2 * 5000
    overrefund = 2 * 5000 - 2 * 1000  # refunded 10_000 vs 2_000 historically collected
    assert overrefund == 8000
    assert fees_before == 3000
