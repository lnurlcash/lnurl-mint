"""LUD-25 script-path spends (`cw1`): a note locked to a leaf script under its
output key Q, redeemed by revealing that leaf, its control block and a
witness, judged by Bitcoin Core's own interpreter (lnurlcashkernel).

Every spend here is built from scratch - leaf, taproot tweak, and a real
BIP-342 signature over the canonical spend transaction's sighash - the way a
WALLET would build one."""

import types
from dataclasses import dataclass
from hashlib import sha256
from os import urandom

import lnurlcashkernel as kernel
import pytest
from coincurve import PrivateKey
from fastapi.testclient import TestClient
from lnurlcashkernel.taproot import NUMS_H, TAPLEAF_VERSION, tapleaf_hash, tweak

from lnurl_mint import bech32m, spend
from lnurl_mint.db import notes
from tests.conftest import FakeNode, bearer_id, fresh_secret, sign_schnorr_message

DOMAIN = "testserver"
AMOUNT = 20_000_000
LOCK = 1_800_000_000
CSV_4_UNITS = (1 << 22) | 4  # BIP-68 time-type, 4 * 512 s


def _xonly(key: PrivateKey) -> bytes:
    return key.public_key.format(compressed=True)[1:]


def _push_num(n: int) -> bytes:
    raw = n.to_bytes((n.bit_length() + 7) // 8, "little")
    if raw[-1] & 0x80:
        raw += b"\x00"
    return bytes([len(raw)]) + raw


def _push_key(key: PrivateKey) -> bytes:
    return b"\x20" + _xonly(key)


# every test uses fresh keys: the note store is shared across the whole run,
# and a fixed key would name the same Q (the same note) in every test
@pytest.fixture
def owner() -> PrivateKey:
    return PrivateKey()


@pytest.fixture
def other() -> PrivateKey:
    return PrivateKey()


def pk_leaf(key: PrivateKey) -> bytes:
    return _push_key(key) + b"\xac"


def cltv_leaf(key: PrivateKey) -> bytes:
    return _push_num(LOCK) + b"\xb1\x75" + pk_leaf(key)


def csv_leaf(key: PrivateKey) -> bytes:
    return _push_num(CSV_4_UNITS) + b"\xb2\x75" + pk_leaf(key)


def two_of_two_leaf(a: PrivateKey, b: PrivateKey) -> bytes:
    """2-of-2 via CHECKSIGVERIFY: in no list of shapes, and needs none."""
    return _push_key(a) + b"\xad" + _push_key(b) + b"\xac"


def _nonce_leaf(script: bytes) -> bytes:
    """`script` behind a fresh pushed-and-dropped nonce: the same condition,
    a Q no other test shares."""
    return b"\x20" + urandom(32) + b"\x75" + script


@dataclass
class Locked:
    """A note locked to one leaf under NUMS: its Q, and a way to spend it."""

    leaf: bytes
    q: bytes
    control: bytes

    @property
    def cp1(self) -> str:
        return bech32m.encode_cp1(self.q)

    def cw1(
        self,
        signers: list[PrivateKey],
        *,
        locktime: int = 0,
        sequence: int = 0xFFFFFFFE,
        extra: list[bytes] | None = None,
        domain: str = DOMAIN,
    ) -> str:
        digest = kernel.script_path_sighash(self.q, domain, self.leaf, locktime=locktime, sequence=sequence)
        # BIP-342 consumes the last key's signature first, so bottom to top
        # the stack is the signatures reversed, then anything else on top
        witness = [sign_schnorr_message(k, digest) for k in reversed(signers)] + (extra or [])
        return kernel.encode_cw1(kernel.Spend(locktime, sequence, self.leaf, self.control, tuple(witness)))


def _lock(leaf: bytes, version: int = TAPLEAF_VERSION) -> Locked:
    q, parity = tweak(NUMS_H, tapleaf_hash(leaf, version))
    return Locked(leaf, q, bytes([version | parity]) + NUMS_H)


def _at(monkeypatch: pytest.MonkeyPatch, now: int) -> None:
    monkeypatch.setattr(spend, "time", types.SimpleNamespace(time=lambda: float(now)))


def _fund(client: TestClient, mint_note, locked: Locked) -> None:
    """Rotate a fresh bearer note into `locked` - as a WALLET locking value."""
    k1 = mint_note(AMOUNT)
    response = client.get(f"/w/cb?k1={k1}&p1={locked.cp1}")
    assert response.json().get("sig"), response.text


def _redeem(client: TestClient, k1: str, p1: str | None = None):
    return client.get(f"/w/cb?k1={k1}&p1={p1 or fresh_secret()[1]}").json()


def _refused(data: dict) -> bool:
    return data.get("status") == "ERROR"


@pytest.mark.parametrize("shape", ["pk", "two-of-two"])
def test_lock_then_redeem_by_script_path(client: TestClient, node: FakeNode, mint_note, owner, other, shape):
    leaf, signers = (pk_leaf(owner), [owner]) if shape == "pk" else (two_of_two_leaf(owner, other), [owner, other])
    locked = _lock(leaf)
    _fund(client, mint_note, locked)
    new_secret, h = fresh_secret()
    cw1 = locked.cw1(signers)

    response = _redeem(client, cw1, h)
    assert not _refused(response), response
    assert bech32m.decode_cs1(response["sig"])[0] == AMOUNT
    assert notes.note_amount(locked.q.hex()) is None  # burned
    assert notes.note_amount(bearer_id(h)) == AMOUNT  # re-issued under p1

    # LUD-25 "Retrying a mutation": the same request again replays its result
    assert _redeem(client, cw1, h) == response
    # ...but a different p1 is a genuine double-spend
    assert _refused(_redeem(client, cw1))


def test_informational_get_verifies_the_cw1_and_certifies(client: TestClient, node: FakeNode, mint_note, owner):
    locked = _lock(pk_leaf(owner))
    _fund(client, mint_note, locked)
    data = client.get(f"/w?k1={locked.cw1([owner])}").json()
    assert data["minWithdrawable"] == data["maxWithdrawable"] == AMOUNT
    assert bech32m.decode_cs1(data["sig"])[0] == AMOUNT
    assert notes.note_amount(locked.q.hex()) == AMOUNT  # informational: not burned


def test_cltv_is_refused_before_its_locktime_with_the_specific_reason(client, node, mint_note, monkeypatch, owner):
    """A cw1 that opens a real note, but whose time claim the mint's clock
    hasn't reached, says so specifically - never the "invalid or already
    spent" wording a wrong or burned spend gets: a cw1 discloses its whole
    secret already, so there's nothing unsafe about being specific."""
    locked = _lock(cltv_leaf(owner))
    _fund(client, mint_note, locked)
    cw1 = locked.cw1([owner], locktime=LOCK)

    _at(monkeypatch, LOCK - 1)
    response = _redeem(client, cw1)
    assert _refused(response) and "future" in response["reason"]
    assert "already spent" not in response["reason"].lower()
    info = client.get(f"/w?k1={cw1}").json()
    assert _refused(info) and "future" in info["reason"]
    assert notes.note_amount(locked.q.hex()) == AMOUNT  # never burned
    # its value is still visible by its public key
    assert client.get(f"/w?p={locked.cp1}").json()["maxWithdrawable"] == AMOUNT

    _at(monkeypatch, LOCK)
    assert not _refused(_redeem(client, cw1))


def test_csv_counts_from_when_the_mint_credited_the_note(client, node, mint_note, monkeypatch, owner):
    locked = _lock(csv_leaf(owner))
    _fund(client, mint_note, locked)
    credited_at = notes.note_record(locked.q.hex())[1]
    cw1 = locked.cw1([owner], sequence=CSV_4_UNITS)

    _at(monkeypatch, credited_at + 2047)  # one second short of 4 * 512
    assert _refused(_redeem(client, cw1))
    _at(monkeypatch, credited_at + 2048)
    assert not _refused(_redeem(client, cw1))


def test_the_signature_commits_to_the_claimed_time(client, node, mint_note, monkeypatch, owner):
    locked = _lock(cltv_leaf(owner))
    _fund(client, mint_note, locked)
    honest = kernel.decode_cw1(locked.cw1([owner], locktime=LOCK))
    # claim an earlier locktime than the one that was signed
    forged = kernel.encode_cw1(
        kernel.Spend(LOCK - 100, honest.sequence, honest.script, honest.control_block, honest.witness)
    )
    _at(monkeypatch, LOCK - 50)
    assert _refused(_redeem(client, forged))
    assert notes.note_amount(locked.q.hex()) == AMOUNT


def test_a_tampered_witness_is_refused(client: TestClient, node: FakeNode, mint_note, owner):
    locked = _lock(pk_leaf(owner))
    _fund(client, mint_note, locked)
    honest = kernel.decode_cw1(locked.cw1([owner]))
    sig = bytearray(honest.witness[0])
    sig[5] ^= 1
    forged = kernel.encode_cw1(
        kernel.Spend(honest.locktime, honest.sequence, honest.script, honest.control_block, (bytes(sig),))
    )
    assert _refused(_redeem(client, forged))
    assert notes.note_amount(locked.q.hex()) == AMOUNT


def test_a_cw1_signed_for_another_domain_is_refused(client: TestClient, node: FakeNode, mint_note, owner, other):
    locked = _lock(pk_leaf(owner))
    _fund(client, mint_note, locked)
    assert _refused(_redeem(client, locked.cw1([owner], domain="other.example")))
    assert notes.note_amount(locked.q.hex()) == AMOUNT


def test_a_leaf_for_another_note_opens_nothing(client: TestClient, node: FakeNode, mint_note, owner, other):
    """A cw1 derives its own Q from its control block: another leaf names
    another note, one never funded here - the ambiguous generic reason."""
    locked = _lock(pk_leaf(owner))
    _fund(client, mint_note, locked)
    elsewhere = _lock(pk_leaf(other))
    assert _redeem(client, elsewhere.cw1([other])) == {"status": "ERROR", "reason": "Invalid or already spent k1."}
    assert notes.note_amount(locked.q.hex()) == AMOUNT


def test_an_op_success_leaf_is_refused_even_though_consensus_would_accept(client, node, mint_note):
    locked = _lock(_nonce_leaf(b"\x50"))  # OP_SUCCESS80
    _fund(client, mint_note, locked)
    response = _redeem(client, locked.cw1([]))
    assert _refused(response) and "OP_SUCCESS" in response["reason"]
    assert notes.note_amount(locked.q.hex()) == AMOUNT


def test_an_unknown_leaf_version_is_refused(client, node, mint_note):
    locked = _lock(_nonce_leaf(b"\x51"), version=0xC2)
    _fund(client, mint_note, locked)
    response = _redeem(client, locked.cw1([]))
    assert _refused(response) and "leaf version" in response["reason"]


def test_mint_straight_to_a_script_path_note(client: TestClient, node: FakeNode, owner):
    locked = _lock(pk_leaf(owner))
    response = client.get(f"/p/cb?amount={AMOUNT}&comment={locked.cp1}")
    assert response.json().get("pr"), response.text
    node.settled.add(sha256(node.last_preimage).hexdigest())
    assert not _refused(_redeem(client, locked.cw1([owner])))


def test_a_bearer_note_spends_in_either_form(client: TestClient, node: FakeNode, mint_note):
    """The hex preimage is the short form of the bearer note's cw1: the mint
    builds the same spend from it, so the full cw1 works just as well."""
    k1 = mint_note(5000)
    full = kernel.encode_cw1(kernel.preimage_spend(bytes.fromhex(k1)))
    assert full.startswith("cw1")
    assert client.get(f"/w?k1={full}").json()["maxWithdrawable"] == 5000
    assert not _refused(_redeem(client, full))
    assert _refused(_redeem(client, k1))  # the same note, already spent


def test_a_pre_taproot_bearer_note_migrates_on_first_use(client: TestClient, node: FakeNode):
    """A note issued before notes were keyed by Q sits under h = sha256(k1).
    Nothing on file tells that apart from a key; the first spend that
    reveals the secret moves it to its Q, and it redeems normally."""
    k1 = urandom(32).hex()
    h = sha256(bytes.fromhex(k1)).hexdigest()
    notes.conn.execute("INSERT INTO notes (id, amount_msat) VALUES (?, ?)", (h, 7000))
    notes.conn.commit()

    assert client.get(f"/w?k1={k1}").json()["maxWithdrawable"] == 7000
    assert notes.note_amount(h) is None
    assert notes.note_amount(bearer_id(h)) == 7000
    assert not _refused(_redeem(client, k1))


def test_a_pre_taproot_bearer_note_is_found_by_its_hash(client: TestClient, node: FakeNode):
    k1 = urandom(32).hex()
    h = sha256(bytes.fromhex(k1)).hexdigest()
    notes.conn.execute("INSERT INTO notes (id, amount_msat) VALUES (?, ?)", (h, 7000))
    notes.conn.commit()
    assert client.get(f"/w?p={h}").json()["maxWithdrawable"] == 7000
    # ...and its hash can't be reused to credit a second note for the same secret
    k2 = urandom(32).hex()
    h2 = sha256(bytes.fromhex(k2)).hexdigest()
    notes.conn.execute("INSERT INTO notes (id, amount_msat) VALUES (?, ?)", (h2, 7000))
    notes.conn.commit()
    reuse = client.get(f"/p/cb?amount=5000&comment={h2}").json()
    assert reuse == {"status": "ERROR", "reason": "comment already in use"}
