import os
import tempfile

# both must run before the package (and its module-level Settings/NoteStore)
# is imported: each test session gets its own throwaway database, and
# Settings is pointed at a dotenv file that doesn't exist rather than the
# repo's own .env (see config.py) - keeps tests isolated from a developer's
# real local config (e.g. FUNDINGSOURCE_* credentials for testing against
# lnurl_server's regtest nodes, or a BASE_URL override), regardless of what
# that file contains.
os.environ["DATABASE_PATH"] = os.path.join(tempfile.mkdtemp(), "test.db")
os.environ["LNURL_MINT_ENV_FILE"] = os.path.join(tempfile.mkdtemp(), "unused.env")
# base_url is a required setting (see config.py) - matches TestClient's own
# default host, so the many assertions elsewhere that expect "testserver"
# keep working unchanged
os.environ["BASE_URL"] = "http://testserver"
# base_fee_msat defaults to 1000 (see config.py) - fee-free here so the many
# assertions elsewhere that expect a minted note's value to equal the
# amount paid keep working unchanged; fee behavior itself is exercised by
# tests that monkeypatch settings.base_fee_msat/fee_percent_ppm directly
os.environ["BASE_FEE_MSAT"] = "0"
# min_mint_msat defaults to 10_000 (see config.py) - 0 here so the many
# small test amounts (e.g. 5000) elsewhere keep minting successfully; the
# floor itself is exercised by tests that monkeypatch settings.min_mint_msat
os.environ["MIN_MINT_MSAT"] = "0"
# min_sendable_msat defaults to 10_000 (see config.py) too - lowered here to
# its old default so the same small test amounts stay above it; the bound
# itself is exercised by tests that monkeypatch settings.min_sendable_msat
os.environ["MIN_SENDABLE_MSAT"] = "1000"
# verify_enabled defaults to True (see config.py) - pinned off here so
# responses stay their pre-LUD-21 shape (bare {"status": "OK"}, no "verify"
# field) for the many assertions elsewhere that don't care about verify;
# the enabled behavior itself is exercised by tests that monkeypatch
# settings.verify_enabled directly
os.environ["VERIFY_ENABLED"] = "false"

import asyncio
import threading
import time
from hashlib import sha256
from os import urandom

import bolt11
import lnurlcashkernel
import pytest
from bolt11.models.tags import TagChar, Tags
from bolt11.types import Bolt11
from coincurve import PrivateKey
from coincurve._libsecp256k1 import ffi, lib
from fastapi.testclient import TestClient

import lnurl_mint.node as node_module
import lnurl_mint.router as router_module
import lnurl_mint.signing as signing_module
from lnurl_mint.config import settings
from lnurl_mint.db import notes
from lnurl_mint.node import NodeInfo, PaymentFailed, PaymentResult
from lnurl_mint.server import app


def sign_schnorr_message(key: PrivateKey, message: bytes) -> bytes:
    """Sign an arbitrary-length BIP-340 message in tests.

    Coincurve's public signing convenience method is limited to 32-byte
    messages, while its bundled libsecp256k1 and public verification method
    support the arbitrary-length messages BIP-340 and LUD-25 specify. Use the
    bundled custom signer here so integration tests exercise the exact wire
    message instead of silently testing sha256(message).
    """
    keypair = ffi.new("secp256k1_keypair *")
    assert lib.secp256k1_keypair_create(key.context.ctx, keypair, key.secret)

    signature = ffi.new("unsigned char[64]")
    params = ffi.new("secp256k1_schnorrsig_extraparams *")
    for index, byte in enumerate(bytes.fromhex("da6fb38c")):
        params.magic[index] = byte
    params.noncefp = ffi.NULL
    aux_randomness = ffi.new("unsigned char[32]", b"\x00" * 32)
    params.ndata = aux_randomness
    assert lib.secp256k1_schnorrsig_sign_custom(
        key.context.ctx,
        signature,
        message,
        len(message),
        keypair,
        params,
    )
    return bytes(ffi.buffer(signature, 64))


def fresh_secret() -> tuple[str, str]:
    """A (k1, h) pair for a WALLET-generated bearer note, in LUD-25's short
    forms: k1 is its spend (the preimage), what a real wallet (here, the
    test itself) keeps; h = sha256(k1) hex names the note on a mint comment
    or as p1/p2 - this mint is never given k1 itself for these. Stored
    under bearer_id(h)."""
    secret = urandom(32).hex()
    return secret, sha256(bytes.fromhex(secret)).hexdigest()


def bearer_id(h: str) -> str:
    """The note id (hex Q) of the bearer note whose secret hashes to `h` -
    where this mint stores a note minted or rotated with `h` as its short
    form (LUD-25: NUMS internal key, one `OP_SHA256 <h> OP_EQUAL` leaf)."""
    return lnurlcashkernel.preimage_note(bytes.fromhex(h))[0].hex()


def k1_hash(k1: str) -> str:
    """The hex `h` naming a hex `k1` secret's bearer note (its `cp1` short
    form, e.g. for ?p=)."""
    return sha256(bytes.fromhex(k1)).hexdigest()


def k1_id(k1: str) -> str:
    """The note id (hex Q) of the bearer note a hex `k1` secret spends."""
    return bearer_id(sha256(bytes.fromhex(k1)).hexdigest())


def ck1_for(key: PrivateKey, domain: str = "testserver") -> str:
    """The `ck1` key-path spend of the note Q = x(key·G) at `domain`: a
    BIP-340 signature (zero aux_rand, like a real WALLET) over the canonical
    spend transaction's sighash (lnurlcashkernel.key_path_sighash)."""
    q = key.public_key.format(compressed=True)[1:]
    sig = sign_schnorr_message(key, lnurlcashkernel.key_path_sighash(q, domain))
    return lnurlcashkernel.encode_ck1(lnurlcashkernel.Spend(0, 0xFFFFFFFF, None, None, (sig,), key=q))


def fake_invoice(amount_msat: int, payment_hash: str | None = None) -> str:
    """A syntactically-valid (but unpayable) BOLT11 invoice, for faking the
    node without needing a real one."""
    tags = Tags()
    tags.add(TagChar.payment_hash, payment_hash or urandom(32).hex())
    tags.add(TagChar.payment_secret, urandom(32).hex())
    tags.add(TagChar.description, "test")
    return bolt11.encode(
        Bolt11(currency="bc", amount_msat=amount_msat, date=int(time.time()), tags=tags),
        private_key=urandom(32).hex(),
    )


class FakeNode:
    def __init__(self) -> None:
        self.settled: set[str] = set()
        self.last_preimage: bytes = b""
        self.preimages: dict[str, bytes] = {}  # payment_hash -> preimage, for invoice_preimage
        self.description_hashes: dict[str, str | None] = {}  # payment_hash -> description_for_hash
        self.melt_preimages: dict[str, bytes] = {}  # payment_hash -> preimage, for payment_preimage (LUD-25 verify)
        self.paid: list[str] = []
        self.fail_payments = False
        # for simulating a *definitive* pay_invoice failure - the funding
        # source cleanly reported the payment did not go through (e.g. no
        # route), so melt should restore immediately without the fallback
        # is_payment_complete check
        self.fail_reason: str | None = None
        # for simulating an *ambiguous* pay_invoice failure - the funding
        # source secretly completed the payment despite pay_invoice raising
        # (e.g. the response was lost) - vs. the confirmation check itself
        # being unable to tell either way
        self.payment_actually_completed = False
        self.is_payment_complete_raises = False
        self.is_payment_complete_called = False
        self.is_payment_complete_calls = 0  # count, for tests asserting a bounded number of retries
        # seconds to block inside pay_invoice before resolving - simulates
        # an in-flight payment for tests of the melt "pending" lock, which
        # otherwise has no observable window in a single-threaded test
        self.pay_delay = 0.0
        # routing fee pay_invoice reports on a successful payment - mirrors
        # what a real lnd/cln backend returns alongside the preimage, for
        # tests of mint_log.log_melt's fee reporting
        self.pay_fee_msat: int | None = 0
        # fee_limit_msat pay_invoice was actually called with - lets tests
        # assert on router._melt_fee_limit_msat's output without
        # duplicating its formula
        self.last_fee_limit_msat: int | None = None
        # a real keypair, standing in for the node's own identity key - lets
        # tests of LUD-25 Offline verification (signing.mint_pubkey/
        # sign_note) exercise the real "Lightning Signed Message" signing
        # and recovery logic without a real lnd/cln node
        self.identity_key = PrivateKey()
        # override to simulate a node with more than one advertised address
        # (e.g. clearnet + Tor) - None means "just the single 127.0.0.1
        # address" (see fetch_node_info below)
        self.uris: list[str] | None = None

    @property
    def pubkey(self) -> str:
        return self.identity_key.public_key.format(compressed=True).hex()

    async def create_invoice(
        self, amount_msat: int, config, memo: str = "", description_for_hash: str | None = None
    ) -> tuple[str, bytes]:
        preimage = urandom(32)
        self.last_preimage = preimage
        payment_hash = sha256(preimage).hexdigest()
        self.preimages[payment_hash] = preimage
        # what a zap invoice was bound to, for the tests to check
        self.description_hashes[payment_hash] = description_for_hash
        return fake_invoice(amount_msat, payment_hash), preimage

    async def is_invoice_settled(self, payment_hash: str, config) -> bool:
        return payment_hash in self.settled

    async def invoice_preimage(self, payment_hash: str, config) -> bytes | None:
        if payment_hash not in self.settled:
            return None
        return self.preimages.get(payment_hash)

    async def pay_invoice(self, invoice: str, config, fee_limit_msat: int) -> PaymentResult:
        self.last_fee_limit_msat = fee_limit_msat
        if self.pay_delay:
            await asyncio.sleep(self.pay_delay)
        if self.fail_reason is not None:
            raise PaymentFailed(self.fail_reason)
        if self.fail_payments:
            raise ValueError("Payment failed: no route.")
        self.paid.append(invoice)
        preimage = urandom(32)
        decoded_payment_hash = bolt11.decode(invoice).payment_hash
        if decoded_payment_hash:
            self.melt_preimages[decoded_payment_hash] = preimage
        return PaymentResult(preimage, self.pay_fee_msat)

    async def is_payment_complete(self, payment_hash: str, config) -> bool:
        self.is_payment_complete_called = True
        self.is_payment_complete_calls += 1
        if self.is_payment_complete_raises:
            raise ConnectionError("funding source unreachable")
        return self.payment_actually_completed

    async def payment_preimage(self, payment_hash: str, config) -> bytes | None:
        if not self.payment_actually_completed:
            return None
        return self.melt_preimages.get(payment_hash)

    async def fetch_node_info(self, config) -> NodeInfo:
        uris = self.uris if self.uris is not None else [f"{self.pubkey}@127.0.0.1:9735"]
        return NodeInfo(
            alias="fakenode",
            uri=uris[0],
            uris=uris,
            color="#3399ff",
            num_channels=3,
            num_peers=5,
            capacity=750_000_000,
        )

    async def sign_message(self, message: str, config) -> tuple[bytes, int]:
        # mirrors lnd's/cln's real signmessage: sign(sha256(sha256(b"Lightning
        # Signed Message:" + message))) - see node.sign_message
        digest = sha256(sha256(b"Lightning Signed Message:" + message.encode()).digest()).digest()
        raw = self.identity_key.sign_recoverable(digest, hasher=None)
        return raw[:64], raw[64]


@pytest.fixture
def node(monkeypatch: pytest.MonkeyPatch) -> FakeNode:
    fake = FakeNode()
    monkeypatch.setattr(settings, "fundingsource_backend", "lnd")
    monkeypatch.setattr(router_module, "create_invoice", fake.create_invoice)
    monkeypatch.setattr(router_module, "is_invoice_settled", fake.is_invoice_settled)
    monkeypatch.setattr(router_module, "invoice_preimage", fake.invoice_preimage)
    monkeypatch.setattr(router_module, "pay_invoice", fake.pay_invoice)
    monkeypatch.setattr(router_module, "is_payment_complete", fake.is_payment_complete)
    monkeypatch.setattr(router_module, "payment_preimage", fake.payment_preimage)
    # cached_fetch_node_info (router.py/frontend.py's shared 1h node-info
    # cache, see node.py) wraps this same fetch_node_info - patched once,
    # here, rather than patching cached_fetch_node_info per-module, so its
    # real caching logic still runs (and is actually exercised) against the
    # fake instead of being bypassed by the patch. A fresh cache per test:
    # the module-level cache would otherwise outlive this fixture and leak
    # one test's FakeNode data into the next.
    monkeypatch.setattr(node_module, "fetch_node_info", fake.fetch_node_info)
    monkeypatch.setattr(node_module, "_node_info_cache", None)
    # no real backoff in tests - individual tests only care whether
    # _confirm_payment eventually succeeds or gives up, never how long
    monkeypatch.setattr(router_module, "_CONFIRMATION_RETRY_DELAYS_SECONDS", ())
    monkeypatch.setattr(signing_module, "fetch_node_info", fake.fetch_node_info)
    monkeypatch.setattr(signing_module, "sign_message", fake.sign_message)
    return fake


@pytest.fixture
def client(node: FakeNode) -> TestClient:
    return TestClient(app)


@pytest.fixture
def mint_note(client: TestClient, node: FakeNode):
    """Mint a settled bearer note of the given value and return its k1
    (the wallet-chosen secret), the way a wallet would obtain one: commit
    to a secret via LUD-25 comment protection (now mandatory, see
    get_pay_callback), fetch an invoice from the pay callback, then 'pay'
    it."""

    def _mint(amount_msat: int) -> str:
        secret = urandom(32)
        comment_hash = sha256(secret).hexdigest()
        response = client.get(f"/p/cb?amount={amount_msat}&comment={comment_hash}")
        assert response.json().get("pr"), response.text
        preimage = node.last_preimage
        node.settled.add(sha256(preimage).hexdigest())
        return secret.hex()

    return _mint


def melt_in_background(client: TestClient, k1: str, pr: str, monkeypatch: pytest.MonkeyPatch) -> threading.Thread:
    """Starts a melt in a background thread and blocks until it has
    actually marked the note pending AND recorded its melts row, before
    returning - deterministic, unlike racing a fixed `time.sleep()`
    against thread startup and request-dispatch overhead, which is exactly
    the kind of guess that passes reliably on a quiet machine and flakes
    under load (thread scheduling delay pushing past the sleep before the
    melt even reaches mark_pending). Waiting for record_melt on top of
    mark_pending matters for callers that immediately query
    /verify/{payment_hash}: the melts row is what keeps that endpoint from
    404ing, and get_withdraw_callback writes it a few statements AFTER
    mark_pending - a gap a preempted background thread can lose on a
    loaded machine, flaking the caller with "Not found" (this was
    test_verify.py::test_melt_verify_reports_unsettled_while_genuinely_pending
    failing in CI). record_melt only runs for invoices carrying a payment
    hash, so that wait is skipped for one without. node.pay_delay (still
    set by the caller) is what keeps the pending window open long enough
    afterward for the caller's own concurrent request to observe it - a
    single TestClient call otherwise blocks until the whole request,
    background task included, is done, so there is no other way to observe
    a melt mid-flight."""
    result: dict = {}
    marked_pending = threading.Event()
    melt_recorded = threading.Event()
    real_mark_pending = notes.mark_pending
    real_record_melt = notes.record_melt

    def _mark_pending_and_signal(note_ids, payment_hash):
        real_mark_pending(note_ids, payment_hash)
        marked_pending.set()

    def _record_melt_and_signal(payment_hash, invoice):
        real_record_melt(payment_hash, invoice)
        melt_recorded.set()

    monkeypatch.setattr(notes, "mark_pending", _mark_pending_and_signal)
    monkeypatch.setattr(notes, "record_melt", _record_melt_and_signal)

    def melt():
        result["melt"] = client.get(f"/w/cb?k1={k1}&pr={pr}").json()

    thread = threading.Thread(target=melt)
    thread.start()
    assert marked_pending.wait(timeout=5), "melt never marked the note pending"
    if bolt11.decode(pr).payment_hash:
        assert melt_recorded.wait(timeout=5), "melt never recorded its melts row"
    thread.result = result  # type: ignore[attr-defined]
    return thread
