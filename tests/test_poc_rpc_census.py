"""PoC B1 (2026-08-17 review): precise per-endpoint funding-source RPC census.

Candidate claim (hunters' P2): unauthenticated endpoints amplify into
funding-source RPCs with no caching. The hunter verification of this failed
as written at one assertion ("/w on an outstanding note made no getinfo
call" was observed once as 2 total instead of 3, then flaked green), so
this file re-measures everything from scratch with counters on all eight
node RPCs and asserts exact per-request deltas.

Update (2026-08-18): GET /'s and the mint-address endpoint's getinfo calls
are no longer 1:1 with requests - both now go through
node.cached_fetch_node_info, a shared 1h in-process cache (see node.py) -
so this file's own getinfo assertions were updated to match rather than
left as a stale "no caching" pin. mint_pubkey's getinfo (GET /w, via
signing.py) is deliberately still live/uncached, and every other RPC here
is unrelated to node info entirely - both remain exactly 1:1 as before.

All local/safe: FakeNode + TestClient + throwaway db.
"""

import time
from hashlib import sha256

import bolt11
import pytest
from fastapi.testclient import TestClient

import lnurl_mint.frontend as frontend_module
import lnurl_mint.node as node_module
import lnurl_mint.router as router_module
import lnurl_mint.signing as signing_module
from lnurl_mint.config import settings
from lnurl_mint.db import notes
from tests.conftest import FakeNode, fake_invoice, fresh_secret, melt_in_background

RPC_NAMES = (
    "create_invoice",
    "is_invoice_settled",
    "invoice_preimage",
    "pay_invoice",
    "is_payment_complete",
    "payment_preimage",
    "fetch_node_info",
    "sign_message",
)


class RpcCensus:
    """Wraps every FakeNode RPC method with a counter; deltas() reports
    per-RPC counts since the last snapshot()."""

    def __init__(self, node: FakeNode, monkeypatch: pytest.MonkeyPatch) -> None:
        self.counts = dict.fromkeys(RPC_NAMES, 0)
        self._snapshot = dict(self.counts)
        for name in RPC_NAMES:
            original = getattr(node, name)

            async def counting(*args, _original=original, _name=name, **kwargs):
                self.counts[_name] += 1
                return await _original(*args, **kwargs)

            for module in (router_module, frontend_module, signing_module):
                if getattr(module, name, None) is not None and name in module.__dict__:
                    monkeypatch.setattr(module, name, counting)
            if name == "fetch_node_info":
                # router.py/frontend.py no longer hold their own
                # fetch_node_info reference - they call
                # node.cached_fetch_node_info, which reaches the fake via
                # node.py's own module-global fetch_node_info name (see
                # conftest.py's node fixture) - counted there instead
                monkeypatch.setattr(node_module, "fetch_node_info", counting)

    def deltas(self) -> dict[str, int]:
        delta = {name: self.counts[name] - self._snapshot[name] for name in RPC_NAMES}
        self._snapshot = dict(self.counts)
        return {name: n for name, n in delta.items() if n}


@pytest.fixture
def census(node: FakeNode, monkeypatch: pytest.MonkeyPatch) -> RpcCensus:
    # /verify must be served at all for its RPC cost to be exercised -
    # VERIFY_ENABLED=false (the test-env default) 404s it since the review
    monkeypatch.setattr(settings, "verify_enabled", True)
    return RpcCensus(node, monkeypatch)


def test_frontend_index_getinfo_cached_across_requests(client: TestClient, census: RpcCensus):
    # GET / renders the node table via node.cached_fetch_node_info - only
    # the first request within the 1h TTL actually hits the funding source
    assert client.get("/").status_code == 200
    assert census.deltas() == {"fetch_node_info": 1}
    for _ in range(2):
        assert client.get("/").status_code == 200
        assert census.deltas() == {}
    # static asset: no RPC at all
    assert client.get("/favicon.svg").status_code == 200
    assert census.deltas() == {}


def test_pay_endpoints_no_rpc(client: TestClient, census: RpcCensus):
    # the LUD-16 alias (this mint's only payRequest entry point) is pure
    # settings arithmetic - zero RPCs.
    assert client.get("/.well-known/lnurlp/mint").status_code == 200
    assert census.deltas() == {}


def test_pay_callback_one_create_invoice_per_call_stateful_bloat(client: TestClient, census: RpcCensus):
    # Every /p/cb mints a fresh invoice on the node (1 RPC) and a row in the
    # local mints table - both persist forever if never paid. On a real
    # lnd/cln backend the invoice persists in the *node's* database too,
    # making this a stateful bloat vector against the funding source, not
    # just a CPU one.
    prs = set()
    for _ in range(3):
        _, comment = fresh_secret()
        resp = client.get(f"/p/cb?amount=50000&comment={comment}")
        assert resp.status_code == 200
        prs.add(resp.json()["pr"])
        assert census.deltas() == {"create_invoice": 1}
    assert len(prs) == 3
    # three unpaid pending mints now sit in the local db (and would sit in
    # the node's invoice db on a real backend)
    import bolt11

    pending = [notes.pending_mint(bolt11.decode(pr).payment_hash) for pr in prs]
    assert all(amount == 50_000 for amount in pending)


def test_withdraw_info_census(client: TestClient, node: FakeNode, mint_note, census: RpcCensus):
    # case 1: first /w on a settled-but-not-yet-materialized mint k1:
    # 1 is_invoice_settled (lazy settlement) + 1 fetch_node_info (mint_pubkey)
    k1 = mint_note(10_000)
    census.deltas()  # discard /p/cb's own create_invoice
    assert client.get(f"/w?k1={k1}").status_code == 200
    assert census.deltas() == {"is_invoice_settled": 1, "fetch_node_info": 1}

    # case 2: same note again - now materialized locally, so the settlement
    # probe is gone, but mint_pubkey (signing.py L30-48) has NO cache:
    # still exactly 1 getinfo-class RPC per request, forever.
    for _ in range(3):
        assert client.get(f"/w?k1={k1}").status_code == 200
        assert census.deltas() == {"fetch_node_info": 1}

    # case 3: /w on an *unsettled* pending mint's k1 (the preimage is only
    # learnable by the payer, but the shape matters for the census): the
    # lazy settlement probe fires on EVERY request - no negative caching -
    # and the ERROR short-circuits before mint_pubkey. (Lnurl routes answer
    # errors as HTTP 200 + {"status": "ERROR", ...} - see error_handler.py.)
    unsettled_k1, comment = fresh_secret()
    resp = client.get(f"/p/cb?amount=50000&comment={comment}")
    assert resp.status_code == 200
    census.deltas()  # discard /p/cb's own create_invoice
    for _ in range(3):
        r = client.get(f"/w?k1={unsettled_k1}")
        assert r.json() == {"status": "ERROR", "reason": "Unknown note."}
        assert census.deltas() == {"is_invoice_settled": 1}

    # case 4: unknown k1 (valid hex, never issued) - no RPC, pure local ERROR
    random_k1, _ = fresh_secret()
    r = client.get(f"/w?k1={random_k1}")
    assert r.json() == {"status": "ERROR", "reason": "Unknown note."}
    assert census.deltas() == {}

    # case 5: spent note - answered from the local spent flag, no RPC
    spent_k1 = mint_note(10_000)
    _, h = fresh_secret()
    assert client.get(f"/w/cb?k1={spent_k1}&p1={h}").json()["status"] == "OK"
    census.deltas()  # discard the rotate's own sign_message
    r = client.get(f"/w?k1={spent_k1}")
    assert r.json() == {"status": "ERROR", "reason": "Note already spent."}
    assert census.deltas() == {}


def test_verify_census_unsettled_mint_polls_forever(client: TestClient, node: FakeNode, census: RpcCensus):
    # an unpaid mint invoice polled via /verify: 1 is_invoice_settled RPC
    # per poll, forever - no negative caching, and (checked live against a
    # real node) this continues even after the invoice would have expired
    # node-side. Comment protection (LUD-25) is what gets verify served at
    # all here - see router.get_pay_callback.
    _, comment = fresh_secret()
    client.get(f"/p/cb?amount=50000&comment={comment}")
    ph = sha256(node.last_preimage).hexdigest()
    census.deltas()  # discard create_invoice
    for _ in range(5):
        r = client.get(f"/verify/{ph}")
        assert r.json()["settled"] is False
        assert census.deltas() == {"is_invoice_settled": 1}


def test_verify_census_settled_mint_preimage_per_poll(client: TestClient, node: FakeNode, census: RpcCensus):
    # once settled, the settlement probe short-circuits on the local minted
    # flag - but the preimage is "fetched live, never cached" by design, so
    # every poll of a settled mint still costs 1 invoice_preimage RPC,
    # forever. Comment protection (LUD-25) is what gets verify served at
    # all here - see router.get_pay_callback.
    _, comment = fresh_secret()
    client.get(f"/p/cb?amount=50000&comment={comment}")
    ph = sha256(node.last_preimage).hexdigest()
    census.deltas()
    node.settled.add(ph)
    # first poll: settles locally (1 is_invoice_settled) + fetches preimage
    r = client.get(f"/verify/{ph}")
    assert r.json()["settled"] is True
    assert r.json()["preimage"] == node.last_preimage.hex()
    assert census.deltas() == {"is_invoice_settled": 1, "invoice_preimage": 1}
    # subsequent polls: preimage only
    for _ in range(3):
        assert client.get(f"/verify/{ph}").json()["settled"] is True
        assert census.deltas() == {"invoice_preimage": 1}


def test_verify_census_melt_direction(
    client: TestClient, node: FakeNode, mint_note, census: RpcCensus, monkeypatch: pytest.MonkeyPatch
):
    k1 = mint_note(10_000)
    invoice = fake_invoice(10_000)
    melt_ph = bolt11.decode(invoice).payment_hash
    node.pay_delay = 0.3

    thread = melt_in_background(client, k1, invoice, monkeypatch)
    # melt_in_background only guarantees mark_pending has fired - give the
    # background task a moment to actually reach (and start counting) its
    # own pay_invoice call, deep inside its 0.3s pay_delay sleep, before
    # establishing the baseline below
    time.sleep(0.05)
    census.deltas()  # discard whatever accrued getting the melt in flight

    # melt genuinely in-flight (mark_pending fired, pay_invoice still
    # running): NoteStore.melt_settled isn't set yet, so this still falls
    # back to 1 is_payment_complete RPC per poll, same as before
    for _ in range(2):
        r = client.get(f"/verify/{melt_ph}")
        assert r.json()["settled"] is False
        assert census.deltas() == {"is_payment_complete": 1}

    thread.join()
    assert thread.result["melt"]["status"] == "OK"  # type: ignore[attr-defined]

    # once _melt_pay finalizes (NoteStore.mark_melt_settled), `settled`
    # is answered locally - zero RPCs, not re-derived from the funding
    # source on every poll. `preimage` is still fetched live, never
    # cached, so payment_preimage costs 1 RPC per poll regardless.
    node.payment_actually_completed = True
    for _ in range(2):
        r = client.get(f"/verify/{melt_ph}")
        assert r.json()["settled"] is True
        assert r.json()["preimage"] is not None
        assert census.deltas() == {"payment_preimage": 1}


def test_withdraw_callback_signing_rpcs(client: TestClient, node: FakeNode, mint_note, census: RpcCensus):
    def minted_materialized_note(amount_msat: int) -> str:
        """A settled note already materialized locally (via /w), with all
        of its mint/resolve RPCs discarded from the census - so the deltas
        below measure the /w/cb call alone."""
        k1 = mint_note(amount_msat)
        assert client.get(f"/w?k1={k1}").status_code == 200
        census.deltas()
        return k1

    # rotate: 1 sign_message per request, never cached
    k1 = minted_materialized_note(10_000)
    _, h = fresh_secret()
    assert client.get(f"/w/cb?k1={k1}&p1={h}").json()["status"] == "OK"
    assert census.deltas() == {"sign_message": 1}

    # split: 2 sign_message per request (one per new note)
    k1 = minted_materialized_note(10_000)
    _, h = fresh_secret()
    _, h2 = fresh_secret()
    assert client.get(f"/w/cb?k1={k1}&p1={h}&p2={h2}&amount=4000").json()["status"] == "OK"
    assert census.deltas() == {"sign_message": 2}

    # merge: 1 sign_message per request (regardless of input count)
    k1a, k1b = minted_materialized_note(10_000), minted_materialized_note(10_000)
    _, h = fresh_secret()
    assert client.get(f"/w/cb?k1={k1a}&k1={k1b}&p1={h}").json()["status"] == "OK"
    assert census.deltas() == {"sign_message": 1}

    # melt: 1 pay_invoice (background task, runs within the TestClient
    # request) + no signing; note value crosses the Lightning network
    k1 = minted_materialized_note(10_000)
    assert client.get(f"/w/cb?k1={k1}&pr={fake_invoice(10_000)}").json()["status"] == "OK"
    assert census.deltas() == {"pay_invoice": 1}
