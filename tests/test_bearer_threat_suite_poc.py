"""Adversarial threat-suite for the bearer-note transport/exposure options
in the LUD-25 design debate (2026-08): one executable scenario per
scorecard row, so candidate fixes get measured against the same attacks
instead of argued about in the abstract.

Options under test:
  A  status quo (lnurl/luds PR #301 as drafted)
  B  A + comment-secret: WALLET attaches a secret's hash, in the clear, to
     the mint on the payRequest (LUD-12 `comment = hex(sha256(secret))`,
     no encryption); once settled the note's k1 becomes `secret` itself
     (not a composite - see luds@cec741b, which simplified this from the
     original encrypted/composite sketch below) and the public LUD-21
     preimage alone no longer redeems anything. LANDED - see
     router.get_pay_callback/NoteStore.mint_uses_comment.
  C  "?p= everywhere": every k1 replaced in transport by that k1 encrypted
     to the mint
  D  A + hash-keyed informational GET (poll /w by sha256(k1), never k1)
  E  blinded signatures (chaumian model)
  F  B + D
  G  locked notes - a second ASSET CLASS, not a bearer variant: the k1
     stays a short plaintext secret, but redemption requires an LUD-04
     signature from the LUD-05/LUD-13 linkingKey registered at
     mint/rotate time. Signature-gated, so no ciphertext in URLs
     anywhere. Scored separately below - the trades differ by note type.

Scorecard (+ = attack fails / property holds, - = attack succeeds):

  scenario                                    A   B   C   D   E   F   covered by
  T1 verify race                              -   +   -   -   -   +   tests/test_poc_verify_race.py
  T2 routing-node race (no verify needed)     -   +   -   -   -   +   test_t2_..., below
  T3 poll-log replay                          -   -   -   +   -   +   test_t3_...
  T4 callback-log replay (control)            +   +   +   +   +   +   test_t4_...
  T5 note at rest (bearer axiom, control)     -   -   -   -   -   -   test_t5_...
  T6 operator correlation                     -   -   -   -   +   -   test_t6_...
  T7 legacy LUD-03 melt                       +   +   -   +   +   +   melt tests in test_lnurlcash.py / test_verify.py
  T8 first-contact offline verify             -   -   -   -   -   -   analytical: needs mintPubkey on record -
                                                                        a spec-level gap, no endpoint to hit
  T9 comment silently ignored today           -   +   -   -   -   +   test_t9_..., below
  T10 merge URL budget                        +   +   -   +   +   +   test_t10_...
  T11 offline handoff                         +   +   +   +   +   +   structural: no endpoint - the bearer
                                                                        property itself (the spec's
                                                                        Offline circulation section)

Option G (locked notes) against the same scenarios - note where it wins
and what it costs:
  T1/T2 + : the wallet authenticates at /p/cb, so the note is locked to
    its linkingKey from birth - a racer holding only P cannot redeem, no
    comment-secret needed for these notes
  T3/T4 + : a logged k1 is useless without the key
  T5    + : the ONLY option that beats the at-rest axiom - precisely
    because it gives up the property the axiom protects
  T6    - : the operator knows exactly which key owns which notes
  T7    - : a plain LUD-03 wallet cannot lnurl-auth - no legacy story
  T11   - : offline handoff dies; transfer needs an online re-lock via
    the mint. That is the whole price: locked notes are registered
    claims, not cash. Bearer core (B/D) and locked notes (G) are
    complements, not competitors - ship the bearer-side race fixes now,
    spec G as the extension for claim-check use cases.

C's three '-' marks in T1/T2/T3 all come from the same place: encrypting
to the mint is a PUBLIC operation (mintPubkey is advertised), so a racer
wraps a leaked preimage himself and replays it, and a logged "p" redeems
exactly like a logged k1 - the mint honors the ciphertext, so the
ciphertext IS the note. Re-encrypting a bearer credential to the party
that redeems it never shrinks its exposure set; the only encryption that
helps is encrypting to the HOLDER, which kills bearer-ness (G takes that
trade deliberately, via signatures rather than ciphertext).

Seed-recoverable notes (no protocol change beyond D needed): a WALLET
that derives its note secrets deterministically from its seed (BIP32,
reusing LUD-05's own m/138'/HMAC(domain) path trick, plus a counter) can
restore outstanding notes from the seed alone: re-derive candidates,
hash them, look them up by sha256 - option D doubles as the restore API.
Freshly minted notes (k1 = the mint-generated preimage) are never
seed-derived; they live in the wallet's Lightning payment history until
rotate-on-receipt converts them into seed-derived ones - the security
rule and the backup rule are the same act. Restore covers device loss,
NOT theft: anyone who copied a circulating note may have spent it long
before the restore runs. (Cashu's NUT-13 already does deterministic
secrets - this is parity, not invention.) Pin ONE derivation convention
in the spec, or wallets fragment and restores silently miss notes.

Red/green policy (same convention as the hodl-invoice PoC,
test_melt_restore_double_payout_poc.py): tests documenting an attack that
succeeds TODAY assert the current vulnerable behavior and say "INVERTS
WHEN" in their docstring - the PR landing the named option flips them
red, forcing the assertions to be rewritten against the fixed behavior.
Control tests (T4, T5) assert behavior that must never change.

Implementation notes for the option-B PR, found while writing this suite:
- router._resolve_note's HEX32_PATTERN rejects any k1 that isn't 64
  lowercase hex - a composite "<secret>:<preimage>" k1 dies at the door.
  That PR must relax the pattern (NoteStore ids stay sha256 over the
  composite's raw bytes, so payment-hash-keyed mints keep working).
- router.py's own docstrings already cite "the spec's Security
  considerations" for the rotate-immediately rule - a section LUD-25 does
  not yet contain. This suite is that section's executable skeleton.
"""

from hashlib import sha256

from fastapi.testclient import TestClient

from lnurl_mint.config import settings
from lnurl_mint.db import notes
from tests.conftest import fresh_secret

VALUE = 50_000


def test_t2_routing_node_race_p_alone_is_sufficient(client: TestClient, mint_note):
    """T2 - deliberately NOT fixed for a WALLET that skips comment
    protection: `mint_note` here mints with no `comment` at all, the
    no-comment fallback LUD-25 keeps for backward compatibility with
    wallets that don't (or choose not to) implement it. See
    test_t2b_comment_protected_note_defeats_the_routing_node_race for the
    protected case, where this exact attack now fails.

    VERIFY_ENABLED is off (the conftest default): no /verify leak at all.
    The attacker is a routing node on the mint payment's path - it learns
    the preimage P as the settling HTLC propagates back, no spec endpoint
    involved. In the fallback, P alone redeems, so the attacker rotates the
    note onto its own h the moment the payment settles, before the payer's
    wallet does, and wins."""
    k1 = mint_note(VALUE)  # victim pays; P (returned here) is now the note

    # ATTACKER (any routing hop, holding only P): rotate immediately
    _, attacker_h = fresh_secret()
    r = client.get(f"/w/cb?k1={k1}&p1={attacker_h}").json()
    assert r["status"] == "OK"  # ATTACK SUCCEEDS in the no-comment fallback
    assert notes.note_amount(attacker_h) == VALUE

    # the legitimate payer arrives a moment later with the same P - too late
    _, victim_h = fresh_secret()
    r = client.get(f"/w/cb?k1={k1}&p1={victim_h}").json()
    assert r == {"status": "ERROR", "reason": "Invalid or already spent k1."}


def test_t2b_comment_protected_note_defeats_the_routing_node_race(client: TestClient, node):
    """T2, protected case - a WALLET that DOES attach LUD-25 comment
    protection is immune to this exact attack: the routing node still
    learns P, same as always (ordinary Lightning routing, not a spec
    endpoint), but P was never the note's k1 to begin with - the note is
    keyed by the WALLET-held `secret` behind `comment` instead, which no
    routing node ever sees."""
    victim_secret, comment = fresh_secret()
    resp = client.get(f"/p/cb?amount={VALUE}&comment={comment}")
    assert resp.json()["pr"]
    p = node.last_preimage.hex()
    node.settled.add(sha256(node.last_preimage).hexdigest())

    # ATTACKER (any routing hop, holding only P): rotating with it fails -
    # P never became this note's k1
    _, attacker_h = fresh_secret()
    r = client.get(f"/w/cb?k1={p}&p1={attacker_h}").json()
    assert r == {"status": "ERROR", "reason": "Invalid or already spent k1."}
    assert notes.note_amount(attacker_h) is None

    # the legitimate payer's own held secret redeems the note, no race at all
    _, victim_h = fresh_secret()
    r = client.get(f"/w/cb?k1={victim_secret}&p1={victim_h}").json()
    assert r["status"] == "OK", r
    assert notes.note_amount(victim_h) == VALUE


def test_t3_informational_poll_leaks_the_live_note(client: TestClient, mint_note):
    """T3 - INVERTS WHEN option D (hash-keyed informational GET) lands.

    Checking a note's value means GET /w?k1=<live bearer secret> - purely
    informational, it burns nothing - so every poll leaves the SPENDABLE k1
    in whatever retains request URLs (reverse proxy, access log, browser
    history on a shared device). Anyone reading that line afterward can
    rotate the note out from under its holder. Keying the informational GET
    by sha256(k1) instead leaves only a harmless hash in those logs, and
    this attack chain must then fail."""
    k1 = mint_note(VALUE)

    # victim checks the note's value - the poll burns nothing, but the
    # request URL carrying the live k1 is exactly what lands in logs
    r = client.get(f"/w?k1={k1}").json()
    assert r["tag"] == "withdrawRequest"
    assert r["maxWithdrawable"] == VALUE
    assert notes.note_amount(sha256(bytes.fromhex(k1)).hexdigest()) == VALUE  # still outstanding

    # ATTACKER, reading the logged URL afterward: replay the k1
    _, attacker_h = fresh_secret()
    r = client.get(f"/w/cb?k1={k1}&p1={attacker_h}").json()
    assert r["status"] == "OK"  # ATTACK SUCCEEDS today
    assert notes.note_amount(attacker_h) == VALUE


def test_t4_callback_log_replay_fails_control(client: TestClient, mint_note):
    """T4 - control, must hold under EVERY option: a k1 captured from a
    MUTATING callback's URL was burned by the very request it rode in on,
    so replaying it after the fact can never work. (A replay landing in
    the same millisecond as the original is a plain race, not a logging
    problem.)"""
    k1 = mint_note(VALUE)
    new_k1, h = fresh_secret()
    r = client.get(f"/w/cb?k1={k1}&p1={h}").json()
    assert r["status"] == "OK"
    assert notes.note_amount(sha256(bytes.fromhex(new_k1)).hexdigest()) == VALUE

    # ATTACKER, reading the logged callback URL after the fact: replay it
    _, attacker_h = fresh_secret()
    r = client.get(f"/w/cb?k1={k1}&p1={attacker_h}").json()
    assert r == {"status": "ERROR", "reason": "Invalid or already spent k1."}
    assert notes.note_amount(h) == VALUE  # the rotated note is untouched


def test_t5_note_at_rest_is_cash_control(client: TestClient, mint_note):
    """T5 - the bearer axiom, expected to "fail" under every option
    forever: a note URL sitting in a chat log, a screenshot or a printed QR
    IS the money, and whoever finds it spends it. Not a bug and not fixable
    without killing bearer-ness itself - pinned here so the scorecard's
    all-minus row stays deliberate, and so any future option claiming to
    fix at-rest exposure has to answer this test first."""
    k1 = mint_note(VALUE)  # circulates as lnurlw://testserver/w?k1=<k1>&amount=...

    # FINDER of the URL, whoever and wherever they are: spend it
    _, finder_h = fresh_secret()
    r = client.get(f"/w/cb?k1={k1}&p1={finder_h}").json()
    assert r["status"] == "OK"
    assert notes.note_amount(finder_h) == VALUE


def test_t6_operator_can_link_rotate_to_later_spend(client: TestClient, mint_note):
    """T6 - the privacy row only option E (blinded signatures) wins. At
    rotate time WALLET discloses h = sha256(new_k1), and the mint keys its
    storage by exactly that h - so when new_k1 is later spent, its hash
    matches a recorded h and issuance links to redemption into a full
    transaction graph. h-preimages give log confidentiality (see T4) but
    NOT unlinkability from the operator; only blinding does. Pinned so the
    scorecard's E column can't be claimed for free by the other options."""
    k1 = mint_note(VALUE)
    new_k1, h = fresh_secret()
    r = client.get(f"/w/cb?k1={k1}&p1={h}").json()
    assert r["status"] == "OK"

    # the mint's storage key for the new note is verbatim the h it was
    # given - the correlation is exact, not inferred
    assert notes.note_amount(h) == VALUE
    assert sha256(bytes.fromhex(new_k1)).hexdigest() == h

    # ...so a later spend of new_k1 matches the recorded h one-to-one
    _, h2 = fresh_secret()
    r = client.get(f"/w/cb?k1={new_k1}&p1={h2}").json()
    assert r["status"] == "OK"


def test_t10_merge_url_budget_plaintext_fits_encrypted_does_not():
    """T10 - pure URL arithmetic against the ~2000 character practical GET
    budget (LUD-12's own note on URL length), no endpoints involved. A
    merge callback carries one k1 per input note plus p1 for the result: 25
    inputs in plaintext hex fit comfortably; the same merge with every k1
    swapped for an encrypted-to-the-mint blob (option C: 33-byte ephemeral
    pubkey + 12-byte nonce + 32-byte ciphertext + 16-byte tag = 93 bytes,
    124 base64 chars) does not. This mint's max_k1s=100 is unreachable in
    BOTH variants under the budget (plaintext caps ~28, blobs cap ~15) -
    option C would halve the merge ceiling in exchange for nothing, per
    T1/T2/T3's footnote."""
    base = "http://testserver/w/cb?"
    h_param = "&p1=" + "0" * 64

    plaintext = base + "&".join(f"k1={'a' * 64}" for _ in range(25)) + h_param
    assert len(plaintext) <= 2000

    blob = "A" * 124  # option-C encrypted k1, base64 - math in the docstring
    encrypted = base + "&".join(f"p={blob}" for _ in range(25)) + h_param
    assert len(encrypted) > 2000


def test_t9_malformed_comment_is_now_rejected_outright(client: TestClient, node, monkeypatch):
    """T9 - INVERTED AGAIN: option B (comment-secret) landed, per the
    simplified design in luds@cec741b (plain `comment = hex(sha256(secret))`,
    no encryption, no composite k1 - superseding this file's original
    "<secret>:<preimage>" sketch above), and `comment` was originally a soft
    requirement - a malformed or absent one silently fell back to the
    ordinary k1=P note (fail-open, just visibly so via withheld verify).

    That fallback is now closed entirely: comment protection is mandatory
    (router.get_pay_callback), and a malformed or absent `comment` (like the
    bogus non-hex string here) is a hard rejection - fail-closed, no invoice
    created, nothing for a wallet to end up holding at all."""
    monkeypatch.setattr(settings, "verify_enabled", True)
    r = client.get("/p/cb?amount=50000&comment=this-will-be-ignored").json()
    assert r["status"] == "ERROR"
    assert "comment" in r["reason"].lower()
