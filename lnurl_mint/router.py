import asyncio
import json
import logging
import re
import threading
import time
from hashlib import sha256
from http import HTTPStatus
from typing import Awaitable, Callable

import bolt11
from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, Request

from . import bech32m, derivation, spend
from . import nostr as nostr_module
from .config import settings
from .db import OutputCollisionError, PendingNoteError, notes
from .error_handler import LnurlErrorResponseHandler
from .errors import log_internal_error
from .mint_log import log_melt, log_mint
from .models import (
    LnurlErrorResponse,
    LnurlMintAddressResponse,
    LnurlPayActionResponse,
    LnurlPayResponse,
    LnurlPayVerifyResponse,
    LnurlWithdrawResponse,
    Nip05Response,
    RegisterUsernameResponse,
    WithdrawSuccessResponse,
)
from .node import (
    LightningBackendConfig,
    cached_fetch_node_info,
    create_invoice,
    invoice_preimage,
    is_invoice_settled,
    is_payment_complete,
    pay_invoice,
    payment_preimage,
)
from .signing import mint_pubkey, sign_note, verify_register_signature

router = APIRouter()
router.route_class = LnurlErrorResponseHandler


def _funding_source() -> LightningBackendConfig:
    funding_source = settings.funding_source()
    if not funding_source.backend:
        raise HTTPException(HTTPStatus.BAD_REQUEST, "This mint's funding source is not configured.")
    return funding_source


# backoff between is_payment_complete retries, when pay_invoice's own
# outcome was ambiguous - gives a momentary funding-source hiccup (the one
# case a retry can actually fix) a chance to clear before _melt_pay gives
# up and leaves the notes pending for manual reconciliation. ~31s total.
_CONFIRMATION_RETRY_DELAYS_SECONDS = (1, 2, 4, 8, 16)

# payment hashes with a live, in-process melt attempt - registered by
# get_withdraw_callback the moment mark_pending succeeds (before the
# response goes out and the background task even starts) and dropped by
# _melt_pay when it finishes. reconcile_pending_melts skips these: for a
# live attempt the funding source can legitimately report "payment
# unknown" (lnd's TrackPaymentV2 404, cln's empty listpays) simply because
# pay_invoice's RPC hasn't landed yet, and restoring the note then frees
# it while its payment is still going out - a double spend (regression
# tests: tests/test_poc_reconcile_inflight_race.py). A note left pending
# by a crashed or restarted process is never in this map (background tasks
# don't survive a restart), so reconcile still picks those up exactly as
# before. Refcounted: two melts of different notes into the same invoice
# share one payment hash. All normal access is on the event loop, but the
# lock keeps the refcount correct when tests drive requests from threads.
_in_flight_melts: dict[str, int] = {}
_in_flight_melts_lock = threading.Lock()


def _track_melt_start(payment_hash: str) -> None:
    with _in_flight_melts_lock:
        _in_flight_melts[payment_hash] = _in_flight_melts.get(payment_hash, 0) + 1


def _track_melt_end(payment_hash: str) -> None:
    with _in_flight_melts_lock:
        remaining = _in_flight_melts.get(payment_hash, 0) - 1
        if remaining > 0:
            _in_flight_melts[payment_hash] = remaining
        else:
            _in_flight_melts.pop(payment_hash, None)


def _melt_in_flight(payment_hash: str) -> bool:
    with _in_flight_melts_lock:
        return payment_hash in _in_flight_melts


async def _confirm_payment(
    payment_hash: str, funding_source: LightningBackendConfig, delays: tuple[int, ...] | None = None
) -> bool | None:
    """Retries is_payment_complete with backoff, returning its definitive
    True/False once it manages to answer, or None if every attempt raised.
    Isolated from _melt_pay's own try/except so a still-failing funding
    source doesn't get mistaken for one that answered False.

    `delays` defaults (via None, resolved here rather than bound as the
    parameter's own default - a module-level default would be captured
    once at import time, permanently, deaf to tests monkeypatching the
    module constant afterward) to the melt-time backoff, appropriate for a
    live request a wallet is waiting on. reconcile_pending_melts passes
    `()` instead - a single attempt per pending note - since retrying
    there would make a boot with several stuck notes take minutes; the
    next boot is itself the retry for whatever still can't be confirmed."""
    if delays is None:
        delays = _CONFIRMATION_RETRY_DELAYS_SECONDS
    for delay in (0, *delays):
        if delay:
            await asyncio.sleep(delay)
        try:
            return await is_payment_complete(payment_hash, funding_source)
        except Exception as exc:
            logging.warning("confirm payment %s: attempt failed, retrying: %s", payment_hash, exc)
    return None


async def _melt_pay(
    note_ids: list[str], pr: str, decoded: bolt11.types.Bolt11, funding_source: LightningBackendConfig
) -> None:
    """Pays `pr` from `note_ids`, which the caller (get_withdraw_callback)
    has already validated and reserved via NoteStore.mark_pending - *after*
    that caller has already replied {"status": "OK"} to the wallet. Per
    LUD-03 step 6, SERVICE responds immediately and only then attempts the
    payment asynchronously, so this runs as a FastAPI BackgroundTask and
    has no way left to report back to the wallet: every path below must
    itself decide finalize (NoteStore.finalize_melt, burns the notes for
    good), restore (NoteStore.restore, leaves them outstanding again), or -
    when neither can be justified - leave them pending for an operator to
    resolve by hand once they've confirmed the true outcome directly
    against the funding source. Never raise. A failure only a
    wallet-visible retry could otherwise fix (e.g. paying a completely
    different invoice) has no such mechanism here - the wallet learns of a
    failed melt only by its own invoice never getting paid, per spec.

    Finalizes only once the payment is positively confirmed settled, and
    restores only once it's positively confirmed not to have gone through.
    A bearer note MUST NOT be destroyed on a guess: if the outcome can't be
    established either way even after _confirm_payment's retries, the
    notes are left pending (see log_internal_error's reference id) rather
    than assumed one way or the other - the note stays frozen and unusable
    until an operator restores or finalizes it manually, but never
    disappears on its own.

    A PaymentFailed from pay_invoice is a clean failure *response*, not
    proof no HTLC remains outstanding - a malicious payee holding a hodl
    invoice can make the funding source give up and report exactly this
    kind of failure while still holding an already-sent HTLC open (see
    PaymentFailed's own docstring). It's therefore handled the same as any
    other raise below: still confirmed independently before anything is
    restored, never treated as reason enough on its own."""
    # decoded.amount_msat is already validated equal to total_msat by the
    # caller (get_withdraw_callback) before this background task is even
    # scheduled - an amountless invoice would already have failed there
    amount_msat = decoded.amount_msat
    assert amount_msat is not None

    try:
        try:
            result = await pay_invoice(pr, funding_source, _melt_fee_limit_msat(amount_msat))
        except Exception as exc:
            if not decoded.has_payment_hash:
                log_internal_error(
                    f"melt {note_ids}: error paying invoice, nothing to confirm against - left pending", exc
                )
                return
            completed = await _confirm_payment(decoded.payment_hash, funding_source)
            if completed is None:
                log_internal_error(
                    f"melt {note_ids}: could not confirm payment status after retries - left pending", exc
                )
                return
            if not completed:
                logging.info("melt %s: confirmed not paid (%s) - restoring", note_ids, exc)
                notes.restore(note_ids)
                return
            notes.finalize_melt(note_ids)
            notes.mark_melt_settled(decoded.payment_hash)
            # routing fee unknown here - confirmed via is_payment_complete
            # (a status check), not pay_invoice's own response, which is the
            # only place either backend reports the fee actually paid
            log_melt(note_ids, amount_msat, None)
            return

        notes.finalize_melt(note_ids)
        if decoded.has_payment_hash:
            notes.mark_melt_settled(decoded.payment_hash)
        log_melt(note_ids, amount_msat, result.fee_msat)
    finally:
        # the attempt is over, whatever its outcome - drop the in-flight
        # registration (see _in_flight_melts) so a note this left pending
        # becomes visible to reconcile_pending_melts again
        _track_melt_end(decoded.payment_hash)


async def reconcile_pending_melts(funding_source: LightningBackendConfig) -> None:
    """Resolves every note _melt_pay left pending without resolving (see
    NoteStore.pending_melts) - a note only ends up there if its melt's
    outgoing payment outcome couldn't be established, whether from a crash
    mid-melt, a restart before the background task finished, or _melt_pay's
    own left-pending fallback for a genuinely unconfirmable outcome (see
    its docstring). Called from server.py's lifespan at boot and from its
    monitor on every healthy tick, so an operator doesn't have to resolve
    these by hand - just keep the funding source up. Same
    confirm-before-acting discipline as _melt_pay: a note that still can't
    be confirmed here is logged and left exactly as it was, to be retried
    at the next tick or boot.

    Notes whose melt attempt is still live IN THIS process are skipped (see
    _in_flight_melts): for those, the funding source can report "payment
    unknown" - lnd's TrackPaymentV2 404, cln's empty listpays - simply
    because pay_invoice's RPC hasn't landed yet, and a restore here would
    free the note while its payment is still going out (a double spend -
    regression tests: tests/test_poc_reconcile_inflight_race.py). Their own
    _melt_pay resolves them."""
    for payment_hash, note_ids in notes.pending_melts().items():
        if _melt_in_flight(payment_hash):
            continue
        completed = await _confirm_payment(payment_hash, funding_source, delays=())
        if completed is None:
            # same log_internal_error as _melt_pay's own left-pending case
            # (not just logging.warning) - otherwise a note that outlives
            # its original melt (interrupted by a restart before that
            # melt's own 31s of retries finished) never reaches error.log
            # at all: every later boot's reconcile attempt would hit this
            # same still-unconfirmed outcome and only ever warn to stdout,
            # forever, with no durable record anywhere an operator would
            # find it
            log_internal_error(
                f"reconcile: melt {note_ids} still unconfirmed at boot - left pending",
                RuntimeError(f"is_payment_complete could not confirm payment_hash={payment_hash}"),
            )
            continue
        if completed:
            # fetched before finalize_melt, which marks these spent - a
            # spent note's own value is no longer readable afterward
            amount_msat = sum(notes.note_amount(note_id) or 0 for note_id in note_ids)
            notes.finalize_melt(note_ids)
            notes.mark_melt_settled(payment_hash)
            logging.info("reconcile: melt %s confirmed paid at boot - finalized", note_ids)
            # routing fee unknown here too, same reason as _melt_pay's own
            # is_payment_complete-confirmed path
            log_melt(note_ids, amount_msat, None)
        else:
            notes.restore(note_ids)
            logging.info("reconcile: melt %s confirmed not paid at boot - restored", note_ids)


def _created_invoice_payment_hash(pr: str) -> str:
    """The payment hash of an invoice this mint just created, read off
    the invoice itself - only reached for backends that cannot know the
    preimage at creation time (spark, whose SSP generates it; see
    node.create_invoice). A BOLT11 invoice always commits to exactly one
    payment hash, so a decode failure or a hashless invoice here is a
    malformed backend response, logged rather than trusted."""
    try:
        decoded = bolt11.decode(pr)
    except Exception as exc:
        raise HTTPException(HTTPStatus.INTERNAL_SERVER_ERROR, log_internal_error("Error decoding created invoice", exc))
    if not decoded.has_payment_hash:
        raise HTTPException(
            HTTPStatus.INTERNAL_SERVER_ERROR,
            log_internal_error("Created invoice carries no payment hash", ValueError(pr[:64])),
        )
    return decoded.payment_hash


async def _mint_settled_by_note_id(note_id: str) -> bool:
    """Whether the LUD-25 comment-protected mint whose secret hashes to
    `note_id` has settled - lazily materializes the resulting note
    (keyed by `note_id` itself, see NoteStore.settle_mint) the first
    time settlement is observed, mirroring _mint_settled's payment-hash
    path but keyed by the WALLET-chosen secret hash instead. Used by
    _note_amount_by_id as a fallback when `note_id` doesn't name a
    payment hash directly - which is always the case once a comment was
    used, since the note's id is then unrelated to the invoice that paid
    for it."""
    pending = notes.pending_mint_by_note_id(note_id)
    if pending is None:
        return False
    payment_hash, _ = pending
    funding_source = settings.funding_source()
    if not funding_source.backend:
        return False
    if not await is_invoice_settled(payment_hash, funding_source):
        return False
    net_amount_msat = notes.settle_mint(payment_hash)
    if net_amount_msat is not None:
        _log_mint_settled(payment_hash, net_amount_msat)
    return True


async def _mint_settled(payment_hash: str) -> bool:
    """Whether the mint invoice `payment_hash` has ever settled - checks
    the funding source live and materializes the note (NoteStore.settle_mint)
    the first time settlement is observed. Used both to lazily resolve a
    note (see _note_amount_by_id) and by LUD-21 verify, which must keep
    reporting True forever once settled, even after the resulting note is
    later spent - unlike _note_amount_by_id, which answers a different
    question ("is there a spendable note *right now*")."""
    if notes.mint_settled(payment_hash):
        return True
    if notes.pending_mint(payment_hash) is None:
        return False
    funding_source = settings.funding_source()
    if not funding_source.backend:
        return False
    if not await is_invoice_settled(payment_hash, funding_source):
        return False
    net_amount_msat = notes.settle_mint(payment_hash)
    if net_amount_msat is not None:
        # None means a concurrent request already settled this same
        # invoice first (see NoteStore.settle_mint) - only the call that
        # actually performed the transition logs it, never both
        _log_mint_settled(payment_hash, net_amount_msat)
    return True


def _log_mint_settled(payment_hash: str, net_amount_msat: int) -> None:
    pr = notes.mint_pr(payment_hash)
    gross_amount_msat = None
    if pr:
        try:
            gross_amount_msat = bolt11.decode(pr).amount_msat
        except Exception:
            gross_amount_msat = None
    fee_msat = gross_amount_msat - net_amount_msat if gross_amount_msat is not None else None
    log_mint(payment_hash, gross_amount_msat, fee_msat, net_amount_msat)


async def _mint_preimage(payment_hash: str) -> str | None:
    """Hex-encoded preimage of a settled mint invoice, fetched live from the
    funding source for LUD-21 verify - never cached locally (see db.py's
    store-hashes-not-secrets policy), so this hits the node on every call
    rather than being persisted anywhere. None if there's no funding source
    to ask, or the node lookup itself fails for any reason - verify still
    reports `settled` correctly either way, just without a preimage to
    hand over."""
    funding_source = settings.funding_source()
    if not funding_source.backend:
        return None
    try:
        preimage = await invoice_preimage(payment_hash, funding_source)
    except Exception:
        return None
    return preimage.hex() if preimage else None


async def _melt_settled(payment_hash: str) -> bool:
    """Whether a melt's outgoing payment (paying `payment_hash`) has
    settled, for LUD-25's melt verify. Checks NoteStore.melt_settled first -
    the local flag _melt_pay/reconcile_pending_melts already set once they
    positively confirmed this exact melt and burned its note(s) for good -
    before ever falling back to a live is_payment_complete call: right
    after a payment lands, the funding source's own bookkeeping can still
    lag or briefly answer inconsistently (e.g. cln's listpays reporting
    "pending" for a moment after xpay itself already returned success), and
    trusting that live call alone would then report `settled: false` for a
    melt this mint already knows completed, even with the note long spent.

    Only once the local flag is unset does this fall back to a live check
    - still with the same read-only, no-note-state-to-protect treatment as
    before: unlike _confirm_payment, which must tell "confirmed not paid"
    apart from "can't tell yet" before a note is ever restored or
    finalized, still pending, a hodl HTLC held open, or a momentary
    funding-source hiccup are all reported the same as "not settled yet"
    rather than raised - a wrong answer here never burns or restores
    anything, it only tells a third party to check back later."""
    if notes.melt_settled(payment_hash):
        return True
    funding_source = settings.funding_source()
    if not funding_source.backend:
        return False
    try:
        return await is_payment_complete(payment_hash, funding_source)
    except Exception:
        return False


async def _melt_preimage(payment_hash: str) -> str | None:
    """Hex-encoded preimage of a settled outgoing payment, fetched live for
    LUD-25 melt verify - mirrors _mint_preimage, but payment_preimage
    (node.py) looks up a payment this mint *sent* rather than an invoice it
    issued. None if there's no funding source to ask, or the lookup fails
    for any reason - verify still reports `settled` correctly either way."""
    funding_source = settings.funding_source()
    if not funding_source.backend:
        return None
    try:
        preimage = await payment_preimage(payment_hash, funding_source)
    except Exception:
        return None
    return preimage.hex() if preimage else None


async def _note_amount_by_id(note_id: str) -> int | None:
    """Value of the outstanding note with id `note_id`, or None - either it
    was never minted, or it has already been spent (rotated/split/merged/
    melted away). Materializes a note whose mint invoice has settled but
    that nothing has asked about yet (see NoteStore.settle_mint), by the
    comment it was minted under."""
    amount_msat = notes.note_amount(note_id)
    if amount_msat is not None:
        return amount_msat
    if await _mint_settled_by_note_id(note_id):
        return notes.note_amount(note_id)
    return None


class _Rejected(Exception):
    """A k1 that names no note, or doesn't open the one it names. `reason`
    is safe to hand back (see spend.verify)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


_INVALID_K1 = "Invalid or already spent k1."


async def _verified_note(k1: str) -> tuple[str, int, bool, bool]:
    """(note id, value, spent, pending) of the note `k1` spends, once the
    spend is verified to open it (spend.verify) - spent notes included, so a
    retried burn can still be recognised. Raises _Rejected otherwise: with
    the generic invalid-k1 reason when `k1` is no spend or names no note on
    file (never existed and already spent stay indistinguishable here), or
    a script path's own specific reason."""
    parsed = spend.parse(k1)
    if parsed is None:
        raise _Rejected(_INVALID_K1)
    await _note_amount_by_id(parsed.note_id)
    record = notes.note_record(parsed.note_id)
    if record is None:
        raise _Rejected(_INVALID_K1)
    amount_msat, locked_at, spent, pending = record
    reason = spend.verify(parsed, locked_at, settings.spend_domains())
    if reason is not None:
        raise _Rejected(reason)
    return parsed.note_id, amount_msat, spent, pending


async def _note_by_ref(value: str) -> str | None:
    """The note id `value` names where a `cp1` goes (?p=, and every other
    cp1-shaped input): a `cp1`, or a bearer note's hex `h` (its short form).
    None if `value` is neither."""
    note_id = spend.decode_note(value)
    if note_id is None:
        return None
    await _note_amount_by_id(note_id)
    return note_id


def _mint_fee_msat(amount_msat: int) -> int:
    """The fee withheld from a mint of `amount_msat` (LUD-25's optional mint
    fee): a flat base_fee_msat plus fee_percent_ppm parts-per-million of the
    amount paid, rounded *up* to the nearest whole sat - Lightning fees are
    conventionally sat-denominated, and rounding up (rather than leaving a
    fractional-sat msat remainder) means the mint is never short a sat,
    matching or slightly exceeding the estimate a wallet derives from the
    advertised `Mint fees: ` metadata entry (see get_lnaddress)."""
    fee_msat = settings.base_fee_msat + (amount_msat * settings.fee_percent_ppm) // 1_000_000
    return -(-fee_msat // 1000) * 1000


def _min_sendable_msat() -> int:
    """The fee-inclusive floor to actually advertise as `minSendable` - a
    wallet paying settings.min_sendable_msat gross gets net_amount_msat =
    amount - _mint_fee_msat(amount) credited (see get_pay_callback), which
    /p/cb then also holds to settings.min_mint_msat. Advertising the raw
    settings.min_sendable_msat when it doesn't clear that net floor means
    paying the advertised minimum always bounces, so this walks amount up
    from the higher of the two configured floors until its net clears
    min_mint_msat too. Bounded defensively: fee_percent_ppm is validated
    to stay well below 100% (see config.py), which guarantees the walk
    terminates quickly - the cap turns any future regression of that
    guarantee into a loud error at request time rather than a worker
    spinning at 100% CPU for the process's lifetime."""
    amount_msat = max(settings.min_sendable_msat, settings.min_mint_msat)
    for _ in range(100_000):
        if amount_msat - _mint_fee_msat(amount_msat) >= settings.min_mint_msat:
            return amount_msat
        amount_msat += 1000
    raise RuntimeError("minSendable walk did not terminate - check the fee settings (fee_percent_ppm too high?)")


def max_mintable_msat() -> int:
    """The largest a freshly minted note's own value can actually reach -
    paying the advertised maxSendable (max_sendable_msat) nets
    max_sendable_msat minus whatever _mint_fee_msat withholds at that
    amount (see get_pay_callback), so whenever a mint fee is configured the
    true ceiling on a note's value sits below the raw setting, same
    fee-aware treatment _min_sendable_msat gives the floor, just for the
    other end. No walk needed here (unlike _min_sendable_msat): the fee
    is computed directly from max_sendable_msat itself, not searched for.
    Public (unlike this module's other fee helpers) because the
    mint-address discovery response and the frontend's own mint-limits
    display both need this exact number, not just router.py."""
    return settings.max_sendable_msat - _mint_fee_msat(settings.max_sendable_msat)


def _melt_fee_limit_msat(amount_msat: int) -> int:
    """The routing-fee budget for melting a note worth `amount_msat` - per
    LUD-25, the mint fee withheld at mint time "is meant to cover whatever
    routing cost SERVICE incurs paying out this note when it is eventually
    melted", so an operator charging more gets a correspondingly higher
    tolerance for this specific melt to actually find a route, rather than
    a value unrelated to what this mint actually charges (previously: a
    flat 0.5%-or-5000msat guess for lnd, cln's xpay left to its own
    built-in max(5000msat, 1%) default). Never less than that same
    0.5%/5000msat floor, though - a fee-free or low-flat-fee mint's melts
    must not start failing to route just because their configured fee
    alone would be too tight a cap for a large note."""
    return max(round(amount_msat * 0.005), 5000, _mint_fee_msat(amount_msat))


def _zaps_offered() -> bool:
    """NIP-57 zaps need a Nostr key to sign receipts with and a funding
    source that can bind an invoice to a description hash - lnd and cln
    can, spark cannot (see spark._create_invoice_spark)."""
    return settings.nostr_key is not None and settings.funding_source().backend in ("lnd", "cln")


# An unpaid zap invoice is polled for settlement this long after it was
# issued, and only this many of the newest per round. A zapping client
# pays at once or not at all, and anyone can mint unpaid zap invoices for
# free (a self-signed request is a valid one), so the poll must not grow
# with them. A zap paid outside the window still mints on the next
# lookup or verify as any invoice does; it just gets no receipt.
_ZAP_POLL_WINDOW_SECONDS = 60 * 60
_ZAP_POLL_LIMIT = 100


async def publish_zap_receipts(funding_source: LightningBackendConfig, now: int | None = None) -> int:
    """Settle every recently issued zap invoice the funding source says
    was paid (the note lands on the username's branch exactly as any
    other payment does), then publish a kind 9735 receipt for each
    settled zap that has none yet: to the relays the zap request named
    plus NOSTR_RELAYS. A receipt that no relay takes stays unpublished
    and is retried next round. Run every ZAP_POLL_INTERVAL_SECONDS by
    server.py; returns how many receipts were published."""
    now = int(time.time()) if now is None else now
    for payment_hash in notes.pending_zap_mints(now - _ZAP_POLL_WINDOW_SECONDS, _ZAP_POLL_LIMIT):
        await _mint_settled(payment_hash)
    published = 0
    assert settings.nostr_key is not None
    secret = settings.nostr_key.get_secret_value()
    for payment_hash, pr, raw in notes.unpublished_zaps():
        request = json.loads(raw)
        preimage = await _mint_preimage(payment_hash)
        receipt = nostr_module.zap_receipt(request, raw, pr, preimage, secret)
        relays = list(dict.fromkeys(nostr_module.relays_of(request) + settings.nostr_relay_list()))
        accepted = await nostr_module.publish(relays, receipt)
        if not accepted:
            logging.warning(f"zap receipt for {payment_hash} reached no relay of {relays}; will retry")
            continue
        notes.mark_zap_published(payment_hash, receipt["id"])
        published += 1
    return published


def _known_username(username: str) -> bool:
    """LUD-16's reserved default username: `_` isn't user facing - it's
    what any WALLET/directory resolving a *bare-domain* address (no
    visible user part, shown as just `{host}` rather than `_@{host}`)
    queries instead of settings.username, per spec. Accepted alongside
    settings.username (never in place of it) on both well-known aliases
    below - this mint answers identically for either name, since both
    name the same identity.

    Case-insensitive: a Lightning Address local-part is conventionally
    matched that way regardless of how a payer's client happened to
    capitalize it (this mint's own USERNAME config included - an operator
    setting USERNAME=Alice still matches alice/ALICE/Alice alike), the
    same normalization _registered_username_branch applies for a
    registered one."""
    normalized = username.lower()
    return normalized == settings.username.lower() or normalized == "_"


# a registrable username (router.upsert_registered_username): lowercase-
# only, so a stored username is always already normalized (see that
# function, which lowercases before ever calling this or
# NoteStore.upsert_username) and every lookup site can just lowercase its
# own input to match - short
# enough to stay a reasonable Lightning Address local-part. Deliberately
# excludes anything 64-hex/bech32m would also match - no registered
# username can ever be confused for a k1/comment/p1 value on another
# endpoint.
_USERNAME_PATTERN = re.compile(r"^[a-z0-9_.-]{1,32}$")


def _registered_username_branch(username: str) -> str | None:
    """The cx1 hex registered under `username` (NoteStore.username_branch),
    or None if there is none - or unconditionally None while
    username_registration_enabled is off, the same full-endpoint-off
    convention verify_enabled uses: turning it off reverts this mint to a
    single fixed identity everywhere, not just at POST/DELETE /p/{username}
    itself.
    Case-insensitive (see _known_username) - `username` is lowercased here
    before the lookup, matching how it was stored at registration time."""
    if not settings.username_registration_enabled:
        return None
    return notes.username_branch(username.lower())


def _registrable_username(username: str) -> bool:
    """Whether `username` (already lowercased by the caller - see
    upsert_registered_username) is syntactically valid AND not one of
    this mint's own reserved identities (settings.username, the
    bare-domain `_` - see _known_username) - a registered username never
    shadows this mint's own fixed identity."""
    return bool(_USERNAME_PATTERN.match(username)) and not _known_username(username)


def _owns_branch(action: str, domain: str, username: str, branch_hex: str, sig_hex: str) -> bool:
    """Whether `sig_hex` is a valid ownership-proof Schnorr signature (see
    signing.verify_register_signature) by `branch_hex`'s own index-0
    public key - "the first secret" a WALLET derives on a branch, the
    same one claim_next_index would hand a note out under first.
    `action` ("register" or "unregister"), `domain` (this mint's own
    resolved host - see call sites), and `username` are folded into the
    signed message itself, per 25.md - domain separation from a note's own
    `ck1` (see signing._CK1_SCHNORR_DIGEST); from any other username's
    proof or this same username's other action, so a signature captured
    from one overwrite/delete can never be replayed against a different
    username sharing this branch, or against the other action for this
    same one; and from any other mint, so a proof captured here can never
    be replayed by this mint against a different one. Gates every path
    through upsert_registered_username (both a fresh claim, proven against
    the NEW cx1 being submitted, and an overwrite, proven against whichever
    branch is CURRENTLY on file - see that function's own docstring for why
    those differ) and delete_registered_username outright - there is no
    proof-free case left; `sig` is a required parameter at both call
    sites, never optional."""
    branch = bytes.fromhex(branch_hex)
    branch_point, chain_code = branch[:32], branch[32:]
    expected = derivation.derive_pubkey(branch_point, chain_code, 0)
    return verify_register_signature(expected, sig_hex, action, domain, username)


@router.post("/p/{username}", tags=["lnurlcash"], response_model=RegisterUsernameResponse | LnurlErrorResponse)
def upsert_registered_username(
    req: Request, username: str, cx1: str, sig: str, npub: str | None = None
) -> RegisterUsernameResponse:
    """LUD-25 Seed & derivation's cx1 registration: claims
    `username` for a WALLET's watch-only branch export (`cx1<P || chain
    code>`), so paying `.well-known/lnurlp/{username}` with no comment
    auto-mints a fresh `cp1` note directly on that branch for every payment
    received (see get_pay_callback_for_username, NoteStore.claim_next_index)
    - no per-payment WALLET involvement needed.

    Always proven, never proof-free - even for a fresh, unclaimed
    `username`: `sig` (see _owns_branch) is a required ownership-proof
    signature over "LNURLcash:register:<domain>:<username>"
    (signing.verify_register_signature, `domain` this mint's own resolved
    host), so it can never be confused with a note's own `ck1`, another
    username's proof, this same username's unregister proof, or the same
    proof captured and replayed by a different mint. What it must prove
    differs by case, though:
    - A fresh claim proves the caller actually controls the `cx1` being
      submitted right now (signed with THAT branch's own index-0 secret
      key).
    - Calling this again on an ALREADY-registered `username` instead
      overwrites it wholesale (new `cx1`, new or absent `npub`) - proving
      continued control of the branch CURRENTLY on file instead, not of
      the new `cx1` being switched to (a WALLET migrating to a new seed
      still holds its old one long enough to sign this once).

    `username` is lowercased before validation and storage - a registered
    username is always case-insensitive (see _known_username), so this is
    the one place that normalization actually has to happen; every lookup
    site just lowercases its own input to match.

    `npub`, if given, is this same `username` doubling as a NIP-05 name
    (see get_nip05): decoded and stored alongside cx1 - rejected outright
    while settings.nip05_enabled is off, rather than accepted and stored for
    an endpoint that won't resolve it (see that setting's own docstring,
    independent of username_registration_enabled itself). Omitted on an
    overwrite, any previously registered npub is cleared - this call
    replaces the registration wholesale, it does not merge into it."""
    if not settings.username_registration_enabled:
        raise HTTPException(HTTPStatus.NOT_FOUND, "Not found")
    username = username.lower()
    if not _registrable_username(username):
        raise HTTPException(HTTPStatus.BAD_REQUEST, "Invalid or reserved username.")
    branch = bech32m.decode_cx1(cx1)
    if branch is None:
        raise HTTPException(HTTPStatus.BAD_REQUEST, "Invalid cx1.")
    nostr_pubkey_hex: str | None = None
    if npub is not None:
        if not settings.nip05_enabled:
            raise HTTPException(HTTPStatus.BAD_REQUEST, "npub registration (NIP-05) is disabled on this mint.")
        decoded_npub = bech32m.decode_npub(npub)
        if decoded_npub is None:
            raise HTTPException(HTTPStatus.BAD_REQUEST, "Invalid npub.")
        nostr_pubkey_hex = decoded_npub.hex()
    existing_branch_hex = notes.username_branch(username)
    # a fresh claim proves control of the NEW branch being submitted; an
    # overwrite proves continued control of whichever branch is CURRENTLY
    # on file instead - see this function's own docstring for why those
    # must differ
    proof_branch_hex = existing_branch_hex if existing_branch_hex is not None else branch.hex()
    _, domain = settings.public_base_url_and_host(str(req.base_url))
    if not _owns_branch("register", domain, username, proof_branch_hex, sig):
        raise HTTPException(HTTPStatus.BAD_REQUEST, "Invalid ownership signature.")
    notes.upsert_username(username, branch.hex(), nostr_pubkey_hex)
    return RegisterUsernameResponse()


@router.delete("/p/{username}", tags=["lnurlcash"], response_model=RegisterUsernameResponse | LnurlErrorResponse)
def delete_registered_username(req: Request, username: str, sig: str) -> RegisterUsernameResponse:
    """Frees `username` entirely (NoteStore.delete_username) - it goes back
    to being unclaimed, first-come-first-served for anyone, same as it was
    never registered. `sig`, an ownership-proof signature over
    "LNURLcash:unregister:<domain>:<username>" (see _owns_branch) - a
    different message than upsert_registered_username's own overwrite
    proof, so one can never be replayed as the other - is mandatory here
    too: there is no proof-free case for deleting an address someone else
    may depend on."""
    if not settings.username_registration_enabled:
        raise HTTPException(HTTPStatus.NOT_FOUND, "Not found")
    username = username.lower()
    existing_branch_hex = notes.username_branch(username)
    if existing_branch_hex is None:
        raise HTTPException(HTTPStatus.NOT_FOUND, "Unknown user.")
    _, domain = settings.public_base_url_and_host(str(req.base_url))
    if not _owns_branch("unregister", domain, username, existing_branch_hex, sig):
        raise HTTPException(HTTPStatus.BAD_REQUEST, "Invalid ownership signature.")
    notes.delete_username(username)
    return RegisterUsernameResponse()


@router.get("/.well-known/nostr.json", tags=["lnurlcash"], response_model=Nip05Response | LnurlErrorResponse)
def get_nip05(name: str | None = None) -> Nip05Response:
    """NIP-05: a registered username that supplied an npub at POST
    /p/{username} (see upsert_registered_username, NoteStore.nostr_pubkey)
    resolves here as a
    Nostr identifier too, `name@host` naming the same npub a client would
    find on a kind 0 profile's own `nostr` field. Only ever answers the
    one `name` actually asked about - never this mint's whole directory,
    even when `name` is omitted - and echoes it back verbatim as the map's
    key (not lowercased) since a verifying client indexes the response by
    the exact local-part string it queried with, same convention
    get_lnaddress's text/identifier follows. An unregistered name, one
    that never supplied an npub, or no `name` at all all come back as an
    empty map - NIP-05's own "not found", not a 404. The endpoint itself is
    disabled outright (404, not an empty map) while settings.nip05_enabled
    is off - a distinct off switch from username_registration_enabled below
    (see nip05_enabled's own docstring), for an operator who wants this
    mint's NIP-05 resolution gone entirely regardless of registration
    status. Answers (200, empty map) rather than 404 while
    username_registration_enabled itself is off, though: a name registered
    before it was turned off does not leak through here either, the same
    revert-to-fixed-identity convention _registered_username_branch
    follows."""
    if not settings.nip05_enabled:
        raise HTTPException(HTTPStatus.NOT_FOUND, "Not found")
    pubkey_hex = (
        notes.nostr_pubkey(name.lower()) if name is not None and settings.username_registration_enabled else None
    )
    return Nip05Response(names={name: pubkey_hex} if pubkey_hex is not None else {})


@router.get("/.well-known/lnurlp/{username}", tags=["lnurlcash"], response_model=LnurlPayResponse | LnurlErrorResponse)
def get_lnaddress(req: Request, username: str) -> LnurlPayResponse:
    """LUD-16 Lightning Address payRequest that mints lnurlcash bearer
    notes: `withdrawLink` points at the withdrawRequest endpoint
    (get_withdraw) that will recognize this mint's payment preimages -
    paying the invoice from the callback makes `<withdrawLink>?k1=<preimage>`
    a bearer note. The mint is payable at {settings.username}@{host} (see
    the frontend one-pager), or at the reserved bare-domain `_@{host}` (see
    _known_username) - this well-known alias is this mint's own fixed
    identity's payRequest entry point.

    Also answers for any `username` registered via POST /p/{username}
    (LUD-25's cx1 auto-mint - see get_pay_callback_for_username):
    such a username's own callback is `/p/{username}` itself, a distinct
    path rather than a query parameter on the fixed identity's `/p/cb` -
    so get_pay_callback_for_username knows which registered branch to
    derive into straight from the URL, no extra parameter needed.
    Unregistered, unrecognized names still 404.

    A registered username's metadata additionally carries a `text/xpub`
    entry (LUD-25's Internal transfer): this same branch's
    own `cx1`, appended with `:<i>`, the best-known next-unused index on
    it (NoteStore.next_index_hint). A payer's WALLET already holding a
    `cp1`/`ck1` note on this same mint can read that straight off this
    response and skip Lightning entirely - deriving `pk_i` itself and
    naming it as `p1`/`p2` on an ordinary rotate/split/merge - rather
    than paying an invoice just to reach the same auto-mint this address
    would otherwise perform. `i` is only a hint; a stale or
    already-claimed one is rejected exactly like any other p1/p2
    collision, and `WALLET` just retries at the next index. The fixed
    identity has no branch of its own, so it never carries this entry."""
    registered = _known_username(username) or _registered_username_branch(username) is not None
    if not registered:
        raise HTTPException(HTTPStatus.NOT_FOUND, "Unknown user.")
    base, host = settings.public_base_url_and_host(str(req.base_url))
    metadata_entries = [
        ["text/plain", f"Mint an lnurlcash bearer note on {host}"],
        # echoes back whichever name was actually queried (settings.username,
        # the reserved `_`, or a registered username), not always the
        # former - a WALLET that resolved this identity by any of those
        # names should see that same identity confirmed here
        ["text/identifier", f"{username}@{host}"],
    ]
    if not _known_username(username):
        branch_hex = _registered_username_branch(username)
        if branch_hex is not None:
            index_hint = notes.next_index_hint(username.lower()) or 0
            cx1 = bech32m.encode_cx1(bytes.fromhex(branch_hex))
            metadata_entries.append(["text/xpub", f"{cx1}:{index_hint}"])
    if settings.base_fee_msat or settings.fee_percent_ppm:
        # a SERVICE that omits this entry is assumed fee-free per spec, so
        # it's only added when there's actually a fee to disclose
        metadata_entries.append(["text/plain", f"Mint fees: {settings.base_fee_msat},{settings.fee_percent_ppm}"])
    metadata = json.dumps(metadata_entries)
    # a registered (non-fixed-identity) username's callback is its own
    # path, /p/{username} (get_pay_callback_for_username), rather than a
    # query parameter tacked onto the fixed identity's /p/cb - so which
    # branch to auto-derive into if the payer's WALLET doesn't supply its
    # own comment is already in the URL, no extra parameter needed
    callback = f"{base}/p/cb" if _known_username(username) else f"{base}/p/{username}"
    # NIP-57: a registered username can be zapped - the note lands on its
    # own branch with no comment needed, and the receipt is what tells the
    # zapper it landed. The fixed identity has no branch to land on.
    zappable = _zaps_offered() and not _known_username(username)
    return LnurlPayResponse(
        callback=callback,
        minSendable=_min_sendable_msat(),
        maxSendable=settings.max_sendable_msat,
        metadata=metadata,
        withdrawLink=f"{base}/w",
        allowsNostr=True if zappable else None,
        nostrPubkey=settings.nostr_pubkey() if zappable else None,
    )


async def _mint_address_response(req: Request, username: str) -> LnurlMintAddressResponse:
    base, host = settings.public_base_url_and_host(str(req.base_url))
    funding_source = settings.funding_source()
    node_alias = node_uri = node_color = mint_pubkey_value = None
    node_uris = None
    node_capacity = node_num_channels = node_num_peers = None
    if funding_source.backend:
        try:
            info = await cached_fetch_node_info(funding_source)
            node_alias = info.alias
            node_uri = info.uri
            node_uris = info.uris or None
            node_color = info.color
            node_capacity = info.capacity
            node_num_channels = info.num_channels
            node_num_peers = info.num_peers
            # same derivation as signing.mint_pubkey - reused directly
            # rather than calling that function, which would fetch_node_info
            # a second time for the exact same round trip. spark advertises
            # its dedicated seed-derived LUD-25 key rather than the node
            # identity: that's the key its notes are actually signed with
            # (see spark._lud25_signing_key), and it derives purely locally,
            # so it costs no extra network round trip either
            if funding_source.backend == "spark":
                from .spark import signing_pubkey_hex

                mint_pubkey_value = signing_pubkey_hex(funding_source)
            else:
                mint_pubkey_value = info.uri.split("@")[0] if info.uri else None
        except Exception as exc:
            logging.warning("mint address: could not reach %s funding source: %s", funding_source.backend, exc)
    return LnurlMintAddressResponse(
        callback=f"{base}/w",
        minWithdrawable=settings.min_mint_msat,
        maxWithdrawable=max_mintable_msat(),
        defaultDescription=f"lnurlcash bearer note on {host}",
        mintPubkey=mint_pubkey_value,
        payLink=f"{base}/.well-known/lnurlp/{username}",
        nodeAlias=node_alias,
        nodeUri=node_uri,
        nodeUris=node_uris,
        nodeColor=node_color,
        nodeCapacity=node_capacity,
        nodeNumChannels=node_num_channels,
        nodeNumPeers=node_num_peers,
        sunsetDate=settings.sunset_date.isoformat() if settings.sunset_date else None,
        outstandingNotesMsat=notes.outstanding_msat(),
    )


@router.get(
    "/.well-known/lnurlw/{username}", tags=["lnurlcash"], response_model=LnurlMintAddressResponse | LnurlErrorResponse
)
async def get_mint_address(req: Request, username: str) -> LnurlMintAddressResponse:
    """Theoretical mint-address alias, the withdraw-side mirror of
    get_lnaddress above - see LnurlMintAddressResponse's own docstring for
    why this is informational only (this mint's node identity/capacity,
    the amount bounds a note can fall into, and `payLink` back to the
    payRequest side), never a functional way to withdraw this mint's own
    funds. Also answers for the reserved bare-domain `_` username and any
    username registered via POST /p/{username}, same as get_lnaddress (see
    _known_username). `payLink` canonicalizes `_`/settings.username to
    settings.username either way - both name the same fixed identity, not
    two different ones to advertise - but echoes back a genuinely
    registered username as-is, since that names a distinct identity."""
    if _known_username(username):
        return await _mint_address_response(req, settings.username)
    if _registered_username_branch(username) is not None:
        return await _mint_address_response(req, username)
    raise HTTPException(HTTPStatus.NOT_FOUND, "Unknown user.")


async def _pay_callback(
    req: Request,
    amount: int,
    comment: str | None,
    nostr: str | None,
    username: str | None,
    branch: bytes | None,
) -> LnurlPayActionResponse:
    """LUD-06 callback: returns an invoice for `amount` msat whose preimage
    this mint generated itself (see node.create_invoice) - once the invoice
    settles, that preimage is an outstanding bearer note worth `amount`
    minus the advertised mint fee, if any (see _mint_fee_msat). Shared by
    get_pay_callback (this mint's own fixed identity, `username`/`branch`
    both None) and get_pay_callback_for_username (a cx1-registered
    Lightning Address, `branch` its own derivation branch, already
    resolved and lowercased by the caller - see that function's own
    docstring for why the split exists).

    `comment` (LUD-12) names the note to credit, per LUD-25's Minting: a
    `cp1<Q>` the WALLET generated, or a bearer note's hex `h` (the short
    form - see spend.decode_note), and once this invoice settles the note
    is credited at that Q (see settle_mint). The payment preimage then
    redeems nothing, closing the race a routing node forwarding this
    invoice would otherwise win by learning it. A comment of any other
    shape never falls back to a preimage-keyed note: without a registered
    branch there is no other key to mint under, so it is rejected outright.

    `comment` is REQUIRED for the fixed identity (`branch` is None), same
    as ever - but for a registered username it becomes OPTIONAL: when
    omitted, this mint derives the next unused note key on that username's
    own registered branch itself (NoteStore.claim_next_index) and credits
    the note under it, exactly as if the payer's WALLET had supplied that
    same `comment=cp1<pk>` in person (25.md's Seed & derivation) - no
    WALLET involvement needed at receive time at all. A comment that names
    an output is still honored; one that does not is the free text
    `commentAllowed` asks for, and the branch key is used instead.

    `verify` (LUD-21, only advertised if VERIFY_ENABLED) lets a wallet with
    no node of its own poll settlement status - see verify_invoice. Safe to
    always offer now that every mint uses comment protection - the
    preimage verify_invoice could hand out is never the note's bearer
    secret.

    `nostr` (NIP-57) is a zap request, a kind 9734 event as JSON, only
    taken for a registered username on a mint with NOSTR_KEY set (see
    _zaps_offered). Validated per the NIP's Appendix D, then the invoice
    is bound to it by description hash and the request kept for the
    receipt this mint publishes once the invoice settles (see
    publish_zap_receipts)."""
    if settings.sunset_mint:
        raise HTTPException(HTTPStatus.BAD_REQUEST, "This mint is sunsetting - minting is disabled.")
    if amount < settings.min_sendable_msat:
        raise HTTPException(HTTPStatus.BAD_REQUEST, "Amount too low.")
    if amount > settings.max_sendable_msat:
        raise HTTPException(HTTPStatus.BAD_REQUEST, "Amount too high.")
    net_amount_msat = amount - _mint_fee_msat(amount)
    if net_amount_msat < settings.min_mint_msat:
        raise HTTPException(
            HTTPStatus.BAD_REQUEST, f"Amount too low to mint a note (min {settings.min_mint_msat} msat net of fees)."
        )

    zap_request: str | None = None
    if nostr is not None:
        if not _zaps_offered() or branch is None:
            raise HTTPException(HTTPStatus.BAD_REQUEST, "Zaps are not offered for this address.")
        _, problem = nostr_module.validate_zap_request(nostr, amount)
        if problem is not None:
            raise HTTPException(HTTPStatus.BAD_REQUEST, problem)
        zap_request = nostr

    note_id = spend.decode_note(comment) if comment is not None else None
    if note_id is None and branch is not None:
        # registered username: a comment that isn't a note ref (a payer's
        # WALLET sending an ordinary human LUD-12 message, or nothing at
        # all - e.g. a zap) doesn't block minting - auto-mint on this
        # username's own branch instead (see this function's own docstring)
        branch_point, chain_code = branch[:32], branch[32:]
        assert username is not None
        note_id, _ = notes.claim_next_index(
            username, lambda i: derivation.derive_pubkey(branch_point, chain_code, i).hex()
        )
    elif note_id is None:
        raise HTTPException(
            HTTPStatus.BAD_REQUEST,
            "Missing or malformed comment: a cp1<Q>, or a bearer note's hex-encoded "
            "32-byte hash, is required to mint.",
        )
    funding_source = _funding_source()
    try:
        if zap_request is None:
            pr, preimage = await create_invoice(amount, funding_source)
        else:
            pr, preimage = await create_invoice(amount, funding_source, description_for_hash=zap_request)
    except Exception as exc:
        # exc's own text (backend error bodies, connection info, ...) is
        # never handed back on the wire - see log_internal_error
        raise HTTPException(HTTPStatus.INTERNAL_SERVER_ERROR, log_internal_error("Error creating invoice", exc))
    # lnd/cln generate the preimage themselves and return it, so the hash
    # is sha256(preimage); the spark backend cannot - its SSP generates
    # and holds the preimage (see spark.py's module docstring) - and
    # returns None instead, so there the hash is read straight off the
    # invoice itself. The preimage never becomes a note's spend now
    # that comment protection is mandatory, and is discarded here, per
    # the spec's storing-hashes-not-secrets guidance - only the payment
    # hash and the invoice itself (for LUD-21 verify) are stored. The
    # invoice itself is for the full `amount` (what the payer actually
    # pays); the note it produces is credited net of the mint fee.
    payment_hash = sha256(preimage).hexdigest() if preimage is not None else _created_invoice_payment_hash(pr)
    try:
        notes.create_mint(
            payment_hash,
            pr,
            net_amount_msat,
            note_id,
            zap_request=zap_request,
        )
    except ValueError as exc:
        raise HTTPException(HTTPStatus.BAD_REQUEST, str(exc))
    # built from settings, not req.url_for (which is Host-header-derived,
    # spoofable via a plain Host header even behind a proxy - see
    # config.py's own public_base_url docstring) - same as get_lnaddress
    base = settings.public_base_url(str(req.base_url))
    verify = f"{base}/verify/{payment_hash}" if settings.verify_enabled else None
    return LnurlPayActionResponse(pr=pr, verify=verify)


@router.get("/p/cb", tags=["lnurlcash"], response_model=LnurlPayActionResponse | LnurlErrorResponse)
async def get_pay_callback(
    req: Request, amount: int, comment: str | None = None, nostr: str | None = None
) -> LnurlPayActionResponse:
    """LUD-06 callback for this mint's own fixed identity
    (settings.username/the bare-domain `_` - see get_lnaddress). No
    `username` in the path here: this is the one payRequest entry point
    that was never a registered address to begin with, so there is
    nothing for get_pay_callback_for_username's path parameter to name.
    See _pay_callback for the shared logic (comment protection, LUD-21
    verify, NIP-57 zaps - always refused here, since zaps need a branch
    for the note to land on, see _zaps_offered)."""
    return await _pay_callback(req, amount, comment, nostr, username=None, branch=None)


@router.get("/p/{username}", tags=["lnurlcash"], response_model=LnurlPayActionResponse | LnurlErrorResponse)
async def get_pay_callback_for_username(
    req: Request, username: str, amount: int, comment: str | None = None, nostr: str | None = None
) -> LnurlPayActionResponse:
    """LUD-06 callback for a cx1-registered Lightning Address
    (get_lnaddress's own callback for a registered `username`, never a
    payer's choice to redirect elsewhere - a request naming a `username`
    nobody registered 404s here exactly like an unknown one anywhere
    else). Declared after GET /p/cb above so an exact match on that
    literal path is always tried first - Starlette resolves routes in
    registration order, and `{username}` would otherwise happily capture
    the literal string "cb" too. See _pay_callback for the shared logic."""
    username = username.lower()
    branch_hex = _registered_username_branch(username)
    if branch_hex is None:
        raise HTTPException(HTTPStatus.NOT_FOUND, "Unknown user.")
    return await _pay_callback(req, amount, comment, nostr, username=username, branch=bytes.fromhex(branch_hex))


async def _verify_response(
    payment_hash: str,
    pr: str,
    is_settled: Callable[[str], Awaitable[bool]],
    preimage_of: Callable[[str], Awaitable[str | None]],
) -> LnurlPayVerifyResponse:
    """The shared shape of a LUD-21 verify response: settled first, then
    (only if settled) its preimage - `is_settled`/`preimage_of` are
    _mint_settled/_mint_preimage or _melt_settled/_melt_preimage, whichever
    direction `pr` came from (see verify_invoice, the only caller)."""
    settled = await is_settled(payment_hash)
    preimage = await preimage_of(payment_hash) if settled else None
    return LnurlPayVerifyResponse(settled=settled, preimage=preimage, pr=pr)


@router.get("/verify/{payment_hash}", tags=["lnurlcash"], response_model=LnurlPayVerifyResponse | LnurlErrorResponse)
async def verify_invoice(payment_hash: str) -> LnurlPayVerifyResponse:
    """LUD-21: reports whether an invoice this mint issued (via /p/cb) or
    paid out (a melt, via /w/cb - LUD-25) has settled - looked up by
    payment_hash, unguessable but not itself secret, same as any other
    LUD-21 verify. Served only while VERIFY_ENABLED is on: unlike the
    usual ecosystem convention (where such a flag merely gates whether
    callbacks *advertise* the URL), false here disables the endpoint
    entirely (404) - deliberately, because for a mint the response's
    `preimage` is not mere proof of payment but the bearer note's spend
    secret itself (see below), so an operator who doesn't want it served
    needs a real off switch, not just a hidden URL. mint_pr and melt_pr
    are separate tables keyed by two different invoices' payment hashes,
    so a lookup can never accidentally match the wrong direction.

    For a mint that skipped LUD-25 comment protection (see get_pay_callback),
    `preimage`, once settled, IS the bearer note's spend secret (see
    LUD-25's Minting a bearer note from a payRequest) - which is exactly
    why this endpoint refuses to serve one for that mint's payment_hash at
    all (see below): unlike the case a wallet with no node of its own
    needs it, serving it here would hand the note to ANY holder of the
    invoice (a bystander seeing the QR, a screenshot, a log line), not
    just the payer, the instant it settles. A mint that used comment
    protection has no such issue - `preimage` there redeems nothing, the
    note's spend secret is the WALLET-held `secret` behind `comment`
    instead - so `preimage` is served normally, fetched live from the
    funding source rather than cached (see _mint_preimage), for whatever
    ordinary proof-of-payment use a wallet with no node of its own has for
    it.

    For a melt, `preimage` is simply that outgoing payment's own settlement
    proof (see _melt_preimage) - not a bearer secret at all, since the
    note(s) that funded it are already burned by the time anyone could use
    it. Because a BOLT-11 `pr` commits to payment_hash = sha256(preimage),
    anyone holding both can independently confirm the melt without trusting
    this mint's word for it, per LUD-25's melt verify."""
    if not settings.verify_enabled:
        raise HTTPException(HTTPStatus.NOT_FOUND, "Not found")
    pr = notes.mint_pr(payment_hash)
    if pr is not None:
        # per spec, SERVICE MUST NOT offer verify for a mint's payment hash
        # in the no-comment fallback - there `preimage` IS the bearer
        # note's entire spend secret, and this endpoint is unauthenticated
        # by design (see NoteStore.mint_uses_comment)
        if not notes.mint_uses_comment(payment_hash):
            raise HTTPException(HTTPStatus.NOT_FOUND, "Not found")
        return await _verify_response(payment_hash, pr, _mint_settled, _mint_preimage)
    pr = notes.melt_pr(payment_hash)
    if pr is not None:
        return await _verify_response(payment_hash, pr, _melt_settled, _melt_preimage)
    raise HTTPException(HTTPStatus.NOT_FOUND, "Not found")


async def _certificate(note_id_hex: str, amount_msat: int, funding_source: LightningBackendConfig) -> str | None:
    """This mint's Offline-verification certificate for a note, `cs1<...>`
    over (Q, amount) - every note has a public Q, so every note gets one.
    None if signing isn't available right now (see sign_note)."""
    raw = await sign_note(note_id_hex, amount_msat, funding_source)
    if raw is None:
        return None
    return bech32m.encode_cs1(amount_msat, bytes.fromhex(raw))


@router.get("/w", tags=["lnurlcash"], response_model=LnurlWithdrawResponse | LnurlErrorResponse)
async def get_withdraw(
    req: Request,
    k1: str | None = None,
    p: str | None = None,
    amount: int | None = None,
) -> LnurlWithdrawResponse:
    """LUD-03 withdrawRequest for a bearer note. Purely informational: it
    never burns or alters the note (which is what makes it safe for any
    wallet to inspect a note's value without consuming it), so the mutating
    callback below lives on a distinct URL, as the spec requires.
    minWithdrawable == maxWithdrawable states the note's value
    authoritatively.

    Exactly one of `k1`/`p` must be given. With `k1` - a `ck1`, a `cw1`, or
    a bearer note's hex preimage - the spend is verified in full against
    its note first (see _verified_note), per LUD-25, so a WALLET checking a
    received note learns whether its spend actually opens it; a script
    path's own failure reason (a timelock not yet due, ...) is passed on.
    The response's `k1` MUST echo the literal value it was queried with, so
    a wallet can copy it verbatim into a new note URL or the callback.

    `p` (LUD-25's "Checking a note without exposing it") is the note's
    `cp1`, or a bearer note's hex `h`, accepted here in place of `k1` and
    ONLY here, never at /w/cb. The response then omits `k1` (see
    LnurlWithdrawResponse). An unknown `p` gets the same response as an
    unknown `k1`; a retained spent note returns "Note already spent." with
    either lookup form.

    `amount` is accepted only because a note's URL encodes a
    (wallet-declared, unauthoritative) value as `?k1=...&amount=...` - it
    MUST be ignored here, never as a stand-in for the actual note value.

    `mintPubkey` (LUD-25 Offline verification) is advertised here rather
    than on the payRequest side: a wallet paying the mint invoice can
    already recover this mint's node id from the invoice's own signature,
    so a freshly minted note needs no separate field - only notes obtained
    via this endpoint's callback (rotate/split/merge, which have no
    invoice) do.

    `sig` (LUD-25 Offline verification) is a ready-made `cs1` certificate
    for the note, so a WALLET need not force a rotate just to obtain one,
    and a recovery scan probing `?p=cp1<pk_i>` gets one for free. A
    certificate isn't a spend authorization - just this mint's signature
    over (Q, amount) - so handing one out for `p` never requires proof the
    caller holds the note's spend."""
    if (k1 is None) == (p is None):
        raise HTTPException(HTTPStatus.BAD_REQUEST, "Specify exactly one of k1 or p.")

    if k1 is not None:
        try:
            note_id, amount_msat, spent, _ = await _verified_note(k1)
        except _Rejected as exc:
            reason = exc.reason if exc.reason != _INVALID_K1 else "Unknown note."
            raise HTTPException(HTTPStatus.BAD_REQUEST, reason)
    else:
        assert p is not None
        ref = await _note_by_ref(p)
        record = notes.note_record(ref) if ref is not None else None
        if ref is None or record is None:
            raise HTTPException(HTTPStatus.BAD_REQUEST, "Unknown note.")
        note_id = ref
        amount_msat, _, spent, _ = record
    # a note names its own spent state: disclosed, while keeping the spend
    # itself off the wire
    if spent:
        raise HTTPException(HTTPStatus.BAD_REQUEST, "Note already spent.")
    # a note reserved by an in-flight melt (NoteStore.mark_pending) must
    # not be advertised as withdrawable: every mutating callback rejects
    # it with reason "pending" per spec, so an informational endpoint
    # claiming min=max=full value meanwhile would be lying - exactly the
    # lie a sell-during-melt scam needs (buyer inspects /w, pays out of
    # band, the melt settles, the note is gone). Same rejection shape as
    # /w/cb's own, per the spec's distinct "pending" reason.
    if notes.note_pending(note_id):
        raise HTTPException(HTTPStatus.BAD_REQUEST, "pending")
    # built from settings, not req.url_for (which is Host-header-derived,
    # spoofable via a plain Host header even behind a proxy) - same as
    # get_lnaddress/get_pay_callback
    base, host = settings.public_base_url_and_host(str(req.base_url))
    sig = await _certificate(note_id, amount_msat, settings.funding_source())
    return LnurlWithdrawResponse(
        callback=f"{base}/w/cb",
        k1=k1,
        minWithdrawable=amount_msat,
        maxWithdrawable=amount_msat,
        defaultDescription=f"lnurlcash bearer note on {host}",
        mintPubkey=await mint_pubkey(settings.funding_source()),
        sig=sig,
    )


@router.get("/w/cb", tags=["lnurlcash"], response_model=WithdrawSuccessResponse | LnurlErrorResponse)
async def get_withdraw_callback(
    req: Request,
    background_tasks: BackgroundTasks,
    k1: list[str] = Query(...),
    pr: str | None = None,
    amount: int | None = None,
    p1: str | None = None,
    p2: str | None = None,
) -> WithdrawSuccessResponse:
    """The lnurlcash redeem callback - see 25.md's "Redeeming a bearer
    note" table for the k1/pr/amount combinations (melt/rotate/split/merge)
    this implements. `pr` MUST NOT be combined with multiple k1s or with
    `amount` (merge or split first). `p1`/`p2` are preimage hashes WALLET
    generates for the replacement note(s) - required whenever `pr` is
    absent, and `p2` additionally whenever `amount` is too - this mint
    never generates one on WALLET's behalf.

    Details the spec leaves to the implementation:
    - min_mint_msat (/p/cb's dust floor for a *fresh* mint) does not apply
      to a split's outputs - only that `change` can't go negative or land
      at exactly 0.
    - A melt reserves its note(s) (NoteStore.mark_pending) and replies
      immediately per LUD-03 step 6; `_melt_pay` pays `pr` in the
      background and only then burns or restores them (see its own
      docstring). A `pr` naming an invoice this same mint issued via
      /p/cb is rejected synchronously instead of being paid back to this
      mint's own node; a `pr` whose payment hash an earlier melt already
      used is likewise rejected (the funding source dedupes by payment
      hash, so it would burn the note without moving funds).
    - Every note minted here (never on melt) is signed per Offline
      verification, over the hash WALLET supplied - omitted if no funding
      source is configured or signing fails (see signing.sign_note).
    - If any k1 is invalid the whole request fails atomically
      (NoteStore.swap); a k1 already reserved by another in-flight melt
      fails with reason "pending" instead (NoteStore.mark_pending).
    - split rejects outright while SUNSET_MINT is on, same as /p/cb - see
      that setting's own docstring in config.py.
    - LUD-25's Retrying a mutation: a rotate/split/merge whose k1(s), p1, p2
      and amount exactly match an earlier completed one gets that same
      result replayed (sig/sig2 recomputed, deterministic per RFC6979)
      instead of "already spent" (see NoteStore.find_burn/swap). Melt is
      unaffected - LUD-25 only asks this of rotate/split/merge."""
    if len(k1) > settings.max_k1s:
        raise HTTPException(HTTPStatus.BAD_REQUEST, f"Too many k1s (max {settings.max_k1s}).")

    if pr is not None and (len(k1) > 1 or amount is not None):
        raise HTTPException(
            HTTPStatus.BAD_REQUEST, "pr cannot be combined with multiple k1s or amount - merge or split first."
        )

    # split (amount is not None, since the check above already rejects it
    # alongside pr) grows the number of outstanding notes just like a fresh
    # mint - rejected the same way while sunsetting. rotate/merge/melt are
    # all left alone: none of them increases this mint's liability, and a
    # sunsetting operator still needs holders able to consolidate/redeem.
    if settings.sunset_mint and amount is not None:
        raise HTTPException(HTTPStatus.BAD_REQUEST, "This mint is sunsetting - splitting is disabled.")

    # checked before any note is resolved, so an invalid/missing output
    # never burns anything. p1/p2 are the WALLET-generated notes to credit:
    # a `cp1<Q>`, or a bearer note's hex `h` (see spend.decode_note)
    p1_id: str | None = None
    p2_id: str | None = None
    if pr is None:
        p1_id = spend.decode_note(p1) if p1 is not None else None
        if p1_id is None:
            raise HTTPException(HTTPStatus.BAD_REQUEST, "missing p1")
        if amount is not None:
            p2_id = spend.decode_note(p2) if p2 is not None else None
            if p2_id is None:
                raise HTTPException(HTTPStatus.BAD_REQUEST, "missing p2")

    # every k1 is verified against its note once, spent or not (see
    # _verified_note) - notes of any kind mix freely in one request, per spec
    verified: list[tuple[str, int, bool, bool]] = []
    for note_k1 in k1:
        try:
            verified.append(await _verified_note(note_k1))
        except _Rejected as exc:
            raise HTTPException(HTTPStatus.BAD_REQUEST, exc.reason)
    note_ids = [note_id for note_id, _, _, _ in verified]

    if pr is None:
        # LUD-25 "Retrying a mutation": a rotate/split/merge is a GET that
        # mutates state once and only ever wants to say so once - an HTTP
        # client's own timeout-retry, a proxy in between, or a flaky
        # connection resending a request it never saw a reply for must see
        # that same original result again, not "already spent" for a note
        # this mint itself just burned. Only an EXACT match (the same set of
        # burned notes, p1, p2 and amount as some earlier completed burn)
        # counts as a replay; these same notes under a different p1/p2/amount
        # is a genuine conflict, not a replay, and still reaches the ordinary
        # already-spent error below. Matched on note ids (Q), never the raw
        # k1 strings: one note may be opened by more than one valid spend.
        burn = notes.find_burn(note_ids)
        if burn is not None:
            recorded_p1, recorded_p2, amount1_msat, amount2_msat = burn
            recorded_amount = amount1_msat if recorded_p2 is not None else None
            if recorded_p1 == p1_id and recorded_p2 == p2_id and recorded_amount == amount:
                funding_source = settings.funding_source()
                sig = await _certificate(recorded_p1, amount1_msat, funding_source)
                sig2 = (
                    await _certificate(recorded_p2, amount2_msat, funding_source)
                    if recorded_p2 is not None and amount2_msat is not None
                    else None
                )
                return WithdrawSuccessResponse(sig=sig, sig2=sig2)

    if any(spent for _, _, spent, _ in verified):
        raise HTTPException(HTTPStatus.BAD_REQUEST, _INVALID_K1)
    values = [amount_msat for _, amount_msat, _, _ in verified]
    total_msat = sum(values)

    if pr is not None:
        try:
            decoded = bolt11.decode(pr)
        except Exception as exc:
            raise HTTPException(HTTPStatus.BAD_REQUEST, f"Invalid invoice: {exc!s}")
        if decoded.amount_msat != total_msat:
            raise HTTPException(HTTPStatus.BAD_REQUEST, f"Invoice must be for exactly {total_msat} msat.")
        # `pr` is itself an invoice this same mint issued via /p/cb (pending
        # or already settled/minted) - reject outright rather than paying
        # it. Paying it over Lightning would just be the funding source
        # routing a payment back to itself, which real nodes handle
        # inconsistently (some reject it as a cycle, some accept it at face
        # value); notes.mint_pr matches regardless of settlement status,
        # since this mint issued the invoice either way. Checked - and
        # rejected synchronously, unlike the actual payment below - because
        # it's a cheap local lookup, not a Lightning round-trip.
        if decoded.has_payment_hash and notes.mint_pr(decoded.payment_hash) is not None:
            raise HTTPException(HTTPStatus.BAD_REQUEST, "Cannot melt into an invoice this mint issued itself.")

        # a payment hash an earlier melt already used is never paid into
        # again: the funding source dedupes by payment hash (cln's xpay
        # rejects with "already paid", lnd replays the prior payment's
        # status), so the second melt would be confirmed against the FIRST
        # payment and burn its note without any funds moving. Reject
        # outright instead. Trade-off: even a genuinely failed melt keeps
        # its melts row (NoteStore.record_melt is unconditional, for LUD-25
        # verify), so retrying one needs a fresh invoice - BOLT-11 invoices
        # are single-use anyway.
        if decoded.has_payment_hash and notes.melt_pr(decoded.payment_hash) is not None:
            raise HTTPException(HTTPStatus.BAD_REQUEST, "Invoice already used by an earlier melt - use a fresh one.")

        funding_source = _funding_source()

        try:
            notes.mark_pending(note_ids, decoded.payment_hash)
        except PendingNoteError:
            raise HTTPException(HTTPStatus.BAD_REQUEST, "pending")
        except ValueError as exc:
            # a note resolved fine above but lost a race with a concurrent
            # request before it could be reserved - same known-safe message
            # _verified_note itself uses, not an internal error
            raise HTTPException(HTTPStatus.BAD_REQUEST, str(exc))

        # registered the moment the reservation lands - BEFORE the response
        # goes out and the background task starts - so the monitor's
        # periodic reconcile never mistakes this live, in-process attempt
        # for a leftover and restores the note out from under a payment
        # that simply hasn't reached the funding source yet (see
        # _in_flight_melts). _melt_pay drops the registration when done.
        _track_melt_start(decoded.payment_hash)
        try:
            # LUD-25 melt verify: recorded unconditionally (see
            # NoteStore.record_melt), same as a mint invoice's own `pr` - the
            # endpoint serves whatever was recorded while VERIFY_ENABLED is on
            # and 404s while off (see verify_invoice), the setting also gating
            # whether it's advertised below
            melt_verify_url = None
            if decoded.has_payment_hash:
                notes.record_melt(decoded.payment_hash, pr)
                if settings.verify_enabled:
                    base = settings.public_base_url(str(req.base_url))
                    melt_verify_url = f"{base}/verify/{decoded.payment_hash}"

            # per LUD-03 step 6, SERVICE replies {"status": "OK"} here and only
            # then attempts the payment asynchronously - _melt_pay runs as a
            # background task after this response has already gone out, so it
            # has no way left to report a failure back to the wallet (see its
            # docstring)
            background_tasks.add_task(_melt_pay, note_ids, pr, decoded, funding_source)
        except Exception:
            # never scheduled - drop the registration again so the periodic
            # reconcile can still pick the stranded pending note up
            _track_melt_end(decoded.payment_hash)
            raise
        if melt_verify_url is not None:
            return WithdrawSuccessResponse(pr=pr, verify=melt_verify_url)
        return WithdrawSuccessResponse()

    try:
        if amount is not None:
            if not 0 < amount < total_msat:
                raise HTTPException(HTTPStatus.BAD_REQUEST, f"amount must be between 0 and {total_msat} msat.")
            # per LUD-25, base_fee_msat (never fee_percent_ppm - that's
            # already been withheld once, at mint time) comes out of
            # change, not the requested amount, so a holder can't dodge it
            # by splitting into many dust notes and melting each
            # separately. 0 when this SERVICE is fee-free, a no-op then.
            change_before_fee = total_msat - amount
            if change_before_fee < settings.base_fee_msat:
                raise HTTPException(HTTPStatus.BAD_REQUEST, "insufficient value")
            change_amount = change_before_fee - settings.base_fee_msat
            # strictly *less than* base_fee_msat above only guards against a
            # negative change_amount - change_before_fee == base_fee_msat
            # passes that check but leaves change_amount at exactly 0, a
            # bearer note for nothing: unlike a configurable dust floor,
            # "nothing" is never a valid note value regardless of settings.
            if change_amount < 1:
                raise HTTPException(HTTPStatus.BAD_REQUEST, "insufficient value")
            # p1_id/p2_id are validated present and well-formed above,
            # whenever pr is None and amount is not - both true here
            assert p1_id is not None and p2_id is not None
            notes.swap(note_ids, [p1_id, p2_id], [amount, change_amount])
            funding_source = settings.funding_source()
            return WithdrawSuccessResponse(
                sig=await _certificate(p1_id, amount, funding_source),
                sig2=await _certificate(p2_id, change_amount, funding_source),
            )

        # rotate is a merge of one note - the refund below is exactly 0
        # then, so it's covered by this same branch without a special case.
        # For an actual merge (n > 1), refunding (n - 1) * base_fee_msat
        # gives back every base fee already collected beyond the single one
        # this now-one note should have cost, per LUD-25.
        assert p1_id is not None  # validated above, whenever pr is None
        refund = (len(note_ids) - 1) * settings.base_fee_msat
        merged_amount = total_msat + refund
        notes.swap(note_ids, [p1_id], [merged_amount])
        return WithdrawSuccessResponse(sig=await _certificate(p1_id, merged_amount, settings.funding_source()))
    except OutputCollisionError as exc:
        raise HTTPException(HTTPStatus.BAD_REQUEST, str(exc))
    except PendingNoteError:
        raise HTTPException(HTTPStatus.BAD_REQUEST, "pending")
    except ValueError as exc:
        # a note resolved fine above but lost a race with a concurrent
        # request before it could be burned - same known-safe message
        # _verified_note itself uses, not an internal error
        raise HTTPException(HTTPStatus.BAD_REQUEST, str(exc))
