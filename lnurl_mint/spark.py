"""The spark funding-source backend (https://github.com/breez/spark-sdk).

A third way to fund this mint besides lnd and cln: a spark wallet driven by
the Breez Spark SDK, via its Python bindings (`breez-sdk-spark`, an optional
dependency - install with `uv sync --extra spark`). The mint's whole
node.py contract is implemented on top of five SDK calls:

- create_invoice   -> receive_payment(BOLT11_INVOICE)   (the SSP issues it)
- pay_invoice      -> prepare_send_payment + send_payment (Lightning route)
- is_payment_complete / invoice_preimage / payment_preimage
                   -> list_payments (scanned by payment hash; a miss in
                      is_payment_complete is only believed after a forced
                      sync bracketed by two-leg remote probes)
- is_invoice_settled -> list_payments (same scan, receive side)
- sign_message     -> signed locally (LUD-25 digest, seed-derived key)
- fetch_node_info  -> _remote_probe (coordinator + SSP) + get_info

Two deviations from the lnd/cln backends are load-bearing:

**create_invoice returns a None preimage.** lnd/cln let the caller supply
the preimage (r_preimage / preimage), so those backends return it and the
router derives payment_hash = sha256(preimage) - then discards the
preimage, per the spec's store-hashes-not-secrets policy. The spark SSP
instead generates and holds the preimage itself for an ordinary invoice
(a caller-supplied payment_hash makes it a *hodl* invoice, which only the
preimage holder can ever settle - and this mint deliberately does not
keep preimages). So the spark backend returns None and the router takes
the payment hash straight off the returned invoice. Since LUD-25 made
comment protection mandatory, that preimage never becomes the note's
bearer secret at all (every note is keyed by the WALLET's comment hash;
the preimage is pure proof-of-payment, "safe to disclose anywhere" per
the spec) - it is only ever materialized live from the SDK's storage
after settlement (see _invoice_preimage_spark), exactly like lnd's
LookupInvoice echo, and served through LUD-21 verify.

**LUD-25 offline verification signs with a dedicated seed-derived key.**
The spec's digest is the "Lightning Signed Message" construction -
sha256(sha256(b"Lightning Signed Message:" + message)) - which lnd's and
cln's signmessage RPCs produce natively. The spark SDK has no signmessage
and its own sign_message signs a single-sha256 digest it cannot redirect,
so this backend derives a dedicated key from the wallet's own seed
(m/25'/0'/0', outside spark's m/8797555' key tree) and signs the exact
spec digest locally (RFC6979, recoverable r||s||recid). LUD-25 only
RECOMMENDS the node-id key - mintPubkey may be any secp256k1 key, and a
spark wallet's invoices are signed by its SSP anyway - so wallets verify
spark-minted notes exactly like lnd/cln ones: recover the key from
(digest, sig), compare to the advertised mintPubkey.

**The SDK is a process-wide singleton** built once (see _sdk), not a
per-call REST client like lnd/cln: it owns a sqlite store of its own (its
storage dir, see config.Settings.fundingsource_spark_storage_dir), background
sync/claim tasks on this process's event loop, and the seed-derived keys
of the mint's spark wallet. Building it per call would re-connect and
re-sync every time; instead every backend function here goes through
_sdk(config), which builds it lazily on first use and disconnects it at
shutdown (see shutdown, called from server.py's lifespan). The same
single-process rule as the mint's own db applies: never point two
processes at the same spark storage dir.

**A missing melt payment is never "not paid" - absence is indeterminate.**
lnd/cln persist their own payment record *before* any HTLC leaves the
node, so "no record" reliably means "nothing was sent". The spark SDK
persists its payment row only *after* the SSP has already accepted the
payment request, so a crash in exactly that gap leaves a live payment
with no local row - and answering False from that absence would let
router._melt_pay restore the note for a second melt into a *different*
invoice, which the idempotency key cannot deduplicate (it is derived from
the original invoice). Worse, the absence can't simply be synced away:
breez-sdk-spark 0.23's sync_wallet_internal catches and logs every
sub-sync failure yet still resolves Ok, and the reconciliation it
swallows spans two independently-operated services (the coordinator's
query_all_transfers and the SSP's transfer enrichment) - so no amount of
probing around a forced sync can *prove* the reconciliation itself
succeeded. is_payment_complete therefore answers False only from a
stored row the SDK itself reports FAILED, or from the same-process
prepare-rejection registry (_prepare_rejected: payments this process
turned away before send_payment was ever called - nothing was sent,
known first-hand). A missing row raises INDETERMINATE instead, after a
forced sync bracketed by the two-leg remote probe gives it every chance
to materialize (a networked attempt converges on a row answer; an outage
surfaces as the probe's own error). A melt that genuinely never happened
but whose rejection predates a restart stays pending for an operator to
resolve by hand - the same discipline the router already applies to any
melts whose outcome can't be established.

Amounts: the SDK's bolt11 surface is sat-denominated (u64) while this
mint is msat throughout. create_invoice requires a sat-aligned
amount_msat and rejects anything else with a clear error rather than
silently rounding; pay_invoice does the same for the melt side, where
the SDK would otherwise CEIL a fractional-sat invoice into whole sats
of spark leaves - debiting more than the note's value, and (since
splits can produce arbitrarily tiny fractional notes) over-draining
the wallet. Every other function converts the SDK's sat amounts back
to msat on the way out.
"""

import asyncio
import hashlib
import hmac
import logging
import unicodedata
import uuid
from collections import OrderedDict
from hashlib import sha256
from typing import Any, Callable

import bolt11
from coincurve import PrivateKey

from .node import LightningBackendConfig, NodeInfo, PaymentFailed, PaymentResult
from .signing import lightning_signed_message_digest

try:  # optional dependency - see the module docstring and pyproject's
    # [project.optional-dependencies] spark extra
    from breez_sdk_spark import (
        GetInfoRequest,
        ListPaymentsRequest,
        Network,
        PaymentRequest,
        PaymentStatus,
        PaymentType,
        PrepareSendPaymentRequest,
        ReceivePaymentMethod,
        ReceivePaymentRequest,
        SdkBuilder,
        SdkError,
        Seed,
        SendPaymentOptions,
        SendPaymentRequest,
        SyncWalletRequest,
        default_config,
    )

    _HAS_SPARK_SDK = True
except ImportError:  # pragma: no cover - exercised only without the extra
    _HAS_SPARK_SDK = False

# how long send_payment waits for the SSP's terminal status before
# returning the still-pending payment (which _pay_invoice_spark then
# treats as ambiguous, per is_payment_complete's contract) - the melt
# itself runs as a background task (see router._melt_pay), so a slow
# settle delays only the note's burn/restore, never a wallet's callback
_SEND_COMPLETION_TIMEOUT_SECS = 60

# page size for the list_payments scans every hash lookup here is built
# on - large enough that a small mint's whole history is one round trip
_PAYMENT_SCAN_PAGE = 100

_sdk_singleton: Any = None
_sdk_build_lock = asyncio.Lock()


def _reset_sdk_for_testing(sdk: Any = None) -> None:
    """Replaces the process-wide SDK singleton - never call this outside
    the test suite, which injects a fake rather than building a real
    wallet (and reset it to None to force a real rebuild)."""
    global _sdk_singleton
    _sdk_singleton = sdk


async def _build_sdk(config: LightningBackendConfig) -> Any:
    if not _HAS_SPARK_SDK:
        raise ValueError(
            "The spark backend requires the breez-sdk-spark package - install it with `uv sync --extra spark`."
        )
    if not config.spark_mnemonic:
        raise ValueError("Mnemonic is required.")
    if not config.spark_storage_dir:
        raise ValueError("Storage dir is required.")
    network = Network.MAINNET if config.spark_network == "mainnet" else Network.REGTEST
    sdk_config = default_config(network=network)
    # a Breez API key is required for the mainnet SSP and optional-ish
    # elsewhere (regtest has none) - passed through as configured rather
    # than guessed
    sdk_config.api_key = config.spark_api_key.get_secret_value() if config.spark_api_key else None
    # how fresh list_payments reads are, without forcing a sync anywhere:
    # the SDK's background loop refreshes its storage at most this often
    # (plus its event stream), so this bounds how long after a payment
    # lands that is_invoice_settled/is_payment_complete can first notice
    sdk_config.sync_interval_secs = config.spark_sync_interval_secs
    # multi-device realtime sync of the wallet - meaningless for a
    # single-process server wallet, and one less external service to
    # depend on
    sdk_config.real_time_sync_server_url = None
    builder = SdkBuilder(
        config=sdk_config, seed=Seed.MNEMONIC(mnemonic=config.spark_mnemonic.get_secret_value(), passphrase=None)
    )
    await builder.with_default_storage(storage_dir=config.spark_storage_dir)
    if config.spark_account_number is not None:
        await builder.with_account_number(account_number=config.spark_account_number)
    return await builder.build()


async def _sdk(config: LightningBackendConfig) -> Any:
    """The process-wide SDK singleton (see the module docstring), built
    on first use with `config` - every later call reuses it regardless of
    which config object reaches it, same assumption server.py's
    build-once-at-boot lifespan already makes."""
    global _sdk_singleton
    if _sdk_singleton is None:
        async with _sdk_build_lock:
            if _sdk_singleton is None:
                _sdk_singleton = await _build_sdk(config)
    return _sdk_singleton


async def shutdown() -> None:
    """Disconnects the singleton SDK, if one was built - called from
    server.py's lifespan at shutdown so the SDK's background tasks stop
    with the process instead of being torn down mid-request by the
    interpreter."""
    global _sdk_singleton
    if _sdk_singleton is None:
        return
    try:
        await _sdk_singleton.disconnect()
    except Exception as exc:  # never fatal at shutdown
        logging.warning("spark shutdown: %s", exc)
    _sdk_singleton = None


async def dispatch(operation: str, config: LightningBackendConfig, leading: tuple, trailing: tuple) -> Any:
    """node._dispatch's spark entry point: maps the operation name onto
    this module's implementation, called as fn(*leading, config,
    *trailing) - the same positional convention the lnd/cln branches use
    minus the (url, credential) pair, which spark has no analogue of
    (credentials live in the built singleton instead)."""
    impls: dict[str, Callable[..., Any]] = {
        "create_invoice": _create_invoice_spark,
        "pay_invoice": _pay_invoice_spark,
        "is_payment_complete": _is_payment_complete_spark,
        "invoice_preimage": _invoice_preimage_spark,
        "payment_preimage": _payment_preimage_spark,
        "sign_message": _sign_message_spark,
        "is_invoice_settled": _is_invoice_settled_spark,
        "fetch_node_info": _fetch_node_info_spark,
    }
    impl = impls.get(operation)
    if impl is None:
        raise ValueError(f"{operation} is not supported for backend 'spark'.")
    return await impl(*leading, config, *trailing)


def _lightning_htlc(payment: Any) -> Any | None:
    """The Lightning-details' htlc_details of `payment`, or None if it has
    none (not a Lightning payment, or one the SDK stored without HTLC
    details) - the payment_hash/preimage carrier every scan below reads."""
    details = payment.details
    if details is None or not details.is_LIGHTNING():
        return None
    return details.htlc_details


async def _payments_by_hash(sdk: Any, payment_hash: str, payment_type: Any) -> list[Any]:
    """Every stored payment of `payment_type` whose Lightning HTLC names
    `payment_hash` - list_payments has no payment-hash filter, so this
    pages through the type-filtered history and scans client-side.
    Newest first (the SDK's default ordering), so the most recent attempt
    of a retried payment is seen first by anything that only reads
    [0]."""
    matches: list[Any] = []
    offset = 0
    while True:
        page = (
            await sdk.list_payments(
                request=ListPaymentsRequest(type_filter=[payment_type], limit=_PAYMENT_SCAN_PAGE, offset=offset)
            )
        ).payments
        for payment in page:
            htlc = _lightning_htlc(payment)
            if htlc is not None and htlc.payment_hash == payment_hash:
                matches.append(payment)
        if len(page) < _PAYMENT_SCAN_PAGE:
            return matches
        offset += _PAYMENT_SCAN_PAGE


def _melt_idempotency_key(invoice: str) -> str | None:
    """A deterministic UUID for a melt's send_payment call, derived from
    the invoice's payment hash - the SDK's documented recipe for making a
    retried payment of the same invoice idempotent (the SSP recognizes
    the transfer id and answers with the existing payment instead of
    sending funds twice). None for a hashless invoice, where there is
    nothing to derive from and the SDK's own random id is used."""
    try:
        decoded = bolt11.decode(invoice)
    except Exception:
        return None
    if not decoded.has_payment_hash:
        return None
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"lnurl-mint:melt:{decoded.payment_hash}"))


async def _create_invoice_spark(
    amount_msat: int,
    config: LightningBackendConfig,
    memo: str = "lnurlcash mint",
    description_for_hash: str | None = None,
    expiry_secs: int | None = None,
) -> tuple[str, None]:
    # the SSP's bolt11 surface is sat-denominated - see the module
    # docstring for why fractional-sat amounts are rejected rather than
    # rounded
    if amount_msat % 1000:
        raise ValueError("The spark backend can only mint sat-aligned amounts.")
    # the SDK's receive request has no description-hash field, so a zap
    # invoice cannot be bound to its request here; router._zaps_offered
    # keeps zaps off for this backend, this is the backstop
    if description_for_hash is not None:
        raise ValueError("The spark backend cannot commit an invoice to a description hash.")
    sdk = await _sdk(config)
    response = await sdk.receive_payment(
        request=ReceivePaymentRequest(
            payment_method=ReceivePaymentMethod.BOLT11_INVOICE(
                description=memo,
                amount_sats=amount_msat // 1000,
                expiry_secs=expiry_secs,
                payment_hash=None,
                receiver_identity_public_key=None,
            )
        )
    )
    if not response.payment_request:
        raise ValueError("The spark SDK did not return an invoice.")
    return response.payment_request, None


def _is_pre_transfer_insufficient_funds(exc: Exception) -> bool:
    """Whether `exc` is the wallet-side leaf-selection balance failure -
    provably raised before any operator signing or SSP request (leaf
    reservation is the first thing the SDK's send path does, and this
    failure has no producer after it), making "nothing was sent" a
    first-hand fact rather than an inference from a missing row.

    Two shapes, both verified against breez-sdk-spark 0.23 on mainnet:
    the dedicated SdkError.InsufficientFunds variant (SparkWalletError's
    own balance check), and - the one the bolt11 send path actually
    raises - TreeServiceError::InsufficientFunds, which the bindings
    flatten into SdkError.SparkError's payload string
    ("Tree service error: insufficient funds"). The string match is
    deliberately narrow (both "tree service" AND "insufficient funds"):
    the tree service is wallet-local, so only its own reservation failure
    can produce that text - a post-acceptance failure comes from the
    operator/SSP layers and stringifies with their prefixes instead."""
    message = str(exc).lower()
    return isinstance(exc, SdkError.InsufficientFunds) or (
        "tree service" in message and "insufficient funds" in message
    )


async def _pay_invoice_spark(invoice: str, config: LightningBackendConfig, fee_limit_msat: int) -> PaymentResult:
    # the SDK's bolt11 surface is sat-denominated here too, and worse than
    # at creation: it CEILS an invoice's msat amount into whole sats before
    # debiting spark leaves (get_invoice_amount_sats: div_ceil(1000)), so
    # paying a fractional-sat melt invoice would debit more than the
    # note's value - and since splits can produce arbitrarily tiny
    # fractional notes, repeating split+drain would over-debit the wallet
    # well beyond this mint's liability. A fractional-sat melt is rejected
    # up front instead (registered as never-sent, so the reserved note
    # restores cleanly - see is_payment_complete's docstring)
    try:
        decoded_pay = bolt11.decode(invoice)
    except Exception as exc:
        raise PaymentFailed(f"spark could not decode the invoice: {exc}") from exc
    if decoded_pay.amount_msat is None or decoded_pay.amount_msat % 1000:
        if decoded_pay.has_payment_hash:
            _mark_prepare_rejected(decoded_pay.payment_hash)
        raise PaymentFailed("The spark backend can only pay sat-aligned invoices.")
    sdk = await _sdk(config)
    try:
        prepare = await sdk.prepare_send_payment(
            request=PrepareSendPaymentRequest(payment_request=PaymentRequest.INPUT(input=invoice))
        )
    except SdkError as exc:
        # a prepare that raises never attempted anything (validate and
        # fee-quote happen at prepare; no payment row, no funds movement) -
        # recorded in the same-process registry so is_payment_complete can
        # later answer a provable False for this exact hash instead of an
        # indeterminate raise (see its docstring)
        try:
            decoded_rejection = bolt11.decode(invoice)
        except Exception:
            decoded_rejection = None
        if decoded_rejection is not None and decoded_rejection.has_payment_hash:
            _mark_prepare_rejected(decoded_rejection.payment_hash)
        raise PaymentFailed(f"spark could not prepare the payment: {exc}") from exc
    method = prepare.payment_method
    if not method.is_BOLT11_INVOICE():
        raise ValueError(f"spark resolved the invoice to an unexpected payment method: {method!r}")
    # the SDK caps the actual send at the fee quoted here (it passes the
    # prepare's fee straight through as the wallet call's max fee), so
    # rejecting an over-budget quote up front is what actually enforces
    # the caller's fee_limit_msat - rather than paying and discovering
    # the overage afterwards
    fee_sats = method.lightning_fee_sats or 0
    if fee_sats * 1000 > fee_limit_msat:
        # rejected before send_payment was ever called - same provable
        # nothing-was-sent fact as a prepare failure above, so it gets the
        # same registry entry (otherwise the wallet's clean over-budget
        # rejection would wedge its note pending forever - see
        # is_payment_complete's docstring)
        try:
            decoded_quote = bolt11.decode(invoice)
        except Exception:
            decoded_quote = None
        if decoded_quote is not None and decoded_quote.has_payment_hash:
            _mark_prepare_rejected(decoded_quote.payment_hash)
        raise PaymentFailed(
            f"spark fee quote of {fee_sats} sats exceeds the {fee_limit_msat} msat budget for this melt."
        )
    try:
        payment = (
            await sdk.send_payment(
                request=SendPaymentRequest(
                    prepare_response=prepare,
                    options=SendPaymentOptions.BOLT11_INVOICE(
                        # always the Lightning route, never a spark-routed
                        # shortcut: a melt's settlement proof IS the payment
                        # preimage (LUD-25 melt verify), and a spark-routed
                        # payment completes with no Lightning preimage at all
                        prefer_spark=False,
                        completion_timeout_secs=_SEND_COMPLETION_TIMEOUT_SECS,
                    ),
                    idempotency_key=_melt_idempotency_key(invoice),
                )
            )
        ).payment
    except SdkError as exc:
        if _is_pre_transfer_insufficient_funds(exc):
            # the wallet raised this selecting leaves, before any operator
            # signing or SSP request (leaf reservation precedes both in the
            # SDK's send path, and this failure has no later producer) - a
            # provably unsent outcome, registered like a prepare rejection
            # so an underfunded wallet's melt restores the note immediately
            # instead of wedging it pending forever on an unconfirmable
            # absence
            if decoded_pay.has_payment_hash:
                _mark_prepare_rejected(decoded_pay.payment_hash)
            raise PaymentFailed(f"spark wallet has insufficient funds: {exc}") from exc
        # every other send error stays genuinely ambiguous in exactly the
        # way PaymentFailed documents: the SDK raising says nothing
        # certain about whether the SSP already accepted it, so
        # router._melt_pay still confirms via is_payment_complete before
        # restoring anything (which raises - indeterminate, note pending)
        raise PaymentFailed(f"spark payment attempt failed: {exc}") from exc
    if payment.status == PaymentStatus.COMPLETED:
        htlc = _lightning_htlc(payment)
        preimage_hex = htlc.preimage if htlc is not None else None
        if not preimage_hex:
            raise ValueError("spark completed the payment without its preimage.")
        preimage = bytes.fromhex(preimage_hex)
        _verify_preimage(preimage, invoice)
        # the SDK reports fees in sats (u128) - back to this mint's msat
        return PaymentResult(preimage, int(payment.fees) * 1000)
    if payment.status == PaymentStatus.FAILED:
        raise PaymentFailed(f"spark payment failed ({payment.id}).")
    # still pending after completion_timeout_secs - e.g. a payee holding
    # a hodl invoice open - genuinely ambiguous, per is_payment_complete
    raise ValueError("spark reports the payment still pending - not a terminal outcome.")


# bounded in-process registry of melt payments that provably never left
# this wallet - the only same-process facts that make "no payment exists"
# a safe answer for is_payment_complete (whose docstring has the full
# contract). Four producers, all in _pay_invoice_spark: a prepare that
# raised, an over-budget fee quote, a fractional-sat invoice rejected up
# front, and a send that failed selecting leaves for insufficient funds
# - in every case no transfer request ever reached the SSP (the last
# because leaf reservation precedes the swap in the SDK's send path).
# Restart-scoped: any of these whose process dies before its note is
# restored leaves the note pending for an operator to resolve by hand -
# never wrongly restored, the same discipline as every other
# unresolvable-outcome melt.
_PREPARE_REJECTED_MAX = 1024
_prepare_rejected: OrderedDict[str, None] = OrderedDict()


def _mark_prepare_rejected(payment_hash: str) -> None:
    _prepare_rejected[payment_hash] = None
    _prepare_rejected.move_to_end(payment_hash)
    while len(_prepare_rejected) > _PREPARE_REJECTED_MAX:
        _prepare_rejected.popitem(last=False)


async def _remote_probe(sdk: Any) -> None:
    """Raises unless authenticated, side-effect-free-enough RPCs against
    BOTH remote legs the backend depends on just succeeded - the two
    services reconciliation and minting actually need, which are
    independently operated and fail independently:

    - the coordinator operators (get_user_settings: a query_wallet_setting
      RPC, `?`-propagated all the way out), and
    - the SSP (a throwaway 1-sat bolt11 invoice - the only SSP round
      trip the bindings expose that moves no funds; created invoices are
      never paid and simply expire, and no payment row is written for an
      unpaid invoice, so this costs one expiring SSP record per probe).

    Both legs are needed: the payment reconciliation's transfer
    enrichment calls ssp_client.get_transfers() in addition to the
    coordinator's query_all_transfers (and that SSP failure is swallowed
    with the rest of the sync), so probing only the coordinator would
    miss a coordinator-up/SSP-down outage entirely; conversely the SSP
    leg is where a revoked Breez API key surfaces (the SSP wants the
    partner JWT, while operator RPCs authenticate with the wallet's own
    session) - the exact degradation the health check exists to notice.

    Verified against breez-sdk-spark 0.23 (see scripts/spark_mainnet_check.py's
    outage self-test): with endpoints unreachable, sync_wallet and get_info
    still resolve Ok - 0.23's sync_wallet_internal catches and logs every
    sub-sync failure - while both probe legs raise. Neither an Ok sync nor
    an Ok get_info is any evidence the network was reachable; this probe
    is what makes the health check in _fetch_node_info_spark real, and
    what gates is_payment_complete's "confirmed not paid" answer on
    connectivity that actually held."""
    await sdk.get_user_settings()
    await sdk.receive_payment(
        request=ReceivePaymentRequest(
            payment_method=ReceivePaymentMethod.BOLT11_INVOICE(
                description="lnurl-mint connectivity probe",
                amount_sats=1,
                expiry_secs=None,
                payment_hash=None,
                receiver_identity_public_key=None,
            )
        )
    )


async def _is_payment_complete_spark(payment_hash: str, config: LightningBackendConfig) -> bool:
    """Whether an outgoing melt payment definitively completed or
    definitively failed - never a guess, which for this backend has a
    hard structural reason: the SDK persists a payment row only *after*
    the SSP has accepted the payment, so a crash in that gap leaves a
    live payment with no local row, and breez-sdk-spark 0.23's
    sync_wallet_internal swallows every reconciliation failure while
    still resolving Ok - meaning "no row, and a sync that claims success"
    can never *prove* the remote view lacks the transfer (the exact
    double-payout shape router._melt_pay guards against: a False here
    restores the bearer note for a second melt into a different
    invoice, which the idempotency key cannot deduplicate).

    So False is answerable from exactly two proofs, never from absence:
    a stored payment row the SDK itself reports as FAILED, or the
    same-process prepare-rejection registry (a payment this process
    rejected before send_payment was ever called - nothing was sent,
    known first-hand). Everything else raises: a pending row raises
    (not terminal), and a missing row raises INDETERMINATE - after first
    giving it every chance to materialize (a forced sync bracketed by
    the two-leg remote probe, so a networked attempt converges on a row
    answer quickly, and an outage surfaces as the probe's error rather
    than a bare "still nothing"). A note whose payment never happened
    and whose rejection predates a restart therefore stays pending for
    an operator - the spec's own resolution for unresolvable melts -
    rather than ever being restored on an inference."""
    sdk = await _sdk(config)
    payments = await _payments_by_hash(sdk, payment_hash, PaymentType.SEND)
    if not payments and payment_hash in _prepare_rejected:
        # this process rejected the payment at prepare - send_payment was
        # never called, so no SSP anywhere ever saw it (the router never
        # re-melts a payment hash it already recorded, so this melt is the
        # only attempt this hash will ever have)
        return False
    if not payments:
        # give the missing row every chance: probes prove both remote
        # legs are up on either side of a forced sync (whose own Ok
        # proves nothing - failures are swallowed), so a row the network
        # knows about materializes here rather than at the next
        # background sync tick; an outage raises from the probe instead
        await _remote_probe(sdk)
        await sdk.sync_wallet(request=SyncWalletRequest())
        await _remote_probe(sdk)
        payments = await _payments_by_hash(sdk, payment_hash, PaymentType.SEND)
    if not payments:
        # absence is NOT "not paid" - see the docstring above
        raise ValueError(
            "spark has no record of this payment and no same-process proof it was never sent "
            "- not a terminal outcome."
        )
    if any(p.status == PaymentStatus.COMPLETED for p in payments):
        return True
    if any(p.status == PaymentStatus.PENDING for p in payments):
        raise ValueError("spark reports the payment still pending - not a terminal outcome.")
    return False


async def _invoice_preimage_spark(payment_hash: str, config: LightningBackendConfig) -> bytes | None:
    sdk = await _sdk(config)
    for payment in await _payments_by_hash(sdk, payment_hash, PaymentType.RECEIVE):
        if payment.status != PaymentStatus.COMPLETED:
            continue
        htlc = _lightning_htlc(payment)
        # the SSP-populated preimage of the invoice this mint issued -
        # only present once settled, fetched live and never persisted by
        # this mint (see the module docstring)
        if htlc is not None and htlc.preimage:
            return bytes.fromhex(htlc.preimage)
    return None


async def _payment_preimage_spark(payment_hash: str, config: LightningBackendConfig) -> bytes | None:
    sdk = await _sdk(config)
    for payment in await _payments_by_hash(sdk, payment_hash, PaymentType.SEND):
        if payment.status != PaymentStatus.COMPLETED:
            continue
        htlc = _lightning_htlc(payment)
        if htlc is not None and htlc.preimage:
            return bytes.fromhex(htlc.preimage)
    return None


# --- LUD-25 offline verification: a dedicated seed-derived signing key -----
#
# The spec's digest (the "Lightning Signed Message" double-sha256 wrap,
# see signing.lightning_signed_message_digest) is produced natively by
# lnd/cln signmessage; the spark SDK has no signmessage and its own
# sign_message signs a single-sha256 digest it cannot redirect. LUD-25
# only RECOMMENDS the node-id key, though - mintPubkey may be any
# secp256k1 key - so this backend derives a dedicated one from the
# wallet's own seed and signs the exact spec digest locally (coincurve /
# libsecp256k1, RFC6979 deterministic nonces, recoverable r||s||recid):
# identical wire behavior to lnd/cln notes, verified by wallets the same
# way - recover the key from (digest, sig), compare to mintPubkey.
#
# Path: m/25'/0'/0' - purpose 25 (LUD-25), fully hardened. Deliberately
# OUTSIDE spark's own key tree (everything spark derives lives under
# m/8797555'/{account}', per the signer's account_master_key), so it can
# never collide with the wallet identity, leaf signing, or deposit keys;
# and distinct from holder-side LUD-25 derivations (m/139' under the
# *user's* master) - this is the MINT's seed. Rotating the mnemonic
# rotates the key.
_LUD25_SIGNING_PATH = (25 + 0x80000000, 0 + 0x80000000, 0 + 0x80000000)

# secp256k1 group order, for BIP32 child-key arithmetic
_SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# cache: mnemonic -> (PrivateKey, pubkey hex), so the per-request sign
# paths (every rotate/split/merge, every /w GET) never re-derive
_signing_keys: dict[str, tuple[PrivateKey, str]] = {}


def _bip39_seed(mnemonic: str) -> bytes:
    """BIP39 mnemonic -> 64-byte seed (PBKDF2-HMAC-SHA512, 2048 rounds,
    salt 'mnemonic'), stdlib-only - the same derivation the SDK applies to
    Seed.MNEMONIC (Seed::to_bytes), so the key really does belong to the
    configured wallet."""
    password = unicodedata.normalize("NFKD", mnemonic).encode()
    salt = unicodedata.normalize("NFKD", "mnemonic").encode()
    return hashlib.pbkdf2_hmac("sha512", password, salt, 2048, dklen=64)


def _bip32_hardened_child(key: bytes, chain_code: bytes, index: int) -> tuple[bytes, bytes]:
    """One BIP32 hardened child step: I = HMAC-SHA512(chain, 0x00 || key
    || ser32(index)); child key = (key + I[:32]) mod n, child chain =
    I[32:]. (Non-hardened derivation needs the parent PUBLIC key in the
    HMAC input; an all-hardened path never does, so this is all we need.)"""
    digest = hmac.new(chain_code, b"\x00" + key + index.to_bytes(4, "big"), hashlib.sha512).digest()
    tweak = int.from_bytes(digest[:32], "big")
    child = (int.from_bytes(key, "big") + tweak) % _SECP256K1_N
    if tweak >= _SECP256K1_N or child == 0:  # BIP32 invalid child, ~2^-127
        raise ValueError("invalid BIP32 child (improbable index)")
    return child.to_bytes(32, "big"), digest[32:]


def _lud25_signing_key(config: LightningBackendConfig) -> tuple[PrivateKey, str]:
    """(private key, compressed pubkey hex) of the wallet's LUD-25 note-
    signing key, derived and cached per mnemonic. Purely local: no SDK,
    no network, deterministic - same mnemonic, same key, forever."""
    if not config.spark_mnemonic:
        raise ValueError("Mnemonic is required.")
    mnemonic = config.spark_mnemonic.get_secret_value().strip()
    cached = _signing_keys.get(mnemonic)
    if cached is not None:
        return cached
    # BIP32 master: I = HMAC-SHA512(key=b"Bitcoin seed", data=seed)
    master = hmac.new(b"Bitcoin seed", _bip39_seed(mnemonic), hashlib.sha512).digest()
    key, chain_code = master[:32], master[32:]
    for index in _LUD25_SIGNING_PATH:
        key, chain_code = _bip32_hardened_child(key, chain_code, index)
    private_key = PrivateKey(key)
    result = (private_key, private_key.public_key.format(compressed=True).hex())
    _signing_keys[mnemonic] = result
    return result


def signing_pubkey_hex(config: LightningBackendConfig) -> str:
    """This spark wallet's LUD-25 mintPubkey (see _lud25_signing_key) - what
    mint_pubkey and the mint-address discovery endpoint advertise."""
    return _lud25_signing_key(config)[1]


async def _sign_message_spark(message: str, config: LightningBackendConfig) -> tuple[bytes, int]:
    # the exact LUD-25 digest and wire format lnd/cln produce via their
    # signmessage RPC, signed locally with the dedicated seed-derived key
    # (RFC6979 deterministic nonces via libsecp256k1) - see the signing-key
    # block above for why a self-generated key rather than the SDK's
    private_key, _ = _lud25_signing_key(config)
    recoverable = private_key.sign_recoverable(lightning_signed_message_digest(message), hasher=None)
    return recoverable[:64], recoverable[64]


async def _is_invoice_settled_spark(payment_hash: str, config: LightningBackendConfig) -> bool:
    sdk = await _sdk(config)
    return any(
        p.status == PaymentStatus.COMPLETED for p in await _payments_by_hash(sdk, payment_hash, PaymentType.RECEIVE)
    )


async def _fetch_node_info_spark(config: LightningBackendConfig) -> NodeInfo:
    sdk = await _sdk(config)
    # a remote probe, deliberately: get_info alone answers from local
    # storage (its identity_pubkey is the local signer's key), and a
    # forced sync proves nothing either - sync_wallet_internal
    # (breez-sdk-spark 0.23) catches and logs every sub-sync failure and
    # resolves Ok regardless, so either would report a healthy wallet
    # while the operators/SSP are unreachable - and server.py's health
    # monitor probes through this exact function, so its outage warning
    # and its gate on melt reconciliation would never fire. The probe is
    # the two-leg _remote_probe instead (coordinator + SSP: an SSP-only
    # outage or a revoked Breez API key is otherwise invisible); its
    # failure is this function's failure. Cost note: each probe leaves
    # one expiring 1-sat invoice at the SSP, so the health cadence (see
    # settings.funding_source_health_check_interval_seconds, default 60s)
    # is also the probe-invoice cadence - raise it if that ever matters.
    await _remote_probe(sdk)
    info = await sdk.get_info(request=GetInfoRequest(ensure_synced=None))
    # a spark wallet has no announced channels, peers, or public-graph
    # capacity - and its balance is private (unlike a Lightning node's
    # channel capacity, which is public by construction), so capacity
    # stays 0 rather than leaking balance_sats onto the public one-pager
    # and mint-address discovery response
    return NodeInfo(
        alias="spark wallet",
        uri=info.identity_pubkey,
        color=None,
        num_channels=0,
        num_peers=0,
        capacity=0,
    )


def _verify_preimage(preimage: bytes, invoice: str) -> None:
    decoded = bolt11.decode(invoice)
    if decoded.has_payment_hash and sha256(preimage).hexdigest() != decoded.payment_hash:
        raise ValueError("Returned preimage does not match the invoice's payment hash.")
