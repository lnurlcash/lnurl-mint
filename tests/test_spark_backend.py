"""The spark backend's SDK-facing functions, exercised against a fake
BreezSdk built from the real breez_sdk_spark types - so the enum/record
shapes the backend reads (PaymentStatus, PaymentDetails.LIGHTNING,
SendPaymentMethod.BOLT11_INVOICE, ...) are the genuine ones the wheel
will hand back at runtime, not a parallel reimplementation that could
drift. Requires the optional spark extra (`uv sync --extra spark`);
skipped entirely without it, which is why none of the mint's
core-behavior tests live here (those are in test_spark.py and run
everywhere)."""

import uuid
from hashlib import sha256
from os import urandom
from typing import Any

import pytest
from coincurve import PrivateKey

breez = pytest.importorskip("breez_sdk_spark")

import lnurl_mint.node as node_module  # noqa: E402
import lnurl_mint.spark as spark_module  # noqa: E402
from lnurl_mint.node import LightningBackendConfig, PaymentFailed  # noqa: E402
from lnurl_mint.signing import mint_pubkey, sign_note, verify_note  # noqa: E402
from lnurl_mint.spark import signing_pubkey_hex  # noqa: E402
from tests.conftest import fake_invoice  # noqa: E402

SPARK_CONFIG = LightningBackendConfig(
    backend="spark", spark_mnemonic="abandon abandon abandon", spark_storage_dir="/nonexistent"
)


def _run(coro):
    import asyncio

    return asyncio.run(coro)


def _htlc(payment_hash: str, preimage: str | None = None, status=None):
    return breez.SparkHtlcDetails(
        payment_hash=payment_hash,
        preimage=preimage,
        expiry_time=0,
        status=status or breez.SparkHtlcStatus.PREIMAGE_SHARED,
    )


def _payment(
    payment_id: str,
    payment_type,
    status,
    payment_hash: str,
    preimage: str | None = None,
    fees: int = 0,
):
    details = breez.PaymentDetails.LIGHTNING(
        description=None,
        invoice="lnbc1fake",
        destination_pubkey="02ab",
        htlc_details=_htlc(payment_hash, preimage),
        lnurl_pay_info=None,
        lnurl_withdraw_info=None,
        lnurl_receive_metadata=None,
        conversion_info=None,
    )
    return breez.Payment(
        id=payment_id,
        payment_type=payment_type,
        status=status,
        amount=1000,
        fees=fees,
        timestamp=1,
        method=breez.PaymentMethod.LIGHTNING,
        details=details,
        conversion_details=None,
    )


def _bolt11_prepare(fee_sats: int):
    invoice = breez.Bolt11Invoice(
        bolt11="lnbc1fake", source=breez.PaymentRequestSource(bip_21_uri=None, bip_353_address=None)
    )
    details = breez.Bolt11InvoiceDetails(
        amount_msat=1_000_000,
        description="",
        description_hash=None,
        expiry=3600,
        invoice=invoice,
        min_final_cltv_expiry_delta=18,
        network=breez.BitcoinNetwork.BITCOIN,
        payee_pubkey="02ab",
        payment_hash="cd" * 32,
        payment_secret="ef" * 32,
        routing_hints=[],
        timestamp=1,
    )
    method = breez.SendPaymentMethod.BOLT11_INVOICE(
        invoice_details=details, spark_transfer_fee_sats=None, lightning_fee_sats=fee_sats
    )
    return breez.PrepareSendPaymentResponse(
        payment_method=method,
        amount=1000,
        token_identifier=None,
        conversion_estimate=None,
        fee_policy=breez.FeePolicy.FEES_EXCLUDED,
    )


class FakeSparkSdk:
    """The BreezSdk surface the backend actually touches, built from real
    breez types. State is plain dicts/lists the tests arrange up front."""

    def __init__(self) -> None:
        self.payments: list[Any] = []
        self.lightning_fee_sats = 3
        self.send_status = breez.PaymentStatus.COMPLETED
        self.send_preimage = "12" * 32
        self.send_fees = 3
        self.fail_prepare: breez.SdkError | None = None
        self.fail_send: breez.SdkError | None = None
        self.last_receive_request = None
        self.last_prepare_request = None
        self.last_send_request = None
        self.sync_wallet_calls = 0
        # payments only a forced sync reveals - the crash-window shape
        # is_payment_complete's forced sync exists for (see spark.py's
        # module docstring): the SSP accepted the payment but this
        # process never persisted its row
        self.remote_only_payments: list[Any] = []
        # the propagating remote probe (get_user_settings) - raising here
        # simulates an unreachable/revoked-credential coordinator
        self.user_settings_calls = 0
        self.fail_user_settings = False
        # the probe's SSP leg (a throwaway 1-sat invoice) - raising here
        # simulates a coordinator-up/SSP-down outage, the split a
        # coordinator-only probe would miss
        self.probe_invoice_calls = 0
        self.fail_probe_invoice = False
        # every remote call in order, to pin the probe/sync bracketing
        self.call_log: list[str] = []
        self.disconnect_called = False
        # a real keypair standing in for the spark wallet's identity key
        self.identity = PrivateKey()

    async def receive_payment(self, request):
        self.last_receive_request = request
        method = request.payment_method
        assert method.is_BOLT11_INVOICE()
        if method.description == "lnurl-mint connectivity probe":
            self.probe_invoice_calls += 1
            self.call_log.append(f"probe-ssp-{self.probe_invoice_calls}")
            if self.fail_probe_invoice:
                raise breez.SdkError.SparkError("SSP unreachable")
        preimage = urandom(32)
        payment_hash = sha256(preimage).hexdigest()
        return breez.ReceivePaymentResponse(
            payment_request=fake_invoice((method.amount_sats or 0) * 1000, payment_hash), fee=0
        )

    async def prepare_send_payment(self, request):
        self.last_prepare_request = request
        if self.fail_prepare is not None:
            raise self.fail_prepare
        return _bolt11_prepare(self.lightning_fee_sats)

    async def send_payment(self, request):
        self.last_send_request = request
        if self.fail_send is not None:
            raise self.fail_send
        # the payment's hash/preimage pair matches whatever the test
        # arranged - only both present once COMPLETED, same as the real
        # SDK reports it
        payment = _payment(
            "tid-1",
            breez.PaymentType.SEND,
            self.send_status,
            sha256(bytes.fromhex(self.send_preimage)).hexdigest() if self.send_preimage else "ab" * 32,
            preimage=self.send_preimage if self.send_status == breez.PaymentStatus.COMPLETED else None,
            fees=self.send_fees,
        )
        self.payments.append(payment)
        return breez.SendPaymentResponse(payment=payment)

    async def list_payments(self, request):
        payments = [p for p in self.payments if not request.type_filter or p.payment_type in request.type_filter]
        offset = request.offset or 0
        limit = request.limit if request.limit is not None else len(payments)
        return breez.ListPaymentsResponse(payments=payments[offset : offset + limit])

    async def sync_wallet(self, request):
        self.sync_wallet_calls += 1
        self.call_log.append(f"sync-{self.sync_wallet_calls}")
        # faithful to breez-sdk-spark 0.23: sync_wallet_internal swallows
        # every sub-sync failure and resolves Ok regardless, so this fake
        # has no failure mode at all - the remote probes are the only
        # thing that can catch an outage (which is exactly why the real
        # code brackets the sync with them)
        #
        # a successful sync re-materializes whatever the remote view
        # holds - both the crash-window row and everything already local
        self.payments[:0] = self.remote_only_payments
        self.remote_only_payments = []
        return breez.SyncWalletResponse()

    async def get_user_settings(self):
        self.user_settings_calls += 1
        self.call_log.append(f"probe-coordinator-{self.user_settings_calls}")
        if self.fail_user_settings:
            raise breez.SdkError.SparkError("Operator RPC error: Connection error: Unavailable")
        return breez.UserSettings(
            spark_private_mode_enabled=True,
            stable_balance_active_label=None,
            spark_master_identity_public_key=None,
        )

    async def sign_message(self, request):
        raise AssertionError("the backend must not call spark sign_message - see spark._sign_message_spark")

    async def get_info(self, request):
        return breez.GetInfoResponse(
            identity_pubkey=self.identity.public_key.format(compressed=True).hex(),
            balance_sats=0,
            token_balances={},
        )

    async def disconnect(self):
        self.disconnect_called = True


@pytest.fixture
def spark_sdk(monkeypatch: pytest.MonkeyPatch) -> FakeSparkSdk:
    fake = FakeSparkSdk()
    spark_module._reset_sdk_for_testing(fake)
    spark_module._prepare_rejected.clear()  # module-level, like the singleton
    yield fake
    spark_module._reset_sdk_for_testing(None)
    spark_module._prepare_rejected.clear()


def test_create_invoice_asks_for_sats_and_returns_no_preimage(spark_sdk):
    pr, preimage = _run(spark_module._create_invoice_spark(5000, SPARK_CONFIG, "a memo"))
    assert preimage is None
    assert pr.startswith("lnbc")
    method = spark_sdk.last_receive_request.payment_method
    assert method.amount_sats == 5
    assert method.description == "a memo"
    assert method.payment_hash is None  # not a hodl invoice - the SSP holds the preimage


def test_create_invoice_rejects_fractional_sats():
    with pytest.raises(ValueError, match="sat-aligned"):
        _run(spark_module._create_invoice_spark(5001, SPARK_CONFIG))


def test_pay_invoice_completed_payment_returns_preimage_and_fee(spark_sdk):
    # the invoice must commit to exactly the preimage the SDK will report
    # back - mirroring a real settled payment
    preimage_hex = "12" * 32
    spark_sdk.send_preimage = preimage_hex
    pr = fake_invoice(5000, sha256(bytes.fromhex(preimage_hex)).hexdigest())
    result = _run(node_module.pay_invoice(pr, SPARK_CONFIG, fee_limit_msat=100_000))
    assert result.preimage.hex() == preimage_hex
    # fees are sats in, msat out
    assert result.fee_msat == 3000
    # deterministic idempotency key, derived from the invoice's hash
    key = spark_sdk.last_send_request.idempotency_key
    assert key is not None
    uuid.UUID(key)  # parses
    _run(node_module.pay_invoice(pr, SPARK_CONFIG, fee_limit_msat=100_000))
    assert spark_sdk.last_send_request.idempotency_key == key
    options = spark_sdk.last_send_request.options
    assert options.is_BOLT11_INVOICE()
    # always the Lightning route - a melt's settlement proof is the
    # preimage, which a spark-routed payment never produces
    assert options.prefer_spark is False


def test_pay_invoice_rejects_an_over_budget_fee_quote_without_paying(spark_sdk):
    spark_sdk.lightning_fee_sats = 500  # 500_000 msat, over a 100 msat budget
    pr = fake_invoice(5000, "ab" * 32)
    with pytest.raises(PaymentFailed, match="budget"):
        _run(node_module.pay_invoice(pr, SPARK_CONFIG, fee_limit_msat=100))
    assert spark_sdk.last_send_request is None  # never attempted
    # and like any prepare-stage rejection, provably nothing was sent - a
    # later confirmation answers a clean False instead of wedging the
    # note pending
    assert _run(node_module.is_payment_complete("ab" * 32, SPARK_CONFIG)) is False


def test_pay_invoice_rejects_a_fractional_sat_melt_before_the_sdk_rounds_it(spark_sdk):
    # the SDK CEILs a fractional-sat invoice into whole sats of spark
    # leaves (get_invoice_amount_sats: div_ceil), so paying a 10.5-sat
    # melt would debit 11 sats against a 10.5-sat note - and with tiny
    # fractional notes from splits, repeated melts would over-drain the
    # wallet. Rejected before any SDK call (nothing was sent, provably)
    # and registered, so the reserved note restores cleanly
    pr = fake_invoice(10_500, "ab" * 32)  # 10.5 sats
    with pytest.raises(PaymentFailed, match="sat-aligned"):
        _run(node_module.pay_invoice(pr, SPARK_CONFIG, fee_limit_msat=100_000))
    assert spark_sdk.last_prepare_request is None  # rejected before prepare too
    assert _run(node_module.is_payment_complete("ab" * 32, SPARK_CONFIG)) is False


def test_pay_invoice_maps_sdk_errors_to_clean_payment_failures(spark_sdk):
    spark_sdk.fail_prepare = breez.SdkError.InsufficientFunds("not enough")
    with pytest.raises(PaymentFailed, match="prepare"):
        _run(node_module.pay_invoice(fake_invoice(5000), SPARK_CONFIG, fee_limit_msat=100_000))

    spark_sdk.fail_prepare = None
    spark_sdk.fail_send = breez.SdkError.Generic("ssp exploded")
    with pytest.raises(PaymentFailed, match="attempt failed"):
        _run(node_module.pay_invoice(fake_invoice(5000), SPARK_CONFIG, fee_limit_msat=100_000))


def test_send_stage_insufficient_funds_restores_instead_of_wedging(spark_sdk):
    # prepare only quotes a fee; the balance check happens inside
    # send_payment while selecting leaves - BEFORE any operator signing or
    # SSP request. That provably-unsent outcome is registered, so an
    # underfunded wallet's melt restores the note immediately instead of
    # leaving it pending forever on an unconfirmable absence. Both error
    # shapes are covered: the flattened SparkError payload the bolt11 path
    # actually raises (verified live on mainnet - the dedicated variant
    # never fires there) and the variant itself
    pr = fake_invoice(5000, "ab" * 32)
    spark_sdk.fail_send = breez.SdkError.SparkError("Tree service error: insufficient funds")
    with pytest.raises(PaymentFailed, match="insufficient funds"):
        _run(node_module.pay_invoice(pr, SPARK_CONFIG, fee_limit_msat=100_000))
    assert spark_sdk.last_send_request is not None  # it got as far as sending
    assert _run(node_module.is_payment_complete("ab" * 32, SPARK_CONFIG)) is False
    assert spark_sdk.sync_wallet_calls == 0  # provable, no probes needed

    spark_sdk.fail_send = breez.SdkError.InsufficientFunds("Insufficient funds")
    with pytest.raises(PaymentFailed, match="insufficient funds"):
        _run(node_module.pay_invoice(fake_invoice(5000, "cd" * 32), SPARK_CONFIG, fee_limit_msat=100_000))
    assert _run(node_module.is_payment_complete("cd" * 32, SPARK_CONFIG)) is False


def test_other_send_errors_stay_ambiguous_not_registered(spark_sdk):
    # a non-balance send error says nothing about whether the SSP already
    # accepted the payment - it must NOT be registered, and its
    # confirmation stays indeterminate (note pending, never restored on
    # an inference). Includes errors that merely MENTION funds but aren't
    # the wallet-local tree-service reservation failure
    pr = fake_invoice(5000, "ab" * 32)
    spark_sdk.fail_send = breez.SdkError.Generic("connection lost mid-request")
    with pytest.raises(PaymentFailed, match="attempt failed"):
        _run(node_module.pay_invoice(pr, SPARK_CONFIG, fee_limit_msat=100_000))
    with pytest.raises(ValueError, match="not a terminal outcome"):
        _run(node_module.is_payment_complete("ab" * 32, SPARK_CONFIG))

    # an SSP-side rejection that happens to say "insufficient funds" is
    # post-acceptance territory - the narrow discriminator must not match
    spark_sdk.fail_send = breez.SdkError.SparkError("SSP swap error: peer reports insufficient funds for route")
    pr2 = fake_invoice(5000, "cd" * 32)
    with pytest.raises(PaymentFailed, match="attempt failed"):
        _run(node_module.pay_invoice(pr2, SPARK_CONFIG, fee_limit_msat=100_000))
    with pytest.raises(ValueError, match="not a terminal outcome"):
        _run(node_module.is_payment_complete("cd" * 32, SPARK_CONFIG))


def test_pay_invoice_failed_status_is_a_clean_payment_failure(spark_sdk):
    spark_sdk.send_status = breez.PaymentStatus.FAILED
    with pytest.raises(PaymentFailed):
        _run(node_module.pay_invoice(fake_invoice(5000), SPARK_CONFIG, fee_limit_msat=100_000))


def test_pay_invoice_still_pending_is_ambiguous_not_failed(spark_sdk):
    # a payment the SDK still reports pending (e.g. a payee holding a
    # hodl invoice) must NOT be reported as a clean failure - the note
    # stays reserved until a terminal answer exists
    spark_sdk.send_status = breez.PaymentStatus.PENDING
    with pytest.raises(ValueError, match="pending"):
        _run(node_module.pay_invoice(fake_invoice(5000), SPARK_CONFIG, fee_limit_msat=100_000))


def test_pay_invoice_completed_without_a_preimage_is_ambiguous(spark_sdk):
    spark_sdk.send_status = breez.PaymentStatus.COMPLETED
    spark_sdk.send_preimage = None
    with pytest.raises(ValueError, match="preimage"):
        _run(node_module.pay_invoice(fake_invoice(5000), SPARK_CONFIG, fee_limit_msat=100_000))


def test_is_payment_complete_absence_is_indeterminate_even_after_a_proven_sync(spark_sdk):
    # absence of a local row must NEVER read as "not paid": the SDK
    # persists its row only after the SSP accepted the payment (crash
    # window), and the forced sync's Ok proves nothing - 0.23 swallows
    # every reconciliation failure, across two independent services, so
    # no probe pattern can prove the sync itself succeeded. Even with
    # both remote legs proven up on both sides of the sync, a still-empty
    # scan stays indeterminate: is_payment_complete raises, the note
    # stays pending, never restored on an inference
    assert spark_sdk.sync_wallet_calls == 0
    with pytest.raises(ValueError, match="not a terminal outcome"):
        _run(node_module.is_payment_complete("ab" * 32, SPARK_CONFIG))
    # it gave the row every chance first: two full probes (coordinator +
    # SSP each) bracketing one forced sync, in exactly that order
    assert spark_sdk.sync_wallet_calls == 1
    assert spark_sdk.user_settings_calls == 2
    assert spark_sdk.probe_invoice_calls == 2
    assert spark_sdk.call_log == [
        "probe-coordinator-1",
        "probe-ssp-1",
        "sync-1",
        "probe-coordinator-2",
        "probe-ssp-2",
    ]


def test_is_payment_complete_recovers_a_row_lost_to_the_crash_window(spark_sdk):
    # the double-payout regression: the SSP accepted the payment but this
    # process died before the SDK persisted its row - the gated forced
    # sync re-materializes it (the SDK's payment reconciliation is a
    # remote query_all_transfers plus SSP enrichment), and
    # is_payment_complete must then report the payment complete from the
    # ROW - not restore the note on the row's absence
    hash_ = "ab" * 32
    spark_sdk.remote_only_payments.append(_payment("t1", breez.PaymentType.SEND, breez.PaymentStatus.COMPLETED, hash_))
    assert _run(node_module.is_payment_complete(hash_, SPARK_CONFIG)) is True


def test_prepare_rejection_is_the_one_provable_not_paid(spark_sdk):
    # a prepare that raises never reached send_payment - nothing was
    # sent, and this process knows it first-hand. The registry makes that
    # a provable False (no probes, no sync - the answer doesn't depend on
    # any remote view), so a wallet's clean fee/insufficient-balance
    # rejection restores its note immediately instead of wedging it
    spark_sdk.fail_prepare = breez.SdkError.InsufficientFunds("not enough")
    pr = fake_invoice(5000, "ab" * 32)
    with pytest.raises(PaymentFailed, match="prepare"):
        _run(node_module.pay_invoice(pr, SPARK_CONFIG, fee_limit_msat=100_000))
    assert _run(node_module.is_payment_complete("ab" * 32, SPARK_CONFIG)) is False
    assert spark_sdk.sync_wallet_calls == 0
    assert spark_sdk.user_settings_calls == 0
    # a FAILED row still answers the same way if one somehow exists
    spark_sdk.payments.append(_payment("t1", breez.PaymentType.SEND, breez.PaymentStatus.FAILED, "ab" * 32))
    assert _run(node_module.is_payment_complete("ab" * 32, SPARK_CONFIG)) is False


def test_is_payment_complete_absence_stays_indeterminate_when_either_probe_leg_fails(
    spark_sdk,
):
    # the probes propagate failures as errors (router._confirm_payment
    # retries and leaves the note pending), never as a False that would
    # restore the note on a guess - before the sync AND after it, since
    # the sync itself can silently fail and prove nothing. Either leg
    # failing counts: the reconciliation needs coordinator AND SSP, so a
    # coordinator-up/SSP-down split must be indeterminate too
    spark_sdk.fail_probe_invoice = True  # SSP down, coordinator up
    with pytest.raises(breez.SdkError):
        _run(node_module.is_payment_complete("ab" * 32, SPARK_CONFIG))
    assert spark_sdk.sync_wallet_calls == 0  # the leading probe gated it

    spark_sdk.fail_probe_invoice = False
    spark_sdk.fail_user_settings = True  # coordinator down
    with pytest.raises(breez.SdkError):
        _run(node_module.is_payment_complete("cd" * 32, SPARK_CONFIG))
    assert spark_sdk.sync_wallet_calls == 0

    # and a leg failing only AFTER the sync (outage began mid-sync) must
    # be indeterminate too - the sync's Ok is worthless as proof
    spark_sdk.fail_user_settings = False
    calls_before = spark_sdk.probe_invoice_calls

    async def fail_after_first_probe(request):
        spark_sdk.probe_invoice_calls += 1
        if spark_sdk.probe_invoice_calls > calls_before + 1:
            raise breez.SdkError.SparkError("SSP unreachable")
        return await FakeSparkSdk.receive_payment(spark_sdk, request)

    import unittest.mock as mock

    with mock.patch.object(spark_sdk, "receive_payment", side_effect=fail_after_first_probe):
        with pytest.raises(breez.SdkError):
            _run(node_module.is_payment_complete("ef" * 32, SPARK_CONFIG))


def test_is_payment_complete_by_status(spark_sdk):
    hash_ = "ab" * 32
    spark_sdk.payments.append(_payment("t1", breez.PaymentType.SEND, breez.PaymentStatus.COMPLETED, hash_))
    assert _run(node_module.is_payment_complete(hash_, SPARK_CONFIG)) is True

    spark_sdk.payments[0] = _payment("t1", breez.PaymentType.SEND, breez.PaymentStatus.FAILED, hash_)
    assert _run(node_module.is_payment_complete(hash_, SPARK_CONFIG)) is False

    spark_sdk.payments[0] = _payment("t1", breez.PaymentType.SEND, breez.PaymentStatus.PENDING, hash_)
    with pytest.raises(ValueError, match="pending"):
        _run(node_module.is_payment_complete(hash_, SPARK_CONFIG))

    # one completed attempt wins even alongside a stale pending one
    spark_sdk.payments.append(_payment("t2", breez.PaymentType.SEND, breez.PaymentStatus.PENDING, hash_))
    spark_sdk.payments[0] = _payment("t1", breez.PaymentType.SEND, breez.PaymentStatus.COMPLETED, hash_)
    assert _run(node_module.is_payment_complete(hash_, SPARK_CONFIG)) is True


def test_is_payment_complete_ignores_receive_payments_and_scans_pages(spark_sdk):
    hash_ = "ab" * 32
    # a receive with the same hash must not answer a send's question
    spark_sdk.payments.append(_payment("r1", breez.PaymentType.RECEIVE, breez.PaymentStatus.COMPLETED, hash_))
    # and the matching send sits past the first results page
    spark_sdk.payments[:0] = [
        _payment(f"filler-{i}", breez.PaymentType.SEND, breez.PaymentStatus.FAILED, "cd" * 32)
        for i in range(spark_module._PAYMENT_SCAN_PAGE)
    ]
    spark_sdk.payments.append(_payment("s1", breez.PaymentType.SEND, breez.PaymentStatus.COMPLETED, hash_))
    assert _run(node_module.is_payment_complete(hash_, SPARK_CONFIG)) is True


def test_invoice_settlement_and_preimage(spark_sdk):
    hash_ = "ab" * 32
    assert _run(node_module.is_invoice_settled(hash_, SPARK_CONFIG)) is False
    assert _run(node_module.invoice_preimage(hash_, SPARK_CONFIG)) is None

    spark_sdk.payments.append(
        _payment("r1", breez.PaymentType.RECEIVE, breez.PaymentStatus.COMPLETED, hash_, preimage="12" * 32)
    )
    assert _run(node_module.is_invoice_settled(hash_, SPARK_CONFIG)) is True
    assert _run(node_module.invoice_preimage(hash_, SPARK_CONFIG)) == bytes.fromhex("12" * 32)

    # settled only in the pending sense - not yet a note, and no preimage
    # to hand out
    spark_sdk.payments[0] = _payment("r1", breez.PaymentType.RECEIVE, breez.PaymentStatus.PENDING, hash_, preimage=None)
    assert _run(node_module.is_invoice_settled(hash_, SPARK_CONFIG)) is False
    assert _run(node_module.invoice_preimage(hash_, SPARK_CONFIG)) is None


def test_payment_preimage_for_melt_verify(spark_sdk):
    hash_ = "ab" * 32
    assert _run(node_module.payment_preimage(hash_, SPARK_CONFIG)) is None
    spark_sdk.payments.append(
        _payment("s1", breez.PaymentType.SEND, breez.PaymentStatus.COMPLETED, hash_, preimage="34" * 32)
    )
    assert _run(node_module.payment_preimage(hash_, SPARK_CONFIG)) == bytes.fromhex("34" * 32)


def test_sign_message_produces_spec_signatures_locally(spark_sdk):
    # LUD-25 signatures via the dedicated seed-derived key: the exact spec
    # digest (Lightning Signed Message double-sha256) and wire format
    # (recoverable r||s||recid), RFC6979-deterministic, and produced with
    # NO sdk call at all - purely local key material, so signing can never
    # fail for network reasons mid-rotate/split/merge (the fake's
    # sign_message would assert if the backend tried the SDK's)
    message = "LNURLcash:testserver:5000:" + "ab" * 32
    assert spark_sdk.user_settings_calls == 0 and spark_sdk.sync_wallet_calls == 0
    r_s, recovery_id = _run(node_module.sign_message(message, SPARK_CONFIG))
    assert spark_sdk.user_settings_calls == 0 and spark_sdk.sync_wallet_calls == 0
    from lnurl_mint.signing import verify_note

    pubkey = signing_pubkey_hex(SPARK_CONFIG)
    signature = (r_s + bytes([recovery_id])).hex()
    assert verify_note(pubkey, "ab" * 32, "testserver", 5000, signature)

    # RFC6979: deterministic nonces - the same message always signs identically
    again = _run(node_module.sign_message(message, SPARK_CONFIG))
    assert (again[0] + bytes([again[1]])) == r_s + bytes([recovery_id])


def test_signing_key_is_derived_from_the_mnemonic():
    # deterministic derivation: same mnemonic -> same key forever, a
    # different mnemonic -> a different key (rotating the wallet rotates
    # the advertised mintPubkey and with it every future signature)
    other = LightningBackendConfig(
        backend="spark",
        spark_mnemonic="legal winner thank year wave sausage worth useful legal winner thank yellow",
        spark_storage_dir="/nonexistent",
    )
    a = signing_pubkey_hex(SPARK_CONFIG)
    assert a == signing_pubkey_hex(SPARK_CONFIG)
    b = signing_pubkey_hex(other)
    assert a != b
    assert len(bytes.fromhex(a)) == 33  # compressed secp256k1 pubkey


def test_sign_note_end_to_end_against_verify_note(spark_sdk):
    h = urandom(32).hex()
    signature = _run(sign_note(h, "testserver", 5000, SPARK_CONFIG))
    assert signature is not None
    assert verify_note(signing_pubkey_hex(SPARK_CONFIG), h, "testserver", 5000, signature)


def test_mint_pubkey_advertises_the_derived_key(spark_sdk):
    # mint_pubkey serves the same dedicated key the notes are signed with,
    # derived locally - no funding-source round trip involved for spark
    assert _run(mint_pubkey(SPARK_CONFIG)) == signing_pubkey_hex(SPARK_CONFIG)


def test_fetch_node_info_probes_both_legs_and_reports_identity_not_balance(spark_sdk):
    # get_info alone answers from local storage and a forced sync proves
    # nothing (0.23 swallows sub-sync failures) - useless as a health
    # probe (server.py's monitor gates its outage warning and melt
    # reconciliation on this function) - so fetch_node_info must make a
    # two-leg propagating remote probe first (coordinator AND SSP: an
    # SSP-only outage or a revoked Breez API key is otherwise invisible),
    # whose failure propagates in turn
    info = _run(node_module.fetch_node_info(SPARK_CONFIG))
    assert spark_sdk.user_settings_calls == 1
    assert spark_sdk.probe_invoice_calls == 1
    assert spark_sdk.sync_wallet_calls == 0
    assert info.uri == spark_sdk.identity.public_key.format(compressed=True).hex()
    assert info.capacity == 0  # balance is private - never a public "capacity"
    assert info.alias == "spark wallet"

    spark_sdk.fail_user_settings = True
    with pytest.raises(breez.SdkError):
        _run(node_module.fetch_node_info(SPARK_CONFIG))
    spark_sdk.fail_user_settings = False
    spark_sdk.fail_probe_invoice = True
    with pytest.raises(breez.SdkError):
        _run(node_module.fetch_node_info(SPARK_CONFIG))


def test_shutdown_disconnects_the_singleton(spark_sdk):
    _run(spark_module.shutdown())
    assert spark_sdk.disconnect_called is True
    assert spark_module._sdk_singleton is None
    # idempotent
    _run(spark_module.shutdown())


def test_melt_idempotency_key_is_deterministic_per_invoice():
    pr = fake_invoice(5000, "ab" * 32)
    first = spark_module._melt_idempotency_key(pr)
    assert first == spark_module._melt_idempotency_key(pr)
    assert first != spark_module._melt_idempotency_key(fake_invoice(5000, "cd" * 32))
