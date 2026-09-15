import json
import logging
import re
import ssl
import time
from base64 import b64decode, b64encode
from hashlib import sha256
from os import urandom
from typing import Any, Awaitable, Callable, Literal, NamedTuple
from urllib.parse import quote

import bolt11
import httpx
from pydantic import BaseModel, SecretStr


async def _raise_for_status(res: httpx.Response) -> None:
    """Like httpx.Response.raise_for_status(), but folds the response body
    into the exception message - lnd and cln both put the actual failure
    reason there (e.g. cln's {"code": ..., "message": "Not permitted: ..."}
    or a rune's rejection reason), which the bare httpx exception otherwise
    discards, leaving only the status code visible in logs. Handles a
    streamed response (see _pay_invoice_lnd) that hasn't been read yet -
    safe to read fully here, since a non-2xx status means the caller was
    never going to consume it as a stream anyway."""
    if res.is_success:
        return
    try:
        body = res.text
    except httpx.ResponseNotRead:
        body = (await res.aread()).decode(errors="replace")
    try:
        res.raise_for_status()
    except httpx.HTTPStatusError as exc:
        raise httpx.HTTPStatusError(f"{exc}: {body}", request=exc.request, response=exc.response) from exc


class PaymentFailed(Exception):
    """Raised by pay_invoice when the funding source's immediate response
    to the payment attempt itself was a clean failure (a routing failure,
    a rejected/expired invoice, ...) - as opposed to a dropped connection,
    our own timeout, or a malformed response, where it's unclear whether
    the payment actually went out (those stay as plain ValueError/httpx
    exceptions). This is NOT the same as "no HTLC can possibly still be
    outstanding": a malicious payee holding a hodl invoice can make the
    funding source give up and report exactly this kind of clean failure
    (lnd's own send attempt timing out, cln's xpay exhausting retry_for)
    while still holding the HTLC open, to be settled later once the
    payment's own sender-side bookkeeping has already moved on - so
    router.py's melt path treats this the same as any other raise: still
    confirmed independently via is_payment_complete before anything is
    restored. Used only to carry `str(exc)` as a clean, human-readable
    reason instead of a wrapped exception dump."""


class LightningBackendConfig(BaseModel):
    """This mint's own funding source backend and credentials (configured
    once by the operator - see config.Settings.funding_source). Only the
    field(s) relevant to `backend` are ever read."""

    backend: Literal["lnd", "cln", "spark"] | None = None
    url: str | None = None
    macaroon: SecretStr | None = None  # lnd
    rune: SecretStr | None = None  # cln
    cert_path: str | None = None  # pin verification to a self-signed cert
    # spark (see spark.py - the breez-sdk-spark wallet this mint funds
    # itself with): the wallet's BIP39 mnemonic, the Breez API key its
    # services want, which network to talk to, where the SDK keeps its
    # own sqlite store, and how often its background loop syncs
    spark_mnemonic: SecretStr | None = None
    spark_api_key: SecretStr | None = None
    spark_network: Literal["mainnet", "regtest"] = "mainnet"
    spark_storage_dir: str | None = None
    spark_sync_interval_secs: int = 15
    spark_account_number: int | None = None

    @property
    def verify(self) -> bool | ssl.SSLContext:
        if not self.cert_path:
            return True
        return ssl.create_default_context(cafile=self.cert_path)


async def _dispatch(
    operation: str,
    config: LightningBackendConfig,
    lnd_fn: Callable[..., Awaitable[Any]],
    cln_fn: Callable[..., Awaitable[Any]],
    *leading: Any,
    trailing: tuple = (),
) -> Any:
    """Runs `lnd_fn`/`cln_fn` (whichever `config.backend` selects) as
    `fn(*leading, config.url, credential, config, *trailing)` - the
    `(url, credential, config)` triple every `_xxx_lnd`/`_xxx_cln`
    implementation below takes in that position, `credential` being
    config's macaroon (lnd) or rune (cln). The credential check (and the
    "which backend" branch itself) would otherwise be copy-pasted into
    every public function in this module - `operation` is just that
    function's own name, for an unsupported-backend error that still
    points at the right one.

    The spark backend has no url/credential pair - its credentials live
    in the process-wide SDK singleton spark.py builds from config - so
    its branch dispatches by operation name to `fn(*leading, config,
    *trailing)` instead (imported lazily: spark.py imports this module's
    shared types, so a module-level import would be circular)."""
    if config.backend == "spark":
        from .spark import dispatch as spark_dispatch

        return await spark_dispatch(operation, config, leading, trailing)
    if config.backend == "lnd":
        if not config.url or not config.macaroon:
            raise ValueError("Macaroon is required.")
        return await lnd_fn(*leading, config.url, config.macaroon.get_secret_value(), config, *trailing)
    if config.backend == "cln":
        if not config.url or not config.rune:
            raise ValueError("Rune is required.")
        return await cln_fn(*leading, config.url, config.rune.get_secret_value(), config, *trailing)
    raise ValueError(f"{operation} is not supported for backend {config.backend!r}.")


async def create_invoice(
    amount_msat: int,
    config: LightningBackendConfig,
    memo: str = "lnurlcash mint",
    description_for_hash: str | None = None,
) -> tuple[str, bytes | None]:
    """The preimage half of the result is None for the spark backend -
    its SSP generates and holds the preimage itself (see spark.py's
    module docstring), so there the caller takes the payment hash off
    the returned invoice instead of sha256(preimage); lnd/cln both let
    the caller supply the preimage, so those return it and nothing else
    ever needs to.

    `description_for_hash` commits the invoice to a text it does not
    carry: the invoice gets `h` = sha256(text) in place of `d`, which is
    how a NIP-57 zap invoice binds to its zap request. lnd and cln both
    do it; spark cannot (see _create_invoice_spark)."""
    return await _dispatch(
        "create_invoice",
        config,
        _create_invoice_lnd,
        _create_invoice_cln,
        amount_msat,
        trailing=(memo, description_for_hash),
    )


class PaymentResult(NamedTuple):
    """A completed outgoing payment - both backends report the actual
    routing fee paid alongside the preimage, which mint_log.log_melt uses
    for its accounting record (see router.py's melt path)."""

    preimage: bytes
    fee_msat: int | None  # None if the backend's response didn't include one


async def pay_invoice(invoice: str, config: LightningBackendConfig, fee_limit_msat: int) -> PaymentResult:
    """`fee_limit_msat` is an absolute cap on the routing fee this payment
    may spend - the caller's responsibility to size (see router.py's
    _melt_fee_limit_msat), not guessed at here; neither backend's own
    built-in default has any notion of what this mint charges to mint a
    note this size in the first place."""
    return await _dispatch(
        "pay_invoice", config, _pay_invoice_lnd, _pay_invoice_cln, invoice, trailing=(fee_limit_msat,)
    )


async def is_payment_complete(payment_hash: str, config: LightningBackendConfig) -> bool:
    """Whether an outgoing payment this mint sent (via pay_invoice) actually
    completed - checked independently of whatever pay_invoice's own call
    returned. A melt that raises (timeout, dropped connection, ...) after
    the underlying payment already went through must not be treated as a
    failure: the caller could otherwise retry with a *different* invoice
    and get the same note's value paid out twice (see router.py's melt
    path, the only caller).

    Returns True/False only once the funding source gives a genuinely
    terminal answer (succeeded, or definitively failed with no HTLC left
    outstanding). A payment that's still in flight - notably one held open
    by a malicious payee's hodl invoice, refusing to either settle or fail
    it - is neither: the backend implementations raise rather than
    reporting False for that case, since "still pending" is not "confirmed
    not paid", and misreporting it as such is exactly what would let a
    holder recover and re-melt a note whose value is still claimable by
    someone else."""
    return await _dispatch(
        "is_payment_complete", config, _is_payment_complete_lnd, _is_payment_complete_cln, payment_hash
    )


async def invoice_preimage(payment_hash: str, config: LightningBackendConfig) -> bytes | None:
    """The preimage of an invoice this mint issued, if it has settled -
    fetched live from the funding source rather than cached anywhere (see
    db.NoteStore's store-hashes-not-secrets policy), since for lnurlcash
    this preimage IS the bearer note's spend secret. Used by LUD-21 verify
    to hand it to a wallet with no node of its own, letting it claim and
    rotate the note immediately, closing the exposure window before anyone
    else who saw the invoice can race it."""
    return await _dispatch("invoice_preimage", config, _invoice_preimage_lnd, _invoice_preimage_cln, payment_hash)


async def payment_preimage(payment_hash: str, config: LightningBackendConfig) -> bytes | None:
    """The preimage of an outgoing payment this mint sent (via pay_invoice),
    if it has settled - fetched live, never cached, same as invoice_preimage
    but for the other direction. Because a BOLT-11 `pr` commits to
    payment_hash = sha256(preimage), this is a melt's own settlement proof:
    LUD-25's melt verify (router._melt_preimage) hands it back alongside the
    `pr` it paid so a third party can confirm the payment independently,
    without trusting this mint's word for it - the same gap LUD-21 verify
    closes for minting, mirrored for the melt side."""
    return await _dispatch("payment_preimage", config, _payment_preimage_lnd, _payment_preimage_cln, payment_hash)


async def sign_message(message: str, config: LightningBackendConfig) -> tuple[bytes, int]:
    """Signs `message` with this mint's own node identity key, via lnd's or
    cln's signmessage RPC - both follow the standard "Lightning Signed
    Message" convention (sign(sha256(sha256(b"Lightning Signed Message:" +
    message))), recoverable), the same one BOLT11-adjacent tools (LNbits,
    Zeus, ...) already use to prove node ownership. Neither backend exposes
    a way to sign an arbitrary raw digest instead - this wrapping is always
    applied. Returns (r || s, recovery_id)."""
    return await _dispatch("sign_message", config, _sign_message_lnd, _sign_message_cln, message)


async def is_invoice_settled(payment_hash: str, config: LightningBackendConfig) -> bool:
    """Whether an invoice this mint issued has been paid, checked against
    the funding source directly - callers should remember a True result
    locally (see db.NoteStore.settle_mint) so a settled invoice doesn't
    need to be re-queried."""
    return await _dispatch("is_invoice_settled", config, _is_invoice_settled_lnd, _is_invoice_settled_cln, payment_hash)


# --- lnd -----------------------------------------------------------------
# REST API: https://lightning.engineering/api-docs/api/lnd/


async def _create_invoice_lnd(
    amount_msat: int,
    url: str,
    macaroon: str,
    config: LightningBackendConfig,
    memo: str,
    description_for_hash: str | None = None,
) -> tuple[str, bytes]:
    # lnd's AddInvoice never returns the preimage - it lets the caller supply
    # one instead (r_preimage), so generate it ourselves and use that: the
    # preimage *is* the bearer note k1 once the invoice settles, so the mint
    # must know it for certain regardless of what the backend reports
    preimage = urandom(32)
    body: dict[str, str] = {"value_msat": str(amount_msat), "r_preimage": b64encode(preimage).decode()}
    if description_for_hash is None:
        body["memo"] = memo
    else:
        # lnd takes the hash itself; a memo alongside would be dropped
        body["description_hash"] = b64encode(sha256(description_for_hash.encode()).digest()).decode()
    async with httpx.AsyncClient(verify=config.verify) as client:
        res = await client.post(f"{url}/v1/invoices", headers={"Grpc-Metadata-macaroon": macaroon}, json=body)
        await _raise_for_status(res)
        payment_request = res.json().get("payment_request")
    if not payment_request:
        raise ValueError("lnd did not return a payment_request.")
    return payment_request, preimage


async def _pay_invoice_lnd(
    invoice: str, url: str, macaroon: str, config: LightningBackendConfig, fee_limit_msat: int
) -> PaymentResult:
    # the non-streaming SendPaymentSync RPC is deprecated in favour of the
    # router's SendPaymentV2, which streams a Payment update per attempt
    # over chunked HTTP until a terminal SUCCEEDED/FAILED status
    async with httpx.AsyncClient(verify=config.verify, timeout=60.0) as client:
        async with client.stream(
            "POST",
            f"{url}/v2/router/send",
            headers={"Grpc-Metadata-macaroon": macaroon},
            json={
                "payment_request": invoice,
                "timeout_seconds": 60,
                "fee_limit_msat": str(fee_limit_msat),
            },
        ) as res:
            await _raise_for_status(res)
            payment = None
            async for line in res.aiter_lines():
                if not line.strip():
                    continue
                event = json.loads(line)
                payment = event.get("result", event)
                if payment.get("status") in ("SUCCEEDED", "FAILED"):
                    break

    if not payment:
        # the stream ended without ever reaching a terminal SUCCEEDED/FAILED
        # event (dropped connection, ...) - genuinely ambiguous, not lnd
        # giving us a definitive answer
        raise ValueError("lnd did not report a terminal payment status.")
    if payment.get("status") != "SUCCEEDED":
        # a terminal FAILED event IS lnd's definitive answer - no htlc is
        # left in flight once it reports this
        raise PaymentFailed(_lnd_failure_reason(payment.get("failure_reason", "FAILURE_REASON_ERROR")))

    preimage_hex = payment.get("payment_preimage")
    if not preimage_hex:
        raise ValueError("lnd did not return a payment_preimage.")
    preimage = _decode_hex_or_base64(preimage_hex)
    _verify_preimage(preimage, invoice)
    fee_msat = payment.get("fee_msat")
    return PaymentResult(preimage, int(fee_msat) if fee_msat is not None else None)


_LND_FAILURE_REASONS = {
    "FAILURE_REASON_NO_ROUTE": "Could not find a route to pay this invoice.",
    "FAILURE_REASON_INCORRECT_PAYMENT_DETAILS": "The invoice's payment details were rejected.",
    "FAILURE_REASON_INSUFFICIENT_BALANCE": "Insufficient balance to pay this invoice.",
    "FAILURE_REASON_TIMEOUT": "Timed out trying to find a route to pay this invoice.",
}


def _lnd_failure_reason(reason: str) -> str:
    return _LND_FAILURE_REASONS.get(reason, f"Payment failed: {reason}.")


async def _is_payment_complete_lnd(payment_hash: str, url: str, macaroon: str, config: LightningBackendConfig) -> bool:
    """lnd's REST TrackPaymentV2 - streams updates for a payment by hash,
    including ones already resolved before this call (lnd retains payment
    records permanently). Unlike r_hash_str elsewhere in this file, this
    path parameter is base64 (grpc-gateway's convention for a raw `bytes`
    field), not hex - a hex string of the same length is silently
    mis-decoded instead of rejected outright. A payment lnd never
    attempted at all is a 404, not a stream - genuinely safe to report as
    incomplete, since no HTLC was ever sent for it.

    IN_FLIGHT (or any other non-terminal status) raises rather than
    returning False: lnd's own timeout_seconds can make a payment attempt
    give up and move on while an HTLC it already sent remains genuinely
    locked at the final hop - e.g. a malicious payee holding a hodl
    invoice open rather than settling or failing it - so anything short of
    a real terminal SUCCEEDED/FAILED must not be reported as "confirmed
    not paid"."""
    hash_b64 = quote(b64encode(bytes.fromhex(payment_hash)).decode(), safe="")
    async with httpx.AsyncClient(verify=config.verify, timeout=10.0) as client:
        async with client.stream(
            "GET",
            f"{url}/v2/router/track/{hash_b64}",
            headers={"Grpc-Metadata-macaroon": macaroon},
            params={"no_inflight_updates": "true"},
        ) as res:
            if res.status_code == 404:
                return False
            await _raise_for_status(res)
            async for line in res.aiter_lines():
                if not line.strip():
                    continue
                event = json.loads(line)
                payment = event.get("result", event)
                status = payment.get("status")
                if status == "SUCCEEDED":
                    return True
                if status == "FAILED":
                    return False
                raise ValueError(f"lnd reports payment status {status!r} - not a terminal outcome.")
    raise ValueError("lnd did not report a payment status.")


_ZBASE32_ALPHABET = "ybndrfg8ejkmcpqxot1uwisza345h769"


def _zbase32_decode(encoded: str) -> bytes:
    bits = "".join(f"{_ZBASE32_ALPHABET.index(c):05b}" for c in encoded.strip())
    whole_bytes = len(bits) // 8
    return bytes(int(bits[i : i + 8], 2) for i in range(0, whole_bytes * 8, 8))


async def _sign_message_lnd(message: str, url: str, macaroon: str, config: LightningBackendConfig) -> tuple[bytes, int]:
    """lnd's REST SignMessage - takes base64, returns a zbase32-encoded 65
    byte compact signature (1 header byte + r + s). lnd always treats its
    identity key as compressed, so header = 27 + recovery_id + 4."""
    async with httpx.AsyncClient(verify=config.verify) as client:
        res = await client.post(
            f"{url}/v1/signmessage",
            headers={"Grpc-Metadata-macaroon": macaroon},
            json={"msg": b64encode(message.encode()).decode()},
        )
        await _raise_for_status(res)
        signature_zbase32 = res.json().get("signature")
    if not signature_zbase32:
        raise ValueError("lnd did not return a signature.")
    raw = _zbase32_decode(signature_zbase32)
    if len(raw) != 65:
        raise ValueError(f"Unexpected lnd signature length: {len(raw)} bytes.")
    header, r, s = raw[0], raw[1:33], raw[33:65]
    return r + s, (header - 27) & 3


# --- cln -------------------------------------------------------------------
# clnrest REST plugin: https://docs.corelightning.org/docs/rest


async def _create_invoice_cln(
    amount_msat: int,
    url: str,
    rune: str,
    config: LightningBackendConfig,
    memo: str,
    description_for_hash: str | None = None,
) -> tuple[str, bytes]:
    # cln's `invoice` accepts a caller-supplied preimage too - same reasoning
    # as lnd above, generate it ourselves so we always know it for certain
    preimage = urandom(32)
    body: dict[str, Any] = {
        "amount_msat": amount_msat,
        "label": urandom(16).hex(),
        "description": memo if description_for_hash is None else description_for_hash,
        "preimage": preimage.hex(),
    }
    if description_for_hash is not None:
        # cln hashes the description it is given and puts only the hash on the invoice
        body["deschashonly"] = True
    async with httpx.AsyncClient(verify=config.verify) as client:
        res = await client.post(f"{url}/v1/invoice", headers={"Rune": rune}, json=body)
        await _raise_for_status(res)
        bolt11_str = res.json().get("bolt11")
    if not bolt11_str:
        raise ValueError("cln did not return a bolt11 invoice.")
    return bolt11_str, preimage


async def _pay_invoice_cln(
    invoice: str, url: str, rune: str, config: LightningBackendConfig, fee_limit_msat: int
) -> PaymentResult:
    # xpay (CLN's newer payment engine, superseding the legacy `pay`)
    # resolves once it stops retrying - but "stops retrying" only means it
    # gives up trying new routes for parts that haven't landed anywhere
    # yet, not that every HTLC it already sent is gone: one already
    # forwarded to a malicious final hop holding a hodl invoice can stay
    # genuinely locked well past xpay's own retry_for, with xpay reporting
    # this response as a failure regardless. A non-2xx here is therefore
    # PaymentFailed's clean-reason case, never treated as proof no HTLC
    # remains outstanding - see _is_payment_complete_cln, which the caller
    # always confirms against before restoring a note. timeout is kept
    # comfortably above xpay's own default 60s retry_for so our client
    # doesn't time out right as xpay is about to answer, which would
    # otherwise turn a clean failure response into an ambiguous one.
    #
    # maxfee (msat): without it, xpay falls back to its own default
    # (max(5000msat, 1%) per its docs) - explicit here so both backends
    # spend from the same fee budget the caller computed (see
    # router._melt_fee_limit_msat), not each backend's own unrelated
    # built-in guess.
    async with httpx.AsyncClient(verify=config.verify, timeout=90.0) as client:
        res = await client.post(
            f"{url}/v1/xpay", headers={"Rune": rune}, json={"invstring": invoice, "maxfee": fee_limit_msat}
        )
        try:
            await _raise_for_status(res)
        except httpx.HTTPStatusError as exc:
            raise PaymentFailed(_cln_pay_failure_reason(res)) from exc
        payment = res.json()

    preimage_hex = payment.get("payment_preimage")
    if not preimage_hex:
        raise ValueError("cln did not return a payment_preimage.")
    preimage = _decode_hex_or_base64(preimage_hex)
    _verify_preimage(preimage, invoice)
    # xpay reports amount_msat (what the destination received) and
    # amount_sent_msat (what actually left this node) separately - the gap
    # between them is the routing fee, the same convention cln's pay and
    # listpays both use
    amount_msat, amount_sent_msat = payment.get("amount_msat"), payment.get("amount_sent_msat")
    fee_msat = (
        int(amount_sent_msat) - int(amount_msat) if amount_msat is not None and amount_sent_msat is not None else None
    )
    return PaymentResult(preimage, fee_msat)


# xpay's documented failure codes - https://docs.corelightning.org/reference/xpay
_CLN_PAY_FAILURE_REASONS = {
    203: "The invoice's destination permanently rejected this payment.",
    205: "Could not find a route to pay this invoice.",
    207: "This invoice has expired.",
    219: "This invoice has already been paid.",
}


def _cln_pay_failure_reason(res: httpx.Response) -> str:
    try:
        body = res.json()
    except ValueError:
        return f"Payment failed ({res.status_code})."
    code, message = body.get("code"), body.get("message")
    return _CLN_PAY_FAILURE_REASONS.get(code, message or f"Payment failed ({res.status_code}).")


async def _is_payment_complete_cln(payment_hash: str, url: str, rune: str, config: LightningBackendConfig) -> bool:
    """Core Lightning's clnrest plugin listpays, filtered by payment_hash -
    an unattempted or unknown one just comes back as an empty list, not an
    error, genuinely safe to report as incomplete since no HTLC was ever
    sent for it.

    A "pending" entry raises rather than returning False: xpay giving up
    on retrying (see PaymentFailed) does not guarantee no HTLC is left
    outstanding - a malicious payee holding a hodl invoice open rather
    than settling or failing it can keep an already-sent HTLC live well
    past xpay's own retry_for, so "pending" must not be reported as
    "confirmed not paid"."""
    async with httpx.AsyncClient(verify=config.verify) as client:
        res = await client.post(f"{url}/v1/listpays", headers={"Rune": rune}, json={"payment_hash": payment_hash})
        await _raise_for_status(res)
        pays = res.json().get("pays") or []
    if any(pay.get("status") == "pending" for pay in pays):
        raise ValueError("cln reports the payment still pending - not a terminal outcome.")
    return any(pay.get("status") == "complete" for pay in pays)


async def _sign_message_cln(message: str, url: str, rune: str, config: LightningBackendConfig) -> tuple[bytes, int]:
    """Core Lightning's clnrest plugin signmessage - already returns r||s
    and the recovery id separately (as hex), no zbase32 decoding needed;
    its `zbase` field is the same lnd-compatible encoding, unused here."""
    async with httpx.AsyncClient(verify=config.verify) as client:
        res = await client.post(f"{url}/v1/signmessage", headers={"Rune": rune}, json={"message": message})
        await _raise_for_status(res)
        result = res.json()
    signature_hex, recovery_id_hex = result.get("signature"), result.get("recid")
    if not signature_hex or recovery_id_hex is None:
        raise ValueError("cln did not return a signature.")
    return bytes.fromhex(signature_hex), int(recovery_id_hex, 16)


async def _is_invoice_settled_lnd(payment_hash: str, url: str, macaroon: str, config: LightningBackendConfig) -> bool:
    """lnd's REST LookupInvoice - r_hash_str takes the hex-encoded payment
    hash directly in the path."""
    async with httpx.AsyncClient(verify=config.verify) as client:
        res = await client.get(f"{url}/v1/invoice/{payment_hash}", headers={"Grpc-Metadata-macaroon": macaroon})
        await _raise_for_status(res)
        return bool(res.json().get("settled"))


async def _is_invoice_settled_cln(payment_hash: str, url: str, rune: str, config: LightningBackendConfig) -> bool:
    """Core Lightning's clnrest plugin listinvoices, filtered by payment_hash."""
    async with httpx.AsyncClient(verify=config.verify) as client:
        res = await client.post(f"{url}/v1/listinvoices", headers={"Rune": rune}, json={"payment_hash": payment_hash})
        await _raise_for_status(res)
        invoices = res.json().get("invoices") or []
    return bool(invoices) and invoices[0].get("status") == "paid"


async def _invoice_preimage_lnd(
    payment_hash: str, url: str, macaroon: str, config: LightningBackendConfig
) -> bytes | None:
    """lnd's REST LookupInvoice always echoes back r_preimage (base64) -
    this mint supplied it itself at creation (see _create_invoice_lnd) - so
    it's only withheld here, not by lnd, until `settled` is true."""
    async with httpx.AsyncClient(verify=config.verify) as client:
        res = await client.get(f"{url}/v1/invoice/{payment_hash}", headers={"Grpc-Metadata-macaroon": macaroon})
        await _raise_for_status(res)
        data = res.json()
    if not data.get("settled"):
        return None
    preimage_b64 = data.get("r_preimage")
    return _decode_hex_or_base64(preimage_b64) if preimage_b64 else None


async def _invoice_preimage_cln(payment_hash: str, url: str, rune: str, config: LightningBackendConfig) -> bytes | None:
    """Core Lightning's clnrest plugin listinvoices - `payment_preimage` is
    only populated once `status` is "paid"."""
    async with httpx.AsyncClient(verify=config.verify) as client:
        res = await client.post(f"{url}/v1/listinvoices", headers={"Rune": rune}, json={"payment_hash": payment_hash})
        await _raise_for_status(res)
        invoices = res.json().get("invoices") or []
    if not invoices or invoices[0].get("status") != "paid":
        return None
    preimage_hex = invoices[0].get("payment_preimage")
    return bytes.fromhex(preimage_hex) if preimage_hex else None


async def _payment_preimage_lnd(
    payment_hash: str, url: str, macaroon: str, config: LightningBackendConfig
) -> bytes | None:
    """lnd's REST TrackPaymentV2, the same stream _is_payment_complete_lnd
    reads - a terminal SUCCEEDED event's own payment_preimage is exactly
    this outgoing payment's settlement secret. A payment lnd never
    attempted (404), or one that never reached SUCCEEDED, has none to
    report."""
    hash_b64 = quote(b64encode(bytes.fromhex(payment_hash)).decode(), safe="")
    async with httpx.AsyncClient(verify=config.verify, timeout=10.0) as client:
        async with client.stream(
            "GET",
            f"{url}/v2/router/track/{hash_b64}",
            headers={"Grpc-Metadata-macaroon": macaroon},
            params={"no_inflight_updates": "true"},
        ) as res:
            if res.status_code == 404:
                return None
            await _raise_for_status(res)
            async for line in res.aiter_lines():
                if not line.strip():
                    continue
                event = json.loads(line)
                payment = event.get("result", event)
                status = payment.get("status")
                if status == "SUCCEEDED":
                    preimage_hex = payment.get("payment_preimage")
                    return _decode_hex_or_base64(preimage_hex) if preimage_hex else None
                if status == "FAILED":
                    return None
    return None


async def _payment_preimage_cln(payment_hash: str, url: str, rune: str, config: LightningBackendConfig) -> bytes | None:
    """Core Lightning's clnrest plugin listpays - a complete pay's own
    `preimage` is this outgoing payment's settlement secret."""
    async with httpx.AsyncClient(verify=config.verify) as client:
        res = await client.post(f"{url}/v1/listpays", headers={"Rune": rune}, json={"payment_hash": payment_hash})
        await _raise_for_status(res)
        pays = res.json().get("pays") or []
    for pay in pays:
        if pay.get("status") == "complete":
            preimage_hex = pay.get("preimage")
            return bytes.fromhex(preimage_hex) if preimage_hex else None
    return None


class NodeInfo(BaseModel):
    """This mint's own funding-source node identity, shown on the one-pager
    frontend (GET /) and advertised on the mint-address discovery endpoint
    (see router.get_mint_address)."""

    alias: str | None = None
    uri: str | None = None  # node_key@host:port, or the bare pubkey if unannounced
    # every announced address, each already "node_key@host:port" - a node
    # can advertise more than one (e.g. a clearnet address plus a Tor v3
    # onion), and `uri` alone only ever surfaced the first, silently
    # dropping the rest. `uri` is kept (== uris[0] when non-empty) since
    # several callers key off a single connect string to derive the bare
    # pubkey (signing.mint_pubkey, server.py's startup log, the mint-address
    # discovery endpoint) or to render one primary row on the frontend.
    uris: list[str] = []
    color: str | None = None  # "#rrggbb", the node's self-reported display color
    num_channels: int = 0
    num_peers: int = 0
    # msat, same denomination as every other amount in this codebase (not
    # named capacity_msat - unlike those, there's no sibling sat-denominated
    # field it needs to disambiguate itself from): sum of this node's
    # *publicly announced* channels' capacity only, sourced from each
    # backend's public graph/gossip view - see _fetch_node_info_lnd/
    # _fetch_node_info_cln for why, never from a private/authenticated view
    # of this node's own channels (which would also count unannounced ones
    # this node's public presence gives no one else visibility into)
    capacity: int = 0


_HEX_COLOR_RE = re.compile(r"#[0-9a-fA-F]{6}")


def _normalize_color(color: str | None) -> str | None:
    """lnd's getinfo already prefixes its `color` with '#'; cln's doesn't -
    normalized to a single "#rrggbb" form so every consumer (the frontend's
    CSS, the mint-address discovery response) can use it directly without
    caring which backend it came from. Also validated here, once, at the
    source: NodeInfo.color is either a well-formed "#rrggbb" or None,
    never anything a consumer would have to sanity-check itself before
    trusting - frontend.py in particular substitutes this straight into a
    style attribute unescaped, so a malformed value (or one containing
    stray characters) must never get this far in the first place."""
    if not color:
        return None
    normalized = f"#{color.lstrip('#')}"
    return normalized if _HEX_COLOR_RE.fullmatch(normalized) else None


async def fetch_node_info(config: LightningBackendConfig) -> NodeInfo:
    """A single getinfo against the funding source - both lnd and cln report
    identity, alias, and channel/peer counts in one call."""
    return await _dispatch("fetch_node_info", config, _fetch_node_info_lnd, _fetch_node_info_cln)


# in-process cache for cached_fetch_node_info below - (fetched_at, info),
# module-level so it's shared across every request/caller within this
# process, not per-request or per-caller
_node_info_cache: tuple[float, NodeInfo] | None = None
_NODE_INFO_CACHE_TTL_SECONDS = 3600


async def cached_fetch_node_info(config: LightningBackendConfig) -> NodeInfo:
    """fetch_node_info, cached in-process for up to an hour - the frontend
    one-pager and the mint-address discovery endpoint (router.py) both call
    this on every single request they serve, but a node's identity/color/
    channel counts/capacity change slowly enough that a live RPC round trip
    per page view or per lnurlw lookup is wasted load on the funding source
    for data that's effectively static minute to minute. Only these two
    display surfaces go through the cache: the startup connectivity check
    and the background health monitor (server.py) need a live, uncached
    probe to actually detect an outage or recovery, and LUD-25's
    mint_pubkey/sign_note (signing.py) call fetch_node_info directly too -
    none of those would be served correctly by up-to-an-hour-stale data.

    Never caches a failure: if the underlying fetch raises, this raises too
    and nothing is cached for next time - a momentary funding-source hiccup
    should be retried (and can recover) on the very next request, not stay
    "unreachable" for a full hour just because it was asked at a bad
    moment."""
    global _node_info_cache
    now = time.monotonic()
    if _node_info_cache is not None:
        fetched_at, info = _node_info_cache
        if now - fetched_at < _NODE_INFO_CACHE_TTL_SECONDS:
            return info
    info = await fetch_node_info(config)
    _node_info_cache = (now, info)
    return info


async def _fetch_node_info_lnd(url: str, macaroon: str, config: LightningBackendConfig) -> NodeInfo:
    """lnd's REST GetInfo - `uris` are already fully-formed "pubkey@host:port"
    strings, empty when the node has no announced address configured.
    Capacity isn't part of GetInfo itself, so it's a second call, but
    deliberately GetNodeInfo (self-lookup by pubkey) rather than
    ListChannels: GetNodeInfo answers from lnd's public graph cache, the
    same total_capacity number any stranger on the network could already
    derive from this node's own announced channel_announcements - unlike
    ListChannels, it can't be used to enumerate this node's private/
    unannounced channels or their individual balances, so it costs no
    privacy this node's public presence doesn't already give away. Best
    effort: a failure there (e.g. an unannounced node with nothing in the
    graph yet, or a macaroon not scoped for it - see README) is logged but
    swallowed rather than failing the whole getinfo, since capacity is
    purely informational - leaves capacity at 0 rather than raising, but
    the warning at least makes a silent 0 diagnosable instead of
    indistinguishable from "this node genuinely has none"."""
    headers = {"Grpc-Metadata-macaroon": macaroon}
    async with httpx.AsyncClient(verify=config.verify) as client:
        res = await client.get(f"{url}/v1/getinfo", headers=headers)
        await _raise_for_status(res)
        info = res.json()
        capacity = 0
        pubkey = info.get("identity_pubkey")
        if pubkey:
            try:
                node_res = await client.get(f"{url}/v1/graph/node/{pubkey}", headers=headers)
                await _raise_for_status(node_res)
                # lnd reports total_capacity in sats, not msat - converted
                # here so NodeInfo.capacity stays msat-denominated
                capacity = int(node_res.json().get("total_capacity", 0)) * 1000
            except Exception as exc:
                logging.warning("fetch_node_info: could not fetch capacity from lnd's graph: %s", exc)
    uris = info.get("uris") or []
    return NodeInfo(
        alias=info.get("alias") or None,
        uri=uris[0] if uris else info.get("identity_pubkey"),
        uris=uris,
        color=_normalize_color(info.get("color")),
        num_channels=int(info.get("num_active_channels", 0)) + int(info.get("num_inactive_channels", 0)),
        num_peers=int(info.get("num_peers", 0)),
        capacity=capacity,
    )


async def _fetch_node_info_cln(url: str, rune: str, config: LightningBackendConfig) -> NodeInfo:
    """Core Lightning's clnrest plugin GetInfo. Capacity isn't part of
    getinfo either, so it's a second call, but deliberately listchannels
    filtered to `source=<our own id>` rather than listfunds: listchannels
    answers from cln's public gossip store, the same channel_announcements
    any peer on the network already sees, unlike listfunds - which is this
    node's own private view of its channels, including unannounced ones
    and their exact local/remote balance split. A public channel gets one
    listchannels entry per direction (two channel_update messages sharing
    one capacity), so entries are deduplicated by short_channel_id before
    summing - counting both would double the real total. Best effort: a
    failure here (e.g. a node with nothing announced yet, or a rune not
    scoped for `listchannels` - see README, a common gap for a rune baked
    before this method was added to the required set) is logged but
    swallowed rather than failing the whole getinfo, since capacity is
    purely informational - leaves capacity at 0 rather than raising, but
    the warning at least makes a silent 0 diagnosable instead of
    indistinguishable from "this node genuinely has none"."""
    headers = {"Rune": rune}
    async with httpx.AsyncClient(verify=config.verify) as client:
        res = await client.post(f"{url}/v1/getinfo", headers=headers)
        await _raise_for_status(res)
        info = res.json()
        capacity_msat = 0
        node_id = info.get("id")
        if node_id:
            try:
                channels_res = await client.post(f"{url}/v1/listchannels", headers=headers, json={"source": node_id})
                await _raise_for_status(channels_res)
                channels = channels_res.json().get("channels") or []
                seen_scids: set[str] = set()
                for c in channels:
                    scid = c.get("short_channel_id")
                    if scid is None or scid in seen_scids:
                        continue
                    seen_scids.add(scid)
                    capacity_msat += int(c.get("amount_msat", 0))
            except Exception as exc:
                logging.warning("fetch_node_info: could not fetch capacity from cln's listchannels: %s", exc)
    addresses = info.get("address") or []
    # a node can have more than one address bound - e.g. a clearnet address
    # plus a Tor v3 onion added for privacy - and every one of them is a
    # valid way in, not just the first
    uris = (
        [
            f"{node_id}@{addr['address']}:{addr['port']}"
            for addr in addresses
            if addr.get("address") and addr.get("port")
        ]
        if node_id
        else []
    )
    uri = uris[0] if uris else node_id
    return NodeInfo(
        alias=info.get("alias") or None,
        uri=uri,
        uris=uris,
        color=_normalize_color(info.get("color")),
        num_channels=int(info.get("num_active_channels", 0)) + int(info.get("num_inactive_channels", 0)),
        num_peers=int(info.get("num_peers", 0)),
        capacity=capacity_msat,
    )


def _decode_hex_or_base64(value: str) -> bytes:
    try:
        return bytes.fromhex(value)
    except ValueError:
        return b64decode(value)


def _verify_preimage(preimage: bytes, invoice: str) -> None:
    decoded = bolt11.decode(invoice)
    if decoded.has_payment_hash and sha256(preimage).hexdigest() != decoded.payment_hash:
        raise ValueError("Returned preimage does not match the invoice's payment hash.")
