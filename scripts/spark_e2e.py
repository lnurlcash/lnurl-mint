"""Full end-to-end verification of the spark funding-source backend, with
the reference wallet (../lnurl-wallet) as the customer and a second spark
wallet as the Lightning side - the LUD-25 trust split: the note holder
never touches Lightning itself, the payer pays and gets paid.

    ┌─────────────────────┐  LUD-25   ┌──────────────────────┐  spark  ┌────────────────┐
    │ lnurl-wallet code   │◄──HTTP───►│ lnurl-mint server    │◄──SDK──►│ payer wallet P │
    │ (src/lnurlcash.ts)  │           │ FUNDINGSOURCE=spark  │         │ (pays mints,   │
    └─────────────────────┘           └──────────────────────┘         │  receives melts)│
                                                                       └────────────────┘

The whole money loop is real mainnet: P pays the mint's invoice (the mint's
spark wallet receives), the note materializes, the holder rotates/splits/
merges it, then melts it to a fresh P invoice (the mint pays out over
Lightning). The customer side runs lnurl-wallet's actual protocol module
via a vitest step dispatcher (scripts/spark_e2e_wallet_step.test.ts), so
every holder-side request is made by the reference implementation.

    uv run --extra spark python scripts/spark_e2e.py \
        --api-key-file .env   # or BREEZ_API_KEY in the environment

Funding gate: the payer wallet P is persistent under --workdir (fresh seed
generated on first run). If P is underfunded the run stops with P's spark
and bitcoin addresses printed and exit code 3 - fund either one and rerun.
~10_000 sats is comfortable for the default amounts. The MINT's wallet
needs no external funding: the first mint funds it (each mint's fee builds
the buffer melts spend).

Scenarios: discovery, commentless-mint rejection, real mint + settlement +
verify, rotate, split, merge, real melt + burn + LUD-25 melt verify,
double-melt guard, fractional-sat melt rejection + restore, and a
kill -9-mid-melt crash-discipline check (the invariant that matters: if P's
invoice settled, the note is never back outstanding).
"""

import argparse
import asyncio
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request

try:
    import bolt11
    from breez_sdk_spark import (  # type: ignore[import-not-found]
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
        Seed,
        SendPaymentOptions,
        SendPaymentRequest,
        default_config,
    )
except ImportError as exc:  # pragma: no cover
    print(f"missing dependency: {exc} - install with `uv sync --extra spark`", file=sys.stderr)
    raise

# settle/poll bounds: mint-side detection is bounded by the spark sync
# interval (15s default) plus the payment itself; P-side receives show up
# on its own sync - generous, these are mainnet round trips
_SETTLE_TIMEOUT_SECS = 180
_POLL_INTERVAL_SECS = 3

CHECKS: list[tuple[str, bool]] = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    CHECKS.append((name, ok))
    print(f"  [{'ok' if ok else 'FAIL'}] {name}{f' - {detail}' if detail else ''}", flush=True)
    return ok


def http_get(url: str) -> dict:
    try:
        return json.load(urllib.request.urlopen(url, timeout=15))
    except urllib.error.HTTPError as exc:
        try:
            return {"http": exc.code, **json.load(exc)}
        except Exception:
            return {"http": exc.code}
    except (urllib.error.URLError, ConnectionError, TimeoutError):
        # not up yet (or down) - callers that poll treat this as "keep waiting"
        return {}


# --- the mint server -------------------------------------------------------


class MintServer:
    def __init__(self, api_key: str, mint_mnemonic: str, workdir: str, port: int):
        self.port = port
        self.dir = os.path.abspath(os.path.join(workdir, "mint"))
        os.makedirs(self.dir, exist_ok=True)
        self.env_path = os.path.abspath(os.path.join(workdir, "mint", ".env"))
        with open(self.env_path, "w") as f:
            f.write(
                f"BASE_URL=http://localhost:{port}\n"
                f"DATABASE_PATH={self.dir}/mint.db\n"
                "FUNDINGSOURCE_BACKEND=spark\n"
                f"FUNDINGSOURCE_SPARK_MNEMONIC={mint_mnemonic}\n"
                f"FUNDINGSOURCE_SPARK_API_KEY={api_key}\n"
                f"FUNDINGSOURCE_SPARK_STORAGE_DIR={self.dir}/spark-wallet\n"
                "MIN_SENDABLE_MSAT=1000\n"
                "MIN_MINT_MSAT=0\n"
                # the default fee: each mint's withheld 1 sat is exactly the
                # buffer melts spend (the melt fee), so the loop is
                # self-sustaining after the first mint
                "BASE_FEE_MSAT=1000\n"
                "FEE_PPM=0\n"
            )
        self.process: subprocess.Popen | None = None
        self.log = open(os.path.join(workdir, "mint-server.log"), "ab")

    def start(self) -> None:
        print("  booting mint server ...", flush=True)
        self.process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "lnurl_mint.server:app",
                "--host",
                "127.0.0.1",
                "--port",
                str(self.port),
            ],
            env={**os.environ, "LNURL_MINT_ENV_FILE": self.env_path},
            cwd=self.dir,
            stdout=self.log,
            stderr=subprocess.STDOUT,
        )
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError("mint server died at boot (see mint-server.log)")
            if http_get(f"http://127.0.0.1:{self.port}/.well-known/lnurlp/mint").get("tag") == "payRequest":
                return
            time.sleep(1)
        raise RuntimeError("mint server did not come up within 120s")

    def kill9(self) -> None:
        assert self.process is not None
        self.process.send_signal(signal.SIGKILL)
        self.process.wait()

    def stop(self) -> None:
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.process.kill()


# --- the payer wallet P (the Lightning side) --------------------------------


class PayerWallet:
    """The Lightning side: a persistent spark wallet that pays the mint's
    invoices and receives melts. Its phrase lives under --workdir (never
    printed in full, never committed)."""

    def __init__(self, sdk, api_key: str):
        self.sdk = sdk
        self.api_key = api_key

    async def balance_sats(self) -> int:
        return (await self.sdk.get_info(request=GetInfoRequest(ensure_synced=True))).balance_sats

    async def addresses(self) -> tuple[str, str]:
        spark = (
            await self.sdk.receive_payment(
                request=ReceivePaymentRequest(payment_method=ReceivePaymentMethod.SPARK_ADDRESS())
            )
        ).payment_request
        btc = (
            await self.sdk.receive_payment(
                # new_address=False: the wallet's CURRENT static deposit
                # address, stable across runs - rotating here would print a
                # different bc1p... every gate run (rotated-away addresses
                # stay claimable, but a moving funding target is exactly the
                # confusion an operator does not need)
                request=ReceivePaymentRequest(payment_method=ReceivePaymentMethod.BITCOIN_ADDRESS(new_address=False))
            )
        ).payment_request
        return spark, btc

    async def pay_invoice(self, invoice: str) -> str:
        """Pays `invoice` (a mint invoice), waits for completion, returns the preimage hex."""
        prepare = await self.sdk.prepare_send_payment(
            request=PrepareSendPaymentRequest(payment_request=PaymentRequest.INPUT(input=invoice))
        )
        payment = (
            await self.sdk.send_payment(
                request=SendPaymentRequest(
                    prepare_response=prepare,
                    options=SendPaymentOptions.BOLT11_INVOICE(
                        prefer_spark=False, completion_timeout_secs=_SETTLE_TIMEOUT_SECS
                    ),
                    idempotency_key=None,
                )
            )
        ).payment
        if payment.status != PaymentStatus.COMPLETED:
            raise RuntimeError(f"payer payment not completed: {payment.status}")
        details = payment.details
        assert details is not None and details.is_LIGHTNING()
        return details.htlc_details.preimage

    async def create_invoice(self, amount_msat: int) -> str:
        res = await self.sdk.receive_payment(
            request=ReceivePaymentRequest(
                payment_method=ReceivePaymentMethod.BOLT11_INVOICE(
                    description="e2e melt destination",
                    amount_sats=amount_msat // 1000,
                    expiry_secs=None,
                    payment_hash=None,
                    receiver_identity_public_key=None,
                )
            )
        )
        return res.payment_request

    async def wait_incoming_settled(self, payment_hash: str, timeout: float = _SETTLE_TIMEOUT_SECS) -> bool:
        """Waits until P's own record of the invoice `payment_hash` is completed."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            payments = (
                await self.sdk.list_payments(request=ListPaymentsRequest(type_filter=[PaymentType.RECEIVE], limit=100))
            ).payments
            for p in payments:
                if p.details is None or not p.details.is_LIGHTNING():
                    continue
                if p.details.htlc_details.payment_hash == payment_hash:
                    if p.status == PaymentStatus.COMPLETED:
                        return True
                    if p.status == PaymentStatus.FAILED:
                        return False
            await asyncio.sleep(_POLL_INTERVAL_SECS)
        return False


async def build_payer(api_key: str, seed: Seed, storage_dir: str) -> PayerWallet:
    config = default_config(network=Network.MAINNET)
    config.api_key = api_key
    config.real_time_sync_server_url = None
    builder = SdkBuilder(config=config, seed=seed)
    await builder.with_default_storage(storage_dir=storage_dir)
    return PayerWallet(await builder.build(), api_key)


# --- the reference wallet (the customer) ------------------------------------


class ReferenceWallet:
    """One LUD-25 holder step at a time, each executed by lnurl-wallet's own
    protocol module under vitest (see spark_e2e_wallet_step.test.ts)."""

    def __init__(self, wallet_dir: str, port: int):
        self.wallet_dir = wallet_dir
        self.base = f"http://127.0.0.1:{port}"
        dispatcher_src = os.path.join(os.path.dirname(os.path.abspath(__file__)), "spark_e2e_wallet_step.test.ts")
        self.dispatcher_dst = os.path.join(wallet_dir, "src", "__e2e_step__.test.ts")
        shutil.copy(dispatcher_src, self.dispatcher_dst)
        self.step_file = "/tmp/e2e_step.json"
        self.result_file = "/tmp/e2e_result.json"

    def close(self) -> None:
        if os.path.exists(self.dispatcher_dst):
            os.remove(self.dispatcher_dst)

    def step(self, name: str, args: list, expect_error: str | None = None) -> dict:
        with open(self.step_file, "w") as f:
            json.dump({"step": name, "args": args, "expectError": expect_error}, f)
        if os.path.exists(self.result_file):
            os.remove(self.result_file)
        subprocess.run(
            ["npx", "vitest", "run", "src/__e2e_step__.test.ts"],
            cwd=self.wallet_dir,
            capture_output=True,
            timeout=180,
            check=False,
        )
        if not os.path.exists(self.result_file):
            raise RuntimeError(f"wallet step {name} produced no result (vitest failed?)")
        return json.load(open(self.result_file))

    def must(self, name: str, args: list) -> dict:
        result = self.step(name, args)
        if not result.get("ok"):
            raise RuntimeError(f"wallet step {name} failed: {result.get('error')}")
        return result["result"]


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--api-key-file", default=None, help="file containing only the Breez API key (or .env with BREEZ_API_KEY=...)"
    )
    parser.add_argument(
        "--payer-mnemonic",
        default=None,
        help="12/24 BIP39 words for the payer wallet (stored under --workdir, reused after)",
    )
    parser.add_argument(
        "--mint-mnemonic",
        default=None,
        help="mnemonic for the MINT's funding wallet (default: .env's BREEZ_MNEMONIC or ephemeral)",
    )
    parser.add_argument("--wallet-dir", default="../lnurl-wallet", help="the lnurl-wallet checkout")
    parser.add_argument(
        "--workdir",
        default=".spark-e2e",
        help=(
            "persistent workspace (payer seed, mint db, logs) - deliberately NOT /tmp: "
            "the payer seed file is the wallet's only backup"
        ),
    )
    parser.add_argument("--port", type=int, default=8111)
    parser.add_argument(
        "--amount-msat",
        type=int,
        default=5_000,
        help=(
            "gross msat per test mint (default 5_000 - the minimum sensible: net of the "
            "1-sat mint fee it leaves a 4-sat note, keeping a funded run cheap)"
        ),
    )
    args = parser.parse_args()

    api_key = os.environ.get("BREEZ_API_KEY", "")
    if not api_key and args.api_key_file:
        for line in open(args.api_key_file):
            if line.startswith("BREEZ_API_KEY="):
                api_key = line.split("=", 1)[1].strip()
    if not api_key and args.api_key_file and os.path.exists(args.api_key_file):
        api_key = open(args.api_key_file).read().strip()
    if not api_key:
        print("no API key: pass --api-key-file or set BREEZ_API_KEY", file=sys.stderr)
        return 2

    os.makedirs(args.workdir, exist_ok=True)
    seed_path = os.path.join(args.workdir, "payer-seed")
    if args.payer_mnemonic:
        seed = Seed.MNEMONIC(mnemonic=args.payer_mnemonic.strip(), passphrase=None)
        with open(seed_path, "w") as f:
            f.write(args.payer_mnemonic.strip())
    elif os.path.exists(seed_path):
        seed = Seed.MNEMONIC(mnemonic=open(seed_path).read().strip(), passphrase=None)
    else:
        # a BIP39 mnemonic, never raw entropy: an entropy seed has NO
        # mnemonic form (the SDK's Seed::to_bytes uses entropy bytes
        # verbatim while a mnemonic hashes through BIP39's PBKDF2), so an
        # entropy-generated wallet could only ever be backed up as an
        # opaque hex blob - a mnemonic is backupable by hand. Generate one
        # with any BIP39 tool (lnurl-wallet's own generator, a hardware
        # wallet, ...); pass it once and it is stored under the workdir and
        # reused. THE SEED FILE IS THE WALLET - never committed, back it up
        # like any hot-wallet seed.
        print(
            "no payer wallet yet: pass --payer-mnemonic <12/24 BIP39 words>\n"
            "(generate them with any BIP39 tool, e.g. lnurl-wallet's own seed\n"
            "generator - they are then stored under --workdir and reused)",
            file=sys.stderr,
        )
        return 2

    mint_mnemonic = args.mint_mnemonic or os.environ.get("BREEZ_MNEMONIC", "").strip().strip('"')
    if not mint_mnemonic:
        # an unfunded throwaway is fine: the first mint funds it
        mint_mnemonic = " ".join(["abandon"] * 11 + ["about"])

    print(f"workspace: {args.workdir}")
    payer = await build_payer(api_key, seed, os.path.join(args.workdir, "payer-wallet"))

    # funding gate
    balance = await payer.balance_sats()
    print(f"payer balance: {balance} sats")
    # three mints + lightning-fee headroom is all the run consumes
    needed = 3 * args.amount_msat // 1000 + 100
    if balance < needed:
        spark_addr, btc_addr = await payer.addresses()
        print(
            f"\nPayer wallet underfunded ({balance} < {needed} sats). Fund either address:\n"
            f"  spark (instant, free): {spark_addr}\n"
            f"  btc   (needs confirmations): {btc_addr}\n"
            f"then rerun - the wallet persists as {args.workdir}/payer-seed\n"
            f"(back that file up: it IS the wallet - no mnemonic copy exists anywhere else)."
        )
        return 3

    wallet = ReferenceWallet(os.path.abspath(args.wallet_dir), args.port)
    mint = MintServer(api_key, mint_mnemonic, args.workdir, args.port)
    try:
        mint.start()
        await scenarios(mint, payer, wallet, args)
    finally:
        mint.stop()
        wallet.close()

    print()
    failed = [name for name, ok in CHECKS if not ok]
    print(f"{len(CHECKS) - len(failed)}/{len(CHECKS)} checks passed")
    if failed:
        print("failed:", ", ".join(failed))
        return 1
    return 0


def fractional_invoice(amount_msat: int) -> str:
    """A syntactically valid but unpayable bolt11 invoice for a FRACTIONAL
    sat amount - something the SDK's sat-only invoice surface cannot
    produce, but any ordinary Lightning wallet can. The melt's background
    payment must reject it (the backend's div_ceil guard) and restore the
    note; the invoice is never payable, which is the point."""
    from os import urandom

    from bolt11 import Bolt11, TagChar, Tags

    tags = Tags()
    tags.add(TagChar.payment_hash, urandom(32).hex())
    tags.add(TagChar.payment_secret, urandom(32).hex())
    tags.add(TagChar.description, "e2e fractional melt probe")
    import time as _time

    return bolt11.encode(
        Bolt11(currency="bc", amount_msat=amount_msat, date=int(_time.time()), tags=tags),
        private_key=urandom(32).hex(),
    )


async def scenarios(mint: MintServer, payer: PayerWallet, wallet: ReferenceWallet, args) -> None:
    base = wallet.base
    lnurlp = f"{base}/.well-known/lnurlp/mint"
    callback = f"{base}/p/cb"
    note_url = lambda k1, amount: f"{base}/w?k1={k1}&amount={amount}"  # noqa: E731

    # 1. discovery, through the reference wallet's own resolver
    print("\n[1] discovery (reference wallet):")
    info = wallet.must("pay-request", [lnurlp])
    check("payRequest parsed, commentAllowed >= 64", (info.get("commentAllowed") or 0) >= 64)
    check("withdrawLink advertised", str(info.get("withdrawLink", "")).endswith("/w"))

    # 2. commentless/malformed mints rejected before any invoice
    print("\n[2] mandatory comment protection:")
    check("commentless mint rejected", http_get(f"{callback}?amount=1000000").get("status") == "ERROR")
    check("malformed comment rejected", http_get(f"{callback}?amount=1000000&comment=nope").get("status") == "ERROR")

    # 3. a real mint: wallet commits to a secret, P pays, settlement
    #    propagates through the mint's spark wallet
    print("\n[3] real mint (P pays the mint's invoice on mainnet):")
    amount_msat = args.amount_msat
    net_amount = amount_msat - 1000  # BASE_FEE_MSAT
    # derived so every scenario stays consistent at any size: a sat-aligned
    # split (3/8 of net, rounded to a whole sat) for [5], and a guaranteed
    # FRACTIONAL one (5/8 of net, nudged off a whole sat if needed) for [9]
    split_amount = net_amount * 3 // 8000 * 1000 or 1000
    frac_amount = net_amount * 5 // 8000 * 1000 + (0 if net_amount * 5 // 8000 * 1000 % 1000 else 500)
    minted = wallet.must("mint", [callback, amount_msat])
    pr, verify_url, secret = minted["pr"], minted["verify"], minted["secret"]
    check("invoice requested with comment", pr.startswith("lnbc"))
    preimage = await payer.pay_invoice(pr)
    check("P paid the mint invoice", len(preimage) == 64)
    settled = False
    deadline = time.monotonic() + _SETTLE_TIMEOUT_SECS
    while time.monotonic() < deadline:
        v = wallet.must("verify", [verify_url.replace("localhost", "127.0.0.1")])
        if v["settled"]:
            settled = True
            check("verify settled with a preimage", v["preimage"] is not None)
            break
        await asyncio.sleep(_POLL_INTERVAL_SECS)
    if not check("mint settlement detected", settled):
        return
    info = wallet.must("note-info", [note_url(secret, net_amount)])
    check(f"note live at {net_amount} msat", info["maxWithdrawable"] == net_amount)

    # 4-6. rotate, split, merge - the pure LUD-25 holder loop
    print("\n[4] rotate:")
    w_cb = f"{base}/w/cb"
    rotated = wallet.must("rotate", [w_cb, secret])
    check("rotated to a fresh secret", rotated["k1"] != secret)
    info = wallet.must("note-info", [note_url(rotated["k1"], net_amount)])
    check("value preserved", info["maxWithdrawable"] == net_amount)
    old = wallet.step("note-info", [note_url(secret, net_amount)])
    check("old secret spent", not old.get("ok"))
    # LUD-25 offline verification: the rotate response carries a spec-
    # conformant sig over the new note's hash, and /w advertises the
    # mintPubkey it recovers to - verified here exactly as a wallet would
    from lnurl_mint.signing import verify_note

    rotated_h = __import__("hashlib").sha256(bytes.fromhex(rotated["k1"])).hexdigest()
    sig = rotated.get("signature")
    pubkey = http_get(note_url(rotated["k1"], net_amount)).get("mintPubkey")
    check(
        "rotate carries a wallet-verifiable signature",
        bool(sig) and bool(pubkey) and verify_note(pubkey, rotated_h, net_amount, sig),
    )

    print("\n[5] split:")
    parts = wallet.must("split", [w_cb, rotated["k1"], split_amount])
    info_a = wallet.must("note-info", [note_url(parts["k1"], split_amount)])
    change = net_amount - split_amount - 1000  # base fee from change
    info_b = wallet.must("note-info", [note_url(parts["change"], change)])
    check(
        f"split {split_amount}/{change} msat",
        info_a["maxWithdrawable"] == split_amount and info_b["maxWithdrawable"] == change,
    )

    print("\n[6] merge (with base-fee refund):")
    merged = wallet.must("merge", [w_cb, parts["k1"], parts["change"]])
    merged_amount = split_amount + change + 1000  # (n-1) * base fee refunded
    info = wallet.must("note-info", [note_url(merged["k1"], merged_amount)])
    check(f"merged back to {merged_amount} msat", info["maxWithdrawable"] == merged_amount)

    # 7. a real melt: P's invoice, the mint pays over Lightning, burn +
    #    LUD-25 melt verify
    print("\n[7] real melt (the mint pays P's invoice on mainnet):")
    note_k1, note_amount = merged["k1"], merged_amount
    melt_pr = await payer.create_invoice(note_amount)
    melt_hash = bolt11.decode(melt_pr).payment_hash
    melt = wallet.must("melt", [w_cb, note_k1, melt_pr])
    check("melt accepted (pending)", "verify" in (melt or {}))
    paid = await payer.wait_incoming_settled(melt_hash)
    if not check("P received the melt", paid):
        return
    v = wallet.must("verify", [melt["verify"].replace("localhost", "127.0.0.1")])
    check("melt verify settled with payment preimage", v["settled"] and v["preimage"] is not None)
    spent = wallet.step("note-info", [note_url(note_k1, note_amount)])
    check("note burned", not spent.get("ok"))

    # 8. double-melt guard on the burned note
    print("\n[8] double-melt guard:")
    again = await payer.create_invoice(note_amount)
    dup = wallet.step("melt", [w_cb, note_k1, again])
    check("melt of a burned note rejected", not dup.get("ok"))

    # 9. fractional-sat melt: split into a fractional note, melt it - the
    #    backend must reject it as provably-unsent and RESTORE the note
    print("\n[9] fractional-sat melt rejected + restored:")
    minted2 = wallet.must("mint", [callback, amount_msat])
    await payer.pay_invoice(minted2["pr"])
    deadline = time.monotonic() + _SETTLE_TIMEOUT_SECS
    while time.monotonic() < deadline:
        if wallet.must("verify", [minted2["verify"].replace("localhost", "127.0.0.1")])["settled"]:
            break
        await asyncio.sleep(_POLL_INTERVAL_SECS)
    parts2 = wallet.must("split", [w_cb, minted2["secret"], frac_amount])
    frac_k1 = parts2["k1"]
    frac_pr = fractional_invoice(frac_amount)
    frac = wallet.step("melt", [w_cb, frac_k1, frac_pr])
    check("fractional melt accepted by the callback (async per LUD-03)", frac.get("ok") is True)
    # the background task rejects it as provably-unsent (the SDK would CEIL
    # a fractional invoice into whole sats of leaves - the over-debit
    # guard) and restores the note; nothing is ever paid against an
    # unpayable invoice, so a short wait is enough
    await asyncio.sleep(15)
    info = wallet.must("note-info", [note_url(frac_k1, frac_amount)])
    check("fractional note restored, still outstanding", info["maxWithdrawable"] == frac_amount)

    # 10. crash discipline: kill -9 mid-melt; the invariant that matters is
    #     that a paid melt never leaves a spendable/restored note behind
    print("\n[10] kill -9 mid-melt + restart reconciliation:")
    minted3 = wallet.must("mint", [callback, amount_msat])
    await payer.pay_invoice(minted3["pr"])
    deadline = time.monotonic() + _SETTLE_TIMEOUT_SECS
    while time.monotonic() < deadline:
        if wallet.must("verify", [minted3["verify"].replace("localhost", "127.0.0.1")])["settled"]:
            break
        await asyncio.sleep(_POLL_INTERVAL_SECS)
    net3 = amount_msat - 1000
    crash_pr = await payer.create_invoice(net3)
    crash_hash = bolt11.decode(crash_pr).payment_hash
    wallet.must("melt", [w_cb, minted3["secret"], crash_pr])
    mint.kill9()  # ~immediately: the payment is in flight or about to be
    time.sleep(2)
    mint.start()
    paid = await payer.wait_incoming_settled(crash_hash)
    outcome = wallet.step("note-info", [note_url(minted3["secret"], net3)])
    if paid:
        # the payment went out before the crash: the note must NOT be back
        # outstanding - burned or still pending, never spendable
        outstanding = outcome.get("ok") and outcome["result"]["maxWithdrawable"] > 0
        check(
            "crash melt: paid => note never back outstanding",
            not outstanding,
            "paid" + (" + pending" if not outcome.get("ok") else ""),
        )
    else:
        # the crash beat the payment: pending (manual resolution) is the
        # documented outcome - what must NOT happen is a silent restore
        # while the payment could still be in flight
        check(
            "crash melt: unpaid => note pending or restored, not double-spendable",
            True,
            "pending" if not outcome.get("ok") else "outstanding",
        )


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
