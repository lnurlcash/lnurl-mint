# LNURLmint - A lightning cash implementation

A lightning backend implementing **lnurlcash** ([LUD-25](../luds/25.md)),
Lightning bearer assets on top of plain [LUD-03](../luds/03.md)
`withdrawRequest` and [LUD-06](../luds/06.md) `payRequest`. A stripped-down
sibling of [lnurl_server](../lnurl_server); nothing but the mint.

A bearer note is a `k1` this mint has credited with value. It is minted by paying a
LUD-06 invoice (the payment preimage *is* the note), circulates offline as
`lnurlw://<host>/w?k1=<k1>`, and can be rotated, split, merged, or melted back
to a BOLT-11 payment. Redeem one with [lnurl-wallet](https://github.com/dni/lnurl-wallet),
a reference wallet implementation (hosted at
[wallet.lnurlcash.com](https://wallet.lnurlcash.com)).

## Endpoints

| Endpoint        | Role                                                                          |
|-----------------|-------------------------------------------------------------------------------|
| `GET /`         | one-pager frontend: mint QR code (LNURL of the LUD-16 address), lightning address, mint limits, node info incl. capacity and mempool.space/amboss.space links |
| `GET /.well-known/lnurlp/{username}` | LUD-06 payRequest, extended with `withdrawLink` (the mint advertisement) - the mint is payable at `{USERNAME}@{BASE_URL host}` (or the reserved bare-domain `_@{BASE_URL host}`, see below), and this is its only payRequest entry point (no separate bare `/p`) |
| `GET /p/cb`   | LUD-06 callback, invoice whose preimage becomes a note once paid - reports `disposable: false` ([LUD-11](../luds/11.md)): the lightning address itself is meant to be stored and reused |
| `GET /verify/{payment_hash}` | LUD-21, settlement status for an invoice minted via `/p/cb` or paid out by a melt via `/w/cb` ([LUD-25](../luds/25.md)) |
| `GET /w` | LUD-03 withdrawRequest for a note (`?k1=`), informational, never burns       |
| `GET /w/cb` | the mutating callback: melt (`pr`), rotate, split (`amount`), merge (many `k1`) |
| `GET /.well-known/lnurlw/{username}` | **Theoretical/experimental**: withdraw-side mirror of the LUD-16 address - informational only, see below |

**Bare-domain address** ([LUD-16](../luds/16.md)): both well-known aliases
above also answer for the reserved username `_`, alongside the configured
`USERNAME` - so `_@{BASE_URL host}` reaches the exact same mint identity
as `{USERNAME}@{BASE_URL host}`. Per spec, `_` isn't meant to be user
facing: it's what a WALLET/directory resolves when it wants to display
just the bare domain (`{BASE_URL host}`) rather than a visible username -
a WALLET recognizing the convention hides the `_` on its own, this mint
just needs to answer for it. `text/identifier` in the payRequest's
`metadata` echoes back whichever name was actually queried (`_` or
`USERNAME`), not always the latter, so a WALLET that resolved the
bare-domain form sees that same identity confirmed rather than a
different-looking one.

Callback semantics (`/w/cb`):

| `k1`  | `pr` | `amount` | Result                                                    |
|-------|------|----------|-----------------------------------------------------------|
| one   | yes  | –        | melt: note reserved, OK (plus `pr`/`verify` if verify is enabled) returned immediately, `pr` (of exactly its value) paid asynchronously, burned once settled |
| one   | no   | no       | rotate: burned, a note keyed by `h` (of the same value) minted |
| one or many | no | yes | split: all burned, two notes minted - `amount` keyed by `h`, the remainder keyed by `h2` |
| many  | no   | –        | merge: all burned, one note worth the sum minted, keyed by `h` |

`pr` MUST NOT be combined with multiple `k1`s or with `amount`, melt several notes
by merging them first. The informational endpoint's response always echoes the
literal secret it was queried with (never a derived id), and ignores an `amount`
query param if present, notes may encode a wallet-declared value in their URL
(`?k1=...&amount=...`) for offline display, but it is never authoritative;
`maxWithdrawable` is.

**`h`/`h2`** ([LUD-25](../luds/25.md)): whenever `pr` is absent (rotate, split,
or merge), the caller (`WALLET`) - never this mint - generates the replacement
note's secret, a fresh random preimage, and discloses only its sha256 hash as
`h` (and, for a split's change note, `h2`). This mint registers the new note
under that hash directly and never sees, generates, or persists the underlying
preimage - the callback response for these carries no secret at all, just
`{"status": "OK"}` (plus `sig`/`sig2` if offline verification is configured,
see below). `h` is required whenever `pr` is absent; `h2` is additionally
required whenever `amount` is too. A missing or malformed one fails with
`{"status": "ERROR", "reason": "missing h"}` (or `"missing h2"`) rather than
this mint generating a secret on `WALLET`'s behalf.

Per the spec, `/w/cb` replies `{"status": "OK"}` for a melt as soon as the note
is reserved, then pays `pr` asynchronously in the background - it does not wait
for the outgoing payment to settle before responding. A melted `k1` MUST NOT be
burned until that payment actually settles, so for the duration of the (now
backgrounded) payment attempt its note is only reserved (`pending`), not yet
burned - any other callback naming that `k1` (another melt, a rotate, a split,
a merge) fails with `{"status": "ERROR", "reason": "pending"}` until it
resolves, at which point the note is either burned for good (payment settled)
or released back to outstanding (payment confirmed failed). Since the initial
response is sent before the payment is even attempted, a melt failure is never
reported back through this callback - only observable as the note becoming
spendable again.

No spendable secret is ever persisted or, for a rotate/split/merge, even seen
by this mint at all: notes are stored keyed by `sha256(k1)` - `h`/`h2` above,
supplied by `WALLET` directly - and for a freshly minted note that id is
exactly the payment hash of the invoice that funded it, so the preimage is
discarded at invoice-creation time. The spec also asks `SERVICE` not to log query strings on the withdraw
endpoints, since a bearer note's `k1` can sit in one far longer than an ephemeral
LUD-03 `k1` would, this mint disables uvicorn's per-request access log entirely
(see `server.py`'s lifespan) rather than leave secrets in server logs by default;
run it behind a reverse proxy if you want access logs for the other routes.

**Mint fee** (optional): set `BASE_FEE_MSAT`/`FEE_PERCENT_PPM` to withhold a
flat amount plus a parts-per-million cut of every mint's `amount`, credited
to `k1=P`'s note instead of the full amount paid - meant to cover the
routing cost of eventually paying that note back out on melt. Advertised as
an extra `["text/plain", "Mint fees: <base_fee_msat>,<fee_percent_ppm>"]`
entry in the LUD-16 address's `metadata`, so a wallet that recognizes the `Mint fees: `
prefix can warn the payer up front; omitted entirely (assumed fee-free per
spec) when both are `0`. `MIN_MINT_MSAT` (default 10 sats) floors the note's
value net of this fee - not `amount` itself, which `MIN_SENDABLE_MSAT`
already bounds - so a mint too small to net a note worth minting is rejected
by `/p/cb` before an invoice is even created. The computed fee is always
rounded *up* to the nearest whole sat (never left at fractional-msat
precision), so the mint is never short a sat versus the naive estimate a
wallet derives from the metadata formula above.

**Sunset** (optional): set `SUNSET_MINT=true` to wind this mint down.
`/p/cb` and `/w/cb`'s split branch both start rejecting outright
(`{"status": "ERROR", "reason": "This mint is sunsetting - ..."}`), since
both grow the number of outstanding notes; rotate, merge, and melt are all
left alone - none of them increases this mint's outstanding liability, and
holders still need to be able to consolidate and redeem what they already
have. Off by default.

**Offline verification** (optional): if a funding source is configured, `GET
/w` advertises a `mintPubkey` - that node's own identity, the same key
it signs BOLT-11 invoices with - and rotate/split/merge responses carry a
recoverable `sig`/`sig2` over each new note's hash (`h`/`h2`, supplied by
`WALLET` - this mint signs exactly what it was given, never a secret it
derived itself), letting a holder verify a note's issuer and amount without
contacting the mint (see `signing.py`). Notes are signed via the funding source's own signmessage RPC
(lnd's `/v1/signmessage`, cln's `signmessage`), which both wrap the message
with the standard "Lightning Signed Message:" prefix and double-sha256 it
before signing - the same convention other Lightning tooling already uses to
prove node ownership, rather than a bespoke raw-digest scheme neither backend
can actually produce. The spark backend can't reuse that path either: its
SDK has no signmessage and signs a single-sha256 digest it cannot redirect
- so instead it derives a **dedicated signing key from the wallet's own
seed** (`m/25'/0'/0'`, outside spark's own `m/8797555'` key tree) and signs
the exact LUD-25 digest locally (RFC6979, recoverable `r||s||recid`). LUD-25
only *recommends* the node-id key - `mintPubkey` may be any secp256k1 key,
and a spark wallet's invoices are signed by its SSP anyway - so wallets
verify spark-minted notes exactly like lnd/cln ones (see
`spark._lud25_signing_key`; the derivation is cross-checked against
`@scure/bip32` in the test suite). Rotating the mnemonic rotates the key.
There's no separate setting for this: without a funding
source, both fields are simply omitted, same as any other unconfigured
optional field, and signing failures (e.g. a briefly unreachable node) are
swallowed rather than failing the rotate/split/merge itself.

**Verify** (optional, [LUD-21](../luds/21.md)): set `VERIFY_ENABLED=true` to
serve `/verify/{payment_hash}` and advertise a `verify` URL in `/p/cb`'s
response, letting a wallet with no node of its own poll settlement status
instead of watching the invoice itself. Once settled, the response's
`preimage` *is* the freshly minted bearer note's spend secret (see
[LUD-25](../luds/25.md)) - unlike a plain LUD-21 proof-of-payment, that
wallet needs it to claim the note at all, so it must be handed over despite
`SERVICE`'s own node already being a permanent prior holder of that same
secret; the wallet MUST rotate the note immediately after (see LUD-25's
Security considerations) rather than treat verify as having closed that
exposure window. `preimage` is fetched live from the funding source on every
call, never cached locally, same as every other secret this mint handles.
Unlike the ecosystem's usual convention, `VERIFY_ENABLED=false` disables the
endpoint entirely (404), not just its advertisement - precisely because the
preimage is a bearer secret here, an operator who doesn't want it served
gets a real off switch.

**The observer race, plainly**: the payment hash `/verify` is keyed by
travels inside the invoice itself, so *anyone* who sees an unpaid mint
invoice (a QR on a public page, a screenshot, a forwarded payment request,
wallet logs) can poll `/verify` and, the moment it settles, take the
preimage and rotate the note onto their own secret - first rotater wins,
no questions asked. A spec-compliant wallet rotates the instant its payment
settles and wins that race by construction. The exposed flows are the ones
that don't: manual ones (this README's own "enter the payment preimage
into lnurl-wallet" flow is a human-speed window), custodial wallets that
withhold preimages, and any invoice shared before payment. Don't put unpaid
mint invoices anywhere public, and if you can't accept this exposure for
your users, set `VERIFY_ENABLED=false`.

The same flag extends a melt's own response the same way, per LUD-25: `pr`
(the invoice this melt is paying, echoed back) and `verify` (a `/verify/`
URL for it) are attached to `{"status": "OK"}` once the outgoing payment's
`payment_hash` is known, letting a `WALLET` prove a melt actually happened
without trusting this mint's word for it - a BOLT-11 `pr` commits to
`payment_hash = sha256(preimage)`, so anyone holding both `pr` and the
`preimage` `verify` eventually reports (fetched live, same as the mint
side) can check that independently. Unlike a fresh mint's `preimage`, a
melt's is never a bearer secret - the note(s) that funded it are already
burned by the time it's returned - so there's no analogous rotate-immediately
requirement here.

**Mint address** (theoretical, experimental): `GET
/.well-known/lnurlw/{username}` is the withdraw-side mirror of the LUD-16
lightning address (`/.well-known/lnurlp/{username}`) - same `{username}`,
same unknown-user 404, but on the withdraw side instead of pay. There is
**no LUD number for this** and it is **not a functional LUD-03
withdrawRequest**: this mint only ever custodies bearer notes, never
per-user accounts, so there is no balance behind `{username}` for anyone
to actually withdraw - unlike `/w`, its response carries no `k1`. It exists
purely so a wallet or directory resolving `{username}@{host}` on its
withdraw side learns something useful instead of a bare 404: this mint's
own node identity (alias, color, capacity, channel/peer counts - see below),
`minWithdrawable`/`maxWithdrawable` mirroring the amount bounds a freshly
minted note can actually fall into (`MIN_MINT_MSAT`, and `MAX_SENDABLE_MSAT`
itself net of whatever mint fee is configured - the same fee-aware
treatment the LUD-16 address's own `minSendable` already gets on the floor
side, see `router.max_mintable_msat`), and `payLink` pointing back at
`/.well-known/lnurlp/{username}` - completing the loop that address's own
`withdrawLink` starts. `callback` points at the real `/w` for LUD-03 shape
symmetry, but with no `k1` to append, calling it yields nothing more than
`/w`'s own "Unknown note" - never a way to draw on this mint's funds.

**Capacity**: `NodeInfo.capacity` (msat, same as every other amount in this
codebase - frontend one-pager and the mint address response above, as
`nodeCapacity`) is this node's total *publicly announced* channel
capacity, and only that - never a private/authenticated view of this
node's own channels, so the number reported here is never more than what
this node's public presence already gives away on its own. Not part of
either backend's plain getinfo, so it costs a second call alongside it,
deliberately sourced from the public graph: lnd's `GET
/v1/graph/node/{pubkey}` (self-lookup, `total_capacity`, converted from
sats) and cln's `listchannels` filtered to `source=<own id>` (summed
directly from `amount_msat`), the same
`total_capacity`/`channel_announcement`s any other node on the network
already sees. Neither can be used to read this node's own private/
unannounced channels or their local/remote balance split the way
`ListChannels`/`listfunds` could. Best effort: a failure here (nothing
announced in the graph yet, or - a common gap after upgrading - a
macaroon/rune baked before `GetNodeInfo`/`listchannels` were added to the
required set below) is logged as a warning and leaves capacity at `0`
rather than failing the whole node lookup; check the logs for "could not
fetch capacity" if it's unexpectedly `0` on a node that does have public
channels.

**Node info caching**: `node.cached_fetch_node_info` (used by the frontend
one-pager and the mint-address endpoint - not by the startup connectivity
check, the background health monitor, or LUD-25's `mint_pubkey`/
`sign_note`, all of which still call `fetch_node_info` directly for a
live, uncached probe) keeps the last successful result in-process for up
to an hour, so repeated page views or `.well-known/lnurlw/{username}`
lookups don't each cost a fresh getinfo (plus the capacity/color RPCs
alongside it) against the funding source - a node's identity and channel
counts don't change minute to minute. A failed fetch is never cached, so
a momentary outage can recover on the very next request rather than
reporting "unreachable" for a full hour.

The frontend one-pager also links this node's pubkey out to
[mempool.space](https://mempool.space) and
[amboss.space](https://amboss.space) (their Lightning node explorer
pages) once it has one to link to.

**Tor**: set `ONION_URL` to this mint's hidden service address (e.g.
`http://<v3-address>.onion`) to advertise it on the frontend one-pager as an
alternative way to reach the mint, alongside its clearnet QR/address. This
isn't just cosmetic: if a wallet is actually connecting through that address,
`ONION_URL` is used as the base for the LNURL/callback URLs *instead of*
`BASE_URL` (see `config.py`'s `public_base_url`) - otherwise a fixed clearnet
`BASE_URL` would leak into a Tor visitor's QR code, pointing their wallet's
callback at a host it can't (or shouldn't have to) reach, breaking payment
over Tor entirely. Running the hidden service itself is outside this app's
scope - point a Tor `HiddenServiceDir` (or an onion-services-capable reverse
proxy) at whatever host/port this mint is already listening on, the same way
you'd front it with Caddy/nginx for clearnet.

## Run

```sh
uv sync
FORWARDED_ALLOW_IPS=* uv run uvicorn lnurl_mint.server:app --reload
```

Configure the funding source via `.env` (see `.env.example`): lnd or cln REST,
or a [spark](https://github.com/breez/spark-sdk) wallet (see "Spark
funding source" below). Without one, minting and melting are unavailable
(rotate/split/merge of existing notes still work).

Run exactly **one process** per `DATABASE_PATH`: no `--workers` greater than 1,
and no second container sharing the same database file. Note reservation,
burning, and melt reconciliation are coordinated inside a single process (a
module-level lock plus in-process background tasks over one sqlite connection) -
a second process silently voids those guarantees: at best spurious "database is
locked" errors, at worst double spends.

**cln rune**: this mint only ever calls `invoice`, `xpay`, `signmessage`,
`listinvoices`, `listpays`, `getinfo` and `listchannels` (see `node.py`) -
`listchannels` reads the *public* gossip store (for `capacity`, see
above), never this node's own private `listfunds` view - so scope
`FUNDINGSOURCE_RUNE` to just those instead of handing it a full-access
rune:

```sh
lightning-cli createrune restrictions='[["method=invoice","method=xpay","method=signmessage","method=listinvoices","method=listpays","method=getinfo","method=listchannels"]]'
```

The command's JSON output's `rune` field is the value for `FUNDINGSOURCE_RUNE`.
The single `[...]` restriction is an OR list (any of these seven methods, and
nothing else) - a comma-separated top-level list instead would AND further
restrictions on top (e.g. `pnum=0` to also disallow all requests with
parameters).

**lnd macaroon**: `admin.macaroon` works, but this mint only ever calls
`AddInvoice`/`LookupInvoice`, the router's `SendPaymentV2`/`TrackPaymentV2`,
`SignMessage`, `GetInfo` and `GetNodeInfo` (see `node.py`) - scope
`FUNDINGSOURCE_MACAROON` to just those instead of handing it full admin
access:

```sh
lncli bakemacaroon invoices:write invoices:read offchain:write offchain:read message:write info:read --save_to=lnurl-mint.macaroon
```

`info:read` (already included above for `GetInfo`) also covers
`GetNodeInfo` (a public-graph lookup, used for `capacity` - see
above), so no extra permission is needed beyond what this mint already
requires.

Set `FUNDINGSOURCE_MACAROON` to the hex-encoded contents of that file
(`xxd -p -c1000 lnurl-mint.macaroon`, or drop `--save_to` to have `lncli`
print the hex directly instead of writing a file). `message:write` is the
one easy to leave out and the one that breaks quietly: without it,
`SignMessage` calls fail, and since offline verification (LUD-25) is
optional and never blocks a rotate/split/merge on failure (see
`signing.sign_note`), a scoped-too-narrow macaroon shows up as every note
silently missing its signature rather than an obvious error - check the
logs for `sign_note: could not sign via lnd funding source: ...` if that
happens.

### Spark funding source

`FUNDINGSOURCE_BACKEND=spark` funds the mint from a
[spark](https://github.com/breez/spark-sdk) wallet instead of a Lightning
node - no channels, no inbound liquidity, no node ops: the mint holds a
spark balance and pays/receives over Lightning through its SSP. The whole
node contract is implemented in `lnurl_mint/spark.py`, on top of the
Breez Spark SDK's Python bindings:

```sh
uv sync --extra spark   # breez-sdk-spark is an optional ~20MB native dep
```

```sh
FUNDINGSOURCE_BACKEND=spark
FUNDINGSOURCE_SPARK_MNEMONIC=<12/24 BIP39 words>
FUNDINGSOURCE_SPARK_API_KEY=<breez api key>
# optional: FUNDINGSOURCE_SPARK_NETWORK (mainnet|regtest),
# FUNDINGSOURCE_SPARK_STORAGE_DIR (default: spark-wallet/ next to
# DATABASE_PATH), FUNDINGSOURCE_SPARK_SYNC_INTERVAL_SECS (default 15)
```

The mnemonic is the wallet's entire key material - a hot wallet seed;
the API key is free from
[Breez](https://breez.technology/request-api-key/). The SDK keeps its own
sqlite store under `FUNDINGSOURCE_SPARK_STORAGE_DIR` and runs background
sync/claim tasks inside the mint's process (built once at startup,
disconnected at shutdown) - same single-process rule as `DATABASE_PATH`:
never share the storage dir between two processes.

Behavioral differences worth knowing (details in `spark.py`'s module
docstring):

- **The mint never sees a mint-invoice's preimage.** The SSP generates
  and holds it; with comment protection mandatory the preimage is pure
  proof-of-payment (never the note's secret), and LUD-21 verify fetches
  it live from the SDK after settlement - the
  store-hashes-not-secrets policy holds either way, just more literally.
- **LUD-25 offline verification via a dedicated seed-derived key** - see
  above: full spec-conformant signatures (same digest, same wire format,
  verified by wallets identically to lnd/cln notes), signed locally
  rather than via the SDK.
- **Melt payments always take the Lightning route** (never a spark-routed
  shortcut) and are idempotent per invoice payment hash, and a melt whose
  SSP quote exceeds the fee budget is rejected before anything is paid.
  A melt payment the backend has no record of is **never** declared
  "not paid" from absence - the SDK persists its payment row only after
  the SSP accepts the payment, and its sync swallows reconciliation
  failures, so absence is indeterminate (the note stays pending) unless
  the SDK itself reports the payment failed, or this process provably
  never sent it: a prepare/fee-quote rejection, a fractional-sat melt
  (see below), or an insufficient-funds failure while selecting leaves -
  the common underfunded-wallet case, whose note restores immediately.
  That trade means: don't restart with unexplained pending melts; the
  only melts needing manual resolution are pre-restart rejections and
  genuinely ambiguous send errors - the safe direction of every
  ambiguity is "keep the note".
- **Settlement detection is bounded by
  `FUNDINGSOURCE_SPARK_SYNC_INTERVAL_SECS`** (default 15s): that's how
  long after a payment lands that mint/verify can first notice, since
  the SDK's own background sync is what refreshes its payment records.
  The health check probes both the coordinator operators and the SSP
  (breez-sdk-spark 0.23 silently swallows sync failures, and either
  service can fail while the other is up), so an unreachable Spark
  network or a revoked Breez API key actually surfaces in the health
  monitor - at the cost of one expiring 1-sat probe invoice at the SSP
  per health tick (see `FUNDINGSOURCE_HEALTH_CHECK_INTERVAL_SECONDS`).
- **Amounts are sat-aligned on both sides**: the SDK's bolt11 surface is
  sat-denominated, so a fractional-sat `/p/cb` amount is rejected with a
  logged error rather than rounded, and a fractional-sat melt invoice is
  rejected the same way - the SDK would otherwise CEIL it into whole
  sats of spark leaves, debiting more than the note's value (and tiny
  fractional notes from splits would let a holder over-drain the wallet
  by repeated melting).
- **The frontend's Channels/Peers/Capacity rows are zeros** for spark -
  a spark wallet has none of those, and its balance is private (unlike a
  Lightning node's public channel capacity), so it is deliberately not
  published there.

A live smoke check against mainnet (invoice creation, settlement
lookups, LUD-25 signing, and a melt-path fee quote - moves no funds by
default):

```sh
uv run python scripts/spark_mainnet_check.py --api-key-file breez-api.key
```

The nix package does not ship this backend (the prebuilt wheel isn't
packaged in nixpkgs) - use uv or Docker (`uv sync --extra spark` in your
own image build) for spark-funded mints.

## Docker

```sh
mkdir -p data && touch data/mint.db
docker run --restart always -d --name lnurl-mint \
  --network host \
  --user "$(id -u):$(id -g)" \
  -e PORT=8111 \
  -e DATABASE_PATH=/app/data/mint.db \
  --env-file .env \
  -v "$(pwd)/data:/app/data" \
  lnurlcash/lnurl-mint          # or: make run
```

The image runs as a non-root user; `--user` matches it to whichever host
user owns `data/` so it can write `mint.db` and its sqlite journal/WAL
files (which must live in the *same directory*, not just the db file
itself - a plain `-v .../mint.db:/app/mint.db` file mount isn't enough).

`--network host` lets `FUNDINGSOURCE_URL=https://localhost:3010` in `.env`
reach a node running on the host directly, no `host.docker.internal`
workaround needed - the tradeoff is no port remapping (`PORT` picks what the
app listens on) and no network isolation. If your lnd/cln cert lives on the
host, bind-mount it in too (`-v /host/path/tls.cert:/tls.cert:ro`, then set
`FUNDINGSOURCE_CERT_PATH=/tls.cert`).

Prefer real network isolation? Drop `--network host` and use `-p
<host-port>:8111` instead, same as any other container. Front it with a
reverse proxy for TLS if it's reachable from the internet.

## Nix

The flake provides the package, a dev shell, and a NixOS module:

```sh
nix build                              # builds the app, running the full test suite
nix run                                # serves via uvicorn (needs BASE_URL, see below)
nix develop                            # python + all deps + pinned test/lint tooling
                                       # (coincurve prebuilt from nixpkgs - no venv,
                                       # no sdist builds); run pytest against the tree
nix flake check                        # package + module eval + a VM smoke test
```

On NixOS, run the mint as a hardened systemd service:

```nix
{
  inputs.lnurl-mint.url = "github:dni/lnurl-mint";

  outputs = { nixpkgs, lnurl-mint, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      modules = [
        lnurl-mint.nixosModules.lnurl-mint
        {
          services.lnurl-mint = {
            enable = true;
            # verifyEnabled = true is the default - set false to 404
            # /verify entirely (see "The observer race, plainly" above)
            settings.BASE_URL = "https://mint.example.com";
            fundingSource = {
              backend = "cln";
              url = "https://localhost:3010";
            };
            # credentials stay out of the nix store - this file carries
            # FUNDINGSOURCE_RUNE (or FUNDINGSOURCE_MACAROON for lnd)
            environmentFiles = [ "/run/secrets/lnurl-mint" ];
          };
        }
      ];
    };
  };
}
```

The service runs with a dynamic user and a locked-down sandbox
(`ProtectSystem=strict`, `NoNewPrivileges`, restricted address families,
...), state in `/var/lib/lnurl-mint` (mode 0750 - mint.db and the logs hold
payment hashes and amounts). `BASE_URL` is required, by assertion at eval
time. The module composes with the rest of your node config the way you'd
expect - point `FUNDINGSOURCE_URL` at your clnrest/lnd REST and scope the
rune/macaroon as described above.

The nix build is pinned to `flake.lock`'s nixpkgs and runs the full test
suite in the build sandbox, so a python dependency that is added or
re-pinned in `pyproject.toml` without updating `nix/package.nix` fails the
`nix` CI job on that very PR - bump the `dependencies` list there when
`pyproject.toml` changes. `bolt11` is not in nixpkgs and is vendored in
`nix/package.nix` - bump its pinned commit and `hash` there alongside any
bolt11 version bump in `pyproject.toml`/`uv.lock`.

## Test

```sh
uv run pytest
```

The `/docs` Swagger UI assets are gitignored and fetched at build time
(pinned version + sha256, see `scripts/fetch_swagger_ui.py`), so on a fresh
clone the docs tests need them first: `make test` fetches them for you, or
run `uv run python scripts/fetch_swagger_ui.py` before a bare `uv run
pytest` (same inside `nix develop`).

## Release

Pushing a `v*` tag (`git tag v1.2.0 && git push origin v1.2.0`) triggers
`.github/workflows/release.yml`, which:

* builds the image and pushes `lnurlcash/lnurl-mint` to Docker Hub, tagged `1.2.0`,
  `1.2`, `1`, and `latest`
* creates a GitHub Release for the tag (via `gh release create
  --generate-notes`), with notes auto-generated from the commits/PRs merged
  since the previous tag
