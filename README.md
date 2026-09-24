# LNURLmint - A lightning cash implementation

A lightning backend implementing **lnurlcash** ([LUD-25](../luds/25.md)),
Lightning bearer assets on top of plain [LUD-03](../luds/03.md)
`withdrawRequest` and [LUD-06](../luds/06.md) `payRequest`. A stripped-down
sibling of [lnurl_server](../lnurl_server); nothing but the mint.

A note is a taproot output key `Q` this mint has credited with value; its
bearer secret is a spend of `Q` - a `ck1` (key path), a `cw1` (script path),
or for a plain bearer note just its 64-hex preimage. It is minted by paying a
LUD-06 invoice with the note's `cp1<Q>` (or bearer hash) as comment,
circulates offline as `lnurlw://<host>/w?k1=<spend>`, and can be rotated,
split, merged, or melted back to a BOLT-11 payment. Every spend is verified
by Bitcoin Core's own script interpreter, via
[lnurlcash-kernel](../lnurlcashkernel). Redeem one with [lnurl-wallet](https://github.com/dni/lnurl-wallet),
a reference wallet implementation (hosted at
[wallet.lnurlcash.com](https://wallet.lnurlcash.com)).

## Endpoints

| Endpoint        | Role                                                                          |
|-----------------|-------------------------------------------------------------------------------|
| `GET /`         | one-pager frontend: mint QR code (LNURL of the LUD-16 address), lightning address, mint limits, node info incl. capacity and mempool.space/amboss.space links |
| `GET /.well-known/lnurlp/{username}` | LUD-06 payRequest, extended with `withdrawLink` (the mint advertisement) - the mint is payable at `{USERNAME}@{BASE_URL host}` (or the reserved bare-domain `_@{BASE_URL host}`, see below), and this is its only payRequest entry point (no separate bare `/p`) |
| `GET /p/cb`   | LUD-06 callback for this mint's own fixed identity - invoice that credits the note named by `comment` (`cp1<Q>`, or a bearer hash) once paid - reports `disposable: false` ([LUD-11](../luds/11.md)): the lightning address itself is meant to be stored and reused |
| `GET /p/{username}` | the same LUD-06 callback, for a registered `{username}` instead (see `POST /p/{username}` below) - no `?username=` query parameter, the path itself says which branch to auto-mint into. Takes a NIP-57 zap request as `nostr=`, see "Zaps" below |
| `GET /verify/{payment_hash}` | LUD-21, settlement status for an invoice minted via `/p/cb`/`/p/{username}` or paid out by a melt via `/w/cb` ([LUD-25](../luds/25.md)) |
| `GET /w` | LUD-03 withdrawRequest for a note (`?k1=`), informational, never burns       |
| `GET /w/cb` | the mutating callback: melt (`pr`), rotate, split (`amount`), merge (many `k1`) |
| `GET /.well-known/lnurlw/{username}` | **Theoretical/experimental**: withdraw-side mirror of the LUD-16 address - informational only, see below |
| `POST /p/{username}` | [LUD-25](../luds/25.md): claims `{username}` for a WALLET's own `cx1` branch, so paying its lightning address auto-mints, or overwrites an existing claim's branch/npub wholesale - see "Wallet-side ownership proofs" below |
| `DELETE /p/{username}` | frees an existing `{username}` claim entirely, back to first-come-first-served - see "Wallet-side ownership proofs" below |
| `GET /.well-known/nostr.json` | [NIP-05](https://github.com/nostr-protocol/nips/blob/master/05.md), `?name=`: a registered username that also supplied an `npub` resolves as a Nostr identifier too - see "NIP-05" below |

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
| one   | no   | no       | rotate: burned, a note keyed by `p1` (of the same value) minted |
| one or many | no | yes | split: all burned, two notes minted - `amount` keyed by `p1`, the remainder keyed by `p2` |
| many  | no   | –        | merge: all burned, one note worth the sum minted, keyed by `p1` |

`pr` MUST NOT be combined with multiple `k1`s or with `amount`, melt several notes
by merging them first. The informational endpoint's response always echoes the
literal secret it was queried with (never a derived id), and ignores an `amount`
query param if present, notes may encode a wallet-declared value in their URL
(`?k1=...&amount=...`) for offline display, but it is never authoritative;
`maxWithdrawable` is.

**`p1`/`p2`** ([LUD-25](../luds/25.md)): whenever `pr` is absent (rotate, split,
or merge), the caller (`WALLET`) - never this mint - generates the replacement
note and discloses only its `cp1<Q>` as `p1` (and, for a split's change note,
`p2`) - or, for a plain bearer note, the sha256 hash of its preimage, the
short form (see "Notes and spends" below). This mint registers the new note
under that Q directly and never sees, generates, or persists its spend - the
callback response for these carries no secret at all, just `{"status": "OK"}` (plus
`sig`/`sig2` if offline verification is configured, see below). `p1` is
required whenever `pr` is absent; `p2` is additionally required whenever
`amount` is too. A missing or malformed one fails with `{"status": "ERROR",
"reason": "missing p1"}` (or `"missing p2"`) rather than this mint generating
a secret on `WALLET`'s behalf.

`h`/`h2` (on `/w/cb`) and `h` (on `/w`) are `p1`/`p2`/`p`'s old names, from
before the spec renamed them - still accepted for a WALLET that hasn't
caught up, equivalent in every way, just an older spelling. If both a field
and its old name are given, the new name wins.

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
by this mint at all: notes are stored keyed by their output key `hex(Q)` -
`p1`/`p2` above, or the mint `comment`, supplied by `WALLET` directly - and a
mint invoice's own preimage is discarded at invoice-creation time. The spec also asks `SERVICE` not to log query strings on the withdraw
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
it signs BOLT-11 invoices with - and rotate/split/merge responses (and the
informational `GET /w`) carry a `cs1` certificate as `sig`/`sig2`: a
recoverable signature over each note's `Q` and amount, the amount carried in
the certificate's own human-readable part (`p1`/`p2`, supplied by `WALLET` -
this mint signs exactly what it was given, never a secret it derived
itself), letting a holder verify a note's issuer and amount without
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

**Notes and spends** ([LUD-25](../luds/25.md)): every note is a BIP-341
taproot output key `Q`, and every `k1` is a spend of one, handed to Bitcoin
Core's own interpreter ([lnurlcash-kernel](../lnurlcashkernel), see
`spend.py`) as input 0 of LUD-25's canonical spend transaction. The wire
values are bech32m (BIP-350):

- **`cp1<Q>`** - a note, its 32-byte x-only output key. Goes on `comment`
  (`/p/cb`, minting), `p1`/`p2` (`/w/cb`) and `p` (`/w`). Never enough to
  redeem anything on its own.
- **`ck1<Q><sig>`** - a key-path spend: a BIP-340 signature by `Q` over the
  canonical spend transaction's sighash for this mint's domain, `Q`
  travelling alongside it. Goes on `k1`.
- **`cw1<...>`** - a script-path spend: a leaf script, its control block,
  its witness, and the redeemer's signed `nLockTime`/`nSequence`. Goes on
  `k1`. Any leaf Core accepts is accepted - no list of shapes - except
  tapscript's upgrade hooks (an unknown leaf version, or any `OP_SUCCESSx`),
  which consensus would accept unconditionally and are refused instead.
- **`cs1<sig>`** - this mint's issuance certificate, see Offline verification.

**Short forms**: a plain bearer note (BIP-341's NUMS key, one
`OP_SHA256 <h> OP_EQUAL` leaf) is fully determined by `h`, so 64 hex
characters in `k1` are its preimage (this mint builds the `cw1` itself), and
64 hex characters where a `cp1` goes are `h`. A wallet that knows nothing of
taproot mints and redeems with sha256 alone, exactly as a plain LUD-03 `k1`
always worked.

**Domains**: a signature is bound to the host its note's URL carries, via
the canonical transaction's prevout. This mint accepts every host it answers
on - `BASE_URL`'s, and `ONION_URL`'s if set - and nothing else, so a spend
seen by another mint can't be replayed here.

**Time**: the kernel never reads a clock. A timelock "verified" here means
this mint asserted its own: a `cw1`'s signed `nLockTime` must be a Unix time
not in the future, and a relative lock (BIP-68 time type only) counts from
when this mint credited the note. That is custodial policy, never a proof.

A `cw1` that opens a real note but fails a script or time check is refused
with that *specific* reason - a `cw1` discloses its whole secret already, so
explaining its failure can't help anyone guess another. Everything else that
fails to resolve (a bad `ck1` signature, a note that never existed, or one
already burned) stays in the same ambiguous "Invalid or already spent k1."

**Deprecated, still accepted** until such notes have aged out: a `ck1` of
the same `Q ‖ sig` shape signed over the old fixed message
(`sha256("LNURLcash")`, or before that the raw string), and the pre-schnorr
bare 65-byte recoverable `ck1` (see `signing.verify_legacy_ck1`,
`bech32m.decode_ck1_legacy`). A note issued before notes were keyed by `Q`
sits under its old id `sha256(k1)`: nothing on file tells that apart from a
key, so it is moved to its `Q` lazily, by the first request that proves the
link - its preimage as `k1`, or its hash as `p` (see
`NoteStore.migrate_legacy_note`).

**cx1 registration & lightning-address auto-mint** (`POST /p/{username}`): a
WALLET claims `{username}` against its own `?cx1=`. A fresh, unclaimed name is
first-come-first-served, no proof of possession required - `cx1` alone never
grants spending, only a note's own private key does, so a squatted
registration only costs the real owner a friendly name, never funds. Once
registered, paying `{username}@{BASE_URL host}` with **no `comment`**
auto-mints a fresh `cp1` note directly on that branch (this mint derives the
next unused key itself - `NoteStore.claim_next_index`, skipping any index
already outstanding or spent, guarding the same race the spec's Seed &
derivation describes) - no per-payment WALLET involvement needed at all. The
payer's WALLET can still supply its own `comment=cp1<pk>` instead (e.g. the
address owner minting for themselves with a specific key already in hand),
which is honored as-is; any other `comment` (an ordinary human LUD-12
message, say) is simply ignored rather than rejected, and auto-mint proceeds
as if none were sent. Set `USERNAME_REGISTRATION_ENABLED=false` to turn this
off entirely (404, same off-switch convention as `VERIFY_ENABLED`) - this
mint's own fixed identity (`USERNAME`/the bare-domain `_`) is never affected
either way. A registered username is always stored lowercase and matched
case-insensitively (same as `USERNAME` itself, see above) - `Alice`,
`alice` and `ALICE` all resolve to the same identity regardless of which
one a payer's client happened to send.

**Internal mint transfers**: a registered username's payRequest metadata
additionally carries a `["text/xpub", "<cx1>:<i>"]` entry - that same branch's
own `cx1`, plus `i`, this mint's best-known next-unused index on it. A payer
who already holds a `cp1`/`ck1` note on this same mint can read that straight
off the recipient's Lightning Address and skip Lightning entirely: derive
`pk_i` from `(cx1, i)` itself and name it as `p1`/`p2` on an ordinary
rotate/split/merge, moving value between two notes on this mint with no
invoice, no payment, and no round trip through the funding source at all. `i`
is only a hint, not a reservation - if it's stale or another transfer already
claimed it, the request fails exactly like any other already-in-use `p1`, and
the sender just retries at the next index.

Calling `POST /p/{username}` again on an **already-registered** name
overwrites it wholesale (new `cx1`, and a new or absent `npub` - see NIP-05
below) instead of claiming it fresh - and that path needs proof: `?sig=`, a
recoverable signature made with the branch **currently on file**'s own
index-0 secret key ("the first secret", the same key `claim_next_index`
would hand a note out under first), over `LNURLcash:register:<username>`,
wrapped the same "Lightning Signed Message" way every other signature here is
(see Offline verification above) - deliberately a *different* message than a
note's own spend (which signs a transaction sighash), and binding both the action
and the username into it so a signature captured from one overwrite/delete
can never be replayed against a different username sharing that branch, or
against the other action for that same one. It proves continued control of
what is registered already, not of the new `cx1` being switched to, so a
WALLET migrating to a new seed only needs to still hold its old one long
enough to sign this once. `DELETE /p/{username}?sig=...` frees the name
entirely (back to unclaimed, first-come-first-served) with the same kind of
signature required instead, over `LNURLcash:unregister:<username>` - there is
no proof-free way to delete a name someone else may depend on.

**NIP-05** ([nostr-protocol/nips#05](https://github.com/nostr-protocol/nips/blob/master/05.md),
optional): `POST /p/{username}` also takes `?npub=` - a WALLET's own Nostr
public key, NIP-19 bech32-encoded - which doubles `{username}@{BASE_URL host}`
as a Nostr identifier too, not just a Lightning Address. `GET
/.well-known/nostr.json?name={username}` then resolves it, the same query
any NIP-05-aware Nostr client already makes. Only ever answers the one `name`
asked about (never this mint's whole directory, even with no `name` at all),
and only for a username that supplied an `npub` - an unregistered or
`npub`-less name just comes back as an empty map, NIP-05's own "not found",
never a 404. Omitting `npub` on an overwrite (see above) clears any
previously registered one. Set `NIP05_ENABLED=false` to turn this off
entirely (404, same off-switch convention as `VERIFY_ENABLED`) - `?npub=` is
then rejected outright at registration too, rather than stored for an
endpoint that won't resolve it. Independent of
`USERNAME_REGISTRATION_ENABLED`: an operator can allow registration while
keeping npub resolution off, or the reverse.

**Zaps** ([NIP-57](https://github.com/nostr-protocol/nips/blob/master/57.md),
optional): set `NOSTR_KEY` (32 bytes of hex, this mint's own Nostr key) and
a registered username's payRequest carries `allowsNostr: true` and
`nostrPubkey`. A zapping client then sends its kind 9734 zap request as
`/p/{username}?nostr=`; this mint checks it the way the NIP's Appendix D says (a
valid signature, exactly one `p`, at most one `e`, a `relays` tag, an
`amount` that matches), binds the invoice to it by description hash, and
mints the note on the username's branch exactly as any other payment there.
Once the invoice settles (polled every `ZAP_POLL_INTERVAL_SECONDS`, default
5) it publishes the kind 9735 receipt, signed with `NOSTR_KEY`, to the relays
the request named plus `NOSTR_RELAYS`, so the zap shows up in clients like
any other. Publish-only: this mint never subscribes to a relay, dials only
`wss://` relays and at most eight from a request, and polls only the newest
hundred unpaid zap invoices of the last hour. It attests to what was paid,
not to whom the payer meant it: it holds no Nostr key for a username, so `p`
is whatever the zapper's client put there, and a receipt naming another
username's owner here is one a client cannot tell from a real one. Every
multi-user LNURL provider signing with one key has the same gap. Needs an lnd or
cln funding source, the two that let a caller set an invoice's description
hash; on spark zaps stay off. The fixed identity (`USERNAME`/`_`) is never
zappable: it has no branch for the note to land on.

**Verify** (optional, [LUD-21](../luds/21.md)): set `VERIFY_ENABLED=true` to
serve `/verify/{payment_hash}` and advertise a `verify` URL in `/p/cb`'s
response, letting a wallet with no node of its own poll settlement status
instead of watching the invoice itself. Once settled, the response's
`preimage` *is* the freshly minted bearer note's spend secret (see
[LUD-25](../luds/25.md)) - unlike a plain LUD-21 proof-of-payment, that
wallet needs it to claim the note at all, so it must be handed over despite
`SERVICE`'s own node already being a permanent prior holder of that same
secret; the wallet MUST rotate the note immediately after rather than treat
verify as having closed that exposure window (see "The observer race,
plainly" below). `preimage` is fetched live from the funding source on every
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
