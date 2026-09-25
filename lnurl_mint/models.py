from typing import Literal

from pydantic import BaseModel


class LnurlPayResponse(BaseModel):
    """LUD-06 payRequest, extended with lnurlcash's `withdrawLink` - the raw
    (LUD-17) URL of the withdrawRequest endpoint that will recognize this
    mint's payment preimages as bearer notes.

    `commentAllowed` (LUD-12) advertises room for LUD-25's comment
    protection: a WALLET attaches `comment=hex(sha256(secret))`, a bare
    hex-encoded 32-byte hash, to close the preimage-propagation race a
    minted note's k1 would otherwise be exposed to (see
    router.get_pay_callback) - 64 hex chars, exactly what's advertised
    here. `comment` is mandatory on the fixed identity's callback, which
    has no other key to mint under (missing or malformed rejects the mint
    outright), unlike LUD-12's own optional/free-text default use. On a
    cx1-registered username it is not: that address has a branch to
    mint on, so a comment naming no output is the free text
    `commentAllowed` invites and is ignored rather than refused.

    `allowsNostr`/`nostrPubkey` (NIP-57) are present only on a registered
    username's payRequest of a mint with NOSTR_KEY set: the callback then
    takes a zap request, and the key is what signs the receipt."""

    tag: Literal["payRequest"] = "payRequest"
    callback: str
    minSendable: int
    maxSendable: int
    metadata: str
    withdrawLink: str
    commentAllowed: int = 64
    allowsNostr: bool | None = None
    nostrPubkey: str | None = None


class LnurlPayActionResponse(BaseModel):
    """LUD-06 callback response - paying `pr` mints a bearer note under the
    WALLET-held secret behind the mandatory `comment` (see
    router.get_pay_callback), not the payment preimage.

    `verify` (LUD-21, optional) lets a wallet with no node of its own poll
    settlement status - omitted unless VERIFY_ENABLED is set.

    `disposable` (LUD-11) tells a WALLET whether the payRequest LNURL/
    lightning address itself (not this one invoice) is meant to be kept
    around and reused - always `false` here: the LUD-16 address is this
    mint's permanent, repeatable way to mint a fresh note, not a
    one-shot link that stops working after this payment. Per LUD-11, a
    WALLET that doesn't recognize this field at all is required to treat
    a link as disposable by default and may discard it - `false` must be
    sent explicitly, omitting it would silently undo that."""

    pr: str
    routes: list = []
    verify: str | None = None
    disposable: bool = False


class LnurlPayVerifyResponse(BaseModel):
    """LUD-21: settlement status for an invoice minted via `/p/cb`.

    `preimage`, once settled, IS the freshly minted bearer note's spend
    secret (see LUD-25's Minting a bearer note from a payRequest) - unlike
    a plain LUD-21 proof-of-payment, a wallet with no node of its own needs
    it to claim and immediately rotate the note: this mint's own node is a
    permanent prior holder of a freshly minted note's secret (it generated
    that preimage to fund the invoice in the first place - the one case
    where LUD-25's WALLET-generates-the-secret rule can't apply, since the
    secret has to come from the payment itself), so deferring the rotate
    leaves that exposure window open regardless of how promptly
    settlement was checked. `status`/`settled`/`pr` otherwise behave
    exactly per LUD-21."""

    status: Literal["OK"] = "OK"
    settled: bool
    preimage: str | None = None
    pr: str


class LnurlWithdrawResponse(BaseModel):
    """LUD-03 withdrawRequest for a single bearer note - min equals max
    equals the note's value, which is how a wallet reads a note's worth
    (this GET is informational and never burns anything).

    `k1` is optional (unlike plain LUD-03) to support LUD-25's "Checking a
    note without exposing it": when the note was looked up by `p` rather
    than `k1` (router.get_withdraw), there is no raw secret to echo back -
    the field is omitted from the response entirely (see
    LnurlErrorResponseHandler's response_model_exclude_none) rather than
    sent as null, exactly the shape the spec says to use.

    `mintPubkey` (LUD-25 Offline verification, optional) is this mint's
    signing key - omitted entirely if no funding source is configured
    (see signing.mint_pubkey).

    `c` (Offline verification, optional) is a ready-made `cs1` certificate
    for the note, whether looked up by a spend (`k1`) or by `p` - see
    router.get_withdraw. Omitted if signing isn't available right now."""

    tag: Literal["withdrawRequest"] = "withdrawRequest"
    callback: str
    k1: str | None = None
    minWithdrawable: int
    maxWithdrawable: int
    defaultDescription: str = ""
    mintPubkey: str | None = None
    c: str | None = None


class LnurlMintAddressResponse(BaseModel):
    """Theoretical companion to LUD-16 lnaddress (get_lnaddress): advertised
    at .well-known/lnurlw/{username}, this is the withdraw-side mirror of
    the mint's payRequest identity, completing the loop that
    LnurlPayResponse.withdrawLink starts. There's no k1 and no real balance
    behind `{username}` to draw from - this mint only ever custodies bearer
    notes, never per-user accounts (see README) - so unlike `/w`, this is
    purely informational: this mint's own node identity/capacity (see
    node.NodeInfo) plus the amount bounds a freshly minted note can fall
    into, and `payLink` (this mint's own LUD-16 address) so a wallet that
    resolves mint@host on its withdraw side still finds its way back to
    actually minting a note. `callback` points at the real `/w` withdraw
    endpoint for symmetry with LUD-03's shape, but with no k1 to append a
    wallet gets nothing more than "Unknown note" there - never a way to
    draw on this mint's own funds."""

    tag: Literal["withdrawRequest"] = "withdrawRequest"
    callback: str
    k1: str | None = None
    minWithdrawable: int
    maxWithdrawable: int
    defaultDescription: str = ""
    mintPubkey: str | None = None
    payLink: str
    nodeAlias: str | None = None
    nodeUri: str | None = None
    # every address this node advertises, each already "node_key@host:port"
    # (see node.NodeInfo.uris, == [nodeUri] in the common single-address
    # case) - a node behind Tor as well as clearnet, for instance, has more
    # than one, and nodeUri alone only ever carried the first. None (not an
    # empty list) when there's no funding source or nothing announced,
    # consistent with every other optional field here (see
    # LnurlErrorResponseHandler's response_model_exclude_none).
    nodeUris: list[str] | None = None
    nodeColor: str | None = None
    nodeCapacity: int | None = None  # msat - see node.NodeInfo.capacity
    # same channel/peer counts NODE_SECTION already shows on the one-pager
    # frontend (see frontend._node_section) - included here too so a wallet
    # discovering this endpoint gets the same picture without scraping HTML
    nodeNumChannels: int | None = None
    nodeNumPeers: int | None = None
    # advance warning of a planned shutdown (config.py's SUNSET_DATE),
    # ISO-8601 (e.g. "2026-12-31") - None whenever it's unset, same as
    # every other optional field here. Independent of sunset_mint (which
    # actually stops minting): the whole point is to let a wallet warn its
    # user *before* that happens, not just report it once it already has.
    sunsetDate: str | None = None
    # this mint's total outstanding liability, msat (see
    # NoteStore.outstanding_msat) - the combined value of every bearer note
    # it has issued and never burned. Unlike the node fields above, always
    # present: it's a fact about this mint's own database, not the funding
    # source, so it's reported even when that's unreachable or unconfigured.
    outstandingNotesMsat: int = 0


class WithdrawSuccessResponse(BaseModel):
    """LUD-03 success response, extended per LUD-25 (see
    router.get_withdraw_callback for the full melt/rotate/split/merge
    semantics). `pr`/`verify` echo a melt's invoice and its LUD-21-style
    settlement-proof URL, present only when VERIFY_ENABLED. `c`/`c2`
    are this mint's Offline-verification certificates over a rotate/split/
    merge's `p1`/`p2` (see signing.sign_note) - `c2` only for a split,
    both omitted if no funding source is configured. None fields are
    excluded on the wire."""

    status: Literal["OK"] = "OK"
    c: str | None = None
    c2: str | None = None
    pr: str | None = None
    verify: str | None = None


class RegisterUsernameResponse(BaseModel):
    """LUD-25's cx1 registration (router's POST/DELETE
    /p/{username}) - claims or frees `username` for/from a WALLET's
    watch-only branch. A fresh claim is first-come-first-served, no proof
    of possession; overwriting or deleting an existing one needs an
    ownership-proof signature instead (see
    router.upsert_registered_username, NoteStore.upsert_username). A bare
    success marker; the error case is the ordinary
    {"status": "ERROR", "reason": ...} every other endpoint here uses."""

    status: Literal["OK"] = "OK"


class LnurlErrorResponse(BaseModel):
    """LUD-01's universal error shape: every LNURL endpoint here always
    replies HTTP 200, success or failure alike (see
    error_handler.LnurlErrorResponseHandler) - `reason` carries a
    human-readable explanation, never machine-parsed detail. Declared purely
    so the OpenAPI schema can document this as a second possible 200 body
    alongside each endpoint's own success model, instead of the framework's
    default (and, here, never actually reachable) 422 Validation Error."""

    status: Literal["ERROR"] = "ERROR"
    reason: str


class Nip05Response(BaseModel):
    """NIP-05's `.well-known/nostr.json` shape (router.get_nip05): a
    registered username that also supplied an npub at POST /p/{username}
    resolves here as a Nostr identifier (`name@host`), same as any other
    NIP-05 server. `names` maps back only the one name that was actually
    queried - and only if it has an npub on file - never this mint's
    whole directory; an unregistered or npub-less name just comes back
    empty, NIP-05's own "not found", not a 404."""

    names: dict[str, str]
