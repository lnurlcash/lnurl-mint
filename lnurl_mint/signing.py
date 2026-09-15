import logging
from hashlib import sha256

from coincurve import PublicKey

from .node import LightningBackendConfig, fetch_node_info, sign_message

# LUD-25 Offline verification: signed via this mint's own funding-source
# identity. For lnd/cln that's the node's signmessage RPC, which always
# wraps the message with this prefix and double-sha256s it before signing -
# not a raw digest over a bespoke scheme, so any tool that already verifies
# a Lightning node's signed messages can verify a note too. Same reuse
# LUD-13 (../luds/13.md) relies on for LNURL-auth seed generation, rather
# than a separate keypair. The spark backend has no signmessage RPC and its
# SDK signs a different (single-sha256) digest it cannot redirect - so
# instead it signs this exact digest locally with a dedicated key derived
# from the wallet's own seed (m/25'/0'/0', see spark._sign_message_spark).
# LUD-25 only RECOMMENDS the node-id key ("SERVICE MAY sign notes with that
# same call"), and a spark wallet's invoices are signed by its SSP anyway;
# a wallet verifies a note by recovering the key from (digest, sig) and
# comparing it to the advertised mintPubkey, which holds for any secp256k1
# key - the spec-digest and wire format below are identical for all three
# backends, only the key differs.
_LIGHTNING_SIGNED_MESSAGE_PREFIX = b"Lightning Signed Message:"
_DOMAIN_TAG = "LNURLcash"


def lightning_signed_message_digest(message: str) -> bytes:
    """The LUD-25 note-signature digest: the standard "Lightning Signed
    Message" double-sha256 wrap (identical to what lnd's and cln's
    signmessage RPCs compute internally, and to what a WALLET recomputes
    to verify a note offline - see verify_note). Shared by the spark
    backend, which unlike lnd/cln has no signmessage RPC to produce it and
    so signs this digest locally with a dedicated seed-derived key (see
    spark._sign_message_spark)."""
    return sha256(sha256(_LIGHTNING_SIGNED_MESSAGE_PREFIX + message.encode()).digest()).digest()


def _message(note_id_hex: str, amount_msat: int) -> str:
    """The message a note's signature commits to. For a Part 1 note,
    `note_id_hex` is sha256(k1) hex-encoded, never k1 itself - per LUD-25
    it's exactly the `p1`/`p2` a WALLET discloses on a rotate/split/merge
    callback (this mint's own note storage id, too), so a holder can prove
    issuance (e.g. to expose a mint that won't honor its own note) without
    revealing the spend secret, and this mint never needs to hash a raw
    secret to produce or verify a signature - it never has one to hash.

    For a Part 2 `cp1` note, `note_id_hex` is instead the note's raw
    32-byte public key, hex - per 25.md's Offline verification, `hex(pk)`
    is signed directly, no hashing needed, since a public key is already a
    non-revealing commitment. This function's message format
    ("LNURLcash:<amount>:<id>") is bit-identical either way; only what the
    caller passes as `note_id_hex` differs, and only the caller (router.py)
    needs to know which kind of note it's signing for."""
    return f"{_DOMAIN_TAG}:{amount_msat}:{note_id_hex}"


async def mint_pubkey(config: LightningBackendConfig) -> str | None:
    """This mint's offline-verification signing key (LUD-25 `mintPubkey`) -
    the funding source node's own identity pubkey for lnd/cln (the same
    key it signs BOLT-11 invoices with, so freshly minted and rotated
    notes verify against the same identity, exactly as the spec
    recommends), and for spark the dedicated seed-derived signing key its
    notes are signed with (see spark._lud25_signing_key - a purely local
    derivation, no network round trip). None if no funding source is
    configured or it's unreachable - offline verification is then simply
    unavailable, the same way funding-source-backed features are when
    that's unconfigured."""
    if not config.backend:
        return None
    if config.backend == "spark":
        from .spark import signing_pubkey_hex

        return signing_pubkey_hex(config)
    try:
        info = await fetch_node_info(config)
    except Exception as exc:
        # not raised (offline verification is optional, see this
        # function's own docstring) but must not vanish with zero trace
        # either - see sign_note's own except below for the same reasoning
        logging.warning("mint_pubkey: could not reach %s funding source: %s", config.backend, exc)
        return None
    return info.uri.split("@")[0] if info.uri else None


async def sign_note(note_id_hex: str, amount_msat: int, config: LightningBackendConfig) -> str | None:
    """A recoverable signature over (note_id_hex, amount_msat) per LUD-25's
    Offline verification, signed by the funding source node's own
    signmessage RPC, as 65 bytes (r, then s, then recovery id),
    hex-encoded. `note_id_hex` is the note's own hash - per LUD-25, the
    `p1`/`p2` a WALLET generated and disclosed for a rotate/split/merge, so
    this mint signs exactly what it was given, never a secret it derived
    itself. The signmessage RPC itself returns recovery-id-leading bytes;
    per LUD-25 those are reordered here into r ‖ s ‖ recovery-id before
    being handed out, matching raw BOLT11 signatures. None if signing
    isn't possible right now (no funding source, or it's unreachable) -
    never raises, since a rotate/split/merge must still succeed without
    it."""
    if not config.backend:
        return None
    try:
        r_s, recovery_id = await sign_message(_message(note_id_hex, amount_msat), config)
    except Exception as exc:
        # not raised (see this function's own docstring) but must not
        # vanish with zero trace either - a signing RPC that always fails
        # (e.g. a macaroon/rune scoped without signmessage permission)
        # would otherwise look identical to "everything's fine, offline
        # verification is just turned off", indistinguishable from the
        # logs alone
        logging.warning("sign_note: could not sign via %s funding source: %s", config.backend, exc)
        return None
    return (r_s + bytes([recovery_id])).hex()


def verify_note(pubkey_hex: str, note_id_hex: str, amount_msat: int, signature_hex: str) -> bool:
    """Verifies a signature produced by sign_note against a mintPubkey - the
    check a WALLET performs offline, by reconstructing the same "Lightning
    Signed Message" digest lnd/cln computed internally when signing.
    `note_id_hex` is the note's hash (sha256(k1), hex) - the `p1`/`p2` a
    real WALLET would already have on hand, since it generated the
    secret itself. This mint never calls it itself; it exists for the
    test suite to confirm sign_note produces what the spec's algorithm
    expects."""
    signature = bytes.fromhex(signature_hex)
    digest = lightning_signed_message_digest(_message(note_id_hex, amount_msat))
    recovered = PublicKey.from_signature_and_message(signature, digest, hasher=None)
    return recovered.format(compressed=True).hex() == pubkey_hex


# LUD-25 Part 2, Encoding: a `ck1` is a WALLET's signature with a `cp1`
# note's own sk, over this one fixed message - unlike `cs1` (per-note,
# amount-and-pubkey-bound, see _message/sign_note), the same `ck1` value is
# reused everywhere that note's secret is needed, redemption included, so
# the message it signs can never depend on anything about the note itself.
# Precomputed once: every ck1 recovery reuses the identical digest.
_CK1_FIXED_DIGEST = lightning_signed_message_digest("LNURLcash")


def recover_note_pubkey(signature_hex: str) -> bytes:
    """Recovers the 32-byte x-only public key a `ck1` signature was
    produced with - router.py's redemption-side counterpart to
    Wallet-side ownership proofs' `ecrecover(digest, sig) -> pk_i`. Unlike
    verify_note (which compares a recovered key to one already known),
    this is a pure recovery: the caller has no prior claim about which
    note `signature_hex` belongs to, only the raw signature a request
    supplied as `k1` - the recovered key's x-coordinate IS the note id to
    look up. Raises ValueError on a malformed signature (wrong length, or
    one that doesn't recover to a valid point) - the same way a malformed
    legacy k1 fails HEX32_PATTERN, left to the caller to turn into the
    ordinary "invalid k1" response."""
    signature = bytes.fromhex(signature_hex)
    recovered = PublicKey.from_signature_and_message(signature, _CK1_FIXED_DIGEST, hasher=None)
    return recovered.format(compressed=True)[1:]


# A username registration's ownership proof (router.py's POST/DELETE
# /p/{username}): a WALLET's signature, with the branch's own index-0
# secret key ("the first secret" - the same key claim_next_index would
# hand out first, before this ever needed proving), over
# "LNURLcash:register:<username>" (to overwrite an existing claim) or
# "LNURLcash:unregister:<username>" (to delete one), per 25.md's Seed &
# derivation. Domain-separated from a note's own `ck1` (_CK1_FIXED_DIGEST
# above) so a note's spend/redemption signature can never be replayed
# here, or vice versa - and binding `action`/`username` into the message
# itself, rather than one fixed value reused everywhere, stops a
# signature captured from one overwrite/delete being replayed against a
# different username on the same branch, or against the other action for
# that same username.
def _register_message(action: str, username: str) -> str:
    return f"{_DOMAIN_TAG}:{action}:{username}"


def recover_register_pubkey(signature_hex: str, action: str, username: str) -> bytes:
    """Recovers the 32-byte x-only public key a registration ownership-
    proof signature was produced with - same recoverable-ECDSA primitive
    as recover_note_pubkey, over _register_message(action, username)'s own
    digest instead, so it can never be mistaken for a note's own `ck1`,
    another username's proof, or this same username's other action.
    `action` is "register" (upsert_registered_username's overwrite path)
    or "unregister" (delete_registered_username). Raises ValueError on a
    malformed signature, same as recover_note_pubkey."""
    signature = bytes.fromhex(signature_hex)
    digest = lightning_signed_message_digest(_register_message(action, username))
    recovered = PublicKey.from_signature_and_message(signature, digest, hasher=None)
    return recovered.format(compressed=True)[1:]
