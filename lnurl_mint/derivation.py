import hmac
from hashlib import sha256, sha512

from coincurve import PublicKey, PublicKeyXOnly

# LUD-26 Seed & derivation - only the SERVICE-side half. A WALLET derives
# its notes with plain BIP-32 below each SERVICE's root S, and hands out a
# share's extended public key, cx1 = chain_code || P (P compressed), for a
# Lightning Address: this mint derives that share's notes S/a'/2/n'/i with
# BIP-32 CKDpub from the cx1 alone, and never holds or needs a private key
# here - this is the one place it derives a note's identity on its own (the
# auto-mint and internal-transfer paths, router.py).


def tagged_hash(tag: bytes, msg: bytes) -> bytes:
    """BIP-340 tagged hash: sha256(sha256(tag) || sha256(tag) || msg)."""
    tag_hash = sha256(tag).digest()
    return sha256(tag_hash + tag_hash + msg).digest()


# secp256k1's group order n
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# BIP-32 reads an index at or above 2^31 as hardened, which only the private
# key can take: a share's note indices are always below it
_HARDENED = 0x80000000


def ckd_pub(pubkey: bytes, chain_code: bytes, index: int) -> tuple[bytes, bytes]:
    """BIP-32 CKDpub: the (compressed pubkey, chain code) of child `index`
    of the extended public key (`pubkey`, `chain_code`). Raises ValueError
    for a hardened index, a pubkey that is not a compressed point, or the
    ~2^-127 index BIP-32 itself calls invalid (the WALLET skips it too)."""
    if not 0 <= index < _HARDENED:
        raise ValueError("CKDpub takes a non-hardened index only")
    if len(pubkey) != 33 or len(chain_code) != 32:
        raise ValueError("an extended public key is a 33-byte pubkey and a 32-byte chain code")
    digest = hmac.new(chain_code, pubkey + index.to_bytes(4, "big"), sha512).digest()
    left = int.from_bytes(digest[:32], "big")
    if left >= _N:
        raise ValueError(f"BIP-32 derivation at {index} is out of range")
    child = PublicKey(pubkey).add(digest[:32])
    return child.format(compressed=True), digest[32:]


def derive_note_pubkey(cx1: bytes, index: int) -> bytes:
    """Q of note `index` on the share a decoded cx1 (chain_code || P, 65
    bytes) exports: x(CKDpub(P, chain_code, index)), 32 bytes - the note
    this mint credits next. Raises ValueError for an index that derives no
    key."""
    child, _ = ckd_pub(cx1[32:], cx1[:32], index)
    return child[1:]


# ---- superseded: the per-note tweak ----
#
# Before LUD-26 (luds a6c4652), a WALLET tweaked its note keys off one branch
# node, and a cx1 was the 64-byte x(P) || chain_code. A username registered
# then still holds that cx1, and this mint keeps auto-minting to it under
# purpose 2, the Lightning Address counter, so the address keeps working
# until its owner moves it to a share (router.update_registered_username).
# `purpose` split the branch into three counters; only 2 is derived here.
PURPOSE_WALLET = 0
PURPOSE_CHANGE = 1
PURPOSE_LIGHTNING_ADDRESS = 2
_INDEX_BYTES = 4


def legacy_derive_pubkey(branch_point: bytes, chain_code: bytes, purpose: int, index: int) -> bytes:
    """pk_i for note index `index` on purpose `purpose` of the branch
    (branch_point, chain_code) = a superseded 64-byte cx1's decoded
    (x(P), chain_code) - as 25.md specified before LUD-26:

        t     = tagged_hash("LNURLcash/derive", P || chaincode || purpose || i) mod n
        Q     = lift_x(P) + t·G
        pk_i  = x(Q)

    coincurve's PublicKeyXOnly.tweak_add implements exactly this BIP-340
    x-only tweak (lift_x and the even-y parity handling included), so no
    manual point arithmetic is needed. It refuses a tweak >= n rather than
    reducing it, so `t` is reduced mod n here first, as 25.md requires (the
    hash lands >= n for only ~2^-128 of outputs, but a WALLET reduces it too
    and both sides must derive the same pk_i). Raises ValueError only if
    Q is the point at infinity (~2^-256)."""
    if len(branch_point) != 32 or len(chain_code) != 32:
        raise ValueError("branch_point and chain_code must each be 32 bytes")
    digest = tagged_hash(
        b"LNURLcash/derive",
        branch_point + chain_code + purpose.to_bytes(_INDEX_BYTES, "big") + index.to_bytes(_INDEX_BYTES, "big"),
    )
    tweak = (int.from_bytes(digest, "big") % _N).to_bytes(32, "big")
    pubkey = PublicKeyXOnly(branch_point)
    pubkey.tweak_add(tweak)
    return pubkey.format()
