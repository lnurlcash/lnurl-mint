from hashlib import sha256

from coincurve import PublicKeyXOnly

# LUD-25 Seed & derivation - only the SERVICE-side half: given a
# WALLET's public branch export (cx1 = P || chain_code), recompute the same
# non-hardened, taproot-style tweak a WALLET derives note keys with. SERVICE
# never holds or needs a private key here - this is the one place it derives
# a note's identity on its own (the cx1 auto-mint path, router.py), always
# from public data alone.


def tagged_hash(tag: bytes, msg: bytes) -> bytes:
    """BIP-340 tagged hash: sha256(sha256(tag) || sha256(tag) || msg)."""
    tag_hash = sha256(tag).digest()
    return sha256(tag_hash + tag_hash + msg).digest()


# secp256k1's group order n
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# The index `i` a WALLET increments once per key it derives - serialized as
# 4-byte big-endian (ser32, the same width the branch root's own hardened
# steps already use per 25.md) into the tagged hash below. 25.md's Seed &
# derivation doesn't pin this width explicitly; ser32 is this
# implementation's choice, consistent with the rest of that section, but
# genuinely interoperability-critical - see this repo's plan notes.
_INDEX_BYTES = 4


def derive_pubkey(branch_point: bytes, chain_code: bytes, index: int) -> bytes:
    """pk_i for note index `index` on the branch (branch_point, chain_code)
    = a cx1's decoded (P, chain_code) - per 25.md:

        t     = tagged_hash("LNURLcash/derive", P || chaincode || i) mod n
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
    digest = tagged_hash(b"LNURLcash/derive", branch_point + chain_code + index.to_bytes(_INDEX_BYTES, "big"))
    tweak = (int.from_bytes(digest, "big") % _N).to_bytes(32, "big")
    pubkey = PublicKeyXOnly(branch_point)
    pubkey.tweak_add(tweak)
    return pubkey.format()
