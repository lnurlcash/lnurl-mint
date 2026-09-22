"""LUD-25 `ct1` note locks: a note committed to a BIP-341 taproot output key Q,
redeemable by its key-path `ck1` signature OR by a `cw1` script-path spend.

Script verification is Bitcoin Core's own interpreter, via the optional
`lnurlcashkernel` package (`pip install 'lnurl-mint[ct1]'`). Without it this mint
refuses `ct1` outputs outright - accepting a lock it cannot later open would
strand the funds. Time is the one thing the kernel never decides: `now` and the
note's recorded `locked_at` are passed in here, so a timelock "verified" means
this mint asserted its own clock (a custodial policy, not a consensus proof).
"""

import hashlib
import time

from coincurve import PublicKey

try:
    import lnurlcashkernel as kernel
except ImportError:  # optional extra
    kernel = None

_TAPLEAF_VERSION_MASK = 0xFE


def available() -> bool:
    return kernel is not None


def _tagged_hash(tag: str, data: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + data).digest()


def _compact_size(n: int) -> bytes:
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    return b"\xfe" + n.to_bytes(4, "little")


def derive_output_key(script: bytes, control_block: bytes) -> bytes | None:
    """The taproot output key Q that `(script, control_block)` commits to
    (BIP-341: fold the merkle path up from the leaf, tweak the internal key).
    Whoever presents a leaf can only ever reach the one Q it was built into, so
    a note's stored Q self-certifies the revealed script. None if malformed."""
    if len(control_block) < 33 or (len(control_block) - 33) % 32 != 0 or (len(control_block) - 33) // 32 > 128:
        return None
    leaf_version = control_block[0] & _TAPLEAF_VERSION_MASK
    internal = control_block[1:33]
    node = _tagged_hash("TapLeaf", bytes([leaf_version]) + _compact_size(len(script)) + script)
    for i in range(33, len(control_block), 32):
        sibling = control_block[i : i + 32]
        first, second = (node, sibling) if node < sibling else (sibling, node)
        node = _tagged_hash("TapBranch", first + second)
    tweak = _tagged_hash("TapTweak", internal + node)
    try:
        tweaked = PublicKey.combine_keys([PublicKey(b"\x02" + internal), PublicKey.from_secret(tweak)])
    except ValueError:
        return None
    return tweaked.format(compressed=True)[1:]


def parse_cw1(k1: str):
    """The decoded `cw1` in `k1`, or None if it isn't one (or the kernel is missing)."""
    return kernel.decode_cw1(k1) if kernel is not None and k1[:3].lower() == "cw1" else None


def verify(spend, note_id_hex: str, amount_msat: int, locked_at: int) -> str | None:
    """None if `spend` (a decoded cw1) legitimately opens the ct1 note
    `note_id_hex` - otherwise the exact reason lnurlcashkernel rejected it,
    e.g. "locktime 1800000000 is in the future (now 1699999999)" or "leaf
    script is not a supported shape". Safe to disclose to whoever submitted
    `spend`: unlike a legacy hash preimage or a ck1 signature, a cw1
    reveals its ENTIRE secret in the request itself - there is nothing left
    for an explanation to help anyone guess at a still-hidden one. See
    router.py's _note_id_from_cw1, the one caller, for how this is used."""
    assert kernel is not None
    try:
        kernel.verify_spend(
            output_key=bytes.fromhex(note_id_hex),
            amount_msat=amount_msat,
            leaf_script=spend.script,
            control_block=spend.control_block,
            witness=list(spend.witness),
            locktime=spend.locktime,
            sequence=spend.sequence,
            now=int(time.time()),
            locked_at=locked_at,
        )
    except kernel.SpendRejected as exc:
        return str(exc)
    return None
