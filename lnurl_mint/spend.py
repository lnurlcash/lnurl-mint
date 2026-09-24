"""LUD-25 notes and spends.

Every note is a BIP-341 taproot output key Q, stored under hex(Q). Every `k1`
a redeemer presents is a spend of one: a `ck1` (key path), a `cw1` (script
path), or the 64-hex preimage of a bearer note, the short form of that note's
`cw1`. Decoding and verification are Bitcoin Core's own, via
`lnurlcashkernel`; this module only adds what is specific to this mint:

- which domains a signature may be bound to (every host this mint answers on);
- the deprecated `ck1` shapes older wallets signed (see _legacy_note_id and
  signing.verify_legacy_ck1), kept so already-issued notes stay redeemable;
- the pre-taproot storage id of a bearer note (see legacy_hash), for notes
  issued before notes were keyed by Q.

Time is the one thing the kernel never decides: `now` and the note's recorded
`locked_at` are passed in here, so a timelock "verified" means this mint
asserted its own clock - a custodial policy, not a consensus proof.
"""

import time
from dataclasses import dataclass

import lnurlcashkernel as kernel

from . import bech32m
from .signing import recover_note_pubkey, verify_legacy_ck1


@dataclass(frozen=True)
class ParsedK1:
    """A decoded `k1`: the note it names, and how to check it opens it."""

    note_id: str  # hex(Q)
    spend: kernel.Spend | None  # None only for a deprecated pre-schnorr ck1, already checked
    legacy_hash: str | None = None  # a bearer note's pre-taproot storage id, see legacy_hash


def decode_note(value: str) -> str | None:
    """hex(Q) of whatever was put where a `cp1` goes (a mint comment, p1/p2,
    ?p=): a `cp1`, or a bearer note's 64-hex `h` (short form). None if it is
    neither."""
    q = kernel.decode_note(value)
    return q.hex() if q is not None else None


def legacy_hash(value: str) -> str | None:
    """The 64-hex `h` itself if `value` is a bearer note's short form - the id
    such a note was stored under before notes were keyed by Q."""
    value = value.strip().lower()
    return value if len(value) == 64 and all(c in "0123456789abcdef" for c in value) else None


def _bearer_hash(spend: kernel.Spend) -> str | None:
    """`h` if `spend` is the canonical bearer note's spend (NUMS internal key,
    one `OP_SHA256 <h> OP_EQUAL` leaf), whatever its encoding."""
    if spend.key_path or spend.script is None or len(spend.script) != 35:
        return None
    image = spend.script[2:34]
    if spend.script != kernel.preimage_leaf(image) or spend.control_block != kernel.preimage_note(image)[1]:
        return None
    return image.hex()


def _legacy_note_id(k1: str) -> str | None:
    """TODO(deprecated): the pre-schnorr ck1 - a bare 65-byte recoverable
    signature, its note's key recovered rather than carried. Recovery IS the
    check here: the recovered key is the only note it can open."""
    signature = bech32m.decode_ck1_legacy(k1)
    if signature is None:
        return None
    try:
        return recover_note_pubkey(signature.hex()).hex()
    except ValueError:
        return None


def parse(k1: str) -> ParsedK1 | None:
    """The note `k1` claims to spend, or None if `k1` is no spend at all.
    Doesn't verify anything that needs the note's record; see verify."""
    spend = kernel.decode_spend(k1)
    if spend is None:
        legacy_id = _legacy_note_id(k1)
        return ParsedK1(legacy_id, None) if legacy_id is not None else None
    q = spend.output_key
    if q is None:
        return None
    return ParsedK1(q.hex(), spend, _bearer_hash(spend))


def verify(parsed: ParsedK1, locked_at: int, domains: list[str]) -> str | None:
    """None if `parsed` opens its note, else why not. `domains` are every
    host this mint answers on: a signature bound to any of them is this
    mint's. `locked_at` is when this mint credited the note (the start of a
    relative timelock).

    The reason is safe to hand back for a script path - a `cw1` discloses its
    whole secret already, so explaining its failure can't help anyone guess
    another - but a key-path failure only ever says "invalid", same as an
    unknown note."""
    spend = parsed.spend
    if spend is None:
        return None  # a deprecated recovered ck1: recovering the key was the check
    q = bytes.fromhex(parsed.note_id)
    now = int(time.time())
    reason = None
    for domain in domains:
        try:
            kernel.verify_spend(output_key=q, domain=domain, spend=spend, now=now, locked_at=locked_at)
            return None
        except kernel.SpendRejected as exc:
            reason = exc.reason
    if spend.key_path:
        # TODO(deprecated): a ck1 signed over the pre-sighash fixed message
        if verify_legacy_ck1(q, spend.witness[0]):
            return None
        return "Invalid or already spent k1."
    return reason
