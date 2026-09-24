"""LUD-25 notes and spends.

Every note is a BIP-341 taproot output key Q, stored under hex(Q). Every `k1`
a redeemer presents is a spend of one: a `ck1` (key path), a `cw1` (script
path), or the 64-hex preimage of a bearer note, the short form of that note's
`cw1`. Decoding and verification are Bitcoin Core's own, via
`lnurlcashkernel`; this module only adds what is specific to this mint:
which domains a signature may be bound to (every host this mint answers on).

Time is the one thing the kernel never decides: `now` and the note's recorded
`locked_at` are passed in here, so a timelock "verified" means this mint
asserted its own clock - a custodial policy, not a consensus proof.
"""

import time
from dataclasses import dataclass

import lnurlcashkernel as kernel


@dataclass(frozen=True)
class ParsedK1:
    """A decoded `k1`: the note it names, and how to check it opens it."""

    note_id: str  # hex(Q)
    spend: kernel.Spend


def decode_note(value: str) -> str | None:
    """hex(Q) of whatever was put where a `cp1` goes (a mint comment, p1/p2,
    ?p=): a `cp1`, or a bearer note's 64-hex `h` (short form). None if it is
    neither."""
    q = kernel.decode_note(value)
    return q.hex() if q is not None else None


def parse(k1: str) -> ParsedK1 | None:
    """The note `k1` claims to spend, or None if `k1` is no spend at all.
    Doesn't verify anything that needs the note's record; see verify."""
    spend = kernel.decode_spend(k1)
    q = spend.output_key if spend is not None else None
    if spend is None or q is None:
        return None
    return ParsedK1(q.hex(), spend)


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
        return "Invalid or already spent k1."
    return reason
