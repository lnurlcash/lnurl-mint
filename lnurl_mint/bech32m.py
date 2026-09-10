from bech32 import CHARSET, bech32_hrp_expand, bech32_polymod, convertbits

# LUD-25 Part 2 Encoding: cp1/ck1/cs1/cx1 are BIP-350 bech32m (not classic
# bech32 - that's LUD-01's `lnurl_encode` in frontend.py, a different
# checksum constant), each under its own 2-char HRP. The `bech32` dependency
# (already used there) only exposes classic bech32 checksums directly, but
# does export the primitives (bech32_hrp_expand, bech32_polymod, CHARSET,
# convertbits) a bech32m checksum is built from - see BIP-350's reference
# implementation, which this mirrors.
#
# bech32_decode from that same package can't be reused here either: it caps
# the total string at ~90 characters (BIP-173's segwit-address limit). Per
# 25.md's Encoding section, ck1/cs1/cx1 all deliberately exceed that - "the
# same departure BOLT-11 invoices already make from the same base encoding"
# - so decode() below re-implements the length/charset checks without it.
BECH32M_CONST = 0x2BC830A3


def _create_checksum(hrp: str, data: list[int]) -> list[int]:
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ BECH32M_CONST
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def _verify_checksum(hrp: str, data: list[int]) -> bool:
    return bech32_polymod(bech32_hrp_expand(hrp) + data) == BECH32M_CONST


def encode(hrp: str, data: bytes) -> str:
    """bech32m-encode `data` under `hrp` (e.g. "cp", "ck", "cs", "cx") - no
    witness-version byte, unlike a segwit address: just the HRP, separator,
    and raw data, per 25.md's Encoding section."""
    values = convertbits(data, 8, 5, True)
    assert values is not None
    combined = values + _create_checksum(hrp, values)
    return hrp + "1" + "".join(CHARSET[d] for d in combined)


def decode(hrp: str, s: str) -> bytes | None:
    """Inverse of encode(). None on any malformed input - wrong HRP, wrong
    checksum, non-charset characters, mixed case, or a non-byte-aligned
    payload - never raises, so callers can treat it like HEX32_PATTERN's
    match/no-match gate."""
    if any(ord(c) < 33 or ord(c) > 126 for c in s):
        return None
    if s.lower() != s and s.upper() != s:
        return None
    s = s.lower()
    pos = s.rfind("1")
    if pos < 1 or pos + 7 > len(s):
        return None
    found_hrp, data_part = s[:pos], s[pos + 1 :]
    if found_hrp != hrp or not all(c in CHARSET for c in data_part):
        return None
    data = [CHARSET.find(c) for c in data_part]
    if not _verify_checksum(found_hrp, data):
        return None
    decoded = convertbits(data[:-6], 5, 8, False)
    if decoded is None:
        return None
    return bytes(decoded)


def _fixed_length_codec(hrp: str, length: int) -> tuple:
    def enc(data: bytes) -> str:
        if len(data) != length:
            raise ValueError(f"{hrp}1... payload must be {length} bytes, got {len(data)}")
        return encode(hrp, data)

    def dec(s: str) -> bytes | None:
        data = decode(hrp, s)
        return data if data is not None and len(data) == length else None

    return enc, dec


# cp1<pk>: a 32-byte x-only secp256k1 public key (BIP-340) - a note's public
# commitment, in place of Part 1's hash-of-preimage.
encode_cp1, decode_cp1 = _fixed_length_codec("cp", 32)
# ck1<sig>: a 65-byte recoverable ECDSA signature (r || s || recovery-id) -
# the bearer secret for a cp1 note, submitted in place of a revealed k1.
encode_ck1, decode_ck1 = _fixed_length_codec("ck", 65)
# cs1<sig>: the same 65-byte shape, produced by SERVICE instead - an
# issuance certificate, never a spend authorization on its own.
encode_cs1, decode_cs1 = _fixed_length_codec("cs", 65)
# cx1<P || chaincode>: a 64-byte watch-only export of a WALLET's derivation
# branch for one SERVICE - never appears in a mint interaction itself, only
# on /register.
encode_cx1, decode_cx1 = _fixed_length_codec("cx", 64)
