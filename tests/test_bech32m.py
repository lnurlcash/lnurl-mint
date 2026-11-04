"""LUD-25's Encoding: this mint's own bech32m (BIP-350) codec, for cp1/cs1/cx1
and the deprecated ck1 shape. Current ck1/cw1 spends are decoded by
lnurlcashkernel (see spend.py)."""

from os import urandom

import pytest
from coincurve import PrivateKey

from lnurl_mint import bech32m


def test_bip350_valid_vectors_decode():
    """A handful of BIP-350's own test vectors, decoded generically (not
    through a fixed-length wrapper) to confirm the checksum/charset/HRP
    logic itself matches the spec, independent of this repo's own
    fixed-length prefixes."""
    assert bech32m.decode("a", "a1lqfn3a") == b""
    assert (
        bech32m.decode("abcdef", "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx").hex()
        == "ffbbcdeb38bdab49ca307b9ac5a928398a418820"
    )


def test_bip173_bech32_vector_is_rejected_as_bech32m():
    """A valid classic-bech32 (not bech32m) checksum must fail here - the
    two use different constants (BECH32M_CONST vs bech32's 1), and mixing
    them up would silently accept the wrong encoding."""
    assert bech32m.decode("a", "A12UEL5L") is None


@pytest.mark.parametrize(
    "encode,decode,length",
    [
        (bech32m.encode_cp1, bech32m.decode_cp1, 32),
        (bech32m.encode_legacy_cx1, bech32m.decode_legacy_cx1, 64),
        (bech32m.encode_cx1, bech32m.decode_cx1, 65),
    ],
)
def test_roundtrip(encode, decode, length):
    data = _cx1_payload() if length == 65 else urandom(length)
    encoded = encode(data)
    assert decode(encoded) == data


def _cx1_payload() -> bytes:
    """chain_code || P: a cx1 decodes only when P is a compressed point."""
    return urandom(32) + PrivateKey().public_key.format(compressed=True)


def _cs1_payload() -> bytes:
    """r || s || recovery-id: a cs1 decodes only with a recovery id 0-3."""
    return urandom(64) + bytes([urandom(1)[0] % 4])


def test_a_cx1_whose_p_is_no_point_or_the_old_shape_is_refused():
    p = PrivateKey().public_key.format(compressed=True)
    assert bech32m.decode_cx1(bech32m.encode_cx1(urandom(32) + b"\x04" + p[1:])) is None
    assert bech32m.decode_cx1(bech32m.encode_cx1(urandom(32) + b"\x02" + b"\xff" * 32)) is None
    assert bech32m.decode_cx1(bech32m.encode_legacy_cx1(urandom(64))) is None


def test_a_cs1_with_a_recovery_id_above_3_is_refused():
    assert bech32m.decode_cs1(bech32m.encode_cs1(1000, urandom(64) + b"\x04")) is None


@pytest.mark.parametrize("amount_msat", [0, 1, 1000, 21000, 5000, 100_000_000])
def test_cs1_roundtrip_carries_the_amount_in_its_hrp(amount_msat):
    """cs1, unlike its siblings, folds amount_msat into its own HRP (BOLT-11
    style) rather than needing it supplied alongside the certificate - see
    25.md's Encoding."""
    sig = _cs1_payload()
    encoded = bech32m.encode_cs1(amount_msat, sig)
    assert encoded.startswith("cs")
    assert bech32m.decode_cs1(encoded) == (amount_msat, sig)


def test_encoded_lengths_match_the_spec():
    """25.md's Encoding section states each prefix's exact total length."""
    assert len(bech32m.encode_cp1(urandom(32))) == 61
    assert len(bech32m.encode_cx1(_cx1_payload())) == 113
    # cs1's total length is no longer fixed - it grows with the number of
    # digits its amount needs (its HRP is "cs" + amount + multiplier, see
    # encode_cs1) - but the example the spec itself gives, "cs10n<...>" for
    # 1000 msat, is exactly 116 characters: 5-char HRP + 1-char separator +
    # 104 data symbols + 6-char checksum.
    assert len(bech32m.encode_cs1(1000, urandom(65))) == 116


def test_wrong_length_raises_on_encode():
    with pytest.raises(ValueError):
        bech32m.encode_cp1(urandom(31))
    with pytest.raises(ValueError):
        bech32m.encode_cx1(urandom(64))


def test_wrong_hrp_is_rejected():
    assert bech32m.decode_cp1(bech32m.encode_cx1(_cx1_payload())) is None
    assert bech32m.decode_cp1(bech32m.encode("ck", urandom(32))) is None


def test_corrupted_checksum_is_rejected():
    cp1 = bech32m.encode_cp1(urandom(32))
    last = cp1[-1]
    replacement = "q" if last != "q" else "p"
    corrupted = cp1[:-1] + replacement
    assert bech32m.decode_cp1(corrupted) is None


def test_exceeds_bip173_length_limit_but_still_decodes():
    """25.md explicitly departs from BIP-173's ~90-character segwit-address
    cap for cs1/cx1 (116/113 chars) - bech32_decode from the `bech32`
    dependency enforces that cap and would reject these, which is exactly
    why bech32m.decode reimplements the length check itself."""
    cx1 = bech32m.encode_cx1(_cx1_payload())
    assert len(cx1) > 90
    assert bech32m.decode_cx1(cx1) is not None


def test_garbage_input_returns_none_not_raises():
    assert bech32m.decode_cp1("not even bech32") is None
    assert bech32m.decode_cp1("") is None
    assert bech32m.decode_cp1("cp1") is None
