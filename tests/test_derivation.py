"""LUD-25 Part 2, Seed & derivation - the SERVICE-side non-hardened tweak
(derivation.derive_pubkey), independent of any router/HTTP wiring."""

from coincurve import PrivateKey, PublicKeyXOnly

from lnurl_mint.derivation import derive_pubkey, tagged_hash


def _branch() -> tuple[bytes, bytes]:
    sk = PrivateKey()
    branch_point = sk.public_key.format(compressed=True)[1:]
    return branch_point, sk.secret  # secret doubles as a valid 32-byte chain code here


def test_derive_pubkey_is_deterministic():
    branch_point, chain_code = _branch()
    assert derive_pubkey(branch_point, chain_code, 0) == derive_pubkey(branch_point, chain_code, 0)


def test_different_indices_give_different_keys():
    branch_point, chain_code = _branch()
    keys = {derive_pubkey(branch_point, chain_code, i) for i in range(10)}
    assert len(keys) == 10


def test_different_branches_give_different_keys_at_the_same_index():
    branch_point_a, chain_code_a = _branch()
    branch_point_b, chain_code_b = _branch()
    assert derive_pubkey(branch_point_a, chain_code_a, 0) != derive_pubkey(branch_point_b, chain_code_b, 0)


def test_output_is_a_valid_32_byte_xonly_point():
    branch_point, chain_code = _branch()
    pk = derive_pubkey(branch_point, chain_code, 0)
    assert len(pk) == 32
    # round-trips through PublicKeyXOnly without raising - a genuinely
    # invalid x-coordinate would fail to construct/format here
    assert PublicKeyXOnly(pk).format() == pk


def test_matches_manual_bip340_tweak():
    """Cross-checks derive_pubkey's use of PublicKeyXOnly.tweak_add against
    an independently computed tagged hash, confirming the message layout
    (P || chain_code || index) and the tweak-add step actually match
    25.md's algorithm rather than some other combination."""
    branch_point, chain_code = _branch()
    index = 7
    expected_tweak = tagged_hash(b"LNURLcash/derive", branch_point + chain_code + index.to_bytes(4, "big"))
    manual = PublicKeyXOnly(branch_point)
    manual.tweak_add(expected_tweak)
    assert derive_pubkey(branch_point, chain_code, index) == manual.format()


def test_rejects_wrong_length_inputs():
    branch_point, chain_code = _branch()
    try:
        derive_pubkey(branch_point[:-1], chain_code, 0)
        raised = False
    except ValueError:
        raised = True
    assert raised
    try:
        derive_pubkey(branch_point, chain_code + b"\x00", 0)
        raised = False
    except ValueError:
        raised = True
    assert raised


def test_tagged_hash_matches_bip340_reference():
    """BIP-340's own worked example for tagged_hash("BIP0340/challenge", ...)
    isn't reused here (different tag), so this instead checks tagged_hash's
    structural definition directly: sha256(sha256(tag)*2 || msg)."""
    from hashlib import sha256

    tag = b"LNURLcash/derive"
    msg = b"hello"
    expected = sha256(sha256(tag).digest() + sha256(tag).digest() + msg).digest()
    assert tagged_hash(tag, msg) == expected
