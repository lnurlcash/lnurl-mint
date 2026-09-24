"""LUD-25 Seed & derivation - the SERVICE-side non-hardened tweak
(derivation.derive_pubkey), independent of any router/HTTP wiring."""

from coincurve import PrivateKey, PublicKeyXOnly

from lnurl_mint import derivation
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


# --- Cross-implementation check against ../luds/25.md's own published
# "Test Vectors" section --------------------------------------------------
#
# Everything above only self-checks against randomly-generated branch
# points - deterministic, but never against a value anything outside this
# file could reproduce. These vectors are the ones 25.md itself publishes
# (https://github.com/lnurl/luds/blob/lnurlcash/25.md#test-vectors),
# generated from and cross-checked against lnurl-wallet's own kit
# (src/lib/specVectors.test.ts asserts the exact same numbers against its
# deriveNotePubkey/deriveNoteSecretKey). If this mint's derive_pubkey ever
# disagrees with them, a note minted to a WALLET's branch under one
# implementation would silently be unfindable under the other - the two
# repos have no other way to catch that short of an end-to-end run against
# each other.
#
# Vector 1 and vector 2 deliberately land on opposite y-parities for their
# own branch key P (see 25.md's own vector intro) - between the two, this
# exercises both sides of the sk_i formula's parity branch, even though
# derive_pubkey itself (the SERVICE-side half) never needs sk_i or the
# parity check at all: PublicKeyXOnly.tweak_add's own lift_x handles
# whichever y the underlying point has internally.


def test_matches_lud25_spec_test_vector_1():
    """25.md "Test vector 1: Seed & derivation (branch root has odd-y P)" -
    BIP-32's own published "Test vector 1" seed, SERVICE domain
    mint.example. Index 5 is included (not just 0-2) because the vector
    itself does, to show i is a plain ser32(i) encode, not restricted to a
    contiguous run."""
    branch_point = bytes.fromhex("b783d2930dc053a971f019054ca43e7c9de50e0769de872dd1ddde5d0bf4c9d1")
    chain_code = bytes.fromhex("ab91cc11aea395ea6b62292a6147f51ef4150ebea04e745137b68719e238f904")
    expected_pk = {
        0: "aad3a0e36c083eb0d2d92ec0860977dc46d10c952f31830e6443b1faa1997634",
        1: "f0c1ea9aede945b9cf84f3bf8df27ac65154a937e4d10cb8a5865df0583b1083",
        2: "c1e51bc2b8ad1c6ecfe382fe201c322506e2783a2e4d3eae0da47fece2eab078",
        5: "c2b6a6d230d3ca51cc680bf84948c416eab70109542a0cf4fd1fbebbd647891a",
    }
    for index, pk_hex in expected_pk.items():
        assert derive_pubkey(branch_point, chain_code, index).hex() == pk_hex

    # t_0 explicitly, not just the final pk_0 - 25.md publishes it as
    # tagged_hash(...) mod n, but the raw tagged_hash output already
    # happens to be < n for this index (as for every index in both
    # vectors - see 25.md's own note on this), so it's numerically
    # identical to the mod-n-reduced value the spec shows
    t_0 = tagged_hash(b"LNURLcash/derive", branch_point + chain_code + (0).to_bytes(4, "big"))
    assert t_0.hex() == "10054a4025dc5678a26e16087703ac1af6be92dab9cc20f10c5a5ae0ffbd057c"


def test_matches_lud25_spec_test_vector_1_cx1_encoding():
    """cx1<P || chain_code> from the same vector, via this implementation's
    own bech32m encoder - confirms it agrees with the kit's @scure/base one
    byte-for-byte, not just the underlying point math."""
    from lnurl_mint.bech32m import encode_cx1

    branch_point = bytes.fromhex("b783d2930dc053a971f019054ca43e7c9de50e0769de872dd1ddde5d0bf4c9d1")
    chain_code = bytes.fromhex("ab91cc11aea395ea6b62292a6147f51ef4150ebea04e745137b68719e238f904")
    assert encode_cx1(branch_point + chain_code) == (
        "cx1k7pa9ycdcpf6ju0sryz5efp70jw72rs8d80gwtw3mh096zl5e8g6hywvzxh28902dd3zj2npgl63aaq4p6l2qnn52ymmdpceugu0jpqes280t"
    )


def test_matches_lud25_spec_test_vector_2():
    """25.md "Test vector 2: Seed & derivation (branch root has even-y P)" -
    BIP-32's own published "Test vector 2" seed, SERVICE domain
    cash.example.com."""
    branch_point = bytes.fromhex("64885a9cab93ec051761b8a0b80e1854a61865878d58f72a365dfd640850f675")
    chain_code = bytes.fromhex("6b95795f9807ada85c8ca50ec93c921483a183abfed4a3b4abe6b95c89880306")
    expected_pk = {
        0: "23bf26d94335b65e84b8383eb0a8baec8c32e2ebc561a204a386bb720b4cd130",
        1: "b1ab49e8ca397385ccb6d17d611bf8afc75390513bdcdfe3d760e0bb9860e0aa",
        2: "9cf00b60589f863cedd2773b42341e6f5102d6bd23d04559a3103d50611b2ada",
    }
    for index, pk_hex in expected_pk.items():
        assert derive_pubkey(branch_point, chain_code, index).hex() == pk_hex

    t_0 = tagged_hash(b"LNURLcash/derive", branch_point + chain_code + (0).to_bytes(4, "big"))
    assert t_0.hex() == "4d010c0ae5b4e0def5d0eb651d5e08de7fc36aef5703231480372b24688d2711"


def test_matches_lud25_spec_test_vector_2_cx1_encoding():
    from lnurl_mint.bech32m import encode_cx1

    branch_point = bytes.fromhex("64885a9cab93ec051761b8a0b80e1854a61865878d58f72a365dfd640850f675")
    chain_code = bytes.fromhex("6b95795f9807ada85c8ca50ec93c921483a183abfed4a3b4abe6b95c89880306")
    assert encode_cx1(branch_point + chain_code) == (
        "cx1vjy9489tj0kq29mphzstsrsc2jnpsev834v0w23kth7kgzzs7e6kh9tet7vq0tdgtjx22rkf8jfpfqapsw4la49rkj47dw2u3xyqxpspgvxpa"
    )


def test_a_tweak_hash_at_or_above_n_is_reduced_mod_n(monkeypatch):
    """25.md: t = tagged_hash(...) mod n. A hash >= n (~2^-128 of outputs,
    never hit naturally) must derive the same pk_i as its reduction, the way
    a WALLET computes it, rather than being refused."""
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    branch_point = PrivateKey().public_key.format(compressed=True)[1:]
    chain_code = bytes(32)
    reduced = 12345
    monkeypatch.setattr(derivation, "tagged_hash", lambda tag, msg: (n + reduced).to_bytes(32, "big"))
    above_n = derive_pubkey(branch_point, chain_code, 0)
    monkeypatch.setattr(derivation, "tagged_hash", lambda tag, msg: reduced.to_bytes(32, "big"))
    assert above_n == derive_pubkey(branch_point, chain_code, 0)
