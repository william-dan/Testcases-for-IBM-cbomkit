from __future__ import annotations

import os
from typing import List, Tuple, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac, constant_time
from cryptography.hazmat.primitives.asymmetric import (
    rsa,
    ec,
    padding as asym_padding,
    utils as asym_utils,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# ---------------------------------------------------------------------------
# Helper: safely construct algorithms that might not exist in this version
# ---------------------------------------------------------------------------

def _maybe_add_algorithm(
    algos: List[hashes.HashAlgorithm],
    name: str,
    digest_size: Optional[int] = None,
) -> None:
    """
    Try to add hashes.<name>(digest_size?) to `algos` if it exists and is usable.

    This avoids AttributeError on older cryptography versions (e.g. no SM3),
    and ValueError in case digest_size is unsupported.
    """
    cls = getattr(hashes, name, None)
    if cls is None:
        return
    try:
        if digest_size is None:
            algos.append(cls())
        else:
            algos.append(cls(digest_size))
    except Exception:
        # Unsupported by backend or wrong digest size
        return


def _get_algorithms_for(
    specs: List[Tuple[str, Optional[int]]],
) -> List[hashes.HashAlgorithm]:
    algos: List[hashes.HashAlgorithm] = []
    for name, size in specs:
        _maybe_add_algorithm(algos, name, size)
    return algos


# ---------------------------------------------------------------------------
# 1. List of all fixed-output hash algorithms & XOFs (SHAKE)
# ---------------------------------------------------------------------------

def get_all_fixed_hash_algorithms() -> List[hashes.HashAlgorithm]:
    """
    Return one instance of each *fixed-output* hash algorithm that exists
    in the current cryptography installation.
    """
    algos: List[hashes.HashAlgorithm] = []

    # SHA-2 family
    for name in ["SHA224", "SHA256", "SHA384", "SHA512",
                 "SHA512_224", "SHA512_256"]:
        _maybe_add_algorithm(algos, name)

    # BLAKE2
    _maybe_add_algorithm(algos, "BLAKE2b", 64)
    _maybe_add_algorithm(algos, "BLAKE2s", 32)

    # SHA-3 family
    for name in ["SHA3_224", "SHA3_256", "SHA3_384", "SHA3_512"]:
        _maybe_add_algorithm(algos, name)

    # Legacy / compatibility
    for name in ["SHA1", "MD5"]:
        _maybe_add_algorithm(algos, name)

    # SM3 (may not exist in older versions)
    _maybe_add_algorithm(algos, "SM3")

    return algos


def get_xof_algorithms() -> List[hashes.HashAlgorithm]:
    """
    Return SHAKE128/SHAKE256 instances (XOFs) if available.
    We choose digest_size=64 as a convenient example limit.
    """
    return _get_algorithms_for([
        ("SHAKE128", 64),
        ("SHAKE256", 64),
    ])


# ---------------------------------------------------------------------------
# 2. Basic message digests with Hash
# ---------------------------------------------------------------------------

def compute_digest(algorithm: hashes.HashAlgorithm, data_chunks: List[bytes]) -> bytes:
    """
    Incrementally compute a digest using hashes.Hash(algorithm).
    """
    digest = hashes.Hash(algorithm)
    for chunk in data_chunks:
        digest.update(chunk)
    return digest.finalize()


def demo_all_hashes_basic() -> None:
    print("=== Basic hashing: all fixed-output algorithms ===")
    data_chunks = [b"dynamic ", b"CBOM ", b"hash demo"]

    algos = get_all_fixed_hash_algorithms()
    if not algos:
        print("No fixed-output hash algorithms available; something is very wrong.")
        return

    for algo in algos:
        digest = compute_digest(algo, data_chunks)
        print(f"{algo.name:<12} ({algo.digest_size} bytes) -> {digest.hex()[:32]}...")

    # Show copy() / finalize() behavior on SHA256
    algo = hashes.SHA256()
    ctx = hashes.Hash(algo)
    ctx.update(b"prefix")
    ctx_copy = ctx.copy()          # snapshot
    ctx.update(b" more")

    full_digest = ctx.finalize()
    prefix_digest = ctx_copy.finalize()
    print("SHA256 full   :", full_digest.hex())
    print("SHA256 prefix :", prefix_digest.hex())


# ---------------------------------------------------------------------------
# 3. XOFs / SHAKE128 / SHAKE256 (with and without XOFHash)
# ---------------------------------------------------------------------------

def demo_xofs() -> None:
    print("\n=== XOF / SHAKE demo ===")

    algos = get_xof_algorithms()
    if not algos:
        print("SHAKE128/SHAKE256 not available in this cryptography version; skipping.")
        return

    message = b"XOF demo for dynamic CBOM"
    xofhash_cls = getattr(hashes, "XOFHash", None)

    for algo in algos:
        if xofhash_cls is not None:
            # Newer cryptography versions: full XOFHash interface
            xof = xofhash_cls(algo)
            xof.update(message)
            out1 = xof.squeeze(16)
            out2 = xof.squeeze(16)
            print(
                f"{algo.name} via XOFHash -> "
                f"squeeze1 {out1.hex()}..., squeeze2 {out2.hex()}..."
            )
        else:
            # Older versions: use Hash(SHAKE*) as a fixed-length digest
            ctx = hashes.Hash(algo)
            ctx.update(message)
            digest = ctx.finalize()
            print(
                f"{algo.name} via Hash (no XOFHash in this version) -> "
                f"{len(digest)} bytes: {digest.hex()[:32]}..."
            )


# ---------------------------------------------------------------------------
# 4. HMAC with various hashes
# ---------------------------------------------------------------------------

def hmac_sign(
    key: bytes,
    algorithm: hashes.HashAlgorithm,
    message: bytes,
) -> bytes:
    """
    Compute HMAC(tag) = HMAC_(key, algo)(message).
    """
    h = hmac.HMAC(key, algorithm)
    h.update(message)
    return h.finalize()


def hmac_verify(
    key: bytes,
    algorithm: hashes.HashAlgorithm,
    message: bytes,
    tag: bytes,
) -> bool:
    """
    Verify HMAC, using constant-time comparison via verify().
    """
    h = hmac.HMAC(key, algorithm)
    h.update(message)
    try:
        h.verify(tag)
        return True
    except InvalidSignature:
        return False


def demo_hmac_all_hashes() -> None:
    print("\n=== HMAC demo: iterate over all fixed-output hashes ===")
    message = b"HMAC over dynamic CBOM event"
    key = os.urandom(32)

    algos = get_all_fixed_hash_algorithms()
    for algo in algos:
        tag = hmac_sign(key, algo, message)
        ok = hmac_verify(key, algo, message, tag)
        print(f"HMAC-{algo.name:<10} verify:", ok)

    # Show copy() reuse pattern
    algo = hashes.SHA256()
    h = hmac.HMAC(key, algo)
    h.update(b"part1-")
    h_copy = h.copy()
    h.update(b"part2")
    tag_full = h.finalize()
    print("HMAC-SHA256 full tag    :", tag_full.hex()[:32], "...")

    # Use copy for alternate finalization
    h_copy.update(b"ALT")
    tag_alt = h_copy.finalize()
    print("HMAC-SHA256 alternate tag:", tag_alt.hex()[:32], "...")


# ---------------------------------------------------------------------------
# 5. Hash-based KDFs: PBKDF2HMAC and HKDF
# ---------------------------------------------------------------------------

def demo_pbkdf2_with_various_hashes() -> None:
    print("\n=== PBKDF2HMAC demo with multiple hashes ===")
    password = b"Tr0ub4dor&3"
    salt = os.urandom(16)
    iterations = 200_000

    algos = _get_algorithms_for([
        ("SHA256", None),
        ("SHA512", None),
        ("SHA3_256", None),
        ("BLAKE2b", 64),
    ])
    if not algos:
        print("No suitable hash algorithms available for PBKDF2 demo; skipping.")
        return

    for algo in algos:
        kdf = PBKDF2HMAC(
            algorithm=algo,
            length=32,
            salt=salt,
            iterations=iterations,
        )
        key = kdf.derive(password)
        print(f"PBKDF2HMAC-{algo.name:<10} -> {key.hex()[:32]}...")

        # verify() style usage
        kdf_verify = PBKDF2HMAC(
            algorithm=algo,
            length=32,
            salt=salt,
            iterations=iterations,
        )
        kdf_verify.verify(password, key)  # raises if mismatch
        print(f"PBKDF2HMAC-{algo.name:<10} verify: OK")


def demo_hkdf_with_various_hashes() -> None:
    print("\n=== HKDF demo with multiple hashes ===")
    ikm = os.urandom(48)  # input key material

    algos = _get_algorithms_for([
        ("SHA256", None),
        ("SHA384", None),
        ("SHA512", None),
        ("SM3", None),     # optional, may be skipped
    ])
    if not algos:
        print("No suitable hash algorithms available for HKDF demo; skipping.")
        return

    for algo in algos:
        hkdf = HKDF(
            algorithm=algo,
            length=32,
            salt=os.urandom(16),
            info=b"dynamic-cbom-hkdf",
        )
        okm = hkdf.derive(ikm)
        print(f"HKDF-{algo.name:<10} -> {okm.hex()[:32]}...")


# ---------------------------------------------------------------------------
# 6. Hashes inside RSA/ECDSA signatures (including Prehashed)
# ---------------------------------------------------------------------------

def generate_rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def generate_ec_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def sign_rsa(
    private_key: rsa.RSAPrivateKey,
    message: bytes,
    algorithm: hashes.HashAlgorithm,
) -> bytes:
    return private_key.sign(
        message,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(algorithm),
            salt_length=asym_padding.PSS.MAX_LENGTH,
        ),
        algorithm,
    )


def verify_rsa(
    public_key: rsa.RSAPublicKey,
    message: bytes,
    signature: bytes,
    algorithm: hashes.HashAlgorithm,
) -> bool:
    try:
        public_key.verify(
            signature,
            message,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(algorithm),
                salt_length=asym_padding.PSS.MAX_LENGTH,
            ),
            algorithm,
        )
        return True
    except InvalidSignature:
        return False


def sign_ecdsa(
    private_key: ec.EllipticCurvePrivateKey,
    message: bytes,
    algorithm: hashes.HashAlgorithm,
) -> bytes:
    return private_key.sign(
        message,
        ec.ECDSA(algorithm),
    )


def verify_ecdsa(
    public_key: ec.EllipticCurvePublicKey,
    message: bytes,
    signature: bytes,
    algorithm: hashes.HashAlgorithm,
) -> bool:
    try:
        public_key.verify(
            signature,
            message,
            ec.ECDSA(algorithm),
        )
        return True
    except InvalidSignature:
        return False


def demo_signatures_with_hashes() -> None:
    print("\n=== Signatures with various hash algorithms ===")

    message = b"long message to sign for dynamic CBOM hashing demo"
    rsa_priv = generate_rsa_key()
    rsa_pub = rsa_priv.public_key()

    ec_priv = generate_ec_key()
    ec_pub = ec_priv.public_key()

    algorithms_for_sig = _get_algorithms_for([
        ("SHA256", None),
        ("SHA384", None),
        ("SHA512", None),
        ("SHA3_256", None),
        ("SHA3_512", None),
        ("SM3", None),    # optional
        ("SHA1", None),   # legacy
    ])
    if not algorithms_for_sig:
        print("No signature hash algorithms available; skipping.")
        return

    for algo in algorithms_for_sig:
        sig_rsa = sign_rsa(rsa_priv, message, algo)
        sig_ok = verify_rsa(rsa_pub, message, sig_rsa, algo)
        print(f"RSA-PSS with {algo.name:<8} -> verify: {sig_ok}")

        sig_ec = sign_ecdsa(ec_priv, message, algo)
        sig_ec_ok = verify_ecdsa(ec_pub, message, sig_ec, algo)
        print(f"ECDSA   with {algo.name:<8} -> verify: {sig_ec_ok}")

    # Prehashed example (hash done externally, then signed)
    print("\n--- Prehashed ECDSA example (SHA-512) ---")
    digest_ctx = hashes.Hash(hashes.SHA512())
    digest_ctx.update(message)
    digest = digest_ctx.finalize()

    prehashed = asym_utils.Prehashed(hashes.SHA512())
    sig_prehashed = ec_priv.sign(digest, ec.ECDSA(prehashed))

    try:
        ec_pub.verify(sig_prehashed, digest, ec.ECDSA(prehashed))
        print("ECDSA Prehashed(SHA-512) verify: OK")
    except InvalidSignature:
        print("ECDSA Prehashed(SHA-512) verify: FAIL")


# ---------------------------------------------------------------------------
# 7. Constant-time comparison for digests
# ---------------------------------------------------------------------------

def demo_constant_time_compare() -> None:
    print("\n=== Constant-time digest comparison ===")

    algo = hashes.SHA256()
    d1 = compute_digest(algo, [b"same message"])
    d2 = compute_digest(algo, [b"same message"])
    d3 = compute_digest(algo, [b"slightly different"])

    print("d1 vs d2 (same):", constant_time.bytes_eq(d1, d2))
    print("d1 vs d3 (diff):", constant_time.bytes_eq(d1, d3))


# ---------------------------------------------------------------------------
# Main entrypoint
# ---------------------------------------------------------------------------

def run_all_hash_demos() -> None:
    demo_all_hashes_basic()
    demo_xofs()
    demo_hmac_all_hashes()
    demo_pbkdf2_with_various_hashes()
    demo_hkdf_with_various_hashes()
    demo_signatures_with_hashes()
    demo_constant_time_compare()


if __name__ == "__main__":
    run_all_hash_demos()
