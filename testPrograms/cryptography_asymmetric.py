from __future__ import annotations

import os
from typing import Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import (
    rsa,
    dsa,
    dh,
    ec,
    ed25519,
    ed448,
    x25519,
    x448,
    padding,
)


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------



def hkdf_sha256_32_bytes(shared_secret: bytes, salt: bytes | None, info: bytes) -> bytes:
    """Derive a 32-byte key from a shared secret using HKDF-SHA256."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    )
    return hkdf.derive(shared_secret)


def serialize_private_key_pem(
    private_key,
    password: bytes | None = None,
) -> bytes:
    """Serialize any asymmetric private key to PEM (PKCS8)."""
    if password is None:
        enc_alg = serialization.NoEncryption()
    else:
        enc_alg = serialization.BestAvailableEncryption(password)

    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc_alg,
    )


def serialize_public_key_pem(public_key) -> bytes:
    """Serialize any asymmetric public key to PEM."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


# ---------------------------------------------------------------------------
# RSA: keygen, serialization, sign/verify, encrypt/decrypt
# ---------------------------------------------------------------------------

def rsa_generate_keys(key_size: int = 2048) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    return private_key, private_key.public_key()


def rsa_sign(private_key: rsa.RSAPrivateKey, message: bytes) -> bytes:
    """Sign using RSA-PSS + SHA256."""
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return signature


def rsa_verify(public_key: rsa.RSAPublicKey, message: bytes, signature: bytes) -> bool:
    """Verify RSA-PSS + SHA256 signature."""
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


def rsa_encrypt(public_key: rsa.RSAPublicKey, plaintext: bytes) -> bytes:
    """Encrypt small message with RSA-OAEP + SHA256."""
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return ciphertext


def rsa_decrypt(private_key: rsa.RSAPrivateKey, ciphertext: bytes) -> bytes:
    """Decrypt RSA-OAEP + SHA256 ciphertext."""
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return plaintext


def rsa_demo() -> None:
    print("=== RSA demo ===")
    private_key, public_key = rsa_generate_keys()
    msg = b"RSA demo message"

    sig = rsa_sign(private_key, msg)
    print("RSA signature valid:", rsa_verify(public_key, msg, sig))

    ct = rsa_encrypt(public_key, msg)
    pt = rsa_decrypt(private_key, ct)
    print("RSA decrypted == original:", pt == msg)

    pem_priv = serialize_private_key_pem(private_key, password=b"secret")
    pem_pub = serialize_public_key_pem(public_key)
    print("RSA private PEM length:", len(pem_priv))
    print("RSA public PEM length:", len(pem_pub))


# ---------------------------------------------------------------------------
# DSA: legacy signatures
# ---------------------------------------------------------------------------

def dsa_generate_keys(key_size: int = 2048) -> Tuple[dsa.DSAPrivateKey, dsa.DSAPublicKey]:
    private_key = dsa.generate_private_key(key_size=key_size)
    return private_key, private_key.public_key()


def dsa_sign(private_key: dsa.DSAPrivateKey, message: bytes) -> bytes:
    signature = private_key.sign(
        message,
        hashes.SHA256(),
    )
    return signature


def dsa_verify(public_key: dsa.DSAPublicKey, message: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(
            signature,
            message,
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


def dsa_demo() -> None:
    print("\n=== DSA demo ===")
    private_key, public_key = dsa_generate_keys()
    msg = b"DSA message"

    sig = dsa_sign(private_key, msg)
    print("DSA signature valid:", dsa_verify(public_key, msg, sig))

    pem_priv = serialize_private_key_pem(private_key)
    pem_pub = serialize_public_key_pem(public_key)
    print("DSA private PEM length:", len(pem_priv))
    print("DSA public PEM length:", len(pem_pub))


# ---------------------------------------------------------------------------
# Finite-field DH: parameters, key pairs, key exchange + HKDF
# ---------------------------------------------------------------------------

def dh_generate_parameters(key_size: int = 2048) -> dh.DHParameters:
    return dh.generate_parameters(generator=2, key_size=key_size)


def dh_generate_key_pair(parameters: dh.DHParameters) -> Tuple[dh.DHPrivateKey, dh.DHPublicKey]:
    priv = parameters.generate_private_key()
    return priv, priv.public_key()


def dh_compute_shared_secret(
    private_key: dh.DHPrivateKey,
    peer_public_key: dh.DHPublicKey,
) -> bytes:
    return private_key.exchange(peer_public_key)


def dh_demo() -> None:
    print("\n=== DH demo ===")
    params = dh_generate_parameters()

    # Alice
    alice_priv, alice_pub = dh_generate_key_pair(params)
    # Bob
    bob_priv, bob_pub = dh_generate_key_pair(params)

    # Both sides compute shared secret
    shared_a = dh_compute_shared_secret(alice_priv, bob_pub)
    shared_b = dh_compute_shared_secret(bob_priv, alice_pub)
    print("DH shared secret matches:", shared_a == shared_b)

    # Derive 32-byte key using HKDF
    salt = os.urandom(16)
    info = b"dh-demo-info"
    key_a = hkdf_sha256_32_bytes(shared_a, salt, info)
    key_b = hkdf_sha256_32_bytes(shared_b, salt, info)
    print("DH derived key matches:", key_a == key_b)


# ---------------------------------------------------------------------------
# EC (classical): ECDSA signatures and ECDH key exchange
# ---------------------------------------------------------------------------

def ec_generate_keys(curve: ec.EllipticCurve = ec.SECP256R1()
                     ) -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    priv = ec.generate_private_key(curve)
    return priv, priv.public_key()


def ecdsa_sign(private_key: ec.EllipticCurvePrivateKey, message: bytes) -> bytes:
    signature = private_key.sign(
        message,
        ec.ECDSA(hashes.SHA256()),
    )
    return signature


def ecdsa_verify(public_key: ec.EllipticCurvePublicKey, message: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(
            signature,
            message,
            ec.ECDSA(hashes.SHA256()),
        )
        return True
    except InvalidSignature:
        return False


def ecdh_compute_shared_secret(
    private_key: ec.EllipticCurvePrivateKey,
    peer_public_key: ec.EllipticCurvePublicKey,
) -> bytes:
    return private_key.exchange(ec.ECDH(), peer_public_key)


def ec_demo() -> None:
    print("\n=== EC (ECDSA + ECDH) demo ===")

    # ECDSA
    priv, pub = ec_generate_keys(ec.SECP256R1())
    msg = b"EC message"
    sig = ecdsa_sign(priv, msg)
    print("ECDSA signature valid:", ecdsa_verify(pub, msg, sig))

    pem_priv = serialize_private_key_pem(priv)
    pem_pub = serialize_public_key_pem(pub)
    print("EC private PEM length:", len(pem_priv))
    print("EC public PEM length:", len(pem_pub))

    # ECDH
    alice_priv, alice_pub = ec_generate_keys(ec.SECP256R1())
    bob_priv, bob_pub = ec_generate_keys(ec.SECP256R1())

    shared_a = ecdh_compute_shared_secret(alice_priv, bob_pub)
    shared_b = ecdh_compute_shared_secret(bob_priv, alice_pub)
    print("ECDH shared secret matches:", shared_a == shared_b)

    key_a = hkdf_sha256_32_bytes(shared_a, salt=None, info=b"ecdh-demo")
    key_b = hkdf_sha256_32_bytes(shared_b, salt=None, info=b"ecdh-demo")
    print("ECDH derived key matches:", key_a == key_b)


# ---------------------------------------------------------------------------
# Ed25519 / Ed448: modern signature-only schemes
# ---------------------------------------------------------------------------

def ed25519_generate_keys() -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    priv = ed25519.Ed25519PrivateKey.generate()
    return priv, priv.public_key()


def ed25519_sign(private_key: ed25519.Ed25519PrivateKey, message: bytes) -> bytes:
    return private_key.sign(message)


def ed25519_verify(public_key: ed25519.Ed25519PublicKey, message: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(signature, message)
        return True
    except InvalidSignature:
        return False


def ed448_generate_keys() -> Tuple[ed448.Ed448PrivateKey, ed448.Ed448PublicKey]:
    priv = ed448.Ed448PrivateKey.generate()
    return priv, priv.public_key()


def ed448_sign(private_key: ed448.Ed448PrivateKey, message: bytes) -> bytes:
    return private_key.sign(message)


def ed448_verify(public_key: ed448.Ed448PublicKey, message: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(signature, message)
        return True
    except InvalidSignature:
        return False


def eddsa_demo() -> None:
    print("\n=== Ed25519 / Ed448 demo ===")
    msg = b"EdDSA message"

    # Ed25519
    priv_25519, pub_25519 = ed25519_generate_keys()
    sig_25519 = ed25519_sign(priv_25519, msg)
    print("Ed25519 signature valid:", ed25519_verify(pub_25519, msg, sig_25519))

    # RAW encoding
    raw_priv_25519 = priv_25519.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    raw_pub_25519 = pub_25519.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    print("Ed25519 raw private length:", len(raw_priv_25519))
    print("Ed25519 raw public length:", len(raw_pub_25519))

    # Ed448
    priv_448, pub_448 = ed448_generate_keys()
    sig_448 = ed448_sign(priv_448, msg)
    print("Ed448 signature valid:", ed448_verify(pub_448, msg, sig_448))

    raw_priv_448 = priv_448.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    raw_pub_448 = pub_448.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    print("Ed448 raw private length:", len(raw_priv_448))
    print("Ed448 raw public length:", len(raw_pub_448))


# ---------------------------------------------------------------------------
# X25519 / X448: modern key-agreement (ECDH-like)
# ---------------------------------------------------------------------------

def x25519_generate_keys() -> Tuple[x25519.X25519PrivateKey, x25519.X25519PublicKey]:
    priv = x25519.X25519PrivateKey.generate()
    return priv, priv.public_key()


def x448_generate_keys() -> Tuple[x448.X448PrivateKey, x448.X448PublicKey]:
    priv = x448.X448PrivateKey.generate()
    return priv, priv.public_key()


def x25519_compute_shared_secret(
    private_key: x25519.X25519PrivateKey,
    peer_public_key: x25519.X25519PublicKey,
) -> bytes:
    return private_key.exchange(peer_public_key)


def x448_compute_shared_secret(
    private_key: x448.X448PrivateKey,
    peer_public_key: x448.X448PublicKey,
) -> bytes:
    return private_key.exchange(peer_public_key)


def xdh_demo() -> None:
    print("\n=== X25519 / X448 demo ===")

    # X25519
    a_priv_25519, a_pub_25519 = x25519_generate_keys()
    b_priv_25519, b_pub_25519 = x25519_generate_keys()

    shared_a_25519 = x25519_compute_shared_secret(a_priv_25519, b_pub_25519)
    shared_b_25519 = x25519_compute_shared_secret(b_priv_25519, a_pub_25519)
    print("X25519 shared secret matches:", shared_a_25519 == shared_b_25519)

    key_a_25519 = hkdf_sha256_32_bytes(shared_a_25519, salt=None, info=b"x25519-demo")
    key_b_25519 = hkdf_sha256_32_bytes(shared_b_25519, salt=None, info=b"x25519-demo")
    print("X25519 derived key matches:", key_a_25519 == key_b_25519)

    raw_pub_a_25519 = a_pub_25519.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    print("X25519 raw public length:", len(raw_pub_a_25519))

    # X448
    a_priv_448, a_pub_448 = x448_generate_keys()
    b_priv_448, b_pub_448 = x448_generate_keys()

    shared_a_448 = x448_compute_shared_secret(a_priv_448, b_pub_448)
    shared_b_448 = x448_compute_shared_secret(b_priv_448, a_pub_448)
    print("X448 shared secret matches:", shared_a_448 == shared_b_448)

    key_a_448 = hkdf_sha256_32_bytes(shared_a_448, salt=None, info=b"x448-demo")
    key_b_448 = hkdf_sha256_32_bytes(shared_b_448, salt=None, info=b"x448-demo")
    print("X448 derived key matches:", key_a_448 == key_b_448)

    raw_pub_a_448 = a_pub_448.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    print("X448 raw public length:", len(raw_pub_a_448))


# ---------------------------------------------------------------------------
# Main entrypoint: run all demos
# ---------------------------------------------------------------------------

def run_all_asymmetric_demos() -> None:
    rsa_demo()
    dsa_demo()
    dh_demo()
    ec_demo()
    eddsa_demo()
    xdh_demo()


if __name__ == "__main__":
    run_all_asymmetric_demos()
