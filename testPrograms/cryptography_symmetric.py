from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.ciphers.aead import AESSIV
from cryptography.hazmat.primitives.keywrap import (
    aes_key_wrap, aes_key_unwrap
)
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os, struct, base64


def fernet_demo() -> None:
    # Generate one random key and persist it (file/secret manager)
    key = Fernet.generate_key()
    f = Fernet(key)

    message = b"dynamic CBOM is awesome"
    token = f.encrypt(message)          # ciphertext + integrity protection
    plaintext = f.decrypt(token)        # raises InvalidToken if tampered

    assert plaintext == message


def aes_cbc_encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """
    AES-CBC with PKCS7 padding.
    Returns (iv, ciphertext).
    """
    # 16 bytes (128 bits) IV for AES/SM4/Camellia
    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # Block ciphers need padding if data length isn’t a multiple of block size
    padder = padding.PKCS7(128).padder()  # 128 = block size in bits for AES
    padded = padder.update(plaintext) + padder.finalize()

    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return iv, ciphertext

def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    return plaintext

def aes_ctr_encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv, ciphertext

def aes_ctr_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()



def chacha20_encrypt(key: bytes, nonce_64: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """
    ChaCha20 in cryptography uses a 64-bit counter + 64-bit nonce concatenated,
    so we build a 16-byte "nonce" from those.
    """
    assert len(key) == 32
    assert len(nonce_64) == 8

    counter = 0
    full_nonce = struct.pack("<Q", counter) + nonce_64

    algorithm = algorithms.ChaCha20(key, full_nonce)
    cipher = Cipher(algorithm, mode=None)
    encryptor = cipher.encryptor()

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return nonce_64, ciphertext

def chacha20_decrypt(key: bytes, nonce_64: bytes, ciphertext: bytes) -> bytes:
    counter = 0
    full_nonce = struct.pack("<Q", counter) + nonce_64
    algorithm = algorithms.ChaCha20(key, full_nonce)
    cipher = Cipher(algorithm, mode=None)
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


# --- AES-GCM example ---

def aesgcm_encrypt(key: bytes, plaintext: bytes, aad: bytes | None = None) -> tuple[bytes, bytes]:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)   # 96-bit nonce is recommended
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce, ciphertext

def aesgcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes | None = None) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, aad)

# --- ChaCha20-Poly1305 example ---

def chacha20poly1305_encrypt(key: bytes, plaintext: bytes, aad: bytes | None = None) -> tuple[bytes, bytes]:
    chacha = ChaCha20Poly1305(key)
    nonce = os.urandom(12)   # 96-bit nonce
    ciphertext = chacha.encrypt(nonce, plaintext, aad)
    return nonce, ciphertext

def chacha20poly1305_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes | None = None) -> bytes:
    chacha = ChaCha20Poly1305(key)
    return chacha.decrypt(nonce, ciphertext, aad)


def aessiv_encrypt(key: bytes, plaintext: bytes, aad_list: list[bytes]) -> bytes:
    aessiv = AESSIV(key)
    return aessiv.encrypt(plaintext, aad_list)

def aessiv_decrypt(key: bytes, ciphertext: bytes, aad_list: list[bytes]) -> bytes:
    aessiv = AESSIV(key)
    return aessiv.decrypt(ciphertext, aad_list)



def wrap_key(kek: bytes, key_to_wrap: bytes) -> bytes:
    # kek = key encryption key (AES key)
    return aes_key_wrap(kek, key_to_wrap)

def unwrap_key(kek: bytes, wrapped: bytes) -> bytes:
    return aes_key_unwrap(kek, wrapped)



def derive_aes256_key_from_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,         # 32 bytes = 256-bit key
        salt=salt,
        iterations=1_200_000,
    )
    return kdf.derive(password.encode("utf-8"))

def password_encrypt(password: str, plaintext: bytes) -> dict:
    salt = os.urandom(16)
    key = derive_aes256_key_from_password(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return {"salt": salt, "nonce": nonce, "ciphertext": ciphertext}

def password_decrypt(password: str, package: dict) -> bytes:
    key = derive_aes256_key_from_password(password, package["salt"])
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(package["nonce"], package["ciphertext"], None)

    # --- Example usage ---

if __name__ == "__main__":
    # fernet example
    fernet_demo()
    
    # AES-CBC example
    key_256 = os.urandom(16)  # AES-128
    plaintext = b"Hello, World!"
    iv, ciphertext = aes_cbc_encrypt(key_256, plaintext)
    decrypted = aes_cbc_decrypt(key_256, iv, ciphertext)
    assert decrypted == plaintext
    print("AES-CBC:", decrypted)

    # AES-CTR example
    iv, ciphertext = aes_ctr_encrypt(key_256, plaintext)
    decrypted = aes_ctr_decrypt(key_256, iv, ciphertext)
    assert decrypted == plaintext
    print("AES-CTR:", decrypted)

    # ChaCha20 example
    key_32 = os.urandom(32)
    nonce_8 = os.urandom(8)
    nonce, ciphertext = chacha20_encrypt(key_32, nonce_8, plaintext)
    decrypted = chacha20_decrypt(key_32, nonce, ciphertext)
    assert decrypted == plaintext
    print("ChaCha20:", decrypted)

    # AES-GCM example
    nonce, ciphertext = aesgcm_encrypt(key_256, plaintext)
    decrypted = aesgcm_decrypt(key_256, nonce, ciphertext)
    assert decrypted == plaintext
    print("AES-GCM:", decrypted)

    # ChaCha20-Poly1305 example
    nonce, ciphertext = chacha20poly1305_encrypt(key_32, plaintext)
    decrypted = chacha20poly1305_decrypt(key_32, nonce, ciphertext)
    assert decrypted == plaintext
    print("ChaCha20-Poly1305:", decrypted)

    # AES-SIV example
    key_64 = os.urandom(64)
    ciphertext = aessiv_encrypt(key_64, plaintext, [b"aad1"])
    decrypted = aessiv_decrypt(key_64, ciphertext, [b"aad1"])
    assert decrypted == plaintext
    print("AES-SIV:", decrypted)

    # Key wrapping example
    kek = os.urandom(32)
    key_to_wrap = os.urandom(32)
    wrapped = wrap_key(kek, key_to_wrap)
    unwrapped = unwrap_key(kek, wrapped)
    assert unwrapped == key_to_wrap
    print("Key wrap/unwrap successful")

    # Password-based encryption example
    password = "my_secure_password"
    package = password_encrypt(password, plaintext)
    decrypted = password_decrypt(password, package)
    assert decrypted == plaintext
    print("Password encryption:", decrypted)