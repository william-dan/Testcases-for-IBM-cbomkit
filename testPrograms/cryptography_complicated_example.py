from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives import keywrap
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import os
# import pycryptodome


# input("Press Enter to continue...")

def symmetric_encryption_demo():
    # AES-GCM encryption/decryption
    key = os.urandom(32)
    iv = os.urandom(12)
    data = b"Secret message"
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    tag = encryptor.tag

    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    assert plaintext == data

def asymmetric_encryption_demo():
    # RSA key generation, encryption, decryption, signing, verification
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    message = b"Encrypt me!"

    # Encryption
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Decryption
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    assert plaintext == message

    # Signing
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    # Verification
    public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def fernet_demo():
    # Symmetric encryption with Fernet
    key = Fernet.generate_key()
    # print("Fernet key len:", len(key))
    f = Fernet(key)
    token = f.encrypt(b"Fernet secret")
    assert f.decrypt(token) == b"Fernet secret"

def ecdsa_demo():
    # ECDSA signing and verification
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    # print("ECDSA key len:", len(private_key.private_numbers().private_value.to_bytes(32, 'big')))
    data = b"Sign me"
    signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    public_key = private_key.public_key()
    public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))

if __name__ == "__main__":
    symmetric_encryption_demo()
    asymmetric_encryption_demo()
    fernet_demo()
    ecdsa_demo()
    print("All cryptography demos completed successfully.")