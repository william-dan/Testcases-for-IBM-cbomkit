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

def key_derivation_demo():
    # PBKDF2 key derivation
    password = b"mysecretpassword"
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password)
    # To verify:
    kdf_verify = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    kdf_verify.verify(password, key)

def hmac_demo():
    # HMAC generation and verification
    key = os.urandom(32)
    data = b"Authenticate me"
    h = HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    tag = h.finalize()
    # Verification
    h2 = HMAC(key, hashes.SHA256(), backend=default_backend())
    h2.update(data)
    h2.verify(tag)

def key_wrap_demo():
    # AES key wrap/unwrap
    kek = os.urandom(32)  # Key encryption key
    key_to_wrap = os.urandom(32)
    wrapped = keywrap.aes_key_wrap(kek, key_to_wrap, backend=default_backend())
    unwrapped = keywrap.aes_key_unwrap(kek, wrapped, backend=default_backend())
    assert key_to_wrap == unwrapped

def serialization_demo():
    # Serialize/deserialize RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b"password")
    )
    loaded_key = serialization.load_pem_private_key(
        pem,
        password=b"password",
        backend=default_backend()
    )
    # print("loaded_key len:", len(loaded_key))
    assert loaded_key.private_numbers() == private_key.private_numbers()

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