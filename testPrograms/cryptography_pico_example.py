from cryptography.fernet import Fernet

#!/usr/bin/env python3
"""
Minimal example using the `cryptography` library (Fernet symmetric encryption).
Save as /home/daz/dynamic-cbom/testPrograms/cryptography_pico_example.py
Requires: pip install cryptography
"""



def generate_key():
    return Fernet.generate_key()


def encrypt(key: bytes, plaintext: bytes) -> bytes:
    f = Fernet(key)
    return f.encrypt(plaintext)


def decrypt(key: bytes, token: bytes) -> bytes:
    f = Fernet(key)
    return f.decrypt(token)


if __name__ == "__main__":
    key = generate_key()
    print("Key:", key.decode())

    message = b"hello, cryptography!"
    token = encrypt(key, message)
    print("Encrypted token:", token)

    recovered = decrypt(key, token)
    print("Decrypted message:", recovered.decode())