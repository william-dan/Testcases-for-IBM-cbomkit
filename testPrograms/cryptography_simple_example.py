from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


def RSA_demo(key_size=2048, public_exponent=65537):
    # Generate RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=public_exponent,
        key_size=key_size,
        backend=default_backend()
    )

    # Serialize private key
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    print(pem.decode())

    # Get public key
    public_key = private_key.public_key()

    # Sign a message
    message = b"Hello, cryptography!"
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # Verify signature
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Signature verified!")
    except Exception as e:
        print("Verification failed:", e)

if __name__ == "__main__":
    RSA_demo(key_size=2048, public_exponent=65537)
    RSA_demo(key_size=4096, public_exponent=65537)
    


