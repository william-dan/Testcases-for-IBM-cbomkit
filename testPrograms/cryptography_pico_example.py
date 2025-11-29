import os, base64, json, importlib

def tiny_crypto(msg: bytes) -> bytes:
    # Example (but unknown to a static analyzer at analysis time):
    cfg = {
      "m":  "cryptography.hazmat.primitives.ciphers",
      "c":  "Cipher",
      "am": "algorithms",
      "a":  "AES",
      "mm": "modes",
      "md": "GCM",
      "kl": 32,
      "iv": 12
    }

    m = importlib.import_module(cfg["m"])
    Cipher = getattr(m, cfg["c"])
    alg_cls = getattr(getattr(m, cfg["am"]), cfg["a"])
    mode_cls = getattr(getattr(m, cfg["mm"]), cfg["md"])

    key = os.urandom(cfg["kl"])
    iv  = os.urandom(cfg["iv"])

    encryptor = Cipher(alg_cls(key), mode_cls(iv)).encryptor()
    return encryptor.update(msg) + encryptor.finalize()

if __name__ == "__main__":
    secret = b"Top secret message!"
    ciphertext = tiny_crypto(secret)
    print("Ciphertext:", ciphertext)
    