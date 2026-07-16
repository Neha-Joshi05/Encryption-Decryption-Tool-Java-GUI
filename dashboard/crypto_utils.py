# ============================================================
# crypto_utils.py — Python mirror of Java AES-GCM crypto logic
# INTERVIEW TIP: "Same algorithm, same binary packet format
#                 as the Java desktop app — cross-language
#                 compatible encryption is real-world practice."
# ============================================================

import os
import struct
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64

MAGIC        = b'ENCR'
VERSION      = 1
SALT_LEN     = 16
IV_LEN       = 12
TAG_BITS     = 128
PBKDF2_ITERS = 120_000
KEY_BITS     = 32   # 256 bits = 32 bytes


def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derives AES-256 key from password using PBKDF2-HMAC-SHA256.
    Identical parameters to the Java EncryptorApp.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_BITS,
        salt=salt,
        iterations=PBKDF2_ITERS,
    )
    return kdf.derive(password.encode('utf-8'))


def encrypt_bytes(plaintext: bytes, password: str) -> bytes:
    """Encrypts bytes using AES-256-GCM. Returns packed binary payload."""
    salt = os.urandom(SALT_LEN)
    iv   = os.urandom(IV_LEN)
    key  = derive_key(password, salt)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(iv, plaintext, None)

    # Pack: MAGIC(4) + VERSION(1) + salt_len(1) + iv_len(1) + salt + iv + ct
    header = MAGIC + struct.pack('BBB', VERSION, SALT_LEN, IV_LEN)
    return header + salt + iv + ct


def decrypt_bytes(packed: bytes, password: str) -> bytes:
    """Decrypts packed binary payload. Raises ValueError on wrong password."""
    if len(packed) < 7:
        raise ValueError("Payload too short")
    if packed[:4] != MAGIC:
        raise ValueError("Bad header — not an encrypted payload")
    version, salt_len, iv_len = struct.unpack('BBB', packed[4:7])
    if version != VERSION:
        raise ValueError("Unsupported version")

    offset = 7
    salt = packed[offset:offset + salt_len]; offset += salt_len
    iv   = packed[offset:offset + iv_len];   offset += iv_len
    ct   = packed[offset:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(iv, ct, None)
    except Exception:
        raise ValueError("Authentication failed — wrong password or tampered data")


def encrypt_text(plaintext: str, password: str) -> str:
    """Encrypts text and returns Base64 string (same format as Java app)."""
    packed = encrypt_bytes(plaintext.encode('utf-8'), password)
    return base64.b64encode(packed).decode('utf-8')


def decrypt_text(b64_ciphertext: str, password: str) -> str:
    """Decrypts Base64 ciphertext string (compatible with Java app output)."""
    try:
        packed = base64.b64decode(b64_ciphertext)
    except Exception:
        raise ValueError("Input is not valid Base64")
    return decrypt_bytes(packed, password).decode('utf-8')