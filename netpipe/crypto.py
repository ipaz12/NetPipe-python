"""
NetPipe encryption - AES-256-GCM, compatible with the Go server.

Key derivation: SHA-256 hash of any string → 32 bytes.
Wire format:   [12 bytes nonce][ciphertext + 16 bytes GCM auth tag]

Uses the 'cryptography' package (the only external dependency).
"""

import os
from hashlib import sha256

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _derive_key(key: str) -> bytes:
    """Derive a 32-byte AES key from any string via SHA-256."""
    return sha256(key.encode("utf-8")).digest()


def encrypt(plaintext: bytes, key: str) -> bytes:
    """
    Encrypt with AES-256-GCM.
    Returns: [12B nonce][ciphertext + GCM tag]
    """
    key_bytes = _derive_key(key)
    nonce = os.urandom(12)
    gcm = AESGCM(key_bytes)
    ciphertext = gcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext


def decrypt(data: bytes, key: str) -> bytes:
    """
    Decrypt AES-256-GCM data produced by encrypt() or the Go server.
    Expects: [12B nonce][ciphertext + GCM tag]
    """
    key_bytes = _derive_key(key)

    if len(data) < 12:
        raise ValueError("netpipe: ciphertext too short")

    nonce = data[:12]
    ciphertext = data[12:]

    gcm = AESGCM(key_bytes)
    return gcm.decrypt(nonce, ciphertext, None)
