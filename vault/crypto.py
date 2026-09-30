"""Key derivation and authenticated encryption.

* Key derivation: scrypt (memory-hard) turns the master password + random salt into a
  256-bit key. The key itself is never written to disk.
* Encryption: AES-256-GCM (authenticated). Each encryption uses a fresh random 96-bit
  nonce. Stored blob layout: nonce (12 bytes) || ciphertext+tag.
* Associated data (AAD) binds a ciphertext to its purpose (e.g. b"password"), so blobs
  cannot be swapped between fields without detection.
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .exceptions import CryptoError

SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32  # AES-256

# OWASP-recommended minimum scrypt cost: N=2^15, r=8, p=1 (~32 MiB, ~100 ms).
DEFAULT_N = 2**15
DEFAULT_R = 8
DEFAULT_P = 1


def generate_salt() -> bytes:
    return os.urandom(SALT_SIZE)


def derive_key(
    password: str,
    salt: bytes,
    n: int = DEFAULT_N,
    r: int = DEFAULT_R,
    p: int = DEFAULT_P,
) -> bytes:
    """Derive a 256-bit key from *password* and *salt* using scrypt."""
    if not password:
        raise CryptoError("Password must not be empty.")
    if len(salt) < SALT_SIZE:
        raise CryptoError("Salt is too short.")
    try:
        return Scrypt(salt=salt, length=KEY_SIZE, n=n, r=r, p=p).derive(password.encode("utf-8"))
    except Exception as exc:  # invalid parameters, etc.
        raise CryptoError("Key derivation failed.") from exc


def encrypt(key: bytes, plaintext: str, aad: bytes = b"") -> bytes:
    """Encrypt *plaintext*; returns nonce || ciphertext||tag."""
    if len(key) != KEY_SIZE:
        raise CryptoError("Invalid key length.")
    nonce = os.urandom(NONCE_SIZE)
    return nonce + AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), aad)


def decrypt(key: bytes, blob: bytes, aad: bytes = b"") -> str:
    """Decrypt a blob from :func:`encrypt`. Raises CryptoError on wrong key or tampering."""
    if len(key) != KEY_SIZE:
        raise CryptoError("Invalid key length.")
    if len(blob) < NONCE_SIZE + 16:
        raise CryptoError("Ciphertext is truncated or corrupt.")
    nonce, ciphertext = blob[:NONCE_SIZE], blob[NONCE_SIZE:]
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad).decode("utf-8")
    except (InvalidTag, UnicodeDecodeError) as exc:
        raise CryptoError("Decryption failed: wrong key or data was modified.") from exc
