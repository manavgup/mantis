"""AES-256-GCM encryption for findings store."""

from __future__ import annotations

import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_NONCE_SIZE = 12  # 96-bit nonce for GCM


def encrypt(plaintext: str, key: bytes) -> bytes:
    """Encrypt plaintext with AES-256-GCM. Returns nonce + ciphertext."""
    nonce = os.urandom(_NONCE_SIZE)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return nonce + ct


def decrypt(ciphertext: bytes, key: bytes) -> str:
    """Decrypt nonce-prefixed ciphertext with AES-256-GCM."""
    nonce = ciphertext[:_NONCE_SIZE]
    ct = ciphertext[_NONCE_SIZE:]
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ct, None)
    return plaintext.decode("utf-8")


def load_key_from_env(env_var: str) -> bytes:
    """Load and validate a base64-encoded 32-byte AES key from an environment variable."""
    raw = os.environ.get(env_var)
    if not raw:
        raise ValueError(f"Environment variable {env_var} is not set")
    key = base64.b64decode(raw)
    if len(key) != 32:
        raise ValueError(f"Key from {env_var} must be exactly 32 bytes (got {len(key)})")
    return key
