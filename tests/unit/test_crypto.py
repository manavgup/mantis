"""Tests for harness.crypto — AES-256-GCM encrypt/decrypt."""

from __future__ import annotations

import base64
import os

import pytest

from harness.crypto import decrypt, encrypt, load_key_from_env


@pytest.fixture()
def key() -> bytes:
    return os.urandom(32)


def test_encrypt_decrypt_roundtrip(key: bytes):
    plaintext = "heap-buffer-overflow in parse_chunk at line 247"
    ct = encrypt(plaintext, key)
    assert decrypt(ct, key) == plaintext


def test_different_nonces_each_call(key: bytes):
    plaintext = "same input twice"
    ct1 = encrypt(plaintext, key)
    ct2 = encrypt(plaintext, key)
    assert ct1 != ct2  # random nonce means different ciphertext
    # But both decrypt to the same thing
    assert decrypt(ct1, key) == plaintext
    assert decrypt(ct2, key) == plaintext


def test_wrong_key_raises(key: bytes):
    ct = encrypt("secret", key)
    wrong_key = os.urandom(32)
    with pytest.raises(Exception):
        decrypt(ct, wrong_key)


def test_load_key_from_env_valid(monkeypatch):
    raw_key = os.urandom(32)
    encoded = base64.b64encode(raw_key).decode()
    monkeypatch.setenv("TEST_ENC_KEY", encoded)
    loaded = load_key_from_env("TEST_ENC_KEY")
    assert loaded == raw_key


def test_load_key_from_env_wrong_length(monkeypatch):
    short_key = os.urandom(16)
    encoded = base64.b64encode(short_key).decode()
    monkeypatch.setenv("TEST_ENC_KEY", encoded)
    with pytest.raises(ValueError, match="exactly 32 bytes"):
        load_key_from_env("TEST_ENC_KEY")


def test_load_key_from_env_missing(monkeypatch):
    monkeypatch.delenv("TEST_ENC_KEY", raising=False)
    with pytest.raises(ValueError, match="not set"):
        load_key_from_env("TEST_ENC_KEY")
