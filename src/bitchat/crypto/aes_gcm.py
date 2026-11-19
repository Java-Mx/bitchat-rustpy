"""
AES-256-GCM encryption wrapper for BitChat legacy direct-message and channel encryption.

Delegates to the native Rust `aes-gcm` engine in `bitchat._bitchat_core`
when available, while retaining the pure-Python `cryptography` implementation
(`py_*`) for fallback and differential verification.

Wire format (matching Rust):
    ``nonce(12 bytes) || ciphertext+tag(N+16 bytes)``
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from bitchat._native import HAS_NATIVE_CORE, _core, raise_mapped_error
from bitchat.exceptions import DecryptionError, EncryptionError

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

AES_KEY_SIZE: int = 32
"""Required AES-256 key size in bytes."""

AES_NONCE_SIZE: int = 12
"""Required AES-GCM nonce size in bytes (96-bit random nonce)."""

AES_TAG_SIZE: int = 16
"""AES-GCM authentication tag size appended to ciphertext."""

_MIN_CIPHERTEXT_SIZE: int = AES_NONCE_SIZE + AES_TAG_SIZE
"""Minimum valid AES-GCM payload size: nonce(12) + tag(16)."""


# ---------------------------------------------------------------------------
# Pure-Python reference implementations (retained for differential tests)
# ---------------------------------------------------------------------------


def py_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Pure-Python AES-256-GCM encryption."""
    _validate_key(key)
    nonce = os.urandom(AES_NONCE_SIZE)
    try:
        aesgcm = AESGCM(bytes(key))
        ciphertext_and_tag = aesgcm.encrypt(nonce, bytes(plaintext), None)
    except (ValueError, TypeError) as exc:
        raise EncryptionError(f"AES-256-GCM encryption failed: {exc}") from exc
    return nonce + ciphertext_and_tag


def py_decrypt(key: bytes, data: bytes) -> bytes:
    """Pure-Python AES-256-GCM decryption."""
    _validate_key(key)
    if not isinstance(data, (bytes, bytearray)):
        raise DecryptionError(f"AES-GCM input must be bytes, got {type(data).__name__}")
    if len(data) < _MIN_CIPHERTEXT_SIZE:
        raise DecryptionError(
            f"AES-GCM data too short: need at least {_MIN_CIPHERTEXT_SIZE} bytes "
            f"(nonce + tag), got {len(data)}"
        )
    nonce = bytes(data[:AES_NONCE_SIZE])
    ciphertext_and_tag = bytes(data[AES_NONCE_SIZE:])
    try:
        aesgcm = AESGCM(bytes(key))
        return aesgcm.decrypt(nonce, ciphertext_and_tag, None)
    except Exception as exc:
        raise DecryptionError(
            "AES-256-GCM decryption or authentication failed"
        ) from exc


# ---------------------------------------------------------------------------
# Public API (Native Rust with Pure-Python Fallback)
# ---------------------------------------------------------------------------


def encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt ``plaintext`` with AES-256-GCM using a fresh random nonce."""
    _validate_key(key)
    if not isinstance(plaintext, (bytes, bytearray, memoryview)):
        raise EncryptionError(
            f"AES-256-GCM plaintext must be bytes, got {type(plaintext).__name__}"
        )
    if HAS_NATIVE_CORE and hasattr(_core, "aes_gcm_encrypt"):
        try:
            return bytes(_core.aes_gcm_encrypt(bytes(key), bytes(plaintext)))
        except ValueError as exc:
            raise_mapped_error(exc)
    return py_encrypt(key, bytes(plaintext))


def encrypt_with_key(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt with an explicit channel key. Alias for ``encrypt``."""
    return encrypt(key, plaintext)


def decrypt(key: bytes, data: bytes) -> bytes:
    """Decrypt an AES-256-GCM payload in ``nonce || ciphertext+tag`` format."""
    _validate_key(key)
    if not isinstance(data, (bytes, bytearray)):
        raise DecryptionError(f"AES-GCM input must be bytes, got {type(data).__name__}")
    if HAS_NATIVE_CORE and hasattr(_core, "aes_gcm_decrypt"):
        try:
            return bytes(_core.aes_gcm_decrypt(bytes(key), bytes(data)))
        except ValueError as exc:
            raise_mapped_error(exc)
    return py_decrypt(key, data)


def decrypt_with_key(key: bytes, data: bytes) -> bytes:
    """Decrypt a channel-key-encrypted payload. Alias for ``decrypt``."""
    return decrypt(key, data)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _validate_key(key: object) -> None:
    """Raise EncryptionError if the AES key is not valid."""
    if not isinstance(key, (bytes, bytearray)):
        raise EncryptionError(f"AES key must be bytes, got {type(key).__name__}")
    if len(key) != AES_KEY_SIZE:  # type: ignore[arg-type]
        raise EncryptionError(
            f"AES-256 key must be {AES_KEY_SIZE} bytes, got {len(key)}"  # type: ignore[arg-type]
        )
