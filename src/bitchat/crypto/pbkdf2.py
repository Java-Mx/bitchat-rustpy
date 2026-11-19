"""
PBKDF2-HMAC-SHA256 key derivation for password-protected BitChat channels.

Delegates to the native Rust `pbkdf2` engine in `bitchat._bitchat_core`
when available, while retaining the pure-Python `cryptography` implementation
(`py_derive_channel_key`) for fallback and differential verification.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from bitchat._native import HAS_NATIVE_CORE, _core, raise_mapped_error

# ---------------------------------------------------------------------------
# Constants — verified against Rust source
# ---------------------------------------------------------------------------

PBKDF2_ITERATIONS: int = 100_000
"""Iteration count matching Rust ``derive_channel_key`` (encryption.rs line 290)."""

PBKDF2_OUTPUT_LENGTH: int = 32
"""Output key length in bytes (AES-256 key)."""


# ---------------------------------------------------------------------------
# Pure-Python reference implementation (retained for differential tests)
# ---------------------------------------------------------------------------


def py_derive_channel_key(password: str, channel_name: str) -> bytes:
    """Pure-Python PBKDF2-HMAC-SHA256 channel key derivation."""
    if not isinstance(password, str):
        raise TypeError(f"password must be str, got {type(password).__name__}")
    if not isinstance(channel_name, str):
        raise TypeError(f"channel_name must be str, got {type(channel_name).__name__}")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=PBKDF2_OUTPUT_LENGTH,
        salt=channel_name.encode("utf-8"),
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


# ---------------------------------------------------------------------------
# Public API (Native Rust with Pure-Python Fallback)
# ---------------------------------------------------------------------------


def derive_channel_key(password: str, channel_name: str) -> bytes:
    """Derive a 32-byte AES-256 channel key from a password and channel name."""
    if not isinstance(password, str):
        raise TypeError(f"password must be str, got {type(password).__name__}")
    if not isinstance(channel_name, str):
        raise TypeError(f"channel_name must be str, got {type(channel_name).__name__}")
    if HAS_NATIVE_CORE and hasattr(_core, "pbkdf2_derive_channel_key"):
        try:
            return bytes(_core.pbkdf2_derive_channel_key(password, channel_name))
        except ValueError as exc:
            raise_mapped_error(exc)
    return py_derive_channel_key(password, channel_name)
