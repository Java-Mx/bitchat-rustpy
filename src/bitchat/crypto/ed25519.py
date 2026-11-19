"""
Ed25519 digital signature wrapper for BitChat.

Delegates to the native Rust `ed25519-dalek` engine in `bitchat._bitchat_core`
when available, while retaining the pure-Python `cryptography` implementation
(`py_*`) for fallback and differential verification.

Key sizes (standard Ed25519):
  - Private (signing) key: 32 bytes
  - Public (verifying) key: 32 bytes
  - Signature: 64 bytes

Do NOT expose private key bytes through logging, repr, or exception messages.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from bitchat._native import HAS_NATIVE_CORE, _core, raise_mapped_error
from bitchat.exceptions import (
    InvalidKeyError,
    InvalidSignatureError,
    SignatureVerificationError,
)

# ---------------------------------------------------------------------------
# Public constants — never change these; they are part of the wire protocol
# ---------------------------------------------------------------------------

ED25519_PRIVATE_KEY_SIZE: int = 32
"""Size of a raw Ed25519 private key in bytes."""

ED25519_PUBLIC_KEY_SIZE: int = 32
"""Size of a raw Ed25519 public key (verifying key) in bytes."""

ED25519_SIGNATURE_SIZE: int = 64
"""Size of an Ed25519 signature in bytes."""


# ---------------------------------------------------------------------------
# Pure-Python reference implementations (retained for differential tests)
# ---------------------------------------------------------------------------


def py_generate_signing_key() -> bytes:
    """Pure-Python Ed25519 signing key generation."""
    private_key = Ed25519PrivateKey.generate()
    return private_key.private_bytes_raw()


def py_public_key_from_private(private_key_bytes: bytes) -> bytes:
    """Pure-Python Ed25519 public key derivation from private key."""
    if not isinstance(private_key_bytes, (bytes, bytearray)):
        raise InvalidKeyError(
            f"Ed25519 private key must be bytes, got {type(private_key_bytes).__name__}"
        )
    if len(private_key_bytes) != ED25519_PRIVATE_KEY_SIZE:
        raise InvalidKeyError(
            f"Ed25519 private key must be {ED25519_PRIVATE_KEY_SIZE} bytes, "
            f"got {len(private_key_bytes)}"
        )
    try:
        private_key = Ed25519PrivateKey.from_private_bytes(bytes(private_key_bytes))
        return private_key.public_key().public_bytes_raw()
    except (ValueError, TypeError) as exc:
        raise InvalidKeyError(f"Invalid Ed25519 private key: {exc}") from exc


def py_load_public_key(public_key_bytes: bytes) -> bytes:
    """Pure-Python Ed25519 public key validation."""
    if not isinstance(public_key_bytes, (bytes, bytearray)):
        raise InvalidKeyError(
            f"Ed25519 public key must be bytes, got {type(public_key_bytes).__name__}"
        )
    if len(public_key_bytes) != ED25519_PUBLIC_KEY_SIZE:
        raise InvalidKeyError(
            f"Ed25519 public key must be {ED25519_PUBLIC_KEY_SIZE} bytes, "
            f"got {len(public_key_bytes)}"
        )
    try:
        Ed25519PublicKey.from_public_bytes(bytes(public_key_bytes))
    except (ValueError, TypeError) as exc:
        raise InvalidKeyError(f"Invalid Ed25519 public key: {exc}") from exc
    return bytes(public_key_bytes)


def py_sign(private_key_bytes: bytes, data: bytes) -> bytes:
    """Pure-Python Ed25519 signing."""
    if not isinstance(private_key_bytes, (bytes, bytearray)):
        raise InvalidKeyError(
            f"Ed25519 private key must be bytes, got {type(private_key_bytes).__name__}"
        )
    if len(private_key_bytes) != ED25519_PRIVATE_KEY_SIZE:
        raise InvalidKeyError(
            f"Ed25519 private key must be {ED25519_PRIVATE_KEY_SIZE} bytes, "
            f"got {len(private_key_bytes)}"
        )
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(f"data must be bytes-like, got {type(data).__name__}")
    try:
        private_key = Ed25519PrivateKey.from_private_bytes(bytes(private_key_bytes))
        sig = private_key.sign(bytes(data))
    except (ValueError, TypeError) as exc:
        raise InvalidKeyError(
            f"Invalid Ed25519 private key during signing: {exc}"
        ) from exc
    assert len(sig) == ED25519_SIGNATURE_SIZE, (
        f"Ed25519 produced unexpected signature length {len(sig)}"
    )
    return sig


def py_verify(public_key_bytes: bytes, signature: bytes, data: bytes) -> None:
    """Pure-Python Ed25519 verification."""
    if not isinstance(public_key_bytes, (bytes, bytearray)):
        raise InvalidKeyError(
            f"Ed25519 public key must be bytes, got {type(public_key_bytes).__name__}"
        )
    if len(public_key_bytes) != ED25519_PUBLIC_KEY_SIZE:
        raise InvalidKeyError(
            f"Ed25519 public key must be {ED25519_PUBLIC_KEY_SIZE} bytes, "
            f"got {len(public_key_bytes)}"
        )
    if not isinstance(signature, (bytes, bytearray)):
        raise InvalidSignatureError(
            f"Signature must be bytes, got {type(signature).__name__}"
        )
    if len(signature) != ED25519_SIGNATURE_SIZE:
        raise InvalidSignatureError(
            f"Ed25519 signature must be {ED25519_SIGNATURE_SIZE} bytes, "
            f"got {len(signature)}"
        )
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(f"data must be bytes-like, got {type(data).__name__}")
    try:
        public_key = Ed25519PublicKey.from_public_bytes(bytes(public_key_bytes))
    except (ValueError, TypeError) as exc:
        raise InvalidKeyError(f"Invalid Ed25519 public key: {exc}") from exc
    try:
        public_key.verify(bytes(signature), bytes(data))
    except InvalidSignature as exc:
        raise SignatureVerificationError(
            "Ed25519 signature verification failed"
        ) from exc


# ---------------------------------------------------------------------------
# Public API (Native Rust with Pure-Python Fallback)
# ---------------------------------------------------------------------------


def generate_signing_key() -> bytes:
    """Generate a new Ed25519 signing key and return the raw 32-byte private key."""
    if HAS_NATIVE_CORE and hasattr(_core, "ed25519_generate_signing_key"):
        try:
            return bytes(_core.ed25519_generate_signing_key())
        except ValueError as exc:
            raise_mapped_error(exc)
    return py_generate_signing_key()


def public_key_from_private(private_key_bytes: bytes) -> bytes:
    """Derive the 32-byte Ed25519 public (verifying) key from a private key."""
    if not isinstance(private_key_bytes, (bytes, bytearray)):
        raise InvalidKeyError(
            f"Ed25519 private key must be bytes, got {type(private_key_bytes).__name__}"
        )
    if HAS_NATIVE_CORE and hasattr(_core, "ed25519_public_key_from_private"):
        try:
            return bytes(
                _core.ed25519_public_key_from_private(bytes(private_key_bytes))
            )
        except ValueError as exc:
            raise_mapped_error(exc)
    return py_public_key_from_private(private_key_bytes)


def load_public_key(public_key_bytes: bytes) -> bytes:
    """Validate and normalise a raw 32-byte Ed25519 public key."""
    if not isinstance(public_key_bytes, (bytes, bytearray)):
        raise InvalidKeyError(
            f"Ed25519 public key must be bytes, got {type(public_key_bytes).__name__}"
        )
    if HAS_NATIVE_CORE and hasattr(_core, "ed25519_load_public_key"):
        try:
            return bytes(_core.ed25519_load_public_key(bytes(public_key_bytes)))
        except ValueError as exc:
            raise_mapped_error(exc)
    return py_load_public_key(public_key_bytes)


def sign(private_key_bytes: bytes, data: bytes) -> bytes:
    """Sign ``data`` with the given Ed25519 private key."""
    if not isinstance(private_key_bytes, (bytes, bytearray)):
        raise InvalidKeyError(
            f"Ed25519 private key must be bytes, got {type(private_key_bytes).__name__}"
        )
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(f"data must be bytes-like, got {type(data).__name__}")
    if HAS_NATIVE_CORE and hasattr(_core, "ed25519_sign"):
        try:
            return bytes(_core.ed25519_sign(bytes(private_key_bytes), bytes(data)))
        except ValueError as exc:
            raise_mapped_error(exc)
    return py_sign(private_key_bytes, data)


def verify(public_key_bytes: bytes, signature: bytes, data: bytes) -> None:
    """Verify an Ed25519 signature."""
    if not isinstance(public_key_bytes, (bytes, bytearray)):
        raise InvalidKeyError(
            f"Ed25519 public key must be bytes, got {type(public_key_bytes).__name__}"
        )
    if not isinstance(signature, (bytes, bytearray)):
        raise InvalidSignatureError(
            f"Signature must be bytes, got {type(signature).__name__}"
        )
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(f"data must be bytes-like, got {type(data).__name__}")
    if HAS_NATIVE_CORE and hasattr(_core, "ed25519_verify"):
        try:
            _core.ed25519_verify(bytes(public_key_bytes), bytes(signature), bytes(data))
            return
        except ValueError as exc:
            raise_mapped_error(exc)
    py_verify(public_key_bytes, signature, data)
