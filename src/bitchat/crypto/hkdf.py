"""
HKDF implementations for BitChat.

Delegates to the native Rust `hkdf` / `hmac` engine in `bitchat._bitchat_core`
when available, while retaining the pure-Python reference implementations
(`py_noise_hkdf`, `py_legacy_hkdf`) for fallback and differential verification.
"""

from __future__ import annotations

import hashlib
import hmac

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from bitchat._native import HAS_NATIVE_CORE, _core, raise_mapped_error

# ---------------------------------------------------------------------------
# Pure-Python reference implementations (retained for differential tests)
# ---------------------------------------------------------------------------


def py_noise_hkdf(chaining_key: bytes, ikm: bytes, num_outputs: int) -> list[bytes]:
    """Pure-Python Noise-protocol HKDF matching Rust `noise_protocol.rs`."""
    if num_outputs < 1 or num_outputs > 255:
        raise ValueError(f"num_outputs must be in [1, 255], got {num_outputs}")

    temp_key = hmac.new(
        bytes(chaining_key), msg=bytes(ikm), digestmod=hashlib.sha256
    ).digest()

    outputs: list[bytes] = []
    current: bytes = b""
    for i in range(1, num_outputs + 1):
        current = hmac.new(
            temp_key, msg=current + bytes([i]), digestmod=hashlib.sha256
        ).digest()
        outputs.append(current)

    return outputs


def py_legacy_hkdf(
    ikm: bytes,
    *,
    salt: bytes = b"bitchat-v1",
    info: bytes = b"",
    length: int = 32,
) -> bytes:
    """Pure-Python standard HKDF-SHA256 matching Rust `encryption.rs`."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=bytes(salt),
        info=bytes(info),
    )
    return hkdf.derive(bytes(ikm))


# ---------------------------------------------------------------------------
# Public API (Native Rust with Pure-Python Fallback)
# ---------------------------------------------------------------------------


def noise_hkdf(chaining_key: bytes, ikm: bytes, num_outputs: int) -> list[bytes]:
    """Compute the Noise-protocol HKDF as implemented in the Rust reference."""
    if num_outputs < 1 or num_outputs > 255:
        raise ValueError(f"num_outputs must be in [1, 255], got {num_outputs}")
    if HAS_NATIVE_CORE and hasattr(_core, "noise_hkdf_raw"):
        try:
            return [
                bytes(b)
                for b in _core.noise_hkdf_raw(
                    bytes(chaining_key), bytes(ikm), num_outputs
                )
            ]
        except ValueError as exc:
            raise_mapped_error(exc)
    return py_noise_hkdf(chaining_key, ikm, num_outputs)


def legacy_hkdf(
    ikm: bytes,
    *,
    salt: bytes = b"bitchat-v1",
    info: bytes = b"",
    length: int = 32,
) -> bytes:
    """Derive a symmetric key using standard HKDF-SHA256."""
    if HAS_NATIVE_CORE and hasattr(_core, "legacy_hkdf_raw"):
        try:
            return bytes(
                _core.legacy_hkdf_raw(bytes(ikm), bytes(salt), bytes(info), length)
            )
        except ValueError as exc:
            raise_mapped_error(exc)
    return py_legacy_hkdf(ikm, salt=salt, info=info, length=length)
