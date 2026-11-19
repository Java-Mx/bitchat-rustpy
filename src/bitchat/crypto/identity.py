"""
Local cryptographic identity abstraction for BitChat.

A ``LocalIdentity`` represents a complete set of cryptographic keys for a
single BitChat session:
  - X25519 static key pair (key agreement, Noise static key)
  - Ed25519 key pair (message signing / verification)

The fingerprint and peer_id are derived from the X25519 public key:
  - ``get_identity_fingerprint`` in ``noise_session.rs`` line 628-631:
    ``SHA-256(X25519_public_key.to_bytes())`` → full hex string
  - Peer ID: first 8 bytes of SHA-256(X25519_public_key) → used for BLE
    identification in this Python implementation.

Private key material is NEVER exposed through:
  - ``__repr__``
  - ``__str__``
  - logging calls
  - exception messages
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from bitchat._native import HAS_NATIVE_CORE, _core, raise_mapped_error
from bitchat.crypto import ed25519 as _ed25519
from bitchat.crypto import x25519 as _x25519


@dataclass(frozen=True)
class LocalIdentity:
    """Immutable local cryptographic identity."""

    # Private key material — handled carefully
    x25519_private: bytes
    ed25519_private: bytes

    # Public material — safe to share
    x25519_public: bytes
    ed25519_public: bytes

    # Derived fields
    peer_id: bytes
    fingerprint: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "x25519_private", bytes(self.x25519_private))
        object.__setattr__(self, "ed25519_private", bytes(self.ed25519_private))
        object.__setattr__(self, "x25519_public", bytes(self.x25519_public))
        object.__setattr__(self, "ed25519_public", bytes(self.ed25519_public))
        object.__setattr__(self, "peer_id", bytes(self.peer_id))

    def __repr__(self) -> str:
        """Return a safe representation that NEVER exposes private key bytes."""
        return (
            f"LocalIdentity("
            f"fingerprint={self.fingerprint!r}, "
            f"peer_id={self.peer_id.hex()!r}"
            f")"
        )

    def __str__(self) -> str:
        return self.__repr__()

    # -----------------------------------------------------------------------
    # Public wire API
    # -----------------------------------------------------------------------

    @property
    def combined_public_key(self) -> bytes:
        """96-byte combined public key for wire exchange."""
        return self.x25519_public + self.ed25519_public + self.ed25519_public

    @property
    def peer_id_hex(self) -> str:
        """Hex-encoded peer ID string (16 lowercase hex characters)."""
        return self.peer_id.hex()

    @property
    def device_id(self) -> bytes:
        """Alias for peer_id representing the stable Device Identity."""
        return self.peer_id

    @property
    def device_id_hex(self) -> str:
        """Hex string of the stable Device Identity (16 lowercase hex characters)."""
        return self.peer_id.hex()

    # -----------------------------------------------------------------------
    # Factory methods
    # -----------------------------------------------------------------------

    @classmethod
    def generate(cls) -> LocalIdentity:
        """Generate a new random ``LocalIdentity`` using the OS CSPRNG."""
        x25519_priv = _x25519.generate_private_key()
        ed25519_priv = _ed25519.generate_signing_key()
        return cls._from_private_keys(x25519_priv, ed25519_priv)

    @classmethod
    def from_x25519_private(
        cls, x25519_private: bytes, ed25519_private: bytes | None = None
    ) -> LocalIdentity:
        """Construct a ``LocalIdentity`` from known private key bytes."""
        if ed25519_private is None:
            ed25519_priv = _ed25519.generate_signing_key()
        else:
            ed25519_priv = bytes(ed25519_private)
        return cls._from_private_keys(bytes(x25519_private), ed25519_priv)

    @classmethod
    def _from_private_keys(
        cls, x25519_priv: bytes, ed25519_priv: bytes
    ) -> LocalIdentity:
        """Internal factory from raw private key bytes."""
        if HAS_NATIVE_CORE and hasattr(_core, "derive_identity_from_private"):
            try:
                x_pub, ed_pub, peer_id, fp = _core.derive_identity_from_private(
                    bytes(x25519_priv), bytes(ed25519_priv)
                )
                return cls(
                    x25519_private=bytes(x25519_priv),
                    ed25519_private=bytes(ed25519_priv),
                    x25519_public=bytes(x_pub),
                    ed25519_public=bytes(ed_pub),
                    peer_id=bytes(peer_id),
                    fingerprint=fp,
                )
            except ValueError as exc:
                raise_mapped_error(exc)

        x25519_pub = _x25519.public_key_from_private(x25519_priv)
        ed25519_pub = _ed25519.public_key_from_private(ed25519_priv)
        fp_digest = hashlib.sha256(x25519_pub).digest()
        fingerprint = fp_digest.hex()
        peer_id = fp_digest[:8]

        return cls(
            x25519_private=x25519_priv,
            ed25519_private=ed25519_priv,
            x25519_public=x25519_pub,
            ed25519_public=ed25519_pub,
            peer_id=peer_id,
            fingerprint=fingerprint,
        )


# ---------------------------------------------------------------------------
# Peer fingerprint utilities
# ---------------------------------------------------------------------------


def py_calculate_fingerprint(x25519_public_key: bytes) -> str:
    """Pure-Python peer fingerprint calculation."""
    return hashlib.sha256(bytes(x25519_public_key)).hexdigest()


def calculate_fingerprint(x25519_public_key: bytes) -> str:
    """Calculate a BitChat peer fingerprint from an X25519 public key."""
    if HAS_NATIVE_CORE and hasattr(_core, "calculate_fingerprint_raw"):
        return _core.calculate_fingerprint_raw(bytes(x25519_public_key))
    return py_calculate_fingerprint(x25519_public_key)


def generate_instance_id() -> str:
    """Generate a 16-hex-character ephemeral process instance ID."""
    import os

    return os.urandom(8).hex()
