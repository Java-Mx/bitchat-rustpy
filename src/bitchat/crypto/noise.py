"""
Noise protocol implementation for BitChat: Noise_XX_25519_ChaChaPoly_SHA256.

Delegates to the native Rust `Noise_XX_25519_ChaChaPoly_SHA256` engine in
`bitchat._bitchat_core` when available, while retaining the pure-Python
reference state machines (`PyNoiseCipherState`, `PyNoiseSymmetricState`,
`PyNoiseHandshakeState`) for fallback and differential verification.

Do NOT log Noise cipher key material, shared secrets, or handshake state.
"""

from __future__ import annotations

import enum
import hashlib
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from bitchat._native import HAS_NATIVE_CORE, _core, raise_mapped_error
from bitchat.crypto.hkdf import noise_hkdf
from bitchat.crypto.x25519 import (
    diffie_hellman,
    generate_private_key,
    public_key_from_private,
    validate_public_key,
)
from bitchat.exceptions import (
    AuthenticationError,
    DecryptionError,
    EncryptionError,
    InvalidKeyError,
    InvalidNonceError,
    NoiseError,
    NoiseStateError,
    ReplayError,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NOISE_PROTOCOL_NAME: str = "Noise_XX_25519_ChaChaPoly_SHA256"
"""Full protocol name string (exactly 32 bytes as UTF-8)."""

NOISE_REPLAY_WINDOW_SIZE: int = 1024
"""Sliding window size for replay protection (matching Rust constant)."""

_NONCE_SIZE_BYTES: int = 4
"""Wire size of the nonce prefix prepended to transport ciphertext (4 bytes LE)."""

_CHACHA_NONCE_SIZE: int = 12
"""ChaCha20-Poly1305 requires a 12-byte nonce."""

_DH_KEY_SIZE: int = 32
"""X25519 key size in bytes."""

_TAG_SIZE: int = 16
"""ChaCha20-Poly1305 authentication tag size in bytes."""


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class NoiseRole(enum.Enum):
    """Role in a Noise handshake."""

    INITIATOR = "initiator"
    RESPONDER = "responder"


class NoiseSessionState(enum.Enum):
    """Lifecycle state of a Noise session."""

    UNINITIALIZED = "uninitialized"
    HANDSHAKING = "handshaking"
    ESTABLISHED = "established"
    FAILED = "failed"
    CLOSED = "closed"


class ObservableSessionPhase(enum.Enum):
    """Explicit observable connection and handshake phases (Section 7)."""

    DISCOVERED = "Discovered"
    CONNECTING = "Connecting"
    TRANSPORT_CONNECTED = "TransportConnected"
    GATT_READY = "GattReady"
    HANDSHAKE_INITIATED = "HandshakeInitiated"
    AWAITING_MESSAGE_2 = "AwaitingMessage2"
    AWAITING_MESSAGE_3 = "AwaitingMessage3"
    AUTHENTICATING_IDENTITY = "AuthenticatingIdentity"
    ESTABLISHED = "Established"
    FAILED = "Failed"
    CLOSING = "Closing"
    CLOSED = "Closed"


# ---------------------------------------------------------------------------
# Handshake role determination
# ---------------------------------------------------------------------------


def py_determine_handshake_role(
    my_peer_id_hex: str, remote_peer_id_hex: str
) -> NoiseRole:
    """Pure-Python handshake role determination."""
    if not my_peer_id_hex:
        raise ValueError("my_peer_id_hex must not be empty")
    if not remote_peer_id_hex:
        raise ValueError("remote_peer_id_hex must not be empty")
    if my_peer_id_hex < remote_peer_id_hex:
        return NoiseRole.INITIATOR
    return NoiseRole.RESPONDER


def determine_handshake_role(my_peer_id_hex: str, remote_peer_id_hex: str) -> NoiseRole:
    """Determine the Noise role based on lexicographic peer ID comparison."""
    if HAS_NATIVE_CORE and hasattr(_core, "determine_handshake_role_raw"):
        try:
            role_str = _core.determine_handshake_role_raw(
                my_peer_id_hex, remote_peer_id_hex
            )
            return (
                NoiseRole.INITIATOR if role_str == "initiator" else NoiseRole.RESPONDER
            )
        except ValueError as exc:
            raise_mapped_error(exc)
    return py_determine_handshake_role(my_peer_id_hex, remote_peer_id_hex)


# ---------------------------------------------------------------------------
# Pure-Python Reference Implementations (retained for differential tests)
# ---------------------------------------------------------------------------


class PyNoiseCipherState:
    """Pure-Python symmetric AEAD cipher state for Noise protocol."""

    def __init__(
        self,
        key: bytes | None = None,
        *,
        use_extracted_nonce: bool = False,
    ) -> None:
        self._key: bytes | None = bytes(key) if key is not None else None
        self._nonce: int = 0
        self._use_extracted_nonce: bool = use_extracted_nonce
        self._replay_window: set[int] = set()
        self._highest_received_nonce: int = 0

    def has_key(self) -> bool:
        return self._key is not None

    def initialize_key(self, key: bytes) -> None:
        self._key = bytes(key)
        self._nonce = 0
        self._replay_window.clear()
        self._highest_received_nonce = 0

    def clear_key(self) -> None:
        self._key = None
        self._nonce = 0
        self._replay_window.clear()
        self._highest_received_nonce = 0

    def _build_chacha_nonce(self, counter: int) -> bytes:
        nonce_bytes = bytearray(12)
        nonce_bytes[4:12] = counter.to_bytes(8, "little")
        return bytes(nonce_bytes)

    def _counter_to_wire_bytes(self, counter: int) -> bytes:
        return counter.to_bytes(8, "little")[:_NONCE_SIZE_BYTES]

    def _extract_wire_nonce(self, data: bytes) -> tuple[int, bytes]:
        if len(data) < _NONCE_SIZE_BYTES:
            raise InvalidNonceError(
                f"Ciphertext too short to contain 4-byte nonce prefix "
                f"(got {len(data)} bytes)"
            )
        counter_bytes = data[:_NONCE_SIZE_BYTES]
        counter = int.from_bytes(counter_bytes, "little")
        return counter, data[_NONCE_SIZE_BYTES:]

    def _is_valid_nonce(self, received_nonce: int) -> bool:
        if received_nonce + NOISE_REPLAY_WINDOW_SIZE <= self._highest_received_nonce:
            return False
        if received_nonce > self._highest_received_nonce:
            return True
        return received_nonce not in self._replay_window

    def _mark_nonce_seen(self, received_nonce: int) -> None:
        if received_nonce > self._highest_received_nonce:
            shift = received_nonce - self._highest_received_nonce
            if shift >= NOISE_REPLAY_WINDOW_SIZE:
                self._replay_window.clear()
            else:
                self._replay_window = {
                    n
                    for n in self._replay_window
                    if n + NOISE_REPLAY_WINDOW_SIZE > received_nonce
                }
            self._highest_received_nonce = received_nonce
        self._replay_window.add(received_nonce)

    def encrypt(self, plaintext: bytes, aad: bytes) -> bytes:
        if self._key is None:
            raise NoiseStateError("NoiseCipherState: no key initialised (encrypt)")
        current_nonce = self._nonce
        chacha_nonce = self._build_chacha_nonce(current_nonce)
        try:
            cipher = ChaCha20Poly1305(self._key)
            ciphertext = cipher.encrypt(chacha_nonce, bytes(plaintext), bytes(aad))
        except Exception as exc:
            raise EncryptionError(
                f"ChaCha20-Poly1305 encryption failed: {exc}"
            ) from exc
        self._nonce += 1
        if self._use_extracted_nonce:
            return self._counter_to_wire_bytes(current_nonce) + ciphertext
        return ciphertext

    def decrypt(self, ciphertext: bytes, aad: bytes) -> bytes:
        if self._key is None:
            raise NoiseStateError("NoiseCipherState: no key initialised (decrypt)")

        if self._use_extracted_nonce:
            counter, payload = self._extract_wire_nonce(bytes(ciphertext))
            if counter >= 0 and not self._is_valid_nonce(counter):
                raise ReplayError(
                    f"Replay detected: nonce {counter} has already been seen "
                    f"or is outside the replay window"
                )
            chacha_nonce = self._build_chacha_nonce(counter)
        else:
            counter = self._nonce
            payload = bytes(ciphertext)
            chacha_nonce = self._build_chacha_nonce(counter)

        try:
            cipher = ChaCha20Poly1305(self._key)
            plaintext = cipher.decrypt(chacha_nonce, payload, bytes(aad))
        except Exception as exc:
            raise DecryptionError(
                "ChaCha20-Poly1305 decryption or authentication failed"
            ) from exc

        if self._use_extracted_nonce:
            if counter >= 0:
                self._mark_nonce_seen(counter)
        else:
            self._nonce += 1

        return plaintext


class PyNoiseSymmetricState:
    """Pure-Python running cryptographic state during a Noise handshake."""

    def __init__(self, protocol_name: str) -> None:
        name_bytes = protocol_name.encode("utf-8")
        if len(name_bytes) <= 32:
            h = bytearray(32)
            h[: len(name_bytes)] = name_bytes
            initial_hash = bytes(h)
        else:
            initial_hash = hashlib.sha256(name_bytes).digest()

        self._hash: bytes = initial_hash
        self._chaining_key: bytes = initial_hash
        self._cipher_state: PyNoiseCipherState = PyNoiseCipherState()

    def has_cipher_key(self) -> bool:
        return self._cipher_state.has_key()

    def get_handshake_hash(self) -> bytes:
        return self._hash

    def mix_key(self, ikm: bytes) -> None:
        outputs = noise_hkdf(self._chaining_key, ikm, 2)
        self._chaining_key = outputs[0]
        self._cipher_state.initialize_key(outputs[1])

    def mix_hash(self, data: bytes) -> None:
        self._hash = hashlib.sha256(self._hash + bytes(data)).digest()

    def mix_key_and_hash(self, ikm: bytes) -> None:
        outputs = noise_hkdf(self._chaining_key, ikm, 3)
        self._chaining_key = outputs[0]
        self.mix_hash(outputs[1])
        self._cipher_state.initialize_key(outputs[2])

    def encrypt_and_hash(self, plaintext: bytes) -> bytes:
        if self._cipher_state.has_key():
            ciphertext = self._cipher_state.encrypt(bytes(plaintext), self._hash)
            self.mix_hash(ciphertext)
            return ciphertext
        else:
            self.mix_hash(bytes(plaintext))
            return bytes(plaintext)

    def decrypt_and_hash(self, ciphertext: bytes) -> bytes:
        if self._cipher_state.has_key():
            if len(ciphertext) == 0:
                self.mix_hash(b"")
                return b""
            try:
                plaintext = self._cipher_state.decrypt(bytes(ciphertext), self._hash)
            except (DecryptionError, ReplayError) as exc:
                raise AuthenticationError(
                    "Noise handshake payload authentication failed"
                ) from exc
            self.mix_hash(bytes(ciphertext))
            return plaintext
        else:
            self.mix_hash(bytes(ciphertext))
            return bytes(ciphertext)

    def split(self) -> tuple[PyNoiseCipherState, PyNoiseCipherState]:
        outputs = noise_hkdf(self._chaining_key, b"", 2)
        c1 = PyNoiseCipherState(outputs[0], use_extracted_nonce=True)
        c2 = PyNoiseCipherState(outputs[1], use_extracted_nonce=True)
        return c1, c2


class PyNoiseHandshakeState:
    """Pure-Python Noise XX handshake state machine."""

    _XX_PATTERNS: tuple[list[str], ...] = (
        ["E"],
        ["E", "EE", "S", "ES"],
        ["S", "SE"],
    )

    def __init__(
        self,
        role: NoiseRole,
        local_static_private: bytes,
        remote_static_public: bytes | None = None,
        *,
        fixed_ephemeral_private: bytes | None = None,
    ) -> None:
        self._role = role
        self._local_static_private = bytes(local_static_private)
        self._local_static_public = public_key_from_private(local_static_private)
        self._local_ephemeral_private: bytes | None = None
        self._local_ephemeral_public: bytes | None = None
        self._remote_static_public: bytes | None = (
            bytes(remote_static_public) if remote_static_public is not None else None
        )
        self._remote_ephemeral_public: bytes | None = None
        self._fixed_ephemeral_private: bytes | None = (
            bytes(fixed_ephemeral_private)
            if fixed_ephemeral_private is not None
            else None
        )

        self._symmetric_state = PyNoiseSymmetricState(NOISE_PROTOCOL_NAME)
        self._patterns = self._XX_PATTERNS
        self._current_pattern = 0
        self._symmetric_state.mix_hash(b"")

    def is_handshake_complete(self) -> bool:
        return self._current_pattern >= len(self._patterns)

    def get_transport_ciphers(
        self,
    ) -> tuple[PyNoiseCipherState, PyNoiseCipherState]:
        if not self.is_handshake_complete():
            raise NoiseStateError(
                "Handshake is not complete; cannot get transport ciphers"
            )
        c1, c2 = self._symmetric_state.split()
        if self._role == NoiseRole.INITIATOR:
            return c1, c2
        else:
            return c2, c1

    def get_remote_static_public_key(self) -> bytes | None:
        return self._remote_static_public

    def get_handshake_hash(self) -> bytes:
        return self._symmetric_state.get_handshake_hash()

    def write_message(self, payload: bytes) -> bytes:
        if self.is_handshake_complete():
            raise NoiseStateError("Handshake is complete; cannot write more messages")

        message_buffer = bytearray()
        patterns = self._patterns[self._current_pattern]

        for token in patterns:
            match token:
                case "E":
                    if self._fixed_ephemeral_private is not None:
                        self._local_ephemeral_private = self._fixed_ephemeral_private
                        self._fixed_ephemeral_private = None
                    else:
                        self._local_ephemeral_private = generate_private_key()
                    self._local_ephemeral_public = public_key_from_private(
                        self._local_ephemeral_private
                    )
                    message_buffer.extend(self._local_ephemeral_public)
                    self._symmetric_state.mix_hash(self._local_ephemeral_public)

                case "S":
                    encrypted_static = self._symmetric_state.encrypt_and_hash(
                        self._local_static_public
                    )
                    message_buffer.extend(encrypted_static)

                case "EE":
                    self._dh_mix_key(
                        self._local_ephemeral_private,
                        self._remote_ephemeral_public,
                        "EE",
                    )

                case "ES":
                    if self._role == NoiseRole.INITIATOR:
                        self._dh_mix_key(
                            self._local_ephemeral_private,
                            self._remote_static_public,
                            "ES(initiator)",
                        )
                    else:
                        self._dh_mix_key(
                            self._local_static_private,
                            self._remote_ephemeral_public,
                            "ES(responder)",
                        )

                case "SE":
                    if self._role == NoiseRole.INITIATOR:
                        self._dh_mix_key(
                            self._local_static_private,
                            self._remote_ephemeral_public,
                            "SE(initiator)",
                        )
                    else:
                        self._dh_mix_key(
                            self._local_ephemeral_private,
                            self._remote_static_public,
                            "SE(responder)",
                        )

        encrypted_payload = self._symmetric_state.encrypt_and_hash(bytes(payload))
        message_buffer.extend(encrypted_payload)
        self._current_pattern += 1
        return bytes(message_buffer)

    def read_message(self, message: bytes) -> bytes:
        if self.is_handshake_complete():
            raise NoiseStateError("Handshake is complete; cannot read more messages")

        patterns = self._patterns[self._current_pattern]
        offset = 0
        message = bytes(message)

        for token in patterns:
            match token:
                case "E":
                    if offset + _DH_KEY_SIZE > len(message):
                        raise NoiseError(
                            f"Message too short for ephemeral key at offset {offset}"
                        )
                    ephemeral_bytes = message[offset : offset + _DH_KEY_SIZE]
                    offset += _DH_KEY_SIZE
                    self._remote_ephemeral_public = ephemeral_bytes
                    self._symmetric_state.mix_hash(ephemeral_bytes)

                case "S":
                    key_len = (
                        _DH_KEY_SIZE + _TAG_SIZE
                        if self._symmetric_state.has_cipher_key()
                        else _DH_KEY_SIZE
                    )
                    if offset + key_len > len(message):
                        raise NoiseError(
                            f"Message too short for static key at offset {offset}"
                        )
                    static_data = message[offset : offset + key_len]
                    offset += key_len
                    decrypted_static = self._symmetric_state.decrypt_and_hash(
                        static_data
                    )
                    if len(decrypted_static) != _DH_KEY_SIZE:
                        msg = (
                            f"Decrypted static key has wrong length: "
                            f"{len(decrypted_static)}"
                        )
                        raise AuthenticationError(msg)
                    try:
                        validated = validate_public_key(decrypted_static)
                    except InvalidKeyError as exc:
                        raise AuthenticationError(
                            "Static public key validation failed"
                        ) from exc
                    self._remote_static_public = validated

                case "EE":
                    self._dh_mix_key(
                        self._local_ephemeral_private,
                        self._remote_ephemeral_public,
                        "EE",
                    )

                case "ES":
                    if self._role == NoiseRole.INITIATOR:
                        self._dh_mix_key(
                            self._local_ephemeral_private,
                            self._remote_static_public,
                            "ES(initiator)",
                        )
                    else:
                        self._dh_mix_key(
                            self._local_static_private,
                            self._remote_ephemeral_public,
                            "ES(responder)",
                        )

                case "SE":
                    if self._role == NoiseRole.INITIATOR:
                        self._dh_mix_key(
                            self._local_static_private,
                            self._remote_ephemeral_public,
                            "SE(initiator)",
                        )
                    else:
                        self._dh_mix_key(
                            self._local_ephemeral_private,
                            self._remote_static_public,
                            "SE(responder)",
                        )

        payload_bytes = message[offset:]
        decrypted_payload = self._symmetric_state.decrypt_and_hash(payload_bytes)
        self._current_pattern += 1
        return decrypted_payload

    def _dh_mix_key(
        self,
        local_private: bytes | None,
        remote_public: bytes | None,
        label: str,
    ) -> None:
        if local_private is None:
            raise NoiseError(f"Missing local private key for DH operation: {label}")
        if remote_public is None:
            raise NoiseError(f"Missing remote public key for DH operation: {label}")
        shared = diffie_hellman(local_private, remote_public)
        self._symmetric_state.mix_key(shared)


# ---------------------------------------------------------------------------
# Public API Classes (Native Rust with Pure-Python Fallback)
# ---------------------------------------------------------------------------


class NoiseCipherState:
    """Symmetric AEAD cipher state for Noise protocol backed by Rust `_bitchat_core`."""

    def __init__(
        self,
        key: bytes | None = None,
        *,
        use_extracted_nonce: bool = False,
        _native_instance: Any | None = None,
    ) -> None:
        self._key: bytes | None = bytes(key) if key is not None else None
        self._use_extracted_nonce: bool = use_extracted_nonce
        if _native_instance is not None:
            self._native = _native_instance
            self._py: PyNoiseCipherState | None = None
            if (
                self._key is None
                and hasattr(_native_instance, "key")
                and _native_instance.key is not None
            ):
                self._key = bytes(_native_instance.key)
        elif HAS_NATIVE_CORE and hasattr(_core, "NativeNoiseCipherState"):
            try:
                self._native = _core.NativeNoiseCipherState(
                    bytes(key) if key is not None else None,
                    use_extracted_nonce,
                )
                self._py = None
            except ValueError as exc:
                raise_mapped_error(exc)
        else:
            self._native = None
            self._py = PyNoiseCipherState(key, use_extracted_nonce=use_extracted_nonce)

    @property
    def _nonce(self) -> int:
        if self._native is not None:
            return int(self._native.nonce)
        assert self._py is not None
        return self._py._nonce

    @_nonce.setter
    def _nonce(self, val: int) -> None:
        if self._native is not None:
            self._native.nonce = int(val)
        elif self._py is not None:
            self._py._nonce = int(val)

    @property
    def _highest_received_nonce(self) -> int:
        if self._native is not None:
            return int(self._native.highest_received_nonce)
        assert self._py is not None
        return self._py._highest_received_nonce

    @_highest_received_nonce.setter
    def _highest_received_nonce(self, val: int) -> None:
        if self._native is not None:
            self._native.highest_received_nonce = int(val)
        elif self._py is not None:
            self._py._highest_received_nonce = int(val)

    @property
    def _replay_window(self) -> set[int]:
        if self._native is not None:
            return set(self._native.replay_window)
        assert self._py is not None
        return self._py._replay_window

    @_replay_window.setter
    def _replay_window(self, window: set[int]) -> None:
        if self._native is not None:
            self._native.replay_window = {int(x) for x in window}
        elif self._py is not None:
            self._py._replay_window = {int(x) for x in window}

    def has_key(self) -> bool:
        """Return True if a cipher key has been initialised."""
        if self._native is not None:
            return bool(self._native.has_key())
        assert self._py is not None
        return self._py.has_key()

    def initialize_key(self, key: bytes) -> None:
        """Set (or reset) the cipher key."""
        self._key = bytes(key)
        if self._native is not None:
            try:
                self._native.initialize_key(bytes(key))
                return
            except ValueError as exc:
                raise_mapped_error(exc)
        assert self._py is not None
        self._py.initialize_key(key)

    def clear_key(self) -> None:
        """Clear and zeroize the cipher key."""
        self._key = None
        if self._native is not None:
            self._native.clear_key()
            return
        if self._py is not None:
            self._py.clear_key()

    def encrypt(self, plaintext: bytes, aad: bytes) -> bytes:
        """Encrypt with the current nonce, then advance the counter."""
        if self._native is not None:
            try:
                return bytes(self._native.encrypt(bytes(plaintext), bytes(aad)))
            except ValueError as exc:
                raise_mapped_error(exc)
        assert self._py is not None
        return self._py.encrypt(plaintext, aad)

    def decrypt(self, ciphertext: bytes, aad: bytes) -> bytes:
        """Decrypt and authenticate, advancing the nonce counter."""
        if self._native is not None:
            try:
                return bytes(self._native.decrypt(bytes(ciphertext), bytes(aad)))
            except ValueError as exc:
                raise_mapped_error(exc)
        assert self._py is not None
        return self._py.decrypt(ciphertext, aad)


class NoiseSymmetricState:
    """Manages the running cryptographic state during a Noise handshake."""

    def __init__(self, protocol_name: str) -> None:
        if HAS_NATIVE_CORE and hasattr(_core, "NativeNoiseSymmetricState"):
            self._native = _core.NativeNoiseSymmetricState(protocol_name)
            self._py: PyNoiseSymmetricState | None = None
        else:
            self._native = None
            self._py = PyNoiseSymmetricState(protocol_name)

    def has_cipher_key(self) -> bool:
        if self._native is not None:
            return bool(self._native.has_cipher_key())
        assert self._py is not None
        return self._py.has_cipher_key()

    def get_handshake_hash(self) -> bytes:
        if self._native is not None:
            return bytes(self._native.get_handshake_hash())
        assert self._py is not None
        return self._py.get_handshake_hash()

    def mix_key(self, ikm: bytes) -> None:
        if self._native is not None:
            try:
                self._native.mix_key(bytes(ikm))
                return
            except ValueError as exc:
                raise_mapped_error(exc)
        assert self._py is not None
        self._py.mix_key(ikm)

    def mix_hash(self, data: bytes) -> None:
        if self._native is not None:
            self._native.mix_hash(bytes(data))
            return
        assert self._py is not None
        self._py.mix_hash(data)

    def mix_key_and_hash(self, ikm: bytes) -> None:
        if self._native is not None:
            try:
                self._native.mix_key_and_hash(bytes(ikm))
                return
            except ValueError as exc:
                raise_mapped_error(exc)
        assert self._py is not None
        self._py.mix_key_and_hash(ikm)

    def encrypt_and_hash(self, plaintext: bytes) -> bytes:
        if self._native is not None:
            try:
                return bytes(self._native.encrypt_and_hash(bytes(plaintext)))
            except ValueError as exc:
                raise_mapped_error(exc)
        assert self._py is not None
        return self._py.encrypt_and_hash(plaintext)

    def decrypt_and_hash(self, ciphertext: bytes) -> bytes:
        if self._native is not None:
            try:
                return bytes(self._native.decrypt_and_hash(bytes(ciphertext)))
            except ValueError as exc:
                raise_mapped_error(exc)
        assert self._py is not None
        return self._py.decrypt_and_hash(ciphertext)

    def split(self) -> tuple[NoiseCipherState, NoiseCipherState]:
        if self._native is not None:
            try:
                c1_nat, c2_nat = self._native.split()
                return (
                    NoiseCipherState(use_extracted_nonce=True, _native_instance=c1_nat),
                    NoiseCipherState(use_extracted_nonce=True, _native_instance=c2_nat),
                )
            except ValueError as exc:
                raise_mapped_error(exc)
        assert self._py is not None
        c1_py, c2_py = self._py.split()
        return (
            NoiseCipherState(c1_py._key, use_extracted_nonce=True),
            NoiseCipherState(c2_py._key, use_extracted_nonce=True),
        )


class NoiseHandshakeState:
    """Orchestrates the Noise XX handshake message exchange."""

    def __init__(
        self,
        role: NoiseRole,
        local_static_private: bytes,
        remote_static_public: bytes | None = None,
        *,
        fixed_ephemeral_private: bytes | None = None,
    ) -> None:
        self._role = role
        if HAS_NATIVE_CORE and hasattr(_core, "NativeNoiseHandshakeState"):
            try:
                self._native = _core.NativeNoiseHandshakeState(
                    role.value,
                    bytes(local_static_private),
                    bytes(remote_static_public)
                    if remote_static_public is not None
                    else None,
                    bytes(fixed_ephemeral_private)
                    if fixed_ephemeral_private is not None
                    else None,
                )
                self._py: PyNoiseHandshakeState | None = None
            except ValueError as exc:
                raise_mapped_error(exc)
        else:
            self._native = None
            self._py = PyNoiseHandshakeState(
                role,
                local_static_private,
                remote_static_public,
                fixed_ephemeral_private=fixed_ephemeral_private,
            )

    def is_handshake_complete(self) -> bool:
        if self._native is not None:
            return bool(self._native.is_handshake_complete())
        assert self._py is not None
        return self._py.is_handshake_complete()

    def get_transport_ciphers(self) -> tuple[NoiseCipherState, NoiseCipherState]:
        if self._native is not None:
            try:
                c1_nat, c2_nat = self._native.get_transport_ciphers()
                return (
                    NoiseCipherState(use_extracted_nonce=True, _native_instance=c1_nat),
                    NoiseCipherState(use_extracted_nonce=True, _native_instance=c2_nat),
                )
            except ValueError as exc:
                raise_mapped_error(exc)
        assert self._py is not None
        c1_py, c2_py = self._py.get_transport_ciphers()
        return (
            NoiseCipherState(c1_py._key, use_extracted_nonce=True),
            NoiseCipherState(c2_py._key, use_extracted_nonce=True),
        )

    def get_remote_static_public_key(self) -> bytes | None:
        if self._native is not None:
            res = self._native.get_remote_static_public_key()
            return bytes(res) if res is not None else None
        assert self._py is not None
        return self._py.get_remote_static_public_key()

    def get_handshake_hash(self) -> bytes:
        if self._native is not None:
            return bytes(self._native.get_handshake_hash())
        assert self._py is not None
        return self._py.get_handshake_hash()

    def write_message(self, payload: bytes) -> bytes:
        if self._native is not None:
            try:
                return bytes(self._native.write_message(bytes(payload)))
            except ValueError as exc:
                raise_mapped_error(exc)
        assert self._py is not None
        return self._py.write_message(payload)

    def read_message(self, message: bytes) -> bytes:
        if self._native is not None:
            try:
                return bytes(self._native.read_message(bytes(message)))
            except ValueError as exc:
                raise_mapped_error(exc)
        assert self._py is not None
        return self._py.read_message(message)
