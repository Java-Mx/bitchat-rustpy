"""
High-level Noise session abstraction for BitChat.

``NoiseSession`` delegates authoritatively to the native Rust
``NativeNoiseSession`` engine in ``bitchat._bitchat_core`` (which owns the
Noise XX handshake state, transport ciphers, replay window, nonce counters,
key zeroization, legacy TUI peer-ID policy, and 12-phase observable state
machine).

``PyNoiseSession`` is retained strictly as an independent pure-Python
reference implementation for differential verification and environments
where the compiled native extension is unavailable. Active native sessions
never fall back to Python on cryptographic errors or maintain a second
authoritative cipher state.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from typing import Any

from bitchat._native import HAS_NATIVE_CORE, _core, raise_mapped_error
from bitchat.crypto.identity import LocalIdentity, calculate_fingerprint
from bitchat.crypto.noise import (
    NoiseRole,
    NoiseSessionState,
    ObservableSessionPhase,
    PyNoiseCipherState,
    PyNoiseHandshakeState,
    determine_handshake_role,
)
from bitchat.exceptions import (
    AuthenticationError,
    CryptoError,
    InvalidNonceError,
    NoiseError,
    NoiseStateError,
)


def _is_legacy_tui_peer_id(peer_id_bytes: bytes) -> bool:
    """Return True for a 4-byte random legacy TUI ID zero-extended to 8 bytes."""
    return (
        len(peer_id_bytes) == 8
        and peer_id_bytes[4:8] == b"\x00\x00\x00\x00"
        and peer_id_bytes[0:4] != b"\x00\x00\x00\x00"
    )


def py_classify_peer_id(hex_str: str) -> str:
    """Pure-Python peer ID classification (`legacy_tui` vs `modern`)."""
    clean = hex_str.strip().lower()
    if len(clean) != 16:
        raise ValueError("Remote peer ID must be 16 hexadecimal characters")
    raw = bytes.fromhex(clean)
    if raw == b"\x00" * 8:
        raise ValueError("Peer ID must not be all zeros")
    if raw == b"\xff" * 8:
        raise ValueError("Broadcast ID is not a valid unicast peer ID")
    return "legacy_tui" if _is_legacy_tui_peer_id(raw) else "modern"


def classify_peer_id(hex_str: str) -> str:
    """Classify a 16-hex-char peer ID as `'legacy_tui'` or `'modern'` via Rust core."""
    if HAS_NATIVE_CORE and hasattr(_core, "classify_peer_id_raw"):
        try:
            return str(_core.classify_peer_id_raw(hex_str))
        except ValueError as exc:
            raise_mapped_error(exc)
    return py_classify_peer_id(hex_str)


_STATE_FROM_STR: dict[str, NoiseSessionState] = {s.value: s for s in NoiseSessionState}
_PHASE_FROM_STR: dict[str, ObservableSessionPhase] = {
    p.value: p for p in ObservableSessionPhase
}


class PyNoiseSession:
    """Pure-Python reference Noise XX session (for differential tests & fallback)."""

    def __init__(
        self,
        local_identity: LocalIdentity,
        remote_peer_id: str,
        role: NoiseRole | None = None,
        transport: str = "lan",
        *,
        allow_legacy_peer_id: bool = True,
        expected_fingerprint: str | None = None,
    ) -> None:
        self._local_identity = local_identity
        self._remote_peer_id = remote_peer_id
        self._transport = transport
        self._role: NoiseRole = (
            role
            if role is not None
            else determine_handshake_role(local_identity.peer_id_hex, remote_peer_id)
        )
        self._state: NoiseSessionState = NoiseSessionState.UNINITIALIZED
        self._handshake_state: PyNoiseHandshakeState | None = None
        self._send_cipher: PyNoiseCipherState | None = None
        self._recv_cipher: PyNoiseCipherState | None = None
        self._remote_static_public: bytes | None = None
        self._handshake_hash: bytes | None = None
        self._remote_fingerprint: str | None = None
        self._expected_fingerprint: str | None = (
            expected_fingerprint.strip().lower()
            if expected_fingerprint is not None
            else None
        )
        self._allow_legacy_peer_id: bool = allow_legacy_peer_id
        self._identity_mode: str = "modern"
        self._trust_level: str = "observed"
        self._handshake_started_at: float | None = None
        self._observable_phase: ObservableSessionPhase = (
            ObservableSessionPhase.DISCOVERED
        )
        self._diagnostic_reason: str = "Peer discovered"
        self._history: list[tuple[str, float, str]] = [
            (self._observable_phase.value, time.monotonic(), self._diagnostic_reason)
        ]

    @property
    def state(self) -> NoiseSessionState:
        return self._state

    @property
    def observable_phase(self) -> ObservableSessionPhase:
        return self._observable_phase

    @property
    def diagnostic_reason(self) -> str:
        return self._diagnostic_reason

    @property
    def role(self) -> NoiseRole:
        return self._role

    @property
    def remote_peer_id(self) -> str:
        return self._remote_peer_id

    @property
    def remote_fingerprint(self) -> str | None:
        return self._remote_fingerprint

    @property
    def expected_fingerprint(self) -> str | None:
        return self._expected_fingerprint

    @expected_fingerprint.setter
    def expected_fingerprint(self, fp: str | None) -> None:
        self._expected_fingerprint = fp.strip().lower() if fp is not None else None

    @property
    def identity_mode(self) -> str:
        return self._identity_mode

    @property
    def trust_level(self) -> str:
        return self._trust_level

    @property
    def handshake_hash(self) -> bytes | None:
        return self._handshake_hash

    @property
    def is_established(self) -> bool:
        return self._state == NoiseSessionState.ESTABLISHED

    @property
    def send_nonce(self) -> int:
        return self._send_cipher._nonce if self._send_cipher is not None else 0

    @property
    def highest_received_nonce(self) -> int:
        return (
            self._recv_cipher._highest_received_nonce
            if self._recv_cipher is not None
            else 0
        )

    def needs_rekey(self) -> bool:
        return self._send_cipher is not None and self._send_cipher.needs_rekey()

    def mark_user_verified(self) -> None:
        if self._remote_fingerprint is None:
            raise NoiseStateError(
                "Cannot mark peer verified before authenticating a remote static key"
            )
        self._trust_level = "verified"

    def record_phase(self, phase: ObservableSessionPhase, reason: str = "") -> None:
        self._observable_phase = phase
        self._diagnostic_reason = reason or phase.value
        if len(self._history) >= 32:
            self._history.pop(0)
        self._history.append((phase.value, time.monotonic(), self._diagnostic_reason))

    def phase_history(self) -> list[tuple[str, float, str]]:
        return list(self._history)

    def reset_for_rehandshake(self, new_role: NoiseRole | None = None) -> None:
        if new_role is not None:
            self._role = new_role
        self._state = NoiseSessionState.UNINITIALIZED
        self._handshake_state = None
        self._send_cipher = None
        self._recv_cipher = None
        self._remote_static_public = None
        self._handshake_hash = None
        self._remote_fingerprint = None
        self._trust_level = "observed"
        self._handshake_started_at = None
        self.record_phase(
            ObservableSessionPhase.HANDSHAKE_INITIATED,
            "Session reset for fresh handshake",
        )

    def start_handshake(self) -> bytes | None:
        if self._state != NoiseSessionState.UNINITIALIZED:
            raise NoiseStateError(
                f"start_handshake() called in invalid state: {self._state.value}"
            )
        self._handshake_state = PyNoiseHandshakeState(
            role=self._role,
            local_static_private=self._local_identity.x25519_private,
        )
        self._state = NoiseSessionState.HANDSHAKING
        self._handshake_started_at = time.monotonic()
        self.record_phase(
            ObservableSessionPhase.HANDSHAKE_INITIATED,
            f"Handshake started as {self._role.value}",
        )
        if self._role == NoiseRole.INITIATOR:
            msg1 = self._handshake_state.write_message(b"")
            self.record_phase(
                ObservableSessionPhase.AWAITING_MESSAGE_2,
                "Noise XX Message 1 [E] generated",
            )
            return msg1
        return None

    def process_handshake_message(self, message: bytes) -> bytes | None:
        try:
            if (
                self._state == NoiseSessionState.UNINITIALIZED
                and self._role == NoiseRole.RESPONDER
            ):
                self._handshake_state = PyNoiseHandshakeState(
                    role=self._role,
                    local_static_private=self._local_identity.x25519_private,
                )
                self._state = NoiseSessionState.HANDSHAKING
                self._handshake_started_at = time.monotonic()
                self.record_phase(
                    ObservableSessionPhase.HANDSHAKE_INITIATED,
                    "Responder auto-initialized on inbound Message 1",
                )

            if self._state != NoiseSessionState.HANDSHAKING:
                raise NoiseStateError(
                    f"process_handshake_message() called in invalid state: "
                    f"{self._state.value}"
                )
            if self._handshake_state is None:
                raise NoiseStateError("Handshake state is not initialised")

            _payload = self._handshake_state.read_message(bytes(message))

            response: bytes | None = None
            if not self._handshake_state.is_handshake_complete():
                response = self._handshake_state.write_message(b"")
                if self._role == NoiseRole.RESPONDER:
                    self.record_phase(
                        ObservableSessionPhase.AWAITING_MESSAGE_3,
                        "Noise XX Message 2 [E, EE, S, ES] generated",
                    )

            if self._handshake_state.is_handshake_complete():
                self.record_phase(
                    ObservableSessionPhase.AUTHENTICATING_IDENTITY,
                    "Verifying remote static key and peer-ID binding",
                )
                self._finalise_handshake()

            return response
        except (NoiseError, CryptoError, Exception) as exc:
            self._handshake_state = None
            self._send_cipher = None
            self._recv_cipher = None
            self._state = NoiseSessionState.FAILED
            self.record_phase(
                ObservableSessionPhase.FAILED,
                f"Handshake failed: {type(exc).__name__}",
            )
            raise

    def _finalise_handshake(self) -> None:
        assert self._handshake_state is not None
        remote_static_public = self._handshake_state.get_remote_static_public_key()
        if remote_static_public is None:
            self._state = NoiseSessionState.FAILED
            self._handshake_state = None
            raise AuthenticationError(
                "Noise handshake did not authenticate a remote key"
            )
        try:
            clean_remote = self._remote_peer_id.strip().lower()
            if len(clean_remote) != 16:
                raise ValueError("Remote peer ID must be 16 hexadecimal characters")
            claimed_peer_id = bytes.fromhex(clean_remote)
        except ValueError as err:
            self._state = NoiseSessionState.FAILED
            self._handshake_state = None
            raise AuthenticationError(
                "Remote peer ID is not valid hexadecimal"
            ) from err

        if hmac.compare_digest(
            remote_static_public, self._local_identity.x25519_public
        ):
            self._state = NoiseSessionState.FAILED
            self._handshake_state = None
            raise AuthenticationError(
                "Self-connection rejected: remote peer authenticated "
                "with local device identity"
            )

        authenticated_peer_id = hashlib.sha256(remote_static_public).digest()[:8]
        fp = calculate_fingerprint(remote_static_public)
        modern_matches = len(claimed_peer_id) == len(
            authenticated_peer_id
        ) and hmac.compare_digest(authenticated_peer_id, claimed_peer_id)

        if modern_matches:
            self._identity_mode = "modern"
        elif self._allow_legacy_peer_id and _is_legacy_tui_peer_id(claimed_peer_id):
            self._identity_mode = "legacy_tui"
        else:
            self._state = NoiseSessionState.FAILED
            self._handshake_state = None
            raise AuthenticationError(
                "Authenticated Noise static key does not match claimed peer ID"
            )

        if self._expected_fingerprint is not None and not hmac.compare_digest(
            self._expected_fingerprint.encode("ascii"),
            fp.encode("ascii"),
        ):
            self._state = NoiseSessionState.FAILED
            self._handshake_state = None
            raise AuthenticationError(
                "Conflicting identity mapping: authenticated Noise static key "
                "does not match pinned fingerprint"
            )

        send_cipher, recv_cipher = self._handshake_state.get_transport_ciphers()
        self._send_cipher = send_cipher
        self._recv_cipher = recv_cipher
        self._remote_static_public = remote_static_public
        self._handshake_hash = self._handshake_state.get_handshake_hash()
        self._remote_fingerprint = fp
        self._trust_level = "authenticated"
        self._handshake_state = None
        self._state = NoiseSessionState.ESTABLISHED
        self.record_phase(
            ObservableSessionPhase.ESTABLISHED,
            "Noise XX transport established and peer identity verified",
        )

    def encrypt(self, plaintext: bytes) -> bytes:
        if self._state != NoiseSessionState.ESTABLISHED:
            raise NoiseStateError(
                f"encrypt() requires ESTABLISHED state, got {self._state.value}"
            )
        if self._send_cipher is None:
            raise NoiseStateError("No send cipher available")
        try:
            return self._send_cipher.encrypt(bytes(plaintext), b"")
        except InvalidNonceError:
            self._send_cipher = None
            self._recv_cipher = None
            self._state = NoiseSessionState.FAILED
            self.record_phase(
                ObservableSessionPhase.FAILED,
                "Transport nonce exhausted; rekey required",
            )
            raise

    def decrypt(self, ciphertext: bytes) -> bytes:
        if self._state != NoiseSessionState.ESTABLISHED:
            raise NoiseStateError(
                f"decrypt() requires ESTABLISHED state, got {self._state.value}"
            )
        if self._recv_cipher is None:
            raise NoiseStateError("No receive cipher available")
        return self._recv_cipher.decrypt(bytes(ciphertext), b"")

    def close(self) -> None:
        self.record_phase(ObservableSessionPhase.CLOSING, "Session closing")
        self._send_cipher = None
        self._recv_cipher = None
        self._handshake_state = None
        self._state = NoiseSessionState.CLOSED
        self.record_phase(ObservableSessionPhase.CLOSED, "Session closed")


class NoiseSession:
    """Authoritative Noise XX session backed by Rust ``NativeNoiseSession``."""

    def __init__(
        self,
        local_identity: LocalIdentity,
        remote_peer_id: str,
        role: NoiseRole | None = None,
        transport: str = "lan",
        *,
        allow_legacy_peer_id: bool = True,
        expected_fingerprint: str | None = None,
    ) -> None:
        self._local_identity = local_identity
        self._remote_peer_id = remote_peer_id
        self._native: Any | None = None
        self._py: PyNoiseSession | None = None

        if HAS_NATIVE_CORE and hasattr(_core, "NativeNoiseSession"):
            try:
                self._native = _core.NativeNoiseSession(
                    bytes(local_identity.x25519_private),
                    local_identity.peer_id_hex,
                    remote_peer_id,
                    role.value if role is not None else None,
                    transport,
                    time.monotonic(),
                    allow_legacy_peer_id,
                    expected_fingerprint,
                )
            except ValueError as exc:
                raise_mapped_error(exc)
        else:
            self._py = PyNoiseSession(
                local_identity=local_identity,
                remote_peer_id=remote_peer_id,
                role=role,
                transport=transport,
                allow_legacy_peer_id=allow_legacy_peer_id,
                expected_fingerprint=expected_fingerprint,
            )

    # -----------------------------------------------------------------------
    # Compatibility & authoritative state accessors
    # -----------------------------------------------------------------------

    @property
    def is_native(self) -> bool:
        """Return True when backed directly by Rust ``NativeNoiseSession``."""
        return self._native is not None

    @property
    def _state(self) -> NoiseSessionState:
        if self._native is not None:
            return _STATE_FROM_STR.get(
                str(self._native.state), NoiseSessionState.FAILED
            )
        assert self._py is not None
        return self._py.state

    @_state.setter
    def _state(self, val: NoiseSessionState) -> None:
        if self._native is not None:
            self._native.state = val.value
        elif self._py is not None:
            self._py._state = val

    @property
    def _remote_fingerprint(self) -> str | None:
        if self._native is not None:
            fp = self._native.remote_fingerprint
            return str(fp) if fp is not None else None
        assert self._py is not None
        return self._py.remote_fingerprint

    @_remote_fingerprint.setter
    def _remote_fingerprint(self, fp: str | None) -> None:
        if self._native is not None:
            self._native.remote_fingerprint = fp
        elif self._py is not None:
            self._py._remote_fingerprint = fp

    @property
    def _handshake_started_at(self) -> float | None:
        if self._native is not None:
            ts = self._native.handshake_started_at
            return float(ts) if ts is not None else None
        assert self._py is not None
        return self._py._handshake_started_at

    @_handshake_started_at.setter
    def _handshake_started_at(self, ts: float | None) -> None:
        if self._native is not None:
            self._native.handshake_started_at = ts
        elif self._py is not None:
            self._py._handshake_started_at = ts

    @property
    def _send_cipher(self) -> Any | None:
        """Never expose raw native transport cipher handles to Python."""
        if self._native is not None:
            return None
        assert self._py is not None
        return self._py._send_cipher

    @property
    def _recv_cipher(self) -> Any | None:
        """Never expose raw native transport cipher handles to Python."""
        if self._native is not None:
            return None
        assert self._py is not None
        return self._py._recv_cipher

    @property
    def state(self) -> NoiseSessionState:
        """Current lifecycle state of this session."""
        return self._state

    @property
    def observable_phase(self) -> ObservableSessionPhase:
        """Detailed 12-phase observable handshake phase."""
        if self._native is not None:
            return _PHASE_FROM_STR.get(
                str(self._native.observable_phase),
                ObservableSessionPhase.DISCOVERED,
            )
        assert self._py is not None
        return self._py.observable_phase

    @property
    def diagnostic_reason(self) -> str:
        """Redacted diagnostic reason for the current phase."""
        if self._native is not None:
            return str(self._native.diagnostic_reason)
        assert self._py is not None
        return self._py.diagnostic_reason

    def record_phase(self, phase: ObservableSessionPhase, reason: str = "") -> None:
        """Transition the observable session phase and record diagnostic metadata."""
        if self._native is not None:
            self._native.record_phase(phase.value, reason, time.monotonic())
            return
        assert self._py is not None
        self._py.record_phase(phase, reason)

    def phase_history(self) -> list[tuple[str, float, str]]:
        """Return recent observable phase transition history."""
        if self._native is not None:
            return list(self._native.phase_history())
        assert self._py is not None
        return self._py.phase_history()

    @property
    def role(self) -> NoiseRole:
        """Noise role (INITIATOR or RESPONDER) for this session."""
        if self._native is not None:
            return (
                NoiseRole.INITIATOR
                if str(self._native.role) == "initiator"
                else NoiseRole.RESPONDER
            )
        assert self._py is not None
        return self._py.role

    @property
    def remote_peer_id(self) -> str:
        """Hex-encoded remote peer ID."""
        return self._remote_peer_id

    @property
    def remote_fingerprint(self) -> str | None:
        """64-char hex fingerprint of the remote peer's X25519 static key."""
        return self._remote_fingerprint

    @property
    def expected_fingerprint(self) -> str | None:
        """Pinned expected fingerprint for collision-safe identity verification."""
        if self._native is not None:
            fp = self._native.expected_fingerprint
            return str(fp) if fp is not None else None
        assert self._py is not None
        return self._py.expected_fingerprint

    @expected_fingerprint.setter
    def expected_fingerprint(self, fp: str | None) -> None:
        if self._native is not None:
            self._native.expected_fingerprint = fp
        elif self._py is not None:
            self._py.expected_fingerprint = fp

    @property
    def identity_mode(self) -> str:
        """Peer identity mode: `'modern'` or `'legacy_tui'`."""
        if self._native is not None:
            return str(self._native.identity_mode)
        assert self._py is not None
        return self._py.identity_mode

    @property
    def trust_level(self) -> str:
        """Trust distinction: `'observed'`, `'authenticated'`, or `'verified'`."""
        if self._native is not None:
            return str(self._native.trust_level)
        assert self._py is not None
        return self._py.trust_level

    @property
    def handshake_hash(self) -> bytes | None:
        """32-byte handshake transcript hash for channel binding."""
        if self._native is not None:
            raw = self._native.handshake_hash
            return bytes(raw) if raw is not None else None
        assert self._py is not None
        return self._py.handshake_hash

    @property
    def is_established(self) -> bool:
        """Return True if the session is in the ESTABLISHED state."""
        if self._native is not None:
            return bool(self._native.is_established)
        assert self._py is not None
        return self._py.is_established

    @property
    def send_nonce(self) -> int:
        """Current outbound Noise transport nonce counter (read-only)."""
        if self._native is not None:
            return int(self._native.send_nonce)
        assert self._py is not None
        return self._py.send_nonce

    @property
    def highest_received_nonce(self) -> int:
        """Highest authenticated inbound transport nonce (read-only)."""
        if self._native is not None:
            return int(self._native.highest_received_nonce)
        assert self._py is not None
        return self._py.highest_received_nonce

    def needs_rekey(self) -> bool:
        """Return True if the send cipher has crossed the rekey warning threshold."""
        if self._native is not None:
            return bool(self._native.needs_rekey())
        assert self._py is not None
        return self._py.needs_rekey()

    def mark_user_verified(self) -> None:
        """Explicitly mark this peer's authenticated static key as user-verified."""
        if self._native is not None:
            try:
                self._native.mark_user_verified()
                return
            except ValueError as exc:
                raise_mapped_error(exc)
        assert self._py is not None
        self._py.mark_user_verified()

    # -----------------------------------------------------------------------
    # Handshake & Transport (authoritative Rust execution)
    # -----------------------------------------------------------------------

    def reset_for_rehandshake(self, new_role: NoiseRole | None = None) -> None:
        """Reset an unestablished or failed session for a clean handshake attempt."""
        if self._native is not None:
            try:
                self._native.reset_for_rehandshake(
                    new_role.value if new_role is not None else None,
                    time.monotonic(),
                )
                return
            except ValueError as exc:
                raise_mapped_error(exc)
        assert self._py is not None
        self._py.reset_for_rehandshake(new_role)

    def start_handshake(self) -> bytes | None:
        """Initialise the handshake and return Message 1 if Initiator."""
        if self._native is not None:
            try:
                out = self._native.start_handshake(time.monotonic())
                return bytes(out) if out is not None else None
            except ValueError as exc:
                raise_mapped_error(exc)
        assert self._py is not None
        return self._py.start_handshake()

    def process_handshake_message(self, message: bytes) -> bytes | None:
        """Process an inbound handshake message and return response if needed."""
        if self._native is not None:
            try:
                out = self._native.process_handshake_message(
                    bytes(message), time.monotonic()
                )
                return bytes(out) if out is not None else None
            except ValueError as exc:
                raise_mapped_error(exc)
        assert self._py is not None
        return self._py.process_handshake_message(message)

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt a transport message via authoritative Rust ChaCha20-Poly1305."""
        if self._native is not None:
            try:
                return bytes(self._native.encrypt(bytes(plaintext)))
            except ValueError as exc:
                raise_mapped_error(exc)
        assert self._py is not None
        return self._py.encrypt(plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt a transport message via authoritative Rust ChaCha20-Poly1305."""
        if self._native is not None:
            try:
                return bytes(self._native.decrypt(bytes(ciphertext)))
            except ValueError as exc:
                raise_mapped_error(exc)
        assert self._py is not None
        return self._py.decrypt(ciphertext)

    def close(self) -> None:
        """Close the session and zeroize all cryptographic state."""
        if self._native is not None:
            self._native.close(time.monotonic())
            return
        assert self._py is not None
        self._py.close()
