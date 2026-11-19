"""
High-level Noise session abstraction for BitChat.

``NoiseSession`` wraps a complete per-peer Noise XX handshake and transport
cipher lifecycle, plus an explicit observable handshake state machine
(`NativeHandshakeStateMachine`).
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import time
from typing import Any

from bitchat._native import HAS_NATIVE_CORE, _core
from bitchat.crypto.identity import LocalIdentity, calculate_fingerprint
from bitchat.crypto.noise import (
    NoiseCipherState,
    NoiseHandshakeState,
    NoiseRole,
    NoiseSessionState,
    ObservableSessionPhase,
    determine_handshake_role,
)
from bitchat.exceptions import (
    AuthenticationError,
    CryptoError,
    NoiseError,
    NoiseStateError,
)


class NoiseSession:
    """Per-peer Noise XX session — handshake and transport cipher lifecycle."""

    def __init__(
        self,
        local_identity: LocalIdentity,
        remote_peer_id: str,
        role: NoiseRole | None = None,
        transport: str = "lan",
    ) -> None:
        self._local_identity = local_identity
        self._remote_peer_id = remote_peer_id
        self._role: NoiseRole = (
            role
            if role is not None
            else determine_handshake_role(local_identity.peer_id_hex, remote_peer_id)
        )
        self._state: NoiseSessionState = NoiseSessionState.UNINITIALIZED
        self._handshake_state: NoiseHandshakeState | None = None
        self._send_cipher: NoiseCipherState | None = None
        self._recv_cipher: NoiseCipherState | None = None
        self._remote_static_public: bytes | None = None
        self._handshake_hash: bytes | None = None
        self._remote_fingerprint: str | None = None
        self._handshake_started_at: float | None = None
        self._observable_phase: ObservableSessionPhase = (
            ObservableSessionPhase.DISCOVERED
        )
        self._state_machine: Any | None = None
        if HAS_NATIVE_CORE and hasattr(_core, "NativeHandshakeStateMachine"):
            self._state_machine = _core.NativeHandshakeStateMachine(
                remote_peer_id, transport, time.monotonic(), 3
            )

    # -----------------------------------------------------------------------
    # Properties — read-only session metadata
    # -----------------------------------------------------------------------

    @property
    def state(self) -> NoiseSessionState:
        """Current lifecycle state of this session."""
        return self._state

    @property
    def observable_phase(self) -> ObservableSessionPhase:
        """Detailed observable handshake phase (Section 7)."""
        return self._observable_phase

    @property
    def diagnostic_reason(self) -> str:
        """Redacted diagnostic reason for the current phase."""
        if self._state_machine is not None:
            return str(self._state_machine.diagnostic_reason)
        return self._observable_phase.value

    def record_phase(self, phase: ObservableSessionPhase, reason: str = "") -> None:
        """Transition the observable session phase and record diagnostic metadata."""
        self._observable_phase = phase
        if self._state_machine is not None:
            with contextlib.suppress(Exception):
                self._state_machine.transition_to(phase.value, reason, time.monotonic())

    def phase_history(self) -> list[tuple[str, float, str]]:
        """Return recent observable phase transition history."""
        if self._state_machine is not None:
            return list(self._state_machine.history())
        return [(self._observable_phase.value, 0.0, self.diagnostic_reason)]

    @property
    def role(self) -> NoiseRole:
        """Noise role (INITIATOR or RESPONDER) for this session."""
        return self._role

    @property
    def remote_peer_id(self) -> str:
        """Hex-encoded remote peer ID."""
        return self._remote_peer_id

    @property
    def remote_fingerprint(self) -> str | None:
        """64-char hex fingerprint of the remote peer's X25519 static key."""
        return self._remote_fingerprint

    @property
    def handshake_hash(self) -> bytes | None:
        """32-byte handshake transcript hash for channel binding."""
        return self._handshake_hash

    @property
    def is_established(self) -> bool:
        """Return True if the session is in the ESTABLISHED state."""
        return self._state == NoiseSessionState.ESTABLISHED

    # -----------------------------------------------------------------------
    # Handshake
    # -----------------------------------------------------------------------

    def reset_for_rehandshake(self, new_role: NoiseRole | None = None) -> None:
        """Reset an unestablished or failed session for a clean handshake attempt."""
        if new_role is not None:
            self._role = new_role
        self._state = NoiseSessionState.UNINITIALIZED
        self._handshake_state = None
        self._send_cipher = None
        self._recv_cipher = None
        self._remote_static_public = None
        self._handshake_hash = None
        self._remote_fingerprint = None
        self._handshake_started_at = None
        self.record_phase(
            ObservableSessionPhase.HANDSHAKE_INITIATED,
            "Session reset for fresh handshake",
        )

    def start_handshake(self) -> bytes | None:
        """Initialise the handshake and return the first message if Initiator."""
        if self._state != NoiseSessionState.UNINITIALIZED:
            raise NoiseStateError(
                f"start_handshake() called in invalid state: {self._state.value}"
            )
        self._handshake_state = NoiseHandshakeState(
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
        """Process an inbound handshake message and return response if needed."""
        try:
            if (
                self._state == NoiseSessionState.UNINITIALIZED
                and self._role == NoiseRole.RESPONDER
            ):
                self._handshake_state = NoiseHandshakeState(
                    role=self._role,
                    local_static_private=self._local_identity.x25519_private,
                )
                self._state = NoiseSessionState.HANDSHAKING
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
            self._state = NoiseSessionState.FAILED
            self.record_phase(
                ObservableSessionPhase.FAILED,
                f"Handshake failed: {type(exc).__name__}",
            )
            raise

    def _finalise_handshake(self) -> None:
        """Extract transport ciphers and transition to ESTABLISHED."""
        assert self._handshake_state is not None
        remote_static_public = self._handshake_state.get_remote_static_public_key()
        if remote_static_public is None:
            self._state = NoiseSessionState.FAILED
            self._handshake_state = None
            raise AuthenticationError(
                "Noise handshake did not authenticate a remote key"
            )
        try:
            if len(self._remote_peer_id) != 16:
                raise ValueError("Remote peer ID must be 16 hexadecimal characters")
            claimed_peer_id = bytes.fromhex(self._remote_peer_id)
        except ValueError as err:
            self._state = NoiseSessionState.FAILED
            self._handshake_state = None
            raise AuthenticationError(
                "Remote peer ID is not valid hexadecimal"
            ) from err
        authenticated_peer_id = hashlib.sha256(remote_static_public).digest()[:8]
        if len(claimed_peer_id) != len(
            authenticated_peer_id
        ) or not hmac.compare_digest(authenticated_peer_id, claimed_peer_id):
            self._state = NoiseSessionState.FAILED
            self._handshake_state = None
            raise AuthenticationError(
                "Authenticated Noise static key does not match claimed peer ID"
            )
        if hmac.compare_digest(
            remote_static_public, self._local_identity.x25519_public
        ):
            self._state = NoiseSessionState.FAILED
            self._handshake_state = None
            raise AuthenticationError(
                "Self-connection rejected: remote peer authenticated "
                "with local device identity"
            )
        send_cipher, recv_cipher = self._handshake_state.get_transport_ciphers()
        self._send_cipher = send_cipher
        self._recv_cipher = recv_cipher
        self._remote_static_public = remote_static_public
        self._handshake_hash = self._handshake_state.get_handshake_hash()
        self._remote_fingerprint = calculate_fingerprint(remote_static_public)
        self._handshake_state = None
        self._state = NoiseSessionState.ESTABLISHED
        self.record_phase(
            ObservableSessionPhase.ESTABLISHED,
            "Noise XX transport established and peer identity verified",
        )

    # -----------------------------------------------------------------------
    # Transport
    # -----------------------------------------------------------------------

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt a transport message."""
        if self._state != NoiseSessionState.ESTABLISHED:
            raise NoiseStateError(
                f"encrypt() requires ESTABLISHED state, got {self._state.value}"
            )
        if self._send_cipher is None:
            raise NoiseStateError("No send cipher available")
        return self._send_cipher.encrypt(bytes(plaintext), b"")

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt a transport message."""
        if self._state != NoiseSessionState.ESTABLISHED:
            raise NoiseStateError(
                f"decrypt() requires ESTABLISHED state, got {self._state.value}"
            )
        if self._recv_cipher is None:
            raise NoiseStateError("No receive cipher available")
        return self._recv_cipher.decrypt(bytes(ciphertext), b"")

    # -----------------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------------

    def close(self) -> None:
        """Close the session and zero out cipher key references."""
        self.record_phase(ObservableSessionPhase.CLOSING, "Session closing")
        self._send_cipher = None
        self._recv_cipher = None
        self._handshake_state = None
        self._state = NoiseSessionState.CLOSED
        self.record_phase(ObservableSessionPhase.CLOSED, "Session closed")
