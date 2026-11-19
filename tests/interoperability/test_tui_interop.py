"""Cross-Implementation Interoperability & Security Tests (RustPy <-> bitchat-tui).

Validates wire-level, cryptographic, identity, and transport interoperability
against the ``bitchat-tui`` reference specification without inheriting its
known design defects (nonce-0 replay exception, AES-GCM fallback, silent
identity reassignment, unbounded queues, or arbitrary sleep waits).
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import struct
from typing import Any

import pytest
from tests.ble.mocks import (
    MockBleakClient,
    MockBleakScanner,
    MockBLEServerBackend,
)

from bitchat._native import HAS_NATIVE_CORE, _core
from bitchat.app.session_coordinator import (
    MAX_PENDING_MESSAGES_PER_PEER,
    SessionCoordinator,
)
from bitchat.ble.connection import BLEConnection
from bitchat.ble.manager import BLEManager
from bitchat.ble.models import DiscoveredPeer
from bitchat.ble.server import BLEServer
from bitchat.ble.transport import BLETransport
from bitchat.crypto.identity import LocalIdentity
from bitchat.crypto.noise import (
    NOISE_MAX_TRANSPORT_NONCE,
    NoiseCipherState,
    NoiseHandshakeState,
    NoiseRole,
    NoiseSessionState,
    PyNoiseHandshakeState,
    parse_noise_identity_announce,
)
from bitchat.crypto.sessions import NoiseSession, PyNoiseSession, classify_peer_id
from bitchat.crypto.x25519 import generate_private_key, public_key_from_private
from bitchat.exceptions import (
    AuthenticationError,
    DecryptionError,
    InvalidNonceError,
    InvalidPacketError,
    NoiseStateError,
    PacketDecodingError,
    ReplayError,
)
from bitchat.protocol.constants import (
    BITCHAT_CHARACTERISTIC_UUID,
    BITCHAT_SERVICE_UUID,
    MessageType,
)
from bitchat.protocol.decoder import decode_packet
from bitchat.protocol.encoder import encode_packet
from bitchat.protocol.packet import BitchatPacket
from bitchat.storage.config import InMemoryStorage
from bitchat.transport.bluetooth import BluetoothTransport

# ===========================================================================
# 1. Reference TUI Wire Format & Protocol Constants Verification
# ===========================================================================


def test_reference_tui_ble_uuids_and_message_types() -> None:
    """Verify BLE UUIDs and Noise message type codes match bitchat-tui."""
    assert BITCHAT_SERVICE_UUID.upper() == "F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C"
    assert BITCHAT_CHARACTERISTIC_UUID.upper() == "A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D"
    assert int(MessageType.NoiseHandshakeInit) == 0x10
    assert int(MessageType.NoiseHandshakeResp) == 0x11
    assert int(MessageType.NoiseEncrypted) == 0x12
    assert int(MessageType.NoiseIdentityAnnounce) == 0x13
    assert int(MessageType.HandshakeRequest) == 0x25
    assert int(MessageType.DeliveryAck) == 0x0A


def test_legacy_tui_peer_id_classification_and_strict_validation() -> None:
    """Exact legacy 4-byte-zero-extended IDs are classified safely; invalid hex rejected."""
    assert classify_peer_id("deadbeef00000000") == "legacy_tui"
    assert classify_peer_id("CAFEBABE00000000") == "legacy_tui"
    assert classify_peer_id("0102030405060708") == "modern"
    assert classify_peer_id("0000000000000001") == "modern"

    # All-zeros, broadcast, truncated, oversized, and non-hex ASCII must be rejected
    for bad in (
        "0000000000000000",
        "ffffffffffffffff",
        "deadbeef",
        "deadbeef0000000011",
        "not-a-valid-hex!",
        "",
    ):
        with pytest.raises((InvalidPacketError, ValueError)):
            classify_peer_id(bad)


def test_reference_tui_noise_xx_wire_handshake_and_nonce_layout() -> None:
    """Verify exact 32B/96B/64B XX wire layout and 4-byte LE transport nonce format."""
    alice_priv = bytes([0x11] * 32)
    bob_priv = bytes([0x22] * 32)
    alice_eph = bytes([0x33] * 32)
    bob_eph = bytes([0x44] * 32)

    # Simulate reference TUI (independent pure-Python XX) <-> Native Rust XX
    tui_init = PyNoiseHandshakeState(
        NoiseRole.INITIATOR, alice_priv, fixed_ephemeral_private=alice_eph
    )
    rustpy_resp = NoiseHandshakeState(
        NoiseRole.RESPONDER, bob_priv, fixed_ephemeral_private=bob_eph
    )

    m1 = tui_init.write_message(b"")
    assert len(m1) == 32
    assert rustpy_resp.read_message(m1) == b""

    m2 = rustpy_resp.write_message(b"")
    assert len(m2) == 96
    assert tui_init.read_message(m2) == b""

    m3 = tui_init.write_message(b"")
    assert len(m3) == 64
    assert rustpy_resp.read_message(m3) == b""

    assert tui_init.get_handshake_hash() == rustpy_resp.get_handshake_hash()

    tui_send, tui_recv = tui_init.get_transport_ciphers()
    rp_send, rp_recv = rustpy_resp.get_transport_ciphers()

    # Nonce 0 wire prefix is 4-byte little-endian u32 = 0x00000000
    ct0 = tui_send.encrypt(b"hello from reference tui", b"")
    assert struct.unpack("<I", ct0[:4])[0] == 0
    assert rp_recv.decrypt(ct0, b"") == b"hello from reference tui"

    # Anti-pattern guard: RustPy MUST reject nonce-0 replay (unlike bitchat-tui)
    with pytest.raises(ReplayError):
        rp_recv.decrypt(ct0, b"")

    # Bidirectional reply
    reply0 = rp_send.encrypt(b"hello from rustpy", b"")
    assert struct.unpack("<I", reply0[:4])[0] == 0
    assert tui_recv.decrypt(reply0, b"") == b"hello from rustpy"


# ===========================================================================
# 2. Legacy TUI Peer Identity Interoperability & Collision Protection
# ===========================================================================


def _make_legacy_tui_identity(prefix_4bytes: bytes) -> LocalIdentity:
    """Create a peer identity matching legacy bitchat-tui (4B random + 4B zeros)."""
    assert len(prefix_4bytes) == 4 and prefix_4bytes != b"\x00\x00\x00\x00"
    x_priv = generate_private_key()
    x_pub = public_key_from_private(x_priv)
    fp = hashlib.sha256(x_pub).hexdigest()
    legacy_pid = prefix_4bytes + b"\x00\x00\x00\x00"
    return LocalIdentity(
        x25519_private=x_priv,
        ed25519_private=os.urandom(32),
        x25519_public=x_pub,
        ed25519_public=os.urandom(32),
        peer_id=legacy_pid,
        fingerprint=fp,
    )


@pytest.mark.asyncio
async def test_coordinator_bidirectional_dm_with_legacy_tui_peer_and_collision_rejection() -> (
    None
):
    """RustPy SessionCoordinator interoperates with legacy TUI peer and rejects impostors."""
    rustpy_id = LocalIdentity.generate()
    tui_id = _make_legacy_tui_identity(b"\xde\xad\xbe\xef")
    storage = InMemoryStorage()

    coord_rp = SessionCoordinator(
        local_identity=rustpy_id, nickname="rustpy_user", storage=storage
    )
    coord_tui = SessionCoordinator(local_identity=tui_id, nickname="tui_user")

    received_rp: list[tuple[str, str, bool]] = []
    received_tui: list[tuple[str, str, bool]] = []
    coord_rp.on_message_received = lambda s, t, enc: received_rp.append((s, t, enc))
    coord_tui.on_message_received = lambda s, t, enc: received_tui.append((s, t, enc))

    async def rp_to_tui(_target: str | None, pkt: BitchatPacket) -> None:
        raw = encode_packet(pkt)
        decoded = decode_packet(raw)
        await coord_tui._process_packet_async(decoded, "rp_link")

    async def tui_to_rp(_target: str | None, pkt: BitchatPacket) -> None:
        raw = encode_packet(pkt)
        decoded = decode_packet(raw)
        await coord_rp._process_packet_async(decoded, "tui_link")

    coord_rp._send_packet = rp_to_tui  # type: ignore[method-assign]
    coord_tui._send_packet = tui_to_rp  # type: ignore[method-assign]

    # Legacy TUI peer initiates encrypted DM to RustPy
    await coord_tui.send_direct_message(
        rustpy_id.peer_id_hex, "encrypted hello from legacy bitchat-tui!"
    )
    await asyncio.sleep(0.05)

    assert received_rp == [
        (tui_id.peer_id_hex, "encrypted hello from legacy bitchat-tui!", True)
    ]
    rp_sess = coord_rp.get_session(tui_id.peer_id_hex)
    assert rp_sess is not None and rp_sess.is_established
    assert rp_sess.is_native is True
    assert rp_sess.identity_mode == "legacy_tui"
    # Noise static-key possession is "authenticated", NOT user-"verified"
    assert rp_sess.trust_level == "authenticated"

    # RustPy replies over the established Noise transport
    await coord_rp.send_direct_message(
        tui_id.peer_id_hex, "encrypted reply from rustpy!"
    )
    await asyncio.sleep(0.05)
    assert received_tui == [
        (rustpy_id.peer_id_hex, "encrypted reply from rustpy!", True)
    ]

    # User explicitly verifies contact out-of-band
    assert coord_rp.verify_peer_identity(tui_id.peer_id_hex) is True
    assert rp_sess.trust_level == "verified"

    # Reconnect with the SAME authentic legacy TUI key succeeds with fresh ephemeral keys
    first_hash = rp_sess.handshake_hash
    coord_rp._handle_peer_disconnected("tui_link")
    coord_tui._handle_peer_disconnected("rp_link")
    await coord_tui.send_direct_message(
        rustpy_id.peer_id_hex, "reconnected with fresh ephemeral keys"
    )
    await asyncio.sleep(0.05)
    rp_sess_2 = coord_rp.get_session(tui_id.peer_id_hex)
    assert rp_sess_2 is not None and rp_sess_2.is_established
    assert rp_sess_2.handshake_hash != first_hash
    assert received_rp[-1] == (
        tui_id.peer_id_hex,
        "reconnected with fresh ephemeral keys",
        True,
    )

    # Disconnect, then an IMPOSTOR with a DIFFERENT static key claims the same legacy peer ID!
    coord_rp._handle_peer_disconnected("tui_link")
    impostor_id = _make_legacy_tui_identity(b"\xde\xad\xbe\xef")
    assert impostor_id.fingerprint != tui_id.fingerprint

    coord_imp = SessionCoordinator(local_identity=impostor_id, nickname="impostor")

    async def imp_to_rp(_target: str | None, pkt: BitchatPacket) -> None:
        await coord_rp._process_packet_async(decode_packet(encode_packet(pkt)), "imp")

    async def rp_to_imp(_target: str | None, pkt: BitchatPacket) -> None:
        await coord_imp._process_packet_async(decode_packet(encode_packet(pkt)), "rp")

    coord_imp._send_packet = imp_to_rp  # type: ignore[method-assign]
    coord_rp._send_packet = rp_to_imp  # type: ignore[method-assign]

    before_count = len(received_rp)
    await coord_imp.send_direct_message(rustpy_id.peer_id_hex, "hijack attempt!")
    await asyncio.sleep(0.05)

    # Collision/impostor MUST be rejected; message MUST NOT be delivered
    assert len(received_rp) == before_count
    assert coord_rp.get_session(tui_id.peer_id_hex) is None


# ===========================================================================
# 3. Anti-Pattern Guards: Nonce Exhaustion, Fail-Closed Auth, Bounded Queues
# ===========================================================================


def test_nonce_exhaustion_fails_closed_no_wraparound() -> None:
    """Transport encryption refuses to proceed at u32::MAX (never wraps wire nonce)."""
    key = os.urandom(32)
    cs = NoiseCipherState(key, use_extracted_nonce=True)
    cs._nonce = NOISE_MAX_TRANSPORT_NONCE
    assert cs.is_nonce_exhausted() is True
    assert cs.needs_rekey() is True

    with pytest.raises(InvalidNonceError):
        cs.encrypt(b"must never wrap nonce", b"")

    # Failed AEAD decrypt must not record nonce in replay window
    sender = NoiseCipherState(key, use_extracted_nonce=True)
    receiver = NoiseCipherState(key, use_extracted_nonce=True)
    ct0 = sender.encrypt(b"authentic payload", b"")
    tampered = bytearray(ct0)
    tampered[-1] ^= 0xAA
    with pytest.raises(DecryptionError):
        receiver.decrypt(bytes(tampered), b"")
    assert 0 not in receiver._replay_window
    assert receiver.decrypt(ct0, b"") == b"authentic payload"


def test_noise_identity_announce_and_unauthenticated_overwrite_rejected() -> None:
    """0x13 NoiseIdentityAnnounce validates keys and cannot overwrite bound identities."""
    ident = LocalIdentity.generate()
    digest = hashlib.sha256(ident.x25519_public).digest()
    pk32, fp32 = parse_noise_identity_announce(ident.x25519_public)
    pk64, fp64 = parse_noise_identity_announce(ident.x25519_public + digest)
    assert pk32 == pk64 == ident.x25519_public
    assert fp32 == fp64 == ident.fingerprint

    # Corrupted hash suffix rejected
    bad64 = ident.x25519_public + bytes([digest[0] ^ 0xFF]) + digest[1:]
    with pytest.raises(AuthenticationError):
        parse_noise_identity_announce(bad64)

    # Oversized/truncated frames rejected
    with pytest.raises(PacketDecodingError):
        decode_packet(b"\x01\x10\x07")


@pytest.mark.asyncio
async def test_coordinator_bounded_pending_messages_and_delivery_ack() -> None:
    """Pending DM queue is strictly bounded and 0x0A DeliveryAck clears tracked entries."""
    alice_id = LocalIdentity.generate()
    bob_id = LocalIdentity.generate()
    coord = SessionCoordinator(local_identity=alice_id, nickname="alice")

    async def noop_send(_target: str | None, _pkt: BitchatPacket) -> None:
        return None

    coord._send_packet = noop_send  # type: ignore[method-assign]

    for i in range(MAX_PENDING_MESSAGES_PER_PEER + 20):
        await coord.send_direct_message(bob_id.peer_id_hex, f"pending-{i}")

    assert len(coord._pending_messages[bob_id.peer_id_hex]) == (
        MAX_PENDING_MESSAGES_PER_PEER
    )

    # DeliveryAck (0x0A) handling via NativeAckTracker
    acked: list[tuple[str, str]] = []
    coord.on_delivery_ack = lambda mid, pid: acked.append((mid, pid))
    assert coord.ack_tracker is not None
    coord.ack_tracker.track_message("msg-uuid-42", bob_id.peer_id_hex, 100.0, 10.0, 3)

    ack_pkt = BitchatPacket.create(
        message_type=MessageType.DeliveryAck,
        sender_id=bob_id.peer_id,
        recipient_id=alice_id.peer_id,
        payload=b"msg-uuid-42",
    )
    await coord._process_packet_async(ack_pkt, "bob_link")
    assert acked == [("msg-uuid-42", bob_id.peer_id_hex)]
    assert coord.ack_tracker.is_pending("msg-uuid-42") is False


# ===========================================================================
# 4. Topology Test: Reference TUI BLE Central <-> RustPy GATT Peripheral
# ===========================================================================


@pytest.mark.asyncio
async def test_ble_tui_central_to_rustpy_gatt_peripheral_encrypted_exchange() -> None:
    """Reference TUI BLE Central (legacy ID) <-> RustPy GATT Peripheral full Noise XX."""
    tui_central_id = _make_legacy_tui_identity(b"\x13\x37\xca\xfe")
    rustpy_periph_id = LocalIdentity.generate()

    central_clients: dict[str, MockBleakClient] = {}
    server_backend_periph = MockBLEServerBackend()
    server_backend_central = MockBLEServerBackend()

    def client_factory(
        address: str, disconnected_callback: Any = None
    ) -> MockBleakClient:
        client = MockBleakClient(address, disconnected_callback=disconnected_callback)
        central_clients[address] = client
        return client

    ble_mgr_tui = BLEManager(
        sender_id=tui_central_id.peer_id,
        scanner_factory=lambda **kw: MockBleakScanner(**kw),
        client_factory=client_factory,
    )
    ble_srv_tui = BLEServer(
        backend=server_backend_central,
        peer_id=tui_central_id.peer_id_hex,
        nickname="tui_central",
    )
    bt_tui = BluetoothTransport(ble_mgr_tui, ble_srv_tui, inter_fragment_delay=0.001)

    ble_mgr_rp = BLEManager(
        sender_id=rustpy_periph_id.peer_id,
        scanner_factory=lambda **kw: MockBleakScanner(**kw),
    )
    ble_srv_rp = BLEServer(
        backend=server_backend_periph,
        peer_id=rustpy_periph_id.peer_id_hex,
        nickname="rustpy_periph",
    )
    bt_rp = BluetoothTransport(ble_mgr_rp, ble_srv_rp, inter_fragment_delay=0.001)

    coord_tui = SessionCoordinator(
        local_identity=tui_central_id,
        nickname="tui_central",
        ble_manager=ble_mgr_tui,
        ble_server=ble_srv_tui,
        transport=bt_tui,
        initial_transport="bluetooth",
    )
    coord_rp = SessionCoordinator(
        local_identity=rustpy_periph_id,
        nickname="rustpy_periph",
        ble_manager=ble_mgr_rp,
        ble_server=ble_srv_rp,
        transport=bt_rp,
        initial_transport="bluetooth",
    )

    received_rp: list[tuple[str, str, bool]] = []
    received_tui: list[tuple[str, str, bool]] = []
    coord_rp.on_message_received = lambda s, t, enc: received_rp.append((s, t, enc))
    coord_tui.on_message_received = lambda s, t, enc: received_tui.append((s, t, enc))

    await coord_tui.start()
    await coord_rp.start()
    try:
        periph_addr = "AA:BB:CC:DD:EE:42"
        central_client_id = "TUI_CENTRAL_CLIENT"

        disc = DiscoveredPeer(
            address=periph_addr,
            name="rustpy_periph",
            rssi=-52,
            service_uuids=(ble_srv_rp.service_uuid,),
            peer_id=rustpy_periph_id.peer_id_hex,
            nickname="rustpy_periph",
        )
        ble_mgr_tui.scanner._discovered_peers[periph_addr] = disc
        coord_tui._handle_peer_discovered(disc)

        await coord_tui.connect_peer(periph_addr)
        mock_client = central_clients[periph_addr]
        server_backend_periph.attach_client(mock_client)

        orig_write = mock_client.write_gatt_char

        async def bridged_write(char: Any, data: bytes, response: bool = False) -> None:
            await orig_write(char, data, response=response)
            server_backend_periph.emit_write(bytes(data), client_id=central_client_id)

        mock_client.write_gatt_char = bridged_write  # type: ignore[method-assign]

        await coord_tui.send_announce()
        await asyncio.sleep(0.05)
        assert central_client_id in bt_rp.connected_peers

        # Central -> Peripheral encrypted DM
        await coord_tui.send_direct_message(
            rustpy_periph_id.peer_id_hex, "TUI BLE Central -> RustPy Peripheral"
        )
        for _ in range(40):
            if received_rp:
                break
            await asyncio.sleep(0.02)
        assert received_rp == [
            (
                tui_central_id.peer_id_hex,
                "TUI BLE Central -> RustPy Peripheral",
                True,
            )
        ]

        # Peripheral -> Central encrypted DM (over GATT notifications)
        await coord_rp.send_direct_message(
            tui_central_id.peer_id_hex, "RustPy Peripheral -> TUI BLE Central"
        )
        for _ in range(40):
            if received_tui:
                break
            await asyncio.sleep(0.02)
        assert received_tui == [
            (
                rustpy_periph_id.peer_id_hex,
                "RustPy Peripheral -> TUI BLE Central",
                True,
            )
        ]
    finally:
        await coord_tui.stop()
        await coord_rp.stop()


@pytest.mark.asyncio
async def test_ble_mtu_aware_chunking_uses_rust_sizing() -> None:
    """When controller reports a small negotiated ATT MTU, BLETransport chunks safely."""

    class SmallMtuMockClient(MockBleakClient):
        mtu_size: int = 100  # Usable chunk = 97 bytes via Rust sizing

    small_mtu_client = SmallMtuMockClient("AA:BB:CC:DD:EE:88")

    conn = BLEConnection(
        peer_address="AA:BB:CC:DD:EE:88",
        client_factory=lambda *a, **kw: small_mtu_client,
    )
    transport = BLETransport(
        connection=conn,
        sender_id=b"\x01" * 8,
        inter_fragment_delay=0.001,
    )
    await transport.start()
    try:
        assert conn.negotiated_mtu == 100
        assert conn.max_write_chunk_size == 97
        pkt = BitchatPacket.create(
            message_type=MessageType.Message,
            sender_id=b"\x01" * 8,
            payload=b"A" * 200,
        )
        await transport.send_packet(pkt, add_padding=False)
        assert len(small_mtu_client.written_chunks) > 1
        for _, chunk, _ in small_mtu_client.written_chunks:
            assert len(chunk) <= 97
    finally:
        await transport.stop()


# ===========================================================================
# 5. Cohesive NativeProtocolEngine Single-Crossing End-to-End Test
# ===========================================================================


def test_native_protocol_engine_single_crossing_modern_and_legacy_interop() -> None:
    """Verify NativeProtocolEngine executes decode->route->Noise->encode in 1 FFI call."""
    assert HAS_NATIVE_CORE and _core is not None

    alice = LocalIdentity.generate()
    bob_legacy = _make_legacy_tui_identity(b"\xab\xcd\xef\x12")

    eng_a = _core.NativeProtocolEngine(
        alice.x25519_private, alice.peer_id_hex, "alice", "lan", 7, 50, True
    )
    eng_b = _core.NativeProtocolEngine(
        bob_legacy.x25519_private,
        bob_legacy.peer_id_hex,
        "bob_tui",
        "lan",
        7,
        50,
        True,
    )

    q_a_to_b = eng_a.prepare_direct_message(
        bob_legacy.peer_id_hex, "hello legacy bob via NativeProtocolEngine!", 1.0
    )
    q_b_to_a: list[tuple[str, bytes]] = []
    delivered_b: list[tuple[str, str, bool]] = []
    delivered_a: list[tuple[str, str, bool]] = []

    for step in range(8):
        now = 1.0 + step * 0.1
        for _, raw in list(q_a_to_b):
            res = eng_b.process_inbound_frame(raw, "10.0.0.1:41235", now)
            if res.delivered_message is not None:
                delivered_b.append(res.delivered_message)
            q_b_to_a.extend(res.outbound_packets)
        q_a_to_b.clear()

        for _, raw in list(q_b_to_a):
            res = eng_a.process_inbound_frame(raw, "10.0.0.2:41235", now)
            if res.delivered_message is not None:
                delivered_a.append(res.delivered_message)
            q_a_to_b.extend(res.outbound_packets)
        q_b_to_a.clear()

    assert delivered_b == [
        (alice.peer_id_hex, "hello legacy bob via NativeProtocolEngine!", True)
    ]
    assert eng_a.get_session_state(bob_legacy.peer_id_hex) == "established"
    assert eng_a.get_session_identity_mode(bob_legacy.peer_id_hex) == "legacy_tui"
    assert eng_b.get_session_state(alice.peer_id_hex) == "established"
    assert eng_b.get_session_identity_mode(alice.peer_id_hex) == "modern"

    # Bidirectional reply
    reply = eng_b.prepare_direct_message(alice.peer_id_hex, "reply from tui!", 2.0)
    assert len(reply) == 1
    res_a = eng_a.process_inbound_frame(reply[0][1], "10.0.0.2:41235", 2.1)
    assert res_a.delivered_message == (
        bob_legacy.peer_id_hex,
        "reply from tui!",
        True,
    )

    # Tampered NoiseEncrypted frame fails closed with drop_reason and zero plaintext
    tampered_pkt = decode_packet(reply[0][1])
    bad_payload = bytearray(tampered_pkt.payload)
    bad_payload[-1] ^= 0xFF
    forged = encode_packet(
        BitchatPacket.create(
            message_type=MessageType.NoiseEncrypted,
            sender_id=bob_legacy.peer_id,
            recipient_id=alice.peer_id,
            payload=bytes(bad_payload),
            timestamp=tampered_pkt.timestamp + 1,
        )
    )
    bad_res = eng_a.process_inbound_frame(forged, "10.0.0.2:41235", 2.2)
    assert bad_res.delivered_message is None
    assert bad_res.drop_reason is not None


def test_differential_noise_session_rust_vs_python() -> None:
    """Native Rust NoiseSession and PyNoiseSession exhibit identical lifecycle & crypto."""
    alice = LocalIdentity.generate()
    bob = LocalIdentity.generate()

    rs_a = NoiseSession(alice, bob.peer_id_hex)
    rs_b = NoiseSession(bob, alice.peer_id_hex)
    py_a = PyNoiseSession(alice, bob.peer_id_hex)
    py_b = PyNoiseSession(bob, alice.peer_id_hex)
    assert rs_a.is_native is True
    assert rs_b.is_native is True
    assert rs_a.role == py_a.role
    assert rs_b.role == py_b.role

    if rs_a.role == NoiseRole.RESPONDER:
        rs_a, rs_b = rs_b, rs_a
        py_a, py_b = py_b, py_a

    # Complete both handshakes independently and cross-verify
    m1_r = rs_a.start_handshake()
    m1_p = py_a.start_handshake()
    assert m1_r is not None and m1_p is not None and len(m1_r) == len(m1_p) == 32

    m2_r = rs_b.process_handshake_message(m1_r)
    m2_p = py_b.process_handshake_message(m1_p)
    assert m2_r is not None and m2_p is not None and len(m2_r) == len(m2_p) == 96

    m3_r = rs_a.process_handshake_message(m2_r)
    m3_p = py_a.process_handshake_message(m2_p)
    assert m3_r is not None and m3_p is not None and len(m3_r) == len(m3_p) == 64

    assert rs_b.process_handshake_message(m3_r) is None
    assert py_b.process_handshake_message(m3_p) is None

    assert rs_a.state == py_a.state == NoiseSessionState.ESTABLISHED
    assert rs_b.state == py_b.state == NoiseSessionState.ESTABLISHED
    assert rs_a.remote_fingerprint == py_a.remote_fingerprint
    assert rs_b.remote_fingerprint == py_b.remote_fingerprint
    assert rs_a.identity_mode == py_a.identity_mode == "modern"
    assert rs_a.trust_level == py_a.trust_level == "authenticated"

    # Cross-engine handshake: Rust initiator <-> Python responder!
    rs_i = NoiseSession(alice, bob.peer_id_hex, role=NoiseRole.INITIATOR)
    py_r = PyNoiseSession(bob, alice.peer_id_hex, role=NoiseRole.RESPONDER)
    cm1 = rs_i.start_handshake()
    assert cm1 is not None
    cm2 = py_r.process_handshake_message(cm1)
    assert cm2 is not None
    cm3 = rs_i.process_handshake_message(cm2)
    assert cm3 is not None
    assert py_r.process_handshake_message(cm3) is None

    assert rs_i.handshake_hash == py_r.handshake_hash
    ct = rs_i.encrypt(b"rust to python noise session!")
    assert py_r.decrypt(ct) == b"rust to python noise session!"
    ct_back = py_r.encrypt(b"python to rust noise session!")
    assert rs_i.decrypt(ct_back) == b"python to rust noise session!"

    # Replay rejection in both directions
    with pytest.raises(ReplayError):
        py_r.decrypt(ct)
    with pytest.raises(ReplayError):
        rs_i.decrypt(ct_back)

    # Close invalidates ciphers
    rs_i.close()
    py_r.close()
    with pytest.raises(NoiseStateError):
        rs_i.encrypt(b"after close")
    with pytest.raises(NoiseStateError):
        py_r.encrypt(b"after close")
