"""Phase 2 Regression & Integration Tests for Real-World LAN & BLE Failures.

Covers the critical real-world communication and Noise XX handshake progression
failures reported in Phase 2:
1. LAN peer discovered via UDP: sending a DM without prior `/connect` auto-connects
   TCP, completes the 3-message Noise XX handshake, and delivers encrypted messages.
2. LAN asymmetric discovery / firewall blocking UDP + low TTL (`ttl < MAX_TTL`):
   inbound ephemeral TCP port is mapped to sender peer_id and reused for Noise
   handshake response and bidirectional encrypted messages.
3. Handshake role contention & stale `HANDSHAKING` recovery on `HandshakeRequest`
   and direct `NoiseHandshakeInit` from higher-peer-ID nodes.
4. BLE discovery -> GATT server client registration -> bidirectional `Announce` ->
   full 3-message Noise XX handshake and encrypted messaging across `BluetoothTransport`
   and `SessionCoordinator` without getting stuck in `Handshake pending`.
5. BLE notification arriving during `BLEConnectionState.SUBSCRIBING` (before
   `start_notify` returns) is buffered in `NativeBleConnectionEngine` and drained
   upon `READY`.
6. Exportable, secret-redacted connection and handshake diagnostics report.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from tests.ble.mocks import (
    MockBleakClient,
    MockBleakScanner,
    MockBLEServerBackend,
)

from bitchat.app.session_coordinator import SessionCoordinator
from bitchat.ble.connection import BLEConnection
from bitchat.ble.manager import BLEManager
from bitchat.ble.models import BLEConnectionState, DiscoveredPeer
from bitchat.ble.server import BLEServer
from bitchat.crypto.identity import LocalIdentity
from bitchat.crypto.noise import (
    NoiseRole,
    NoiseSessionState,
    ObservableSessionPhase,
)
from bitchat.network.adapter import NetworkAdapterManager
from bitchat.network.models import LANDiscoveredPeer, NetworkInfo
from bitchat.network.transport import LANTransport
from bitchat.protocol.constants import MessageType
from bitchat.protocol.packet import BitchatPacket
from bitchat.transport.bluetooth import BluetoothTransport


def _make_connected_adapter_manager() -> NetworkAdapterManager:
    mgr = NetworkAdapterManager()
    info = NetworkInfo(
        status="Connected",
        interface="Wi-Fi",
        ssid="TestMeshNet",
        local_ip="127.0.0.1",
        interface_name="wlan0",
        interface_state="up",
        ipv4_addresses=("127.0.0.1",),
        subnet_prefixes=(24,),
    )
    mgr._current_info = info

    async def _refresh_async(
        listening_port: int | None = None,
        discovery_active: bool | None = None,
    ) -> NetworkInfo:
        return info

    mgr.refresh_async = _refresh_async  # type: ignore[method-assign]
    return mgr


# ===========================================================================
# 1. LAN Unconnected Discovered Peer Auto-Connect & Full Noise XX Handshake
# ===========================================================================


@pytest.mark.asyncio
async def test_lan_discovered_peer_dm_auto_connects_and_completes_noise_handshake() -> (
    None
):
    """Sending a DM to a UDP-discovered LAN peer auto-connects TCP and completes Noise XX."""
    id_a = LocalIdentity.generate()
    id_b = LocalIdentity.generate()

    lan_a = LANTransport(
        local_peer_id=id_a.peer_id_hex,
        local_nickname="alice",
        tcp_port=0,
        discovery_port=0,
        adapter_manager=_make_connected_adapter_manager(),
    )
    lan_b = LANTransport(
        local_peer_id=id_b.peer_id_hex,
        local_nickname="bob",
        tcp_port=0,
        discovery_port=0,
        adapter_manager=_make_connected_adapter_manager(),
    )

    coord_a = SessionCoordinator(
        local_identity=id_a,
        nickname="alice",
        transport=lan_a,
        initial_transport="lan",
    )
    coord_b = SessionCoordinator(
        local_identity=id_b,
        nickname="bob",
        transport=lan_b,
        initial_transport="lan",
    )

    received_by_a: list[tuple[str, str, bool]] = []
    received_by_b: list[tuple[str, str, bool]] = []
    coord_a.on_message_received = lambda s, t, enc: received_by_a.append((s, t, enc))
    coord_b.on_message_received = lambda s, t, enc: received_by_b.append((s, t, enc))

    await coord_a.start()
    await coord_b.start()

    try:
        port_a = lan_a.server.bound_port
        port_b = lan_b.server.bound_port
        assert port_a > 0 and port_b > 0

        # Simulate UDP discovery on both sides WITHOUT calling connect_peer first
        peer_b_disc = LANDiscoveredPeer(
            address=f"127.0.0.1:{port_b}",
            ip="127.0.0.1",
            port=port_b,
            peer_id=id_b.peer_id_hex,
            nickname="bob",
        )
        peer_a_disc = LANDiscoveredPeer(
            address=f"127.0.0.1:{port_a}",
            ip="127.0.0.1",
            port=port_a,
            peer_id=id_a.peer_id_hex,
            nickname="alice",
        )
        lan_a.discovery._discovered_peers[peer_b_disc.address] = peer_b_disc
        lan_b.discovery._discovered_peers[peer_a_disc.address] = peer_a_disc
        coord_a._handle_peer_discovered(peer_b_disc)
        coord_b._handle_peer_discovered(peer_a_disc)

        assert lan_a.connected_peers == []
        assert lan_b.connected_peers == []

        # Alice sends DM directly to Bob without prior /connect
        await coord_a.send_direct_message(
            id_b.peer_id_hex, "hello over LAN auto-connect!"
        )

        for _ in range(40):
            if received_by_b:
                break
            await asyncio.sleep(0.05)

        assert received_by_b == [
            (id_a.peer_id_hex, "hello over LAN auto-connect!", True)
        ]
        session_a = coord_a.get_session(id_b.peer_id_hex)
        session_b = coord_b.get_session(id_a.peer_id_hex)
        assert session_a is not None and session_a.is_established
        assert session_b is not None and session_b.is_established
        assert session_a.observable_phase == ObservableSessionPhase.ESTABLISHED
        assert session_b.observable_phase == ObservableSessionPhase.ESTABLISHED

        # Bob replies over the established session
        await coord_b.send_direct_message(id_a.peer_id_hex, "loud and clear, Alice!")
        for _ in range(40):
            if received_by_a:
                break
            await asyncio.sleep(0.05)

        assert received_by_a == [(id_b.peer_id_hex, "loud and clear, Alice!", True)]
    finally:
        await coord_a.stop()
        await coord_b.stop()


# ===========================================================================
# 2. LAN Asymmetric Discovery / Inbound Ephemeral Port Mapping (ttl < MAX_TTL)
# ===========================================================================


@pytest.mark.asyncio
async def test_lan_inbound_ephemeral_port_and_low_ttl_handshake_succeeds() -> None:
    """When UDP discovery is blocked on responder and TTL < 7, inbound TCP still completes Noise XX."""
    id_a = LocalIdentity.generate()
    id_b = LocalIdentity.generate()

    lan_a = LANTransport(
        local_peer_id=id_a.peer_id_hex,
        local_nickname="fedora_node",
        tcp_port=0,
        discovery_port=0,
        adapter_manager=_make_connected_adapter_manager(),
    )
    lan_b = LANTransport(
        local_peer_id=id_b.peer_id_hex,
        local_nickname="windows_node",
        tcp_port=0,
        discovery_port=0,
        adapter_manager=_make_connected_adapter_manager(),
    )

    coord_a = SessionCoordinator(
        local_identity=id_a,
        nickname="fedora_node",
        transport=lan_a,
        initial_transport="lan",
    )
    coord_b = SessionCoordinator(
        local_identity=id_b,
        nickname="windows_node",
        transport=lan_b,
        initial_transport="lan",
    )

    received_by_b: list[tuple[str, str, bool]] = []
    coord_b.on_message_received = lambda s, t, enc: received_by_b.append((s, t, enc))

    await coord_a.start()
    await coord_b.start()

    try:
        port_b = lan_b.server.bound_port
        # Only Alice knows Bob's endpoint; Bob has NOT received any UDP beacon from Alice!
        coord_a.peer_addresses[id_b.peer_id_hex] = f"127.0.0.1:{port_b}"
        coord_a.address_to_peer_id[f"127.0.0.1:{port_b}"] = id_b.peer_id_hex
        assert id_a.peer_id_hex not in coord_b.peer_addresses

        # Connect outbound from Alice to Bob
        await coord_a.connect_peer(f"127.0.0.1:{port_b}")
        await asyncio.sleep(0.05)

        # Send Announce with TTL=3 (< MAX_TTL=7) from Alice to Bob over the inbound socket
        low_ttl_announce = BitchatPacket.create(
            message_type=MessageType.Announce,
            sender_id=id_a.peer_id,
            payload=b"fedora_node",
            ttl=3,
        )
        await lan_a.send_to_peer(f"127.0.0.1:{port_b}", low_ttl_announce)
        await asyncio.sleep(0.05)

        # Bob must have bound the inbound ephemeral address to Alice's peer_id
        assert id_a.peer_id_hex in coord_b.peer_addresses

        # Now Alice sends an encrypted DM to Bob
        await coord_a.send_direct_message(id_b.peer_id_hex, "cross-OS message")
        for _ in range(40):
            if received_by_b:
                break
            await asyncio.sleep(0.05)

        assert received_by_b == [(id_a.peer_id_hex, "cross-OS message", True)]
    finally:
        await coord_a.stop()
        await coord_b.stop()


# ===========================================================================
# 3. Handshake Role Contention & Stale Initiator Recovery
# ===========================================================================


@pytest.mark.asyncio
async def test_stale_initiator_recovers_on_handshake_request_and_direct_init() -> None:
    """Verify stale HANDSHAKING initiator resets on HandshakeRequest, and direct Init succeeds."""
    id_low = LocalIdentity.from_x25519_private(bytes([0x01] * 32))
    id_high = LocalIdentity.from_x25519_private(bytes([0x02] * 32))
    if id_low.peer_id_hex > id_high.peer_id_hex:
        id_low, id_high = id_high, id_low

    coord_low = SessionCoordinator(local_identity=id_low, nickname="low")
    coord_high = SessionCoordinator(local_identity=id_high, nickname="high")

    # Wire direct packet exchange between coord_low and coord_high
    async def send_low_to_high(_target: str | None, pkt: BitchatPacket) -> None:
        await coord_high._process_packet_async(pkt, "link_low")

    async def send_high_to_low(_target: str | None, pkt: BitchatPacket) -> None:
        await coord_low._process_packet_async(pkt, "link_high")

    coord_low._send_packet = send_low_to_high  # type: ignore[method-assign]
    coord_high._send_packet = send_high_to_low  # type: ignore[method-assign]

    received_low: list[tuple[str, str, bool]] = []
    coord_low.on_message_received = lambda s, t, enc: received_low.append((s, t, enc))

    # Simulate stale HANDSHAKING state on low-ID initiator (as if earlier msg1 was lost)
    stale_session = coord_low.get_or_create_session(id_high.peer_id_hex)
    assert stale_session.role == NoiseRole.INITIATOR
    stale_session.start_handshake()
    stale_session._handshake_started_at = 0.0
    assert stale_session.state == NoiseSessionState.HANDSHAKING

    # High-ID responder sends a DM -> triggers HandshakeRequest -> low-ID resets and completes handshake
    await coord_high.send_direct_message(
        id_low.peer_id_hex, "recovered from stale handshake"
    )

    for _ in range(20):
        if received_low:
            break
        await asyncio.sleep(0.02)

    assert received_low == [
        (id_high.peer_id_hex, "recovered from stale handshake", True)
    ]
    assert coord_low.get_session(id_high.peer_id_hex).is_established  # type: ignore[union-attr]
    assert coord_high.get_session(id_low.peer_id_hex).is_established  # type: ignore[union-attr]


# ===========================================================================
# 4. BLE Discovery -> GATT Readiness -> Full Noise XX Handshake & DM
# ===========================================================================


@pytest.mark.asyncio
async def test_ble_central_and_peripheral_complete_noise_handshake_via_coordinator() -> (
    None
):
    """Verify BLE Central and Peripheral complete Noise XX handshake without remaining pending."""
    id_central = LocalIdentity.generate()
    id_periph = LocalIdentity.generate()

    central_clients: dict[str, MockBleakClient] = {}
    server_backend_periph = MockBLEServerBackend()
    server_backend_central = MockBLEServerBackend()

    def central_client_factory(
        address: str, disconnected_callback: Any = None
    ) -> MockBleakClient:
        client = MockBleakClient(address, disconnected_callback=disconnected_callback)
        central_clients[address] = client
        return client

    ble_mgr_central = BLEManager(
        sender_id=id_central.peer_id,
        scanner_factory=lambda **kw: MockBleakScanner(**kw),
        client_factory=central_client_factory,
    )
    ble_srv_central = BLEServer(
        backend=server_backend_central,
        peer_id=id_central.peer_id_hex,
        nickname="central_node",
    )
    bt_central = BluetoothTransport(
        ble_mgr_central, ble_srv_central, inter_fragment_delay=0.001
    )

    ble_mgr_periph = BLEManager(
        sender_id=id_periph.peer_id,
        scanner_factory=lambda **kw: MockBleakScanner(**kw),
    )
    ble_srv_periph = BLEServer(
        backend=server_backend_periph,
        peer_id=id_periph.peer_id_hex,
        nickname="periph_node",
    )
    bt_periph = BluetoothTransport(
        ble_mgr_periph, ble_srv_periph, inter_fragment_delay=0.001
    )

    coord_central = SessionCoordinator(
        local_identity=id_central,
        nickname="central_node",
        ble_manager=ble_mgr_central,
        ble_server=ble_srv_central,
        transport=bt_central,
        initial_transport="bluetooth",
    )
    coord_periph = SessionCoordinator(
        local_identity=id_periph,
        nickname="periph_node",
        ble_manager=ble_mgr_periph,
        ble_server=ble_srv_periph,
        transport=bt_periph,
        initial_transport="bluetooth",
    )

    received_periph: list[tuple[str, str, bool]] = []
    received_central: list[tuple[str, str, bool]] = []
    coord_periph.on_message_received = lambda s, t, enc: received_periph.append(
        (s, t, enc)
    )
    coord_central.on_message_received = lambda s, t, enc: received_central.append(
        (s, t, enc)
    )

    await coord_central.start()
    await coord_periph.start()

    try:
        periph_addr = "AA:BB:CC:DD:EE:99"
        central_client_id = "CENTRAL_GATT_CLIENT_1"

        # Register discovered peripheral on central
        disc_peer = DiscoveredPeer(
            address=periph_addr,
            name="periph_node",
            rssi=-55,
            service_uuids=(ble_srv_periph.service_uuid,),
            peer_id=id_periph.peer_id_hex,
            nickname="periph_node",
        )
        ble_mgr_central.scanner._discovered_peers[periph_addr] = disc_peer
        coord_central._handle_peer_discovered(disc_peer)

        # Connect Central to Peripheral GATT server
        await coord_central.connect_peer(periph_addr)
        mock_client = central_clients[periph_addr]
        server_backend_periph.attach_client(mock_client)

        # Bridge Central GATT writes -> Peripheral BLEServer
        orig_write = mock_client.write_gatt_char

        async def bridged_write(char: Any, data: bytes, response: bool = False) -> None:
            await orig_write(char, data, response=response)
            server_backend_periph.emit_write(bytes(data), client_id=central_client_id)

        mock_client.write_gatt_char = bridged_write  # type: ignore[method-assign]

        # Exchange Announce over BLE link
        await coord_central.send_announce()
        await asyncio.sleep(0.05)

        # Verify Peripheral registered central_client_id in BluetoothTransport._server_clients
        # and includes it in connected_peers!
        assert central_client_id in bt_periph.connected_peers
        assert (
            coord_periph.address_to_peer_id.get(central_client_id)
            == id_central.peer_id_hex
        )

        # Central sends encrypted DM to Peripheral -> triggers 3-message Noise XX handshake over BLE
        await coord_central.send_direct_message(
            id_periph.peer_id_hex, "hello over BLE GATT!"
        )
        for _ in range(40):
            if received_periph:
                break
            await asyncio.sleep(0.02)

        assert received_periph == [
            (id_central.peer_id_hex, "hello over BLE GATT!", True)
        ]
        assert coord_central.get_session(id_periph.peer_id_hex).is_established  # type: ignore[union-attr]
        assert coord_periph.get_session(id_central.peer_id_hex).is_established  # type: ignore[union-attr]

        # Peripheral replies over BLE notification path
        await coord_periph.send_direct_message(
            id_central.peer_id_hex, "BLE handshake complete!"
        )
        for _ in range(40):
            if received_central:
                break
            await asyncio.sleep(0.02)

        assert received_central == [
            (id_periph.peer_id_hex, "BLE handshake complete!", True)
        ]

        # Verify structured connection diagnostics report contains zero secret keys
        report = coord_central.get_connection_diagnostics_report()
        assert report["active_transport"] == "bluetooth"
        assert len(report["sessions"]) >= 1
        assert report["sessions"][0]["state_after"] == "Established"
        report_str = str(report)
        assert id_central.x25519_private.hex() not in report_str
        assert id_periph.x25519_private.hex() not in report_str
    finally:
        await coord_central.stop()
        await coord_periph.stop()


# ===========================================================================
# 5. BLE Pre-Ready Notification Buffering During SUBSCRIBING
# ===========================================================================


@pytest.mark.asyncio
async def test_ble_connection_buffers_notifications_during_subscribing() -> None:
    """Notifications arriving inside start_notify before READY are buffered and delivered."""
    early_notifications: list[bytes] = []

    class EarlyNotifyMockClient(MockBleakClient):
        async def start_notify(self, char: Any, callback: Any) -> None:
            await super().start_notify(char, callback)
            # Fire notification immediately while BLEConnection is still in SUBSCRIBING state!
            self.emit_notification(b"early_handshake_init_frame")

    conn = BLEConnection(
        peer_address="AA:BB:CC:DD:EE:77",
        notification_callback=early_notifications.append,
        client_factory=lambda addr, disconnected_callback=None: EarlyNotifyMockClient(
            addr, disconnected_callback=disconnected_callback
        ),
    )

    await conn.connect()
    assert conn.state == BLEConnectionState.READY
    assert early_notifications == [b"early_handshake_init_frame"]
    await conn.disconnect()


# ===========================================================================
# 6. Failed Session Recovery & Simultaneous Initiation Contention
# ===========================================================================


@pytest.mark.asyncio
async def test_failed_session_recovers_on_incoming_noise_handshake_init() -> None:
    """A responder session in FAILED state resets and completes when fresh NoiseHandshakeInit arrives."""
    id_low = LocalIdentity.from_x25519_private(bytes([0x01] * 32))
    id_high = LocalIdentity.from_x25519_private(bytes([0x02] * 32))
    if id_low.peer_id_hex > id_high.peer_id_hex:
        id_low, id_high = id_high, id_low

    coord_low = SessionCoordinator(local_identity=id_low, nickname="low")
    coord_high = SessionCoordinator(local_identity=id_high, nickname="high")

    async def send_low_to_high(_target: str | None, pkt: BitchatPacket) -> None:
        await coord_high._process_packet_async(pkt, "link_low")

    async def send_high_to_low(_target: str | None, pkt: BitchatPacket) -> None:
        await coord_low._process_packet_async(pkt, "link_high")

    coord_low._send_packet = send_low_to_high  # type: ignore[method-assign]
    coord_high._send_packet = send_high_to_low  # type: ignore[method-assign]

    received_high: list[tuple[str, str, bool]] = []
    coord_high.on_message_received = lambda s, t, enc: received_high.append((s, t, enc))

    # Force responder session to FAILED (simulating a prior failed handshake)
    s_high = coord_high.get_or_create_session(id_low.peer_id_hex)
    s_high._state = NoiseSessionState.FAILED

    # Low-ID initiator sends direct message
    await coord_low.send_direct_message(id_high.peer_id_hex, "recovered after failure")
    await asyncio.sleep(0.05)

    assert received_high == [(id_low.peer_id_hex, "recovered after failure", True)]
    assert coord_low.get_session(id_high.peer_id_hex).is_established  # type: ignore[union-attr]
    assert coord_high.get_session(id_low.peer_id_hex).is_established  # type: ignore[union-attr]


@pytest.mark.asyncio
async def test_failed_session_recovers_on_send_direct_message() -> None:
    """An initiator session in FAILED state resets and completes when send_direct_message is called."""
    id_low = LocalIdentity.from_x25519_private(bytes([0x01] * 32))
    id_high = LocalIdentity.from_x25519_private(bytes([0x02] * 32))
    if id_low.peer_id_hex > id_high.peer_id_hex:
        id_low, id_high = id_high, id_low

    coord_low = SessionCoordinator(local_identity=id_low, nickname="low")
    coord_high = SessionCoordinator(local_identity=id_high, nickname="high")

    async def send_low_to_high(_target: str | None, pkt: BitchatPacket) -> None:
        await coord_high._process_packet_async(pkt, "link_low")

    async def send_high_to_low(_target: str | None, pkt: BitchatPacket) -> None:
        await coord_low._process_packet_async(pkt, "link_high")

    coord_low._send_packet = send_low_to_high  # type: ignore[method-assign]
    coord_high._send_packet = send_high_to_low  # type: ignore[method-assign]

    received_high: list[tuple[str, str, bool]] = []
    coord_high.on_message_received = lambda s, t, enc: received_high.append((s, t, enc))

    # Force initiator session to FAILED
    s_low = coord_low.get_or_create_session(id_high.peer_id_hex)
    s_low._state = NoiseSessionState.FAILED

    await coord_low.send_direct_message(id_high.peer_id_hex, "initiator retry recovery")
    await asyncio.sleep(0.05)

    assert received_high == [(id_low.peer_id_hex, "initiator retry recovery", True)]
    assert coord_low.get_session(id_high.peer_id_hex).is_established  # type: ignore[union-attr]
    assert coord_high.get_session(id_low.peer_id_hex).is_established  # type: ignore[union-attr]


@pytest.mark.asyncio
async def test_simultaneous_noise_handshake_init_contention_resolved() -> None:
    """When both peers send DMs simultaneously, role contention resolves without dropped frames."""
    id_low = LocalIdentity.from_x25519_private(bytes([0x01] * 32))
    id_high = LocalIdentity.from_x25519_private(bytes([0x02] * 32))
    if id_low.peer_id_hex > id_high.peer_id_hex:
        id_low, id_high = id_high, id_low

    coord_low = SessionCoordinator(local_identity=id_low, nickname="low")
    coord_high = SessionCoordinator(local_identity=id_high, nickname="high")

    received_low: list[tuple[str, str, bool]] = []
    received_high: list[tuple[str, str, bool]] = []
    coord_low.on_message_received = lambda s, t, enc: received_low.append((s, t, enc))
    coord_high.on_message_received = lambda s, t, enc: received_high.append((s, t, enc))

    queue_low_to_high: list[BitchatPacket] = []
    queue_high_to_low: list[BitchatPacket] = []

    async def send_low_to_high(_target: str | None, pkt: BitchatPacket) -> None:
        queue_low_to_high.append(pkt)

    async def send_high_to_low(_target: str | None, pkt: BitchatPacket) -> None:
        queue_high_to_low.append(pkt)

    coord_low._send_packet = send_low_to_high  # type: ignore[method-assign]
    coord_high._send_packet = send_high_to_low  # type: ignore[method-assign]

    # Both nodes initiate direct messages concurrently
    await coord_low.send_direct_message(
        id_high.peer_id_hex, "concurrent message from low"
    )
    await coord_high.send_direct_message(
        id_low.peer_id_hex, "concurrent message from high"
    )

    # Propagate inflight packets across rounds
    for _ in range(10):
        low_pkts = list(queue_low_to_high)
        high_pkts = list(queue_high_to_low)
        queue_low_to_high.clear()
        queue_high_to_low.clear()
        if not low_pkts and not high_pkts:
            break
        for p in low_pkts:
            await coord_high._process_packet_async(p, "link_low")
        for p in high_pkts:
            await coord_low._process_packet_async(p, "link_high")
        await asyncio.sleep(0.01)

    assert received_low == [(id_high.peer_id_hex, "concurrent message from high", True)]
    assert received_high == [(id_low.peer_id_hex, "concurrent message from low", True)]
    assert coord_low.get_session(id_high.peer_id_hex).is_established  # type: ignore[union-attr]
    assert coord_high.get_session(id_low.peer_id_hex).is_established  # type: ignore[union-attr]
