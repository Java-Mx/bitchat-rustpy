"""Phase 3 BLE Reliability, Native Rust BLE Core & bitchat-tui Noise XX Interoperability Tests."""

from __future__ import annotations

import asyncio
import struct
import sys
import types
from typing import Any

import pytest
from tests.ble.mocks import (
    MockBleakCharacteristic,
    MockBleakClient,
    MockBleakService,
)

from bitchat._native import HAS_NATIVE_CORE, _core
from bitchat.app.session_coordinator import SessionCoordinator, _decode_chat_payload
from bitchat.ble.gatt import GATTManager
from bitchat.ble.scanner import BLEScanner
from bitchat.ble.server import BLEServer
from bitchat.crypto.identity import LocalIdentity
from bitchat.crypto.noise import (
    NoiseHandshakeState,
    NoiseRole,
    PyNoiseHandshakeState,
)
from bitchat.exceptions import BLEGATTError, ReplayError
from bitchat.protocol.constants import (
    BITCHAT_CHARACTERISTIC_UUID,
    BITCHAT_SERVICE_UUID,
    MessageType,
)
from bitchat.protocol.decoder import decode_packet
from bitchat.protocol.encoder import encode_packet
from bitchat.protocol.packet import BitchatPacket

# ===========================================================================
# 1. Reference bitchat-tui (commit 107a13c) Binary DM Payload & Noise XX Tests
# ===========================================================================


@pytest.mark.skipif(not HAS_NATIVE_CORE, reason="Requires native Rust core")
def test_tui_binary_dm_payload_variants_decode_cleanly() -> None:
    """Rust core decodes all bitchat-tui DM inner payloads without false positives."""
    assert _decode_chat_payload(b"Plain UTF-8 DM") == "Plain UTF-8 DM"
    assert _decode_chat_payload(bytes([MessageType.Message]) + b"Prefixed UTF-8") == (
        "Prefixed UTF-8"
    )

    bin_msg = _core.encode_bitchat_message_payload_raw(
        "alice_tui",
        "Encrypted DM from bitchat-tui 107a13c",
        "deadbeef00000000",
        "msg-uuid-001",
        True,
        None,
        1_730_000_000_000,
    )
    # Variant A: [0x04] || binary BitchatMessage (message_handlers.rs:168)
    assert _decode_chat_payload(bytes([MessageType.Message]) + bin_msg) == (
        "Encrypted DM from bitchat-tui 107a13c"
    )
    # Variant B: bare binary BitchatMessage
    assert _decode_chat_payload(bin_msg) == "Encrypted DM from bitchat-tui 107a13c"
    # Variant C: nested BitchatPacket(Message) (notification_handlers.rs:1454)
    inner_pkt = BitchatPacket.create(
        message_type=MessageType.Message,
        sender_id=bytes.fromhex("deadbeef00000000"),
        payload=bin_msg,
    )
    nested_wire = encode_packet(inner_pkt, add_padding=False)
    assert _decode_chat_payload(nested_wire) == "Encrypted DM from bitchat-tui 107a13c"


@pytest.mark.asyncio
async def test_differential_noise_xx_both_roles_and_tui_binary_dm() -> None:
    """Verify RustPy as both initiator and responder with bitchat-tui binary DM payloads."""
    id_a = LocalIdentity.generate()
    id_b = LocalIdentity.generate()
    # Ensure deterministic initiator < responder ordering
    init_id, resp_id = (
        (id_a, id_b) if id_a.peer_id_hex < id_b.peer_id_hex else (id_b, id_a)
    )

    # Role 1: RustPy initiator <-> Reference pure-Python responder
    rp_init = NoiseHandshakeState(NoiseRole.INITIATOR, init_id.x25519_private)
    ref_resp = PyNoiseHandshakeState(NoiseRole.RESPONDER, resp_id.x25519_private)

    m1 = rp_init.write_message(b"")
    assert len(m1) == 32
    assert ref_resp.read_message(m1) == b""
    m2 = ref_resp.write_message(b"")
    assert len(m2) == 96
    assert rp_init.read_message(m2) == b""
    m3 = rp_init.write_message(b"")
    assert len(m3) == 64
    assert ref_resp.read_message(m3) == b""
    assert rp_init.get_handshake_hash() == ref_resp.get_handshake_hash()

    rp_send, rp_recv = rp_init.get_transport_ciphers()
    ref_send, ref_recv = ref_resp.get_transport_ciphers()

    # Nonce 0 works once and replay of nonce 0 MUST fail closed
    if HAS_NATIVE_CORE:
        tui_bin = bytes(
            [MessageType.Message]
        ) + _core.encode_bitchat_message_payload_raw(
            "tui",
            "Hello over BLE Noise!",
            resp_id.peer_id_hex,
            "id-1",
            True,
            None,
            1_730_000_000_000,
        )
    else:
        tui_bin = b"Hello over BLE Noise!"
    ct_from_tui = ref_send.encrypt(tui_bin, b"")
    assert struct.unpack("<I", ct_from_tui[:4])[0] == 0
    pt = rp_recv.decrypt(ct_from_tui, b"")
    assert _decode_chat_payload(pt) == "Hello over BLE Noise!"

    with pytest.raises(ReplayError):
        rp_recv.decrypt(ct_from_tui, b"")

    # Bidirectional reply
    ct_reply = rp_send.encrypt(b"Reply from RustPy", b"")
    assert ref_recv.decrypt(ct_reply, b"") == b"Reply from RustPy"


@pytest.mark.asyncio
async def test_simultaneous_handshake_arbitration_and_reconnect_fresh_keys() -> None:
    """Simultaneous Noise XX initiation resolves deterministically; reconnect rotates keys."""
    id_low = LocalIdentity.generate()
    id_high = LocalIdentity.generate()
    if id_low.peer_id_hex > id_high.peer_id_hex:
        id_low, id_high = id_high, id_low

    c_low = SessionCoordinator(local_identity=id_low, nickname="low_node")
    c_high = SessionCoordinator(local_identity=id_high, nickname="high_node")

    got_low: list[tuple[str, str, bool]] = []
    got_high: list[tuple[str, str, bool]] = []
    c_low.on_message_received = lambda s, t, enc: got_low.append((s, t, enc))
    c_high.on_message_received = lambda s, t, enc: got_high.append((s, t, enc))

    async def low_to_high(_target: str | None, pkt: BitchatPacket) -> None:
        await c_high._process_packet_async(
            decode_packet(encode_packet(pkt)), "low_addr"
        )

    async def high_to_low(_target: str | None, pkt: BitchatPacket) -> None:
        await c_low._process_packet_async(
            decode_packet(encode_packet(pkt)), "high_addr"
        )

    c_low._send_packet = low_to_high  # type: ignore[method-assign]
    c_high._send_packet = high_to_low  # type: ignore[method-assign]

    # Trigger simultaneous initiation from both sides
    await asyncio.gather(
        c_low.send_direct_message(id_high.peer_id_hex, "msg from low"),
        c_high.send_direct_message(id_low.peer_id_hex, "msg from high"),
    )
    await asyncio.sleep(0.08)

    sess_low = c_low.get_session(id_high.peer_id_hex)
    sess_high = c_high.get_session(id_low.peer_id_hex)
    assert sess_low is not None and sess_low.is_established
    assert sess_high is not None and sess_high.is_established
    assert sess_low.handshake_hash == sess_high.handshake_hash
    assert any(t == "msg from low" and enc for _, t, enc in got_high)
    assert any(t == "msg from high" and enc for _, t, enc in got_low)

    # Disconnect & reconnect MUST create a fresh handshake hash (fresh ephemerals)
    first_hash = sess_low.handshake_hash
    c_low._handle_peer_disconnected("high_addr")
    c_high._handle_peer_disconnected("low_addr")
    await c_low.send_direct_message(id_high.peer_id_hex, "after reconnect")
    await asyncio.sleep(0.08)

    sess_low_2 = c_low.get_session(id_high.peer_id_hex)
    assert sess_low_2 is not None and sess_low_2.is_established
    assert sess_low_2.handshake_hash != first_hash
    assert any(t == "after reconnect" and enc for _, t, enc in got_high)


# ===========================================================================
# 2. Windows GATT + Decoupled Companion Advertisement Fix
# ===========================================================================


@pytest.mark.asyncio
async def test_windows_gatt_provider_survives_companion_publisher_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If GattServiceProvider succeeds and companion publisher fails, GATT MUST stay active."""
    monkeypatch.setattr(sys, "platform", "win32")

    provider_stopped = False
    publisher_stopped = False

    class DummyCharacteristic:
        def __init__(self) -> None:
            self.subscribed_clients: list[Any] = []

        def add_write_requested(self, cb: Any) -> int:
            return 1

        def add_subscribed_clients_changed(self, cb: Any) -> int:
            return 2

    class DummyService:
        async def create_characteristic_async(self, _uuid: Any, _params: Any) -> Any:
            return types.SimpleNamespace(error=0, characteristic=DummyCharacteristic())

    class DummyProvider:
        advertisement_status = 2  # Started

        def __init__(self) -> None:
            self.service = DummyService()

        def start_advertising_with_parameters(self, _params: Any) -> None:
            self.advertisement_status = 2

        def stop_advertising(self) -> None:
            nonlocal provider_stopped
            provider_stopped = True

    class FailingPublisher:
        status = 5  # Aborted

        def __init__(self) -> None:
            self.advertisement = types.SimpleNamespace(manufacturer_data=[])

        def start(self) -> None:
            raise RuntimeError("WinRT companion advertisement rejected (status 5)")

        def stop(self) -> None:
            nonlocal publisher_stopped
            publisher_stopped = True

    class DummyGatt:
        class GattServiceProvider:
            @staticmethod
            async def create_async(_srv_uuid: Any) -> Any:
                return types.SimpleNamespace(error=0, service_provider=DummyProvider())

        class GattServiceProviderAdvertisingParameters:
            is_connectable = True
            is_discoverable = True

        class GattLocalCharacteristicParameters:
            characteristic_properties = 0
            write_protection_level = 0
            read_protection_level = 0

        class GattCharacteristicProperties:
            WRITE_WITHOUT_RESPONSE = 4
            WRITE = 8
            NOTIFY = 16

    class DummyAdv:
        BluetoothLEAdvertisementPublisher = FailingPublisher

        class BluetoothLEManufacturerData:
            def __init__(self) -> None:
                self.company_id = 0
                self.data = None

    class DummyStreams:
        class DataWriter:
            def write_bytes(self, _b: bytes) -> None:
                pass

            def detach_buffer(self) -> bytes:
                return b""

    winrt_pkg: Any = types.ModuleType("winrt")
    windows_pkg: Any = types.ModuleType("winrt.windows")
    devices_pkg: Any = types.ModuleType("winrt.windows.devices")
    bluetooth_pkg: Any = types.ModuleType("winrt.windows.devices.bluetooth")
    storage_pkg: Any = types.ModuleType("winrt.windows.storage")
    winrt_pkg.windows = windows_pkg
    windows_pkg.devices = devices_pkg
    devices_pkg.bluetooth = bluetooth_pkg
    windows_pkg.storage = storage_pkg
    bluetooth_pkg.advertisement = DummyAdv
    bluetooth_pkg.genericattributeprofile = DummyGatt
    storage_pkg.streams = DummyStreams

    for mod_name, mod in (
        ("winrt", winrt_pkg),
        ("winrt.windows", windows_pkg),
        ("winrt.windows.devices", devices_pkg),
        ("winrt.windows.devices.bluetooth", bluetooth_pkg),
        ("winrt.windows.devices.bluetooth.advertisement", DummyAdv),
        ("winrt.windows.devices.bluetooth.genericattributeprofile", DummyGatt),
        ("winrt.windows.storage", storage_pkg),
        ("winrt.windows.storage.streams", DummyStreams),
    ):
        monkeypatch.setitem(sys.modules, mod_name, mod)

    server = BLEServer()
    await server.start()

    # CRITICAL PHASE 3 INVARIANT: GATT provider survived companion publisher failure!
    assert server.is_advertising is True
    assert server._provider is not None
    assert server._characteristic is not None
    assert server._publisher is None
    assert provider_stopped is False
    assert publisher_stopped is True

    telem = server.get_telemetry()
    assert telem["has_provider"] is True
    assert telem["has_publisher"] is False
    assert "Active" in telem["gatt_server_status"]
    assert "GATT service remains active" in telem["discovery_advertisement_status"]

    await server.stop()
    assert provider_stopped is True


# ===========================================================================
# 3. Scanner Peer-ID Extraction, GATT Property Validation & Rust BLE Core
# ===========================================================================


def test_scanner_service_data_peer_id_requires_full_8_bytes() -> None:
    """Scanner must NOT emit truncated 12/14-char peer IDs from 6-7 byte service data."""
    scanner = BLEScanner()
    dev = types.SimpleNamespace(address="AA:BB:CC:DD:EE:01", name="PeerShort")

    # 6-byte service data: valid BitChat service match, but peer_id must be None (not 12-char)
    adv_short = types.SimpleNamespace(
        service_uuids=[],
        service_data={BITCHAT_SERVICE_UUID.lower(): b"\x01\x02\x03\x04\x05\x06"},
        manufacturer_data={},
        rssi=-55,
        local_name="PeerShort",
    )
    scanner._detection_callback(dev, adv_short)  # type: ignore[arg-type]
    peer = scanner.discovered_peers["AA:BB:CC:DD:EE:01"]
    assert peer.peer_id is None

    # All-zero 8-byte service data: peer_id must be None
    adv_zero = types.SimpleNamespace(
        service_uuids=[],
        service_data={BITCHAT_SERVICE_UUID.lower(): b"\x00" * 8},
        manufacturer_data={},
        rssi=-55,
        local_name="PeerShort",
    )
    scanner._detection_callback(dev, adv_zero)  # type: ignore[arg-type]
    assert scanner.discovered_peers["AA:BB:CC:DD:EE:01"].peer_id is None

    # Valid 8-byte service data: full 16-hex-char peer_id extracted
    adv_valid = types.SimpleNamespace(
        service_uuids=[],
        service_data={BITCHAT_SERVICE_UUID.lower(): bytes.fromhex("0102030405060708")},
        manufacturer_data={},
        rssi=-50,
        local_name="PeerShort",
    )
    scanner._detection_callback(dev, adv_valid)  # type: ignore[arg-type]
    assert scanner.discovered_peers["AA:BB:CC:DD:EE:01"].peer_id == "0102030405060708"


@pytest.mark.asyncio
async def test_gatt_manager_enforces_required_properties_and_hyphen_insensitive_uuids() -> (
    None
):
    """GATTManager rejects characteristics missing notify or write and normalizes UUIDs."""
    # Valid characteristic without hyphens in UUID
    svc_ok = MockBleakService(
        uuid=BITCHAT_SERVICE_UUID.replace("-", "").upper(),
        characteristics=[
            MockBleakCharacteristic(
                uuid=BITCHAT_CHARACTERISTIC_UUID.replace("-", "").upper(),
                properties=["read", "write", "notify"],
            )
        ],
    )
    client_ok = MockBleakClient(address="11:22:33:44:55:01", services=[svc_ok])
    await client_ok.connect()
    gm = GATTManager()
    ch = await gm.discover(client_ok)
    assert ch is not None
    assert gm.last_write_mode == "write-with-response"

    # Missing notify must raise BLEGATTError
    svc_no_notify = MockBleakService(
        uuid=BITCHAT_SERVICE_UUID,
        characteristics=[
            MockBleakCharacteristic(
                uuid=BITCHAT_CHARACTERISTIC_UUID,
                properties=["read", "write"],
            )
        ],
    )
    client_bad = MockBleakClient(address="11:22:33:44:55:02", services=[svc_no_notify])
    await client_bad.connect()
    with pytest.raises(BLEGATTError, match="notify"):
        await gm.discover(client_bad)

    # Missing write must raise BLEGATTError
    svc_no_write = MockBleakService(
        uuid=BITCHAT_SERVICE_UUID,
        characteristics=[
            MockBleakCharacteristic(
                uuid=BITCHAT_CHARACTERISTIC_UUID,
                properties=["read", "notify"],
            )
        ],
    )
    client_bad2 = MockBleakClient(address="11:22:33:44:55:03", services=[svc_no_write])
    await client_bad2.connect()
    with pytest.raises(BLEGATTError, match="write"):
        await gm.discover(client_bad2)


@pytest.mark.skipif(not HAS_NATIVE_CORE, reason="Requires native Rust core")
def test_native_rust_ble_transport_manager_telemetry_and_redacted_diagnostics() -> None:
    """NativeBleTransportManager exposes truthful telemetry and secret-free traces."""
    mgr = _core.NativeBleTransportManager("0102030405060708", "RustNode")
    try:
        mgr.record_diagnostic("handshake_m1", "aabbccdd", "ok", "Sent 32B Noise M1")
        telem = mgr.get_telemetry()
        assert telem["rust_ble_active"] is True
        assert telem["service_uuid"] == BITCHAT_SERVICE_UUID.upper()
        assert telem["characteristic_uuid"] == BITCHAT_CHARACTERISTIC_UUID.upper()
        assert telem["active_mtu"] == 185
        trace = mgr.get_diagnostic_trace()
        assert any(stage == "handshake_m1" for _, stage, _, _, _ in trace)
        # Verify no private key material or secrets appear in trace
        joined = " ".join(detail for _, _, _, _, detail in trace)
        assert "private" not in joined.lower()
    finally:
        mgr.shutdown()
