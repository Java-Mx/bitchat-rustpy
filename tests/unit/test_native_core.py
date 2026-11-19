"""Differential and unit tests for the Rust/PyO3 native core (bitchat._bitchat_core)."""

from __future__ import annotations

import os

import pytest

from bitchat._native import HAS_NATIVE_CORE, _core
from bitchat.exceptions import (
    FragmentLimitExceededError,
    FramingError,
    InvalidFragmentError,
    PacketDecodingError,
    UnknownMessageTypeError,
    UnsupportedProtocolVersionError,
)
from bitchat.mesh.dedup import (
    PacketDeduplicator,
    PyPacketDeduplicator,
    compute_packet_id,
    py_compute_packet_id,
)
from bitchat.network.framing import (
    PyStreamFramer,
    StreamFramer,
    encode_frame,
    py_encode_frame,
)
from bitchat.protocol.constants import (
    FLAG_HAS_RECIPIENT,
    FLAG_HAS_SIGNATURE,
    FLAG_IS_COMPRESSED,
    MessageType,
)
from bitchat.protocol.decoder import (
    decode_packet,
    py_decode_packet,
    py_unpad_packet_data,
    unpad_packet_data,
)
from bitchat.protocol.encoder import (
    encode_packet,
    get_optimal_block_size,
    pad_packet_data,
    py_encode_packet,
    py_get_optimal_block_size,
)
from bitchat.protocol.fragmentation import (
    fragment_encoded_packet,
    parse_fragment_payload,
    py_fragment_encoded_packet,
    py_parse_fragment_payload,
    py_split_chunks,
    split_chunks,
)
from bitchat.protocol.packet import (
    BitchatPacket,
    peer_id_from_hex,
    peer_id_to_hex,
    py_peer_id_from_hex,
    py_peer_id_to_hex,
)
from bitchat.protocol.reassembly import FragmentReassembler, PyFragmentReassembler


def test_native_core_is_loaded_and_version_matches() -> None:
    """Verify the compiled Rust extension module is loaded and reports version 0.3.2."""
    from bitchat import __version__

    assert HAS_NATIVE_CORE is True
    assert _core is not None
    assert _core.native_core_version() == __version__
    assert _core.native_core_version() == "0.3.2"


@pytest.mark.parametrize(
    ("msg_type", "flags", "ttl", "payload", "recipient", "signature"),
    [
        (MessageType.Announce, 0, 7, b"alice-announce", None, None),
        (
            MessageType.Message,
            FLAG_HAS_RECIPIENT,
            5,
            b"hello mesh world!",
            b"\xaa" * 8,
            None,
        ),
        (
            MessageType.NoiseHandshakeInit,
            FLAG_HAS_RECIPIENT | FLAG_HAS_SIGNATURE,
            3,
            os.urandom(96),
            b"\xbb" * 8,
            b"\xcc" * 64,
        ),
        (
            MessageType.DeliveryAck,
            FLAG_HAS_RECIPIENT | FLAG_HAS_SIGNATURE | FLAG_IS_COMPRESSED,
            1,
            os.urandom(512),
            b"\xdd" * 8,
            b"\xee" * 64,
        ),
    ],
)
def test_differential_packet_encode_decode_and_id(
    msg_type: MessageType,
    flags: int,
    ttl: int,
    payload: bytes,
    recipient: bytes | None,
    signature: bytes | None,
) -> None:
    """Rust and pure-Python packet encoding, decoding, and SHA-256 ID match byte-for-byte."""
    pkt = BitchatPacket(
        version=1,
        message_type=msg_type,
        ttl=ttl,
        timestamp=1_730_000_123_456,
        flags=flags,
        sender_id=b"\x11\x22\x33\x44\x55\x66\x77\x88",
        recipient_id=recipient,
        payload=payload,
        signature=signature,
    )

    rust_unpadded = encode_packet(pkt, add_padding=False)
    py_unpadded = py_encode_packet(pkt, add_padding=False)
    assert rust_unpadded == py_unpadded

    rust_padded = encode_packet(pkt, add_padding=True)
    py_padded = py_encode_packet(pkt, add_padding=True)
    assert len(rust_padded) == len(py_padded)

    assert decode_packet(rust_padded) == py_decode_packet(rust_padded) == pkt
    assert decode_packet(py_padded) == py_decode_packet(py_padded) == pkt

    rust_id = compute_packet_id(pkt)
    py_id = py_compute_packet_id(pkt)
    assert rust_id == py_id


def test_differential_peer_id_hex_and_block_padding() -> None:
    """Rust and Python peer ID hex conversion and block padding match."""
    raw_peer = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
    assert peer_id_to_hex(raw_peer) == py_peer_id_to_hex(raw_peer) == "0123456789abcdef"
    assert (
        peer_id_from_hex("0123456789ABCDEF")
        == py_peer_id_from_hex("0123456789ABCDEF")
        == raw_peer
    )

    for sz in (0, 1, 15, 63, 64, 240, 256, 300, 500, 900, 1024, 1900, 2048, 4096):
        assert get_optimal_block_size(sz) == py_get_optimal_block_size(sz)
        sample = bytes(i % 251 for i in range(sz))
        padded = pad_packet_data(sample)
        assert unpad_packet_data(padded) == py_unpad_packet_data(padded)
        if len(padded) > len(sample):
            assert unpad_packet_data(padded) == sample


def test_differential_decode_error_parity() -> None:
    """Rust and Python packet decoders raise identical BitChat exception subclasses."""
    # 1. Insufficient bytes
    with pytest.raises(PacketDecodingError):
        decode_packet(b"\x01\x02\x03")
    with pytest.raises(PacketDecodingError):
        py_decode_packet(b"\x01\x02\x03")

    base_pkt = BitchatPacket.create(
        message_type=MessageType.Announce,
        sender_id=b"\x01" * 8,
        payload=b"hello",
    )

    # 2. Unsupported protocol version
    bad_ver = bytearray(encode_packet(base_pkt, add_padding=False))
    bad_ver[0] = 99
    with pytest.raises(UnsupportedProtocolVersionError):
        decode_packet(bytes(bad_ver))
    with pytest.raises(UnsupportedProtocolVersionError):
        py_decode_packet(bytes(bad_ver))

    # 3. Unknown message type
    bad_type = bytearray(encode_packet(base_pkt, add_padding=False))
    bad_type[1] = 0xFE
    with pytest.raises(UnknownMessageTypeError):
        decode_packet(bytes(bad_type))
    with pytest.raises(UnknownMessageTypeError):
        py_decode_packet(bytes(bad_type))

    # 4. Malformed padding byte
    bad_pad = bytearray(encode_packet(base_pkt, add_padding=False) + b"\x00\x00\x99")
    with pytest.raises(PacketDecodingError):
        decode_packet(bytes(bad_pad))
    with pytest.raises(PacketDecodingError):
        py_decode_packet(bytes(bad_pad))


def test_differential_fragmentation_and_reassembly() -> None:
    """Rust and Python fragmentation and reassembly match across multi-chunk payloads."""
    raw_packet = os.urandom(4096)
    sender_id = b"\xaa\xbb\xcc\xdd\x11\x22\x33\x44"
    frag_id = b"\xca\xfe\xba\xbe\x00\x01\x02\x03"

    assert split_chunks(raw_packet, 469) == py_split_chunks(raw_packet, 469)

    rust_frags = fragment_encoded_packet(
        raw_packet,
        sender_id=sender_id,
        original_message_type=MessageType.Message,
        fragment_id=frag_id,
        ttl=5,
        timestamp=1_730_000_000_000,
    )
    py_frags = py_fragment_encoded_packet(
        raw_packet,
        sender_id=sender_id,
        original_message_type=MessageType.Message,
        fragment_id=frag_id,
        ttl=5,
        timestamp=1_730_000_000_000,
    )
    assert rust_frags == py_frags
    assert len(rust_frags) > 2

    for rf, pf in zip(rust_frags, py_frags, strict=True):
        assert parse_fragment_payload(rf.payload) == py_parse_fragment_payload(
            pf.payload
        )

    # Out-of-order reassembly parity
    rust_reasm = FragmentReassembler()
    py_reasm = PyFragmentReassembler()

    shuffled = list(reversed(rust_frags))
    for i, frag in enumerate(shuffled):
        r_out = rust_reasm.add_fragment_packet(frag)
        p_out = py_reasm.add_fragment_packet(frag)
        assert r_out == p_out
        if i < len(shuffled) - 1:
            assert r_out is None
        else:
            assert r_out == raw_packet


def test_differential_reassembly_security_errors() -> None:
    """Rust and Python reassemblers enforce identical security limits and error types."""
    sender_id = b"\x01" * 8
    raw = os.urandom(1500)
    frag_id = b"\x10" * 8
    frags = fragment_encoded_packet(
        raw,
        sender_id=sender_id,
        original_message_type=MessageType.Message,
        fragment_id=frag_id,
        ttl=4,
        timestamp=1000,
    )
    assert len(frags) >= 3

    r_reasm = FragmentReassembler()
    p_reasm = PyFragmentReassembler()
    assert r_reasm.add_fragment_packet(frags[0]) is None
    assert p_reasm.add_fragment_packet(frags[0]) is None

    # Exact duplicate is ignored cleanly
    assert r_reasm.add_fragment_packet(frags[0]) is None
    assert p_reasm.add_fragment_packet(frags[0]) is None

    # Mutate payload byte at the end to create conflicting chunk content
    bad_payload = bytearray(frags[0].payload)
    bad_payload[-1] ^= 0xFF
    conflicting = BitchatPacket(
        version=frags[0].version,
        message_type=frags[0].message_type,
        ttl=frags[0].ttl,
        timestamp=frags[0].timestamp,
        flags=frags[0].flags,
        sender_id=frags[0].sender_id,
        recipient_id=None,
        payload=bytes(bad_payload),
        signature=None,
    )
    with pytest.raises(InvalidFragmentError):
        r_reasm.add_fragment_packet(conflicting)
    with pytest.raises(InvalidFragmentError):
        p_reasm.add_fragment_packet(conflicting)

    # Max reassembled bytes exceeded
    r_small = FragmentReassembler(max_reassembled_bytes=100)
    p_small = PyFragmentReassembler(max_reassembled_bytes=100)
    with pytest.raises(FragmentLimitExceededError):
        r_small.add_fragment_packet(frags[0])
    with pytest.raises(FragmentLimitExceededError):
        p_small.add_fragment_packet(frags[0])


def test_differential_stream_framer() -> None:
    """Rust StreamFramer and PyStreamFramer behave identically on arbitrary TCP chunks."""
    r_framer = StreamFramer(max_frame_size=1024)
    p_framer = PyStreamFramer(max_frame_size=1024)

    payloads = [b"alpha", b"bravo" * 40, b"charlie", os.urandom(512)]
    for p in payloads:
        assert encode_frame(p) == py_encode_frame(p)
    stream = b"".join(encode_frame(p) for p in payloads)

    # Feed in irregular chunk sizes (e.g., 7 bytes at a time)
    r_out: list[bytes] = []
    p_out: list[bytes] = []
    step = 7
    for i in range(0, len(stream), step):
        chunk = stream[i : i + step]
        r_frames = r_framer.feed(chunk)
        p_frames = p_framer.feed(chunk)
        assert r_frames == p_frames
        r_out.extend(r_frames)
        p_out.extend(p_frames)

    assert r_out == p_out == payloads
    assert r_framer.buffered_bytes == p_framer.buffered_bytes == 0

    # Invalid magic raises FramingError in both
    with pytest.raises(FramingError):
        r_framer.feed(b"BADMAGIC\x00\x00\x00\x04test")
    with pytest.raises(FramingError):
        p_framer.feed(b"BADMAGIC\x00\x00\x00\x04test")


def test_differential_packet_deduplicator() -> None:
    """Rust PacketDeduplicator and PyPacketDeduplicator maintain identical LRU + TTL semantics."""
    r_dedup = PacketDeduplicator(max_entries=4, entry_ttl_seconds=10.0)
    py_dedup = PyPacketDeduplicator(max_entries=4, entry_ttl_seconds=10.0)

    packets = [
        BitchatPacket.create(
            message_type=MessageType.Message,
            sender_id=b"\x01" * 8,
            payload=f"msg-{idx}".encode(),
            timestamp=1000 + idx,
        )
        for idx in range(6)
    ]

    for idx, pkt in enumerate(packets):
        assert r_dedup.is_duplicate(pkt, now=100.0 + idx) == py_dedup.is_duplicate(
            pkt, now=100.0 + idx
        )
        assert r_dedup.check_and_record(
            pkt, now=100.0 + idx
        ) == py_dedup.check_and_record(pkt, now=100.0 + idx)
        assert r_dedup.is_duplicate(pkt, now=100.0 + idx) == py_dedup.is_duplicate(
            pkt, now=100.0 + idx
        )
        assert len(r_dedup) == len(py_dedup)

    # First two packets were evicted due to max_entries=4
    assert r_dedup.is_duplicate(packets[0], now=106.0) is False
    assert py_dedup.is_duplicate(packets[0], now=106.0) is False
    assert r_dedup.is_duplicate(packets[5], now=106.0) is True
    assert py_dedup.is_duplicate(packets[5], now=106.0) is True

    # Expiry after entry_ttl_seconds=10.0s
    assert r_dedup.prune_expired(now=200.0) == py_dedup.prune_expired(now=200.0) == 4
    assert len(r_dedup) == len(py_dedup) == 0


# ---------------------------------------------------------------------------
# Stage 2 Differential Tests: Cryptography & Noise XX Engine
# ---------------------------------------------------------------------------


def test_differential_ed25519_and_x25519_primitives() -> None:
    """Rust and Python Ed25519 and X25519 primitives produce identical outputs."""
    from bitchat.crypto import ed25519 as _ed
    from bitchat.crypto import x25519 as _x
    from bitchat.exceptions import InvalidKeyError, SignatureVerificationError

    # Ed25519 deterministic key derivation, signing, and cross-verification
    ed_seed = os.urandom(32)
    rust_ed_pub = _ed.public_key_from_private(ed_seed)
    py_ed_pub = _ed.py_public_key_from_private(ed_seed)
    assert rust_ed_pub == py_ed_pub
    assert _ed.load_public_key(rust_ed_pub) == _ed.py_load_public_key(py_ed_pub)

    msg = b"BitChat Phase 2 deterministic Ed25519 differential test vector"
    rust_sig = _ed.sign(ed_seed, msg)
    py_sig = _ed.py_sign(ed_seed, msg)
    assert rust_sig == py_sig

    _ed.verify(rust_ed_pub, py_sig, msg)
    _ed.py_verify(py_ed_pub, rust_sig, msg)

    with pytest.raises(SignatureVerificationError):
        _ed.verify(rust_ed_pub, rust_sig, msg + b"x")
    with pytest.raises(SignatureVerificationError):
        _ed.py_verify(py_ed_pub, py_sig, msg + b"x")

    # X25519 deterministic key derivation, low-order rejection, and DH parity
    alice_seed = os.urandom(32)
    bob_seed = os.urandom(32)
    assert _x.public_key_from_private(alice_seed) == _x.py_public_key_from_private(
        alice_seed
    )
    assert _x.public_key_from_private(bob_seed) == _x.py_public_key_from_private(
        bob_seed
    )

    alice_pub = _x.public_key_from_private(alice_seed)
    bob_pub = _x.public_key_from_private(bob_seed)
    assert _x.diffie_hellman(alice_seed, bob_pub) == _x.py_diffie_hellman(
        alice_seed, bob_pub
    )
    assert _x.diffie_hellman(bob_seed, alice_pub) == _x.py_diffie_hellman(
        bob_seed, alice_pub
    )

    for bad_point in _x._LOW_ORDER_POINTS:
        with pytest.raises(InvalidKeyError):
            _x.validate_public_key(bad_point)
        with pytest.raises(InvalidKeyError):
            _x.py_validate_public_key(bad_point)


def test_differential_aes_gcm_hkdf_pbkdf2_and_identity() -> None:
    """Rust and Python AES-256-GCM, HKDF, PBKDF2, and identity derivation match."""
    from bitchat.crypto import aes_gcm as _aes
    from bitchat.crypto import hkdf as _hkdf
    from bitchat.crypto import identity as _id
    from bitchat.crypto import pbkdf2 as _pbkdf2

    key = os.urandom(32)
    pt = b"cross-engine AES-256-GCM payload"
    ct_rust = _aes.encrypt(key, pt)
    ct_py = _aes.py_encrypt(key, pt)
    assert _aes.py_decrypt(key, ct_rust) == pt
    assert _aes.decrypt(key, ct_py) == pt

    ck = os.urandom(32)
    ikm = os.urandom(32)
    assert _hkdf.noise_hkdf(ck, ikm, 2) == _hkdf.py_noise_hkdf(ck, ikm, 2)
    assert _hkdf.noise_hkdf(ck, ikm, 3) == _hkdf.py_noise_hkdf(ck, ikm, 3)
    assert _hkdf.legacy_hkdf(ikm) == _hkdf.py_legacy_hkdf(ikm)

    assert _pbkdf2.derive_channel_key(
        "correct-horse-battery-staple", "#general"
    ) == _pbkdf2.py_derive_channel_key("correct-horse-battery-staple", "#general")

    ident = _id.LocalIdentity.generate()
    assert _id.calculate_fingerprint(
        ident.x25519_public
    ) == _id.py_calculate_fingerprint(ident.x25519_public)


def test_differential_noise_xx_handshake_byte_for_byte() -> None:
    """Verify Rust and Python Noise XX 3-message handshake match byte-for-byte."""
    from bitchat.crypto.noise import (
        NoiseHandshakeState,
        NoiseRole,
        PyNoiseHandshakeState,
    )

    alice_static = bytes([0x11] * 32)
    bob_static = bytes([0x22] * 32)
    alice_eph = bytes([0x33] * 32)
    bob_eph = bytes([0x44] * 32)

    # 1. Pure-Python handshake with deterministic ephemeral keys
    py_init = PyNoiseHandshakeState(
        NoiseRole.INITIATOR,
        alice_static,
        fixed_ephemeral_private=alice_eph,
    )
    py_resp = PyNoiseHandshakeState(
        NoiseRole.RESPONDER,
        bob_static,
        fixed_ephemeral_private=bob_eph,
    )

    # 2. Native Rust handshake with identical deterministic ephemeral keys
    rs_init = NoiseHandshakeState(
        NoiseRole.INITIATOR,
        alice_static,
        fixed_ephemeral_private=alice_eph,
    )
    rs_resp = NoiseHandshakeState(
        NoiseRole.RESPONDER,
        bob_static,
        fixed_ephemeral_private=bob_eph,
    )

    # Message 1: Initiator -> Responder ([E])
    py_m1 = py_init.write_message(b"")
    rs_m1 = rs_init.write_message(b"")
    assert rs_m1 == py_m1
    assert len(rs_m1) == 32

    assert py_resp.read_message(py_m1) == b""
    assert rs_resp.read_message(rs_m1) == b""

    # Message 2: Responder -> Initiator ([E, EE, S, ES])
    py_m2 = py_resp.write_message(b"")
    rs_m2 = rs_resp.write_message(b"")
    assert rs_m2 == py_m2
    assert len(rs_m2) == 96

    assert py_init.read_message(py_m2) == b""
    assert rs_init.read_message(rs_m2) == b""

    # Message 3: Initiator -> Responder ([S, SE])
    py_m3 = py_init.write_message(b"")
    rs_m3 = rs_init.write_message(b"")
    assert rs_m3 == py_m3
    assert len(rs_m3) == 64

    assert py_resp.read_message(py_m3) == b""
    assert rs_resp.read_message(rs_m3) == b""

    assert py_init.is_handshake_complete() and rs_init.is_handshake_complete()
    assert py_resp.is_handshake_complete() and rs_resp.is_handshake_complete()

    # Handshake hashes and authenticated static keys match byte-for-byte
    assert (
        rs_init.get_handshake_hash()
        == py_init.get_handshake_hash()
        == rs_resp.get_handshake_hash()
        == py_resp.get_handshake_hash()
    )
    assert (
        rs_init.get_remote_static_public_key() == py_init.get_remote_static_public_key()
    )
    assert (
        rs_resp.get_remote_static_public_key() == py_resp.get_remote_static_public_key()
    )

    # Transport ciphers produce identical wire ciphertexts and cross-decrypt
    py_i_send, py_i_recv = py_init.get_transport_ciphers()
    py_r_send, py_r_recv = py_resp.get_transport_ciphers()
    rs_i_send, rs_i_recv = rs_init.get_transport_ciphers()
    rs_r_send, rs_r_recv = rs_resp.get_transport_ciphers()

    for idx in range(5):
        payload = f"deterministic transport message #{idx}".encode()
        py_ct = py_i_send.encrypt(payload, b"")
        rs_ct = rs_i_send.encrypt(payload, b"")
        assert rs_ct == py_ct
        assert py_r_recv.decrypt(rs_ct, b"") == payload
        assert rs_r_recv.decrypt(py_ct, b"") == payload

        py_reply = py_r_send.encrypt(payload, b"")
        rs_reply = rs_r_send.encrypt(payload, b"")
        assert rs_reply == py_reply
        assert py_i_recv.decrypt(rs_reply, b"") == payload
        assert rs_i_recv.decrypt(py_reply, b"") == payload


# ---------------------------------------------------------------------------
# Stage 3, 4 & 5 Differential Tests: Mesh, LAN, BLE & Handshake State Machine
# ---------------------------------------------------------------------------


def test_differential_mesh_router_and_store_forward() -> None:
    """Verify Rust NativeMeshRouter and NativeStoreAndForwardQueue match Python."""
    from bitchat.mesh.router import MeshRouter, PyMeshRouter
    from bitchat.mesh.store_forward import (
        PyStoreAndForwardQueue,
        StoreAndForwardQueue,
    )

    my_id = b"\xaa" * 8
    r_router = MeshRouter(local_peer_id=my_id, max_relay_ttl=7, rate_limit_per_peer=5)
    p_router = PyMeshRouter(local_peer_id=my_id, max_relay_ttl=7, rate_limit_per_peer=5)

    for idx in range(6):
        pkt = BitchatPacket.create(
            message_type=MessageType.Message,
            sender_id=b"\xbb" * 8,
            recipient_id=None,
            payload=f"broadcast-{idx}".encode(),
            ttl=5,
            timestamp=5000 + idx,
        )
        r_dec = r_router.evaluate_incoming(
            pkt, ingress_source="10.0.0.2:41235", now=10.0
        )
        p_dec = p_router.evaluate_incoming(
            pkt, ingress_source="10.0.0.2:41235", now=10.0
        )
        assert r_dec.should_process_locally == p_dec.should_process_locally
        assert r_dec.drop_reason == p_dec.drop_reason
        if r_dec.packet_to_relay is not None and p_dec.packet_to_relay is not None:
            assert r_dec.packet_to_relay.ttl == p_dec.packet_to_relay.ttl

    assert r_router.get_next_hop(b"\xbb" * 8, now=10.5) == p_router.get_next_hop(
        b"\xbb" * 8, now=10.5
    )

    r_sf = StoreAndForwardQueue(
        max_total_packets=4, max_per_peer=2, packet_ttl_seconds=30.0
    )
    p_sf = PyStoreAndForwardQueue(
        max_total_packets=4, max_per_peer=2, packet_ttl_seconds=30.0
    )
    for idx in range(3):
        pkt = BitchatPacket.create(
            message_type=MessageType.Message,
            sender_id=my_id,
            recipient_id=b"\xcc" * 8,
            payload=f"queued-{idx}".encode(),
            timestamp=6000 + idx,
        )
        assert r_sf.enqueue("cccccccccccccccc", pkt, now=1.0 + idx) == p_sf.enqueue(
            "cccccccccccccccc", pkt, now=1.0 + idx
        )

    assert r_sf.total_packets == p_sf.total_packets == 2
    assert r_sf.dequeue_for_peer("cccccccccccccccc", now=5.0) == p_sf.dequeue_for_peer(
        "cccccccccccccccc", now=5.0
    )


def test_native_lan_ble_and_state_machine_primitives() -> None:
    """Verify Stage 4 LAN, Stage 5 BLE, and Section 7 state machine in Rust."""
    assert _core is not None

    # LAN discovery codec & interface selection
    raw_disc = _core.encode_discovery_packet_raw(
        "0102030405060708", 41235, "alice", "aabbccddeeff0011", 1
    )
    decoded = _core.decode_discovery_packet_raw(raw_disc)
    assert decoded == ("0102030405060708", 41235, "alice", "aabbccddeeff0011", 1)

    ifaces = [
        ("vEthernet (WSL)", "172.28.16.1", 20, True),
        ("Wi-Fi", "192.168.1.50", 24, True),
    ]
    assert _core.select_best_lan_ip(ifaces) == "192.168.1.50"
    bcasts = _core.compute_broadcast_targets(ifaces)
    assert "192.168.1.255" in bcasts
    assert "255.255.255.255" in bcasts

    assert (
        _core.arbitrate_simultaneous_connection("0000000000000001", "ffffffffffffffff")
        == "keep_outbound"
    )
    assert (
        _core.arbitrate_simultaneous_connection("ffffffffffffffff", "0000000000000001")
        == "keep_inbound"
    )

    # BLE advertisement codec & pre-ready notification buffering
    svc_bytes = b"\xaa" * 16
    pid_bytes = bytes.fromhex("0102030405060708")
    adv_payload = _core.encode_ble_manufacturer_payload(svc_bytes, pid_bytes)
    assert _core.decode_ble_manufacturer_payload(adv_payload, svc_bytes) == (
        True,
        "0102030405060708",
    )

    ble_engine = _core.NativeBleConnectionEngine("AA:BB:CC:DD:EE:FF", 185, 32)
    ble_engine.set_state("subscribing")
    assert ble_engine.on_notification(b"handshake_msg_1") is None
    assert ble_engine.buffered_notification_count() == 1
    drained = ble_engine.mark_ready_and_drain()
    assert drained == [b"handshake_msg_1"]
    assert ble_engine.state == "ready"

    # Deterministic 12-phase Handshake State Machine
    sm = _core.NativeHandshakeStateMachine("0102030405060708", "ble", 10.0, 3)
    assert sm.phase == "Discovered"
    for next_phase in (
        "Connecting",
        "TransportConnected",
        "GattReady",
        "HandshakeInitiated",
        "AwaitingMessage2",
        "AwaitingMessage3",
        "AuthenticatingIdentity",
        "Established",
    ):
        assert sm.transition_to(next_phase, f"enter {next_phase}", 11.0) == next_phase
    assert len(sm.history()) == 9

    # Native cipher state key inspection and zeroization
    test_k = b"\x42" * 32
    cs = _core.NativeNoiseCipherState(test_k, True)
    assert cs.has_key() is True
    assert cs.key == test_k
    cs.clear_key()
    assert cs.has_key() is False
    assert cs.key is None
