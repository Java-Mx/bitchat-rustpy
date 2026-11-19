"""Reproducible Phase 2.2 Performance, FFI Crossing & Memory Benchmark Suite.

Compares pure-Python reference implementations against native Rust
(`bitchat._bitchat_core`) and measures single-crossing `NativeProtocolEngine`
overhead, multi-peer throughput, and `tracemalloc` peak heap usage.
"""

from __future__ import annotations

import os
import platform
import time
import tracemalloc
from typing import Any

from bitchat._native import HAS_NATIVE_CORE, _core
from bitchat.crypto.identity import LocalIdentity
from bitchat.crypto.noise import NoiseRole
from bitchat.crypto.sessions import NoiseSession, PyNoiseSession
from bitchat.mesh.dedup import PacketDeduplicator, PyPacketDeduplicator
from bitchat.mesh.router import MeshRouter, PyMeshRouter
from bitchat.network.framing import PyStreamFramer, StreamFramer, encode_frame
from bitchat.protocol.constants import FLAG_HAS_RECIPIENT, MessageType
from bitchat.protocol.decoder import decode_packet, py_decode_packet
from bitchat.protocol.encoder import encode_packet, py_encode_packet
from bitchat.protocol.fragmentation import (
    fragment_encoded_packet,
    py_fragment_encoded_packet,
)
from bitchat.protocol.packet import BitchatPacket
from bitchat.protocol.reassembly import FragmentReassembler, PyFragmentReassembler


def _bench_us(fn: Any, iterations: int) -> float:
    t0 = time.perf_counter()
    for _ in range(iterations):
        fn()
    elapsed = time.perf_counter() - t0
    return (elapsed / iterations) * 1_000_000.0


def main() -> None:
    assert HAS_NATIVE_CORE and _core is not None, "Native Rust core must be loaded"

    print(
        f"Environment: {platform.system()} {platform.release()} "
        f"({platform.machine()}), Python {platform.python_version()}, "
        f"bitchat._bitchat_core v{_core.native_core_version()}"
    )
    print("-" * 78)
    print(f"{'Benchmark':<38} {'Python (us)':>12} {'Rust (us)':>12} {'Speedup':>10}")
    print("-" * 78)

    pkt = BitchatPacket.create(
        message_type=MessageType.Message,
        sender_id=b"\x11" * 8,
        recipient_id=b"\x22" * 8,
        payload=b"BitChat Phase 2.2 benchmark payload " * 4,
    )
    encoded_wire = encode_packet(pkt, add_padding=True)

    # 1. Packet Encode
    py_enc = _bench_us(lambda: py_encode_packet(pkt, True), 5000)
    rs_enc = _bench_us(lambda: encode_packet(pkt, True), 5000)
    print(f"{'Packet encode (padded 256B)':<38} {py_enc:>12.2f} {rs_enc:>12.2f} {py_enc / rs_enc:>9.2f}x")

    # 2. Packet Decode
    py_dec = _bench_us(lambda: py_decode_packet(encoded_wire), 5000)
    rs_dec = _bench_us(lambda: decode_packet(encoded_wire), 5000)
    print(f"{'Packet decode (padded 256B)':<38} {py_dec:>12.2f} {rs_dec:>12.2f} {py_dec / rs_dec:>9.2f}x")

    # 3. Noise XX 3-Message Handshake (full Initiator <-> Responder)
    alice = LocalIdentity.generate()
    bob = LocalIdentity.generate()

    def run_py_hs() -> None:
        sa = PyNoiseSession(alice, bob.peer_id_hex, role=NoiseRole.INITIATOR)
        sb = PyNoiseSession(bob, alice.peer_id_hex, role=NoiseRole.RESPONDER)
        m1 = sa.start_handshake()
        assert m1 is not None
        m2 = sb.process_handshake_message(m1)
        assert m2 is not None
        m3 = sa.process_handshake_message(m2)
        assert m3 is not None
        sb.process_handshake_message(m3)

    def run_rs_hs() -> None:
        sa = NoiseSession(alice, bob.peer_id_hex, role=NoiseRole.INITIATOR)
        sb = NoiseSession(bob, alice.peer_id_hex, role=NoiseRole.RESPONDER)
        m1 = sa.start_handshake()
        assert m1 is not None
        m2 = sb.process_handshake_message(m1)
        assert m2 is not None
        m3 = sa.process_handshake_message(m2)
        assert m3 is not None
        sb.process_handshake_message(m3)

    py_hs = _bench_us(run_py_hs, 200)
    rs_hs = _bench_us(run_rs_hs, 200)
    print(f"{'Noise XX full 3-msg handshake':<38} {py_hs:>12.2f} {rs_hs:>12.2f} {py_hs / rs_hs:>9.2f}x")

    # 4. Noise Transport Encrypt + Decrypt roundtrip
    py_sa = PyNoiseSession(alice, bob.peer_id_hex, role=NoiseRole.INITIATOR)
    py_sb = PyNoiseSession(bob, alice.peer_id_hex, role=NoiseRole.RESPONDER)
    pm1 = py_sa.start_handshake()
    assert pm1 is not None
    pm2 = py_sb.process_handshake_message(pm1)
    assert pm2 is not None
    pm3 = py_sa.process_handshake_message(pm2)
    assert pm3 is not None
    py_sb.process_handshake_message(pm3)

    rs_sa = NoiseSession(alice, bob.peer_id_hex, role=NoiseRole.INITIATOR)
    rs_sb = NoiseSession(bob, alice.peer_id_hex, role=NoiseRole.RESPONDER)
    rm1 = rs_sa.start_handshake()
    assert rm1 is not None
    rm2 = rs_sb.process_handshake_message(rm1)
    assert rm2 is not None
    rm3 = rs_sa.process_handshake_message(rm2)
    assert rm3 is not None
    rs_sb.process_handshake_message(rm3)

    msg_bytes = b"Encrypted direct message payload over ChaCha20-Poly1305" * 4
    py_encdec = _bench_us(lambda: py_sb.decrypt(py_sa.encrypt(msg_bytes)), 3000)
    rs_encdec = _bench_us(lambda: rs_sb.decrypt(rs_sa.encrypt(msg_bytes)), 3000)
    print(f"{'Noise transport enc+dec (220B)':<38} {py_encdec:>12.2f} {rs_encdec:>12.2f} {py_encdec / rs_encdec:>9.2f}x")

    # 5. Fragmentation + Reassembly (2KB packet)
    big_raw = os.urandom(2048)

    def run_py_frag() -> None:
        frags = py_fragment_encoded_packet(big_raw, b"\x01" * 8, MessageType.Message)
        reasm = PyFragmentReassembler()
        for f in frags:
            reasm.add_fragment_packet(f)

    def run_rs_frag() -> None:
        frags = fragment_encoded_packet(big_raw, b"\x01" * 8, MessageType.Message)
        reasm = FragmentReassembler()
        for f in frags:
            reasm.add_fragment_packet(f)

    py_fr = _bench_us(run_py_frag, 1000)
    rs_fr = _bench_us(run_rs_frag, 1000)
    print(f"{'Fragment + reassemble (2KB)':<38} {py_fr:>12.2f} {rs_fr:>12.2f} {py_fr / rs_fr:>9.2f}x")

    # 6. Deduplication
    py_dedup = PyPacketDeduplicator(max_entries=2000)
    rs_dedup = PacketDeduplicator(max_entries=2000)
    dedup_pkts = [
        BitchatPacket.create(
            MessageType.Message, b"\x02" * 8, f"dedup-{i}".encode(), timestamp=1000 + i
        )
        for i in range(1000)
    ]
    t0 = time.perf_counter()
    for i, dp in enumerate(dedup_pkts):
        py_dedup.check_and_record(dp, now=100.0 + i * 0.001)
    py_dd = (time.perf_counter() - t0) / len(dedup_pkts) * 1_000_000.0
    t0 = time.perf_counter()
    for i, dp in enumerate(dedup_pkts):
        rs_dedup.check_and_record(dp, now=100.0 + i * 0.001)
    rs_dd = (time.perf_counter() - t0) / len(dedup_pkts) * 1_000_000.0
    print(f"{'Deduplication (SHA-256 LRU)':<38} {py_dd:>12.2f} {rs_dd:>12.2f} {py_dd / rs_dd:>9.2f}x")

    # 7. Mesh Routing (single-pass Rust vs Python)
    py_mr = PyMeshRouter(local_peer_id=b"\xaa" * 8, rate_limit_per_peer=10000)
    rs_mr = MeshRouter(local_peer_id=b"\xaa" * 8, rate_limit_per_peer=10000)
    t0 = time.perf_counter()
    for i, dp in enumerate(dedup_pkts):
        py_mr.evaluate_incoming(dp, ingress_source="10.0.0.2:41235", now=200.0 + i * 0.001)
    py_rt = (time.perf_counter() - t0) / len(dedup_pkts) * 1_000_000.0
    t0 = time.perf_counter()
    for i, dp in enumerate(dedup_pkts):
        rs_mr.evaluate_incoming(dp, ingress_source="10.0.0.2:41235", now=200.0 + i * 0.001)
    rs_rt = (time.perf_counter() - t0) / len(dedup_pkts) * 1_000_000.0
    print(f"{'Mesh routing (1-pass Rust vs Py)':<38} {py_rt:>12.2f} {rs_rt:>12.2f} {py_rt / rs_rt:>9.2f}x")

    # 8. LAN TCP Stream Framing (20-frame burst)
    burst = b"".join(encode_frame(encoded_wire) for _ in range(20))
    py_sf = PyStreamFramer()
    rs_sf = StreamFramer()
    py_fr_us = _bench_us(lambda: py_sf.feed(burst), 2000)
    rs_fr_us = _bench_us(lambda: rs_sf.feed(burst), 2000)
    print(f"{'LAN TCP StreamFramer (20 frames)':<38} {py_fr_us:>12.2f} {rs_fr_us:>12.2f} {py_fr_us / rs_fr_us:>9.2f}x")

    # 9. Cohesive NativeProtocolEngine (1 FFI crossing: decode+route+decrypt) vs multi-step Python
    eng_a = _core.NativeProtocolEngine(alice.x25519_private, alice.peer_id_hex, "alice", "lan", 7, 10000, True)
    eng_b = _core.NativeProtocolEngine(bob.x25519_private, bob.peer_id_hex, "bob", "lan", 7, 10000, True)
    q = eng_a.prepare_direct_message(bob.peer_id_hex, "warmup", 1.0)
    for _ in range(6):
        nq: list[tuple[str, bytes]] = []
        for _, raw in q:
            r = eng_b.process_inbound_frame(raw, "10.0.0.1:41235", 1.1)
            for _, raw2 in r.outbound_packets:
                r2 = eng_a.process_inbound_frame(raw2, "10.0.0.2:41235", 1.2)
                nq.extend(r2.outbound_packets)
        q = nq
    assert eng_a.get_session_state(bob.peer_id_hex) == "established"
    assert eng_b.get_session_state(alice.peer_id_hex) == "established"

    n_frames = 1000
    rust_frames = [
        eng_a.prepare_direct_message(bob.peer_id_hex, f"msg-{i}", 10.0 + i * 0.001)[0][1]
        for i in range(n_frames)
    ]
    py_frames = [
        py_encode_packet(
            BitchatPacket(
                version=1,
                message_type=MessageType.NoiseEncrypted,
                ttl=7,
                timestamp=5000 + i,
                flags=FLAG_HAS_RECIPIENT,
                sender_id=alice.peer_id,
                recipient_id=bob.peer_id,
                payload=py_sa.encrypt(f"msg-{i}".encode()),
                signature=None,
            ),
            add_padding=True,
        )
        for i in range(n_frames)
    ]

    py_mr2 = PyMeshRouter(local_peer_id=bob.peer_id, rate_limit_per_peer=10000)
    tracemalloc.start()
    t0 = time.perf_counter()
    for i, wf in enumerate(py_frames):
        dp = py_decode_packet(wf)
        dec = py_mr2.evaluate_incoming(dp, ingress_source="10.0.0.1:41235", now=20.0 + i * 0.001)
        if dec.should_process_locally:
            _ = py_sb.decrypt(dp.payload).decode("utf-8")
    py_pipe_us = (time.perf_counter() - t0) / n_frames * 1_000_000.0
    _, py_peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    tracemalloc.start()
    t0 = time.perf_counter()
    for i, wf in enumerate(rust_frames):
        _res = eng_b.process_inbound_frame(wf, "10.0.0.1:41235", 20.0 + i * 0.001)
    rs_pipe_us = (time.perf_counter() - t0) / n_frames * 1_000_000.0
    _, rs_peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    print(f"{'Full inbound DM pipeline (1000 pkts)':<38} {py_pipe_us:>12.2f} {rs_pipe_us:>12.2f} {py_pipe_us / rs_pipe_us:>9.2f}x")
    print("-" * 78)
    print(f"Python inbound pipeline peak tracemalloc: {py_peak_mem / 1024:.1f} KiB")
    print(f"Rust 1-FFI inbound pipeline peak tracemalloc: {rs_peak_mem / 1024:.1f} KiB")
    print("FFI crossings per inbound NoiseEncrypted frame: 1 (NativeProtocolEngine) vs 4+ (piecewise)")


if __name__ == "__main__":
    main()
