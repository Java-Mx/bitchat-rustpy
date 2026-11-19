"""Store-and-Forward queue for disconnected or transient mesh peers."""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from bitchat._native import HAS_NATIVE_CORE, _core

if TYPE_CHECKING:
    from bitchat.protocol.packet import BitchatPacket

DEFAULT_MAX_TOTAL_PACKETS: int = 100
DEFAULT_MAX_PER_PEER: int = 20
DEFAULT_MAX_TOTAL_BYTES: int = 256 * 1024  # 256 KB
DEFAULT_PACKET_TTL_SECONDS: float = 300.0


def _normalize_peer_id(peer: str | bytes) -> str:
    """Normalize binary or hex peer ID into lowercase hex string."""
    if isinstance(peer, (bytes, bytearray)):
        return bytes(peer).hex().lower()
    return peer.strip().lower()


@dataclass(frozen=True)
class QueuedPacket:
    """Packet envelope within the Store-and-Forward queue."""

    packet: BitchatPacket
    enqueued_at: float
    byte_size: int


class PyStoreAndForwardQueue:
    """Pure-Python reference bounded, memory-capped Store-and-Forward buffer."""

    def __init__(
        self,
        max_total_packets: int = DEFAULT_MAX_TOTAL_PACKETS,
        max_per_peer: int = DEFAULT_MAX_PER_PEER,
        max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
        packet_ttl_seconds: float = DEFAULT_PACKET_TTL_SECONDS,
    ) -> None:
        self.max_total_packets = max_total_packets
        self.max_per_peer = max_per_peer
        self.max_total_bytes = max_total_bytes
        self.packet_ttl_seconds = packet_ttl_seconds

        self._queues: dict[str, deque[QueuedPacket]] = {}
        self._current_total_packets: int = 0
        self._current_total_bytes: int = 0

    @property
    def total_packets(self) -> int:
        return self._current_total_packets

    @property
    def total_bytes(self) -> int:
        return self._current_total_bytes

    @property
    def peer_count(self) -> int:
        return len(self._queues)

    def enqueue(
        self,
        target_peer_id: str | bytes,
        packet: BitchatPacket,
        now: float | None = None,
    ) -> bool:
        current_time = time.time() if now is None else now
        self.prune_expired(now=current_time)

        pkt_size = len(packet.payload) + 32
        if pkt_size > self.max_total_bytes:
            return False

        peer_key = _normalize_peer_id(target_peer_id)
        peer_queue = self._queues.setdefault(peer_key, deque())

        if len(peer_queue) >= self.max_per_peer:
            evicted = peer_queue.popleft()
            self._current_total_packets -= 1
            self._current_total_bytes -= evicted.byte_size

        while self._current_total_packets >= self.max_total_packets:
            self._evict_oldest()

        while (
            self._current_total_bytes + pkt_size > self.max_total_bytes
            and self._current_total_packets > 0
        ):
            self._evict_oldest()

        if self._current_total_bytes + pkt_size > self.max_total_bytes:
            return False

        queued = QueuedPacket(
            packet=packet,
            enqueued_at=current_time,
            byte_size=pkt_size,
        )
        peer_queue.append(queued)
        self._current_total_packets += 1
        self._current_total_bytes += pkt_size
        return True

    def _evict_oldest(self) -> None:
        oldest_peer: str | None = None
        oldest_time: float = float("inf")

        for peer_id, queue in self._queues.items():
            if queue and queue[0].enqueued_at < oldest_time:
                oldest_time = queue[0].enqueued_at
                oldest_peer = peer_id

        if oldest_peer is not None:
            queue = self._queues[oldest_peer]
            evicted = queue.popleft()
            self._current_total_packets -= 1
            self._current_total_bytes -= evicted.byte_size
            if not queue:
                del self._queues[oldest_peer]

    def dequeue_for_peer(
        self,
        target_peer_id: str | bytes,
        now: float | None = None,
    ) -> list[BitchatPacket]:
        current_time = time.time() if now is None else now
        peer_key = _normalize_peer_id(target_peer_id)
        queue = self._queues.pop(peer_key, None)
        if not queue:
            return []

        packets: list[BitchatPacket] = []
        for item in queue:
            self._current_total_packets -= 1
            self._current_total_bytes -= item.byte_size
            if current_time - item.enqueued_at <= self.packet_ttl_seconds:
                packets.append(item.packet)

        return packets

    def has_pending(self, target_peer_id: str | bytes) -> bool:
        peer_key = _normalize_peer_id(target_peer_id)
        return bool(self._queues.get(peer_key))

    def prune_expired(self, now: float | None = None) -> int:
        current_time = time.time() if now is None else now
        pruned_count = 0

        for peer_key in list(self._queues.keys()):
            queue = self._queues[peer_key]
            while queue and (
                current_time - queue[0].enqueued_at > self.packet_ttl_seconds
            ):
                expired = queue.popleft()
                self._current_total_packets -= 1
                self._current_total_bytes -= expired.byte_size
                pruned_count += 1
            if not queue:
                del self._queues[peer_key]

        return pruned_count

    def clear(self) -> None:
        self._queues.clear()
        self._current_total_packets = 0
        self._current_total_bytes = 0


class StoreAndForwardQueue:
    """Bounded Store-and-Forward buffer backed by Rust `_bitchat_core`."""

    def __init__(
        self,
        max_total_packets: int = DEFAULT_MAX_TOTAL_PACKETS,
        max_per_peer: int = DEFAULT_MAX_PER_PEER,
        max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
        packet_ttl_seconds: float = DEFAULT_PACKET_TTL_SECONDS,
    ) -> None:
        self.max_total_packets = max_total_packets
        self.max_per_peer = max_per_peer
        self.max_total_bytes = max_total_bytes
        self.packet_ttl_seconds = packet_ttl_seconds

        self._py = PyStoreAndForwardQueue(
            max_total_packets=max_total_packets,
            max_per_peer=max_per_peer,
            max_total_bytes=max_total_bytes,
            packet_ttl_seconds=packet_ttl_seconds,
        )
        self._native: Any | None = None
        if HAS_NATIVE_CORE and hasattr(_core, "NativeStoreAndForwardQueue"):
            self._native = _core.NativeStoreAndForwardQueue(
                max_total_packets,
                max_per_peer,
                max_total_bytes,
                packet_ttl_seconds,
            )

    @property
    def _queues(self) -> dict[str, deque[QueuedPacket]]:
        return self._py._queues

    @property
    def total_packets(self) -> int:
        """Return total number of currently stored packets."""
        if self._native is not None:
            return int(self._native.total_packets)
        return self._py.total_packets

    @property
    def total_bytes(self) -> int:
        """Return current memory footprint in bytes."""
        if self._native is not None:
            return int(self._native.total_bytes)
        return self._py.total_bytes

    @property
    def peer_count(self) -> int:
        """Return number of distinct peers with queued packets."""
        if self._native is not None:
            return int(self._native.peer_count)
        return self._py.peer_count

    def enqueue(
        self,
        target_peer_id: str | bytes,
        packet: BitchatPacket,
        now: float | None = None,
    ) -> bool:
        """Enqueue packet for delivery to target peer once connected."""
        current_time = time.time() if now is None else now
        peer_key = _normalize_peer_id(target_peer_id)
        self._py.enqueue(peer_key, packet, now=current_time)
        if self._native is not None:
            return bool(
                self._native.enqueue(
                    peer_key, packet, len(packet.payload), current_time
                )
            )
        return bool(self._py.has_pending(peer_key))

    def dequeue_for_peer(
        self,
        target_peer_id: str | bytes,
        now: float | None = None,
    ) -> list[BitchatPacket]:
        """Retrieve and remove all valid queued packets for target peer."""
        current_time = time.time() if now is None else now
        peer_key = _normalize_peer_id(target_peer_id)
        py_result = self._py.dequeue_for_peer(peer_key, now=current_time)
        if self._native is not None:
            return list(self._native.dequeue_for_peer(peer_key, current_time))
        return py_result

    def has_pending(self, target_peer_id: str | bytes) -> bool:
        """Return True if there are pending packets queued for peer."""
        peer_key = _normalize_peer_id(target_peer_id)
        if self._native is not None:
            return bool(self._native.has_pending(peer_key))
        return self._py.has_pending(peer_key)

    def prune_expired(self, now: float | None = None) -> int:
        """Remove packets that have exceeded packet_ttl_seconds."""
        current_time = time.time() if now is None else now
        py_pruned = self._py.prune_expired(now=current_time)
        if self._native is not None:
            return int(self._native.prune_expired(current_time))
        return py_pruned

    def clear(self) -> None:
        """Clear all stored packets and reset counters."""
        self._py.clear()
        if self._native is not None:
            self._native.clear()
