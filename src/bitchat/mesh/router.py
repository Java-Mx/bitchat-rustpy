"""BitChat mesh routing engine coordinating TTL, deduplication, and forwarding."""

from __future__ import annotations

import logging
import random
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from bitchat._native import HAS_NATIVE_CORE, _core
from bitchat.mesh.dedup import PacketDeduplicator
from bitchat.mesh.store_forward import StoreAndForwardQueue
from bitchat.protocol.constants import BROADCAST_RECIPIENT
from bitchat.protocol.packet import BitchatPacket

logger = logging.getLogger(__name__)

DEFAULT_MAX_RELAY_TTL: int = 10
DEFAULT_RELAY_JITTER_MIN: float = 0.010  # 10 ms
DEFAULT_RELAY_JITTER_MAX: float = 0.050  # 50 ms
DEFAULT_PEER_RATE_LIMIT: int = 50  # Max packets per second per peer
DEFAULT_MAX_ROUTES: int = 1000  # Max cached routing table entries
DEFAULT_ROUTE_TTL_SECONDS: float = 300.0  # 5 minutes


def _normalize_route_key(key: str | bytes) -> str:
    """Normalize binary or string peer ID/address into lowercase string."""
    if isinstance(key, (bytes, bytearray)):
        return bytes(key).hex().lower()
    return str(key).strip().lower()


@dataclass
class RouteEntry:
    """Mesh routing table entry mapping a destination to next hop and metric."""

    next_hop: str
    hop_count: int
    updated_at: float


@dataclass(frozen=True)
class RoutingDecision:
    """Actionable decision produced by MeshRouter for an incoming packet."""

    should_process_locally: bool
    packet_to_relay: BitchatPacket | None = None
    target_peer_id_hex: str | None = None
    exclude_ingress: str | None = None
    drop_reason: str | None = None


class PyMeshRouter:
    """Pure-Python reference mesh router retained for differential tests."""

    def __init__(
        self,
        local_peer_id: bytes,
        deduplicator: PacketDeduplicator | None = None,
        store_forward_queue: StoreAndForwardQueue | None = None,
        max_relay_ttl: int = DEFAULT_MAX_RELAY_TTL,
        relay_jitter_min: float = DEFAULT_RELAY_JITTER_MIN,
        relay_jitter_max: float = DEFAULT_RELAY_JITTER_MAX,
        rate_limit_per_peer: int = DEFAULT_PEER_RATE_LIMIT,
    ) -> None:
        self.local_peer_id = bytes(local_peer_id)
        self.deduplicator = deduplicator or PacketDeduplicator()
        self.store_forward_queue = store_forward_queue or StoreAndForwardQueue()
        self.max_relay_ttl = max_relay_ttl
        self.relay_jitter_min = relay_jitter_min
        self.relay_jitter_max = relay_jitter_max
        self.rate_limit_per_peer = rate_limit_per_peer
        self.max_routes = DEFAULT_MAX_ROUTES
        self.route_ttl_seconds = DEFAULT_ROUTE_TTL_SECONDS

        self._routes: dict[str, RouteEntry] = {}
        self._rate_limiter: dict[str, list[float]] = defaultdict(list)

    def prune_rate_limiter(self, max_age: float = 1.0, now: float | None = None) -> int:
        current_time = time.time() if now is None else now
        cutoff = current_time - max_age
        to_delete = [
            peer
            for peer, timestamps in self._rate_limiter.items()
            if not timestamps or timestamps[-1] < cutoff
        ]
        for peer in to_delete:
            self._rate_limiter.pop(peer, None)
        return len(to_delete)

    def is_rate_limited(self, sender_hex: str, now: float | None = None) -> bool:
        current_time = time.time() if now is None else now
        if len(self._rate_limiter) > 1000:
            self.prune_rate_limiter(now=current_time)

        timestamps = self._rate_limiter.get(sender_hex)
        if not timestamps:
            self._rate_limiter[sender_hex] = [current_time]
            return False

        cutoff = current_time - 1.0
        if timestamps[-1] < cutoff:
            timestamps.clear()
            timestamps.append(current_time)
            return False

        if timestamps[0] < cutoff:
            idx = 0
            n = len(timestamps)
            while idx < n and timestamps[idx] < cutoff:
                idx += 1
            del timestamps[:idx]

        if len(timestamps) >= self.rate_limit_per_peer:
            return True

        timestamps.append(current_time)
        return False

    @property
    def routes(self) -> dict[str, RouteEntry]:
        return self._routes.copy()

    def add_route(
        self,
        destination: str | bytes,
        next_hop: str | bytes,
        hop_count: int = 1,
        now: float | None = None,
    ) -> None:
        dest_key = _normalize_route_key(destination)
        next_hop_str = _normalize_route_key(next_hop)
        current_time = time.time() if now is None else now

        existing = self._routes.get(dest_key)
        if existing is not None:
            if (
                current_time - existing.updated_at <= self.route_ttl_seconds
                and existing.hop_count < hop_count
            ):
                return
            existing.next_hop = next_hop_str
            existing.hop_count = hop_count
            existing.updated_at = current_time
            return

        if len(self._routes) >= self.max_routes:
            self.prune_routes(now=current_time)
            if len(self._routes) >= self.max_routes:
                oldest_dest = min(
                    self._routes.keys(), key=lambda k: self._routes[k].updated_at
                )
                self._routes.pop(oldest_dest, None)

        self._routes[dest_key] = RouteEntry(
            next_hop=next_hop_str,
            hop_count=hop_count,
            updated_at=current_time,
        )

    def get_next_hop(
        self, destination: str | bytes, now: float | None = None
    ) -> str | None:
        dest_key = _normalize_route_key(destination)
        current_time = time.time() if now is None else now
        entry = self._routes.get(dest_key)
        if entry is None:
            return None
        if current_time - entry.updated_at > self.route_ttl_seconds:
            self._routes.pop(dest_key, None)
            return None
        return entry.next_hop

    def remove_route(self, destination: str | bytes) -> None:
        dest_key = _normalize_route_key(destination)
        self._routes.pop(dest_key, None)

    def prune_routes(
        self, max_age: float | None = None, now: float | None = None
    ) -> int:
        current_time = time.time() if now is None else now
        ttl = self.route_ttl_seconds if max_age is None else max_age
        expired = [
            k
            for k, entry in self._routes.items()
            if current_time - entry.updated_at > ttl
        ]
        for k in expired:
            self._routes.pop(k, None)
        return len(expired)

    def get_relay_jitter(self) -> float:
        return random.uniform(self.relay_jitter_min, self.relay_jitter_max)

    def evaluate_incoming(
        self,
        packet: BitchatPacket,
        ingress_source: str | None = None,
        now: float | None = None,
    ) -> RoutingDecision:
        current_time = time.time() if now is None else now

        if packet.sender_id == self.local_peer_id:
            return RoutingDecision(
                should_process_locally=False,
                drop_reason="Packet originated from local peer",
            )

        sender_hex = packet.sender_id.hex()

        if self.is_rate_limited(sender_hex, now=current_time):
            logger.warning(
                "Packet dropped: rate limit exceeded for peer %s", sender_hex
            )
            return RoutingDecision(
                should_process_locally=False,
                drop_reason=f"Rate limit exceeded for {sender_hex}",
            )

        if packet.ttl <= 0:
            return RoutingDecision(
                should_process_locally=False,
                drop_reason="Invalid or expired TTL (<= 0)",
            )

        if self.deduplicator.check_and_record(packet, now=current_time):
            return RoutingDecision(
                should_process_locally=False,
                drop_reason="Duplicate packet suppressed",
            )

        if ingress_source:
            hop_count = max(1, 7 - packet.ttl + 1) if packet.ttl <= 7 else 1
            self.add_route(
                destination=sender_hex,
                next_hop=ingress_source,
                hop_count=hop_count,
                now=current_time,
            )

        rcpt = packet.recipient_id
        is_broadcast = rcpt is None or rcpt == BROADCAST_RECIPIENT
        is_for_us = is_broadcast or (rcpt == self.local_peer_id)

        packet_to_relay: BitchatPacket | None = None
        target_peer_id_hex: str | None = None

        if not is_for_us and rcpt is not None:
            target_peer_id_hex = rcpt.hex()

        if packet.ttl > 1 and (is_broadcast or not is_for_us):
            clamped_ttl = (
                packet.ttl if packet.ttl <= self.max_relay_ttl else self.max_relay_ttl
            )
            decremented_ttl = clamped_ttl - 1
            if decremented_ttl >= 1:
                packet_to_relay = BitchatPacket._from_trusted(
                    version=packet.version,
                    message_type=packet.message_type,
                    ttl=decremented_ttl,
                    timestamp=packet.timestamp,
                    flags=packet.flags,
                    sender_id=packet.sender_id,
                    recipient_id=rcpt,
                    payload=packet.payload,
                    signature=packet.signature,
                )

        return RoutingDecision(
            should_process_locally=is_for_us,
            packet_to_relay=packet_to_relay,
            target_peer_id_hex=target_peer_id_hex,
            exclude_ingress=ingress_source,
        )


class _NativeRateLimiterView:
    """Dict-like view backed directly by Rust ``NativeMeshRouter`` rate limiter."""

    def __init__(self, native_router: Any) -> None:
        self._native = native_router

    def __len__(self) -> int:
        return int(self._native.rate_limiter_peer_count())

    def __contains__(self, peer: object) -> bool:
        if not isinstance(peer, str):
            return False
        return bool(self._native.rate_limiter_contains(peer))

    def __getitem__(self, peer: str) -> list[float]:
        val = self._native.rate_limiter_get_timestamps(peer)
        if val is None:
            raise KeyError(peer)
        return list(val)

    def __setitem__(self, peer: str, timestamps: list[float]) -> None:
        self._native.rate_limiter_set_timestamps(peer, [float(ts) for ts in timestamps])

    def __delitem__(self, peer: str) -> None:
        if not self._native.rate_limiter_remove_peer(peer):
            raise KeyError(peer)

    def clear(self) -> None:
        self._native.clear_rate_limiter()


class _NativeRouterDedupAdapter(PacketDeduplicator):
    """PacketDeduplicator view backed directly by ``NativeMeshRouter``'s Rust dedup."""

    def __init__(
        self,
        native_router: Any,
        *,
        max_entries: int = 2000,
        entry_ttl_seconds: float = 300.0,
    ) -> None:
        self.max_entries = max_entries
        self.entry_ttl_seconds = entry_ttl_seconds
        self._native_router = native_router
        self._native = None
        self._py = None

    def is_duplicate(self, packet: BitchatPacket, now: float | None = None) -> bool:
        current_time = time.time() if now is None else now
        return bool(
            self._native_router.dedup_is_duplicate_raw(
                packet.sender_id,
                packet.timestamp,
                int(packet.message_type),
                packet.recipient_id,
                packet.payload,
                current_time,
            )
        )

    def record(self, packet: BitchatPacket, now: float | None = None) -> None:
        current_time = time.time() if now is None else now
        self._native_router.dedup_record_raw(
            packet.sender_id,
            packet.timestamp,
            int(packet.message_type),
            packet.recipient_id,
            packet.payload,
            current_time,
        )

    def check_and_record(self, packet: BitchatPacket, now: float | None = None) -> bool:
        current_time = time.time() if now is None else now
        if self.is_duplicate(packet, now=current_time):
            return True
        self.record(packet, now=current_time)
        return False

    def prune_expired(self, now: float | None = None) -> int:
        current_time = time.time() if now is None else now
        return int(self._native_router.dedup_prune_expired(current_time))

    def clear(self) -> None:
        self._native_router.dedup_clear()

    def __len__(self) -> int:
        return int(self._native_router.dedup_size())


class MeshRouter:
    """Authoritative mesh router backed by Rust ``NativeMeshRouter`` (single-pass)."""

    def __init__(
        self,
        local_peer_id: bytes,
        deduplicator: PacketDeduplicator | None = None,
        store_forward_queue: StoreAndForwardQueue | None = None,
        max_relay_ttl: int = DEFAULT_MAX_RELAY_TTL,
        relay_jitter_min: float = DEFAULT_RELAY_JITTER_MIN,
        relay_jitter_max: float = DEFAULT_RELAY_JITTER_MAX,
        rate_limit_per_peer: int = DEFAULT_PEER_RATE_LIMIT,
    ) -> None:
        self._local_peer_id = bytes(local_peer_id)
        self.store_forward_queue = store_forward_queue or StoreAndForwardQueue()
        self._max_relay_ttl = max_relay_ttl
        self.relay_jitter_min = relay_jitter_min
        self.relay_jitter_max = relay_jitter_max
        self._rate_limit_per_peer = rate_limit_per_peer
        self._max_routes = DEFAULT_MAX_ROUTES
        self._route_ttl_seconds = DEFAULT_ROUTE_TTL_SECONDS
        self._uses_external_deduplicator = deduplicator is not None

        self._native: Any | None = None
        self._py: PyMeshRouter | None = None
        if HAS_NATIVE_CORE and hasattr(_core, "NativeMeshRouter"):
            dedup_max = deduplicator.max_entries if deduplicator is not None else 2000
            dedup_ttl = (
                deduplicator.entry_ttl_seconds if deduplicator is not None else 300.0
            )
            self._native = _core.NativeMeshRouter(
                self._local_peer_id,
                max_relay_ttl,
                rate_limit_per_peer,
                self._max_routes,
                self._route_ttl_seconds,
                dedup_max,
                dedup_ttl,
            )
            self._rate_limiter_view: Any = _NativeRateLimiterView(self._native)
            self.deduplicator: PacketDeduplicator = (
                deduplicator
                if deduplicator is not None
                else _NativeRouterDedupAdapter(
                    self._native,
                    max_entries=dedup_max,
                    entry_ttl_seconds=dedup_ttl,
                )
            )
        else:
            self.deduplicator = deduplicator or PacketDeduplicator()
            self._py = PyMeshRouter(
                local_peer_id=self._local_peer_id,
                deduplicator=self.deduplicator,
                store_forward_queue=self.store_forward_queue,
                max_relay_ttl=max_relay_ttl,
                relay_jitter_min=relay_jitter_min,
                relay_jitter_max=relay_jitter_max,
                rate_limit_per_peer=rate_limit_per_peer,
            )
            self._rate_limiter_view = self._py._rate_limiter

    @property
    def local_peer_id(self) -> bytes:
        return self._local_peer_id

    @local_peer_id.setter
    def local_peer_id(self, val: bytes) -> None:
        self._local_peer_id = bytes(val)
        if self._native is not None:
            self._native.local_peer_id = self._local_peer_id
        elif self._py is not None:
            self._py.local_peer_id = self._local_peer_id

    @property
    def max_relay_ttl(self) -> int:
        return self._max_relay_ttl

    @max_relay_ttl.setter
    def max_relay_ttl(self, val: int) -> None:
        self._max_relay_ttl = int(val)
        if self._native is not None:
            self._native.max_relay_ttl = int(val)
        elif self._py is not None:
            self._py.max_relay_ttl = int(val)

    @property
    def rate_limit_per_peer(self) -> int:
        return self._rate_limit_per_peer

    @rate_limit_per_peer.setter
    def rate_limit_per_peer(self, val: int) -> None:
        self._rate_limit_per_peer = int(val)
        if self._native is not None:
            self._native.rate_limit_per_peer = int(val)
        elif self._py is not None:
            self._py.rate_limit_per_peer = int(val)

    @property
    def max_routes(self) -> int:
        return self._max_routes

    @max_routes.setter
    def max_routes(self, val: int) -> None:
        self._max_routes = int(val)
        if self._native is not None:
            self._native.max_routes = int(val)
        elif self._py is not None:
            self._py.max_routes = int(val)

    @property
    def route_ttl_seconds(self) -> float:
        return self._route_ttl_seconds

    @route_ttl_seconds.setter
    def route_ttl_seconds(self, val: float) -> None:
        self._route_ttl_seconds = float(val)
        if self._native is not None:
            self._native.route_ttl_seconds = float(val)
        elif self._py is not None:
            self._py.route_ttl_seconds = float(val)

    @property
    def _rate_limiter(self) -> Any:
        return self._rate_limiter_view

    def prune_rate_limiter(self, max_age: float = 1.0, now: float | None = None) -> int:
        """Prune empty or expired peer entries from rate limiter."""
        current_time = time.time() if now is None else now
        if self._native is not None:
            return int(self._native.prune_rate_limiter(max_age, current_time))
        assert self._py is not None
        return self._py.prune_rate_limiter(max_age=max_age, now=current_time)

    def is_rate_limited(self, sender_hex: str, now: float | None = None) -> bool:
        """Check if sender has exceeded allowed packet rate within the last second."""
        current_time = time.time() if now is None else now
        if self._native is not None:
            return bool(self._native.is_rate_limited(sender_hex, current_time))
        assert self._py is not None
        return self._py.is_rate_limited(sender_hex, now=current_time)

    @property
    def routes(self) -> dict[str, RouteEntry]:
        """Return shallow copy of current routing table."""
        if self._native is not None:
            return {
                dest: RouteEntry(
                    next_hop=next_hop, hop_count=hop_count, updated_at=updated_at
                )
                for dest, next_hop, hop_count, updated_at in self._native.get_routes()
            }
        assert self._py is not None
        return self._py.routes

    @property
    def _routes(self) -> dict[str, RouteEntry]:
        return self.routes

    def add_route(
        self,
        destination: str | bytes,
        next_hop: str | bytes,
        hop_count: int = 1,
        now: float | None = None,
    ) -> None:
        """Record or update a route to destination via next_hop."""
        current_time = time.time() if now is None else now
        dest_key = _normalize_route_key(destination)
        next_hop_str = _normalize_route_key(next_hop)
        if self._native is not None:
            self._native.add_route(dest_key, next_hop_str, hop_count, current_time)
            return
        assert self._py is not None
        self._py.add_route(
            dest_key, next_hop_str, hop_count=hop_count, now=current_time
        )

    def get_next_hop(
        self, destination: str | bytes, now: float | None = None
    ) -> str | None:
        """Resolve the next hop address/peer_id for a given destination."""
        current_time = time.time() if now is None else now
        dest_key = _normalize_route_key(destination)
        if self._native is not None:
            return self._native.get_next_hop(dest_key, current_time)
        assert self._py is not None
        return self._py.get_next_hop(dest_key, now=current_time)

    def remove_route(self, destination: str | bytes) -> None:
        """Remove a route from the routing table."""
        dest_key = _normalize_route_key(destination)
        if self._native is not None:
            self._native.remove_route(dest_key)
            return
        assert self._py is not None
        self._py.remove_route(dest_key)

    def prune_routes(
        self, max_age: float | None = None, now: float | None = None
    ) -> int:
        """Prune expired routes older than max_age (defaults to route_ttl_seconds)."""
        current_time = time.time() if now is None else now
        if self._native is not None:
            return int(self._native.prune_routes(max_age, current_time))
        assert self._py is not None
        return self._py.prune_routes(max_age=max_age, now=current_time)

    def get_relay_jitter(self) -> float:
        """Return random jitter delay in seconds to mitigate radio collision."""
        return random.uniform(self.relay_jitter_min, self.relay_jitter_max)

    def evaluate_incoming(
        self,
        packet: BitchatPacket,
        ingress_source: str | None = None,
        now: float | None = None,
    ) -> RoutingDecision:
        """Evaluate an incoming packet in a single native Rust pass."""
        current_time = time.time() if now is None else now

        if self._native is not None:
            is_dup_override: bool | None = None
            if self._uses_external_deduplicator:
                is_not_self = packet.sender_id != self._local_peer_id
                if is_not_self and packet.ttl > 0:
                    is_dup_override = self.deduplicator.check_and_record(
                        packet, now=current_time
                    )
            (
                should_process_locally,
                relay_ttl,
                target_peer_id_hex,
                exclude_ingress,
                drop_reason,
            ) = self._native.evaluate_incoming_raw(
                packet.sender_id,
                packet.recipient_id,
                int(packet.message_type),
                packet.ttl,
                packet.timestamp,
                packet.payload,
                ingress_source,
                current_time,
                is_dup_override,
                None,
            )
            if drop_reason is not None and drop_reason.startswith(
                "Rate limit exceeded"
            ):
                logger.warning(
                    "Packet dropped: rate limit exceeded for peer %s",
                    packet.sender_id.hex(),
                )
            packet_to_relay: BitchatPacket | None = None
            if relay_ttl is not None:
                packet_to_relay = BitchatPacket._from_trusted(
                    version=packet.version,
                    message_type=packet.message_type,
                    ttl=int(relay_ttl),
                    timestamp=packet.timestamp,
                    flags=packet.flags,
                    sender_id=packet.sender_id,
                    recipient_id=packet.recipient_id,
                    payload=packet.payload,
                    signature=packet.signature,
                )
            return RoutingDecision(
                should_process_locally=bool(should_process_locally),
                packet_to_relay=packet_to_relay,
                target_peer_id_hex=target_peer_id_hex,
                exclude_ingress=exclude_ingress,
                drop_reason=drop_reason,
            )

        assert self._py is not None
        return self._py.evaluate_incoming(
            packet, ingress_source=ingress_source, now=current_time
        )
