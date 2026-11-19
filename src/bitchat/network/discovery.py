"""UDP multicast/broadcast peer discovery protocol with security bounds."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import socket
import time
from collections import defaultdict
from typing import TYPE_CHECKING, Any

from bitchat._native import HAS_NATIVE_CORE, _core
from bitchat.crypto.identity import generate_instance_id
from bitchat.network.adapter import get_broadcast_targets, get_local_ip, is_local_ip
from bitchat.network.models import DiscoveryPacket, LANDiscoveredPeer

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)

DEFAULT_DISCOVERY_PORT: int = 41234
DEFAULT_BROADCAST_INTERVAL: float = 3.0
MAX_DISCOVERY_RATE_PER_IP: int = 10  # Packets per second per sender IP


class _NativeIpRateLimiterView:
    """Dict-like view backed directly by Rust ``NativeIpRateLimiter``."""

    def __init__(self, native_limiter: Any) -> None:
        self._native = native_limiter

    def __len__(self) -> int:
        return int(self._native.tracked_ip_count())

    def __contains__(self, ip: object) -> bool:
        if not isinstance(ip, str):
            return False
        return bool(self._native.contains_ip(ip))

    def __getitem__(self, ip: str) -> list[float]:
        val = self._native.get_ip_timestamps(ip)
        if val is None:
            raise KeyError(ip)
        return list(val)

    def __setitem__(self, ip: str, timestamps: list[float]) -> None:
        self._native.set_ip_timestamps(ip, [float(t) for t in timestamps])

    def __delitem__(self, ip: str) -> None:
        if not self._native.remove_ip(ip):
            raise KeyError(ip)

    def clear(self) -> None:
        self._native.clear()


class LANDiscovery:
    """Manages UDP broadcast announcement broadcasting and peer discovery."""

    def __init__(
        self,
        local_peer_id: str,
        local_nickname: str,
        listening_port: int,
        ssid: str = "",
        discovery_port: int = DEFAULT_DISCOVERY_PORT,
        broadcast_interval: float = DEFAULT_BROADCAST_INTERVAL,
        on_peer_discovered: Callable[[LANDiscoveredPeer], None] | None = None,
        instance_id: str | None = None,
    ) -> None:
        self.local_peer_id = local_peer_id
        self.local_nickname = local_nickname
        self.listening_port = listening_port
        self.ssid = ssid
        self.discovery_port = discovery_port
        self.broadcast_interval = broadcast_interval
        self.on_peer_discovered = on_peer_discovered
        self.instance_id = instance_id or generate_instance_id()

        self._is_running: bool = False
        self._discovered_peers: dict[str, LANDiscoveredPeer] = {}
        self._previous_peer_ids: set[str] = set()
        self._native_rate_limiter: Any | None = (
            _core.NativeIpRateLimiter(MAX_DISCOVERY_RATE_PER_IP, 1.0, 4096)
            if HAS_NATIVE_CORE and hasattr(_core, "NativeIpRateLimiter")
            else None
        )
        self._rate_limiter: Any = (
            _NativeIpRateLimiterView(self._native_rate_limiter)
            if self._native_rate_limiter is not None
            else defaultdict(list)
        )
        self._broadcast_task: asyncio.Task[Any] | None = None
        self._listen_task: asyncio.Task[Any] | None = None
        self._listen_sock: socket.socket | None = None
        self._send_sock: socket.socket | None = None
        self.last_broadcast_at: float | None = None
        self.last_error: str | None = None

    @property
    def is_running(self) -> bool:
        return self._is_running

    @property
    def is_listening(self) -> bool:
        return self._is_running and self._listen_sock is not None

    @property
    def is_broadcasting(self) -> bool:
        return self._is_running and self._send_sock is not None

    @property
    def discovered_peers(self) -> dict[str, LANDiscoveredPeer]:
        return self._discovered_peers.copy()

    def update_identity(self, peer_id: str, nickname: str, ssid: str = "") -> None:
        """Update identity advertised in outgoing beacons."""
        if peer_id.lower() != self.local_peer_id.lower():
            if self.local_peer_id:
                self._previous_peer_ids.add(self.local_peer_id.lower())
            self._discovered_peers.clear()
        self.local_peer_id = peer_id
        self.local_nickname = nickname
        if ssid:
            self.ssid = "" if ssid.lower() == "unavailable" else ssid

    def update_listening_port(self, port: int) -> None:
        """Update TCP listening port announced to LAN peers."""
        self.listening_port = port

    async def start(self) -> None:
        """Initialize sockets and launch UDP listen and broadcast loops."""
        if self._is_running:
            return
        if not 0 <= self.discovery_port <= 65535:
            raise ValueError("UDP discovery port must be between 0 and 65535")
        self.last_error = None

        # 1. Setup send socket
        try:
            send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            send_sock.setblocking(False)
            self._send_sock = send_sock
        except Exception as e:
            self.last_error = f"UDP send socket failed: {e}"
            logger.warning("Failed creating UDP discovery send socket: %s", e)
            raise RuntimeError(self.last_error) from e

        # 2. Setup listen socket (required for real discovery)
        try:
            listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            listen_sock.setblocking(False)
            listen_sock.bind(("0.0.0.0", self.discovery_port))
            self.discovery_port = int(listen_sock.getsockname()[1])
            self._listen_sock = listen_sock
        except Exception as e:
            if self._send_sock:
                with contextlib.suppress(Exception):
                    self._send_sock.close()
                self._send_sock = None
            raise RuntimeError(
                f"Could not bind UDP discovery listen socket on port "
                f"{self.discovery_port}: {e}"
            ) from e

        self._is_running = True
        self._listen_task = asyncio.create_task(self._listen_loop())

        # 3. Launch periodic broadcaster
        self._broadcast_task = asyncio.create_task(self._broadcast_loop())
        # Immediate initial beacon
        await self.send_broadcast_now()

    def clear(self) -> None:
        """Clear discovered peer cache."""
        self._discovered_peers.clear()

    async def stop(self) -> None:
        """Stop discovery loops and release sockets."""
        self._is_running = False
        self._discovered_peers.clear()

        if self._broadcast_task:
            self._broadcast_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._broadcast_task
            self._broadcast_task = None

        if self._listen_task:
            self._listen_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._listen_task
            self._listen_task = None

        if self._listen_sock:
            with contextlib.suppress(Exception):
                self._listen_sock.close()
            self._listen_sock = None

        if self._send_sock:
            with contextlib.suppress(Exception):
                self._send_sock.close()
            self._send_sock = None

    async def send_broadcast_now(self) -> None:
        """Transmit an immediate discovery broadcast beacon."""
        if not self._is_running or not self._send_sock or self.listening_port <= 0:
            return

        try:
            beacon = DiscoveryPacket(
                peer_id=self.local_peer_id,
                nickname=self.local_nickname,
                port=self.listening_port,
                ssid=self.ssid,
                instance_id=self.instance_id,
            )
            raw = beacon.to_bytes()
            loop = asyncio.get_running_loop()
            targets = list(get_broadcast_targets())
            local_ip = get_local_ip()
            if local_ip and not local_ip.startswith("127."):
                parts = local_ip.split(".")
                if len(parts) == 4:
                    bcast24 = f"{parts[0]}.{parts[1]}.{parts[2]}.255"
                    if bcast24 not in targets:
                        targets.append(bcast24)
            if "255.255.255.255" not in targets:
                targets.append("255.255.255.255")
            sent = 0
            for target_ip in dict.fromkeys(targets):
                try:
                    await loop.sock_sendto(
                        self._send_sock, raw, (target_ip, self.discovery_port)
                    )
                    sent += 1
                except OSError as e:
                    self.last_error = f"UDP beacon send failed: {e}"
                    logger.debug("Failed sending UDP discovery to %s: %s", target_ip, e)
            if sent:
                self.last_broadcast_at = time.time()
                self.last_error = None
            elif self.last_error is None:
                self.last_error = "No UDP discovery broadcast target was available."
        except Exception as e:
            self.last_error = f"UDP discovery beacon failed: {e}"
            logger.debug("Failed sending discovery broadcast: %s", e)

    async def _broadcast_loop(self) -> None:
        while self._is_running:
            try:
                await asyncio.sleep(self.broadcast_interval)
                if not self._is_running:
                    break
                await self.send_broadcast_now()
                self.prune_stale_peers()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug("Error in discovery broadcast loop: %s", e)

    async def _listen_loop(self) -> None:
        loop = asyncio.get_running_loop()
        while self._is_running and self._listen_sock:
            try:
                data, addr = await loop.sock_recvfrom(self._listen_sock, 2048)
                self._process_incoming_packet(data, addr[0])
            except asyncio.CancelledError:
                break
            except Exception as e:
                if self._is_running:
                    logger.debug("Error in discovery listen loop: %s", e)
                    await asyncio.sleep(0.1)

    def _process_incoming_packet(
        self, data: bytes, sender_ip: str
    ) -> LANDiscoveredPeer | None:
        """Process incoming raw UDP bytes and register discovered peer if valid.

        The registry holds at most one record per canonical peer ID. Beacons
        repeat every few seconds, so a repeat beacon only refreshes the
        existing record; ``on_peer_discovered`` fires only when a peer is new
        or its identity metadata (peer ID, nickname, SSID, endpoint) changed.

        Distinct peer IDs are never merged, even when they share an IP address,
        nickname, or network. Beacons are unauthenticated hints: a peer is only
        trusted after the Noise handshake binds its peer ID to its static key.
        """
        sender_ip = sender_ip.strip()
        if ":" in sender_ip and sender_ip.count(":") == 1:
            sender_ip = sender_ip.split(":", 1)[0]

        if self._is_rate_limited(sender_ip):
            return None

        packet = DiscoveryPacket.from_bytes(data)
        if packet is None:
            return None

        if (
            packet.peer_id == self.local_peer_id.lower()
            or packet.peer_id in self._previous_peer_ids
            or (
                self.instance_id
                and packet.instance_id
                and packet.instance_id == self.instance_id
            )
            or (is_local_ip(sender_ip) and packet.port == self.listening_port)
        ):
            return None

        if sender_ip.startswith("127.") or sender_ip in ("localhost", "::1"):
            logger.debug("Ignoring loopback discovery packet from %s", sender_ip)
            return None

        now = time.time()
        endpoint = f"{sender_ip}:{packet.port}"
        ssid = "" if packet.ssid.lower() == "unavailable" else packet.ssid

        # Same canonical peer already registered under a different endpoint?
        prior_keys = [
            key
            for key, known in self._discovered_peers.items()
            if known.peer_id.lower() == packet.peer_id.lower() and key != endpoint
        ]
        if prior_keys:
            prior_key = prior_keys[0]
            prior = self._discovered_peers[prior_key]
            restarted_on_new_port = prior.ip == sender_ip
            prior_is_stale = (now - prior.last_seen) > 2 * self.broadcast_interval
            if restarted_on_new_port or prior_is_stale:
                # The peer moved (new listening port or host address): update
                # the existing record in place and re-key rather than keep a
                # stale duplicate of the same peer.
                for stale_key in prior_keys:
                    self._discovered_peers.pop(stale_key, None)
                prior.address = endpoint
                prior.ip = sender_ip
                prior.port = packet.port
                prior.peer_id = packet.peer_id
                prior.nickname = packet.nickname
                prior.ssid = ssid
                prior.last_seen = now
                self._discovered_peers[endpoint] = prior
                if self.on_peer_discovered:
                    try:
                        self.on_peer_discovered(prior)
                    except Exception as e:
                        logger.warning("Error in on_peer_discovered: %s", e)
                return prior
            # Multi-homed peer reachable via another address while the
            # registered endpoint is still fresh: keep one record.
            prior.last_seen = now
            if prior.nickname != packet.nickname or prior.ssid != ssid:
                prior.nickname = packet.nickname
                prior.ssid = ssid
                if self.on_peer_discovered:
                    try:
                        self.on_peer_discovered(prior)
                    except Exception as e:
                        logger.warning("Error in on_peer_discovered: %s", e)
            return prior

        existing = self._discovered_peers.get(endpoint)
        if existing is not None and existing.peer_id.lower() == packet.peer_id.lower():
            existing.last_seen = now
            if existing.nickname == packet.nickname and existing.ssid == ssid:
                return existing
            existing.nickname = packet.nickname
            existing.ssid = ssid
            if self.on_peer_discovered:
                try:
                    self.on_peer_discovered(existing)
                except Exception as e:
                    logger.warning("Error in on_peer_discovered: %s", e)
            return existing

        peer = LANDiscoveredPeer(
            address=endpoint,
            ip=sender_ip,
            port=packet.port,
            peer_id=packet.peer_id,
            nickname=packet.nickname,
            ssid=ssid,
            instance_id=packet.instance_id,
            last_seen=now,
        )
        self._discovered_peers[endpoint] = peer
        if self.on_peer_discovered:
            try:
                self.on_peer_discovered(peer)
            except Exception as e:
                logger.warning("Error in on_peer_discovered: %s", e)
        return peer

    def prune_rate_limiter(self, max_age: float = 1.0, now: float | None = None) -> int:
        """Prune empty or expired IP entries from rate limiter."""
        current_time = time.time() if now is None else now
        if self._native_rate_limiter is not None:
            return int(self._native_rate_limiter.prune(max_age, current_time))
        to_delete = [
            ip
            for ip, timestamps in self._rate_limiter.items()
            if not timestamps or (current_time - max(timestamps) > max_age)
        ]
        for ip in to_delete:
            self._rate_limiter.pop(ip, None)
        return len(to_delete)

    def _is_rate_limited(self, ip: str, now: float | None = None) -> bool:
        current_time = time.time() if now is None else now
        if self._native_rate_limiter is not None:
            return bool(self._native_rate_limiter.is_rate_limited(ip, current_time))
        if len(self._rate_limiter) > 256:
            self.prune_rate_limiter(now=current_time)

        timestamps = self._rate_limiter.get(ip)
        if timestamps is None:
            self._rate_limiter[ip] = [current_time]
            return False

        valid = [t for t in timestamps if current_time - t <= 1.0]
        if not valid:
            self._rate_limiter[ip] = [current_time]
            return False

        if len(valid) >= MAX_DISCOVERY_RATE_PER_IP:
            self._rate_limiter[ip] = valid
            return True

        valid.append(current_time)
        self._rate_limiter[ip] = valid
        return False

    def prune_stale_peers(
        self, max_age: float = 30.0, now: float | None = None
    ) -> list[str]:
        """Prune peers not heard from within max_age seconds and clean rate limiters."""
        current = time.time() if now is None else now
        self.prune_rate_limiter(now=current)
        stale = [
            addr
            for addr, peer in self._discovered_peers.items()
            if peer.is_expired(ttl=max_age, now=current)
        ]
        for addr in stale:
            self._discovered_peers.pop(addr, None)
        return stale
