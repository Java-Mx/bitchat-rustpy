//! Native Rust Mesh Engine for BitChat (Stage 3).
//!
//! Implements:
//! - Packet ID computation (`compute_packet_id_raw`)
//! - Bounded LRU + TTL packet deduplication (`NativePacketDeduplicator`)
//! - Per-peer sliding window rate limiting (`NativePeerRateLimiter`)
//! - Mesh routing table, hop-count decrementing, TTL clamping, and single-pass
//!   packet evaluation (`NativeMeshRouter`)
//! - Bounded Store-and-Forward queue (`NativeStoreAndForwardQueue`)
//! - Delivery acknowledgment and retry scheduler (`NativeAckTracker`)

use std::collections::{HashMap, VecDeque};

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use sha2::{Digest, Sha256};

use crate::protocol::hex_encode_lower;

pub const BROADCAST_RECIPIENT: [u8; 8] = [0xFF; 8];
pub const DEFAULT_MAX_ROUTES: usize = 1000;
pub const DEFAULT_ROUTE_TTL_SECONDS: f64 = 300.0;

pub fn compute_packet_id_bytes(
    sender_id: &[u8],
    timestamp: u64,
    message_type: u8,
    recipient_id: Option<&[u8]>,
    payload: &[u8],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(sender_id);
    hasher.update(timestamp.to_be_bytes());
    hasher.update([message_type]);
    if let Some(rcpt) = recipient_id {
        hasher.update(rcpt);
    }
    hasher.update(payload);
    let digest = hasher.finalize();
    hex_encode_lower(&digest[..16])
}

#[pyfunction]
#[pyo3(signature = (sender_id, timestamp, message_type, recipient_id, payload))]
pub fn compute_packet_id_raw(
    sender_id: &[u8],
    timestamp: u64,
    message_type: u8,
    recipient_id: Option<&[u8]>,
    payload: &[u8],
) -> String {
    compute_packet_id_bytes(sender_id, timestamp, message_type, recipient_id, payload)
}

// ---------------------------------------------------------------------------
// NativePacketDeduplicator
// ---------------------------------------------------------------------------

#[pyclass(module = "bitchat._bitchat_core")]
pub struct NativePacketDeduplicator {
    max_entries: usize,
    entry_ttl_seconds: f64,
    entries: HashMap<String, (f64, u64)>,
    order: VecDeque<(String, u64)>,
    next_gen: u64,
}

impl NativePacketDeduplicator {
    fn clean_front(&mut self) {
        while let Some((front_key, front_gen)) = self.order.front() {
            match self.entries.get(front_key) {
                Some(&(_, current_gen)) if current_gen == *front_gen => break,
                _ => {
                    self.order.pop_front();
                }
            }
        }
    }

    fn compact_order_if_needed(&mut self) {
        if self.order.len() > self.entries.len().saturating_mul(2).saturating_add(64) {
            let entries = &self.entries;
            self.order.retain(|(k, g)| {
                entries
                    .get(k)
                    .map(|&(_, cur_g)| cur_g == *g)
                    .unwrap_or(false)
            });
        }
    }

    fn evict_oldest(&mut self) {
        self.clean_front();
        if let Some((oldest_key, _)) = self.order.pop_front() {
            self.entries.remove(&oldest_key);
        }
    }
}

#[pymethods]
impl NativePacketDeduplicator {
    #[new]
    #[pyo3(signature = (max_entries=2000, entry_ttl_seconds=300.0))]
    pub fn new(max_entries: isize, entry_ttl_seconds: f64) -> PyResult<Self> {
        if max_entries <= 0 {
            return Err(PyValueError::new_err(
                "max_entries must be greater than zero",
            ));
        }
        if entry_ttl_seconds <= 0.0 {
            return Err(PyValueError::new_err(
                "entry_ttl_seconds must be greater than zero",
            ));
        }
        let cap = max_entries as usize;
        Ok(Self {
            max_entries: cap,
            entry_ttl_seconds,
            entries: HashMap::with_capacity(cap.min(2048)),
            order: VecDeque::with_capacity(cap.min(2048)),
            next_gen: 0,
        })
    }

    #[getter]
    pub fn max_entries(&self) -> usize {
        self.max_entries
    }

    #[getter]
    pub fn entry_ttl_seconds(&self) -> f64 {
        self.entry_ttl_seconds
    }

    pub fn is_id_duplicate(&mut self, packet_id: &str, now: f64) -> bool {
        if let Some(&(recorded_time, _)) = self.entries.get(packet_id) {
            if now - recorded_time > self.entry_ttl_seconds {
                self.entries.remove(packet_id);
                self.compact_order_if_needed();
                return false;
            }
            true
        } else {
            false
        }
    }

    pub fn record_id(&mut self, packet_id: String, now: f64) {
        if !self.entries.contains_key(&packet_id) && self.entries.len() >= self.max_entries {
            self.evict_oldest();
        }
        self.next_gen = self.next_gen.wrapping_add(1);
        let gen = self.next_gen;
        self.entries.insert(packet_id.clone(), (now, gen));
        self.order.push_back((packet_id, gen));
        self.compact_order_if_needed();
    }

    pub fn check_and_record_id(&mut self, packet_id: String, now: f64) -> bool {
        if self.is_id_duplicate(&packet_id, now) {
            return true;
        }
        self.record_id(packet_id, now);
        false
    }

    #[pyo3(signature = (sender_id, timestamp, message_type, recipient_id, payload, now))]
    pub fn check_and_record_raw(
        &mut self,
        sender_id: &[u8],
        timestamp: u64,
        message_type: u8,
        recipient_id: Option<&[u8]>,
        payload: &[u8],
        now: f64,
    ) -> bool {
        let packet_id =
            compute_packet_id_bytes(sender_id, timestamp, message_type, recipient_id, payload);
        self.check_and_record_id(packet_id, now)
    }

    pub fn prune_expired(&mut self, now: f64) -> usize {
        let mut pruned_count = 0usize;
        loop {
            self.clean_front();
            let should_evict = match self.order.front() {
                Some((front_key, _)) => match self.entries.get(front_key) {
                    Some(&(recorded_time, _)) => now - recorded_time > self.entry_ttl_seconds,
                    None => false,
                },
                None => false,
            };
            if should_evict {
                if let Some((key, _)) = self.order.pop_front() {
                    self.entries.remove(&key);
                    pruned_count += 1;
                }
            } else {
                break;
            }
        }
        self.compact_order_if_needed();
        pruned_count
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
    }

    pub fn size(&self) -> usize {
        self.entries.len()
    }
}

// ---------------------------------------------------------------------------
// NativePeerRateLimiter
// ---------------------------------------------------------------------------

#[pyclass(module = "bitchat._bitchat_core")]
pub struct NativePeerRateLimiter {
    rate_limit_per_peer: usize,
    buckets: HashMap<String, VecDeque<f64>>,
}

#[pymethods]
impl NativePeerRateLimiter {
    #[new]
    #[pyo3(signature = (rate_limit_per_peer=50))]
    pub fn new(rate_limit_per_peer: usize) -> Self {
        Self {
            rate_limit_per_peer,
            buckets: HashMap::new(),
        }
    }

    #[getter]
    pub fn rate_limit_per_peer(&self) -> usize {
        self.rate_limit_per_peer
    }

    #[setter]
    pub fn set_rate_limit_per_peer(&mut self, value: usize) {
        self.rate_limit_per_peer = value;
    }

    pub fn prune(&mut self, max_age: f64, now: f64) -> usize {
        let before = self.buckets.len();
        self.buckets
            .retain(|_, timestamps| match timestamps.back() {
                Some(&latest) => now - latest <= max_age,
                None => false,
            });
        before.saturating_sub(self.buckets.len())
    }

    pub fn is_rate_limited(&mut self, sender_hex: &str, now: f64) -> bool {
        if self.buckets.len() > 1000 {
            self.prune(1.0, now);
        }

        let queue = self
            .buckets
            .entry(sender_hex.to_string())
            .or_insert_with(|| VecDeque::with_capacity(self.rate_limit_per_peer.min(64)));

        while let Some(&oldest) = queue.front() {
            if now - oldest > 1.0 {
                queue.pop_front();
            } else {
                break;
            }
        }

        if queue.len() >= self.rate_limit_per_peer {
            return true;
        }

        queue.push_back(now);
        false
    }

    pub fn peer_count(&self) -> usize {
        self.buckets.len()
    }

    pub fn clear(&mut self) {
        self.buckets.clear();
    }
}

// ---------------------------------------------------------------------------
// NativeMeshRouter (Stage 3)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct NativeRouteEntry {
    pub next_hop: String,
    pub hop_count: i64,
    pub updated_at: f64,
}

#[pyclass(module = "bitchat._bitchat_core")]
pub struct NativeMeshRouter {
    local_peer_id: Vec<u8>,
    max_relay_ttl: i64,
    max_routes: usize,
    route_ttl_seconds: f64,
    routes: HashMap<String, NativeRouteEntry>,
    rate_limiter: NativePeerRateLimiter,
    deduplicator: NativePacketDeduplicator,
}

impl NativeMeshRouter {
    fn normalize_key(key: &str) -> String {
        key.trim().to_ascii_lowercase()
    }
}

#[pymethods]
impl NativeMeshRouter {
    #[new]
    #[pyo3(signature = (
        local_peer_id,
        max_relay_ttl=10,
        rate_limit_per_peer=50,
        max_routes=1000,
        route_ttl_seconds=300.0,
        dedup_max_entries=2000,
        dedup_ttl_seconds=300.0
    ))]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        local_peer_id: &[u8],
        max_relay_ttl: i64,
        rate_limit_per_peer: usize,
        max_routes: usize,
        route_ttl_seconds: f64,
        dedup_max_entries: isize,
        dedup_ttl_seconds: f64,
    ) -> PyResult<Self> {
        let deduplicator = NativePacketDeduplicator::new(dedup_max_entries, dedup_ttl_seconds)?;
        Ok(Self {
            local_peer_id: local_peer_id.to_vec(),
            max_relay_ttl,
            max_routes,
            route_ttl_seconds,
            routes: HashMap::new(),
            rate_limiter: NativePeerRateLimiter::new(rate_limit_per_peer),
            deduplicator,
        })
    }

    #[getter]
    pub fn local_peer_id(&self) -> Vec<u8> {
        self.local_peer_id.clone()
    }

    #[setter]
    pub fn set_local_peer_id(&mut self, peer_id: &[u8]) {
        self.local_peer_id = peer_id.to_vec();
    }

    #[getter]
    pub fn max_relay_ttl(&self) -> i64 {
        self.max_relay_ttl
    }

    #[setter]
    pub fn set_max_relay_ttl(&mut self, val: i64) {
        self.max_relay_ttl = val;
    }

    #[getter]
    pub fn max_routes(&self) -> usize {
        self.max_routes
    }

    #[setter]
    pub fn set_max_routes(&mut self, val: usize) {
        self.max_routes = val;
    }

    #[getter]
    pub fn route_ttl_seconds(&self) -> f64 {
        self.route_ttl_seconds
    }

    #[setter]
    pub fn set_route_ttl_seconds(&mut self, val: f64) {
        self.route_ttl_seconds = val;
    }

    #[getter]
    pub fn rate_limit_per_peer(&self) -> usize {
        self.rate_limiter.rate_limit_per_peer()
    }

    #[setter]
    pub fn set_rate_limit_per_peer(&mut self, val: usize) {
        self.rate_limiter.set_rate_limit_per_peer(val);
    }

    pub fn is_rate_limited(&mut self, sender_hex: &str, now: f64) -> bool {
        self.rate_limiter.is_rate_limited(sender_hex, now)
    }

    pub fn prune_rate_limiter(&mut self, max_age: f64, now: f64) -> usize {
        self.rate_limiter.prune(max_age, now)
    }

    pub fn rate_limiter_peer_count(&self) -> usize {
        self.rate_limiter.peer_count()
    }

    pub fn clear_rate_limiter(&mut self) {
        self.rate_limiter.clear();
    }

    #[pyo3(signature = (destination, next_hop, hop_count=1, now=0.0))]
    pub fn add_route(&mut self, destination: &str, next_hop: &str, hop_count: i64, now: f64) {
        let dest_key = Self::normalize_key(destination);
        let next_hop_str = Self::normalize_key(next_hop);

        if let Some(existing) = self.routes.get_mut(&dest_key) {
            if now - existing.updated_at <= self.route_ttl_seconds && existing.hop_count < hop_count
            {
                return;
            }
            existing.next_hop = next_hop_str;
            existing.hop_count = hop_count;
            existing.updated_at = now;
            return;
        }

        if self.routes.len() >= self.max_routes {
            self.prune_routes(None, now);
            if self.routes.len() >= self.max_routes {
                if let Some(oldest_key) = self
                    .routes
                    .iter()
                    .min_by(|a, b| {
                        a.1.updated_at
                            .partial_cmp(&b.1.updated_at)
                            .unwrap_or(std::cmp::Ordering::Equal)
                    })
                    .map(|(k, _)| k.clone())
                {
                    self.routes.remove(&oldest_key);
                }
            }
        }

        self.routes.insert(
            dest_key,
            NativeRouteEntry {
                next_hop: next_hop_str,
                hop_count,
                updated_at: now,
            },
        );
    }

    pub fn get_next_hop(&mut self, destination: &str, now: f64) -> Option<String> {
        let dest_key = Self::normalize_key(destination);
        let entry = self.routes.get(&dest_key)?;
        if now - entry.updated_at > self.route_ttl_seconds {
            self.routes.remove(&dest_key);
            return None;
        }
        Some(entry.next_hop.clone())
    }

    pub fn remove_route(&mut self, destination: &str) {
        let dest_key = Self::normalize_key(destination);
        self.routes.remove(&dest_key);
    }

    #[pyo3(signature = (max_age=None, now=0.0))]
    pub fn prune_routes(&mut self, max_age: Option<f64>, now: f64) -> usize {
        let ttl = max_age.unwrap_or(self.route_ttl_seconds);
        let before = self.routes.len();
        self.routes.retain(|_, entry| now - entry.updated_at <= ttl);
        before.saturating_sub(self.routes.len())
    }

    pub fn get_routes(&self) -> Vec<(String, String, i64, f64)> {
        self.routes
            .iter()
            .map(|(k, v)| (k.clone(), v.next_hop.clone(), v.hop_count, v.updated_at))
            .collect()
    }

    pub fn clear_routes(&mut self) {
        self.routes.clear();
    }

    /// Evaluate an incoming packet in a single native Rust pass.
    ///
    /// Returns `(should_process_locally, relay_ttl, target_peer_id_hex, exclude_ingress, drop_reason)`.
    #[pyo3(signature = (
        sender_id,
        recipient_id,
        message_type,
        ttl,
        timestamp,
        payload,
        ingress_source,
        now,
        is_duplicate_override=None,
        is_rate_limited_override=None
    ))]
    #[allow(clippy::too_many_arguments, clippy::type_complexity)]
    pub fn evaluate_incoming_raw(
        &mut self,
        sender_id: &[u8],
        recipient_id: Option<&[u8]>,
        message_type: u8,
        ttl: i64,
        timestamp: u64,
        payload: &[u8],
        ingress_source: Option<&str>,
        now: f64,
        is_duplicate_override: Option<bool>,
        is_rate_limited_override: Option<bool>,
    ) -> (
        bool,
        Option<i64>,
        Option<String>,
        Option<String>,
        Option<String>,
    ) {
        // 1. Loop prevention: ignore packets originated by local peer
        if sender_id == self.local_peer_id.as_slice() {
            return (
                false,
                None,
                None,
                None,
                Some("Packet originated from local peer".to_string()),
            );
        }

        let sender_hex = hex_encode_lower(sender_id);

        // 2. Rate limiting per peer
        let rate_limited = match is_rate_limited_override {
            Some(flag) => flag,
            None => self.rate_limiter.is_rate_limited(&sender_hex, now),
        };
        if rate_limited {
            return (
                false,
                None,
                None,
                None,
                Some(format!("Rate limit exceeded for {}", sender_hex)),
            );
        }

        // 3. Basic TTL check
        if ttl <= 0 {
            return (
                false,
                None,
                None,
                None,
                Some("Invalid or expired TTL (<= 0)".to_string()),
            );
        }

        // 4. Deduplication (TTL-invariant key)
        let is_dup = match is_duplicate_override {
            Some(dup) => dup,
            None => self.deduplicator.check_and_record_raw(
                sender_id,
                timestamp,
                message_type,
                recipient_id,
                payload,
                now,
            ),
        };
        if is_dup {
            return (
                false,
                None,
                None,
                None,
                Some("Duplicate packet suppressed".to_string()),
            );
        }

        // 5. Route learning from valid incoming packet
        if let Some(source) = ingress_source {
            if !source.is_empty() {
                let hop_count = if ttl <= 7 { (7 - ttl + 1).max(1) } else { 1 };
                self.add_route(&sender_hex, source, hop_count, now);
            }
        }

        // 6. Determine destination
        let is_broadcast = match recipient_id {
            None => true,
            Some(rcpt) => rcpt == BROADCAST_RECIPIENT,
        };
        let is_for_us = is_broadcast
            || recipient_id
                .map(|r| r == self.local_peer_id.as_slice())
                .unwrap_or(false);

        let target_peer_id_hex = if !is_for_us {
            recipient_id.map(hex_encode_lower)
        } else {
            None
        };

        // 7. Determine relay TTL
        let relay_ttl = if ttl > 1 && (is_broadcast || !is_for_us) {
            let clamped = ttl.min(self.max_relay_ttl);
            let decremented = clamped - 1;
            if decremented >= 1 {
                Some(decremented)
            } else {
                None
            }
        } else {
            None
        };

        (
            is_for_us,
            relay_ttl,
            target_peer_id_hex,
            ingress_source.map(|s| s.to_string()),
            None,
        )
    }
}

// ---------------------------------------------------------------------------
// NativeStoreAndForwardQueue (Stage 3)
// ---------------------------------------------------------------------------

struct NativeQueuedEntry {
    item: PyObject,
    enqueued_at: f64,
    byte_size: usize,
}

#[pyclass(module = "bitchat._bitchat_core")]
pub struct NativeStoreAndForwardQueue {
    max_total_packets: usize,
    max_per_peer: usize,
    max_total_bytes: usize,
    packet_ttl_seconds: f64,
    queues: HashMap<String, VecDeque<NativeQueuedEntry>>,
    current_total_packets: usize,
    current_total_bytes: usize,
}

impl NativeStoreAndForwardQueue {
    fn normalize_peer_id(peer: &str) -> String {
        peer.trim().to_ascii_lowercase()
    }

    fn evict_oldest(&mut self) {
        let mut oldest_peer: Option<String> = None;
        let mut oldest_time = f64::INFINITY;

        for (peer_id, queue) in &self.queues {
            if let Some(front) = queue.front() {
                if front.enqueued_at < oldest_time {
                    oldest_time = front.enqueued_at;
                    oldest_peer = Some(peer_id.clone());
                }
            }
        }

        if let Some(peer_key) = oldest_peer {
            if let Some(queue) = self.queues.get_mut(&peer_key) {
                if let Some(evicted) = queue.pop_front() {
                    self.current_total_packets = self.current_total_packets.saturating_sub(1);
                    self.current_total_bytes =
                        self.current_total_bytes.saturating_sub(evicted.byte_size);
                }
                if queue.is_empty() {
                    self.queues.remove(&peer_key);
                }
            }
        }
    }
}

#[pymethods]
impl NativeStoreAndForwardQueue {
    #[new]
    #[pyo3(signature = (
        max_total_packets=100,
        max_per_peer=20,
        max_total_bytes=262144,
        packet_ttl_seconds=300.0
    ))]
    pub fn new(
        max_total_packets: usize,
        max_per_peer: usize,
        max_total_bytes: usize,
        packet_ttl_seconds: f64,
    ) -> Self {
        Self {
            max_total_packets,
            max_per_peer,
            max_total_bytes,
            packet_ttl_seconds,
            queues: HashMap::new(),
            current_total_packets: 0,
            current_total_bytes: 0,
        }
    }

    #[getter]
    pub fn max_total_packets(&self) -> usize {
        self.max_total_packets
    }

    #[setter]
    pub fn set_max_total_packets(&mut self, val: usize) {
        self.max_total_packets = val;
    }

    #[getter]
    pub fn max_per_peer(&self) -> usize {
        self.max_per_peer
    }

    #[setter]
    pub fn set_max_per_peer(&mut self, val: usize) {
        self.max_per_peer = val;
    }

    #[getter]
    pub fn max_total_bytes(&self) -> usize {
        self.max_total_bytes
    }

    #[setter]
    pub fn set_max_total_bytes(&mut self, val: usize) {
        self.max_total_bytes = val;
    }

    #[getter]
    pub fn packet_ttl_seconds(&self) -> f64 {
        self.packet_ttl_seconds
    }

    #[setter]
    pub fn set_packet_ttl_seconds(&mut self, val: f64) {
        self.packet_ttl_seconds = val;
    }

    #[getter]
    pub fn total_packets(&self) -> usize {
        self.current_total_packets
    }

    #[getter]
    pub fn total_bytes(&self) -> usize {
        self.current_total_bytes
    }

    #[getter]
    pub fn peer_count(&self) -> usize {
        self.queues.len()
    }

    pub fn enqueue(
        &mut self,
        target_peer_id: &str,
        packet: PyObject,
        payload_len: usize,
        now: f64,
    ) -> bool {
        self.prune_expired(now);

        let pkt_size = payload_len.saturating_add(32);
        if pkt_size > self.max_total_bytes {
            return false;
        }

        let peer_key = Self::normalize_peer_id(target_peer_id);
        if let Some(peer_queue) = self.queues.get_mut(&peer_key) {
            if peer_queue.len() >= self.max_per_peer {
                if let Some(evicted) = peer_queue.pop_front() {
                    self.current_total_packets = self.current_total_packets.saturating_sub(1);
                    self.current_total_bytes =
                        self.current_total_bytes.saturating_sub(evicted.byte_size);
                }
            }
        }

        while self.current_total_packets >= self.max_total_packets && self.current_total_packets > 0
        {
            self.evict_oldest();
        }

        while self.current_total_bytes.saturating_add(pkt_size) > self.max_total_bytes
            && self.current_total_packets > 0
        {
            self.evict_oldest();
        }

        if self.current_total_bytes.saturating_add(pkt_size) > self.max_total_bytes {
            return false;
        }

        let queue = self.queues.entry(peer_key).or_default();
        queue.push_back(NativeQueuedEntry {
            item: packet,
            enqueued_at: now,
            byte_size: pkt_size,
        });
        self.current_total_packets += 1;
        self.current_total_bytes += pkt_size;
        true
    }

    pub fn dequeue_for_peer(&mut self, target_peer_id: &str, now: f64) -> Vec<PyObject> {
        let peer_key = Self::normalize_peer_id(target_peer_id);
        let queue = match self.queues.remove(&peer_key) {
            Some(q) => q,
            None => return Vec::new(),
        };

        let mut packets = Vec::with_capacity(queue.len());
        for entry in queue {
            self.current_total_packets = self.current_total_packets.saturating_sub(1);
            self.current_total_bytes = self.current_total_bytes.saturating_sub(entry.byte_size);
            if now - entry.enqueued_at <= self.packet_ttl_seconds {
                packets.push(entry.item);
            }
        }
        packets
    }

    pub fn has_pending(&self, target_peer_id: &str) -> bool {
        let peer_key = Self::normalize_peer_id(target_peer_id);
        self.queues.get(&peer_key).is_some_and(|q| !q.is_empty())
    }

    pub fn prune_expired(&mut self, now: f64) -> usize {
        let mut pruned_count = 0usize;
        let ttl = self.packet_ttl_seconds;
        let keys: Vec<String> = self.queues.keys().cloned().collect();

        for peer_key in keys {
            let mut empty = false;
            if let Some(queue) = self.queues.get_mut(&peer_key) {
                while let Some(front) = queue.front() {
                    if now - front.enqueued_at > ttl {
                        if let Some(expired) = queue.pop_front() {
                            self.current_total_packets =
                                self.current_total_packets.saturating_sub(1);
                            self.current_total_bytes =
                                self.current_total_bytes.saturating_sub(expired.byte_size);
                            pruned_count += 1;
                        }
                    } else {
                        break;
                    }
                }
                empty = queue.is_empty();
            }
            if empty {
                self.queues.remove(&peer_key);
            }
        }
        pruned_count
    }

    pub fn clear(&mut self) {
        self.queues.clear();
        self.current_total_packets = 0;
        self.current_total_bytes = 0;
    }
}

// ---------------------------------------------------------------------------
// NativeAckTracker (Stage 3 Delivery Acknowledgment & Retry Scheduler)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct PendingAckEntry {
    peer_id: String,
    last_sent_at: f64,
    timeout_seconds: f64,
    retries: u32,
    max_retries: u32,
}

#[pyclass(module = "bitchat._bitchat_core")]
pub struct NativeAckTracker {
    max_entries: usize,
    pending: HashMap<String, PendingAckEntry>,
    order: VecDeque<String>,
}

#[pymethods]
impl NativeAckTracker {
    #[new]
    #[pyo3(signature = (max_entries=512))]
    pub fn new(max_entries: usize) -> Self {
        Self {
            max_entries: max_entries.max(1),
            pending: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    #[pyo3(signature = (msg_id, peer_id, now, timeout_seconds=10.0, max_retries=3))]
    pub fn track_message(
        &mut self,
        msg_id: &str,
        peer_id: &str,
        now: f64,
        timeout_seconds: f64,
        max_retries: u32,
    ) {
        while !self.pending.contains_key(msg_id) && self.pending.len() >= self.max_entries {
            if let Some(oldest) = self.order.pop_front() {
                self.pending.remove(&oldest);
            } else {
                break;
            }
        }
        if !self.pending.contains_key(msg_id) {
            self.order.push_back(msg_id.to_string());
        }
        self.pending.insert(
            msg_id.to_string(),
            PendingAckEntry {
                peer_id: peer_id.to_string(),
                last_sent_at: now,
                timeout_seconds,
                retries: 0,
                max_retries,
            },
        );
    }

    pub fn acknowledge(&mut self, msg_id: &str) -> Option<String> {
        self.pending.remove(msg_id).map(|e| e.peer_id)
    }

    pub fn is_pending(&self, msg_id: &str) -> bool {
        self.pending.contains_key(msg_id)
    }

    /// Collect messages that need retry at `now` and advance their retry counters.
    /// Returns `Vec<(msg_id, peer_id, retry_number)>`.
    pub fn collect_due_retries(&mut self, now: f64) -> Vec<(String, String, u32)> {
        let mut due = Vec::new();
        for (msg_id, entry) in self.pending.iter_mut() {
            if now - entry.last_sent_at >= entry.timeout_seconds
                && entry.retries < entry.max_retries
            {
                entry.retries += 1;
                entry.last_sent_at = now;
                due.push((msg_id.clone(), entry.peer_id.clone(), entry.retries));
            }
        }
        due
    }

    /// Collect and remove messages that have exhausted retries and timed out.
    /// Returns `Vec<(msg_id, peer_id)>`.
    pub fn collect_expired(&mut self, now: f64) -> Vec<(String, String)> {
        let mut expired = Vec::new();
        self.pending.retain(|msg_id, entry| {
            let is_expired = now - entry.last_sent_at >= entry.timeout_seconds
                && entry.retries >= entry.max_retries;
            if is_expired {
                expired.push((msg_id.clone(), entry.peer_id.clone()));
                false
            } else {
                true
            }
        });
        expired
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    pub fn clear(&mut self) {
        self.pending.clear();
        self.order.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_packet_id_deterministic() {
        let sender = [0x11u8; 8];
        let rcpt = [0x22u8; 8];
        let payload = b"hello mesh";
        let id1 = compute_packet_id_bytes(&sender, 123456, 0x01, Some(&rcpt), payload);
        let id2 = compute_packet_id_bytes(&sender, 123456, 0x01, Some(&rcpt), payload);
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 32);
    }

    #[test]
    fn test_deduplicator_lru_and_ttl() {
        let mut dedup = NativePacketDeduplicator::new(2, 10.0).unwrap();
        assert!(!dedup.check_and_record_id("pkt1".to_string(), 100.0));
        assert!(dedup.check_and_record_id("pkt1".to_string(), 105.0));
        assert!(!dedup.check_and_record_id("pkt2".to_string(), 106.0));
        // Refresh pkt1 so pkt2 becomes oldest
        dedup.record_id("pkt1".to_string(), 107.0);
        // Adding pkt3 should evict pkt2
        assert!(!dedup.check_and_record_id("pkt3".to_string(), 108.0));
        assert!(!dedup.is_id_duplicate("pkt2", 108.0));
        assert!(dedup.is_id_duplicate("pkt1", 108.0));
        assert!(dedup.is_id_duplicate("pkt3", 108.0));
        // Expire pkt1 at t=118.0
        assert!(!dedup.is_id_duplicate("pkt1", 118.0));
    }

    #[test]
    fn test_rate_limiter() {
        let mut limiter = NativePeerRateLimiter::new(3);
        assert!(!limiter.is_rate_limited("peer1", 10.0));
        assert!(!limiter.is_rate_limited("peer1", 10.1));
        assert!(!limiter.is_rate_limited("peer1", 10.2));
        assert!(limiter.is_rate_limited("peer1", 10.3));
        assert!(!limiter.is_rate_limited("peer1", 11.1));
    }

    #[test]
    fn test_native_mesh_router_evaluation_and_routes() {
        let local_id = [0x01u8; 8];
        let remote_id = [0x02u8; 8];
        let third_id = [0x03u8; 8];
        let mut router = NativeMeshRouter::new(&local_id, 7, 50, 100, 300.0, 2000, 300.0).unwrap();

        // Loopback dropped
        let (local, relay, _, _, drop) = router.evaluate_incoming_raw(
            &local_id,
            None,
            0x01,
            5,
            1000,
            b"self",
            Some("10.0.0.2:41235"),
            10.0,
            None,
            None,
        );
        assert!(!local);
        assert!(relay.is_none());
        assert_eq!(drop.as_deref(), Some("Packet originated from local peer"));

        // Broadcast from remote_id with TTL 5 -> processed locally AND relayed with TTL 4
        let (local, relay, target, excl, drop) = router.evaluate_incoming_raw(
            &remote_id,
            None,
            0x01,
            5,
            1001,
            b"hello mesh",
            Some("10.0.0.2:41235"),
            10.0,
            None,
            None,
        );
        assert!(local);
        assert_eq!(relay, Some(4));
        assert!(target.is_none());
        assert_eq!(excl.as_deref(), Some("10.0.0.2:41235"));
        assert!(drop.is_none());

        // Route learned
        assert_eq!(
            router
                .get_next_hop(&hex_encode_lower(&remote_id), 10.5)
                .as_deref(),
            Some("10.0.0.2:41235")
        );

        // Duplicate suppressed even if TTL decremented
        let (local2, relay2, _, _, drop2) = router.evaluate_incoming_raw(
            &remote_id,
            None,
            0x01,
            4,
            1001,
            b"hello mesh",
            Some("10.0.0.3:41235"),
            10.1,
            None,
            None,
        );
        assert!(!local2);
        assert!(relay2.is_none());
        assert_eq!(drop2.as_deref(), Some("Duplicate packet suppressed"));

        // Unicast for third_id -> not processed locally, relayed with target_peer_id_hex
        let (local3, relay3, target3, _, drop3) = router.evaluate_incoming_raw(
            &remote_id,
            Some(&third_id),
            0x02,
            3,
            1002,
            b"dm",
            Some("10.0.0.2:41235"),
            10.2,
            None,
            None,
        );
        assert!(!local3);
        assert_eq!(relay3, Some(2));
        assert_eq!(target3, Some(hex_encode_lower(&third_id)));
        assert!(drop3.is_none());
    }

    #[test]
    fn test_ack_tracker_retries_and_expiration() {
        let mut tracker = NativeAckTracker::new(16);
        tracker.track_message("m1", "peer_a", 0.0, 5.0, 2);
        assert!(tracker.is_pending("m1"));
        assert!(tracker.collect_due_retries(4.0).is_empty());

        let r1 = tracker.collect_due_retries(5.0);
        assert_eq!(r1, vec![("m1".to_string(), "peer_a".to_string(), 1)]);
        assert!(tracker.collect_expired(5.0).is_empty());

        let r2 = tracker.collect_due_retries(10.0);
        assert_eq!(r2, vec![("m1".to_string(), "peer_a".to_string(), 2)]);

        // At t=15.0, retries (2) >= max_retries (2), so it expires
        let exp = tracker.collect_expired(15.0);
        assert_eq!(exp, vec![("m1".to_string(), "peer_a".to_string())]);
        assert!(!tracker.is_pending("m1"));
    }
}
