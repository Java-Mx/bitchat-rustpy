//! Native Rust BLE GATT connection state machine, bounded write/notification
//! queues, MTU chunking, and authoritative peer/connection registry.

use std::collections::{HashMap, HashSet, VecDeque};

use pyo3::prelude::*;

use crate::ble::advertisement::compute_ble_write_chunk_size;
use crate::ble::types::{
    now_unix_seconds, BleDiscoveredPeer, BleWriteMode, MAX_BUFFERED_NOTIFICATIONS,
    MAX_DISCOVERED_PEERS, MAX_PENDING_WRITES, MIN_BLE_MTU,
};

/// Deterministic BLE GATT connection & subscription state machine with bounded
/// early-notification buffering and bounded outbound write queue.
#[pyclass(module = "bitchat._bitchat_core")]
pub struct NativeBleConnectionEngine {
    address: String,
    state: String,
    mtu: usize,
    write_mode: BleWriteMode,
    pending_notifications: VecDeque<Vec<u8>>,
    pending_writes: VecDeque<Vec<u8>>,
    server_clients: HashSet<String>,
    max_clients: usize,
    reconnect_attempts: u32,
    notifications_buffered_total: u64,
    writes_dropped_total: u64,
    last_error: Option<String>,
}

#[pymethods]
impl NativeBleConnectionEngine {
    #[new]
    #[pyo3(signature = (address="", mtu=185, max_clients=32))]
    pub fn new(address: &str, mtu: usize, max_clients: usize) -> Self {
        Self {
            address: address.to_string(),
            state: "disconnected".to_string(),
            mtu: mtu.max(MIN_BLE_MTU),
            write_mode: BleWriteMode::WriteWithoutResponse,
            pending_notifications: VecDeque::new(),
            pending_writes: VecDeque::new(),
            server_clients: HashSet::new(),
            max_clients: max_clients.max(1),
            reconnect_attempts: 0,
            notifications_buffered_total: 0,
            writes_dropped_total: 0,
            last_error: None,
        }
    }

    #[getter]
    pub fn address(&self) -> &str {
        &self.address
    }

    #[getter]
    pub fn state(&self) -> &str {
        &self.state
    }

    pub fn set_state(&mut self, state: &str) {
        self.state = state.to_ascii_lowercase();
        if self.state == "disconnected" || self.state == "failed" {
            self.pending_notifications.clear();
            self.pending_writes.clear();
        } else if self.state == "ready" {
            self.reconnect_attempts = 0;
            self.last_error = None;
        }
    }

    #[getter]
    pub fn mtu(&self) -> usize {
        self.mtu
    }

    #[setter]
    pub fn set_mtu(&mut self, mtu: usize) {
        self.mtu = mtu.max(MIN_BLE_MTU);
    }

    #[getter]
    pub fn write_mode(&self) -> &'static str {
        self.write_mode.as_str()
    }

    pub fn set_write_mode(&mut self, mode: &str) {
        self.write_mode = if mode.eq_ignore_ascii_case("write-with-response")
            || mode.eq_ignore_ascii_case("write")
        {
            BleWriteMode::WriteWithResponse
        } else {
            BleWriteMode::WriteWithoutResponse
        };
    }

    pub fn max_write_chunk_size(&self) -> usize {
        compute_ble_write_chunk_size(self.mtu)
    }

    /// Split an outbound payload into ATT-MTU-safe write chunks.
    pub fn chunk_payload(&self, data: &[u8]) -> Vec<Vec<u8>> {
        if data.is_empty() {
            return Vec::new();
        }
        let chunk_size = self.max_write_chunk_size();
        data.chunks(chunk_size).map(|c| c.to_vec()).collect()
    }

    /// Enqueue an outbound write frame with bounded backpressure.
    pub fn enqueue_write(&mut self, data: &[u8]) -> bool {
        if data.is_empty() {
            return false;
        }
        if self.pending_writes.len() >= MAX_PENDING_WRITES {
            self.writes_dropped_total = self.writes_dropped_total.saturating_add(1);
            return false;
        }
        self.pending_writes.push_back(data.to_vec());
        true
    }

    pub fn dequeue_write(&mut self) -> Option<Vec<u8>> {
        self.pending_writes.pop_front()
    }

    pub fn pending_write_count(&self) -> usize {
        self.pending_writes.len()
    }

    pub fn record_reconnect_attempt(&mut self, reason: &str) -> u32 {
        self.reconnect_attempts = self.reconnect_attempts.saturating_add(1);
        self.last_error = Some(reason.to_string());
        self.reconnect_attempts
    }

    #[getter]
    pub fn reconnect_attempts(&self) -> u32 {
        self.reconnect_attempts
    }

    #[getter]
    pub fn notifications_buffered_total(&self) -> u64 {
        self.notifications_buffered_total
    }

    #[getter]
    pub fn writes_dropped_total(&self) -> u64 {
        self.writes_dropped_total
    }

    #[getter]
    pub fn last_error(&self) -> Option<String> {
        self.last_error.clone()
    }

    /// Handle an incoming BLE GATT notification according to current connection state.
    ///
    /// - If `state == "ready"`, returns `Some(data)` for immediate dispatch.
    /// - If `state == "subscribing"` or `state == "discovering"`, buffers up to
    ///   `MAX_BUFFERED_NOTIFICATIONS` frames so notifications arriving before
    ///   `start_notify` returns are not lost, and returns `None`.
    /// - Otherwise drops the frame and returns `None`.
    pub fn on_notification(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        if data.is_empty() {
            return None;
        }
        match self.state.as_str() {
            "ready" => Some(data.to_vec()),
            "subscribing" | "discovering" => {
                if self.pending_notifications.len() >= MAX_BUFFERED_NOTIFICATIONS {
                    self.pending_notifications.pop_front();
                }
                self.pending_notifications.push_back(data.to_vec());
                self.notifications_buffered_total =
                    self.notifications_buffered_total.saturating_add(1);
                None
            }
            _ => None,
        }
    }

    /// Transition to `"ready"` and drain any notifications buffered during `"subscribing"`.
    pub fn mark_ready_and_drain(&mut self) -> Vec<Vec<u8>> {
        self.state = "ready".to_string();
        self.reconnect_attempts = 0;
        self.pending_notifications.drain(..).collect()
    }

    pub fn buffered_notification_count(&self) -> usize {
        self.pending_notifications.len()
    }

    pub fn register_server_client(&mut self, client_address: &str) -> bool {
        let addr = client_address.trim();
        if addr.is_empty() {
            return false;
        }
        if !self.server_clients.contains(addr) && self.server_clients.len() >= self.max_clients {
            return false;
        }
        self.server_clients.insert(addr.to_string())
    }

    pub fn unregister_server_client(&mut self, client_address: &str) -> bool {
        self.server_clients.remove(client_address.trim())
    }

    pub fn is_server_client(&self, client_address: &str) -> bool {
        self.server_clients.contains(client_address.trim())
    }

    pub fn server_clients(&self) -> Vec<String> {
        let mut out: Vec<String> = self.server_clients.iter().cloned().collect();
        out.sort();
        out
    }

    pub fn clear_server_clients(&mut self) {
        self.server_clients.clear();
    }
}

/// Authoritative Rust registry tracking discovered peers, active central links,
/// and inbound peripheral subscribers.
#[derive(Debug, Default)]
pub struct BlePeerRegistry {
    pub discovered: HashMap<String, BleDiscoveredPeer>,
    pub peer_id_to_address: HashMap<String, String>,
    pub address_to_peer_id: HashMap<String, String>,
    pub connected_central: HashMap<String, (usize, BleWriteMode)>,
    pub server_clients: HashSet<String>,
}

impl BlePeerRegistry {
    pub fn upsert_discovered(&mut self, peer: BleDiscoveredPeer) {
        let key = peer.address.clone();
        if !self.discovered.contains_key(&key) && self.discovered.len() >= MAX_DISCOVERED_PEERS {
            // Evict oldest discovered peer not currently connected.
            if let Some(oldest_key) = self
                .discovered
                .iter()
                .filter(|(addr, _)| !self.connected_central.contains_key(*addr))
                .min_by(|a, b| a.1.last_seen.total_cmp(&b.1.last_seen))
                .map(|(k, _)| k.clone())
            {
                self.discovered.remove(&oldest_key);
            }
        }
        if let Some(pid) = &peer.peer_id {
            let pid_lower = pid.to_ascii_lowercase();
            self.peer_id_to_address
                .insert(pid_lower.clone(), key.clone());
            self.address_to_peer_id.insert(key.clone(), pid_lower);
        }
        self.discovered.insert(key, peer);
    }

    pub fn prune_stale_discovered(&mut self, max_age_seconds: f64) -> usize {
        let cutoff = now_unix_seconds() - max_age_seconds;
        let stale_keys: Vec<String> = self
            .discovered
            .iter()
            .filter(|(addr, peer)| {
                peer.last_seen < cutoff && !self.connected_central.contains_key(*addr)
            })
            .map(|(k, _)| k.clone())
            .collect();
        let count = stale_keys.len();
        for key in stale_keys {
            self.discovered.remove(&key);
        }
        count
    }

    pub fn resolve_address(&self, peer_id_or_addr: &str) -> Option<String> {
        let clean = peer_id_or_addr.trim().to_ascii_lowercase();
        if let Some(addr) = self.peer_id_to_address.get(&clean) {
            return Some(addr.clone());
        }
        for (pid, addr) in &self.peer_id_to_address {
            if pid.starts_with(&clean) {
                return Some(addr.clone());
            }
        }
        for addr in self.discovered.keys() {
            if addr.eq_ignore_ascii_case(peer_id_or_addr.trim()) {
                return Some(addr.clone());
            }
        }
        None
    }

    pub fn clear(&mut self) {
        self.discovered.clear();
        self.peer_id_to_address.clear();
        self.address_to_peer_id.clear();
        self.connected_central.clear();
        self.server_clients.clear();
    }
}
