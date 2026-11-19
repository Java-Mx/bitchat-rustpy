//! Native Rust BLE Transport State, Advertisement, and GATT Framing Engine (Stage 5).
//!
//! Provides:
//! - Manufacturer advertisement payload encoding/decoding with backward-compatible
//!   optional 8-byte `peer_id` extension (`b"BC" || service_uuid(16) [|| peer_id(8)]`)
//! - Negotiated ATT MTU payload sizing (`compute_ble_write_chunk_size`)
//! - Deterministic BLE GATT connection & subscription state machine (`NativeBleConnectionEngine`)
//!   with pre-ready notification buffering during `SUBSCRIBING` so early handshake
//!   frames are never lost on Windows WinRT or Linux BlueZ.

use std::collections::{HashSet, VecDeque};

use pyo3::prelude::*;

use crate::errors::CoreError;
use crate::protocol::hex_encode_lower;

pub const BITCHAT_BLE_PREFIX: &[u8; 2] = b"BC";
pub const UUID_BYTES_LEN: usize = 16;
pub const PEER_ID_BYTES_LEN: usize = 8;
pub const DEFAULT_BLE_MTU: usize = 185;
pub const MIN_BLE_CHUNK_SIZE: usize = 20;
pub const MAX_BLE_CHUNK_SIZE: usize = 512;
pub const MAX_BUFFERED_NOTIFICATIONS: usize = 64;

/// Encode a BitChat BLE manufacturer payload: `b"BC" || service_uuid(16) [|| peer_id(8)]`.
#[pyfunction]
#[pyo3(signature = (service_uuid_bytes, peer_id=None))]
pub fn encode_ble_manufacturer_payload(
    service_uuid_bytes: &[u8],
    peer_id: Option<&[u8]>,
) -> PyResult<Vec<u8>> {
    if service_uuid_bytes.len() != UUID_BYTES_LEN {
        return Err(CoreError::ble(format!(
            "BLE service UUID bytes must be {} bytes, got {}",
            UUID_BYTES_LEN,
            service_uuid_bytes.len()
        ))
        .into());
    }
    if let Some(pid) = peer_id {
        if pid.len() != PEER_ID_BYTES_LEN {
            return Err(CoreError::ble(format!(
                "BLE peer_id must be {} bytes, got {}",
                PEER_ID_BYTES_LEN,
                pid.len()
            ))
            .into());
        }
    }

    let cap = 2 + UUID_BYTES_LEN + peer_id.map_or(0, |p| p.len());
    let mut out = Vec::with_capacity(cap);
    out.extend_from_slice(BITCHAT_BLE_PREFIX);
    out.extend_from_slice(service_uuid_bytes);
    if let Some(pid) = peer_id {
        out.extend_from_slice(pid);
    }
    Ok(out)
}

/// Validate and decode a BitChat BLE manufacturer payload.
///
/// Returns:
/// - `(false, None)` if payload does not match `b"BC" + expected_uuid_bytes`
/// - `(true, None)` if payload matches 18-byte legacy format without peer_id
/// - `(true, Some(peer_id_hex))` if payload includes the 8-byte peer_id extension
#[pyfunction]
pub fn decode_ble_manufacturer_payload(
    payload: &[u8],
    expected_uuid_bytes: &[u8],
) -> (bool, Option<String>) {
    if expected_uuid_bytes.len() != UUID_BYTES_LEN {
        return (false, None);
    }
    let min_len = BITCHAT_BLE_PREFIX.len() + UUID_BYTES_LEN;
    if payload.len() < min_len {
        return (false, None);
    }
    if &payload[..2] != BITCHAT_BLE_PREFIX {
        return (false, None);
    }
    if &payload[2..min_len] != expected_uuid_bytes {
        return (false, None);
    }
    if payload.len() >= min_len + PEER_ID_BYTES_LEN {
        let peer_id_slice = &payload[min_len..min_len + PEER_ID_BYTES_LEN];
        if peer_id_slice != [0u8; PEER_ID_BYTES_LEN] {
            return (true, Some(hex_encode_lower(peer_id_slice)));
        }
    }
    (true, None)
}

/// Compute the usable GATT write chunk size from a negotiated ATT MTU.
#[pyfunction]
pub fn compute_ble_write_chunk_size(negotiated_mtu: usize) -> usize {
    negotiated_mtu
        .saturating_sub(3)
        .clamp(MIN_BLE_CHUNK_SIZE, MAX_BLE_CHUNK_SIZE)
}

// ---------------------------------------------------------------------------
// NativeBleConnectionEngine
// ---------------------------------------------------------------------------

#[pyclass(module = "bitchat._bitchat_core")]
pub struct NativeBleConnectionEngine {
    address: String,
    state: String,
    mtu: usize,
    pending_notifications: VecDeque<Vec<u8>>,
    server_clients: HashSet<String>,
    max_clients: usize,
}

#[pymethods]
impl NativeBleConnectionEngine {
    #[new]
    #[pyo3(signature = (address="", mtu=185, max_clients=32))]
    pub fn new(address: &str, mtu: usize, max_clients: usize) -> Self {
        Self {
            address: address.to_string(),
            state: "disconnected".to_string(),
            mtu: mtu.max(23),
            pending_notifications: VecDeque::new(),
            server_clients: HashSet::new(),
            max_clients: max_clients.max(1),
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
        }
    }

    #[getter]
    pub fn mtu(&self) -> usize {
        self.mtu
    }

    #[setter]
    pub fn set_mtu(&mut self, mtu: usize) {
        self.mtu = mtu.max(23);
    }

    pub fn max_write_chunk_size(&self) -> usize {
        compute_ble_write_chunk_size(self.mtu)
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
                None
            }
            _ => None,
        }
    }

    /// Transition to `"ready"` and drain any notifications buffered during `"subscribing"`.
    pub fn mark_ready_and_drain(&mut self) -> Vec<Vec<u8>> {
        self.state = "ready".to_string();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ble_manufacturer_payload_encode_decode() {
        let uuid = [0xAAu8; 16];
        let peer_id = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

        // Legacy 18-byte payload
        let legacy = encode_ble_manufacturer_payload(&uuid, None).unwrap();
        assert_eq!(legacy.len(), 18);
        assert_eq!(
            decode_ble_manufacturer_payload(&legacy, &uuid),
            (true, None)
        );

        // Extended 26-byte payload with peer_id
        let ext = encode_ble_manufacturer_payload(&uuid, Some(&peer_id)).unwrap();
        assert_eq!(ext.len(), 26);
        assert_eq!(
            decode_ble_manufacturer_payload(&ext, &uuid),
            (true, Some("0102030405060708".to_string()))
        );

        // Wrong UUID rejected
        let wrong_uuid = [0xBBu8; 16];
        assert_eq!(
            decode_ble_manufacturer_payload(&ext, &wrong_uuid),
            (false, None)
        );
    }

    #[test]
    fn test_ble_engine_subscribing_buffer_and_drain() {
        let mut engine = NativeBleConnectionEngine::new("AA:BB:CC:DD:EE:FF", 185, 32);
        engine.set_state("subscribing");
        assert!(engine.on_notification(b"early_frame_1").is_none());
        assert!(engine.on_notification(b"early_frame_2").is_none());
        assert_eq!(engine.buffered_notification_count(), 2);

        let drained = engine.mark_ready_and_drain();
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0], b"early_frame_1");
        assert_eq!(drained[1], b"early_frame_2");
        assert_eq!(engine.state(), "ready");
        assert_eq!(
            engine.on_notification(b"live_frame").as_deref(),
            Some(b"live_frame".as_slice())
        );
    }
}
