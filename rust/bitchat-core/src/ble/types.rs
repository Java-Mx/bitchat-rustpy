//! Shared types, constants, telemetry snapshots, and redacted diagnostics for
//! BitChat's native Rust BLE transport (Phase 3).

use std::time::{SystemTime, UNIX_EPOCH};

/// Canonical BitChat BLE GATT Service UUID (128-bit, matches bitchat-tui & iOS/Android).
pub const BITCHAT_SERVICE_UUID_STR: &str = "f47b5e2d-4a9e-4c5a-9b3f-8e1d2c3a4b5c";
pub const BITCHAT_SERVICE_UUID_U128: u128 = 0xF47B5E2D_4A9E_4C5A_9B3F_8E1D2C3A4B5C;

/// Canonical BitChat BLE GATT Characteristic UUID (read/write/write-without-response/notify).
pub const BITCHAT_CHARACTERISTIC_UUID_STR: &str = "a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d";
pub const BITCHAT_CHARACTERISTIC_UUID_U128: u128 = 0xA1B2C3D4_E5F6_4A5B_8C9D_0E1F2A3B4C5D;

/// BitChat BLE Manufacturer Company ID (`0xFFFF`, Bluetooth SIG test/internal).
pub const BITCHAT_MANUFACTURER_ID: u16 = 0xFFFF;
pub const BITCHAT_BLE_PREFIX: &[u8; 2] = b"BC";
pub const UUID_BYTES_LEN: usize = 16;
pub const PEER_ID_BYTES_LEN: usize = 8;
pub const DEFAULT_BLE_MTU: usize = 185;
pub const MIN_BLE_MTU: usize = 23;
pub const MIN_BLE_CHUNK_SIZE: usize = 20;
pub const MAX_BLE_CHUNK_SIZE: usize = 512;
pub const MAX_BUFFERED_NOTIFICATIONS: usize = 64;
pub const MAX_PENDING_WRITES: usize = 128;
pub const MAX_BLE_EVENTS: usize = 512;
pub const MAX_DIAGNOSTIC_TRACE: usize = 128;
pub const MAX_DISCOVERED_PEERS: usize = 256;

#[inline]
pub fn now_unix_seconds() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Truthful Bluetooth hardware adapter & radio diagnostic snapshot.
#[derive(Debug, Clone)]
pub struct BleAdapterSnapshot {
    pub platform_backend: String,
    pub adapter_present: bool,
    pub adapter_name: String,
    pub adapter_address: String,
    pub device_id: String,
    pub radio_state: String,
    pub ble_supported: bool,
    pub central_supported: bool,
    pub peripheral_supported: bool,
    pub advertisement_offload_supported: bool,
    pub secure_connections_supported: bool,
    pub max_advertisement_data_length: usize,
    pub diagnostic_detail: String,
    pub error_message: Option<String>,
}

impl BleAdapterSnapshot {
    pub fn unavailable(platform_backend: &str, reason: impl Into<String>) -> Self {
        let msg = reason.into();
        Self {
            platform_backend: platform_backend.to_string(),
            adapter_present: false,
            adapter_name: "None Detected".to_string(),
            adapter_address: "Unavailable".to_string(),
            device_id: "Unavailable".to_string(),
            radio_state: "Unavailable".to_string(),
            ble_supported: false,
            central_supported: false,
            peripheral_supported: false,
            advertisement_offload_supported: false,
            secure_connections_supported: false,
            max_advertisement_data_length: 0,
            diagnostic_detail: msg.clone(),
            error_message: Some(msg),
        }
    }
}

/// Validated BitChat BLE discovered peer entry.
#[derive(Debug, Clone)]
pub struct BleDiscoveredPeer {
    pub address: String,
    pub name: String,
    pub peer_id: Option<String>,
    pub rssi: i16,
    pub service_uuids: Vec<String>,
    pub last_seen: f64,
    pub matched_by: String,
}

/// Gatt characteristic write capability mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BleWriteMode {
    WriteWithoutResponse,
    WriteWithResponse,
}

impl BleWriteMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::WriteWithoutResponse => "write-without-response",
            Self::WriteWithResponse => "write-with-response",
        }
    }
}

/// Redacted BLE-to-Noise progression trace entry (NEVER contains keys/secrets/plaintext).
#[derive(Debug, Clone)]
pub struct BleDiagnosticEntry {
    pub timestamp: f64,
    pub stage: String,
    pub peer: String,
    pub status: String,
    pub detail: String,
}

/// Structured event delivered from native Rust BLE runtime to Python/SessionCoordinator.
#[derive(Debug, Clone)]
pub enum BleRuntimeEvent {
    PeerDiscovered {
        address: String,
        name: String,
        peer_id: Option<String>,
        rssi: i16,
        service_uuids: Vec<String>,
        matched_by: String,
    },
    PeerConnected {
        address: String,
        mtu: usize,
        write_mode: String,
    },
    PeerDisconnected {
        address: String,
        reason: String,
    },
    NotificationReceived {
        address: String,
        payload: Vec<u8>,
    },
    ServerWriteReceived {
        client_id: String,
        payload: Vec<u8>,
    },
    ServerClientSubscribed {
        client_id: String,
    },
    ServerClientUnsubscribed {
        client_id: String,
    },
    AdvertisingStateChanged {
        gatt_active: bool,
        companion_active: bool,
        status_text: String,
    },
    Error {
        stage: String,
        message: String,
    },
}

/// Truthful point-in-time BLE transport telemetry snapshot for UI & diagnostics.
#[derive(Debug, Clone)]
pub struct BleTransportTelemetry {
    pub backend_name: String,
    pub rust_ble_active: bool,
    pub adapter: BleAdapterSnapshot,
    pub central_status: String,
    pub scanning_active: bool,
    pub peripheral_status: String,
    pub gatt_server_status: String,
    pub discovery_advertisement_status: String,
    pub advertising_active: bool,
    pub gatt_service_registered: bool,
    pub service_uuid: String,
    pub characteristic_uuid: String,
    pub discovered_peers_count: usize,
    pub connected_central_count: usize,
    pub connected_server_clients_count: usize,
    pub active_mtu: usize,
    pub last_error: Option<String>,
    pub last_refresh_timestamp: f64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub notifications_buffered_early: u64,
}
