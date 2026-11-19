//! Authoritative Native Rust BLE Transport Manager (`NativeBleTransportManager`).
//!
//! Coordinates platform-native BLE backends (Windows WinRT, Linux BlueZ D-Bus,
//! macOS CoreBluetooth probe) on a GIL-free Tokio runtime, owns the authoritative
//! peer/connection registry, bounded event channel, and redacted 20-step
//! BLE-to-Noise progression trace.

use std::collections::VecDeque;
#[cfg(target_os = "linux")]
use std::sync::OnceLock;
use std::sync::{Arc, Mutex};

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};
#[cfg(target_os = "linux")]
use tokio::runtime::Runtime;
use tokio::sync::mpsc;

type PyBleEventTuple = (String, String, String, Option<Py<PyBytes>>);
type PyDiscoveredPeerTuple = (
    String,
    String,
    Option<String>,
    i16,
    Vec<String>,
    f64,
    String,
);

use crate::ble::advertisement::compute_ble_write_chunk_size;
use crate::ble::connection::BlePeerRegistry;
use crate::ble::types::{
    now_unix_seconds, BleAdapterSnapshot, BleDiagnosticEntry, BleDiscoveredPeer, BleRuntimeEvent,
    BleWriteMode, BITCHAT_CHARACTERISTIC_UUID_STR, BITCHAT_SERVICE_UUID_STR, DEFAULT_BLE_MTU,
    MAX_BLE_EVENTS, MAX_DIAGNOSTIC_TRACE,
};
use crate::errors::CoreError;

#[cfg(target_os = "linux")]
use crate::ble::linux_bluez::{probe_linux_adapter_async, LinuxBluezBackend};
#[cfg(target_os = "macos")]
use crate::ble::macos_corebt::{probe_macos_adapter, MacosBleBackend};
#[cfg(target_os = "windows")]
use crate::ble::windows_winrt::{probe_windows_adapter, WindowsBleBackend};

#[cfg(target_os = "linux")]
static BLE_TOKIO_RT: OnceLock<Runtime> = OnceLock::new();

#[cfg(target_os = "linux")]
fn ble_runtime() -> Result<&'static Runtime, String> {
    if let Some(rt) = BLE_TOKIO_RT.get() {
        return Ok(rt);
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("bitchat-ble-rt")
        .enable_all()
        .build()
        .map_err(|e| format!("Failed creating native BLE Tokio runtime: {}", e))?;
    let _ = BLE_TOKIO_RT.set(rt);
    BLE_TOKIO_RT
        .get()
        .ok_or_else(|| "BLE Tokio runtime initialization race".to_string())
}

/// Probe the host's native Bluetooth hardware adapter & radio state without holding the GIL.
pub fn probe_native_adapter_sync() -> BleAdapterSnapshot {
    #[cfg(target_os = "windows")]
    {
        probe_windows_adapter()
    }
    #[cfg(target_os = "linux")]
    {
        match ble_runtime() {
            Ok(rt) => rt.block_on(probe_linux_adapter_async()),
            Err(e) => BleAdapterSnapshot::unavailable("Linux BlueZ D-Bus (Rust native zbus)", e),
        }
    }
    #[cfg(target_os = "macos")]
    {
        probe_macos_adapter()
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        BleAdapterSnapshot::unavailable(
            "Unsupported Platform",
            "Native Rust BLE backend is not implemented for this operating system",
        )
    }
}

fn adapter_snapshot_to_pydict(py: Python<'_>, snap: &BleAdapterSnapshot) -> PyResult<Py<PyDict>> {
    let d = PyDict::new(py);
    d.set_item("platform_backend", &snap.platform_backend)?;
    d.set_item("adapter_present", snap.adapter_present)?;
    d.set_item("adapter_name", &snap.adapter_name)?;
    d.set_item("adapter_address", &snap.adapter_address)?;
    d.set_item("device_id", &snap.device_id)?;
    d.set_item("radio_state", &snap.radio_state)?;
    d.set_item("ble_supported", snap.ble_supported)?;
    d.set_item("central_supported", snap.central_supported)?;
    d.set_item("peripheral_supported", snap.peripheral_supported)?;
    d.set_item(
        "advertisement_offload_supported",
        snap.advertisement_offload_supported,
    )?;
    d.set_item(
        "secure_connections_supported",
        snap.secure_connections_supported,
    )?;
    d.set_item(
        "max_advertisement_data_length",
        snap.max_advertisement_data_length,
    )?;
    d.set_item("diagnostic_detail", &snap.diagnostic_detail)?;
    d.set_item("error_message", snap.error_message.as_deref())?;
    Ok(d.unbind())
}

/// Standalone GIL-free native BLE adapter probe returning a Python dictionary.
#[pyfunction]
pub fn probe_native_ble_adapter_raw(py: Python<'_>) -> PyResult<Py<PyDict>> {
    let snap = py.allow_threads(probe_native_adapter_sync);
    adapter_snapshot_to_pydict(py, &snap)
}

enum PlatformBackendImpl {
    #[cfg(target_os = "windows")]
    Windows(WindowsBleBackend),
    #[cfg(target_os = "linux")]
    Linux(LinuxBluezBackend),
    #[cfg(target_os = "macos")]
    Macos(MacosBleBackend),
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    Unsupported,
}

impl PlatformBackendImpl {
    fn new(event_tx: mpsc::Sender<BleRuntimeEvent>) -> Self {
        #[cfg(target_os = "windows")]
        {
            Self::Windows(WindowsBleBackend::new(event_tx))
        }
        #[cfg(target_os = "linux")]
        {
            Self::Linux(LinuxBluezBackend::new(event_tx))
        }
        #[cfg(target_os = "macos")]
        {
            Self::Macos(MacosBleBackend::new(event_tx))
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            let _ = event_tx;
            Self::Unsupported
        }
    }

    fn backend_label(&self) -> &'static str {
        #[cfg(target_os = "windows")]
        {
            "Windows WinRT (Rust native)"
        }
        #[cfg(target_os = "linux")]
        {
            "Linux BlueZ D-Bus (Rust native zbus)"
        }
        #[cfg(target_os = "macos")]
        {
            "macOS CoreBluetooth (Rust probe)"
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            "Unsupported Platform"
        }
    }

    fn set_identity(&mut self, peer_id_hex: &str) {
        #[cfg(target_os = "windows")]
        {
            let Self::Windows(b) = self;
            b.set_identity(peer_id_hex);
        }
        #[cfg(target_os = "linux")]
        {
            let Self::Linux(b) = self;
            b.set_identity(peer_id_hex);
        }
        #[cfg(target_os = "macos")]
        {
            let Self::Macos(b) = self;
            b.set_identity(peer_id_hex);
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        let _ = peer_id_hex;
    }

    fn start_scan(&mut self) -> Result<(), String> {
        #[cfg(target_os = "windows")]
        {
            let Self::Windows(b) = self;
            b.start_scan()
        }
        #[cfg(target_os = "linux")]
        {
            let Self::Linux(b) = self;
            ble_runtime()?.block_on(b.start_scan())
        }
        #[cfg(target_os = "macos")]
        {
            let Self::Macos(b) = self;
            b.start_scan()
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            Err("Native BLE scanning is not supported on this platform".to_string())
        }
    }

    fn stop_scan(&mut self) {
        #[cfg(target_os = "windows")]
        {
            let Self::Windows(b) = self;
            b.stop_scan();
        }
        #[cfg(target_os = "linux")]
        {
            let Self::Linux(b) = self;
            if let Ok(rt) = ble_runtime() {
                rt.block_on(b.stop_scan());
            }
        }
        #[cfg(target_os = "macos")]
        {
            let Self::Macos(b) = self;
            b.stop_scan();
        }
    }

    fn is_scanning(&self) -> bool {
        #[cfg(target_os = "windows")]
        {
            let Self::Windows(b) = self;
            b.is_scanning()
        }
        #[cfg(target_os = "linux")]
        {
            let Self::Linux(b) = self;
            b.is_scanning()
        }
        #[cfg(target_os = "macos")]
        {
            let Self::Macos(b) = self;
            b.is_scanning()
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            false
        }
    }

    fn connect_peer(&mut self, address: &str) -> Result<(usize, BleWriteMode), String> {
        #[cfg(target_os = "windows")]
        {
            let Self::Windows(b) = self;
            b.connect_peer(address)
        }
        #[cfg(target_os = "linux")]
        {
            let Self::Linux(b) = self;
            ble_runtime()?.block_on(b.connect_peer(address))
        }
        #[cfg(target_os = "macos")]
        {
            let Self::Macos(b) = self;
            b.connect_peer(address)
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            let _ = address;
            Err("Native BLE connect not supported on this platform".to_string())
        }
    }

    fn disconnect_peer(&mut self, address: &str) {
        #[cfg(target_os = "windows")]
        {
            let Self::Windows(b) = self;
            b.disconnect_peer(address);
        }
        #[cfg(target_os = "linux")]
        {
            let Self::Linux(b) = self;
            if let Ok(rt) = ble_runtime() {
                rt.block_on(b.disconnect_peer(address));
            }
        }
        #[cfg(target_os = "macos")]
        {
            let Self::Macos(b) = self;
            b.disconnect_peer(address);
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        let _ = address;
    }

    fn write_peer(&self, address: &str, data: &[u8]) -> Result<(), String> {
        #[cfg(target_os = "windows")]
        {
            let Self::Windows(b) = self;
            b.write_peer(address, data)
        }
        #[cfg(target_os = "linux")]
        {
            let Self::Linux(b) = self;
            ble_runtime()?.block_on(b.write_peer(address, data))
        }
        #[cfg(target_os = "macos")]
        {
            let Self::Macos(b) = self;
            b.write_peer(address, data)
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            let _ = (address, data);
            Err("Native BLE write not supported on this platform".to_string())
        }
    }

    fn start_peripheral(&mut self) -> Result<(bool, bool, String, String), String> {
        #[cfg(target_os = "windows")]
        {
            let Self::Windows(b) = self;
            b.start_peripheral()
        }
        #[cfg(target_os = "linux")]
        {
            let Self::Linux(b) = self;
            ble_runtime()?.block_on(b.start_peripheral())
        }
        #[cfg(target_os = "macos")]
        {
            let Self::Macos(b) = self;
            b.start_peripheral()
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            Err("Native BLE peripheral mode not supported on this platform".to_string())
        }
    }

    fn notify_clients(&self, data: &[u8]) -> Result<usize, String> {
        #[cfg(target_os = "windows")]
        {
            let Self::Windows(b) = self;
            b.notify_clients(data)
        }
        #[cfg(target_os = "linux")]
        {
            let Self::Linux(b) = self;
            ble_runtime()?.block_on(b.notify_clients(data))
        }
        #[cfg(target_os = "macos")]
        {
            let Self::Macos(b) = self;
            b.notify_clients(data)
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            let _ = data;
            Err("Native BLE peripheral notify not supported on this platform".to_string())
        }
    }

    fn stop_peripheral(&mut self) {
        #[cfg(target_os = "windows")]
        {
            let Self::Windows(b) = self;
            b.stop_peripheral();
        }
        #[cfg(target_os = "linux")]
        {
            let Self::Linux(b) = self;
            if let Ok(rt) = ble_runtime() {
                rt.block_on(b.stop_peripheral());
            }
        }
        #[cfg(target_os = "macos")]
        {
            let Self::Macos(b) = self;
            b.stop_peripheral();
        }
    }

    fn peripheral_status(&self) -> (bool, bool, String, String) {
        #[cfg(target_os = "windows")]
        {
            let Self::Windows(b) = self;
            b.peripheral_status()
        }
        #[cfg(target_os = "linux")]
        {
            let Self::Linux(b) = self;
            b.peripheral_status()
        }
        #[cfg(target_os = "macos")]
        {
            let Self::Macos(b) = self;
            b.peripheral_status()
        }
        #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
        {
            (
                false,
                false,
                "Unsupported".to_string(),
                "Unsupported".to_string(),
            )
        }
    }

    fn shutdown(&mut self) {
        #[cfg(target_os = "windows")]
        {
            let Self::Windows(b) = self;
            b.shutdown();
        }
        #[cfg(target_os = "linux")]
        {
            let Self::Linux(b) = self;
            if let Ok(rt) = ble_runtime() {
                rt.block_on(b.shutdown());
            }
        }
        #[cfg(target_os = "macos")]
        {
            let Self::Macos(b) = self;
            b.shutdown();
        }
    }
}

struct SharedState {
    backend: PlatformBackendImpl,
    registry: BlePeerRegistry,
    last_adapter: Option<BleAdapterSnapshot>,
    last_refresh_ts: f64,
    last_error: Option<String>,
    packets_sent: u64,
    packets_received: u64,
    active_mtu: usize,
    diagnostics: VecDeque<BleDiagnosticEntry>,
}

/// Authoritative Native Rust BLE Transport Manager exposed to Python.
#[pyclass(module = "bitchat._bitchat_core")]
pub struct NativeBleTransportManager {
    state: Arc<Mutex<SharedState>>,
    event_rx: Arc<Mutex<mpsc::Receiver<BleRuntimeEvent>>>,
}

impl NativeBleTransportManager {
    fn push_diagnostic(
        state: &mut SharedState,
        stage: &str,
        peer: &str,
        status: &str,
        detail: &str,
    ) {
        if state.diagnostics.len() >= MAX_DIAGNOSTIC_TRACE {
            state.diagnostics.pop_front();
        }
        state.diagnostics.push_back(BleDiagnosticEntry {
            timestamp: now_unix_seconds(),
            stage: stage.to_string(),
            peer: peer.to_string(),
            status: status.to_string(),
            detail: detail.to_string(),
        });
    }
}

#[pymethods]
impl NativeBleTransportManager {
    #[new]
    #[pyo3(signature = (local_peer_id="", local_nickname=""))]
    pub fn new(local_peer_id: &str, local_nickname: &str) -> Self {
        let (tx, rx) = mpsc::channel(MAX_BLE_EVENTS);
        let mut backend = PlatformBackendImpl::new(tx);
        backend.set_identity(local_peer_id);
        let mut diagnostics = VecDeque::with_capacity(32);
        diagnostics.push_back(BleDiagnosticEntry {
            timestamp: now_unix_seconds(),
            stage: "init".to_string(),
            peer: if local_peer_id.is_empty() {
                "local".to_string()
            } else {
                local_peer_id.chars().take(8).collect()
            },
            status: "ok".to_string(),
            detail: format!(
                "NativeBleTransportManager initialized ({}; nick_len={})",
                backend.backend_label(),
                local_nickname.len()
            ),
        });
        Self {
            state: Arc::new(Mutex::new(SharedState {
                backend,
                registry: BlePeerRegistry::default(),
                last_adapter: None,
                last_refresh_ts: 0.0,
                last_error: None,
                packets_sent: 0,
                packets_received: 0,
                active_mtu: DEFAULT_BLE_MTU,
                diagnostics,
            })),
            event_rx: Arc::new(Mutex::new(rx)),
        }
    }

    pub fn backend_name(&self) -> String {
        self.state
            .lock()
            .map(|s| s.backend.backend_label().to_string())
            .unwrap_or_else(|_| "Unknown".to_string())
    }

    pub fn set_identity(&self, peer_id_hex: &str, _nickname: &str) {
        if let Ok(mut s) = self.state.lock() {
            s.backend.set_identity(peer_id_hex);
        }
    }

    /// Probe hardware Bluetooth adapter/radio without holding Python's GIL.
    pub fn probe_adapter(&self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        let snap = py.allow_threads(probe_native_adapter_sync);
        if let Ok(mut s) = self.state.lock() {
            s.last_adapter = Some(snap.clone());
            s.last_refresh_ts = now_unix_seconds();
            if let Some(err) = &snap.error_message {
                s.last_error = Some(err.clone());
            }
            Self::push_diagnostic(
                &mut s,
                "adapter_probe",
                "local",
                if snap.adapter_present && snap.radio_state == "On" {
                    "ok"
                } else {
                    "degraded"
                },
                &snap.diagnostic_detail,
            );
        }
        adapter_snapshot_to_pydict(py, &snap)
    }

    pub fn start_scan(&self, py: Python<'_>) -> PyResult<()> {
        let state = Arc::clone(&self.state);
        let res = py.allow_threads(move || {
            let mut s = state
                .lock()
                .map_err(|_| "BLE state lock poisoned".to_string())?;
            let r = s.backend.start_scan();
            match &r {
                Ok(()) => Self::push_diagnostic(
                    &mut s,
                    "central_scan_start",
                    "local",
                    "ok",
                    "Native Rust BLE advertisement scanner started",
                ),
                Err(e) => {
                    s.last_error = Some(e.clone());
                    Self::push_diagnostic(&mut s, "central_scan_start", "local", "error", e);
                }
            }
            r
        });
        res.map_err(|e| CoreError::ble(e).into())
    }

    pub fn stop_scan(&self, py: Python<'_>) {
        let state = Arc::clone(&self.state);
        py.allow_threads(move || {
            if let Ok(mut s) = state.lock() {
                s.backend.stop_scan();
                Self::push_diagnostic(
                    &mut s,
                    "central_scan_stop",
                    "local",
                    "ok",
                    "Native Rust BLE advertisement scanner stopped",
                );
            }
        });
    }

    pub fn is_scanning(&self) -> bool {
        self.state
            .lock()
            .map(|s| s.backend.is_scanning())
            .unwrap_or(false)
    }

    pub fn start_peripheral(&self, py: Python<'_>) -> PyResult<(bool, bool, String, String)> {
        let state = Arc::clone(&self.state);
        let res = py.allow_threads(move || {
            let mut s = state
                .lock()
                .map_err(|_| "BLE state lock poisoned".to_string())?;
            let r = s.backend.start_peripheral();
            match &r {
                Ok((gatt_ok, adv_ok, gatt_msg, adv_msg)) => Self::push_diagnostic(
                    &mut s,
                    "peripheral_start",
                    "local",
                    if *gatt_ok { "ok" } else { "degraded" },
                    &format!(
                        "GATT={} ({}); CompanionAdv={} ({})",
                        gatt_ok, gatt_msg, adv_ok, adv_msg
                    ),
                ),
                Err(e) => {
                    s.last_error = Some(e.clone());
                    Self::push_diagnostic(&mut s, "peripheral_start", "local", "error", e);
                }
            }
            r
        });
        res.map_err(|e| CoreError::ble(e).into())
    }

    pub fn stop_peripheral(&self, py: Python<'_>) {
        let state = Arc::clone(&self.state);
        py.allow_threads(move || {
            if let Ok(mut s) = state.lock() {
                s.backend.stop_peripheral();
                Self::push_diagnostic(
                    &mut s,
                    "peripheral_stop",
                    "local",
                    "ok",
                    "Native Rust BLE peripheral GATT server stopped",
                );
            }
        });
    }

    pub fn connect_peer(&self, py: Python<'_>, address: &str) -> PyResult<(usize, String)> {
        let state = Arc::clone(&self.state);
        let addr_owned = address.to_string();
        let res = py.allow_threads(move || {
            let mut s = state
                .lock()
                .map_err(|_| "BLE state lock poisoned".to_string())?;
            let r = s.backend.connect_peer(&addr_owned);
            match &r {
                Ok((mtu, mode)) => {
                    s.active_mtu = *mtu;
                    s.registry
                        .connected_central
                        .insert(addr_owned.to_ascii_uppercase(), (*mtu, *mode));
                    Self::push_diagnostic(
                        &mut s,
                        "gatt_connected",
                        &addr_owned,
                        "ok",
                        &format!("Connected; MTU={}, write_mode={}", mtu, mode.as_str()),
                    );
                }
                Err(e) => {
                    s.last_error = Some(e.clone());
                    Self::push_diagnostic(&mut s, "gatt_connect", &addr_owned, "error", e);
                }
            }
            r.map(|(mtu, mode)| (mtu, mode.as_str().to_string()))
        });
        res.map_err(|e| CoreError::ble(e).into())
    }

    pub fn disconnect_peer(&self, py: Python<'_>, address: &str) {
        let state = Arc::clone(&self.state);
        let addr_owned = address.to_string();
        py.allow_threads(move || {
            if let Ok(mut s) = state.lock() {
                s.backend.disconnect_peer(&addr_owned);
                s.registry
                    .connected_central
                    .remove(&addr_owned.to_ascii_uppercase());
                Self::push_diagnostic(
                    &mut s,
                    "gatt_disconnected",
                    &addr_owned,
                    "ok",
                    "Disconnected central GATT link",
                );
            }
        });
    }

    pub fn write_peer(&self, py: Python<'_>, address: &str, data: &[u8]) -> PyResult<()> {
        let state = Arc::clone(&self.state);
        let addr_owned = address.to_string();
        let payload = data.to_vec();
        let res = py.allow_threads(move || {
            let mut s = state
                .lock()
                .map_err(|_| "BLE state lock poisoned".to_string())?;
            let mtu = s
                .registry
                .connected_central
                .get(&addr_owned.to_ascii_uppercase())
                .map(|(m, _)| *m)
                .unwrap_or(s.active_mtu);
            let chunk_size = compute_ble_write_chunk_size(mtu);
            for chunk in payload.chunks(chunk_size) {
                s.backend.write_peer(&addr_owned, chunk)?;
            }
            s.packets_sent = s.packets_sent.saturating_add(1);
            Ok::<(), String>(())
        });
        res.map_err(|e| CoreError::ble(e).into())
    }

    pub fn notify_clients(&self, py: Python<'_>, data: &[u8]) -> PyResult<usize> {
        let state = Arc::clone(&self.state);
        let payload = data.to_vec();
        let res = py.allow_threads(move || {
            let mut s = state
                .lock()
                .map_err(|_| "BLE state lock poisoned".to_string())?;
            let count = s.backend.notify_clients(&payload)?;
            s.packets_sent = s.packets_sent.saturating_add(1);
            Ok::<usize, String>(count)
        });
        res.map_err(|e| CoreError::ble(e).into())
    }

    /// Drain pending native BLE runtime events without blocking.
    ///
    /// Each returned tuple is `(event_type, address_or_client, metadata_str, optional_bytes)`.
    pub fn drain_events<'py>(&self, py: Python<'py>) -> PyResult<Vec<PyBleEventTuple>> {
        let mut out = Vec::new();
        let Ok(mut rx) = self.event_rx.lock() else {
            return Ok(out);
        };
        while let Ok(ev) = rx.try_recv() {
            match ev {
                BleRuntimeEvent::PeerDiscovered {
                    address,
                    name,
                    peer_id,
                    rssi,
                    service_uuids,
                    matched_by,
                } => {
                    if let Ok(mut s) = self.state.lock() {
                        s.registry.upsert_discovered(BleDiscoveredPeer {
                            address: address.clone(),
                            name: name.clone(),
                            peer_id: peer_id.clone(),
                            rssi,
                            service_uuids,
                            last_seen: now_unix_seconds(),
                            matched_by: matched_by.clone(),
                        });
                    }
                    let meta = format!(
                        "{}|{}|{}|{}",
                        name,
                        peer_id.unwrap_or_default(),
                        rssi,
                        matched_by
                    );
                    out.push(("peer_discovered".to_string(), address, meta, None));
                }
                BleRuntimeEvent::PeerConnected {
                    address,
                    mtu,
                    write_mode,
                } => {
                    out.push((
                        "peer_connected".to_string(),
                        address,
                        format!("{}|{}", mtu, write_mode),
                        None,
                    ));
                }
                BleRuntimeEvent::PeerDisconnected { address, reason } => {
                    if let Ok(mut s) = self.state.lock() {
                        s.registry.connected_central.remove(&address);
                    }
                    out.push(("peer_disconnected".to_string(), address, reason, None));
                }
                BleRuntimeEvent::NotificationReceived { address, payload } => {
                    if let Ok(mut s) = self.state.lock() {
                        s.packets_received = s.packets_received.saturating_add(1);
                    }
                    let b = PyBytes::new(py, &payload).unbind();
                    out.push(("notification".to_string(), address, String::new(), Some(b)));
                }
                BleRuntimeEvent::ServerWriteReceived { client_id, payload } => {
                    if let Ok(mut s) = self.state.lock() {
                        s.packets_received = s.packets_received.saturating_add(1);
                        s.registry.server_clients.insert(client_id.clone());
                    }
                    let b = PyBytes::new(py, &payload).unbind();
                    out.push((
                        "server_write".to_string(),
                        client_id,
                        String::new(),
                        Some(b),
                    ));
                }
                BleRuntimeEvent::ServerClientSubscribed { client_id } => {
                    if let Ok(mut s) = self.state.lock() {
                        s.registry.server_clients.insert(client_id.clone());
                    }
                    out.push((
                        "server_subscribed".to_string(),
                        client_id,
                        String::new(),
                        None,
                    ));
                }
                BleRuntimeEvent::ServerClientUnsubscribed { client_id } => {
                    if let Ok(mut s) = self.state.lock() {
                        s.registry.server_clients.remove(&client_id);
                    }
                    out.push((
                        "server_unsubscribed".to_string(),
                        client_id,
                        String::new(),
                        None,
                    ));
                }
                BleRuntimeEvent::AdvertisingStateChanged {
                    gatt_active,
                    companion_active,
                    status_text,
                } => {
                    out.push((
                        "advertising_state".to_string(),
                        format!("{}:{}", gatt_active, companion_active),
                        status_text,
                        None,
                    ));
                }
                BleRuntimeEvent::Error { stage, message } => {
                    if let Ok(mut s) = self.state.lock() {
                        s.last_error = Some(message.clone());
                        Self::push_diagnostic(&mut s, &stage, "local", "error", &message);
                    }
                    out.push(("error".to_string(), stage, message, None));
                }
            }
        }
        Ok(out)
    }

    pub fn record_diagnostic(&self, stage: &str, peer: &str, status: &str, detail: &str) {
        if let Ok(mut s) = self.state.lock() {
            Self::push_diagnostic(&mut s, stage, peer, status, detail);
        }
    }

    pub fn get_diagnostic_trace(&self) -> Vec<(f64, String, String, String, String)> {
        self.state
            .lock()
            .map(|s| {
                s.diagnostics
                    .iter()
                    .map(|e| {
                        (
                            e.timestamp,
                            e.stage.clone(),
                            e.peer.clone(),
                            e.status.clone(),
                            e.detail.clone(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn discovered_peers(&self) -> Vec<PyDiscoveredPeerTuple> {
        self.state
            .lock()
            .map(|s| {
                s.registry
                    .discovered
                    .values()
                    .map(|p| {
                        (
                            p.address.clone(),
                            p.name.clone(),
                            p.peer_id.clone(),
                            p.rssi,
                            p.service_uuids.clone(),
                            p.last_seen,
                            p.matched_by.clone(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn prune_stale_discovered(&self, max_age_seconds: f64) -> usize {
        self.state
            .lock()
            .map(|mut s| s.registry.prune_stale_discovered(max_age_seconds))
            .unwrap_or(0)
    }

    pub fn resolve_address(&self, target: &str) -> Option<String> {
        self.state
            .lock()
            .ok()
            .and_then(|s| s.registry.resolve_address(target))
    }

    pub fn connected_central_peers(&self) -> Vec<String> {
        self.state
            .lock()
            .map(|s| {
                let mut v: Vec<String> = s.registry.connected_central.keys().cloned().collect();
                v.sort();
                v
            })
            .unwrap_or_default()
    }

    pub fn server_clients(&self) -> Vec<String> {
        self.state
            .lock()
            .map(|s| {
                let mut v: Vec<String> = s.registry.server_clients.iter().cloned().collect();
                v.sort();
                v
            })
            .unwrap_or_default()
    }

    /// Return a truthful, comprehensive BLE telemetry dictionary for UI & diagnostics.
    pub fn get_telemetry(&self, py: Python<'_>) -> PyResult<Py<PyDict>> {
        let d = PyDict::new(py);
        let Ok(s) = self.state.lock() else {
            return Ok(d.unbind());
        };
        let (gatt_active, companion_active, gatt_status, adv_status) =
            s.backend.peripheral_status();
        let scanning = s.backend.is_scanning();
        let adapter = s.last_adapter.clone().unwrap_or_else(|| {
            BleAdapterSnapshot::unavailable(s.backend.backend_label(), "Adapter not yet probed")
        });

        d.set_item("backend_name", s.backend.backend_label())?;
        d.set_item("rust_ble_active", true)?;
        d.set_item("adapter_present", adapter.adapter_present)?;
        d.set_item("adapter_name", &adapter.adapter_name)?;
        d.set_item("adapter_address", &adapter.adapter_address)?;
        d.set_item("device_id", &adapter.device_id)?;
        d.set_item("adapter_state", &adapter.radio_state)?;
        d.set_item("radio_state", &adapter.radio_state)?;
        d.set_item("ble_supported", adapter.ble_supported)?;
        d.set_item("central_supported", adapter.central_supported)?;
        d.set_item("peripheral_supported", adapter.peripheral_supported)?;
        d.set_item("scanning_active", scanning)?;
        d.set_item(
            "central_status",
            if scanning {
                "Active (Scanning)"
            } else if adapter.central_supported {
                "Idle (Supported)"
            } else {
                "Unsupported"
            },
        )?;
        d.set_item(
            "peripheral_status",
            if gatt_active {
                "Active (GATT Ready)"
            } else if adapter.peripheral_supported {
                "Idle (Supported)"
            } else {
                "Unsupported"
            },
        )?;
        d.set_item("gatt_server_status", &gatt_status)?;
        d.set_item("discovery_advertisement_status", &adv_status)?;
        d.set_item("gatt_service_registered", gatt_active)?;
        d.set_item("advertising_active", gatt_active || companion_active)?;
        d.set_item("companion_advertising_active", companion_active)?;
        d.set_item("service_uuid", BITCHAT_SERVICE_UUID_STR.to_uppercase())?;
        d.set_item(
            "characteristic_uuid",
            BITCHAT_CHARACTERISTIC_UUID_STR.to_uppercase(),
        )?;
        d.set_item("discovered_peers_count", s.registry.discovered.len())?;
        d.set_item(
            "connected_central_count",
            s.registry.connected_central.len(),
        )?;
        d.set_item(
            "connected_server_clients_count",
            s.registry.server_clients.len(),
        )?;
        d.set_item("active_mtu", s.active_mtu)?;
        d.set_item("packets_sent", s.packets_sent)?;
        d.set_item("packets_received", s.packets_received)?;
        d.set_item("last_error", s.last_error.as_deref())?;
        d.set_item("diagnostic_detail", &adapter.diagnostic_detail)?;
        d.set_item("last_refresh_timestamp", s.last_refresh_ts)?;
        Ok(d.unbind())
    }

    pub fn shutdown(&self, py: Python<'_>) {
        let state = Arc::clone(&self.state);
        py.allow_threads(move || {
            if let Ok(mut s) = state.lock() {
                s.backend.shutdown();
                s.registry.clear();
                Self::push_diagnostic(
                    &mut s,
                    "shutdown",
                    "local",
                    "ok",
                    "Native Rust BLE transport shut down cleanly",
                );
            }
        });
    }
}
