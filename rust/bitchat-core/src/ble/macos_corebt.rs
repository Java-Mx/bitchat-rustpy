//! Native macOS CoreBluetooth capability probe & transport boundary
//! (`#[cfg(target_os = "macos")]`).
//!
//! Reports truthful macOS Bluetooth hardware/radio status via `system_profiler`
//! without external Objective-C/Xcode build fragility, while honestly declaring
//! CoreBluetooth peripheral mode as unimplemented in Rust core.

#![cfg(target_os = "macos")]

use std::process::Command;

use tokio::sync::mpsc;

use crate::ble::types::{BleAdapterSnapshot, BleRuntimeEvent, BleWriteMode};

pub fn probe_macos_adapter() -> BleAdapterSnapshot {
    let backend = "macOS CoreBluetooth (Rust probe + Bleak central bridge)";
    let output = Command::new("system_profiler")
        .arg("SPBluetoothDataType")
        .output();

    let Ok(out) = output else {
        return BleAdapterSnapshot::unavailable(
            backend,
            "Unable to query macOS Bluetooth controller via system_profiler",
        );
    };
    if !out.status.success() {
        return BleAdapterSnapshot::unavailable(
            backend,
            "system_profiler SPBluetoothDataType exited with error",
        );
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let powered_on = stdout.contains("State: On") || stdout.contains("Bluetooth Power: On");
    let address = stdout
        .lines()
        .find(|l| l.trim().starts_with("Address:"))
        .and_then(|l| l.split_once(':'))
        .map(|(_, v)| v.trim().to_string())
        .unwrap_or_else(|| "Protected by macOS CoreBluetooth".to_string());

    BleAdapterSnapshot {
        platform_backend: backend.to_string(),
        adapter_present: true,
        adapter_name: "Apple Bluetooth Controller".to_string(),
        adapter_address: address,
        device_id: "CoreBluetooth".to_string(),
        radio_state: if powered_on {
            "On".to_string()
        } else {
            "Off".to_string()
        },
        ble_supported: true,
        central_supported: true,
        peripheral_supported: false,
        advertisement_offload_supported: false,
        secure_connections_supported: true,
        max_advertisement_data_length: 31,
        diagnostic_detail: if powered_on {
            "macOS Bluetooth powered on — Central supported; Peripheral GATT server not implemented on macOS".to_string()
        } else {
            "macOS Bluetooth radio appears powered off".to_string()
        },
        error_message: if powered_on {
            None
        } else {
            Some("macOS Bluetooth radio is powered off".to_string())
        },
    }
}

pub struct MacosBleBackend {
    _event_tx: mpsc::Sender<BleRuntimeEvent>,
}

impl MacosBleBackend {
    pub fn new(event_tx: mpsc::Sender<BleRuntimeEvent>) -> Self {
        Self {
            _event_tx: event_tx,
        }
    }

    pub fn set_identity(&mut self, _peer_id_hex: &str) {}

    pub fn start_scan(&mut self) -> Result<(), String> {
        Err("Use CoreBluetooth Central bridge on macOS".to_string())
    }

    pub fn stop_scan(&mut self) {}

    pub fn is_scanning(&self) -> bool {
        false
    }

    pub fn connect_peer(&mut self, _address: &str) -> Result<(usize, BleWriteMode), String> {
        Err("Use CoreBluetooth Central bridge on macOS".to_string())
    }

    pub fn disconnect_peer(&mut self, _address: &str) {}

    pub fn write_peer(&self, _address: &str, _data: &[u8]) -> Result<(), String> {
        Err("Use CoreBluetooth Central bridge on macOS".to_string())
    }

    pub fn start_peripheral(&mut self) -> Result<(bool, bool, String, String), String> {
        Err("CoreBluetooth Peripheral GATT server is not implemented on macOS".to_string())
    }

    pub fn notify_clients(&self, _data: &[u8]) -> Result<usize, String> {
        Err("CoreBluetooth Peripheral GATT server is not implemented on macOS".to_string())
    }

    pub fn stop_peripheral(&mut self) {}

    pub fn peripheral_status(&self) -> (bool, bool, String, String) {
        (
            false,
            false,
            "Unsupported (macOS CoreBluetooth peripheral not implemented)".to_string(),
            "Unsupported".to_string(),
        )
    }

    pub fn shutdown(&mut self) {}
}
