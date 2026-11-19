//! Native Windows WinRT BLE backend (`#[cfg(target_os = "windows")]`).
//!
//! Uses Microsoft's official `windows` WinRT bindings directly from Rust:
//! - Adapter & radio telemetry (`BluetoothAdapter`, `Radio`)
//! - Central advertisement scanning (`BluetoothLEAdvertisementWatcher`)
//! - Central GATT client (`BluetoothLEDevice`, `GattDeviceService`, `GattCharacteristic`, `GattSession`)
//! - Peripheral GATT server (`GattServiceProvider`, `GattLocalCharacteristic`) with a
//!   **decoupled** optional companion manufacturer `BluetoothLEAdvertisementPublisher` so
//!   a companion advertisement failure (e.g. status 3 / Aborted) NEVER tears down an
//!   already-working GATT service provider.

#![cfg(target_os = "windows")]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;
use windows::core::{GUID, HSTRING};
use windows::Devices::Bluetooth::Advertisement::{
    BluetoothLEAdvertisement, BluetoothLEAdvertisementDataSection,
    BluetoothLEAdvertisementDataTypes, BluetoothLEAdvertisementPublisher,
    BluetoothLEAdvertisementPublisherStatus, BluetoothLEAdvertisementReceivedEventArgs,
    BluetoothLEAdvertisementWatcher, BluetoothLEAdvertisementWatcherStoppedEventArgs,
    BluetoothLEManufacturerData, BluetoothLEScanningMode,
};
use windows::Devices::Bluetooth::GenericAttributeProfile::{
    GattCharacteristic, GattCharacteristicProperties,
    GattClientCharacteristicConfigurationDescriptorValue, GattCommunicationStatus,
    GattLocalCharacteristic, GattLocalCharacteristicParameters, GattProtectionLevel,
    GattReadRequestedEventArgs, GattServiceProvider, GattServiceProviderAdvertisementStatus,
    GattServiceProviderAdvertisementStatusChangedEventArgs,
    GattServiceProviderAdvertisingParameters, GattSession, GattValueChangedEventArgs,
    GattWriteOption, GattWriteRequestedEventArgs,
};
use windows::Devices::Bluetooth::{BluetoothAdapter, BluetoothError, BluetoothLEDevice};
use windows::Devices::Radios::RadioState;
use windows::Foundation::{EventRegistrationToken, TypedEventHandler};
use windows::Storage::Streams::{DataReader, DataWriter, IBuffer};

use crate::ble::advertisement::{
    bitchat_service_uuid_bytes, encode_ble_manufacturer_payload, match_bitchat_advertisement,
    validate_gatt_characteristic,
};
use crate::ble::types::{
    BleAdapterSnapshot, BleRuntimeEvent, BleWriteMode, BITCHAT_CHARACTERISTIC_UUID_STR,
    BITCHAT_CHARACTERISTIC_UUID_U128, BITCHAT_MANUFACTURER_ID, BITCHAT_SERVICE_UUID_STR,
    BITCHAT_SERVICE_UUID_U128, DEFAULT_BLE_MTU, MIN_BLE_MTU,
};

fn guid_from_u128(v: u128) -> GUID {
    GUID::from_u128(v)
}

fn guid_to_uuid_string(g: &GUID) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        g.data1,
        g.data2,
        g.data3,
        g.data4[0],
        g.data4[1],
        g.data4[2],
        g.data4[3],
        g.data4[4],
        g.data4[5],
        g.data4[6],
        g.data4[7],
    )
}

pub fn format_bluetooth_address(addr: u64) -> String {
    let bytes = addr.to_be_bytes();
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]
    )
}

pub fn parse_bluetooth_address(addr: &str) -> Result<u64, String> {
    let hex_only: String = addr
        .trim()
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect();
    if hex_only.len() != 12 {
        return Err(format!("Invalid Bluetooth MAC address: '{}'", addr));
    }
    u64::from_str_radix(&hex_only, 16)
        .map_err(|e| format!("Failed to parse Bluetooth MAC '{}': {}", addr, e))
}

fn ibuffer_to_vec(buf: &IBuffer) -> Result<Vec<u8>, String> {
    let len = buf
        .Length()
        .map_err(|e| format!("Failed reading IBuffer length: {}", e))? as usize;
    if len == 0 {
        return Ok(Vec::new());
    }
    let reader =
        DataReader::FromBuffer(buf).map_err(|e| format!("DataReader::FromBuffer failed: {}", e))?;
    let mut out = vec![0u8; len];
    reader
        .ReadBytes(&mut out)
        .map_err(|e| format!("DataReader::ReadBytes failed: {}", e))?;
    Ok(out)
}

fn slice_to_ibuffer(data: &[u8]) -> Result<IBuffer, String> {
    let writer = DataWriter::new().map_err(|e| format!("DataWriter::new failed: {}", e))?;
    writer
        .WriteBytes(data)
        .map_err(|e| format!("DataWriter::WriteBytes failed: {}", e))?;
    writer
        .DetachBuffer()
        .map_err(|e| format!("DataWriter::DetachBuffer failed: {}", e))
}

fn gatt_adv_status_label(status: GattServiceProviderAdvertisementStatus) -> String {
    match status {
        GattServiceProviderAdvertisementStatus::Created => "Created (0)".to_string(),
        GattServiceProviderAdvertisementStatus::Stopped => "Stopped (1)".to_string(),
        GattServiceProviderAdvertisementStatus::Started => "Started (2)".to_string(),
        GattServiceProviderAdvertisementStatus::Aborted => {
            "Aborted (3 — Windows Bluetooth radio/driver rejected GATT advertising)".to_string()
        }
        GattServiceProviderAdvertisementStatus::StartedWithoutAllAdvertisementData => {
            "StartedWithoutAllAdvertisementData (4 — GATT active with partial adv data)".to_string()
        }
        other => format!("Unknown ({})", other.0),
    }
}

fn publisher_status_label(status: BluetoothLEAdvertisementPublisherStatus) -> String {
    match status {
        BluetoothLEAdvertisementPublisherStatus::Created => "Created (0)".to_string(),
        BluetoothLEAdvertisementPublisherStatus::Waiting => "Waiting (1)".to_string(),
        BluetoothLEAdvertisementPublisherStatus::Started => "Started (2)".to_string(),
        BluetoothLEAdvertisementPublisherStatus::Stopping => "Stopping (3)".to_string(),
        BluetoothLEAdvertisementPublisherStatus::Stopped => "Stopped (4)".to_string(),
        BluetoothLEAdvertisementPublisherStatus::Aborted => {
            "Aborted (5 — Windows rejected companion manufacturer advertisement)".to_string()
        }
        other => format!("Unknown ({})", other.0),
    }
}

fn radio_state_label(state: RadioState) -> String {
    match state {
        RadioState::On => "On".to_string(),
        RadioState::Off => "Off".to_string(),
        RadioState::Disabled => "Disabled".to_string(),
        _ => "Unknown".to_string(),
    }
}

fn gatt_props_to_strings(props: GattCharacteristicProperties) -> Vec<String> {
    let mut out = Vec::new();
    let bits = props.0;
    if (bits & GattCharacteristicProperties::Read.0) != 0 {
        out.push("read".to_string());
    }
    if (bits & GattCharacteristicProperties::Write.0) != 0 {
        out.push("write".to_string());
    }
    if (bits & GattCharacteristicProperties::WriteWithoutResponse.0) != 0 {
        out.push("write-without-response".to_string());
    }
    if (bits & GattCharacteristicProperties::Notify.0) != 0 {
        out.push("notify".to_string());
    }
    if (bits & GattCharacteristicProperties::Indicate.0) != 0 {
        out.push("indicate".to_string());
    }
    out
}

/// Probe the default Windows Bluetooth adapter and radio state via WinRT.
pub fn probe_windows_adapter() -> BleAdapterSnapshot {
    let backend = "Windows WinRT (Rust native)";
    let async_op = match BluetoothAdapter::GetDefaultAsync() {
        Ok(op) => op,
        Err(e) => {
            return BleAdapterSnapshot::unavailable(
                backend,
                format!("BluetoothAdapter::GetDefaultAsync failed: {}", e),
            );
        }
    };

    let adapter = match async_op.get() {
        Ok(a) => a,
        Err(e) => {
            return BleAdapterSnapshot::unavailable(
                backend,
                format!("No default Windows Bluetooth adapter available ({})", e),
            );
        }
    };

    let address_u64 = adapter.BluetoothAddress().unwrap_or(0);
    let adapter_address = if address_u64 != 0 {
        format_bluetooth_address(address_u64)
    } else {
        "Unavailable".to_string()
    };
    let device_id = adapter
        .DeviceId()
        .map(|s| s.to_string())
        .unwrap_or_else(|_| "Unavailable".to_string());
    let ble_supported = adapter.IsLowEnergySupported().unwrap_or(false);
    let central_supported = adapter.IsCentralRoleSupported().unwrap_or(false);
    let peripheral_supported = adapter.IsPeripheralRoleSupported().unwrap_or(false);
    let advertisement_offload_supported =
        adapter.IsAdvertisementOffloadSupported().unwrap_or(false);
    let secure_connections_supported = adapter
        .AreLowEnergySecureConnectionsSupported()
        .unwrap_or(false);
    let max_adv_len = adapter.MaxAdvertisementDataLength().unwrap_or(0) as usize;

    let (adapter_name, radio_state, radio_err) = match adapter.GetRadioAsync() {
        Ok(radio_op) => match radio_op.get() {
            Ok(radio) => {
                let name = radio
                    .Name()
                    .map(|n| n.to_string())
                    .unwrap_or_else(|_| "Windows Bluetooth Adapter".to_string());
                let state = radio
                    .State()
                    .map(radio_state_label)
                    .unwrap_or_else(|_| "Unknown".to_string());
                (name, state, None)
            }
            Err(e) => (
                "Windows Bluetooth Adapter".to_string(),
                "Unknown".to_string(),
                Some(format!("Radio query failed: {}", e)),
            ),
        },
        Err(e) => (
            "Windows Bluetooth Adapter".to_string(),
            "Unknown".to_string(),
            Some(format!("GetRadioAsync failed: {}", e)),
        ),
    };

    let detail = if radio_state != "On" {
        format!(
            "Adapter '{}' detected ({}), radio state is {}",
            adapter_name, adapter_address, radio_state
        )
    } else if !ble_supported {
        format!(
            "Adapter '{}' detected ({}), but Bluetooth Low Energy is not supported",
            adapter_name, adapter_address
        )
    } else {
        format!(
            "Adapter '{}' ready ({}) — Central: {}, Peripheral: {}, MaxAdvLen: {}B",
            adapter_name,
            adapter_address,
            if central_supported {
                "Supported"
            } else {
                "Unsupported"
            },
            if peripheral_supported {
                "Supported"
            } else {
                "Unsupported"
            },
            max_adv_len
        )
    };

    BleAdapterSnapshot {
        platform_backend: backend.to_string(),
        adapter_present: true,
        adapter_name,
        adapter_address,
        device_id,
        radio_state,
        ble_supported,
        central_supported,
        peripheral_supported,
        advertisement_offload_supported,
        secure_connections_supported,
        max_advertisement_data_length: max_adv_len,
        diagnostic_detail: detail,
        error_message: radio_err,
    }
}

struct ActiveCentralLink {
    device: BluetoothLEDevice,
    characteristic: GattCharacteristic,
    value_changed_token: EventRegistrationToken,
    mtu: usize,
    write_mode: BleWriteMode,
}

struct PeripheralRuntime {
    provider: GattServiceProvider,
    characteristic: GattLocalCharacteristic,
    companion_publisher: Option<BluetoothLEAdvertisementPublisher>,
    gatt_active: bool,
    companion_active: bool,
    gatt_status_text: String,
    companion_status_text: String,
    last_value: Arc<Mutex<Vec<u8>>>,
}

/// Authoritative native Windows WinRT BLE backend owned by Rust.
pub struct WindowsBleBackend {
    event_tx: mpsc::Sender<BleRuntimeEvent>,
    watcher: Option<BluetoothLEAdvertisementWatcher>,
    watcher_received_token: Option<EventRegistrationToken>,
    watcher_stopped_token: Option<EventRegistrationToken>,
    central_links: HashMap<String, ActiveCentralLink>,
    peripheral: Option<PeripheralRuntime>,
    local_peer_id_hex: String,
}

impl WindowsBleBackend {
    pub fn new(event_tx: mpsc::Sender<BleRuntimeEvent>) -> Self {
        Self {
            event_tx,
            watcher: None,
            watcher_received_token: None,
            watcher_stopped_token: None,
            central_links: HashMap::new(),
            peripheral: None,
            local_peer_id_hex: String::new(),
        }
    }

    pub fn set_identity(&mut self, peer_id_hex: &str) {
        self.local_peer_id_hex = peer_id_hex.trim().to_ascii_lowercase();
    }

    pub fn start_scan(&mut self) -> Result<(), String> {
        if self.watcher.is_some() {
            return Ok(());
        }
        let watcher = BluetoothLEAdvertisementWatcher::new().map_err(|e| {
            format!(
                "Failed creating WinRT BluetoothLEAdvertisementWatcher: {}",
                e
            )
        })?;
        watcher
            .SetScanningMode(BluetoothLEScanningMode::Active)
            .map_err(|e| format!("Failed setting Active BLE scanning mode: {}", e))?;

        let tx_recv = self.event_tx.clone();
        let recv_handler = TypedEventHandler::<
            BluetoothLEAdvertisementWatcher,
            BluetoothLEAdvertisementReceivedEventArgs,
        >::new(move |_sender, args| {
            let Some(args) = args.as_ref() else {
                return Ok(());
            };
            let addr_u64 = args.BluetoothAddress().unwrap_or(0);
            if addr_u64 == 0 {
                return Ok(());
            }
            let rssi = args.RawSignalStrengthInDBm().unwrap_or(-127);
            let Ok(adv) = args.Advertisement() else {
                return Ok(());
            };
            let name = adv.LocalName().map(|n| n.to_string()).unwrap_or_default();

            let mut service_uuids = Vec::new();
            if let Ok(uuids) = adv.ServiceUuids() {
                let count = uuids.Size().unwrap_or(0);
                for idx in 0..count {
                    if let Ok(g) = uuids.GetAt(idx) {
                        service_uuids.push(guid_to_uuid_string(&g));
                    }
                }
            }

            let mut manufacturer_payload: Option<Vec<u8>> = None;
            if let Ok(mfg_list) = adv.ManufacturerData() {
                let count = mfg_list.Size().unwrap_or(0);
                for idx in 0..count {
                    if let Ok(item) = mfg_list.GetAt(idx) {
                        if item.CompanyId().unwrap_or(0) == BITCHAT_MANUFACTURER_ID {
                            if let Ok(buf) = item.Data() {
                                if let Ok(bytes) = ibuffer_to_vec(&buf) {
                                    manufacturer_payload = Some(bytes);
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            let mut service_data_entries: Vec<(String, Vec<u8>)> = Vec::new();
            if let Ok(sections) = adv.DataSections() {
                let count = sections.Size().unwrap_or(0);
                let sd128_type =
                    BluetoothLEAdvertisementDataTypes::ServiceData128BitUuids().unwrap_or(0x21);
                for idx in 0..count {
                    if let Ok(sec) = sections.GetAt(idx) {
                        if sec.DataType().unwrap_or(0) == sd128_type {
                            if let Ok(buf) = sec.Data() {
                                if let Ok(bytes) = ibuffer_to_vec(&buf) {
                                    if bytes.len() >= 16 {
                                        // 128-bit UUID in AD Service Data is little-endian
                                        let mut le_uuid = [0u8; 16];
                                        le_uuid.copy_from_slice(&bytes[..16]);
                                        le_uuid.reverse();
                                        let uuid_u128 = u128::from_be_bytes(le_uuid);
                                        let suuid = guid_to_uuid_string(&guid_from_u128(uuid_u128));
                                        service_data_entries.push((suuid, bytes[16..].to_vec()));
                                    }
                                }
                            }
                        }
                    }
                }
            }

            let matched = match_bitchat_advertisement(
                &service_uuids,
                manufacturer_payload.as_deref(),
                &service_data_entries,
                BITCHAT_SERVICE_UUID_STR,
            );
            if !matched.is_bitchat {
                return Ok(());
            }

            let address = format_bluetooth_address(addr_u64);
            let display_name = if name.is_empty() {
                "BitChat Peer".to_string()
            } else {
                name
            };
            let _ = tx_recv.try_send(BleRuntimeEvent::PeerDiscovered {
                address,
                name: display_name,
                peer_id: matched.peer_id,
                rssi,
                service_uuids,
                matched_by: matched.matched_by.to_string(),
            });
            Ok(())
        });

        let recv_token = watcher
            .Received(&recv_handler)
            .map_err(|e| format!("Failed attaching WinRT watcher Received handler: {}", e))?;

        let tx_stop = self.event_tx.clone();
        let stop_handler = TypedEventHandler::<
            BluetoothLEAdvertisementWatcher,
            BluetoothLEAdvertisementWatcherStoppedEventArgs,
        >::new(move |_sender, args| {
            if let Some(args) = args.as_ref() {
                if let Ok(err) = args.Error() {
                    if err != BluetoothError::Success {
                        let _ = tx_stop.try_send(BleRuntimeEvent::Error {
                            stage: "central_scan".to_string(),
                            message: format!(
                                "Windows BLE scanner stopped unexpectedly (BluetoothError={})",
                                err.0
                            ),
                        });
                    }
                }
            }
            Ok(())
        });

        let stop_token = watcher
            .Stopped(&stop_handler)
            .map_err(|e| format!("Failed attaching WinRT watcher Stopped handler: {}", e))?;

        watcher
            .Start()
            .map_err(|e| format!("Failed starting WinRT BLE scanner: {}", e))?;

        self.watcher = Some(watcher);
        self.watcher_received_token = Some(recv_token);
        self.watcher_stopped_token = Some(stop_token);
        Ok(())
    }

    pub fn stop_scan(&mut self) {
        if let Some(watcher) = self.watcher.take() {
            let _ = watcher.Stop();
            if let Some(tok) = self.watcher_received_token.take() {
                let _ = watcher.RemoveReceived(tok);
            }
            if let Some(tok) = self.watcher_stopped_token.take() {
                let _ = watcher.RemoveStopped(tok);
            }
        }
    }

    pub fn is_scanning(&self) -> bool {
        self.watcher.is_some()
    }

    pub fn connect_peer(&mut self, address: &str) -> Result<(usize, BleWriteMode), String> {
        let addr_norm = address.trim().to_ascii_uppercase();
        if let Some(existing) = self.central_links.get(&addr_norm) {
            return Ok((existing.mtu, existing.write_mode));
        }

        let addr_u64 = parse_bluetooth_address(&addr_norm)?;
        let device = BluetoothLEDevice::FromBluetoothAddressAsync(addr_u64)
            .map_err(|e| format!("FromBluetoothAddressAsync failed: {}", e))?
            .get()
            .map_err(|e| format!("Failed connecting to BLE device {}: {}", addr_norm, e))?;

        let service_guid = guid_from_u128(BITCHAT_SERVICE_UUID_U128);
        let svc_result = device
            .GetGattServicesForUuidAsync(service_guid)
            .map_err(|e| format!("GetGattServicesForUuidAsync failed: {}", e))?
            .get()
            .map_err(|e| format!("GATT service discovery failed for {}: {}", addr_norm, e))?;

        if svc_result.Status().ok() != Some(GattCommunicationStatus::Success) {
            return Err(format!(
                "GATT service discovery returned status {:?} for {}",
                svc_result.Status().ok(),
                addr_norm
            ));
        }
        let services = svc_result
            .Services()
            .map_err(|e| format!("Failed reading discovered GATT services: {}", e))?;
        if services.Size().unwrap_or(0) == 0 {
            return Err(format!(
                "BitChat GATT service {} not found on {}",
                BITCHAT_SERVICE_UUID_STR, addr_norm
            ));
        }
        let service = services
            .GetAt(0)
            .map_err(|e| format!("Failed accessing GATT service 0: {}", e))?;

        let char_guid = guid_from_u128(BITCHAT_CHARACTERISTIC_UUID_U128);
        let char_result = service
            .GetCharacteristicsForUuidAsync(char_guid)
            .map_err(|e| format!("GetCharacteristicsForUuidAsync failed: {}", e))?
            .get()
            .map_err(|e| {
                format!(
                    "GATT characteristic discovery failed for {}: {}",
                    addr_norm, e
                )
            })?;
        if char_result.Status().ok() != Some(GattCommunicationStatus::Success) {
            return Err(format!(
                "GATT characteristic discovery returned status {:?} for {}",
                char_result.Status().ok(),
                addr_norm
            ));
        }
        let chars = char_result
            .Characteristics()
            .map_err(|e| format!("Failed reading GATT characteristics: {}", e))?;
        if chars.Size().unwrap_or(0) == 0 {
            return Err(format!(
                "BitChat GATT characteristic {} not found on {}",
                BITCHAT_CHARACTERISTIC_UUID_STR, addr_norm
            ));
        }
        let characteristic = chars
            .GetAt(0)
            .map_err(|e| format!("Failed accessing GATT characteristic 0: {}", e))?;

        let props = characteristic
            .CharacteristicProperties()
            .map_err(|e| format!("Failed querying characteristic properties: {}", e))?;
        let prop_names = gatt_props_to_strings(props);
        let write_mode = validate_gatt_characteristic(
            BITCHAT_CHARACTERISTIC_UUID_STR,
            &prop_names,
            Some(BITCHAT_CHARACTERISTIC_UUID_STR),
        )?;

        // Query negotiated ATT MTU via GattSession when available.
        let mut mtu = DEFAULT_BLE_MTU;
        if let Ok(dev_id) = device.BluetoothDeviceId() {
            if let Ok(session_op) = GattSession::FromDeviceIdAsync(&dev_id) {
                if let Ok(session) = session_op.get() {
                    if let Ok(pdu) = session.MaxPduSize() {
                        mtu = (pdu as usize).max(MIN_BLE_MTU);
                    }
                }
            }
        }

        // Attach ValueChanged handler BEFORE writing CCCD so early notifications are never missed.
        let tx_notify = self.event_tx.clone();
        let addr_for_cb = addr_norm.clone();
        let value_handler = TypedEventHandler::<GattCharacteristic, GattValueChangedEventArgs>::new(
            move |_sender, args| {
                let Some(args) = args.as_ref() else {
                    return Ok(());
                };
                if let Ok(buf) = args.CharacteristicValue() {
                    if let Ok(bytes) = ibuffer_to_vec(&buf) {
                        if !bytes.is_empty() {
                            let _ = tx_notify.try_send(BleRuntimeEvent::NotificationReceived {
                                address: addr_for_cb.clone(),
                                payload: bytes,
                            });
                        }
                    }
                }
                Ok(())
            },
        );
        let value_changed_token = characteristic
            .ValueChanged(&value_handler)
            .map_err(|e| format!("Failed attaching ValueChanged handler: {}", e))?;

        let cccd_status = characteristic
            .WriteClientCharacteristicConfigurationDescriptorAsync(
                GattClientCharacteristicConfigurationDescriptorValue::Notify,
            )
            .map_err(|e| format!("Failed starting CCCD Notify write: {}", e))?
            .get()
            .map_err(|e| format!("CCCD Notify subscription failed: {}", e))?;
        if cccd_status != GattCommunicationStatus::Success {
            let _ = characteristic.RemoveValueChanged(value_changed_token);
            return Err(format!(
                "CCCD Notify subscription rejected with status {:?} on {}",
                cccd_status, addr_norm
            ));
        }

        self.central_links.insert(
            addr_norm.clone(),
            ActiveCentralLink {
                device,
                characteristic,
                value_changed_token,
                mtu,
                write_mode,
            },
        );
        let _ = self.event_tx.try_send(BleRuntimeEvent::PeerConnected {
            address: addr_norm,
            mtu,
            write_mode: write_mode.as_str().to_string(),
        });
        Ok((mtu, write_mode))
    }

    pub fn disconnect_peer(&mut self, address: &str) {
        let addr_norm = address.trim().to_ascii_uppercase();
        if let Some(link) = self.central_links.remove(&addr_norm) {
            let _ = link
                .characteristic
                .RemoveValueChanged(link.value_changed_token);
            let _ = link
                .characteristic
                .WriteClientCharacteristicConfigurationDescriptorAsync(
                    GattClientCharacteristicConfigurationDescriptorValue::None,
                );
            drop(link.device);
            let _ = self.event_tx.try_send(BleRuntimeEvent::PeerDisconnected {
                address: addr_norm,
                reason: "disconnected".to_string(),
            });
        }
    }

    pub fn write_peer(&self, address: &str, data: &[u8]) -> Result<(), String> {
        let addr_norm = address.trim().to_ascii_uppercase();
        let link = self
            .central_links
            .get(&addr_norm)
            .ok_or_else(|| format!("Peer {} is not connected via native WinRT GATT", addr_norm))?;
        let buffer = slice_to_ibuffer(data)?;
        let option = match link.write_mode {
            BleWriteMode::WriteWithoutResponse => GattWriteOption::WriteWithoutResponse,
            BleWriteMode::WriteWithResponse => GattWriteOption::WriteWithResponse,
        };
        let result = link
            .characteristic
            .WriteValueWithResultAndOptionAsync(&buffer, option)
            .map_err(|e| format!("WriteValueWithResultAndOptionAsync failed: {}", e))?
            .get()
            .map_err(|e| format!("GATT write failed for {}: {}", addr_norm, e))?;
        if result.Status().ok() != Some(GattCommunicationStatus::Success) {
            return Err(format!(
                "GATT write returned status {:?} for {}",
                result.Status().ok(),
                addr_norm
            ));
        }
        Ok(())
    }

    /// Start native Windows WinRT GATT Peripheral server AND decoupled optional
    /// companion manufacturer advertisement.
    ///
    /// Returns `(gatt_active, companion_active, gatt_status_text, companion_status_text)`.
    pub fn start_peripheral(&mut self) -> Result<(bool, bool, String, String), String> {
        if let Some(p) = &self.peripheral {
            return Ok((
                p.gatt_active,
                p.companion_active,
                p.gatt_status_text.clone(),
                p.companion_status_text.clone(),
            ));
        }

        let service_guid = guid_from_u128(BITCHAT_SERVICE_UUID_U128);
        let create_result = GattServiceProvider::CreateAsync(service_guid)
            .map_err(|e| format!("GattServiceProvider::CreateAsync failed: {}", e))?
            .get()
            .map_err(|e| format!("GattServiceProvider creation error: {}", e))?;

        let err_code = create_result
            .Error()
            .map_err(|e| format!("Failed checking GattServiceProvider error: {}", e))?;
        if err_code != BluetoothError::Success {
            return Err(format!(
                "GattServiceProvider creation rejected (BluetoothError={})",
                err_code.0
            ));
        }
        let provider = create_result
            .ServiceProvider()
            .map_err(|e| format!("Failed retrieving GattServiceProvider: {}", e))?;
        let service = provider
            .Service()
            .map_err(|e| format!("Failed retrieving GattLocalService: {}", e))?;

        let params = GattLocalCharacteristicParameters::new()
            .map_err(|e| format!("Failed creating GattLocalCharacteristicParameters: {}", e))?;
        let props = GattCharacteristicProperties::Read
            | GattCharacteristicProperties::Write
            | GattCharacteristicProperties::WriteWithoutResponse
            | GattCharacteristicProperties::Notify;
        params
            .SetCharacteristicProperties(props)
            .map_err(|e| format!("Failed setting characteristic properties: {}", e))?;
        params
            .SetReadProtectionLevel(GattProtectionLevel::Plain)
            .map_err(|e| format!("Failed setting read protection level: {}", e))?;
        params
            .SetWriteProtectionLevel(GattProtectionLevel::Plain)
            .map_err(|e| format!("Failed setting write protection level: {}", e))?;

        let char_guid = guid_from_u128(BITCHAT_CHARACTERISTIC_UUID_U128);
        let char_result = service
            .CreateCharacteristicAsync(char_guid, &params)
            .map_err(|e| format!("CreateCharacteristicAsync failed: {}", e))?
            .get()
            .map_err(|e| format!("Failed creating GattLocalCharacteristic: {}", e))?;
        if char_result.Error().ok() != Some(BluetoothError::Success) {
            return Err(format!(
                "CreateCharacteristicAsync rejected (BluetoothError={:?})",
                char_result.Error().ok()
            ));
        }
        let characteristic = char_result
            .Characteristic()
            .map_err(|e| format!("Failed accessing GattLocalCharacteristic: {}", e))?;

        let last_value = Arc::new(Mutex::new(Vec::<u8>::new()));

        // Attach WriteRequested handler
        let tx_write = self.event_tx.clone();
        let last_val_w = Arc::clone(&last_value);
        let write_handler =
            TypedEventHandler::<GattLocalCharacteristic, GattWriteRequestedEventArgs>::new(
                move |_sender, args| {
                    let Some(args) = args.as_ref() else {
                        return Ok(());
                    };
                    let deferral = args.GetDeferral().ok();
                    let client_id = args
                        .Session()
                        .ok()
                        .and_then(|s| s.DeviceId().ok())
                        .and_then(|d| d.Id().ok())
                        .map(|h| h.to_string())
                        .unwrap_or_else(|| "winrt_client".to_string());
                    if let Ok(req_op) = args.GetRequestAsync() {
                        if let Ok(req) = req_op.get() {
                            if let Ok(buf) = req.Value() {
                                if let Ok(bytes) = ibuffer_to_vec(&buf) {
                                    if let Ok(mut guard) = last_val_w.lock() {
                                        *guard = bytes.clone();
                                    }
                                    if !bytes.is_empty() {
                                        let _ = tx_write.try_send(
                                            BleRuntimeEvent::ServerWriteReceived {
                                                client_id,
                                                payload: bytes,
                                            },
                                        );
                                    }
                                }
                            }
                            if req.Option().ok() == Some(GattWriteOption::WriteWithResponse) {
                                let _ = req.Respond();
                            }
                        }
                    }
                    if let Some(d) = deferral {
                        let _ = d.Complete();
                    }
                    Ok(())
                },
            );
        let _ = characteristic.WriteRequested(&write_handler);

        // Attach ReadRequested handler
        let last_val_r = Arc::clone(&last_value);
        let read_handler =
            TypedEventHandler::<GattLocalCharacteristic, GattReadRequestedEventArgs>::new(
                move |_sender, args| {
                    let Some(args) = args.as_ref() else {
                        return Ok(());
                    };
                    let deferral = args.GetDeferral().ok();
                    if let Ok(req_op) = args.GetRequestAsync() {
                        if let Ok(req) = req_op.get() {
                            let bytes = last_val_r.lock().map(|g| g.clone()).unwrap_or_default();
                            if let Ok(buf) = slice_to_ibuffer(&bytes) {
                                let _ = req.RespondWithValue(&buf);
                            }
                        }
                    }
                    if let Some(d) = deferral {
                        let _ = d.Complete();
                    }
                    Ok(())
                },
            );
        let _ = characteristic.ReadRequested(&read_handler);

        // Attach SubscribedClientsChanged handler
        let tx_sub = self.event_tx.clone();
        let sub_handler =
            TypedEventHandler::<GattLocalCharacteristic, windows::core::IInspectable>::new(
                move |sender, _args| {
                    if let Some(ch) = sender.as_ref() {
                        if let Ok(clients) = ch.SubscribedClients() {
                            let count = clients.Size().unwrap_or(0);
                            for idx in 0..count {
                                if let Ok(client) = clients.GetAt(idx) {
                                    let cid = client
                                        .Session()
                                        .ok()
                                        .and_then(|s| s.DeviceId().ok())
                                        .and_then(|d| d.Id().ok())
                                        .map(|h| h.to_string())
                                        .unwrap_or_else(|| format!("winrt_client_{}", idx));
                                    let _ =
                                        tx_sub.try_send(BleRuntimeEvent::ServerClientSubscribed {
                                            client_id: cid,
                                        });
                                }
                            }
                        }
                    }
                    Ok(())
                },
            );
        let _ = characteristic.SubscribedClientsChanged(&sub_handler);

        // Attach AdvertisementStatusChanged handler
        let tx_adv = self.event_tx.clone();
        let adv_status_handler = TypedEventHandler::<
            GattServiceProvider,
            GattServiceProviderAdvertisementStatusChangedEventArgs,
        >::new(move |_sender, args| {
            if let Some(args) = args.as_ref() {
                if let Ok(status) = args.Status() {
                    let active = matches!(
                        status,
                        GattServiceProviderAdvertisementStatus::Started
                            | GattServiceProviderAdvertisementStatus::StartedWithoutAllAdvertisementData
                    );
                    let _ = tx_adv.try_send(BleRuntimeEvent::AdvertisingStateChanged {
                        gatt_active: active,
                        companion_active: false,
                        status_text: gatt_adv_status_label(status),
                    });
                }
            }
            Ok(())
        });
        let _ = provider.AdvertisementStatusChanged(&adv_status_handler);

        let adv_params = GattServiceProviderAdvertisingParameters::new()
            .map_err(|e| format!("Failed creating GATT advertising params: {}", e))?;
        adv_params
            .SetIsDiscoverable(true)
            .map_err(|e| format!("Failed setting IsDiscoverable: {}", e))?;
        adv_params
            .SetIsConnectable(true)
            .map_err(|e| format!("Failed setting IsConnectable: {}", e))?;

        provider
            .StartAdvertisingWithParameters(&adv_params)
            .map_err(|e| format!("GattServiceProvider::StartAdvertising failed: {}", e))?;

        // Poll up to 400ms for WinRT asynchronous Created(0)/Stopped(1) -> Started(2)/Aborted(3) transition.
        let mut gatt_status = provider
            .AdvertisementStatus()
            .unwrap_or(GattServiceProviderAdvertisementStatus::Stopped);
        for _ in 0..40 {
            if !matches!(
                gatt_status,
                GattServiceProviderAdvertisementStatus::Created
                    | GattServiceProviderAdvertisementStatus::Stopped
            ) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
            gatt_status = provider
                .AdvertisementStatus()
                .unwrap_or(GattServiceProviderAdvertisementStatus::Stopped);
        }
        let gatt_status_text = gatt_adv_status_label(gatt_status);
        let gatt_active = matches!(
            gatt_status,
            GattServiceProviderAdvertisementStatus::Started
                | GattServiceProviderAdvertisementStatus::StartedWithoutAllAdvertisementData
        );

        if !gatt_active {
            let _ = provider.StopAdvertising();
            return Err(format!(
                "Windows GATT Service Provider failed to advertise: {}",
                gatt_status_text
            ));
        }

        // Decoupled OPTIONAL companion manufacturer advertisement publisher.
        // If this fails (e.g. Windows Aborted / status 5 or advertisement slot limit),
        // clean up ONLY the companion publisher and KEEP the active GattServiceProvider!
        let (companion_publisher, companion_active, companion_status_text) =
            self.try_start_companion_publisher();

        self.peripheral = Some(PeripheralRuntime {
            provider,
            characteristic,
            companion_publisher,
            gatt_active,
            companion_active,
            gatt_status_text: gatt_status_text.clone(),
            companion_status_text: companion_status_text.clone(),
            last_value,
        });

        Ok((
            gatt_active,
            companion_active,
            gatt_status_text,
            companion_status_text,
        ))
    }

    fn try_start_companion_publisher(
        &self,
    ) -> (Option<BluetoothLEAdvertisementPublisher>, bool, String) {
        let peer_bytes: Option<Vec<u8>> = if self.local_peer_id_hex.len() == 16 {
            (0..8)
                .map(|i| u8::from_str_radix(&self.local_peer_id_hex[i * 2..i * 2 + 2], 16).ok())
                .collect()
        } else {
            None
        };
        let payload = match encode_ble_manufacturer_payload(
            &bitchat_service_uuid_bytes(),
            peer_bytes.as_deref(),
        ) {
            Ok(p) => p,
            Err(e) => {
                return (
                    None,
                    false,
                    format!("Unavailable (payload encode error: {})", e),
                );
            }
        };

        let adv = match BluetoothLEAdvertisement::new() {
            Ok(a) => a,
            Err(e) => {
                return (
                    None,
                    false,
                    format!("Inactive (BluetoothLEAdvertisement::new failed: {})", e),
                );
            }
        };

        let mfg = match BluetoothLEManufacturerData::new() {
            Ok(m) => m,
            Err(e) => {
                return (
                    None,
                    false,
                    format!("Inactive (ManufacturerData init failed: {})", e),
                );
            }
        };
        if let Err(e) = mfg.SetCompanyId(BITCHAT_MANUFACTURER_ID) {
            return (
                None,
                false,
                format!("Inactive (SetCompanyId failed: {})", e),
            );
        }
        let buf = match slice_to_ibuffer(&payload) {
            Ok(b) => b,
            Err(e) => {
                return (None, false, format!("Inactive ({})", e));
            }
        };
        if let Err(e) = mfg.SetData(&buf) {
            return (None, false, format!("Inactive (SetData failed: {})", e));
        }
        if let Ok(mfg_list) = adv.ManufacturerData() {
            let _ = mfg_list.Append(&mfg);
        }

        // Also include local name hint safely if short enough
        let _ = adv.SetLocalName(&HSTRING::from("BitChat"));
        let _ = BluetoothLEAdvertisementDataSection::new();

        let publisher = match BluetoothLEAdvertisementPublisher::Create(&adv) {
            Ok(p) => p,
            Err(e) => {
                return (
                    None,
                    false,
                    format!(
                        "Failed (Publisher::Create error: {} — GATT service remains active)",
                        e
                    ),
                );
            }
        };

        if let Err(e) = publisher.Start() {
            let _ = publisher.Stop();
            return (
                None,
                false,
                format!(
                    "Failed (Publisher::Start error: {} — GATT service remains active)",
                    e
                ),
            );
        }

        let mut pub_status = publisher
            .Status()
            .unwrap_or(BluetoothLEAdvertisementPublisherStatus::Stopped);
        for _ in 0..40 {
            if !matches!(
                pub_status,
                BluetoothLEAdvertisementPublisherStatus::Created
                    | BluetoothLEAdvertisementPublisherStatus::Waiting
            ) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
            pub_status = publisher
                .Status()
                .unwrap_or(BluetoothLEAdvertisementPublisherStatus::Stopped);
        }
        let label = publisher_status_label(pub_status);
        let active = pub_status == BluetoothLEAdvertisementPublisherStatus::Started;
        if !active {
            let _ = publisher.Stop();
            return (
                None,
                false,
                format!("{} — GATT service remains active", label),
            );
        }

        (Some(publisher), true, label)
    }

    pub fn notify_clients(&self, data: &[u8]) -> Result<usize, String> {
        let p = self
            .peripheral
            .as_ref()
            .ok_or_else(|| "Windows GATT Peripheral server is not running".to_string())?;
        if let Ok(mut guard) = p.last_value.lock() {
            *guard = data.to_vec();
        }
        let buf = slice_to_ibuffer(data)?;
        let results = p
            .characteristic
            .NotifyValueAsync(&buf)
            .map_err(|e| format!("NotifyValueAsync failed: {}", e))?
            .get()
            .map_err(|e| format!("GATT notification delivery error: {}", e))?;
        let count = results.Size().unwrap_or(0) as usize;
        Ok(count)
    }

    pub fn stop_peripheral(&mut self) {
        if let Some(p) = self.peripheral.take() {
            if let Some(pub_) = p.companion_publisher {
                let _ = pub_.Stop();
            }
            let _ = p.provider.StopAdvertising();
        }
    }

    pub fn peripheral_status(&self) -> (bool, bool, String, String) {
        if let Some(p) = &self.peripheral {
            let live_gatt_status = p
                .provider
                .AdvertisementStatus()
                .map(gatt_adv_status_label)
                .unwrap_or_else(|_| p.gatt_status_text.clone());
            let live_gatt_active = p
                .provider
                .AdvertisementStatus()
                .map(|s| {
                    matches!(
                        s,
                        GattServiceProviderAdvertisementStatus::Started
                            | GattServiceProviderAdvertisementStatus::StartedWithoutAllAdvertisementData
                    )
                })
                .unwrap_or(p.gatt_active);
            (
                live_gatt_active,
                p.companion_active,
                live_gatt_status,
                p.companion_status_text.clone(),
            )
        } else {
            (false, false, "Stopped".to_string(), "Inactive".to_string())
        }
    }

    pub fn shutdown(&mut self) {
        self.stop_scan();
        let addrs: Vec<String> = self.central_links.keys().cloned().collect();
        for addr in addrs {
            self.disconnect_peer(&addr);
        }
        self.stop_peripheral();
    }
}
