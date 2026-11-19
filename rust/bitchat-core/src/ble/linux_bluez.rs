//! Native Linux BlueZ D-Bus BLE backend (`#[cfg(target_os = "linux")]`).
//!
//! Uses pure-Rust `zbus` over the system D-Bus (`org.bluez`) to provide:
//! - Truthful BlueZ adapter discovery & capability probing (`Adapter1`,
//!   `GattManager1`, `LEAdvertisingManager1`)
//! - Native BlueZ LE central discovery & device filtering
//! - Native BlueZ GATT client (`Device1.Connect`, `GattCharacteristic1.StartNotify`,
//!   `WriteValue`, `PropertiesChanged`)
//! - Native BlueZ GATT peripheral application (`ObjectManager`, `GattService1`,
//!   `GattCharacteristic1`) and `LEAdvertisement1` registration with clean
//!   unregistration and decoupled GATT retention if manufacturer data is rejected.

#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};
use zbus::{interface, Connection, Proxy};

use crate::ble::advertisement::{
    bitchat_service_uuid_bytes, encode_ble_manufacturer_payload, match_bitchat_advertisement,
    uuids_match, validate_gatt_characteristic,
};
use crate::ble::types::{
    BleAdapterSnapshot, BleRuntimeEvent, BleWriteMode, BITCHAT_CHARACTERISTIC_UUID_STR,
    BITCHAT_MANUFACTURER_ID, BITCHAT_SERVICE_UUID_STR, DEFAULT_BLE_MTU,
};

type InterfaceMap = HashMap<String, HashMap<String, OwnedValue>>;
type ManagedObjects = HashMap<OwnedObjectPath, InterfaceMap>;

static BLUEZ_OBJ_COUNTER: AtomicU64 = AtomicU64::new(1);

fn next_bluez_obj_id() -> u64 {
    BLUEZ_OBJ_COUNTER.fetch_add(1, Ordering::Relaxed)
}

fn owned_val_bool(map: &HashMap<String, OwnedValue>, key: &str, default: bool) -> bool {
    map.get(key)
        .and_then(|v| bool::try_from(v).ok())
        .unwrap_or(default)
}

fn owned_val_string(map: &HashMap<String, OwnedValue>, key: &str) -> Option<String> {
    map.get(key).and_then(|v| match &**v {
        Value::Str(s) => Some(s.to_string()),
        Value::ObjectPath(p) => Some(p.as_str().to_string()),
        _ => None,
    })
}

async fn get_managed_objects(conn: &Connection) -> Result<ManagedObjects, String> {
    let proxy = Proxy::new(conn, "org.bluez", "/", "org.freedesktop.DBus.ObjectManager")
        .await
        .map_err(|e| format!("Failed creating BlueZ ObjectManager proxy: {}", e))?;

    proxy
        .call("GetManagedObjects", &())
        .await
        .map_err(|e| format!("BlueZ GetManagedObjects failed: {}", e))
}

/// Probe Linux BlueZ adapters and capabilities directly over system D-Bus.
pub async fn probe_linux_adapter_async() -> BleAdapterSnapshot {
    let backend = "Linux BlueZ D-Bus (Rust native zbus)";
    let conn = match Connection::system().await {
        Ok(c) => c,
        Err(e) => {
            return BleAdapterSnapshot::unavailable(
                backend,
                format!("Failed to connect to Linux system D-Bus: {}", e),
            );
        }
    };

    let objects = match get_managed_objects(&conn).await {
        Ok(o) => o,
        Err(e) => {
            return BleAdapterSnapshot::unavailable(
                backend,
                format!("BlueZ daemon unreachable or permission denied: {}", e),
            );
        }
    };

    let mut adapters: Vec<(String, &InterfaceMap)> = objects
        .iter()
        .filter(|(_, ifaces)| ifaces.contains_key("org.bluez.Adapter1"))
        .map(|(path, ifaces)| (path.as_str().to_string(), ifaces))
        .collect();
    adapters.sort_by(|a, b| a.0.cmp(&b.0));

    if adapters.is_empty() {
        return BleAdapterSnapshot::unavailable(backend, "No Bluetooth adapter found in BlueZ");
    }

    // Prefer first powered adapter; fall back to first adapter overall.
    let (adapter_path, ifaces) = adapters
        .iter()
        .find(|(_, ifaces)| {
            ifaces
                .get("org.bluez.Adapter1")
                .map(|p| owned_val_bool(p, "Powered", false))
                .unwrap_or(false)
        })
        .cloned()
        .unwrap_or_else(|| adapters[0].clone());

    let adapter_props = ifaces.get("org.bluez.Adapter1");
    let powered = adapter_props
        .map(|p| owned_val_bool(p, "Powered", false))
        .unwrap_or(false);
    let address = adapter_props
        .and_then(|p| owned_val_string(p, "Address"))
        .unwrap_or_else(|| "Unavailable".to_string());
    let name = adapter_props
        .and_then(|p| owned_val_string(p, "Alias").or_else(|| owned_val_string(p, "Name")))
        .unwrap_or_else(|| adapter_path.clone());

    let has_gatt_mgr = ifaces.contains_key("org.bluez.GattManager1");
    let has_adv_mgr = ifaces.contains_key("org.bluez.LEAdvertisingManager1");
    let peripheral_supported = has_gatt_mgr && has_adv_mgr;

    let radio_state = if powered {
        "On".to_string()
    } else {
        "Off".to_string()
    };

    let detail = if !powered {
        format!(
            "BlueZ adapter '{}' ({}) at {} is powered off",
            name, address, adapter_path
        )
    } else {
        format!(
            "BlueZ adapter '{}' ({}) at {} ready — GattManager1: {}, LEAdvertisingManager1: {}",
            name,
            address,
            adapter_path,
            if has_gatt_mgr { "Yes" } else { "No" },
            if has_adv_mgr { "Yes" } else { "No" }
        )
    };

    BleAdapterSnapshot {
        platform_backend: backend.to_string(),
        adapter_present: true,
        adapter_name: name,
        adapter_address: address,
        device_id: adapter_path,
        radio_state,
        ble_supported: true,
        central_supported: true,
        peripheral_supported,
        advertisement_offload_supported: has_adv_mgr,
        secure_connections_supported: true,
        max_advertisement_data_length: 31,
        diagnostic_detail: detail,
        error_message: if powered {
            None
        } else {
            Some("Bluetooth adapter is powered off".to_string())
        },
    }
}

// ---------------------------------------------------------------------------
// Exported BlueZ Peripheral D-Bus Objects
// ---------------------------------------------------------------------------

struct BluezGattServiceIface {
    uuid: String,
    char_path: OwnedObjectPath,
}

#[interface(name = "org.bluez.GattService1")]
impl BluezGattServiceIface {
    #[zbus(property, name = "UUID")]
    fn uuid(&self) -> String {
        self.uuid.clone()
    }

    #[zbus(property, name = "Primary")]
    fn primary(&self) -> bool {
        true
    }

    #[zbus(property, name = "Characteristics")]
    fn characteristics(&self) -> Vec<OwnedObjectPath> {
        vec![self.char_path.clone()]
    }
}

struct BluezGattCharacteristicIface {
    uuid: String,
    service_path: OwnedObjectPath,
    value: Arc<Mutex<Vec<u8>>>,
    notifying: Arc<Mutex<bool>>,
    event_tx: mpsc::Sender<BleRuntimeEvent>,
}

#[interface(name = "org.bluez.GattCharacteristic1")]
impl BluezGattCharacteristicIface {
    #[zbus(property, name = "UUID")]
    fn uuid(&self) -> String {
        self.uuid.clone()
    }

    #[zbus(property, name = "Service")]
    fn service(&self) -> OwnedObjectPath {
        self.service_path.clone()
    }

    #[zbus(property, name = "Flags")]
    fn flags(&self) -> Vec<String> {
        vec![
            "read".to_string(),
            "write".to_string(),
            "write-without-response".to_string(),
            "notify".to_string(),
        ]
    }

    #[zbus(property, name = "Value")]
    fn value(&self) -> Vec<u8> {
        self.value.lock().map(|g| g.clone()).unwrap_or_default()
    }

    #[zbus(property, name = "Notifying")]
    fn notifying(&self) -> bool {
        self.notifying.lock().map(|g| *g).unwrap_or(false)
    }

    fn read_value(&self, _options: HashMap<String, OwnedValue>) -> Vec<u8> {
        self.value.lock().map(|g| g.clone()).unwrap_or_default()
    }

    fn write_value(&self, value: Vec<u8>, options: HashMap<String, OwnedValue>) {
        if let Ok(mut guard) = self.value.lock() {
            *guard = value.clone();
        }
        let client_id = owned_val_string(&options, "device")
            .map(|dev_path| {
                let tail = dev_path.rsplit('/').next().unwrap_or("bluez_client");
                if let Some(stripped) = tail.strip_prefix("dev_") {
                    stripped.replace('_', ":")
                } else {
                    tail.to_string()
                }
            })
            .unwrap_or_else(|| "bluez_client".to_string());
        if !value.is_empty() {
            let _ = self
                .event_tx
                .try_send(BleRuntimeEvent::ServerWriteReceived {
                    client_id,
                    payload: value,
                });
        }
    }

    fn start_notify(&self) {
        if let Ok(mut guard) = self.notifying.lock() {
            *guard = true;
        }
        let _ = self
            .event_tx
            .try_send(BleRuntimeEvent::ServerClientSubscribed {
                client_id: "bluez_client".to_string(),
            });
    }

    fn stop_notify(&self) {
        if let Ok(mut guard) = self.notifying.lock() {
            *guard = false;
        }
        let _ = self
            .event_tx
            .try_send(BleRuntimeEvent::ServerClientUnsubscribed {
                client_id: "bluez_client".to_string(),
            });
    }
}

struct BluezAdvertisementIface {
    service_uuid: String,
    include_mfg: bool,
    peer_id_hex: String,
    event_tx: mpsc::Sender<BleRuntimeEvent>,
}

#[interface(name = "org.bluez.LEAdvertisement1")]
impl BluezAdvertisementIface {
    #[zbus(property, name = "Type")]
    fn adv_type(&self) -> String {
        "peripheral".to_string()
    }

    #[zbus(property, name = "ServiceUUIDs")]
    fn service_uuids(&self) -> Vec<String> {
        vec![self.service_uuid.clone()]
    }

    #[zbus(property, name = "Discoverable")]
    fn discoverable(&self) -> bool {
        true
    }

    #[zbus(property, name = "ManufacturerData")]
    fn manufacturer_data(&self) -> HashMap<u16, OwnedValue> {
        let mut out = HashMap::new();
        if !self.include_mfg {
            return out;
        }
        let peer_bytes: Option<Vec<u8>> = if self.peer_id_hex.len() == 16 {
            (0..8)
                .map(|i| u8::from_str_radix(&self.peer_id_hex[i * 2..i * 2 + 2], 16).ok())
                .collect()
        } else {
            None
        };
        if let Ok(payload) =
            encode_ble_manufacturer_payload(&bitchat_service_uuid_bytes(), peer_bytes.as_deref())
        {
            if let Ok(val) = OwnedValue::try_from(Value::from(payload)) {
                out.insert(BITCHAT_MANUFACTURER_ID, val);
            }
        }
        out
    }

    fn release(&self) {
        let _ = self
            .event_tx
            .try_send(BleRuntimeEvent::AdvertisingStateChanged {
                gatt_active: true,
                companion_active: false,
                status_text: "Released by BlueZ daemon".to_string(),
            });
    }
}

struct BluezCentralLink {
    device_path: String,
    char_path: String,
    mtu: usize,
    write_mode: BleWriteMode,
}

/// Authoritative Linux BlueZ native Rust BLE backend.
pub struct LinuxBluezBackend {
    event_tx: mpsc::Sender<BleRuntimeEvent>,
    conn: Option<Connection>,
    adapter_path: Option<String>,
    scanning: bool,
    central_links: HashMap<String, BluezCentralLink>,
    app_path: Option<String>,
    service_path: Option<String>,
    char_path: Option<String>,
    adv_path: Option<String>,
    gatt_active: bool,
    adv_active: bool,
    gatt_status_text: String,
    adv_status_text: String,
    local_peer_id_hex: String,
    char_value: Arc<Mutex<Vec<u8>>>,
}

impl LinuxBluezBackend {
    pub fn new(event_tx: mpsc::Sender<BleRuntimeEvent>) -> Self {
        Self {
            event_tx,
            conn: None,
            adapter_path: None,
            scanning: false,
            central_links: HashMap::new(),
            app_path: None,
            service_path: None,
            char_path: None,
            adv_path: None,
            gatt_active: false,
            adv_active: false,
            gatt_status_text: "Stopped".to_string(),
            adv_status_text: "Inactive".to_string(),
            local_peer_id_hex: String::new(),
            char_value: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn set_identity(&mut self, peer_id_hex: &str) {
        self.local_peer_id_hex = peer_id_hex.trim().to_ascii_lowercase();
    }

    async fn ensure_connection(&mut self) -> Result<(Connection, String), String> {
        if let (Some(c), Some(ap)) = (&self.conn, &self.adapter_path) {
            return Ok((c.clone(), ap.clone()));
        }
        let snap = probe_linux_adapter_async().await;
        if !snap.adapter_present {
            return Err(snap
                .error_message
                .unwrap_or_else(|| "No BlueZ adapter available".to_string()));
        }
        if snap.radio_state != "On" {
            return Err(format!("BlueZ adapter {} is powered off", snap.device_id));
        }
        let conn = Connection::system()
            .await
            .map_err(|e| format!("Failed connecting to D-Bus system bus: {}", e))?;
        self.conn = Some(conn.clone());
        self.adapter_path = Some(snap.device_id.clone());
        Ok((conn, snap.device_id))
    }

    pub async fn start_scan(&mut self) -> Result<(), String> {
        if self.scanning {
            return Ok(());
        }
        let (conn, adapter_path) = self.ensure_connection().await?;
        let adapter = Proxy::new(
            &conn,
            "org.bluez",
            adapter_path.as_str(),
            "org.bluez.Adapter1",
        )
        .await
        .map_err(|e| format!("Failed creating Adapter1 proxy: {}", e))?;

        let mut filter: HashMap<&str, Value<'_>> = HashMap::new();
        filter.insert("Transport", Value::from("le"));
        let _ = adapter
            .call::<_, _, ()>("SetDiscoveryFilter", &(filter,))
            .await;

        adapter
            .call::<_, _, ()>("StartDiscovery", &())
            .await
            .map_err(|e| format!("BlueZ StartDiscovery failed: {}", e))?;
        self.scanning = true;

        // Immediately inspect known BlueZ devices for BitChat service UUIDs.
        if let Ok(objects) = get_managed_objects(&conn).await {
            for (_path, ifaces) in objects {
                if let Some(dev) = ifaces.get("org.bluez.Device1") {
                    let addr = owned_val_string(dev, "Address").unwrap_or_default();
                    if addr.is_empty() {
                        continue;
                    }
                    let name = owned_val_string(dev, "Alias")
                        .or_else(|| owned_val_string(dev, "Name"))
                        .unwrap_or_else(|| "BitChat Peer".to_string());
                    let rssi = dev
                        .get("RSSI")
                        .and_then(|v| i16::try_from(v).ok())
                        .unwrap_or(-60);
                    let uuids: Vec<String> = dev
                        .get("UUIDs")
                        .and_then(|v| Vec::<String>::try_from(v.clone()).ok())
                        .unwrap_or_default();
                    let matched =
                        match_bitchat_advertisement(&uuids, None, &[], BITCHAT_SERVICE_UUID_STR);
                    if matched.is_bitchat {
                        let _ = self.event_tx.try_send(BleRuntimeEvent::PeerDiscovered {
                            address: addr,
                            name,
                            peer_id: matched.peer_id,
                            rssi,
                            service_uuids: uuids,
                            matched_by: matched.matched_by.to_string(),
                        });
                    }
                }
            }
        }
        Ok(())
    }

    pub async fn stop_scan(&mut self) {
        if !self.scanning {
            return;
        }
        self.scanning = false;
        if let (Some(conn), Some(adapter_path)) = (&self.conn, &self.adapter_path) {
            if let Ok(adapter) = Proxy::new(
                conn,
                "org.bluez",
                adapter_path.as_str(),
                "org.bluez.Adapter1",
            )
            .await
            {
                let _ = adapter.call::<_, _, ()>("StopDiscovery", &()).await;
            }
        }
    }

    pub fn is_scanning(&self) -> bool {
        self.scanning
    }

    pub async fn connect_peer(&mut self, address: &str) -> Result<(usize, BleWriteMode), String> {
        let addr_norm = address.trim().to_ascii_uppercase();
        if let Some(existing) = self.central_links.get(&addr_norm) {
            return Ok((existing.mtu, existing.write_mode));
        }
        let (conn, _adapter_path) = self.ensure_connection().await?;
        let objects = get_managed_objects(&conn).await?;

        let device_path = objects
            .iter()
            .find_map(|(path, ifaces)| {
                let dev = ifaces.get("org.bluez.Device1")?;
                let dev_addr = owned_val_string(dev, "Address")?;
                if dev_addr.eq_ignore_ascii_case(&addr_norm) {
                    Some(path.as_str().to_string())
                } else {
                    None
                }
            })
            .ok_or_else(|| format!("BlueZ device {} not found in managed objects", addr_norm))?;

        let dev_proxy = Proxy::new(
            &conn,
            "org.bluez",
            device_path.as_str(),
            "org.bluez.Device1",
        )
        .await
        .map_err(|e| format!("Failed creating Device1 proxy: {}", e))?;
        dev_proxy
            .call::<_, _, ()>("Connect", &())
            .await
            .map_err(|e| format!("BlueZ Device1.Connect failed for {}: {}", addr_norm, e))?;

        // Re-fetch objects to locate BitChat GATT characteristic under this device
        let refreshed = get_managed_objects(&conn).await?;
        let (char_path, flags) = refreshed
            .iter()
            .find_map(|(path, ifaces)| {
                if !path.as_str().starts_with(&device_path) {
                    return None;
                }
                let ch = ifaces.get("org.bluez.GattCharacteristic1")?;
                let uuid = owned_val_string(ch, "UUID")?;
                if uuids_match(&uuid, BITCHAT_CHARACTERISTIC_UUID_STR) {
                    let fl: Vec<String> = ch
                        .get("Flags")
                        .and_then(|v| Vec::<String>::try_from(v.clone()).ok())
                        .unwrap_or_default();
                    Some((path.as_str().to_string(), fl))
                } else {
                    None
                }
            })
            .ok_or_else(|| {
                format!(
                    "BitChat GATT characteristic {} not found on BlueZ device {}",
                    BITCHAT_CHARACTERISTIC_UUID_STR, addr_norm
                )
            })?;

        let write_mode = validate_gatt_characteristic(
            BITCHAT_CHARACTERISTIC_UUID_STR,
            &flags,
            Some(BITCHAT_CHARACTERISTIC_UUID_STR),
        )?;

        let char_proxy = Proxy::new(
            &conn,
            "org.bluez",
            char_path.as_str(),
            "org.bluez.GattCharacteristic1",
        )
        .await
        .map_err(|e| format!("Failed creating GattCharacteristic1 proxy: {}", e))?;
        char_proxy
            .call::<_, _, ()>("StartNotify", &())
            .await
            .map_err(|e| format!("BlueZ StartNotify failed for {}: {}", addr_norm, e))?;

        let mtu = DEFAULT_BLE_MTU;
        self.central_links.insert(
            addr_norm.clone(),
            BluezCentralLink {
                device_path,
                char_path,
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

    pub async fn disconnect_peer(&mut self, address: &str) {
        let addr_norm = address.trim().to_ascii_uppercase();
        if let Some(link) = self.central_links.remove(&addr_norm) {
            if let Some(conn) = &self.conn {
                if let Ok(ch) = Proxy::new(
                    conn,
                    "org.bluez",
                    link.char_path.as_str(),
                    "org.bluez.GattCharacteristic1",
                )
                .await
                {
                    let _ = ch.call::<_, _, ()>("StopNotify", &()).await;
                }
                if let Ok(dev) = Proxy::new(
                    conn,
                    "org.bluez",
                    link.device_path.as_str(),
                    "org.bluez.Device1",
                )
                .await
                {
                    let _ = dev.call::<_, _, ()>("Disconnect", &()).await;
                }
            }
            let _ = self.event_tx.try_send(BleRuntimeEvent::PeerDisconnected {
                address: addr_norm,
                reason: "disconnected".to_string(),
            });
        }
    }

    pub async fn write_peer(&self, address: &str, data: &[u8]) -> Result<(), String> {
        let addr_norm = address.trim().to_ascii_uppercase();
        let link = self
            .central_links
            .get(&addr_norm)
            .ok_or_else(|| format!("Peer {} is not connected via BlueZ GATT", addr_norm))?;
        let conn = self
            .conn
            .as_ref()
            .ok_or_else(|| "BlueZ D-Bus connection not active".to_string())?;
        let char_proxy = Proxy::new(
            conn,
            "org.bluez",
            link.char_path.as_str(),
            "org.bluez.GattCharacteristic1",
        )
        .await
        .map_err(|e| format!("Failed creating GattCharacteristic1 proxy: {}", e))?;

        let mut opts: HashMap<&str, Value<'_>> = HashMap::new();
        let write_type = match link.write_mode {
            BleWriteMode::WriteWithoutResponse => "command",
            BleWriteMode::WriteWithResponse => "request",
        };
        opts.insert("type", Value::from(write_type));
        char_proxy
            .call::<_, _, ()>("WriteValue", &(data.to_vec(), opts))
            .await
            .map_err(|e| format!("BlueZ WriteValue failed for {}: {}", addr_norm, e))
    }

    pub async fn start_peripheral(&mut self) -> Result<(bool, bool, String, String), String> {
        if self.gatt_active {
            return Ok((
                self.gatt_active,
                self.adv_active,
                self.gatt_status_text.clone(),
                self.adv_status_text.clone(),
            ));
        }
        let (conn, adapter_path) = self.ensure_connection().await?;
        let obj_id = next_bluez_obj_id();
        let app_path = format!("/io/github/java_mx/bitchat/rust{}/app", obj_id);
        let service_path = format!("{}/service0", app_path);
        let char_path = format!("{}/char0", service_path);
        let adv_path = format!("/io/github/java_mx/bitchat/rust{}/adv0", obj_id);

        let service_obj_path = OwnedObjectPath::try_from(service_path.as_str())
            .map_err(|e| format!("Invalid service path: {}", e))?;
        let char_obj_path = OwnedObjectPath::try_from(char_path.as_str())
            .map_err(|e| format!("Invalid characteristic path: {}", e))?;

        let server = conn.object_server();
        server
            .at(app_path.as_str(), zbus::fdo::ObjectManager)
            .await
            .map_err(|e| format!("Failed exporting BlueZ ObjectManager: {}", e))?;
        server
            .at(
                service_path.as_str(),
                BluezGattServiceIface {
                    uuid: BITCHAT_SERVICE_UUID_STR.to_string(),
                    char_path: char_obj_path,
                },
            )
            .await
            .map_err(|e| format!("Failed exporting BlueZ GattService1: {}", e))?;
        server
            .at(
                char_path.as_str(),
                BluezGattCharacteristicIface {
                    uuid: BITCHAT_CHARACTERISTIC_UUID_STR.to_string(),
                    service_path: service_obj_path,
                    value: Arc::clone(&self.char_value),
                    notifying: Arc::new(Mutex::new(false)),
                    event_tx: self.event_tx.clone(),
                },
            )
            .await
            .map_err(|e| format!("Failed exporting BlueZ GattCharacteristic1: {}", e))?;

        let gatt_mgr = Proxy::new(
            &conn,
            "org.bluez",
            adapter_path.as_str(),
            "org.bluez.GattManager1",
        )
        .await
        .map_err(|e| format!("Failed creating GattManager1 proxy: {}", e))?;
        let empty_opts: HashMap<&str, Value<'_>> = HashMap::new();
        let app_obj = ObjectPath::try_from(app_path.as_str())
            .map_err(|e| format!("Invalid app path: {}", e))?;
        gatt_mgr
            .call::<_, _, ()>("RegisterApplication", &(app_obj, empty_opts))
            .await
            .map_err(|e| format!("BlueZ GattManager1.RegisterApplication failed: {}", e))?;

        self.app_path = Some(app_path);
        self.service_path = Some(service_path);
        self.char_path = Some(char_path);
        self.gatt_active = true;
        self.gatt_status_text = format!("Active (registered on {})", adapter_path);

        // Register LEAdvertisement1 with automatic fallback without ManufacturerData
        // while keeping GattManager1 active even if advertising is rejected.
        let adv_mgr = Proxy::new(
            &conn,
            "org.bluez",
            adapter_path.as_str(),
            "org.bluez.LEAdvertisingManager1",
        )
        .await;

        let mut adv_active = false;
        let mut adv_status = "Unavailable".to_string();
        if let Ok(mgr) = adv_mgr {
            let adv_obj = ObjectPath::try_from(adv_path.as_str()).ok();
            let _ = server
                .at(
                    adv_path.as_str(),
                    BluezAdvertisementIface {
                        service_uuid: BITCHAT_SERVICE_UUID_STR.to_string(),
                        include_mfg: true,
                        peer_id_hex: self.local_peer_id_hex.clone(),
                        event_tx: self.event_tx.clone(),
                    },
                )
                .await;
            if let Some(path_ref) = adv_obj {
                let opts: HashMap<&str, Value<'_>> = HashMap::new();
                if mgr
                    .call::<_, _, ()>("RegisterAdvertisement", &(path_ref.clone(), opts))
                    .await
                    .is_ok()
                {
                    adv_active = true;
                    adv_status = "Active (ServiceUUID + ManufacturerData)".to_string();
                    self.adv_path = Some(adv_path);
                } else {
                    let _ = server
                        .remove::<BluezAdvertisementIface, _>(adv_path.as_str())
                        .await;
                    let _ = server
                        .at(
                            adv_path.as_str(),
                            BluezAdvertisementIface {
                                service_uuid: BITCHAT_SERVICE_UUID_STR.to_string(),
                                include_mfg: false,
                                peer_id_hex: String::new(),
                                event_tx: self.event_tx.clone(),
                            },
                        )
                        .await;
                    let opts2: HashMap<&str, Value<'_>> = HashMap::new();
                    match mgr
                        .call::<_, _, ()>("RegisterAdvertisement", &(path_ref, opts2))
                        .await
                    {
                        Ok(_) => {
                            adv_active = true;
                            adv_status =
                                "Active (ServiceUUID only; ManufacturerData rejected)".to_string();
                            self.adv_path = Some(adv_path);
                        }
                        Err(e) => {
                            let _ = server
                                .remove::<BluezAdvertisementIface, _>(adv_path.as_str())
                                .await;
                            adv_status = format!("Failed ({} — GATT service remains active)", e);
                        }
                    }
                }
            }
        }

        self.adv_active = adv_active;
        self.adv_status_text = adv_status.clone();
        Ok((
            self.gatt_active,
            self.adv_active,
            self.gatt_status_text.clone(),
            adv_status,
        ))
    }

    pub async fn notify_clients(&self, data: &[u8]) -> Result<usize, String> {
        if !self.gatt_active {
            return Err("Linux BlueZ GATT Peripheral server is not active".to_string());
        }
        if let Ok(mut guard) = self.char_value.lock() {
            *guard = data.to_vec();
        }
        if let (Some(conn), Some(char_path)) = (&self.conn, &self.char_path) {
            let iface_ref = conn
                .object_server()
                .interface::<_, BluezGattCharacteristicIface>(char_path.as_str())
                .await
                .map_err(|e| format!("Failed retrieving BlueZ characteristic interface: {}", e))?;
            iface_ref
                .get()
                .await
                .value_changed(iface_ref.signal_emitter())
                .await
                .map_err(|e| format!("BlueZ PropertiesChanged notify failed: {}", e))?;
            Ok(1)
        } else {
            Err("BlueZ GATT characteristic object not exported".to_string())
        }
    }

    pub async fn stop_peripheral(&mut self) {
        if let (Some(conn), Some(adapter_path)) = (&self.conn, &self.adapter_path) {
            if let Some(adv_path) = self.adv_path.take() {
                if let Ok(mgr) = Proxy::new(
                    conn,
                    "org.bluez",
                    adapter_path.as_str(),
                    "org.bluez.LEAdvertisingManager1",
                )
                .await
                {
                    if let Ok(p) = ObjectPath::try_from(adv_path.as_str()) {
                        let _ = mgr.call::<_, _, ()>("UnregisterAdvertisement", &(p,)).await;
                    }
                }
                let _ = conn
                    .object_server()
                    .remove::<BluezAdvertisementIface, _>(adv_path.as_str())
                    .await;
            }
            if let Some(app_path) = self.app_path.take() {
                if let Ok(mgr) = Proxy::new(
                    conn,
                    "org.bluez",
                    adapter_path.as_str(),
                    "org.bluez.GattManager1",
                )
                .await
                {
                    if let Ok(p) = ObjectPath::try_from(app_path.as_str()) {
                        let _ = mgr.call::<_, _, ()>("UnregisterApplication", &(p,)).await;
                    }
                }
                let _ = conn
                    .object_server()
                    .remove::<zbus::fdo::ObjectManager, _>(app_path.as_str())
                    .await;
            }
            if let Some(sp) = self.service_path.take() {
                let _ = conn
                    .object_server()
                    .remove::<BluezGattServiceIface, _>(sp.as_str())
                    .await;
            }
            if let Some(cp) = self.char_path.take() {
                let _ = conn
                    .object_server()
                    .remove::<BluezGattCharacteristicIface, _>(cp.as_str())
                    .await;
            }
        }
        self.gatt_active = false;
        self.adv_active = false;
        self.gatt_status_text = "Stopped".to_string();
        self.adv_status_text = "Inactive".to_string();
    }

    pub fn peripheral_status(&self) -> (bool, bool, String, String) {
        (
            self.gatt_active,
            self.adv_active,
            self.gatt_status_text.clone(),
            self.adv_status_text.clone(),
        )
    }

    pub async fn shutdown(&mut self) {
        self.stop_scan().await;
        let addrs: Vec<String> = self.central_links.keys().cloned().collect();
        for addr in addrs {
            self.disconnect_peer(&addr).await;
        }
        self.stop_peripheral().await;
    }
}
