//! Native Rust BLE Transport Architecture (Phase 3 / v0.3.4).
//!
//! Provides genuine Rust ownership of BLE discovery, GATT client/server,
//! advertisement filtering, peer-ID extraction, MTU chunking, bounded queues,
//! early-notification buffering, and platform-native OS backends:
//! - Windows: native WinRT (`windows_winrt.rs`)
//! - Linux: native BlueZ D-Bus (`linux_bluez.rs` via `zbus`)
//! - macOS: CoreBluetooth capability probe (`macos_corebt.rs`)

pub mod advertisement;
pub mod connection;
pub mod linux_bluez;
pub mod macos_corebt;
pub mod manager;
pub mod types;
pub mod windows_winrt;

pub use advertisement::{
    bitchat_ble_uuids_raw, compute_ble_write_chunk_size, decode_ble_manufacturer_payload,
    encode_ble_manufacturer_payload, extract_ble_service_data_peer_id,
    validate_ble_gatt_characteristic_raw,
};
pub use connection::NativeBleConnectionEngine;
pub use manager::{probe_native_ble_adapter_raw, NativeBleTransportManager};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ble::advertisement::{
        bitchat_service_uuid_bytes, match_bitchat_advertisement, normalize_uuid,
        validate_gatt_characteristic,
    };
    use crate::ble::types::{
        BleWriteMode, BITCHAT_CHARACTERISTIC_UUID_STR, BITCHAT_SERVICE_UUID_STR,
    };

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

        // All-zero peer ID ignored
        let zero_ext = encode_ble_manufacturer_payload(&uuid, Some(&[0u8; 8])).unwrap();
        assert_eq!(
            decode_ble_manufacturer_payload(&zero_ext, &uuid),
            (true, None)
        );

        // Broadcast peer ID ignored
        let bcast_ext = encode_ble_manufacturer_payload(&uuid, Some(&[0xFFu8; 8])).unwrap();
        assert_eq!(
            decode_ble_manufacturer_payload(&bcast_ext, &uuid),
            (true, None)
        );

        // Wrong UUID rejected
        let wrong_uuid = [0xBBu8; 16];
        assert_eq!(
            decode_ble_manufacturer_payload(&ext, &wrong_uuid),
            (false, None)
        );
    }

    #[test]
    fn test_service_data_peer_id_requires_full_8_bytes_and_nonzero() {
        assert_eq!(extract_ble_service_data_peer_id(&[1, 2, 3, 4, 5, 6]), None);
        assert_eq!(
            extract_ble_service_data_peer_id(&[1, 2, 3, 4, 5, 6, 7]),
            None
        );
        assert_eq!(extract_ble_service_data_peer_id(&[0u8; 8]), None);
        assert_eq!(extract_ble_service_data_peer_id(&[0xFFu8; 8]), None);
        assert_eq!(
            extract_ble_service_data_peer_id(&[0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04]),
            Some("deadbeef01020304".to_string())
        );
    }

    #[test]
    fn test_advertisement_filtering_and_gatt_characteristic_validation() {
        let uuid_bytes = bitchat_service_uuid_bytes();
        let mfg = encode_ble_manufacturer_payload(
            &uuid_bytes,
            Some(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]),
        )
        .unwrap();

        let matched = match_bitchat_advertisement(
            &[BITCHAT_SERVICE_UUID_STR.to_uppercase()],
            Some(&mfg),
            &[],
            BITCHAT_SERVICE_UUID_STR,
        );
        assert!(matched.is_bitchat);
        assert_eq!(matched.peer_id.as_deref(), Some("1122334455667788"));

        let rejected = match_bitchat_advertisement(
            &["00001800-0000-1000-8000-00805f9b34fb".to_string()],
            Some(b"NOTBITCHAT"),
            &[],
            BITCHAT_SERVICE_UUID_STR,
        );
        assert!(!rejected.is_bitchat);

        assert_eq!(
            normalize_uuid("F47B5E2D4A9E4C5A9B3F8E1D2C3A4B5C"),
            BITCHAT_SERVICE_UUID_STR
        );

        assert_eq!(
            validate_gatt_characteristic(
                BITCHAT_CHARACTERISTIC_UUID_STR,
                &[
                    "read".into(),
                    "write-without-response".into(),
                    "notify".into()
                ],
                None
            ),
            Ok(BleWriteMode::WriteWithoutResponse)
        );
        assert_eq!(
            validate_gatt_characteristic(
                &BITCHAT_CHARACTERISTIC_UUID_STR.to_uppercase(),
                &["write".into(), "notify".into()],
                None
            ),
            Ok(BleWriteMode::WriteWithResponse)
        );
        assert!(validate_gatt_characteristic(
            BITCHAT_CHARACTERISTIC_UUID_STR,
            &["read".into(), "write".into()],
            None
        )
        .is_err());
        assert!(validate_gatt_characteristic(
            BITCHAT_CHARACTERISTIC_UUID_STR,
            &["read".into(), "notify".into()],
            None
        )
        .is_err());
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

        // MTU chunking test
        engine.set_mtu(23);
        assert_eq!(engine.max_write_chunk_size(), 20);
        let chunks = engine.chunk_payload(&[0x42u8; 45]);
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].len(), 20);
        assert_eq!(chunks[1].len(), 20);
        assert_eq!(chunks[2].len(), 5);
    }
}
