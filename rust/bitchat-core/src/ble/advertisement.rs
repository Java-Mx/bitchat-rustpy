//! BLE advertisement payload encoding/decoding, strict scanner filtering,
//! peer-ID extraction, UUID normalization, and GATT characteristic validation.

use pyo3::prelude::*;

use crate::ble::types::{
    BleWriteMode, BITCHAT_BLE_PREFIX, BITCHAT_CHARACTERISTIC_UUID_STR, BITCHAT_SERVICE_UUID_STR,
    BITCHAT_SERVICE_UUID_U128, MAX_BLE_CHUNK_SIZE, MIN_BLE_CHUNK_SIZE, PEER_ID_BYTES_LEN,
    UUID_BYTES_LEN,
};
use crate::errors::CoreError;
use crate::protocol::hex_encode_lower;

/// Normalize a UUID string to canonical lowercase without surrounding whitespace.
pub fn normalize_uuid(uuid: &str) -> String {
    let hex_only: String = uuid
        .trim()
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if hex_only.len() == 32 {
        format!(
            "{}-{}-{}-{}-{}",
            &hex_only[0..8],
            &hex_only[8..12],
            &hex_only[12..16],
            &hex_only[16..20],
            &hex_only[20..32]
        )
    } else {
        uuid.trim().to_ascii_lowercase()
    }
}

/// Return true if two UUID strings represent the same UUID (case- and hyphen-insensitive).
pub fn uuids_match(a: &str, b: &str) -> bool {
    normalize_uuid(a) == normalize_uuid(b)
}

/// Convert canonical 128-bit UUID string to 16 big-endian bytes.
pub fn uuid_str_to_bytes(uuid: &str) -> Option<[u8; UUID_BYTES_LEN]> {
    let hex_only: String = uuid
        .trim()
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect();
    if hex_only.len() != 32 {
        return None;
    }
    let mut out = [0u8; UUID_BYTES_LEN];
    for (idx, byte) in out.iter_mut().enumerate() {
        let s = &hex_only[idx * 2..idx * 2 + 2];
        *byte = u8::from_str_radix(s, 16).ok()?;
    }
    Some(out)
}

/// Return the canonical 16-byte representation of `BITCHAT_SERVICE_UUID`.
pub fn bitchat_service_uuid_bytes() -> [u8; UUID_BYTES_LEN] {
    BITCHAT_SERVICE_UUID_U128.to_be_bytes()
}

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
/// - `(true, Some(peer_id_hex))` if payload includes a valid non-zero/non-broadcast 8-byte peer_id
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
        if let Some(hex) = validate_extracted_peer_id_bytes(peer_id_slice) {
            return (true, Some(hex));
        }
    }
    (true, None)
}

/// Validate an extracted 8-byte BLE peer ID slice (rejecting all-zero and broadcast IDs).
pub fn validate_extracted_peer_id_bytes(raw: &[u8]) -> Option<String> {
    if raw.len() < PEER_ID_BYTES_LEN {
        return None;
    }
    let slice = &raw[..PEER_ID_BYTES_LEN];
    if slice == [0u8; PEER_ID_BYTES_LEN] || slice == [0xFFu8; PEER_ID_BYTES_LEN] {
        return None;
    }
    Some(hex_encode_lower(slice))
}

/// Extract a valid 16-hex-char peer ID from BLE service data bytes.
///
/// Strict Phase 3 rule: requires at least 8 full bytes (never silently emits
/// 12-char or 14-char truncated IDs) and rejects all-zero/broadcast values.
#[pyfunction]
pub fn extract_ble_service_data_peer_id(service_data: &[u8]) -> Option<String> {
    validate_extracted_peer_id_bytes(service_data)
}

/// Compute the usable GATT write chunk size from a negotiated ATT MTU.
#[pyfunction]
pub fn compute_ble_write_chunk_size(negotiated_mtu: usize) -> usize {
    negotiated_mtu
        .saturating_sub(3)
        .clamp(MIN_BLE_CHUNK_SIZE, MAX_BLE_CHUNK_SIZE)
}

/// Result of evaluating a raw BLE advertisement against BitChat discovery rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvertisementMatch {
    pub is_bitchat: bool,
    pub peer_id: Option<String>,
    pub matched_by: &'static str,
}

/// Evaluate whether a BLE advertisement belongs to BitChat and extract any peer ID.
pub fn match_bitchat_advertisement(
    service_uuids: &[String],
    manufacturer_payload: Option<&[u8]>,
    service_data_entries: &[(String, Vec<u8>)],
    expected_service_uuid: &str,
) -> AdvertisementMatch {
    let target_uuid = normalize_uuid(expected_service_uuid);
    let target_bytes = uuid_str_to_bytes(&target_uuid).unwrap_or_else(bitchat_service_uuid_bytes);

    let has_service_uuid = service_uuids
        .iter()
        .any(|u| normalize_uuid(u) == target_uuid);

    let (has_mfg_match, mfg_peer_id) = match manufacturer_payload {
        Some(payload) => decode_ble_manufacturer_payload(payload, &target_bytes),
        None => (false, None),
    };

    let mut service_data_peer_id: Option<String> = None;
    let mut has_service_data_uuid = false;
    for (suuid, sbytes) in service_data_entries {
        if normalize_uuid(suuid) == target_uuid {
            has_service_data_uuid = true;
            if service_data_peer_id.is_none() {
                service_data_peer_id = extract_ble_service_data_peer_id(sbytes);
            }
        }
    }

    if !has_service_uuid && !has_mfg_match && !has_service_data_uuid {
        return AdvertisementMatch {
            is_bitchat: false,
            peer_id: None,
            matched_by: "none",
        };
    }

    let peer_id = mfg_peer_id.or(service_data_peer_id);
    let matched_by = match (has_service_uuid, has_mfg_match, has_service_data_uuid) {
        (true, true, _) => "service_uuid+manufacturer_data",
        (true, false, _) => "service_uuid",
        (false, true, _) => "manufacturer_data",
        (false, false, true) => "service_data",
        (false, false, false) => "none",
    };

    AdvertisementMatch {
        is_bitchat: true,
        peer_id,
        matched_by,
    }
}

/// Validate a GATT characteristic UUID and property flags for BitChat transport use.
///
/// Requires:
/// - UUID matches `BITCHAT_CHARACTERISTIC_UUID` (case/hyphen-insensitive)
/// - Supports `notify` (or `indicate`)
/// - Supports `write-without-response` or `write`
pub fn validate_gatt_characteristic(
    char_uuid: &str,
    properties: &[String],
    expected_char_uuid: Option<&str>,
) -> Result<BleWriteMode, String> {
    let target = expected_char_uuid.unwrap_or(BITCHAT_CHARACTERISTIC_UUID_STR);
    if !uuids_match(char_uuid, target) {
        return Err(format!(
            "Characteristic UUID '{}' does not match expected '{}'",
            char_uuid, target
        ));
    }

    let props_lower: Vec<String> = properties
        .iter()
        .map(|p| p.trim().to_ascii_lowercase())
        .collect();
    let has_notify = props_lower.iter().any(|p| p == "notify" || p == "indicate");
    let has_write_no_resp = props_lower
        .iter()
        .any(|p| p == "write-without-response" || p == "write_without_response");
    let has_write_with_resp = props_lower.iter().any(|p| p == "write");

    if !has_notify {
        return Err(format!(
            "Characteristic '{}' is missing required 'notify' property (found: {:?})",
            char_uuid, props_lower
        ));
    }
    if has_write_no_resp {
        Ok(BleWriteMode::WriteWithoutResponse)
    } else if has_write_with_resp {
        Ok(BleWriteMode::WriteWithResponse)
    } else {
        Err(format!(
            "Characteristic '{}' is missing required write capability (found: {:?})",
            char_uuid, props_lower
        ))
    }
}

/// PyO3 wrapper for validating GATT characteristic UUID and properties.
#[pyfunction]
#[pyo3(signature = (char_uuid, properties, expected_char_uuid=None))]
pub fn validate_ble_gatt_characteristic_raw(
    char_uuid: &str,
    properties: Vec<String>,
    expected_char_uuid: Option<&str>,
) -> PyResult<String> {
    validate_gatt_characteristic(char_uuid, &properties, expected_char_uuid)
        .map(|mode| mode.as_str().to_string())
        .map_err(|e| CoreError::ble(e).into())
}

/// Return canonical BitChat BLE service and characteristic UUID strings.
#[pyfunction]
pub fn bitchat_ble_uuids_raw() -> (String, String) {
    (
        BITCHAT_SERVICE_UUID_STR.to_uppercase(),
        BITCHAT_CHARACTERISTIC_UUID_STR.to_uppercase(),
    )
}
