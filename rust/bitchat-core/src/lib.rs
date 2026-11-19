use pyo3::prelude::*;

pub mod ble;
pub mod crypto;
pub mod errors;
pub mod fragmentation;
pub mod framing;
pub mod lan;
pub mod mesh;
pub mod noise;
pub mod protocol;

#[pyfunction]
fn native_core_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[pymodule]
fn _bitchat_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(native_core_version, m)?)?;

    // Protocol functions (Stage 1)
    m.add_function(wrap_pyfunction!(protocol::get_optimal_block_size, m)?)?;
    m.add_function(wrap_pyfunction!(protocol::pad_packet_data, m)?)?;
    m.add_function(wrap_pyfunction!(protocol::unpad_packet_data, m)?)?;
    m.add_function(wrap_pyfunction!(protocol::peer_id_to_hex, m)?)?;
    m.add_function(wrap_pyfunction!(protocol::peer_id_from_hex, m)?)?;
    m.add_function(wrap_pyfunction!(protocol::encode_packet_raw, m)?)?;
    m.add_function(wrap_pyfunction!(protocol::decode_packet_raw, m)?)?;

    // Fragmentation and reassembly (Stage 1)
    m.add_function(wrap_pyfunction!(fragmentation::should_fragment_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(fragmentation::split_chunks, m)?)?;
    m.add_function(wrap_pyfunction!(fragmentation::create_fragment_payload, m)?)?;
    m.add_function(wrap_pyfunction!(fragmentation::parse_fragment_payload, m)?)?;
    m.add_function(wrap_pyfunction!(
        fragmentation::fragment_encoded_packet_raw,
        m
    )?)?;
    m.add_class::<fragmentation::NativeFragmentReassembler>()?;

    // Network framing (Stage 1)
    m.add_function(wrap_pyfunction!(framing::encode_frame_bytes, m)?)?;
    m.add_class::<framing::NativeStreamFramer>()?;

    // Cryptographic primitives (Stage 2)
    m.add_function(wrap_pyfunction!(crypto::ed25519_generate_signing_key, m)?)?;
    m.add_function(wrap_pyfunction!(
        crypto::ed25519_public_key_from_private,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(crypto::ed25519_load_public_key, m)?)?;
    m.add_function(wrap_pyfunction!(crypto::ed25519_sign, m)?)?;
    m.add_function(wrap_pyfunction!(crypto::ed25519_verify, m)?)?;
    m.add_function(wrap_pyfunction!(crypto::x25519_generate_private_key, m)?)?;
    m.add_function(wrap_pyfunction!(crypto::x25519_public_key_from_private, m)?)?;
    m.add_function(wrap_pyfunction!(crypto::x25519_validate_public_key, m)?)?;
    m.add_function(wrap_pyfunction!(crypto::x25519_diffie_hellman, m)?)?;
    m.add_function(wrap_pyfunction!(crypto::aes_gcm_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(crypto::aes_gcm_decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(crypto::noise_hkdf_raw, m)?)?;
    m.add_function(wrap_pyfunction!(crypto::legacy_hkdf_raw, m)?)?;
    m.add_function(wrap_pyfunction!(crypto::pbkdf2_derive_channel_key, m)?)?;
    m.add_function(wrap_pyfunction!(crypto::calculate_fingerprint_raw, m)?)?;
    m.add_function(wrap_pyfunction!(crypto::derive_identity_from_private, m)?)?;

    // Noise XX engine and deterministic handshake state machine (Stage 2 & Section 7)
    m.add_function(wrap_pyfunction!(noise::determine_handshake_role_raw, m)?)?;
    m.add_class::<noise::NativeNoiseCipherState>()?;
    m.add_class::<noise::NativeNoiseSymmetricState>()?;
    m.add_class::<noise::NativeNoiseHandshakeState>()?;
    m.add_class::<noise::NativeNoiseSession>()?;
    m.add_class::<noise::NativeHandshakeStateMachine>()?;

    // Mesh deduplication, rate limiting, routing, store-and-forward, ACK tracking (Stage 3)
    m.add_function(wrap_pyfunction!(mesh::compute_packet_id_raw, m)?)?;
    m.add_class::<mesh::NativePacketDeduplicator>()?;
    m.add_class::<mesh::NativePeerRateLimiter>()?;
    m.add_class::<mesh::NativeMeshRouter>()?;
    m.add_class::<mesh::NativeStoreAndForwardQueue>()?;
    m.add_class::<mesh::NativeAckTracker>()?;

    // LAN discovery, interface selection, arbitration, and Tokio transport helpers (Stage 4)
    m.add_function(wrap_pyfunction!(lan::encode_discovery_packet_raw, m)?)?;
    m.add_function(wrap_pyfunction!(lan::decode_discovery_packet_raw, m)?)?;
    m.add_function(wrap_pyfunction!(lan::decode_discovery_packet_full_raw, m)?)?;
    m.add_function(wrap_pyfunction!(lan::is_virtual_or_vpn_interface, m)?)?;
    m.add_function(wrap_pyfunction!(lan::compute_subnet_broadcast, m)?)?;
    m.add_function(wrap_pyfunction!(lan::select_best_lan_ip, m)?)?;
    m.add_function(wrap_pyfunction!(lan::compute_broadcast_targets, m)?)?;
    m.add_function(wrap_pyfunction!(lan::arbitrate_simultaneous_connection, m)?)?;
    m.add_function(wrap_pyfunction!(lan::tokio_send_framed_packet, m)?)?;
    m.add_function(wrap_pyfunction!(lan::tokio_udp_broadcast_beacon, m)?)?;
    m.add_class::<lan::NativeIpRateLimiter>()?;

    // BLE advertisement codec, MTU sizing, and GATT connection engine (Stage 5)
    m.add_function(wrap_pyfunction!(ble::encode_ble_manufacturer_payload, m)?)?;
    m.add_function(wrap_pyfunction!(decode_ble_adv, m)?)?;
    m.add_function(wrap_pyfunction!(ble::decode_ble_manufacturer_payload, m)?)?;
    m.add_function(wrap_pyfunction!(ble::compute_ble_write_chunk_size, m)?)?;
    m.add_class::<ble::NativeBleConnectionEngine>()?;

    Ok(())
}

#[pyfunction]
fn decode_ble_adv(payload: &[u8], expected_uuid_bytes: &[u8]) -> (bool, Option<String>) {
    ble::decode_ble_manufacturer_payload(payload, expected_uuid_bytes)
}
