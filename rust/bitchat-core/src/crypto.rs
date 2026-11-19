//! Native Rust cryptographic primitives for BitChat (Stage 2).
//!
//! Provides X25519 Diffie-Hellman key exchange, Ed25519 digital signatures,
//! AES-256-GCM authenticated encryption, Noise and legacy HKDF-SHA256,
//! PBKDF2-HMAC-SHA256 channel key derivation, and identity fingerprint
//! calculation.
//!
//! Secret material is zeroized on drop where applicable and never written to
//! logs, debug strings, or error messages.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce as AesNonce};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use pyo3::prelude::*;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroize;

use crate::errors::CoreError;

type HmacSha256 = Hmac<Sha256>;

pub const ED25519_PRIVATE_KEY_SIZE: usize = 32;
pub const ED25519_PUBLIC_KEY_SIZE: usize = 32;
pub const ED25519_SIGNATURE_SIZE: usize = 64;

pub const X25519_KEY_SIZE: usize = 32;
pub const X25519_SHARED_SECRET_SIZE: usize = 32;

pub const AES_KEY_SIZE: usize = 32;
pub const AES_NONCE_SIZE: usize = 12;
pub const AES_TAG_SIZE: usize = 16;
pub const AES_MIN_CIPHERTEXT_SIZE: usize = AES_NONCE_SIZE + AES_TAG_SIZE;

pub const PBKDF2_ITERATIONS: u32 = 100_000;
pub const PBKDF2_OUTPUT_LENGTH: usize = 32;

/// Known low-order / weak points on Curve25519 rejected by BitChat and the
/// Rust reference `noise_protocol.rs` `validate_public_key`.
pub const LOW_ORDER_POINTS: [[u8; 32]; 8] = [
    // All zeros — point at infinity
    [0x00; 32],
    // Point of order 1 (with trailing 0x01)
    [
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01,
    ],
    // Another low-order point
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01,
    ],
    // Low-order point (order 8)
    [
        0xE0, 0xEB, 0x7A, 0x7C, 0x3B, 0x41, 0xB8, 0xAE, 0x16, 0x56, 0xE3, 0xFA, 0xF1, 0x9F, 0xC4,
        0x6A, 0xDA, 0x09, 0x8D, 0xEB, 0x9C, 0x32, 0xB1, 0xFD, 0x86, 0x62, 0x05, 0x16, 0x5F, 0x49,
        0xB8, 0x00,
    ],
    // Low-order point
    [
        0x5F, 0x9C, 0x95, 0xBC, 0xA3, 0x50, 0x8C, 0x24, 0xB1, 0xD0, 0xB1, 0x55, 0x9C, 0x83, 0xEF,
        0x5B, 0x04, 0x44, 0x5C, 0xC4, 0x58, 0x1C, 0x8E, 0x86, 0xD8, 0x22, 0x4E, 0xDD, 0xD0, 0x9F,
        0x11, 0x57,
    ],
    // All ones
    [0xFF; 32],
    // Bad point 0xDA...
    [
        0xDA, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF,
    ],
    // Bad point 0xDB...
    [
        0xDB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF,
    ],
];

// ---------------------------------------------------------------------------
// Internal Rust API (used by noise.rs and PyO3 wrappers)
// ---------------------------------------------------------------------------

pub fn validate_x25519_public_key_slice(public_key_bytes: &[u8]) -> Result<[u8; 32], CoreError> {
    if public_key_bytes.len() != X25519_KEY_SIZE {
        return Err(CoreError::invalid_key(format!(
            "X25519 public key must be {} bytes, got {}",
            X25519_KEY_SIZE,
            public_key_bytes.len()
        )));
    }
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(public_key_bytes);
    if LOW_ORDER_POINTS.iter().any(|bad| bad == &key_arr) {
        return Err(CoreError::invalid_key(
            "X25519 public key is a known low-order/weak point",
        ));
    }
    Ok(key_arr)
}

pub fn x25519_public_from_private_slice(private_key_bytes: &[u8]) -> Result<[u8; 32], CoreError> {
    if private_key_bytes.len() != X25519_KEY_SIZE {
        return Err(CoreError::invalid_key(format!(
            "X25519 private key must be {} bytes, got {}",
            X25519_KEY_SIZE,
            private_key_bytes.len()
        )));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(private_key_bytes);
    let secret = X25519StaticSecret::from(seed);
    seed.zeroize();
    let public = X25519PublicKey::from(&secret);
    Ok(public.to_bytes())
}

pub fn x25519_dh_slices(
    local_private_bytes: &[u8],
    remote_public_bytes: &[u8],
) -> Result<[u8; 32], CoreError> {
    if local_private_bytes.len() != X25519_KEY_SIZE {
        return Err(CoreError::invalid_key(format!(
            "X25519 private key must be {} bytes, got {}",
            X25519_KEY_SIZE,
            local_private_bytes.len()
        )));
    }
    let remote_arr = validate_x25519_public_key_slice(remote_public_bytes)?;
    let mut seed = [0u8; 32];
    seed.copy_from_slice(local_private_bytes);
    let secret = X25519StaticSecret::from(seed);
    seed.zeroize();

    let remote_pub = X25519PublicKey::from(remote_arr);
    let shared = secret.diffie_hellman(&remote_pub);
    let shared_bytes = shared.to_bytes();
    if shared_bytes == [0u8; 32] {
        return Err(CoreError::invalid_key(
            "X25519 public key produced an all-zero shared secret (low-order point)",
        ));
    }
    Ok(shared_bytes)
}

pub fn noise_hkdf_slices(
    chaining_key: &[u8],
    ikm: &[u8],
    num_outputs: usize,
) -> Result<Vec<[u8; 32]>, CoreError> {
    if !(1..=255).contains(&num_outputs) {
        return Err(CoreError::value_err(format!(
            "num_outputs must be in [1, 255], got {}",
            num_outputs
        )));
    }

    let mut mac = <HmacSha256 as Mac>::new_from_slice(chaining_key)
        .map_err(|e| CoreError::crypto(format!("HMAC init failed: {}", e)))?;
    mac.update(ikm);
    let mut temp_key = [0u8; 32];
    temp_key.copy_from_slice(&mac.finalize().into_bytes());

    let mut outputs = Vec::with_capacity(num_outputs);
    let mut current = [0u8; 32];
    let mut has_prev = false;

    for i in 1..=num_outputs {
        let mut inner = <HmacSha256 as Mac>::new_from_slice(&temp_key)
            .map_err(|e| CoreError::crypto(format!("HMAC init failed: {}", e)))?;
        if has_prev {
            inner.update(&current);
        }
        inner.update(&[i as u8]);
        current.copy_from_slice(&inner.finalize().into_bytes());
        outputs.push(current);
        has_prev = true;
    }

    temp_key.zeroize();
    current.zeroize();
    Ok(outputs)
}

pub fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let mut out = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(&mut out, "{:02x}", b);
    }
    out
}

// ---------------------------------------------------------------------------
// PyO3 Exposed Functions
// ---------------------------------------------------------------------------

#[pyfunction]
pub fn ed25519_generate_signing_key() -> PyResult<Vec<u8>> {
    let mut seed = [0u8; ED25519_PRIVATE_KEY_SIZE];
    OsRng.fill_bytes(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    seed.zeroize();
    Ok(signing_key.to_bytes().to_vec())
}

#[pyfunction]
pub fn ed25519_public_key_from_private(private_key_bytes: &[u8]) -> PyResult<Vec<u8>> {
    if private_key_bytes.len() != ED25519_PRIVATE_KEY_SIZE {
        return Err(CoreError::invalid_key(format!(
            "Ed25519 private key must be {} bytes, got {}",
            ED25519_PRIVATE_KEY_SIZE,
            private_key_bytes.len()
        ))
        .into());
    }
    let mut seed = [0u8; ED25519_PRIVATE_KEY_SIZE];
    seed.copy_from_slice(private_key_bytes);
    let signing_key = SigningKey::from_bytes(&seed);
    seed.zeroize();
    Ok(signing_key.verifying_key().to_bytes().to_vec())
}

#[pyfunction]
pub fn ed25519_load_public_key(public_key_bytes: &[u8]) -> PyResult<Vec<u8>> {
    if public_key_bytes.len() != ED25519_PUBLIC_KEY_SIZE {
        return Err(CoreError::invalid_key(format!(
            "Ed25519 public key must be {} bytes, got {}",
            ED25519_PUBLIC_KEY_SIZE,
            public_key_bytes.len()
        ))
        .into());
    }
    let mut arr = [0u8; ED25519_PUBLIC_KEY_SIZE];
    arr.copy_from_slice(public_key_bytes);
    VerifyingKey::from_bytes(&arr)
        .map_err(|_| CoreError::invalid_key("Invalid Ed25519 public key"))?;
    Ok(arr.to_vec())
}

#[pyfunction]
pub fn ed25519_sign(private_key_bytes: &[u8], data: &[u8]) -> PyResult<Vec<u8>> {
    if private_key_bytes.len() != ED25519_PRIVATE_KEY_SIZE {
        return Err(CoreError::invalid_key(format!(
            "Ed25519 private key must be {} bytes, got {}",
            ED25519_PRIVATE_KEY_SIZE,
            private_key_bytes.len()
        ))
        .into());
    }
    let mut seed = [0u8; ED25519_PRIVATE_KEY_SIZE];
    seed.copy_from_slice(private_key_bytes);
    let signing_key = SigningKey::from_bytes(&seed);
    seed.zeroize();
    let sig: Signature = signing_key.sign(data);
    Ok(sig.to_bytes().to_vec())
}

#[pyfunction]
pub fn ed25519_verify(public_key_bytes: &[u8], signature: &[u8], data: &[u8]) -> PyResult<()> {
    if public_key_bytes.len() != ED25519_PUBLIC_KEY_SIZE {
        return Err(CoreError::invalid_key(format!(
            "Ed25519 public key must be {} bytes, got {}",
            ED25519_PUBLIC_KEY_SIZE,
            public_key_bytes.len()
        ))
        .into());
    }
    if signature.len() != ED25519_SIGNATURE_SIZE {
        return Err(CoreError::invalid_signature(format!(
            "Ed25519 signature must be {} bytes, got {}",
            ED25519_SIGNATURE_SIZE,
            signature.len()
        ))
        .into());
    }
    let mut pub_arr = [0u8; ED25519_PUBLIC_KEY_SIZE];
    pub_arr.copy_from_slice(public_key_bytes);
    let verifying_key = VerifyingKey::from_bytes(&pub_arr)
        .map_err(|_| CoreError::invalid_key("Invalid Ed25519 public key"))?;

    let sig = Signature::from_slice(signature)
        .map_err(|_| CoreError::invalid_signature("Invalid Ed25519 signature encoding"))?;

    verifying_key
        .verify_strict(data, &sig)
        .map_err(|_| CoreError::signature_verification("Ed25519 signature verification failed"))?;
    Ok(())
}

#[pyfunction]
pub fn x25519_generate_private_key() -> PyResult<Vec<u8>> {
    let mut key = [0u8; X25519_KEY_SIZE];
    OsRng.fill_bytes(&mut key);
    let out = key.to_vec();
    key.zeroize();
    Ok(out)
}

#[pyfunction]
pub fn x25519_public_key_from_private(private_key_bytes: &[u8]) -> PyResult<Vec<u8>> {
    let pub_bytes = x25519_public_from_private_slice(private_key_bytes)?;
    Ok(pub_bytes.to_vec())
}

#[pyfunction]
pub fn x25519_validate_public_key(public_key_bytes: &[u8]) -> PyResult<Vec<u8>> {
    let valid = validate_x25519_public_key_slice(public_key_bytes)?;
    Ok(valid.to_vec())
}

#[pyfunction]
pub fn x25519_diffie_hellman(
    local_private_bytes: &[u8],
    remote_public_bytes: &[u8],
) -> PyResult<Vec<u8>> {
    let mut shared = x25519_dh_slices(local_private_bytes, remote_public_bytes)?;
    let out = shared.to_vec();
    shared.zeroize();
    Ok(out)
}

#[pyfunction]
pub fn aes_gcm_encrypt(key: &[u8], plaintext: &[u8]) -> PyResult<Vec<u8>> {
    if key.len() != AES_KEY_SIZE {
        return Err(CoreError::encryption(format!(
            "AES-256 key must be {} bytes, got {}",
            AES_KEY_SIZE,
            key.len()
        ))
        .into());
    }
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| CoreError::encryption("AES-256-GCM key initialization failed"))?;
    let mut nonce_bytes = [0u8; AES_NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = AesNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CoreError::encryption("AES-256-GCM encryption failed"))?;

    let mut out = Vec::with_capacity(AES_NONCE_SIZE + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

#[pyfunction]
pub fn aes_gcm_decrypt(key: &[u8], data: &[u8]) -> PyResult<Vec<u8>> {
    if key.len() != AES_KEY_SIZE {
        return Err(CoreError::encryption(format!(
            "AES-256 key must be {} bytes, got {}",
            AES_KEY_SIZE,
            key.len()
        ))
        .into());
    }
    if data.len() < AES_MIN_CIPHERTEXT_SIZE {
        return Err(CoreError::decryption(format!(
            "AES-GCM data too short: need at least {} bytes (nonce + tag), got {}",
            AES_MIN_CIPHERTEXT_SIZE,
            data.len()
        ))
        .into());
    }
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| CoreError::decryption("AES-256-GCM key initialization failed"))?;
    let nonce = AesNonce::from_slice(&data[..AES_NONCE_SIZE]);
    let ciphertext = &data[AES_NONCE_SIZE..];
    cipher.decrypt(nonce, ciphertext).map_err(|_| {
        CoreError::decryption("AES-256-GCM decryption or authentication failed").into()
    })
}

#[pyfunction]
pub fn noise_hkdf_raw(
    chaining_key: &[u8],
    ikm: &[u8],
    num_outputs: usize,
) -> PyResult<Vec<Vec<u8>>> {
    let outputs = noise_hkdf_slices(chaining_key, ikm, num_outputs)?;
    Ok(outputs.into_iter().map(|b| b.to_vec()).collect())
}

#[pyfunction]
#[pyo3(signature = (ikm, salt=None, info=None, length=32))]
pub fn legacy_hkdf_raw(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: Option<&[u8]>,
    length: usize,
) -> PyResult<Vec<u8>> {
    if length == 0 || length > 255 * 32 {
        return Err(CoreError::value_err(format!("Invalid HKDF output length: {}", length)).into());
    }
    let salt_bytes = salt.unwrap_or(b"bitchat-v1");
    let info_bytes = info.unwrap_or(b"");
    let hk = Hkdf::<Sha256>::new(Some(salt_bytes), ikm);
    let mut okm = vec![0u8; length];
    hk.expand(info_bytes, &mut okm)
        .map_err(|_| CoreError::value_err("HKDF expand failed"))?;
    Ok(okm)
}

#[pyfunction]
pub fn pbkdf2_derive_channel_key(password: &str, channel_name: &str) -> PyResult<Vec<u8>> {
    let mut key = [0u8; PBKDF2_OUTPUT_LENGTH];
    pbkdf2_hmac::<Sha256>(
        password.as_bytes(),
        channel_name.as_bytes(),
        PBKDF2_ITERATIONS,
        &mut key,
    );
    let out = key.to_vec();
    key.zeroize();
    Ok(out)
}

#[pyfunction]
pub fn calculate_fingerprint_raw(x25519_public_key: &[u8]) -> String {
    sha256_hex(x25519_public_key)
}

#[pyfunction]
#[allow(clippy::type_complexity)]
pub fn derive_identity_from_private(
    x25519_private: &[u8],
    ed25519_private: &[u8],
) -> PyResult<(Vec<u8>, Vec<u8>, Vec<u8>, String)> {
    let x25519_pub = x25519_public_from_private_slice(x25519_private)?;
    let ed25519_pub = ed25519_public_key_from_private(ed25519_private)?;
    let digest = Sha256::digest(x25519_pub);
    let peer_id = digest[..8].to_vec();
    let mut fingerprint = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(&mut fingerprint, "{:02x}", b);
    }
    Ok((x25519_pub.to_vec(), ed25519_pub, peer_id, fingerprint))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_rfc8032_tv1() {
        let priv_key: [u8; 32] = [
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x3d, 0x55,
        ];
        let expected_pub: [u8; 32] = [
            0x70, 0x0e, 0x2c, 0xe7, 0xc4, 0xb6, 0x74, 0x42, 0x7e, 0xab, 0x27, 0xba, 0x82, 0x0b,
            0xcf, 0x6f, 0x0f, 0xae, 0xbe, 0x68, 0xe0, 0x9f, 0xe8, 0x56, 0x42, 0x92, 0x11, 0x4e,
            0x41, 0xdc, 0x6a, 0x41,
        ];
        let pub_key = ed25519_public_key_from_private(&priv_key).unwrap();
        assert_eq!(pub_key, expected_pub);
        let sig = ed25519_sign(&priv_key, b"").unwrap();
        assert_eq!(sig.len(), 64);
        ed25519_verify(&pub_key, &sig, b"").unwrap();
    }

    #[test]
    fn test_x25519_known_vectors_and_low_order_rejection() {
        let alice_seed: [u8; 32] = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x1f, 0xb9, 0xc7, 0x7c, 0x5e, 0x61, 0xfc, 0xf5, 0xb9, 0xda, 0x37,
            0xc5, 0x4d, 0x7c, 0xe9,
        ];
        let bob_seed: [u8; 32] = [
            0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80,
            0x0e, 0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27,
            0xff, 0x88, 0xe0, 0xeb,
        ];
        let expected_shared: [u8; 32] = [
            0x9f, 0xe3, 0xfd, 0x0e, 0x48, 0x80, 0x50, 0xc3, 0x65, 0xa2, 0xe5, 0x6c, 0x9a, 0x89,
            0x09, 0x6e, 0x19, 0x0d, 0x51, 0x94, 0x64, 0xc5, 0x37, 0xb7, 0x6a, 0xb4, 0xaa, 0xa7,
            0xb8, 0x82, 0x8d, 0x1c,
        ];
        let alice_pub = x25519_public_from_private_slice(&alice_seed).unwrap();
        let bob_pub = x25519_public_from_private_slice(&bob_seed).unwrap();
        let s1 = x25519_dh_slices(&alice_seed, &bob_pub).unwrap();
        let s2 = x25519_dh_slices(&bob_seed, &alice_pub).unwrap();
        assert_eq!(s1, expected_shared);
        assert_eq!(s2, expected_shared);

        for bad_pt in &LOW_ORDER_POINTS {
            assert!(validate_x25519_public_key_slice(bad_pt).is_err());
        }
    }

    #[test]
    fn test_aes_gcm_roundtrip_and_tamper() {
        let key = [0x42u8; 32];
        let pt = b"confidential mesh payload";
        let ct = aes_gcm_encrypt(&key, pt).unwrap();
        assert_eq!(ct.len(), pt.len() + 28);
        let dec = aes_gcm_decrypt(&key, &ct).unwrap();
        assert_eq!(dec, pt);

        let mut tampered = ct.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(aes_gcm_decrypt(&key, &tampered).is_err());
    }
}
