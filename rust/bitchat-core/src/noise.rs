//! Native Rust Noise_XX_25519_ChaChaPoly_SHA256 engine and deterministic
//! handshake state machine for BitChat (Stage 2 & Section 7).
//!
//! Preserves wire-level and cryptographic compatibility with both the BitChat
//! Python implementation and the Rust reference `bitchat-tui` (`noise_protocol.rs`
//! and `noise_session.rs`), while enforcing fail-closed authentication,
//! nonce-0 replay protection, and static key to peer-ID binding.

use std::collections::HashSet;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce};
use pyo3::prelude::*;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::crypto::{
    noise_hkdf_slices, sha256_hex, validate_x25519_public_key_slice, x25519_dh_slices,
    x25519_public_from_private_slice,
};
use crate::errors::CoreError;
use crate::protocol::is_legacy_tui_peer_id_bytes;

#[inline]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    std::hint::black_box(diff) == 0
}

pub const NOISE_PROTOCOL_NAME: &str = "Noise_XX_25519_ChaChaPoly_SHA256";
pub const NOISE_REPLAY_WINDOW_SIZE: u64 = 1024;
pub const NOISE_NONCE_REKEY_WARNING_THRESHOLD: u64 = 1_000_000_000;
/// Maximum transport nonce before 4-byte wire nonce overflow (`u32::MAX`).
/// Encryption refuses to proceed once `nonce >= NOISE_MAX_TRANSPORT_NONCE` so a
/// 4-byte LE wire nonce can never wrap around or be reused.
pub const NOISE_MAX_TRANSPORT_NONCE: u64 = u32::MAX as u64;
pub const NONCE_WIRE_SIZE_BYTES: usize = 4;
pub const CHACHA_NONCE_SIZE: usize = 12;
pub const DH_KEY_SIZE: usize = 32;
pub const TAG_SIZE: usize = 16;

#[pyfunction]
pub fn determine_handshake_role_raw(
    my_peer_id_hex: &str,
    remote_peer_id_hex: &str,
) -> PyResult<&'static str> {
    if my_peer_id_hex.is_empty() {
        return Err(CoreError::value_err("my_peer_id_hex must not be empty").into());
    }
    if remote_peer_id_hex.is_empty() {
        return Err(CoreError::value_err("remote_peer_id_hex must not be empty").into());
    }
    if my_peer_id_hex < remote_peer_id_hex {
        Ok("initiator")
    } else {
        Ok("responder")
    }
}

// ---------------------------------------------------------------------------
// NativeNoiseCipherState
// ---------------------------------------------------------------------------

#[pyclass(module = "bitchat._bitchat_core")]
#[derive(Clone)]
pub struct NativeNoiseCipherState {
    key: Option<[u8; 32]>,
    nonce: u64,
    use_extracted_nonce: bool,
    replay_window: HashSet<u64>,
    highest_received_nonce: u64,
}

impl Drop for NativeNoiseCipherState {
    fn drop(&mut self) {
        if let Some(ref mut k) = self.key {
            k.zeroize();
        }
    }
}

impl NativeNoiseCipherState {
    #[allow(clippy::too_many_arguments)]
    pub fn new_internal(key: Option<[u8; 32]>, use_extracted_nonce: bool) -> Self {
        Self {
            key,
            nonce: 0,
            use_extracted_nonce,
            replay_window: HashSet::new(),
            highest_received_nonce: 0,
        }
    }

    fn build_chacha_nonce(counter: u64) -> [u8; CHACHA_NONCE_SIZE] {
        let mut nonce_bytes = [0u8; CHACHA_NONCE_SIZE];
        nonce_bytes[4..12].copy_from_slice(&counter.to_le_bytes());
        nonce_bytes
    }

    fn counter_to_wire_bytes(counter: u64) -> [u8; NONCE_WIRE_SIZE_BYTES] {
        let le = counter.to_le_bytes();
        [le[0], le[1], le[2], le[3]]
    }

    fn extract_wire_nonce(data: &[u8]) -> Result<(u64, &[u8]), CoreError> {
        if data.len() < NONCE_WIRE_SIZE_BYTES {
            return Err(CoreError::invalid_nonce(format!(
                "Ciphertext too short to contain 4-byte nonce prefix (got {} bytes)",
                data.len()
            )));
        }
        let mut prefix = [0u8; 4];
        prefix.copy_from_slice(&data[..NONCE_WIRE_SIZE_BYTES]);
        let counter = u32::from_le_bytes(prefix) as u64;
        Ok((counter, &data[NONCE_WIRE_SIZE_BYTES..]))
    }

    fn is_valid_nonce(&self, received_nonce: u64) -> bool {
        if received_nonce.saturating_add(NOISE_REPLAY_WINDOW_SIZE) <= self.highest_received_nonce {
            return false;
        }
        if received_nonce > self.highest_received_nonce {
            return true;
        }
        !self.replay_window.contains(&received_nonce)
    }

    fn mark_nonce_seen(&mut self, received_nonce: u64) {
        if received_nonce > self.highest_received_nonce {
            let shift = received_nonce - self.highest_received_nonce;
            if shift >= NOISE_REPLAY_WINDOW_SIZE {
                self.replay_window.clear();
            } else {
                self.replay_window
                    .retain(|&n| n.saturating_add(NOISE_REPLAY_WINDOW_SIZE) > received_nonce);
            }
            self.highest_received_nonce = received_nonce;
        }
        self.replay_window.insert(received_nonce);
    }

    pub fn is_nonce_exhausted_internal(&self) -> bool {
        if self.use_extracted_nonce {
            self.nonce >= NOISE_MAX_TRANSPORT_NONCE
        } else {
            self.nonce == u64::MAX
        }
    }

    pub fn needs_rekey_internal(&self) -> bool {
        self.use_extracted_nonce && self.nonce >= NOISE_NONCE_REKEY_WARNING_THRESHOLD
    }

    pub fn encrypt_internal(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CoreError> {
        let key = self.key.as_ref().ok_or_else(|| {
            CoreError::noise_state("NoiseCipherState: no key initialised (encrypt)")
        })?;
        if self.is_nonce_exhausted_internal() {
            return Err(CoreError::invalid_nonce(
                "Noise transport nonce exhausted; session rekey or termination required",
            ));
        }
        let current_nonce = self.nonce;
        let next_nonce = current_nonce.checked_add(1).ok_or_else(|| {
            CoreError::invalid_nonce("Noise cipher nonce overflow; session rekey required")
        })?;
        let chacha_nonce_bytes = Self::build_chacha_nonce(current_nonce);
        let cipher = ChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| CoreError::encryption("ChaCha20-Poly1305 key init failed"))?;
        let ciphertext = cipher
            .encrypt(
                ChaChaNonce::from_slice(&chacha_nonce_bytes),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| CoreError::encryption("ChaCha20-Poly1305 encryption failed"))?;

        self.nonce = next_nonce;
        if self.use_extracted_nonce {
            let prefix = Self::counter_to_wire_bytes(current_nonce);
            let mut out = Vec::with_capacity(NONCE_WIRE_SIZE_BYTES + ciphertext.len());
            out.extend_from_slice(&prefix);
            out.extend_from_slice(&ciphertext);
            Ok(out)
        } else {
            Ok(ciphertext)
        }
    }

    pub fn decrypt_internal(
        &mut self,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, CoreError> {
        let key = self.key.as_ref().ok_or_else(|| {
            CoreError::noise_state("NoiseCipherState: no key initialised (decrypt)")
        })?;

        let (counter, payload) = if self.use_extracted_nonce {
            let (c, p) = Self::extract_wire_nonce(ciphertext)?;
            if !self.is_valid_nonce(c) {
                return Err(CoreError::replay(format!(
                    "Replay detected: nonce {} has already been seen or is outside the replay window",
                    c
                )));
            }
            (c, p)
        } else {
            (self.nonce, ciphertext)
        };

        let chacha_nonce_bytes = Self::build_chacha_nonce(counter);
        let cipher = ChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| CoreError::decryption("ChaCha20-Poly1305 key init failed"))?;
        let plaintext = cipher
            .decrypt(
                ChaChaNonce::from_slice(&chacha_nonce_bytes),
                Payload { msg: payload, aad },
            )
            .map_err(|_| {
                CoreError::decryption("ChaCha20-Poly1305 decryption or authentication failed")
            })?;

        if self.use_extracted_nonce {
            self.mark_nonce_seen(counter);
        } else {
            self.nonce = self.nonce.saturating_add(1);
        }

        Ok(plaintext)
    }
}

#[pymethods]
impl NativeNoiseCipherState {
    #[new]
    #[pyo3(signature = (key=None, use_extracted_nonce=false))]
    pub fn new(key: Option<&[u8]>, use_extracted_nonce: bool) -> PyResult<Self> {
        let key_arr = match key {
            Some(k) => {
                if k.len() != 32 {
                    return Err(CoreError::invalid_key(format!(
                        "ChaCha20-Poly1305 key must be 32 bytes, got {}",
                        k.len()
                    ))
                    .into());
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(k);
                Some(arr)
            }
            None => None,
        };
        Ok(Self::new_internal(key_arr, use_extracted_nonce))
    }

    pub fn has_key(&self) -> bool {
        self.key.is_some()
    }

    pub fn initialize_key(&mut self, key: &[u8]) -> PyResult<()> {
        if key.len() != 32 {
            return Err(CoreError::invalid_key(format!(
                "ChaCha20-Poly1305 key must be 32 bytes, got {}",
                key.len()
            ))
            .into());
        }
        if let Some(ref mut old) = self.key {
            old.zeroize();
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(key);
        self.key = Some(arr);
        self.nonce = 0;
        self.replay_window.clear();
        self.highest_received_nonce = 0;
        Ok(())
    }

    pub fn clear_key(&mut self) {
        if let Some(ref mut old) = self.key {
            old.zeroize();
        }
        self.key = None;
    }

    pub fn encrypt(&mut self, plaintext: &[u8], aad: &[u8]) -> PyResult<Vec<u8>> {
        Ok(self.encrypt_internal(plaintext, aad)?)
    }

    pub fn decrypt(&mut self, ciphertext: &[u8], aad: &[u8]) -> PyResult<Vec<u8>> {
        Ok(self.decrypt_internal(ciphertext, aad)?)
    }

    #[getter]
    pub fn key(&self) -> Option<Vec<u8>> {
        self.key.map(|k| k.to_vec())
    }

    #[getter]
    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    #[setter]
    pub fn set_nonce(&mut self, val: u64) {
        self.nonce = val;
    }

    #[getter]
    pub fn highest_received_nonce(&self) -> u64 {
        self.highest_received_nonce
    }

    #[setter]
    pub fn set_highest_received_nonce(&mut self, val: u64) {
        self.highest_received_nonce = val;
    }

    #[getter]
    pub fn replay_window(&self) -> HashSet<u64> {
        self.replay_window.clone()
    }

    #[setter]
    pub fn set_replay_window(&mut self, window: HashSet<u64>) {
        self.replay_window = window;
    }

    #[getter]
    pub fn use_extracted_nonce(&self) -> bool {
        self.use_extracted_nonce
    }

    pub fn needs_rekey(&self) -> bool {
        self.needs_rekey_internal()
    }

    pub fn is_nonce_exhausted(&self) -> bool {
        self.is_nonce_exhausted_internal()
    }
}

// ---------------------------------------------------------------------------
// NativeNoiseSymmetricState
// ---------------------------------------------------------------------------

#[pyclass(module = "bitchat._bitchat_core")]
#[derive(Clone)]
pub struct NativeNoiseSymmetricState {
    hash: [u8; 32],
    chaining_key: [u8; 32],
    cipher_state: NativeNoiseCipherState,
}

impl Drop for NativeNoiseSymmetricState {
    fn drop(&mut self) {
        self.chaining_key.zeroize();
    }
}

impl NativeNoiseSymmetricState {
    #[allow(clippy::too_many_arguments)]
    pub fn new_internal(protocol_name: &str) -> Self {
        let name_bytes = protocol_name.as_bytes();
        let initial_hash = if name_bytes.len() <= 32 {
            let mut h = [0u8; 32];
            h[..name_bytes.len()].copy_from_slice(name_bytes);
            h
        } else {
            let digest = Sha256::digest(name_bytes);
            let mut h = [0u8; 32];
            h.copy_from_slice(&digest);
            h
        };
        Self {
            hash: initial_hash,
            chaining_key: initial_hash,
            cipher_state: NativeNoiseCipherState::new_internal(None, false),
        }
    }

    pub fn mix_key_internal(&mut self, ikm: &[u8]) -> Result<(), CoreError> {
        let mut outputs = noise_hkdf_slices(&self.chaining_key, ikm, 2)?;
        self.chaining_key.copy_from_slice(&outputs[0]);
        self.cipher_state
            .initialize_key(&outputs[1])
            .map_err(|_| CoreError::noise("Failed to initialize cipher key"))?;
        for out in &mut outputs {
            out.zeroize();
        }
        Ok(())
    }

    pub fn mix_hash_internal(&mut self, data: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(self.hash);
        hasher.update(data);
        let digest = hasher.finalize();
        self.hash.copy_from_slice(&digest);
    }

    pub fn mix_key_and_hash_internal(&mut self, ikm: &[u8]) -> Result<(), CoreError> {
        let mut outputs = noise_hkdf_slices(&self.chaining_key, ikm, 3)?;
        self.chaining_key.copy_from_slice(&outputs[0]);
        self.mix_hash_internal(&outputs[1]);
        self.cipher_state
            .initialize_key(&outputs[2])
            .map_err(|_| CoreError::noise("Failed to initialize cipher key"))?;
        for out in &mut outputs {
            out.zeroize();
        }
        Ok(())
    }

    pub fn encrypt_and_hash_internal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CoreError> {
        if self.cipher_state.has_key() {
            let ct = self.cipher_state.encrypt_internal(plaintext, &self.hash)?;
            self.mix_hash_internal(&ct);
            Ok(ct)
        } else {
            self.mix_hash_internal(plaintext);
            Ok(plaintext.to_vec())
        }
    }

    pub fn decrypt_and_hash_internal(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CoreError> {
        if self.cipher_state.has_key() {
            if ciphertext.is_empty() {
                self.mix_hash_internal(b"");
                return Ok(Vec::new());
            }
            let pt = self
                .cipher_state
                .decrypt_internal(ciphertext, &self.hash)
                .map_err(|_| {
                    CoreError::authentication("Noise handshake payload authentication failed")
                })?;
            self.mix_hash_internal(ciphertext);
            Ok(pt)
        } else {
            self.mix_hash_internal(ciphertext);
            Ok(ciphertext.to_vec())
        }
    }

    pub fn split_internal(
        &self,
    ) -> Result<(NativeNoiseCipherState, NativeNoiseCipherState), CoreError> {
        let mut outputs = noise_hkdf_slices(&self.chaining_key, b"", 2)?;
        let c1 = NativeNoiseCipherState::new_internal(Some(outputs[0]), true);
        let c2 = NativeNoiseCipherState::new_internal(Some(outputs[1]), true);
        for out in &mut outputs {
            out.zeroize();
        }
        Ok((c1, c2))
    }
}

#[pymethods]
impl NativeNoiseSymmetricState {
    #[new]
    pub fn new(protocol_name: &str) -> Self {
        Self::new_internal(protocol_name)
    }

    pub fn has_cipher_key(&self) -> bool {
        self.cipher_state.has_key()
    }

    pub fn get_handshake_hash(&self) -> Vec<u8> {
        self.hash.to_vec()
    }

    pub fn get_chaining_key(&self) -> Vec<u8> {
        self.chaining_key.to_vec()
    }

    pub fn mix_key(&mut self, ikm: &[u8]) -> PyResult<()> {
        Ok(self.mix_key_internal(ikm)?)
    }

    pub fn mix_hash(&mut self, data: &[u8]) {
        self.mix_hash_internal(data);
    }

    pub fn mix_key_and_hash(&mut self, ikm: &[u8]) -> PyResult<()> {
        Ok(self.mix_key_and_hash_internal(ikm)?)
    }

    pub fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> PyResult<Vec<u8>> {
        Ok(self.encrypt_and_hash_internal(plaintext)?)
    }

    pub fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> PyResult<Vec<u8>> {
        Ok(self.decrypt_and_hash_internal(ciphertext)?)
    }

    pub fn split(&self) -> PyResult<(NativeNoiseCipherState, NativeNoiseCipherState)> {
        Ok(self.split_internal()?)
    }
}

// ---------------------------------------------------------------------------
// NativeNoiseHandshakeState
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeRole {
    Initiator,
    Responder,
}

impl HandshakeRole {
    pub fn from_str_role(role: &str) -> Result<Self, CoreError> {
        match role {
            "initiator" | "INITIATOR" => Ok(Self::Initiator),
            "responder" | "RESPONDER" => Ok(Self::Responder),
            _ => Err(CoreError::value_err(format!(
                "Invalid Noise role: {}",
                role
            ))),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Initiator => "initiator",
            Self::Responder => "responder",
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum HandshakeToken {
    E,
    S,
    EE,
    ES,
    SE,
}

const XX_PATTERN_0: &[HandshakeToken] = &[HandshakeToken::E];
const XX_PATTERN_1: &[HandshakeToken] = &[
    HandshakeToken::E,
    HandshakeToken::EE,
    HandshakeToken::S,
    HandshakeToken::ES,
];
const XX_PATTERN_2: &[HandshakeToken] = &[HandshakeToken::S, HandshakeToken::SE];
const XX_PATTERNS: &[&[HandshakeToken]] = &[XX_PATTERN_0, XX_PATTERN_1, XX_PATTERN_2];

#[pyclass(module = "bitchat._bitchat_core")]
pub struct NativeNoiseHandshakeState {
    role: HandshakeRole,
    local_static_private: [u8; 32],
    local_static_public: [u8; 32],
    local_ephemeral_private: Option<[u8; 32]>,
    local_ephemeral_public: Option<[u8; 32]>,
    remote_static_public: Option<[u8; 32]>,
    remote_ephemeral_public: Option<[u8; 32]>,
    symmetric_state: NativeNoiseSymmetricState,
    current_pattern: usize,
    fixed_ephemeral_private: Option<[u8; 32]>,
}

impl Drop for NativeNoiseHandshakeState {
    fn drop(&mut self) {
        self.local_static_private.zeroize();
        if let Some(ref mut eph) = self.local_ephemeral_private {
            eph.zeroize();
        }
        if let Some(ref mut fixed) = self.fixed_ephemeral_private {
            fixed.zeroize();
        }
    }
}

impl NativeNoiseHandshakeState {
    #[allow(clippy::too_many_arguments)]
    pub fn new_internal(
        role: HandshakeRole,
        local_static_private: &[u8],
        remote_static_public: Option<&[u8]>,
        fixed_ephemeral_private: Option<&[u8]>,
    ) -> Result<Self, CoreError> {
        let local_static_public = x25519_public_from_private_slice(local_static_private)?;
        let mut static_priv = [0u8; 32];
        static_priv.copy_from_slice(local_static_private);

        let remote_static = match remote_static_public {
            Some(r) => Some(validate_x25519_public_key_slice(r)?),
            None => None,
        };

        let fixed_eph = match fixed_ephemeral_private {
            Some(f) => {
                if f.len() != 32 {
                    return Err(CoreError::invalid_key(
                        "Ephemeral private key must be 32 bytes",
                    ));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(f);
                Some(arr)
            }
            None => None,
        };

        let mut symmetric_state = NativeNoiseSymmetricState::new_internal(NOISE_PROTOCOL_NAME);
        // Empty prologue for XX pattern (noise_protocol.rs line 662)
        symmetric_state.mix_hash_internal(b"");

        Ok(Self {
            role,
            local_static_private: static_priv,
            local_static_public,
            local_ephemeral_private: None,
            local_ephemeral_public: None,
            remote_static_public: remote_static,
            remote_ephemeral_public: None,
            symmetric_state,
            current_pattern: 0,
            fixed_ephemeral_private: fixed_eph,
        })
    }

    pub fn is_complete_internal(&self) -> bool {
        self.current_pattern >= XX_PATTERNS.len()
    }

    fn dh_mix_key(
        &mut self,
        local_private: Option<[u8; 32]>,
        remote_public: Option<[u8; 32]>,
        label: &str,
    ) -> Result<(), CoreError> {
        let mut priv_key = local_private.ok_or_else(|| {
            CoreError::noise(format!(
                "Missing local private key for DH operation: {}",
                label
            ))
        })?;
        let pub_key = remote_public.ok_or_else(|| {
            CoreError::noise(format!(
                "Missing remote public key for DH operation: {}",
                label
            ))
        })?;
        let mut shared = x25519_dh_slices(&priv_key, &pub_key)?;
        priv_key.zeroize();
        let res = self.symmetric_state.mix_key_internal(&shared);
        shared.zeroize();
        res
    }

    pub fn write_message_internal(&mut self, payload: &[u8]) -> Result<Vec<u8>, CoreError> {
        if self.is_complete_internal() {
            return Err(CoreError::noise_state(
                "Handshake is complete; cannot write more messages",
            ));
        }

        let mut message_buffer = Vec::with_capacity(96 + payload.len());
        let tokens = XX_PATTERNS[self.current_pattern];

        for &token in tokens {
            match token {
                HandshakeToken::E => {
                    let eph_priv = if let Some(mut fixed) = self.fixed_ephemeral_private.take() {
                        let out = fixed;
                        fixed.zeroize();
                        out
                    } else {
                        let mut k = [0u8; 32];
                        OsRng.fill_bytes(&mut k);
                        k
                    };
                    let eph_pub = x25519_public_from_private_slice(&eph_priv)?;
                    self.local_ephemeral_private = Some(eph_priv);
                    self.local_ephemeral_public = Some(eph_pub);
                    message_buffer.extend_from_slice(&eph_pub);
                    self.symmetric_state.mix_hash_internal(&eph_pub);
                }
                HandshakeToken::S => {
                    let pub_s = self.local_static_public;
                    let enc_s = self.symmetric_state.encrypt_and_hash_internal(&pub_s)?;
                    message_buffer.extend_from_slice(&enc_s);
                }
                HandshakeToken::EE => {
                    self.dh_mix_key(
                        self.local_ephemeral_private,
                        self.remote_ephemeral_public,
                        "EE",
                    )?;
                }
                HandshakeToken::ES => match self.role {
                    HandshakeRole::Initiator => {
                        self.dh_mix_key(
                            self.local_ephemeral_private,
                            self.remote_static_public,
                            "ES(initiator)",
                        )?;
                    }
                    HandshakeRole::Responder => {
                        self.dh_mix_key(
                            Some(self.local_static_private),
                            self.remote_ephemeral_public,
                            "ES(responder)",
                        )?;
                    }
                },
                HandshakeToken::SE => match self.role {
                    HandshakeRole::Initiator => {
                        self.dh_mix_key(
                            Some(self.local_static_private),
                            self.remote_ephemeral_public,
                            "SE(initiator)",
                        )?;
                    }
                    HandshakeRole::Responder => {
                        self.dh_mix_key(
                            self.local_ephemeral_private,
                            self.remote_static_public,
                            "SE(responder)",
                        )?;
                    }
                },
            }
        }

        let encrypted_payload = self.symmetric_state.encrypt_and_hash_internal(payload)?;
        message_buffer.extend_from_slice(&encrypted_payload);
        self.current_pattern += 1;
        Ok(message_buffer)
    }

    pub fn read_message_internal(&mut self, message: &[u8]) -> Result<Vec<u8>, CoreError> {
        if self.is_complete_internal() {
            return Err(CoreError::noise_state(
                "Handshake is complete; cannot read more messages",
            ));
        }

        let tokens = XX_PATTERNS[self.current_pattern];
        let mut offset = 0usize;

        for &token in tokens {
            match token {
                HandshakeToken::E => {
                    if offset + DH_KEY_SIZE > message.len() {
                        return Err(CoreError::noise(format!(
                            "Message too short for ephemeral key at offset {}",
                            offset
                        )));
                    }
                    let mut eph_bytes = [0u8; DH_KEY_SIZE];
                    eph_bytes.copy_from_slice(&message[offset..offset + DH_KEY_SIZE]);
                    offset += DH_KEY_SIZE;
                    self.remote_ephemeral_public = Some(eph_bytes);
                    self.symmetric_state.mix_hash_internal(&eph_bytes);
                }
                HandshakeToken::S => {
                    let key_len = if self.symmetric_state.has_cipher_key() {
                        DH_KEY_SIZE + TAG_SIZE
                    } else {
                        DH_KEY_SIZE
                    };
                    if offset + key_len > message.len() {
                        return Err(CoreError::noise(format!(
                            "Message too short for static key at offset {}",
                            offset
                        )));
                    }
                    let static_data = &message[offset..offset + key_len];
                    offset += key_len;
                    let decrypted_static = self
                        .symmetric_state
                        .decrypt_and_hash_internal(static_data)?;
                    if decrypted_static.len() != DH_KEY_SIZE {
                        return Err(CoreError::authentication(format!(
                            "Decrypted static key has wrong length: {}",
                            decrypted_static.len()
                        )));
                    }
                    let validated =
                        validate_x25519_public_key_slice(&decrypted_static).map_err(|_| {
                            CoreError::authentication("Static public key validation failed")
                        })?;
                    self.remote_static_public = Some(validated);
                }
                HandshakeToken::EE => {
                    self.dh_mix_key(
                        self.local_ephemeral_private,
                        self.remote_ephemeral_public,
                        "EE",
                    )?;
                }
                HandshakeToken::ES => match self.role {
                    HandshakeRole::Initiator => {
                        self.dh_mix_key(
                            self.local_ephemeral_private,
                            self.remote_static_public,
                            "ES(initiator)",
                        )?;
                    }
                    HandshakeRole::Responder => {
                        self.dh_mix_key(
                            Some(self.local_static_private),
                            self.remote_ephemeral_public,
                            "ES(responder)",
                        )?;
                    }
                },
                HandshakeToken::SE => match self.role {
                    HandshakeRole::Initiator => {
                        self.dh_mix_key(
                            Some(self.local_static_private),
                            self.remote_ephemeral_public,
                            "SE(initiator)",
                        )?;
                    }
                    HandshakeRole::Responder => {
                        self.dh_mix_key(
                            self.local_ephemeral_private,
                            self.remote_static_public,
                            "SE(responder)",
                        )?;
                    }
                },
            }
        }

        let payload_bytes = &message[offset..];
        let decrypted_payload = self
            .symmetric_state
            .decrypt_and_hash_internal(payload_bytes)?;
        self.current_pattern += 1;
        Ok(decrypted_payload)
    }

    pub fn get_transport_ciphers_internal(
        &self,
    ) -> Result<(NativeNoiseCipherState, NativeNoiseCipherState), CoreError> {
        if !self.is_complete_internal() {
            return Err(CoreError::noise_state(
                "Handshake is not complete; cannot get transport ciphers",
            ));
        }
        let (c1, c2) = self.symmetric_state.split_internal()?;
        match self.role {
            HandshakeRole::Initiator => Ok((c1, c2)),
            HandshakeRole::Responder => Ok((c2, c1)),
        }
    }
}

#[pymethods]
impl NativeNoiseHandshakeState {
    #[new]
    #[pyo3(signature = (role, local_static_private, remote_static_public=None, fixed_ephemeral_private=None))]
    pub fn new(
        role: &str,
        local_static_private: &[u8],
        remote_static_public: Option<&[u8]>,
        fixed_ephemeral_private: Option<&[u8]>,
    ) -> PyResult<Self> {
        let parsed_role = HandshakeRole::from_str_role(role)?;
        Ok(Self::new_internal(
            parsed_role,
            local_static_private,
            remote_static_public,
            fixed_ephemeral_private,
        )?)
    }

    pub fn is_handshake_complete(&self) -> bool {
        self.is_complete_internal()
    }

    pub fn get_transport_ciphers(
        &self,
    ) -> PyResult<(NativeNoiseCipherState, NativeNoiseCipherState)> {
        Ok(self.get_transport_ciphers_internal()?)
    }

    pub fn get_remote_static_public_key(&self) -> Option<Vec<u8>> {
        self.remote_static_public.map(|k| k.to_vec())
    }

    pub fn get_local_ephemeral_public_key(&self) -> Option<Vec<u8>> {
        self.local_ephemeral_public.map(|k| k.to_vec())
    }

    pub fn get_remote_ephemeral_public_key(&self) -> Option<Vec<u8>> {
        self.remote_ephemeral_public.map(|k| k.to_vec())
    }

    pub fn get_handshake_hash(&self) -> Vec<u8> {
        self.symmetric_state.get_handshake_hash()
    }

    pub fn set_ephemeral_private_for_testing(&mut self, key: &[u8]) -> PyResult<()> {
        if key.len() != 32 {
            return Err(CoreError::invalid_key("Ephemeral private key must be 32 bytes").into());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(key);
        self.fixed_ephemeral_private = Some(arr);
        Ok(())
    }

    pub fn write_message(&mut self, payload: &[u8]) -> PyResult<Vec<u8>> {
        Ok(self.write_message_internal(payload)?)
    }

    pub fn read_message(&mut self, message: &[u8]) -> PyResult<Vec<u8>> {
        Ok(self.read_message_internal(message)?)
    }
}

// ---------------------------------------------------------------------------
// NoiseIdentityAnnounce (0x13) Payload Validation
// ---------------------------------------------------------------------------

/// Validate a `0x13 NoiseIdentityAnnounce` payload.
///
/// Accepts either:
/// - 32 bytes: `[32B X25519 static public key]`
/// - 64 bytes: `[32B X25519 static public key || 32B SHA-256 identity hash]`
///
/// Validates Curve25519 low-order rejection and verifies hash consistency when
/// the 32-byte hash suffix is present. Returns `(static_public_key, fingerprint_hex)`.
pub fn parse_noise_identity_announce_bytes(
    payload: &[u8],
) -> Result<([u8; 32], String), CoreError> {
    if payload.len() != 32 && payload.len() != 64 {
        return Err(CoreError::authentication(format!(
            "Invalid NoiseIdentityAnnounce payload length: expected 32 or 64 bytes, got {}",
            payload.len()
        )));
    }
    let validated = validate_x25519_public_key_slice(&payload[..32]).map_err(|_| {
        CoreError::authentication("NoiseIdentityAnnounce contains invalid X25519 static public key")
    })?;
    let digest = Sha256::digest(validated);
    if payload.len() == 64 && !constant_time_eq(&digest, &payload[32..64]) {
        return Err(CoreError::authentication(
            "NoiseIdentityAnnounce identity hash does not match static public key",
        ));
    }
    Ok((validated, sha256_hex(&validated)))
}

#[pyfunction]
pub fn parse_noise_identity_announce_raw(payload: &[u8]) -> PyResult<(Vec<u8>, String)> {
    let (pk, fp) = parse_noise_identity_announce_bytes(payload)?;
    Ok((pk.to_vec(), fp))
}

// ---------------------------------------------------------------------------
// NativeNoiseSession
// ---------------------------------------------------------------------------

#[pyclass(module = "bitchat._bitchat_core")]
pub struct NativeNoiseSession {
    local_x25519_private: [u8; 32],
    local_x25519_public: [u8; 32],
    local_peer_id_hex: String,
    remote_peer_id: String,
    role: HandshakeRole,
    state: String,
    handshake_state: Option<NativeNoiseHandshakeState>,
    send_cipher: Option<NativeNoiseCipherState>,
    recv_cipher: Option<NativeNoiseCipherState>,
    remote_static_public: Option<[u8; 32]>,
    handshake_hash: Option<[u8; 32]>,
    remote_fingerprint: Option<String>,
    expected_fingerprint: Option<String>,
    identity_mode: String,
    trust_level: String,
    allow_legacy_peer_id: bool,
    handshake_started_at: Option<f64>,
    state_machine: NativeHandshakeStateMachine,
}

impl Drop for NativeNoiseSession {
    fn drop(&mut self) {
        self.local_x25519_private.zeroize();
    }
}

impl NativeNoiseSession {
    #[allow(clippy::chunks_exact_to_as_chunks)]
    fn decode_hex_8_bytes(hex_str: &str) -> Result<[u8; 8], CoreError> {
        let clean = hex_str.trim().to_ascii_lowercase();
        if clean.len() != 16 {
            return Err(CoreError::authentication(
                "Remote peer ID must be 16 hexadecimal characters",
            ));
        }
        let mut out = [0u8; 8];
        for (i, chunk) in clean.as_bytes().chunks_exact(2).enumerate() {
            let s = std::str::from_utf8(chunk).map_err(|_| {
                CoreError::authentication("Remote peer ID is not valid hexadecimal")
            })?;
            out[i] = u8::from_str_radix(s, 16).map_err(|_| {
                CoreError::authentication("Remote peer ID is not valid hexadecimal")
            })?;
        }
        Ok(out)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_internal(
        local_x25519_private: &[u8],
        local_peer_id_hex: &str,
        remote_peer_id: &str,
        role: Option<HandshakeRole>,
        transport: &str,
        now: f64,
        allow_legacy_peer_id: bool,
        expected_fingerprint: Option<String>,
    ) -> Result<Self, CoreError> {
        let local_pub = x25519_public_from_private_slice(local_x25519_private)?;
        let mut priv_arr = [0u8; 32];
        priv_arr.copy_from_slice(local_x25519_private);

        let clean_local = local_peer_id_hex.trim().to_ascii_lowercase();
        let clean_remote = remote_peer_id.trim().to_ascii_lowercase();

        let resolved_role = match role {
            Some(r) => r,
            None => {
                if clean_local.is_empty() || clean_remote.is_empty() {
                    return Err(CoreError::value_err("Peer IDs must not be empty"));
                }
                if clean_local < clean_remote {
                    HandshakeRole::Initiator
                } else {
                    HandshakeRole::Responder
                }
            }
        };

        let initial_mode = match Self::decode_hex_8_bytes(&clean_remote) {
            Ok(id) if is_legacy_tui_peer_id_bytes(&id) => "legacy_tui",
            _ => "modern",
        };

        Ok(Self {
            local_x25519_private: priv_arr,
            local_x25519_public: local_pub,
            local_peer_id_hex: clean_local,
            remote_peer_id: remote_peer_id.to_string(),
            role: resolved_role,
            state: "uninitialized".to_string(),
            handshake_state: None,
            send_cipher: None,
            recv_cipher: None,
            remote_static_public: None,
            handshake_hash: None,
            remote_fingerprint: None,
            expected_fingerprint: expected_fingerprint.map(|s| s.trim().to_ascii_lowercase()),
            identity_mode: initial_mode.to_string(),
            trust_level: "observed".to_string(),
            allow_legacy_peer_id,
            handshake_started_at: None,
            state_machine: NativeHandshakeStateMachine::new(remote_peer_id, transport, now, 3),
        })
    }

    pub fn state_str(&self) -> &str {
        &self.state
    }

    pub fn role_enum(&self) -> HandshakeRole {
        self.role
    }

    pub fn is_established_internal(&self) -> bool {
        self.state == "established"
    }

    pub fn handshake_started_at_internal(&self) -> Option<f64> {
        self.handshake_started_at
    }

    pub fn remote_fingerprint_internal(&self) -> Option<&str> {
        self.remote_fingerprint.as_deref()
    }

    pub fn identity_mode_internal(&self) -> &str {
        &self.identity_mode
    }

    pub fn trust_level_internal(&self) -> &str {
        &self.trust_level
    }

    pub fn record_phase_internal(&mut self, target_phase: &str, reason: &str, now: f64) {
        let _ = self.state_machine.transition_to(target_phase, reason, now);
    }

    pub fn reset_for_rehandshake_internal(&mut self, new_role: Option<HandshakeRole>, now: f64) {
        if let Some(r) = new_role {
            self.role = r;
        }
        self.state = "uninitialized".to_string();
        self.handshake_state = None;
        self.send_cipher = None;
        self.recv_cipher = None;
        self.remote_static_public = None;
        self.handshake_hash = None;
        self.remote_fingerprint = None;
        self.trust_level = "observed".to_string();
        self.handshake_started_at = None;
        self.record_phase_internal(
            "HandshakeInitiated",
            "Session reset for fresh handshake",
            now,
        );
    }

    pub fn start_handshake_internal(&mut self, now: f64) -> Result<Option<Vec<u8>>, CoreError> {
        if self.state != "uninitialized" {
            return Err(CoreError::noise_state(format!(
                "start_handshake() called in invalid state: {}",
                self.state
            )));
        }
        let mut hs = NativeNoiseHandshakeState::new_internal(
            self.role,
            &self.local_x25519_private,
            None,
            None,
        )?;
        self.state = "handshaking".to_string();
        self.handshake_started_at = Some(now);
        self.record_phase_internal(
            "HandshakeInitiated",
            &format!("Handshake started as {}", self.role.as_str()),
            now,
        );
        if self.role == HandshakeRole::Initiator {
            let msg1 = hs.write_message_internal(b"")?;
            self.handshake_state = Some(hs);
            self.record_phase_internal("AwaitingMessage2", "Noise XX Message 1 [E] generated", now);
            Ok(Some(msg1))
        } else {
            self.handshake_state = Some(hs);
            Ok(None)
        }
    }

    pub fn process_handshake_message_internal(
        &mut self,
        message: &[u8],
        now: f64,
    ) -> Result<Option<Vec<u8>>, CoreError> {
        let result: Result<Option<Vec<u8>>, CoreError> = (|| {
            if self.state == "uninitialized" && self.role == HandshakeRole::Responder {
                let hs = NativeNoiseHandshakeState::new_internal(
                    self.role,
                    &self.local_x25519_private,
                    None,
                    None,
                )?;
                self.handshake_state = Some(hs);
                self.state = "handshaking".to_string();
                self.handshake_started_at = Some(now);
                self.record_phase_internal(
                    "HandshakeInitiated",
                    "Responder auto-initialized on inbound Message 1",
                    now,
                );
            }

            if self.state != "handshaking" {
                return Err(CoreError::noise_state(format!(
                    "process_handshake_message() called in invalid state: {}",
                    self.state
                )));
            }

            let hs = self
                .handshake_state
                .as_mut()
                .ok_or_else(|| CoreError::noise_state("Handshake state is not initialised"))?;

            let _payload = hs.read_message_internal(message)?;

            let response = if !hs.is_complete_internal() {
                let out = hs.write_message_internal(b"")?;
                if self.role == HandshakeRole::Responder {
                    self.record_phase_internal(
                        "AwaitingMessage3",
                        "Noise XX Message 2 [E, EE, S, ES] generated",
                        now,
                    );
                }
                Some(out)
            } else {
                None
            };

            let is_done = self
                .handshake_state
                .as_ref()
                .is_some_and(|h| h.is_complete_internal());
            if is_done {
                self.record_phase_internal(
                    "AuthenticatingIdentity",
                    "Verifying remote static key and peer-ID binding",
                    now,
                );
                self.finalise_handshake(now)?;
            }
            Ok(response)
        })();

        match result {
            Ok(resp) => Ok(resp),
            Err(err) => {
                self.handshake_state = None;
                self.send_cipher = None;
                self.recv_cipher = None;
                self.state = "failed".to_string();
                self.record_phase_internal(
                    "Failed",
                    &format!("Handshake failed: {}", err.kind.tag()),
                    now,
                );
                Err(err)
            }
        }
    }

    fn finalise_handshake(&mut self, now: f64) -> Result<(), CoreError> {
        let hs = self
            .handshake_state
            .as_ref()
            .ok_or_else(|| CoreError::noise_state("Handshake state is not initialised"))?;

        let remote_static = match hs.remote_static_public {
            Some(k) => k,
            None => {
                self.state = "failed".to_string();
                self.handshake_state = None;
                return Err(CoreError::authentication(
                    "Noise handshake did not authenticate a remote key",
                ));
            }
        };

        let claimed_peer_id = match Self::decode_hex_8_bytes(&self.remote_peer_id) {
            Ok(id) => id,
            Err(err) => {
                self.state = "failed".to_string();
                self.handshake_state = None;
                return Err(err);
            }
        };

        if constant_time_eq(&remote_static, &self.local_x25519_public) {
            self.state = "failed".to_string();
            self.handshake_state = None;
            return Err(CoreError::authentication(
                "Self-connection rejected: remote peer authenticated with local device identity",
            ));
        }

        let digest = Sha256::digest(remote_static);
        let mut authenticated_peer_id = [0u8; 8];
        authenticated_peer_id.copy_from_slice(&digest[..8]);
        let fp = sha256_hex(&remote_static);

        let is_legacy = is_legacy_tui_peer_id_bytes(&claimed_peer_id);
        let modern_matches = constant_time_eq(&authenticated_peer_id, &claimed_peer_id);

        if modern_matches {
            self.identity_mode = "modern".to_string();
        } else if is_legacy && self.allow_legacy_peer_id {
            // Controlled legacy bitchat-tui compatibility path:
            // Noise static key is authenticated by XX; routing peer ID is bound only
            // after authentication and checked against any pinned fingerprint.
            self.identity_mode = "legacy_tui".to_string();
        } else {
            self.state = "failed".to_string();
            self.handshake_state = None;
            return Err(CoreError::authentication(
                "Authenticated Noise static key does not match claimed peer ID",
            ));
        }

        // Collision-safe identity check: reject silent reassignment if peer ID is
        // already bound to a different static-key fingerprint.
        if let Some(ref expected_fp) = self.expected_fingerprint {
            if !constant_time_eq(expected_fp.as_bytes(), fp.as_bytes()) {
                self.state = "failed".to_string();
                self.handshake_state = None;
                return Err(CoreError::authentication(
                    "Conflicting identity mapping: authenticated Noise static key does not match pinned fingerprint",
                ));
            }
        }

        let (send_c, recv_c) = hs.get_transport_ciphers_internal()?;
        let mut h_hash = [0u8; 32];
        h_hash.copy_from_slice(&hs.symmetric_state.hash);

        self.send_cipher = Some(send_c);
        self.recv_cipher = Some(recv_c);
        self.remote_static_public = Some(remote_static);
        self.handshake_hash = Some(h_hash);
        self.remote_fingerprint = Some(fp);
        self.trust_level = "authenticated".to_string();
        self.handshake_state = None;
        self.state = "established".to_string();
        let mode_note = if self.identity_mode == "legacy_tui" {
            "Noise XX transport established (legacy TUI peer ID bound post-auth)"
        } else {
            "Noise XX transport established and peer identity verified"
        };
        self.record_phase_internal("Established", mode_note, now);
        Ok(())
    }

    pub fn encrypt_internal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CoreError> {
        if self.state != "established" {
            return Err(CoreError::noise_state(format!(
                "encrypt() requires ESTABLISHED state, got {}",
                self.state
            )));
        }
        let send = self
            .send_cipher
            .as_mut()
            .ok_or_else(|| CoreError::noise_state("No send cipher available"))?;
        match send.encrypt_internal(plaintext, b"") {
            Ok(ct) => Ok(ct),
            Err(err) => {
                if err.kind == crate::errors::CoreErrorKind::InvalidNonce {
                    // Fail closed on nonce exhaustion: invalidate transport ciphers so
                    // caller must establish a fresh session.
                    self.send_cipher = None;
                    self.recv_cipher = None;
                    self.state = "failed".to_string();
                    self.record_phase_internal(
                        "Failed",
                        "Transport nonce exhausted; rekey required",
                        0.0,
                    );
                }
                Err(err)
            }
        }
    }

    pub fn decrypt_internal(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, CoreError> {
        if self.state != "established" {
            return Err(CoreError::noise_state(format!(
                "decrypt() requires ESTABLISHED state, got {}",
                self.state
            )));
        }
        let recv = self
            .recv_cipher
            .as_mut()
            .ok_or_else(|| CoreError::noise_state("No receive cipher available"))?;
        recv.decrypt_internal(ciphertext, b"")
    }

    pub fn close_internal(&mut self, now: f64) {
        self.record_phase_internal("Closing", "Session closing", now);
        self.send_cipher = None;
        self.recv_cipher = None;
        self.handshake_state = None;
        self.state = "closed".to_string();
        self.record_phase_internal("Closed", "Session closed", now);
    }
}

#[pymethods]
impl NativeNoiseSession {
    #[new]
    #[pyo3(signature = (
        local_x25519_private,
        local_peer_id_hex,
        remote_peer_id,
        role=None,
        transport="lan",
        now=0.0,
        allow_legacy_peer_id=true,
        expected_fingerprint=None
    ))]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        local_x25519_private: &[u8],
        local_peer_id_hex: &str,
        remote_peer_id: &str,
        role: Option<&str>,
        transport: &str,
        now: f64,
        allow_legacy_peer_id: bool,
        expected_fingerprint: Option<String>,
    ) -> PyResult<Self> {
        let parsed_role = match role {
            Some(r) => Some(HandshakeRole::from_str_role(r)?),
            None => None,
        };
        Ok(Self::new_internal(
            local_x25519_private,
            local_peer_id_hex,
            remote_peer_id,
            parsed_role,
            transport,
            now,
            allow_legacy_peer_id,
            expected_fingerprint,
        )?)
    }

    #[getter]
    pub fn state(&self) -> &str {
        &self.state
    }

    #[setter]
    pub fn set_state(&mut self, state: &str) {
        self.state = state.to_string();
    }

    #[getter]
    pub fn role(&self) -> &str {
        self.role.as_str()
    }

    #[setter]
    pub fn set_role(&mut self, role: &str) -> PyResult<()> {
        self.role = HandshakeRole::from_str_role(role)?;
        Ok(())
    }

    #[getter]
    pub fn local_peer_id_hex(&self) -> &str {
        &self.local_peer_id_hex
    }

    #[getter]
    pub fn remote_peer_id(&self) -> &str {
        &self.remote_peer_id
    }

    #[getter]
    pub fn remote_fingerprint(&self) -> Option<String> {
        self.remote_fingerprint.clone()
    }

    #[setter]
    pub fn set_remote_fingerprint(&mut self, fp: Option<String>) {
        self.remote_fingerprint = fp;
    }

    #[getter]
    pub fn expected_fingerprint(&self) -> Option<String> {
        self.expected_fingerprint.clone()
    }

    #[setter]
    pub fn set_expected_fingerprint(&mut self, fp: Option<String>) {
        self.expected_fingerprint = fp.map(|s| s.trim().to_ascii_lowercase());
    }

    #[getter]
    pub fn identity_mode(&self) -> &str {
        &self.identity_mode
    }

    #[getter]
    pub fn trust_level(&self) -> &str {
        &self.trust_level
    }

    #[getter]
    pub fn allow_legacy_peer_id(&self) -> bool {
        self.allow_legacy_peer_id
    }

    #[getter]
    pub fn handshake_started_at(&self) -> Option<f64> {
        self.handshake_started_at
    }

    #[setter]
    pub fn set_handshake_started_at(&mut self, ts: Option<f64>) {
        self.handshake_started_at = ts;
    }

    #[getter]
    pub fn observable_phase(&self) -> &str {
        self.state_machine.phase()
    }

    #[getter]
    pub fn diagnostic_reason(&self) -> &str {
        self.state_machine.diagnostic_reason()
    }

    #[getter]
    pub fn remote_static_public(&self) -> Option<Vec<u8>> {
        self.remote_static_public.map(|k| k.to_vec())
    }

    #[getter]
    pub fn handshake_hash(&self) -> Option<Vec<u8>> {
        self.handshake_hash.map(|h| h.to_vec())
    }

    #[getter]
    pub fn is_established(&self) -> bool {
        self.state == "established"
    }

    #[getter]
    pub fn send_nonce(&self) -> u64 {
        self.send_cipher.as_ref().map_or(0, |c| c.nonce)
    }

    #[getter]
    pub fn highest_received_nonce(&self) -> u64 {
        self.recv_cipher
            .as_ref()
            .map_or(0, |c| c.highest_received_nonce)
    }

    pub fn needs_rekey(&self) -> bool {
        self.send_cipher
            .as_ref()
            .is_some_and(|c| c.needs_rekey_internal())
    }

    pub fn mark_user_verified(&mut self) -> PyResult<()> {
        if self.remote_fingerprint.is_none() {
            return Err(CoreError::noise_state(
                "Cannot mark peer verified before authenticating a remote static key",
            )
            .into());
        }
        self.trust_level = "verified".to_string();
        Ok(())
    }

    #[pyo3(signature = (target_phase, reason="", now=0.0))]
    pub fn record_phase(&mut self, target_phase: &str, reason: &str, now: f64) -> PyResult<String> {
        self.state_machine.transition_to(target_phase, reason, now)
    }

    pub fn phase_history(&self) -> Vec<(String, f64, String)> {
        self.state_machine.history()
    }

    #[pyo3(signature = (new_role=None, now=0.0))]
    pub fn reset_for_rehandshake(&mut self, new_role: Option<&str>, now: f64) -> PyResult<()> {
        let parsed_role = match new_role {
            Some(r) => Some(HandshakeRole::from_str_role(r)?),
            None => None,
        };
        self.reset_for_rehandshake_internal(parsed_role, now);
        Ok(())
    }

    #[pyo3(signature = (now=0.0))]
    pub fn start_handshake(&mut self, now: f64) -> PyResult<Option<Vec<u8>>> {
        Ok(self.start_handshake_internal(now)?)
    }

    #[pyo3(signature = (message, now=0.0))]
    pub fn process_handshake_message(
        &mut self,
        message: &[u8],
        now: f64,
    ) -> PyResult<Option<Vec<u8>>> {
        Ok(self.process_handshake_message_internal(message, now)?)
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> PyResult<Vec<u8>> {
        Ok(self.encrypt_internal(plaintext)?)
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> PyResult<Vec<u8>> {
        Ok(self.decrypt_internal(ciphertext)?)
    }

    #[pyo3(signature = (now=0.0))]
    pub fn close(&mut self, now: f64) {
        self.close_internal(now);
    }
}

// ---------------------------------------------------------------------------
// Deterministic Handshake State Machine (Section 7)
// ---------------------------------------------------------------------------

/// Observable handshake lifecycle states for LAN and BLE sessions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservableSessionPhase {
    Discovered,
    Connecting,
    TransportConnected,
    GattReady,
    HandshakeInitiated,
    AwaitingMessage2,
    AwaitingMessage3,
    AuthenticatingIdentity,
    Established,
    Failed,
    Closing,
    Closed,
}

impl ObservableSessionPhase {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Discovered => "Discovered",
            Self::Connecting => "Connecting",
            Self::TransportConnected => "TransportConnected",
            Self::GattReady => "GattReady",
            Self::HandshakeInitiated => "HandshakeInitiated",
            Self::AwaitingMessage2 => "AwaitingMessage2",
            Self::AwaitingMessage3 => "AwaitingMessage3",
            Self::AuthenticatingIdentity => "AuthenticatingIdentity",
            Self::Established => "Established",
            Self::Failed => "Failed",
            Self::Closing => "Closing",
            Self::Closed => "Closed",
        }
    }

    pub fn from_str_phase(phase: &str) -> Result<Self, CoreError> {
        match phase {
            "Discovered" => Ok(Self::Discovered),
            "Connecting" => Ok(Self::Connecting),
            "TransportConnected" => Ok(Self::TransportConnected),
            "GattReady" => Ok(Self::GattReady),
            "HandshakeInitiated" => Ok(Self::HandshakeInitiated),
            "AwaitingMessage2" => Ok(Self::AwaitingMessage2),
            "AwaitingMessage3" => Ok(Self::AwaitingMessage3),
            "AuthenticatingIdentity" => Ok(Self::AuthenticatingIdentity),
            "Established" => Ok(Self::Established),
            "Failed" => Ok(Self::Failed),
            "Closing" => Ok(Self::Closing),
            "Closed" => Ok(Self::Closed),
            _ => Err(CoreError::value_err(format!(
                "Unknown observable session phase: {}",
                phase
            ))),
        }
    }

    pub const fn timeout_seconds(self) -> f64 {
        match self {
            Self::Discovered => 120.0,
            Self::Connecting => 10.0,
            Self::TransportConnected => 30.0,
            Self::GattReady => 30.0,
            Self::HandshakeInitiated => 10.0,
            Self::AwaitingMessage2 => 10.0,
            Self::AwaitingMessage3 => 10.0,
            Self::AuthenticatingIdentity => 5.0,
            Self::Established => 3600.0,
            Self::Failed => 0.0,
            Self::Closing => 5.0,
            Self::Closed => 0.0,
        }
    }

    pub const fn allowed_events(self) -> &'static [&'static str] {
        match self {
            Self::Discovered => &[
                "connect",
                "transport_connected",
                "gatt_ready",
                "handshake_initiated",
                "msg1_sent",
                "msg1_received",
                "fail",
                "close",
            ],
            Self::Connecting => &[
                "transport_connected",
                "gatt_ready",
                "fail",
                "timeout",
                "close",
            ],
            Self::TransportConnected => &[
                "gatt_ready",
                "handshake_initiated",
                "msg1_sent",
                "msg1_received",
                "fail",
                "timeout",
                "close",
            ],
            Self::GattReady => &[
                "handshake_initiated",
                "msg1_sent",
                "msg1_received",
                "fail",
                "timeout",
                "close",
            ],
            Self::HandshakeInitiated => &[
                "msg1_sent",
                "msg1_received",
                "msg2_sent",
                "fail",
                "timeout",
                "close",
            ],
            Self::AwaitingMessage2 => &[
                "msg2_received",
                "msg3_sent",
                "authenticating",
                "established",
                "fail",
                "timeout",
                "close",
            ],
            Self::AwaitingMessage3 => &[
                "msg3_received",
                "authenticating",
                "established",
                "fail",
                "timeout",
                "close",
            ],
            Self::AuthenticatingIdentity => &["established", "fail", "timeout", "close"],
            Self::Established => &["rehandshake", "closing", "close", "fail"],
            Self::Failed => &["reset", "connect", "handshake_initiated", "close"],
            Self::Closing => &["closed", "close"],
            Self::Closed => &["reset", "connect", "discovered"],
        }
    }

    pub const fn entry_condition(self) -> &'static str {
        match self {
            Self::Discovered => "Peer beacon or BLE advertisement parsed",
            Self::Connecting => "Outbound TCP or BLE connection initiated",
            Self::TransportConnected => "TCP stream or BLE link connected",
            Self::GattReady => "BLE GATT service resolved, notify subscribed, MTU negotiated",
            Self::HandshakeInitiated => "Noise XX handshake requested or started",
            Self::AwaitingMessage2 => "Noise XX Message 1 [E] transmitted; awaiting Message 2",
            Self::AwaitingMessage3 => {
                "Noise XX Message 2 [E, EE, S, ES] transmitted; awaiting Message 3"
            }
            Self::AuthenticatingIdentity => {
                "Noise XX static key extracted; verifying peer-ID binding and TOFU"
            }
            Self::Established => "Noise XX transport ciphers split and identity verified",
            Self::Failed => "Transport, GATT, timeout, or cryptographic verification error",
            Self::Closing => "Graceful session or transport teardown started",
            Self::Closed => "Session and transport resources released and zeroized",
        }
    }

    pub const fn retry_behavior(self) -> &'static str {
        match self {
            Self::Discovered => "Await user or automatic connection trigger",
            Self::Connecting => "Bounded exponential backoff up to max_retries",
            Self::TransportConnected => "Trigger Announce/HandshakeRequest if idle",
            Self::GattReady => "Transmit queued Announce and initiate Noise handshake",
            Self::HandshakeInitiated => "Retry HandshakeRequest or initiate Message 1 on timeout",
            Self::AwaitingMessage2 => "Discard stale handshake and retry up to max_retries",
            Self::AwaitingMessage3 => "Discard half-open responder state and await fresh Init",
            Self::AuthenticatingIdentity => "No automatic retry on authentication mismatch",
            Self::Established => "No retry needed; transport active",
            Self::Failed => "Allow clean re-initiation if retry budget remains",
            Self::Closing => "Force close after 5s timeout",
            Self::Closed => "Require fresh connection or discovery event",
        }
    }

    pub const fn cleanup_behavior(self) -> &'static str {
        match self {
            Self::Failed | Self::Closing | Self::Closed => {
                "Zeroize ephemeral/cipher keys, cancel pending timers, purge half-open state"
            }
            _ => "Retain bounded pending message queue until Established or Failed",
        }
    }
}

#[pyclass(module = "bitchat._bitchat_core")]
#[derive(Clone)]
pub struct NativeHandshakeStateMachine {
    peer_id: String,
    transport: String,
    phase: ObservableSessionPhase,
    entered_at: f64,
    retry_count: u32,
    max_retries: u32,
    diagnostic_reason: String,
    history: Vec<(String, f64, String)>,
}

#[pymethods]
impl NativeHandshakeStateMachine {
    #[new]
    #[pyo3(signature = (peer_id, transport="lan", now=0.0, max_retries=3))]
    pub fn new(peer_id: &str, transport: &str, now: f64, max_retries: u32) -> Self {
        let phase = ObservableSessionPhase::Discovered;
        Self {
            peer_id: peer_id.to_string(),
            transport: transport.to_string(),
            phase,
            entered_at: now,
            retry_count: 0,
            max_retries,
            diagnostic_reason: "Peer discovered".to_string(),
            history: vec![(
                phase.as_str().to_string(),
                now,
                "Peer discovered".to_string(),
            )],
        }
    }

    #[getter]
    pub fn peer_id(&self) -> &str {
        &self.peer_id
    }

    #[getter]
    pub fn transport(&self) -> &str {
        &self.transport
    }

    #[getter]
    pub fn phase(&self) -> &str {
        self.phase.as_str()
    }

    #[getter]
    pub fn entered_at(&self) -> f64 {
        self.entered_at
    }

    #[getter]
    pub fn retry_count(&self) -> u32 {
        self.retry_count
    }

    #[getter]
    pub fn max_retries(&self) -> u32 {
        self.max_retries
    }

    #[getter]
    pub fn diagnostic_reason(&self) -> &str {
        &self.diagnostic_reason
    }

    pub fn timeout_seconds(&self) -> f64 {
        self.phase.timeout_seconds()
    }

    pub fn entry_condition(&self) -> &str {
        self.phase.entry_condition()
    }

    pub fn retry_behavior(&self) -> &str {
        self.phase.retry_behavior()
    }

    pub fn cleanup_behavior(&self) -> &str {
        self.phase.cleanup_behavior()
    }

    pub fn allowed_events(&self) -> Vec<String> {
        self.phase
            .allowed_events()
            .iter()
            .map(|s| (*s).to_string())
            .collect()
    }

    pub fn is_timed_out(&self, now: f64) -> bool {
        let timeout = self.phase.timeout_seconds();
        if timeout <= 0.0 || self.phase == ObservableSessionPhase::Established {
            return false;
        }
        now >= self.entered_at && (now - self.entered_at) >= timeout
    }

    pub fn can_retry(&self) -> bool {
        self.retry_count < self.max_retries
    }

    #[pyo3(signature = (target_phase, reason="", now=0.0))]
    pub fn transition_to(
        &mut self,
        target_phase: &str,
        reason: &str,
        now: f64,
    ) -> PyResult<String> {
        let next = ObservableSessionPhase::from_str_phase(target_phase)?;
        if next == ObservableSessionPhase::Failed {
            self.retry_count = self.retry_count.saturating_add(1);
        } else if next == ObservableSessionPhase::Established {
            self.retry_count = 0;
        }
        self.phase = next;
        self.entered_at = now;
        self.diagnostic_reason = if reason.is_empty() {
            next.entry_condition().to_string()
        } else {
            reason.to_string()
        };
        if self.history.len() >= 32 {
            self.history.remove(0);
        }
        self.history.push((
            next.as_str().to_string(),
            now,
            self.diagnostic_reason.clone(),
        ));
        Ok(self.phase.as_str().to_string())
    }

    pub fn history(&self) -> Vec<(String, f64, String)> {
        self.history.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_noise_xx_deterministic_handshake_and_transport() {
        let alice_priv = [0x11u8; 32];
        let bob_priv = [0x22u8; 32];
        let alice_eph = [0x33u8; 32];
        let bob_eph = [0x44u8; 32];

        let mut initiator = NativeNoiseHandshakeState::new_internal(
            HandshakeRole::Initiator,
            &alice_priv,
            None,
            Some(&alice_eph),
        )
        .unwrap();
        let mut responder = NativeNoiseHandshakeState::new_internal(
            HandshakeRole::Responder,
            &bob_priv,
            None,
            Some(&bob_eph),
        )
        .unwrap();

        let msg1 = initiator.write_message_internal(b"").unwrap();
        assert_eq!(msg1.len(), 32);
        responder.read_message_internal(&msg1).unwrap();

        let msg2 = responder.write_message_internal(b"").unwrap();
        assert_eq!(msg2.len(), 32 + 48 + 16);
        initiator.read_message_internal(&msg2).unwrap();

        let msg3 = initiator.write_message_internal(b"").unwrap();
        assert_eq!(msg3.len(), 48 + 16);
        responder.read_message_internal(&msg3).unwrap();

        assert!(initiator.is_complete_internal());
        assert!(responder.is_complete_internal());
        assert_eq!(
            initiator.get_handshake_hash(),
            responder.get_handshake_hash()
        );

        let (mut i_send, mut i_recv) = initiator.get_transport_ciphers_internal().unwrap();
        let (mut r_send, mut r_recv) = responder.get_transport_ciphers_internal().unwrap();

        let ct = i_send.encrypt_internal(b"hello rust noise", b"").unwrap();
        let pt = r_recv.decrypt_internal(&ct, b"").unwrap();
        assert_eq!(pt, b"hello rust noise");

        // Replay of nonce 0 must fail
        assert!(r_recv.decrypt_internal(&ct, b"").is_err());

        let ct2 = r_send.encrypt_internal(b"reply from bob", b"").unwrap();
        let pt2 = i_recv.decrypt_internal(&ct2, b"").unwrap();
        assert_eq!(pt2, b"reply from bob");
    }

    #[test]
    fn test_nonce_exhaustion_fails_closed_and_failed_aead_does_not_mark_replay() {
        let key = [0x55u8; 32];
        let mut sender = NativeNoiseCipherState::new_internal(Some(key), true);
        let mut receiver = NativeNoiseCipherState::new_internal(Some(key), true);

        let ct0 = sender.encrypt_internal(b"valid nonce 0", b"").unwrap();
        // Tamper tag: decryption must fail AND must NOT record nonce 0 in replay window!
        let mut bad_ct0 = ct0.clone();
        *bad_ct0.last_mut().unwrap() ^= 0xFF;
        assert!(receiver.decrypt_internal(&bad_ct0, b"").is_err());
        assert!(!receiver.replay_window.contains(&0));

        // Legitimate nonce 0 still decrypts once, then replay is rejected
        assert_eq!(
            receiver.decrypt_internal(&ct0, b"").unwrap(),
            b"valid nonce 0"
        );
        assert!(receiver.decrypt_internal(&ct0, b"").is_err());

        // Nonce exhaustion at u32::MAX must fail closed without wrapping
        sender.nonce = NOISE_MAX_TRANSPORT_NONCE;
        assert!(sender.is_nonce_exhausted_internal());
        assert!(sender.needs_rekey_internal());
        let err = sender.encrypt_internal(b"must fail", b"").unwrap_err();
        assert_eq!(err.kind, crate::errors::CoreErrorKind::InvalidNonce);
        assert_eq!(sender.nonce, NOISE_MAX_TRANSPORT_NONCE);
    }

    #[test]
    fn test_native_session_legacy_tui_compat_and_collision_rejection() {
        let rustpy_priv = [0x12u8; 32];
        let rustpy_pub = x25519_public_from_private_slice(&rustpy_priv).unwrap();
        let rustpy_pid = crate::protocol::hex_encode_lower(&Sha256::digest(rustpy_pub)[..8]);

        let tui_priv = [0x34u8; 32];
        let tui_pub = x25519_public_from_private_slice(&tui_priv).unwrap();
        let tui_fp = sha256_hex(&tui_pub);
        // Legacy bitchat-tui peer ID: 4 random non-zero bytes zero-extended to 8 bytes
        let tui_legacy_pid = "deadbeef00000000";

        let mut rustpy_sess = NativeNoiseSession::new_internal(
            &rustpy_priv,
            &rustpy_pid,
            tui_legacy_pid,
            Some(HandshakeRole::Responder),
            "lan",
            1.0,
            true,
            None,
        )
        .unwrap();
        let mut tui_sess = NativeNoiseSession::new_internal(
            &tui_priv,
            tui_legacy_pid,
            &rustpy_pid,
            Some(HandshakeRole::Initiator),
            "lan",
            1.0,
            true,
            None,
        )
        .unwrap();

        let m1 = tui_sess.start_handshake_internal(1.0).unwrap().unwrap();
        let m2 = rustpy_sess
            .process_handshake_message_internal(&m1, 1.1)
            .unwrap()
            .unwrap();
        let m3 = tui_sess
            .process_handshake_message_internal(&m2, 1.2)
            .unwrap()
            .unwrap();
        assert!(rustpy_sess
            .process_handshake_message_internal(&m3, 1.3)
            .unwrap()
            .is_none());

        assert!(rustpy_sess.is_established_internal());
        assert_eq!(rustpy_sess.identity_mode_internal(), "legacy_tui");
        assert_eq!(rustpy_sess.trust_level_internal(), "authenticated");
        assert_eq!(
            rustpy_sess.remote_fingerprint_internal(),
            Some(tui_fp.as_str())
        );

        // Bidirectional transport
        let ct = tui_sess.encrypt_internal(b"hi from legacy tui").unwrap();
        assert_eq!(
            rustpy_sess.decrypt_internal(&ct).unwrap(),
            b"hi from legacy tui"
        );

        // Impostor with different static key reusing the same pinned legacy peer ID MUST be rejected!
        let impostor_priv = [0x78u8; 32];
        let mut pinned_rustpy = NativeNoiseSession::new_internal(
            &rustpy_priv,
            &rustpy_pid,
            tui_legacy_pid,
            Some(HandshakeRole::Responder),
            "lan",
            2.0,
            true,
            Some(tui_fp),
        )
        .unwrap();
        let mut impostor = NativeNoiseSession::new_internal(
            &impostor_priv,
            tui_legacy_pid,
            &rustpy_pid,
            Some(HandshakeRole::Initiator),
            "lan",
            2.0,
            true,
            None,
        )
        .unwrap();
        let im1 = impostor.start_handshake_internal(2.0).unwrap().unwrap();
        let im2 = pinned_rustpy
            .process_handshake_message_internal(&im1, 2.1)
            .unwrap()
            .unwrap();
        let im3 = impostor
            .process_handshake_message_internal(&im2, 2.2)
            .unwrap()
            .unwrap();
        let err = pinned_rustpy
            .process_handshake_message_internal(&im3, 2.3)
            .unwrap_err();
        assert_eq!(err.kind, crate::errors::CoreErrorKind::Authentication);
        assert_eq!(pinned_rustpy.state_str(), "failed");
    }

    #[test]
    fn test_parse_noise_identity_announce() {
        let priv_key = [0x99u8; 32];
        let pub_key = x25519_public_from_private_slice(&priv_key).unwrap();
        let digest = Sha256::digest(pub_key);
        let mut payload64 = Vec::with_capacity(64);
        payload64.extend_from_slice(&pub_key);
        payload64.extend_from_slice(&digest);

        let (pk32, fp32) = parse_noise_identity_announce_bytes(&pub_key).unwrap();
        let (pk64, fp64) = parse_noise_identity_announce_bytes(&payload64).unwrap();
        assert_eq!(pk32, pub_key);
        assert_eq!(pk64, pub_key);
        assert_eq!(fp32, fp64);

        // Tampered hash suffix rejected
        payload64[63] ^= 0x01;
        assert!(parse_noise_identity_announce_bytes(&payload64).is_err());
        // Invalid length rejected
        assert!(parse_noise_identity_announce_bytes(&[0u8; 16]).is_err());
    }
}
