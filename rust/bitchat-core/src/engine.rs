//! Native Rust Peer State Engine & Cohesive Protocol Engine (Phase 2.2 / Stage 3).
//!
//! Consolidates protocol-critical stateful execution inside Rust to eliminate
//! repeated PyO3 boundary crossings and guarantee single authoritative ownership of:
//! - Binary packet decoding, validation, and encoding
//! - Fragment reassembly (`NativeFragmentReassembler`)
//! - Mesh routing, TTL handling, deduplication, and per-peer rate limiting (`NativeMeshRouter`)
//! - Peer state management, anti-spoofing nicknames, and collision-safe identity
//!   bindings for modern RustPy and legacy `bitchat-tui` peers (`NativePeerStateEngine`)
//! - Noise XX session lifecycle, handshake arbitration, transport encryption/decryption,
//!   and bounded pending queues (`NativeNoiseSession`)
//! - Delivery acknowledgement and retry tracking (`NativeAckTracker`)

use std::collections::{HashMap, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

use pyo3::prelude::*;
use zeroize::Zeroize;

use crate::crypto::x25519_public_from_private_slice;
use crate::errors::CoreError;
use crate::fragmentation::{
    NativeFragmentReassembler, MSG_FRAGMENT_CONTINUE, MSG_FRAGMENT_END, MSG_FRAGMENT_START,
};
use crate::mesh::{NativeAckTracker, NativeMeshRouter};
use crate::noise::{parse_noise_identity_announce_bytes, HandshakeRole, NativeNoiseSession};
use crate::protocol::{
    decode_packet_slice, encode_packet_bytes, hex_encode_lower, is_legacy_tui_peer_id_bytes,
    parse_peer_id_hex_bytes, FLAG_HAS_RECIPIENT, PROTOCOL_VERSION,
};

pub const MSG_ANNOUNCE: u8 = 0x01;
pub const MSG_MESSAGE: u8 = 0x04;
pub const MSG_DELIVERY_ACK: u8 = 0x0A;
pub const MSG_NOISE_HANDSHAKE_INIT: u8 = 0x10;
pub const MSG_NOISE_HANDSHAKE_RESP: u8 = 0x11;
pub const MSG_NOISE_ENCRYPTED: u8 = 0x12;
pub const MSG_NOISE_IDENTITY_ANNOUNCE: u8 = 0x13;
pub const MSG_HANDSHAKE_REQUEST: u8 = 0x25;

pub const DEFAULT_MAX_PEERS: usize = 512;
pub const DEFAULT_MAX_PENDING_HANDSHAKES: usize = 64;
pub const DEFAULT_MAX_SESSIONS: usize = 256;
pub const DEFAULT_MAX_PENDING_PER_PEER: usize = 32;
pub const DEFAULT_MAX_TOTAL_PENDING: usize = 512;
pub const MAX_CHAT_MESSAGE_BYTES: usize = 32_768;
pub const DEFAULT_HANDSHAKE_TIMEOUT_SECONDS: f64 = 10.0;
pub const STALE_HANDSHAKE_RETRY_SECONDS: f64 = 2.0;
pub const DEFAULT_PEER_EXPIRY_SECONDS: f64 = 300.0;
pub const DEFAULT_PACKET_TTL: i64 = 7;

#[inline]
fn now_millis_u64() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

const MSG_FLAG_IS_PRIVATE: u8 = 0x02;
const MSG_FLAG_HAS_ORIGINAL_SENDER: u8 = 0x04;
const MSG_FLAG_HAS_RECIPIENT_NICKNAME: u8 = 0x08;
const MSG_FLAG_HAS_SENDER_PEER_ID: u8 = 0x10;
const MSG_FLAG_HAS_MENTIONS: u8 = 0x20;
const MSG_FLAG_HAS_CHANNEL: u8 = 0x40;
const MSG_FLAG_IS_ENCRYPTED: u8 = 0x80;
/// Lower bound for plausible Unix millisecond timestamps (2000-01-01T00:00:00Z).
const MIN_PLAUSIBLE_TIMESTAMP_MS: u64 = 946_684_800_000;
/// Upper bound for plausible Unix millisecond timestamps (2200-01-01T00:00:00Z).
const MAX_PLAUSIBLE_TIMESTAMP_MS: u64 = 7_258_118_400_000;

/// Attempt to parse a binary `BitchatMessage` payload matching `bitchat-tui` / Swift
/// (`src/payload_handling.rs`) and return its UTF-8 content string.
///
/// Requires a plausible millisecond timestamp and exact structural bounds so plain
/// UTF-8 messages are never misidentified as binary payloads.
pub(crate) fn try_parse_bitchat_message_content(data: &[u8]) -> Option<String> {
    if data.len() < 13 {
        return None;
    }
    let flags = data[0];
    if (flags & MSG_FLAG_IS_ENCRYPTED) != 0 {
        return None;
    }
    let ts_bytes: [u8; 8] = data[1..9].try_into().ok()?;
    let timestamp_ms = u64::from_be_bytes(ts_bytes);
    if !(MIN_PLAUSIBLE_TIMESTAMP_MS..=MAX_PLAUSIBLE_TIMESTAMP_MS).contains(&timestamp_ms) {
        return None;
    }
    let mut offset = 9usize;

    let id_len = *data.get(offset)? as usize;
    offset += 1;
    if offset + id_len > data.len() {
        return None;
    }
    let _id = std::str::from_utf8(&data[offset..offset + id_len]).ok()?;
    offset += id_len;

    let sender_len = *data.get(offset)? as usize;
    offset += 1;
    if offset + sender_len > data.len() {
        return None;
    }
    let _sender = std::str::from_utf8(&data[offset..offset + sender_len]).ok()?;
    offset += sender_len;

    let content_len_bytes: [u8; 2] = data.get(offset..offset + 2)?.try_into().ok()?;
    let content_len = u16::from_be_bytes(content_len_bytes) as usize;
    offset += 2;
    if offset + content_len > data.len() {
        return None;
    }
    let content = std::str::from_utf8(&data[offset..offset + content_len])
        .ok()?
        .to_string();
    offset += content_len;

    // Validate optional trailing fields match bounds cleanly.
    let skip_len_prefixed = |off: &mut usize| -> Option<()> {
        let field_len = *data.get(*off)? as usize;
        *off += 1;
        if *off + field_len > data.len() {
            return None;
        }
        *off += field_len;
        Some(())
    };

    if (flags & MSG_FLAG_HAS_ORIGINAL_SENDER) != 0 {
        skip_len_prefixed(&mut offset)?;
    }
    if (flags & MSG_FLAG_HAS_RECIPIENT_NICKNAME) != 0 {
        skip_len_prefixed(&mut offset)?;
    }
    if (flags & MSG_FLAG_HAS_SENDER_PEER_ID) != 0 {
        skip_len_prefixed(&mut offset)?;
    }
    if (flags & MSG_FLAG_HAS_MENTIONS) != 0 {
        let count = *data.get(offset)? as usize;
        offset += 1;
        for _ in 0..count {
            skip_len_prefixed(&mut offset)?;
        }
    }
    if (flags & MSG_FLAG_HAS_CHANNEL) != 0 {
        skip_len_prefixed(&mut offset)?;
    }

    if offset == data.len() {
        Some(content)
    } else {
        None
    }
}

/// Encode a `bitchat-tui` / Swift compatible binary `BitchatMessage` payload.
#[pyfunction]
#[pyo3(signature = (sender, content, sender_peer_id, message_id="msg-1", is_private=true, channel=None, timestamp_ms=None))]
pub fn encode_bitchat_message_payload_raw(
    sender: &str,
    content: &str,
    sender_peer_id: &str,
    message_id: &str,
    is_private: bool,
    channel: Option<&str>,
    timestamp_ms: Option<u64>,
) -> PyResult<Vec<u8>> {
    let id_bytes = message_id.as_bytes();
    let sender_bytes = sender.as_bytes();
    let content_bytes = content.as_bytes();
    let peer_bytes = sender_peer_id.as_bytes();
    if id_bytes.len() > u8::MAX as usize
        || sender_bytes.len() > u8::MAX as usize
        || peer_bytes.len() > u8::MAX as usize
        || content_bytes.len() > u16::MAX as usize
    {
        return Err(CoreError::invalid_packet("BitchatMessage field exceeds wire bounds").into());
    }
    let mut flags: u8 = MSG_FLAG_HAS_SENDER_PEER_ID;
    if is_private {
        flags |= MSG_FLAG_IS_PRIVATE;
    }
    if let Some(ch) = channel {
        if ch.len() > u8::MAX as usize {
            return Err(CoreError::invalid_packet("Channel name exceeds 255 bytes").into());
        }
        flags |= MSG_FLAG_HAS_CHANNEL;
    }
    let ts = timestamp_ms.unwrap_or_else(now_millis_u64);
    let mut out = Vec::with_capacity(
        13 + id_bytes.len() + sender_bytes.len() + content_bytes.len() + peer_bytes.len() + 16,
    );
    out.push(flags);
    out.extend_from_slice(&ts.to_be_bytes());
    out.push(id_bytes.len() as u8);
    out.extend_from_slice(id_bytes);
    out.push(sender_bytes.len() as u8);
    out.extend_from_slice(sender_bytes);
    out.extend_from_slice(&(content_bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(content_bytes);
    out.push(peer_bytes.len() as u8);
    out.extend_from_slice(peer_bytes);
    if let Some(ch) = channel {
        out.push(ch.len() as u8);
        out.extend_from_slice(ch.as_bytes());
    }
    Ok(out)
}

pub(crate) fn decode_chat_payload_lossy(payload: &[u8]) -> String {
    // 1. Nested BitchatPacket (bitchat-tui notification_handlers.rs:1454 format)
    if payload.len() >= 21 && payload[0] == PROTOCOL_VERSION && payload[1] == MSG_MESSAGE {
        if let Ok((_ver, msg_type, _ttl, _ts, _flags, _sender, _recip, inner_payload, _sig)) =
            decode_packet_slice(payload)
        {
            if msg_type == MSG_MESSAGE {
                if let Some(content) = try_parse_bitchat_message_content(&inner_payload) {
                    return content;
                }
                if let Ok(text) = std::str::from_utf8(&inner_payload) {
                    return text.to_string();
                }
            }
        }
    }

    // 2. [0x04] || binary BitchatMessage (bitchat-tui message_handlers.rs:168 format)
    if payload.len() > 1 && payload[0] == MSG_MESSAGE {
        if let Some(content) = try_parse_bitchat_message_content(&payload[1..]) {
            return content;
        }
    }

    // 3. Bare binary BitchatMessage
    if let Some(content) = try_parse_bitchat_message_content(payload) {
        return content;
    }

    // 4. [0x04] || UTF-8 message prefix
    if payload.len() > 1 && payload[0] == MSG_MESSAGE {
        if let Ok(s) = std::str::from_utf8(&payload[1..]) {
            return s.to_string();
        }
    }

    // 5. Raw UTF-8 text (or lossy fallback)
    match std::str::from_utf8(payload) {
        Ok(s) => s.to_string(),
        Err(_) => String::from_utf8_lossy(payload).into_owned(),
    }
}

/// Decode a chat payload (supporting raw UTF-8, `[0x04] || UTF-8`, `[0x04] || BitchatMessage`,
/// bare binary `BitchatMessage`, and nested `BitchatPacket(Message)`).
#[pyfunction]
pub fn decode_chat_payload_raw(payload: &[u8]) -> String {
    decode_chat_payload_lossy(payload)
}

// ---------------------------------------------------------------------------
// NativePeerStateEngine (Stage 3)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct PeerRecord {
    peer_id_hex: String,
    identity_mode: String,
    nickname: Option<String>,
    endpoint: Option<String>,
    observed_fingerprint: Option<String>,
    authenticated_fingerprint: Option<String>,
    trust_level: String, // "observed" | "authenticated" | "verified"
    last_seen: f64,
    is_connected: bool,
}

#[derive(Debug, Clone)]
struct IdentityBinding {
    fingerprint: String,
    identity_mode: String,
    trust_level: String, // "authenticated" | "verified"
}

/// Native Rust Peer State & Collision-Safe Identity Binding Engine.
///
/// Separates:
/// - Observed / cached peer hints (unauthenticated discovery / announce)
/// - Authenticated Noise static-key possession (`trust_level = "authenticated"`)
/// - User out-of-band contact verification (`trust_level = "verified"`)
///
/// Rejects silent reassignment of any established `peer_id <-> fingerprint`
/// binding across both modern and legacy `bitchat-tui` routing IDs.
#[pyclass(module = "bitchat._bitchat_core")]
pub struct NativePeerStateEngine {
    local_peer_id_hex: String,
    local_nickname: String,
    max_peers: usize,
    max_pending_per_peer: usize,
    max_total_pending: usize,
    peers: HashMap<String, PeerRecord>,
    /// Authoritative collision-safe bindings (`peer_id_hex -> IdentityBinding`).
    bindings: HashMap<String, IdentityBinding>,
    /// Reverse collision index (`fingerprint -> peer_id_hex`).
    fingerprint_owner: HashMap<String, String>,
    /// Bounded pending plaintext messages awaiting Noise handshake completion.
    pending_messages: HashMap<String, VecDeque<String>>,
    total_pending_messages: usize,
}

impl NativePeerStateEngine {
    fn normalize_pid(pid: &str) -> String {
        pid.trim().to_ascii_lowercase()
    }

    fn classify_mode(pid_hex: &str) -> &'static str {
        match parse_peer_id_hex_bytes(pid_hex) {
            Ok(id) if is_legacy_tui_peer_id_bytes(&id) => "legacy_tui",
            _ => "modern",
        }
    }

    fn evict_peer_if_needed(&mut self) {
        if self.peers.len() < self.max_peers {
            return;
        }
        // Prefer evicting oldest disconnected, unauthenticated peer first
        let candidate = self
            .peers
            .iter()
            .filter(|(_, r)| !r.is_connected && r.authenticated_fingerprint.is_none())
            .min_by(|a, b| {
                a.1.last_seen
                    .partial_cmp(&b.1.last_seen)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .or_else(|| {
                self.peers
                    .iter()
                    .filter(|(_, r)| !r.is_connected)
                    .min_by(|a, b| {
                        a.1.last_seen
                            .partial_cmp(&b.1.last_seen)
                            .unwrap_or(std::cmp::Ordering::Equal)
                    })
            })
            .or_else(|| {
                self.peers.iter().min_by(|a, b| {
                    a.1.last_seen
                        .partial_cmp(&b.1.last_seen)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
            })
            .map(|(k, _)| k.clone());

        if let Some(key) = candidate {
            self.peers.remove(&key);
        }
    }

    pub fn get_bound_fingerprint_internal(&self, peer_id_hex: &str) -> Option<String> {
        let key = Self::normalize_pid(peer_id_hex);
        self.bindings.get(&key).map(|b| b.fingerprint.clone())
    }

    pub fn bind_authenticated_identity_internal(
        &mut self,
        peer_id_hex: &str,
        fingerprint: &str,
        identity_mode: &str,
        now: f64,
    ) -> Result<(), CoreError> {
        let pid = Self::normalize_pid(peer_id_hex);
        let fp = fingerprint.trim().to_ascii_lowercase();
        if pid.len() != 16 || fp.len() != 64 {
            return Err(CoreError::authentication(
                "Invalid peer ID or fingerprint length for identity binding",
            ));
        }

        // 1. Check existing peer_id -> fingerprint binding (prevent silent overwrite)
        if let Some(existing) = self.bindings.get(&pid) {
            if existing.fingerprint != fp {
                return Err(CoreError::authentication(format!(
                    "Identity collision detected for peer {}: bound fingerprint does not match authenticated Noise key",
                    &pid[..8]
                )));
            }
        }

        // 2. Check reverse fingerprint -> peer_id collision index
        if let Some(existing_owner) = self.fingerprint_owner.get(&fp) {
            if existing_owner != &pid {
                return Err(CoreError::authentication(format!(
                    "Fingerprint collision detected: static key is already bound to peer {}",
                    &existing_owner[..8.min(existing_owner.len())]
                )));
            }
        }

        // Preserve user-verified status if already verified; otherwise mark authenticated
        let trust_level = match self.bindings.get(&pid) {
            Some(existing) if existing.trust_level == "verified" => "verified".to_string(),
            _ => "authenticated".to_string(),
        };

        self.bindings.insert(
            pid.clone(),
            IdentityBinding {
                fingerprint: fp.clone(),
                identity_mode: identity_mode.to_string(),
                trust_level: trust_level.clone(),
            },
        );
        self.fingerprint_owner.insert(fp.clone(), pid.clone());

        self.evict_peer_if_needed();
        let entry = self.peers.entry(pid.clone()).or_insert_with(|| PeerRecord {
            peer_id_hex: pid.clone(),
            identity_mode: identity_mode.to_string(),
            nickname: None,
            endpoint: None,
            observed_fingerprint: None,
            authenticated_fingerprint: None,
            trust_level: trust_level.clone(),
            last_seen: now,
            is_connected: true,
        });
        entry.identity_mode = identity_mode.to_string();
        entry.authenticated_fingerprint = Some(fp);
        entry.trust_level = trust_level;
        entry.last_seen = now;
        Ok(())
    }

    pub fn record_observed_identity_announce_internal(
        &mut self,
        peer_id_hex: &str,
        fingerprint: &str,
        now: f64,
    ) -> Result<(), CoreError> {
        let pid = Self::normalize_pid(peer_id_hex);
        let fp = fingerprint.trim().to_ascii_lowercase();

        // Unauthenticated announce MUST NEVER overwrite an existing authenticated/verified binding
        if let Some(existing) = self.bindings.get(&pid) {
            if existing.fingerprint != fp {
                return Err(CoreError::authentication(format!(
                    "Rejected conflicting NoiseIdentityAnnounce for bound peer {}",
                    &pid[..8.min(pid.len())]
                )));
            }
        }

        self.evict_peer_if_needed();
        let mode = Self::classify_mode(&pid).to_string();
        let entry = self.peers.entry(pid.clone()).or_insert_with(|| PeerRecord {
            peer_id_hex: pid,
            identity_mode: mode,
            nickname: None,
            endpoint: None,
            observed_fingerprint: None,
            authenticated_fingerprint: None,
            trust_level: "observed".to_string(),
            last_seen: now,
            is_connected: false,
        });
        entry.observed_fingerprint = Some(fp);
        entry.last_seen = now;
        Ok(())
    }

    pub fn is_nickname_spoofed_internal(&self, peer_id_hex: &str, nickname: &str) -> bool {
        let clean_nick = nickname.trim().to_ascii_lowercase();
        if clean_nick.is_empty() {
            return true;
        }
        let clean_pid = Self::normalize_pid(peer_id_hex);
        if !self.local_nickname.is_empty()
            && clean_nick == self.local_nickname.trim().to_ascii_lowercase()
        {
            return true;
        }
        for (pid, record) in &self.peers {
            if pid != &clean_pid {
                if let Some(ref existing_nick) = record.nickname {
                    if existing_nick.trim().to_ascii_lowercase() == clean_nick {
                        return true;
                    }
                }
            }
        }
        false
    }

    pub fn enqueue_pending_internal(&mut self, peer_id_hex: &str, text: String) -> bool {
        let pid = Self::normalize_pid(peer_id_hex);
        if self.total_pending_messages >= self.max_total_pending {
            return false;
        }
        let queue = self.pending_messages.entry(pid).or_default();
        if queue.len() >= self.max_pending_per_peer {
            return false;
        }
        queue.push_back(text);
        self.total_pending_messages += 1;
        true
    }

    pub fn drain_pending_internal(&mut self, peer_id_hex: &str) -> Vec<String> {
        let pid = Self::normalize_pid(peer_id_hex);
        match self.pending_messages.remove(&pid) {
            Some(queue) => {
                self.total_pending_messages =
                    self.total_pending_messages.saturating_sub(queue.len());
                queue.into_iter().collect()
            }
            None => Vec::new(),
        }
    }
}

#[pymethods]
impl NativePeerStateEngine {
    #[new]
    #[pyo3(signature = (
        local_peer_id_hex,
        local_nickname="Anonymous",
        max_peers=DEFAULT_MAX_PEERS,
        max_pending_per_peer=DEFAULT_MAX_PENDING_PER_PEER,
        max_total_pending=DEFAULT_MAX_TOTAL_PENDING
    ))]
    pub fn new(
        local_peer_id_hex: &str,
        local_nickname: &str,
        max_peers: usize,
        max_pending_per_peer: usize,
        max_total_pending: usize,
    ) -> Self {
        Self {
            local_peer_id_hex: Self::normalize_pid(local_peer_id_hex),
            local_nickname: local_nickname.trim().to_string(),
            max_peers: max_peers.max(1),
            max_pending_per_peer: max_pending_per_peer.max(1),
            max_total_pending: max_total_pending.max(1),
            peers: HashMap::new(),
            bindings: HashMap::new(),
            fingerprint_owner: HashMap::new(),
            pending_messages: HashMap::new(),
            total_pending_messages: 0,
        }
    }

    pub fn set_local_nickname(&mut self, nickname: &str) {
        self.local_nickname = nickname.trim().to_string();
    }

    #[pyo3(signature = (peer_id_hex, fingerprint, verified=false))]
    pub fn seed_trusted_contact(
        &mut self,
        peer_id_hex: &str,
        fingerprint: &str,
        verified: bool,
    ) -> PyResult<()> {
        let pid = Self::normalize_pid(peer_id_hex);
        let fp = fingerprint.trim().to_ascii_lowercase();
        let mode = Self::classify_mode(&pid).to_string();
        let trust = if verified {
            "verified"
        } else {
            "authenticated"
        }
        .to_string();
        self.bindings.insert(
            pid.clone(),
            IdentityBinding {
                fingerprint: fp.clone(),
                identity_mode: mode,
                trust_level: trust,
            },
        );
        self.fingerprint_owner.insert(fp, pid);
        Ok(())
    }

    #[pyo3(signature = (peer_id_hex, fingerprint, identity_mode="modern", now=0.0))]
    pub fn bind_authenticated_identity(
        &mut self,
        peer_id_hex: &str,
        fingerprint: &str,
        identity_mode: &str,
        now: f64,
    ) -> PyResult<()> {
        Ok(self.bind_authenticated_identity_internal(
            peer_id_hex,
            fingerprint,
            identity_mode,
            now,
        )?)
    }

    #[pyo3(signature = (peer_id_hex, fingerprint, now=0.0))]
    pub fn record_observed_identity_announce(
        &mut self,
        peer_id_hex: &str,
        fingerprint: &str,
        now: f64,
    ) -> PyResult<()> {
        Ok(self.record_observed_identity_announce_internal(peer_id_hex, fingerprint, now)?)
    }

    pub fn get_bound_identity_mode(&self, peer_id_hex: &str) -> Option<String> {
        let pid = Self::normalize_pid(peer_id_hex);
        self.bindings.get(&pid).map(|b| b.identity_mode.clone())
    }

    pub fn get_bound_fingerprint(&self, peer_id_hex: &str) -> Option<String> {
        self.get_bound_fingerprint_internal(peer_id_hex)
    }

    pub fn get_trust_level(&self, peer_id_hex: &str) -> String {
        let pid = Self::normalize_pid(peer_id_hex);
        if let Some(binding) = self.bindings.get(&pid) {
            return binding.trust_level.clone();
        }
        if let Some(rec) = self.peers.get(&pid) {
            return rec.trust_level.clone();
        }
        "observed".to_string()
    }

    pub fn mark_verified(&mut self, peer_id_hex: &str) -> PyResult<()> {
        let pid = Self::normalize_pid(peer_id_hex);
        let binding = self.bindings.get_mut(&pid).ok_or_else(|| {
            CoreError::authentication("Cannot verify a peer that has not been Noise-authenticated")
        })?;
        binding.trust_level = "verified".to_string();
        if let Some(rec) = self.peers.get_mut(&pid) {
            rec.trust_level = "verified".to_string();
        }
        Ok(())
    }

    /// Explicit trust reset / migration: removes an established identity binding
    /// so a new static key may be bound on subsequent authentication.
    pub fn untrust_peer(&mut self, peer_id_hex: &str) -> bool {
        let pid = Self::normalize_pid(peer_id_hex);
        if let Some(removed) = self.bindings.remove(&pid) {
            self.fingerprint_owner.remove(&removed.fingerprint);
            if let Some(rec) = self.peers.get_mut(&pid) {
                rec.authenticated_fingerprint = None;
                rec.trust_level = "observed".to_string();
            }
            return true;
        }
        false
    }

    pub fn is_nickname_spoofed(&self, peer_id_hex: &str, nickname: &str) -> bool {
        self.is_nickname_spoofed_internal(peer_id_hex, nickname)
    }

    #[pyo3(signature = (peer_id_hex, endpoint=None, nickname=None, connected=None, now=0.0))]
    pub fn observe_peer(
        &mut self,
        peer_id_hex: &str,
        endpoint: Option<&str>,
        nickname: Option<&str>,
        connected: Option<bool>,
        now: f64,
    ) -> bool {
        let pid = Self::normalize_pid(peer_id_hex);
        if pid.is_empty() || pid == self.local_peer_id_hex {
            return false;
        }
        let accepted_nick = match nickname {
            Some(n) if !self.is_nickname_spoofed_internal(&pid, n) => {
                Some(n.trim().chars().take(32).collect::<String>())
            }
            _ => None,
        };

        self.evict_peer_if_needed();
        let mode = Self::classify_mode(&pid).to_string();
        let bound_fp = self.bindings.get(&pid).map(|b| b.fingerprint.clone());
        let bound_trust = self
            .bindings
            .get(&pid)
            .map(|b| b.trust_level.clone())
            .unwrap_or_else(|| "observed".to_string());

        let record = self.peers.entry(pid.clone()).or_insert_with(|| PeerRecord {
            peer_id_hex: pid,
            identity_mode: mode,
            nickname: None,
            endpoint: None,
            observed_fingerprint: None,
            authenticated_fingerprint: bound_fp,
            trust_level: bound_trust,
            last_seen: now,
            is_connected: false,
        });
        record.last_seen = now;
        if let Some(ep) = endpoint {
            if !ep.is_empty() {
                record.endpoint = Some(ep.to_string());
            }
        }
        if let Some(nick) = accepted_nick {
            record.nickname = Some(nick);
        }
        if let Some(conn) = connected {
            record.is_connected = conn;
        }
        true
    }

    pub fn enqueue_pending_message(&mut self, peer_id_hex: &str, text: String) -> bool {
        self.enqueue_pending_internal(peer_id_hex, text)
    }

    pub fn drain_pending_messages(&mut self, peer_id_hex: &str) -> Vec<String> {
        self.drain_pending_internal(peer_id_hex)
    }

    pub fn clear_pending_messages(&mut self, peer_id_hex: &str) {
        let _ = self.drain_pending_internal(peer_id_hex);
    }

    pub fn pending_message_count(&self, peer_id_hex: Option<&str>) -> usize {
        match peer_id_hex {
            Some(pid) => self
                .pending_messages
                .get(&Self::normalize_pid(pid))
                .map_or(0, |q| q.len()),
            None => self.total_pending_messages,
        }
    }

    #[pyo3(signature = (max_age_seconds=DEFAULT_PEER_EXPIRY_SECONDS, now=0.0))]
    pub fn prune_expired_peers(&mut self, max_age_seconds: f64, now: f64) -> Vec<String> {
        let expired: Vec<String> = self
            .peers
            .iter()
            .filter(|(_, rec)| !rec.is_connected && (now - rec.last_seen) > max_age_seconds)
            .map(|(k, _)| k.clone())
            .collect();
        for key in &expired {
            self.peers.remove(key);
        }
        expired
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    pub fn authenticated_peer_count(&self) -> usize {
        self.bindings.len()
    }

    /// Return a read-only snapshot tuple for a peer:
    /// `(peer_id_hex, identity_mode, nickname, endpoint, authenticated_fingerprint, trust_level, last_seen, is_connected)`.
    #[allow(clippy::type_complexity)]
    pub fn get_peer_snapshot(
        &self,
        peer_id_hex: &str,
    ) -> Option<(
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        String,
        f64,
        bool,
    )> {
        let pid = Self::normalize_pid(peer_id_hex);
        self.peers.get(&pid).map(|r| {
            (
                r.peer_id_hex.clone(),
                r.identity_mode.clone(),
                r.nickname.clone(),
                r.endpoint.clone(),
                r.authenticated_fingerprint.clone(),
                r.trust_level.clone(),
                r.last_seen,
                r.is_connected,
            )
        })
    }

    pub fn clear_peers(&mut self) {
        self.peers.clear();
        self.pending_messages.clear();
        self.total_pending_messages = 0;
    }
}

// ---------------------------------------------------------------------------
// NativeInboundResult & NativeProtocolEngine
// ---------------------------------------------------------------------------

/// Result of processing a single inbound wire frame through `NativeProtocolEngine`.
#[pyclass(module = "bitchat._bitchat_core")]
#[derive(Debug, Clone, Default)]
pub struct NativeInboundResult {
    #[pyo3(get)]
    pub outbound_packets: Vec<(String, Vec<u8>)>,
    #[pyo3(get)]
    pub relay_packet: Option<Vec<u8>>,
    #[pyo3(get)]
    pub relay_target_peer_id: Option<String>,
    #[pyo3(get)]
    pub relay_exclude_ingress: Option<String>,
    #[pyo3(get)]
    pub delivered_message: Option<(String, String, bool)>,
    #[pyo3(get)]
    pub handshake_completed: Option<(String, String, String)>,
    #[pyo3(get)]
    pub peer_status_event: Option<(String, String)>,
    #[pyo3(get)]
    pub ack_received: Option<(String, String)>,
    #[pyo3(get)]
    pub drop_reason: Option<String>,
}

/// Cohesive, single-FFI-crossing Native Rust Protocol Engine.
///
/// Executes decode -> fragment reassembly -> mesh routing/dedup/rate-limit ->
/// protocol message dispatch -> Noise XX state advancement -> identity binding ->
/// outbound packet encoding inside one native Rust transition.
#[pyclass(module = "bitchat._bitchat_core")]
pub struct NativeProtocolEngine {
    local_x25519_private: [u8; 32],
    local_peer_id: [u8; 8],
    local_peer_id_hex: String,
    transport_name: String,
    allow_legacy_peer_id: bool,
    max_pending_handshakes: usize,
    max_sessions: usize,
    mesh_router: NativeMeshRouter,
    reassembler: NativeFragmentReassembler,
    peer_state: NativePeerStateEngine,
    sessions: HashMap<String, NativeNoiseSession>,
    ack_tracker: NativeAckTracker,
    last_packet_ts_ms: u64,
}

impl Drop for NativeProtocolEngine {
    fn drop(&mut self) {
        self.local_x25519_private.zeroize();
    }
}

impl NativeProtocolEngine {
    fn encode_local_packet(
        &mut self,
        message_type: u8,
        recipient_id: Option<&[u8; 8]>,
        payload: &[u8],
        ttl: i64,
        now: f64,
    ) -> Result<Vec<u8>, CoreError> {
        let flags = if recipient_id.is_some() {
            FLAG_HAS_RECIPIENT as i64
        } else {
            0
        };
        let ts = now_millis_u64().max(self.last_packet_ts_ms.saturating_add(1));
        self.last_packet_ts_ms = ts;
        let rec_slice = recipient_id.map(|r| r.as_slice());
        self.mesh_router.dedup_record_raw(
            &self.local_peer_id,
            ts,
            message_type,
            rec_slice,
            payload,
            now,
        );
        encode_packet_bytes(
            PROTOCOL_VERSION as i64,
            message_type as i64,
            ttl,
            ts as i128,
            flags,
            &self.local_peer_id,
            rec_slice,
            payload,
            None,
            true,
        )
    }

    fn pending_handshakes_count_internal(&self) -> usize {
        self.sessions
            .values()
            .filter(|s| s.state_str() == "handshaking")
            .count()
    }

    fn ensure_session_internal(
        &mut self,
        remote_peer_id_hex: &str,
        now: f64,
    ) -> Result<&mut NativeNoiseSession, CoreError> {
        let clean = remote_peer_id_hex.trim().to_ascii_lowercase();
        if clean == self.local_peer_id_hex {
            return Err(CoreError::value_err(
                "Cannot establish Noise session with self",
            ));
        }
        if !self.sessions.contains_key(&clean) {
            if self.sessions.len() >= self.max_sessions {
                // Evict one closed/failed session if possible
                let evict_key = self
                    .sessions
                    .iter()
                    .find(|(_, s)| matches!(s.state_str(), "failed" | "closed" | "uninitialized"))
                    .map(|(k, _)| k.clone());
                if let Some(k) = evict_key {
                    self.sessions.remove(&k);
                } else {
                    return Err(CoreError::noise_state(
                        "Maximum concurrent Noise sessions limit reached",
                    ));
                }
            }
            let expected_fp = self.peer_state.get_bound_fingerprint_internal(&clean);
            let session = NativeNoiseSession::new_internal(
                &self.local_x25519_private,
                &self.local_peer_id_hex,
                &clean,
                None,
                &self.transport_name,
                now,
                self.allow_legacy_peer_id,
                expected_fp,
            )?;
            self.sessions.insert(clean.clone(), session);
        }
        self.sessions
            .get_mut(&clean)
            .ok_or_else(|| CoreError::noise_state("Session lookup failed"))
    }

    fn handle_session_established_internal(
        &mut self,
        remote_hex: &str,
        recipient_bytes: [u8; 8],
        now: f64,
        result: &mut NativeInboundResult,
    ) {
        let (fp, mode) = match self.sessions.get(remote_hex) {
            Some(s) if s.is_established_internal() => (
                s.remote_fingerprint_internal()
                    .unwrap_or_default()
                    .to_string(),
                s.identity_mode_internal().to_string(),
            ),
            _ => return,
        };

        if let Err(err) = self
            .peer_state
            .bind_authenticated_identity_internal(remote_hex, &fp, &mode, now)
        {
            if let Some(mut sess) = self.sessions.remove(remote_hex) {
                sess.close_internal(now);
            }
            let _ = self.peer_state.drain_pending_internal(remote_hex);
            result.drop_reason = Some(err.message);
            return;
        }

        result.handshake_completed = Some((remote_hex.to_string(), fp, mode));

        // Flush bounded pending direct messages immediately inside Rust
        let pending = self.peer_state.drain_pending_internal(remote_hex);
        for text in pending {
            let ct = match self.sessions.get_mut(remote_hex) {
                Some(s) => match s.encrypt_internal(text.as_bytes()) {
                    Ok(c) => c,
                    Err(_) => break,
                },
                None => break,
            };
            if let Ok(wire) = self.encode_local_packet(
                MSG_NOISE_ENCRYPTED,
                Some(&recipient_bytes),
                &ct,
                DEFAULT_PACKET_TTL,
                now,
            ) {
                result.outbound_packets.push((remote_hex.to_string(), wire));
            }
        }
    }

    pub fn process_inbound_frame_internal(
        &mut self,
        raw_bytes: &[u8],
        ingress_source: Option<&str>,
        now: f64,
    ) -> Result<NativeInboundResult, CoreError> {
        let mut result = NativeInboundResult::default();

        // 1. Decode outer packet
        let decoded = decode_packet_slice(raw_bytes)?;
        let (version, msg_type, ttl, timestamp, flags, sender_id, recipient_id, payload, signature) =
            if matches!(
                decoded.1,
                MSG_FRAGMENT_START | MSG_FRAGMENT_CONTINUE | MSG_FRAGMENT_END
            ) {
                match self
                    .reassembler
                    .add_fragment_internal(decoded.1, &decoded.5, &decoded.7)?
                {
                    Some(reassembled_wire) => decode_packet_slice(&reassembled_wire)?,
                    None => {
                        return Ok(result);
                    }
                }
            } else {
                decoded
            };

        // 2. Evaluate in NativeMeshRouter (loop prevention, rate limit, TTL, dedup, route learning)
        let (should_process_locally, relay_ttl, target_peer_id_hex, exclude_ingress, drop_reason) =
            self.mesh_router.evaluate_incoming_raw(
                &sender_id,
                recipient_id.as_deref(),
                msg_type,
                ttl as i64,
                timestamp,
                &payload,
                ingress_source,
                now,
                None,
                None,
            );

        if let Some(reason) = drop_reason {
            result.drop_reason = Some(reason);
            return Ok(result);
        }

        // Encode relay packet natively in Rust if needed
        if let Some(r_ttl) = relay_ttl {
            if let Ok(relay_wire) = encode_packet_bytes(
                version as i64,
                msg_type as i64,
                r_ttl,
                timestamp as i128,
                flags as i64,
                &sender_id,
                recipient_id.as_deref(),
                &payload,
                signature.as_deref(),
                true,
            ) {
                result.relay_packet = Some(relay_wire);
                result.relay_target_peer_id = target_peer_id_hex;
                result.relay_exclude_ingress = exclude_ingress;
            }
        }

        if !should_process_locally {
            return Ok(result);
        }

        let sender_hex = hex_encode_lower(&sender_id);
        let mut sender_arr = [0u8; 8];
        sender_arr.copy_from_slice(&sender_id);

        // Track observed peer metadata
        self.peer_state
            .observe_peer(&sender_hex, ingress_source, None, None, now);

        // 3. Native protocol dispatch
        match msg_type {
            MSG_ANNOUNCE => {
                let nick = String::from_utf8_lossy(&payload).trim().to_string();
                if self
                    .peer_state
                    .is_nickname_spoofed_internal(&sender_hex, &nick)
                {
                    result.drop_reason = Some(format!(
                        "Rejected spoofed nickname from {}",
                        &sender_hex[..8]
                    ));
                } else {
                    self.peer_state.observe_peer(
                        &sender_hex,
                        ingress_source,
                        Some(&nick),
                        None,
                        now,
                    );
                    result.peer_status_event = Some((sender_hex, format!("Online ({})", nick)));
                }
            }
            MSG_MESSAGE => {
                let text = decode_chat_payload_lossy(&payload);
                result.delivered_message = Some((sender_hex, text, false));
            }
            MSG_DELIVERY_ACK => {
                let msg_id = String::from_utf8_lossy(&payload).trim().to_string();
                if let Some(peer) = self.ack_tracker.acknowledge(&msg_id) {
                    result.ack_received = Some((msg_id, peer));
                }
            }
            MSG_NOISE_IDENTITY_ANNOUNCE => match parse_noise_identity_announce_bytes(&payload) {
                Ok((_pk, fp)) => {
                    if let Err(err) = self.peer_state.record_observed_identity_announce_internal(
                        &sender_hex,
                        &fp,
                        now,
                    ) {
                        result.drop_reason = Some(err.message);
                    }
                }
                Err(err) => {
                    result.drop_reason = Some(err.message);
                }
            },
            MSG_HANDSHAKE_REQUEST => {
                let is_pending = self
                    .sessions
                    .get(&sender_hex)
                    .is_some_and(|s| s.state_str() == "handshaking");
                if !is_pending
                    && self.pending_handshakes_count_internal() >= self.max_pending_handshakes
                {
                    result.drop_reason = Some("Pending handshake limit reached".to_string());
                    return Ok(result);
                }

                let init_payload = {
                    let sess = self.ensure_session_internal(&sender_hex, now)?;
                    let is_stale = sess.state_str() == "handshaking"
                        && sess
                            .handshake_started_at_internal()
                            .is_some_and(|t| (now - t) >= STALE_HANDSHAKE_RETRY_SECONDS);
                    if sess.role_enum() == HandshakeRole::Initiator
                        && (matches!(sess.state_str(), "uninitialized" | "failed") || is_stale)
                    {
                        if sess.state_str() != "uninitialized" {
                            sess.reset_for_rehandshake_internal(
                                Some(HandshakeRole::Initiator),
                                now,
                            );
                        }
                        sess.start_handshake_internal(now)?
                    } else {
                        None
                    }
                };

                if let Some(m1) = init_payload {
                    let wire = self.encode_local_packet(
                        MSG_NOISE_HANDSHAKE_INIT,
                        Some(&sender_arr),
                        &m1,
                        DEFAULT_PACKET_TTL,
                        now,
                    )?;
                    result.outbound_packets.push((sender_hex, wire));
                }
            }
            MSG_NOISE_HANDSHAKE_INIT => {
                let is_pending = self
                    .sessions
                    .get(&sender_hex)
                    .is_some_and(|s| s.state_str() == "handshaking");
                if !is_pending
                    && self.pending_handshakes_count_internal() >= self.max_pending_handshakes
                {
                    result.drop_reason = Some("Pending handshake limit reached".to_string());
                    return Ok(result);
                }

                let local_is_canonical = self.local_peer_id_hex < sender_hex;
                let step = {
                    let sess = self.ensure_session_internal(&sender_hex, now)?;
                    let is_stale = sess.state_str() == "handshaking"
                        && sess
                            .handshake_started_at_internal()
                            .is_some_and(|t| (now - t) >= STALE_HANDSHAKE_RETRY_SECONDS);

                    match sess.state_str() {
                        "failed" | "closed" => {
                            sess.reset_for_rehandshake_internal(
                                Some(HandshakeRole::Responder),
                                now,
                            );
                        }
                        "uninitialized" => {
                            if sess.role_enum() == HandshakeRole::Initiator {
                                sess.reset_for_rehandshake_internal(
                                    Some(HandshakeRole::Responder),
                                    now,
                                );
                            }
                        }
                        "handshaking" => {
                            if !local_is_canonical
                                || sess.role_enum() == HandshakeRole::Responder
                                || is_stale
                            {
                                sess.reset_for_rehandshake_internal(
                                    Some(HandshakeRole::Responder),
                                    now,
                                );
                            } else {
                                // Canonical initiator with active handshake: ignore simultaneous remote init
                                return Ok(result);
                            }
                        }
                        "established" => {
                            // Peer reconnected with fresh ephemeral handshake: invalidate stale transport keys
                            sess.reset_for_rehandshake_internal(
                                Some(HandshakeRole::Responder),
                                now,
                            );
                        }
                        _ => {}
                    }

                    sess.process_handshake_message_internal(&payload, now)
                };

                match step {
                    Ok(resp_opt) => {
                        if let Some(m2) = resp_opt {
                            let wire = self.encode_local_packet(
                                MSG_NOISE_HANDSHAKE_RESP,
                                Some(&sender_arr),
                                &m2,
                                DEFAULT_PACKET_TTL,
                                now,
                            )?;
                            result.outbound_packets.push((sender_hex.clone(), wire));
                        }
                        if self
                            .sessions
                            .get(&sender_hex)
                            .is_some_and(|s| s.is_established_internal())
                        {
                            self.handle_session_established_internal(
                                &sender_hex,
                                sender_arr,
                                now,
                                &mut result,
                            );
                        }
                    }
                    Err(err) => {
                        if let Some(mut sess) = self.sessions.remove(&sender_hex) {
                            sess.close_internal(now);
                        }
                        let _ = self.peer_state.drain_pending_internal(&sender_hex);
                        result.drop_reason = Some(err.message);
                    }
                }
            }
            MSG_NOISE_HANDSHAKE_RESP => {
                if !self.sessions.contains_key(&sender_hex) {
                    result.drop_reason =
                        Some("Unexpected NoiseHandshakeResp from unknown peer".to_string());
                    return Ok(result);
                }

                let step = {
                    let sess = self.sessions.get_mut(&sender_hex).unwrap();
                    sess.process_handshake_message_internal(&payload, now)
                };

                match step {
                    Ok(resp_opt) => {
                        if let Some(m3) = resp_opt {
                            let wire = self.encode_local_packet(
                                MSG_NOISE_HANDSHAKE_RESP,
                                Some(&sender_arr),
                                &m3,
                                DEFAULT_PACKET_TTL,
                                now,
                            )?;
                            result.outbound_packets.push((sender_hex.clone(), wire));
                        }
                        if self
                            .sessions
                            .get(&sender_hex)
                            .is_some_and(|s| s.is_established_internal())
                        {
                            self.handle_session_established_internal(
                                &sender_hex,
                                sender_arr,
                                now,
                                &mut result,
                            );
                        }
                    }
                    Err(err) => {
                        if let Some(mut sess) = self.sessions.remove(&sender_hex) {
                            sess.close_internal(now);
                        }
                        let _ = self.peer_state.drain_pending_internal(&sender_hex);
                        result.drop_reason = Some(err.message);
                    }
                }
            }
            MSG_NOISE_ENCRYPTED => {
                // Fail closed: never fall back to legacy encryption or plaintext!
                let dec_res = match self.sessions.get_mut(&sender_hex) {
                    Some(sess) if sess.is_established_internal() => sess.decrypt_internal(&payload),
                    _ => Err(CoreError::noise_state(
                        "Received NoiseEncrypted without established Noise session",
                    )),
                };
                match dec_res {
                    Ok(plaintext) => {
                        let text = decode_chat_payload_lossy(&plaintext);
                        result.delivered_message = Some((sender_hex, text, true));
                    }
                    Err(err) => {
                        result.drop_reason = Some(err.message);
                    }
                }
            }
            _ => {}
        }

        Ok(result)
    }

    pub fn prepare_direct_message_internal(
        &mut self,
        target_peer_id_hex: &str,
        text: &str,
        now: f64,
    ) -> Result<Vec<(String, Vec<u8>)>, CoreError> {
        let encoded = text.as_bytes();
        if encoded.len() > MAX_CHAT_MESSAGE_BYTES {
            return Err(CoreError::value_err(format!(
                "Message payload exceeds maximum size ({} bytes)",
                MAX_CHAT_MESSAGE_BYTES
            )));
        }
        let target_arr = parse_peer_id_hex_bytes(target_peer_id_hex)?;
        let target_hex = hex_encode_lower(&target_arr);

        let is_established = self
            .sessions
            .get(&target_hex)
            .is_some_and(|s| s.is_established_internal());

        if is_established {
            let ct = self
                .sessions
                .get_mut(&target_hex)
                .ok_or_else(|| CoreError::noise_state("Session missing"))?
                .encrypt_internal(encoded)?;
            let wire = self.encode_local_packet(
                MSG_NOISE_ENCRYPTED,
                Some(&target_arr),
                &ct,
                DEFAULT_PACKET_TTL,
                now,
            )?;
            return Ok(vec![(target_hex, wire)]);
        }

        // Queue bounded pending plaintext until handshake establishes
        if !self
            .peer_state
            .enqueue_pending_internal(&target_hex, text.to_string())
        {
            return Err(CoreError::noise_state(
                "Pending message queue full for target peer",
            ));
        }

        let action: Option<(u8, Vec<u8>)> = {
            let sess = self.ensure_session_internal(&target_hex, now)?;
            let is_stale = sess.state_str() == "handshaking"
                && sess
                    .handshake_started_at_internal()
                    .is_some_and(|t| (now - t) >= STALE_HANDSHAKE_RETRY_SECONDS);
            if matches!(sess.state_str(), "uninitialized" | "failed" | "closed") || is_stale {
                if sess.state_str() != "uninitialized" {
                    let r = sess.role_enum();
                    sess.reset_for_rehandshake_internal(Some(r), now);
                }
                if sess.role_enum() == HandshakeRole::Initiator {
                    sess.start_handshake_internal(now)?
                        .map(|m1| (MSG_NOISE_HANDSHAKE_INIT, m1))
                } else {
                    sess.record_phase_internal(
                        "HandshakeInitiated",
                        "Sent HandshakeRequest to initiator",
                        now,
                    );
                    Some((MSG_HANDSHAKE_REQUEST, Vec::new()))
                }
            } else {
                None
            }
        };

        if let Some((mtype, payload)) = action {
            let wire = self.encode_local_packet(
                mtype,
                Some(&target_arr),
                &payload,
                DEFAULT_PACKET_TTL,
                now,
            )?;
            return Ok(vec![(target_hex, wire)]);
        }

        Ok(Vec::new())
    }
}

#[pymethods]
impl NativeProtocolEngine {
    #[new]
    #[pyo3(signature = (
        local_x25519_private,
        local_peer_id_hex,
        local_nickname="Anonymous",
        transport="lan",
        max_relay_ttl=10,
        rate_limit_per_peer=50,
        allow_legacy_peer_id=true
    ))]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        local_x25519_private: &[u8],
        local_peer_id_hex: &str,
        local_nickname: &str,
        transport: &str,
        max_relay_ttl: i64,
        rate_limit_per_peer: usize,
        allow_legacy_peer_id: bool,
    ) -> PyResult<Self> {
        let _local_pub = x25519_public_from_private_slice(local_x25519_private)?;
        let mut priv_arr = [0u8; 32];
        priv_arr.copy_from_slice(local_x25519_private);

        let local_pid = parse_peer_id_hex_bytes(local_peer_id_hex)?;
        let clean_hex = hex_encode_lower(&local_pid);

        let mesh_router = NativeMeshRouter::new(
            &local_pid,
            max_relay_ttl,
            rate_limit_per_peer,
            1000,
            300.0,
            2000,
            300.0,
        )?;
        let reassembler = NativeFragmentReassembler::new(100, 1000, 150_000);
        let peer_state = NativePeerStateEngine::new(
            &clean_hex,
            local_nickname,
            DEFAULT_MAX_PEERS,
            DEFAULT_MAX_PENDING_PER_PEER,
            DEFAULT_MAX_TOTAL_PENDING,
        );
        let ack_tracker = NativeAckTracker::new(512);

        Ok(Self {
            local_x25519_private: priv_arr,
            local_peer_id: local_pid,
            local_peer_id_hex: clean_hex,
            transport_name: transport.to_string(),
            allow_legacy_peer_id,
            max_pending_handshakes: DEFAULT_MAX_PENDING_HANDSHAKES,
            max_sessions: DEFAULT_MAX_SESSIONS,
            mesh_router,
            reassembler,
            peer_state,
            sessions: HashMap::new(),
            ack_tracker,
            last_packet_ts_ms: 0,
        })
    }

    #[pyo3(signature = (raw_bytes, ingress_source=None, now=0.0))]
    pub fn process_inbound_frame(
        &mut self,
        raw_bytes: &[u8],
        ingress_source: Option<&str>,
        now: f64,
    ) -> PyResult<NativeInboundResult> {
        Ok(self.process_inbound_frame_internal(raw_bytes, ingress_source, now)?)
    }

    #[pyo3(signature = (target_peer_id_hex, text, now=0.0))]
    pub fn prepare_direct_message(
        &mut self,
        target_peer_id_hex: &str,
        text: &str,
        now: f64,
    ) -> PyResult<Vec<(String, Vec<u8>)>> {
        Ok(self.prepare_direct_message_internal(target_peer_id_hex, text, now)?)
    }

    #[pyo3(signature = (text, now=0.0))]
    pub fn prepare_broadcast_message(&mut self, text: &str, now: f64) -> PyResult<Vec<u8>> {
        let encoded = text.as_bytes();
        if encoded.len() > MAX_CHAT_MESSAGE_BYTES {
            return Err(CoreError::value_err(format!(
                "Message payload exceeds maximum size ({} bytes)",
                MAX_CHAT_MESSAGE_BYTES
            ))
            .into());
        }
        Ok(self.encode_local_packet(MSG_MESSAGE, None, encoded, DEFAULT_PACKET_TTL, now)?)
    }

    #[pyo3(signature = (target_peer_id_hex, msg_id, now=0.0))]
    pub fn prepare_delivery_ack(
        &mut self,
        target_peer_id_hex: &str,
        msg_id: &str,
        now: f64,
    ) -> PyResult<Vec<u8>> {
        let target_arr = parse_peer_id_hex_bytes(target_peer_id_hex)?;
        Ok(self.encode_local_packet(
            MSG_DELIVERY_ACK,
            Some(&target_arr),
            msg_id.as_bytes(),
            DEFAULT_PACKET_TTL,
            now,
        )?)
    }

    #[pyo3(signature = (msg_id, peer_id_hex, now=0.0, timeout_seconds=10.0, max_retries=3))]
    pub fn track_delivery_ack(
        &mut self,
        msg_id: &str,
        peer_id_hex: &str,
        now: f64,
        timeout_seconds: f64,
        max_retries: u32,
    ) {
        self.ack_tracker
            .track_message(msg_id, peer_id_hex, now, timeout_seconds, max_retries);
    }

    #[pyo3(signature = (peer_id_hex, fingerprint, verified=false))]
    pub fn seed_trusted_contact(
        &mut self,
        peer_id_hex: &str,
        fingerprint: &str,
        verified: bool,
    ) -> PyResult<()> {
        self.peer_state
            .seed_trusted_contact(peer_id_hex, fingerprint, verified)
    }

    pub fn mark_peer_verified(&mut self, peer_id_hex: &str) -> PyResult<()> {
        let clean = peer_id_hex.trim().to_ascii_lowercase();
        self.peer_state.mark_verified(&clean)?;
        if let Some(sess) = self.sessions.get_mut(&clean) {
            let _ = sess.mark_user_verified();
        }
        Ok(())
    }

    pub fn untrust_peer(&mut self, peer_id_hex: &str) -> bool {
        self.peer_state.untrust_peer(peer_id_hex)
    }

    #[pyo3(signature = (peer_id_hex, now=0.0))]
    pub fn on_peer_disconnected(&mut self, peer_id_hex: &str, now: f64) {
        let clean = peer_id_hex.trim().to_ascii_lowercase();
        if let Some(mut sess) = self.sessions.remove(&clean) {
            sess.close_internal(now);
        }
        let _ = self.peer_state.drain_pending_internal(&clean);
        self.peer_state
            .observe_peer(&clean, None, None, Some(false), now);
    }

    pub fn get_session_state(&self, peer_id_hex: &str) -> Option<String> {
        let clean = peer_id_hex.trim().to_ascii_lowercase();
        self.sessions.get(&clean).map(|s| s.state_str().to_string())
    }

    pub fn get_session_identity_mode(&self, peer_id_hex: &str) -> Option<String> {
        let clean = peer_id_hex.trim().to_ascii_lowercase();
        self.sessions
            .get(&clean)
            .map(|s| s.identity_mode_internal().to_string())
    }

    pub fn get_session_fingerprint(&self, peer_id_hex: &str) -> Option<String> {
        let clean = peer_id_hex.trim().to_ascii_lowercase();
        self.sessions
            .get(&clean)
            .and_then(|s| s.remote_fingerprint_internal().map(|f| f.to_string()))
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn pending_handshakes_count(&self) -> usize {
        self.pending_handshakes_count_internal()
    }

    pub fn peer_count(&self) -> usize {
        self.peer_state.peer_count()
    }

    pub fn authenticated_peer_count(&self) -> usize {
        self.peer_state.authenticated_peer_count()
    }

    pub fn get_next_hop(&mut self, destination: &str, now: f64) -> Option<String> {
        self.mesh_router.get_next_hop(destination, now)
    }

    /// Prune all bounded caches, timed-out handshakes, expired peers, and expired ACKs.
    ///
    /// Returns `(pruned_fragments, pruned_dedup, pruned_routes, pruned_rate, pruned_peers, expired_handshakes, expired_acks)`.
    #[pyo3(signature = (now=0.0))]
    #[allow(clippy::type_complexity)]
    pub fn prune_all(&mut self, now: f64) -> (usize, usize, usize, usize, usize, usize, usize) {
        let p_frag = self.reassembler.prune_stale(60.0, Some(now));
        let p_dedup = self.mesh_router.dedup_prune_expired(now);
        let p_routes = self.mesh_router.prune_routes(None, now);
        let p_rate = self.mesh_router.prune_rate_limiter(1.0, now);
        let p_peers = self
            .peer_state
            .prune_expired_peers(DEFAULT_PEER_EXPIRY_SECONDS, now)
            .len();

        let expired_hs: Vec<String> = self
            .sessions
            .iter()
            .filter(|(_, s)| {
                s.state_str() == "handshaking"
                    && s.handshake_started_at_internal()
                        .is_some_and(|t| (now - t) >= DEFAULT_HANDSHAKE_TIMEOUT_SECONDS)
            })
            .map(|(k, _)| k.clone())
            .collect();
        for k in &expired_hs {
            if let Some(mut s) = self.sessions.remove(k) {
                s.close_internal(now);
            }
            let _ = self.peer_state.drain_pending_internal(k);
        }
        let p_acks = self.ack_tracker.collect_expired(now).len();

        (
            p_frag,
            p_dedup,
            p_routes,
            p_rate,
            p_peers,
            expired_hs.len(),
            p_acks,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::derive_identity_from_private;
    use sha2::{Digest, Sha256};

    fn make_engine(seed_byte: u8, nick: &str) -> (NativeProtocolEngine, String) {
        let priv_key = [seed_byte; 32];
        let ed_key = [seed_byte.wrapping_add(1); 32];
        let (_xpub, _edpub, pid, _fp) = derive_identity_from_private(&priv_key, &ed_key).unwrap();
        let pid_hex = hex_encode_lower(&pid);
        let engine =
            NativeProtocolEngine::new(&priv_key, &pid_hex, nick, "lan", 7, 50, true).unwrap();
        (engine, pid_hex)
    }

    #[test]
    fn test_protocol_engine_full_noise_xx_and_bidirectional_dm() {
        let (mut eng_a, pid_a) = make_engine(0x11, "alice");
        let (mut eng_b, pid_b) = make_engine(0x22, "bob");

        // Alice initiates encrypted DM to Bob (single Rust call)
        let mut queue_a_to_b = eng_a
            .prepare_direct_message_internal(&pid_b, "hello bob over native rust!", 10.0)
            .unwrap();
        let mut queue_b_to_a: Vec<(String, Vec<u8>)> = Vec::new();
        let mut delivered_b: Vec<(String, String, bool)> = Vec::new();
        let mut delivered_a: Vec<(String, String, bool)> = Vec::new();

        for round in 0..8 {
            let now = 10.0 + (round as f64) * 0.1;
            let to_b = std::mem::take(&mut queue_a_to_b);
            for (_, frame) in to_b {
                let res = eng_b
                    .process_inbound_frame_internal(&frame, Some("10.0.0.1:41235"), now)
                    .unwrap();
                if let Some(msg) = res.delivered_message {
                    delivered_b.push(msg);
                }
                queue_b_to_a.extend(res.outbound_packets);
            }
            let to_a = std::mem::take(&mut queue_b_to_a);
            for (_, frame) in to_a {
                let res = eng_a
                    .process_inbound_frame_internal(&frame, Some("10.0.0.2:41235"), now)
                    .unwrap();
                if let Some(msg) = res.delivered_message {
                    delivered_a.push(msg);
                }
                queue_a_to_b.extend(res.outbound_packets);
            }
        }

        assert_eq!(
            delivered_b,
            vec![(
                pid_a.clone(),
                "hello bob over native rust!".to_string(),
                true
            )]
        );
        assert_eq!(
            eng_a.get_session_state(&pid_b).as_deref(),
            Some("established")
        );
        assert_eq!(
            eng_b.get_session_state(&pid_a).as_deref(),
            Some("established")
        );

        // Bob replies over established Noise transport
        let reply_frames = eng_b
            .prepare_direct_message_internal(&pid_a, "reply from bob!", 12.0)
            .unwrap();
        assert_eq!(reply_frames.len(), 1);
        let res_a = eng_a
            .process_inbound_frame_internal(&reply_frames[0].1, Some("10.0.0.2:41235"), 12.1)
            .unwrap();
        assert_eq!(
            res_a.delivered_message,
            Some((pid_b.clone(), "reply from bob!".to_string(), true))
        );

        // Replay of the exact same encrypted frame is dropped (dedup + replay window)
        let replay_res = eng_a
            .process_inbound_frame_internal(&reply_frames[0].1, Some("10.0.0.2:41235"), 12.2)
            .unwrap();
        assert!(replay_res.delivered_message.is_none());
        assert!(replay_res.drop_reason.is_some());
    }

    #[test]
    fn test_protocol_engine_legacy_tui_interop_and_collision_rejection() {
        let (mut rustpy_eng, rustpy_pid) = make_engine(0x31, "rustpy");

        // Legacy bitchat-tui peer: random 4-byte ID zero-extended to 8 bytes
        let tui_priv = [0x41u8; 32];
        let tui_legacy_pid = "cafebabe00000000";
        let mut tui_eng =
            NativeProtocolEngine::new(&tui_priv, tui_legacy_pid, "tui_user", "lan", 7, 50, true)
                .unwrap();

        let mut q_tui_to_rp = tui_eng
            .prepare_direct_message_internal(&rustpy_pid, "hello from bitchat-tui!", 20.0)
            .unwrap();
        let mut q_rp_to_tui: Vec<(String, Vec<u8>)> = Vec::new();
        let mut delivered_rp: Vec<(String, String, bool)> = Vec::new();

        for round in 0..8 {
            let now = 20.0 + (round as f64) * 0.1;
            for (_, frame) in std::mem::take(&mut q_tui_to_rp) {
                let res = rustpy_eng
                    .process_inbound_frame_internal(&frame, Some("tui_ble"), now)
                    .unwrap();
                if let Some(m) = res.delivered_message {
                    delivered_rp.push(m);
                }
                q_rp_to_tui.extend(res.outbound_packets);
            }
            for (_, frame) in std::mem::take(&mut q_rp_to_tui) {
                let res = tui_eng
                    .process_inbound_frame_internal(&frame, Some("rp_ble"), now)
                    .unwrap();
                q_tui_to_rp.extend(res.outbound_packets);
            }
        }

        assert_eq!(
            delivered_rp,
            vec![(
                tui_legacy_pid.to_string(),
                "hello from bitchat-tui!".to_string(),
                true
            )]
        );
        assert_eq!(
            rustpy_eng
                .get_session_identity_mode(tui_legacy_pid)
                .as_deref(),
            Some("legacy_tui")
        );

        // Disconnect legacy peer, then have an IMPOSTOR with a different static key claim the same legacy ID.
        // Sleep 2ms so wall-clock millisecond timestamps cannot collide with the legitimate peer's
        // empty MSG_HANDSHAKE_REQUEST in the deduplicator on fast Linux CI runners.
        std::thread::sleep(std::time::Duration::from_millis(2));
        rustpy_eng.on_peer_disconnected(tui_legacy_pid, 25.0);
        let impostor_priv = [0x99u8; 32];
        let mut impostor_eng = NativeProtocolEngine::new(
            &impostor_priv,
            tui_legacy_pid,
            "impostor",
            "lan",
            7,
            50,
            true,
        )
        .unwrap();

        let mut q_imp = impostor_eng
            .prepare_direct_message_internal(&rustpy_pid, "spoofed!", 30.0)
            .unwrap();
        let mut q_back: Vec<(String, Vec<u8>)> = Vec::new();
        let mut spoof_delivered = false;
        let mut saw_rejection = false;

        for round in 0..8 {
            let now = 30.0 + (round as f64) * 0.1;
            for (_, frame) in std::mem::take(&mut q_imp) {
                let res = rustpy_eng
                    .process_inbound_frame_internal(&frame, Some("imp_ble"), now)
                    .unwrap();
                if res.delivered_message.is_some() {
                    spoof_delivered = true;
                }
                if res
                    .drop_reason
                    .as_deref()
                    .is_some_and(|r| r.contains("Conflicting") || r.contains("collision"))
                {
                    saw_rejection = true;
                }
                q_back.extend(res.outbound_packets);
            }
            for (_, frame) in std::mem::take(&mut q_back) {
                let res = impostor_eng
                    .process_inbound_frame_internal(&frame, Some("rp_ble"), now)
                    .unwrap();
                q_imp.extend(res.outbound_packets);
            }
        }

        assert!(!spoof_delivered);
        assert!(saw_rejection);
        assert!(rustpy_eng.get_session_state(tui_legacy_pid).is_none());
    }

    #[test]
    fn test_peer_state_collision_and_unauthenticated_overwrite_rejected() {
        let mut ps = NativePeerStateEngine::new("0102030405060708", "Alice", 64, 8, 64);
        let fp1 = hex_encode_lower(&Sha256::digest(b"key1"));
        let fp2 = hex_encode_lower(&Sha256::digest(b"key2"));

        ps.bind_authenticated_identity_internal("deadbeef00000000", &fp1, "legacy_tui", 1.0)
            .unwrap();
        assert_eq!(ps.get_trust_level("deadbeef00000000"), "authenticated");

        // Unauthenticated announce with different fingerprint must be rejected
        assert!(ps
            .record_observed_identity_announce_internal("deadbeef00000000", &fp2, 2.0)
            .is_err());
        // Different key for same peer ID rejected
        assert!(ps
            .bind_authenticated_identity_internal("deadbeef00000000", &fp2, "legacy_tui", 3.0)
            .is_err());
        // Same key claiming a different peer ID rejected (reverse collision index)
        assert!(ps
            .bind_authenticated_identity_internal("feedface00000000", &fp1, "legacy_tui", 4.0)
            .is_err());

        // User verification is distinct from Noise authentication
        ps.mark_verified("deadbeef00000000").unwrap();
        assert_eq!(ps.get_trust_level("deadbeef00000000"), "verified");

        // Explicit untrust allows controlled migration
        assert!(ps.untrust_peer("deadbeef00000000"));
        ps.bind_authenticated_identity_internal("deadbeef00000000", &fp2, "legacy_tui", 5.0)
            .unwrap();
        assert_eq!(ps.get_trust_level("deadbeef00000000"), "authenticated");
    }

    #[test]
    fn test_decode_bitchat_tui_dm_payload_formats() {
        // 1. Plain UTF-8
        assert_eq!(decode_chat_payload_lossy(b"Hello RustPy!"), "Hello RustPy!");

        // 2. [0x04] || UTF-8
        let mut prefixed_utf8 = vec![MSG_MESSAGE];
        prefixed_utf8.extend_from_slice(b"Hello prefixed!");
        assert_eq!(decode_chat_payload_lossy(&prefixed_utf8), "Hello prefixed!");

        // 3. [0x04] || binary BitchatMessage (exact bitchat-tui message_handlers.rs format)
        let bin_msg = encode_bitchat_message_payload_raw(
            "alice",
            "Secret DM from bitchat-tui",
            "deadbeef00000000",
            "uuid-1234",
            true,
            None,
            Some(1_730_000_000_000),
        )
        .unwrap();
        let mut prefixed_bin = vec![MSG_MESSAGE];
        prefixed_bin.extend_from_slice(&bin_msg);
        assert_eq!(
            decode_chat_payload_lossy(&prefixed_bin),
            "Secret DM from bitchat-tui"
        );

        // 4. Bare binary BitchatMessage
        assert_eq!(
            decode_chat_payload_lossy(&bin_msg),
            "Secret DM from bitchat-tui"
        );

        // 5. Nested BitchatPacket(Message) (exact bitchat-tui notification_handlers.rs format)
        let sender_id = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00];
        let nested_pkt = encode_packet_bytes(
            i64::from(PROTOCOL_VERSION),
            i64::from(MSG_MESSAGE),
            7,
            1_730_000_000_000,
            0,
            &sender_id,
            None,
            &bin_msg,
            None,
            false,
        )
        .unwrap();
        assert_eq!(
            decode_chat_payload_lossy(&nested_pkt),
            "Secret DM from bitchat-tui"
        );
    }
}
