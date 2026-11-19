//! Native Rust LAN Transport & Discovery Engine for BitChat (Stage 4).
//!
//! Provides:
//! - Wire-compatible `BC_DISC_V1` UDP discovery packet encoding, decoding, and
//!   strict validation (`encode_discovery_packet_raw`, `decode_discovery_packet_raw`)
//! - Multi-interface classification, physical vs. virtual/VPN adapter scoring,
//!   and directed subnet broadcast calculation (`select_best_lan_ip`,
//!   `compute_subnet_broadcast`, `compute_broadcast_targets`)
//! - Deterministic simultaneous TCP connection arbitration (`arbitrate_simultaneous_connection`)
//! - Per-IP sliding window rate limiter (`NativeIpRateLimiter`)
//! - Asynchronous Tokio TCP framed exchange & UDP beacon helpers

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use pyo3::prelude::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::errors::CoreError;
use crate::framing::{encode_frame_vec, FRAME_MAGIC, HEADER_SIZE, MAX_FRAME_SIZE};

pub const DEFAULT_DISCOVERY_PORT: u16 = 41234;
pub const DEFAULT_TCP_PORT: u16 = 41235;
pub const DISCOVERY_MAGIC: &str = "BC_DISC_V1";
pub const DISCOVERY_PROTOCOL_VERSION: u8 = 1;
pub const MAX_DISCOVERY_PACKET_SIZE: usize = 1024;

const VIRTUAL_INTERFACE_KEYWORDS: &[&str] = &[
    "loopback",
    "vethernet",
    "wsl",
    "docker",
    "virbr",
    "veth",
    "br-",
    "tun",
    "tap",
    "tailscale",
    "wireguard",
    "wg",
    "zt",
    "zerotier",
    "utun",
    "vboxnet",
    "vmnet",
    "vmware",
    "hyper-v",
    "hamachi",
    "nordlynx",
    " proton",
];

fn is_valid_hex_range(s: &str, min_len: usize, max_len: usize) -> bool {
    let trimmed = s.trim();
    (min_len..=max_len).contains(&trimmed.len()) && trimmed.bytes().all(|b| b.is_ascii_hexdigit())
}

fn escape_json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() || !c.is_ascii() => {
                use std::fmt::Write;
                let code = c as u32;
                if code <= 0xFFFF {
                    let _ = write!(&mut out, "\\u{:04x}", code);
                } else {
                    let u = code - 0x10000;
                    let high = 0xD800 + ((u >> 10) & 0x3FF);
                    let low = 0xDC00 + (u & 0x3FF);
                    let _ = write!(&mut out, "\\u{:04x}\\u{:04x}", high, low);
                }
            }
            c => out.push(c),
        }
    }
    out
}

/// Minimal, allocation-safe JSON string/number extractor for BitChat UDP discovery packets.
fn extract_json_string_field(json_str: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{}\"", key);
    let mut search_from = 0usize;
    while let Some(rel_idx) = json_str[search_from..].find(&pattern) {
        let key_end = search_from + rel_idx + pattern.len();
        let rest = json_str[key_end..].trim_start();
        if let Some(after_colon) = rest.strip_prefix(':') {
            let val_start = after_colon.trim_start();
            if let Some(after_quote) = val_start.strip_prefix('"') {
                let mut result = String::new();
                let mut chars = after_quote.chars();
                while let Some(c) = chars.next() {
                    if c == '"' {
                        return Some(result);
                    }
                    if c == '\\' {
                        match chars.next()? {
                            '"' => result.push('"'),
                            '\\' => result.push('\\'),
                            '/' => result.push('/'),
                            'n' => result.push('\n'),
                            'r' => result.push('\r'),
                            't' => result.push('\t'),
                            'u' => {
                                let mut hex = String::with_capacity(4);
                                for _ in 0..4 {
                                    hex.push(chars.next()?);
                                }
                                let code = u32::from_str_radix(&hex, 16).ok()?;
                                if let Some(ch) = char::from_u32(code) {
                                    result.push(ch);
                                }
                            }
                            other => result.push(other),
                        }
                    } else {
                        result.push(c);
                    }
                }
                return None;
            }
        }
        search_from = key_end;
    }
    None
}

fn extract_json_int_field(json_str: &str, key: &str) -> Option<i64> {
    let pattern = format!("\"{}\"", key);
    let mut search_from = 0usize;
    while let Some(rel_idx) = json_str[search_from..].find(&pattern) {
        let key_end = search_from + rel_idx + pattern.len();
        let rest = json_str[key_end..].trim_start();
        if let Some(after_colon) = rest.strip_prefix(':') {
            let val_start = after_colon.trim_start();
            if val_start.starts_with('"')
                || val_start.starts_with("true")
                || val_start.starts_with("false")
            {
                return None;
            }
            let num_end = val_start
                .find(|c: char| !c.is_ascii_digit() && c != '-')
                .unwrap_or(val_start.len());
            if num_end == 0 {
                return None;
            }
            return val_start[..num_end].parse::<i64>().ok();
        }
        search_from = key_end;
    }
    None
}

#[pyfunction]
#[pyo3(signature = (peer_id, tcp_port, nickname="", instance_id="", protocol_version=1, ssid="", protocol="bitchat", transport="lan"))]
#[allow(clippy::too_many_arguments)]
pub fn encode_discovery_packet_raw(
    peer_id: &str,
    tcp_port: i64,
    nickname: &str,
    instance_id: &str,
    protocol_version: i64,
    ssid: &str,
    protocol: &str,
    transport: &str,
) -> PyResult<Vec<u8>> {
    if !is_valid_hex_range(peer_id, 8, 64) {
        return Err(CoreError::value_err(format!("Invalid peer_id hex: '{}'", peer_id)).into());
    }
    if !(1..=65535).contains(&tcp_port) {
        return Err(CoreError::value_err(format!("Invalid TCP port: {}", tcp_port)).into());
    }
    if !instance_id.is_empty() && !is_valid_hex_range(instance_id, 1, 32) {
        return Err(
            CoreError::value_err(format!("Invalid instance_id hex: '{}'", instance_id)).into(),
        );
    }

    let nick_truncated: String = nickname.chars().take(32).collect();
    let ssid_truncated: String = ssid.chars().take(64).collect();
    let inst_truncated: String = instance_id.chars().take(32).collect();

    let json = format!(
        "{{\"protocol\":\"{}\",\"version\":{},\"transport\":\"{}\",\"peer_id\":\"{}\",\"nickname\":\"{}\",\"port\":{},\"ssid\":\"{}\",\"instance_id\":\"{}\"}}",
        escape_json_string(protocol),
        protocol_version,
        escape_json_string(transport),
        escape_json_string(peer_id),
        escape_json_string(&nick_truncated),
        tcp_port,
        escape_json_string(&ssid_truncated),
        escape_json_string(&inst_truncated),
    );
    let raw = json.into_bytes();
    if raw.len() > MAX_DISCOVERY_PACKET_SIZE {
        return Err(CoreError::value_err(format!(
            "Discovery packet exceeds max size {} bytes",
            MAX_DISCOVERY_PACKET_SIZE
        ))
        .into());
    }
    Ok(raw)
}

/// Decode and validate a BitChat LAN UDP discovery packet with full fields.
///
/// Returns `Some((peer_id, port, nickname, ssid, instance_id, protocol_version))`
/// or `None` if malformed or invalid.
#[pyfunction]
pub fn decode_discovery_packet_full_raw(
    data: &[u8],
) -> Option<(String, u16, String, String, String, u8)> {
    if data.is_empty() || data.len() > MAX_DISCOVERY_PACKET_SIZE {
        return None;
    }
    let text = std::str::from_utf8(data).ok()?.trim();
    if !text.starts_with('{') || !text.ends_with('}') {
        return None;
    }

    let version = extract_json_int_field(text, "version")?;
    if version != DISCOVERY_PROTOCOL_VERSION as i64 {
        return None;
    }

    // Support both canonical BitChat DiscoveryPacket schema ("protocol"="bitchat", "transport"="lan", "port")
    // and legacy "magic"="BC_DISC_V1" + "tcp_port".
    let is_canonical = extract_json_string_field(text, "protocol").as_deref() == Some("bitchat")
        && extract_json_string_field(text, "transport").as_deref() == Some("lan");
    let is_legacy_magic =
        extract_json_string_field(text, "magic").as_deref() == Some(DISCOVERY_MAGIC);
    if !is_canonical && !is_legacy_magic {
        return None;
    }

    let peer_id_raw = extract_json_string_field(text, "peer_id")?;
    let peer_id = peer_id_raw.trim().to_ascii_lowercase();
    if !is_valid_hex_range(&peer_id, 8, 64) {
        return None;
    }

    let port_val = if is_canonical {
        let p = extract_json_int_field(text, "port")?;
        if !(1024..=65535).contains(&p) {
            return None;
        }
        p
    } else {
        let p = extract_json_int_field(text, "tcp_port")
            .or_else(|| extract_json_int_field(text, "port"))?;
        if !(1..=65535).contains(&p) {
            return None;
        }
        p
    };

    let instance_id_raw = extract_json_string_field(text, "instance_id").unwrap_or_default();
    let instance_id: String = instance_id_raw.trim().chars().take(32).collect();

    let nickname_raw =
        extract_json_string_field(text, "nickname").unwrap_or_else(|| "Anonymous".to_string());
    let nick_clamped: String = nickname_raw.trim().chars().take(32).collect();

    let ssid_raw = extract_json_string_field(text, "ssid").unwrap_or_default();
    let ssid_clamped: String = ssid_raw.trim().chars().take(64).collect();

    Some((
        peer_id,
        port_val as u16,
        nick_clamped,
        ssid_clamped,
        instance_id,
        version as u8,
    ))
}

/// Decode and validate a BitChat UDP discovery packet.
///
/// Returns `Some((peer_id, tcp_port, nickname, instance_id, protocol_version))`
/// or `None` if malformed or invalid.
#[pyfunction]
pub fn decode_discovery_packet_raw(data: &[u8]) -> Option<(String, u16, String, String, u8)> {
    let (peer_id, port, nickname, _ssid, instance_id, version) =
        decode_discovery_packet_full_raw(data)?;
    Some((peer_id, port, nickname, instance_id, version))
}

// ---------------------------------------------------------------------------
// Interface Selection & Subnet Broadcast Computation
// ---------------------------------------------------------------------------

#[pyfunction]
pub fn is_virtual_or_vpn_interface(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    VIRTUAL_INTERFACE_KEYWORDS
        .iter()
        .any(|kw| lower.contains(kw))
}

#[pyfunction]
pub fn compute_subnet_broadcast(ip_str: &str, prefix_len: u8) -> Option<String> {
    if prefix_len == 0 || prefix_len >= 31 {
        return None;
    }
    let ip: Ipv4Addr = ip_str.parse().ok()?;
    if ip.is_loopback() || ip.is_link_local() || ip.is_unspecified() || ip.is_multicast() {
        return None;
    }
    let ip_u32 = u32::from(ip);
    let mask = if prefix_len == 32 {
        u32::MAX
    } else {
        !((1u32 << (32 - prefix_len)) - 1)
    };
    let broadcast_u32 = ip_u32 | (!mask);
    let broadcast_ip = Ipv4Addr::from(broadcast_u32);
    if broadcast_ip == ip || broadcast_ip == Ipv4Addr::BROADCAST {
        return None;
    }
    Some(broadcast_ip.to_string())
}

/// Score an interface tuple `(name, ipv4, prefix_len, is_up)` for LAN communication.
fn score_lan_interface(name: &str, ip: Ipv4Addr, is_up: bool) -> i32 {
    if !is_up || ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return -1000;
    }
    let mut score = 0i32;
    if is_virtual_or_vpn_interface(name) {
        score -= 200;
    } else {
        score += 100;
    }

    let lower = name.to_ascii_lowercase();
    if lower.contains("wi-fi")
        || lower.contains("wifi")
        || lower.contains("wlan")
        || lower.contains("wl")
        || lower.contains("eth")
        || lower.contains("en")
        || lower.contains("ethernet")
    {
        score += 50;
    }

    let octets = ip.octets();
    if octets[0] == 192 && octets[1] == 168 {
        score += 40;
    } else if octets[0] == 172 && (16..=31).contains(&octets[1]) {
        // Note: Docker/WSL often uses 172.17-31.x.x; physical interfaces still win via +100
        score += 25;
    } else if octets[0] == 10 {
        score += 20;
    } else if ip.is_link_local() {
        score -= 100;
    } else {
        score += 10;
    }

    score
}

/// Select the best LAN IPv4 address from a list of `(name, ipv4, prefix_len, is_up)` tuples.
#[pyfunction]
pub fn select_best_lan_ip(interfaces: Vec<(String, String, u8, bool)>) -> String {
    let mut best_ip: Option<(i32, String)> = None;

    for (name, ip_str, _prefix, is_up) in interfaces {
        if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
            let s = score_lan_interface(&name, ip, is_up);
            if s > -500 {
                match &best_ip {
                    Some((best_score, _)) if *best_score >= s => {}
                    _ => {
                        best_ip = Some((s, ip.to_string()));
                    }
                }
            }
        }
    }

    best_ip
        .map(|(_, ip)| ip)
        .unwrap_or_else(|| "127.0.0.1".to_string())
}

/// Compute all directed subnet broadcast targets + global broadcast for active interfaces.
#[pyfunction]
pub fn compute_broadcast_targets(interfaces: Vec<(String, String, u8, bool)>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut targets = Vec::new();

    // First add directed broadcasts for physical interfaces, then virtual interfaces
    let mut scored: Vec<(i32, String, u8)> = Vec::new();
    for (name, ip_str, prefix_len, is_up) in interfaces {
        if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
            let s = score_lan_interface(&name, ip, is_up);
            if s > -500 {
                scored.push((s, ip_str, prefix_len));
            }
        }
    }
    scored.sort_by_key(|a| std::cmp::Reverse(a.0));

    for (_score, ip_str, prefix_len) in scored {
        if let Some(bcast) = compute_subnet_broadcast(&ip_str, prefix_len) {
            if seen.insert(bcast.clone()) {
                targets.push(bcast);
            }
        }
        // Also add /24 fallback if prefix != 24 and IP is private
        if prefix_len != 24 {
            if let Some(bcast24) = compute_subnet_broadcast(&ip_str, 24) {
                if seen.insert(bcast24.clone()) {
                    targets.push(bcast24);
                }
            }
        }
    }

    if seen.insert("255.255.255.255".to_string()) {
        targets.push("255.255.255.255".to_string());
    }

    targets
}

/// Deterministic simultaneous connection tie-breaker between two peers.
///
/// Returns:
/// - `"keep_outbound"` if `local_peer_id_hex < remote_peer_id_hex`
/// - `"keep_inbound"` if `local_peer_id_hex > remote_peer_id_hex`
/// - `"same_peer"` if equal
#[pyfunction]
pub fn arbitrate_simultaneous_connection(
    local_peer_id_hex: &str,
    remote_peer_id_hex: &str,
) -> &'static str {
    let a = local_peer_id_hex.trim().to_ascii_lowercase();
    let b = remote_peer_id_hex.trim().to_ascii_lowercase();
    if a < b {
        "keep_outbound"
    } else if a > b {
        "keep_inbound"
    } else {
        "same_peer"
    }
}

// ---------------------------------------------------------------------------
// NativeIpRateLimiter
// ---------------------------------------------------------------------------

#[pyclass(module = "bitchat._bitchat_core")]
pub struct NativeIpRateLimiter {
    max_events: usize,
    window_seconds: f64,
    max_tracked_ips: usize,
    events: HashMap<String, VecDeque<f64>>,
}

#[pymethods]
impl NativeIpRateLimiter {
    #[new]
    #[pyo3(signature = (max_events=20, window_seconds=1.0, max_tracked_ips=1024))]
    pub fn new(max_events: usize, window_seconds: f64, max_tracked_ips: usize) -> Self {
        Self {
            max_events: max_events.max(1),
            window_seconds: window_seconds.max(0.001),
            max_tracked_ips: max_tracked_ips.max(16),
            events: HashMap::new(),
        }
    }

    pub fn allow(&mut self, ip: &str, now: f64) -> bool {
        let cutoff = now - self.window_seconds;

        if !self.events.contains_key(ip) && self.events.len() >= self.max_tracked_ips {
            self.events
                .retain(|_, q| q.back().is_some_and(|&last| last >= cutoff));
            if self.events.len() >= self.max_tracked_ips {
                if let Some(first_key) = self.events.keys().next().cloned() {
                    self.events.remove(&first_key);
                }
            }
        }

        let queue = self.events.entry(ip.to_string()).or_default();
        while let Some(&front) = queue.front() {
            if front < cutoff {
                queue.pop_front();
            } else {
                break;
            }
        }

        if queue.len() >= self.max_events {
            return false;
        }
        queue.push_back(now);
        true
    }

    /// Sliding-window rate check matching `LANDiscovery._is_rate_limited`:
    /// auto-prunes expired entries once tracked IPs exceed 256 without dropping
    /// still-active entries inside the current window.
    pub fn is_rate_limited(&mut self, ip: &str, now: f64) -> bool {
        if self.events.len() > 256 {
            self.prune(self.window_seconds, now);
        }
        let cutoff = now - self.window_seconds;
        let queue = self.events.entry(ip.to_string()).or_default();
        while let Some(&front) = queue.front() {
            if front < cutoff {
                queue.pop_front();
            } else {
                break;
            }
        }
        if queue.len() >= self.max_events {
            return true;
        }
        queue.push_back(now);
        false
    }

    pub fn prune(&mut self, max_age: f64, now: f64) -> usize {
        let before = self.events.len();
        self.events.retain(|_, timestamps| match timestamps.back() {
            Some(&latest) => now - latest <= max_age,
            None => false,
        });
        before.saturating_sub(self.events.len())
    }

    pub fn contains_ip(&self, ip: &str) -> bool {
        self.events.contains_key(ip)
    }

    pub fn get_ip_timestamps(&self, ip: &str) -> Option<Vec<f64>> {
        self.events.get(ip).map(|q| q.iter().copied().collect())
    }

    pub fn set_ip_timestamps(&mut self, ip: String, timestamps: Vec<f64>) {
        self.events.insert(ip, VecDeque::from(timestamps));
    }

    pub fn remove_ip(&mut self, ip: &str) -> bool {
        self.events.remove(ip).is_some()
    }

    pub fn tracked_ip_count(&self) -> usize {
        self.events.len()
    }

    pub fn clear(&mut self) {
        self.events.clear();
    }
}

// ---------------------------------------------------------------------------
// Tokio Asynchronous LAN Frame Exchange Engine (Stage 4)
// ---------------------------------------------------------------------------

/// Asynchronously send a length-framed BitChat packet to a TCP endpoint using Tokio.
#[pyfunction]
#[pyo3(signature = (host, port, payload, timeout_ms=5000))]
pub fn tokio_send_framed_packet(
    py: Python<'_>,
    host: &str,
    port: u16,
    payload: &[u8],
    timeout_ms: u64,
) -> PyResult<()> {
    let frame = encode_frame_vec(payload, MAX_FRAME_SIZE)?;
    let addr_str = format!("{}:{}", host, port);
    let timeout = Duration::from_millis(timeout_ms.max(100));

    py.allow_threads(|| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| CoreError::framing(format!("Tokio runtime init failed: {}", e)))?;

        rt.block_on(async move {
            let mut stream = tokio::time::timeout(timeout, TcpStream::connect(&addr_str))
                .await
                .map_err(|_| CoreError::framing(format!("TCP connect timed out to {}", addr_str)))?
                .map_err(|e| {
                    CoreError::framing(format!("TCP connect failed to {}: {}", addr_str, e))
                })?;

            let _ = stream.set_nodelay(true);
            tokio::time::timeout(timeout, stream.write_all(&frame))
                .await
                .map_err(|_| CoreError::framing("TCP write timed out"))?
                .map_err(|e| CoreError::framing(format!("TCP write failed: {}", e)))?;
            let _ = tokio::time::timeout(timeout, stream.flush()).await;
            Ok::<(), CoreError>(())
        })
    })?;

    Ok(())
}

/// Asynchronously broadcast a UDP discovery payload to multiple target addresses using Tokio.
#[pyfunction]
pub fn tokio_udp_broadcast_beacon(
    py: Python<'_>,
    payload: &[u8],
    targets: Vec<String>,
    port: u16,
) -> PyResult<usize> {
    let data = payload.to_vec();
    let count = py.allow_threads(|| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| CoreError::value_err(format!("Tokio runtime init failed: {}", e)))?;

        rt.block_on(async move {
            let sock = UdpSocket::bind("0.0.0.0:0")
                .await
                .map_err(|e| CoreError::value_err(format!("UDP bind failed: {}", e)))?;
            let _ = sock.set_broadcast(true);
            let mut sent = 0usize;
            for target in targets {
                let dest = format!("{}:{}", target, port);
                if let Ok(addr) = dest.parse::<SocketAddr>() {
                    if sock.send_to(&data, addr).await.is_ok() {
                        sent += 1;
                    }
                }
            }
            Ok::<usize, CoreError>(sent)
        })
    })?;
    Ok(count)
}

/// Read a single `BC\x01\x00`-framed packet from an async Tokio TcpStream.
pub async fn tokio_read_single_frame(
    stream: &mut TcpStream,
    timeout: Duration,
) -> Result<Vec<u8>, CoreError> {
    let mut header = [0u8; HEADER_SIZE];
    tokio::time::timeout(timeout, stream.read_exact(&mut header))
        .await
        .map_err(|_| CoreError::framing("TCP frame header read timed out"))?
        .map_err(|e| CoreError::framing(format!("TCP frame header read error: {}", e)))?;

    if header[0..4] != FRAME_MAGIC {
        return Err(CoreError::framing("Invalid stream framing magic"));
    }
    let length = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;
    if length > MAX_FRAME_SIZE {
        return Err(CoreError::framing(format!(
            "Frame payload length {} exceeds maximum",
            length
        )));
    }
    let mut body = vec![0u8; length];
    tokio::time::timeout(timeout, stream.read_exact(&mut body))
        .await
        .map_err(|_| CoreError::framing("TCP frame body read timed out"))?
        .map_err(|e| CoreError::framing(format!("TCP frame body read error: {}", e)))?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn test_discovery_packet_roundtrip_and_validation() {
        let peer_id = "0102030405060708";
        let inst_id = "aabbccddeeff0011";
        let raw = encode_discovery_packet_raw(
            peer_id, 41235, "alice", inst_id, 1, "MeshWiFi", "bitchat", "lan",
        )
        .unwrap();
        let (dec_peer, dec_port, dec_nick, dec_ssid, dec_inst, dec_ver) =
            decode_discovery_packet_full_raw(&raw).unwrap();
        assert_eq!(dec_peer, peer_id);
        assert_eq!(dec_port, 41235);
        assert_eq!(dec_nick, "alice");
        assert_eq!(dec_ssid, "MeshWiFi");
        assert_eq!(dec_inst, inst_id);
        assert_eq!(dec_ver, 1);

        let (dec_peer2, dec_port2, dec_nick2, dec_inst2, dec_ver2) =
            decode_discovery_packet_raw(&raw).unwrap();
        assert_eq!(dec_peer2, peer_id);
        assert_eq!(dec_port2, 41235);
        assert_eq!(dec_nick2, "alice");
        assert_eq!(dec_inst2, inst_id);
        assert_eq!(dec_ver2, 1);

        // Invalid magic or port rejected
        assert!(decode_discovery_packet_raw(b"{\"magic\":\"WRONG\"}").is_none());
        assert!(
            encode_discovery_packet_raw("bad", 41235, "a", "", 1, "", "bitchat", "lan").is_err()
        );
        assert!(
            encode_discovery_packet_raw(peer_id, 70000, "a", "", 1, "", "bitchat", "lan").is_err()
        );
    }

    #[test]
    fn test_interface_scoring_prefers_physical_over_wsl_or_vpn() {
        let interfaces = vec![
            (
                "vEthernet (WSL)".to_string(),
                "172.24.16.1".to_string(),
                20,
                true,
            ),
            ("utun0".to_string(), "10.8.0.2".to_string(), 24, true),
            ("Wi-Fi".to_string(), "192.168.1.42".to_string(), 24, true),
        ];
        assert_eq!(select_best_lan_ip(interfaces.clone()), "192.168.1.42");
        let bcasts = compute_broadcast_targets(interfaces);
        assert_eq!(bcasts[0], "192.168.1.255");
        assert!(bcasts.contains(&"255.255.255.255".to_string()));
    }

    #[test]
    fn test_tokio_tcp_framed_roundtrip() {
        let frame = encode_frame_vec(b"hello tokio lan", MAX_FRAME_SIZE).unwrap();
        assert_eq!(&frame[0..4], &FRAME_MAGIC);
        assert_eq!(
            u32::from_be_bytes([frame[4], frame[5], frame[6], frame[7]]) as usize,
            b"hello tokio lan".len()
        );

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let listener = match TcpListener::bind("127.0.0.1:0").await {
                Ok(l) => l,
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return,
                Err(e) => panic!("TcpListener::bind failed: {}", e),
            };
            let addr = listener.local_addr().unwrap();

            let server_task = tokio::spawn(async move {
                let (mut sock, _) = listener.accept().await.unwrap();
                tokio_read_single_frame(&mut sock, Duration::from_secs(2))
                    .await
                    .unwrap()
            });

            let mut client = match TcpStream::connect(addr).await {
                Ok(c) => c,
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                    server_task.abort();
                    return;
                }
                Err(e) => panic!("TcpStream::connect failed: {}", e),
            };
            client.write_all(&frame).await.unwrap();

            let received = server_task.await.unwrap();
            assert_eq!(received, b"hello tokio lan");
        });
    }
}
