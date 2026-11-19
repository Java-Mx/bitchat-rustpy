# Changelog

All notable changes to this project will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.4] - 2026-11-19

### Added
- **Native Rust BLE Transport Architecture (`rust/bitchat-core/src/ble/`):** Replaced the single-file BLE helper stub with a modular native Rust BLE transport stack (`types.rs`, `advertisement.rs`, `connection.rs`, `manager.rs`, `windows_winrt.rs`, `linux_bluez.rs`, `macos_corebt.rs`) exposing `NativeBleTransportManager`, `probe_native_ble_adapter_raw`, `extract_ble_service_data_peer_id`, `validate_ble_gatt_characteristic_raw`, and `bitchat_ble_uuids_raw` with GIL-free execution (`py.allow_threads`), bounded event/write queues, early-notification buffering, and secret-redacted diagnostic traces.
- **Platform-Native Rust BLE Backends:** Implemented native Windows WinRT BLE (`windows` 0.58: `BluetoothAdapter`, `Radio`, `BluetoothLEAdvertisementWatcher`, `BluetoothLEDevice`, `GattSession`, `GattServiceProvider`, `GattLocalCharacteristic`, and decoupled `BluetoothLEAdvertisementPublisher`), native Linux BlueZ D-Bus (`zbus` 5: `Adapter1`, `Device1`, `GattManager1`, `LEAdvertisingManager1`, `GattService1`, `GattCharacteristic1`, `LEAdvertisement1`), and truthful macOS CoreBluetooth capability probing (`macos_corebt.rs`).
- **Reference `bitchat-tui` Binary DM Payload Interoperability (`rust/bitchat-core/src/engine.rs`, `src/bitchat/app/session_coordinator.py`):** Audited `vaibhav-mattoo/bitchat-tui` (`107a13c570cfb2f1c5cdb9a49c8945e57d794023`) and added native Rust `decode_chat_payload_raw` & `encode_bitchat_message_payload_raw` supporting plain UTF-8, `[0x04] || UTF-8`, `[0x04] || binary BitchatMessage`, bare binary `BitchatMessage`, and nested `BitchatPacket(Message)` payloads with zero false positives while preserving strict fail-closed Noise XX security and nonce-0 replay rejection.
- **Live Bluetooth Settings Diagnostics (`src/bitchat/tui/screens/settings.py`, `src/bitchat/transport/bluetooth.py`):** Replaced hardcoded/placeholder Bluetooth Settings values with live asynchronous hardware & transport telemetry covering backend driver, adapter name/address/device ID, radio power state, canonical BitChat Service & Characteristic UUIDs, Central/Peripheral role statuses, independent GATT server & discovery advertisement statuses, peer counts, negotiated ATT MTU, error diagnostics, and an explicit Refresh Bluetooth Information button with safe worker cancellation.
- **Phase 3 Verification & Regression Test Suites (`tests/interoperability/test_phase3_ble_noise_interop.py`, `tests/unit/test_phase3_ui_stability_and_bt_diagnostics.py`, `docs/release/PHASE-3-IMPLEMENTATION-AND-VERIFICATION-REPORT.md`):** Added differential `bitchat-tui` Noise XX tests, decoupled Windows GATT lifecycle tests, strict scanner/GATT validation tests, Textual mouse-pilot navigation stability tests, and Bluetooth Settings diagnostics tests.

### Fixed
- **Mouse Navigation Jitter & Triple-Fire Screen Fluctuation (`src/bitchat/tui/widgets/status_bar.py`, `src/bitchat/tui/app.py`, `src/bitchat/tui/screens/*.py`):** Fixed `StatusBar.on_button_pressed` firing every action button three times per click (direct call + `ActionTriggered` + bubbled `Button.Pressed`) by stopping event propagation and dispatching once; added `event.stop()` across all screen button handlers, batched multi-layer screen pops (`batch_update()`), and deduplicated `PeersScreen.refresh_peer_list()` row rebuilds to eliminate periodic DataTable flicker and cursor jumps.
- **Windows GATT Server / Companion Advertisement Coupling (`src/bitchat/ble/server.py`, `rust/bitchat-core/src/ble/windows_winrt.rs`):** Decoupled the optional companion manufacturer `BluetoothLEAdvertisementPublisher` from `GattServiceProvider` so a companion publisher failure cleans up only the publisher and never tears down an active GATT service or characteristic, while reporting GATT and discovery advertisement statuses independently.
- **Wrong Hardcoded Service UUID & False Scanner Status in Settings (`src/bitchat/tui/screens/settings.py`):** Replaced the incorrect hardcoded `0000fee0-0000-1000-8000-00805f9b34fb` UUID with canonical `BITCHAT_SERVICE_UUID` (`F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C`) and `BITCHAT_CHARACTERISTIC_UUID` (`A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D`), and eliminated the falsely hardcoded `"Active / Scanning"` Central status.
- **Truncated BLE Service-Data Peer IDs (`src/bitchat/ble/scanner.py`, `rust/bitchat-core/src/ble/advertisement.rs`):** Enforced full 8-byte (16-hex-char) non-zero, non-broadcast peer IDs for BLE service data instead of emitting malformed 12/14-char IDs from 6–7 byte payloads.
- **GATT Characteristic Property Validation (`src/bitchat/ble/gatt.py`):** Enforced hyphen/case-insensitive UUID matching and strict `notify` + `write`/`write-without-response` characteristic validation with write-mode selection (`last_write_mode`).

## [0.3.3] - 2026-11-19

### Added
- **Authoritative Native Noise XX Session Integration (`rust/bitchat-core/src/noise.rs`, `src/bitchat/crypto/sessions.py`):** Migrated `NoiseSession` to delegate authoritatively to Rust `NativeNoiseSession` (with embedded 12-phase `NativeHandshakeStateMachine`), eliminating duplicate Python/Rust cipher states and preventing unzeroized symmetric key copies from entering Python heap memory. Retained `PyNoiseSession` strictly as a pure-Python differential reference and non-native fallback.
- **Cohesive Single-Crossing Native Protocol Engine (`rust/bitchat-core/src/engine.rs`):** Implemented `NativeProtocolEngine` executing wire decode, fragment reassembly, mesh routing/dedup/rate-limiting, protocol message dispatch (`0x01`, `0x04`, `0x0A`, `0x10`, `0x11`, `0x12`, `0x13`, `0x25`), Noise XX state advancement, collision-safe identity binding, and outbound wire encoding in a single FFI crossing (7.28x faster inbound DM pipeline and 132x lower Python `tracemalloc` peak allocation).
- **Stage 3 Native Peer State Engine (`rust/bitchat-core/src/engine.rs`, `src/bitchat/app/session_coordinator.py`):** Implemented `NativePeerStateEngine` owning bounded peer tables, anti-spoofing nickname validation, bounded pending direct-message queues (`32` per peer / `512` global), and collision-safe identity bindings (`peer_id <-> fingerprint` with reverse collision index).
- **Controlled Legacy `bitchat-tui` Peer-ID Interoperability (`rust/bitchat-core/src/protocol.rs`, `noise.rs`, `engine.rs`):** Added `classify_peer_id_raw` and `normalize_peer_id_raw` recognizing exact 4-byte random zero-extended legacy TUI identifiers (`XXXXXXXX00000000`) while keeping modern RustPy `SHA-256(X25519_pub)[:8]` binding strict. Legacy peer IDs are bound only after Noise XX static-key authentication, checked against collision-safe pinned fingerprints, and explicitly distinguished between `authenticated` (Noise possession) and `verified` (out-of-band user confirmation).
- **`NoiseIdentityAnnounce` (`0x13`) & `DeliveryAck` (`0x0A`) Integration:** Added native Rust `parse_noise_identity_announce_raw` validation and integrated `NativeAckTracker` into `SessionCoordinator` without permitting unauthenticated announces to overwrite trusted identity mappings.
- **Cross-Implementation Interoperability Test Suite (`tests/interoperability/test_tui_interop.py`):** Added comprehensive tests verifying `bitchat-tui` wire compatibility, legacy peer-ID bidirectional encrypted messaging, impostor collision rejection, BLE Central ↔ RustPy GATT Peripheral exchange, BLE MTU-aware chunking, nonce-0 replay rejection, nonce exhaustion fail-closed behavior, and `NativeNoiseSession` vs `PyNoiseSession` cross-engine differential parity.
- **Phase 2.2 Benchmark Suite & Engineering Reports (`scripts/benchmark_phase22.py`, `docs/release/PHASE-2.2-IMPLEMENTATION-AND-VERIFICATION-REPORT.md`, `docs/release/V0.3.3-RUST-MIGRATION-PERFORMANCE-AND-SECURITY-IMPACT.md`, `docs/release/V0.3.3-RELEASE-NOTES.md`):** Added reproducible Python-vs-Rust latency, FFI crossing, and heap memory benchmarks along with full release and Rust migration impact documentation.
- **macOS Apple Silicon ABI3 Wheel Release (`.github/workflows/release.yml`):** Added automated `macos-latest` (`arm64`) CI build and verification producing `bitchat-0.3.3-cp312-abi3-macosx_11_0_arm64.whl` + `.sha256`.
- **Safe Windows Editable Native Build Tooling (`scripts/build_native.py`, `scripts/dev-windows.ps1`, `pyproject.toml`, `tests/unit/test_windows_native_build.py`):** Added OS-level build lock serialization, Win32 `CreateFileW` + Restart Manager exact PID lock diagnostics for both `src/bitchat/_bitchat_core.pyd` (`os error 32`) and `.venv/Scripts/bitchat.exe` (`os error 5`), PowerShell 5.1 workflow scripts, and `[tool.uv] cache-keys`.
- **WinGet `v0.3.3` Submission & Release Automation Hardening (`manifests/j/Java-Mx/BitChat/0.3.3/`, `.github/workflows/release.yml`):** Submitted official `Java-Mx.BitChat` `0.3.3` manifests upstream in [microsoft/winget-pkgs#483934](https://github.com/microsoft/winget-pkgs/pull/483934) preserving Inno Setup AppId `{B17CHA70-B1EC-4E87-99B7-4DA78D0B7001}` for in-place `0.3.1 → 0.3.3` upgrades, and hardened `.github/workflows/release.yml` to verify manifest version/SHA-256 consistency, check upstream duplicates, and emit explicit warnings and step summaries when `WINGET_TOKEN` is unset.

### Changed
- **Eliminated Duplicate Python+Rust Mesh Execution (`src/bitchat/mesh/router.py`, `src/bitchat/mesh/store_forward.py`):** Removed parallel `PyMeshRouter` and `PyStoreAndForwardQueue` execution when native `_bitchat_core` is loaded; `NativeMeshRouter` and `NativeStoreAndForwardQueue` are now the sole authoritative runtime owners with single-pass `evaluate_incoming_raw`.
- **Native LAN Discovery IP Rate Limiting (`rust/bitchat-core/src/lan.rs`, `src/bitchat/network/discovery.py`):** Wired `LANDiscovery` to use `NativeIpRateLimiter` natively instead of a Python dictionary.
- **MTU-Aware BLE Write Chunking (`src/bitchat/ble/connection.py`, `src/bitchat/ble/transport.py`, `src/bitchat/protocol/fragmentation.py`):** Wired negotiated controller ATT MTU detection (`client.mtu_size`) into `NativeBleConnectionEngine` and `compute_ble_write_chunk_size`, dynamically chunking outbound packets when a controller negotiates a constrained ATT MTU.
- **Event-Driven Handshake Wait (`src/bitchat/app/session_coordinator.py`):** Replaced the `asyncio.sleep(0.04)` polling loop during `NoiseEncrypted` arrival with an explicit per-peer `asyncio.Event` bounded wait.

### Security
- **Noise Transport Nonce Exhaustion Fail-Closed (`rust/bitchat-core/src/noise.rs`, `src/bitchat/crypto/noise.py`):** Enforced hard ceiling `NOISE_MAX_TRANSPORT_NONCE = u32::MAX` (with `needs_rekey()` warning at `1_000_000_000`), failing closed with `InvalidNonceError` and invalidating transport ciphers so 4-byte wire nonces can never wrap around or be reused.
- **Zero Python Key Copies in Active Native Sessions:** Removed eager copying of `NativeNoiseCipherState.key` into unzeroized Python `bytes` during initialization; active `NoiseSession` instances keep transport keys strictly inside `zeroize::ZeroizeOnDrop`-protected Rust memory.
- **Reconnect Key Invalidation:** Inbound `NoiseHandshakeInit` on an established session cleanly resets and zeroizes stale transport ciphers before starting fresh ephemeral handshake state.

## [0.3.2] - 2026-11-19

### Added
- **Native Rust Cryptography (`rust/bitchat-core/src/crypto.rs`):** Implemented audited Rust cryptographic primitives using `x25519-dalek` (2.0 with low-order Curve25519 point rejection), `ed25519-dalek` (2.1 with constant-time verification), `chacha20poly1305` (0.10 AEAD), `aes-gcm` (0.10 channel encryption), `hkdf` (0.12), `hmac` (0.12), `sha2` (0.10), and `pbkdf2` (0.12 with 100,000-iteration key derivation).
- **Native Rust Noise XX Session Engine (`rust/bitchat-core/src/noise.rs`):** Implemented the full `Noise_XX_25519_ChaChaPoly_SHA256` state machine (`NativeNoiseHandshakeState`, `NativeNoiseSymmetricState`, `NativeNoiseCipherState`, `NativeNoiseSession`) with strict `zeroize::ZeroizeOnDrop` memory scrubbing for static private keys, ephemeral handshake keys, chaining keys, and transport keys.
- **Deterministic 12-Phase Handshake State Machine (`rust/bitchat-core/src/noise.rs`):** Implemented `NativeHandshakeStateMachine` tracking explicit observable stages (`Discovered`, `Connecting`, `TransportConnected`, `GattReady`, `HandshakeInitiated`, `AwaitingMessage2`, `AwaitingMessage3`, `AuthenticatingIdentity`, `Established`, `Failed`, `Closing`, `Closed`) with redacted diagnostic reporting.
- **Replay Protection & Nonce Boundary Enforcement:** Implemented a bounded 1,024-entry sliding replay window in `NativeNoiseCipherState` protecting all wire nonces including wire nonce `0`.
- **Native Mesh Routing, Store-and-Forward & Ack Tracking (`rust/bitchat-core/src/mesh.rs`):** Implemented single-pass `NativeMeshRouter`, `NativeStoreAndForwardQueue`, and `NativeAckTracker` eliminating repetitive Python/Rust FFI crossings during multi-hop forwarding.
- **Native LAN Transport Engine Foundation (`rust/bitchat-core/src/lan.rs`):** Implemented `encode_discovery_packet_raw`, `decode_discovery_packet_raw`, `select_best_lan_ip` (scoring physical Wi-Fi/Ethernet adapters above virtual WSL/Docker/VPN adapters), `compute_subnet_broadcast`, `compute_broadcast_targets`, `arbitrate_simultaneous_connection`, `NativeIpRateLimiter`, and Tokio asynchronous TCP/UDP streaming helpers.
- **Native BLE Connection Engine Foundation (`rust/bitchat-core/src/ble.rs`):** Implemented `NativeBleConnectionEngine` with pre-ready notification queueing during `SUBSCRIBING`, `compute_ble_write_chunk_size` (dynamically adapting to controller MTU), and `encode_ble_manufacturer_payload` / `decode_ble_manufacturer_payload` supporting backward-compatible 8-byte peer ID advertisement extensions.
- **WinGet Manifests for v0.3.2 (`manifests/j/Java-Mx/BitChat/0.3.2/`):** Generated and validated official multi-file WinGet manifests for package `Java-Mx.BitChat` with moniker `bitchat-rustpy`.

### Fixed
- **LAN Multi-Interface Selection Failure:** Fixed cross-machine discovery failure between Windows and Linux machines by scoring physical network adapters above virtual WSL/Hyper-V/Docker/VPN interfaces.
- **Dynamic Bound TCP Port Mismatch:** Fixed discovery packet serialization to query and advertise the actual bound TCP listener port instead of assuming default port 41235.
- **Subnet-Directed UDP Discovery Beacons:** Replaced global-only broadcast with per-adapter directed subnet broadcasts, overcoming Wi-Fi AP client isolation.
- **Stranded Messages on Session Failure:** Fixed `SessionCoordinator.send_direct_message` to detect failed and stale handshaking sessions, cancel stale timers, reset state safely, and re-initiate handshakes without stranding queued direct messages.
- **Dropped Inbound Handshake Retries:** Fixed `SessionCoordinator._process_packet_async` to automatically reset responder sessions in `FAILED` state upon receiving valid `NoiseHandshakeInit` packets.
- **Simultaneous Handshake Contention:** Resolved race conditions when both peers initiate handshakes simultaneously by implementing deterministic canonical role tie-breaking (`local_peer_id < remote_peer_id`).
- **BLE Notification Subscription Race:** Prevented dropped Message 2 notifications by buffering inbound notifications in `NativeBleConnectionEngine` during the `SUBSCRIBING` state and draining them upon reaching `READY`.
- **BLE GATT Server Client Tracking:** Preserved inbound GATT server client registrations in `BluetoothTransport._server_clients` and included them in `connected_peers`.
- **MTU-Aware BLE Writes:** Clamped BLE GATT writes dynamically according to negotiated controller MTU to prevent packet truncation or OS GATT errors.

### Security
- **Native Memory Scrubbing:** Protected all secret key material via `zeroize::ZeroizeOnDrop` in native Rust so private keys, nonces, and shared secrets do not reside in unzeroized Python memory.
- **Fail-Closed Authentication:** Guaranteed fail-closed behavior on decryption errors, static identity mismatch, or replay violations across both native Rust and Python fallbacks.

## [0.3.1] - 2026-11-09

### Performance
- **PeerSidebar In-Place Updates & Render Caching (`src/bitchat/tui/widgets/sidebar.py`):** Replaced full container DOM teardown (`remove_children()`) with structural snapshot diffing and in-place `PeerEntry.update_peer_data` updates, reducing 10-peer sidebar refresh latency from 70.3 ms to 0.28 ms at P50 (248x faster) and 252.3 ms to 0.76 ms at P99 (331x faster).
- **Coalesced Peer & Transport Status Updates (`src/bitchat/tui/app.py`):** Added status-bar state signature deduplication (`_last_status_bar_signature`) and debounced peer-list refresh scheduling (`_schedule_peer_ui_refresh`), reducing keyboard input latency under sustained multi-peer load by 4.69x at P99.
- **Batched Chat Message Rendering (`src/bitchat/tui/widgets/chat_view.py`):** Wrapped message overflow pruning and widget mounting inside `app.batch_update()` and coalesced viewport scrolling via `call_after_refresh` (`_schedule_scroll_end`), cutting P99 chat render spikes by 5.58x.
- **BLE Advertisement Filtering Improvements (`src/bitchat/ble/scanner.py`):** Added fast-path advertisement pre-filtering and RSSI hysteresis (`< 3 dBm` within `2.0s`) in `BLEScanner._detection_callback` to eliminate redundant allocations on non-matching or unchanged BLE advertisements.
- **Reduced Mesh Packet-Processing Overhead (`src/bitchat/mesh/router.py`):** Computed deterministic SHA-256 packet IDs once per hop and passed precomputed IDs through deduplication checks and recordings.

### Rust Acceleration
- **Rust / PyO3 / Maturin Architecture (`rust/bitchat-core/`, `bitchat._bitchat_core`):** Introduced a compiled Rust native extension crate built with `maturin` (`abi3-py312`) and `pyo3 0.24`, with full PEP 484 type stubs (`src/bitchat/_bitchat_core.pyi`) and runtime fallback loader (`src/bitchat/_native.py`).
- **Native Protocol Encoding & Decoding (`rust/bitchat-core/src/protocol.rs`):** Accelerated binary wire packet serialization, header/routing/signature unpacking, peer ID hex conversion, and PKCS#7 optimal block padding (`encode_packet_raw`, `decode_packet_raw`, `pad_packet_data`, `unpad_packet_data`).
- **Fragmentation & Reassembly (`rust/bitchat-core/src/fragmentation.rs`):** Accelerated payload chunk splitting, fragment header encoding/parsing, and stateful concurrent fragment reassembly (`NativeFragmentReassembler`).
- **TCP Stream Framing (`rust/bitchat-core/src/framing.rs`):** Implemented zero-copy cursor-indexed TCP length-prefixed framing (`NativeStreamFramer` and `encode_frame_bytes`), delivering a 27.4x throughput increase on burst frame extraction.
- **Mesh Packet Identification, Deduplication & Rate Limiting (`rust/bitchat-core/src/mesh.rs`):** Implemented native SHA-256 packet ID computation (`compute_packet_id_raw`), O(1) FIFO/LRU ring deduplication with monotonic TTL expiration (`NativePacketDeduplicator`), and per-peer token-bucket rate limiting (`NativePeerRateLimiter`).
- **Python Reference Implementations (`py_*` / `Py*`):** Retained pure-Python reference implementations across `encoder.py`, `decoder.py`, `packet.py`, `fragmentation.py`, `reassembly.py`, `framing.py`, and `dedup.py` for fallback and differential verification.

### Uninstaller
- **Unified Windows & Linux Uninstallation (`src/bitchat/platform/uninstaller.py`, `bitchat --uninstall`):** Added a comprehensive cross-platform uninstaller supporting `--uninstall`, `--remove-user-data` (`--purge`), `--keep-user-data`, `--dry-run`, and `--yes`.
- **Python, pip, uv & pipx Launcher Cleanup:** Automatically discovers and removes residual `bitchat.exe`, `bitchat-script.py`, `bitchat.cmd`, `bitchat.ps1`, and `bitchat` console-script wrappers and `bitchat*.dist-info` metadata across active, user-base, multi-version `Programs\Python\Python3*\Scripts` (including `Python314\Scripts\bitchat.exe`), `uv` tools, and `pipx` environments without modifying shared parent directories.
- **PATH & Packaging Lifecycle Cleanup:** Cleans BitChat-specific user `PATH` entries (`HKCU\Environment\Path`), shortcuts, caches, and running `bitchat` processes across Windows Inno Setup (`packaging/windows/bitchat.iss`) and Debian maintainer scripts (`packaging/linux/deb/prerm`, `packaging/linux/deb/postrm`).
- **User-Data Preservation vs. Explicit Complete Removal:** Preserves `~/.bitchat` (identity keys, SQLite history, known peers, and configuration) by default during standard uninstallation, and removes `~/.bitchat` only when explicitly requested via `--remove-user-data` / `--purge` / `/REMOVEUSERDATA` or interactive confirmation.

### Compatibility and Security
- **Wire Compatibility Preserved:** 100% byte-for-byte wire compatibility verified between the Rust native core and pure-Python reference implementations across all packet types, flags, fragmentation headers, and TCP frames.
- **Existing Noise XX & Identity Implementations Retained:** Cryptographic Noise XX handshakes, X25519/Ed25519 identity management, and SQLite persistence remain intact.
- **Existing BLE, LAN & Offline Mode Behavior Preserved:** Full compatibility with BLE GATT/Scanner, LAN UDP discovery/TCP transport, `HomeScreen`, strict 2:2:2 Peer Grid layout, and `OFFLINE MODE` isolation.

## [0.3.0] - 2026-11-08

### Added
- **Home Screen Dashboard (`HomeScreen`):** Branded entry dashboard featuring quick-action navigation cards for Connect, Peers, Settings, Commands, and Telemetry, with full keyboard shortcuts and seamless screen transitions.
- **Connection Modal & Management (`ConnectionModal`, `ConnectionMenu`):** Dedicated modal interfaces for transport switching (BLE Mesh, LAN/Wi-Fi, and Offline Mode) and manual peer connection.
- **Dedicated Offline Mode:** Complete network isolation mode that suppresses all BLE advertising/scanning and LAN UDP broadcasts, reports explicit `OFFLINE MODE` status in the status bar, and enables safe offline startup.
- **Strict 2:2:2 Ratio Peer Grid (`PeersScreen`):** 3-column by 2-row action grid layout with standardized button dimensions, keyboard focus navigation, and direct chat launching from discovered peers.
- **Telemetry Dashboard (`TelemetryScreen`):** Real-time diagnostics displaying active transport state, interface IP and SSID, BLE radio health, MTU, packet transmit/receive counters, and reassembly statistics.
- **Commands Reference (`CommandsScreen`):** In-app documentation and quick reference for all BitChat slash commands and shortcuts.
- **Appearance Themes:** Preset color themes (Terminal Emerald, Midnight Blue, Amethyst Purple, Cyber Cyan) with live preview and configuration persistence.

### Changed
- **Disambiguated Network & BLE Status:** Disambiguated LAN/Wi-Fi status from BLE status; status bar accurately reports network SSID/IP without false Bluetooth errors when operating on LAN.
- **Transport Lifecycle Hardening:** Transport switching gracefully stops active listeners, cancels background tasks, and cleans up sockets before transitioning.
- **Navigation Flow:** Bidirectional navigation between Home Screen, Chat View, Peers Screen, Settings, and Telemetry.

### Fixed
- **Transport Switch Concurrency:** Prevented overlapping transport switch commands from leaving the coordinator in an inconsistent state.
- **BLE Status Leak in LAN Mode:** Suppressed BLE peripheral warning messages in the status bar when running in LAN mode.
- **Keybinding Conflict Validation:** Hardened keybinding parser and conflict validator across TUI screens.

## [0.2.1] - 2026-10-31

### Added
- **Device identity and self-connection prevention (M6):** a persistent device identity
  is now distinct from per-process instance IDs and per-connection sessions. Two BitChat
  instances sharing the same profile on one machine recognise each other as the same
  device and no longer discover or connect to themselves over BLE, LAN or Noise.
  Identity loading is atomic and guarded by a cross-platform inter-process lock
  (`msvcrt` on Windows, `fcntl` on Linux).
- **Diagnostic logging (M5):** rotating file log (`bitchat.log`, 10 MB x 5 backups) with
  redaction of private keys, tokens and credentials; console logging is suppressed in
  TUI mode to avoid screen tearing.
- **Test suites:** mesh routing/rate-limit tests, a 132-test tiered end-to-end suite,
  M4 crypto hardening/adversarial tests and M5 lifecycle/stress tests.

### Changed
- Switching transport now preserves the persistent device identity instead of creating a
  new one.
- TUI shutdown cancels background tasks and stops the coordinator exactly once.
- Broad exception suppression in the TUI was replaced with targeted handling and logging.

### Fixed
- The TUI no longer raises `NoMatches` when an input event arrives before the
  autocomplete palette is mounted.
- Noise handshake rejects self-handshakes and hardens nonce-0 replay bounds.
- CI and Build workflows contained invalid YAML (unquoted `: ` in step names) and never
  ran; they now run on Linux and Windows (Python 3.12 and 3.13).

### Known limitations
- No Flatpak bundle is attached to the release.
- Windows installer authenticode signing depends on repository signing secrets.

## [0.2.0] - 2026-10-30

### Added
- **BitChat Windows Installer 2.0 (`packaging/windows/`, `BitChat-0.2.0-windows-x64.exe`):**
  - 7-screen Inno Setup 6 installation wizard: Welcome, Terms of Use (`TERMS_OF_USE.md`), Privacy Policy (`PRIVACY_POLICY.md`), Installation Location (with write-permission, ≥80 MB disk-space, and user-data path collision validation), Installation Options, Installation Progress, and Completion.
  - Official BitChat branding integration (`packaging/windows/assets.py`) from official SVG/PNG design assets into multi-resolution `bitchat.ico`, `wizard-large.bmp`, `wizard-small.bmp`, and embedded Windows `VSVersionInfo`.
  - Per-user Windows sign-in startup management (`bitchat.platform.startup`) and CLI commands (`bitchat --startup {enable,disable,status}`, `bitchat --startup-launch`) with Windows named mutex (`Local\BitChatAppRunningMutex`) duplicate-instance guard (`SingleInstanceGuard`).
  - Safe user `PATH` management (`HKCU\Environment\Path`) with installer ownership tracking (`PathAddedByInstaller`), automatic running-process shutdown before upgrade/uninstall, and preservation of `~/.bitchat/identity.json` and `~/.bitchat/config.json` across upgrades and default uninstallations (with optional `/REMOVEUSERDATA` cleanup).
  - Authenticode SHA-256 + RFC3161 timestamp signing and verification pipeline in `packaging/windows/build.py` and `.github/workflows/release.yml`.
  - Official Windows Download Page (`docs/download/index.html`) and distribution guide (`docs/DOWNLOAD.md`).
- Cross-platform BLE selection (`bitchat.platform.detection`, `bitchat.platform.recovery`): a single place decides Windows vs Linux from `sys.platform`; BLE backend availability, adapter hardware, GATT/advertising, and the active transport are reported separately. Linux is reported as BLE central-only (no GATT server), Windows keeps the WinRT GATT server.
- OS-specific Bluetooth recovery guidance now comes from the platform layer instead of text hard-coded in the TUI dialog.
- WinRT GATT event handlers are unregistered on cleanup, and `SessionCoordinator` ignores `start()` while the user is in offline mode.
- Persistent per-application event loop for the CLI (`Application._run_async`) so BlueZ/WinRT resources survive between commands.
- Phase 11: Transport Abstraction Layer & Local Area Network (LAN / Wi-Fi) Chat (`bitchat.transport`, `bitchat.network`):
  - Abstract base class `BaseTransport` (`bitchat.transport.base`) defining standard transport lifecycle (`start`, `stop`, `start_discovery`, `stop_discovery`), messaging (`send_to_peer`, `broadcast_packet`), peer connections (`connect_peer`, `disconnect_peer`), identity propagation (`update_identity`, `resolve_peer_id_to_address`), and live telemetry (`get_telemetry`).
  - Concrete `BluetoothTransport` bridging existing `BLEManager` and `BLEServer` to `BaseTransport` with complete null-safety for mock and headless environments.
  - High-performance LAN/Wi-Fi transport (`LANTransport`):
    - Zero-configuration UDP broadcast discovery on port 41234 (`LANDiscovery`) broadcasting bounded JSON beacons (`BC_DISCOVER_V1`) carrying peer ID, nickname, TCP port, and Wi-Fi SSID, with per-IP rate limiting (10 pkts/s) and 30-second TTL peer table pruning.
    - Robust 8-byte length-prefixed TCP streaming framing (`StreamFramer`, `encode_frame`) utilizing `BC\x01\x00` magic and 4-byte big-endian payload lengths, enforcing 65,536-byte max frame limits with full chunk fragmentation and concatenation assembly.
    - Asynchronous TCP client connection (`LANConnection`) with connect timeouts, send queues, reader loops, and safe proactor loop close handling.
    - Concurrent TCP listener (`LANServer`) supporting up to 32 concurrent peer links with ephemeral port fallback.
    - Real-time Windows network adapter telemetry (`NetworkAdapterManager`): detects active network interfaces, local non-loopback IPv4 addresses, and Windows Wi-Fi SSIDs (`netsh wlan show interfaces`) with background polling and state transition events.
  - Ephemeral transport switching with privacy guarantees:
    - `SessionCoordinator.switch_transport()` stops active transport, terminates all existing Noise XX sessions, and generates a fresh transport-scoped identity (`LocalIdentity.generate()`) with a new Peer ID; permanent disk storage (`identity.json`) is never modified or leaked across transports.
    - In-app notification informs user of the new peer identity and fresh cryptographic context.
  - User interface and command updates:
    - Added `/transport [bluetooth|lan]` slash command with autocomplete suggestions and input validation.
    - Added `Transport Selection:` radio button set (`Bluetooth`, `LAN / Wi-Fi`) to Settings modal (`F3`).
    - Dynamic sidebar border title updating between `Peers (BLE Mesh)` and `Peers (LAN / Wi-Fi)` with LAN peer indicators showing Wi-Fi SSID and `ip:port` endpoints.
    - Transport-aware autocomplete and `/status` diagnostics.
  - Expanded test suite to 594 passing tests with 100% pass rate.
- Phase 9.3 Addendum: UI Functional Completeness Audit & Real Settings Implementation (`bitchat.storage`, `bitchat.tui`):
  - Real display density switching: `Comfortable` mode (multi-line structured message bubbles, spacious 32-col sidebar) vs `Compact` mode (dense single-line chat messages, 25-col sidebar, compact message input) dynamically updates root CSS classes and re-renders full message history.
  - Dynamic message timestamp toggling: `Show Timestamps` vs `Hide Timestamps` dynamically controls timestamp rendering on incoming messages and retroactively re-renders structured history with or without timestamps.
  - Accent tone customization: supports `Midnight Blue` (`#58a6ff`), `Cyber Cyan` (`#39c5cf`), `Terminal Emerald` (`#56d364`), and `Amethyst Purple` (`#bc8cff`), dynamically applying scoped highlight and focus styles across the application interface while strictly preserving dark midnight backgrounds and deterministic peer identity colors.
  - End-to-end settings persistence: extended `AppConfig` with `density`, `show_timestamps`, `accent`, `max_hops`, and `inter_fragment_delay_ms` with defensive validation and deserialization. Configuration changes in `EditThemeModal`, `SettingsModal`, and `/name <nick>` command persist to `~/.bitchat/config.json` and are restored on application boot.
  - Unapplied changes discard: closing `EditThemeModal` via `Esc` or `Close` cleanly leaves active application settings and disk storage unaltered.
  - Expanded unit and behavioral test suite to 554 tests with 100% pass rate.
- Phase 9.3: Mesh / Store-and-Forward Hardening & Final TUI Layout Refinement (`bitchat.mesh`, `bitchat.tui`):
  - Enforced strict TTL boundary invariants in `MeshRouter`: drops incoming packets with TTL <= 0, clamps oversized TTL to `max_relay_ttl` to prevent amplification attacks, and ensures decremented TTL is strictly monotonically decreasing and >= 1 prior to relay.
  - Bounded TTL-invariant SHA-256 deduplication cache (LRU capped at 1,000 entries) preventing unbounded memory growth under flooding while guaranteeing duplicate packet rejection.
  - Bounded store-and-forward queue (`StoreAndForwardQueue`) with strict per-peer limits (20 packets), total queue capacity (100 packets), and aggregate byte limit (256 KB) with FIFO eviction on overflow.
  - Hardened concurrent packet relaying in `SessionCoordinator._relay_packet_async` checking running state before/after jitter sleep and safely handling cancellation and peer disconnects.
  - Redesigned bottom Action Bar in `StatusBar`: left column stacked operational telemetry (Mesh status, Noise XX encryption, and truthful active target), right column balanced 2:2:2 button grid (Row 1: `Edit`, `Settings`, `Peers`; Row 2: `Commands`, `Help`, `Quit`) with strictly equal column widths.
  - Truthful target status detection: dynamically renders `Target: #public`, `Target: @<peer>`, and `Target: @<peer> • Offline` based on real peer connection state.
  - Responsive Help modal (`HelpScreen`): expanded width to 90% (max 120 cols), full-width `DataTable` displaying all commands and shortcuts without truncation, and dedicated bottom action bar with centered `[ Close (Esc) ]` button.
  - Guaranteed keyboard shortcut reliability: `priority=True` on global app bindings (`f1`, `?`, `f2`, `f3`, `ctrl+q`, `ctrl+l`, `pageup`, `pagedown`) and explicit forwarding in `MessageInput.on_key` ensuring function keys trigger reliably regardless of input focus.
  - Edge-to-edge spatial alignment verified across multiple terminal resolutions (`80x24`, `100x30`, `120x40`, `160x50`): `ChatView` and `MessageInput` share identical horizontal boundaries, and `PeerSidebar` spans 100% of `#main-body` height down to the footer with zero gaps.
  - Unit and integration test suite expanded to 545 tests with 100% pass rate.
- Phase 9.2: TUI UX Polish, Interaction Model & Terminal Reliability (`bitchat.tui`, `bitchat.commands`):
  - Subtle dark midnight focus borders (`#28334e` / `#22283a`) and restrained surface highlights (`#121624`), eliminating aggressive neon outlines.
  - Edge-to-edge horizontal panel alignment with zero offset discrepancies across chat view, input bar, and sidebar.
  - Interactive Action Bar in `StatusBar` with clickable action buttons (`Edit (F2)`, `Settings (F3)`, `Peers`, `Commands (/)`, `Help (?)`, `Quit`) alongside live operational telemetry.
  - Cryptographic peer security modal (`PeerInfoModal`) displaying full 64-char fingerprint, 64-char peer ID, signal strength, transport details, and Noise XX cipher state, with `[Copy Fingerprint]` and `[Direct Message]` actions, strictly keeping private keys confidential.
  - Node configuration dialog (`SettingsModal`) for dynamic nickname adjustments, max mesh relay hops (TTL), and inter-fragment transmission delay.
  - Appearance customization modal (`EditThemeModal`) supporting display density modes (comfortable vs compact) and timestamp toggling.
  - Bluetooth error dialog (`BLEErrorModal`) providing diagnostic advice and an interactive `[Retry Adapter]` recovery workflow.
  - Truthful BLE status reporting (`✕ BLE Offline` when adapter is uninitialized or missing), preventing false "Mesh Active" claims.
  - Direct message `@peer <message>` syntax and `@` peer autocomplete trigger with deterministic peer coloring and automatic dismissal on space.
  - Active conversation context switching between `#public` and direct message target `@<peer>`.
  - Expanded command registry with `/settings`, `/edit`, `/status`, `/info`, `/public`, and `/peers`.
  - Comprehensive unit and integration test suite expanded to 531 tests with 100% pass rate.
- Phase 9.1: Full Terminal UI Redesign & Design System (`bitchat.tui`):
  - Cohesive edge-to-edge terminal dashboard composition utilizing 100% of viewport with zero wasted margins.
  - Strict 5-family color palette: Black (`#080a0f`, `#0f121c`, `#141824`), Blue (`#58a6ff`, `#388bfd`), Purple (`#bc8cff`, `#a371f7`), Deterministic Peer Identity Colors (8 curated distinct colors with CRC32 hashing), and Restrained Semantic Status (`#3fb950`, `#d29922`, `#f85149`).
  - Dedicated Textual CSS stylesheet (`src/bitchat/tui/styles/app.tcss`) centralizing layout, spacing, borders, focus states, and scrollbars.
  - Panel borders with inline titles (`border-title: "Peers [BLE Mesh]"`, `border-title: "Conversation [#public]"`).
  - Two-tier message rendering in `ChatView` with sender identity anchor in that peer's deterministic color, muted timestamp, and clear message body.
  - Compact 1-line top header (`HeaderWidget`) with branding, channel indicator, and peer/telemetry badges.
  - IDE-quality floating autocomplete palette (`AutocompletePalette`) anchored right above the input bar with real-time prefix filtering and dynamic contextual completion for `/dm <peer>` and `/connect <address>`.
  - Persistent keyboard footer (`StatusBar`) with monospace shortcut guide and operational telemetry.
  - PageUp / PageDown chat scroll keybindings.
  - Responsive layout verified across standard terminal resolutions (`80x24`, `100x30`, `120x40`, `160x50`).
  - Unit test suite expanded to 523 tests with 100% pass rate.
- Phase 9: Mesh Routing, Store-and-Forward, and Modern Textual TUI with Autocompletion:
  - Multi-hop mesh relay engine (`bitchat.mesh.router.MeshRouter`) featuring TTL decrementing, loop prevention, peer rate-limiting (50 pkts/s), destination filtering, and 10–50ms randomized relay jitter to mitigate BLE broadcast collisions.
  - TTL-invariant packet deduplication (`bitchat.mesh.dedup.PacketDeduplicator`) computing SHA-256 hashes over invariant packet fields (`sender_id`, `timestamp`, `message_type`, `recipient_id`, `payload`), bounded LRU cache (2,000 entries), and 300s TTL expiration window.
  - Offline store-and-forward queue (`bitchat.mesh.store_forward.StoreAndForwardQueue`) with strict per-peer limits (20 packets), global queue cap (100 packets), aggregate byte budget (256 KB), and automatic queue flushing upon peer presence announcement.
  - Central command registry (`bitchat.commands.parser`) with prefix-based suggestion lookup, command metadata, argument specifiers, and contextual peer target completion.
  - Complete Textual TUI redesign (`bitchat.tui`) with modular widget architecture:
    - Pure dark GitHub-inspired theme (`#0d1117`, `#161b22`, `#30363d`, `#58a6ff`).
    - Top header widget (`HeaderWidget`) with dynamic BLE connection pill, peer counter, and local ID.
    - Peer sidebar (`PeerSidebar`) with connected peers, discovered nodes, and identity summary.
    - Message stream (`ChatView`) with timestamps, badges (`[Public]`, `[🔒 DM]`, `[System]`, `[Security]`, `[Error]`), and scrollback log.
    - Message input (`MessageInput`) with command history navigation ($\uparrow/\downarrow$) and autocompletion interception.
    - IDE-style floating autocomplete palette (`AutocompletePalette`) with `/` trigger, prefix filtering, arrow key navigation, Tab/Enter acceptance, and Esc dismissal.
    - Bottom status bar (`StatusBar`) with real-time status and shortcut hint legend.
    - Modal help screen (`HelpScreen`) displaying keyboard shortcuts and command reference table.
  - Multi-hop mesh relay integration test ($A \to B \to C$) in `tests/integration/test_end_to_end.py`.
  - Comprehensive unit test suites for mesh subsystem (`tests/unit/test_mesh.py`) and TUI components (`tests/unit/test_tui.py`), expanding test suite to 515 passing tests.
- Phase 8: Two-PC End-to-End Functional Prototype (`bitchat.app`, `bitchat.tui`, `bitchat.ble.server`):
  - GATT peripheral server and advertising (`bitchat.ble.server.BLEServer`) with native Windows WinRT support and injectable mock backends for testing.
  - Asynchronous session coordinator (`bitchat.app.session_coordinator.SessionCoordinator`) orchestrating peer discovery, presence announce exchange, deterministic Noise XX handshake progression, encrypted direct messages, and 20ms fragment pacing for large messages (>500B).
  - Terminal User Interface (`bitchat.tui.app.BitChatApp`) built with Textual, featuring live scrollable message log, active peer discovery sidebar, local identity/fingerprint display, and full slash command integration (`/connect`, `/disconnect`, `/scan`, `/online`, `/name`, `/dm`, `/large`, `/clear`, `/help`, `/exit`).
  - Dual runtime mode in `bitchat.__main__`: automatic interactive TUI when running in a TTY, and headless/scripted CLI mode (`--cli` or piped stdin).
  - Identity persistence in `StorageInterface` (`load_identity`, `save_identity`) storing `LocalIdentity` in `~/.bitchat/identity.json` with restricted file permissions (`0o600` on POSIX).
  - Comprehensive End-to-End integration suite (`tests/integration/test_end_to_end.py`) validating full two-node handshake, direct messaging, 1500B fragmentation/reassembly, and reconnection.
  - Automated integration test suite expanded to 491 tests with 100% passing rate.
- Bluetooth Low Energy (BLE) transport layer (`bitchat.ble`):
  - Service and characteristic discovery matching BitChat UUID specification (`F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C` and `A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D`) with case-insensitive matching across platform backends.
  - Asynchronous BLE scanner (`BLEScanner`) filtering for the BitChat service UUID, duplicate address deduplication, and RSSI tracking.
  - Connection lifecycle state machine (`BLEConnection`) with states `DISCONNECTED`, `CONNECTING`, `CONNECTED`, `DISCOVERING_GATT`, `SUBSCRIBING`, `READY`, and `DISCONNECTING`, including unexpected remote disconnect callbacks.
  - GATT discovery manager (`GATTManager`) validating required characteristic properties (`write-without-response`, `notify`).
  - BLE transport (`BLETransport`) handling direct writes (`response=False`), automatic packet fragmentation (>500B) with 20ms inter-fragment pacing matching the reference implementation, decoupled background receive worker, bounded `asyncio.Queue` reception with backpressure protection, and automatic out-of-order fragment reassembly.
  - Central BLE manager (`BLEManager`) coordinating scanner, active multi-peer connections, unicast sending, and broadcast delivery.
  - BLE exception hierarchy (`BLEError`, `BLEScanError`, `BLEConnectionError`, `BLEGATTError`, `BLETransportError`).
  - Hardware-independent mock suite and unit tests (`tests/ble/`) covering scanning, connection transitions, GATT validation, pacing, queue backpressure, malformed packet isolation, and multi-peer dispatch (472 total project tests passing).
- Experimental Nim performance prototype and FFI evaluation (`nim/`):
  - Isolated prototype area implementing byte-level packet encode/decode validation, BitChat random block padding/unpadding, 150-byte chunk slicing, 13-byte fragment header packing, and bounded out-of-order reassembly with sender isolation.
  - Caller-allocated C-ABI FFI boundary (`bitchat_nim.dll` / `.so`) with strict buffer bounds and zero cross-runtime heap allocations.
  - Native unit tests (`test_packet.nim`, `test_fragment.nim`) and comprehensive Python-Nim equivalence test suite (`tests/interoperability/test_nim_equivalence.py`, 445 total project tests passing).
  - Comparative benchmark suite (`bench_native.nim`, `bench_comparison.py`) measuring pure Python, Python+FFI, and native Nim across realistic payloads and fragment topologies.
  - Technical evaluation report and architectural decision documentation (`nim/README.md`) recommending rejection of production Nim integration due to FFI marshalling overhead and Python 3.14's sufficient native performance (400k packets/sec).
- BitChat packet fragmentation and reassembly layer (`bitchat.protocol`):
  - Fragmentation engine (`fragmentation.py`): conditional thresholding at >500 bytes (`FRAGMENTATION_THRESHOLD`), chunk size 150 bytes (`FRAGMENT_CHUNK_SIZE`), 13-byte metadata header encoding (`fragment_id`, `index`, `total`, `original_type`), outer fragment packet generation (`FragmentStart`, `FragmentContinue`, `FragmentEnd`), and strict handling of two-fragment edge case.
  - Reassembly engine (`reassembly.py`): `FragmentReassembler` supporting out-of-order fragment arrivals, per-sender isolation via `(sender_id, fragment_id)` composite keys, LRU active assembly eviction (`MAX_ACTIVE_ASSEMBLIES`), chunk count limits (`MAX_FRAGMENTS_PER_ASSEMBLY`), byte caps (`MAX_REASSEMBLED_BYTES`), duplicate chunk rejection, conflicting metadata validation, and automatic assembly cleanup upon completion.
  - Fragmentation exceptions hierarchy (`FragmentationError`, `InvalidFragmentError`, `FragmentPayloadError`, `FragmentLimitExceededError`).
  - Comprehensive test suite for fragmentation, out-of-order reassembly, resource exhaustion defense, and Rust interoperability (435 total tests passing).
- Cryptographic layer and identity foundation (`bitchat.crypto`):
  - Digital signature module (`ed25519`): raw 32-byte key handling, strict size verification, and signing/verification using `cryptography` hazard-free primitives.
  - Diffie-Hellman key exchange module (`x25519`): shared secret derivation and strict low-order/weak point validation matching the 8 known bad points from the Rust reference.
  - Symmetric encryption (`aes_gcm`): AES-256-GCM authenticated encryption/decryption with OS CSPRNG 96-bit random nonces matching Rust wire format (`nonce || ciphertext+tag`).
  - Key derivation functions (`hkdf`): dual HKDF modules containing `noise_hkdf` (Rust-compatible custom HMAC-SHA256 multi-output chain) and `legacy_hkdf` (standard HKDF-SHA256).
  - Channel key derivation (`pbkdf2`): PBKDF2-HMAC-SHA256 with 100,000 iterations and channel-name salt matching `EncryptionService::derive_channel_key`.
  - Noise protocol (`noise`): complete `Noise_XX_25519_ChaChaPoly_SHA256` implementation including `NoiseCipherState` with 4-byte LE extracted wire nonces, 1024-entry sliding replay window, `NoiseSymmetricState`, and three-stage `NoiseHandshakeState`.
  - Tie-breaking mechanism (`determine_handshake_role`): lexicographic comparison of peer ID hex strings matching `notification_handlers.rs`.
  - Session lifecycle abstraction (`sessions.py`): high-level `NoiseSession` supporting full handshake negotiation, secure state transitions, and transport encryption.
  - Local identity management (`identity.py`): immutable `LocalIdentity` dataclass with safe representation preventing secret exposure in strings or logs.
  - Comprehensive test suite for crypto primitives, invariants, and interoperability vectors (374 total tests passing).
- BitChat binary packet protocol implementation (`bitchat.protocol`):
  - `BitchatPacket` dataclass representing binary packet structures with validation, property flags, and factory method.
  - Wire packet encoder (`encode_packet`, `pad_packet_data`, `get_optimal_block_size`) adhering to big-endian serialization and BitChat random block padding (PKCS#7-style length delimiter).
  - Wire packet decoder (`decode_packet`, `unpad_packet_data`) with defensive bounds checking, version enforcement, and strict padding validation.
  - Protocol constants and full 22-variant `MessageType` IntEnum matching the reference implementation.
  - Protocol exceptions hierarchy (`ProtocolError`, `PacketEncodingError`, `PacketDecodingError`, `UnsupportedProtocolVersionError`, `UnknownMessageTypeError`, `InvalidPacketError`).
  - Comprehensive unit and adversarial test suites with security invariant verification (186 total tests passing).
- Initial repository foundation (Phase 0).
- Application core controller, command parser, peer model, and storage interface (Phase 2).

### Changed
- Hardened `BitchatPacket` immutability by normalizing all binary fields (`sender_id`, `recipient_id`, `payload`, `signature`) to immutable `bytes` on construction, preventing in-place mutations from external `bytearray` sources.
- Hardened integer field validations in `BitchatPacket` to explicitly reject `bool` values.
- Updated block padding terminology throughout documentation and docstrings to "BitChat random block padding (PKCS#7-style length delimiter)".
- Documented intentional defensive parsing difference in Python decoder (strict padding-length consistency verification vs. reference parser's permissive stripping).
- Clarified signature field documentation: wire placement is implemented, while signing semantics are verified in the cryptographic interoperability phase.
