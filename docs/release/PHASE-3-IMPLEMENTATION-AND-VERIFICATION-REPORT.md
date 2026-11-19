# BitChat RustPy — Phase 3 (`v0.3.4`) Implementation & Verification Report

**Release Version:** `v0.3.4`  
**Milestone:** Phase 3 — Native Rust BLE Transport, Noise XX over BLE, Reference `bitchat-tui` Interoperability, Live Bluetooth Diagnostics & Mouse Navigation Stability  
**Repository:** https://github.com/Java-Mx/bitchat-rustpy  
**Branch:** `main`  
**Reference Implementation Audited:** `vaibhav-mattoo/bitchat-tui` at commit `107a13c570cfb2f1c5cdb9a49c8945e57d794023` (`receiving noise protocol messages finally!!!!!!!!!!!!`)

---

## 1. Executive Summary

Phase 3 (`v0.3.4`) advances BitChat RustPy from BLE helper stubs into a genuine, modular **native Rust BLE transport architecture** (`rust/bitchat-core/src/ble/`) across desktop operating systems, fixes Windows GATT/companion advertisement coupling, closes the `bitchat-tui` encrypted binary DM payload gap, replaces placeholder/wrong Bluetooth Settings fields with live asynchronous hardware & transport telemetry, and eliminates mouse-click navigation jitter across the Textual TUI.

Both the application Home Screen (`src/bitchat/tui/screens/home.py`) and the official website homepage (`website/index.html`) were strictly preserved with zero modifications.

---

## 2. Reference `bitchat-tui` Differential Audit (`107a13c570cfb2f1c5cdb9a49c8945e57d794023`)

| Protocol Dimension | Reference `bitchat-tui` | BitChat RustPy (`v0.3.4`) | Status |
| :--- | :--- | :--- | :--- |
| Protocol Name | `Noise_XX_25519_ChaChaPoly_SHA256` | `Noise_XX_25519_ChaChaPoly_SHA256` | **MATCH** |
| Handshake Prologue | Empty (`mix_hash(&[])`) | Empty (`mix_hash(&[])`) | **MATCH** |
| Wire Message Sizes | M1 = `32B`, M2 = `96B`, M3 = `64B` | M1 = `32B`, M2 = `96B`, M3 = `64B` | **MATCH** |
| Message Type Codes | `0x10` (M1), `0x11` (M2 & M3), `0x12` (Encrypted), `0x13` (Identity Announce) | Identical | **MATCH** |
| Transport Cipher Split | Initiator `(send=c1, recv=c2)`, Responder `(send=c2, recv=c1)` | Identical | **MATCH** |
| Wire Nonce Format | 4-byte LE `u32` prefix; 12-byte ChaCha nonce `[0,0,0,0] \|\| u64_le` | Identical | **MATCH** |
| Encrypted DM Inner Payload | `[0x04] \|\| binary BitchatMessage` (send) & nested `BitchatPacket(Message)` (receive) | Decoded natively in Rust `decode_chat_payload_raw` (supports raw UTF-8, `[0x04]+UTF-8`, `[0x04]+BitchatMessage`, bare `BitchatMessage`, and nested `BitchatPacket`) | **FIXED & VERIFIED** |
| Nonce-0 Replay Protection | `if n > 0` replay bypass (anti-pattern) | Strictly rejects nonce-0 replay in Rust `NativeNoiseCipherState` | **HARDENED (Fail-Closed)** |
| Secret Redaction | Writes raw keys/packets to `noise_debug.log` (anti-pattern) | Zero secrets/keys/plaintext ever logged; `ZeroizeOnDrop` scrubbing | **HARDENED** |
| Handshake Read Error Handling | Swallows payload decrypt error (`noise_protocol.rs:1194`) | Fails closed with `AuthenticationError` and clears session state | **HARDENED** |

---

## 3. Native Rust BLE Transport Architecture (`rust/bitchat-core/src/ble/`)

Replaced single-file helper stub `rust/bitchat-core/src/ble.rs` with modular Rust ownership:

- `rust/bitchat-core/src/ble/types.rs` — Canonical BitChat UUID constants (`F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C`, `A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D`), telemetry snapshots, bounded channel capacities, and secret-redacted diagnostic trace records.
- `rust/bitchat-core/src/ble/advertisement.rs` — Manufacturer payload codec (`b"BC" || service_uuid(16) [|| peer_id(8)]`), strict 8-byte non-zero/non-broadcast service-data peer-ID extraction (`extract_ble_service_data_peer_id`), strict advertisement filtering, hyphen/case-insensitive UUID normalization, and GATT characteristic property validation (`validate_ble_gatt_characteristic_raw`).
- `rust/bitchat-core/src/ble/connection.rs` — `NativeBleConnectionEngine` with bounded early-notification buffering (`subscribing`/`discovering` -> `mark_ready_and_drain`), bounded outbound write queue, ATT MTU chunking (`compute_ble_write_chunk_size`), reconnect tracking, and `BlePeerRegistry`.
- `rust/bitchat-core/src/ble/windows_winrt.rs` (`#[cfg(target_os = "windows")]`) — Native Rust WinRT BLE via `windows = "0.58"` (`BluetoothAdapter`, `Radio`, `BluetoothLEAdvertisementWatcher`, `BluetoothLEDevice`, `GattSession`, `GattServiceProvider`, `GattLocalCharacteristic`, and decoupled optional `BluetoothLEAdvertisementPublisher` with asynchronous status settlement polling).
- `rust/bitchat-core/src/ble/linux_bluez.rs` (`#[cfg(target_os = "linux")]`) — Pure-Rust BlueZ D-Bus backend via `zbus = "5"` (`Adapter1`, `Device1`, `GattManager1`, `LEAdvertisingManager1`, exported `ObjectManager`, `GattService1`, `GattCharacteristic1`, `LEAdvertisement1`, and decoupled manufacturer-data fallback).
- `rust/bitchat-core/src/ble/macos_corebt.rs` (`#[cfg(target_os = "macos")]`) — Truthful macOS Bluetooth hardware/radio probe honestly declaring CoreBluetooth Peripheral mode as unsupported.
- `rust/bitchat-core/src/ble/manager.rs` — `NativeBleTransportManager` & `probe_native_ble_adapter_raw` executing all OS BLE operations off the Python GIL (`py.allow_threads`).

---

## 4. Real Hardware Verification & Honest Interoperability Matrix

### Local Windows Hardware Probe (Executed Live on Host)
- **Host Hardware:** `Intel(R) Wireless Bluetooth(R)` (`USB\VID_8087&PID_0033`, MAC `74:13:EA:F6:32:7B`, Radio State `On`, MaxAdvLen `160B`)
- **Native Rust WinRT Adapter Probe (`probe_native_ble_adapter_raw`):** **PASS** — Detected adapter, real MAC address, radio `On`, BLE/Central/Peripheral/Offload flags with zero Python WinRT dependencies.
- **Native Rust WinRT Central Scanner (`BluetoothLEAdvertisementWatcher`):** **PASS** — Started in Active mode, ran 1.5s live scan, drained event queue, and stopped cleanly.
- **Windows Companion Manufacturer Advertisement (`BluetoothLEAdvertisementPublisher`):** **PASS** — Reached status `2` (`Started`) broadcasting `0xFFFF` BitChat manufacturer beacon.
- **Windows Unpackaged Win32 `GattServiceProvider` Advertising:** **BLOCKED BY OS/DRIVER (`status 3 / Aborted`)** — `GattServiceProvider.CreateAsync` and `CreateCharacteristicAsync` succeed (`error = 0`), while `StartAdvertisingWithParameters` returns Windows `Aborted (3)` on unpackaged Win32 with the Intel driver. BitChat truthfully reports `Aborted (3)` and continues in Central + companion discovery mode without crashing or misrepresenting GATT status.

### Cross-Device Physical Radio Interoperability Status
| Test Pair | Verification Status | Notes |
| :--- | :--- | :--- |
| Local Windows Host Hardware Probe & Central Scan | **PASS** | Verified live on `Intel(R) Wireless Bluetooth(R)` (`74:13:EA:F6:32:7B`) |
| Simulated End-to-End BLE + Noise XX + `bitchat-tui` Binary DM | **PASS** | Verified in `tests/interoperability/test_phase3_ble_noise_interop.py` & `test_tui_interop.py` |
| Physical Windows ↔ Fedora KDE over BLE | **UNTESTED** | Secondary physical Linux BLE device not attached to build host |
| Physical Windows ↔ Android / `bitchat-tui` over BLE | **UNTESTED** | Secondary physical Android/TUI BLE device not attached to build host |
| Physical Fedora KDE ↔ `bitchat-tui` over BLE | **UNTESTED** | Secondary physical Linux BLE device not attached to build host |

---

## 5. Bluetooth Settings Diagnostics & Mouse Navigation Stability

1. **Bluetooth Settings Tab (`src/bitchat/tui/screens/settings.py`):**
   - Removed wrong hardcoded UUID (`0000fee0-0000-1000-8000-00805f9b34fb`) and false hardcoded `"Active / Scanning"` Central status.
   - Displays live canonical `BITCHAT_SERVICE_UUID` (`F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C`) and `BITCHAT_CHARACTERISTIC_UUID` (`A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D`), backend driver, hardware adapter name/MAC/device ID, radio power & capabilities, Central/Peripheral statuses, independent GATT server & discovery advertisement statuses, peer counts, negotiated ATT MTU, last error/diagnostic detail, refresh timestamp, and explicit `"Refresh Bluetooth Information"` button backed by bounded async worker refresh with cancellation on unmount/category switch.
2. **Mouse Navigation Jitter Elimination (`status_bar.py`, `app.py`, `screens/*.py`):**
   - Fixed root cause in `StatusBar.on_button_pressed` where a single mouse click fired every action **3 times** (`ActionTriggered` + direct `app.action_*` call + bubbled `Button.Pressed` to `BitChatApp`).
   - Added `event.stop()` across all screen `on_button_pressed` handlers, batched multi-layer screen pops inside `with self.batch_update():`, and deduplicated `PeersScreen.refresh_peer_list()` table rows to stop periodic 2-second DataTable rebuild flicker.
3. **Homepage Preservation:**
   - Verified via `git diff` that `src/bitchat/tui/screens/home.py` and `website/index.html` have **zero modifications**.
