# Download BitChat for Windows (x64)

<p align="center">
  <img src="download/assets/bitchat-wordmark-dark.png" alt="BitChat" width="280" />
</p>

## Official Windows Release Package

| Field | Value |
|---|---|
| **Application** | BitChat (`Java-Mx.BitChat`) |
| **Version** | `0.3.2` |
| **Publisher** | `Java-Mx` |
| **Platform / Architecture** | Windows 10 (1809+) & Windows 11 (`x64`) |
| **Installer Filename** | `BitChat-0.3.2-windows-x64.exe` |
| **Installer File Size** | 17.62 MB (18,479,490 bytes) |
| **Release Date** | `2026-11-19` |
| **SHA-256 Checksum** | `61FB2A5E882CF6CF8D59AA6916C174CBD12C5C4DA4077A98880FC860908410B4` |
| **Digital Signature Status** | NotSigned — No commercial code-signing certificate configured yet. Do not treat as a Microsoft-verified publisher until a real certificate signature is verified. Always verify the SHA-256 checksum below. |
| **Official Download URL** | [https://github.com/Java-Mx/bitchat-rustpy/releases/download/v0.3.2/BitChat-0.3.2-windows-x64.exe](https://github.com/Java-Mx/bitchat-rustpy/releases/download/v0.3.2/BitChat-0.3.2-windows-x64.exe) |
| **All Releases** | [GitHub Releases](https://github.com/Java-Mx/bitchat-rustpy/releases) |

---

## Legal Notices & Pre-Download Review

Before downloading or installing BitChat, please review:

1. **[BitChat Terms of Use](../TERMS_OF_USE.md)** *(Draft — pending publisher/legal review)*
2. **[BitChat Privacy Policy](../PRIVACY_POLICY.md)** *(Draft — audited zero-telemetry, no accounts, local-only identity keys)*
3. **[MIT License](../LICENSE)** and **[Security Policy](../SECURITY.md)**

> **Privacy Commitment:** No personal information, email address, account creation, tracking, or marketing consent is required to download or use BitChat. Acknowledging the Privacy Policy during download or installation is informational only and never authorizes optional data collection.

---

## System Requirements

- **Operating System:** Windows 10 version 1809 (build 17763) or later, or Windows 11 (x64).
- **Hardware / Network:** Bluetooth 4.0+ Low Energy (BLE) adapter with Windows WinRT support, and/or Wi-Fi or Ethernet Local Area Network (LAN).
- **Disk Space:** At least 80 MB of free disk space.
- **Permissions:** Standard user account (installs to `%LOCALAPPDATA%\Programs\BitChat` by default; no Administrator privileges required).
- **Dependencies:** None (Python 3 runtime, Rust `bitchat._bitchat_core` native extension, Textual TUI, Bleak WinRT stack, and Cryptography are fully bundled).

---

## All Official `v0.3.2` Release Assets & SHA-256 Checksums

All official release artifacts are available on the [Official GitHub Release (`v0.3.2`)](https://github.com/Java-Mx/bitchat-rustpy/releases/tag/v0.3.2):

| Platform / Format | Asset Filename | SHA-256 Checksum |
|---|---|---|
| **Windows x64 Installer** | `BitChat-0.3.2-windows-x64.exe` | `61FB2A5E882CF6CF8D59AA6916C174CBD12C5C4DA4077A98880FC860908410B4` |
| **Linux Debian/Ubuntu (`amd64`)** | `bitchat_0.3.2_amd64.deb` | `85BFDB6BCDBB54B8C054D7ED580C4F4736D1205173550794D6BE88C314CEE329` |
| **Linux AppImage (`x86_64`)** | `BitChat-0.3.2-x86_64.AppImage` | `E561B1095C9058E5BBD08A797D1E7CC226D5A3ADB0B9C54ABA1EAF1AE3CC8EEA` |
| **Windows Wheel (`cp312-abi3`)** | `bitchat-0.3.2-cp312-abi3-win_amd64.whl` | `8F4D207F30896C6E3C123D58B96124DB33AFE566C0B428634337B7BE311CD910` |
| **Linux Wheel (`cp312-abi3`)** | `bitchat-0.3.2-cp312-abi3-linux_x86_64.whl` | `D1B723D02791686635F7609090E42C706F25D6E14BE5276F1638A6ECECEBFD4B` |
| **Source Archive (`sdist`)** | `bitchat-0.3.2.tar.gz` | `8DAB5F6C34ACD8FCDB1341A42A1E1945871EDC729604966DABCE5E114F42B53D` |

---

## Checksum & Signature Verification

After downloading `BitChat-0.3.2-windows-x64.exe`, verify its integrity in PowerShell before running Setup:

```powershell
# 1. Verify SHA-256 Checksum
Get-FileHash .\BitChat-0.3.2-windows-x64.exe -Algorithm SHA256
# Expected: 61FB2A5E882CF6CF8D59AA6916C174CBD12C5C4DA4077A98880FC860908410B4

# 2. Inspect Authenticode Signature
Get-AuthenticodeSignature .\BitChat-0.3.2-windows-x64.exe | Format-List *
```

---

## Installation, Startup, Upgrade & Uninstallation

### Interactive Setup Wizard
Run `BitChat-0.3.2-windows-x64.exe` to step through the 7-screen setup wizard:
1. **Welcome** — BitChat branding, version `0.3.2`, and publisher (`Java-Mx`).
2. **Terms of Use** — Scrollable Terms of Use with required acceptance checkbox.
3. **Privacy Policy** — Scrollable Privacy Policy with required acknowledgment checkbox.
4. **Installation Location** — Defaults to `%LOCALAPPDATA%\Programs\BitChat` with permission, disk-space, and conflict validation.
5. **Installation Options** — Configure Desktop shortcut (enabled), Start Menu shortcut (enabled), user `PATH` integration (enabled), Launch after installation (enabled), Start with Windows after sign-in (disabled by default), and Windows Installed Apps uninstaller entry (enabled).
6. **Installation Progress** — Real-time extraction progress and automatic rollback on interruption.
7. **Completion** — Summary of installed version, path, `PATH` status, startup configuration, and immediate launch option.

### Command-Line & WinGet Usage
```powershell
# Launch interactive TUI
bitchat --tui

# Launch headless CLI mode
bitchat --cli

# Inspect version, help, and hardware diagnostics
bitchat --version
bitchat --help
bitchat --configure

# Check or toggle per-user Windows sign-in startup
bitchat --startup status
bitchat --startup enable
bitchat --startup disable

# Preview or run uninstallation (see docs/UNINSTALLATION.md)
bitchat --uninstall --dry-run
bitchat --uninstall
bitchat --uninstall --remove-user-data --yes
```

### Troubleshooting
- **`bitchat` command not recognized:** Reopen your PowerShell or Command Prompt window after installation so the updated user `PATH` environment variable is loaded.
- **Uninstalling completely:** See [`docs/UNINSTALLATION.md`](UNINSTALLATION.md) for normal vs. complete removal (`--remove-user-data`).
- **Windows Defender SmartScreen:** See [`docs/platform/WINDOWS.md`](platform/WINDOWS.md) for the distinction between Authenticode signature validity, publisher identity, and SmartScreen download reputation. Never disable Windows Defender or SmartScreen; always verify the SHA-256 checksum above.
