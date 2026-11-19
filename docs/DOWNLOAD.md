# Download BitChat for Windows (x64)

<p align="center">
  <img src="download/assets/bitchat-wordmark-dark.png" alt="BitChat" width="280" />
</p>

## Official Windows Release Package

| Field | Value |
|---|---|
| **Application** | BitChat (`Java-Mx.BitChat`) |
| **Version** | `0.3.3` |
| **Publisher** | `Java-Mx` |
| **Platform / Architecture** | Windows 10 (1809+) & Windows 11 (`x64`) |
| **Installer Filename** | `BitChat-0.3.3-windows-x64.exe` |
| **Installer File Size** | 17.76 MB (18,618,754 bytes) |
| **Release Date** | `2026-11-19` |
| **SHA-256 Checksum** | `BB0609FCE1B3A68A1EA358024FE501093D330CC092D1BD562EAC5FF124ECCEEC` |
| **Digital Signature Status** | NotSigned — No commercial code-signing certificate configured yet. Do not treat as a Microsoft-verified publisher until a real certificate signature is verified. Always verify the SHA-256 checksum below. |
| **Official Download URL** | [https://github.com/Java-Mx/bitchat-rustpy/releases/download/v0.3.3/BitChat-0.3.3-windows-x64.exe](https://github.com/Java-Mx/bitchat-rustpy/releases/download/v0.3.3/BitChat-0.3.3-windows-x64.exe) |
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

## All Official `v0.3.3` Release Assets & SHA-256 Checksums

All official release artifacts are available on the [Official GitHub Release (`v0.3.3`)](https://github.com/Java-Mx/bitchat-rustpy/releases/tag/v0.3.3):

| Platform / Format | Asset Filename | Size | SHA-256 Checksum |
|---|---|---|---|
| **Windows x64 Installer** | `BitChat-0.3.3-windows-x64.exe` | `17.76 MB` | `BB0609FCE1B3A68A1EA358024FE501093D330CC092D1BD562EAC5FF124ECCEEC` |
| **Linux Debian/Ubuntu (`amd64`)** | `bitchat_0.3.3_amd64.deb` | `18.30 MB` | `6916C412824EC2A93343FEE39F8975C72613C41BE3D4B6BD453DF77B0A4592A6` |
| **Linux AppImage (`x86_64`)** | `BitChat-0.3.3-x86_64.AppImage` | `20.75 MB` | `C96FB175C97DBC9C32FA160C8A97AA0E72572DBFF01728B7C48F70F82FD20156` |
| **Windows Wheel (`cp312-abi3`)** | `bitchat-0.3.3-cp312-abi3-win_amd64.whl` | `987.61 KB` | `3FA7A9608FDEF55005200264877CF7CEB3B3E24F6D8367B61DF8BA6D7CF8B48F` |
| **Linux Wheel (`cp312-abi3`)** | `bitchat-0.3.3-cp312-abi3-linux_x86_64.whl` | `1012.43 KB` | `4F2136A5070E0173A3C52E5AC21F56E3EB33D536B75CBC09673CFAF9A8A21BDF` |
| **macOS Apple Silicon Wheel (`cp312-abi3`)** | `bitchat-0.3.3-cp312-abi3-macosx_11_0_arm64.whl` | `929.78 KB` | `6259AF88170F981D5D6C1F3395E976B24DF6FB85BC71628251A0BF173B4CBEE4` |
| **Source Archive (`sdist`)** | `bitchat-0.3.3.tar.gz` | `317.01 KB` | `8B96CAFB08564C20ED76C66F8FB2EF97DA00BC99005055105602706ED55F50D6` |
| **WinGet Manifest** | `Java-Mx.BitChat.yaml` | `1.63 KB` | `C440175BC3612E687A0FFBD1FEE4F6E14BE7C63AF79CC7EFADE285D136C235C4` |

---

## Checksum & Signature Verification

After downloading `BitChat-0.3.3-windows-x64.exe`, verify its integrity in PowerShell before running Setup:

```powershell
# 1. Verify SHA-256 Checksum
Get-FileHash .\BitChat-0.3.3-windows-x64.exe -Algorithm SHA256
# Expected: BB0609FCE1B3A68A1EA358024FE501093D330CC092D1BD562EAC5FF124ECCEEC

# 2. Inspect Authenticode Signature
Get-AuthenticodeSignature .\BitChat-0.3.3-windows-x64.exe | Format-List *
```

---

## Installation, Startup, Upgrade & Uninstallation

### Interactive Setup Wizard
Run `BitChat-0.3.3-windows-x64.exe` to step through the 7-screen setup wizard:
1. **Welcome** — BitChat branding, version `0.3.3`, and publisher (`Java-Mx`).
2. **Terms of Use** — Scrollable Terms of Use with required acceptance checkbox.
3. **Privacy Policy** — Scrollable Privacy Policy with required acknowledgment checkbox.
4. **Installation Location** — Defaults to `%LOCALAPPDATA%\Programs\BitChat` with permission, disk-space, and conflict validation.
5. **Installation Options** — Configure Desktop shortcut (enabled), Start Menu shortcut (enabled), user `PATH` integration (enabled), Launch after installation (enabled), Start with Windows after sign-in (disabled by default), and Windows Installed Apps uninstaller entry (enabled).
6. **Installation Progress** — Real-time extraction progress and automatic rollback on interruption.
7. **Completion** — Summary of installed version, path, `PATH` status, startup configuration, and immediate launch option.

### Command-Line & WinGet Usage

> **WinGet Status (`Java-Mx.BitChat` / moniker `bitchat-rustpy`):** The `v0.3.3` manifest update has been submitted upstream in [microsoft/winget-pkgs#483934](https://github.com/microsoft/winget-pkgs/pull/483934) (preserving Inno Setup AppId `{B17CHA70-B1EC-4E87-99B7-4DA78D0B7001}` for in-place `0.3.1 → 0.3.3` upgrades) and is **pending Microsoft validation & merge**. Until `#483934` merges and propagates, `winget` serves `0.3.1` or you can install `v0.3.3` directly from the `.exe` installer above.

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
