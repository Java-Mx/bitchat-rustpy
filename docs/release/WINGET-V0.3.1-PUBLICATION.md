# BitChat RustPy v0.3.1 — Microsoft WinGet Publication Report

**Document Type:** Release & Package Management Engineering Report  
**Official Repository:** `https://github.com/Java-Mx/bitchat-rustpy`  
**Official Release Tag:** [`v0.3.1`](https://github.com/Java-Mx/bitchat-rustpy/releases/tag/v0.3.1)  
**Microsoft WinGet Package Identifier:** `Java-Mx.BitChat`  
**Previous Published WinGet Version:** `0.1.0` ([PR #443445](https://github.com/microsoft/winget-pkgs/pull/443445))  
**Target WinGet Version:** `0.3.1` ([PR #481727](https://github.com/microsoft/winget-pkgs/pull/481727))  
**Report Date:** November 16, 2026  

---

## 1. Verification of the Official v0.3.1 Release

The `v0.3.1` release (`BitChat v0.3.1 — Phase 1: Rust Core Acceleration, Performance Overhaul & Complete Uninstaller`) was published on November 9, 2026 (`2026-11-09T11:05:41Z`) in the canonical repository `https://github.com/Java-Mx/bitchat-rustpy`.

### 1.1 Authoritative Installer Asset & Checksum Verification

| Property | Value |
| :--- | :--- |
| **Asset Filename** | `BitChat-0.3.1-windows-x64.exe` |
| **Download URL** | `https://github.com/Java-Mx/bitchat-rustpy/releases/download/v0.3.1/BitChat-0.3.1-windows-x64.exe` |
| **File Size** | `18,165,765` bytes |
| **GitHub API Asset Digest** | `sha256:2a2d68f5b7b975620af7197030a6dd068c8a0d096aeeecfc69f5dbb3fa84a75a` |
| **Published `.sha256` File** | `2A2D68F5B7B975620AF7197030A6DD068C8A0D096AEEECFC69F5DBB3FA84A75A *BitChat-0.3.1-windows-x64.exe` |
| **Independent `Get-FileHash` (SHA256)** | `2A2D68F5B7B975620AF7197030A6DD068C8A0D096AEEECFC69F5DBB3FA84A75A` (64 hex chars, verified) |

> **Checksum Audit Note:** A truncated 62-character string (`...AEEEC69F5...`, missing the `FC` byte at offset 23) was identified in the task brief and corrected to the verified 64-character SHA-256 digest `2A2D68F5B7B975620AF7197030A6DD068C8A0D096AEEECFC69F5DBB3FA84A75A`.

### 1.2 Inspection of the Existing v0.3.1 Release Manifest Asset

The `Java-Mx.BitChat.yaml` file uploaded as a release asset on `v0.3.1` was inspected:
- It used `ManifestType: singleton` and `ManifestVersion: 1.6.0`.
- Microsoft's `winget-pkgs` repository requires the **multi-file manifest structure** (`version`, `installer`, and `defaultLocale` manifests) and schema version **`1.28.0`** (schema `1.6.0` is deprecated by `winget-pkgs` policy).
- Accordingly, a compliant 3-file `1.28.0` manifest directory (`manifests/j/Java-Mx/BitChat/0.3.1/`) was generated and validated.

---

## 2. Existing WinGet Package Status (`0.1.0`)

- **Package Identifier:** `Java-Mx.BitChat`
- **Published Version:** `0.1.0`
- **Merged PR:** [`microsoft/winget-pkgs#443445`](https://github.com/microsoft/winget-pkgs/pull/443445) (merged `2026-11-16T15:46:40Z`, commit `bcdec30c5583d01408f5cfb3c9e950e913a6bad5`)
- **Catalogue Status:** Active and live in the `winget` community source (`https://cdn.winget.microsoft.com/cache`).

---

## 3. Product Branding, Package Identifier & Moniker Decisions

### 3.1 Preserving `PackageIdentifier: Java-Mx.BitChat`
- Changing `PackageIdentifier` in WinGet creates an entirely separate catalogue entry, breaking `winget upgrade` for existing `0.1.0` users and requiring deprecation of the prior package.
- Retaining `PackageIdentifier: Java-Mx.BitChat` ensures seamless upgrade continuity (`0.1.0` → `0.3.1`).

### 3.2 Updating Product Branding & Moniker
- **`PackageName`:** Updated to `BitChat RustPy` in `Java-Mx.BitChat.locale.en-US.yaml`.
- **`Moniker`:** Set to `bitchat-rustpy`.
- **`Tags`:** Includes `bitchat`, `bitchat-rustpy`, `bitchat-rustpyl`, `ble`, `bluetooth`, `chat`, `lan`, `mesh`, `p2p`, `python`, `rust`, `terminal`, and `tui`.
- **How WinGet Resolves Queries:**
  - By default, `winget install <query>` matches case-insensitively against `PackageIdentifier`, `PackageName`, and `Moniker`.
  - Setting `Moniker: bitchat-rustpy` enables:
    ```powershell
    winget install bitchat-rustpy
    ```
  - Including `bitchat-rustpyl` in `Tags` also ensures that `winget search bitchat-rustpyl --source winget` resolves to `Java-Mx.BitChat` even if a trailing `l` is typed.

### 3.3 Privacy URL Policy
- In accordance with legal/publisher review requirements, `PRIVACY_POLICY.md` remains in draft status and `PrivacyUrl` has intentionally been omitted from the `0.3.1` manifest until final sign-off.

---

## 4. WinGet v0.3.1 Manifest Files (`manifests/j/Java-Mx/BitChat/0.3.1/`)

### 4.1 `Java-Mx.BitChat.yaml` (Version Manifest)
```yaml
# Created using wingetcreate 1.12.13.0
# yaml-language-server: $schema=https://aka.ms/winget-manifest.version.1.28.0.schema.json

PackageIdentifier: Java-Mx.BitChat
PackageVersion: 0.3.1
DefaultLocale: en-US
ManifestType: version
ManifestVersion: 1.28.0
```

### 4.2 `Java-Mx.BitChat.installer.yaml` (Installer Manifest)
```yaml
# Created using wingetcreate 1.12.13.0
# yaml-language-server: $schema=https://aka.ms/winget-manifest.installer.1.28.0.schema.json

PackageIdentifier: Java-Mx.BitChat
PackageVersion: 0.3.1
InstallerLocale: en-US
InstallerType: inno
Scope: user
InstallModes:
- interactive
- silent
- silentWithProgress
UpgradeBehavior: install
Commands:
- bitchat
Installers:
- Architecture: x64
  InstallerUrl: https://github.com/Java-Mx/bitchat-rustpy/releases/download/v0.3.1/BitChat-0.3.1-windows-x64.exe
  InstallerSha256: 2A2D68F5B7B975620AF7197030A6DD068C8A0D096AEEECFC69F5DBB3FA84A75A
ManifestType: installer
ManifestVersion: 1.28.0
ReleaseDate: 2026-11-09
```

### 4.3 `Java-Mx.BitChat.locale.en-US.yaml` (Default Locale Manifest)
```yaml
# Created using wingetcreate 1.12.13.0
# yaml-language-server: $schema=https://aka.ms/winget-manifest.defaultLocale.1.28.0.schema.json

PackageIdentifier: Java-Mx.BitChat
PackageVersion: 0.3.1
PackageLocale: en-US
Publisher: Java-Mx
PublisherUrl: https://github.com/Java-Mx
PublisherSupportUrl: https://github.com/Java-Mx/bitchat-rustpy/issues
PackageName: BitChat RustPy
PackageUrl: https://github.com/Java-Mx/bitchat-rustpy
License: MIT
LicenseUrl: https://github.com/Java-Mx/bitchat-rustpy/blob/main/LICENSE
Copyright: Copyright (c) BitChat Contributors
ShortDescription: Decentralized encrypted peer-to-peer mesh terminal chat client built with Python and Rust
Description: |-
  BitChat RustPy is a decentralized, end-to-end encrypted peer-to-peer mesh chat application for the terminal operating over Bluetooth Low Energy (BLE) and local area networks (LAN).
  Built with Python and a native Rust core (_bitchat_core), it features authenticated Noise XX sessions, multi-hop mesh routing, and an interactive Textual terminal user interface with no servers or accounts required.
Moniker: bitchat-rustpy
Tags:
- bitchat
- bitchat-rustpy
- bitchat-rustpyl
- ble
- bluetooth
- chat
- lan
- mesh
- p2p
- python
- rust
- terminal
- tui
ReleaseNotes: |-
  - Phase 1 Rust Core Acceleration (_bitchat_core PyO3/Maturin native extension) for binary packet encoding/decoding, fragmentation, TCP framing, and mesh deduplication
  - TUI Performance Overhaul: in-place PeerSidebar diffing, coalesced status refreshes, and batched chat message rendering
  - Complete cross-platform uninstaller (--uninstall) with PATH protection and stale launcher cleanup
ReleaseNotesUrl: https://github.com/Java-Mx/bitchat-rustpy/releases/tag/v0.3.1
ManifestType: defaultLocale
ManifestVersion: 1.28.0
```

---

## 5. Local Validation Output

Validated on Windows 11 with WinGet `v1.29.380`:

```powershell
PS D:\bitchat-python> winget validate --manifest D:\bitchat-python\manifests\j\Java-Mx\BitChat\0.3.1
Manifest validation succeeded.
```

Automated packaging test suite (`tests/unit/test_packaging_windows.py`):
```text
tests/unit/test_packaging_windows.py::test_generate_winget_manifests PASSED
tests/unit/test_packaging_windows.py::test_winget_manifest_validation PASSED
tests/unit/test_packaging_windows.py::test_committed_manifests_consistency PASSED
12 passed in 9.49s
```

---

## 6. Upgrade Compatibility Verification (`0.1.0` → `0.3.1`)

An end-to-end upgrade test was executed on Windows starting from an installed `0.1.0` WinGet instance:

1. **Initial Installation (`0.1.0`):**
   - Installed via `winget install --id Java-Mx.BitChat --exact --version 0.1.0 --silent`
   - `winget list Java-Mx.BitChat` reported `BitChat 0.1.0 | Java-Mx.BitChat | 0.1.0 | winget`
   - `bitchat.exe --version` reported `bitchat 0.1.0`
   - Pre-upgrade user data hashes recorded:
     - `~/.bitchat/identity.json`: `28400CF8A39B64164E039C9518D78878A76F4BCFDD1A550BED344C99DE7B72B3`
     - `~/.bitchat/config.json`: `E6B7B94216B93967D9C6A416019A901C0F0FC4458E9A871D5C14E30D05E23E04`

2. **In-Place Upgrade Execution (`0.3.1`):**
   - Executed `BitChat-0.3.1-windows-x64.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART`
   - Because both versions share Inno Setup `AppId` `{B17CHA70-B1EC-4E87-99B7-4DA78D0B7001}`, the installer upgraded the existing installation at `%LOCALAPPDATA%\Programs\BitChat\` in-place and cleaned stale `_internal` runtime artifacts without touching user data.

3. **Post-Upgrade Verification:**
   - `winget list Java-Mx.BitChat` output:
     ```text
     Name          Id              Version Source
     ---------------------------------------------
     BitChat 0.3.1 Java-Mx.BitChat 0.3.1   winget
     ```
     (Single entry correlated to `Java-Mx.BitChat` on `winget` source; no duplicate ARP entries.)
   - `bitchat.exe --version` output: `bitchat 0.3.1`
   - Post-upgrade user data hashes:
     - `~/.bitchat/identity.json`: `28400CF8A39B64164E039C9518D78878A76F4BCFDD1A550BED344C99DE7B72B3` (**100% preserved**)
     - `~/.bitchat/config.json`: `E6B7B94216B93967D9C6A416019A901C0F0FC4458E9A871D5C14E30D05E23E04` (**100% preserved**)
   - User `PATH` registration at `%LOCALAPPDATA%\Programs\BitChat` remained intact without duplication.

---

## 7. Microsoft `winget-pkgs` Pull Request Status

- **Pull Request URL:** [`https://github.com/microsoft/winget-pkgs/pull/481727`](https://github.com/microsoft/winget-pkgs/pull/481727)
- **PR Number:** `#481727`
- **PR Title:** `New version: Java-Mx.BitChat version 0.3.1`
- **Source Branch:** `Java-Mx:Java-Mx.BitChat-0.3.1` (commit `eea2d49f62725bc2148fc519ff1c4041398b75b6`)
- **Target Branch:** `microsoft:master`
- **Automated Check Results (Verified):**
  - `license/cla`: **SUCCESS**
  - `01. Pull Request Validation`: **SUCCESS**
  - `02. Manifest Validation`: **SUCCESS**
  - `03. URLs Validation`: **SUCCESS**
  - `04. URL Domain Validation`: **SUCCESS**
  - `05. Manifest Policy Validation`: **SUCCESS**
  - `06. Catalog Content Verification`: **SUCCESS**
  - `07. Installers Scan` / `08. Installation Validation`: **Running in Microsoft Azure Pipeline**

> **Current Publication State:**  
> - **PR Submitted & Validated:** Confirmed (`microsoft/winget-pkgs#481727`).  
> - **Microsoft Merge & CDN Catalogue Publication:** Pending Microsoft moderator approval and post-merge Azure DevOps Publish Pipeline execution (~60–90 minutes after merge).

---

## 8. Final Verification & Installation Commands

Once [`microsoft/winget-pkgs#481727`](https://github.com/microsoft/winget-pkgs/pull/481727) is merged and `wingetbot` confirms that the Publish Pipeline has completed, run the following commands on Windows:

```powershell
# 1. Refresh the local WinGet catalogue index
winget source update

# 2. Search and inspect via moniker / tag
winget search bitchat-rustpy --source winget
winget show bitchat-rustpy --source winget

# 3. Fresh installation using moniker
winget install bitchat-rustpy --source winget

# 4. Or upgrade an existing 0.1.0 installation in-place
winget upgrade --id Java-Mx.BitChat --exact

# 5. Verify installed version
winget list BitChat
bitchat --version
```
