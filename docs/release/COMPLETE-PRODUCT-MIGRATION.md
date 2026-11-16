# BitChat RustPy — Complete Product Rebrand, Website Modernization & Distribution Migration Report

**Document Status:** Final Engineering & Release Report  
**Product Name:** BitChat RustPy  
**Official Repository:** `https://github.com/Java-Mx/bitchat-rustpy`  
**Official Website:** `https://java-mx.github.io/bitchat-rustpy/`  
**Current Confirmed Release:** [`v0.3.1`](https://github.com/Java-Mx/bitchat-rustpy/releases/tag/v0.3.1)  
**WinGet Package Identifier:** `Java-Mx.BitChat`  
**WinGet Moniker:** `bitchat-rustpy` (`winget install bitchat-rustpy`)  
**Report Date:** November 16, 2026  

---

## 1. Full Repository Audit

A complete repository-wide audit was performed across all 250+ source files, Cargo crates, Python packaging configs, installers, documentation files, GitHub templates, and website files (documented in detail in [`docs/release/BRANDING-AND-MIGRATION-AUDIT.md`](BRANDING-AND-MIGRATION-AUDIT.md)).

### Summary of Audit Findings & Actions
- **217 occurrences** of `bitchat-python` / `Java-Mx/bitchat-python` were audited:
  - **166 active public-facing references** across `README.md`, `pyproject.toml`, `Cargo.toml`, `website/`, `docs/`, `packaging/`, legal notices, and GitHub issue/PR templates were migrated to `Java-Mx/bitchat-rustpy`.
  - **20 historical WinGet manifest references** in `manifests/j/Java-Mx/BitChat/0.1.0/` through `0.3.0/` were intentionally preserved as immutable historical release records.
- **23 occurrences** of `BitChat Python` were updated to **BitChat RustPy**.
- **7 occurrences** of the typo `bitchat-rustpyl` were completely removed from the repository and from the `Java-Mx.BitChat-0.3.1` WinGet PR branch.
- **8 occurrences** of `Python terminal client...` were updated in current metadata to describe the hybrid Python + Rust architecture (`Decentralized, encrypted peer-to-peer mesh messaging over Bluetooth LE and local networks, built with Python and accelerated by Rust`), while preserving historical `0.1.0`–`0.3.0` manifests.

---

## 2. Website Audit & Modernization

The official static website (`website/`, deployed to `https://java-mx.github.io/bitchat-rustpy/`) was audited and modernized:

- **Visual & Aesthetic Direction:**
  - Updated `website/assets/css/style.css` to a dark terminal-inspired palette with restrained electric-green accents (`--accent: #10b981`, `--accent-hover: #34d399`, `--border-active: #10b981`).
- **Identity & Copy:**
  - Updated all 9 HTML pages (`index.html`, `downloads.html`, `docs.html`, `security.html`, `roadmap.html`, `about.html`, `privacy.html`, `terms.html`, `404.html`) and `website/assets/js/downloads.js` to consistently display **BitChat RustPy**.
  - Updated hero and download WinGet copy buttons to `winget install bitchat-rustpy`.
- **Release Asset & Checksum Corrections (`downloads.html` & `releases.json`):**
  - Replaced broken `bitchat_python-0.3.1-*.whl` and `.flatpak` links with the exact verified `v0.3.1` GitHub Release assets, byte sizes, and SHA-256 digests:
    - `BitChat-0.3.1-windows-x64.exe` (`17.32 MB` / `18,165,765` bytes) — `2A2D68F5B7B975620AF7197030A6DD068C8A0D096AEEECFC69F5DBB3FA84A75A`
    - `bitchat_0.3.1_amd64.deb` (`17.87 MB` / `18,735,222` bytes) — `42D60D72F6DD7FA78D2A2056388A716054B00A25EDDE451E9A848F5E6E0358F8`
    - `BitChat-0.3.1-x86_64.AppImage` (`20.23 MB` / `21,212,949` bytes) — `04F0D73BAA3D9063BD72C4C510CBDFD2B041E16B3EA5174411346920B35457E8`
    - `bitchat-0.3.1-cp312-abi3-win_amd64.whl` (`469.36 KB` / `480,629` bytes) — `B5F7DB74CF31F39260106C3FB6FC66F5E090AC9BACB1349B8E1D2849ACF7C5D0`
    - `bitchat-0.3.1-cp312-abi3-linux_x86_64.whl` (`551.38 KB` / `564,611` bytes) — `82E238D949B6103FA36D29B07FAB4FE748014954D9A56DAB284E202672265A2B`
    - `bitchat-0.3.1.tar.gz` (`256.60 KB` / `262,759` bytes) — `3743DD4F3EF00543C2D759B8B33BDE8010A2DA6B513B2B59ACFB50D8B6969067`
  - Verified that all 6 downloadable release URLs return `HTTP 200 OK`.

---

## 3. GitHub Repository Audit

- **Repository Identity:** `https://github.com/Java-Mx/bitchat-rustpy`
- **GitHub Pages Endpoint:** `https://java-mx.github.io/bitchat-rustpy/` (`https_enforced: true`, workflow deployment via `.github/workflows/website.yml`)
- **Templates & Policies Updated:**
  - `.github/ISSUE_TEMPLATE/bug_report.md`
  - `.github/ISSUE_TEMPLATE/feature_request.md`
  - `.github/ISSUE_TEMPLATE/interoperability_issue.md`
  - `.github/ISSUE_TEMPLATE/protocol_issue.md`
  - `.github/pull_request_template.md`
  - `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SUPPORT.md`

---

## 4. Old Repository Migration Status (`Java-Mx/bitchat-python`)

- Querying `https://api.github.com/repos/Java-Mx/bitchat-python` confirmed that `Java-Mx/bitchat-python` was renamed in-place on GitHub to `Java-Mx/bitchat-rustpy`.
- GitHub provides automatic, permanent **HTTP 301 redirects** for all web URLs, Git clone URLs, and release asset download URLs from `Java-Mx/bitchat-python/*` to `Java-Mx/bitchat-rustpy/*` (including the `v0.1.0` installer URL in the original WinGet manifest).
- No separate duplicate repository exists to delete or archive, and all historical inbound links remain unbroken.

---

## 5. Branding & Internal Compatibility Preservation

| Surface / Identifier | Value | Rationale |
| :--- | :--- | :--- |
| **Public Product Name** | `BitChat RustPy` | Reflects the hybrid Python + Rust architecture across website, README, docs, and WinGet. |
| **WinGet Moniker** | `bitchat-rustpy` | Enables `winget install bitchat-rustpy`. |
| **WinGet Package ID** | `Java-Mx.BitChat` | Preserved so existing `0.1.0` users can run `winget upgrade` seamlessly. |
| **CLI Command / Binary** | `bitchat` (`bitchat.exe`) | Preserved for backward compatibility across scripts, PATH, and muscle memory. |
| **Python Package / Module** | `bitchat` (`bitchat._bitchat_core`) | Preserved so existing Python imports and wheels remain compatible. |
| **Inno Setup `AppId`** | `{B17CHA70-B1EC-4E87-99B7-4DA78D0B7001}` | Preserved so Windows upgrades overwrite `0.1.0` in-place without duplicate ARP entries. |
| **User Data Directory** | `~/.bitchat` (`%USERPROFILE%\.bitchat`) | Preserved so `identity.json` and `config.json` survive upgrades untouched. |

---

## 6. Application Packaging Changes

- **`pyproject.toml` & `Cargo.toml`:** Updated `description`, `keywords`, `Homepage`, `Repository`, `Issues`, and `Documentation` URLs to `Java-Mx/bitchat-rustpy` and `https://java-mx.github.io/bitchat-rustpy/`.
- **Windows Packaging (`packaging/windows/`):**
  - Updated `bitchat.iss`, `build.py`, `download_page.py`, `winget/Java-Mx.BitChat.yaml`, `legal/PRIVACY_POLICY.txt`, and `legal/TERMS_OF_USE.txt` to `Java-Mx/bitchat-rustpy`.
  - Regenerated `docs/DOWNLOAD.md` and `docs/download/index.html` with verified `v0.3.1` checksums.
- **Linux Packaging (`packaging/linux/`):**
  - Updated `deb/control.template`, `flatpak/io.github.java_mx.bitchat.metainfo.xml`, and `snap/snapcraft.yaml` to `Java-Mx/bitchat-rustpy` and **BitChat RustPy**.

---

## 7. WinGet Migration Status

- **v0.1.0 Status:** Merged ([microsoft/winget-pkgs#443445](https://github.com/microsoft/winget-pkgs/pull/443445)), indexed in Microsoft's CDN catalog, and verified live via `winget search` and `winget install`.
- **v0.3.1 Status:** Multi-file `1.28.0` schema manifests (`manifests/j/Java-Mx/BitChat/0.3.1/`) validated locally (`Manifest validation succeeded`) and submitted in **[microsoft/winget-pkgs#481727](https://github.com/microsoft/winget-pkgs/pull/481727)** (commit `2b0f5bc84d36cb70b3470a75f3d56955a9529f9c`, with `PackageName: BitChat RustPy` and `Moniker: bitchat-rustpy`).

---

## 8. Documentation Changes

Updated repository links, clone commands, and product branding across:
- `README.md`
- `docs/INDEX.md`, `docs/ARCHITECTURE.md`, `docs/DOWNLOAD.md`, `docs/RELEASE_PROCESS.md`, `docs/REQUIREMENTS.md`, `docs/UNINSTALLATION.md`
- `docs/platform/WINDOWS.md`, `docs/platform/MACOS.md`
- `docs/protocol/COMPATIBILITY.md`, `docs/protocol/ROUTING.md`
- `docs/security/CRYPTOGRAPHY.md`, `docs/security/THREAT_MODEL.md`

---

## 9. SEO & Metadata Modernization

- Added `<link rel="canonical" href="https://java-mx.github.io/bitchat-rustpy/..." />` across all website pages.
- Updated Open Graph (`og:title`, `og:description`, `og:url`, `og:site_name`, `og:image`) and Twitter/X Card (`twitter:card`, `twitter:title`, `twitter:description`, `twitter:image`) tags across all pages.
- Added `SoftwareApplication` JSON-LD structured data to `website/index.html`.
- Updated `website/robots.txt` and all 8 `<loc>` entries in `website/sitemap.xml` to `https://java-mx.github.io/bitchat-rustpy/`.

---

## 10. Security & Privacy Review

- Verified that `PRIVACY_POLICY.md` and `TERMS_OF_USE.md` retain their explicit `DRAFT` status pending final legal/publisher sign-off.
- Confirmed that `PrivacyUrl` is omitted from the `0.3.1` WinGet manifest until the privacy policy is finalized.
- Verified that all security documentation and website pages accurately describe the implemented Phase 1 architecture (Python application with `_bitchat_core` Rust native extension, Noise XX session encryption in RAM, and explicit non-guarantees in `THREAT_MODEL.md`).

---

## 11. Validation & Test Results

| Validation Check | Command | Result |
| :--- | :--- | :--- |
| **WinGet Multi-File Manifest Validation** | `winget validate --manifest manifests\j\Java-Mx\BitChat\0.3.1` | `Manifest validation succeeded.` |
| **WinGet Singleton Manifest Validation** | `winget validate --manifest packaging\windows\winget\Java-Mx.BitChat.yaml` | `Manifest validation succeeded.` |
| **Ruff Linter** | `uv run --no-sync ruff check .` | `All checks passed!` |
| **Ruff Formatter** | `uv run --no-sync ruff format --check .` | `252 files already formatted` |
| **Pyright Type Checker** | `uv run --no-sync pyright` | `0 errors, 0 warnings, 0 informations` |
| **Documentation & Packaging Pytest Suite** | `uv run --no-sync pytest tests/unit/test_documentation.py tests/unit/test_packaging_windows.py tests/unit/test_packaging_linux.py tests/unit/test_package.py` | `28 passed in 10.35s` |
| **Website Internal Link Audit** | `verify_website.py` (9 HTML pages) | `0 broken internal links` |
| **Website Release Asset HTTP Probe** | `curl -sIL` across all 6 release assets | `HTTP 200 OK` on all 6 assets |
| **In-Place Upgrade Test (`0.1.0` → `0.3.1`)** | `BitChat-0.3.1-windows-x64.exe /VERYSILENT` over `0.1.0` | Upgraded in-place; `identity.json` & `config.json` SHA-256 100% preserved |

---

## 12. Remaining Manual / External Actions

1. **Microsoft WinGet Moderator Review:** Wait for Microsoft moderator approval and auto-merge of [`microsoft/winget-pkgs#481727`](https://github.com/microsoft/winget-pkgs/pull/481727). Once merged and published by `wingetbot`, `winget install bitchat-rustpy` will install `v0.3.1` directly from the default `winget` catalog.
2. **Legal Sign-Off on Privacy Policy:** Once `PRIVACY_POLICY.md` completes final legal review, remove the `DRAFT` banner and include `PrivacyUrl: https://github.com/Java-Mx/bitchat-rustpy/blob/main/PRIVACY_POLICY.md` in subsequent WinGet manifest submissions.

---

## 13. Deployment & Publication Status

| Channel | Status | URL / Reference |
| :--- | :--- | :--- |
| **GitHub Repository (`main`)** | **PUBLISHED** | [`https://github.com/Java-Mx/bitchat-rustpy`](https://github.com/Java-Mx/bitchat-rustpy) |
| **GitHub Release (`v0.3.1`)** | **PUBLISHED** | [`https://github.com/Java-Mx/bitchat-rustpy/releases/tag/v0.3.1`](https://github.com/Java-Mx/bitchat-rustpy/releases/tag/v0.3.1) |
| **Official Website (GitHub Pages)** | **DEPLOYING / LIVE** | [`https://java-mx.github.io/bitchat-rustpy/`](https://java-mx.github.io/bitchat-rustpy/) |
| **WinGet (`0.1.0`)** | **PUBLISHED & LIVE** | [`microsoft/winget-pkgs#443445`](https://github.com/microsoft/winget-pkgs/pull/443445) (`winget install --id Java-Mx.BitChat --exact`) |
| **WinGet (`0.3.1` + `bitchat-rustpy` moniker)** | **PR SUBMITTED & VALIDATING** | [`microsoft/winget-pkgs#481727`](https://github.com/microsoft/winget-pkgs/pull/481727) (`winget install bitchat-rustpy`) |
