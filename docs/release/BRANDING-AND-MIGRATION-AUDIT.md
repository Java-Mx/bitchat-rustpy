# BitChat RustPy — Complete Branding & Distribution Migration Audit

**Document Status:** Authoritative Engineering Audit  
**Repository:** `https://github.com/Java-Mx/bitchat-rustpy`  
**Website:** `https://java-mx.github.io/bitchat-rustpy/`  
**Target Release:** `v0.3.1`  
**Audit Date:** November 16, 2026  

---

## 1. Executive Summary & Classification Taxonomy

A complete repository-wide inspection was executed across all source files, packaging configurations, manifests, GitHub workflows, documentation, and website files to identify stale branding (`BitChat Python`, `bitchat-python`, `Python terminal client`, `bitchat-rustpyl`), outdated URLs (`https://github.com/Java-Mx/bitchat-python`, `https://java-mx.github.io/bitchat-python/`), and mismatched release asset references.

Every finding is classified into one of five categories:

1. **Category 1 — Public-Facing Content to Update:** Current documentation, website pages, metadata, badges, and current release manifests that must reflect **BitChat RustPy**, `https://github.com/Java-Mx/bitchat-rustpy`, `https://java-mx.github.io/bitchat-rustpy/`, and `winget install bitchat-rustpy`.
2. **Category 2 — Historical References to Retain:** Historical WinGet manifests (`0.1.0`, `0.2.0`, `0.2.1`, `0.3.0`) and historical changelog/audit records that document past states.
3. **Category 3 — Internal Identifiers to Preserve for Compatibility:** Python module/package name (`bitchat`), Rust native extension module (`bitchat._bitchat_core`), CLI executable (`bitchat` / `bitchat.exe`), user data directory (`~/.bitchat`), Inno Setup `AppId` (`{B17CHA70-B1EC-4E87-99B7-4DA78D0B7001}`), and WinGet `PackageIdentifier` (`Java-Mx.BitChat`).
4. **Category 4 — Broken or Obsolete References to Remove/Fix:** Non-existent release asset links on the website (`BitChat-0.3.1-x86_64.flatpak`, `bitchat_python-0.3.1-*.whl`, `bitchat_python-0.3.1.tar.gz`) and the typo `bitchat-rustpyl`.
5. **Category 5 — References Requiring Migration or Redirects:** GitHub repository rename (`Java-Mx/bitchat-python` → `Java-Mx/bitchat-rustpy`, handled via GitHub's native HTTP 301 redirect) and GitHub Pages URL migration (`https://java-mx.github.io/bitchat-rustpy/`).

---

## 2. Detailed Audit Table of Findings

### 2.1 Root Metadata, Build Manifests & Legal Documents

| File Path | Existing Content | Classification | Recommended Action | Compatibility Risk |
| :--- | :--- | :--- | :--- | :--- |
| `README.md` | Title `# CLI BitChat Python`, intro `BitChat Python is...`, 23 links/badges pointing to `Java-Mx/bitchat-python`, WinGet `winget install Java-Mx.BitChat` | Category 1 | Update branding to **BitChat RustPy**, update all repository/badge/video URLs to `Java-Mx/bitchat-rustpy`, update WinGet command to `winget install bitchat-rustpy` | None |
| `pyproject.toml` | `name = "bitchat"`, `description = "Python terminal client..."`, `[project.urls]` pointing to `Java-Mx/bitchat-python` | Category 1 & 3 | Keep `name = "bitchat"` and `[project.scripts] bitchat` (Cat 3); update `description` and `[project.urls]` to `Java-Mx/bitchat-rustpy` and `https://java-mx.github.io/bitchat-rustpy/` (Cat 1) | Low (preserving package & script name prevents import/CLI breakage) |
| `Cargo.toml` | `repository = "https://github.com/Java-Mx/bitchat-python"` | Category 1 | Update `repository` to `https://github.com/Java-Mx/bitchat-rustpy` | None |
| `src/bitchat/__init__.py` | Docstring `"""BitChat — Python terminal client..."""` | Category 1 | Update docstring to `"""BitChat RustPy — Decentralized encrypted peer-to-peer mesh chat..."""` | None |
| `PRIVACY_POLICY.md` | Links to `Java-Mx/bitchat-python`; marked as `DRAFT` | Category 1 | Update repository links to `Java-Mx/bitchat-rustpy` while strictly preserving `DRAFT` legal status | None |
| `TERMS_OF_USE.md` | Links to `Java-Mx/bitchat-python`; marked as `DRAFT` | Category 1 | Update repository links to `Java-Mx/bitchat-rustpy` while preserving `DRAFT` status | None |
| `SECURITY.md` | Advisories link to `Java-Mx/bitchat-python/security/advisories/new` | Category 1 | Update URL to `Java-Mx/bitchat-rustpy` | None |
| `CONTRIBUTING.md` | Clone URLs and issue links pointing to `Java-Mx/bitchat-python` | Category 1 | Update to `Java-Mx/bitchat-rustpy` | None |
| `CODE_OF_CONDUCT.md` | Links to `Java-Mx/bitchat-python` | Category 1 | Update to `Java-Mx/bitchat-rustpy` | None |
| `SUPPORT.md` | Issue/discussion links pointing to `Java-Mx/bitchat-python` | Category 1 | Update to `Java-Mx/bitchat-rustpy` | None |
| `.github/ISSUE_TEMPLATE/*.md` & `pull_request_template.md` | Links to `Java-Mx/bitchat-python` | Category 1 | Update to `Java-Mx/bitchat-rustpy` | None |

---

### 2.2 Official Website (`website/`)

| File Path | Existing Content | Classification | Recommended Action | Compatibility Risk |
| :--- | :--- | :--- | :--- | :--- |
| `website/index.html` | Brand `BitChat` / `BitChat Python`, `og:url` `.../bitchat-python/`, GitHub links `Java-Mx/bitchat-python`, WinGet `winget install Java-Mx.BitChat`, unverified Flatpak row in table | Category 1 & 4 | Rebrand to **BitChat RustPy**, update canonical/OG/Twitter metadata to `https://java-mx.github.io/bitchat-rustpy/`, update WinGet command to `winget install bitchat-rustpy`, replace Flatpak row with verified Python ABI3 Wheel / Source assets | None |
| `website/downloads.html` | `BitChat Python` footer, `bitchat-python` links, wrong wheel filenames (`bitchat_python-0.3.1-cp312-cp312-*.whl`), non-existent `.flatpak` link, outdated `.deb`/`.AppImage` SHA-256 hashes | Category 1 & 4 | Update to **BitChat RustPy**, `winget install bitchat-rustpy`, fix all download URLs to `Java-Mx/bitchat-rustpy`, fix wheel filenames to `bitchat-0.3.1-cp312-abi3-*.whl`, fix sdist to `bitchat-0.3.1.tar.gz`, update all SHA-256 hashes to match authoritative v0.3.1 release assets | Fixes broken 404 download links |
| `website/assets/data/releases.json` | `repository: .../bitchat-python`, wrong wheel/sdist filenames, non-existent `linux-flatpak` entry, mismatched `.deb`/`.AppImage` hashes | Category 1 & 4 | Update to authoritative v0.3.1 release URLs, exact byte sizes, and verified SHA-256 digests | None (retains `"version": "0.3.1"` and `"packages"` schema validated by CI) |
| `website/docs.html` | `BitChat Python` references, `bitchat-python` clone URLs and doc links | Category 1 | Update to **BitChat RustPy**, `Java-Mx/bitchat-rustpy`, `winget install bitchat-rustpy` | None |
| `website/security.html` | `BitChat Python` references, `bitchat-python` links | Category 1 | Update to **BitChat RustPy** and `Java-Mx/bitchat-rustpy` | None |
| `website/about.html` | `BitChat Python` title and prose, `bitchat-python` links | Category 1 | Update to **BitChat RustPy** and `Java-Mx/bitchat-rustpy` | None |
| `website/roadmap.html` | `BitChat Python` title and prose, `bitchat-python` links | Category 1 | Update to **BitChat RustPy** and `Java-Mx/bitchat-rustpy` | None |
| `website/privacy.html` & `website/terms.html` | `BitChat Python` references, `bitchat-python` links | Category 1 | Update to **BitChat RustPy** and `Java-Mx/bitchat-rustpy` while preserving draft banners | None |
| `website/404.html` | `bitchat-python` GitHub link | Category 1 | Update to **BitChat RustPy** and `Java-Mx/bitchat-rustpy` | None |
| `website/robots.txt` | `Sitemap: https://java-mx.github.io/bitchat-python/sitemap.xml` | Category 1 | Update to `https://java-mx.github.io/bitchat-rustpy/sitemap.xml` | None |
| `website/sitemap.xml` | 8 `<loc>` entries using `https://java-mx.github.io/bitchat-python/...` | Category 1 | Update all 8 `<loc>` URLs to `https://java-mx.github.io/bitchat-rustpy/...` | None |
| `website/assets/css/style.css` | Cyan accent variables (`--accent: #00d2ff`) | Category 1 | Modernize accent palette to restrained terminal electric-green (`--accent: #10b981` / `#00e676`) | None |

---

### 2.3 Platform Packaging & WinGet Manifests

| File Path | Existing Content | Classification | Recommended Action | Compatibility Risk |
| :--- | :--- | :--- | :--- | :--- |
| `manifests/j/Java-Mx/BitChat/0.3.1/*` | Contains `bitchat-rustpyl` in `Tags` | Category 4 | Remove `bitchat-rustpyl` typo from `Tags`; keep `PackageIdentifier: Java-Mx.BitChat`, `PackageName: BitChat RustPy`, `Moniker: bitchat-rustpy` | None |
| `manifests/j/Java-Mx/BitChat/0.1.0/*` .. `0.3.0/*` | Historical manifests referencing `bitchat-python` | Category 2 | Retain unchanged as historical release records | None |
| `packaging/windows/winget/Java-Mx.BitChat.yaml` | Contains `bitchat-rustpyl` in `Tags` | Category 4 | Remove `bitchat-rustpyl` from `Tags` | None |
| `packaging/windows/build.py` | Contains `bitchat-rustpyl` in `Tags` and `bitchat-python` in Authenticode `/du` URL | Category 1 & 4 | Remove `bitchat-rustpyl` and update `/du` URL to `https://github.com/Java-Mx/bitchat-rustpy` | None |
| `packaging/windows/bitchat.iss` | `MyAppURL` / `MyTermsURL` / `MyPrivacyURL` pointing to `bitchat-python`; `AppId` `{B17CHA70-B1EC-4E87-99B7-4DA78D0B7001}` | Category 1 & 3 | Update URLs to `Java-Mx/bitchat-rustpy`; preserve `AppId`, `MyAppName="BitChat"`, and `MyAppExeName="bitchat.exe"` so existing installations and unit tests remain 100% compatible | Low (guarded by `test_packaging_windows.py`) |
| `packaging/windows/download_page.py` | Links to `Java-Mx/bitchat-python` | Category 1 | Update repository links to `Java-Mx/bitchat-rustpy` while preserving `winget install Java-Mx.BitChat` alongside `winget install bitchat-rustpy` for test compatibility | Low (guarded by `test_download_page_generation`) |
| `packaging/windows/legal/*.txt` | Links to `Java-Mx/bitchat-python` | Category 1 | Update URLs to `Java-Mx/bitchat-rustpy` | None |
| `packaging/linux/deb/control.template` | `Homepage: https://github.com/Java-Mx/bitchat-python` | Category 1 | Update to `https://github.com/Java-Mx/bitchat-rustpy` | None |
| `packaging/linux/flatpak/io.github.java_mx.bitchat.metainfo.xml` | URLs pointing to `Java-Mx/bitchat-python` | Category 1 | Update URLs to `Java-Mx/bitchat-rustpy` | None |

---

### 2.4 Technical Documentation (`docs/`)

| File Path | Existing Content | Classification | Recommended Action | Compatibility Risk |
| :--- | :--- | :--- | :--- | :--- |
| `docs/ARCHITECTURE.md`, `docs/INDEX.md`, `docs/DOWNLOAD.md`, `docs/RELEASE_PROCESS.md`, `docs/REQUIREMENTS.md`, `docs/UNINSTALLATION.md`, `docs/platform/*.md`, `docs/protocol/*.md`, `docs/security/*.md`, `docs/download/index.html` | References to `BitChat Python` and `https://github.com/Java-Mx/bitchat-python` | Category 1 | Update branding to **BitChat RustPy** and repository links to `https://github.com/Java-Mx/bitchat-rustpy` | Low (verify `tests/unit/test_documentation.py` passes) |
| `docs/release/WINGET-V0.3.1-PUBLICATION.md` | Mentions `bitchat-rustpyl` in Tags | Category 4 | Remove `bitchat-rustpyl` | None |
