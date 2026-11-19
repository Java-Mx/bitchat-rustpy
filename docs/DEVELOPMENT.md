# BitChat Development Guide (`v0.3.3`)

## 1. Prerequisites & Environment Setup

- **Python**: `3.12+` (`3.12` / `3.13` tested in CI)
- **Rust Toolchain**: Stable Rust (`rustc` & `cargo` via [rustup](https://rustup.rs/), edition 2021)
- **Package Manager**: [uv](https://github.com/astral-sh/uv)
- **Native Extension Builder**: [Maturin](https://www.maturin.rs/) (installed automatically in the `uv` dev group)
- **Windows Shell**: Windows PowerShell 5.1 (`powershell.exe`) or PowerShell 7+ (`pwsh.exe`)

From the repository root, synchronize all Python dependencies and build the editable package:

```bash
uv sync --all-groups
```

To compile and install the optimized Rust native extension (`bitchat._bitchat_core`) into your virtual environment:

```bash
# Recommended safe/serialized builder (checks Windows .pyd locks & verifies import):
uv run --no-sync python scripts/build_native.py

# Or directly via Maturin:
uv run --no-sync maturin develop --release
```

### 1.1 Reliable Windows PowerShell 5.1 Development Workflow

On Windows, **always separate building the native Rust extension from launching BitChat** by using `--no-sync` when launching:

```powershell
# 1. Build (serialized with pre-flight .pyd lock detection + post-build import verification)
Set-Location D:\bitchat-python
uv run --no-sync python scripts/build_native.py
# Or using the PowerShell 5.1 helper:
powershell -ExecutionPolicy Bypass -File .\scripts\dev-windows.ps1 -Action Build

# 2. Verify native extension import
uv run --no-sync python -c "import bitchat._bitchat_core; print('Native Rust extension loaded successfully')"

# 3. Launch BitChat (without triggering an automatic editable rebuild)
uv run --no-sync bitchat
```

### 1.2 Troubleshooting Windows `.pyd` File Locks (`os error 32`)

**Symptom:** Running `uv run bitchat` (without `--no-sync`) or `maturin develop --release` completes Rust compilation (`Finished 'release' profile`), then fails during copy:

```text
Failed to copy:
D:\bitchat-python\target\maturin\_bitchat_core.dll
to:
D:\bitchat-python\src\bitchat\_bitchat_core.pyd
The process cannot access the file because it is being used by another process. (os error 32)
```

**Root Cause:** Rust compilation **succeeded**. Unlike Linux/macOS, the Windows kernel exclusively locks any loaded `.pyd`/`.dll` image (`src\bitchat\_bitchat_core.pyd` → `os error 32`) and running console-script executable (`.venv\Scripts\bitchat.exe` → `Access is denied (os error 5)`) while a process has them mapped in memory. If another BitChat instance, Python REPL, pytest runner, or IDE debugger has `src\bitchat\_bitchat_core.pyd` or `.venv\Scripts\bitchat.exe` open, Maturin/`uv pip install` cannot replace them in place, and running `uv run bitchat` without `--no-sync` triggers an editable rebuild whenever `pyproject.toml`, `Cargo.toml`, or Rust sources change.

**Diagnosis & Safe Recovery:**

1. Check lock status and identify the exact locking process (uses the built-in Windows Restart Manager API + CIM):
   ```powershell
   uv run --no-sync python scripts/build_native.py --check-locks
   # Or via the PowerShell 5.1 helper:
   powershell -ExecutionPolicy Bypass -File .\scripts\dev-windows.ps1 -Action CheckLocks
   ```
   Or inspect candidate processes manually in PowerShell 5.1:
   ```powershell
   Get-CimInstance Win32_Process |
   Where-Object { $_.Name -match '^(python|pythonw|bitchat|uv)\.exe$' } |
   Select-Object ProcessId, ParentProcessId, Name, CommandLine
   ```
2. Close **only** the identified BitChat / Python process holding the extension (press `Ctrl+Q` / `/exit` in BitChat, or close that specific PID via `Stop-Process -Id <PID>`, or run `.\scripts\dev-windows.ps1 -Action CloseBitChat` which prompts before closing verified BitChat processes only). **Never** run indiscriminate commands like `taskkill /IM python.exe /F`.
3. Retry the build and launch with `--no-sync`:
   ```powershell
   uv run --no-sync python scripts/build_native.py
   uv run --no-sync bitchat
   ```
4. **Concurrent Builds:** `scripts/build_native.py` acquires an OS-managed lock (`target/.bitchat-native-build.lock`) so simultaneous builds do not race on `_bitchat_core.pyd`. Pass `--wait` to queue behind an active build; locks are released automatically by the OS even if a build is interrupted.

---

## 2. Running the Test Suite

The test suite is organized under `tests/`:

- `tests/unit/` — Unit tests for application core, TUI, storage, commands, platform detection, uninstaller, packaging, documentation, and Rust/Python differential parity (`test_native_core.py`).
- `tests/protocol/` — Binary wire encoding, decoding, padding, fragmentation, reassembly, and defensive bounds tests.
- `tests/crypto/` — `Noise_XX_25519_ChaChaPoly_SHA256`, `AES-256-GCM`, `X25519`, `Ed25519`, `HKDF`, `PBKDF2`, and `LocalIdentity` tests.
- `tests/ble/` & `tests/network/` — Simulated WinRT and BlueZ BLE transport tests, LAN UDP discovery, and TCP framing tests.
- `tests/mesh/` — Multi-hop flood routing, deduplication, and peer rate-limiting tests.
- `tests/integration/`, `tests/interoperability/`, `tests/e2e/`, `tests/stress/` — End-to-end multi-peer, interoperability vector, and adversarial stress tests.

### Python Tests

```bash
# Run full test suite
uv run --no-sync pytest

# Run specific test suites
uv run --no-sync pytest tests/unit/
uv run --no-sync pytest tests/protocol/
uv run --no-sync pytest tests/crypto/
uv run --no-sync pytest tests/ble/ tests/network/ tests/mesh/
uv run --no-sync pytest tests/unit/test_native_core.py
uv run --no-sync pytest tests/unit/test_uninstaller.py
uv run --no-sync pytest tests/unit/test_documentation.py
uv run --no-sync pytest tests/e2e/
```

### Rust Native Core Tests (`rust/bitchat-core`)

> **Important:** Because `bitchat-core` is a `cdylib` PyO3 extension crate, run `cargo test` and `cargo clippy` with `--no-default-features` (which disables the `extension-module` linker flag during standalone Rust test compilation):

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --no-default-features -- -D warnings
cargo test --workspace --no-default-features
```

---

## 3. Code Quality, Formatting & Static Analysis

```bash
# Python linting and formatting (Ruff)
uv run --no-sync ruff check .
uv run --no-sync ruff format --check .

# Python static type checking (Pyright)
uv run --no-sync pyright

# Rust formatting
cargo fmt --all
```

---

## 4. Running BitChat Locally

```bash
# Launch interactive Textual TUI
uv run --no-sync bitchat --tui

# Launch headless CLI mode
uv run --no-sync bitchat --cli

# Run hardware and network capability diagnostics
uv run --no-sync bitchat --configure

# Preview uninstaller actions without modifying the system
uv run --no-sync bitchat --uninstall --dry-run
```

---

## 5. Differential Equivalence & Stress Verification

To run the Rust/Python differential equivalence and adversarial stress suites:

```bash
uv run --no-sync pytest tests/unit/test_native_core.py tests/stress/ -q
```

---

## 6. Building Distributable Packages

```bash
# Build Python wheel and sdist
uv build

# Build Windows standalone installer (.exe) and WinGet manifests (Windows only)
uv run python packaging/windows/build.py

# Build Linux .deb, AppImage, and Flatpak bundles (Linux only)
uv run python packaging/linux/build.py --build-flatpak
```

See [`docs/RELEASE_PROCESS.md`](RELEASE_PROCESS.md) for the complete release engineering workflow.
