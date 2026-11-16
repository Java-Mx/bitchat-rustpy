# BitChat RustPy — GitHub Actions & Branch Cleanup Audit Report

**Repository:** `https://github.com/Java-Mx/bitchat-rustpy`  
**Default Branch:** `main`  
**Target Release:** `v0.3.1`  
**Audit Date:** November 17, 2026  

---

## 1. Workflow & Job Failures Discovered

An inspection of all GitHub Actions workflows (`.github/workflows/ci.yml`, `build.yml`, `security.yml`, `website.yml`, `release.yml`) and recent workflow runs (`43930459232`, `43930459224`, `43922127754`, `43922127745`) on commits `8ad1cd1` and `7d92029` identified two specific test failures across the CI and Build workflows.

### Failure 1: `test_winget_manifest_validation` on Windows CI Runners

- **Failed Workflows & Jobs:**
  - `Build` (`43930459224`, `43922127745`) — Job: `Build & Validate Windows Package` (`windows-latest`)
  - `CI` (`43930459232`, `43922127754`) — Jobs: `Test (windows-latest, Python 3.12)` and `Test (windows-latest, Python 3.13)`
- **Relevant Commits:** `8ad1cd1`, `7d92029`
- **Exact Failure Output:**
  ```text
  FAILED tests/unit/test_packaging_windows.py::test_winget_manifest_validation - AssertionError: Validation failed:

    Manifest validation succeeded with warnings.
    Manifest Warning: The schema header URL does not match the expected pattern. Value: # yaml-language-server: $schema=https://aka.ms/winget-manifest.installer.1.28.0.schema.json Line: 2, Column: 25 File: Java-Mx.BitChat.installer.yaml
    Manifest Warning: The schema header URL does not match the expected pattern. Value: # yaml-language-server: $schema=https://aka.ms/winget-manifest.defaultLocale.1.28.0.schema.json Line: 2, Column: 25 File: Java-Mx.BitChat.locale.en-US.yaml
    Manifest Warning: The schema header URL does not match the expected pattern. Value: # yaml-language-server: $schema=https://aka.ms/winget-manifest.version.1.28.0.schema.json Line: 2, Column: 25 File: Java-Mx.BitChat.yaml

  assert 2316632104 == 0
  ```
- **Root Cause:**
  - Microsoft's `winget-pkgs` repository requires manifest schema version `1.28.0`.
  - While modern WinGet (`v1.29.380`) validates `1.28.0` schema headers with exit code `0`, the older pre-installed `winget` binary on GitHub Actions `windows-latest` runner VMs (`windows-2025-vs2026`) emits a non-fatal `Manifest Warning: The schema header URL does not match the expected pattern` when encountering `1.28.0` schema URLs, printing `Manifest validation succeeded with warnings.` and returning exit code `0x8A150028` (`2316632104` unsigned 32-bit, `APPINSTALLER_CLI_ERROR_MANIFEST_VALIDATION_WARNING`).
- **Files Requiring Changes:**
  - `tests/unit/test_packaging_windows.py`
  - `packaging/windows/build.py`
- **Proposed Fix:**
  - Pass `--nowarn` (`--ignore-warnings`) to `winget validate` in `tests/unit/test_packaging_windows.py` and `packaging/windows/build.py` so that `winget validate` still fails on any genuine manifest validation error while returning `0` (`S_OK`) when validation succeeds with schema-version warnings on older runner binaries.

---

### Failure 2: `test_releases_json_schema_and_checksum_consistency` in Website Validation

- **Failed Workflows & Jobs:**
  - `CI` (`43930459232`) — Jobs: `Test (ubuntu-latest, Python 3.12)`, `Test (ubuntu-latest, Python 3.13)`, `Test (windows-latest, Python 3.12)`, `Test (windows-latest, Python 3.13)`
- **Relevant Commit:** `7d92029`
- **Exact Failure Output:**
  ```text
  FAILED tests/unit/test_website.py::test_releases_json_schema_and_checksum_consistency - AssertionError: assert 6 >= 7
   +  where 6 = len([{'id': 'win-exe', ...}, ...])
  ```
- **Root Cause:**
  - During the website audit on commit `7d92029`, the non-existent `linux-flatpak` entry was removed from `website/assets/data/releases.json`, reducing the `packages` array from 7 items to 6 items.
  - `tests/unit/test_website.py` line 150 asserts `assert len(data["packages"]) >= 7`.
  - The official `v0.3.1` GitHub Release actually publishes **7** non-checksum assets:
    1. `BitChat-0.3.1-windows-x64.exe` (`win-exe`)
    2. `bitchat_0.3.1_amd64.deb` (`linux-deb`)
    3. `BitChat-0.3.1-x86_64.AppImage` (`linux-appimage`)
    4. `bitchat-0.3.1-cp312-abi3-win_amd64.whl` (`wheel-win`)
    5. `bitchat-0.3.1-cp312-abi3-linux_x86_64.whl` (`wheel-linux`)
    6. `bitchat-0.3.1.tar.gz` (`sdist`)
    7. `Java-Mx.BitChat.yaml` (`winget-manifest`, `1,435` bytes, SHA-256 `C614823018AA0A85ADF256C98FAAA71069EF57012B00862F2C1681B10A6F4A04`)
- **Files Requiring Changes:**
  - `website/assets/data/releases.json`
- **Proposed Fix:**
  - Include the 7th verified `v0.3.1` GitHub release asset (`Java-Mx.BitChat.yaml`, `id: "winget-manifest"`) in `website/assets/data/releases.json` with its verified URL, byte size (`1435`), and SHA-256 digest (`C614823018AA0A85ADF256C98FAAA71069EF57012B00862F2C1681B10A6F4A04`).

---

## 2. Pytest Asyncio Configuration Warning Cleanup

- **Observation:** Every pytest run emits:
  `PytestDeprecationWarning: The configuration option "asyncio_default_fixture_loop_scope" is unset.`
- **Proposed Fix:** Set `asyncio_default_fixture_loop_scope = "function"` in `[tool.pytest.ini_options]` in `pyproject.toml` so pytest-asyncio runs cleanly without deprecation warnings.

---

## 3. Branch Inventory & Cleanup Audit

### 3.1 Default Branch
- `main` is confirmed as the default branch on GitHub (`HEAD -> origin/main`).
- Branch protection on all branches is currently `protected: false`.

### 3.2 Non-Main Remote & Local Branches Audited

Every branch was inspected with `git log main..<branch> --oneline` to check for unmerged commits:

| Branch Name | Location | Unmerged Commits vs. `main` | Open PR | Recommended Action |
| :--- | :--- | :--- | :--- | :--- |
| `agents/security-lan-harden-validation-steps` | Local (worktree) & Remote (`origin`) | `0` (already merged in `main`) | None | Remove local git worktree, delete local branch, delete remote branch |
| `fix/windows-ble-advertising` | Remote (`origin`) | `0` (already merged in `main`) | None | Delete remote branch |
| `dependabot/github_actions/main/actions/checkout-7` | Remote (`origin`) | `0` (already merged in PR #33) | None | Delete remote branch |
| `dependabot/github_actions/main/actions/deploy-pages-5` | Remote (`origin`) | `0` (already merged in PR #30) | None | Delete remote branch |
| `dependabot/github_actions/main/astral-sh/setup-uv-7` | Remote (`origin`) | `0` (already in `main`) | None | Delete remote branch |
| `dependabot/github_actions/main/softprops/action-gh-release-3` | Remote (`origin`) | `0` (already in `main`) | None | Delete remote branch |
| `dependabot/pip/main/pytest-gte-9.2.0` | Remote (`origin`) | `0` (already in `main`) | None | Delete remote branch |
| `dependabot/pip/main/ruff-gte-0.17.2` | Remote (`origin`) | `0` (superseded by `>=0.17.3`) | None | Delete remote branch |
| `dependabot/pip/main/ruff-gte-0.17.3` | Remote (`origin`) | `0` (already in `main`) | None | Delete remote branch |
| `dependabot/pip/main/ruff-gte-0.17.4` | Remote (`origin`) | `1` (`9e894f9`: bump `ruff>=0.17.4`) | PR #35 (Open) | Incorporate `ruff>=0.17.4` into `main`, close/merge PR #35, and delete remote branch |
