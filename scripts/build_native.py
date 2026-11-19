"""Safe, serialized builder for the BitChat native Rust extension (`bitchat._bitchat_core`).

Addresses Windows editable-build file locks (``os error 32``) when copying
``target/maturin/_bitchat_core.dll`` to ``src/bitchat/_bitchat_core.pyd`` while
another BitChat or Python process has the extension loaded in memory.

Features:
- OS-level build lock serialization (``msvcrt.locking`` on Windows, ``fcntl.flock``
  on POSIX) so two simultaneous builds cannot corrupt or race on the ``.pyd``/``.so``,
  and locks are automatically released by the kernel even if a build is killed.
- Pre-flight exclusive-access probe on Windows using Win32 ``CreateFileW`` with
  ``dwShareMode = 0`` (no deletion, no overwrite, no forced termination).
- Exact locking-process discovery on Windows via the built-in Restart Manager API
  (``rstrtmgr.dll``) enriched with command-line details from ``Win32_Process``.
- Post-build stderr classification so a copy/file-lock failure after a successful
  ``cargo``/``rustc`` compilation is never misreported as a Rust compile error.
- Optional post-build verification importing ``bitchat._bitchat_core`` in an isolated
  subprocess that exits immediately so no handle remains open.

Usage:
    uv run --no-sync python scripts/build_native.py
    uv run --no-sync python scripts/build_native.py --check-locks
    uv run --no-sync python scripts/build_native.py --wait --verify
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as wintypes
import json
import os
import re
import subprocess
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_BITCHAT_DIR = REPO_ROOT / "src" / "bitchat"
LOCK_FILE_PATH = REPO_ROOT / "target" / ".bitchat-native-build.lock"

# Win32 constants for safe lock probing and Restart Manager
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x00000080
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
ERROR_SHARING_VIOLATION = 32
ERROR_LOCK_VIOLATION = 33
ERROR_ACCESS_DENIED = 5
ERROR_MORE_DATA = 234

CCH_RM_SESSION_KEY = 32
CCH_RM_MAX_APP_NAME = 255
CCH_RM_MAX_SVC_NAME = 63


@dataclass(frozen=True)
class LockingProcess:
    """Information about a process holding a handle/module on the native extension."""

    pid: int
    name: str
    command_line: str | None = None
    source: str = "restart_manager"


@dataclass(frozen=True)
class ExtensionLockStatus:
    """Result of probing whether the native extension destination can be replaced."""

    destination: Path
    exists: bool
    locked: bool
    win_error: int | None
    locking_processes: tuple[LockingProcess, ...]


def get_extension_candidates(
    src_dir: Path = SRC_BITCHAT_DIR,
    venv_dir: Path | None = None,
) -> list[Path]:
    """Return editable native extension & Windows launcher files replaced by maturin."""
    if sys.platform == "win32":
        primary = src_dir / "_bitchat_core.pyd"
        matches = sorted(src_dir.glob("_bitchat_core*.pyd"))
        candidates = matches if matches else [primary]
        resolved_venv = venv_dir if venv_dir is not None else (REPO_ROOT / ".venv")
        launcher = resolved_venv / "Scripts" / "bitchat.exe"
        if launcher.exists():
            candidates.append(launcher)
        return candidates
    matches = sorted(src_dir.glob("_bitchat_core*.so"))
    if matches:
        return matches
    return [src_dir / "_bitchat_core.so"]


def _probe_windows_file_lock(path: Path) -> tuple[bool, int | None]:
    """Safely probe if ``path`` is locked by another process on Windows.

    Opens an existing file with ``dwShareMode = 0`` (exclusive) without modifying,
    truncating, or deleting it, and immediately closes the handle if acquired.
    """
    if sys.platform != "win32" or not path.exists():
        return False, None

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE

    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL

    handle = create_file(
        str(path),
        GENERIC_READ | GENERIC_WRITE,
        0,  # Exclusive probe: fails with ERROR_SHARING_VIOLATION if loaded/open
        None,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        None,
    )
    if handle == INVALID_HANDLE_VALUE:
        err = ctypes.get_last_error()
        if err in (ERROR_SHARING_VIOLATION, ERROR_LOCK_VIOLATION, ERROR_ACCESS_DENIED):
            return True, err
        return False, err

    close_handle(handle)
    return False, None


def _query_windows_command_lines(pids: list[int]) -> dict[int, tuple[str, str | None]]:
    """Query process names and command lines for specific PIDs via PowerShell CIM."""
    if sys.platform != "win32" or not pids:
        return {}

    pid_filter = " -or ".join(f"$_.ProcessId -eq {int(p)}" for p in pids)
    ps_cmd = (
        "Get-CimInstance Win32_Process | "
        f"Where-Object {{ {pid_filter} }} | "
        "Select-Object ProcessId, Name, CommandLine | "
        "ConvertTo-Json -Compress"
    )
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        raw = proc.stdout.strip()
        if proc.returncode != 0 or not raw:
            return {}
        parsed = json.loads(raw)
        items = parsed if isinstance(parsed, list) else [parsed]
        result: dict[int, tuple[str, str | None]] = {}
        for item in items:
            pid = int(item.get("ProcessId", 0))
            name = str(item.get("Name") or "unknown")
            cmdline = item.get("CommandLine")
            result[pid] = (name, str(cmdline) if cmdline else None)
        return result
    except Exception:
        return {}


def _find_locking_processes_restart_manager(path: Path) -> list[LockingProcess]:
    """Use the built-in Windows Restart Manager API to identify exact locking PIDs."""
    if sys.platform != "win32" or not path.exists():
        return []

    class RM_UNIQUE_PROCESS(ctypes.Structure):
        _fields_ = [
            ("dwProcessId", wintypes.DWORD),
            ("ProcessStartTime", wintypes.FILETIME),
        ]

    class RM_PROCESS_INFO(ctypes.Structure):
        _fields_ = [
            ("Process", RM_UNIQUE_PROCESS),
            ("strAppName", wintypes.WCHAR * (CCH_RM_MAX_APP_NAME + 1)),
            ("strServiceShortName", wintypes.WCHAR * (CCH_RM_MAX_SVC_NAME + 1)),
            ("ApplicationType", wintypes.DWORD),
            ("AppStatus", wintypes.ULONG),
            ("TSSessionId", wintypes.DWORD),
            ("bRestartable", wintypes.BOOL),
        ]

    try:
        rstrtmgr = ctypes.WinDLL("rstrtmgr")
    except OSError:
        return []

    session_handle = wintypes.DWORD(0)
    session_key = ctypes.create_unicode_buffer(CCH_RM_SESSION_KEY + 1)
    rc = rstrtmgr.RmStartSession(ctypes.byref(session_handle), 0, session_key)
    if rc != 0:
        return []

    try:
        file_array = (wintypes.LPCWSTR * 1)(str(path.resolve()))
        rc = rstrtmgr.RmRegisterResources(
            session_handle, 1, file_array, 0, None, 0, None
        )
        if rc != 0:
            return []

        needed = wintypes.UINT(0)
        count = wintypes.UINT(0)
        reasons = wintypes.DWORD(0)
        rc = rstrtmgr.RmGetList(
            session_handle,
            ctypes.byref(needed),
            ctypes.byref(count),
            None,
            ctypes.byref(reasons),
        )
        if rc != ERROR_MORE_DATA or needed.value == 0:
            return []

        buf_len = needed.value + 4
        proc_info = (RM_PROCESS_INFO * buf_len)()
        count = wintypes.UINT(buf_len)
        rc = rstrtmgr.RmGetList(
            session_handle,
            ctypes.byref(needed),
            ctypes.byref(count),
            proc_info,
            ctypes.byref(reasons),
        )
        if rc != 0:
            return []

        found: dict[int, str] = {}
        for i in range(count.value):
            pid = int(proc_info[i].Process.dwProcessId)
            app_name = proc_info[i].strAppName or "unknown"
            found[pid] = app_name

        cmdlines = _query_windows_command_lines(list(found.keys()))
        results: list[LockingProcess] = []
        for pid, app_name in sorted(found.items()):
            exe_name, cmdline = cmdlines.get(pid, (app_name, None))
            results.append(
                LockingProcess(
                    pid=pid,
                    name=exe_name or app_name,
                    command_line=cmdline,
                    source="restart_manager",
                )
            )
        return results
    finally:
        rstrtmgr.RmEndSession(session_handle)


def _find_candidate_bitchat_processes_windows() -> list[LockingProcess]:
    """Fallback CIM scan for Python/BitChat processes referencing this repository."""
    if sys.platform != "win32":
        return []

    ps_cmd = (
        "Get-CimInstance Win32_Process | "
        "Where-Object { $_.Name -match '^(python|pythonw|bitchat|uv)\\.exe$' } | "
        "Select-Object ProcessId, Name, CommandLine | "
        "ConvertTo-Json -Compress"
    )
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        raw = proc.stdout.strip()
        if proc.returncode != 0 or not raw:
            return []
        parsed = json.loads(raw)
        items = parsed if isinstance(parsed, list) else [parsed]
    except Exception:
        return []

    current_pid = os.getpid()
    repo_lower = str(REPO_ROOT).lower()
    candidates: list[LockingProcess] = []
    for item in items:
        pid = int(item.get("ProcessId", 0))
        if pid == current_pid or pid <= 0:
            continue
        name = str(item.get("Name") or "unknown")
        cmdline = str(item.get("CommandLine") or "")
        cmdline_lower = cmdline.lower()
        if (
            "bitchat" in cmdline_lower
            or repo_lower in cmdline_lower
            or name.lower() == "bitchat.exe"
        ):
            candidates.append(
                LockingProcess(
                    pid=pid,
                    name=name,
                    command_line=cmdline or None,
                    source="cim_heuristic",
                )
            )
    return candidates


def inspect_extension_locks(src_dir: Path = SRC_BITCHAT_DIR) -> list[ExtensionLockStatus]:
    """Inspect all editable native extension files for active locks."""
    statuses: list[ExtensionLockStatus] = []
    for dest in get_extension_candidates(src_dir):
        exists = dest.exists()
        if not exists:
            statuses.append(
                ExtensionLockStatus(
                    destination=dest,
                    exists=False,
                    locked=False,
                    win_error=None,
                    locking_processes=(),
                )
            )
            continue

        locked, win_err = _probe_windows_file_lock(dest)
        procs: list[LockingProcess] = []
        if locked:
            procs = _find_locking_processes_restart_manager(dest)
            if not procs:
                procs = _find_candidate_bitchat_processes_windows()

        statuses.append(
            ExtensionLockStatus(
                destination=dest,
                exists=True,
                locked=locked,
                win_error=win_err,
                locking_processes=tuple(procs),
            )
        )
    return statuses


def format_lock_diagnostic(
    status: ExtensionLockStatus,
    *,
    rust_compiled: bool = False,
) -> str:
    """Format a clear, actionable Windows file-lock diagnostic message."""
    try:
        rel_dest = status.destination.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        rel_dest = str(status.destination)

    lines = [
        "Native Rust extension replacement failed.",
        "",
    ]
    if rust_compiled:
        lines.extend(
            [
                "Note: Rust compilation SUCCEEDED. Only the Windows file copy/replacement",
                "step failed because the destination .pyd file is locked by another process.",
                "",
            ]
        )

    lines.extend(
        [
            "Destination:",
            rel_dest,
            "",
            "Possible cause:",
            "The extension is currently loaded by another process.",
            "",
        ]
    )

    if status.win_error is not None:
        lines.append(f"Windows error code: os error {status.win_error}")
        lines.append("")

    if status.locking_processes:
        lines.append("Detected process(es):")
        for proc in status.locking_processes:
            tag = (
                "confirmed handle"
                if proc.source == "restart_manager"
                else "matching BitChat process"
            )
            cmd_preview = proc.command_line or "(command line unavailable)"
            lines.append(f"  - PID {proc.pid} ({proc.name}) [{tag}]: {cmd_preview}")
        lines.append("")
    else:
        lines.extend(
            [
                "Inspect candidate processes in PowerShell:",
                "  Get-CimInstance Win32_Process | Where-Object { $_.Name -match '^(python|pythonw|bitchat|uv)\\.exe$' } | Select-Object ProcessId, ParentProcessId, Name, CommandLine",
                "",
            ]
        )

    lines.extend(
        [
            "Action:",
            "Close the BitChat process or Python session using this project,",
            "then rerun the native extension build:",
            "",
            "  uv run --no-sync python scripts/build_native.py",
            "  # or directly:",
            "  uv run --no-sync maturin develop --release",
            "",
            "To launch BitChat without triggering an editable rebuild:",
            "  uv run --no-sync bitchat",
        ]
    )
    return "\n".join(lines)


class BuildLockBusyError(RuntimeError):
    """Raised when another BitChat native build already holds the build lock."""


def _acquire_os_lock(fd: int) -> None:
    """Acquire a non-blocking exclusive OS lock on the first byte of ``fd``."""
    os.lseek(fd, 0, os.SEEK_SET)
    if sys.platform == "win32":
        import msvcrt

        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
    else:
        import fcntl

        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)


def _release_os_lock(fd: int) -> None:
    """Release the OS lock held on ``fd``."""
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        if sys.platform == "win32":
            import msvcrt

            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_UN)
    except OSError:
        pass


def _read_lock_owner(lock_path: Path) -> str:
    """Best-effort read of lock metadata (PID/timestamp) for diagnostics."""
    try:
        # Read without blocking via a separate descriptor
        text = lock_path.read_text(encoding="utf-8", errors="replace").strip()
        return text or "unknown process"
    except OSError:
        return "another build process"


@contextmanager
def native_build_lock(
    lock_path: Path = LOCK_FILE_PATH,
    *,
    wait: bool = False,
    timeout_sec: float = 120.0,
) -> Iterator[Path]:
    """Serialize concurrent native extension builds safely across processes.

    Uses OS-managed file locking so interrupted or killed builds never leave
    permanent deadlocks.
    """
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_CREAT | os.O_RDWR
    fd = os.open(str(lock_path), flags, 0o600)
    deadline = time.monotonic() + timeout_sec
    acquired = False

    try:
        while True:
            try:
                _acquire_os_lock(fd)
                acquired = True
                break
            except OSError as exc:
                if not wait or time.monotonic() >= deadline:
                    owner = _read_lock_owner(lock_path)
                    raise BuildLockBusyError(
                        "Another BitChat native extension build is already in progress.\n"
                        f"Lock file: {lock_path}\n"
                        f"Active holder: {owner}\n\n"
                        "Wait for the existing build to finish, or rerun with --wait."
                    ) from exc
                time.sleep(0.25)

        # Record owner info after byte 0 (keeping byte 0 locked cleanly)
        payload = f" pid={os.getpid()} started={time.strftime('%Y-%m-%dT%H:%M:%S')}\n"
        try:
            os.ftruncate(fd, 0)
            os.lseek(fd, 0, os.SEEK_SET)
            os.write(fd, payload.encode("utf-8"))
        except OSError:
            pass

        yield lock_path
    finally:
        if acquired:
            _release_os_lock(fd)
        try:
            os.close(fd)
        except OSError:
            pass
        if acquired:
            try:
                lock_path.unlink(missing_ok=True)
            except OSError:
                pass


def is_windows_copy_lock_error(output: str) -> bool:
    """Detect whether Maturin failed specifically on the Windows file-lock install step."""
    lowered = output.lower()
    return (
        "os error 32" in lowered
        or "being used by another process" in lowered
        or ("failed to copy" in lowered and "_bitchat_core" in lowered)
        or (
            ("os error 5" in lowered or "access is denied" in lowered)
            and ("bitchat.exe" in lowered or "_bitchat_core" in lowered)
        )
    )


def rust_compile_succeeded(output: str) -> bool:
    """Detect whether Cargo reported finishing compilation before Maturin failed."""
    return bool(re.search(r"Finished\s+`[^`]+`\s+profile", output))


def run_maturin_develop(*, release: bool = True, uv_no_sync: bool = True) -> int:
    """Run ``maturin develop`` while capturing output to classify copy-lock errors."""
    cmd = ["uv", "run"]
    if uv_no_sync:
        cmd.append("--no-sync")
    cmd.extend(["maturin", "develop"])
    if release:
        cmd.append("--release")

    print(f"[build_native] Running: {' '.join(cmd)}", flush=True)
    proc = subprocess.run(
        cmd,
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.stdout:
        print(proc.stdout, end="", flush=True)
    if proc.stderr:
        print(proc.stderr, end="", file=sys.stderr, flush=True)

    if proc.returncode == 0:
        return 0

    combined = f"{proc.stdout}\n{proc.stderr}"
    if is_windows_copy_lock_error(combined):
        compiled = rust_compile_succeeded(combined)
        statuses = inspect_extension_locks()
        locked = next((s for s in statuses if s.locked), statuses[0])
        print("\n" + "=" * 72, file=sys.stderr)
        print(
            format_lock_diagnostic(locked, rust_compiled=compiled),
            file=sys.stderr,
        )
        print("=" * 72 + "\n", file=sys.stderr)
        return 32

    return proc.returncode


def verify_native_import() -> int:
    """Verify the compiled native extension imports cleanly in a fresh subprocess."""
    verify_code = (
        "import bitchat, bitchat._bitchat_core as c; "
        "ver = c.native_core_version(); "
        "assert bitchat.__version__ == ver, "
        "f'Version mismatch: {bitchat.__version__} != {ver}'; "
        "print(f'Native Rust extension loaded successfully (bitchat {bitchat.__version__}, _bitchat_core {ver})')"
    )
    proc = subprocess.run(
        ["uv", "run", "--no-sync", "python", "-c", verify_code],
        cwd=str(REPO_ROOT),
        check=False,
    )
    return proc.returncode


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Safe, serialized builder for the BitChat native Rust extension."
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Build in debug profile instead of --release.",
    )
    parser.add_argument(
        "--check-locks",
        action="store_true",
        help="Only inspect whether src/bitchat/_bitchat_core.pyd is locked and exit.",
    )
    parser.add_argument(
        "--wait",
        action="store_true",
        help="Wait for an in-progress native build lock instead of failing immediately.",
    )
    parser.add_argument(
        "--wait-timeout",
        type=float,
        default=120.0,
        help="Seconds to wait when --wait is set (default: 120).",
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Skip post-build subprocess import verification.",
    )
    args = parser.parse_args(argv)

    statuses = inspect_extension_locks()
    locked_statuses = [s for s in statuses if s.locked]

    if args.check_locks:
        if locked_statuses:
            for st in locked_statuses:
                print(format_lock_diagnostic(st), file=sys.stderr)
            return 32
        for st in statuses:
            state = "present, unlocked" if st.exists else "not yet built"
            print(f"[build_native] OK: {st.destination} ({state})")
        return 0

    try:
        with native_build_lock(wait=args.wait, timeout_sec=args.wait_timeout):
            # Re-check locks after acquiring build lock (in case another build just finished)
            statuses = inspect_extension_locks()
            locked_statuses = [s for s in statuses if s.locked]
            if locked_statuses:
                for st in locked_statuses:
                    print(format_lock_diagnostic(st), file=sys.stderr)
                return 32

            rc = run_maturin_develop(release=not args.debug)
            if rc != 0:
                return rc
    except BuildLockBusyError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if not args.no_verify:
        return verify_native_import()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
