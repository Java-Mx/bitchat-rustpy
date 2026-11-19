"""Tests for safe Windows native extension lock detection, diagnostics, and serialization."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from types import ModuleType

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
BUILD_SCRIPT = REPO_ROOT / "scripts" / "build_native.py"
PS_DEV_SCRIPT = REPO_ROOT / "scripts" / "dev-windows.ps1"


def _load_build_native() -> ModuleType:
    spec = importlib.util.spec_from_file_location("bitchat_build_native", BUILD_SCRIPT)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["bitchat_build_native"] = mod
    spec.loader.exec_module(mod)
    return mod


def test_scripts_exist() -> None:
    assert BUILD_SCRIPT.is_file()
    assert PS_DEV_SCRIPT.is_file()


def test_error_classification_distinguishes_copy_lock_from_rust_compile_error() -> None:
    mod = _load_build_native()

    maturin_lock_stderr = (
        "   Compiling pyo3 v0.24.2\n"
        "   Compiling bitchat-core v0.3.3\n"
        "    Finished `release` profile [optimized] target(s) in 12.34s\n"
        "💥 maturin failed\n"
        "  Caused by: Failed to add the files to the wheel\n"
        "  Caused by: Failed to copy D:\\bitchat-python\\target\\maturin\\_bitchat_core.dll "
        "to D:\\bitchat-python\\src\\bitchat\\_bitchat_core.pyd\n"
        "  Caused by: The process cannot access the file because it is being used by another process. (os error 32)\n"
    )
    assert mod.is_windows_copy_lock_error(maturin_lock_stderr) is True
    assert mod.rust_compile_succeeded(maturin_lock_stderr) is True

    uv_launcher_lock_stderr = (
        "    Finished `release` profile [optimized] target(s) in 2m 10s\n"
        "💥 maturin failed\n"
        "error: failed to remove file `D:\\bitchat-python\\.venv\\Lib\\site-packages\\../../Scripts/bitchat.exe`: Access is denied. (os error 5)\n"
    )
    assert mod.is_windows_copy_lock_error(uv_launcher_lock_stderr) is True
    assert mod.rust_compile_succeeded(uv_launcher_lock_stderr) is True

    real_compile_err = (
        "error[E0308]: mismatched types\n"
        "  --> rust/bitchat-core/src/lib.rs:10:5\n"
        "error: could not compile `bitchat-core` due to 1 previous error\n"
    )
    assert mod.is_windows_copy_lock_error(real_compile_err) is False
    assert mod.rust_compile_succeeded(real_compile_err) is False


def test_build_lock_rejects_concurrent_and_cleans_up_on_exception(
    tmp_path: Path,
) -> None:
    mod = _load_build_native()
    lock_file = tmp_path / ".test-native-build.lock"

    # Non-waiting second caller must be rejected cleanly while lock is held.
    with (
        mod.native_build_lock(lock_file, wait=False),
        pytest.raises(mod.BuildLockBusyError, match="already in progress"),
        mod.native_build_lock(lock_file, wait=False),
    ):
        pass

    # Lock file must be cleaned up on normal exit.
    assert not lock_file.exists()

    # Lock file must also be released and cleaned up if an exception occurs mid-build.
    with (
        pytest.raises(RuntimeError, match="boom"),
        mod.native_build_lock(lock_file, wait=False),
    ):
        raise RuntimeError("boom")
    assert not lock_file.exists()


def test_build_lock_waits_for_concurrent_holder(tmp_path: Path) -> None:
    mod = _load_build_native()
    lock_file = tmp_path / ".test-wait-build.lock"
    events: list[str] = []

    def holder() -> None:
        with mod.native_build_lock(lock_file, wait=False):
            events.append("holder_acquired")
            time.sleep(0.4)
            events.append("holder_releasing")

    t = threading.Thread(target=holder)
    t.start()

    # Wait until holder has acquired the lock.
    deadline = time.monotonic() + 5.0
    while "holder_acquired" not in events and time.monotonic() < deadline:
        time.sleep(0.02)

    assert "holder_acquired" in events

    with mod.native_build_lock(lock_file, wait=True, timeout_sec=5.0):
        events.append("waiter_acquired")

    t.join(timeout=5.0)
    assert events == ["holder_acquired", "holder_releasing", "waiter_acquired"]
    assert not lock_file.exists()


def test_format_lock_diagnostic_contains_required_actionable_fields() -> None:
    mod = _load_build_native()
    status = mod.ExtensionLockStatus(
        destination=REPO_ROOT / "src" / "bitchat" / "_bitchat_core.pyd",
        exists=True,
        locked=True,
        win_error=32,
        locking_processes=(
            mod.LockingProcess(
                pid=42424,
                name="python.exe",
                command_line="python.exe -m bitchat",
                source="restart_manager",
            ),
        ),
    )
    msg = mod.format_lock_diagnostic(status, rust_compiled=True)
    assert "Native Rust extension replacement failed." in msg
    assert "Rust compilation SUCCEEDED" in msg
    assert "src/bitchat/_bitchat_core.pyd" in msg
    assert "currently loaded by another process" in msg
    assert "PID 42424" in msg
    assert "uv run --no-sync maturin develop --release" in msg
    assert "uv run --no-sync bitchat" in msg


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only .pyd file lock test")
def test_windows_live_pyd_lock_detection_and_release() -> None:
    """Reproduce a real Windows .pyd lock using a child process loading _bitchat_core."""
    mod = _load_build_native()
    pyd_path = REPO_ROOT / "src" / "bitchat" / "_bitchat_core.pyd"
    if not pyd_path.exists():
        pytest.skip("Editable _bitchat_core.pyd is not present in src/bitchat")

    was_already_locked_before = any(s.locked for s in mod.inspect_extension_locks())

    # Spawn a real child Python process that loads src/bitchat/_bitchat_core.pyd
    # and holds it mapped in memory until stdin closes.
    # Note: on Windows venvs, .venv/Scripts/python.exe is a redirector launcher
    # whose child process (os.getpid() inside the script) actually maps the .pyd.
    holder_script = (
        "import os, sys, bitchat._bitchat_core as c; "
        "print(f'LOADED:{os.getpid()}:{c.__file__}', flush=True); "
        "sys.stdin.read()"
    )
    proc = subprocess.Popen(
        [sys.executable, "-c", holder_script],
        cwd=str(REPO_ROOT),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    actual_pid: int | None = None
    try:
        assert proc.stdout is not None
        ready_line = proc.stdout.readline().strip()
        assert ready_line.startswith("LOADED:"), f"Child failed to load: {ready_line}"

        _, pid_str, file_str = ready_line.split(":", 2)
        actual_pid = int(pid_str)
        loaded_path = Path(file_str).resolve()
        assert loaded_path == pyd_path.resolve(), (
            f"Expected editable {pyd_path}, got {loaded_path}"
        )

        statuses = mod.inspect_extension_locks()
        pyd_status = next(
            s for s in statuses if s.destination.resolve() == pyd_path.resolve()
        )
        assert pyd_status.locked, (
            "Expected _bitchat_core.pyd to be reported locked while child holds it"
        )
        assert pyd_status.win_error in (32, 33, 5)
        detected_pids = {p.pid for p in pyd_status.locking_processes}
        assert actual_pid in detected_pids, (
            f"Expected Restart Manager to detect real Python PID {actual_pid}, got {detected_pids}"
        )

        # CLI pre-flight check must fail with code 32 and actionable diagnostic (not crash).
        check_proc = subprocess.run(
            [sys.executable, str(BUILD_SCRIPT), "--check-locks"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        assert check_proc.returncode == 32
        assert "Native Rust extension replacement failed." in check_proc.stderr
        assert str(actual_pid) in check_proc.stderr
    finally:
        if proc.stdin is not None:
            proc.stdin.close()
        proc.wait(timeout=10)

    # Once the child process exits, it must no longer hold a lock on _bitchat_core.pyd.
    statuses_after = mod.inspect_extension_locks()
    remaining_pids = {p.pid for s in statuses_after for p in s.locking_processes}
    assert actual_pid not in remaining_pids, (
        f"Exited child PID {actual_pid} still reported as locking _bitchat_core.pyd"
    )
    if not was_already_locked_before and "bitchat._bitchat_core" not in sys.modules:
        assert not any(s.locked for s in statuses_after), (
            "Expected _bitchat_core.pyd to be unlocked after child process exited"
        )
