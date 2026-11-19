<#
.SYNOPSIS
    Reliable Windows PowerShell 5.1 development workflow for BitChat RustPy.

.DESCRIPTION
    Separates building the native Rust extension (`bitchat._bitchat_core`) from
    launching BitChat so Windows `.pyd` file locks (os error 32) are diagnosed
    clearly with exact locking process details instead of failing mid-build.

    Compatible with Windows PowerShell 5.1 and PowerShell 7+.

.PARAMETER Action
    Workflow step to execute:
      - Build        : Check locks, serialize build, run `maturin develop --release`, verify import.
      - Verify       : Verify `bitchat._bitchat_core` loads cleanly in a fresh Python process.
      - Run          : Launch BitChat via `uv run --no-sync bitchat` (never triggers an accidental rebuild).
      - BuildAndRun  : Run Build, then Run.
      - CheckLocks   : Inspect `src\bitchat\_bitchat_core.pyd` lock status and list locking processes.
      - CloseBitChat : Safely inspect and (with confirmation) close ONLY verified BitChat processes
                       currently holding `src\bitchat\_bitchat_core.pyd`. Never terminates unrelated Python processes.

.PARAMETER Wait
    Wait if another native build is currently holding the build lock.

.PARAMETER Force
    Skip interactive confirmation for -Action CloseBitChat (still restricts strictly to verified BitChat processes).

.PARAMETER AppArgs
    Additional arguments forwarded to `bitchat` when using `-Action Run` or `-Action BuildAndRun`.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\dev-windows.ps1 -Action Build

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\dev-windows.ps1 -Action Run -AppArgs @('--version')

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\dev-windows.ps1 -Action CheckLocks
#>
[CmdletBinding()]
param(
    [ValidateSet('Build', 'Verify', 'Run', 'BuildAndRun', 'CheckLocks', 'CloseBitChat')]
    [string]$Action = 'Build',

    [switch]$Wait,

    [switch]$Force,

    [string[]]$AppArgs = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$PydPath = Join-Path $RepoRoot 'src\bitchat\_bitchat_core.pyd'

function Show-CandidateProcesses {
    Write-Host ''
    Write-Host 'Running Python / BitChat / uv processes:' -ForegroundColor Cyan
    $procs = Get-CimInstance Win32_Process |
        Where-Object { $_.Name -match '^(python|pythonw|bitchat|uv)\.exe$' } |
        Select-Object ProcessId, ParentProcessId, Name, CommandLine
    if ($procs) {
        $procs | Format-Table -AutoSize -Wrap
    } else {
        Write-Host '  (none found)'
    }
}

function Invoke-Build {
    Push-Location $RepoRoot
    try {
        $pyArgs = @('run', '--no-sync', 'python', 'scripts/build_native.py')
        if ($Wait) {
            $pyArgs += '--wait'
        }
        & uv @pyArgs
        $code = $LASTEXITCODE
        if ($code -ne 0) {
            exit $code
        }
    } finally {
        Pop-Location
    }
}

function Invoke-Verify {
    Push-Location $RepoRoot
    try {
        & uv run --no-sync python -c "import bitchat, bitchat._bitchat_core as c; v = c.native_core_version(); assert bitchat.__version__ == v; print('Native Rust extension loaded successfully (bitchat ' + bitchat.__version__ + ', _bitchat_core ' + v + ')')"
        $code = $LASTEXITCODE
        if ($code -ne 0) {
            exit $code
        }
    } finally {
        Pop-Location
    }
}

function Invoke-Run {
    Push-Location $RepoRoot
    try {
        $uvArgs = @('run', '--no-sync', 'bitchat') + $AppArgs
        & uv @uvArgs
        $code = $LASTEXITCODE
        if ($code -ne 0) {
            exit $code
        }
    } finally {
        Pop-Location
    }
}

function Invoke-CheckLocks {
    Push-Location $RepoRoot
    try {
        & uv run --no-sync python scripts/build_native.py --check-locks
        $code = $LASTEXITCODE
        Show-CandidateProcesses
        if ($code -ne 0) {
            exit $code
        }
    } finally {
        Pop-Location
    }
}

function Invoke-CloseVerifiedBitChat {
    Push-Location $RepoRoot
    try {
        $inspectCode = @"
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path('scripts').resolve()))
import build_native
statuses = build_native.inspect_extension_locks()
out = []
for st in statuses:
    if st.locked:
        for p in st.locking_processes:
            out.append({'pid': p.pid, 'name': p.name, 'command_line': p.command_line or '', 'source': p.source})
print(json.dumps(out))
"@
        $raw = & uv run --no-sync python -c $inspectCode
        if ($LASTEXITCODE -ne 0) {
            Write-Error 'Failed to inspect locking processes.'
            exit 1
        }
        $locking = @()
        if ($raw) {
            $parsed = $raw | ConvertFrom-Json
            if ($parsed -is [System.Array]) {
                $locking = $parsed
            } elseif ($null -ne $parsed) {
                $locking = @($parsed)
            }
        }

        if ($locking.Count -eq 0) {
            Write-Host "No process is currently locking $PydPath." -ForegroundColor Green
            return
        }

        $repoLower = $RepoRoot.ToLowerInvariant()
        foreach ($entry in $locking) {
            $pidVal = [int]$entry.pid
            $nameVal = [string]$entry.name
            $cmdVal = [string]$entry.command_line
            $cmdLower = $cmdVal.ToLowerInvariant()

            $isVerifiedBitChat = (
                ($entry.source -eq 'restart_manager') -and
                (
                    ($nameVal.ToLowerInvariant() -eq 'bitchat.exe') -or
                    ($cmdLower.Contains('bitchat')) -or
                    ($cmdLower.Contains($repoLower))
                )
            )

            if (-not $isVerifiedBitChat) {
                Write-Warning "Skipping PID $pidVal ($nameVal) because it could not be verified as a BitChat development process for this repository. Close it manually if appropriate."
                continue
            }

            Write-Host "Verified locking BitChat process:" -ForegroundColor Yellow
            Write-Host "  PID     : $pidVal"
            Write-Host "  Name    : $nameVal"
            Write-Host "  Command : $cmdVal"

            $proceed = $Force.IsPresent
            if (-not $proceed) {
                $answer = Read-Host "Close PID $pidVal? [y/N]"
                $proceed = ($answer -match '^(y|yes)$')
            }

            if ($proceed) {
                Stop-Process -Id $pidVal -ErrorAction Stop
                Write-Host "Closed PID $pidVal cleanly." -ForegroundColor Green
            } else {
                Write-Host "Skipped PID $pidVal."
            }
        }
    } finally {
        Pop-Location
    }
}

switch ($Action) {
    'Build'        { Invoke-Build }
    'Verify'       { Invoke-Verify }
    'Run'          { Invoke-Run }
    'BuildAndRun'  { Invoke-Build; Invoke-Run }
    'CheckLocks'   { Invoke-CheckLocks }
    'CloseBitChat' { Invoke-CloseVerifiedBitChat }
}
