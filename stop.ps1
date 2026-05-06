param(
    [int]$Port = 0
)

# stop.ps1 -- tears down a server started via start.ps1 (or run.ps1).
# Order:
#   1. taskkill the PID recorded in .engine.pid (process tree, force).
#   2. Invoke-RepoSweep belt-and-suspenders (catches stragglers + port holders).
#   3. Remove the PID file.
# Idempotent -- safe to run when the engine is already down.

$ErrorActionPreference = 'Stop'
$originalDir = Get-Location

try {
    $root = $PSScriptRoot
    Set-Location $root

    . (Join-Path $root "_engine_lib.ps1")

    Import-DotEnv -Path (Join-Path $root ".env")
    $port = Resolve-EnginePort -ExplicitPort $Port

    $pidFile = Get-EnginePidFilePath -RepoRoot $root
    $killedByPid = $false

    if (Test-Path $pidFile) {
        $pidRaw = (Get-Content -LiteralPath $pidFile -ErrorAction SilentlyContinue | Select-Object -First 1)
        $serverPid = 0
        if ([int]::TryParse($pidRaw, [ref]$serverPid) -and $serverPid -gt 0) {
            $proc = Get-Process -Id $serverPid -ErrorAction SilentlyContinue
            if ($proc) {
                Write-Host "Stopping engine (pid $serverPid)..."
                & taskkill.exe /PID $serverPid /T /F 2>&1 | Out-Null
                $killedByPid = $true
            } else {
                Write-Host "PID file points at $serverPid but no such process -- sweeping anyway."
            }
        } else {
            Write-Warning "PID file '$pidFile' content not parseable: '$pidRaw'"
        }
    } else {
        Write-Host "No PID file at '$pidFile' -- sweeping by port/cmdline only."
    }

    Write-Host "Sweeping repo-bound processes + port $port..."
    Invoke-RepoSweep -RepoRoot $root -PortStr $port

    if (Test-Path $pidFile) {
        Remove-Item -LiteralPath $pidFile -Force -ErrorAction SilentlyContinue
    }

    if ($killedByPid) {
        Write-Host "Engine stopped."
    } else {
        Write-Host "Done."
    }
} finally {
    Set-Location $originalDir
}
