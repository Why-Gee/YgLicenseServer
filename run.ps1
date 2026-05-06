param(
    [int]$Port = 0,
    [switch]$Reload,
    # Skip opening the browser -- useful when running headless / from CI.
    [switch]$NoBrowser
)

# run.ps1 -- foreground "session" wrapper around start.ps1 + stop.ps1.
# The admin UI is served by FastAPI itself (Jinja templates at /admin), so
# unlike AiDatabase there's no separate UI dev server to manage.
#   1. start.ps1 -- bootstrap + launch detached uvicorn
#   2. open the admin UI in the default browser
#   3. spawn watchdog so the engine is killed if this script dies unexpectedly
#   4. tail logs/engine.log to the console; Ctrl+C exits the tail
#   5. stop.ps1 on exit (Ctrl+C, normal exit, trap)

$ErrorActionPreference = 'Stop'
$originalDir = Get-Location

try {
    $root = $PSScriptRoot
    Set-Location $root

    . (Join-Path $root "_engine_lib.ps1")

    # Initialize $cleanup early so the trap below (declared at parse time,
    # active for the entire try-block scope) can reference it safely even
    # when a failure aborts before the real cleanup is wired up.
    $cleanup = $null

    # ── 1. start engine ──────────────────────────────────────────────────────
    $startArgs = @()
    if ($Port -gt 0) { $startArgs += @('-Port', $Port) }
    if ($Reload)     { $startArgs += '-Reload' }
    & (Join-Path $root "start.ps1") @startArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Error "start.ps1 failed (exit $LASTEXITCODE)."
        exit $LASTEXITCODE
    }

    Import-DotEnv -Path (Join-Path $root ".env")
    $port    = Resolve-EnginePort -ExplicitPort $Port
    $pidFile = Get-EnginePidFilePath -RepoRoot $root
    $logPath = Get-EngineLogFilePath -RepoRoot $root
    $serverPid = 0
    if (Test-Path $pidFile) {
        [int]::TryParse((Get-Content -LiteralPath $pidFile | Select-Object -First 1), [ref]$serverPid) | Out-Null
    }
    if ($serverPid -le 0) {
        Write-Error "start.ps1 returned but no valid PID at $pidFile. Aborting."
        exit 1
    }

    # ── 2. open browser ──────────────────────────────────────────────────────
    $browserJob = $null
    if (-not $NoBrowser) {
        $url = "http://localhost:$port/admin"
        $browserJob = Start-Job -ScriptBlock {
            param($u) Start-Sleep -Seconds 1; Start-Process $u
        } -ArgumentList $url
    }

    # ── 3. watchdog ──────────────────────────────────────────────────────────
    # Detached PS process polls our PID; when we die (any cause) it sweeps the
    # engine tree + repo-bound python + port holders. Idempotent with the
    # cleanup hook -- whichever runs first makes the other a no-op.
    $wdPath = Join-Path $env:TEMP ("ls_watchdog_{0}.ps1" -f $PID)
    $wdBody = @'
param(
    [int]$ParentPid,
    [int]$ServerPid,
    [string]$RepoRoot,
    [string]$PortStr,
    [string]$SelfPath,
    [string]$PidFile
)
$ErrorActionPreference = 'SilentlyContinue'
try {
    try {
        $pp = [System.Diagnostics.Process]::GetProcessById($ParentPid)
        $pp.WaitForExit()
    } catch {
        # Parent already gone -- fall through to sweep.
    }
    $portToken = "*--port $PortStr*"
    for ($i = 0; $i -lt 6; $i++) {
        if ($ServerPid -gt 0) { & taskkill.exe /PID $ServerPid /T /F 2>&1 | Out-Null }
        Get-CimInstance Win32_Process -Filter "Name='python.exe' OR Name='uvicorn.exe'" -ErrorAction SilentlyContinue |
            Where-Object {
                if (-not $_.CommandLine) { return $false }
                ($_.CommandLine -like "*$RepoRoot*" -or $_.CommandLine -like "*app.main:app*") -and
                ($_.CommandLine -like $portToken)
            } | ForEach-Object {
                & taskkill.exe /PID $_.ProcessId /T /F 2>&1 | Out-Null
            }
        $holders = @()
        try {
            $holders = @(Get-NetTCPConnection -LocalPort $PortStr -State Listen -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty OwningProcess -Unique |
                Where-Object { $_ -and $_ -ne 0 })
        } catch {}
        if ($holders.Count -eq 0) { break }
        foreach ($pidHolder in $holders) {
            & taskkill.exe /PID $pidHolder /T /F 2>&1 | Out-Null
        }
        Start-Sleep -Milliseconds 300
    }
    if ($PidFile) { Remove-Item -LiteralPath $PidFile -Force -ErrorAction SilentlyContinue }
} finally {
    Remove-Item -LiteralPath $SelfPath -Force -ErrorAction SilentlyContinue
}
'@
    Set-Content -LiteralPath $wdPath -Value $wdBody -Encoding UTF8

    $wdArgs = @(
        '-NoProfile','-NoLogo','-ExecutionPolicy','Bypass',
        '-File', $wdPath,
        '-ParentPid', $PID,
        '-ServerPid', $serverPid,
        '-RepoRoot', $root,
        '-PortStr', $port,
        '-SelfPath', $wdPath,
        '-PidFile', $pidFile
    )
    $wdProc = Start-Process -FilePath powershell.exe -ArgumentList $wdArgs `
        -WindowStyle Hidden -PassThru
    Write-Host "Watchdog pid: $($wdProc.Id) (parent=$PID, server=$serverPid)"

    # ── 5. cleanup hook ──────────────────────────────────────────────────────
    $script:Cleaned = $false
    $cleanup = {
        if ($script:Cleaned) { return }
        $script:Cleaned = $true

        Write-Host "`nStopping engine via stop.ps1..."
        try {
            & (Join-Path $root "stop.ps1") -Port ([int]$port)
        } catch {
            Write-Warning "stop.ps1 raised: $($_.Exception.Message)"
        }

        if ($browserJob) {
            Stop-Job  -Job $browserJob -ErrorAction SilentlyContinue
            Remove-Job -Job $browserJob -Force -ErrorAction SilentlyContinue
        }
        if ($wdProc -and -not $wdProc.HasExited) {
            Stop-Process -Id $wdProc.Id -Force -ErrorAction SilentlyContinue
        }
        if ($wdPath) {
            Remove-Item -LiteralPath $wdPath -Force -ErrorAction SilentlyContinue
        }
    }

    trap { if ($cleanup) { & $cleanup }; break }

    # ── 4. tail log ──────────────────────────────────────────────────────────
    Write-Host "Tailing $logPath (Ctrl+C to stop)..."
    try {
        $deadline = (Get-Date).AddSeconds(5)
        while (-not (Test-Path $logPath) -and (Get-Date) -lt $deadline) {
            Start-Sleep -Milliseconds 200
        }
        if (Test-Path $logPath) {
            Get-Content -LiteralPath $logPath -Wait -Tail 50 | ForEach-Object {
                Write-Host $_
                $proc = Get-Process -Id $serverPid -ErrorAction SilentlyContinue
                if (-not $proc) {
                    Write-Warning "Server process $serverPid is gone -- exiting tail."
                    break
                }
            }
        } else {
            Write-Warning "Log file did not appear within 5s. Falling back to PID poll."
            while ($true) {
                $proc = Get-Process -Id $serverPid -ErrorAction SilentlyContinue
                if (-not $proc) { break }
                Start-Sleep -Seconds 1
            }
        }
    } finally {
        & $cleanup
    }
} finally {
    Set-Location $originalDir
}
