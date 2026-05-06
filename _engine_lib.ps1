# Shared helpers for start.ps1 / stop.ps1 / run.ps1.
# Dot-source from the caller:
#   . (Join-Path $PSScriptRoot "_engine_lib.ps1")
#
# Keep this file dependency-free (no module imports, no external state) so the
# three scripts can be invoked individually without ordering surprises.
#
# Adapted from AiDatabase/_engine_lib.ps1 for LicenseServer:
#   - Module: app.main:app
#   - Health: GET /health
#   - Port env var: APP_PORT, default 8540 (the deployed Docker image uses 8800
#     internally; that's behind Caddy on the VM and never exposed). 8540 is
#     unclaimed by common dev services -- no Ethereum-JSON-RPC (8545) collision.

function Expand-EnvVarRefs {
    # Expand ${VAR} (POSIX, matches python-dotenv) and %VAR% (Windows) against
    # the current process environment. Undefined ${VAR} references are left
    # as-is so a typo surfaces visibly instead of silently turning into "".
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return $Value }
    $Value = [regex]::Replace($Value, '\$\{([A-Za-z_][A-Za-z0-9_]*)\}', {
        param($m)
        $name = $m.Groups[1].Value
        $v = [Environment]::GetEnvironmentVariable($name)
        if ($null -eq $v) { return $m.Value }
        return $v
    })
    $Value = [Environment]::ExpandEnvironmentVariables($Value)
    return $Value
}

function Import-DotEnv {
    # Load KEY=VALUE pairs from a .env file into the current Process env.
    # Strips matched surrounding single/double quotes. Comments (lines starting
    # with #) and lines without `=` are ignored. Idempotent.
    param([string]$Path)
    if (-not (Test-Path $Path)) { return }
    Get-Content $Path | ForEach-Object {
        if ($_ -match "^\s*([^#][^=]*)=(.*)$") {
            $key = $matches[1].Trim()
            $value = $matches[2].Trim()
            if ($value -match '^([^#]*?)\s+#.*$') { $value = $matches[1].Trim() }
            $singleQuoted = $false
            if ($value.Length -ge 2) {
                if ($value.StartsWith("'") -and $value.EndsWith("'")) {
                    $value = $value.Substring(1, $value.Length - 2)
                    $singleQuoted = $true
                } elseif ($value.StartsWith('"') -and $value.EndsWith('"')) {
                    $value = $value.Substring(1, $value.Length - 2)
                }
            }
            if (-not $singleQuoted) {
                $value = Expand-EnvVarRefs -Value $value
            }
            [System.Environment]::SetEnvironmentVariable($key, $value, "Process")
        }
    }
}

function Resolve-EnginePort {
    # Resolution order: explicit -Port arg > $env:APP_PORT > default 8540.
    # Returns a string (uvicorn arg form).
    param([int]$ExplicitPort = 0)
    if ($ExplicitPort -gt 0) { return "$ExplicitPort" }
    if ($env:APP_PORT)       { return $env:APP_PORT }
    return "8540"
}

function Get-EnginePidFilePath {
    # Single source of truth for the PID file path. start.ps1 writes it,
    # stop.ps1 + run.ps1 watchdog read it. Lives in repo root, gitignored.
    param([string]$RepoRoot)
    return (Join-Path $RepoRoot ".engine.pid")
}

function Get-EngineLogFilePath {
    # Engine stdout+stderr log when launched detached. Under logs/ which we
    # gitignore.
    param([string]$RepoRoot)
    $logsDir = Join-Path $RepoRoot "logs"
    if (-not (Test-Path $logsDir)) { New-Item -ItemType Directory -Path $logsDir -Force | Out-Null }
    return (Join-Path $logsDir "engine.log")
}

function Wait-EngineReady {
    # Poll /health until FastAPI reports 200, the uvicorn process exits, or
    # the timeout fires. Returns $true on ready, $false otherwise.
    param(
        [int]$ServerPid,
        [string]$PortStr,
        [int]$TimeoutSec = 15,
        [int]$PollMs = 400
    )
    $url = "http://localhost:$PortStr/health"
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSec)
    while ([DateTime]::UtcNow -lt $deadline) {
        if ($ServerPid -gt 0) {
            $proc = Get-Process -Id $ServerPid -ErrorAction SilentlyContinue
            if (-not $proc) { return $false }
        }
        try {
            $resp = Invoke-WebRequest -Uri $url -Method Get -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop
            if ([int]$resp.StatusCode -eq 200) { return $true }
        } catch {
            # Connection refused / timeout / 5xx -- keep polling until deadline.
        }
        Start-Sleep -Milliseconds $PollMs
    }
    return $false
}

function Get-EngineLogTail {
    # Returns the last $Lines lines from engine.log + engine.log.err for
    # diagnostics on failed starts.
    param([string]$RepoRoot, [int]$Lines = 30)
    $logPath = Get-EngineLogFilePath -RepoRoot $RepoRoot
    $errPath = $logPath + ".err"
    $sb = New-Object System.Text.StringBuilder
    foreach ($p in @(@($logPath, 'engine.log'), @($errPath, 'engine.log.err'))) {
        if (Test-Path $p[0]) {
            [void]$sb.AppendLine("--- $($p[1]) (tail $Lines) ---")
            Get-Content -LiteralPath $p[0] -Tail $Lines -ErrorAction SilentlyContinue | ForEach-Object {
                [void]$sb.AppendLine($_)
            }
        }
    }
    return $sb.ToString().TrimEnd()
}

$script:RepoSweepProtectedNames = @(
    'docker', 'Docker Desktop', 'com.docker.backend', 'com.docker.build',
    'com.docker.cli', 'com.docker.dev-envs', 'com.docker.diagnose',
    'com.docker.extensions', 'com.docker.proxy', 'com.docker.service',
    'docker-agent', 'docker-credential-desktop', 'docker-credential-wincred',
    'docker-sandbox', 'dockerd', 'vpnkit', 'wsl', 'wslhost', 'wslrelay',
    'wslservice', 'vmmemWSL', 'WslService'
)

function Invoke-SafeTaskKill {
    # taskkill /T /F unless ProcessName matches a Docker/WSL infra process.
    param([int]$ProcessIdToKill, [string]$Why)
    if ($ProcessIdToKill -le 0 -or $ProcessIdToKill -eq $PID) { return }
    $p = Get-Process -Id $ProcessIdToKill -ErrorAction SilentlyContinue
    if (-not $p) { return }
    foreach ($protected in $script:RepoSweepProtectedNames) {
        if ($p.ProcessName -ieq $protected) {
            Write-Warning "Invoke-RepoSweep: SKIP pid=$ProcessIdToKill name=$($p.ProcessName) reason=$Why - protected (Docker/WSL infra)"
            return
        }
    }
    $cmd = $null
    try { $cmd = (Get-CimInstance Win32_Process -Filter "ProcessId=$ProcessIdToKill" -ErrorAction SilentlyContinue).CommandLine } catch {}
    Write-Verbose "Invoke-RepoSweep: KILL pid=$ProcessIdToKill name=$($p.ProcessName) reason=$Why cmd=$cmd"
    & taskkill.exe /PID $ProcessIdToKill /T /F 2>&1 | Out-Null
}

function Invoke-RepoSweep {
    # Kills the API instance bound to a SPECIFIC port and anything holding
    # that port. PORT-SCOPED: a sibling LicenseServer instance on a different
    # port survives. Loops up to $MaxAttempts times waiting briefly between
    # iterations until the port is free.
    #
    # SAFETY: every taskkill goes through Invoke-SafeTaskKill which refuses to
    # touch Docker/WSL infra PIDs.
    param([string]$RepoRoot, [string]$PortStr, [int]$MaxAttempts = 6)
    $portToken = "*--port $PortStr*"
    for ($i = 0; $i -lt $MaxAttempts; $i++) {
        Get-CimInstance Win32_Process `
            -Filter "Name='python.exe' OR Name='uvicorn.exe'" `
            -ErrorAction SilentlyContinue |
            Where-Object {
                $_.ProcessId -ne $PID -and $_.CommandLine -and
                ($_.CommandLine -like "*$RepoRoot*" -or $_.CommandLine -like "*app.main:app*") -and
                $_.CommandLine -like $portToken
            } | ForEach-Object {
                Invoke-SafeTaskKill -ProcessIdToKill $_.ProcessId -Why "cmdline-matches-repo-and-port-$PortStr"
            }
        # Catch --reload worker children whose own cmdline may not match. Scope
        # to children whose PARENT is bound to $PortStr -- that way an instance
        # on a different port keeps its workers.
        Get-CimInstance Win32_Process -Filter "Name='python.exe'" -ErrorAction SilentlyContinue |
            ForEach-Object {
                $parent = Get-CimInstance Win32_Process -Filter "ProcessId=$($_.ParentProcessId)" -ErrorAction SilentlyContinue
                if ($parent -and $parent.CommandLine -and
                    ($parent.CommandLine -like "*app.main:app*" -or $parent.CommandLine -like "*$RepoRoot*") -and
                    $parent.CommandLine -like $portToken) {
                    Invoke-SafeTaskKill -ProcessIdToKill $_.ProcessId -Why "parent-cmdline-matches-repo-and-port-$PortStr"
                }
            }
        # Port-holder sweep -- by PID regardless of cmdline.
        $holders = @()
        try {
            $holders = @(Get-NetTCPConnection -LocalPort $PortStr -State Listen -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty OwningProcess -Unique |
                Where-Object { $_ -and $_ -ne 0 -and $_ -ne $PID })
        } catch {}
        if ($holders.Count -eq 0) { return }
        $allProtected = $true
        $holderDetail = @()
        foreach ($pidHolder in $holders) {
            $p = Get-Process -Id $pidHolder -ErrorAction SilentlyContinue
            $name = if ($p) { $p.ProcessName } else { '<unknown>' }
            $isProt = $false
            foreach ($protected in $script:RepoSweepProtectedNames) {
                if ($p -and $p.ProcessName -ieq $protected) { $isProt = $true; break }
            }
            if (-not $isProt) { $allProtected = $false }
            $holderDetail += "  - PID $pidHolder $name$( if ($isProt) { ' (protected)' } else { '' })"
        }
        if ($allProtected) {
            $hint = "docker ps --filter publish=$PortStr"
            $msg = "Port $PortStr is held only by protected (Docker/WSL) processes -- cannot be freed by sweep:`n" +
                   ($holderDetail -join "`n") + "`n" +
                   "Likely cause: a Docker container is forwarding -p $($PortStr):$($PortStr). Free the port (e.g. '$hint', then 'docker stop NAME') or set APP_PORT=NNNN in .env, then retry."
            throw $msg
        }
        foreach ($pidHolder in $holders) {
            Invoke-SafeTaskKill -ProcessIdToKill $pidHolder -Why "port-$PortStr-holder"
        }
        Start-Sleep -Milliseconds 300
    }
}
