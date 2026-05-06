param(
    [int]$Port = 0,
    # --reload spawns watchfiles + worker children, which complicates clean
    # shutdown on Windows. Off by default; pass -Reload to opt in.
    [switch]$Reload
)

# start.ps1 -- bootstrap deps, validate config, launch uvicorn detached so this
# script can return while the API keeps serving. Use stop.ps1 to tear it down.
# run.ps1 wraps both for a foreground-style session.

$ErrorActionPreference = 'Stop'
$originalDir = Get-Location

try {
    $root = $PSScriptRoot
    Set-Location $root

    . (Join-Path $root "_engine_lib.ps1")

    $pip    = Join-Path $root ".venv\Scripts\pip.exe"
    $python = Join-Path $root ".venv\Scripts\python.exe"

    if (-not (Test-Path $python)) {
        Write-Host "Creating .venv..."
        & python -m venv (Join-Path $root ".venv")
    }

    Write-Host "Installing dependencies..."
    & $pip install -e ".[dev]" --quiet

    Import-DotEnv -Path (Join-Path $root ".env")

    # ── Pre-flight checks ────────────────────────────────────────────────────
    $errors = @()
    $warnings = @()

    if ([string]::IsNullOrWhiteSpace($env:ADMIN_TOKEN)) {
        $errors += "ADMIN_TOKEN is not set. Generate one with:`n" +
                   "  python -c `"import secrets; print(secrets.token_urlsafe(32))`"`n" +
                   "Then add to .env: ADMIN_TOKEN=<value>"
    } elseif ($env:ADMIN_TOKEN.Length -lt 16) {
        $errors += "ADMIN_TOKEN must be at least 16 chars (anything shorter is brute-forceable)."
    } elseif ($env:ADMIN_TOKEN.Length -lt 32) {
        $warnings += "ADMIN_TOKEN is shorter than 32 chars; consider regenerating."
    }

    if ([string]::IsNullOrWhiteSpace($env:SESSION_SECRET)) {
        $warnings += "SESSION_SECRET is not set. Falling back to ADMIN_TOKEN -- fine for dev, set a distinct value for prod."
    }

    # COOKIE_SECURE=true (default) makes the admin session cookie HTTPS-only.
    # Local dev runs over http://localhost so the cookie won't stick -- login
    # appears to "succeed" but the dashboard kicks back to /admin/login.
    if ($env:COOKIE_SECURE -ne "false") {
        $warnings += "COOKIE_SECURE is unset/true -- admin UI session cookies require HTTPS. For local http://localhost set COOKIE_SECURE=false in .env."
    }

    if (-not $env:DATABASE_URL) {
        $warnings += "DATABASE_URL unset -- defaulting to sqlite:///./license.db"
    }

    # Email is optional; warn only if half-configured.
    if ($env:RESEND_API_KEY -and -not $env:EMAIL_FROM) {
        $warnings += "RESEND_API_KEY set but EMAIL_FROM unset -- defaulting sender to onboarding@resend.dev (Resend test address)."
    }

    foreach ($w in $warnings) { Write-Warning $w }
    if ($errors.Count -gt 0) {
        foreach ($e in $errors) { Write-Error $e }
        exit 1
    }

    $host_ = if ($env:APP_HOST) { $env:APP_HOST } else { "127.0.0.1" }
    $port  = Resolve-EnginePort -ExplicitPort $Port
    $level = if ($env:LOG_LEVEL) { $env:LOG_LEVEL } else { "info" }

    Write-Host "Pre-start cleanup..."
    Invoke-RepoSweep -RepoRoot $root -PortStr $port

    # ── Feature summary ──────────────────────────────────────────────────────
    $features = @()
    $dbType = if ($env:DATABASE_URL) {
        if ($env:DATABASE_URL.StartsWith("sqlite")) { "sqlite" }
        elseif ($env:DATABASE_URL.StartsWith("postgres")) { "postgres" }
        else { "custom" }
    } else { "sqlite (default)" }
    $features += "DB: $dbType"
    if ($env:RESEND_API_KEY)  { $features += "email: Resend ($($env:EMAIL_FROM))" }
    else                       { $features += "email: disabled (no RESEND_API_KEY)" }
    $features += "cookie_secure: $(if ($env:COOKIE_SECURE -eq 'false') { 'OFF (dev)' } else { 'on' })"
    if ($env:APP_ENV)         { $features += "env: $($env:APP_ENV)" }
    Write-Host ("Features: " + ($features -join ", "))

    Write-Host "Starting server on ${host_}:${port}..."

    # Launch uvicorn detached + wait for /health 200. Retry once: stale SQLite
    # locks, port still in TIME_WAIT, etc. usually clear after a sweep + delay.
    $logPath = Get-EngineLogFilePath -RepoRoot $root
    $pidFile = Get-EnginePidFilePath -RepoRoot $root
    $uvicornArgs = @(
        '-m', 'uvicorn',
        'app.main:app',
        '--host', $host_,
        '--port', $port,
        '--log-level', $level
    )
    if ($Reload) { $uvicornArgs += '--reload' }

    $maxAttempts = 2
    $readyTimeoutSec = 20
    $serverProc = $null
    $ready = $false
    $startTs = [DateTime]::UtcNow
    for ($attempt = 1; $attempt -le $maxAttempts -and -not $ready; $attempt++) {
        if ($attempt -gt 1) {
            Write-Warning "Engine not ready after attempt $($attempt - 1). Sweeping + retrying."
            Invoke-RepoSweep -RepoRoot $root -PortStr $port
            Start-Sleep -Milliseconds 500
        }
        $serverProc = Start-Process `
            -FilePath $python `
            -ArgumentList $uvicornArgs `
            -WindowStyle Hidden `
            -RedirectStandardOutput $logPath `
            -RedirectStandardError  ($logPath + ".err") `
            -PassThru
        $ready = Wait-EngineReady -ServerPid $serverProc.Id -PortStr $port -TimeoutSec $readyTimeoutSec
        if (-not $ready) {
            Write-Host "--- attempt $attempt diagnostic ---"
            Write-Host (Get-EngineLogTail -RepoRoot $root -Lines 30)
            if ($serverProc -and (Get-Process -Id $serverProc.Id -ErrorAction SilentlyContinue)) {
                & taskkill.exe /PID $serverProc.Id /T /F 2>&1 | Out-Null
            }
            $serverProc = $null
        }
    }

    if (-not $ready -or -not $serverProc) {
        if (Test-Path $pidFile) { Remove-Item -LiteralPath $pidFile -Force -ErrorAction SilentlyContinue }
        Write-Error "Engine failed to become ready after $maxAttempts attempts."
        exit 1
    }

    Set-Content -LiteralPath $pidFile -Value $serverProc.Id -Encoding ASCII

    $readyElapsed = [int]([DateTime]::UtcNow - $startTs).TotalSeconds
    Write-Host "Server pid: $($serverProc.Id) | port: $port | log: $logPath | ready in ${readyElapsed}s"
    Write-Host "Health: http://localhost:$port/health"
    Write-Host "Admin:  http://localhost:$port/admin"
    Write-Host "Stop with: ./stop.ps1"
} finally {
    Set-Location $originalDir
}
