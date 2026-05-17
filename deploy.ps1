param(
    # Optional version-bump helpers. If set, deploy.ps1 bumps app/__init__.py
    # + pyproject.toml and commits the bump itself. If NONE are set (default),
    # deploy.ps1 uses whatever version is already in app/__init__.py and
    # expects the bump to have been committed already (the normal path -- the
    # session that wrote the feature code is responsible for the version
    # bump).
    [switch]$Patch,
    [switch]$Minor,
    [switch]$Major,
    # Skip the working-tree-clean check. Use only if you know what you're doing.
    [switch]$AllowDirty,
    # Skip waiting for CI green before SSH'ing the VM. Restart will pull
    # whatever :latest is on ghcr.io at that moment -- could be old if the
    # build hasn't finished. Off by default.
    [switch]$SkipCiWait,
    # Skip the systemctl restart on the VM. Useful for "just tag and push,
    # I'll restart manually later".
    [switch]$NoRestart,
    # Skip the env-file push step. Use when prod env hasn't changed and you
    # just want to ship code.
    [switch]$NoEnvPush,
    # ── Env-file management modes (mutually exclusive with the bump flags) ──
    # Pull the VM's current /etc/yg-license-server/yg-license-server.env down
    # to local .env.prod. One-time bootstrap when switching to laptop-managed
    # secrets. Exits without doing anything else.
    [switch]$ImportEnv,
    # Generate fresh ADMIN_TOKEN + SESSION_SECRET + LICENSE_KEY_ENCRYPTION_KEY
    # in local .env.prod, then run the rest of the deploy. The OLD KEK is
    # preserved as LICENSE_KEY_ENCRYPTION_KEY_PREV so you can decrypt
    # existing rows before re-running the rewrap under the new KEK.
    [switch]$RotateSecrets,
    # Push .env.prod to the VM + restart, without bumping version or waiting
    # for CI. Use for secret rotations on a release that's already deployed.
    [switch]$PushEnvOnly,
    # Print what would happen without doing it.
    [switch]$DryRun
)

# deploy.ps1 -- ship whatever version is in app/__init__.py: tag, push, wait
# for CI, push .env.prod to the VM, restart the GCP VM. The session that
# modified the code owns the version bump (it's part of the feature change).
#
# Code deploys:
#   ./deploy.ps1            -- ship the current version (no bump)
#   ./deploy.ps1 -Patch     -- 0.3.0 -> 0.3.1, PR + squash-merge, ship
#   ./deploy.ps1 -Minor     -- 0.3.0 -> 0.4.0, PR + squash-merge, ship
#   ./deploy.ps1 -Major     -- 0.3.0 -> 1.0.0, PR + squash-merge, ship
#
# Prod env (.env.prod, gitignored, laptop is source of truth):
#   ./deploy.ps1 -ImportEnv      -- pull VM's current env -> local .env.prod
#                                   (one-time bootstrap)
#   ./deploy.ps1 -PushEnvOnly    -- push .env.prod + restart, no image bump
#   ./deploy.ps1 -RotateSecrets  -- regenerate ADMIN_TOKEN/SESSION_SECRET/KEK
#                                   in .env.prod, then push (combine with
#                                   -PushEnvOnly for rotation-only flow)
#   ./deploy.ps1 -NoEnvPush      -- code-only deploy, leave VM env alone
#
# Branch-protected main: bumps go through a yg/release-vX.Y.Z PR which we
# create + squash-merge via gh, then tag the resulting main HEAD.
#
# Source of truth for current version: app/__init__.py:__version__.
# pyproject.toml:version is bumped to match (when bumping).

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
Set-Location $root

# ── arg validation ───────────────────────────────────────────────────────────
$bumps = @($Patch, $Minor, $Major) | Where-Object { $_ }
if ($bumps.Count -gt 1) {
    Write-Host "Specify at most one of: -Patch, -Minor, -Major" -ForegroundColor Red
    exit 1
}
$DoBump = $bumps.Count -eq 1
$envModes = @($ImportEnv, $PushEnvOnly) | Where-Object { $_ }
if ($envModes.Count -gt 1) {
    Write-Host "Specify at most one of: -ImportEnv, -PushEnvOnly" -ForegroundColor Red
    exit 1
}
if ($ImportEnv -and ($DoBump -or $RotateSecrets -or $PushEnvOnly)) {
    Write-Host "-ImportEnv is a one-shot bootstrap; can't combine with bump/rotate/push." -ForegroundColor Red
    exit 1
}

# ── helpers ──────────────────────────────────────────────────────────────────
function Run([string]$cmd, [switch]$Capture) {
    if ($DryRun) {
        Write-Host "[dry-run] $cmd" -ForegroundColor Yellow
        return ""
    }
    Write-Host "+ $cmd" -ForegroundColor DarkGray
    if ($Capture) {
        $out = & cmd.exe /c $cmd 2>&1
        if ($LASTEXITCODE -ne 0) { throw "command failed (exit $LASTEXITCODE): $cmd" }
        return $out
    }
    & cmd.exe /c $cmd
    if ($LASTEXITCODE -ne 0) { throw "command failed (exit $LASTEXITCODE): $cmd" }
}

function Read-Version {
    $line = Select-String -Path "app/__init__.py" -Pattern '__version__\s*=\s*"([^"]+)"' | Select-Object -First 1
    if (-not $line) { throw "couldn't find __version__ in app/__init__.py" }
    return $line.Matches[0].Groups[1].Value
}

function Bump-Version([string]$v, [string]$kind) {
    $parts = $v.Split('.') | ForEach-Object { [int]$_ }
    if ($parts.Count -ne 3) { throw "version $v isn't semver MAJOR.MINOR.PATCH" }
    switch ($kind) {
        'patch' { $parts[2] += 1 }
        'minor' { $parts[1] += 1; $parts[2] = 0 }
        'major' { $parts[0] += 1; $parts[1] = 0; $parts[2] = 0 }
    }
    return "$($parts[0]).$($parts[1]).$($parts[2])"
}

function Write-Version([string]$file, [string]$pattern, [string]$replacement) {
    $content = Get-Content -Raw -LiteralPath $file
    $new = [regex]::Replace($content, $pattern, $replacement)
    if ($new -eq $content) { throw "no version line matched in $file" }
    Set-Content -LiteralPath $file -Value $new -NoNewline
}

# ── prod-env management ─────────────────────────────────────────────────────
# Source-of-truth lives at .env.prod (gitignored). VM gets a verbatim copy at
# /etc/yg-license-server/yg-license-server.env. Three flows touch this file:
#   - -ImportEnv: pull VM's current contents down (bootstrap)
#   - -RotateSecrets: regenerate ADMIN_TOKEN/SESSION_SECRET/KEK in-place
#   - normal deploy: scp + atomic install on VM, timestamped backup kept

$PROD_ENV_PATH = Join-Path $root '.env.prod'
$VM_ZONE = 'us-west1-a'
$VM_NAME = 'yg-license-server'
$VM_ENV_PATH = '/etc/yg-license-server/yg-license-server.env'

function Read-EnvLines([string]$path) {
    # Returns the file as a string array (one line per entry). Comments,
    # blanks, and KV lines all live in this array; Get-EnvLineValue +
    # Set-EnvLineValue operate on it as a unit. Order preserved on write.
    if (-not (Test-Path -LiteralPath $path)) { return @() }
    return @(Get-Content -LiteralPath $path)
}

function Write-EnvLines([string]$path, [string[]]$lines) {
    # POSIX-friendly trailing newline + LF line endings (dockerd env-file
    # parser reads CRLF as part of the value otherwise, breaking secrets).
    $body = ($lines -join "`n") + "`n"
    [System.IO.File]::WriteAllText($path, $body, [System.Text.UTF8Encoding]::new($false))
}

function Get-EnvLineValue([string[]]$lines, [string]$key) {
    foreach ($line in $lines) {
        if ($line -match "^\s*$([regex]::Escape($key))\s*=(.*)$") {
            return $matches[1]
        }
    }
    return $null
}

function Set-EnvLineValue([string[]]$lines, [string]$key, [string]$value) {
    # Returns a new string[] with the key updated (or appended). Caller
    # reassigns: `$lines = Set-EnvLineValue $lines 'FOO' 'bar'`.
    $found = $false
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($line in $lines) {
        if ((-not $found) -and ($line -match "^\s*$([regex]::Escape($key))\s*=")) {
            $out.Add("$key=$value")
            $found = $true
        } else {
            $out.Add($line)
        }
    }
    if (-not $found) {
        $out.Add("$key=$value")
    }
    return ,$out.ToArray()
}

function New-RandomToken {
    # 32 random bytes -> urlsafe-base64 (no padding). Same shape as
    # `python -c "import secrets; print(secrets.token_urlsafe(32))"`.
    $bytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    $b64 = [Convert]::ToBase64String($bytes)
    return ($b64 -replace '\+','-' -replace '/','_' -replace '=','')
}

function New-FernetKey {
    # Fernet key is 32 raw bytes encoded as urlsafe-b64 WITH padding.
    $bytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    $b64 = [Convert]::ToBase64String($bytes)
    return ($b64 -replace '\+','-' -replace '/','_')
}

function Test-ProdEnvFile([string]$path) {
    # Validates that the on-disk .env.prod has the required keys with
    # non-empty values + secrets are distinct. Returns $null on success,
    # a string error message on failure.
    if (-not (Test-Path -LiteralPath $path)) { return ".env.prod not found at $path" }
    $lines = Read-EnvLines $path
    $required = @('ADMIN_TOKEN','SESSION_SECRET','DATABASE_URL','IMAGE')
    foreach ($k in $required) {
        $v = Get-EnvLineValue $lines $k
        if ([string]::IsNullOrWhiteSpace($v)) { return "missing/empty $k in $path" }
    }
    $admin = Get-EnvLineValue $lines 'ADMIN_TOKEN'
    $sess  = Get-EnvLineValue $lines 'SESSION_SECRET'
    if ($admin -eq $sess) { return "ADMIN_TOKEN equals SESSION_SECRET -- must be distinct" }
    return $null
}

function Invoke-VmSsh([string]$remoteCmd) {
    # Run an arbitrary command on the VM as the gcloud-authenticated user.
    # -t allocates a TTY so sudo prompts (if ever needed) can echo properly.
    if ($DryRun) {
        Write-Host "[dry-run] gcloud compute ssh $VM_NAME -- $remoteCmd" -ForegroundColor Yellow
        return ""
    }
    $out = & gcloud compute ssh $VM_NAME --zone=$VM_ZONE --ssh-flag=-t --command=$remoteCmd 2>&1
    if ($LASTEXITCODE -ne 0) { throw "ssh failed (exit $LASTEXITCODE): $remoteCmd`n$out" }
    return $out
}

function Invoke-VmScp([string]$localPath, [string]$remotePath, [switch]$Reverse) {
    # Copy via gcloud compute scp. If -Reverse, pull from VM to laptop.
    if ($DryRun) {
        $arrow = if ($Reverse) { '<-' } else { '->' }
        Write-Host "[dry-run] scp $localPath $arrow VM:$remotePath" -ForegroundColor Yellow
        return
    }
    if ($Reverse) {
        & gcloud compute scp --zone=$VM_ZONE "${VM_NAME}:${remotePath}" $localPath 2>&1 | Out-Host
    } else {
        & gcloud compute scp --zone=$VM_ZONE $localPath "${VM_NAME}:${remotePath}" 2>&1 | Out-Host
    }
    if ($LASTEXITCODE -ne 0) { throw "scp failed (exit $LASTEXITCODE)" }
}

function Import-ProdEnvFromVm {
    # Pulls the VM's current env file to local .env.prod. Refuses to clobber
    # an existing local file -- the user has to delete .env.prod first if
    # they really want a re-import.
    if (Test-Path -LiteralPath $PROD_ENV_PATH) {
        throw "$PROD_ENV_PATH already exists. Delete it first if you really want to re-import from the VM."
    }
    Write-Host "==> pulling VM env file to $PROD_ENV_PATH..."
    # /etc/yg-license-server/* is root-owned 0600; sudo-copy to /tmp + chmod
    # 644 so the SSH user (which is whatever gcloud authed as) can read it
    # for scp. The temp file is short-lived and lives only on the VM.
    Invoke-VmSsh "sudo cp $VM_ENV_PATH /tmp/yg-license-env.export && sudo chmod 644 /tmp/yg-license-env.export"
    Invoke-VmScp -Reverse '/tmp/yg-license-env.export' $PROD_ENV_PATH
    Invoke-VmSsh "sudo rm -f /tmp/yg-license-env.export"
    Write-Host "imported -> $PROD_ENV_PATH" -ForegroundColor Green
    Write-Host "  Treat this file as a secret. It is gitignored." -ForegroundColor DarkGray
}

function Update-LocalSecrets {
    # Rotates ADMIN_TOKEN, SESSION_SECRET, and LICENSE_KEY_ENCRYPTION_KEY in
    # local .env.prod. Old KEK is preserved as LICENSE_KEY_ENCRYPTION_KEY_PREV
    # so the operator can run a two-step rewrap (decrypt old, encrypt new).
    if (-not (Test-Path -LiteralPath $PROD_ENV_PATH)) {
        throw "$PROD_ENV_PATH not found. Run with -ImportEnv first (or copy from .env.prod.example)."
    }
    $lines = Read-EnvLines $PROD_ENV_PATH
    $newAdmin = New-RandomToken
    $newSess  = New-RandomToken
    $newKek   = New-FernetKey
    $oldKek   = Get-EnvLineValue $lines 'LICENSE_KEY_ENCRYPTION_KEY'
    $lines = Set-EnvLineValue $lines 'ADMIN_TOKEN' $newAdmin
    $lines = Set-EnvLineValue $lines 'SESSION_SECRET' $newSess
    $lines = Set-EnvLineValue $lines 'LICENSE_KEY_ENCRYPTION_KEY' $newKek
    if ($oldKek -and $oldKek -ne $newKek) {
        $lines = Set-EnvLineValue $lines 'LICENSE_KEY_ENCRYPTION_KEY_PREV' $oldKek
    }
    Write-EnvLines $PROD_ENV_PATH $lines
    Write-Host "rotated ADMIN_TOKEN + SESSION_SECRET + KEK in $PROD_ENV_PATH" -ForegroundColor Green
    Write-Host "  new ADMIN_TOKEN: $newAdmin" -ForegroundColor Cyan
    Write-Host "  (copy this into ASM's LS_ADMIN_TOKEN now -- it won't be shown again)" -ForegroundColor DarkGray
}

function Push-ProdEnv {
    # scp .env.prod to /tmp on the VM, then move into place with root perms
    # + 0600 mode. Keep a timestamped backup so a botched push can be
    # rolled back manually.
    $err = Test-ProdEnvFile $PROD_ENV_PATH
    if ($err) { throw "validation failed: $err" }
    Write-Host "==> pushing $PROD_ENV_PATH to VM..."
    Invoke-VmScp $PROD_ENV_PATH '/tmp/yg-license-env.new'
    $ts = Get-Date -Format 'yyyyMMddHHmmss'
    $backup = "${VM_ENV_PATH}.bak.${ts}"
    # Atomic-ish: backup, install (writes tmpfile + rename within same dir).
    $remote = "sudo cp -a $VM_ENV_PATH $backup && sudo install -m 600 -o root -g root /tmp/yg-license-env.new $VM_ENV_PATH && sudo rm -f /tmp/yg-license-env.new && echo 'env installed, backup at $backup'"
    Invoke-VmSsh $remote | Out-Host
    Write-Host "[env] pushed + installed (backup kept on VM at $backup)" -ForegroundColor Green
}

# ── tool check (runs for every mode, including env-only flows) ──────────────
function Find-Gcloud {
    if (Get-Command gcloud -ErrorAction SilentlyContinue) { return $true }
    $candidates = @(
        "$env:LOCALAPPDATA\Google\Cloud SDK\google-cloud-sdk\bin",
        "$env:USERPROFILE\AppData\Local\Google\Cloud SDK\google-cloud-sdk\bin",
        "${env:ProgramFiles(x86)}\Google\Cloud SDK\google-cloud-sdk\bin",
        "$env:ProgramFiles\Google\Cloud SDK\google-cloud-sdk\bin"
    )
    foreach ($d in $candidates) {
        if (Test-Path (Join-Path $d 'gcloud.cmd')) {
            $env:Path = "$d;$env:Path"
            Write-Host "  (gcloud not on PATH; auto-detected at $d)" -ForegroundColor DarkGray
            return $true
        }
    }
    return $false
}

# Env-only modes need just gcloud; the version-tag flow needs all three.
$toolsNeeded = if ($ImportEnv -or $PushEnvOnly) { @('gcloud') } else { @('git','gh','gcloud') }
foreach ($tool in $toolsNeeded) {
    $found = if ($tool -eq 'gcloud') { Find-Gcloud } else { [bool](Get-Command $tool -ErrorAction SilentlyContinue) }
    if (-not $found) {
        Write-Host "$tool not found in PATH." -ForegroundColor Red
        exit 1
    }
}

# ── ImportEnv: one-shot pull, then exit ─────────────────────────────────────
if ($ImportEnv) {
    Import-ProdEnvFromVm
    exit 0
}

# ── PushEnvOnly: skip version bump + CI wait, just push env + restart ───────
if ($PushEnvOnly) {
    if ($RotateSecrets) { Update-LocalSecrets }
    Push-ProdEnv
    if (-not $NoRestart) {
        Write-Host "==> restarting yg-license-server.service on GCP VM..."
        Invoke-VmSsh "sudo systemctl restart yg-license-server.service" | Out-Host
    }
    Write-Host "done." -ForegroundColor Green
    exit 0
}

# ── pre-flight (version-tag flow only) ──────────────────────────────────────
$current = Read-Version
if ($DoBump) {
    $kind = if ($Patch) { 'patch' } elseif ($Minor) { 'minor' } else { 'major' }
    $next = Bump-Version $current $kind
    Write-Host "version: $current  ->  $next  ($kind)"
} else {
    $next = $current
    Write-Host "version: $current  (using current; no bump)"
}
$tag = "v$next"
Write-Host "tag:     $tag"

# Working tree clean?
$status = git status --porcelain
if ($status -and -not $AllowDirty) {
    Write-Host "working tree dirty. Commit/stash first, or rerun with -AllowDirty." -ForegroundColor Red
    git status --short
    exit 1
}

# On main?
$branch = (git rev-parse --abbrev-ref HEAD).Trim()
if ($branch -ne 'main') {
    Write-Host "not on main (currently on $branch). Switch to main first." -ForegroundColor Red
    exit 1
}

# Up to date with origin?
Run "git fetch origin --tags --quiet"
$behind = (git rev-list --count HEAD..origin/main).Trim()
if ([int]$behind -gt 0) {
    Write-Host "local main is $behind commits behind origin. Pull first." -ForegroundColor Red
    exit 1
}

# Tag doesn't already exist?
$existing = git tag -l $tag
if ($existing) {
    Write-Host "tag $tag already exists locally. Aborting." -ForegroundColor Red
    exit 1
}

# ── 1. bump version files (if --Patch/--Minor/--Major given) ────────────────
# Branch-protected main: bump goes through a PR (yg/release-vX.Y.Z) merged
# via `gh pr merge --squash`, then we sync main locally before tagging.
$branch_release = "yg/release-$tag"
if ($DoBump) {
    if (-not $DryRun) {
        Write-Version "app/__init__.py"  '__version__\s*=\s*"[^"]+"'  "__version__ = `"$next`""
        Write-Version "pyproject.toml"   '(?m)^version\s*=\s*"[^"]+"' "version = `"$next`""
    }
    Write-Host "[1/6] bumped app/__init__.py + pyproject.toml -> $next"
    Run "git checkout -b $branch_release"
    Run "git add app/__init__.py pyproject.toml"
    Run "git commit -m `"release: $tag`""
    Run "git push -u origin $branch_release"
    if (-not $DryRun) {
        & gh pr create --title "release: $tag" --body "Version bump $current -> $next." | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "gh pr create failed (exit $LASTEXITCODE)" }
        & gh pr merge $branch_release --squash --delete-branch
        if ($LASTEXITCODE -ne 0) { throw "gh pr merge failed (exit $LASTEXITCODE) -- merge required checks not green yet? rerun with --SkipCiWait off after CI passes" }
    } else {
        Write-Host "[dry-run] gh pr create + gh pr merge --squash --delete-branch" -ForegroundColor Yellow
    }
    Run "git checkout main"
    Run "git pull --ff-only origin main"
    Write-Host "[2/6] PR merged + main synced"
} else {
    Write-Host "[1/6] no bump requested (current version $current); nothing to commit"
    Write-Host "[2/6] skipped commit"
}

# ── 3. tag + push ────────────────────────────────────────────────────────────
Run "git tag $tag"
Run "git push origin $tag"
Write-Host "[3/6] pushed $tag to origin"

# ── 4. wait for CI ───────────────────────────────────────────────────────────
if ($SkipCiWait) {
    Write-Host "[4/6] skipped CI wait (--SkipCiWait)" -ForegroundColor Yellow
} else {
    Write-Host "[4/6] waiting for release.yml to build $tag and push to ghcr.io..."
    if ($DryRun) {
        Write-Host "[dry-run] gh run watch (release workflow on $tag)" -ForegroundColor Yellow
    } else {
        # Find the latest release-workflow run for this tag and watch it.
        # Retry up to 30s for the run to appear (GitHub takes a moment to
        # register the tag-push event).
        $runId = $null
        for ($i = 0; $i -lt 30; $i++) {
            $runs = gh run list --workflow=release.yml --limit=5 --json databaseId,headBranch,status 2>$null | ConvertFrom-Json
            $match = $runs | Where-Object { $_.headBranch -eq $tag } | Select-Object -First 1
            if ($match) { $runId = $match.databaseId; break }
            Start-Sleep -Seconds 1
        }
        if (-not $runId) { throw "couldn't find release.yml run for $tag after 30s" }
        Write-Host "  watching run $runId..."
        # `gh run watch` polls the API and dies on transient 504/5xx. Retry up
        # to 3 times -- a 504 is almost never a real CI failure. After retries,
        # fall back to polling the run's status field directly so a flaky API
        # doesn't fail the whole release.
        $watchOk = $false
        for ($try = 1; $try -le 3 -and -not $watchOk; $try++) {
            gh run watch $runId --exit-status
            if ($LASTEXITCODE -eq 0) { $watchOk = $true; break }
            Write-Host "  gh run watch exited $LASTEXITCODE (attempt $try/3); retrying in 5s..." -ForegroundColor Yellow
            Start-Sleep -Seconds 5
        }
        if (-not $watchOk) {
            Write-Host "  gh run watch kept failing -- polling run status directly..." -ForegroundColor Yellow
            for ($i = 0; $i -lt 60; $i++) {
                $info = gh run view $runId --json status,conclusion 2>$null | ConvertFrom-Json
                if ($info -and $info.status -eq 'completed') {
                    if ($info.conclusion -ne 'success') { throw "release CI conclusion=$($info.conclusion)" }
                    $watchOk = $true; break
                }
                Start-Sleep -Seconds 10
            }
            if (-not $watchOk) { throw "release CI didn't complete within 10min" }
        }
    }
    Write-Host "[4/6] CI green, image ghcr.io/why-gee/yg-license-server:$tag published"
}

# ── 4.5 rotate (if asked) + push .env.prod to VM ────────────────────────────
# Env file is laptop-managed (.env.prod, gitignored). Push happens BEFORE
# restart so the new container picks up the new values. -NoEnvPush skips
# the push (use when only the image changed and env is already in sync).
if ($RotateSecrets) {
    Update-LocalSecrets
}
if ($NoEnvPush) {
    Write-Host "[4.5/6] skipped env push (--NoEnvPush)" -ForegroundColor Yellow
} elseif (-not (Test-Path -LiteralPath $PROD_ENV_PATH)) {
    Write-Host "[4.5/6] no $PROD_ENV_PATH on disk -- skipping env push." -ForegroundColor Yellow
    Write-Host "  Run with -ImportEnv to bootstrap from the VM's current file." -ForegroundColor DarkGray
} else {
    Write-Host "[4.5/6] pushing .env.prod to VM..."
    Push-ProdEnv
}

# ── 5. restart VM ────────────────────────────────────────────────────────────
if ($NoRestart) {
    Write-Host "[5/6] skipped VM restart (--NoRestart). Restart manually with:" -ForegroundColor Yellow
    Write-Host '  gcloud compute ssh yg-license-server --zone=us-west1-a --ssh-flag=-t --command="sudo systemctl restart yg-license-server.service"' -ForegroundColor DarkGray
} else {
    Write-Host "[5/6] restarting yg-license-server.service on GCP VM..."
    if ($DryRun) {
        Write-Host '[dry-run] gcloud compute ssh ... systemctl restart' -ForegroundColor Yellow
    } else {
        & gcloud compute ssh yg-license-server --zone=us-west1-a --ssh-flag=-t --command="sudo systemctl restart yg-license-server.service"
        if ($LASTEXITCODE -ne 0) { throw "remote restart failed (exit $LASTEXITCODE)" }
    }
    Write-Host "[5/6] restarted"
}

# ── 6. verify ────────────────────────────────────────────────────────────────
if ($NoRestart -or $DryRun) {
    Write-Host "[6/6] skipping verify"
} else {
    Write-Host "[6/6] verifying live server reports new version..."
    # Give the container a few seconds to come up.
    Start-Sleep -Seconds 5
    $health = $null
    for ($i = 0; $i -lt 12; $i++) {
        try {
            $health = Invoke-RestMethod -Uri 'https://yg-license-server.duckdns.org/health' -TimeoutSec 5
            break
        } catch {
            Start-Sleep -Seconds 5
        }
    }
    if (-not $health) { throw "live /health didn't respond within 60s" }
    if ($health.version -eq "$next" -or $health.version -eq "$next-dev") {
        Write-Host "  /health -> version=$($health.version) ok=$($health.ok)" -ForegroundColor Green
    } else {
        Write-Host "  /health -> version=$($health.version) (expected $next). Container may still be starting; check again in a minute." -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "done. $tag is live at https://yg-license-server.duckdns.org" -ForegroundColor Green
