param(
    # Version bump kind. Exactly one of these must be set.
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
    # Print what would happen without doing it.
    [switch]$DryRun
)

# deploy.ps1 -- one-shot release: bump version, commit, tag, push, wait for CI,
# restart the GCP VM. Replaces the 7-step manual flow.
#
#   ./deploy.ps1 -Patch     -- 0.3.0 -> 0.3.1
#   ./deploy.ps1 -Minor     -- 0.3.0 -> 0.4.0
#   ./deploy.ps1 -Major     -- 0.3.0 -> 1.0.0
#
# Source of truth for current version: app/__init__.py:__version__.
# pyproject.toml:version is bumped to match in the same commit.

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
Set-Location $root

# ── arg validation ───────────────────────────────────────────────────────────
$bumps = @($Patch, $Minor, $Major) | Where-Object { $_ }
if ($bumps.Count -ne 1) {
    Write-Host "Specify exactly one of: -Patch, -Minor, -Major" -ForegroundColor Red
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

# ── pre-flight ───────────────────────────────────────────────────────────────
$kind = if ($Patch) { 'patch' } elseif ($Minor) { 'minor' } else { 'major' }
$current = Read-Version
$next = Bump-Version $current $kind
$tag = "v$next"

Write-Host "version: $current  ->  $next  ($kind)"
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

# Required tools
foreach ($tool in @('git', 'gh', 'gcloud')) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        Write-Host "$tool not found in PATH." -ForegroundColor Red
        exit 1
    }
}

# ── 1. bump version files ────────────────────────────────────────────────────
if (-not $DryRun) {
    Write-Version "app/__init__.py"  '__version__\s*=\s*"[^"]+"'  "__version__ = `"$next`""
    Write-Version "pyproject.toml"   '(?m)^version\s*=\s*"[^"]+"' "version = `"$next`""
}
Write-Host "[1/6] bumped app/__init__.py + pyproject.toml -> $next"

# ── 2. commit ────────────────────────────────────────────────────────────────
Run "git add app/__init__.py pyproject.toml"
Run "git commit -m `"release: $tag`""
Write-Host "[2/6] committed"

# ── 3. tag + push ────────────────────────────────────────────────────────────
Run "git tag $tag"
Run "git push origin main"
Run "git push origin $tag"
Write-Host "[3/6] pushed main + $tag to origin"

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
        gh run watch $runId --exit-status
        if ($LASTEXITCODE -ne 0) { throw "release CI failed (exit $LASTEXITCODE)" }
    }
    Write-Host "[4/6] CI green, image ghcr.io/why-gee/yg-license-server:$tag published"
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
