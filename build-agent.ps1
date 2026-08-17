<#
.SYNOPSIS
    GIAM-SAT Agent Build Script v3.5.0
    Build GiamSatAgent.exe + GiamSatUpdater.exe (2 EXE files).

.DESCRIPTION
    Agent: collector, TCP connection to server, forward commands to Updater.
    Updater: daemon, HTTP localhost server, kill/start Agent, auto-update 15ph.

.PARAMETER Version
    Version number (e.g., "3.5.0"). Required.

.PARAMETER NoServer
    Skip server restart after build.

.EXAMPLE
    .\build-agent.ps1 -Version "3.5.1"
    .\build-agent.ps1 -Version "3.5.1" -NoServer
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$Version,

    [switch]$RestartServer
)

$ErrorActionPreference = "Continue"
$ROOT = $PSScriptRoot
$AGENT_DIR = Join-Path $ROOT "agent"
$DIST_DIR = Join-Path $ROOT "dist"
$SERVER_DIR = Join-Path $ROOT "server"
$BUILD_DIR = Join-Path $ROOT "build"

$startTime = Get-Date

function Write-OK   { Write-Host "[OK] " -NoNewline -ForegroundColor Green; Write-Host $args[0] }
function Write-FAIL { Write-Host "[FAIL] " -NoNewline -ForegroundColor Red; Write-Host $args[0] }
function Write-INFO { Write-Host "[*] " -NoNewline -ForegroundColor Cyan; Write-Host $args[0] }
function Write-STEP { Write-Host "`n>>> " -NoNewline -ForegroundColor Magenta; Write-Host $args[0] -ForegroundColor White }

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  GIAM-SAT Agent Build Script v3.5.0" -ForegroundColor Cyan
Write-Host "  Version: $Version  |  2 files: Agent + Updater daemon" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# STEP 1: Check environment
Write-STEP "STEP 1: Checking environment..."
try { $pyVer = python --version 2>&1; Write-OK "Python: $pyVer" } catch { Write-FAIL "Python not found!"; exit 1 }
try { $piVer = python -m PyInstaller --version 2>&1; Write-OK "PyInstaller: $piVer" } catch { Write-INFO "Installing PyInstaller..."; pip install pyinstaller; Write-OK "Done" }

# STEP 2: Update version
Write-STEP "STEP 2: Updating version to $Version..."
Set-Content -Path "$AGENT_DIR\agent_version.txt" -Value $Version -Encoding ASCII
Set-Content -Path "$SERVER_DIR\version.txt" -Value $Version -Encoding ASCII
Write-OK "agent_version.txt -> $Version"
Write-OK "server/version.txt -> $Version"

# STEP 3: Clear cache
Write-STEP "STEP 3: Clearing build cache..."
if (Test-Path $BUILD_DIR) { Remove-Item -Path $BUILD_DIR -Recurse -Force -ErrorAction SilentlyContinue; Write-OK "Removed: $BUILD_DIR" }
else { Write-INFO "No cache to clear" }

# STEP 4: Verify specs
Write-STEP "STEP 4: Verifying spec files..."
$agentSpec = "$AGENT_DIR\GiamSatAgent.spec"
$updaterSpec = "$AGENT_DIR\updater.spec"
if (-not (Test-Path $agentSpec)) { Write-FAIL "GiamSatAgent.spec not found!"; exit 1 }
if (-not (Test-Path $updaterSpec)) { Write-FAIL "updater.spec not found!"; exit 1 }
$spec1 = Get-Content $agentSpec -Raw
$spec2 = Get-Content $updaterSpec -Raw
if ($spec1 -match "console\s*=\s*False" -or $spec2 -match "console\s*=\s*False") { Write-FAIL "console=False in spec!"; exit 1 }
Write-OK "Both specs: console=True"

# STEP 5: Build GiamSatAgent.exe
Write-STEP "STEP 5: Building GiamSatAgent.exe (~24 MB)..."
$s = Get-Date
Push-Location $ROOT
try {
    & python -m PyInstaller $agentSpec --noconfirm
    if ($LASTEXITCODE -ne 0) { Write-FAIL "Build failed (exit code: $LASTEXITCODE)"; Pop-Location; exit 1 }
    $exe = "$DIST_DIR\GiamSatAgent.exe"
    if (Test-Path $exe) { try { Write-OK "GiamSatAgent.exe: $([math]::Round((Get-Item $exe).Length/1MB,1)) MB" } catch { Write-OK "GiamSatAgent.exe: built" } }
    else { Write-FAIL "Output not found!"; Pop-Location; exit 1 }
    try { Write-INFO "Build time: $([math]::Round(((Get-Date)-$s).TotalSeconds,0))s" } catch { Write-INFO "Build done" }
} finally { Pop-Location }

# STEP 6: Build GiamSatUpdater.exe
Write-STEP "STEP 6: Building GiamSatUpdater.exe (~6-8 MB)..."
$s = Get-Date
Push-Location $ROOT
try {
    & python -m PyInstaller $updaterSpec --noconfirm
    if ($LASTEXITCODE -ne 0) { Write-FAIL "Build failed (exit code: $LASTEXITCODE)"; Pop-Location; exit 1 }
    $exe = "$DIST_DIR\GiamSatUpdater.exe"
    if (Test-Path $exe) { try { Write-OK "GiamSatUpdater.exe: $([math]::Round((Get-Item $exe).Length/1MB,1)) MB" } catch { Write-OK "GiamSatUpdater.exe: built" } }
    else { Write-FAIL "Output not found!"; Pop-Location; exit 1 }
    try { Write-INFO "Build time: $([math]::Round(((Get-Date)-$s).TotalSeconds,0))s" } catch { Write-INFO "Build done" }
} finally { Pop-Location }

# STEP 7: Restart server (only with -RestartServer flag)
if ($RestartServer) {
    Write-STEP "STEP 7: Restarting server..."
    taskkill /F /IM python.exe 2>$null
    Start-Sleep -Seconds 2
    Start-Process python -ArgumentList "$SERVER_DIR\main.py" -WorkingDirectory $SERVER_DIR -WindowStyle Hidden
    Write-OK "Server restarted"
}

# SUMMARY
try { $total = [math]::Round(((Get-Date) - $startTime).TotalSeconds, 0) } catch { $total = "?" }
Write-Host "`n============================================================" -ForegroundColor Green
Write-Host "  BUILD COMPLETE!  Total: ${total}s" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host "`n  $DIST_DIR\" -ForegroundColor DarkGray
foreach ($f in @("GiamSatAgent.exe","GiamSatUpdater.exe")) {
    $p = "$DIST_DIR\$f"
    if (Test-Path $p) { try { Write-Host "  -- $f  $([math]::Round((Get-Item $p).Length/1MB,1)) MB" -ForegroundColor Cyan } catch { Write-Host "  -- $f" -ForegroundColor Cyan } }
}
Write-Host "`nMay tram: Copy 2 file -> Run as Admin tung file" -ForegroundColor Yellow
Write-Host "  -> GiamSatAgent.exe:  tu dong dang ky Windows Service" -ForegroundColor Gray
Write-Host "  -> GiamSatUpdater.exe: tu dong dang ky Scheduled Task (ONLOGON)" -ForegroundColor Gray
Write-Host "`nDone!" -ForegroundColor Green