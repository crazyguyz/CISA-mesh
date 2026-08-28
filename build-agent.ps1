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

    [switch]$RestartServer,

    # v4.6.2 (FIX): stop agent/updater BEFORE building so the watchdog cannot
    # auto-restart the agent from dist\ while PyInstaller is overwriting the EXE
    # (that race produced a half-written bundle missing _ssl.pyd -> agent crashed
    # with "No module named '_ssl'" at startup, boots 11x/12x at 16:37:52).
    [switch]$RestartAgent
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

# STEP 1.5: Stop agent/updater before build (prevents watchdog race on dist\ EXE)
if ($RestartAgent) {
    Write-STEP "STEP 1.5: Stopping GiamSatAgent + GiamSatUpdater..."
    Get-Process -Name "GiamSatAgent","GiamSatUpdater" -ErrorAction SilentlyContinue |
        ForEach-Object { Write-INFO "Stopping $($_.ProcessName) (PID $($_.Id))"; Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Seconds 2
    # Disable the watchdog scheduled task so it cannot relaunch the agent mid-build
    try {
        schtasks /Change /TN "GIAM-SAT Agent Monitor" /DISABLE 2>&1 | Out-Null
        Write-OK "Watchdog task disabled (re-enabled after build)"
    } catch { Write-INFO "Watchdog task not found - skip" }
    Write-OK "Agents stopped"
}

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
# v5.0.2: windowed (console=False) build - prevents the black console window that
# flashed at boot via Task Scheduler and could be closed by users, killing the
# agent/updater. main.py + updater.py redirect stdout/stderr for windowed mode.
if ($spec1 -match "console\s*=\s*True" -or $spec2 -match "console\s*=\s*True") {
    Write-INFO "WARN: specs still have console=True - a black console window will flash at boot. Set console=False in both .spec files for a hidden launch."
} else {
    Write-OK "Both specs: console=False (windowed - no console flash)"
}

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
    # v4.6.2 (FIX): verify the bundle actually contains the OpenSSL chain BEFORE it
    # ships - a build that loses _ssl.pyd would only crash at agent runtime.
    try {
        $missing = @()
        foreach ($needle in '_ssl.pyd', '_hashlib.pyd', 'libssl-3-x64.dll', 'libcrypto-3-x64.dll') {
            $hit = python -m PyInstaller.utils.cliutils.archive_viewer -l $exe 2>&1 | Select-String -SimpleMatch $needle
            if (-not $hit) { $missing += $needle }
        }
        if ($missing.Count -gt 0) {
            Write-FAIL "BUNDLE VERIFY FAILED - missing: $($missing -join ', ')"
            Pop-Location; exit 1
        }
        Write-OK "Bundle verify: _ssl.pyd + OpenSSL DLLs present"
    } catch {
        Write-INFO "Bundle verify skipped (PyInstaller archive_viewer unavailable): $_"
    }
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

# STEP 6.5: Ship agent_version.txt next to the EXEs - the updater reads
# INSTALL_DIR\agent_version.txt to know the local version. Without it the version
# reads as 0.0.0 and the server keeps offering updates forever (endless loop that
# produced 'Failed to extract' popups on workstations). v5.0.4 FIX.
Copy-Item "$AGENT_DIR\agent_version.txt" "$DIST_DIR\agent_version.txt" -Force
Write-OK "dist\agent_version.txt -> $Version (update-loop fix)"

# STEP 7: Restart server (only with -RestartServer flag)
if ($RestartServer) {
    Write-STEP "STEP 7: Restarting server..."
    # v4.10 (LOW-16): kill ONLY the server process (python running main.py) -
    # `taskkill /F /IM python.exe` killed every python.exe on the machine.
    Get-CimInstance Win32_Process -Filter "Name='python.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -like '*main.py*' } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Seconds 2
    Start-Process python -ArgumentList "$SERVER_DIR\main.py" -WorkingDirectory $SERVER_DIR -WindowStyle Hidden
    Write-OK "Server restarted"
}

# STEP 7.5: Re-enable watchdog + restart agent/updater (with -RestartAgent)
if ($RestartAgent) {
    Write-STEP "STEP 7.5: Restarting GiamSatAgent + GiamSatUpdater..."
    try {
        schtasks /Change /TN "GIAM-SAT Agent Monitor" /ENABLE 2>&1 | Out-Null
        Write-OK "Watchdog task re-enabled"
    } catch { Write-INFO "Watchdog task not found - skip" }
    $agentExe = "$DIST_DIR\GiamSatAgent.exe"
    $updaterExe = "$DIST_DIR\GiamSatUpdater.exe"
    if (Test-Path $agentExe) { Start-Process $agentExe -WorkingDirectory $DIST_DIR; Write-OK "GiamSatAgent.exe started" }
    else { Write-FAIL "GiamSatAgent.exe not found - skip" }
    if (Test-Path $updaterExe) { Start-Process $updaterExe -WorkingDirectory $DIST_DIR; Write-OK "GiamSatUpdater.exe started" }
    else { Write-FAIL "GiamSatUpdater.exe not found - skip" }
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