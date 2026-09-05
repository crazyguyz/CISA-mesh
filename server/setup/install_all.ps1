# =============================================================================
# GIAM-SAT Server Auto-Installer v2.2.0
# Tu dong cai dat toan bo cong cu can thiet de chay GIAM-SAT Server
# Bilingual: Vietnamese (vi, default) or English (en) — asked on start.
#
# Usage (Run as Administrator):
#   powershell -ExecutionPolicy Bypass -File install_all.ps1
#
# What this does:
#   1. Install Python 3.11.9 (silent)
#   2. Upgrade pip to latest
#   3. Install all required Python packages
#   4. Install Npcap (network packet capture)
#   5. Install Git (Sigma rule updates)
#   6. Verify installation
#   7. Create start script shortcut
# =============================================================================

$ErrorActionPreference = "Continue"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$SetupDir = $ScriptDir
$ServerDir = Split-Path -Parent $SetupDir

# =============================================================================
# Language selection (vi = Tieng Viet khong dau, en = English)
# =============================================================================
$lang = ""
while ($lang -notin @("vi", "en")) {
    $langInput = Read-Host "Language / Ngon ngu [vi|en] (Enter = vi)"
    if ($langInput -eq "") { $lang = "vi" }
    else { $lang = $langInput.Trim().ToLower() }
    if ($lang -notin @("vi", "en")) {
        Write-Host "  [!] Invalid choice - choose 'vi' or 'en'." -ForegroundColor Red
    }
}
Write-Host ""

$TR = @{
    en = @{
        bannerTitle    = "  Installing all required tools..."
        s1Title        = "[1/6] Installing Python 3.11.9..."
        pyFound        = "  [+] Found Python installer"
        pyInstalling   = "  [*] Installing Python (silent mode)..."
        pySuccess      = "  [+] Python 3.11.9 installed successfully!"
        pyExit         = "  [!] Python installer returned exit code: "
        pyManual       = "  [*] Manual install may be needed. Run: "
        pyFail         = "  [-] Python install failed: "
        pyNotFound     = "  [-] Python installer NOT found at: "
        pyDownload     = "  [*] Download from: https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe"
        pathFail       = "  [!] Cannot refresh PATH (ConstrainedLanguage mode). Continuing..."
        s2Title        = "[2/6] Upgrading pip..."
        pipReady       = "  [+] pip ready"
        pipNotFound    = "  [-] pip not found. Please install Python first."
        pipUpgradeFail = "  [-] pip upgrade failed: "
        s3Title        = "[3/6] Installing Python packages..."
        pkgsFromReq    = "  [*] Installing from requirements.txt..."
        pkgsFailed     = "  [-] Some packages may have failed. See errors above."
        reqNotFound    = "  [-] requirements.txt not found at: "
        reqFallback    = "  [*] Falling back to manual package list..."
        pkgInstalling  = "  [*] Installing: "
        pkgInstalled   = "installed"
        pkgFail        = "  [-] Failed to install "
        s4Title        = "[4/6] Installing Npcap (network packet capture)..."
        npFound        = "  [+] Found Npcap installer"
        npInstalling   = "  [*] Installing Npcap (silent mode)..."
        npDesc         = "  [*] Npcap lets the Agent capture network packets for analysis"
        npSuccess      = "  [+] Npcap installed successfully!"
        npFail         = "  [-] Npcap install failed: "
        npManual       = "  [*] You can install manually later: "
        npNotFound     = "  [-] Npcap installer NOT found at: "
        npDownload     = "  [*] Download from: https://npcap.com/dist/npcap-1.80.exe"
        npNote         = "  [*] Without Npcap, Agent will not capture network packets (other features still work)."
        s5Title        = "[5/6] Installing Git (Sigma rule updates)..."
        gitFound       = "  [+] Found Git installer"
        gitInstalling  = "  [*] Installing Git (silent mode)..."
        gitDesc        = "  [*] Git is used to auto-sync Sigma rules from SigmaHQ"
        gitSuccess     = "  [+] Git installed successfully!"
        gitFail        = "  [-] Git install failed: "
        gitManual      = "  [*] You can install manually later: "
        gitNotFound    = "  [-] Git installer NOT found at: "
        gitDownload    = "  [*] Download from: https://git-scm.com/download/win"
        gitNote        = "  [*] Without Git, Sigma rule auto-update will be disabled."
        s6Title        = "[6/6] Verifying installation..."
        pyCheck        = "  [+] Python: "
        pyMissing      = "  [-] Python not found in PATH"
        pipCheck       = "  [+] pip: "
        pipMissing     = "  [-] pip not found"
        npVer          = "  [+] Npcap: installed (version "
        npNotDetected  = "  [!] Npcap: not detected (optional - network packet capture)"
        gitCheck       = "  [+] Git: "
        gitNotDetected = "  [!] Git: not detected (optional - Sigma auto-update)"
        startScript    = "  [+] Created start script: "
        sumTitle       = "  GIAM-SAT Server Installation Complete!"
        dirHeader      = "  SETUP FOLDER CONTENTS:"
        pkgsHeader     = "  INSTALLED PACKAGES:"
        nextHeader     = "  NEXT STEPS:"
        next1          = "    1. Configure:  powershell -File setup\\setup_config.ps1"
        next2          = "    2. Start:      cd .. && python main.py"
        next3          = "    OR:            Run start_server.bat (created in setup folder)"
        webUI          = "  Web UI:  http://localhost:5000"
        loginAdmin     = "  Admin login: run setup_config.ps1 to set it (or the server prints a random password on first start)"
        pgHeader       = "  POSTGRESQL (Optional but recommended):"
        pgDesc         = "    Default backend is SQLite. For production, install PostgreSQL 16:"
        pgDownload     = "    Download: https://get.enterprisedb.com/postgresql/postgresql-16.4-1-windows-x64.exe"
        pgEnv          = "    After install, set in "
        pgBackend      = "      GIAMSAT_DB_BACKEND=postgres"
        pgHost         = "      GIAMSAT_PG_HOST=127.0.0.1"
        pgPass         = "      GIAMSAT_PG_PASSWORD=your_password"
        cfgNote        = "  CONFIGURE "
        exitPrompt     = "Press Enter to exit"
    }
    vi = @{
        bannerTitle  = "  Dang cai dat tat ca cong cu can thiet..."
        s1Title      = "[1/6] Cai dat Python 3.11.9..."
        pyFound      = "  [+] Tim thay Python installer"
        pyInstalling = "  [*] Dang cai dat Python (silent mode)..."
        s2Title      = "[2/6] Nang cap pip..."
        s3Title      = "[3/6] Cai dat Python packages..."
        s4Title      = "[4/6] Cai dat Npcap (network packet capture)..."
        npFound      = "  [+] Tim thay Npcap installer"
        npInstalling = "  [*] Dang cai dat Npcap (silent mode)..."
        npDesc       = "  [*] Npcap cho phep Agent bat goi tin mang de phan tich"
        s5Title      = "[5/6] Cai dat Git (Sigma rule updates)..."
        gitFound     = "  [+] Tim thay Git installer"
        gitInstalling = "  [*] Dang cai dat Git (silent mode)..."
        gitDesc      = "  [*] Git dung de tu dong dong bo Sigma rules tu SigmaHQ"
        s6Title      = "[6/6] Kiem tra cai dat..."
        pkgInstalled = "da cai"
        sumTitle     = "  HOAN TAT CAI DAT GIAM-SAT Server!"
        dirHeader    = "  THU MUC SETUP HIEN CO:"
        pkgsHeader   = "  PACKAGES DA CAI:"
        nextHeader   = "  BUOC TIEP THEO:"
        loginAdmin   = "  Login admin: chay setup_config.ps1 de dat mat khau (hoac server in mat khau ngau nhien lan dau chay)"
        exitPrompt   = "Nhan Enter de thoat"
    }
}
# vi overrides English defaults; keys not overridden fall back to English
$T = $TR[$lang].Clone()
if ($lang -eq "vi") {
    foreach ($k in $TR["en"].Keys) {
        if (-not $T.ContainsKey($k)) { $T[$k] = $TR["en"][$k] }
    }
}

# Banner
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  GIAM-SAT Server Auto-Installer v2.2.0" -ForegroundColor Cyan
Write-Host "  $($T['bannerTitle'])" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# =============================================================================
# 1. Install Python 3.11.9
# =============================================================================
Write-Host "  $($T['s1Title'])" -ForegroundColor Yellow

$PythonInstaller = Join-Path $SetupDir "python-3.11.9-amd64.exe"

if (Test-Path $PythonInstaller) {
    Write-Host "  $($T['pyFound'])" -ForegroundColor Green
    Write-Host "  $($T['pyInstalling'])" -ForegroundColor Gray
    
    $installArgs = "/quiet InstallAllUsers=1 PrependPath=1 Include_test=0 Include_pip=1"
    try {
        $process = Start-Process -FilePath $PythonInstaller -ArgumentList $installArgs -Wait -PassThru -NoNewWindow
        if ($process.ExitCode -eq 0) {
            Write-Host "  $($T['pySuccess'])" -ForegroundColor Green
        } else {
            Write-Host ("$($T['pyExit'])$($process.ExitCode)") -ForegroundColor Yellow
            Write-Host ("$($T['pyManual'])$PythonInstaller") -ForegroundColor Yellow
        }
    } catch {
        Write-Host ("$($T['pyFail'])$_") -ForegroundColor Red
    }
} else {
    Write-Host ("$($T['pyNotFound'])$PythonInstaller") -ForegroundColor Red
    Write-Host "  $($T['pyDownload'])" -ForegroundColor Yellow
}

# Refresh PATH (try/catch for ConstrainedLanguage mode)
try {
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
} catch {
    Write-Host "  $($T['pathFail'])" -ForegroundColor Yellow
}
Write-Host ""

# =============================================================================
# 2. Upgrade pip
# =============================================================================
Write-Host "  $($T['s2Title'])" -ForegroundColor Yellow

try {
    $pipCmd = Get-Command pip -ErrorAction SilentlyContinue
    if (-not $pipCmd) { $pipCmd = Get-Command pip3 -ErrorAction SilentlyContinue }
    if (-not $pipCmd) {
        $pythonPaths = @(
            "C:\Program Files\Python311\Scripts\pip.exe",
            "C:\Python311\Scripts\pip.exe",
            "$env:LOCALAPPDATA\Programs\Python\Python311\Scripts\pip.exe",
            "$env:APPDATA\Python\Python311\Scripts\pip.exe"
        )
        foreach ($p in $pythonPaths) {
            if (Test-Path $p) { $pipCmd = $p; break }
        }
    }
    
    if ($pipCmd) {
        # Try upgrading pip (may fail if system-managed, that's OK)
        $null = python -m pip install --upgrade pip 2>&1
        Write-Host "  $($T['pipReady'])" -ForegroundColor Green
    } else {
        Write-Host "  $($T['pipNotFound'])" -ForegroundColor Red
    }
} catch {
    Write-Host ("$($T['pipUpgradeFail'])$_") -ForegroundColor Red
}
Write-Host ""

# =============================================================================
# 3. Install Python packages (from requirements.txt)
# =============================================================================
Write-Host "  $($T['s3Title'])" -ForegroundColor Yellow

$reqFile = Join-Path $SetupDir "requirements.txt"

if (Test-Path $reqFile) {
    Write-Host "  $($T['pkgsFromReq'])" -ForegroundColor Gray
    try {
        pip install -r $reqFile 2>&1 | ForEach-Object {
            if ($_ -match "Successfully installed") { Write-Host "  [+] $_" -ForegroundColor Green }
            elseif ($_ -match "already satisfied") { Write-Host "  [~] $_" -ForegroundColor Gray }
            elseif ($_ -match "ERROR|error") { Write-Host "  [-] $_" -ForegroundColor Red }
        }
    } catch {
        Write-Host "  $($T['pkgsFailed'])" -ForegroundColor Red
    }
} else {
    Write-Host ("$($T['reqNotFound'])$reqFile") -ForegroundColor Red
    Write-Host "  $($T['reqFallback'])" -ForegroundColor Yellow
    $packages = @(
        "flask", "pyjwt", "pyyaml", "cryptography", "requests", "urllib3",
        "psycopg2-binary", "waitress", "openpyxl", "bcrypt", "python-dotenv",
        "aiohttp", "watchdog",
        "psutil", "paramiko", "redis", "pika", "geoip2", "maxminddb"
    )
    foreach ($pkg in $packages) {
        Write-Host ("$($T['pkgInstalling'])$pkg...") -ForegroundColor Gray
        try { pip install $pkg 2>&1 | Out-Null; Write-Host ("  [+] $pkg $($T['pkgInstalled'])") -ForegroundColor Green }
        catch { Write-Host ("$($T['pkgFail'])$pkg") -ForegroundColor Red }
    }
}
Write-Host ""

# =============================================================================
# 4. Install Npcap (packet capture for Agent network collector)
# =============================================================================
Write-Host "  $($T['s4Title'])" -ForegroundColor Yellow

$NpcapInstaller = Join-Path $SetupDir "npcap-1.80.exe"

if (Test-Path $NpcapInstaller) {
    Write-Host "  $($T['npFound'])" -ForegroundColor Green
    Write-Host "  $($T['npInstalling'])" -ForegroundColor Gray
    Write-Host "  $($T['npDesc'])" -ForegroundColor Gray
    
    # Npcap silent install options:
    # /S = silent
    # winpcap_mode = no (use npcap native, not WinPcap compat)
    # loopback = yes (capture loopback traffic)
    # dot11 = yes (WiFi capture support)
    $npcapArgs = "/S /winpcap_mode=no /loopback_support=yes /dot11_support=yes"
    try {
        $process = Start-Process -FilePath $NpcapInstaller -ArgumentList $npcapArgs -Wait -PassThru -NoNewWindow
        Write-Host "  $($T['npSuccess'])" -ForegroundColor Green
    } catch {
        Write-Host ("$($T['npFail'])$_") -ForegroundColor Red
        Write-Host ("$($T['npManual'])$NpcapInstaller") -ForegroundColor Yellow
    }
} else {
    Write-Host ("$($T['npNotFound'])$NpcapInstaller") -ForegroundColor Red
    Write-Host "  $($T['npDownload'])" -ForegroundColor Yellow
    Write-Host "  $($T['npNote'])" -ForegroundColor Yellow
}
Write-Host ""

# =============================================================================
# 5. Install Git (for Sigma rule updates)
# =============================================================================
Write-Host "  $($T['s5Title'])" -ForegroundColor Yellow

$GitInstaller = Join-Path $SetupDir "Git-2.47.0-64-bit.exe"

if (Test-Path $GitInstaller) {
    Write-Host "  $($T['gitFound'])" -ForegroundColor Green
    Write-Host "  $($T['gitInstalling'])" -ForegroundColor Gray
    Write-Host "  $($T['gitDesc'])" -ForegroundColor Gray
    
    # Git silent install options:
    # /VERYSILENT = no UI at all
    # /NORESTART = don't restart
    # /NOCANCEL = prevent cancel
    # /CLOSEAPPLICATIONS = close apps using git files
    # /NOICONS = no desktop icon
    $gitArgs = "/VERYSILENT /NORESTART /NOCANCEL /CLOSEAPPLICATIONS /NOICONS"
    try {
        $process = Start-Process -FilePath $GitInstaller -ArgumentList $gitArgs -Wait -PassThru -NoNewWindow
        Write-Host "  $($T['gitSuccess'])" -ForegroundColor Green
    } catch {
        Write-Host ("$($T['gitFail'])$_") -ForegroundColor Red
        Write-Host ("$($T['gitManual'])$GitInstaller") -ForegroundColor Yellow
    }
} else {
    Write-Host ("$($T['gitNotFound'])$GitInstaller") -ForegroundColor Red
    Write-Host "  $($T['gitDownload'])" -ForegroundColor Yellow
    Write-Host "  $($T['gitNote'])" -ForegroundColor Yellow
}
Write-Host ""

# =============================================================================
# 6. Verify installation
# =============================================================================
Write-Host "  $($T['s6Title'])" -ForegroundColor Yellow

# Check Python
try {
    $pythonVer = & python --version 2>&1
    Write-Host ("$($T['pyCheck'])$pythonVer") -ForegroundColor Green
} catch {
    Write-Host "  $($T['pyMissing'])" -ForegroundColor Red
}

# Check pip
try {
    $pipVer = & pip --version 2>&1
    Write-Host ("$($T['pipCheck'])$pipVer") -ForegroundColor Green
} catch {
    Write-Host "  $($T['pipMissing'])" -ForegroundColor Red
}

# Check Npcap
$npcapReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Npcap" -ErrorAction SilentlyContinue
if ($npcapReg) {
    Write-Host ("$($T['npVer'])$($npcapReg.CurrentVersion))") -ForegroundColor Green
} else {
    Write-Host "  $($T['npNotDetected'])" -ForegroundColor Yellow
}

# Check Git
try {
    $gitVer = & git --version 2>&1
    Write-Host ("$($T['gitCheck'])$gitVer") -ForegroundColor Green
} catch {
    Write-Host "  $($T['gitNotDetected'])" -ForegroundColor Yellow
}

# Check Python packages via script
$checkScript = @"
import sys
results = []
packages = ['flask', 'jwt', 'yaml', 'cryptography', 'requests', 'urllib3',
            'psycopg2', 'waitress', 'openpyxl', 'bcrypt', 'dotenv',
            'aiohttp', 'watchdog']
for pkg in packages:
    try:
        __import__(pkg)
        results.append(f'  [+] {pkg}: OK')
    except ImportError:
        results.append(f'  [-] {pkg}: MISSING')
print('\n'.join(results))
"@

$checkScript | python 2>&1 | ForEach-Object {
    if ($_ -match "OK") { Write-Host $_ -ForegroundColor Green }
    elseif ($_ -match "MISSING") { Write-Host $_ -ForegroundColor Red }
    else { Write-Host $_ }
}
Write-Host ""

# =============================================================================
# 7. Create start script
# =============================================================================
$StartScriptPath = Join-Path $SetupDir "start_server.bat"
$ServerMainPath = Join-Path (Split-Path -Parent $SetupDir) "main.py"

$startBat = @"
@echo off
title GIAM-SAT Server v2.1.0
echo ============================================
echo   GIAM-SAT Server v2.1.0
echo   Starting at http://localhost:5000
echo ============================================
echo.

REM Tim Python installation
set PYTHON=
for /f "tokens=*" %%i in ('where python 2^>nul') do set PYTHON=%%i & goto :found
for /f "tokens=*" %%i in ('where python3 2^>nul') do set PYTHON=%%i & goto :found

REM Try common paths
if exist "C:\Program Files\Python311\python.exe" set PYTHON=C:\Program Files\Python311\python.exe & goto :found
if exist "C:\Python311\python.exe" set PYTHON=C:\Python311\python.exe & goto :found

echo [ERROR] Python not found. Please install Python first.
pause
exit /b 1

:found
echo Using Python: %PYTHON%
echo Starting server...
"%PYTHON%" "$ServerMainPath"
pause
"@

Set-Content -Path $StartScriptPath -Value $startBat -Encoding ASCII
Write-Host ("$($T['startScript'])$StartScriptPath") -ForegroundColor Green

# =============================================================================
# Summary
# =============================================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  $($T['sumTitle'])" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  $($T['dirHeader'])" -ForegroundColor White
Get-ChildItem $SetupDir -Name | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
Write-Host ""
Write-Host "  $($T['pkgsHeader'])" -ForegroundColor White
Write-Host "    flask, pyjwt, pyyaml, cryptography, requests, urllib3" -ForegroundColor Gray
Write-Host "    psycopg2-binary (PostgreSQL), waitress (production server)" -ForegroundColor Gray
Write-Host "    openpyxl (Excel export), bcrypt, python-dotenv" -ForegroundColor Gray
Write-Host "    aiohttp (async HTTP), watchdog (FIM monitor on agent)" -ForegroundColor Gray
Write-Host ""
Write-Host "  $($T['nextHeader'])" -ForegroundColor White
Write-Host "  $($T['next1'])" -ForegroundColor Yellow
Write-Host "  $($T['next2'])" -ForegroundColor Yellow
Write-Host "  $($T['next3'])" -ForegroundColor Yellow
Write-Host ""
Write-Host "  $($T['webUI'])" -ForegroundColor Cyan
Write-Host "  $($T['loginAdmin'])" -ForegroundColor Cyan
Write-Host ""
Write-Host "  $($T['pgHeader'])" -ForegroundColor Yellow
Write-Host "  $($T['pgDesc'])" -ForegroundColor Yellow
Write-Host "  $($T['pgDownload'])" -ForegroundColor Yellow
Write-Host ("$($T['pgEnv'])$ServerDir\.env:") -ForegroundColor Yellow
Write-Host "  $($T['pgBackend'])" -ForegroundColor Yellow
Write-Host "  $($T['pgHost'])" -ForegroundColor Yellow
Write-Host "  $($T['pgPass'])" -ForegroundColor Yellow
Write-Host ""
Write-Host ("$($T['cfgNote'])$ServerDir\.env with your API keys!") -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Cyan

Read-Host "  $($T['exitPrompt'])"