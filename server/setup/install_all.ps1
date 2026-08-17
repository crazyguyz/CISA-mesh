# =============================================================================
# GIAM-SAT Server Auto-Installer v2.1.0
# Tu dong cai dat toan bo cong cu can thiet de chay GIAM-SAT Server
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

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  GIAM-SAT Server Auto-Installer v2.1.0" -ForegroundColor Cyan
Write-Host "  Dang cai dat tat ca cong cu can thiet..." -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# =============================================================================
# 1. Install Python 3.11.9
# =============================================================================
Write-Host "[1/6] Cai dat Python 3.11.9..." -ForegroundColor Yellow

$PythonInstaller = Join-Path $SetupDir "python-3.11.9-amd64.exe"

if (Test-Path $PythonInstaller) {
    Write-Host "  [+] Tim thay Python installer" -ForegroundColor Green
    Write-Host "  [*] Dang cai dat Python (silent mode)..." -ForegroundColor Gray
    
    $installArgs = "/quiet InstallAllUsers=1 PrependPath=1 Include_test=0 Include_pip=1"
    try {
        $process = Start-Process -FilePath $PythonInstaller -ArgumentList $installArgs -Wait -PassThru -NoNewWindow
        if ($process.ExitCode -eq 0) {
            Write-Host "  [+] Python 3.11.9 installed successfully!" -ForegroundColor Green
        } else {
            Write-Host "  [!] Python installer returned exit code: $($process.ExitCode)" -ForegroundColor Yellow
            Write-Host "  [*] Manual install may be needed. Run: $PythonInstaller" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  [-] Python install failed: $_" -ForegroundColor Red
    }
} else {
    Write-Host "  [-] Python installer NOT found at: $PythonInstaller" -ForegroundColor Red
    Write-Host "  [*] Download from: https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe" -ForegroundColor Yellow
}

# Refresh PATH (try/catch for ConstrainedLanguage mode)
try {
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
} catch {
    Write-Host "  [!] Cannot refresh PATH (ConstrainedLanguage mode). Continuing..." -ForegroundColor Yellow
}
Write-Host ""

# =============================================================================
# 2. Upgrade pip
# =============================================================================
Write-Host "[2/6] Nang cap pip..." -ForegroundColor Yellow

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
        Write-Host "  [+] pip ready" -ForegroundColor Green
    } else {
        Write-Host "  [-] pip not found. Please install Python first." -ForegroundColor Red
    }
} catch {
    Write-Host "  [-] pip upgrade failed: $_" -ForegroundColor Red
}
Write-Host ""

# =============================================================================
# 3. Install Python packages (from requirements.txt)
# =============================================================================
Write-Host "[3/6] Cai dat Python packages..." -ForegroundColor Yellow

$reqFile = Join-Path $SetupDir "requirements.txt"

if (Test-Path $reqFile) {
    Write-Host "  [*] Installing from requirements.txt..." -ForegroundColor Gray
    try {
        pip install -r $reqFile 2>&1 | ForEach-Object {
            if ($_ -match "Successfully installed") { Write-Host "  [+] $_" -ForegroundColor Green }
            elseif ($_ -match "already satisfied") { Write-Host "  [~] $_" -ForegroundColor Gray }
            elseif ($_ -match "ERROR|error") { Write-Host "  [-] $_" -ForegroundColor Red }
        }
    } catch {
        Write-Host "  [-] Some packages may have failed. See errors above." -ForegroundColor Red
    }
} else {
    Write-Host "  [-] requirements.txt not found at: $reqFile" -ForegroundColor Red
    Write-Host "  [*] Falling back to manual package list..." -ForegroundColor Yellow
    $packages = @(
        "flask", "pyjwt", "pyyaml", "cryptography", "requests", "urllib3",
        "psycopg2-binary", "waitress", "openpyxl", "bcrypt", "python-dotenv",
        "aiohttp", "watchdog"
    )
    foreach ($pkg in $packages) {
        Write-Host "  [*] Installing: $pkg..." -ForegroundColor Gray
        try { pip install $pkg 2>&1 | Out-Null; Write-Host "  [+] $pkg installed" -ForegroundColor Green }
        catch { Write-Host "  [-] Failed to install $pkg" -ForegroundColor Red }
    }
}
Write-Host ""

# =============================================================================
# 4. Install Npcap (packet capture for Agent network collector)
# =============================================================================
Write-Host "[4/6] Cai dat Npcap (network packet capture)..." -ForegroundColor Yellow

$NpcapInstaller = Join-Path $SetupDir "npcap-1.80.exe"

if (Test-Path $NpcapInstaller) {
    Write-Host "  [+] Tim thay Npcap installer" -ForegroundColor Green
    Write-Host "  [*] Dang cai dat Npcap (silent mode)..." -ForegroundColor Gray
    Write-Host "  [*] Npcap cho phep Agent bat goi tin mang de phan tich" -ForegroundColor Gray
    
    # Npcap silent install options:
    # /S = silent
    # winpcap_mode = no (use npcap native, not WinPcap compat)
    # loopback = yes (capture loopback traffic)
    # dot11 = yes (WiFi capture support)
    $npcapArgs = "/S /winpcap_mode=no /loopback_support=yes /dot11_support=yes"
    try {
        $process = Start-Process -FilePath $NpcapInstaller -ArgumentList $npcapArgs -Wait -PassThru -NoNewWindow
        Write-Host "  [+] Npcap installed successfully!" -ForegroundColor Green
    } catch {
        Write-Host "  [-] Npcap install failed: $_" -ForegroundColor Red
        Write-Host "  [*] You can install manually later: $NpcapInstaller" -ForegroundColor Yellow
    }
} else {
    Write-Host "  [-] Npcap installer NOT found at: $NpcapInstaller" -ForegroundColor Red
    Write-Host "  [*] Download from: https://npcap.com/dist/npcap-1.80.exe" -ForegroundColor Yellow
    Write-Host "  [*] Without Npcap, Agent will not capture network packets (other features still work)." -ForegroundColor Yellow
}
Write-Host ""

# =============================================================================
# 5. Install Git (for Sigma rule updates)
# =============================================================================
Write-Host "[5/6] Cai dat Git (Sigma rule updates)..." -ForegroundColor Yellow

$GitInstaller = Join-Path $SetupDir "Git-2.47.0-64-bit.exe"

if (Test-Path $GitInstaller) {
    Write-Host "  [+] Tim thay Git installer" -ForegroundColor Green
    Write-Host "  [*] Dang cai dat Git (silent mode)..." -ForegroundColor Gray
    Write-Host "  [*] Git dung de tu dong dong bo Sigma rules tu SigmaHQ" -ForegroundColor Gray
    
    # Git silent install options:
    # /VERYSILENT = no UI at all
    # /NORESTART = don't restart
    # /NOCANCEL = prevent cancel
    # /CLOSEAPPLICATIONS = close apps using git files
    # /NOICONS = no desktop icon
    $gitArgs = "/VERYSILENT /NORESTART /NOCANCEL /CLOSEAPPLICATIONS /NOICONS"
    try {
        $process = Start-Process -FilePath $GitInstaller -ArgumentList $gitArgs -Wait -PassThru -NoNewWindow
        Write-Host "  [+] Git installed successfully!" -ForegroundColor Green
    } catch {
        Write-Host "  [-] Git install failed: $_" -ForegroundColor Red
        Write-Host "  [*] You can install manually later: $GitInstaller" -ForegroundColor Yellow
    }
} else {
    Write-Host "  [-] Git installer NOT found at: $GitInstaller" -ForegroundColor Red
    Write-Host "  [*] Download from: https://git-scm.com/download/win" -ForegroundColor Yellow
    Write-Host "  [*] Without Git, Sigma rule auto-update will be disabled." -ForegroundColor Yellow
}
Write-Host ""

# =============================================================================
# 6. Verify installation
# =============================================================================
Write-Host "[6/6] Kiem tra cai dat..." -ForegroundColor Yellow

# Check Python
try {
    $pythonVer = & python --version 2>&1
    Write-Host "  [+] Python: $pythonVer" -ForegroundColor Green
} catch {
    Write-Host "  [-] Python not found in PATH" -ForegroundColor Red
}

# Check pip
try {
    $pipVer = & pip --version 2>&1
    Write-Host "  [+] pip: $pipVer" -ForegroundColor Green
} catch {
    Write-Host "  [-] pip not found" -ForegroundColor Red
}

# Check Npcap
$npcapReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Npcap" -ErrorAction SilentlyContinue
if ($npcapReg) {
    Write-Host "  [+] Npcap: installed (version $($npcapReg.CurrentVersion))" -ForegroundColor Green
} else {
    Write-Host "  [!] Npcap: not detected (optional - network packet capture)" -ForegroundColor Yellow
}

# Check Git
try {
    $gitVer = & git --version 2>&1
    Write-Host "  [+] Git: $gitVer" -ForegroundColor Green
} catch {
    Write-Host "  [!] Git: not detected (optional - Sigma auto-update)" -ForegroundColor Yellow
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
Write-Host "  [+] Created start script: $StartScriptPath" -ForegroundColor Green

# =============================================================================
# Summary
# =============================================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  GIAM-SAT Server Installation Complete!" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  THU MUC SETUP HIEN CO:" -ForegroundColor White
Get-ChildItem $SetupDir -Name | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
Write-Host ""
Write-Host "  PACKAGES DA CAI:" -ForegroundColor White
Write-Host "    flask, pyjwt, pyyaml, cryptography, requests, urllib3" -ForegroundColor Gray
Write-Host "    psycopg2-binary (PostgreSQL), waitress (production server)" -ForegroundColor Gray
Write-Host "    openpyxl (Excel export), bcrypt, python-dotenv" -ForegroundColor Gray
Write-Host "    aiohttp (async HTTP), watchdog (FIM monitor on agent)" -ForegroundColor Gray
Write-Host ""
Write-Host "  NEXT STEPS:" -ForegroundColor White
Write-Host "    1. Configure:  powershell -File setup\setup_config.ps1" -ForegroundColor Yellow
Write-Host "    2. Start:      cd .. && python main.py" -ForegroundColor Yellow
Write-Host "    OR:            Run start_server.bat (created in setup folder)" -ForegroundColor Yellow
Write-Host ""
Write-Host "  Web UI:  http://localhost:5000" -ForegroundColor Cyan
Write-Host "  Login:   admin / admin (doi mat khau ngay khi dang nhap)" -ForegroundColor Cyan
Write-Host ""
Write-Host "  POSTGRESQL (Optional but recommended):" -ForegroundColor Yellow
Write-Host "    Default backend is SQLite. For production, install PostgreSQL 16:" -ForegroundColor Yellow
Write-Host "    Download: https://get.enterprisedb.com/postgresql/postgresql-16.4-1-windows-x64.exe" -ForegroundColor Yellow
Write-Host "    After install, set in $ServerDir\.env:" -ForegroundColor Yellow
Write-Host "      GIAMSAT_DB_BACKEND=postgres" -ForegroundColor Yellow
Write-Host "      GIAMSAT_PG_HOST=127.0.0.1" -ForegroundColor Yellow
Write-Host "      GIAMSAT_PG_PASSWORD=your_password" -ForegroundColor Yellow
Write-Host ""
Write-Host "  CONFIGURE $ServerDir\.env with your API keys!" -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Cyan

Read-Host "Press Enter to exit"