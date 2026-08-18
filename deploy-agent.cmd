@echo off
REM ========================================================
REM  GIAM-SAT Agent Deployment Script v4.3
REM  Chạy trên máy trạm (Run as Administrator)
REM  Usage: deploy-agent.cmd [ServerIP] [Port]
REM ========================================================
setlocal enabledelayedexpansion

echo ================================================
echo   GIAM-SAT Agent Deployer v4.3
echo ================================================
echo.

:: ── Check Admin ──
net session >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Can quyen Administrator!
    echo Click chuot phai vao file .cmd -> Run as Administrator
    pause
    exit /b 1
)

:: ── STEP 1: Add Windows Defender Exclusions (TRUOC KHI COPY FILE) ──
echo [*] STEP 1: Them Windows Defender Exclusions...
echo   Tranh bi xoa file EXE do false positive cua PyInstaller

:: v4.10 (MED-17): removed ExclusionProcess + _MEI* wildcard - excluding the
:: process by name would let ANY GiamSatAgent.exe (unsigned) bypass scanning.
set "EXCL_DIRS=C:\ProgramData\GIAM-SAT"
for %%D in (%EXCL_DIRS%) do (
    powershell -Command "Add-MpPreference -ExclusionPath '%%D' -ErrorAction SilentlyContinue" 2>nul
    echo   [+] Folder: %%D
)

echo   [OK] Defender exclusions added
echo.

:: ── STEP 2: Create directories ──
echo [*] STEP 2: Tao thu muc...
set AGENT_DIR=C:\ProgramData\GIAM-SAT\Agent
set DIST_DIR=C:\ProgramData\dist
mkdir "%AGENT_DIR%" 2>nul
mkdir "%AGENT_DIR%\logs" 2>nul
mkdir "%DIST_DIR%" 2>nul
echo   [OK] %AGENT_DIR%
echo.

:: ── STEP 3: Copy agent files ──
echo [*] STEP 3: Copy agent files...
set SCRIPT_DIR=%~dp0
copy /Y "%SCRIPT_DIR%GiamSatAgent.exe" "%DIST_DIR%\" >nul 2>&1
if exist "%DIST_DIR%\GiamSatAgent.exe" (
    echo   [+] GiamSatAgent.exe -^> %DIST_DIR%
) else (
    echo   [WARN] Khong tim thay GiamSatAgent.exe trong thu muc script
)

copy /Y "%SCRIPT_DIR%GiamSatUpdater.exe" "%DIST_DIR%\" >nul 2>&1
if exist "%DIST_DIR%\GiamSatUpdater.exe" (
    echo   [+] GiamSatUpdater.exe -^> %DIST_DIR%
) else (
    echo   [WARN] Khong tim thay GiamSatUpdater.exe trong thu muc script
)

copy /Y "%SCRIPT_DIR%tools\add_defender_exclusion.ps1" "%AGENT_DIR%\" >nul 2>&1
echo.

:: ── STEP 3.5: Deploy CA certificate (v4.10 - TLS server verification) ──
echo [*] STEP 3.5: Deploy ca.crt (xac thuc server khi dung TLS)...
if exist "%SCRIPT_DIR%ca.crt" (
    mkdir "%PROGRAMDATA%\GIAM-SAT\certs" 2>nul
    copy /Y "%SCRIPT_DIR%ca.crt" "%PROGRAMDATA%\GIAM-SAT\certs\ca.crt" >nul 2>&1
    echo   [+] ca.crt -^> %PROGRAMDATA%\GIAM-SAT\certs\
) else (
    echo   [WARN] Khong tim thay ca.crt trong thu muc script.
    echo   [WARN] Neu bat TLS, agent se TU CHOI ket noi khi khong co CA/pin (fail-closed).
)
echo.

:: ── STEP 4: Config server address ──
set SERVER_IP=%1
set SERVER_PORT=%2
if "%SERVER_IP%"=="" set SERVER_IP=YOUR_SERVER_IP
if "%SERVER_PORT%"=="" set SERVER_PORT=6666

echo [*] STEP 4: Cau hinh server (%SERVER_IP%:%SERVER_PORT%)...
echo   Agent se ket noi den: %SERVER_IP%:%SERVER_PORT%
echo.

:: ── STEP 5: Start Updater + Agent (tu dong dang ky Task Scheduler) ──
echo [*] STEP 5: Khoi dong Updater + Agent...
echo   Updater + Agent se tu dong dang ky Scheduled Task khi chay lan dau.
echo   Khong can tao task thu cong - tranh trung lap voi code cu.
echo.

:: Start updater (noi no tu dang ky Task Scheduler "GiamSatUpdater")
start /MIN "" "%DIST_DIR%\GiamSatUpdater.exe" --server %SERVER_IP% --port %SERVER_PORT%
echo   [OK] GiamSatUpdater started

:: Start agent (noi no tu dang ky Task Scheduler "GiamSatAgentStartup")
start "" "%DIST_DIR%\GiamSatAgent.exe" --server %SERVER_IP% --port %SERVER_PORT%
echo   [OK] GiamSatAgent started

echo.
:: ── STEP 6: Done ──
echo [*] STEP 6: Khoi dong GiamSatAgent...
echo   Agent se hien thi bang nhap thong tin nguoi dung.
echo   Sau khi nhap xong, Agent se chay ngam.
echo.
start "" "%DIST_DIR%\GiamSatAgent.exe" --server %SERVER_IP% --port %SERVER_PORT%
echo   [OK] GiamSatAgent started

echo.
echo ================================================
echo   DEPLOY HOAN THANH!
echo ================================================
echo.
echo Trang thai:
echo   - Updater: Scheduled Task + dang chay
echo   - Agent: Bang nhap thong tin hien ra
echo   - Defender: Da them exclusions
echo.
echo Kiem tra ket noi: Mo Dashboard -> Machines tab
echo.
pause