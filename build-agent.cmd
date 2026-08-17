@echo off
REM ============================================================
REM  GIAM-SAT v3.9.3 - Multi-Platform Build Script (CMD wrapper)
REM  Builds Agent + Updater for Windows AND Linux (via WSL)
REM
REM  Auto-update: Server serves files from dist\
REM  Windows: build-agent.ps1 -> dist\GiamSatAgent.exe, GiamSatUpdater.exe
REM  Linux:   agent/build-agent.sh (via WSL) -> agent/dist/linux_*/
REM
REM  Double-click to build, or: build-agent.cmd 3.9.3 [windows|all]
REM ============================================================
setlocal enabledelayedexpansion

set VERSION=%1
set TARGET=%2

if "%VERSION%"=="" set /p VERSION="Enter version (e.g., 3.9.3): "
if "%VERSION%"=="" set VERSION=3.9.3
if "%TARGET%"=="" (
    echo.
    echo Select build target:
    echo   [1] Windows only ^(agent.exe + updater.exe^)
    echo   [2] Windows + Linux ^(requires WSL^)
    echo.
    set /p CHOICE="Choice [1-2]: "
    if "!CHOICE!"=="2" set TARGET=all
    if "!CHOICE!"=="1" set TARGET=windows
)

echo.
echo ========================================
echo  GIAM-SAT Build v%VERSION%
echo  Target: %TARGET%
echo  Auto-update source: %~dp0dist\
echo ========================================
echo.

REM ========================================
REM  STEP 0: Clear Python caches
REM ========================================
echo [0/3] Clearing Python __pycache__ caches...
for /d /r "%~dp0.." %%d in (__pycache__) do @if exist "%%d" rd /s /q "%%d" 2>nul
echo   Done.

REM ========================================
REM  STEP 1: Build Windows (build-agent.ps1)
REM ========================================
echo [1/2] Building Windows Agent + Updater...
echo   -> Output: dist\GiamSatAgent.exe, dist\GiamSatUpdater.exe
echo   -> Server auto-update serves from: dist\
powershell -ExecutionPolicy Bypass -File "%~dp0build-agent.ps1" -Version "%VERSION%" -NoServer
if errorlevel 1 (
    echo [!] WARNING: Build completed with errors
) else (
    echo [OK] Windows build complete
)

echo.
echo   Results:
for %%f in ("%~dp0dist\GiamSatAgent.exe" "%~dp0dist\GiamSatUpdater.exe" "%~dp0dist\GiamSatAgent_v%VERSION%.exe") do (
    if exist %%f echo     %%~nxf  %%~zf bytes
)
if errorlevel 1 echo     (no .exe found - build may have failed)

REM ========================================
REM  STEP 2: Build Linux (agent/build-agent.sh via WSL)
REM ========================================
if "%TARGET%"=="windows" goto :done

echo.
echo [2/2] Building Linux Agent...

REM Check WSL
wsl --status >nul 2>&1
if errorlevel 1 (
    echo   [!] WSL not installed. Skipping Linux build.
    echo   To build on Linux directly: bash agent/build-agent.sh
    goto :done
)

REM Helper: run build-agent.sh in WSL for a given arch
REM Detect WSL mount path from current directory
for %%I in ("%~dp0.") do set "WSL_PROJECT=/mnt/%%~dI%%~pI"
set "WSL_PROJECT=%WSL_PROJECT:\=/%"
set "WSL_PROJECT=%WSL_PROJECT::=%"
if "%WSL_PROJECT:~-1%"=="/" set "WSL_PROJECT=%WSL_PROJECT:~0,-1%"
echo   WSL path: %WSL_PROJECT%
del "%TEMP%\giamsat_wsl_check.txt" 2>nul

REM Build x86_64
echo   [*] Building x86_64...
wsl bash -c "cd %WSL_PROJECT%/agent && bash build-agent.sh" 2>nul
if exist "%~dp0agent\dist\linux_x86_64\giamsat_agent" (
    echo     [OK] x86_64: agent\dist\linux_x86_64\giamsat_agent
) else (
    echo     [!] x86_64 build FAILED
)

REM Build ARM64
echo   [*] Building ARM64 (Raspberry Pi 4/5)...
wsl bash -c "cd %WSL_PROJECT%/agent && bash build-agent.sh arm64" 2>nul
if exist "%~dp0agent\dist\linux_arm64\giamsat_agent" (
    echo     [OK] ARM64: agent\dist\linux_arm64\giamsat_agent
) else (
    echo     [!] ARM64 build FAILED
)

REM Build ARMv7
echo   [*] Building ARMv7 lightweight (Raspberry Pi 3)...
wsl bash -c "cd %WSL_PROJECT%/agent && bash build-agent.sh armv7 --lightweight" 2>nul
if exist "%~dp0agent\dist\linux_armv7\giamsat_agent" (
    echo     [OK] ARMv7: agent\dist\linux_armv7\giamsat_agent
) else (
    echo     [!] ARMv7 build FAILED
)

:done
echo.
echo ========================================
echo  BUILD COMPLETE - v%VERSION%
echo ========================================
echo.
echo  Windows (auto-update via /api/agent/download):
echo    dist\GiamSatAgent.exe
echo    dist\GiamSatUpdater.exe
echo.
echo  Linux (manual install):
dir /s /b "%~dp0agent\dist\linux_*\giamsat_agent" 2>nul
if errorlevel 1 echo    (no Linux binaries - WSL may not be available)
echo.
echo  To install on Linux:
echo    sudo cp agent/dist/linux_x86_64/giamsat_agent /usr/local/bin/
echo    sudo cp agent/giamsat-agent.service /etc/systemd/system/
echo    sudo systemctl enable --now giamsat-agent
echo.
pause