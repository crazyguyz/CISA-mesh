@echo off
REM =============================================================================
REM GIAM-SAT v3.0 Multi-Instance Startup Script
REM =============================================================================
REM Purpose: Launch 4 ingest servers + 1 main server for 1000 agents.
REM
REM Usage:
REM   start_multi_instance.bat           (all 5 processes)
REM   start_multi_instance.bat ingest    (ingest servers only)
REM   start_multi_instance.bat main      (main server only)
REM
REM Prerequisites:
REM   - Python 3.11+ installed
REM   - Redis running (optional, for shared queue)
REM   - PostgreSQL running (optional, for scale)
REM =============================================================================

setlocal enabledelayedexpansion

set SERVER_DIR=E:\giamsat\server

echo ========================================
echo  GIAM-SAT v3.0 Multi-Instance Startup
echo ========================================
echo.

if "%1"=="" goto all
if "%1"=="ingest" goto ingest
if "%1"=="main" goto main

:all
echo [*] Starting ALL services...
echo.

REM ---- Ingest Servers (4 instances) ----
echo [*] Starting Ingest Server on port 6667...
start "GIAM-Ingest-6667" cmd /c "cd /d %SERVER_DIR% && python ingest_server.py --port 6667 --workers 250"
timeout /t 2 > nul

echo [*] Starting Ingest Server on port 6668...
start "GIAM-Ingest-6668" cmd /c "cd /d %SERVER_DIR% && python ingest_server.py --port 6668 --workers 250"
timeout /t 2 > nul

echo [*] Starting Ingest Server on port 6669...
start "GIAM-Ingest-6669" cmd /c "cd /d %SERVER_DIR% && python ingest_server.py --port 6669 --workers 250"
timeout /t 2 > nul

echo [*] Starting Ingest Server on port 6670...
start "GIAM-Ingest-6670" cmd /c "cd /d %SERVER_DIR% && python ingest_server.py --port 6670 --workers 250"
timeout /t 3 > nul

REM ---- Main Server (Web UI + Worker Pool) ----
echo [*] Starting Main Server (Web UI + Workers)...
start "GIAM-Main" cmd /c "cd /d %SERVER_DIR% && python main.py"

echo.
echo ========================================
echo  All services started!
echo.
echo  Ingest: ports 6667, 6668, 6669, 6670
echo  Web UI: http://localhost:5000
echo  TCP LB: port 6666 (if Nginx running)
echo.
echo  Close this window to stop (or Ctrl+C each terminal).
echo ========================================
goto end

:ingest
echo [*] Starting Ingest Servers only...
start "GIAM-Ingest-6667" cmd /c "cd /d %SERVER_DIR% && python ingest_server.py --port 6667 --workers 250"
timeout /t 2 > nul
start "GIAM-Ingest-6668" cmd /c "cd /d %SERVER_DIR% && python ingest_server.py --port 6668 --workers 250"
timeout /t 2 > nul
start "GIAM-Ingest-6669" cmd /c "cd /d %SERVER_DIR% && python ingest_server.py --port 6669 --workers 250"
timeout /t 2 > nul
start "GIAM-Ingest-6670" cmd /c "cd /d %SERVER_DIR% && python ingest_server.py --port 6670 --workers 250"
echo [*] Ingest servers started on ports 6667-6670.
goto end

:main
echo [*] Starting Main Server only...
start "GIAM-Main" cmd /c "cd /d %SERVER_DIR% && python main.py"
echo [*] Main Server started (Web UI: http://localhost:5000).
goto end

:end
endlocal