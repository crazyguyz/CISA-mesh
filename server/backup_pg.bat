@echo off
REM GIAM-SAT PostgreSQL Backup Script
REM Schedule: Windows Task Scheduler, chạy 2:00 AM hàng ngày
REM Usage: backup_pg.bat [retention_days]

setlocal enabledelayedexpansion

:: ── Config ──
set BACKUP_DIR=E:\giamsat\backups
set PGUSER=postgres
set PGPASSWORD=postgres
set PGHOST=127.0.0.1
set PGPORT=5432
set DBNAME=giamsat
set RETENTION_DAYS=%1
if "%RETENTION_DAYS%"=="" set RETENTION_DAYS=30

:: ── Create backup dir if not exists ──
if not exist "%BACKUP_DIR%" mkdir "%BACKUP_DIR%"

:: ── Generate timestamp ──
for /f "tokens=2 delims==" %%I in ('wmic os get localdatetime /value') do set DT=%%I
set TIMESTAMP=%DT:~0,4%%DT:~4,2%%DT:~6,2%_%DT:~8,2%%DT:~10,2%%DT:~12,2%
set FILE=%BACKUP_DIR%\giamsat_%TIMESTAMP%.sql

:: ── Run pg_dump ──
echo [%date% %time%] Starting backup to %FILE%
pg_dump -h %PGHOST% -p %PGPORT% -U %PGUSER% -d %DBNAME% -F p --no-owner --no-acl > "%FILE%" 2>&1

if %ERRORLEVEL% neq 0 (
    echo [ERROR] pg_dump failed with exit code %ERRORLEVEL%
    type "%FILE%"
    del "%FILE%" 2>nul
    exit /b 1
)

:: ── Compress with PowerShell ──
powershell -Command "Compress-Archive -Path '%FILE%' -DestinationPath '%FILE%.zip' -Force" 2>nul
if exist "%FILE%.zip" (
    del "%FILE%"
    for %%F in ("%FILE%.zip") do set SIZE=%%~zF
    set /a SIZE_KB=!SIZE!/1024
    echo [%date% %time%] Backup saved: %FILE%.zip (!SIZE_KB! KB)
) else (
    echo [%date% %time%] Backup saved: %FILE% (uncompressed)
)

:: ── Rotation: xóa backup cũ hơn RETENTION_DAYS ──
echo Cleaning backups older than %RETENTION_DAYS% days...
forfiles /p "%BACKUP_DIR%" /s /m giamsat_*.sql /d -%RETENTION_DAYS% /c "cmd /c echo Deleting @file && del @file" 2>nul
forfiles /p "%BACKUP_DIR%" /s /m giamsat_*.zip /d -%RETENTION_DAYS% /c "cmd /c echo Deleting @file && del @file" 2>nul

echo [%date% %time%] Backup complete.
exit /b 0