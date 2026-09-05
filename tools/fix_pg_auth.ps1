# =============================================================================
# GIAM-SAT fix_pg_auth.ps1 — Đồng bộ role/db PostgreSQL với server\.env
# -----------------------------------------------------------------------------
# Dùng khi dashboard báo:
#   "WARNING: Database is running on SQLite fallback! PostgreSQL unreachable"
#
# Việc cần làm:
#   1. Chạy với tài khoản Windows Admin.
#   2. Nhập mật khẩu SUPERUSER PostgreSQL (role "postgres") khi được hỏi.
#   3. Script sẽ: tạo role nếu thiếu -> đặt mật khẩu role = GIAMSAT_PG_PASSWORD
#      (giá trị trong server\.env) -> đảm bảo database tồn tại + owner đúng.
#   4. Restart server GIAM-SAT để kết nối PG (fallback chỉ thử 1 lần lúc start).
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File tools\fix_pg_auth.ps1
#   powershell -ExecutionPolicy Bypass -File tools\fix_pg_auth.ps1 -ServerDir D:\test\server
# =============================================================================

param(
    [string]$ServerDir = ""
)
$ErrorActionPreference = "Stop"

if (-not $ServerDir) { $ServerDir = Split-Path -Parent (Split-Path -Parent $PSScriptRoot) }
$envFile = Join-Path $ServerDir ".env"
if (-not (Test-Path $envFile)) {
    Write-Host "[FAIL] Khong tim thay .env tai: $envFile" -ForegroundColor Red
    exit 1
}

# ---- doc .env (khong BOM) ----
$cfg = @{}
Get-Content $envFile | ForEach-Object {
    $line = $_.Trim()
    if ($line -match '^([A-Za-z0-9_]+)=(.*)$') { $cfg[$Matches[1]] = $Matches[2].Trim() }
}
$pgHost = $cfg['GIAMSAT_PG_HOST']; if (-not $pgHost) { $pgHost = '127.0.0.1' }
$pgPort = $cfg['GIAMSAT_PG_PORT']; if (-not $pgPort) { $pgPort = '5432' }
$pgDb   = $cfg['GIAMSAT_PG_DBNAME']; if (-not $pgDb) { $pgDb = 'giamsat' }
$pgUser = $cfg['GIAMSAT_PG_USER']; if (-not $pgUser) { $pgUser = 'postgres' }
$pgPass = $cfg['GIAMSAT_PG_PASSWORD']
if (-not $pgPass) { Write-Host "[FAIL] GIAMSAT_PG_PASSWORD rong trong .env" -ForegroundColor Red; exit 1 }
Write-Host "ServerDir : $ServerDir"
Write-Host "PG target : $pgHost`:$pgPort  db=$pgDb  role=$pgUser"

# ---- tim psql.exe ----
$psql = Get-Command psql -ErrorAction SilentlyContinue
if (-not $psql) {
    foreach ($cand in @(
        "$env:ProgramFiles\PostgreSQL\16\bin\psql.exe",
        "$env:ProgramFiles\PostgreSQL\17\bin\psql.exe",
        "$env:ProgramFiles\PostgreSQL\15\bin\psql.exe",
        "${env:ProgramFiles(x86)}\PostgreSQL\16\bin\psql.exe")) {
        if (Test-Path $cand) { $psql = $cand; break }
    }
}
if (-not $psql) { Write-Host "[FAIL] Khong tim thay psql.exe (PostgreSQL chua cai hoac chua vao PATH?)" -ForegroundColor Red; exit 1 }
$psqlPath = if ($psql -is [string]) { $psql } else { $psql.Source }
Write-Host "psql     : $psqlPath"

# ---- mat khau SUPERUSER (role postgres) ----
$sec = Read-Host "Mat khau SUPERUSER PostgreSQL (role 'postgres')" -AsSecureString
$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
$suPass = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)

$env:PGPASSWORD = $suPass
function Invoke-Psql([string]$sql) {
    & $psqlPath -h $pgHost -p $pgPort -U postgres -d postgres -v ON_ERROR_STOP=1 -t -A -c $sql 2>&1
}
function Quote-Sql([string]$s) { return $s.Replace("'", "''") }

Write-Host ""
Write-Host "==> Dang kiem tra role '$pgUser'..."
$roleSql = "SELECT 1 FROM pg_roles WHERE rolname='$($pgUser.Replace("'","''"))'"
$roleExists = Invoke-Psql $roleSql
if ($LASTEXITCODE -ne 0) { Write-Host "[FAIL] Khong ket noi duoc voi role postgres (sai mat khau / pg_hba?)" -ForegroundColor Red; exit 1 }
if ($roleExists -match '1') {
    Write-Host "  [~] Role da ton tai -> cap nhat mat khau..."
    Invoke-Psql "ALTER ROLE `"$($pgUser.Replace('"','""'))`" WITH LOGIN PASSWORD '$($pgPass | Quote-Sql)'" | Out-Null
} else {
    Write-Host "  [+] Tao role moi..."
    Invoke-Psql "CREATE ROLE `"$($pgUser.Replace('"','""'))`" WITH LOGIN SUPERUSER PASSWORD '$($pgPass | Quote-Sql)'" | Out-Null
}
if ($LASTEXITCODE -ne 0) { Write-Host "[FAIL] ALTER/CREATE ROLE that bai" -ForegroundColor Red; exit 1 }

Write-Host "==> Kiem tra database '$pgDb'..."
$dbExists = Invoke-Psql "SELECT 1 FROM pg_database WHERE datname='$($pgDb.Replace("'","''"))'"
if ($dbExists -match '1') {
    Write-Host "  [~] Database da ton tai -> set owner..."
    Invoke-Psql "ALTER DATABASE `"$($pgDb.Replace('"','""'))`" OWNER TO `"$($pgUser.Replace('"','""'))`"" | Out-Null
} else {
    Write-Host "  [+] Tao database moi..."
    Invoke-Psql "CREATE DATABASE `"$($pgDb.Replace('"','""'))`" OWNER `"$($pgUser.Replace('"','""'))`"" | Out-Null
}
if ($LASTEXITCODE -ne 0) { Write-Host "[FAIL] Database step that bai" -ForegroundColor Red; exit 1 }

Write-Host ""
Write-Host "==> Verify bang dung role '$pgUser' (gioi han 8s)..."
$env:PGPASSWORD = $pgPass
$ver = & $psqlPath -h $pgHost -p $pgPort -U $pgUser -d $pgDb -t -A -c "select version()" 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "  [OK] Ket noi thanh cong: $ver" -ForegroundColor Green
} else {
    Write-Host "  [FAIL] Van khong ket noi duoc voi role $pgUser" -ForegroundColor Red
    Write-Host "  $ver"
    exit 1
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  XONG. Gio restart server GIAM-SAT de chuyen sang PostgreSQL." -ForegroundColor Green
Write-Host "  (SQLite fallback chi duoc thu 1 lan luc khoi dong - restart la ap dung)" -ForegroundColor Yellow
Write-Host "  Neu van bao fallback: xem logs\\server_error.log va kiem tra pg_hba.conf" -ForegroundColor Yellow
Write-Host "  (PG >=15 mac dinh SCRAM-SHA-256 - dung loai bo; neu sua pg_hba sang md5 nho chinh lai)." -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Green
