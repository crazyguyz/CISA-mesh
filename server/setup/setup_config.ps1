# =============================================================================
# GIAM-SAT Configuration Setup v1.0
# Interactive .env generator — run anytime to add/update settings.
#
# Usage (Run as Administrator):
#   powershell -ExecutionPolicy Bypass -File setup_config.ps1
#
# Safe to re-run: existing values are preserved unless you type new ones.
# Leave blank = skip (keep existing or leave empty).
# =============================================================================

$ErrorActionPreference = "Continue"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ServerDir = Split-Path -Parent $ScriptDir
$EnvFile = Join-Path $ServerDir ".env"
$EnvExample = Join-Path $ServerDir ".env.example"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  GIAM-SAT Configuration Setup v1.0" -ForegroundColor Cyan
Write-Host "  Press Enter to skip optional items." -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Load existing .env if available
$env = @{}
if (Test-Path $EnvFile) {
    Get-Content $EnvFile | ForEach-Object {
        $line = $_.Trim()
        if ($line -match '^\s*$' -or $line.StartsWith('#')) { return }
        if ($line -match '^([^=]+)=(.*)$') {
            $env[$Matches[1].Trim()] = $Matches[2].Trim()
        }
    }
} elseif (Test-Path $EnvExample) {
    Get-Content $EnvExample | ForEach-Object {
        $line = $_.Trim()
        if ($line -match '^\s*$' -or $line.StartsWith('#')) { return }
        if ($line -match '^([^=]+)=(.*)$') {
            $env[$Matches[1].Trim()] = $Matches[2].Trim()
        }
    }
}

function Ask-Config {
    param([string]$Key, [string]$Prompt, [string]$Default, [switch]$IsPassword)
    
    $current = $env[$Key]
    if (-not $current) { $current = $Default }
    
    $displayDefault = if ($IsPassword -and $current) { "(co san - an)" } elseif ($current) { "($current)" } else { "(trong)" }
    
    $answer = Read-Host "$Prompt $displayDefault"
    
    if ($answer -ne "") {
        $env[$Key] = $answer
    } elseif ($current) {
        $env[$Key] = $current
    } else {
        $env[$Key] = ""
    }
}

# v4.10: Password policy (same as server PASSWORD_POLICY)
function Test-PasswordPolicy([string]$pw) {
    if ($pw.Length -lt 12)        { return "Mat khau phai co it nhat 12 ky tu" }
    if ($pw -notmatch '[A-Z]')    { return "Thieu ky tu IN HOA (A-Z)" }
    if ($pw -notmatch '[a-z]')    { return "Thieu ky tu thuong (a-z)" }
    if ($pw -notmatch '[0-9]')    { return "Thieu chu so (0-9)" }
    if ($pw -notmatch '[^A-Za-z0-9]') { return "Thieu ky tu dac biet (!@#...)" }
    return ""
}

# v4.10: Admin account - setup_config.ps1 owns first-run admin creation.
function Ask-AdminCredentials {
    $currentUser = $env["GIAMSAT_ADMIN_USER"]
    $currentPw = $env["GIAMSAT_ADMIN_PASSWORD"]

    $user = Read-Host "  Ten dang nhap admin (Enter = 'admin')"
    if ($user -eq "") { $user = if ($currentUser) { $currentUser } else { "admin" } }
    $env["GIAMSAT_ADMIN_USER"] = $user

    if ($currentPw) {
        Write-Host "  Mat khau admin hien tai: da co (an). Enter de giu nguyen, nhap de doi." -ForegroundColor Gray
    }
    $pw1 = Read-Host "  Mat khau admin (toi thieu 12 ky tu: hoa/thuong/so/dac biet)"
    if ($pw1 -eq "" -and $currentPw) {
        $env["GIAMSAT_ADMIN_PASSWORD"] = $currentPw
        return
    }
    if ($pw1 -eq "") {
        # Leave empty -> server auto-generates a random password (printed once)
        $env.Remove("GIAMSAT_ADMIN_PASSWORD")
        Write-Host "  [!] Bo qua: server se TU DONG sinh mat khau ngau nhien khi khoi dong." -ForegroundColor DarkYellow
        return
    }
    while ($true) {
        $pw2 = Read-Host "  Nhap lai mat khau admin"
        if ($pw1 -ne $pw2) { Write-Host "  [!] Hai lan nhap khong khop, nhap lai." -ForegroundColor Red; continue }
        $err = Test-PasswordPolicy $pw1
        if ($err) { Write-Host "  [!] $err" -ForegroundColor Red }
        else { break }
        $pw1 = Read-Host "  Mat khau admin"
    }
    $env["GIAMSAT_ADMIN_PASSWORD"] = $pw1
}

# =============================================================================
# 1. Database Backend
# =============================================================================
Write-Host "--- DATABASE ---" -ForegroundColor Yellow
Write-Host "  1. SQLite (mac dinh, khong can cau hinh)" -ForegroundColor Gray
Write-Host "  2. PostgreSQL (khuyen nghi cho production)" -ForegroundColor Gray
$dbChoice = Read-Host "  Chon [1-2] (Enter = SQLite)"
if ($dbChoice -eq "2") {
    $env["GIAMSAT_DB_BACKEND"] = "postgres"
    Write-Host "  [*] PostgreSQL selected" -ForegroundColor Green
    Ask-Config "GIAMSAT_PG_HOST"       "  Host"        "127.0.0.1"
    Ask-Config "GIAMSAT_PG_PORT"       "  PostgreSQL Port (5432)"        "5432"
    Ask-Config "GIAMSAT_PG_DBNAME"     "  Database"    "giamsat"
    Ask-Config "GIAMSAT_PG_USER"       "  User"        "postgres"
    Ask-Config "GIAMSAT_PG_PASSWORD"   "  Password"    "" -IsPassword
} else {
    $env["GIAMSAT_DB_BACKEND"] = "sqlite"
    Write-Host "  [*] SQLite selected (default)" -ForegroundColor Green
}
Write-Host ""

# =============================================================================
# 2. DeepSeek AI (optional)
# =============================================================================
Write-Host "--- AI / DeepSeek (tuy chon) ---" -ForegroundColor Yellow
Write-Host "  Dung cho AI Assistant & Auto-Monitor phan tich tu dong." -ForegroundColor Gray
Ask-Config "DEEPSEEK_API_KEY" "  API Key" ""
Write-Host ""

# =============================================================================
# 3. Telegram Alerts (optional)
# =============================================================================
Write-Host "--- Telegram Alerts (tuy chon) ---" -ForegroundColor Yellow
Write-Host "  Canh bao thoi gian thuc qua Telegram Bot." -ForegroundColor Gray
Write-Host "  Tao bot tai: https://t.me/BotFather" -ForegroundColor Gray
Ask-Config "TELEGRAM_BOT_TOKEN" "  Bot Token" ""
Ask-Config "TELEGRAM_CHAT_ID"   "  Chat ID" ""
Write-Host ""

# =============================================================================
# 4. Email Alerts (optional)
# =============================================================================
Write-Host "--- Email Alerts (tuy chon) ---" -ForegroundColor Yellow
Write-Host "  Canh bao qua SMTP email." -ForegroundColor Gray
Ask-Config "GIAMSAT_SMTP_HOST" "  SMTP Host" ""
Ask-Config "GIAMSAT_SMTP_PORT" "  SMTP Port" "465"
Ask-Config "GIAMSAT_SMTP_USER" "  SMTP User" ""
Ask-Config "GIAMSAT_SMTP_PASS" "  SMTP Password" "" -IsPassword
Write-Host ""

# =============================================================================
# 5. Admin Account - v4.10
# =============================================================================
Write-Host "--- Tai khoan quan tri (admin) ---" -ForegroundColor Yellow
Write-Host "  Server chi tao admin khi CHUA co nguoi dung nao (lan chay dau tien)." -ForegroundColor Gray
Write-Host "  Mat khau do ban nhap se duoc luu trong .env (chi dung 1 lan de tao)." -ForegroundColor Gray
Ask-AdminCredentials
Write-Host ""

# =============================================================================
# 6. Enrollment Secret
# =============================================================================
Write-Host "--- Enrollment ---" -ForegroundColor Yellow
Write-Host "  Token xac thuc khi Agent ket noi lan dau tien." -ForegroundColor Gray
Ask-Config "GIAMSAT_ENROLLMENT_SECRET" "  Secret" "change-me-enroll-secret"
Write-Host ""

# =============================================================================
# 7. Security Keys (PSK + Command Signing) - v4.5.5 (BAT BUOC)
# =============================================================================
Write-Host "--- Bao mat Agent (bat buoc) ---" -ForegroundColor Yellow
Write-Host "  GIAMSAT_AGENT_PSK: khoa xac thuc agent (TCP 6666 + HTTP polling)." -ForegroundColor Gray
Write-Host "  GIAMSAT_COMMAND_KEY: khoa ky lenh server -> agent (chong gia mao lenh)." -ForegroundColor Gray
Write-Host "  De trong de TU DONG sinh khoa ngau nhien manh (khuyen nghi)." -ForegroundColor Gray
Write-Host "  GHI CHU: Agent phai dung CHUNG GIAMSAT_AGENT_PSK voi server." -ForegroundColor DarkYellow

function New-RandomKey([int]$Length = 32) {
    $bytes = New-Object byte[] $Length
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    $rng.Dispose()
    return -join ($bytes | ForEach-Object { $_.ToString("x2") })
}

function Ask-SecretKey {
    param([string]$Key, [string]$Label)
    $current = $env[$Key]
    $hint = if ($current) { "(co san - Enter de giu)" } else { "(trong - Enter = tu sinh)" }
    $val = Read-Host "  $Label $hint"
    if ($val -eq "") {
        if ($current) { $val = $current }
        else {
            $val = New-RandomKey 32
            Write-Host ("    [+] Tu sinh " + $Label + ": " + $val) -ForegroundColor Green
        }
    }
    $env[$Key] = $val
}

Ask-SecretKey "GIAMSAT_AGENT_PSK"   "GIAMSAT_AGENT_PSK"
Ask-SecretKey "GIAMSAT_COMMAND_KEY" "GIAMSAT_COMMAND_KEY"
Write-Host ""

# =============================================================================
# Save to .env
# =============================================================================
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Saving configuration..." -ForegroundColor Cyan

$lines = @(
    "# GIAM-SAT Server Configuration",
    "# Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
    "# Run: powershell -File setup\setup_config.ps1 to edit",
    ""
)

$keys = @(
    "GIAMSAT_DB_BACKEND",
    "GIAMSAT_PG_HOST", "GIAMSAT_PG_PORT", "GIAMSAT_PG_DBNAME",
    "GIAMSAT_PG_USER", "GIAMSAT_PG_PASSWORD",
    "GIAMSAT_PG_POOL_MIN", "GIAMSAT_PG_POOL_MAX",
    "DEEPSEEK_API_KEY",
    "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID",
    "GIAMSAT_SMTP_HOST", "GIAMSAT_SMTP_PORT",
    "GIAMSAT_SMTP_USER", "GIAMSAT_SMTP_PASS",
    "GIAMSAT_ADMIN_USER", "GIAMSAT_ADMIN_PASSWORD",
    "GIAMSAT_ENROLLMENT_SECRET",
    "GIAMSAT_AGENT_PSK",
    "GIAMSAT_COMMAND_KEY"
)

foreach ($key in $keys) {
    if ($env.ContainsKey($key) -and $env[$key]) {
        $lines += "$key=$($env[$key])"
    }
}

$lines | Out-File -Encoding utf8 $EnvFile

Write-Host "  [+] Configuration saved to:" -ForegroundColor Green
Write-Host "      $EnvFile" -ForegroundColor White
Write-Host ""
Write-Host "  [*] Restart server if it's currently running." -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Read-Host "Press Enter to exit"