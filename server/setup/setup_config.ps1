# =============================================================================
# GIAM-SAT Configuration Setup v1.1
# Interactive .env generator — run anytime to add/update settings.
# Bilingual: Vietnamese (vi, default) or English (en) — asked on start.
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
    vi = @{
        bannerSub     = "  Nhan Enter de bo qua cac muc khong bat buoc."
        dbHeader      = "--- DATABASE ---"
        dbSqliteOpt   = "  1. SQLite (mac dinh, khong can cau hinh)"
        dbPgOpt       = "  2. PostgreSQL (khuyen nghi cho production)"
        dbChoose      = "  Chon [1-2] (Enter = SQLite)"
        dbPgSelected  = "  [*] PostgreSQL selected"
        dbSqliteSel   = "  [*] SQLite selected (mac dinh)"
        aiHeader      = "--- AI / DeepSeek (tuy chon) ---"
        aiDesc        = "  Dung cho AI Assistant & Auto-Monitor phan tich tu dong."
        tgHeader      = "--- Telegram Alerts (tuy chon) ---"
        tgDesc        = "  Canh bao thoi gian thuc qua Telegram Bot."
        tgCreate      = "  Tao bot tai: https://t.me/BotFather"
        mailHeader    = "--- Email Alerts (tuy chon) ---"
        mailDesc      = "  Canh bao qua SMTP email."
        admHeader     = "--- Tai khoan quan tri (admin) ---"
        admInfo1      = "  Server chi tao admin khi CHUA co nguoi dung nao (lan chay dau tien)."
        admInfo2      = "  Mat khau do ban nhap se duoc luu trong .env (chi dung 1 lan de tao)."
        admUser       = "  Ten dang nhap admin (Enter = 'admin')"
        admPwExists   = "  Mat khau admin hien tai: da co (an). Enter de giu nguyen, nhap de doi."
        admPwPrompt   = "  Mat khau admin (toi thieu 12 ky tu: hoa/thuong/so/dac biet)"
        admSkip       = "  [!] Bo qua: server se TU DONG sinh mat khau ngau nhien khi khoi dong."
        admConfirm    = "  Nhap lai mat khau admin"
        admMismatch   = "  [!] Hai lan nhap khong khop, nhap lai."
        admTooMany    = "  [!] Qua nhieu lan thu - bo qua mat khau admin (server se tu sinh ngau nhien)."
        enrollHeader  = "--- Enrollment ---"
        enrollDesc    = "  Token xac thuc khi Agent ket noi lan dau tien."
        secHeader     = "--- Bao mat Agent (bat buoc) ---"
        secPsk        = "  GIAMSAT_AGENT_PSK: khoa xac thuc agent (TCP 6666 + HTTP polling)."
        secCmd        = "  GIAMSAT_COMMAND_KEY: khoa ky lenh server -> agent (chong gia mao lenh)."
        secAuto       = "  De trong de TU DONG sinh khoa ngau nhien manh (khuyen nghi)."
        secNote       = "  GHI CHU: Agent phai dung CHUNG GIAMSAT_AGENT_PSK voi server."
        hintExists    = "(co san - an)"
        hintEmpty     = "(trong)"
        keyHintKeep   = "(co san - Enter de giu)"
        keyHintGen    = "(trong - Enter = tu sinh)"
        keyGenerated  = "    [+] Tu sinh "
        saveTitle     = "  Saving configuration..."
        savedTo       = "  [+] Cau hinh da luu tai:"
        restart       = "  [*] Khoi dong lai server neu dang chay."
        exitPrompt    = "Nhan Enter de thoat"
        ppLength      = "Mat khau phai co it nhat 12 ky tu"
        ppUpper       = "Thieu ky tu IN HOA (A-Z)"
        ppLower       = "Thieu ky tu thuong (a-z)"
        ppDigit       = "Thieu chu so (0-9)"
        ppSpecial     = "Thieu ky tu dac biet (!@#...)"
    }
    en = @{
        bannerSub     = "  Press Enter to skip optional items."
        dbHeader      = "--- DATABASE ---"
        dbSqliteOpt   = "  1. SQLite (default, no configuration needed)"
        dbPgOpt       = "  2. PostgreSQL (recommended for production)"
        dbChoose      = "  Choose [1-2] (Enter = SQLite)"
        dbPgSelected  = "  [*] PostgreSQL selected"
        dbSqliteSel   = "  [*] SQLite selected (default)"
        aiHeader      = "--- AI / DeepSeek (optional) ---"
        aiDesc        = "  Used by AI Assistant & Auto-Monitor automatic analysis."
        tgHeader      = "--- Telegram Alerts (optional) ---"
        tgDesc        = "  Real-time alerts via Telegram Bot."
        tgCreate      = "  Create a bot at: https://t.me/BotFather"
        mailHeader    = "--- Email Alerts (optional) ---"
        mailDesc      = "  Alerts via SMTP email."
        admHeader     = "--- Admin account ---"
        admInfo1      = "  The admin is created only when there are NO users yet (first run)."
        admInfo2      = "  The password you type is saved to .env (used once to create the account)."
        admUser       = "  Admin username (Enter = 'admin')"
        admPwExists   = "  Admin password already set (hidden). Enter to keep, type to change."
        admPwPrompt   = "  Admin password (min 12 chars: upper/lower/digit/special)"
        admSkip       = "  [!] Skipped: server will AUTO-GENERATE a random password on first start."
        admConfirm    = "  Confirm admin password"
        admMismatch   = "  [!] The two entries do not match, retry."
        admTooMany    = "  [!] Too many attempts - skipping admin password (server will auto-generate)."
        enrollHeader  = "--- Enrollment ---"
        enrollDesc    = "  Token to authenticate agents on first connection."
        secHeader     = "--- Agent Security (required) ---"
        secPsk        = "  GIAMSAT_AGENT_PSK: agent authentication key (TCP 6666 + HTTP polling)."
        secCmd        = "  GIAMSAT_COMMAND_KEY: key signing server -> agent commands (anti-forgery)."
        secAuto       = "  Leave empty to AUTO-GENERATE a strong random key (recommended)."
        secNote       = "  NOTE: Agents must use THE SAME GIAMSAT_AGENT_PSK as the server."
        hintExists    = "(existing - hidden)"
        hintEmpty     = "(empty)"
        keyHintKeep   = "(existing - Enter to keep)"
        keyHintGen    = "(empty - Enter = auto-generate)"
        keyGenerated  = "    [+] Auto-generated "
        saveTitle     = "  Saving configuration..."
        savedTo       = "  [+] Configuration saved to:"
        restart       = "  [*] Restart server if it's currently running."
        exitPrompt    = "Press Enter to exit"
        ppLength      = "Password must be at least 12 characters"
        ppUpper       = "Missing UPPERCASE (A-Z)"
        ppLower       = "Missing lowercase (a-z)"
        ppDigit       = "Missing digit (0-9)"
        ppSpecial     = "Missing special character (!@#...)"
    }
}
$T = $TR[$lang]

# Banner
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  GIAM-SAT Configuration Setup v1.0" -ForegroundColor Cyan
Write-Host "  $($T['bannerSub'])" -ForegroundColor Cyan
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
    
    $displayDefault = if ($IsPassword -and $current) { $T['hintExists'] } elseif ($current) { "($current)" } else { $T['hintEmpty'] }
    
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
    if ($pw.Length -lt 12)        { return $T['ppLength'] }
    if ($pw -notmatch '[A-Z]')    { return $T['ppUpper'] }
    if ($pw -notmatch '[a-z]')    { return $T['ppLower'] }
    if ($pw -notmatch '[0-9]')    { return $T['ppDigit'] }
    if ($pw -notmatch '[^A-Za-z0-9]') { return $T['ppSpecial'] }
    return ""
}

# v4.10: Admin account - setup_config.ps1 owns first-run admin creation.
function Ask-AdminCredentials {
    $currentUser = $env["GIAMSAT_ADMIN_USER"]
    $currentPw = $env["GIAMSAT_ADMIN_PASSWORD"]

    $user = Read-Host "  $($T['admUser'])"
    if ($user -eq "") { $user = if ($currentUser) { $currentUser } else { "admin" } }
    $env["GIAMSAT_ADMIN_USER"] = $user

    if ($currentPw) {
        Write-Host "  $($T['admPwExists'])" -ForegroundColor Gray
    }
    $pw1 = Read-Host "  $($T['admPwPrompt'])"
    if ($pw1 -eq "" -and $currentPw) {
        $env["GIAMSAT_ADMIN_PASSWORD"] = $currentPw
        return
    }
    if ($pw1 -eq "") {
        # Leave empty -> server auto-generates a random password (printed once)
        $env.Remove("GIAMSAT_ADMIN_PASSWORD")
        Write-Host "  $($T['admSkip'])" -ForegroundColor DarkYellow
        return
    }
    $attempts = 0
    while ($true) {
        $attempts++
        if ($attempts -gt 10) {
            Write-Host "  $($T['admTooMany'])" -ForegroundColor DarkYellow
            $env.Remove("GIAMSAT_ADMIN_PASSWORD")
            return
        }
        $pw2 = Read-Host "  $($T['admConfirm'])"
        if ($pw1 -ne $pw2) { Write-Host "  $($T['admMismatch'])" -ForegroundColor Red; continue }
        $err = Test-PasswordPolicy $pw1
        if ($err) { Write-Host "  [!] $err" -ForegroundColor Red }
        else { break }
        $pw1 = Read-Host "  $($T['admPwPrompt'])"
    }
    $env["GIAMSAT_ADMIN_PASSWORD"] = $pw1
}

# =============================================================================
# 1. Database Backend
# =============================================================================
Write-Host "  $($T['dbHeader'])" -ForegroundColor Yellow
Write-Host "  $($T['dbSqliteOpt'])" -ForegroundColor Gray
Write-Host "  $($T['dbPgOpt'])" -ForegroundColor Gray
$dbChoice = Read-Host "  $($T['dbChoose'])"
if ($dbChoice -eq "2") {
    $env["GIAMSAT_DB_BACKEND"] = "postgres"
    Write-Host "  $($T['dbPgSelected'])" -ForegroundColor Green
    Ask-Config "GIAMSAT_PG_HOST"       "  Host"        "127.0.0.1"
    Ask-Config "GIAMSAT_PG_PORT"       "  PostgreSQL Port (5432)"        "5432"
    Ask-Config "GIAMSAT_PG_DBNAME"     "  Database"    "giamsat"
    Ask-Config "GIAMSAT_PG_USER"       "  User"        "postgres"
    Ask-Config "GIAMSAT_PG_PASSWORD"   "  Password"    "" -IsPassword
} else {
    $env["GIAMSAT_DB_BACKEND"] = "sqlite"
    Write-Host "  $($T['dbSqliteSel'])" -ForegroundColor Green
}
Write-Host ""

# =============================================================================
# 2. DeepSeek AI (optional)
# =============================================================================
Write-Host "  $($T['aiHeader'])" -ForegroundColor Yellow
Write-Host "  $($T['aiDesc'])" -ForegroundColor Gray
Ask-Config "DEEPSEEK_API_KEY" "  API Key" ""
Write-Host ""

# =============================================================================
# 3. Telegram Alerts (optional)
# =============================================================================
Write-Host "  $($T['tgHeader'])" -ForegroundColor Yellow
Write-Host "  $($T['tgDesc'])" -ForegroundColor Gray
Write-Host "  $($T['tgCreate'])" -ForegroundColor Gray
Ask-Config "TELEGRAM_BOT_TOKEN" "  Bot Token" ""
Ask-Config "TELEGRAM_CHAT_ID"   "  Chat ID" ""
Write-Host ""

# =============================================================================
# 4. Email Alerts (optional)
# =============================================================================
Write-Host "  $($T['mailHeader'])" -ForegroundColor Yellow
Write-Host "  $($T['mailDesc'])" -ForegroundColor Gray
Ask-Config "GIAMSAT_SMTP_HOST" "  SMTP Host" ""
Ask-Config "GIAMSAT_SMTP_PORT" "  SMTP Port" "465"
Ask-Config "GIAMSAT_SMTP_USER" "  SMTP User" ""
Ask-Config "GIAMSAT_SMTP_PASS" "  SMTP Password" "" -IsPassword
Write-Host ""

# =============================================================================
# 5. Admin Account - v4.10
# =============================================================================
Write-Host "  $($T['admHeader'])" -ForegroundColor Yellow
Write-Host "  $($T['admInfo1'])" -ForegroundColor Gray
Write-Host "  $($T['admInfo2'])" -ForegroundColor Gray
Ask-AdminCredentials
Write-Host ""

# =============================================================================
# 6. Enrollment Secret
# =============================================================================
Write-Host "  $($T['enrollHeader'])" -ForegroundColor Yellow
Write-Host "  $($T['enrollDesc'])" -ForegroundColor Gray
Ask-Config "GIAMSAT_ENROLLMENT_SECRET" "  Secret" "change-me-enroll-secret"
Write-Host ""

# =============================================================================
# 7. Security Keys (PSK + Command Signing) - v4.5.5 (BAT BUOC)
# =============================================================================
Write-Host "  $($T['secHeader'])" -ForegroundColor Yellow
Write-Host "  $($T['secPsk'])" -ForegroundColor Gray
Write-Host "  $($T['secCmd'])" -ForegroundColor Gray
Write-Host "  $($T['secAuto'])" -ForegroundColor Gray
Write-Host "  $($T['secNote'])" -ForegroundColor DarkYellow

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
    $hint = if ($current) { $T['keyHintKeep'] } else { $T['keyHintGen'] }
    $val = Read-Host "  $Label $hint"
    if ($val -eq "") {
        if ($current) { $val = $current }
        else {
            $val = New-RandomKey 32
            Write-Host ("$($T['keyGenerated'])" + $Label + ": " + $val) -ForegroundColor Green
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
Write-Host "  $($T['saveTitle'])" -ForegroundColor Cyan

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
    "OPENAI_API_KEY", "GEMINI_API_KEY", "GROQ_API_KEY", "GIAMSAT_DISABLE_AI",
    "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID", "GIAMSAT_TELEGRAM_SOC_IDS",
    "GIAMSAT_SMTP_HOST", "GIAMSAT_SMTP_PORT",
    "GIAMSAT_SMTP_USER", "GIAMSAT_SMTP_PASS",
    "GIAMSAT_ADMIN_USER", "GIAMSAT_ADMIN_PASSWORD",
    "GIAMSAT_ENROLLMENT_SECRET",
    "GIAMSAT_AGENT_PSK", "GIAMSAT_SECRET_KEY", "GIAMSAT_COMMAND_KEY",
    "GIAMSAT_CLUSTER_SECRET",
    "GIAMSAT_PER_MACHINE_PSK", "GIAMSAT_PER_MACHINE_PSK_FILE",
    # v5.0.4 — cổng / TLS / syslog TCP / threat-intel / net behavior
    "GIAMSAT_WEB_PORT", "GIAMSAT_TCP_PORT", "GIAMSAT_WEB_TLS_ENABLED",
    "GIAMSAT_SYSLOG_TCP_PORT", "GIAMSAT_SYSLOG_TLS_CERT", "GIAMSAT_SYSLOG_TLS_KEY",
    "GIAMSAT_SYSLOG_MAX_PPS", "GIAMSAT_SYSLOG_MAX_WORKERS",
    "GIAMSAT_NETFLOW_PORT", "GIAMSAT_NET_ALERT_INTERVAL", "GIAMSAT_NET_ALERT_WINDOW",
    "GIAMSAT_NET_BEACON_MIN_FLOWS", "GIAMSAT_NET_BEACON_MAX_CV", "GIAMSAT_NET_BEACON_MIN_SPAN",
    "GIAMSAT_NET_FIRST_SEEN_DAYS",
    "GIAMSAT_INTEL_FILE", "GIAMSAT_OTX_API_KEY",
    "GIAMSAT_SIGMA_AUTO", "GIAMSAT_EVENT_WORKERS", "GIAMSAT_SSE_MAX",
    "GIAMSAT_API_RATE_LIMIT", "GIAMSAT_GEOIP_ASN_DB", "GIAMSAT_GEOIP_CITY_DB",
    "GIAMSAT_REDIS_HOST", "GIAMSAT_REDIS_PORT", "GIAMSAT_REDIS_PASSWORD",
    "GIAMSAT_RABBITMQ_URL", "GIAMSAT_RABBITMQ_EXCHANGE"
)

foreach ($key in $keys) {
    if ($env.ContainsKey($key) -and $env[$key]) {
        $lines += "$key=$($env[$key])"
    }
}
# Giữ NGUYÊN mọi key phụ khác đã có trong .env cũ / .env.example (không bao giờ
# làm rơi cấu hình khi chạy lại script này).
foreach ($key in ($env.Keys | Where-Object { $_ -and $keys -notcontains $_ } | Sort-Object)) {
    if ($env[$key]) {
        $lines += "$key=$($env[$key])"
    }
}

# UTF-8 KHÔNG có BOM — python-dotenv sẽ đọc đúng key đầu tiên (Out-File -Encoding
# utf8 trong Windows PowerShell 5.1 ghi BOM làm key đầu tiên bị lỗi).
$content = ($lines -join [Environment]::NewLine) + [Environment]::NewLine
[System.IO.File]::WriteAllText($EnvFile, $content, (New-Object System.Text.UTF8Encoding($false)))

Write-Host "  $($T['savedTo'])" -ForegroundColor Green
Write-Host "      $EnvFile" -ForegroundColor White
Write-Host ""
Write-Host "  $($T['restart'])" -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Read-Host "  $($T['exitPrompt'])"