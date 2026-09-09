<#
.SYNOPSIS
    GIAM-SAT - Cài/cập nhật Agent + Updater trên MỘT máy trạm (chạy chung cho mọi máy).

.DESCRIPTION
    Idempotent - chạy lại bao nhiêu lần cũng được:
      1. Tạo C:\Tool\GIAM-SAT (thư mục ĐÃ được bảo mật exclusion - chống Defender
         soi/xoá runtime _MEI gây 'Failed to load Python DLL').
      2. Thêm exclusion Windows Defender: C:\Tool và C:\ProgramData\GIAM-SAT.
      3. Dừng agent/updater cũ + xoá task cũ.
      4. Copy GiamSatAgent.exe / GiamSatUpdater.exe / agent_version.txt vào C:\Tool.
      5. Đăng ký DUY NHẤT task GiamSatUpdater (ONLOGON, /RL HIGHEST) - Updater daemon
         quản lý agent (watchdog restart) => không còn 2 nguồn khởi động khi logon.
      6. Khởi động Updater (agent sẽ được nó chạy theo).

.PARAMETER SourceDir
    Thư mục chứa file build (GiamSatAgent.exe + GiamSatUpdater.exe + agent_version.txt).
    Mặc định: <repo>\dist kế bên thư mục chứa script này.

.PARAMETER SkipStart
    Không khởi động Updater sau khi cài (chỉ chuẩn bị máy).

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File tools\deploy_agent.ps1
    powershell -NoProfile -ExecutionPolicy Bypass -File tools\deploy_agent.ps1 -SourceDir D:\test\dist
#>
param(
    [string]$SourceDir = "",
    [switch]$SkipStart
)
$ErrorActionPreference = "Continue"

# ---- tự nâng quyền Admin nếu đang chạy thiếu quyền ----
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$pr = New-Object Security.Principal.WindowsPrincipal($id)
if (-not $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[!] Khong phai Admin - tu khoi dong lai voi quyen Admin..." -ForegroundColor Yellow
    Start-Process powershell -Verb RunAs -ArgumentList @(
        "-NoProfile","-ExecutionPolicy","Bypass","-File",("`"$($MyInvocation.MyCommand.Path)`""),
        "-SourceDir",("`"$SourceDir`""), $(if($SkipStart){"-SkipStart"}else{""})
    )
    exit
}

$dest = "C:\Tool"
$installDir = Join-Path $dest "GIAM-SAT"
if (-not $SourceDir) { $SourceDir = Join-Path (Split-Path -Parent $PSScriptRoot) "dist" }
if (-not (Test-Path (Join-Path $SourceDir "GiamSatAgent.exe"))) {
    Write-Host "[FAIL] Khong thay GiamSatAgent.exe trong: $SourceDir" -ForegroundColor Red
    exit 1
}

Write-Host "==> 1. Tao thu muc + exclusions Defender..." -ForegroundColor Cyan
New-Item -ItemType Directory -Path $installDir -Force | Out-Null
Add-MpPreference -ExclusionPath $dest -ErrorAction SilentlyContinue
Add-MpPreference -ExclusionPath "C:\ProgramData\GIAM-SAT" -ErrorAction SilentlyContinue
Write-Host ("    Exclusions hien tai: " + ((Get-MpPreference).ExclusionPath -join ", ")) -ForegroundColor Gray

Write-Host "==> 2. Dung agent/updater cu + xoa task cu..." -ForegroundColor Cyan
Get-Process GiamSatAgent, GiamSatUpdater -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
schtasks /delete /tn "GiamSatUpdater" /f 2>$null | Out-Null
schtasks /delete /tn "GiamSatAgentStartup" /f 2>$null | Out-Null

Write-Host "==> 3. Copy file build vao C:\Tool..." -ForegroundColor Cyan
foreach ($f in @("GiamSatAgent.exe", "GiamSatUpdater.exe", "agent_version.txt")) {
    $src = Join-Path $SourceDir $f
    if (Test-Path $src) { Copy-Item $src (Join-Path $dest $f) -Force; Write-Host ("    [OK] " + $f) }
}

Write-Host "==> 3b. Siec ACL (v5.0.5 fix CRITICAL-3: user thuong khong ghi de duoc exe)..." -ForegroundColor Cyan
# Mặc định C:\Tool kế thừa ACL C:\ -> "Authenticated Users:(M)" khiến MỌI user
# local (hoặc malware chay user) ghi de duoc GiamSatAgent.exe / GiamSatUpdater.exe
# - lan logon sau, task ONLOGON /RL HIGHEST chay file doc voi token admin (LPE).
$sys = "*S-1-5-18"; $adm = "*S-1-5-32-544"
try {
    icacls $dest /inheritance:r /grant:r ($sys + ":(OI)(CI)F") ($adm + ":(OI)(CI)F") 2>&1 | Out-Null
    foreach ($f in @("GiamSatAgent.exe", "GiamSatUpdater.exe", "agent_version.txt")) {
        $fp = Join-Path $dest $f
        if (Test-Path $fp) { icacls $fp /inheritance:r /grant:r ($sys + ":F") ($adm + ":F") 2>&1 | Out-Null }
    }
    Write-Host "    [OK] $dest : chi SYSTEM + Administrators (full)." -ForegroundColor Green
} catch { Write-Host "    [!] ACL $dest that bai: $_" -ForegroundColor Yellow }

# HIGH-3: ProgramData\GIAM-SAT truoc day BUILTIN\Users:(CI)(WD,AD,WEA,WA) - user
# thuong tao duoc file (plant tailscale-hide-force -> taskkill GUI tailnet, DoS).
# Gio: SYSTEM/Admins full, Users CHI DOC (khong tao/sua file); khoa luon cache/flags.
$pd = "C:\ProgramData\GIAM-SAT"
New-Item -ItemType Directory -Path $pd -Force | Out-Null
try {
    icacls $pd /inheritance:r /grant:r ($sys + ":(OI)(CI)F") ($adm + ":(OI)(CI)F") ("*S-1-5-11" + ":(OI)(CI)RX") 2>&1 | Out-Null
    foreach ($f in @("Agent\tailscale-conf.txt", "Agent\tailscale-enabled.flag", "Agent\tailscale-hide-force")) {
        $fp = Join-Path $pd $f
        if (Test-Path $fp) { icacls $fp /inheritance:r /grant:r ($sys + ":F") ($adm + ":F") 2>&1 | Out-Null }
    }
    Write-Host "    [OK] $pd : Users doc-only (khong tao file)." -ForegroundColor Green
} catch { Write-Host "    [!] ACL $pd that bai: $_" -ForegroundColor Yellow }

Write-Host "==> 4. Dang ky task GiamSatUpdater (ONLOGON, HIGHEST)..." -ForegroundColor Cyan
schtasks /create /tn "GiamSatUpdater" /tr ('"' + (Join-Path $dest "GiamSatUpdater.exe") + '"') /sc onlogon /rl highest /f 2>&1 | Out-String | Write-Host

if (-not $SkipStart) {
    Write-Host "==> 5. Khoi dong Updater (agent se duoc Updater chay theo)..." -ForegroundColor Cyan
    schtasks /run /tn "GiamSatUpdater" 2>&1 | Out-String | Write-Host
    Start-Sleep -Seconds 10
    if (Get-Process GiamSatUpdater -ErrorAction SilentlyContinue) {
        Write-Host "[OK] GiamSatUpdater dang chay." -ForegroundColor Green
    } else {
        Write-Host "[!] Updater chua thay - chay lai script hoac xem log." -ForegroundColor Yellow
    }
}
Write-Host "XONG. Machine: $env:COMPUTERNAME" -ForegroundColor Green
