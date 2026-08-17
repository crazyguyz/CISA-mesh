# create_it_support_shortcut.ps1
# Tạo lối tắt desktop "IT support" để người dùng máy trạm gửi tin nhắn cho quản trị viên.
# Lối tắt chạy GiamSatAgent.exe --send-message (mở hộp thoại gửi tin nhắn).
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File create_it_support_shortcut.ps1
#   powershell -ExecutionPolicy Bypass -File create_it_support_shortcut.ps1 -ExePath "C:\...\GiamSatAgent.exe"

param(
    [string]$ExePath = ""
)

$ErrorActionPreference = "Continue"

# 1. Tìm GiamSatAgent.exe nếu chưa truyền đường dẫn
if (-not $ExePath -or -not (Test-Path $ExePath)) {
    $candidates = @(
        "$env:ProgramData\GIAM-SAT\Agent\GiamSatAgent.exe",
        "$env:ProgramFiles\GIAM-SAT\Agent\GiamSatAgent.exe",
        "$env:ProgramFiles\GIAM-SAT\GiamSatAgent.exe",
        "$env:LOCALAPPDATA\GIAM-SAT\Agent\GiamSatAgent.exe"
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) { $ExePath = $c; break }
    }
}

if (-not $ExePath -or -not (Test-Path $ExePath)) {
    Write-Host "[FAIL] Khong tim thay GiamSatAgent.exe. Hay truyen -ExePath." -ForegroundColor Red
    exit 1
}

# 2. Tạo lối tắt trên Desktop
$desktop = [Environment]::GetFolderPath('Desktop')
$ws = New-Object -ComObject WScript.Shell
$lnkPath = Join-Path $desktop "IT support.lnk"
$shortcut = $ws.CreateShortcut($lnkPath)
$shortcut.TargetPath = $ExePath
$shortcut.Arguments = "--send-message"
$shortcut.WorkingDirectory = Split-Path $ExePath
$shortcut.Description = "Gui tin nhan cho quan tri vien IT"
$shortcut.Save()

Write-Host "[OK] Da tao loi tat: $lnkPath" -ForegroundColor Green
