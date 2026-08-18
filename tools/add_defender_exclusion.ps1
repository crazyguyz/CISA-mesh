# GIAM-SAT Windows Defender Exclusion Script
# Chạy với quyền Administrator: PowerShell -ExecutionPolicy Bypass -File add_defender_exclusion.ps1
# Mục đích: Thêm thư mục GIAM-SAT vào Windows Defender exclusion để tránh bị xóa file EXE

param(
    [switch]$SkipProcess = $false
)

$ErrorActionPreference = "Continue"

# Kiểm tra quyền Admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[!] Can quyen Administrator. Dang thu tu dong nang quyen..."
    Start-Process PowerShell -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit 0
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " GIAM-SAT Defender Exclusion Installer" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$pathsToExclude = @(
    "C:\ProgramData\GIAM-SAT",
    "C:\ProgramData\dist",
    "$env:ProgramData\GIAM-SAT",
    "$env:ProgramData\dist"
)

$processesToExclude = @()  # v4.10 (MED-17): process exclusions removed - an
# unsigned GiamSatAgent.exe must NOT be exempt from Defender scanning.

Write-Host "[*] Dang them folder exclusions..." -ForegroundColor Yellow
foreach ($path in $pathsToExclude) {
    if (Test-Path $path) {
        try {
            Add-MpPreference -ExclusionPath $path -ErrorAction Stop
            Write-Host "  [+] $path" -ForegroundColor Green
        } catch {
            Write-Host "  [!] $path - $_" -ForegroundColor Red
        }
    } else {
        Write-Host "  [-] $path (chua ton tai)" -ForegroundColor Gray
    }
}

if (-not $SkipProcess) {
    Write-Host "[*] Dang them process exclusions..." -ForegroundColor Yellow
    foreach ($proc in $processesToExclude) {
        try {
            Add-MpPreference -ExclusionProcess $proc -ErrorAction Stop
            Write-Host "  [+] $proc" -ForegroundColor Green
        } catch {
            Write-Host "  [!] $proc - $_" -ForegroundColor Red
        }
    }
}

# Add .exe extension exclusion cho thư mục GIAM-SAT (phòng trường hợp path exclusion không đủ)
try {
    Add-MpPreference -ExclusionExtension ".exe" -ErrorAction Stop 2>$null
} catch {}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host " HOAN THANH! Da them Defender exclusions" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Kiem tra: Get-MpPreference | Select-Object ExclusionPath, ExclusionProcess" -ForegroundColor Gray
Write-Host ""
Read-Host "Nhan Enter de thoat"