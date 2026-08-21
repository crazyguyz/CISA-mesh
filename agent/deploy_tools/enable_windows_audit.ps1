<#
.SYNOPSIS
    GIAM-SAT Windows Audit + PowerShell Logging Enabler (SEC review Phase 2)

.DESCRIPTION
    Enables the Windows-side audit baseline that unlocks the detection rules:
      - 4688 process creation WITH command line  -> THREAT-012 (reg save), THREAT-052,
        RANSOM-00x + hundreds of CommandLine-based rules
      - 4624/4625/4648/4768/4769/4771 logon       -> THREAT-001 brute force + logon rules
      - 4663 object access via SACL on lsass.exe  -> THREAT-009 (LSASS access), DCSync 4662
      - 5145 detailed file share                  -> lateral movement / share abuse detection
      - 4104 PowerShell Script Block Logging      -> THREAT-017 (download cradle) etc.
      - PS Module Logging + Transcription         -> investigation transcripts

    Uses auditpol by SUBGUID (language-independent - works on Vietnamese/any locale),
    registry for command-line/SBL, and .NET FileSystemAuditRule for the lsass SACL.

    Deployment options:
      * Run as Administrator on each workstation:  .\enable_windows_audit.ps1
      * Remote push via PSRemoting:                .\enable_windows_audit.ps1 -Computers pc01,pc02
      * Domain GPO: import audit_policy.inf into a new GPO
        (Computer Config > Policies > Security Settings > right-click > Import Policy),
        then deploy the SACL + PS logging parts via Group Policy Preferences or this script.

.PARAMETER Restore
    Disable everything this script enabled (audit categories -> disable, remove registry
    values, remove the lsass SACL audit ACE).

.PARAMETER Computers
    Remote computer names (requires WinRM/PSRemoting + admin credentials).

.PARAMETER SkipElevationCheck
    Skip the admin/elevation check (used when this script is executed inside a remote
    PSSession where the token is already elevated).

.EXAMPLE
    .\enable_windows_audit.ps1
    .\enable_windows_audit.ps1 -Computers wk01,wk02
    .\enable_windows_audit.ps1 -Restore
#>
[CmdletBinding()]
param(
    [switch]$Restore,
    [switch]$SkipElevationCheck,
    [string[]]$Computers
)

$ErrorActionPreference = "Continue"

# ---------------------------------------------------------------------------
# Remote deployment (orchestrator -> remotes)
# ---------------------------------------------------------------------------
if ($Computers -and $Computers.Count -gt 0 -and -not $SkipElevationCheck) {
    Write-Host "`n[GIAM-SAT AUDIT] Deploying to $($Computers -join ', ') via PSRemoting..." -ForegroundColor Cyan
    $content = Get-Content -Path $PSCommandPath -Raw
    Invoke-Command -ComputerName $Computers -ArgumentList $content, ($Restore.IsPresent) -ScriptBlock {
        param($c, $r)
        $block = [scriptblock]::Create($c)
        if ($r) { & $block -SkipElevationCheck -Restore } else { & $block -SkipElevationCheck }
    } -ErrorAction Continue
    exit
}

# ---------------------------------------------------------------------------
# Self elevation
# ---------------------------------------------------------------------------
if (-not $SkipElevationCheck) {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "[-] Administrator rights required. Relaunching elevated..." -ForegroundColor Yellow
        $extra = ""
        if ($Restore) { $extra += " -Restore" }
        if ($Computers) { $extra += " -Computers $($Computers -join ',')" }
        Start-Process powershell.exe -Verb RunAs `
            -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"$extra"
        exit
    }
}

$global:okCount = 0
$global:failCount = 0

function Write-Step { param([string]$s) Write-Host "`n>>> $s" -ForegroundColor Magenta }
function Report {
    if ($LASTEXITCODE -eq 0) { $global:okCount++; Write-Host "  [OK]   $($args[0])" -ForegroundColor Green }
    else { $global:failCount++; Write-Host "  [FAIL] $($args[0]) (exit=$LASTEXITCODE)" -ForegroundColor Red }
}
function Set-AuditSub {
    param([string]$Guid, [string]$Name, [string]$Success = "enable", [string]$Failure = "enable")
    if ($Restore) { $Success = "disable"; $Failure = "disable" }
    $null = & auditpol /set /subcategory:"$Guid" /success:$Success /failure:$Failure 2>&1
    Report "$Name ($Guid) -> S=$Success F=$Failure"
}

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "  GIAM-SAT Windows Audit + PowerShell Logging Enabler" -ForegroundColor Cyan
if ($Restore) { Write-Host "  MODE: RESTORE (disable everything)" -ForegroundColor Yellow }
else { Write-Host "  MODE: ENABLE baseline" -ForegroundColor Green }
Write-Host "============================================================" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# 1) Advanced Audit Policy subcategories (GUID-based, locale-independent)
# ---------------------------------------------------------------------------
Write-Step "STEP 1: Advanced Audit Policy (auditpol)"

# Logon/Logoff
Set-AuditSub "{0CCE9215-69AE-11D9-BED3-505054503030}" "Logon (4624/4625/4648)"
Set-AuditSub "{0CCE9216-69AE-11D9-BED3-505054503030}" "Logoff" success disable
Set-AuditSub "{0CCE9217-69AE-11D9-BED3-505054503030}" "Account Lockout" disable failure
Set-AuditSub "{0CCE921B-69AE-11D9-BED3-505054503030}" "Special Logon (4964)" success disable
Set-AuditSub "{0CCE921C-69AE-11D9-BED3-505054503030}" "Other Logon/Logoff Events"
# Account Logon
Set-AuditSub "{0CCE923F-69AE-11D9-BED3-505054503030}" "Credential Validation (4776)"
Set-AuditSub "{0CCE9242-69AE-11D9-BED3-505054503030}" "Kerberos Authentication Service (4768)"
Set-AuditSub "{0CCE9240-69AE-11D9-BED3-505054503030}" "Kerberos Service Ticket Operations (4769/4771)"
# Account Management
Set-AuditSub "{0CCE9235-69AE-11D9-BED3-505054503030}" "User Account Management"
Set-AuditSub "{0CCE9236-69AE-11D9-BED3-505054503030}" "Computer Account Management" success disable
Set-AuditSub "{0CCE9237-69AE-11D9-BED3-505054503030}" "Security Group Management" success disable
# Object Access (4663 driven by SACL - see STEP 3)
Set-AuditSub "{0CCE921D-69AE-11D9-BED3-505054503030}" "File System (4663 via SACL)" success disable
Set-AuditSub "{0CCE9220-69AE-11D9-BED3-505054503030}" "SAM" success disable
Set-AuditSub "{0CCE9224-69AE-11D9-BED3-505054503030}" "File Share (5140/5142)"
Set-AuditSub "{0CCE9244-69AE-11D9-BED3-505054503030}" "Detailed File Share (5145)"
# Detailed Tracking
Set-AuditSub "{0CCE922B-69AE-11D9-BED3-505054503030}" "Process Creation (4688)"

# ---------------------------------------------------------------------------
# 2) Process creation command line (4688 with command_line)
# ---------------------------------------------------------------------------
Write-Step "STEP 2: Process Creation 'Include command line' (4688)"
$auditKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
try {
    New-Item -Path $auditKey -Force -ErrorAction Stop | Out-Null
    if ($Restore) { Remove-ItemProperty -Path $auditKey -Name "ProcessCreationIncludeCmdLine_Enabled" -ErrorAction SilentlyContinue }
    else { Set-ItemProperty -Path $auditKey -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord }
    Report "ProcessCreationIncludeCmdLine_Enabled"
} catch { Write-Host "  [FAIL] registry cmdline: $_" -ForegroundColor Red; $global:failCount++ }

# ---------------------------------------------------------------------------
# 3) SACL on lsass.exe (4663 for credential-dumping detection)
# ---------------------------------------------------------------------------
Write-Step "STEP 3: SACL on lsass.exe (4663)"
$lsassPath = Join-Path $env:SystemRoot "System32\lsass.exe"
try {
    $acl = Get-Acl -Path $lsassPath -ErrorAction Stop
    $existing = $acl.Audit | Where-Object { $_.IdentityReference.Value -match "Everyone" -and $_.AuditFlags -match "Success" }
    if ($Restore) {
        foreach ($ace in @($acl.Audit | Where-Object { $_.IdentityReference.Value -match "Everyone" })) {
            $acl.RemoveAuditRuleSpecific($ace) | Out-Null
        }
        Set-Acl -Path $lsassPath -AclObject $acl -ErrorAction Stop
        Report "lsass.exe SACL removed"
    } elseif ($existing) {
        Write-Host "  [SKIP] lsass.exe SACL already present" -ForegroundColor Yellow
        $global:okCount++
    } else {
        $rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
            "Everyone", "Read, ReadAttributes", "None", "None", "Success")
        $acl.AddAuditRule($rule)
        Set-Acl -Path $lsassPath -AclObject $acl -ErrorAction Stop
        Report "lsass.exe SACL (Everyone/Read, Success)"
    }
} catch { Write-Host "  [FAIL] lsass SACL: $_" -ForegroundColor Red; $global:failCount++ }


# ---------------------------------------------------------------------------
# 4) PowerShell Script Block Logging + Module Logging + Transcription (4104)
# ---------------------------------------------------------------------------
Write-Step "STEP 4: PowerShell Script Block / Module Logging + Transcription"
$psPolicy = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
$transcriptDir = "C:\ProgramData\GIAM-SAT\PSLogs"
try {
    New-Item -Path $psPolicy -Force -ErrorAction Stop | Out-Null
    $sbl = Join-Path $psPolicy "ScriptBlockLogging"
    $ml  = Join-Path $psPolicy "ModuleLogging"
    $tr  = Join-Path $psPolicy "Transcription"
    New-Item -Path $sbl -Force -ErrorAction Stop | Out-Null
    New-Item -Path $tr  -Force -ErrorAction Stop | Out-Null
    if ($Restore) {
        Remove-ItemProperty -Path $sbl -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $sbl -Name "EnableScriptInvocationLogging" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $tr -Name "EnableTranscripting" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $tr -Name "EnableInvocationHeader" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $tr -Name "OutputDirectory" -ErrorAction SilentlyContinue
        Remove-Item -Path $ml -Recurse -Force -ErrorAction SilentlyContinue
        Report "PowerShell logging keys removed"
    } else {
        Set-ItemProperty -Path $sbl -Name "EnableScriptBlockLogging" -Value 1 -Type DWord
        Set-ItemProperty -Path $sbl -Name "EnableScriptInvocationLogging" -Value 1 -Type DWord
        New-Item -Path (Join-Path $ml "ModuleNames") -Force -ErrorAction Stop | Out-Null
        Set-ItemProperty -Path $ml -Name "EnableModuleLogging" -Value 1 -Type DWord
        Set-ItemProperty -Path (Join-Path $ml "ModuleNames") -Name "*" -Value "*" -Type String
        Set-ItemProperty -Path $tr -Name "EnableTranscripting" -Value 1 -Type DWord
        Set-ItemProperty -Path $tr -Name "EnableInvocationHeader" -Value 1 -Type DWord
        Set-ItemProperty -Path $tr -Name "OutputDirectory" -Value $transcriptDir -Type ExpandString
        New-Item -Path $transcriptDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null
        Report "SBL + Module Logging + Transcription enabled"
    }
} catch { Write-Host "  [FAIL] PowerShell logging: $_" -ForegroundColor Red; $global:failCount++ }

# ---------------------------------------------------------------------------
# 5) Verification
# ---------------------------------------------------------------------------
Write-Step "STEP 5: Verification"
if (-not $Restore) {
    $procAudit = (& auditpol /get /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" 2>&1 | Out-String)
    Write-Host "  Process Creation audit:" -NoNewline; Write-Host $procAudit.Trim() -ForegroundColor Gray
    $cmdLineVal = (Get-ItemProperty -Path $auditKey -Name "ProcessCreationIncludeCmdLine_Enabled" -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled
    Write-Host "  IncludeCommandLine = $cmdLineVal" -ForegroundColor Gray
    $sblVal = (Get-ItemProperty -Path $sbl -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue).EnableScriptBlockLogging
    Write-Host "  EnableScriptBlockLogging = $sblVal" -ForegroundColor Gray
    $acl = Get-Acl -Path $lsassPath -ErrorAction SilentlyContinue
    Write-Host "  lsass SACL ACEs: $($acl.Audit.Count)" -ForegroundColor Gray
}

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "  RESULT: OK=$global:okCount FAIL=$global:failCount" -ForegroundColor $(if ($global:failCount -eq 0) { "Green" } else { "Red" })
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Next: the agent will now see 4688+command_line, 4663 (lsass), 5145," -ForegroundColor Gray
Write-Host "        4104 events. Restart the agent or wait for the next poll to confirm" -ForegroundColor Gray
Write-Host "        in the server event table." -ForegroundColor Gray
if ($global:failCount -gt 0) { exit 1 }

