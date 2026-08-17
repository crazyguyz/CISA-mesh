# GIAM-SAT Agent GPO Deployment Script v2.0.0
# Deploys GiamSatAgent.exe via Group Policy (Startup Script or Scheduled Task)
#
# Usage (run as Domain Admin on DC):
#   powershell -ExecutionPolicy Bypass -File gpo_deploy.ps1 -ServerIP "192.168.1.200" -ServerPort 6666
#
# What this does:
#   1. Copies GiamSatAgent.exe to NETLOGON share
#   2. Creates GPO "GIAM-SAT Agent Deployment"
#   3. Configures Scheduled Task to run agent at startup
#   4. Links GPO to target OUs

param(
    [Parameter(Mandatory=$true)][string]$ServerIP,
    [Parameter(Mandatory=$false)][int]$ServerPort = 6666,
    [Parameter(Mandatory=$false)][string]$AgentExePath = ".\GiamSatAgent.exe",
    [Parameter(Mandatory=$false)][string]$TargetOU = "",  # Empty = entire domain
    [Parameter(Mandatory=$false)][string]$GPOName = "GIAM-SAT Agent Deployment",
    [Parameter(Mandatory=$false)][string]$DomainNetlogon = "\\$env:USERDNSDOMAIN\NETLOGON"
)

$ErrorActionPreference = "Stop"

# =========================================================================
# 1. Copy agent to NETLOGON
# =========================================================================
Write-Host "[*] Copying GiamSatAgent.exe to $DomainNetlogon\GiamSat\" -ForegroundColor Cyan
$destPath = "$DomainNetlogon\GiamSat"
if (!(Test-Path $destPath)) { New-Item -ItemType Directory -Path $destPath -Force | Out-Null }
Copy-Item -Path $AgentExePath -Destination "$destPath\GiamSatAgent.exe" -Force

# Create config file
$config = @{ server_ip = $ServerIP; server_port = $ServerPort; auto_start = $true } | ConvertTo-Json
Set-Content -Path "$destPath\agent_config.json" -Value $config -Force

Write-Host "[*] Agent copied to NETLOGON successfully" -ForegroundColor Green

# =========================================================================
# 2. Create Scheduled Task XML
# =========================================================================
$taskName = "GIAM-SAT Agent Monitor"
$taskXML = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Date>$(Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')</Date><Author>GIAM-SAT</Author><Description>GIAM-SAT Security Monitoring Agent - Auto-start on boot</Description></RegistrationInfo>
  <Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>true</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><IdleSettings><StopOnIdleEnd>true</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>true</Hidden><RunOnlyIfIdle>false</RunOnlyIfIdle><DisallowStartOnRemoteAppSession>false</DisallowStartOnRemoteAppSession><UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine><WakeToRun>false</WakeToRun><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Priority>4</Priority></Settings>
  <Actions Context="Author">
    <Exec>
      <Command>\\$env:USERDNSDOMAIN\NETLOGON\GiamSat\GiamSatAgent.exe</Command>
      <Arguments>--server $ServerIP --port $ServerPort</Arguments>
      <WorkingDirectory>\\$env:USERDNSDOMAIN\NETLOGON\GiamSat</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"@

$taskPath = "$destPath\giamsat_agent_task.xml"
Set-Content -Path $taskPath -Value $taskXML -Force

# =========================================================================
# 3. Create import script for clients
# =========================================================================
$importScript = @"
@echo off
REM GIAM-SAT Agent Auto-Installer via GPO
REM This runs once at startup, imports the scheduled task, then self-deletes

schtasks /create /tn "GIAM-SAT Agent Monitor" /xml "\\$env:USERDNSDOMAIN\NETLOGON\GiamSat\giamsat_agent_task.xml" /f
schtasks /run /tn "GIAM-SAT Agent Monitor"
echo GIAM-SAT Agent installed > "C:\ProgramData\GiamSat\installed.txt"
"@
Set-Content -Path "$destPath\install_agent.bat" -Value $importScript -Force

# =========================================================================
# 4. Create and link GPO
# =========================================================================
Write-Host "[*] Creating GPO: $GPOName" -ForegroundColor Cyan
try {
    Import-Module GroupPolicy -ErrorAction SilentlyContinue
    
    # Create GPO
    $gpo = New-GPO -Name $GPOName -Comment "GIAM-SAT Security Agent Deployment" -ErrorAction Continue
    
    if ($gpo) {
        # Set startup script
        Set-GPRegistryValue -Name $GPOName -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -ValueName "GiamSatInstall" -Type String -Value "cmd /c \\$env:USERDNSDOMAIN\NETLOGON\GiamSat\install_agent.bat" -ErrorAction SilentlyContinue
        
        # Link GPO to target OU or domain root
        if ($TargetOU) {
            New-GPLink -Name $GPOName -Target $TargetOU -ErrorAction SilentlyContinue
        } else {
            $domainDN = (Get-ADDomain).DistinguishedName
            New-GPLink -Name $GPOName -Target $domainDN -ErrorAction SilentlyContinue
        }
        
        Write-Host "[+] GPO '$GPOName' created and linked successfully" -ForegroundColor Green
    }
} catch {
    Write-Host "[-] GPO creation requires ActiveDirectory module. Creating manual instructions..." -ForegroundColor Yellow
    
    # Fallback: Print manual instructions
    Write-Host "`n=== MANUAL SETUP INSTRUCTIONS ===" -ForegroundColor Yellow
    Write-Host "1. Copy GiamSatAgent.exe to $DomainNetlogon\GiamSat\" -ForegroundColor White
    Write-Host "2. Run this on each target machine as admin:" -ForegroundColor White
    Write-Host "   schtasks /create /tn `"GIAM-SAT Agent Monitor`" /xml `"$DomainNetlogon\GiamSat\giamsat_agent_task.xml`" /f" -ForegroundColor Cyan
    Write-Host "   schtasks /run /tn `"GIAM-SAT Agent Monitor`"" -ForegroundColor Cyan
}

Write-Host "`n[*] Deployment preparation complete!" -ForegroundColor Green
Write-Host "[*] Agent will auto-install on next reboot via GPO startup script" -ForegroundColor Cyan