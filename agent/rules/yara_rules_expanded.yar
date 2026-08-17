/*
 * GIAM-SAT Expanded YARA Rules v1.7.0
 * Extended ruleset for ransomware, webshell, credential theft, and malware detection.
 * Rules adapted from community resources: YARA Rules project, Neo23x0, Elastic, Florian Roth.
 * 
 * Categories:
 *   - Ransomware (indicators, notes, extensions)
 *   - Web Shell (PHP, ASP.NET, JSP)
 *   - Credential Theft (mimikatz, procdump, LSASS access)
 *   - Malware Droppers (PowerShell, VBS, HTA)
 *   - C2 Frameworks (Cobalt Strike, Metasploit, Empire)
 */

// =============================================================================
// RANSOMWARE RULES
// =============================================================================

rule Ransomware_Extension_Encrypted {
    meta:
        description = "Detects files with common ransomware encrypted extensions"
        severity = "CRITICAL"
        author = "GIAM-SAT"
        date = "2026-07-11"
        category = "ransomware"
    strings:
        $ext1 = ".encrypted" nocase
        $ext2 = ".locked" nocase
        $ext3 = ".crypted" nocase
        $ext4 = ".encrypt" nocase
        $ext5 = ".cry" nocase
        $ext6 = ".crypt" nocase
        $ext7 = ".wncry" nocase
        $ext8 = ".wcry" nocase
        $ext9 = ".locky" nocase
        $ext10 = ".zepto" nocase
        $ext11 = ".odin" nocase
        $ext12 = ".cerber" nocase
        $ext13 = ".cerber2" nocase
        $ext14 = ".cerber3" nocase
        $ext15 = ".dharma" nocase
        $ext16 = ".phobos" nocase
        $ext17 = ".ryuk" nocase
        $ext18 = ".conti" nocase
        $ext19 = ".revil" nocase
        $ext20 = ".sodinokibi" nocase
        $ext21 = ".maze" nocase
        $ext22 = ".ekans" nocase
        $ext23 = ".netwalker" nocase
        $ext24 = ".ragnar" nocase
        $ext25 = ".lockbit" nocase
    condition:
        any of them
}

rule Ransomware_Note_Filename {
    meta:
        description = "Detects ransomware ransom note files by filename"
        severity = "CRITICAL"
        author = "GIAM-SAT"
        category = "ransomware"
    strings:
        $n1 = "HOW TO DECRYPT" nocase wide
        $n2 = "HOW TO RESTORE" nocase wide
        $n3 = "DECRYPT_INSTRUCTIONS" nocase wide
        $n4 = "RECOVERY_INSTRUCTIONS" nocase wide
        $n5 = "RESTORE_FILES" nocase wide
        $n6 = "YOUR_FILES_ARE_ENCRYPTED" nocase wide
        $n7 = "README_FOR_DECRYPT" nocase wide
        $n8 = "_readme.txt" nocase
        $n9 = "_README_" nocase
        $n10 = "ransom_note" nocase
        $n11 = "HELP_DECRYPT" nocase
        $n12 = "!READ_ME!" nocase wide
        $n13 = "!!!READ_ME!!!" nocase wide
        $n14 = "DECRYPTION_INFO" nocase
    condition:
        any of them
}

rule Ransomware_ShadowCopy_Deletion {
    meta:
        description = "Detects commands used to delete shadow copies (ransomware behavior)"
        severity = "CRITICAL"
        author = "GIAM-SAT"
        category = "ransomware"
    strings:
        $cmd1 = "vssadmin delete shadows" nocase wide ascii
        $cmd2 = "vssadmin.exe delete shadows" nocase wide ascii
        $cmd3 = "wmic shadowcopy delete" nocase wide ascii
        $cmd4 = "Get-WmiObject Win32_Shadowcopy" nocase wide
        $cmd5 = "DeleteShadowCopies" nocase
        $cmd6 = "bcdedit /set {default} recoveryenabled No" nocase wide ascii
        $cmd7 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" nocase wide ascii
        $cmd8 = "wbadmin delete catalog" nocase wide ascii
        $cmd9 = "Disable-ComputerRestore" nocase wide
    condition:
        2 of them
}

rule Ransomware_WMI_ShadowCopy_Delete {
    meta:
        description = "Detects WMI-based shadow copy deletion via PowerShell"
        severity = "CRITICAL"
        author = "GIAM-SAT"
        category = "ransomware"
    strings:
        $s1 = "Win32_ShadowCopy" nocase
        $s2 = ".Delete()" nocase
        $s3 = "Get-WmiObject" nocase
    condition:
        $s1 and ($s2 or $s3)
}

rule Ransomware_File_Encrypt_Commands {
    meta:
        description = "Detects file encryption shell commands used by ransomware"
        severity = "HIGH"
        author = "GIAM-SAT"
        category = "ransomware"
    strings:
        $c1 = "cipher /e" nocase
        $c2 = "gpg --encrypt" nocase
        $c3 = "openssl enc" nocase
        $c4 = "7z a -p" nocase
    condition:
        any of them
}

// =============================================================================
// WEB SHELL RULES
// =============================================================================

rule Webshell_PHP_Simple {
    meta:
        description = "Detects common PHP web shells (simple variants)"
        severity = "CRITICAL"
        author = "GIAM-SAT"
        category = "webshell"
    strings:
        $php1 = "<?php" nocase
        $eval1 = "eval($_POST" nocase
        $eval2 = "eval($_GET" nocase
        $eval3 = "eval($_REQUEST" nocase
        $exec1 = "exec($_POST" nocase
        $exec2 = "shell_exec($_POST" nocase
        $exec3 = "system($_POST" nocase
        $exec4 = "passthru($_POST" nocase
        $exec5 = "popen($_POST" nocase
        $exec6 = "proc_open(" nocase
        $exec7 = "pcntl_exec" nocase
        $assert = "assert($_POST" nocase
        $assert2 = "assert($_GET" nocase
        $base64 = "base64_decode" nocase
        $gz = "gzinflate" nocase
        $strrot = "str_rot13" nocase
        $preg_replace = "preg_replace('/.*/e'" nocase
        $backtick1 = "`$_POST" nocase
        $backtick2 = "`$_GET" nocase
    condition:
        $php1 and 2 of ($eval*, $exec*, $assert, $assert2, $backtick1, $backtick2)
}

rule Webshell_PHP_Obfuscated {
    meta:
        description = "Detects obfuscated PHP web shells using encoding techniques"
        severity = "CRITICAL"
        author = "GIAM-SAT"
        category = "webshell"
    strings:
        $php = "<?php" nocase
        $b64  = "base64_decode" nocase
        $gz1  = "gzinflate" nocase
        $gz2  = "gzuncompress" nocase
        $rot  = "str_rot13" nocase
        $chr  = "chr(" nocase
        $ord  = "ord(" nocase
        $hex  = "\\x" nocase
        $urldecode = "urldecode" nocase
        $create_func = "create_function" nocase
        $call_user   = "call_user_func" nocase
        $array_map   = "array_map" nocase
        $reflection  = "ReflectionFunction" nocase
    condition:
        $php and $b64 and 3 of ($gz1, $gz2, $rot, $chr, $ord, $create_func, $call_user, $array_map, $reflection)
}

rule Webshell_China_Chopper {
    meta:
        description = "Detects China Chopper web shell and variants"
        severity = "CRITICAL"
        author = "GIAM-SAT"
        category = "webshell"
    strings:
        $chopper1 = "chopper" nocase
        $chopper2 = "Cknife" nocase
        $caidao   = "Caidao" nocase
        $ee1 = "eval(base64_decode" nocase
        $ee2 = "eval(gzinflate(base64_decode" nocase
        $ee3 = "@eval(" nocase
        $z0 = "$_0" nocase
        $password1 = "$password" nocase wide
        $password2 = "$pass" nocase wide
        $header1 = "eval (chr" nocase
    condition:
        2 of ($chopper*, $caidao) or ($ee1 or $ee2 or $ee3) and ($z0 or $password1 or $password2)
}

rule Webshell_ASP_NET {
    meta:
        description = "Detects ASP.NET web shells"
        severity = "CRITICAL"
        author = "GIAM-SAT"
        category = "webshell"
    strings:
        $asp1 = "<%@ Page" nocase
        $asp2 = "System.Diagnostics.Process" nocase
        $asp3 = "Process.Start" nocase
        $asp4 = "Request.Form" nocase
        $asp5 = "Request.QueryString" nocase
        $asp6 = "Server.Execute" nocase
        $asp7 = "eval(" nocase
        $asp8 = "Execute(" nocase
        $asp9 = "Runtime.exec" nocase
        $asp10 = "java.lang.Runtime" nocase
        $jsp1 = "<%@ page import=\"java.io.*\"%>" nocase
    condition:
        ($asp1 and 2 of ($asp2, $asp3, $asp4, $asp5, $asp6)) or ($asp1 and ($asp7 or $asp8)) or ($jsp1 and ($asp9 or $asp10))
}

rule Webshell_File_Manager {
    meta:
        description = "Detects web-based file manager scripts (potential web shells)"
        severity = "HIGH"
        author = "GIAM-SAT"
        category = "webshell"
    strings:
        $fm1 = "file manager" nocase wide
        $fm2 = "file browser" nocase wide
        $fm3 = "web shell" nocase wide
        $fm4 = "command shell" nocase wide
        $fm5 = "server information" nocase
        $fm6 = "phpinfo()" nocase
        $fm7 = "disk_free_space" nocase
        $fm8 = "scandir" nocase
        $fm9 = "Directory Listing" nocase
    condition:
        3 of them
}

// =============================================================================
// CREDENTIAL THEFT RULES
// =============================================================================

rule CredentialTheft_Mimikatz {
    meta:
        description = "Detects Mimikatz credential dumping tool"
        severity = "CRITICAL"
        author = "GIAM-SAT"
        category = "credential_theft"
    strings:
        $mk1 = "mimikatz" nocase wide ascii
        $mk2 = "mimikatz.exe" nocase wide ascii
        $mk3 = "mimidrv" nocase wide ascii
        $mk4 = "sekurlsa" nocase wide ascii
        $mk5 = "sekurlsa::logonpasswords" nocase wide ascii
        $mk6 = "kerberos::golden" nocase wide
        $mk7 = "kerberos::ptt" nocase wide
        $mk8 = "lsadump::sam" nocase wide
        $mk9 = "lsadump::secrets" nocase wide
        $mk10 = "lsadump::dcsync" nocase wide
        $mk11 = "lsadump::cache" nocase wide
        $mk12 = "privilege::debug" nocase wide ascii
        $mk13 = "crypto::capi" nocase wide
        $mk14 = "crypto::cng" nocase wide
        $mk15 = "token::elevate" nocase wide
        $mk16 = "vault::cred" nocase wide
        $mk17 = "ts::multirdp" nocase wide
        $mk18 = '"mimikatz"' nocase
    condition:
        2 of them or $mk18
}

rule CredentialTheft_ProcDump_LSASS {
    meta:
        description = "Detects process dumping of LSASS (credential theft)"
        severity = "CRITICAL"
        author = "GIAM-SAT"
        category = "credential_theft"
    strings:
        $p1 = "procdump" nocase wide ascii
        $p2 = "procdump.exe" nocase wide ascii
        $p3 = "procdump64.exe" nocase wide ascii
        $p4 = "-ma lsass.exe" nocase wide ascii
        $p5 = "-accepteula" nocase wide ascii
        $p6 = "lsass.dmp" nocase wide
        $p7 = "lsass.exe" nocase wide
    condition:
        ($p1 or $p2 or $p3) and ($p4 or $p6 or ($p7 and $p5))
}

rule CredentialTheft_SamDump {
    meta:
        description = "Detects SAM/SECURITY/SYSTEM registry hive dumping"
        severity = "CRITICAL"
        author = "GIAM-SAT"
        category = "credential_theft"
    strings:
        $r1 = "reg save hklm\\sam" nocase wide ascii
        $r2 = "reg save hklm\\system" nocase wide ascii
        $r3 = "reg save hklm\\security" nocase wide ascii
        $r4 = "reg.exe save hklm\\sam" nocase wide ascii
        $r5 = "reg.exe save hklm\\system" nocase wide ascii
        $r6 = "reg.exe save hklm\\security" nocase wide ascii
        $n1 = "ntdsutil" nocase wide ascii
        $n2 = "create full" nocase wide ascii
        $n3 = "ifm" nocase wide ascii
    condition:
        any of ($r1, $r2, $r3, $r4, $r5, $r6) or (all of ($n1, $n2, $n3))
}

rule CredentialTheft_NinjaCopy {
    meta:
        description = "Detects tools that copy locked files (NTDS.dit access)"
        severity = "HIGH"
        author = "GIAM-SAT"
        category = "credential_theft"
    strings:
        $nc1 = "ninjacopy" nocase
        $nc2 = "NtdsAudit" nocase
        $nc3 = "Invoke-NinjaCopy" nocase
        $nc4 = "Copy-VSS" nocase
        $nc5 = "Ntdsutil" nocase wide ascii
        $nc6 = "ntds.dit" nocase wide
        $nc7 = "vssown" nocase
    condition:
        2 of them
}

rule CredentialTheft_LaZagne {
    meta:
        description = "Detects LaZagne multi-application password recovery tool"
        severity = "CRITICAL"
        author = "GIAM-SAT"
        category = "credential_theft"
    strings:
        $l1 = "LaZagne" nocase wide ascii
        $l2 = "lazagne.exe" nocase wide ascii
        $l3 = "lazagne.py" nocase
        $l4 = "all -oN" nocase
        $l5 = "passwordFound" nocase
    condition:
        any of ($l1, $l2, $l3) or ($l4 and $l5)
}

rule CredentialTheft_Browser_Password_Dump {
    meta:
        description = "Detects browser password dumping tools"
    severity = "HIGH"
        author = "GIAM-SAT"
        category = "credential_theft"
    strings:
        $ch1 = "chrome_passwords" nocase
        $ch2 = "ChromePass" nocase
        $ch3 = "WebBrowserPassView" nocase
        $ch4 = "iepv" nocase
        $ch5 = "firefox_decrypt" nocase
        $ch6 = "Login Data" nocase
        $ch7 = "browser_password" nocase
        $ch8 = "credential_dump" nocase
    condition:
        2 of them
}

rule CredentialTheft_WCE {
    meta:
        description = "Detects Windows Credential Editor (WCE)"
        severity = "CRITICAL"
        author = "GIAM-SAT"
        category = "credential_theft"
    strings:
        $wce1 = "wce.exe" nocase wide ascii
        $wce2 = "wce64.exe" nocase wide ascii
        $wce3 = "Windows Credentials Editor" nocase wide ascii
        $wce4 = "-w" nocase
        $wce5 = "wceaux.dll" nocase wide
    condition:
        any of ($wce1, $wce2, $wce3) or ($wce4 and $wce5)
}

// =============================================================================
// MALWARE DROPPERS
// =============================================================================

rule Malware_Dropper_PowerShell {
    meta:
        description = "Detects PowerShell-based malware droppers and downloaders"
        severity = "HIGH"
        author = "GIAM-SAT"
        category = "malware_dropper"
    strings:
        $ps1 = "powershell" nocase wide
        $dl1 = "DownloadFile" nocase wide ascii
        $dl2 = "DownloadString" nocase wide ascii
        $dl3 = "DownloadData" nocase wide ascii
        $dl4 = "Invoke-WebRequest" nocase wide
        $dl5 = "Invoke-RestMethod" nocase wide
        $dl6 = "Net.WebClient" nocase wide ascii
        $dl7 = "Start-BitsTransfer" nocase wide
        $dl8 = "New-Object System.Net.WebClient" nocase
        $b64 = "-EncodedCommand" nocase wide ascii
        $iex = "IEX" nocase
        $iex2 = "Invoke-Expression" nocase wide
    condition:
        ($ps1 or $dl6 or $dl8) and 2 of ($dl*, $b64, $iex, $iex2)
}

rule Malware_Dropper_VBS_HTA {
    meta:
        description = "Detects VBScript/HTA-based malware droppers"
        severity = "HIGH"
        author = "GIAM-SAT"
        category = "malware_dropper"
    strings:
        $vbs1 = "WScript.Shell" nocase
        $vbs2 = "WScript.CreateObject" nocase
        $vbs3 = "MSXML2.XMLHTTP" nocase
        $vbs4 = "WinHttp.WinHttpRequest" nocase
        $vbs5 = "ADODB.Stream" nocase
        $vbs6 = "Shell.Application" nocase
        $vbs7 = "Microsoft.XMLHTTP" nocase
        $vbs8 = "Scripting.FileSystemObject" nocase
        $hta1 = "<HTA:APPLICATION" nocase
        $hta2 = "mshta.exe" nocase wide
    condition:
        2 of ($vbs1, $vbs2, $vbs3, $vbs4, $vbs5, $vbs6, $vbs7, $vbs8) or ($hta1 and $hta2)
}

rule Malware_Dropper_Certutil {
    meta:
        description = "Detects certutil used as malware downloader (LOLBin)"
        severity = "HIGH"
        author = "GIAM-SAT"
        category = "malware_dropper"
    strings:
        $c1 = "certutil" nocase wide ascii
        $c2 = "-urlcache" nocase wide ascii
        $c3 = "-split" nocase wide ascii
        $c4 = "-f" nocase wide
        $c5 = "http" nocase
    condition:
        $c1 and ($c2 or $c3) and $c5
}

rule Malware_Dropper_BitsAdmin {
    meta:
        description = "Detects bitsadmin used for malware download (LOLBin)"
        severity = "MEDIUM"
        author = "GIAM-SAT"
        category = "malware_dropper"
    strings:
        $b1 = "bitsadmin" nocase wide ascii
        $b2 = "/transfer" nocase wide ascii
        $b3 = "http" nocase wide
        $b4 = "/download" nocase wide ascii
    condition:
        $b1 and $b2 and $b3
}

// =============================================================================
// C2 FRAMEWORKS
// =============================================================================

rule C2_CobaltStrike_Beacon {
    meta:
        description = "Detects Cobalt Strike beacon configuration patterns"
        severity = "CRITICAL"
        author = "GIAM-SAT"
        category = "c2"
    strings:
        $cs1 = "ReflectiveLoader" nocase
        $cs2 = "beacon.dll" nocase wide
        $cs3 = "beacon.x64.dll" nocase wide
        $cs4 = "beacon.x86.dll" nocase wide
        $cs5 = "%cobaltstrike%" nocase wide
        $cs6 = "CobaltStrike" nocase wide
        $cs7 = /\\x2e\\x2f\\x2e\\x2f/
        $http_get = "Mozilla/5.0" nocase
        $cs8 = "beacon_obfuscate" nocase
        $cs9 = "beacon sleep" nocase
    condition:
        2 of them or ($cs1 and $cs2) or ($cs8 and $cs9)
}

rule C2_Metasploit_Meterpreter {
    meta:
        description = "Detects Metasploit Meterpreter payloads"
        severity = "HIGH"
        author = "GIAM-SAT"
        category = "c2"
    strings:
        $msf1 = "Meterpreter" nocase wide
        $msf2 = "metsrv" nocase
        $msf3 = "metasploit" nocase wide ascii
        $msf4 = "stdapi" nocase
        $msf5 = "ReflectiveDllInjection" nocase
        $msf6 = "msf.dll" nocase
        $msf7 = "payload/windows" nocase
    condition:
        2 of them
}

rule C2_Empire {
    meta:
        description = "Detects PowerShell Empire / Starkiller C2 framework"
        severity = "HIGH"
        author = "GIAM-SAT"
        category = "c2"
    strings:
        $e1 = "Empire" nocase wide
        $e2 = "starkiller" nocase wide
        $e3 = "Invoke-Empire" nocase
        $e4 = "PowerShell Empire" nocase wide
        $e5 = "startup.bat Empire" nocase
        $e6 = "Koadic" nocase wide
    condition:
        2 of them
}

rule C2_Covenant_Grunt {
    meta:
        description = "Detects Covenant C2 framework Grunt implants"
        severity = "HIGH"
        author = "GIAM-SAT"
        category = "c2"
    strings:
        $c1 = "GruntStager" nocase
        $c2 = "GruntHTTP" nocase
        $c3 = "GruntSMB" nocase
        $c4 = "Covenant" nocase wide
        $c5 = "Covenant.dll" nocase
    condition:
        2 of them
}

// =============================================================================
// DEFENSE EVASION
// =============================================================================

rule Evasion_ETW_Patching {
    meta:
        description = "Detects ETW (Event Tracing for Windows) patching/disablement"
        severity = "HIGH"
        author = "GIAM-SAT"
        category = "defense_evasion"
    strings:
        $etw1 = "EtwEventWrite" nocase
        $etw2 = "NtTraceEvent" nocase
        $etw3 = "EtwpCreateEtwThread" nocase
        $patch1 = "VirtualProtect" nocase
        $patch2 = "WriteProcessMemory" nocase
        $etw4 = "SetEtwEnabled" nocase
    condition:
        ($etw1 or $etw2 or $etw3 or $etw4) and ($patch1 or $patch2)
}

rule Evasion_AMSI_Bypass {
    meta:
        description = "Detects AMSI (Antimalware Scan Interface) bypass attempts"
        severity = "HIGH"
        author = "GIAM-SAT"
        category = "defense_evasion"
    strings:
        $amsi1 = "AmsiInitialize" nocase
        $amsi2 = "AmsiScanBuffer" nocase
        $amsi3 = "AmsiOpenSession" nocase
        $amsi4 = "amsi.dll" nocase
        $amsi5 = "amsiInitFailed" nocase
        $amsi6 = "Amsi bypass" nocase wide
        $amsi7 = "Disable-Amsi" nocase
        $amsi8 = "AMSI_RESULT" nocase
        $patch = "VirtualProtect" nocase
    condition:
        2 of them or ($amsi6 or $amsi7)
}

// =============================================================================
// PRIVILEGE ESCALATION
// =============================================================================

rule PrivEsc_JuicyPotato {
    meta:
        description = "Detects JuicyPotato and similar privilege escalation tools"
        severity = "HIGH"
        author = "GIAM-SAT"
        category = "privilege_escalation"
    strings:
        $j1 = "JuicyPotato" nocase wide ascii
        $j2 = "RoguePotato" nocase wide
        $j3 = "RottenPotato" nocase wide
        $j4 = "SweetPotato" nocase wide
        $j5 = "PrintSpoofer" nocase wide
        $j6 = "PipePotato" nocase wide
        $j7 = "EfsPotato" nocase wide
        $j8 = "GodPotato" nocase wide
        $j9 = "CLSID" nocase
        $j10 = "CreateProcessWithToken" nocase
    condition:
        any of ($j1, $j2, $j3, $j4, $j5, $j6, $j7, $j8) or ($j9 and $j10)
}

rule PrivEsc_UAC_Bypass {
    meta:
        description = "Detects UAC bypass techniques"
        severity = "HIGH"
        author = "GIAM-SAT"
        category = "privilege_escalation"
    strings:
        $u1 = "fodhelper" nocase wide
        $u2 = "eventvwr" nocase wide
        $u3 = "compmgmtlauncher" nocase wide
        $u4 = "sdclt" nocase wide
        $u5 = "silentcleanup" nocase wide
        $u6 = "WSReset" nocase wide
        $u7 = "wsreset.exe" nocase wide
        $u8 = "ComputerDefaults" nocase wide
        $u9 = "cmstp" nocase wide
        $i1 = "HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\System" nocase
        $i2 = "ConsentPromptBehaviorAdmin" nocase
    condition:
        (any of ($u1, $u2, $u3, $u4, $u5, $u6, $u7, $u8, $u9)) or ($i1 and $i2)
}

// =============================================================================
// RECONNAISSANCE TOOLS
// =============================================================================

rule Recon_Network_Scanning_Tools {
    meta:
        description = "Detects network scanning and reconnaissance tools"
        severity = "MEDIUM"
        author = "GIAM-SAT"
        category = "recon"
    strings:
        $n1 = "nmap" nocase wide ascii
        $n2 = "masscan" nocase wide
        $n3 = "zenmap" nocase wide
        $n4 = "angry ip scanner" nocase wide
        $n5 = "advanced port scanner" nocase wide
        $n6 = "SoftPerfect Network Scanner" nocase
        $n7 = "netcat" nocase wide
        $n8 = "nc.exe" nocase wide ascii
        $n9 = "nc64.exe" nocase wide
    condition:
        any of them
}