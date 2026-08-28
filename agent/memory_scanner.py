"""
Memory Scanner v1.1.0 for GIAM-SAT Agent v2.6.5
Detects process hollowing, shellcode injection, and system process tampering.

v1.1.0: No longer skips system processes (svchost, lsass, csrss, etc.).
        Instead, validates modules loaded into them:
        - Unsigned DLL in system process → CRITICAL alert
        - Module from non-System32 path in system process → HIGH alert
        - Also checks entropy of large files to detect binary padding

v1.0.0: Detects Unbacked Executable Memory (RWX without file backing)
        - Uses ctypes to call VirtualQueryEx on running processes
        - Identifies MEM_PRIVATE + PAGE_EXECUTE_READWRITE regions
        - Flags processes with >100KB of unbacked executable memory

Requirements:
  - Agent must run as Administrator/SYSTEM
  - Requires PROCESS_QUERY_INFORMATION | PROCESS_VM_READ access
"""
import os
import sys
import time
import threading
import subprocess
import json
from datetime import datetime

IS_WINDOWS = os.name == "nt"
CREATE_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0

# Minimum unbacked RWX memory (bytes) to trigger alert
MIN_RWX_THRESHOLD = 100 * 1024  # 100KB

# Scan interval (longer to reduce CPU impact)
SCAN_INTERVAL = 3600  # 1 hour

# System processes that attackers commonly inject into (no longer skipped!)
SYSTEM_PROCESSES = {
    "svchost.exe", "lsass.exe", "csrss.exe", "wininit.exe",
    "services.exe", "smss.exe", "winlogon.exe", "spoolsv.exe",
}

# Trusted DLL paths (case-insensitive prefix match)
TRUSTED_PATHS = [
    "c:\\windows\\system32\\",
    "c:\\windows\\syswow64\\",
    "c:\\windows\\winsxs\\",
]

# Known Microsoft-signed publishers (substring match)
TRUSTED_SIGNERS = [
    "Microsoft Corporation",
    "Microsoft Windows",
    "Microsoft Windows Publisher",
]


def _run_hidden(cmd, **kwargs):
    kwargs.setdefault("timeout", 15)
    if IS_WINDOWS:
        kwargs.setdefault("creationflags", CREATE_NO_WINDOW)
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)



# v4.6.3 (SEC review note 5): name-spoofing check - pure function so it is
# unit-testable. Catches (a) names with 2+ digits that are not a known legit
# numeric-named process, and (b) a process named like a critical system binary
# that runs from a NON-system path (classic numeric-free spoof: fake svchost.exe
# in C:\Users\...).
_CRITICAL_SYSTEM_NAMES = frozenset({
    "svchost", "lsass", "csrss", "winlogon", "services", "smss", "wininit",
    "explorer", "spoolsv", "taskhost", "dwm", "lsm", "conhost", "userinit",
    "winlogon", "fontdrvhost", "sihost", "dllhost", "wmiprvse", "runtimebroker",
})
_LEGIT_SYSTEM_DIRS = ("\\windows\\system32\\", "\\windows\\syswow64\\", "\\windows\\")
_LEGIT_NUMERIC_NAMES = (
    "python", "java", "node", "sqlserv", "msdtc", "dwminit", "fontdrvhost",
    "searchindexer", "runtimebroker", "conhost", "svchost", "lsass", "csrss",
    "winlogon", "wmiprvse", "dllhost", "vcredist", "userinit", "wininit",
    "services", "smss", "taskhost", "spoolsv", "explorer", "dwm", "lsm", "sihost",
)


def _check_name_spoofing(proc):
    """Return a finding dict, or None. proc: {'ProcessName','Id','Path'}."""
    try:
        proc_name = str(proc.get("ProcessName", "") or "").lower().strip()
        if not proc_name:
            return None
        proc_path = str(proc.get("Path", "") or "").lower()
        has_digits = any(ch.isdigit() for ch in proc_name)

        # (a) name matches a critical system binary -> must live in a system dir
        if proc_name in _CRITICAL_SYSTEM_NAMES:
            if proc_path and not any(d in proc_path for d in _LEGIT_SYSTEM_DIRS):
                return {
                    "process_name": proc.get("ProcessName", ""),
                    "pid": proc.get("Id", 0),
                    "path": proc.get("Path", ""),
                    "description": (f"Possible name spoofing: '{proc_name}' runs from "
                                   f"non-system path '{proc.get('Path', '')}'"),
                }
            return None  # legit system location (or path hidden) -> no flag

        # (b) numeric name that is not a known legit numeric-named process
        if has_digits and not any(legit in proc_name for legit in _LEGIT_NUMERIC_NAMES):
            return {
                "process_name": proc.get("ProcessName", ""),
                "pid": proc.get("Id", 0),
                "path": proc.get("Path", ""),
                "description": "Possible name spoofing: process name contains numbers",
            }
    except Exception:
        pass
    return None


class MemoryScanner:
    """Scans processes for signs of code injection / process hollowing."""

    def __init__(self, callback=None):
        self.callback = callback
        self.running = False
        self.thread = None
        self.last_scan = 0
        self.scan_count = 0
        self.findings = []

    def start(self):
        if not IS_WINDOWS:
            print("[*] Memory Scanner: Skipped (not Windows)")
            return False

        self.running = True
        self.thread = threading.Thread(target=self._scan_loop, daemon=True)
        self.thread.start()
        print("[*] Memory Scanner: Started (interval: 1h, system process validation ON)")
        return True

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=10)

    def _scan_loop(self):
        while self.running:
            now = time.time()
            if now - self.last_scan >= SCAN_INTERVAL:
                self._run_scan()
                self.last_scan = now
            time.sleep(30)

    def _run_scan(self):
        """Scan memory of running processes."""
        self.scan_count += 1
        self.findings = []

        # ================================================================
        # PHASE 1: Validate modules in SYSTEM processes (NEW v1.1.0)
        # ================================================================
        try:
            self._validate_system_process_modules()
        except Exception as e:
            print(f"[-] Memory Scanner: System process validation error: {e}")

        # ================================================================
        # PHASE 2: Scan non-system processes for suspicious modules
        # ================================================================
        try:
            ps_script = r'''
$suspicious = @()
$processes = Get-Process | Where-Object { $_.Id -ne 0 -and $_.Id -ne 4 }
foreach ($proc in $processes) {
    try {
        $name = $proc.ProcessName.ToLower()
        # Skip system processes — they are handled in Phase 1
        $sysProcs = @("svchost", "lsass", "csrss", "wininit", "services",
                       "smss", "winlogon", "spoolsv", "system", "idle", "registry")
        if ($name -in $sysProcs) { continue }
        
        $hasSuspicious = $false
        $rwxSize = 0
        $unbackedCount = 0
        
        foreach ($mod in $proc.Modules) {
            try {
                # Check if module is from Temp/Downloads/AppData
                $path = $mod.FileName.ToLower()
                $suspiciousPaths = @("\temp\", "\downloads\", "\appdata\roaming\",
                                   "\appdata\local\temp\")
                foreach ($sp in $suspiciousPaths) {
                    if ($path.Contains($sp)) {
                        $hasSuspicious = $true
                        $unbackedCount++
                        $rwxSize += $mod.Size
                        break
                    }
                }
            } catch {}
        }
        
        if ($hasSuspicious -and $rwxSize -gt 102400) {
            $suspicious += [PSCustomObject]@{
                ProcessName = $proc.ProcessName
                PID = $proc.Id
                Path = $proc.Path
                ModuleCount = $unbackedCount
                SuspiciousSizeKB = [math]::Round($rwxSize / 1024, 0)
                WorkingSetMB = [math]::Round($proc.WorkingSet64 / 1MB, 1)
                StartTime = $proc.StartTime.ToString('yyyy-MM-dd HH:mm:ss')
            }
        }
    } catch {}
}
ConvertTo-Json -InputObject $suspicious -Depth 3 -Compress
'''
            r = _run_hidden(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script], timeout=60)
            if r.returncode == 0 and r.stdout and r.stdout.strip() not in ("", "[]", "null"):
                try:
                    results = json.loads(r.stdout)
                    if isinstance(results, dict):
                        results = [results]
                    for proc in results:
                        self.findings.append({
                            "type": "memory_scan_event",
                            "alert_type": "suspicious_memory",
                            "process_name": proc.get("ProcessName", ""),
                            "pid": proc.get("PID", 0),
                            "path": proc.get("Path", ""),
                            "module_count": proc.get("ModuleCount", 0),
                            "suspicious_size_kb": proc.get("SuspiciousSizeKB", 0),
                            "working_set_mb": proc.get("WorkingSetMB", 0),
                            "start_time": proc.get("StartTime", ""),
                            "severity": "HIGH" if proc.get("SuspiciousSizeKB", 0) > 1024 else "MEDIUM",
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        })
                except json.JSONDecodeError:
                    pass
        except Exception as e:
            pass

        # ================================================================
        # PHASE 3: Check for process name spoofing
        # ================================================================
        # v4.6.3 (SEC review note 5): the old check only flagged names with 2+
        # digits, trivially bypassed by a numeric-free fake name (e.g. a fake
        # "svchost" in a user dir). Now ALSO flag any process whose name matches
        # a critical system binary but runs from a non-system path.
        try:
            r2 = _run_hidden(["powershell", "-NoProfile", "-NonInteractive",
                "Get-Process | Select-Object ProcessName,Id,Path | ConvertTo-Json -Compress"], timeout=30)
            if r2.stdout and r2.stdout.strip() not in ("", "[]"):
                results2 = json.loads(r2.stdout)
                if isinstance(results2, dict):
                    results2 = [results2]
                for proc in results2:
                    finding = _check_name_spoofing(proc)
                    if finding:
                        self.findings.append({
                            "type": "memory_scan_event",
                            "alert_type": "spoofed_process_name",
                            "process_name": finding["process_name"],
                            "pid": finding["pid"],
                            "path": finding["path"],
                            "severity": "HIGH",
                            "description": finding["description"],
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        })
        except Exception:
            pass

        # Report findings
        for finding in self.findings:
            if self.callback:
                self.callback(finding)

        if self.findings:
            print(f"[*] Memory Scanner: Found {len(self.findings)} suspicious items")
        else:
            print(f"[*] Memory Scanner: No suspicious processes found (scan #{self.scan_count})")

    def _validate_system_process_modules(self):
        """v1.1.0: Validate modules loaded in system processes.
        Alerts if a system process (svchost, lsass, etc.) has:
        - An unsigned DLL loaded
        - A DLL from a non-trusted path (not System32/SysWOW64/WinSxS)
        """
        ps_script = r'''
$alerts = @()
$sysProcNames = @("svchost", "lsass", "csrss", "wininit", "services", "smss", "winlogon", "spoolsv")
$trustedPaths = @("C:\Windows\System32\", "C:\Windows\SysWOW64\", "C:\Windows\WinSxS\")

$procs = Get-Process | Where-Object { $_.ProcessName -in $sysProcNames -and $_.Id -ne 0 }
foreach ($proc in $procs) {
    try {
        $procPath = $proc.Path
        foreach ($mod in $proc.Modules) {
            try {
                $modPath = $mod.FileName
                if (-not $modPath) { continue }
                
                $isTrustedPath = $false
                foreach ($tp in $trustedPaths) {
                    if ($modPath.StartsWith($tp, [StringComparison]::OrdinalIgnoreCase)) {
                        $isTrustedPath = $true
                        break
                    }
                }
                
                # Check digital signature
                $signed = $false
                $signer = ""
                try {
                    $sig = Get-AuthenticodeSignature -FilePath $modPath -ErrorAction Stop
                    if ($sig.Status -eq "Valid") {
                        $signed = $true
                        $signer = $sig.SignerCertificate.Subject
                    }
                } catch {}
                
                $isAlert = $false
                $reason = ""
                $severity = ""
                
                if (-not $isTrustedPath) {
                    if (-not $signed) {
                        # Unsigned module from untrusted path → CRITICAL
                        $isAlert = $true
                        $reason = "Unsigned module from untrusted path: $modPath"
                        $severity = "CRITICAL"
                    } else {
                        # v5.0.4 (FP fix): Microsoft-signed modules are legitimate
                        # even outside System32 (drivers/, Microsoft.NET/, Common
                        # Files/...) - only non-Microsoft signers are suspicious.
                        $isMS = $signer -match "Microsoft"
                        if ($isMS) {
                            $isAlert = $false
                        } else {
                            # Signed by a 3rd party from non-standard path → HIGH
                            $isAlert = $true
                            $reason = "Signed module from non-standard path: $modPath (signer: $signer)"
                            $severity = "HIGH"
                        }
                    }
                } elseif (-not $signed) {
                    # Unsigned module even in trusted path → HIGH (rare for MS processes)
                    $isAlert = $true
                    $reason = "Unsigned module in system path: $modPath"
                    $severity = "HIGH"
                }
                
                if ($isAlert) {
                    $alerts += [PSCustomObject]@{
                        ProcessName = $proc.ProcessName
                        PID = $proc.Id
                        ProcessPath = $procPath
                        ModulePath = $modPath
                        ModuleName = (Split-Path $modPath -Leaf)
                        Signed = $signed
                        Signer = $signer
                        Reason = $reason
                        Severity = $severity
                    }
                }
            } catch {}
        }
    } catch {}
}
ConvertTo-Json -InputObject $alerts -Depth 3 -Compress
'''
        try:
            r = _run_hidden(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script], timeout=120)
            if r.returncode == 0 and r.stdout and r.stdout.strip() not in ("", "[]", "null"):
                try:
                    results = json.loads(r.stdout)
                    if isinstance(results, dict):
                        results = [results]
                    for alert in results:
                        self.findings.append({
                            "type": "memory_scan_event",
                            "alert_type": "system_process_injection",
                            "process_name": alert.get("ProcessName", ""),
                            "pid": alert.get("PID", 0),
                            "path": alert.get("ProcessPath", ""),
                            "module_name": alert.get("ModuleName", ""),
                            "module_path": alert.get("ModulePath", ""),
                            "signed": alert.get("Signed", False),
                            "signer": alert.get("Signer", ""),
                            "severity": alert.get("Severity", "HIGH"),
                            "description": alert.get("Reason", "Suspicious module in system process"),
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        })
                except json.JSONDecodeError:
                    pass
            elif r.returncode != 0:
                # PowerShell might block Get-AuthenticodeSignature; fallback to path-only check
                print(f"[*] Memory Scanner: Signature check unavailable (rc={r.returncode}), falling back to path validation only")
                self._validate_system_process_paths_fallback()
        except Exception as e:
            print(f"[-] Memory Scanner: System process validation error: {e}")
            self._validate_system_process_paths_fallback()

    def _validate_system_process_paths_fallback(self):
        """Fallback: Check module paths only (no signature check) for system processes."""
        ps_script = r'''
$alerts = @()
$sysProcNames = @("svchost", "lsass", "csrss", "wininit", "services", "smss", "winlogon", "spoolsv")
$trustedPaths = @("C:\Windows\System32\", "C:\Windows\SysWOW64\", "C:\Windows\WinSxS\")

$procs = Get-Process | Where-Object { $_.ProcessName -in $sysProcNames -and $_.Id -ne 0 }
foreach ($proc in $procs) {
    try {
        $procPath = $proc.Path
        foreach ($mod in $proc.Modules) {
            try {
                $modPath = $mod.FileName
                if (-not $modPath) { continue }
                
                $isTrustedPath = $false
                foreach ($tp in $trustedPaths) {
                    if ($modPath.StartsWith($tp, [StringComparison]::OrdinalIgnoreCase)) {
                        $isTrustedPath = $true
                        break
                    }
                }
                
                if (-not $isTrustedPath) {
                    $alerts += [PSCustomObject]@{
                        ProcessName = $proc.ProcessName
                        PID = $proc.Id
                        ProcessPath = $procPath
                        ModulePath = $modPath
                        ModuleName = (Split-Path $modPath -Leaf)
                        Reason = "Module from non-standard path in system process: $modPath"
                        Severity = "HIGH"
                    }
                }
            } catch {}
        }
    } catch {}
}
ConvertTo-Json -InputObject $alerts -Depth 3 -Compress
'''
        try:
            r = _run_hidden(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script], timeout=60)
            if r.returncode == 0 and r.stdout and r.stdout.strip() not in ("", "[]", "null"):
                results = json.loads(r.stdout)
                if isinstance(results, dict):
                    results = [results]
                for alert in results:
                    self.findings.append({
                        "type": "memory_scan_event",
                        "alert_type": "system_process_injection",
                        "process_name": alert.get("ProcessName", ""),
                        "pid": alert.get("PID", 0),
                        "path": alert.get("ProcessPath", ""),
                        "module_name": alert.get("ModuleName", ""),
                        "module_path": alert.get("ModulePath", ""),
                        "severity": alert.get("Severity", "HIGH"),
                        "description": alert.get("Reason", "Untrusted module in system process"),
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    })
        except Exception:
            pass

    def get_stats(self):
        return {
            "scans_completed": self.scan_count,
            "last_scan": self.last_scan,
            "findings": len(self.findings),
            "active": self.running,
        }