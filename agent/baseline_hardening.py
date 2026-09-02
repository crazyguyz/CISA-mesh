"""
GIAM-SAT Agent Baseline Hardening v4.11 (HIGH-1 fix)
Enables the Windows audit/logging sources that the detection rules depend on,
so the Security channel is not empty and 4624/4625/4688/7045/4104 rules have
data to run against:
  - auditpol subcategories (Logon/Logoff, Account Logon, Account Management,
    Detailed Tracking incl. process creation + command line, Object Access,
    Policy Change, Privilege Use, System)
  - registry: "Include command line in process creation events" (4688 cmdline)
  - registry: PowerShell ScriptBlockLogging + ModuleLogging
Runs ONCE per install (marker file). The agent service normally runs as SYSTEM,
so admin rights are available. All failures are logged, never crash the agent.
"""
import os
import subprocess

_HAS_WINDOWS = os.name == "nt"

# auditpol subcategories to enable with both Success and Failure
AUDIT_SUBCATEGORIES = [
    "Logon", "Logoff", "Account Lockout", "Special Logon",
    "Credential Validation", "Kerberos Authentication Service",
    "Kerberos Service Ticket Operations",
    "User Account Management", "Computer Account Management",
    "Security Group Management", "Distribution Group Management",
    "Process Creation", "Process Termination", "DPAPI Activity", "RPC Events",
    "File System", "Registry",
    "Audit Policy Change", "Authentication Policy Change", "Authorization Policy Change",
    "Sensitive Privilege Use", "Non Sensitive Privilege Use",
    "Security System Extension", "System Integrity",
]


def _log(msg):
    try:
        print(f"[BASELINE] {msg}")
    except Exception:
        pass


def _run(cmd, timeout=15):
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            creationflags=subprocess.CREATE_NO_WINDOW if _HAS_WINDOWS else 0,
        )
        return r.returncode == 0, ((r.stdout or "") + (r.stderr or ""))[:200]
    except Exception as e:
        return False, str(e)


def _set_reg_dword(path, name, value=1):
    try:
        import winreg
        with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, name, 0, winreg.REG_DWORD, value)
        return True
    except Exception as e:
        _log(f"registry {path}\\{name} failed: {e}")
        return False


def enable_windows_audit():
    """auditpol /set /subcategory:'X' /success:enable /failure:enable"""
    ok = 0
    for sub in AUDIT_SUBCATEGORIES:
        good, out = _run(["auditpol", "/set", "/subcategory:" + sub,
                          "/success:enable", "/failure:enable"])
        if good:
            ok += 1
        else:
            _log(f"auditpol '{sub}' failed: {out[:120]}")
    _log(f"auditpol: enabled {ok}/{len(AUDIT_SUBCATEGORIES)} subcategories")
    return ok


def enable_command_line_logging():
    """Registry flag so 4688 'Process Creation' events include the command line."""
    ok = _set_reg_dword(
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit",
        "ProcessCreationIncludeCmdLine_Enabled", 1)
    _log(f"4688 command-line logging: {'OK' if ok else 'FAILED'}")
    return ok


def enable_powershell_logging():
    """PowerShell ScriptBlockLogging (4104) + ModuleLogging."""
    ok1 = _set_reg_dword(
        r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
        "EnableScriptBlockLogging", 1)
    ok2 = _set_reg_dword(
        r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging",
        "EnableModuleLogging", 1)
    ok3 = False
    try:
        import winreg
        with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE,
                                r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging",
                                0, winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, "ModuleNames", 0, winreg.REG_MULTI_SZ, ["*"])
        ok3 = True
    except Exception as e:
        _log(f"ModuleNames failed: {e}")
    _log(f"PowerShell logging: scriptblock={ok1} module={ok2 and ok3}")
    return ok1 and ok2 and ok3


def run_baseline_hardening(marker_dir=None):
    """Run once per install (idempotent via marker file)."""
    if not _HAS_WINDOWS:
        return False
    if marker_dir is None:
        marker_dir = os.path.join(os.environ.get("PROGRAMDATA", r"C:\ProgramData"), "GIAM-SAT", "Agent")
    marker = os.path.join(marker_dir, ".baseline_hardened")
    if os.path.exists(marker):
        return False
    _log("Running baseline hardening (auditpol + PS logging + 4688 cmdline)...")
    n = enable_windows_audit()
    enable_command_line_logging()
    enable_powershell_logging()
    # v5.0.4 R9 (MEDIUM-5): the marker used to be written UNCONDITIONALLY, so
    # 'auditpol_enabled' on the coverage dashboard meant "the script ran once",
    # never "the audit policy is actually on" (a 0/N result still wrote it).
    # Only mark when most subcategories really enabled; otherwise leave the marker
    # out so the next agent/service start retries, and store the achieved count.
    try:
        os.makedirs(marker_dir, exist_ok=True)
        if n >= max(1, int(len(AUDIT_SUBCATEGORIES) * 0.6)):
            with open(marker, "w") as f:
                f.write(str(n))
            _log(f"Baseline hardening done ({n}/{len(AUDIT_SUBCATEGORIES)} audit subcategories enabled)")
        else:
            _log(f"Baseline hardening INCOMPLETE: only {n}/{len(AUDIT_SUBCATEGORIES)} audit subcategories enabled - marker NOT set (will retry on next start)")
    except Exception:
        pass
    return True
