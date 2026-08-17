"""
Windows Registry Monitoring Collector for GIAM-SAT Agent v1.7.0
Monitors critical Windows registry keys for changes indicating persistence,
privilege escalation, defense evasion, and other malicious activity.

Monitored keys:
- Run/RunOnce (persistence)
- Services (Winlogon, etc.)
- LSA/Security packages
- Browser extensions
- AppInit DLLs
- Shell extensions
- Scheduled tasks registry
- WMI filters/consumers
"""
import os
import sys
import json
import time
import hashlib
import threading
from datetime import datetime
from collections import defaultdict

IS_WINDOWS = os.name == "nt"

if IS_WINDOWS:
    import winreg

# Registry keys to monitor (path, description, severity, category)
MONITORED_REGISTRY_KEYS = [
    # ---- Persistence: Run/RunOnce ----
    ("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
     "HKLM Run (System-wide startup)", "HIGH", "persistence"),
    ("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
     "HKLM RunOnce", "HIGH", "persistence"),
    ("HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
     "HKCU Run (User startup)", "HIGH", "persistence"),
    ("HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
     "HKCU RunOnce", "HIGH", "persistence"),
    ("HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
     "HKLM WOW6432Node Run", "HIGH", "persistence"),
    ("HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
     "Explorer Run Policies", "HIGH", "persistence"),

    # ---- Persistence: Winlogon ----
    ("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
     "Winlogon (Shell/Userinit/Notify)", "CRITICAL", "persistence"),

    # ---- Persistence: Services ----
    ("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services",
     "Windows Services", "HIGH", "persistence"),

    # ---- Credential Access: LSA ----
    ("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
     "LSA Configuration (Security Packages)", "CRITICAL", "credential_access"),
    ("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest",
     "WDigest (UseLogonCredential)", "CRITICAL", "credential_access"),

    # ---- Defense Evasion ----
    ("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender",
     "Windows Defender Policy", "CRITICAL", "defense_evasion"),
    ("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
     "System Policies (UAC, etc.)", "HIGH", "defense_evasion"),

    # ---- Browser / Extension Hijacking ----
    ("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Internet Explorer\\Main",
     "Internet Explorer Settings", "MEDIUM", "browser_hijack"),
    ("HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Internet Explorer\\Main",
     "IE User Settings", "MEDIUM", "browser_hijack"),

    # ---- AppInit DLLs ----
    ("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
     "AppInit_DLLs", "CRITICAL", "persistence"),

    # ---- Shell Extensions / Context Menu ----
    ("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Approved",
     "Approved Shell Extensions", "MEDIUM", "persistence"),

    # ---- Scheduled Tasks Registry ----
    ("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree",
     "Scheduled Tasks Tree", "HIGH", "persistence"),

    # ---- WMI ----
    ("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Wbem\\Scripting",
     "WMI Scripting", "HIGH", "persistence"),

    # ---- Network Settings ----
    ("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
     "TCP/IP Parameters", "MEDIUM", "network"),
    ("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\DNSClient\\Parameters",
     "DNS Client Parameters", "MEDIUM", "network"),

    # ---- NTLM/SMB Settings ----
    ("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0",
     "NTLM Settings", "HIGH", "credential_access"),

    # ---- Session Manager ----
    ("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager",
     "Session Manager (BootExecute)", "CRITICAL", "persistence"),

    # ---- Print Monitors ----
    ("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors",
     "Print Monitors", "MEDIUM", "persistence"),

    # ---- Terminal Services (RDP) ----
    ("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server",
     "Terminal Server Settings", "HIGH", "lateral_movement"),

    # ---- WMI Filters ----
    ("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Wbem\\CIMOM",
     "WMI CIMOM", "MEDIUM", "persistence"),

    # ---- Group Policy ----
    ("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy",
     "Group Policy Scripts", "HIGH", "persistence"),

    # ---- Kernel Drivers ----
    ("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services",
     "System Services (Drivers)", "HIGH", "persistence"),

    # ---- RDP Winstations ----
    ("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
     "RDP-Tcp Settings", "HIGH", "lateral_movement"),

    # ---- Microsoft Edge / Chrome Extension Registry ----
    ("HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Google\\Chrome\\ExtensionInstallForcelist",
     "Chrome Enterprise Extension Forcelist", "MEDIUM", "browser_hijack"),

    # ---- Office Add-ins ----
    ("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Office",
     "Microsoft Office Addins", "MEDIUM", "persistence"),

    # ---- Boot Configuration ----
    ("HKEY_LOCAL_MACHINE\\BCD00000000",
     "Boot Configuration Data", "CRITICAL", "defense_evasion"),
]


def _parse_registry_path(full_path):
    """
    Parse a registry path into (hive_key, subkey, value_name).
    Example: 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'
         -> (winreg.HKEY_LOCAL_MACHINE, 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run')
    """
    parts = full_path.split("\\", 1)
    hive_name = parts[0]
    subkey = parts[1] if len(parts) > 1 else ""

    hive_map = {
        "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
        "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
        "HKEY_USERS": winreg.HKEY_USERS,
        "HKEY_CLASSES_ROOT": winreg.HKEY_CLASSES_ROOT,
        "HKEY_CURRENT_CONFIG": winreg.HKEY_CURRENT_CONFIG,
    }
    return hive_map.get(hive_name, winreg.HKEY_LOCAL_MACHINE), subkey


def _hash_registry_values(key_path):
    """Calculate a hash of all values in a registry key for comparison."""
    try:
        hive, subkey = _parse_registry_path(key_path)
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
            data = {}
            i = 0
            while True:
                try:
                    name, value, vtype = winreg.EnumValue(key, i)
                    data[name] = str(value)
                    i += 1
                except OSError:
                    break
            content = json.dumps(data, sort_keys=True, ensure_ascii=False)
            return hashlib.sha256(content.encode("utf-8")).hexdigest(), data
    except FileNotFoundError:
        return "KEY_NOT_FOUND", {}
    except PermissionError:
        return "ACCESS_DENIED", {}
    except Exception:
        return "ERROR", {}


class RegistryCollector:
    """Monitors Windows registry keys for changes indicating malicious activity."""

    def __init__(self, callback=None, check_interval=60, monitor_keys=None):
        self.callback = callback
        self.check_interval = check_interval
        self.running = False
        self._thread = None
        self._baseline = {}  # key_path -> hash
        self._baseline_data = {}  # key_path -> dict of values
        self.monitor_keys = monitor_keys or MONITORED_REGISTRY_KEYS

    def start(self):
        """Start registry monitoring."""
        if not IS_WINDOWS:
            print("[*] Registry Collector: Skipped (not Windows)")
            return

        self.running = True
        # Build initial baseline silently
        print(f"[*] Registry Collector: Building baseline for {len(self.monitor_keys)} registry keys...")
        self._build_baseline()
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        print(f"[*] Registry Collector: Monitoring started (interval={self.check_interval}s)")

    def _build_baseline(self):
        """Build initial baseline hash of all monitored registry keys."""
        for item in self.monitor_keys:
            key_path = item[0]
            h, data = _hash_registry_values(key_path)
            self._baseline[key_path] = h
            self._baseline_data[key_path] = data

        valid_count = sum(1 for h in self._baseline.values() if h not in ("KEY_NOT_FOUND", "ACCESS_DENIED", "ERROR"))
        print(f"[*] Registry Collector: Baselines {valid_count}/{len(self.monitor_keys)} keys")

    def _monitor_loop(self):
        """Periodic monitoring loop."""
        while self.running:
            time.sleep(self.check_interval)
            try:
                self._check_changes()
            except Exception as e:
                print(f"[-] Registry Collector error: {e}")

    def _check_changes(self):
        """Check monitored registry keys for changes."""
        for item in self.monitor_keys:
            key_path, description, severity, category = item
            new_hash, new_data = _hash_registry_values(key_path)

            old_hash = self._baseline.get(key_path, "")
            old_data = self._baseline_data.get(key_path, {})

            # Skip keys that can't be read
            if new_hash in ("KEY_NOT_FOUND", "ACCESS_DENIED", "ERROR"):
                if old_hash not in ("KEY_NOT_FOUND", "ACCESS_DENIED", "ERROR"):
                    # Key disappeared!
                    self._send_event("REGISTRY_KEY_DELETED", key_path, description,
                                     f"Registry key was deleted or became inaccessible", "CRITICAL", category)
                    self._baseline[key_path] = new_hash
                    self._baseline_data[key_path] = new_data
                continue

            if new_hash != old_hash:
                # Key changed - find diff
                added = set(new_data.keys()) - set(old_data.keys())
                removed = set(old_data.keys()) - set(new_data.keys())
                changed = set()

                for k in set(new_data.keys()) & set(old_data.keys()):
                    if new_data[k] != old_data[k]:
                        changed.add(k)

                changes = []
                if added:
                    changes.append(f"Added values: {', '.join(sorted(added)[:5])}")
                if removed:
                    changes.append(f"Removed values: {', '.join(sorted(removed)[:5])}")
                if changed:
                    changes.append(f"Changed values: {', '.join(sorted(changed)[:5])}")

                # Highlight specific suspicious changes
                suspicious_values = self._check_suspicious_values(key_path, added, changed, new_data)

                primary_severity = severity
                if suspicious_values:
                    primary_severity = "CRITICAL"
                    changes.append(f"SUSPICIOUS: {suspicious_values}")

                change_desc = "; ".join(changes) if changes else "Registry key modified"

                self._send_event("REGISTRY_KEY_MODIFIED", key_path, description,
                                 change_desc, primary_severity, category)

                # Update baseline
                self._baseline[key_path] = new_hash
                self._baseline_data[key_path] = new_data

    def _check_suspicious_values(self, key_path, added_values, changed_values, all_data):
        """Check for known-suspicious registry values."""
        suspicious = []

        suspicious_patterns = {
            # Persistence
            "Shell": "shell replacement detected",
            "Userinit": "userinit modification",
            "AppInit_DLLs": "AppInit DLL loaded",
            "BootExecute": "boot execute modification",
            "Notification Packages": "LSA notification package added",

            # Credential access
            "Security Packages": "security package added",
            "Authentication Packages": "authentication package added",
            "UseLogonCredential": "WDigest credential caching enabled",

            # Defense evasion
            "DisableAntiSpyware": "Defender disabled",
            "DisableRealtimeMonitoring": "real-time protection disabled",
            "EnableLUA": "UAC modified",
            "DisableTaskMgr": "Task Manager disabled",
            "DisableRegistryTools": "Registry tools disabled",

            # Autoruns
            "Load": "kernel driver load",
            "Run": "autorun entry",
            "SCRNSAVE.EXE": "screensaver hijack",
        }

        all_changed = added_values | changed_values

        for value_name, risk_desc in suspicious_patterns.items():
            if value_name in all_changed:
                suspicious.append(f"{risk_desc} ('{value_name}')")
            elif any(value_name.lower() in v.lower() for v in all_changed):
                suspicious.append(f"possible {risk_desc}")

        # Specific key path checks
        if "Winlogon" in key_path:
            if "Shell" in all_changed:
                shell_val = all_data.get("Shell", "")
                if shell_val and "explorer.exe" not in shell_val.lower():
                    suspicious.append(f"Winlogon Shell replaced: {shell_val}")

        if "Lsa" in key_path:
            pkgs = all_data.get("Security Packages", "")
            if pkgs and any(pkg in pkgs.lower() for pkg in ["wdigest", "kerberos"]):
                suspicious.append(f"LSA Security Package modified: {pkgs[:100]}")

        return "; ".join(suspicious) if suspicious else ""

    def _send_event(self, event_type, key_path, description, details, severity, category):
        """Send registry change event via callback."""
        event = {
            "type": "registry_event",
            "subtype": event_type,
            "key_path": key_path,
            "description": description,
            "details": details[:500],
            "severity": severity,
            "category": category,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        if self.callback:
            self.callback(event)

    def stop(self):
        """Stop registry monitoring."""
        self.running = False