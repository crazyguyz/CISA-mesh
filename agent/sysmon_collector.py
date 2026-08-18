"""
Sysmon Collector v1.0.0 for GIAM-SAT Agent v2.6.0
Collects Microsoft Sysmon events from Windows Event Log and converts to GIAM-SAT format.

Sysmon Event IDs mapped:
  1  → Process Create (Full command line, hashes, parent PID, user, integrity level)
  3  → Network Connect (PID + Protocol + Source/Dest IP + Port) ← GIẢI QUYẾT #6
  7  → Image Load (DLL loaded into process)
  8  → CreateRemoteThread (Process Injection detection!)
  10 → Process Access (LSASS dumping detection, Mimikatz behavior)
  11 → File Create (File creation with process context)
  12 → Registry Create/Delete (Registry key/value create/delete)
  13 → Registry Set (Registry value modification)
  14 → Registry Rename (Registry key/value rename)
  22 → DNS Query (Process + domain query)

Requirements:
  - Sysmon must be installed on the machine (Sysinternals, free)
  - Agent needs read access to "Microsoft-Windows-Sysmon/Operational" event log
"""
import os
import sys
import json
import time
import threading
import subprocess
import re
from datetime import datetime
from xml.etree import ElementTree as ET

IS_WINDOWS = os.name == "nt"
CREATE_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0

# v3.2: Process Tree Builder for LOTL chain detection
try:
    from process_tree import ProcessTreeBuilder
    HAS_PROCESS_TREE = True
except ImportError:
    HAS_PROCESS_TREE = False

# Sysmon event log channel
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
SYSMON_QUERY = f"*[System[Provider[@Name='Microsoft-Windows-Sysmon']]]"

# Check interval
POLL_INTERVAL = 5  # seconds

# Map Sysmon EventID to GIAM-SAT event type
EVENT_TYPE_MAP = {
    1:  "process_event",       # Process Create
    2:  "process_event",       # v3.1: Process Terminate (Timestomping detection via CreationUtcTime)
    3:  "network_event",       # Network Connect (CÓ PID!)
    4:  "service_state_change",# v3.9.16: Sysmon Service State (stopped/started) → Tampering Detection
    7:  "module_load_event",   # Image/DLL Load
    8:  "process_injection",   # CreateRemoteThread
    10: "process_access",      # Process Access (LSASS dumping)
    11: "file_create_event",   # File Create
    12: "registry_event",      # Registry Create/Delete
    13: "registry_event",      # Registry Set
    14: "registry_event",      # Registry Rename
    15: "file_create_event",   # v3.1: FileCreateStreamHash (MOTW/Zone.Identifier detection)
    16: "config_change",       # v3.9.16: Sysmon Config Change (rules deleted/modified)
    17: "pipe_created",        # v3.9.16: Named Pipe Created (IPC)
    18: "pipe_connected",      # v3.9.16: Named Pipe Connected (IPC)
    22: "dns_query_event",     # DNS Query
}

# High-value process names for credential dumping detection
CRED_DUMP_TARGETS = {"lsass.exe", "winlogon.exe", "csrss.exe", "services.exe"}

# Suspicious sysmon patterns (detected directly from Sysmon data)
SUSPICIOUS_PARENT_COMBOS = {
    # parent → child → suspicion
    # Original v2.6.0 rules
    ("winword.exe", "powershell.exe"): "Word macro spawning PowerShell",
    ("excel.exe", "powershell.exe"): "Excel macro spawning PowerShell",
    ("outlook.exe", "powershell.exe"): "Outlook spawning PowerShell",
    ("winword.exe", "cmd.exe"): "Word macro spawning cmd",
    ("excel.exe", "cmd.exe"): "Excel macro spawning cmd",
    ("powershell.exe", "wscript.exe"): "PowerShell spawning WScript",
    ("java.exe", "powershell.exe"): "Java spawning PowerShell (Log4Shell?)",
    ("mshta.exe", "powershell.exe"): "MSHTA spawning PowerShell",
    # v2.6.5: Expanded LOLBins coverage
    ("wmiprvse.exe", "powershell.exe"): "WMI spawning PowerShell (lateral movement)",
    ("wmiprvse.exe", "cmd.exe"): "WMI spawning cmd (lateral movement)",
    ("rundll32.exe", "powershell.exe"): "Rundll32 spawning PowerShell (LOLBin)",
    ("rundll32.exe", "cmd.exe"): "Rundll32 spawning cmd (LOLBin)",
    ("regsvr32.exe", "powershell.exe"): "Regsvr32 spawning PowerShell (squiblydoo)",
    ("regsvr32.exe", "cmd.exe"): "Regsvr32 spawning cmd",
    ("msbuild.exe", "powershell.exe"): "MSBuild spawning PowerShell (LOLBin)",
    ("cscript.exe", "powershell.exe"): "Cscript spawning PowerShell",
    ("wscript.exe", "powershell.exe"): "Wscript spawning PowerShell",
    ("certutil.exe", "cmd.exe"): "Certutil spawning cmd (download cradle)",
    ("cmstp.exe", "powershell.exe"): "CMSTP spawning PowerShell (UAC bypass)",
    ("svchost.exe", "cmd.exe"): "Service Host spawning cmd (highly suspicious)",
    ("svchost.exe", "powershell.exe"): "Service Host spawning PowerShell (highly suspicious)",
}


def _run_hidden(cmd, **kwargs):
    kwargs.setdefault("timeout", 10)
    if IS_WINDOWS:
        kwargs.setdefault("creationflags", CREATE_NO_WINDOW)
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)


def check_sysmon_installed():
    """Check if Sysmon is installed and running."""
    try:
        # Check if Sysmon service exists
        r = _run_hidden(["sc", "query", "Sysmon"], timeout=5)
        if r.returncode == 0 and "RUNNING" in r.stdout:
            return True
        # Also check Sysmon64
        r2 = _run_hidden(["sc", "query", "Sysmon64"], timeout=5)
        if r2.returncode == 0 and "RUNNING" in r2.stdout:
            return True
    except Exception:
        pass
    return False


def get_sysmon_install_path():
    """Get Sysmon installation path for configuration reference."""
    paths = [
        r"C:\Windows\Sysmon.exe",
        r"C:\Windows\Sysmon64.exe",
        r"C:\Sysmon\Sysmon.exe",
        r"C:\Sysmon\Sysmon64.exe",
    ]
    for p in paths:
        if os.path.exists(p):
            return p
    return None


class SysmonCollector:
    """Collects and parses Sysmon events from Windows Event Log."""

    def __init__(self, callback=None):
        self.callback = callback  # Called with each GIAM-SAT formatted event
        self.running = False
        self.thread = None
        self.last_timestamp = None  # Track last event timestamp for dedup
        self.event_count = 0
        self.sysmon_available = False
        # v3.8.0: Network event queue for _sysmon_network_dispatch()
        self._network_events = []  # (src_ip, dst_ip, src_port, dst_port, protocol, process_name)
        self._network_lock = threading.Lock()
        # v3.2: Process Tree Builder for LOTL chain analysis
        self.process_tree = ProcessTreeBuilder(callback=callback) if HAS_PROCESS_TREE else None

    def start(self):
        if not IS_WINDOWS:
            print("[*] Sysmon Collector: Skipped (not Windows)")
            return False

        self.sysmon_available = check_sysmon_installed()
        if not self.sysmon_available:
            print("[!] Sysmon Collector: Sysmon NOT installed. Install from:")
            print("    https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon")
            print("    Then: sysmon64 -accepteula -i sysmonconfig.xml")
            return False

        print("[*] Sysmon Collector: Sysmon detected, starting collector...")
        self.running = True
        self.thread = threading.Thread(target=self._collect_loop, daemon=True)
        self.thread.start()
        return True

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=10)

    def _collect_loop(self):
        """Main collection loop using PowerShell to query Sysmon events."""
        if self.last_timestamp is None:
            # Start from 5 minutes ago on first run
            self.last_timestamp = (datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"))

        last_log_time = 0  # For periodic status logging
        while self.running:
            try:
                events = self._query_sysmon_events()
                if events:
                    for event in events:
                        gi_format = self._convert_to_giamsat(event)
                        if gi_format:
                            self.event_count += 1
                            # v3.2: Feed EID 1 events into process tree for LOTL detection
                            if self.process_tree and gi_format.get("sysmon_event_id") == 1:
                                self.process_tree.add_event(gi_format)
                            if self.callback:
                                self.callback(gi_format)
                    if self.event_count > 0 and self.event_count % 50 == 0:
                        print(f"[*] Sysmon Collector: {self.event_count} events collected, last timestamp: {self.last_timestamp}")
                else:
                    # Periodic "still alive" log every 60s
                    now_ts = time.time()
                    if now_ts - last_log_time > 60:
                        print(f"[*] Sysmon Collector: idle (no new events since {self.last_timestamp})")
                        last_log_time = now_ts
            except Exception as e:
                import traceback
                print(f"[-] Sysmon Collector error in _collect_loop: {e}")
                traceback.print_exc()

            time.sleep(POLL_INTERVAL)

    def _query_sysmon_events(self):
        """Query Sysmon events since last timestamp using PowerShell.
        Uses Get-WinEvent with XML filter for efficiency.
        """
        ps_script = f'''
$start = [datetime]::Parse('{self.last_timestamp}')
$end = [datetime]::UtcNow
$filter = @{{
    LogName = '{SYSMON_CHANNEL}'
    StartTime = $start
    EndTime = $end
}}
try {{
    $events = Get-WinEvent -FilterHashtable $filter -MaxEvents 500 -ErrorAction Stop
    $result = @()
    foreach ($evt in $events) {{
        $xml = [xml]$evt.ToXml()
        $eventData = @{{}}
        foreach ($data in $xml.Event.EventData.Data) {{
            $eventData[$data.Name] = $data.'#text'
        }}
        $obj = [PSCustomObject]@{{
            EventID = $evt.Id
            TimeCreated = $evt.TimeCreated.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
            MachineName = $evt.MachineName
            EventData = $eventData
        }}
        $result += $obj
    }}
    ConvertTo-Json -InputObject $result -Depth 5 -Compress
}} catch {{
    "[]"
}}
'''
        try:
            r = _run_hidden(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script], timeout=30)
            if r.returncode == 0 and r.stdout and r.stdout.strip() != "[]":
                events = json.loads(r.stdout)
                if events:
                    # Update timestamp to latest event + 1ms
                    if isinstance(events, dict):
                        events = [events]
                    latest = max(e.get("TimeCreated", self.last_timestamp) for e in events)
                    if latest > self.last_timestamp:
                        # v4.10 (HIGH-15): Get-WinEvent StartTime is inclusive (>=),
                        # so store latest + 1ms to avoid re-reading the same event.
                        try:
                            from datetime import datetime as _dt, timedelta as _td
                            latest_dt = _dt.strptime(latest, "%Y-%m-%dT%H:%M:%S.%fZ") + _td(milliseconds=1)
                            self.last_timestamp = latest_dt.strftime("%Y-%m-%dT%H:%M:%S.") + latest_dt.strftime("%f")[:3] + "Z"
                        except Exception:
                            self.last_timestamp = latest
                return events if isinstance(events, list) else [events]
            elif r.returncode != 0:
                if r.stderr and self.event_count == 0:
                    print(f"[-] Sysmon PowerShell query failed (rc={r.returncode}): {r.stderr[:200]}")
        except json.JSONDecodeError as e:
            if self.event_count == 0:
                print(f"[-] Sysmon JSON decode error: {e} | raw: {r.stdout[:200] if r else 'N/A'}")
        except Exception as e:
            if self.event_count == 0:
                print(f"[-] Sysmon query exception: {e}")
        return []

    def _convert_to_giamsat(self, sysmon_event):
        """Convert a raw Sysmon PowerShell event to GIAM-SAT standard format."""
        try:
            event_id = sysmon_event.get("EventID", 0)
            event_type = EVENT_TYPE_MAP.get(event_id, "sysmon_event")
            event_data = sysmon_event.get("EventData", {})
            time_created = sysmon_event.get("TimeCreated", datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"))
            machine_name = sysmon_event.get("MachineName", "")

            base_event = {
                "type": event_type,
                "source": "sysmon",
                "sysmon_event_id": event_id,
                "timestamp": time_created,
                "hostname": machine_name,
            }

            # ---- Event ID 1: Process Create ----
            if event_id == 1:
                image = event_data.get("Image", "")
                cmdline = event_data.get("CommandLine", "")
                parent_image = event_data.get("ParentImage", "")
                parent_cmdline = event_data.get("ParentCommandLine", "")
                parent_pid = event_data.get("ParentProcessId", "")
                pid = event_data.get("ProcessId", "")
                user = event_data.get("User", "")
                hashes = event_data.get("Hashes", "")
                integrity = event_data.get("IntegrityLevel", "")
                process_guid = event_data.get("ProcessGuid", "")
                parent_guid = event_data.get("ParentProcessGuid", "")

                base_event.update({
                    "process_name": os.path.basename(image) if image else "",
                    "process_path": image,
                    "command_line": cmdline,
                    "pid": pid,
                    "parent_process": os.path.basename(parent_image) if parent_image else "",
                    "parent_path": parent_image,
                    "parent_command_line": parent_cmdline,
                    "parent_pid": parent_pid,
                    "user": user,
                    "hashes": hashes,
                    "integrity_level": integrity,
                    "process_guid": process_guid,
                    "parent_guid": parent_guid,
                })

                # v2.6.0: Detect suspicious parent-child combinations
                parent_name = os.path.basename(parent_image).lower() if parent_image else ""
                proc_name = os.path.basename(image).lower() if image else ""
                combo = (parent_name, proc_name)
                if combo in SUSPICIOUS_PARENT_COMBOS:
                    base_event["suspicious_parent"] = True
                    base_event["suspicion_reason"] = SUSPICIOUS_PARENT_COMBOS[combo]
                    base_event["severity"] = "HIGH"

                    # Check for encoded commands
                    if cmdline and ("-enc" in cmdline.lower() or "-encodedcommand" in cmdline.lower()):
                        base_event["severity"] = "CRITICAL"
                        base_event["suspicion_reason"] += " + encoded command"

                # v2.6.0: Check from Temp/Downloads/AppData
                suspicious_dirs = ["\\temp\\", "\\downloads\\", "\\appdata\\local\\temp\\",
                                  "\\appdata\\roaming\\", "\\programdata\\"]
                if any(d in image.lower() for d in suspicious_dirs):
                    if "suspicious_parent" not in base_event:
                        base_event["suspicious_parent"] = True
                        base_event["suspicion_reason"] = f"Process from suspicious directory: {image}"
                        base_event["severity"] = base_event.get("severity", "MEDIUM")

            # ---- Event ID 3: Network Connect (CÓ PID!) ----
            elif event_id == 3:
                image = event_data.get("Image", "")
                pid = event_data.get("ProcessId", "")
                src_ip = event_data.get("SourceIp", "")
                src_port = event_data.get("SourcePort", "")
                dst_ip = event_data.get("DestinationIp", "")
                dst_port = event_data.get("DestinationPort", "")
                proto = event_data.get("Protocol", "")
                process_guid = event_data.get("ProcessGuid", "")
                user = event_data.get("User", "")

                # v2.6.0: Process-Network Association! ← GIẢI QUYẾT GỢI Ý #6
                base_event.update({
                    "process_name": os.path.basename(image) if image else "",
                    "process_path": image,
                    "pid": pid,
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "protocol": proto,
                    "process_guid": process_guid,
                    "user": user,
                    "direction": "outbound",
                })

            # ---- Event ID 7: Image/DLL Load ----
            elif event_id == 7:
                image = event_data.get("Image", "")
                image_loaded = event_data.get("ImageLoaded", "")
                pid = event_data.get("ProcessId", "")
                hashes = event_data.get("Hashes", "")
                signed = event_data.get("Signed", "")

                base_event.update({
                    "process_name": os.path.basename(image) if image else "",
                    "process_path": image,
                    "pid": pid,
                    "image_loaded": image_loaded,
                    "dll_name": os.path.basename(image_loaded) if image_loaded else "",
                    "dll_path": image_loaded,
                    "hashes": hashes,
                    "signed": signed,
                })

                # Detect unsigned DLLs loaded from suspicious paths
                if signed == "false" and image_loaded:
                    suspicious_dll_dirs = ["\\temp\\", "\\downloads\\", "\\appdata\\"]
                    if any(d in image_loaded.lower() for d in suspicious_dll_dirs):
                        base_event["suspicious_dll"] = True
                        base_event["severity"] = "HIGH"

            # ---- Event ID 8: CreateRemoteThread (Process Injection!) ----
            elif event_id == 8:
                source_image = event_data.get("SourceImage", "")
                target_image = event_data.get("TargetImage", "")
                source_pid = event_data.get("SourceProcessId", "")
                target_pid = event_data.get("TargetProcessId", "")
                start_address = event_data.get("StartAddress", "")
                start_function = event_data.get("StartFunction", "")

                base_event.update({
                    "process_name": os.path.basename(source_image) if source_image else "",
                    "process_path": source_image,
                    "pid": source_pid,
                    "target_process": os.path.basename(target_image) if target_image else "",
                    "target_path": target_image,
                    "target_pid": target_pid,
                    "start_address": start_address,
                    "start_function": start_function,
                    "injection_type": "CreateRemoteThread",
                    "severity": "CRITICAL",
                })

                # Memory injection into sensitive process → immediate CRITICAL
                target_name = os.path.basename(target_image).lower() if target_image else ""
                if target_name in CRED_DUMP_TARGETS:
                    base_event["credential_dumping"] = True
                    base_event["severity"] = "CRITICAL"
                    base_event["description"] = f"Process injection into {target_name} (potential credential dumping)"

            # ---- Event ID 10: Process Access (LSASS dumping!) ----
            elif event_id == 10:
                source_image = event_data.get("SourceImage", "")
                target_image = event_data.get("TargetImage", "")
                granted_access = event_data.get("GrantedAccess", "")
                source_pid = event_data.get("SourceProcessId", "")
                target_pid = event_data.get("TargetProcessId", "")

                target_name = os.path.basename(target_image).lower() if target_image else ""

                base_event.update({
                    "process_name": os.path.basename(source_image) if source_image else "",
                    "process_path": source_image,
                    "pid": source_pid,
                    "target_process": target_name,
                    "target_path": target_image,
                    "target_pid": target_pid,
                    "granted_access": granted_access,
                })

                # LSASS access detection
                if "lsass.exe" in target_name:
                    # Check for dangerous access masks: PROCESS_VM_READ (0x10), PROCESS_QUERY_INFORMATION (0x400)
                    # PROCESS_ALL_ACCESS (0x1FFFFF)
                    try:
                        access_val = int(granted_access, 16) if granted_access.startswith("0x") else int(granted_access)
                        dangerous_masks = {0x10, 0x40, 0x400, 0x1000, 0x1FFFFF, 0x143A}
                        if access_val in dangerous_masks or access_val >= 0x1000:
                            base_event["credential_dumping"] = True
                            base_event["severity"] = "CRITICAL"
                            base_event["description"] = f"LSASS process access by {os.path.basename(source_image) if source_image else 'unknown'} (GrantedAccess: {granted_access})"
                    except (ValueError, TypeError):
                        base_event["severity"] = "HIGH"

            # ---- Event ID 2: Process Terminate (Timestomping detection) ----
            elif event_id == 2:
                image = event_data.get("Image", "")
                pid = event_data.get("ProcessId", "")
                user = event_data.get("User", "")
                process_guid = event_data.get("ProcessGuid", "")
                utc_time = event_data.get("UtcTime", "")

                base_event.update({
                    "process_name": os.path.basename(image) if image else "",
                    "process_path": image,
                    "pid": pid,
                    "user": user,
                    "process_guid": process_guid,
                    "process_action": "terminated",
                })

                # v3.1: Timestomping Detection
                # Sysmon EID 2 provides ProcessId which can be cross-referenced with
                # the process start time from EID 1 to detect CreationUtcTime manipulation.
                # We flag processes that terminated suspiciously quickly after our detection
                # or processes from suspicious paths.
                suspicious_dirs = ["\\temp\\", "\\downloads\\", "\\appdata\\local\\temp\\",
                                  "\\appdata\\roaming\\"]
                if any(d in image.lower() for d in suspicious_dirs):
                    base_event["suspicious_termination"] = True
                    base_event["severity"] = "MEDIUM"

            # ---- Event ID 11: File Create ----
            elif event_id == 11:
                image = event_data.get("Image", "")
                pid = event_data.get("ProcessId", "")
                target_file = event_data.get("TargetFilename", "")
                creation_time = event_data.get("CreationUtcTime", "")

                base_event.update({
                    "process_name": os.path.basename(image) if image else "",
                    "process_path": image,
                    "pid": pid,
                    "file_path": target_file,
                    "file_name": os.path.basename(target_file) if target_file else "",
                    "file_extension": os.path.splitext(target_file)[1] if target_file else "",
                    "creation_time": creation_time,
                })

                # Suspicious file extensions in user-writable directories
                suspicious_exts = {".exe", ".dll", ".ps1", ".vbs", ".bat", ".js", ".hta", ".scr", ".sys"}
                file_ext = os.path.splitext(target_file)[1].lower() if target_file else ""
                if file_ext in suspicious_exts:
                    suspicious_dirs = ["\\temp\\", "\\downloads\\", "\\appdata\\", "\\programdata\\"]
                    if any(d in target_file.lower() for d in suspicious_dirs):
                        base_event["suspicious_file"] = True
                        base_event["severity"] = "MEDIUM"

            # ---- Event ID 12-14: Registry Events ----
            elif event_id in (12, 13, 14):
                image = event_data.get("Image", "")
                pid = event_data.get("ProcessId", "")
                target_obj = event_data.get("TargetObject", "")
                details = event_data.get("Details", "")
                event_type_name = event_data.get("EventType", "")

                base_event.update({
                    "process_name": os.path.basename(image) if image else "",
                    "process_path": image,
                    "pid": pid,
                    "registry_key": target_obj,
                    "registry_value": details,
                    "registry_action": event_type_name,
                })

                # Detect persistence registry keys
                persistence_keys = [
                    "\\run", "\\runonce", "\\runservices", "\\policies\\explorer\\run",
                    "\\winlogon\\shell", "\\winlogon\\userinit",
                    "\\windows\\currentversion\\run",
                    "\\image file execution options",
                    "\\appinit_dlls",
                    "\\session manager\\bootexecute",
                ]
                target_lower = target_obj.lower() if target_obj else ""
                if any(pk in target_lower for pk in persistence_keys):
                    base_event["persistence_detected"] = True
                    base_event["severity"] = "HIGH"
                    base_event["description"] = f"Registry persistence modification: {target_obj}"

            # ---- Event ID 15: FileCreateStreamHash (MOTW/Zone.Identifier) ----
            elif event_id == 15:
                image = event_data.get("Image", "")
                pid = event_data.get("ProcessId", "")
                target_file = event_data.get("TargetFilename", "")
                creation_time = event_data.get("CreationUtcTime", "")
                contents = event_data.get("Contents", "")
                hash_val = event_data.get("Hash", "")

                base_event.update({
                    "process_name": os.path.basename(image) if image else "",
                    "process_path": image,
                    "pid": pid,
                    "file_path": target_file,
                    "file_name": os.path.basename(target_file) if target_file else "",
                    "file_hash": hash_val,
                    "stream_data": contents[:500] if contents else "",
                    "creation_time": creation_time,
                })

                # v3.1: MOTW (Mark of the Web) Evasion Detection
                # Sysmon EID 15 captures Zone.Identifier alternate data streams.
                # Files without MOTW (no ZoneId=3) downloaded from the internet
                # may indicate SmartScreen bypass or macro-enabled attacks.
                file_name = os.path.basename(target_file).lower() if target_file else ""
                has_motw = "ZoneId=3" in contents if contents else False

                if file_name.endswith(":zone.identifier"):
                    # This IS the Zone.Identifier stream itself → check MOTW tampering
                    if not has_motw or "ZoneId=3" not in contents:
                        base_event["motw_evasion"] = True
                        base_event["severity"] = "HIGH"
                        base_event["description"] = (
                            f"MOTW tampering detected: {target_file} has modified/missing ZoneId=3"
                        )
                else:
                    # Regular file — check if from browser zone (downloaded) but lacks MOTW
                    suspicious_dirs = ["\\downloads\\", "\\temp\\", "\\appdata\\local\\temp\\"]
                    if any(d in target_file.lower() for d in suspicious_dirs):
                        exts = {".exe", ".dll", ".ps1", ".vbs", ".bat", ".js", ".hta", ".scr", ".docm", ".xlsm"}
                        if os.path.splitext(file_name)[1] in exts:
                            base_event["motw_check"] = True
                            base_event["severity"] = "MEDIUM"

            # ---- Event ID 22: DNS Query ----
            elif event_id == 22:
                image = event_data.get("Image", "")
                pid = event_data.get("ProcessId", "")
                query_name = event_data.get("QueryName", "")
                query_status = event_data.get("QueryStatus", "")
                query_results = event_data.get("QueryResults", "")

                base_event.update({
                    "process_name": os.path.basename(image) if image else "",
                    "process_path": image,
                    "pid": pid,
                    "dns_query": query_name,
                    "dns_status": query_status,
                    "dns_results": query_results,
                })

            return base_event

        except Exception as e:
            return None

    def get_stats(self):
        """Return collector statistics."""
        return {
            "sysmon_available": self.sysmon_available,
            "events_collected": self.event_count,
            "last_timestamp": self.last_timestamp,
            "active": self.running,
        }