"""
Enhanced Event Collector for GIAM-SAT Agent v1.9.0
Collects 12+ Windows Event Log channels with extended StringInserts parsing.
Supports real-time Event Subscription (EvtSubscribe) with polling fallback.
"""
import json
import os
import time
import threading
import win32evtlog
import win32evtlogutil
from datetime import datetime

try:
    import win32evtlog
    HAS_EVT_SUBSCRIBE = hasattr(win32evtlog, 'EvtSubscribe')
except Exception:
    HAS_EVT_SUBSCRIBE = False

# v4.6.5: 4688 process-creation events for the agent's OWN routine children are
# noise (the agent polls netstat, runs powershell/conhost for scans). Skipped only
# when their parent is the agent itself (attacker-spawned copies keep flowing).
_SELF_NOISE_PROCESSES = {
    "netstat.exe", "powershell.exe", "pwsh.exe", "conhost.exe",
    "wmic.exe", "ping.exe", "nslookup.exe", "schtasks.exe", "cmd.exe",
}

# Expanded log channels (12+) with categories
MONITORED_LOGS = {
    "Security": {"priority": "HIGH", "category": "Security"},
    "System": {"priority": "HIGH", "category": "System"},
    "Application": {"priority": "MEDIUM", "category": "Application"},
    # v1.9.0 - Added deep monitoring channels
    "Microsoft-Windows-PowerShell/Operational": {"priority": "HIGH", "category": "PowerShell"},
    "Microsoft-Windows-TaskScheduler/Operational": {"priority": "HIGH", "category": "TaskScheduler"},
    "Microsoft-Windows-WMI-Activity/Operational": {"priority": "HIGH", "category": "WMI"},
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational": {"priority": "HIGH", "category": "RDP"},
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational": {"priority": "MEDIUM", "category": "RDP"},
    "Microsoft-Windows-Windows Defender/Operational": {"priority": "HIGH", "category": "Defender"},
    "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall": {"priority": "HIGH", "category": "Firewall"},
    "Microsoft-Windows-DNS Client/Operational": {"priority": "MEDIUM", "category": "DNS"},
    "Microsoft-Windows-WindowsUpdateClient/Operational": {"priority": "LOW", "category": "WindowsUpdate"},
    "Microsoft-Windows-SmbClient/Security": {"priority": "MEDIUM", "category": "SMB"},
    # Directory Service (for DCs)
    "Directory Service": {"priority": "HIGH", "category": "DirectoryService", "skip_if_missing": True},
    # Print Service
    "Microsoft-Windows-PrintService/Operational": {"priority": "LOW", "category": "PrintService", "skip_if_missing": True},
    # v4.13 (P2): NTLM authentication (pass-the-hash detection - EID 8004/8005)
    "Microsoft-Windows-NTLM/Operational": {"priority": "HIGH", "category": "NTLM", "skip_if_missing": True},
    # v4.13 (P2): DHCP server + client (MAC<->IP attribution for investigations)
    "Microsoft-Windows-DHCP-Server/Operational": {"priority": "MEDIUM", "category": "DHCP", "skip_if_missing": True},
    "Microsoft-Windows-DHCP-Client/Operational": {"priority": "MEDIUM", "category": "DHCP", "skip_if_missing": True},
}

# Event filtering - event IDs to ALWAYS collect (high value)
ALWAYS_COLLECT_IDS = {
    '4624', '4625', '4648', '4672', '4688', '4697', '4698', '4699',
    '4702', '4719', '4720', '4722', '4723', '4724', '4725', '4726',
    '4728', '4729', '4732', '4733', '4738', '4740', '4756', '4757',
    '4765', '4766', '4767', '4768', '4769', '4771', '4776', '4778',
    '4781', '4793', '4798', '4799', '4825', '4882', '4885', '4886',
    '4887', '4944', '4945', '4946', '4947', '4948', '4950', '4951',
    '4952', '4953', '4954', '4956', '4957', '4958', '4964', '4977',
    '4985', '5024', '5033', '5058', '5059', '5061', '5066', '5069',
    '5136', '5137', '5138', '5139', '5140', '5141', '5142', '5143',
    '5144', '5145', '5152', '5153', '5154', '5155', '5157',
    '5170', '5376', '5377', '5378', '5379', '5447', '5448',
    '5449', '5450', '6144', '6281', '6416', '6423', '6424', '8002',
    '1', '3', '6', '7', '8', '10', '11', '12', '13', '14', '15', '16', '17', '18', '22', '23', '25', '26', '255',  # Sysmon (v4.6.2: +6/10/16/23/25/26/255 so EID-10 LSASS, BYOVD, tampering, file-delete rules have data)
    '1102', '1104', '1105', '1108', '4608', '4616',  # Event log service
    '4103', '4104',  # PowerShell
    '106', '140', '141', '200', '201', '202', '1000', '1001',  # TaskScheduler
    '5857', '5858', '5859', '5860', '5861',  # WMI
    '21', '22', '23', '24', '25', '39', '40',  # RDP
    '1006', '1007', '1008', '1009', '1015', '1116', '1117', '1118', '1119', '5001', '5007',  # Defender
    '8004', '8005',  # v4.13 (P2): NTLM authentication (pass-the-hash)
    '1006', '1007', '1008', '1009',  # v4.13 (P2): DHCP server (address granted/renewed/denied)
    '1100', '1103', '1104', '1105', '1108',  # v4.13 (P2): DHCP client events
    '2003', '2004', '2005', '2006', '2009', '2033',  # Firewall
    '3008', '3020',  # DNS
    '1000', '1001', '1002', '5140', '5145',  # SMB
}

# Event IDs to always skip (noise reduction)
# v4.13 (P0.3): '4663' removed - required by THREAT-009/011/051 (LSASS/SAM object
# access). Volume is acceptable on HIGH-priority channels; re-tune with a selective
# SACL later if needed.
SKIP_IDS = {
    '4656', '4658', '4660',  # File system object access (noisy variants)
    '4689',  # Process termination
    '5156', '5158',  # WFP permitted (extremely noisy)
    '5376', '5377',  # Logon cache (noisy)
    '5447', '5448', '5449', '5450', '5451', '5452', '5453', '5454', '5455', '5456',  # WFP frequent noise
}

# Extended StringInserts parsing for critical Event IDs
EVENT_STRINGINSERTS_MAP = {
    # Format: event_id: {field_name: insert_index}
    '4688': {  # Process Creation
        # v4.6.5 FIX: 4688 has exactly 9 inserts (0..8):
        # [0]SubjectSid [1]SubjectUser [2]SubjectDomain [3]SubjectLogonId
        # [4]NewProcessId [5]NewProcessName [6]TokenElevationType
        # [7]CreatorProcessId(parent PID) [8]CommandLine
        # Old map had command_line:9 (out of range -> never populated) and
        # parent_pid:8 (actually the command line).
        # v5.0.4 (HIGH-3): process_path = the FULL NewProcessName (insert 5) so
        # the ~410 Sigma Image/process_path rules match 4688 events too (Sysmon 1
        # already emits process_path; the Security path previously only had the
        # basename under process_name).
        'process_name': 5,
        'process_path': 5,
        'command_line': 8,
        'parent_pid': 7,
        'token_elevation': 6,
        'target_username': 1,
        'target_domain': 2,
    },
    '4624': {  # Successful Logon
        'target_username': 5,
        'target_domain': 6,
        'logon_id': 7,
        'logon_type': 8,
        'source_ip': 18,
        'source_hostname': 11,
        'auth_package': 10,
    },
    '4625': {  # Failed Logon
        'target_username': 5,
        'target_domain': 6,
        'logon_type': 10,
        'source_ip': 19,
        'failure_reason': 8,
        'status_code': 7,
    },
    '4728': {  # User added to global group
        'target_username': 0,
        'target_domain': 4,
        'group_name': 2,
        'group_domain': 5,
        'admin_username': 6,
    },
    '4732': {  # User added to local group
        'target_username': 0,
        'group_name': 2,
        'admin_username': 6,
    },
    '4768': {  # Kerberos TGT
        'target_username': 0,
        'target_domain': 1,
        'source_ip': 9,
    },
    '4769': {  # Kerberos TGS
        'target_username': 0,
        'target_domain': 1,
        'service_name': 2,
        'source_ip': 6,
        'ticket_encryption': 4,
    },
    '4776': {  # NTLM Authentication
        'source_hostname': 1,
        'target_username': 0,
    },
    '7045': {  # Service Installed
        'service_name': 0,
        'service_file': 1,
    },
    '4697': {  # Service Installed (Security)
        'service_name': 1,
        'service_file': 2,
    },
    '4698': {  # Scheduled Task Created
        'task_name': 1,
        'task_content': 2,
        'user_context': 0,
    },
    '5140': {  # File Share Accessed
        'share_name': 0,
        'share_path': 1,
        'source_ip': 2,
        'target_username': 3,
    },
    '5145': {  # File Share Object Accessed
        'share_name': 0,
        'object_name': 1,
        'access_type': 3,
        'source_ip': 2,
        'target_username': 4,
    },
    '4663': {  # Object Access
        'object_name': 6,
        'process_name': 1,
        'access_type': 5,
    },
    '4702': {  # Scheduled Task Updated
        'task_name': 1,
        'user_context': 0,
    },
    '1102': {  # v4.13 (P1.3): Audit log cleared
        'subject_username': 1,
        'subject_domain': 2,
        'channel': 4,
    },
    '4720': {  # v4.13 (P1.3): User account created
        'target_username': 0,
        'target_domain': 1,
        'admin_username': 6,
    },
    '4722': {  # v4.13 (P1.3): User account enabled
        'target_username': 0,
        'target_domain': 1,
        'admin_username': 6,
    },
    '4723': {  # v4.13 (P1.3): Password change attempted
        'target_username': 0,
        'target_domain': 1,
        'admin_username': 6,
    },
    '4724': {  # v4.13 (P1.3): Password reset attempted
        'target_username': 0,
        'target_domain': 1,
        'admin_username': 6,
    },
    '4725': {  # v4.13 (P1.3): User account disabled
        'target_username': 0,
        'target_domain': 1,
        'admin_username': 6,
    },
    '4726': {  # v4.13 (P1.3): User account deleted
        'target_username': 0,
        'target_domain': 1,
        'admin_username': 6,
    },
    '4740': {  # v4.13 (P1.3): Account locked out
        'target_username': 0,
        'target_domain': 1,
    },
    '4771': {  # v4.13 (P1.3): Kerberos pre-auth failure
        'target_username': 0,
        'target_domain': 1,
        'source_ip': 6,
        'failure_code': 7,
    },
    '5136': {  # v4.13 (P1.3): GPO modified
        'subject_user': 1,
        'subject_domain': 2,
        'object_dn': 3,
        'attribute': 4,
    },
    # Sysmon Event IDs (parsed from StringInserts)
    '1': {  # Process Creation
        'process_name': 4,
        'command_line': 10,
        'parent_pid': 17,
        'parent_process': 20,
        'hashes': 11,
        'process_guid': 5,
        'user': 12,
    },
    '3': {  # Network Connection
        'process_name': 4,
        'process_id': 3,
        'source_ip': 15,
        'dest_ip': 18,
        'source_port': 14,
        'dest_port': 17,
        'protocol': 13,
    },
    '7': {  # Image Loaded
        'process_name': 4,
        'image_loaded': 7,
        'hashes': 9,
        'signed': 10,
        'signature': 11,
    },
    '8': {  # CreateRemoteThread
        'source_process': 4,
        'target_process': 8,
        'source_pid': 3,
        'target_pid': 7,
    },
}


class EnhancedEventCollector(threading.Thread):
    def __init__(self, callback, collect_sysmon=True, agent_pid=None, skip_processes=()):
        super().__init__(daemon=True)
        self.callback = callback
        self.running = True
        self.last_event_ids = {}
        self.log_configs = {}
        self._active_logs = []
        self._use_realtime = False
        # v4.6.5: reduce self-inflicted 4688 volume - drop the agent's OWN routine
        # child processes (netstat poll, powershell/conhost from scans) and any
        # configured process (e.g. postgres.exe when the server runs on SQLite).
        self.agent_pid = str(agent_pid) if agent_pid else ""
        self.skip_processes = set(skip_processes or ())
        # v4.6.4: the dedicated SysmonCollector reads the same channel with RICHER
        # fields - don't read it here too (double-send); agent_core passes False.
        self.collect_sysmon = collect_sysmon
        # v5.0.4 (HIGH-3): YAML decoder enriches events the StringInserts parser
        # does not cover (4104 ScriptBlock, 7045, non-insert channels).
        self.decoder = None
        try:
            from event_decoder import EventDecoder
            self.decoder = EventDecoder()
        except Exception:
            self.decoder = None
        self._init_logs()

    def _init_logs(self):
        """Initialize monitored log channels."""
        for log_name, config in MONITORED_LOGS.items():
            skip_missing = config.get("skip_if_missing", False)
            try:
                hand = win32evtlog.OpenEventLog(None, log_name)
                win32evtlog.CloseEventLog(hand)
                self._active_logs.append(log_name)
                self.log_configs[log_name] = config
            except Exception:
                if not skip_missing:
                    pass  # Log will be silently skipped

        # Try Sysmon (v4.6.4: skipped when SysmonCollector is running - avoids
        # double-sending every sysmon event; see __init__ comment)
        if self.collect_sysmon:
            try:
                hand = win32evtlog.OpenEventLog(None, "Microsoft-Windows-Sysmon/Operational")
                win32evtlog.CloseEventLog(hand)
                self._active_logs.append("Microsoft-Windows-Sysmon/Operational")
                self.log_configs["Microsoft-Windows-Sysmon/Operational"] = {"priority": "HIGH", "category": "Sysmon"}
            except Exception:
                pass

        print(f"[*] Event Collector: {len(self._active_logs)} channels active")
        for log in self._active_logs:
            cfg = self.log_configs.get(log, {})
            print(f"    - {log} [{cfg.get('category', '?')}]")

    def _should_collect_event(self, event_id, log_name, event_type):
        """Filter events: collect high-value events, skip noise."""
        eid = str(event_id)

        # Always collect critical security events
        if eid in ALWAYS_COLLECT_IDS:
            return True

        # Skip known noisy event IDs
        if eid in SKIP_IDS:
            return False

        # For high-priority logs, collect all
        cfg = self.log_configs.get(log_name, {})
        if cfg.get("priority") == "HIGH":
            return True

        # For medium/low priority, only collect audit failures and warnings
        if event_type in ("AUDIT_FAILURE", "ERROR", "WARNING"):
            return True

        return False

    def _parse_string_inserts(self, event_id, string_inserts):
        """Extended parsing of StringInserts for critical Event IDs."""
        parsed = {}
        mapping = EVENT_STRINGINSERTS_MAP.get(str(event_id))
        if mapping and string_inserts:
            for field_name, insert_idx in mapping.items():
                if insert_idx < len(string_inserts):
                    val = str(string_inserts[insert_idx])
                    if val.strip():
                        parsed[field_name] = val.strip()

        # Special handling for Logon Type mapping
        logon_type_map = {
            '2': 'Interactive', '3': 'Network', '4': 'Batch',
            '5': 'Service', '7': 'Unlock', '8': 'NetworkCleartext',
            '9': 'NewCredentials', '10': 'RemoteInteractive', '11': 'CachedInteractive'
        }
        lt = parsed.get('logon_type')
        if lt and lt in logon_type_map:
            parsed['logon_type_desc'] = logon_type_map[lt]

        return parsed

    def _get_new_events(self, log_name):
        """Retrieve new events from a specific Windows Event Log."""
        events = []
        try:
            hand = win32evtlog.OpenEventLog(None, log_name)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

            # v4.10 (HIGH-16): ReadEventLog returns at most ~1024 records per call.
            # Drain in a loop until empty so high-volume logs (Security on DCs/busy
            # hosts) never silently lose events between polls.
            event_records = []
            for _chunk_i in range(200):
                chunk = win32evtlog.ReadEventLog(hand, flags, 0)
                if not chunk:
                    break
                event_records.extend(list(chunk))
                if len(chunk) < 1024:
                    break
            last_seen = self.last_event_ids.get(log_name, 0)
            new_max_id = last_seen

            # v4.13 (P0.1): detect event-log clear / record-number reset.
            # After 'wevtutil cl Security', Windows restarts record numbering at 1,
            # so every new event (incl. 1102 'audit log cleared') has a record number
            # <= the old watermark and gets skipped forever -> the host goes blind.
            if last_seen > 0 and event_records:
                _min_rec = None
                for _ev in event_records:
                    try:
                        _rn = int(_ev.RecordNumber)
                    except (AttributeError, TypeError, ValueError):
                        continue
                    if _min_rec is None or _rn < _min_rec:
                        _min_rec = _rn
                if _min_rec is not None and _min_rec <= last_seen and (last_seen - _min_rec) > 50:
                    print(f"[!] LOG RESET DETECTED on '{log_name}': record number dropped from {last_seen} to {_min_rec}")
                    events.append({
                        "type": "windows_event",
                        "subtype": log_name,
                        "event_category": "EventLog",
                        "event_id": "LOG_RESET",
                        "event_type": "ALERT",
                        "source": "EventCollector",
                        "computer": os.environ.get("COMPUTERNAME", ""),
                        "user": "N/A",
                        "category": "Tampering",
                        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "description": f"Event log '{log_name}' was CLEARED or reset (record number dropped from {last_seen} to {_min_rec}). Possible log tampering - historical events lost.",
                        "raw_data": "",
                        "severity": "HIGH",
                    })
                    # Reset the watermark so the restarted log (incl. 1102) IS collected
                    last_seen = _min_rec - 1
                    new_max_id = last_seen
                    self.last_event_ids[log_name] = last_seen

            for event in event_records:
                try:
                    record_number = event.RecordNumber
                except AttributeError:
                    continue

                if record_number <= last_seen:
                    continue
                if record_number > new_max_id:
                    new_max_id = record_number

                time_gen = event.TimeGenerated.Format() if hasattr(event.TimeGenerated, 'Format') else str(event.TimeGenerated)

                event_type_map = {
                    win32evtlog.EVENTLOG_SUCCESS: "SUCCESS",
                    win32evtlog.EVENTLOG_ERROR_TYPE: "ERROR",
                    win32evtlog.EVENTLOG_WARNING_TYPE: "WARNING",
                    win32evtlog.EVENTLOG_INFORMATION_TYPE: "INFO",
                    win32evtlog.EVENTLOG_AUDIT_SUCCESS: "AUDIT_SUCCESS",
                    win32evtlog.EVENTLOG_AUDIT_FAILURE: "AUDIT_FAILURE",
                }
                event_type = event_type_map.get(event.EventType, "UNKNOWN")
                event_id = str(getattr(event, 'EventID', ''))

                # Noise filtering
                if not self._should_collect_event(event_id, log_name, event_type):
                    continue

                # StringInserts
                string_inserts = []
                try:
                    if hasattr(event, 'StringInserts') and event.StringInserts:
                        string_inserts = list(event.StringInserts)
                except Exception:
                    pass

                # Parse StringInserts for structured fields
                parsed_fields = self._parse_string_inserts(event_id, string_inserts)

                category = self.log_configs.get(log_name, {}).get("category", log_name)

                event_data = {
                    "type": "windows_event",
                    "subtype": log_name,
                    "event_category": category,
                    "event_id": event_id,
                    "event_type": event_type,
                    "source": str(getattr(event, 'SourceName', '')),
                    "computer": str(getattr(event, 'ComputerName', '')),
                    "user": str(getattr(event, 'UserName', 'N/A')) if getattr(event, 'UserName', None) else "N/A",
                    "category": str(getattr(event, 'EventCategory', '')),
                    "time": str(time_gen),
                    "description": "",
                    "raw_data": "",
                }

                # Merge parsed fields
                event_data.update(parsed_fields)

                # Description from template
                try:
                    desc = win32evtlogutil.EventMessage(event.SourceName, event.EventID)
                    event_data["description"] = str(desc) if desc else ""
                except Exception:
                    try:
                        desc = win32evtlogutil.FormatMessage(event.SourceName, event.EventID, None)
                        event_data["description"] = str(desc) if desc else f"Event ID {event_id} from {event.SourceName}"
                    except Exception:
                        event_data["description"] = f"Event ID {event_id} from {event.SourceName}"

                # Raw data from StringInserts
                if string_inserts:
                    event_data["raw_data"] = " | ".join(str(s) for s in string_inserts)

                # v5.0.4 (HIGH-3): enrich events the StringInserts parser missed -
                # the YAML decoder regex-parses the description and fills
                # parsed_fields (scriptblock_text, registry_key, service fields...)
                # which the correlation matcher reads directly.
                try:
                    if not parsed_fields and self.decoder is not None and event_data.get("description"):
                        _ann = self.decoder.decode_and_annotate(event_data)
                        _pf = _ann.get("parsed_fields") or {}
                        if _pf:
                            parsed_fields = _pf
                            event_data.update(_pf)
                except Exception:
                    pass
                # v5.0.4 (HIGH-3): 4104 ScriptBlock - the script text lives in the
                # message; expose it as scriptblock_text so the 226 Sigma
                # ScriptBlock rules can match (they previously had no field).
                if event_id == "4104" and not event_data.get("scriptblock_text"):
                    event_data["scriptblock_text"] = event_data.get("description", "")

                # v4.6.5: drop the agent's own process-creation noise (its routine
                # netstat/powershell/conhost children) + configured processes.
                if event_id == "4688":
                    ppid = str(event_data.get("parent_pid", ""))
                    pname = str(event_data.get("process_name", "")).lower()
                    pbase = os.path.basename(pname).lower() if pname else ""
                    if self.agent_pid and ppid == self.agent_pid and pbase in _SELF_NOISE_PROCESSES:
                        continue
                    if pbase and pbase in self.skip_processes:
                        continue

                events.append(event_data)

            if new_max_id > last_seen:
                self.last_event_ids[log_name] = new_max_id

            win32evtlog.CloseEventLog(hand)

        except Exception:
            pass

        return events

    def run(self):
        """Main event collection loop - polling mode (real-time via EvtSubscribe in future)."""
        use_realtime = HAS_EVT_SUBSCRIBE and False  # Disabled by default, experimental
        if use_realtime:
            self._run_realtime_mode()
        else:
            self._run_polling_mode()

    def _run_polling_mode(self):
        while self.running:
            try:
                for log_name in self._active_logs[:]:  # Iterate copy to allow changes
                    new_events = self._get_new_events(log_name)
                    for event in new_events:
                        try:
                            self.callback(event)
                        except Exception:
                            pass
                time.sleep(3)
            except Exception:
                time.sleep(5)

    def _run_realtime_mode(self):
        """Experimental: real-time event subscription (Windows Event Log Forwarding)."""
        print("[*] Event Collector: Using real-time EvtSubscribe mode")
        try:
            import win32evtlog
            all_channels = [
                "Security", "System", "Application",
                "Microsoft-Windows-PowerShell/Operational",
                "Microsoft-Windows-Sysmon/Operational",
            ]
            channel_query = " OR ".join(f"Channel='{ch}'" for ch in all_channels)
            query = f"*[System[({channel_query})]]"

            subscription = win32evtlog.EvtSubscribe(
                None,  # All channels
                None,  # EventSignal - None = blocking
                Query=query,
                Flags=win32evtlog.EvtSubscribeToFutureEvents
            )
            while self.running:
                events = win32evtlog.EvtNext(subscription, 10, 1000, 0)
                for evt in events:
                    try:
                        event_data = self._parse_evt_event(evt)
                        if event_data:
                            self.callback(event_data)
                    except Exception:
                        pass
        except Exception as e:
            print(f"[!] Real-time mode failed: {e}, falling back to polling")
            self._run_polling_mode()

    def _parse_evt_event(self, evt):
        """Parse an EvtSubscribe event (placeholder for future real-time mode)."""
        # This requires win32evtlog.EvtRender which is available in recent pywin32
        return None  # Placeholder

    def stop(self):
        self.running = False

    def add_channel(self, channel_name, priority="MEDIUM", category="Custom"):
        """Dynamically add a new event log channel."""
        if channel_name in self._active_logs:
            return
        try:
            hand = win32evtlog.OpenEventLog(None, channel_name)
            win32evtlog.CloseEventLog(hand)
            self._active_logs.append(channel_name)
            self.log_configs[channel_name] = {"priority": priority, "category": category}
            print(f"[*] Event Collector: Added channel '{channel_name}'")
        except Exception as e:
            print(f"[-] Event Collector: Cannot add channel '{channel_name}': {e}")