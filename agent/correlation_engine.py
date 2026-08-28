"""
Correlation Engine for GIAM-SAT Agent v1.15.0
Detects threat patterns by correlating multiple events within time windows.

v1.15.0: PPID Spoofing Detection
  - _verify_parent_integrity(): check parent PID still alive + name matches
  - Digital Signature check on parent process (via PowerShell)
  - Process CreationTime sanity check (parent must exist BEFORE child)
  - Adds spoof_penalty to confidence score when anomaly detected

v1.14.0: False-positive reduction overhaul
  - Increased thresholds for common noisy rules
  - Process parent whitelist (OneDrive, Teams, SharePoint, Defender updates)
  - Domain whitelist (*.office.com, *.azure.com, *.windowsupdate.com)
  - Confidence scoring: each alert gets score 0-100, <50 → informational only
  - Alert cooldown extended: 1h → 6h for same rule on same machine
  - LOTL detection: only alert if LOTL process + network to new IP
"""

import json
import os
import re
import time
import subprocess
from collections import defaultdict, deque

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

IS_WINDOWS = os.name == "nt"
CREATE_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0

# v3.9.16: Process Tree Builder for injection chain detection
try:
    from process_tree import ProcessTreeBuilder
    HAS_PROCESS_TREE_FOR_CORR = True
except ImportError:
    HAS_PROCESS_TREE_FOR_CORR = False

RULES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules", "correlation_rules.yaml")

# v4.13 (P1.3): SIGMA field-name aliases (PascalCase -> agent snake_case) so the
# ~1000 SIGMA field_contains rules can actually resolve data. See field_aliases.yaml.
FIELD_ALIASES = {}
if HAS_YAML:
    try:
        _aliases_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "field_aliases.yaml")
        if os.path.exists(_aliases_path):
            with open(_aliases_path, "r", encoding="utf-8") as _f:
                _alias_data = yaml.safe_load(_f) or {}
            FIELD_ALIASES = _alias_data.get("aliases", {}) or {}
    except Exception:
        FIELD_ALIASES = {}

# v5.0.4 (HIGH-3): the sigma_parser emits LOWERCASE field keys (imagepath,
# integritylevel, parentcommandline, targetfilename...) but field_aliases.yaml
# uses PascalCase keys - a lowercase condition key never resolved, leaving
# hundreds of field_contains rules dead. Build a lowercase lookup too.
FIELD_ALIASES_LOWER = {str(k).lower(): v for k, v in FIELD_ALIASES.items()}

PROCESS_PARENT_WHITELIST = {
    "powershell.exe": {"explorer.exe", "svchost.exe", "services.exe", "msmpeng.exe", "sppsvc.exe",
                        "taskeng.exe", "ommsync.exe", "onedrive.exe", "teams.exe", "outlook.exe",
                        "winword.exe", "excel.exe", "powerpnt.exe", "msaccess.exe"},
    "cmd.exe": {"explorer.exe", "svchost.exe", "services.exe", "winlogon.exe", "taskeng.exe",
                "msmpeng.exe", "trustedinstaller.exe", "sppsvc.exe"},
    "wscript.exe": {"explorer.exe", "taskeng.exe"},
    "cscript.exe": {"explorer.exe", "taskeng.exe"},
    "mshta.exe": set(),
    "rundll32.exe": {"explorer.exe", "svchost.exe", "services.exe", "msmpeng.exe"},
    "regsvr32.exe": {"explorer.exe", "msiexec.exe"},
    "certutil.exe": {"explorer.exe", "svchost.exe"},
    "bitsadmin.exe": {"explorer.exe", "svchost.exe"},
}

NETWORK_DOMAIN_WHITELIST = {
    "office.com", "office.net", "office365.com", "microsoft.com", "microsoftonline.com",
    "azure.com", "azure.net", "azureedge.net", "windowsupdate.com", "windows.com",
    "msecnd.net", "visualstudio.com", "sharepoint.com", "onedrive.com", "live.com",
    "skype.com", "msn.com", "bing.com", "xboxlive.com", "msftncsi.com",
}

_CORE_RULES_FALLBACK = [
    {"id": "THREAT-001", "name": "Brute Force Attack Detected",
     "description": "Multiple failed login attempts (Event ID 4625) from same source within 120 seconds",
     "severity": "HIGH",
     "conditions": [{"type": "windows_event", "event_id": "4625", "threshold": 20, "within_seconds": 120, "group_by": "source_ip"}],
     "confidence_score": 75},
    {"id": "THREAT-002", "name": "Ransomware Behavior - Mass File Modification",
     "description": "500+ file modifications detected within 120 seconds",
     "severity": "CRITICAL",
     "conditions": [{"type": "fim", "action": "FILE_MODIFIED", "threshold": 500, "within_seconds": 120}],
     "confidence_score": 85},
    {"id": "THREAT-003", "name": "Suspicious Service Creation",
     "description": "New Windows service created (Event ID 7045 or 4697) from non-system process",
     "severity": "HIGH",
     "conditions": [{"type": "windows_event", "event_id": ["7045", "4697"], "threshold": 1, "within_seconds": 3600}],
     "confidence_score": 65},
    {"id": "THREAT-005", "name": "Windows Defender Disabled",
     "description": "Windows Defender or Firewall was disabled (Event ID 5001)",
     "severity": "CRITICAL",
     "conditions": [{"type": "windows_event", "event_id": ["5001"], "threshold": 1, "within_seconds": 60}],
     "confidence_score": 90},
    {"id": "THREAT-006", "name": "C2 Communication Detected",
     "description": "Outbound connection to known C2 ports to non-whitelisted destination",
     "severity": "CRITICAL",
     "conditions": [{"type": "network_traffic", "dst_port": [4444, 1337, 31337, 8080, 8000], "threshold": 3, "within_seconds": 300}],
     "confidence_score": 70},
    {"id": "THREAT-009", "name": "Credential Dumping - LSASS Access",
     "description": "Process accessed LSASS memory (Event 4663 + potential mimikatz behavior)",
     "severity": "CRITICAL",
     "conditions": [{"type": "windows_event", "event_id": "4663", "description_contains": ["lsass.exe"], "threshold": 1, "within_seconds": 60}],
     "confidence_score": 95},
    {"id": "THREAT-017", "name": "PowerShell Download Cradle",
     "description": "PowerShell invoked with WebClient/Net.WebRequest (suspicious download) from non-whitelisted parent",
     "severity": "CRITICAL",
     "conditions": [{"type": "windows_event", "event_id": "4104", "description_contains": ["WebClient", "Net.WebRequest", "DownloadFile", "DownloadString", "Invoke-WebRequest", "Invoke-RestMethod"], "threshold": 1, "within_seconds": 60}],
     "confidence_score": 80},

    # ==== v3.9.16: ETW/Sysmon Tampering Detection ====
    {"id": "THREAT-EVASION-001", "name": "Sysmon Service Stopped (Tampering)",
     "description": "Sysmon service state changed to stopped (EID 4) — attacker may be disabling monitoring",
     "severity": "CRITICAL",
     "conditions": [{"type": "service_state_change", "description_contains": ["stopped", "Stop"], "threshold": 1, "within_seconds": 300}],
     "confidence_score": 95},
    {"id": "THREAT-EVASION-002", "name": "Sysmon Config Modified (Tampering)",
     "description": "Sysmon configuration changed (EID 16) — rules may have been deleted or modified",
     "severity": "CRITICAL",
     "conditions": [{"type": "config_change", "threshold": 1, "within_seconds": 300}],
     "confidence_score": 90},

    # ==== v3.9.16: Ransomware-Specific Detection ====
    {"id": "RANSOM-001", "name": "Shadow Copy Deletion (VSSADMIN)",
     "description": "vssadmin delete shadows detected — classic ransomware behavior to prevent recovery",
     "severity": "CRITICAL",
     "conditions": [{"type": "windows_event", "event_id": "4688", "description_contains": ["vssadmin", "delete", "shadows", "/quiet"], "threshold": 1, "within_seconds": 60}],
     "confidence_score": 98},
    {"id": "RANSOM-002", "name": "Shadow Copy Deletion (WMIC)",
     "description": "WMIC shadowcopy delete detected — alternative ransomware shadow copy deletion method",
     "severity": "CRITICAL",
     "conditions": [{"type": "windows_event", "event_id": "4688", "description_contains": ["wmic", "shadowcopy", "delete"], "threshold": 1, "within_seconds": 60}],
     "confidence_score": 98},
    {"id": "RANSOM-003", "name": "Boot Configuration Tampering (BCDEDIT)",
     "description": "bcdedit used to modify boot configuration — ransomware may disable recovery or safe mode",
     "severity": "CRITICAL",
     "conditions": [{"type": "windows_event", "event_id": "4688", "description_contains": ["bcdedit", "/set", "recoveryenabled", "bootstatuspolicy"], "threshold": 1, "within_seconds": 60}],
     "confidence_score": 95},
    {"id": "RANSOM-004", "name": "Ransomware Note Files Created",
     "description": "Multiple .hta or ransomware-named text files created in user directories within 60 seconds",
     "severity": "CRITICAL",
     "conditions": [{"type": "fim", "action": "FILE_CREATED", "description_contains": [".hta", "README", "DECRYPT", "RESTORE", "HOW_TO", "RECOVER", "ransom"], "threshold": 5, "within_seconds": 60}],
     "confidence_score": 90},
    {"id": "RANSOM-005", "name": "Multiple Services Stopped Rapidly",
     "description": "5+ Windows services stopped within 60 seconds (ransomware disables AV/backup services before encryption)",
     "severity": "HIGH",
     "conditions": [{"type": "windows_event", "event_id": "7036", "description_contains": ["stopped"], "threshold": 5, "within_seconds": 60}],
     "confidence_score": 75},

    # ==== v3.9.16: Kerberos Attack Detection ====
    {"id": "KERB-001", "name": "Golden Ticket Attack - RC4 TGS",
     "description": "TGS request for krbtgt service with RC4 encryption (0x17) — signature of Golden Ticket attack",
     "severity": "CRITICAL",
     "conditions": [{"type": "windows_event", "event_id": "4769", "description_contains": ["0x17", "krbtgt"], "threshold": 1, "within_seconds": 60}],
     "confidence_score": 95},
    {"id": "KERB-002", "name": "Kerberos Pre-Authentication Attack",
     "description": "Multiple Kerberos pre-auth failures (Event 4771) from multiple source IPs — brute force or AS-REP roasting",
     "severity": "HIGH",
     "conditions": [{"type": "windows_event", "event_id": "4771", "threshold": 10, "within_seconds": 300, "count_distinct": "source_ip"}],
     "confidence_score": 80},
    {"id": "KERB-003", "name": "Suspicious TGT Lifetime",
     "description": "Multiple TGT requests (Event 4768) with abnormal frequency — potential DCSync or ticket harvesting",
     "severity": "HIGH",
     "conditions": [{"type": "windows_event", "event_id": "4768", "threshold": 20, "within_seconds": 60}],
     "confidence_score": 70},

    # ==== v3.9.16: DNS/ICMP Exfiltration ====
    {"id": "EXFIL-001", "name": "DNS Tunneling Detected",
     "description": "Suspiciously long DNS queries (>52 chars) repeated frequently — possible DNS tunneling for data exfiltration",
     "severity": "CRITICAL",
     "conditions": [{"type": "network_traffic", "description_contains": ["dns_tunnel", "entropy_high"], "threshold": 10, "within_seconds": 300}],
     "confidence_score": 85},
    {"id": "EXFIL-002", "name": "ICMP Large Payload Exfiltration",
     "description": "ICMP packets with unusually large payload (>200 bytes) to external IPs — classic ICMP tunneling",
     "severity": "HIGH",
     "conditions": [{"type": "network_traffic", "description_contains": ["icmp_exfil", "large_payload"], "threshold": 5, "within_seconds": 60}],
     "confidence_score": 80},
    {"id": "EXFIL-003", "name": "Unusual Outbound Data Spike",
     "description": "Outbound data spike > 10MB to a new external IP in 5 minutes — potential data exfiltration",
     "severity": "MEDIUM",
     "conditions": [{"type": "network_traffic", "description_contains": ["exfil_spike", "new_destination"], "threshold": 3, "within_seconds": 300}],
     "confidence_score": 60},

    # ==== v3.9.16: Cross-Process Injection Chain ====
    {"id": "INJ-001", "name": "System-to-User Process Chain Injection",
     "description": "System-level process spawned untrusted child from user directory that then spawned LOLBin — injection chain detected",
     "severity": "CRITICAL",
     "conditions": [{"type": "sysmon_event", "description_contains": ["injection_chain", "system_to_user", "lolbin"], "threshold": 1, "within_seconds": 120}],
     "confidence_score": 90},
    {"id": "INJ-002", "name": "Deep Process Tree Anomaly (Depth > 4)",
     "description": "Process tree depth exceeds 4 with digital signature mismatch at level > 2 — possible nested injection",
     "severity": "HIGH",
     "conditions": [{"type": "sysmon_event", "description_contains": ["deep_chain", "sig_mismatch"], "threshold": 1, "within_seconds": 300}],
     "confidence_score": 75},
]


def load_correlation_rules():
    if not os.path.exists(RULES_PATH):
        return _CORE_RULES_FALLBACK
    if not HAS_YAML:
        return _CORE_RULES_FALLBACK
    try:
        with open(RULES_PATH, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            if data and "rules" in data:
                return data["rules"]
    except Exception:
        pass
    return _CORE_RULES_FALLBACK

CORRELATION_RULES = load_correlation_rules()


class CorrelationEngine:
    def __init__(self, alert_callback=None):
        self.alert_callback = alert_callback
        self.event_buffers = defaultdict(lambda: deque())
        self.sequence_states = defaultdict(list)
        self.fired_alerts = {}
        # v4.11 (P2): NOT/filter conditions set an exclusion timestamp per rule
        self.rule_exclusions = {}
        self.alert_cooldown = 21600
        self.machine_id = ""
        # v3.9.16: Process Tree for injection chain detection
        self.process_tree = ProcessTreeBuilder() if HAS_PROCESS_TREE_FOR_CORR else None

    def process_event(self, event_data):
        triggered = []
        now = time.time()
        self._clean_sequence_states(now)

        # v3.9.16: Feed Sysmon EID 1 events into Process Tree for injection chain detection
        if self.process_tree and event_data.get("type") in ("process_event", "sysmon_event"):
            is_sysmon = event_data.get("source") == "sysmon" and event_data.get("sysmon_event_id") == 1
            is_process_create = event_data.get("type") == "process_event" and event_data.get("event_id") in ("4688", "1")
            if is_sysmon or is_process_create:
                try:
                    chain_alert = self.process_tree.add_event(event_data)
                    if chain_alert:
                        # Tag the event so rules INJ-001/INJ-002 can match
                        event_data["description"] = event_data.get("description", "") + " " + chain_alert
                except Exception:
                    pass

        for rule in CORRELATION_RULES:
            if rule.get("rule_type") == "sequence" or "sequence" in rule:
                alert = self._check_sequence_rule(rule, event_data, now)
            else:
                alert = self._check_rule(rule, event_data, now)
            if alert:
                triggered.append(alert)
        return triggered

    def _check_rule(self, rule, event_data, now):
        conditions = rule.get("conditions", [])
        if not conditions:
            return None
        logic = rule.get("logic", "AND").upper()
        if isinstance(conditions, dict):
            logic = conditions.get("logic", "AND").upper()
            conditions = conditions.get("conditions", [])
        for i, cond in enumerate(conditions):
            self._buffer_matching_condition(rule["id"], i, cond, event_data, now)
        if logic == "OR":
            return self._evaluate_or(rule, conditions, event_data, now)
        else:
            return self._evaluate_and(rule, conditions, event_data, now)

    def _is_excluded(self, rule_id, now, window=300):
        return now - self.rule_exclusions.get(rule_id, 0) <= window

    def _evaluate_and(self, rule, conditions, event_data, now):
        # v4.11 (P2): a NOT/filter match inside the window suppresses the rule
        if self._is_excluded(rule["id"], now):
            return None
        checked_any = False
        for i, cond in enumerate(conditions):
            # v4.6.4: only pure suppressors (NOT without threshold) are skipped -
            # a merged NOT+threshold condition (e.g. THREAT-044/045/057) is a real
            # counter whose buffered events are filtered by the inner NOT.
            if cond.get("NOT") and cond.get("threshold") in (None, 0):
                continue
            checked_any = True
            if not self._check_condition_threshold(rule["id"], i, cond, now):
                return None
        # v4.6.4: never fire a rule whose conditions were all suppressors - the old
        # code skipped every NOT condition and then fired unconditionally, so rules
        # like THREAT-045 ('Network Connection NOT to Private IP') alerted on EVERY
        # event regardless of type/threshold.
        if not checked_any:
            return None
        return self._fire_alert(rule, event_data, conditions)

    def _evaluate_or(self, rule, conditions, event_data, now):
        if self._is_excluded(rule["id"], now):
            return None
        for i, cond in enumerate(conditions):
            if cond.get("NOT") and cond.get("threshold") in (None, 0):
                continue
            if self._check_condition_threshold(rule["id"], i, cond, now):
                return self._fire_alert(rule, event_data, conditions)
        return None

    def _buffer_matching_condition(self, rule_id, cond_index, cond, event_data, now):
        # v4.11 (P2): NOT (filter) conditions do NOT buffer - a matching event
        # suppresses the rule for the window instead (the sigma parser emits flat
        # {..., "NOT": True} filters; threshold=0 would otherwise fire always).
        if cond.get("NOT"):
            # v4.6.4: a NOT condition that ALSO carries a threshold is a merged
            # counter+filter (e.g. THREAT-045 'network_traffic NOT private dst') -
            # buffer the events that satisfy the OUTER criteria AND fail the inner
            # filter, so the threshold counts only non-filtered events.
            if cond.get("threshold") not in (None, 0):
                if self._event_matches_condition(event_data, cond):
                    self.event_buffers[f"{rule_id}:{cond_index}"].append((now, event_data))
                return
            positive = {k: v for k, v in cond.items()
                        if k not in ("NOT", "threshold", "within_seconds")}
            if self._event_matches_condition(event_data, positive):
                self.rule_exclusions[rule_id] = now
            return
        if "logic" in cond and "conditions" in cond:
            sub_conditions = cond["conditions"]
            sub_logic = cond.get("logic", "AND").upper()
            if sub_logic == "OR":
                matched = any(self._event_matches_condition(event_data, sc) for sc in sub_conditions)
            else:
                matched = all(self._event_matches_condition(event_data, sc) for sc in sub_conditions)
            if matched:
                self.event_buffers[f"{rule_id}:group:{cond_index}"].append((now, event_data))
            return
        if self._event_matches_condition(event_data, cond):
            self.event_buffers[f"{rule_id}:{cond_index}"].append((now, event_data))

    def _check_condition_threshold(self, rule_id, cond_index, cond, now):
        key = f"{rule_id}:{'group' if 'logic' in cond else ''}:{cond_index}" if "logic" in cond else f"{rule_id}:{cond_index}"
        buffer = self.event_buffers.get(key, deque())
        threshold = cond.get("threshold", 1)
        within_seconds = cond.get("within_seconds", 300)

        while buffer and (now - buffer[0][0]) > within_seconds:
            buffer.popleft()

        if cond.get("count_distinct"):
            field = cond.get("count_distinct")
            return len({ev.get(field, "") for _, ev in buffer if ev.get(field)}) >= threshold
        if cond.get("group_by"):
            groups = defaultdict(int)
            for _, ev in buffer:
                groups[ev.get(cond["group_by"], "")] += 1
            return any(c >= threshold for c in groups.values())
        return len(buffer) >= threshold

    def _check_sequence_rule(self, rule, event_data, now):
        sequence = rule.get("sequence", []) or rule.get("conditions", [])
        if not sequence:
            return None
        rule_id = rule["id"]
        seq_within = rule.get("sequence_within_seconds", 300)
        for phase_idx, phase_cond in enumerate(sequence):
            if self._event_matches_condition(event_data, phase_cond):
                if phase_idx == 0:
                    self.sequence_states[rule_id].append({"start_time": now, "phases": {0: event_data}, "complete": False})
                for state in self.sequence_states[rule_id]:
                    if state.get("complete"):
                        continue
                    max_phase = max(state["phases"].keys()) if state["phases"] else -1
                    if phase_idx == max_phase + 1:
                        state["phases"][phase_idx] = event_data
                        if len(state["phases"]) == len(sequence) and (now - state["start_time"]) <= seq_within:
                            return self._fire_alert(rule, event_data, sequence)
        return None

    def _clean_sequence_states(self, now, max_age=3600):
        for rule_id in list(self.sequence_states.keys()):
            self.sequence_states[rule_id] = [s for s in self.sequence_states[rule_id] if now - s["start_time"] <= max_age]

    # =========================================================================
    # ALERT FIRING with PPID SPOOFING DETECTION (v1.15.0)
    # =========================================================================

    def _verify_parent_integrity(self, event_data):
        """v1.15.0: Verify parent process is legitimate (not PPID spoofed).
        Returns: (is_spoofed: bool, penalty: int, reason: str)
        """
        parent_pid = event_data.get("parent_pid", "")
        parent_name = event_data.get("parent_process", "").lower()
        child_name = event_data.get("process_name", "").lower()

        if not parent_pid or not parent_name:
            return False, 0, ""

        spoof_targets = {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
                        "rundll32.exe", "regsvr32.exe", "mshta.exe"}
        if child_name not in spoof_targets:
            return False, 0, ""

        try:
            # v4.5.4 FIX: wmic is deprecated/removed on Windows 11 24H2+; use CIM.
            ps_parent = (
                '$p = Get-CimInstance Win32_Process -Filter "ProcessId=' + str(parent_pid) + '"; '
                'if ($p) { "{0}|{1}" -f $p.Name, $p.CreationDate.ToUniversalTime().ToString("yyyyMMddHHmmss.ffffff") }'
            )
            r = subprocess.run(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_parent],
                capture_output=True, text=True, timeout=8,
                creationflags=CREATE_NO_WINDOW
            )
            if r.returncode != 0 or not r.stdout.strip():
                return True, 40, f"Parent PID {parent_pid} not found (dead/spoofed)"

            out = r.stdout.strip().split("|")
            if len(out) < 2:
                return True, 40, f"Parent PID {parent_pid} has no data"

            actual_parent_name = out[0].strip().lower()
            parent_creation_date = out[1].strip()

            if actual_parent_name != parent_name:
                return True, 50, f"Parent name mismatch: claimed={parent_name}, actual={actual_parent_name}"

            child_pid = event_data.get("pid", "")
            if child_pid and parent_creation_date:
                ps_child = (
                    '$p = Get-CimInstance Win32_Process -Filter "ProcessId=' + str(child_pid) + '"; '
                    'if ($p) { $p.CreationDate.ToUniversalTime().ToString("yyyyMMddHHmmss.ffffff") }'
                )
                r2 = subprocess.run(
                    ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_child],
                    capture_output=True, text=True, timeout=8,
                    creationflags=CREATE_NO_WINDOW
                )
                if r2.returncode == 0 and r2.stdout.strip():
                    child_creation = r2.stdout.strip()
                    if parent_creation_date >= child_creation:
                        return True, 60, f"Parent created AFTER child: parent={parent_creation_date}, child={child_creation}"

        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass

        return False, 0, ""

    def _fire_alert(self, rule, event_data, conditions):
        machine_id = self.machine_id or event_data.get("machine_id", "")
        cooldown_key = f"{rule['id']}:{machine_id}"
        # v4.5.4 FIX: sliding-window cooldown (previous epoch-bucketing allowed
        # duplicate alerts right at bucket boundaries).
        if time.time() - self.fired_alerts.get(cooldown_key, 0) < self.alert_cooldown:
            return None

        skip_alert = False
        penalty = 0
        parent_pid = event_data.get("parent_pid", "")

        # v1.15.0: PPID Spoofing Check
        is_spoofed = False
        spoof_reason = ""
        if parent_pid:
            is_spoofed, spoof_penalty, spoof_reason = self._verify_parent_integrity(event_data)
            if is_spoofed:
                penalty += spoof_penalty

        # Process parent whitelist
        event_process = event_data.get("process_name", "").lower()
        event_parent = event_data.get("parent_process", "").lower()
        if event_process and event_parent:
            if event_process in PROCESS_PARENT_WHITELIST:
                allowed = PROCESS_PARENT_WHITELIST[event_process]
                if event_parent in allowed:
                    if not is_spoofed:
                        skip_alert = True
                elif allowed:
                    penalty += 30

        # Network domain whitelist
        dst_domain = event_data.get("dst_domain", "").lower()
        if dst_domain:
            domain_parts = dst_domain.split(".")
            for i in range(len(domain_parts) - 2, len(domain_parts)):
                if ".".join(domain_parts[i:]) in NETWORK_DOMAIN_WHITELIST:
                    skip_alert = True
                    break

        if skip_alert:
            self.fired_alerts[cooldown_key] = time.time()
            return None

        base_confidence = rule.get("confidence_score", 50)
        event_count = sum(1 for i in range(len(conditions))
                          if self._check_condition_threshold(rule["id"], i, conditions[i], time.time()))
        condition_ratio = event_count / max(1, len(conditions))
        confidence = int(base_confidence + (condition_ratio - 0.5) * 20 - penalty)
        confidence = max(0, min(100, confidence))

        actual_severity = rule["severity"]
        if confidence < 50:
            actual_severity = "INFO"

        self.fired_alerts[cooldown_key] = time.time()

        alert = {
            "type": "threat_alert",
            "rule_id": rule["id"],
            "rule_name": rule["name"],
            "description": rule["description"],
            "severity": actual_severity,
            "original_severity": rule["severity"],
            "confidence_score": confidence,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "trigger_event": event_data,
            "machine_id": machine_id,
        }

        if confidence < 50:
            alert["note"] = "Low confidence - informational only. Review before action."
        if is_spoofed:
            alert["ppid_spoofing"] = True
            alert["spoof_reason"] = spoof_reason
        if rule.get("mitre"):
            alert["mitre"] = rule["mitre"]
        if rule.get("tactic"):
            alert["tactic"] = rule["tactic"]

        for i in range(len(conditions)):
            for prefix in [f"{rule['id']}:{i}", f"{rule['id']}:group:{i}"]:
                if prefix in self.event_buffers:
                    self.event_buffers[prefix].clear()

        if self.alert_callback:
            self.alert_callback(alert)
        return alert

    # =========================================================================
    # CONDITION MATCHING
    # =========================================================================

    def _event_matches_condition(self, event, condition):
        if condition.get("NOT", False):
            inner = condition.get("condition", {})
            outer = {k: v for k, v in condition.items() if k not in ("NOT", "condition")}
            if not self._event_matches_condition(event, outer):
                return False
            if inner and self._event_matches_condition(event, inner):
                return False
            return True
        cond_type = condition.get("type", "")
        event_type = event.get("type", "")
        if cond_type:
            if isinstance(cond_type, list):
                if event_type not in cond_type:
                    return False
            elif cond_type != "*" and event_type != cond_type:
                return False
        if condition.get("threat_intel_match") and not event.get("threat_intel_match"):
            return False
        if condition.get("threat_intel_tor") and not event.get("threat_intel_tor"):
            return False
        expected_ids = condition.get("event_id")
        if expected_ids:
            event_id = str(event.get("event_id", ""))
            if isinstance(expected_ids, list):
                if event_id not in expected_ids:
                    return False
            elif event_id != str(expected_ids):
                return False
        expected_subtype = condition.get("subtype")
        if expected_subtype:
            subtype = event.get("subtype", "")
            if isinstance(expected_subtype, list):
                if not any(s in subtype for s in expected_subtype):
                    return False
            elif expected_subtype not in subtype:
                return False
        expected_action = condition.get("action")
        if expected_action and event.get("action", "") != expected_action:
            return False
        expected_ports = condition.get("dst_port")
        if expected_ports:
            try:
                dst_port = int(event.get("dst_port", 0) or 0)
            except (TypeError, ValueError):
                dst_port = -1
            if isinstance(expected_ports, list):
                if dst_port not in expected_ports:
                    return False
            elif dst_port != expected_ports:
                return False
        desc_contains = condition.get("description_contains")
        if desc_contains:
            desc = event.get("description", "").lower()
            if isinstance(desc_contains, list):
                if not any(d.lower() in desc for d in desc_contains):
                    return False
            elif desc_contains.lower() not in desc:
                return False
        path_contains = condition.get("path_contains")
        if path_contains:
            path_val = event.get("path", "").lower()
            if isinstance(path_contains, list):
                if not any(p.lower() in path_val for p in path_contains):
                    return False
            elif path_contains.lower() not in path_val:
                return False
        expected_severity = condition.get("severity")
        if expected_severity:
            ev_severity = event.get("severity", "").upper()
            if isinstance(expected_severity, list):
                if ev_severity not in [s.upper() for s in expected_severity]:
                    return False
            elif ev_severity != expected_severity.upper():
                return False
        def _field_value(field_name):
            v = event.get(field_name)
            if v is None:
                pf = event.get("parsed_fields") or {}
                v = pf.get(field_name)
            # v4.13 (P1.3): resolve SIGMA PascalCase field names to agent snake_case
            if v is None and field_name in FIELD_ALIASES:
                alias = FIELD_ALIASES[field_name]
                v = event.get(alias)
                if v is None:
                    pf = event.get("parsed_fields") or {}
                    v = pf.get(alias)
            # v5.0.4 (HIGH-3): the converted rules store LOWERCASE field keys
            # (imagepath, integritylevel, parentcommandline, targetfilename...) -
            # resolve them against the lowercase alias map as well.
            if v is None:
                alias = FIELD_ALIASES_LOWER.get(str(field_name).lower())
                if alias and alias != field_name:
                    v = event.get(alias)
                    if v is None:
                        pf = event.get("parsed_fields") or {}
                        v = pf.get(alias)
            return "" if v is None else v

        field_contains = condition.get("field_contains")
        if field_contains and isinstance(field_contains, dict):
            for field_name, patterns in field_contains.items():
                field_val = str(_field_value(field_name)).lower()
                if isinstance(patterns, list):
                    if not any(str(p).lower() in field_val for p in patterns):
                        return False
                elif str(patterns).lower() not in field_val:
                    return False
        field_equals = condition.get("field_equals")
        if field_equals and isinstance(field_equals, dict):
            for field_name, expected_val in field_equals.items():
                field_val = str(_field_value(field_name))
                if isinstance(expected_val, list):
                    if field_val not in [str(v) for v in expected_val]:
                        return False
                elif field_val != str(expected_val):
                    return False
        field_regex = condition.get("field_regex")
        if field_regex and isinstance(field_regex, dict):
            for field_name, pattern in field_regex.items():
                if not re.search(pattern, str(_field_value(field_name)), re.IGNORECASE):
                    return False
        return True