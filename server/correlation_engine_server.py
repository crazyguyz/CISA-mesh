"""
Server-side Cross-Machine Correlation Engine for GIAM-SAT v1.8.0
Correlates events across multiple agents to detect attack chains, lateral movement,
and multi-stage compromises that span across hosts.

Key features:
- Cross-host attack chain detection (lateral movement, credential theft cascade)
- Time-window based correlation across different machine_ids
- Server-side event buffer with multi-machine event slicing
- Threat scoring for correlated attack chains
- Integration with alerting engine
"""
import json
import time
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta

CROSS_MACHINE_RULES = [
    # =========================================================================
    # LATERAL MOVEMENT DETECTION
    # =========================================================================
    {
        "id": "CROSS-001",
        "name": "Lateral Movement - Brute Force Followed by Successful Logon",
        "description": "Brute force attack on Machine A, then successful logon on Machine B from same source IP",
        "severity": "CRITICAL",
        "mitre": "T1110 → T1021",
        "conditions": [
            {
                "type": "event",
                "event_id": "4625",  # Failed logon
                "threshold": 5,
                "within_seconds": 300,
            },
            {
                "type": "event",
                "event_id": "4624",  # Successful logon
                "threshold": 1,
                "within_seconds": 300,
                "must_be_different_machine": True,  # Must be on DIFFERENT machine from first condition
            }
        ],
        "correlate_by": "source_ip"  # Correlate events from same source IP
    },
    {
        "id": "CROSS-002",
        "name": "Lateral Movement - PsExec Detected Across Machines",
        "description": "PsExec service installed on Machine A, then new logon on Machine B from Machine A's IP",
        "severity": "HIGH",
        "mitre": "T1569.002 → T1021.002",
        "conditions": [
            {
                "type": "event",
                "event_id": "7045",
                "description_contains": ["PSEXESVC", "PsExec"],
                "threshold": 1,
                "within_seconds": 120,
            },
            {
                "type": "event",
                "event_id": "4624",
                "logon_type": "3",  # Network logon
                "threshold": 1,
                "within_seconds": 120,
                "must_be_different_machine": True,
            }
        ],
        "correlate_by": None  # Uses parent-child relationship via parsed fields
    },
    {
        "id": "CROSS-003",
        "name": "Lateral Movement - Remote Desktop Spread",
        "description": "RDP logon (Type 10) on multiple machines from same source within short timeframe",
        "severity": "HIGH",
        "mitre": "T1021.001",
        "conditions": [
            {
                "type": "event",
                "event_id": "4624",
                "logon_type": "10",  # RemoteInteractive (RDP)
                "threshold": 3,
                "within_seconds": 600,
                "must_be_different_machine": True,
                "count_distinct_machines": True,
            }
        ],
        "correlate_by": "source_ip"
    },

    # =========================================================================
    # CREDENTIAL THEFT CASCADE
    # =========================================================================
    {
        "id": "CROSS-004",
        "name": "Credential Theft Cascade - LSASS Dump Then Lateral Spread",
        "description": "LSASS credential dumping on Machine A, then logon on multiple other machines using same account",
        "severity": "CRITICAL",
        "mitre": "T1003.001 → T1550.002",
        "conditions": [
            {
                "type": "event",
                "event_id": "4663",
                "description_contains": ["lsass.exe"],
                "threshold": 1,
                "within_seconds": 600,
            },
            {
                "type": "event",
                "event_id": "4624",
                "logon_type": "3",
                "threshold": 2,
                "within_seconds": 600,
                "must_be_different_machine": True,
                "count_distinct_machines": True,
            }
        ],
        "correlate_by": "username"  # Same user account appearing across machines
    },
    {
        "id": "CROSS-005",
        "name": "Pass-the-Hash Attack Across Machines",
        "description": "NTLM logon (Type 3 with NTLM) from Machine A appearing on Machine B and C",
        "severity": "CRITICAL",
        "mitre": "T1550.002",
        "conditions": [
            {
                "type": "event",
                "event_id": "4624",
                "logon_type": "3",
                "description_contains": ["NtLmSsp"],
                "threshold": 3,
                "within_seconds": 600,
                "must_be_different_machine": True,
                "count_distinct_machines": True,
            }
        ],
        "correlate_by": "username"
    },

    # =========================================================================
    # PRIVILEGE ESCALATION + SPREAD
    # =========================================================================
    {
        "id": "CROSS-006",
        "name": "Privilege Escalation Then Lateral Spread",
        "description": "Token manipulation or special logon on Machine A, then admin logon on Machine B",
        "severity": "HIGH",
        "mitre": "T1134 → T1078",
        "conditions": [
            {
                "type": "event",
                "event_id": "4672",
                "description_contains": ["SeDebugPrivilege"],
                "threshold": 1,
                "within_seconds": 600,
            },
            {
                "type": "event",
                "event_id": "4624",
                "description_contains": ["Administrator", "Domain Admin"],
                "threshold": 1,
                "within_seconds": 600,
                "must_be_different_machine": True,
            }
        ],
        "correlate_by": "username"
    },

    # =========================================================================
    # C2 BEACONING ACROSS HOSTS
    # =========================================================================
    {
        "id": "CROSS-007",
        "name": "Coordinated C2 Communication Across Hosts",
        "description": "Multiple machines connecting to same external IP/port (C2 infrastructure)",
        "severity": "CRITICAL",
        "mitre": "T1071.001",
        "conditions": [
            {
                "type": "network_traffic",
                "threshold": 2,
                "within_seconds": 300,
                "must_be_different_machine": True,
                "count_distinct_machines": True,
            }
        ],
        "correlate_by": "dst_ip"
    },

    # =========================================================================
    # MALWARE SPREAD
    # =========================================================================
    {
        "id": "CROSS-008",
        "name": "Ransomware Behavior Spreading Across Hosts",
        "description": "Mass file modifications detected on multiple machines within short timeframe",
        "severity": "CRITICAL",
        "mitre": "T1486",
        "conditions": [
            {
                "type": "fim_event",
                "action": "FILE_MODIFIED",
                "threshold": 50,
                "within_seconds": 300,
                "must_be_different_machine": True,
                "count_distinct_machines": True,
            }
        ],
        "correlate_by": None  # Any machines
    },
    {
        "id": "CROSS-009",
        "name": "Suspicious Service Creation Across Hosts",
        "description": "New services installed on multiple machines from the same external IP or user",
        "severity": "HIGH",
        "mitre": "T1543.003",
        "conditions": [
            {
                "type": "event",
                "event_id": "7045",
                "threshold": 2,
                "within_seconds": 600,
                "must_be_different_machine": True,
                "count_distinct_machines": True,
            }
        ],
        "correlate_by": None
    },

    # =========================================================================
    # DATA EXFILTRATION
    # =========================================================================
    {
        "id": "CROSS-010",
        "name": "Multi-Host Data Exfiltration",
        "description": "Large outbound data transfers from multiple machines to same external IP",
        "severity": "CRITICAL",
        "mitre": "T1041",
        "conditions": [
            {
                "type": "network_traffic",
                "threshold": 3,
                "within_seconds": 300,
                "must_be_different_machine": True,
                "count_distinct_machines": True,
            }
        ],
        "correlate_by": "dst_ip"
    },
    {
        "id": "CROSS-011",
        "name": "Reconnaissance Followed by Attack",
        "description": "Port scan from Machine A, followed by exploit attempt on scanned ports from same source",
        "severity": "HIGH",
        "mitre": "T1046 → T1190",
        "conditions": [
            {
                "type": "network_traffic",
                "threshold": 20,
                "within_seconds": 30,
            },
            {
                "type": "event",
                "event_id": ["4625", "4688"],
                "threshold": 3,
                "within_seconds": 120,
                "must_be_different_machine": True,
            }
        ],
        "correlate_by": "source_ip"
    },
]


class ServerCorrelationEngine:
    """Cross-machine correlation engine running on the server.

    Maintains an event buffer from all agents and checks for multi-machine
    attack patterns that span across different hosts.
    """

    def __init__(self, db_manager=None, alerting_engine=None):
        self.db = db_manager
        self.alerting = alerting_engine
        self.rules = CROSS_MACHINE_RULES
        self.event_buffers = defaultdict(lambda: defaultdict(lambda: deque()))
        self.fired_alerts = {}
        self.alert_cooldown = 1800  # 30 minutes
        self._lock = threading.Lock()

    def process_event(self, event_data):
        """Feed an event from any machine into the cross-machine correlation engine.

        Args:
            event_data: dict with at minimum:
                'type', 'machine_id', 'hostname', 'event_id',
                'description', 'parsed_fields' (optional)
        """
        triggered = []
        for rule in self.rules:
            alert = self._check_cross_machine_rule(rule, event_data)
            if alert:
                triggered.append(alert)
        return triggered

    def _check_cross_machine_rule(self, rule, event_data):
        """Check if event triggers a cross-machine correlation rule."""
        conditions = rule.get("conditions", [])
        if not conditions:
            return None

        # v4.11 (P2): NOT (filter) conditions exclude this event for the rule -
        # the sigma parser emits flat {..., "NOT": True} filters.
        for cond in conditions:
            if cond.get("NOT"):
                positive = {k: v for k, v in cond.items()
                            if k not in ("NOT", "threshold", "within_seconds")}
                if self._event_matches_condition(event_data, positive):
                    return None

        # Check if event matches any condition in the rule
        matched_condition_idx = None
        for idx, cond in enumerate(conditions):
            if self._event_matches_condition(event_data, cond):
                matched_condition_idx = idx
                break

        if matched_condition_idx is None:
            return None

        # Store the event in buffer keyed by rule_id + condition_index
        cond_key = f"{rule['id']}:cond{matched_condition_idx}"
        machine_id = event_data.get("machine_id", "")
        with self._lock:
            self.event_buffers[cond_key][machine_id].append({
                "timestamp": time.time(),
                "machine_id": machine_id,
                "hostname": event_data.get("hostname", ""),
                "event": event_data,
            })
            # Trim old events
            self._trim_buffer(cond_key, machine_id)

        # Evaluate the full rule (honoring correlate_by + must_be_different_machine)
        if not self._rule_conditions_satisfied(rule):
            return None

        # Check cooldown (sliding window, not epoch bucket)
        cooldown_key = f"CROSS:{rule['id']}"
        with self._lock:
            if time.time() - self.fired_alerts.get(cooldown_key, 0) < self.alert_cooldown:
                return None
            self.fired_alerts[cooldown_key] = time.time()

        # Build detailed alert
        alert = self._build_alert(rule)

        # Notify alerting engine
        if self.alerting:
            try:
                self.alerting.send_alert(
                    title=f"[CROSS-MACHINE] {rule['name']} [{rule['severity']}]",
                    message=alert["description"],
                    severity=rule["severity"],
                    rule_id=rule["id"],
                )
            except Exception:
                pass

        return alert

    def _event_matches_condition(self, event, condition):
        """Check if event matches a single condition within a rule."""
        # Type matching
        cond_type = condition.get("type", "")
        evt_type = event.get("type", "")

        if cond_type == "event":
            if evt_type != "event" and evt_type != "windows_event":
                return False
        elif cond_type != evt_type:
            return False

        # Event ID matching
        expected_ids = condition.get("event_id")
        if expected_ids:
            evt_id = str(event.get("event_id", ""))
            if isinstance(expected_ids, list):
                if evt_id not in expected_ids:
                    return False
            else:
                if evt_id != str(expected_ids):
                    return False

        # Description contains
        desc_contains = condition.get("description_contains")
        if desc_contains:
            desc = event.get("description", "").lower()
            if isinstance(desc_contains, list):
                if not any(d.lower() in desc for d in desc_contains):
                    return False
            else:
                if desc_contains.lower() not in desc:
                    return False

        # Action matching (for FIM)
        action = condition.get("action")
        if action and event.get("action", "") != action:
            return False

        # Logon type matching (from parsed fields)
        logon_type = condition.get("logon_type")
        if logon_type:
            parsed = event.get("parsed_fields", {})
            actual_lt = str(parsed.get("logon_type", ""))
            if actual_lt != str(logon_type):
                return False

        # v4.11 (CRITICAL-1 FIX): field_contains - match structured event fields
        # (parsed_fields first, then top-level event fields). The server silently
        # ignored this condition before, so rules like THREAT-052 (4688 + command
        # line contains \Temp\) and THREAT-053 (4625 + 'Logon Type: 10') matched
        # EVERY event of that type -> false-positive storm. Mirrors the agent-side
        # engine (agent/correlation_engine.py) but also reads parsed_fields.
        field_contains = condition.get("field_contains")
        if field_contains and isinstance(field_contains, dict):
            parsed = event.get("parsed_fields") or {}
            for field_name, patterns in field_contains.items():
                raw = event.get(field_name)
                if raw is None:
                    raw = parsed.get(field_name)
                field_val = str(raw if raw is not None else "").lower()
                if isinstance(patterns, list):
                    if not any(str(p).lower() in field_val for p in patterns):
                        return False
                elif str(patterns).lower() not in field_val:
                    return False

        return True

    def _get_correlation_value(self, event, field):
        """Extract a correlation key value from an event for a given field name."""
        if not field:
            return None
        aliases = {
            "source_ip": ["source_ip", "src_ip", "ip_address", "SourceIp", "IpAddress"],
            "dst_ip": ["dst_ip", "dest_ip", "destination_ip", "DestinationIp"],
            "username": ["username", "user", "user_name", "account_name", "TargetUserName", "AccountName"],
        }
        keys = aliases.get(field, [field])
        parsed = event.get("parsed_fields") or {}
        for k in keys:
            v = event.get(k)
            if v in (None, ""):
                v = parsed.get(k)
            if v not in (None, ""):
                return str(v).strip().lower()
        return None

    def _condition_recent_events(self, rule_id, cond_idx, within_seconds):
        """Return events (within the time window) for a rule+condition across all machines."""
        cond_key = f"{rule_id}:cond{cond_idx}"
        now = time.time()
        events = []
        with self._lock:
            for mid, buffer in self.event_buffers[cond_key].items():
                for e in buffer:
                    if (now - e["timestamp"]) <= within_seconds:
                        events.append(e)
        return events

    def _rule_conditions_satisfied(self, rule):
        """Evaluate all conditions of a rule, honoring correlate_by and
        must_be_different_machine."""
        conditions = rule.get("conditions", [])
        correlate_by = rule.get("correlate_by")

        per_condition = []
        for idx, cond in enumerate(conditions):
            within = cond.get("within_seconds", 300)
            per_condition.append(self._condition_recent_events(rule["id"], idx, within))

        # When correlated by a shared key, require a single key value to satisfy
        # every condition (e.g. same source IP across brute-force + logon).
        if correlate_by:
            groups = defaultdict(list)
            for idx, events in enumerate(per_condition):
                for e in events:
                    val = self._get_correlation_value(e["event"], correlate_by)
                    if val:
                        groups[val].append((idx, e))
            for pairs in groups.values():
                if self._conditions_satisfied_for_events(conditions, pairs):
                    return True
            return False

        # No correlation key: evaluate conditions independently.
        pairs = []
        for idx, events in enumerate(per_condition):
            for e in events:
                pairs.append((idx, e))
        return self._conditions_satisfied_for_events(conditions, pairs)

    def _conditions_satisfied_for_events(self, conditions, pairs):
        """Check every condition meets its threshold over the given (cond_idx, event) pairs."""
        cond_events = defaultdict(list)
        for idx, e in pairs:
            cond_events[idx].append(e)

        base_machines = set()
        for idx, cond in enumerate(conditions):
            events = cond_events.get(idx, [])
            threshold = cond.get("threshold", 1)
            if cond.get("count_distinct_machines"):
                # Count distinct machines meeting this condition.
                if len(set(e["machine_id"] for e in events)) < threshold:
                    return False
            elif cond.get("must_be_different_machine"):
                # Must include at least one machine not seen in earlier conditions.
                machines = set(e["machine_id"] for e in events)
                if not (machines - base_machines):
                    return False
                if len(events) < threshold:
                    return False
            else:
                if len(events) < threshold:
                    return False
            base_machines |= set(e["machine_id"] for e in events)
        return True

    def _trim_buffer(self, cond_key, machine_id, max_age=3600):
        """Remove events older than max_age seconds from buffer."""
        now = time.time()
        buffer = self.event_buffers[cond_key][machine_id]
        while buffer and (now - buffer[0]["timestamp"]) > max_age:
            buffer.popleft()
        if not buffer:
            del self.event_buffers[cond_key][machine_id]

    def _build_alert(self, rule):
        """Build a detailed alert object from triggered rule."""
        machines_involved = set()
        event_summaries = []

        with self._lock:
            for idx in range(len(rule.get("conditions", []))):
                cond_key = f"{rule['id']}:cond{idx}"
                for mid, buffer in self.event_buffers[cond_key].items():
                    for entry in buffer:
                        machines_involved.add(f"{entry.get('hostname', mid)} ({mid})")
                        evt = entry.get("event", {})
                        event_summaries.append({
                            "machine_id": mid,
                            "hostname": entry.get("hostname", ""),
                            "timestamp": datetime.fromtimestamp(entry["timestamp"]).strftime("%Y-%m-%d %H:%M:%S"),
                            "event_type": evt.get("type", "?"),
                            "event_id": evt.get("event_id", "?"),
                            "summary": str(evt.get("description", ""))[:150],
                        })

        description = (
            f"═══ CROSS-MACHINE THREAT ═══\n"
            f"Rule: {rule['id']} - {rule['name']}\n"
            f"MITRE: {rule.get('mitre', 'N/A')}\n"
            f"Severity: {rule['severity']}\n"
            f"Description: {rule['description']}\n"
            f"Machines involved: {', '.join(sorted(machines_involved))}\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"Events triggering detection:\n"
        )
        for es in event_summaries[-10:]:  # Last 10 events
            description += f"  [{es['hostname']}] {es['event_type']}/{es['event_id']}: {es['summary']}\n"

        return {
            "type": "cross_machine_threat",
            "rule_id": rule["id"],
            "rule_name": rule["name"],
            "description": description,
            "severity": rule["severity"],
            "mitre": rule.get("mitre", ""),
            "machines_involved": list(machines_involved),
            "events": event_summaries,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

    def get_engine_stats(self):
        """Get statistics about the correlation engine state."""
        total_buffered = 0
        with self._lock:
            for cond_key in self.event_buffers:
                for mid in self.event_buffers[cond_key]:
                    total_buffered += len(self.event_buffers[cond_key][mid])

        return {
            "total_rules": len(self.rules),
            "fired_alerts": len(self.fired_alerts),
            "buffered_events": total_buffered,
            "active_rules_tracking": len(self.event_buffers),
        }

    def reset_buffers(self):
        """Clear all event buffers."""
        with self._lock:
            self.event_buffers = defaultdict(lambda: defaultdict(lambda: deque()))
            self.fired_alerts.clear()