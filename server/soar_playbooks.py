"""
SOAR Playbook Engine for GIAM-SAT v2.0.0
Security Orchestration, Automation and Response

Provides automated response workflows triggered by alerts:
  - Conditional logic (IF/THEN/ELSE)
  - Multi-step response chains
  - Time-based escalation
  - Integration with Responder (agent actions)
  - Notification via Email/Slack/Telegram

Playbooks are defined in YAML and can be updated without restart.
"""

import os
import json
import re
import time
import threading
from datetime import datetime, timedelta

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

PLAYBOOK_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "playbooks.yaml")


class SOARPlaybookEngine:
    """SOAR engine that executes automated response playbooks."""

    def __init__(self, callback=None, telegram_sender=None, tcp_server=None):
        self.callback = callback
        self.telegram_sender = telegram_sender
        self.tcp_server = tcp_server  # v3.9.3: TCP command dispatch to agents
        self.playbooks = []
        self.active_incidents = {}  # incident_id -> state
        self._executed_actions = set()  # dedup
        self._auto_response_lock = threading.Lock()
        self._auto_response_cooldown = {}  # machine_id -> last_action_time
        self.running = True
        self._load_playbooks()

    def _load_playbooks(self):
        """Load playbooks from YAML file."""
        if not HAS_YAML or not os.path.exists(PLAYBOOK_PATH):
            self.playbooks = self._default_playbooks()
            return

        try:
            with open(PLAYBOOK_PATH, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                if data and "playbooks" in data:
                    self.playbooks = data["playbooks"]
        except Exception:
            self.playbooks = self._default_playbooks()

    def _default_playbooks(self):
        """Built-in default playbooks."""
        return [
            {
                "id": "PB-001",
                "name": "Ransomware Response",
                "trigger": {"type": "threat_alert", "rule_id": ["THREAT-002", "THREAT-054"], "severity": "CRITICAL"},
                "actions": [
                    {"order": 1, "action": "quarantine_file", "params": {"file_path": "{{ alert.file_path }}"}, "wait_seconds": 0},
                    {"order": 2, "action": "isolate_network", "params": {}, "wait_seconds": 5},
                    {"order": 3, "action": "forensic_snapshot", "params": {}, "wait_seconds": 0},
                    {"order": 4, "action": "notify_telegram", "params": {"message": "🚨 RANSOMWARE DETECTED on {{ alert.machine_id }}. Machine isolated. File quarantined."}, "wait_seconds": 0},
                    {"order": 5, "action": "create_incident", "params": {"priority": "P1", "title": "Ransomware Attack - {{ alert.machine_id }}"}, "wait_seconds": 0},
                ],
                "escalation": {
                    "after_minutes": 15,
                    "actions": [
                        {"action": "notify_telegram", "params": {"message": "⚠️ ESCALATION: Ransomware incident on {{ alert.machine_id }} still active after 15 minutes."}},
                    ],
                },
            },
            {
                "id": "PB-002",
                "name": "Brute Force Response",
                "trigger": {"type": "threat_alert", "rule_id": ["THREAT-001", "THREAT-053"], "severity": "HIGH"},
                "actions": [
                    {"order": 1, "action": "firewall_block", "params": {"ip": "{{ alert.source_ip }}", "direction": "both"}, "wait_seconds": 0},
                    {"order": 2, "action": "notify_telegram", "params": {"message": "🔒 Brute force attack from {{ alert.source_ip }} blocked via firewall."}, "wait_seconds": 0},
                ],
            },
            {
                "id": "PB-003",
                "name": "Credential Theft Response",
                "trigger": {"type": "threat_alert", "rule_id": ["THREAT-009", "THREAT-046", "THREAT-051"], "severity": "CRITICAL"},
                "actions": [
                    {"order": 1, "action": "kill_process", "params": {"name": "{{ alert.process_name }}", "pid": "{{ alert.pid }}"}, "wait_seconds": 0},
                    {"order": 2, "action": "forensic_snapshot", "params": {}, "wait_seconds": 0},
                    {"order": 3, "action": "disable_account", "params": {"username": "{{ alert.user }}"}, "wait_seconds": 2},
                    {"order": 4, "action": "notify_telegram", "params": {"message": "🔑 Credential theft detected on {{ alert.machine_id }}. Account {{ alert.user }} disabled. Process killed."}, "wait_seconds": 0},
                ],
            },
            {
                "id": "PB-004",
                "name": "C2 Communication Response",
                "trigger": {"type": "threat_alert", "rule_id": ["THREAT-006", "THREAT-025", "THREAT-045"], "severity": "CRITICAL"},
                "actions": [
                    {"order": 1, "action": "firewall_block", "params": {"ip": "{{ alert.dst_ip }}", "direction": "outbound"}, "wait_seconds": 0},
                    {"order": 2, "action": "notify_telegram", "params": {"message": "🛰️ C2 communication detected from {{ alert.machine_id }} to {{ alert.dst_ip }}. Outbound blocked."}, "wait_seconds": 0},
                    {"order": 3, "action": "forensic_snapshot", "params": {}, "wait_seconds": 0},
                ],
            },
            {
                "id": "PB-005",
                "name": "Defense Evasion Response",
                "trigger": {"type": "threat_alert", "rule_id": ["THREAT-005", "THREAT-043"], "severity": "CRITICAL"},
                "actions": [
                    {"order": 1, "action": "notify_telegram", "params": {"message": "🛡️ Defense evasion detected on {{ alert.machine_id }} - Defender/Firewall/Audit may be disabled."}, "wait_seconds": 0},
                    {"order": 2, "action": "create_incident", "params": {"priority": "P1", "title": "Defense Evasion - {{ alert.machine_id }}"}, "wait_seconds": 0},
                ],
                "escalation": {
                    "after_minutes": 30,
                    "actions": [
                        {"action": "notify_telegram", "params": {"message": "⚠️ ESCALATION: Defense evasion on {{ alert.machine_id }} not remediated after 30 min."}},
                    ],
                },
            },
            {
                "id": "PB-006",
                "name": "All CRITICAL Alerts",
                "trigger": {"type": "*", "severity": "CRITICAL"},
                "actions": [
                    {"order": 1, "action": "notify_telegram", "params": {"message": "🚨 CRITICAL alert: {{ alert.rule_name }} on {{ alert.machine_id }}. {{ alert.description }}"}, "wait_seconds": 0},
                    {"order": 2, "action": "forensic_snapshot", "params": {}, "wait_seconds": 0},
                ],
            },
        ]

    # =========================================================================
    # Trigger Evaluation
    # =========================================================================

    def process_alert(self, alert_data: dict) -> list:
        """Process an alert and trigger matching playbooks. Returns list of action results."""
        results = []
        incident_id = f"INC-{int(time.time())}-{alert_data.get('rule_id', 'UNKNOWN')}"

        for pb in self.playbooks:
            if self._matches_trigger(pb.get("trigger", {}), alert_data):
                print(f"[*] SOAR: Playbook '{pb['name']}' triggered by {alert_data.get('rule_id')}")
                result = self._execute_playbook(pb, alert_data, incident_id)
                results.append(result)

                # Track active incident for escalation
                if any(a.get("action") == "create_incident" for a in pb.get("actions", [])):
                    self.active_incidents[incident_id] = {
                        "playbook": pb,
                        "alert": alert_data,
                        "started_at": datetime.now(),
                        "status": "active",
                    }

        return results

    def _matches_trigger(self, trigger: dict, alert: dict) -> bool:
        """Check if an alert matches a playbook trigger."""
        trigger_type = trigger.get("type", "*")
        alert_type = alert.get("type", "")

        # Type matching
        if trigger_type != "*" and alert_type != trigger_type:
            return False

        # Rule ID matching
        rule_ids = trigger.get("rule_id", [])
        if rule_ids:
            alert_rule = alert.get("rule_id", "")
            if isinstance(rule_ids, list):
                if alert_rule not in rule_ids:
                    return False
            elif alert_rule != rule_ids:
                return False

        # Severity matching
        trigger_sev = trigger.get("severity", "")
        if trigger_sev:
            alert_sev = alert.get("severity", "")
            if isinstance(trigger_sev, list):
                if alert_sev not in trigger_sev:
                    return False
            elif alert_sev != trigger_sev:
                return False

        return True

    # =========================================================================
    # Playbook Execution
    # =========================================================================

    def _execute_playbook(self, playbook: dict, alert: dict, incident_id: str) -> dict:
        """Execute all actions in a playbook in order."""
        result = {
            "playbook_id": playbook["id"],
            "playbook_name": playbook["name"],
            "incident_id": incident_id,
            "actions_executed": [],
            "status": "completed",
        }

        actions = sorted(playbook.get("actions", []), key=lambda a: a.get("order", 99))

        for action_def in actions:
            action_name = action_def.get("action", "")
            params = self._resolve_params(action_def.get("params", {}), alert)
            wait = action_def.get("wait_seconds", 0)

            # Dedup: Skip if same action+params already executed for this incident
            action_key = f"{incident_id}:{action_name}:{json.dumps(params, sort_keys=True)}"
            if action_key in self._executed_actions:
                continue
            self._executed_actions.add(action_key)

            # Clean old dedup keys
            if len(self._executed_actions) > 1000:
                self._executed_actions.clear()

            # Execute the action
            action_result = self._execute_action(action_name, params, alert)
            result["actions_executed"].append({
                "action": action_name,
                "params": params,
                "result": action_result,
            })

            if self.callback:
                self.callback({
                    "type": "soar_action",
                    "playbook": playbook["name"],
                    "incident_id": incident_id,
                    "action": action_name,
                    "result": action_result,
                    "timestamp": datetime.now().isoformat(),
                })

            # Wait between actions if specified
            if wait > 0:
                time.sleep(wait)

        return result

    def _resolve_params(self, params: dict, alert: dict) -> dict:
        """Resolve template variables in params using alert data."""
        resolved = {}
        for key, value in params.items():
            if isinstance(value, str) and "{{" in value:
                # Simple template resolution
                resolved_val = self._resolve_template(value, alert)
                resolved[key] = resolved_val
            else:
                resolved[key] = value
        return resolved

    def _resolve_template(self, template: str, alert: dict) -> str:
        """Resolve {{ alert.field }} style templates."""
        def replace_var(match):
            field_path = match.group(1).strip()
            if field_path.startswith("alert."):
                field = field_path[6:]
                return str(alert.get(field, match.group(0)))
            return match.group(0)

        return re.sub(r'\{\{\s*(.+?)\s*\}\}', replace_var, template)

    def _execute_action(self, action_name: str, params: dict, alert: dict) -> dict:
        """Execute a single SOAR action."""
        if action_name == "notify_telegram":
            return self._action_notify_telegram(params, alert)
        elif action_name == "create_incident":
            return self._action_create_incident(params, alert)
        elif action_name in ("firewall_block", "quarantine_file", "isolate_network",
                             "forensic_snapshot", "kill_process", "disable_account"):
            # v3.9.3: Auto-dispatch agent-side actions via TCP command
            return self._dispatch_agent_action(action_name, params, alert)
        else:
            return {"status": "skipped", "reason": f"Unknown action: {action_name}"}

    def _dispatch_agent_action(self, action_name: str, params: dict, alert: dict) -> dict:
        """v3.9.3: Send agent command via TCP with safety gate checks.
        Only auto-respond when: CRITICAL severity + cooldown not active.
        Returns result dict for logging."""
        machine_id = alert.get("machine_id", "")
        severity = alert.get("severity", "MEDIUM")
        rule_id = alert.get("rule_id", "UNKNOWN")

        # SAFETY GATE 1: Only auto-respond to CRITICAL severity
        if severity != "CRITICAL":
            return {
                "status": "skipped",
                "reason": f"Auto-response requires CRITICAL severity, got {severity}",
            }

        # SAFETY GATE 2: Cooldown per machine (60s between actions)
        if not machine_id:
            return {"status": "skipped", "reason": "No machine_id in alert"}
        with self._auto_response_lock:
            last_action = self._auto_response_cooldown.get(machine_id, 0)
            now = time.time()
            if now - last_action < 60:
                return {
                    "status": "skipped",
                    "reason": f"Cooldown active ({int(now - last_action)}s since last action)",
                }
            self._auto_response_cooldown[machine_id] = now

        # SAFETY GATE 3: TCP server must be available
        if not self.tcp_server:
            return {"status": "skipped", "reason": "TCP server not connected to SOAR engine"}

        # Map SOAR action names to agent command actions
        action_map = {
            "isolate_network": "isolate_network",
            "kill_process": "kill_process",
            "quarantine_file": "quarantine_file",
            "firewall_block": "firewall_block",
            "forensic_snapshot": "forensic_snapshot",
            "disable_account": "disable_account",
        }
        agent_action = action_map.get(action_name, action_name)

        exec_id = f"soar_{rule_id}_{int(time.time())}"
        cmd_data = {
            "action": agent_action,
            "command": json.dumps(params, ensure_ascii=False),
            "exec_id": exec_id,
            "params": {"alert_rule_id": rule_id, "auto_response": True},
        }

        try:
            success = self.tcp_server.send_command(machine_id, cmd_data)
            if success:
                print(f"[SOAR] Auto-response dispatched: {action_name} -> {machine_id} (rule={rule_id})")
                return {
                    "status": "dispatched",
                    "agent_action": agent_action,
                    "machine_id": machine_id,
                    "exec_id": exec_id,
                }
            else:
                print(f"[SOAR] Auto-response FAILED: {action_name} -> {machine_id} (agent offline?)")
                return {
                    "status": "failed",
                    "reason": "Agent offline or command send failed",
                    "agent_action": agent_action,
                }
        except Exception as e:
            print(f"[SOAR] Auto-response ERROR: {action_name}: {e}")
            return {"status": "error", "reason": str(e)[:200]}

    def _action_notify_telegram(self, params: dict, alert: dict) -> dict:
        """Send notification via Telegram."""
        message = params.get("message", "SOAR Alert")
        if self.telegram_sender:
            success = self.telegram_sender(message)
            return {"status": "sent" if success else "failed"}
        return {"status": "skipped", "reason": "No Telegram sender configured"}

    def _action_create_incident(self, params: dict, alert: dict) -> dict:
        """Create an incident tracking record."""
        incident = {
            "id": f"INC-{int(time.time())}",
            "priority": params.get("priority", "P3"),
            "title": params.get("title", "Security Incident"),
            "machine_id": alert.get("machine_id", ""),
            "alert_id": alert.get("rule_id", ""),
            "severity": alert.get("severity", "MEDIUM"),
            "created_at": datetime.now().isoformat(),
            "status": "open",
            "playbook_triggered": True,
        }
        return {"status": "created", "incident": incident}

    # =========================================================================
    # Escalation Monitoring
    # =========================================================================

    def check_escalations(self) -> list:
        """Check for incidents that need escalation."""
        escalations = []
        now = datetime.now()

        for incident_id, incident in list(self.active_incidents.items()):
            pb = incident.get("playbook", {})
            escalation = pb.get("escalation", {})
            after_minutes = escalation.get("after_minutes", 0)

            if after_minutes > 0:
                elapsed = (now - incident["started_at"]).total_seconds() / 60
                if elapsed >= after_minutes and incident["status"] == "active":
                    incident["status"] = "escalated"
                    escalations.append(incident)

                    # Execute escalation actions
                    for action_def in escalation.get("actions", []):
                        result = self._execute_action(
                            action_def.get("action", ""),
                            action_def.get("params", {}),
                            incident.get("alert", {}),
                        )
                        escalations.append({"action": action_def, "result": result})

        return escalations

    def start_escalation_monitor(self, interval_seconds: int = 60):
        """Start background escalation monitoring thread."""
        def monitor():
            while self.running:
                time.sleep(interval_seconds)
                try:
                    self.check_escalations()
                except Exception:
                    pass

        threading.Thread(target=monitor, daemon=True).start()

    # =========================================================================
    # Playbook Management API
    # =========================================================================

    def get_playbooks(self) -> list:
        """Get all loaded playbooks."""
        return [{"id": pb["id"], "name": pb["name"]} for pb in self.playbooks]

    def get_active_incidents(self) -> list:
        """Get all active incidents."""
        return list(self.active_incidents.values())

    def resolve_incident(self, incident_id: str) -> bool:
        """Mark an incident as resolved."""
        if incident_id in self.active_incidents:
            self.active_incidents[incident_id]["status"] = "resolved"
            self.active_incidents[incident_id]["resolved_at"] = datetime.now().isoformat()
            return True
        return False

    def stop(self):
        self.running = False