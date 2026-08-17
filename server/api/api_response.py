"""
API Response Actions - Execute incident response commands on agents.
POST /api/response/execute
Body: { "machine_id": "...", "action": "kill_process|firewall_block|disable_account|quarantine_file|forensic_snapshot", "params": { ... } }
"""
import json
import time
from flask import request, jsonify

from .api_common import check_auth


def register(app, core):
    """Register response execution routes."""

    # Action → command mapping for agent responder
    ACTION_MAP = {
        "kill_process": "kill_process",
        "firewall_block": "firewall_block",
        "firewall_unblock": "firewall_unblock",
        "disable_account": "disable_account",
        "quarantine_file": "quarantine_file",
        "isolate_network": "isolate_network",
        "restore_network": "restore_network",
        "forensic_snapshot": "forensic_snapshot",
    }

    # Action descriptions for audit logging
    ACTION_LABELS = {
        "kill_process": "Kill Process",
        "firewall_block": "Block IP (Firewall)",
        "firewall_unblock": "Unblock IP",
        "disable_account": "Disable User Account",
        "quarantine_file": "Quarantine File",
        "isolate_network": "Isolate Machine (Emergency)",
        "restore_network": "Restore Network",
        "forensic_snapshot": "Forensic Snapshot",
    }

    # Params expected for each action (used for validation)
    ACTION_PARAMS = {
        "kill_process": ["pid", "name"],
        "firewall_block": ["ip"],
        "firewall_unblock": ["ip"],
        "disable_account": ["username"],
        "quarantine_file": ["file_path"],
        "isolate_network": [],
        "restore_network": [],
        "forensic_snapshot": [],
    }

    @app.route("/api/response/execute", methods=["POST"])
    def api_response_execute():
        """Execute an incident response action on a specific machine."""
        import traceback as _tb
        try:
            return _api_response_execute_impl()
        except Exception as _exc:
            _tb.print_exc()
            print(f"[RESP] FATAL: {_exc}")
            return jsonify({"success": False, "error": f"Server error: {str(_exc)[:200]}"}), 500

    def _api_response_execute_impl():
        u, err, code = check_auth("api")
        if err:
            return err, code

        data = request.json or {}
        machine_id = data.get("machine_id", "").strip()
        action = data.get("action", "").strip()
        params = data.get("params", {})

        # Validate
        if not machine_id:
            return jsonify({"success": False, "error": "Missing machine_id"}), 400
        if action not in ACTION_MAP:
            return jsonify({"success": False, "error": f"Unknown action: {action}. Valid: {list(ACTION_MAP.keys())}"}), 400
        if not isinstance(params, dict):
            return jsonify({"success": False, "error": "params must be a JSON object"}), 400

        # Validate required params
        required = ACTION_PARAMS.get(action, [])
        for p in required:
            if p not in params or not params[p]:
                return jsonify({"success": False, "error": f"Missing required param: {p}"}), 400

        # Check machine exists and is online
        machines = core.db.get_machines()
        machine = next((m for m in machines if m["machine_id"] == machine_id), None)
        if not machine:
            return jsonify({"success": False, "error": f"Machine {machine_id} not found"}), 404
        if not machine.get("is_online"):
            return jsonify({"success": False, "error": f"Machine {machine.get('hostname', machine_id)} is offline"}), 400

        # Build command for agent
        exec_id = f"resp_{int(time.time())}_{machine_id[:8]}"
        agent_action = ACTION_MAP[action]

        cmd_data = {
            "action": agent_action,
            "exec_id": exec_id,
            "params": params,
        }

        # v3.9.12: Pull Model - Queue command, mark sent to avoid HTTP poll duplicate
        core.db.add_command(machine_id, agent_action, json.dumps({"params": params}, ensure_ascii=False), exec_id)
        
        # Mark sent immediately - TCP will deliver, if it fails revert to pending
        try:
            core.db.conn.execute("UPDATE commands SET status='sent' WHERE exec_id=?", (exec_id,))
            core.db.conn.commit()
        except Exception:
            pass

        # Try TCP push as best-effort
        tcp_sent = False
        if core.tcp_server:
            try:
                tcp_sent = core.tcp_server.send_command(machine_id, cmd_data)
                if tcp_sent:
                    print(f"[RESP] TCP push SUCCESS for {machine_id}")
            except Exception:
                pass

        # If TCP failed, revert to pending so HTTP poll picks it up
        if not tcp_sent:
            try:
                core.db.conn.execute("UPDATE commands SET status='pending' WHERE exec_id=?", (exec_id,))
                core.db.conn.commit()
                print(f"[RESP] TCP push FAILED for {machine_id} (will rely on HTTP poll)")
            except Exception:
                pass

        # Log the action
        action_label = ACTION_LABELS.get(action, action)
        param_summary = ", ".join(f"{k}={v}" for k, v in params.items())
        username = u if isinstance(u, str) else u.get("username", "system")
        core.db.insert_audit_log(
            username,
            "response_execute",
            f"{action_label} on {machine.get('hostname', machine_id)} ({machine_id}) | Params: {param_summary}",
            request.remote_addr or "",
        )

        return jsonify({
            "success": True,
            "exec_id": exec_id,
            "machine_id": machine_id,
            "hostname": machine.get("hostname", machine_id),
            "action": action,
            "params": params,
            "message": f"✅ Sent {action_label} command to {machine.get('hostname', machine_id)}. Tracking ID: {exec_id}",
        })

    @app.route("/api/response/actions", methods=["GET"])
    def api_response_actions():
        """List available response actions."""
        _, err, code = check_auth("api")
        if err:
            return err, code

        actions = []
        for action_name, agent_action in ACTION_MAP.items():
            actions.append({
                "action": action_name,
                "label": ACTION_LABELS.get(action_name, action_name),
                "params": ACTION_PARAMS.get(action_name, []),
                "severity_suitable": _get_severity_suitability(action_name),
            })

        return jsonify({"success": True, "actions": actions})


def _get_severity_suitability(action_name):
    """Return which severity levels this action is suitable for."""
    critical_only = ["isolate_network", "restore_network"]
    high_plus = ["firewall_block", "firewall_unblock", "disable_account"]
    all_levels = ["kill_process", "quarantine_file", "forensic_snapshot"]

    if action_name in critical_only:
        return ["CRITICAL"]
    elif action_name in high_plus:
        return ["CRITICAL", "HIGH"]
    return ["CRITICAL", "HIGH", "MEDIUM", "LOW"]