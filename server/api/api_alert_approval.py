"""
v4.0: Alert Approval API for Human-in-the-Loop auto-response.
Receives SOC approval/denial from Telegram webhook or Dashboard.
"""
import json
import time
from flask import request, jsonify

from .api_common import check_auth, check_agent_psk

# In-memory approval queue (key: approval_id, value: {machine_id, action, rule_id, created_at, status})
_pending_approvals = {}
_approval_lock = __import__("threading").Lock()

# v4.10 (MED-1): only these server-issued response actions may be requested for
# approval - an agent (or anyone holding the shared PSK) cannot queue arbitrary
# actions that the SOC then executes on the target machine.
APPROVED_PENDING_ACTIONS = {
    "isolate_network", "restore_network", "kill_process", "quarantine_file",
    "restore_file", "disable_account", "firewall_block", "firewall_unblock",
    "dump_memory",
}


def process_approval(core, callback_data="", approval_id="", action=""):
    """Process an approval/denial action. Returns (result_dict, status_code).
    Shared by the HTTP endpoint (Dashboard) and the Telegram callback poller
    so the poller does not need to go through HTTP (and thus does not rely on
    the removed localhost auth bypass)."""
    if callback_data and not approval_id and not action:
        # Telegram query-string style callback
        approval_id = callback_data
        action = "approve" if "giamsat_approve" in callback_data else "deny"

    if not callback_data and not approval_id:
        return {"error": "callback_data or approval_id required"}, 400

    # Parse Telegram callback: giamsat_approve|machine_id|action|rule_id
    if "|" in callback_data:
        parts = callback_data.split("|")
        if len(parts) >= 3:
            action = "approve" if parts[0] == "giamsat_approve" else "deny"
            machine_id = parts[1]
            pending_action = parts[2]
            matched_id = None
            with _approval_lock:
                for aid, ainfo in _pending_approvals.items():
                    if (ainfo.get("machine_id") == machine_id and
                            ainfo.get("action") == pending_action and
                            ainfo.get("status") == "pending"):
                        matched_id = aid
                        break
            if not matched_id:
                return {"error": "No matching pending approval found"}, 404
            approval_id = matched_id

    if not approval_id:
        return {"error": "approval_id required"}, 400

    with _approval_lock:
        if approval_id not in _pending_approvals:
            return {"error": "Approval not found"}, 404
        ainfo = _pending_approvals[approval_id]
        if ainfo.get("status") != "pending":
            return {"error": f"Already {ainfo.get('status')}"}, 409
        ainfo["status"] = action
        ainfo["resolved_at"] = time.time()

    if action == "approve":
        try:
            cmd = {
                "action": ainfo["action"],
                "machine_id": ainfo["machine_id"],
                "exec_id": f"approved_{approval_id}",
            }
            if ainfo.get("params"):
                cmd["params"] = ainfo["params"]
            if hasattr(core, 'tcp_server') and core.tcp_server:
                core.tcp_server.send_command(ainfo["machine_id"], cmd)
                print(f"[APPROVAL] Executed approved action: {ainfo['action']} on {ainfo['machine_id']}")
            else:
                print(f"[APPROVAL] Cannot execute (no TCP server): {ainfo['action']} on {ainfo['machine_id']}")
        except Exception as e:
            print(f"[-] Approval execution failed: {e}")
            return {"error": f"Execution failed: {e}"}, 500

    return {
        "status": "ok",
        "approval_id": approval_id,
        "action": action,
        "pending_action": ainfo.get("action"),
        "machine_id": ainfo.get("machine_id"),
    }, 200


def register(app, core):
    """Register alert approval API routes."""

    @app.route("/api/alert/pending", methods=["GET"])
    def alert_pending_list():
        """List all pending approval requests."""
        u, err, code = check_auth("api")
        if err:
            return err, code
        with _approval_lock:
            pending = [
                {"id": k, **v, "created_at": str(v.get("created_at", ""))}
                for k, v in _pending_approvals.items()
                if v.get("status") == "pending"
            ]
        return jsonify({"pending": pending})

    @app.route("/api/alert/approve", methods=["POST"])
    def alert_approve():
        """
        Approve or deny a pending action.
        From Dashboard: {"approval_id": "...", "action": "approve|deny"}
        """
        # v4.5.4 SECURITY: require admin auth
        u, err, code = check_auth("settings")
        if err:
            return err, code

        callback_data = request.args.get("callback_data", "")
        approval_id = ""
        action = ""
        if not callback_data:
            data = request.get_json(force=True, silent=True) or {}
            callback_data = data.get("callback_data", "")
            approval_id = data.get("approval_id", "")
            action = data.get("action", "")

        result, status = process_approval(core, callback_data, approval_id, action)
        return jsonify(result), status

    @app.route("/api/alert/add-pending", methods=["POST"])
    def alert_add_pending():
        """
        Add a new pending approval request (called internally by agent_core).
        Body: {"machine_id": "...", "action": "isolate_network", "rule_id": "RANSOM-001", "params": {...}}
        """
        data = request.get_json(force=True, silent=True) or {}
        if not check_agent_psk(data):
            return jsonify({"error": "invalid psk"}), 401
        machine_id = data.get("machine_id", "")
        action = data.get("action", "")
        rule_id = data.get("rule_id", "")
        params = data.get("params", {})
        hostname = data.get("hostname", "")

        if not machine_id or not action:
            return jsonify({"error": "machine_id and action required"}), 400

        # v4.10 (MED-1): only allowlisted actions may be queued for approval
        if action not in APPROVED_PENDING_ACTIONS:
            return jsonify({"error": f"action '{action}' is not allowed for pending approval"}), 400
        # v4.10 (MED-1): target machine must be a registered machine
        try:
            machines = core.db.get_machines() or []
            if not any(m.get("machine_id") == machine_id for m in machines):
                return jsonify({"error": "unknown machine_id"}), 400
        except Exception:
            pass

        approval_id = f"apr_{machine_id}_{action}_{int(time.time())}"
        with _approval_lock:
            _pending_approvals[approval_id] = {
                "machine_id": machine_id,
                "hostname": hostname,
                "action": action,
                "rule_id": rule_id,
                "params": params,
                "status": "pending",
                "created_at": time.time(),
            }
            # Cleanup old entries (> 1 hour)
            now = time.time()
            stale = [k for k, v in _pending_approvals.items() if now - v.get("created_at", 0) > 3600]
            for k in stale:
                del _pending_approvals[k]

        # Notify via alerting engine
        if hasattr(core, 'alerting') and core.alerting:
            try:
                core.alerting.send_alert({
                    "severity": "CRITICAL",
                    "rule_id": rule_id,
                    "rule_name": f"Pending Action: {action}",
                    "hostname": hostname,
                    "machine_id": machine_id,
                    "description": f"SOC approval required for {action} on {hostname}",
                    "confidence_score": data.get("confidence_score", 95),
                    "pending_action": action,
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                })
            except Exception:
                pass

        return jsonify({"status": "pending", "approval_id": approval_id})

    # Auto-deny cleanup thread
    def _auto_deny_cleanup():
        import time as _time
        _time.sleep(30)
        while True:
            _time.sleep(30)
            now = _time.time()
            with _approval_lock:
                for aid, ainfo in list(_pending_approvals.items()):
                    if ainfo.get("status") != "pending":
                        continue
                    timeout = 300  # 5 minutes default
                    if now - ainfo.get("created_at", 0) > timeout:
                        ainfo["status"] = "denied"
                        ainfo["resolved_at"] = now
                        print(f"[APPROVAL] Auto-denied (timeout): {aid} — {ainfo['action']} on {ainfo['machine_id']}")

    import threading
    threading.Thread(target=_auto_deny_cleanup, daemon=True, name="ApprovalCleanup").start()