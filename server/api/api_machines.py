"""
API Machines - Machine management, isolate/unisolate, stop, delete, rename, config.
"""

import json
import time
from flask import request, jsonify

from .api_common import check_auth


def register(app, core):
    """Register machine-related routes."""

    @app.route("/api/machines")
    def api_machines():
        _, err, code = check_auth("api")
        if err: return err, code
        machines = core.db.get_machines()
        user_info_map = {u["machine_id"]: u for u in core.db.get_all_machine_users()}
        uptime_map = core.db.get_all_machine_uptime_today()
        for m in machines:
            uid = m.get("machine_id", "")
            u = user_info_map.get(uid)
            if u:
                m["user_name"] = u.get("user_name", "")
                m["employee_id"] = u.get("employee_id", "")
                m["email"] = u.get("email", "")
            else:
                m["user_name"] = ""
                m["employee_id"] = ""
                m["email"] = ""
            ut = uptime_map.get(uid, {})
            m["uptime_hours"] = ut.get("uptime_hours", 0.0) if ut else 0.0
            m["uptime_alert_24h"] = (ut.get("uptime_hours", 0) >= 24) if ut else False
        return jsonify(machines)

    @app.route("/api/machines/summary")
    def api_machines_summary():
        """v2.5.22: Lightweight endpoint: machines + alert counts in 1 query.
        Replaces 3 separate API calls (threats/vulns/yara) for the network graph."""
        _, err, code = check_auth("api")
        if err: return err, code
        machines = core.db.get_machines()
        alert_counts = core.db.get_alert_counts_by_machine()
        user_info_map = {u["machine_id"]: u for u in core.db.get_all_machine_users()}
        uptime_map = core.db.get_all_machine_uptime_today()
        for m in machines:
            uid = m.get("machine_id", "")
            ac = alert_counts.get(uid, {})
            m["alert_threats"] = ac.get("threats", 0)
            m["alert_vulns"] = ac.get("vulns", 0)
            m["alert_yara"] = ac.get("yara", 0)
            u = user_info_map.get(uid)
            m["user_name"] = u.get("user_name", "") if u else ""
            m["employee_id"] = u.get("employee_id", "") if u else ""
            m["email"] = u.get("email", "") if u else ""
            ut = uptime_map.get(uid, {})
            m["uptime_hours"] = ut.get("uptime_hours", 0.0) if ut else 0.0
            m["uptime_alert_24h"] = (ut.get("uptime_hours", 0) >= 24) if ut else False
        return jsonify(machines)

    @app.route("/api/machines/<machine_id>/user", methods=["GET"])
    def api_get_machine_user(machine_id):
        _, err, code = check_auth("api")
        if err: return err, code
        u = core.db.get_machine_user(machine_id)
        return jsonify(u if u else {})

    @app.route("/api/machine-users", methods=["GET"])
    def api_all_machine_users():
        _, err, code = check_auth("api")
        if err: return err, code
        return jsonify(core.db.get_all_machine_users())

    @app.route("/api/machine/<machine_id>/config")
    def api_machine_config(machine_id):
        _, err, code = check_auth("api")
        if err: return err, code
        current = core.db.get_hardware_info(machine_id)
        baseline = core.db.get_baseline(machine_id)
        if current:
            result = dict(current)
            if baseline:
                result["baseline_data"] = baseline.get("data", {})
                result["baseline_saved_at"] = baseline.get("saved_at", "")
                result["diffs"] = core.db._compute_diff(baseline.get("data", {}), current.get("data", {}))
            else:
                result["baseline_data"] = None
                result["diffs"] = []
            return jsonify(result)
        return jsonify(None)

    @app.route("/api/machine/<machine_id>/rename", methods=["POST"])
    def api_machine_rename(machine_id):
        _, err, code = check_auth("api")
        if err: return err, code
        data = request.json
        if data.get("name"):
            core.db.update_machine_hostname(machine_id, data["name"])
            return jsonify({"success": True})
        return jsonify({"success": False}), 400

    @app.route("/api/machine/<machine_id>/events")
    def api_machine_events(machine_id):
        _, err, code = check_auth("api")
        if err: return err, code
        events = core.db.get_events(machine_id=machine_id, limit=request.args.get("limit", 50, type=int))
        fim = core.db.get_fim_events(machine_id=machine_id, limit=50)
        return jsonify({"events": events, "fim": fim})

    @app.route("/api/command", methods=["POST"])
    def api_command_wrapper():
        username, err, code = check_auth("command")
        if err: return err, code
        data = request.json
        machine_id = (data.get("machine_id") or "").strip()
        action = (data.get("action") or "").strip()
        command = data.get("command", "")
        import uuid as _uuid
        exec_id = data.get("exec_id") or f"cmd_{int(time.time())}_{_uuid.uuid4().hex[:6]}"
        # v4.10: queue as 'pending' so the agent HTTP poll can deliver over unstable
        # (Tailscale) links; TCP push is best-effort (half-open sockets can silently
        # swallow the sendall without an error).
        try:
            core.db.add_command(machine_id, action, command, exec_id)
        except Exception as e:
            print(f"[-] api_command add_command failed: {e}")
        success = False
        if core.tcp_server:
            success = core.tcp_server.send_command(
                machine_id,
                {"action": action, "command": command, "exec_id": exec_id}
            )
        core.db.insert_audit_log(username, "send_command",
                                 f"Machine: {machine_id} Action: {action}",
                                 request.remote_addr)
        return jsonify({"success": success, "exec_id": exec_id})

    @app.route("/api/machine/<machine_id>/isolate", methods=["POST"])
    def api_machine_isolate(machine_id):
        username, err, code = check_auth("command")
        if err: return err, code
        server_ip = request.host.split(":")[0] if ":" in request.host else request.host
        if server_ip in ("127.0.0.1", "localhost", "0.0.0.0"):
            machines = core.db.get_machines()
            for m in machines:
                if m.get("machine_id") == machine_id:
                    server_ip = m.get("ip_address", "192.168.1.1")
                    break
            if server_ip in ("127.0.0.1", "localhost", "0.0.0.0"):
                server_ip = "192.168.1.1"
        # v4.5.5 SECURITY: use dedicated isolate_network action (no arbitrary PowerShell).
        # server_ip is passed as a param and sanitized on the agent side (no shell injection).
        # v4.10: queue as 'pending' first so HTTP poll can deliver if TCP push fails.
        import uuid as _uuid
        exec_id = f"isolate_{int(time.time())}_{_uuid.uuid4().hex[:6]}"
        try:
            core.db.add_command(machine_id, "isolate_network",
                                json.dumps({"server_ip": server_ip}), exec_id)
        except Exception as e:
            print(f"[-] isolate add_command failed: {e}")
        success = core.tcp_server.send_command(
            machine_id,
            {"action": "isolate_network", "exec_id": exec_id,
             "params": {"server_ip": server_ip}}
        )
        core.db.insert_audit_log(username, "isolate_machine", f"Machine: {machine_id} (isolated by admin)", request.remote_addr)
        return jsonify({"success": success, "message": "Isolate command sent to agent" if success else "Agent offline"})

    @app.route("/api/machine/<machine_id>/unisolate", methods=["POST"])
    def api_machine_unisolate(machine_id):
        username, err, code = check_auth("command")
        if err: return err, code
        # v4.5.5 SECURITY: use dedicated restore_network action (no arbitrary PowerShell).
        # v4.10: queue as 'pending' first so HTTP poll can deliver if TCP push fails.
        import uuid as _uuid
        exec_id = f"unisolate_{int(time.time())}_{_uuid.uuid4().hex[:6]}"
        try:
            core.db.add_command(machine_id, "restore_network",
                                json.dumps({}), exec_id)
        except Exception as e:
            print(f"[-] unisolate add_command failed: {e}")
        success = core.tcp_server.send_command(
            machine_id,
            {"action": "restore_network", "exec_id": exec_id}
        )
        core.db.insert_audit_log(username, "unisolate_machine", f"Machine: {machine_id} (isolation removed)", request.remote_addr)
        return jsonify({"success": success, "message": "Unisolate command sent" if success else "Agent offline"})

    @app.route("/api/machine/<machine_id>/notes", methods=["POST"])
    def api_machine_notes(machine_id):
        username, err, code = check_auth("api")
        if err: return err, code
        data = request.get_json(force=True, silent=True) or {}
        notes = (data.get("notes") or "")[:500]
        try:
            core.db.conn.execute("UPDATE machines SET notes=? WHERE machine_id=?", (notes, machine_id))
            core.db.conn.commit()
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500
        core.db.insert_audit_log(username, "update_notes", f"Machine: {machine_id}", request.remote_addr)
        return jsonify({"success": True, "notes": notes})

    @app.route("/api/machine/<machine_id>/stop", methods=["POST"])
    def api_machine_stop(machine_id):
        username, err, code = check_auth("command")
        if err: return err, code
        core.db.machine_offline(machine_id)
        core.tcp_server.disconnect_client(machine_id)
        core.db.insert_audit_log(username, "stop_machine", f"Machine: {machine_id}", request.remote_addr)
        return jsonify({"success": True})

    @app.route("/api/machine/<machine_id>/delete", methods=["POST"])
    def api_machine_delete(machine_id):
        username, err, code = check_auth("delete")
        if err: return err, code
        core.tcp_server.disconnect_client(machine_id)
        core.db.delete_machine(machine_id)
        core.db.insert_audit_log(username, "delete_machine", f"Machine: {machine_id}", request.remote_addr)
        return jsonify({"success": True})