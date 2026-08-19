"""
API Agent Update - Agent version check, download, push update, reset user.
"""

import json
import os
import time
import uuid
from flask import request, jsonify, send_file

from .api_common import check_auth, check_agent_psk


def register(app, core):
    """Register agent update routes."""

    _AGENT_BUILD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "dist")

    @app.route("/api/agent/version")
    def api_agent_version():
        _, err, code = check_auth("api")
        if err: return err, code
        return jsonify({"version": core.db.get_server_agent_version()})

    @app.route("/api/agent/version", methods=["POST"])
    def api_agent_check_version():
        data = request.json or {}
        if not check_agent_psk(data):
            return jsonify({"error": "invalid psk"}), 401
        agent_version = data.get("version", "0.0.0")
        server_version = core.db.get_server_agent_version()
        update_available = agent_version != server_version
        return jsonify({
            "update_available": update_available,
            "current_version": agent_version,
            "server_version": server_version,
            "download_url": "/api/agent/download" if update_available else None
        })

    @app.route("/api/agent/download")
    def api_agent_download():
        if not check_agent_psk():
            return jsonify({"error": "invalid psk"}), 401
        exe_path = None
        exe_name = "GiamSatAgent.exe"
        candidate = os.path.join(_AGENT_BUILD_DIR, exe_name)
        if os.path.exists(candidate):
            exe_path = candidate
        else:
            if os.path.isdir(_AGENT_BUILD_DIR):
                for f in sorted(os.listdir(_AGENT_BUILD_DIR), reverse=True):
                    if f.startswith("GiamSatAgent") and f.endswith(".exe"):
                        exe_path = os.path.join(_AGENT_BUILD_DIR, f)
                        exe_name = f
                        break
        if not exe_path or not os.path.exists(exe_path):
            return jsonify({"error": "Agent executable not found on server"}), 404
        machine_id = request.headers.get("X-Machine-ID", "") or request.args.get("machine_id", "unknown")
        core.db.insert_agent_update_log(
            machine_id, "", "",
            core.db.get_server_agent_version(), "downloading",
            "Agent downloading update", "auto"
        )
        import hashlib as _hashlib
        _sha = _hashlib.sha256()
        with open(exe_path, "rb") as _f:
            for _chunk in iter(lambda: _f.read(65536), b""):
                _sha.update(_chunk)
        # v4.10 (CRITICAL-1): sign the file hash with command_key so the agent can
        # reject a MITM that forges X-File-SHA256 on the plaintext download.
        # v4.11 (CRITICAL-1 FIX): the signature is MANDATORY - fail-closed, never
        # serve an unsigned EXE (a MITM could otherwise strip the sig header and
        # ship a forged hash+EXE pair that would pass agent verification).
        import hmac as _hmac, os as _os
        _cmd_key = _os.environ.get("GIAMSAT_COMMAND_KEY", "").strip()
        if not _cmd_key:
            return jsonify({"error": "GIAMSAT_COMMAND_KEY not configured - unsigned downloads rejected (fail-closed)"}), 503
        resp = send_file(exe_path, as_attachment=True, download_name=exe_name)
        resp.headers["X-File-SHA256"] = _sha.hexdigest()
        resp.headers["X-File-Sig"] = _hmac.new(
            _cmd_key.encode("utf-8"), _sha.hexdigest().encode("utf-8"), _hashlib.sha256
        ).hexdigest()
        return resp

    @app.route("/api/agent/update-log", methods=["GET"])
    def api_agent_update_log():
        _, err, code = check_auth("api")
        if err: return err, code
        machine_id = request.args.get("machine_id", None)
        limit = request.args.get("limit", 100, type=int)
        return jsonify(core.db.get_agent_update_logs(machine_id=machine_id, limit=limit))

    @app.route("/api/agent/update-report", methods=["POST"])
    def api_agent_update_report():
        data = request.json or {}
        if not check_agent_psk(data):
            return jsonify({"error": "invalid psk"}), 401
        core.db.insert_agent_update_log(
            data.get("machine_id", ""),
            data.get("hostname", ""),
            data.get("from_version", ""),
            data.get("to_version", ""),
            data.get("status", "unknown"),
            data.get("message", ""),
            data.get("source", "agent")
        )
        # v3.3.5 FIX: Do NOT update machines.version here.
        # Version is synced from agent's heartbeat/register (real version from agent).
        return jsonify({"success": True})

    @app.route("/api/agent/push-update", methods=["POST"])
    def api_agent_push_update():
        u, err, code = check_auth("settings")
        if err: return err, code
        data = request.json or {}
        group_id = data.get("group_id")
        target_machine_id = data.get("machine_id")
        server_version = core.db.get_server_agent_version()
        results = {"success": [], "failed": []}

        if target_machine_id:
            machine = core.db.get_machines()
            machine_info = next((m for m in machine if m["machine_id"] == target_machine_id), None)
            hostname = machine_info["hostname"] if machine_info else target_machine_id
            if core.tcp_server.send_command(target_machine_id, {
                "action": "agent_update",
                "version": server_version,
                "exec_id": f"update_{uuid.uuid4().hex[:12]}"
            }):
                core.db.insert_agent_update_log(
                    target_machine_id, hostname,
                    machine_info.get("version", "?") if machine_info else "?",
                    server_version, "pending", "Push update initiated by admin", "push"
                )
                results["success"].append({"machine_id": target_machine_id, "hostname": hostname})
            else:
                core.db.insert_agent_update_log(
                    target_machine_id, hostname,
                    machine_info.get("version", "?") if machine_info else "?",
                    server_version, "failed", "Agent offline or unreachable", "push"
                )
                results["failed"].append({"machine_id": target_machine_id, "hostname": hostname, "reason": "Agent offline"})
        elif group_id:
            group = core.db.get_agent_group(group_id)
            if not group:
                return jsonify({"success": False, "error": "Group not found"}), 404
            for member in group.get("members", []):
                mid = member["machine_id"]
                hostname = member.get("hostname", mid)
                machine = core.db.get_machines()
                machine_info = next((m for m in machine if m["machine_id"] == mid), None)
                if core.tcp_server.send_command(mid, {
                    "action": "agent_update",
                    "version": server_version,
                    "exec_id": f"update_{uuid.uuid4().hex[:12]}_{mid[:8]}"
                }):
                    core.db.insert_agent_update_log(
                        mid, hostname,
                        machine_info.get("version", "?") if machine_info else "?",
                        server_version, "pending", "Push update initiated by admin", "push"
                    )
                    results["success"].append({"machine_id": mid, "hostname": hostname})
                else:
                    results["failed"].append({"machine_id": mid, "hostname": hostname, "reason": "Agent offline"})
        else:
            return jsonify({"success": False, "error": "Specify group_id or machine_id"}), 400

        core.db.insert_audit_log(u, "agent_push_update",
                                 f"Push update to {len(results['success'])} agents (version {server_version})",
                                 request.remote_addr)
        return jsonify({
            "success": True,
            "version": server_version,
            "pushed": len(results["success"]),
            "failed": len(results["failed"]),
            "details": results
        })

    @app.route("/api/agent/reset-user", methods=["POST"])
    def api_agent_reset_user():
        u, err, code = check_auth("settings")
        if err: return err, code
        data = request.json or {}
        group_id = data.get("group_id")
        target_machine_id = data.get("machine_id")
        results = {"success": [], "failed": []}

        if target_machine_id:
            machine = core.db.get_machines()
            machine_info = next((m for m in machine if m["machine_id"] == target_machine_id), None)
            hostname = machine_info["hostname"] if machine_info else target_machine_id
            if core.tcp_server.send_command(target_machine_id, {
                "action": "reset_user",
                "exec_id": f"reset_{int(time.time())}"
            }):
                try:
                    core.db.conn.execute("DELETE FROM machine_users WHERE machine_id = ?", (target_machine_id,))
                    core.db.conn.commit()
                except Exception:
                    pass
                results["success"].append({"machine_id": target_machine_id, "hostname": hostname})
            else:
                results["failed"].append({"machine_id": target_machine_id, "hostname": hostname, "reason": "Agent offline"})
        elif group_id:
            group = core.db.get_agent_group(group_id)
            if not group:
                return jsonify({"success": False, "error": "Group not found"}), 404
            for member in group.get("members", []):
                mid = member["machine_id"]
                hostname = member.get("hostname", mid)
                if core.tcp_server.send_command(mid, {
                    "action": "reset_user",
                    "exec_id": f"reset_{int(time.time())}_{mid[:8]}"
                }):
                    try:
                        core.db.conn.execute("DELETE FROM machine_users WHERE machine_id = ?", (mid,))
                        core.db.conn.commit()
                    except Exception:
                        pass
                    results["success"].append({"machine_id": mid, "hostname": hostname})
                else:
                    results["failed"].append({"machine_id": mid, "hostname": hostname, "reason": "Agent offline"})
        else:
            return jsonify({"success": False, "error": "Specify group_id or machine_id"}), 400

        core.db.insert_audit_log(u, "agent_reset_user",
                                 f"Reset user info for {len(results['success'])} agents",
                                 request.remote_addr)
        return jsonify({
            "success": True,
            "message": f"Reset command sent to {len(results['success'])} agents",
            "pushed": len(results["success"]),
            "failed": len(results["failed"]),
            "details": results
        })