"""
Group Policies API v1.0.0 for GIAM-SAT Server v3.9.2
REST API for managing per-group security policies:
  - block_websites: Block specific websites via hosts file + firewall
  - block_software: Block software installation via registry policies
  - block_usb: Block USB storage devices via registry
"""
import json
from datetime import datetime
from flask import request, jsonify
from .api_common import check_auth

_POLICY_TYPES = ["block_websites", "block_software", "block_usb"]

def register_routes(app, server_core):
    """Register all policy API routes with the Flask app."""

    @app.route("/api/policies/add", methods=["POST"])
    def api_policy_add():
        """Add a new policy to a group."""
        username, err, code = check_auth("delete")
        if err: return err, code
        data = request.get_json() or {}
        group_id = data.get("group_id")
        policy_type = data.get("policy_type", "")
        policy_name = data.get("policy_name", "")
        config = data.get("config", {})

        if not group_id:
            return jsonify({"success": False, "error": "group_id is required"}), 400
        if policy_type not in _POLICY_TYPES:
            return jsonify({"success": False, "error": f"Invalid policy_type. Must be one of: {_POLICY_TYPES}"}), 400

        try:
            policy_id = server_core.db.add_policy(
                group_id=int(group_id),
                policy_type=policy_type,
                policy_name=policy_name or f"{policy_type} - {datetime.now().strftime('%H:%M')}",
                config_json=json.dumps(config, ensure_ascii=False)
            )
            server_core.db.insert_audit_log(username, "policy_add",
                f"Tạo policy '{policy_name or policy_type}' cho group {group_id} (id={policy_id})",
                request.remote_addr)
            return jsonify({"success": True, "policy_id": policy_id, "message": "Policy created"})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    @app.route("/api/policies/update/<int:policy_id>", methods=["POST"])
    def api_policy_update(policy_id):
        """Update an existing policy (resets to pending)."""
        username, err, code = check_auth("delete")
        if err: return err, code
        data = request.get_json() or {}
        policy_name = data.get("policy_name")
        config = data.get("config")
        enabled = data.get("enabled")

        config_json = json.dumps(config, ensure_ascii=False) if config is not None else None
        ok = server_core.db.update_policy(
            policy_id,
            policy_name=policy_name,
            config_json=config_json,
            enabled=enabled
        )
        if not ok:
            return jsonify({"success": False, "error": "Policy not found"}), 404
        server_core.db.insert_audit_log(username, "policy_update",
            f"Cập nhật policy id={policy_id} (name='{policy_name}', enabled={enabled})",
            request.remote_addr)
        return jsonify({"success": True, "message": "Policy updated, status reset to pending"})

    @app.route("/api/policies/delete/<int:policy_id>", methods=["POST"])
    def api_policy_delete(policy_id):
        """Delete a policy."""
        username, err, code = check_auth("delete")
        if err: return err, code
        server_core.db.delete_policy(policy_id)
        server_core.db.insert_audit_log(username, "policy_delete",
            f"Xóa policy id={policy_id}", request.remote_addr)
        return jsonify({"success": True, "message": "Policy deleted"})

    @app.route("/api/policies/list")
    def api_policy_list():
        """List policies, optionally filtered by group_id."""
        _, err, code = check_auth("api")
        if err: return err, code
        group_id = request.args.get("group_id", type=int)
        policies = server_core.db.get_policies(group_id=group_id)
        for p in policies:
            try:
                p["config"] = json.loads(p.get("config_json", "{}"))
            except Exception:
                p["config"] = {}
            del p["config_json"]
        return jsonify({"success": True, "policies": policies})

    @app.route("/api/policies/get/<int:policy_id>")
    def api_policy_get(policy_id):
        """Get a single policy by ID."""
        _, err, code = check_auth("api")
        if err: return err, code
        p = server_core.db.get_policy(policy_id)
        if not p:
            return jsonify({"success": False, "error": "Policy not found"}), 404
        try:
            p["config"] = json.loads(p.get("config_json", "{}"))
        except Exception:
            p["config"] = {}
        del p["config_json"]
        return jsonify({"success": True, "policy": p})

    @app.route("/api/policies/status", methods=["POST"])
    def api_policy_status():
        """Update policy apply status (called by agent after applying)."""
        _, err, code = check_auth("api")
        if err: return err, code
        data = request.get_json() or {}
        policy_id = data.get("policy_id")
        status = data.get("status", "applied")
        message = data.get("message", "")

        if not policy_id:
            return jsonify({"success": False, "error": "policy_id is required"}), 400
        if status not in ("applied", "failed"):
            return jsonify({"success": False, "error": "Invalid status"}), 400

        server_core.db.update_policy_status(policy_id, status, message)
        return jsonify({"success": True, "message": f"Policy status updated to {status}"})

    @app.route("/api/policies/pending/<machine_id>")
    def api_policy_pending(machine_id):
        """Get pending policies for a specific machine."""
        _, err, code = check_auth("api")
        if err: return err, code
        policies = server_core.db.get_pending_policies_for_machine(machine_id)
        for p in policies:
            try:
                p["config"] = json.loads(p.get("config_json", "{}"))
            except Exception:
                p["config"] = {}
            del p["config_json"]
        return jsonify({"success": True, "pending": policies})