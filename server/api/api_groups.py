"""
API Groups - Agent group CRUD, member management, machine-group lookup.
"""

import json
from flask import request, jsonify
from .api_common import check_auth


def register(app, core):
    """Register agent group routes."""

    @app.route("/api/groups", methods=["GET"])
    def api_get_groups():
        _, err, code = check_auth("api")
        if err: return err, code
        return jsonify({"groups": core.db.get_agent_groups()})

    @app.route("/api/groups", methods=["POST"])
    def api_create_group():
        u, err, code = check_auth("settings")
        if err: return err, code
        data = request.json or {}
        name = data.get("name", "").strip()
        if not name:
            return jsonify({"success": False, "error": "Group name required"}), 400
        try:
            gid = core.db.create_agent_group(
                name, data.get("description", ""),
                json.dumps(data.get("config", {}))
            )
            core.db.insert_audit_log(u, "group_create", f"Created group '{name}' (id={gid})", request.remote_addr)
            return jsonify({"success": True, "group_id": gid})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)[:200]}), 400

    @app.route("/api/groups/<int:group_id>", methods=["PUT"])
    def api_update_group(group_id):
        u, err, code = check_auth("settings")
        if err: return err, code
        data = request.json or {}
        cfg = data.get("config")
        ok = core.db.update_agent_group(
            group_id,
            name=data.get("name"),
            description=data.get("description"),
            config_json=json.dumps(cfg) if cfg else None
        )
        if not ok:
            return jsonify({"success": False, "error": "Group not found"}), 404
        core.db.insert_audit_log(u, "group_update", f"Updated group id={group_id}", request.remote_addr)
        return jsonify({"success": True})

    @app.route("/api/groups/<int:group_id>", methods=["DELETE"])
    def api_delete_group(group_id):
        u, err, code = check_auth("settings")
        if err: return err, code
        core.db.delete_agent_group(group_id)
        core.db.insert_audit_log(u, "group_delete", f"Deleted group id={group_id}", request.remote_addr)
        return jsonify({"success": True})

    @app.route("/api/groups/<int:group_id>/members", methods=["POST"])
    def api_add_member(group_id):
        u, err, code = check_auth("settings")
        if err: return err, code
        data = request.json or {}
        machine_id = data.get("machine_id", "")
        if not machine_id:
            return jsonify({"success": False, "error": "machine_id required"}), 400
        core.db.add_machine_to_group(machine_id, group_id)
        core.db.insert_audit_log(u, "group_member_add", f"Added {machine_id} to group {group_id}", request.remote_addr)
        return jsonify({"success": True})

    @app.route("/api/groups/<int:group_id>/members/<machine_id>", methods=["DELETE"])
    def api_remove_member(group_id, machine_id):
        u, err, code = check_auth("settings")
        if err: return err, code
        core.db.remove_machine_from_group(machine_id, group_id)
        core.db.insert_audit_log(u, "group_member_remove", f"Removed {machine_id} from group {group_id}", request.remote_addr)
        return jsonify({"success": True})

    @app.route("/api/machines/<machine_id>/group", methods=["GET"])
    def api_get_machine_group(machine_id):
        _, err, code = check_auth("api")
        if err: return err, code
        g = core.db.get_machine_group(machine_id)
        cfg = core.db.get_group_config(machine_id)
        return jsonify({"group": g, "config": cfg})