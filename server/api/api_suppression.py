"""
API Alert Suppression - v3.8.0: Global Whitelist for False Positive Tuning.
CRUD for suppression rules: suppress alerts by rule_id + optional machine_id/path/hash.
"""
from flask import request, jsonify
from .api_common import check_auth


def register(app, core):
    """Register suppression routes."""

    @app.route("/api/suppression/list", methods=["GET"])
    def api_suppression_list():
        # v4.10 (LOW-1): "admin" is not a valid permission in USER_ROLES - every
        # role (including admin) got 403 and the whole suppression feature was dead.
        _, err, code = check_auth("settings")
        if err: return err, code
        list_data = core.db.get_suppressions()
        return jsonify({"suppressions": list_data})

    @app.route("/api/suppression/add", methods=["POST"])
    def api_suppression_add():
        # v4.10 (LOW-1): see list endpoint - "admin" permission does not exist
        username, err, code = check_auth("settings")
        if err: return err, code
        data = request.json or {}
        rule_id = data.get("rule_id", "").strip()
        if not rule_id:
            return jsonify({"error": "rule_id is required"}), 400
        sid = core.db.add_suppression(
            rule_id=rule_id,
            machine_id=data.get("machine_id") or None,
            field_path=data.get("field_path") or None,
            field_hash=data.get("field_hash") or None,
            reason=data.get("reason", ""),
            created_by=data.get("created_by", "admin")
        )
        core.db.insert_audit_log(username, "suppression_add",
            f"Thêm luật suppression rule='{rule_id}' machine='{data.get('machine_id') or ''}' (id={sid})",
            request.remote_addr)
        return jsonify({"success": True, "id": sid})

    @app.route("/api/suppression/remove/<int:suppression_id>", methods=["POST"])
    def api_suppression_remove(suppression_id):
        # v4.10 (LOW-1): see list endpoint - "admin" permission does not exist
        username, err, code = check_auth("settings")
        if err: return err, code
        core.db.remove_suppression(suppression_id)
        core.db.insert_audit_log(username, "suppression_remove",
            f"Xóa luật suppression id={suppression_id}", request.remote_addr)
        return jsonify({"success": True})