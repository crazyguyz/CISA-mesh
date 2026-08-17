"""
API Agentless - Agentless device CRUD, events.
"""

import json
from flask import request, jsonify
from .api_common import check_auth


def register(app, core):
    """Register agentless routes."""

    @app.route("/api/agentless")
    def api_agentless():
        _, err, code = check_auth("api")
        if err: return err, code
        try:
            rows = core.db.get_agentless_events(limit=request.args.get("limit", 100, type=int))
        except Exception as e:
            print(f"[-] Agentless API error: {e}")
            return jsonify([])
        result = []
        for row in rows:
            try:
                item = dict(row)
            except Exception:
                item = {}
            # Normalize: PostgreSQL JSONB returns dict, but frontend expects flat fields
            if "data_json" in item:
                dj = item["data_json"]
                if isinstance(dj, dict):
                    # Extract device_name, ip, device_type from data_json if not at top level
                    if not item.get("device_name") and dj.get("device_name"):
                        item["device_name"] = dj["device_name"]
                    if not item.get("ip") and dj.get("ip"):
                        item["ip"] = dj["ip"]
                    if not item.get("device_type") and dj.get("device_type"):
                        item["device_type"] = dj["device_type"]
                    if not item.get("timestamp") and dj.get("timestamp"):
                        item["timestamp"] = dj["timestamp"]
                    # Keep data_json for debug, add flat 'data' field
                    item["data"] = json.dumps(dj, ensure_ascii=False) if isinstance(dj, dict) else str(dj)
                elif isinstance(dj, str):
                    try:
                        parsed = json.loads(dj)
                        item["data"] = dj
                        if not item.get("device_name") and parsed.get("device_name"):
                            item["device_name"] = parsed["device_name"]
                    except Exception:
                        item["data"] = str(dj)
            result.append(item)
        return jsonify(result)

    @app.route("/api/agentless/clear", methods=["POST"])
    def api_agentless_clear():
        _, err, code = check_auth("api")
        if err: return err, code
        deleted = core.db.clear_agentless_events()
        return jsonify({"success": True, "deleted": deleted})

    @app.route("/api/agentless/devices", methods=["GET"])
    def api_agentless_devices():
        _, err, code = check_auth("api")
        if err: return err, code
        sanitized = []
        for d in core.agentless.devices:
            sd = dict(d)
            sd["ssh_password"] = "***" if sd.get("ssh_password") else ""
            sd["ssh_user"] = sd.get("ssh_user", "")
            sd["snmp_community"] = "***" if sd.get("snmp_community") not in ("", "public") else sd.get("snmp_community", "public")
            sanitized.append(sd)
        return jsonify(sanitized)

    @app.route("/api/agentless/devices", methods=["POST"])
    def api_agentless_add_device():
        _, err, code = check_auth("api")
        if err: return err, code
        data = request.json
        if not data or not data.get("name") or not data.get("ip"):
            return jsonify({"success": False, "error": "Thiếu name hoặc ip"}), 400
        core.agentless.add_device(
            name=data.get("name"), ip=data.get("ip"),
            device_type=data.get("device_type", "generic"),
            method=data.get("method", "ping"),
            snmp_community=data.get("snmp_community", "public"),
            ssh_user=data.get("ssh_user", ""),
            ssh_password=data.get("ssh_password", ""),
            interval_seconds=data.get("interval_seconds", 300)
        )
        return jsonify({"success": True, "devices": core.agentless.devices})

    @app.route("/api/agentless/devices/<int:index>", methods=["DELETE"])
    def api_agentless_delete_device(index):
        _, err, code = check_auth("api")
        if err: return err, code
        if 0 <= index < len(core.agentless.devices):
            removed = core.agentless.devices.pop(index)
            core.agentless._save_devices()
            return jsonify({"success": True, "removed": removed, "devices": core.agentless.devices})
        return jsonify({"success": False, "error": "Index không hợp lệ"}), 404