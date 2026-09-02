"""
API Threats - Threats, Vulns, YARA, Network Inspection, SCA.
"""

from flask import request, jsonify
from .api_common import check_auth


def register(app, core):
    """Register threat-related routes."""

    @app.route("/api/threats")
    def api_threats():
        _, err, code = check_auth("api")
        if err: return err, code
        since_h = request.args.get("since")
        since_hours = int(since_h) if since_h and since_h.isdigit() and int(since_h) > 0 else None
        return jsonify(core.db.get_threat_alerts(
            machine_id=request.args.get("machine_id"),
            limit=request.args.get("limit", 100, type=int),
            since_hours=since_hours,
            status=request.args.get("status")
        ))

    @app.route("/api/threats/grouped")
    def api_threats_grouped():
        """v5.0.4 (Phase1 B3): alerts grouped by (rule, window) with machine count."""
        _, err, code = check_auth("api")
        if err: return err, code
        try:
            since_hours = max(1, min(int(request.args.get("since", 24)), 720))
        except (TypeError, ValueError):
            since_hours = 24
        try:
            min_machines = max(1, min(int(request.args.get("min_machines", 2)), 1000))
        except (TypeError, ValueError):
            min_machines = 2
        rows = core.db.get_threat_alerts_grouped(
            since_hours=since_hours,
            min_machines=min_machines,
            status=request.args.get("status"))
        return jsonify({"groups": rows})

    @app.route("/api/threats/<int:threat_id>/status", methods=["POST"])
    def api_threat_status(threat_id):
        """v4.13 (E1): triage status on a threat alert.
        v5.0.4 (Phase1 B1): lifecycle states + audit who/when."""
        username, err, code = check_auth("threat_triage")
        if err: return err, code
        data = request.json or {}
        status = data.get("status", "new")
        if status not in ("new", "in_progress", "investigating", "contained", "resolved", "false_positive"):
            return jsonify({"success": False, "error": "Invalid status"}), 400
        try:
            core.db.set_threat_status(threat_id, status, username)
            core.db.insert_audit_log(username, "threat_status",
                f"Threat #{threat_id} -> {status}", request.remote_addr)
            return jsonify({"success": True})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)[:200]}), 500

    @app.route("/api/threats/<int:threat_id>/assign", methods=["POST"])
    def api_threat_assign(threat_id):
        """v5.0.4 (Phase1 B1): assign an alert to a SOC analyst."""
        username, err, code = check_auth("threat_triage")
        if err: return err, code
        assignee = ((request.json or {}).get("assignee") or "").strip()[:64]
        if not assignee:
            return jsonify({"success": False, "error": "assignee required"}), 400
        try:
            core.db.set_threat_assign(threat_id, assignee, username)
            core.db.insert_audit_log(username, "threat_assign",
                f"Threat #{threat_id} -> {assignee}", request.remote_addr)
            return jsonify({"success": True})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)[:200]}), 500

    @app.route("/api/threats/<int:threat_id>/comment", methods=["POST"])
    def api_threat_comment(threat_id):
        """v5.0.4 (Phase1 B1): add a comment to an alert."""
        username, err, code = check_auth("threat_triage")
        if err: return err, code
        comment = ((request.json or {}).get("comment") or "").strip()[:2000]
        if not comment:
            return jsonify({"success": False, "error": "comment required"}), 400
        try:
            core.db.set_threat_comment(threat_id, comment, username)
            core.db.insert_audit_log(username, "threat_comment",
                f"Threat #{threat_id}: {comment[:80]}", request.remote_addr)
            return jsonify({"success": True})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)[:200]}), 500

    @app.route("/api/vulns")
    def api_vulns():
        _, err, code = check_auth("api")
        if err: return err, code
        since_h = request.args.get("since")
        since_hours = int(since_h) if since_h and since_h.isdigit() and int(since_h) > 0 else None
        return jsonify(core.db.get_vuln_alerts(
            machine_id=request.args.get("machine_id"),
            limit=request.args.get("limit", 100, type=int),
            since_hours=since_hours,
            status=request.args.get("status")
        ))

    @app.route("/api/vulns/<int:alert_id>/status", methods=["POST"])
    def api_vuln_status(alert_id):
        """v4.6.6: triage status on a vulnerability alert (resolved = mitigated/accepted risk)."""
        username, err, code = check_auth("threat_triage")
        if err: return err, code
        status = (request.json or {}).get("status", "new")
        if status not in ("new", "in_progress", "investigating", "contained", "resolved", "false_positive"):
            return jsonify({"success": False, "error": "Invalid status"}), 400
        try:
            core.db.set_vuln_status(alert_id, status)
            core.db.insert_audit_log(username, "vuln_status",
                f"Vuln #{alert_id} -> {status}", request.remote_addr)
            return jsonify({"success": True})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)[:200]}), 500

    @app.route("/api/inspection")
    def api_inspection():
        _, err, code = check_auth("api")
        if err: return err, code
        return jsonify(core.db.get_network_inspection(
            machine_id=request.args.get("machine_id"),
            subtype=request.args.get("subtype"),
            limit=request.args.get("limit", 100, type=int),
            status=request.args.get("status")
        ))

    @app.route("/api/inspection/<int:alert_id>/status", methods=["POST"])
    def api_inspection_status(alert_id):
        """v4.6.6: triage status on a network inspection finding."""
        username, err, code = check_auth("threat_triage")
        if err: return err, code
        status = (request.json or {}).get("status", "new")
        if status not in ("new", "in_progress", "investigating", "contained", "resolved", "false_positive"):
            return jsonify({"success": False, "error": "Invalid status"}), 400
        try:
            core.db.set_inspection_status(alert_id, status)
            core.db.insert_audit_log(username, "inspection_status",
                f"Inspection #{alert_id} -> {status}", request.remote_addr)
            return jsonify({"success": True})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)[:200]}), 500

    @app.route("/api/yara")
    def api_yara():
        _, err, code = check_auth("api")
        if err: return err, code
        since_h = request.args.get("since")
        since_hours = int(since_h) if since_h and since_h.isdigit() and int(since_h) > 0 else None
        return jsonify(core.db.get_yara_alerts(
            machine_id=request.args.get("machine_id"),
            limit=request.args.get("limit", 100, type=int),
            since_hours=since_hours,
            status=request.args.get("status")
        ))

    @app.route("/api/yara/<int:alert_id>/status", methods=["POST"])
    def api_yara_status(alert_id):
        """v4.6.6: triage status on a YARA alert."""
        username, err, code = check_auth("threat_triage")
        if err: return err, code
        status = (request.json or {}).get("status", "new")
        if status not in ("new", "in_progress", "investigating", "contained", "resolved", "false_positive"):
            return jsonify({"success": False, "error": "Invalid status"}), 400
        try:
            core.db.set_yara_status(alert_id, status)
            core.db.insert_audit_log(username, "yara_status",
                f"YARA #{alert_id} -> {status}", request.remote_addr)
            return jsonify({"success": True})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)[:200]}), 500

    @app.route("/api/sca")
    def api_sca():
        _, err, code = check_auth("api")
        if err: return err, code
        return jsonify(core.db.get_sca_events(
            machine_id=request.args.get("machine_id"),
            limit=request.args.get("limit", 100, type=int)
        ))