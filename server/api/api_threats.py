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
            since_hours=since_hours
        ))

    @app.route("/api/vulns")
    def api_vulns():
        _, err, code = check_auth("api")
        if err: return err, code
        since_h = request.args.get("since")
        since_hours = int(since_h) if since_h and since_h.isdigit() and int(since_h) > 0 else None
        return jsonify(core.db.get_vuln_alerts(
            machine_id=request.args.get("machine_id"),
            limit=request.args.get("limit", 100, type=int),
            since_hours=since_hours
        ))

    @app.route("/api/inspection")
    def api_inspection():
        _, err, code = check_auth("api")
        if err: return err, code
        return jsonify(core.db.get_network_inspection(
            machine_id=request.args.get("machine_id"),
            subtype=request.args.get("subtype"),
            limit=request.args.get("limit", 100, type=int)
        ))

    @app.route("/api/yara")
    def api_yara():
        _, err, code = check_auth("api")
        if err: return err, code
        since_h = request.args.get("since")
        since_hours = int(since_h) if since_h and since_h.isdigit() and int(since_h) > 0 else None
        return jsonify(core.db.get_yara_alerts(
            machine_id=request.args.get("machine_id"),
            limit=request.args.get("limit", 100, type=int),
            since_hours=since_hours
        ))

    @app.route("/api/sca")
    def api_sca():
        _, err, code = check_auth("api")
        if err: return err, code
        return jsonify(core.db.get_sca_events(
            machine_id=request.args.get("machine_id"),
            limit=request.args.get("limit", 100, type=int)
        ))