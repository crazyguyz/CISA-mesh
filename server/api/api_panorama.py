"""
API Panorama - Server panoramic dashboard data.
"""

from flask import jsonify
from .api_common import check_auth


def register(app, core):
    """Register panorama routes."""

    @app.route("/api/panorama")
    def api_panorama():
        _, err, code = check_auth("api")
        if err: return err, code
        try:
            data = core.panorama.get_full_panorama()
            return jsonify(data)
        except Exception as e:
            return jsonify({"error": str(e)[:300]}), 500

    @app.route("/api/server/resources")
    def api_server_resources():
        _, err, code = check_auth("api")
        if err: return err, code
        return jsonify(core.panorama.get_resources())

    @app.route("/api/server/attack-stats")
    def api_server_attack_stats():
        _, err, code = check_auth("api")
        if err: return err, code
        return jsonify(core.panorama.get_attack_stats())

    @app.route("/api/server/db-stats")
    def api_server_db_stats():
        _, err, code = check_auth("api")
        if err: return err, code
        return jsonify(core.panorama.get_db_stats())

    @app.route("/api/server/agent-fleet")
    def api_server_agent_fleet():
        _, err, code = check_auth("api")
        if err: return err, code
        return jsonify(core.panorama.get_agent_fleet_stats())