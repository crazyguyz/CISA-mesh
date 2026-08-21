"""
API Attack Overview - Canvas topology map, Attack Chains, Timeline.
"""

from flask import request, jsonify
from .api_common import check_auth


def register(app, core):
    """Register attack overview routes."""

    @app.route("/api/attack/overview")
    def api_attack_overview():
        _, err, code = check_auth("api")
        if err: return err, code
        try:
            from attack_overview import build_attack_graph
            result = build_attack_graph(core.db)
            return jsonify(result)
        except Exception as e:
            return jsonify({"error": str(e)[:300]}), 500

    @app.route("/api/risk/killchain")
    def api_risk_killchain():
        """v4.13 (P2): per-machine MITRE kill-chain scoring (>= min_tactics distinct
        tactics in the window = incident)."""
        _, err, code = check_auth("api")
        if err: return err, code
        try:
            from attack_overview import risk_killchain
            since_hours = request.args.get("since_hours", 24, type=int)
            min_tactics = request.args.get("min_tactics", 3, type=int)
            return jsonify(risk_killchain(core.db, since_hours=since_hours, min_tactics=min_tactics))
        except Exception as e:
            return jsonify({"error": str(e)[:300]}), 500