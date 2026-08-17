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