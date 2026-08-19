"""
API endpoints for Threat Hunting module.
POST /api/hunt/start   - Start a new hunting campaign with AI-powered hypothesis parsing
GET  /api/hunt/result/<campaign_id> - Get campaign results
GET  /api/hunt/campaigns - List all campaigns
GET  /api/hunt/templates - List available tactic templates
GET  /api/hunt/stats - Hunting statistics
"""

from flask import request, jsonify
from .api_common import check_auth


def register(app, core):
    """Register threat hunting API routes."""

    # Lazy-init hunting engine (singleton)
    _hunting = None

    def get_hunting():
        nonlocal _hunting
        if _hunting is None:
            try:
                from hunting_engine import HuntingEngine
                _hunting = HuntingEngine(core.db)
            except ImportError:
                _hunting = None
        return _hunting

    @app.route("/api/hunt/start", methods=["POST"])
    def hunt_start():
        """Start a new hunting campaign.
        Body: {hypothesis, tactic?, since_hours?, use_ai?}
        """
        username, err, code = check_auth("delete")
        if err: return err, code
        hunting = get_hunting()
        if not hunting:
            return jsonify({"error": "Hunting engine not available"}), 500

        data = request.get_json(silent=True) or {}
        hypothesis = data.get("hypothesis", "").strip()
        if not hypothesis:
            return jsonify({"error": "hypothesis is required"}), 400

        tactic = data.get("tactic", None)
        since_hours = int(data.get("since_hours", 168))
        use_ai = data.get("use_ai", True)

        try:
            result = hunting.start_campaign(
                hypothesis=hypothesis,
                tactic=tactic,
                since_hours=since_hours,
                use_ai=use_ai,
            )
            core.db.insert_audit_log(username, "hunt_start",
                f"Chạy chiến dịch hunting: '{hypothesis[:120]}' (since={since_hours}h, AI={use_ai})",
                request.remote_addr)
            return jsonify(result)
        except Exception as e:
            return jsonify({"error": f"Failed to start campaign: {str(e)}"}), 500

    @app.route("/api/hunt/result/<campaign_id>", methods=["GET"])
    def hunt_result(campaign_id):
        """Get results of a specific hunting campaign."""
        _, err, code = check_auth("api")
        if err: return err, code
        hunting = get_hunting()
        if not hunting:
            return jsonify({"error": "Hunting engine not available"}), 500

        result = hunting.get_campaign(campaign_id)
        if not result:
            return jsonify({"error": "Campaign not found"}), 404
        return jsonify(result)

    @app.route("/api/hunt/campaigns", methods=["GET"])
    def hunt_campaigns():
        """List all hunting campaigns."""
        _, err, code = check_auth("api")
        if err: return err, code
        hunting = get_hunting()
        if not hunting:
            return jsonify({"error": "Hunting engine not available"}), 500

        return jsonify(hunting.list_campaigns())

    @app.route("/api/hunt/templates", methods=["GET"])
    def hunt_templates():
        """Get available hypothesis templates (tactics)."""
        _, err, code = check_auth("api")
        if err: return err, code
        hunting = get_hunting()
        if not hunting:
            return jsonify({"error": "Hunting engine not available"}), 500

        return jsonify(hunting.get_templates())

    @app.route("/api/hunt/stats", methods=["GET"])
    def hunt_stats():
        """Get hunting engine statistics."""
        _, err, code = check_auth("api")
        if err: return err, code
        hunting = get_hunting()
        if not hunting:
            return jsonify({"error": "Hunting engine not available"}), 500

        return jsonify(hunting.get_stats())