"""
API Dashboard v1.0.0 - Dashboard Template Engine
Supports listing, rendering, and previewing dashboard templates.

GET  /api/dashboard/list         → List all available templates
GET  /api/dashboard/render?name= → Render a template to HTML+Chart.js
POST /api/dashboard/import       → Import a template JSON
"""
import json
import os
from flask import request, jsonify
from .api_common import check_auth
from dashboard_templates import get_engine, TEMPLATE_DIR


def register(app, core):
    """Register dashboard API routes."""

    @app.route("/api/dashboard/list", methods=["GET"])
    def dashboard_list():
        """List all available dashboard templates."""
        _, err, code = check_auth("api")
        if err:
            return err, code

        try:
            engine = get_engine()
            templates = engine.list_templates()
            return jsonify({"templates": templates, "count": len(templates)})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/dashboard/render", methods=["GET"])
    def dashboard_render():
        """Render a dashboard template to HTML. Returns HTML string.
        Query params: ?name=Tổng quan hệ thống"""
        _, err, code = check_auth("api")
        if err:
            return err, code

        name = request.args.get("name", "").strip()
        if not name:
            return jsonify({"error": "name parameter required"}), 400

        try:
            engine = get_engine()
            html = engine.render_html(name, core.db)
            return html, 200, {"Content-Type": "text/html; charset=utf-8"}
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/dashboard/import", methods=["POST"])
    def dashboard_import():
        """Import a new dashboard template JSON."""
        username, err, code = check_auth("api")
        if err:
            return err, code

        data = request.get_json(force=True, silent=True) or {}
        name = (data.get("name") or "").strip()
        if not name:
            return jsonify({"error": "name required"}), 400

        # Validate minimum structure
        if "panels" not in data:
            return jsonify({"error": "panels array required"}), 400

        # Sanitize filename
        safe_name = name.lower().replace(" ", "_").replace("/", "_")[:50]
        if not safe_name.endswith(".json"):
            safe_name += ".json"

        filepath = os.path.join(TEMPLATE_DIR, safe_name)
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

            # Reload engine to pick up new template
            engine = get_engine()
            engine._load_all_templates()

            return jsonify({
                "status": "imported",
                "name": name,
                "filename": safe_name,
            })
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/dashboard/delete", methods=["POST"])
    def dashboard_delete():
        """Delete a dashboard template by name."""
        username, err, code = check_auth("api")
        if err:
            return err, code

        data = request.get_json(force=True, silent=True) or {}
        name = (data.get("name") or "").strip()
        if not name:
            return jsonify({"error": "name required"}), 400

        engine = get_engine()
        tpl = engine.get_template(name)
        if not tpl:
            return jsonify({"error": "Template not found"}), 404

        try:
            os.remove(tpl.filepath)
            engine._load_all_templates()
            return jsonify({"status": "deleted", "name": name})
        except Exception as e:
            return jsonify({"error": str(e)}), 500