"""
API Custom Dashboard v2.0.0 - Drag-and-Drop Dashboard Builder
CRUD for custom dashboards + widget schema discovery.

GET  /api/custom-dashboard/list → List saved dashboards
POST /api/custom-dashboard/save  → Save/update a dashboard
POST /api/custom-dashboard/load  → Load a dashboard by name
POST /api/custom-dashboard/delete → Delete a dashboard
GET  /api/custom-dashboard/schema → Data source schema for widget builder
"""
import json
from flask import request, jsonify
from .api_common import check_auth, localize_utc


def register(app, core):
    """Register custom dashboard API routes."""

    @app.route("/api/custom-dashboard/list", methods=["GET"])
    def custom_dashboard_list():
        """List all saved custom dashboards."""
        _, err, code = check_auth("api")
        if err:
            return err, code

        try:
            rows = core.db.conn.execute(
                "SELECT id, name, description, created_by, created_at, updated_at FROM custom_dashboards ORDER BY updated_at DESC"
            ).fetchall()
            dashboards = [dict(r) for r in rows]
            # v4.13: created_at/updated_at stored as UTC - convert to local time
            for d in dashboards:
                d["created_at"] = localize_utc(d.get("created_at"))
                d["updated_at"] = localize_utc(d.get("updated_at"))
            return jsonify({"dashboards": dashboards})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/custom-dashboard/save", methods=["POST"])
    def custom_dashboard_save():
        """Save or update a custom dashboard layout.
        v4.11 (authz): dashboards are SHARED (name-keyed) - viewer must not be
        able to overwrite them -> 'settings' (admin) + audit."""
        username, err, code = check_auth("settings")
        if err:
            return err, code

        data = request.get_json(force=True, silent=True) or {}
        name = (data.get("name") or "").strip()
        if not name:
            return jsonify({"error": "name required"}), 400

        description = data.get("description", "")
        layout_json = json.dumps(data.get("layout", []), ensure_ascii=False)
        widgets_json = json.dumps(data.get("widgets", []), ensure_ascii=False)

        try:
            # Check if dashboard with this name already exists
            existing = core.db.conn.execute(
                "SELECT id FROM custom_dashboards WHERE name=?", (name,)
            ).fetchone()

            if existing:
                core.db.conn.execute(
                    """UPDATE custom_dashboards SET description=?, layout_json=?, widgets_json=?,
                       updated_at=CURRENT_TIMESTAMP WHERE name=?""",
                    (description, layout_json, widgets_json, name)
                )
            else:
                core.db.conn.execute(
                    """INSERT INTO custom_dashboards (name, description, layout_json, widgets_json, created_by)
                       VALUES (?, ?, ?, ?, ?)""",
                    (name, description, layout_json, widgets_json, username or "admin")
                )
            core.db.conn.commit()
            core.db.insert_audit_log(username, "custom_dashboard_save",
                f"Lưu dashboard '{name}'", request.remote_addr)
            return jsonify({"status": "saved", "name": name})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/custom-dashboard/load", methods=["POST"])
    def custom_dashboard_load():
        """Load a dashboard by name."""
        _, err, code = check_auth("api")
        if err:
            return err, code

        data = request.get_json(force=True, silent=True) or {}
        name = (data.get("name") or "").strip()
        if not name:
            return jsonify({"error": "name required"}), 400

        try:
            row = core.db.conn.execute(
                "SELECT * FROM custom_dashboards WHERE name=?", (name,)
            ).fetchone()
            if not row:
                return jsonify({"error": "Dashboard not found"}), 404

            d = dict(row)
            result = {
                "name": d["name"],
                "description": d.get("description", ""),
                "created_by": d.get("created_by", "admin"),
                "created_at": d.get("created_at", ""),
                "updated_at": d.get("updated_at", ""),
            }
            # v4.3.4: PostgreSQL JSONB columns are auto-parsed to dict/list by psycopg2.
            # Only call json.loads() on raw strings.
            layout_raw = d.get("layout_json", [])
            if isinstance(layout_raw, (dict, list)):
                result["layout"] = layout_raw
            elif isinstance(layout_raw, str):
                try:
                    result["layout"] = json.loads(layout_raw)
                except json.JSONDecodeError:
                    result["layout"] = []
            else:
                result["layout"] = []
            
            widgets_raw = d.get("widgets_json", [])
            if isinstance(widgets_raw, (dict, list)):
                result["widgets"] = widgets_raw
            elif isinstance(widgets_raw, str):
                try:
                    result["widgets"] = json.loads(widgets_raw)
                except json.JSONDecodeError:
                    result["widgets"] = []
            else:
                result["widgets"] = []
            return jsonify(result)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/custom-dashboard/delete", methods=["POST"])
    def custom_dashboard_delete():
        """Delete a dashboard by name.
        v4.11 (authz): shared dashboards - viewer must not delete -> 'settings'."""
        username, err, code = check_auth("settings")
        if err:
            return err, code

        data = request.get_json(force=True, silent=True) or {}
        name = (data.get("name") or "").strip()
        if not name:
            return jsonify({"error": "name required"}), 400

        try:
            core.db.conn.execute("DELETE FROM custom_dashboards WHERE name=?", (name,))
            core.db.conn.commit()
            core.db.insert_audit_log(username, "custom_dashboard_delete",
                f"Xóa dashboard '{name}'", request.remote_addr)
            return jsonify({"status": "deleted", "name": name})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/custom-dashboard/schema", methods=["GET"])
    def custom_dashboard_schema():
        """Return data source schema for widget builder UI.
        Lists available data sources and their fields."""
        schema = {
            "sources": [
                {
                    "id": "stats",
                    "label": "Thống kê hệ thống",
                    "endpoint": "/api/stats",
                    "type": "single_object",
                    "widget_types": ["stat", "number"],
                    "fields": [
                        {"name": "online_machines", "label": "Máy Online", "type": "number"},
                        {"name": "offline_machines", "label": "Máy Offline", "type": "number"},
                        {"name": "total_machines", "label": "Tổng máy", "type": "number"},
                        {"name": "events", "label": "Events 24h", "type": "number"},
                        {"name": "threats", "label": "Threats 24h", "type": "number"},
                        {"name": "fim_events", "label": "FIM 24h", "type": "number"},
                        {"name": "syslog", "label": "Syslog 24h", "type": "number"},
                        {"name": "responses", "label": "Responses 24h", "type": "number"},
                    ]
                },
                {
                    "id": "machines",
                    "label": "Danh sách máy trạm",
                    "endpoint": "/api/machines",
                    "type": "array",
                    "widget_types": ["table"],
                    "fields": [
                        {"name": "hostname", "label": "Hostname", "type": "text"},
                        {"name": "ip_address", "label": "IP", "type": "text"},
                        {"name": "platform", "label": "HĐH", "type": "text"},
                        {"name": "version", "label": "Agent version", "type": "text"},
                        {"name": "is_online", "label": "Online", "type": "text"},
                        {"name": "last_seen", "label": "Last seen", "type": "text"},
                    ]
                },
                {
                    "id": "threats",
                    "label": "Threat Alerts",
                    "endpoint": "/api/threats",
                    "type": "array",
                    "widget_types": ["table", "bar_chart", "pie_chart"],
                    "fields": [
                        {"name": "hostname", "label": "Hostname", "type": "text"},
                        {"name": "rule_name", "label": "Rule", "type": "text"},
                        {"name": "severity", "label": "Severity", "type": "text"},
                        {"name": "description", "label": "Description", "type": "text"},
                        {"name": "timestamp", "label": "Time", "type": "text"},
                    ]
                },
                {
                    "id": "events",
                    "label": "Windows Events",
                    "endpoint": "/api/events",
                    "type": "array",
                    "widget_types": ["table"],
                    "fields": [
                        {"name": "hostname", "label": "Hostname", "type": "text"},
                        {"name": "subtype", "label": "Channel", "type": "text"},
                        {"name": "event_id", "label": "Event ID", "type": "text"},
                        {"name": "description", "label": "Description", "type": "text"},
                        {"name": "time", "label": "Time", "type": "text"},
                    ]
                },
                {
                    "id": "vulns",
                    "label": "Vulnerabilities",
                    "endpoint": "/api/vulns",
                    "type": "array",
                    "widget_types": ["table"],
                    "fields": [
                        {"name": "hostname", "label": "Hostname", "type": "text"},
                        {"name": "cve", "label": "CVE", "type": "text"},
                        {"name": "severity", "label": "Severity", "type": "text"},
                        {"name": "software", "label": "Software", "type": "text"},
                        {"name": "description", "label": "Description", "type": "text"},
                        {"name": "timestamp", "label": "Time", "type": "text"},
                    ]
                },
                {
                    "id": "network",
                    "label": "Network Traffic",
                    "endpoint": "/api/network",
                    "type": "array",
                    "widget_types": ["table"],
                    "fields": [
                        {"name": "hostname", "label": "Hostname", "type": "text"},
                        {"name": "src_ip", "label": "Source IP", "type": "text"},
                        {"name": "dst_ip", "label": "Dest IP", "type": "text"},
                        {"name": "dst_port", "label": "Port", "type": "number"},
                        {"name": "protocol", "label": "Protocol", "type": "text"},
                        {"name": "timestamp", "label": "Time", "type": "text"},
                    ]
                },
                {
                    "id": "sysmon",
                    "label": "Sysmon Events",
                    "endpoint": "/api/sysmon",
                    "type": "array",
                    "widget_types": ["table", "bar_chart"],
                    "fields": [
                        {"name": "hostname", "label": "Hostname", "type": "text"},
                        {"name": "sysmon_event_id", "label": "EID", "type": "number"},
                        {"name": "process_name", "label": "Process", "type": "text"},
                        {"name": "severity", "label": "Severity", "type": "text"},
                        {"name": "description", "label": "Description", "type": "text"},
                        {"name": "timestamp", "label": "Time", "type": "text"},
                    ]
                },
                {
                    "id": "yara",
                    "label": "YARA Alerts",
                    "endpoint": "/api/yara",
                    "type": "array",
                    "widget_types": ["table"],
                    "fields": [
                        {"name": "hostname", "label": "Hostname", "type": "text"},
                        {"name": "rule_name", "label": "Rule", "type": "text"},
                        {"name": "file", "label": "File", "type": "text"},
                        {"name": "description", "label": "Description", "type": "text"},
                        {"name": "timestamp", "label": "Time", "type": "text"},
                    ]
                },
            ]
        }
        return jsonify(schema)