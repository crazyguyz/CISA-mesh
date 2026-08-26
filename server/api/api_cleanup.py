"""
API endpoints for Data Cleanup (v3.2).
POST /api/cleanup      - Delete old data by type + days
GET  /api/cleanup/summary - Get data summary for cleanup UI
"""

from flask import request, jsonify
from .api_common import check_auth


def register(app, core):
    """Register data cleanup API routes."""

    @app.route("/api/cleanup/summary", methods=["GET"])
    def cleanup_summary():
        """Get summary of data sizes for cleanup UI."""
        _, err, code = check_auth("api")
        if err: return err, code
        try:
            summary = core.db.get_data_summary()
            return jsonify({"success": True, "data": summary})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    @app.route("/api/cleanup", methods=["POST"])
    def cleanup_data():
        """
        Delete old data from specified tables.
        Body: {
            "types": ["events", "network_traffic", ...],
            "days": 30,
            "keep_threats": true
        }
        """
        username, err, code = check_auth("delete")
        if err: return err, code
        data = request.get_json(silent=True) or {}
        types = data.get("types", None)  # None = all
        days = int(data.get("days", 30))
        keep_threats = data.get("keep_threats", True)

        if days < 1:
            return jsonify({"success": False, "error": "Số ngày phải >= 1"}), 400

        try:
            deleted = core.db.cleanup_old_data(
                retention_days=days,
                types=types,
                keep_threats=keep_threats
            )
            total = sum(deleted.values())

            # Run VACUUM after large deletes
            if total > 10000:
                try:
                    core.db.vacuum()
                except:
                    pass

            # Audit log (v5.0.2: use the actual logged-in user, not hardcoded 'admin')
            try:
                core.db.insert_audit_log(
                    username=username or "admin",
                    action="manual_cleanup",
                    details=f"Deleted {total} records older than {days} days. "
                            + ", ".join(f"{k}={v}" for k, v in deleted.items() if v > 0)
                )
            except:
                pass

            return jsonify({
                "success": True,
                "deleted": deleted,
                "total": total,
                "message": f"Deleted {total} records from {len([k for k,v in deleted.items() if v > 0])} table(s)"
            })
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500