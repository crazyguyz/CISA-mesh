"""
API Analytics (v5.0.4 Phase2 A7/B2 + Phase3 B4).
  GET /api/risk/hosts     -> per-host risk score 0-100 (severity-weighted, decayed)
  GET /api/cases          -> case list (auto-clustered or manual)
  GET /api/cases/<id>     -> case detail
  POST /api/cases/<id>/status
  GET /api/search?q=      -> global search (machines/alerts/events) for Ctrl+K
"""

import json
from flask import request, jsonify
from .api_common import check_auth


def _alert_ids(v):
    """v5.0.4 R9 (MEDIUM-2): SQLite stores alert_ids as TEXT '[1,2]' -> json.loads;
    PG returns a JSONB column pre-parsed as a Python list -> json.loads(list) raises
    TypeError (silently swallowed to []). Handle both shapes."""
    if isinstance(v, list):
        return v
    try:
        x = json.loads(v or "[]")
        return x if isinstance(x, list) else []
    except Exception:
        return []


def register(app, core):
    @app.route("/api/risk/hosts")
    def api_risk_hosts():
        _, err, code = check_auth("api")
        if err: return err, code
        try:
            since = max(1, min(int(request.args.get("since", 168)), 720))
        except (TypeError, ValueError):
            since = 168
        scores = core.db.get_risk_scores(since_hours=since) or {}
        ranked = sorted(scores.items(), key=lambda kv: kv[1]["score"], reverse=True)
        return jsonify({"hosts": [{"machine_id": k, **v} for k, v in ranked], "since_hours": since})

    @app.route("/api/cases")
    def api_cases():
        _, err, code = check_auth("api")
        if err: return err, code
        try:
            limit = max(1, min(int(request.args.get("limit", 100)), 1000))
        except (TypeError, ValueError):
            limit = 100
        rows = core.db.list_cases(limit=limit, status=request.args.get("status")) or []
        for r in rows:
            r["alert_ids"] = _alert_ids(r.get("alert_ids"))
        return jsonify({"cases": rows})

    @app.route("/api/cases", methods=["POST"])
    def api_create_case():
        """v5.0.4 R9 (LOW): manual case creation (the docstring always promised it).
        analyst/admin can group alerts of a host into a case by hand."""
        username, err, code = check_auth("threat_triage")
        if err: return err, code
        d = request.json or {}
        machine_id = (d.get("machine_id") or "").strip()[:64]
        title = (d.get("title") or "").strip()[:200]
        description = (d.get("description") or "").strip()[:2000]
        severity = str(d.get("severity") or "MEDIUM").upper()
        if severity not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            severity = "MEDIUM"
        if not machine_id or not title:
            return jsonify({"success": False, "error": "machine_id + title required"}), 400
        try:
            hostname = (d.get("hostname") or "").strip()[:128] or machine_id
            alert_ids = [int(x) for x in (d.get("alert_ids") or []) if str(x).isdigit()][:500]
            case_id = core.db.create_case(machine_id, hostname, title, description,
                                          severity, alert_ids, created_by=username)
            core.db.insert_audit_log(username, "case_create", f"Case #{case_id} '{title}'", request.remote_addr)
            return jsonify({"success": True, "case_id": case_id})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)[:200]}), 500

    @app.route("/api/cases/<int:case_id>")
    def api_case_detail(case_id):
        _, err, code = check_auth("api")
        if err: return err, code
        # v5.0.4 R9: direct lookup instead of scanning list_cases(limit=1000) -
        # a case outside the newest 1000 returned 404 even though it exists.
        c = core.db.get_case(case_id) if hasattr(core.db, "get_case") else None
        if not c:
            for _c in (core.db.list_cases(limit=100000) or []):
                if _c.get("id") == case_id:
                    c = _c
                    break
        if c:
            c["alert_ids"] = _alert_ids(c.get("alert_ids"))
            return jsonify(c)
        return jsonify({"error": "case not found"}), 404

    @app.route("/api/cases/<int:case_id>/status", methods=["POST"])
    def api_case_status(case_id):
        username, err, code = check_auth("threat_triage")
        if err: return err, code
        status = (request.json or {}).get("status", "open")
        if status not in ("open", "investigating", "contained", "closed", "false_positive"):
            return jsonify({"success": False, "error": "invalid status"}), 400
        try:
            core.db.set_case_status(case_id, status)
            core.db.insert_audit_log(username, "case_status", f"Case #{case_id} -> {status}", request.remote_addr)
            return jsonify({"success": True})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)[:200]}), 500

    @app.route("/api/search")
    def api_search():
        _, err, code = check_auth("api")
        if err: return err, code
        q = (request.args.get("q") or "").strip()[:100]
        if not q:
            return jsonify({"machines": [], "alerts": [], "events": []})
        try:
            limit = max(1, min(int(request.args.get("limit", 25)), 100))
        except (TypeError, ValueError):
            limit = 25
        return jsonify(core.db.search_all(q, limit=limit))
