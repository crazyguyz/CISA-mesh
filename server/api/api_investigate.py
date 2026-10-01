"""GIAM-SAT investigation API - v5.0.8 (Phase A: "điều tra 1 chạm").

    GET    /api/investigate/search?q=&scopes=&hours=&limit=&offset=   unified DSL search
    GET    /api/investigate/entity/<kind>/<value>?hours=&limit=       entity-360 timeline
    GET    /api/investigate/fields                                    scopes/fields hints
    GET    /api/investigate/saved                                     list saved searches
    POST   /api/investigate/saved                                     save/update (name+query)
    DELETE /api/investigate/saved/<id>                                delete
    GET    /api/investigate/export?fmt=csv|json&...                   evidence export

Read-only except the saved-search CRUD. All heavy lifting (query DSL, SQL
building, facets, entity merge) lives in ../search_engine.py so it is testable
without Flask and reusable by the CLI tools.
"""

import json

from flask import Response, jsonify, request

import search_engine as se

from .api_common import check_auth

MAX_LIMIT = 1000
EXPORT_LIMIT = 1000
_YEARS_HOURS = 24 * 365


def scopes_from(arg, default=None):
    """Accept 'a,b' or ['a','b']; keep only known scopes."""
    fallback = list(default if default is not None else se.DEFAULT_SCOPES)
    if arg is None or arg == "":
        return fallback
    items = [str(x) for x in arg] if isinstance(arg, (list, tuple)) else str(arg).split(",")
    keep = [s.strip().lower() for s in items if str(s).strip()]
    keep = [s for s in keep if s in se.SCOPES]
    return keep or fallback


def _int(arg, default, lo, hi):
    try:
        v = int(arg)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, v))


def _truthy(arg):
    return str(arg or "").strip().lower() in ("1", "true", "yes", "on")


def register(app, core):
    @app.route("/api/investigate/search")
    def api_investigate_search():
        """Unified search across alerts/events/sysmon/traffic/netflow/syslog/..."""
        _, err, code = check_auth("api")
        if err:
            return err, code
        scopes = list(se.SCOPES) if _truthy(request.args.get("all_scopes")) \
            else scopes_from(request.args.get("scopes"))
        try:
            out = se.search(
                core.db,
                request.args.get("q", ""),
                scopes=scopes,
                hours=_int(request.args.get("hours"), 24, 0, _YEARS_HOURS),
                limit=_int(request.args.get("limit"), 100, 1, MAX_LIMIT),
                offset=_int(request.args.get("offset"), 0, 0, 100000),
            )
        except Exception as e:  # never 500 on an investigation query
            return jsonify({"error": str(e)[:200], "results": [], "total": 0,
                            "facets": {}, "unknown": []})
        return jsonify(out)

    @app.route("/api/investigate/entity/<kind>/<path:value>")
    def api_investigate_entity(kind, value):
        """Entity-360: everything about one indicator, time ordered."""
        _, err, code = check_auth("api")
        if err:
            return err, code
        scope_arg = request.args.get("scopes")
        scopes = scopes_from(scope_arg, default=list(se.SCOPES)) if scope_arg else list(se.SCOPES)
        try:
            out = se.entity(
                core.db, kind, value, scopes=scopes,
                hours=_int(request.args.get("hours"), 24, 0, _YEARS_HOURS),
                limit=_int(request.args.get("limit"), 300, 1, 2000),
            )
        except Exception as e:
            return jsonify({"error": str(e)[:200], "results": [], "total": 0})
        return jsonify(out)

    @app.route("/api/investigate/fields")
    def api_investigate_fields():
        """Scope + field hints for the UI (autocomplete, printable help)."""
        _, err, code = check_auth("api")
        if err:
            return err, code
        return jsonify({
            "scopes": {k: {"label": v["label"], "table": v["table"]} for k, v in se.SCOPES.items()},
            "fields": se.all_fields(),
            "entity_kinds": list(se.ENTITY_FIELDS),
            "default_scopes": list(se.DEFAULT_SCOPES),
        })

    @app.route("/api/investigate/saved")
    def api_investigate_saved_list():
        _, err, code = check_auth("api")
        if err:
            return err, code
        items = se.list_saved_searches(core.db)
        return jsonify({"items": items, "count": len(items)})

    @app.route("/api/investigate/saved", methods=["POST"])
    def api_investigate_saved_add():
        username, err, code = check_auth("command")
        if err:
            return err, code
        d = request.json or {}
        sid = se.save_search(core.db, d.get("name"), d.get("query"),
                             scopes_from(d.get("scopes")), d.get("hours", 24),
                             created_by=username, shared=d.get("shared", True) is not False)
        if sid is None:
            return jsonify({"success": False, "error": "name và query là bắt buộc"}), 400
        if hasattr(core.db, "insert_audit_log"):
            core.db.insert_audit_log(username, "search_save",
                                     "saved search '%s'" % d.get("name"), request.remote_addr)
        return jsonify({"success": True, "id": sid})

    @app.route("/api/investigate/saved/<int:sid>", methods=["DELETE"])
    def api_investigate_saved_delete(sid):
        username, err, code = check_auth("command")
        if err:
            return err, code
        ok = se.delete_saved_search(core.db, sid)
        if ok and hasattr(core.db, "insert_audit_log"):
            core.db.insert_audit_log(username, "search_delete",
                                     "removed saved search #%d" % sid, request.remote_addr)
        return jsonify({"success": ok})

    @app.route("/api/investigate/export")
    def api_investigate_export():
        """Download the current investigation as CSV (Excel-ready) or JSON."""
        _, err, code = check_auth("api")
        if err:
            return err, code
        fmt = (request.args.get("fmt") or "csv").strip().lower()
        scopes = list(se.SCOPES) if _truthy(request.args.get("all_scopes")) \
            else scopes_from(request.args.get("scopes"))
        out = se.search(
            core.db, request.args.get("q", ""), scopes=scopes,
            hours=_int(request.args.get("hours"), 24, 0, _YEARS_HOURS),
            limit=EXPORT_LIMIT, per_scope=EXPORT_LIMIT,
        )
        rows = out.get("results") or []
        if fmt == "json":
            payload = json.dumps(out, ensure_ascii=False, indent=2)
            return Response(payload, mimetype="application/json",
                            headers={"Content-Disposition":
                                     'attachment; filename="giamsat-investigation.json"'})
        body = "\ufeff" + se.to_csv(rows)   # BOM so Excel opens UTF-8 correctly
        return Response(body, mimetype="text/csv; charset=utf-8",
                        headers={"Content-Disposition":
                                 'attachment; filename="giamsat-investigation.csv"'})
