"""GIAM-SAT forensic API - v5.0.8 (Phase B: cây tiến trình + hồ sơ điều tra).

    GET    /api/forensics/process-tree/<machine_id>?hours=&root_pid=&limit=
    POST   /api/forensics/evidence      create + store a packet (+ optional case)
    GET    /api/forensics/evidence      list stored packets (metadata only)
    GET    /api/forensics/evidence/<id>?fmt=html|json   view / download a packet
    DELETE /api/forensics/evidence/<id>
    POST   /api/forensics/render        preview a packet without storing it

Reads require the "api" permission, writes the stronger "command" permission and
append to the audit log. All heavy lifting lives in ../forensics.py.
"""

from datetime import datetime, timedelta

from flask import Response, jsonify, request

import forensics as fo

from .api_common import check_auth

_YEARS_HOURS = 24 * 365


def _int(arg, default, lo, hi):
    try:
        value = int(arg)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, value))


def _window(hours):
    if not hours:
        return None, None
    end_dt = datetime.now()
    return ((end_dt - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S"),
            end_dt.strftime("%Y-%m-%d %H:%M:%S"))


def register(app, core):
    @app.route("/api/forensics/process-tree/<machine_id>")
    def api_forensics_process_tree(machine_id):
        """Parent -> children process tree for one machine."""
        _, err, code = check_auth("api")
        if err:
            return err, code
        hours = _int(request.args.get("hours"), 24, 0, _YEARS_HOURS)
        start, end = _window(hours)
        try:
            records = fo.collect_process_records(
                core.db, machine_id, start, end,
                _int(request.args.get("limit"), 2000, 1, 5000))
            tree = fo.build_process_tree(
                records, root_pid=request.args.get("root_pid"),
                max_nodes=_int(request.args.get("max_nodes"), 600, 20, 2000))
        except Exception as e:
            return jsonify({"error": str(e)[:200], "roots": [], "flat": [], "stats": {}})
        tree["machine_id"] = machine_id
        tree["hours"] = hours
        return jsonify(tree)

    @app.route("/api/forensics/evidence", methods=["POST"])
    def api_forensics_evidence_create():
        """Collect +/- N minutes around an anchor and store the packet."""
        username, err, code = check_auth("command")
        if err:
            return err, code
        body = request.json or {}
        machine_id = str(body.get("machine_id") or "").strip()
        if not machine_id:
            return jsonify({"success": False, "error": "machine_id là bắt buộc"}), 400
        payload = fo.collect_evidence(
            core.db, machine_id,
            anchor=body.get("anchor"),
            window_minutes=_int(body.get("window_minutes"), 15, 1, 720),
            title=str(body.get("title") or "")[:200],
            created_by=username,
        )
        evidence_id = fo.save_evidence(core.db, payload, created_by=username,
                                       case_id=body.get("case_id"),
                                       alert_id=body.get("alert_id"))
        if evidence_id is None:
            return jsonify({"success": False, "error": "không lưu được hồ sơ"}), 500
        if hasattr(core.db, "insert_audit_log"):
            core.db.insert_audit_log(username, "evidence_create",
                                     "evidence #%s for %s" % (evidence_id, machine_id),
                                     request.remote_addr)
        return jsonify({"success": True, "id": evidence_id, "machine_id": machine_id,
                        "anchor": payload.get("anchor"),
                        "window_minutes": payload.get("window", {}).get("minutes"),
                        "counts": payload.get("counts"),
                        "sha256": payload.get("integrity", {}).get("sha256"),
                        "process_stats": payload.get("process_tree", {}).get("stats")})

    @app.route("/api/forensics/evidence")
    def api_forensics_evidence_list():
        _, err, code = check_auth("api")
        if err:
            return err, code
        items = fo.list_evidence(core.db, machine_id=request.args.get("machine_id"),
                                 limit=_int(request.args.get("limit"), 100, 1, 500))
        return jsonify({"items": items, "count": len(items)})

    @app.route("/api/forensics/evidence/<int:evidence_id>")
    def api_forensics_evidence_view(evidence_id):
        _, err, code = check_auth("api")
        if err:
            return err, code
        payload = fo.load_evidence(core.db, evidence_id)
        if not payload:
            return jsonify({"error": "không tìm thấy hồ sơ #%d" % evidence_id}), 404
        if (request.args.get("fmt") or "json").strip().lower() == "html":
            return Response(fo.render_html(payload), mimetype="text/html; charset=utf-8",
                            headers={"Content-Disposition":
                                     'inline; filename="giamsat-evidence-%d.html"' % evidence_id})
        return jsonify(payload)

    @app.route("/api/forensics/evidence/<int:evidence_id>", methods=["DELETE"])
    def api_forensics_evidence_delete(evidence_id):
        username, err, code = check_auth("command")
        if err:
            return err, code
        ok = fo.delete_evidence(core.db, evidence_id)
        if ok and hasattr(core.db, "insert_audit_log"):
            core.db.insert_audit_log(username, "evidence_delete",
                                     "removed evidence #%d" % evidence_id, request.remote_addr)
        return jsonify({"success": ok})

    @app.route("/api/forensics/render", methods=["POST"])
    def api_forensics_render():
        """Preview a packet WITHOUT storing it (fmt=html for the printable view)."""
        username, err, code = check_auth("api")
        if err:
            return err, code
        body = request.json or {}
        machine_id = str(body.get("machine_id") or "").strip()
        if not machine_id:
            return jsonify({"error": "machine_id là bắt buộc"}), 400
        payload = fo.collect_evidence(
            core.db, machine_id, anchor=body.get("anchor"),
            window_minutes=_int(body.get("window_minutes"), 15, 1, 720),
            title=str(body.get("title") or "")[:200], created_by=username,
            include_tree=body.get("include_tree", True) is not False)
        if (request.args.get("fmt") or "json").strip().lower() == "html":
            return Response(fo.render_html(payload), mimetype="text/html; charset=utf-8")
        return jsonify(payload)
