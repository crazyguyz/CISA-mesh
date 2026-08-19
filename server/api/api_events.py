"""
API Events - Events, FIM, Syslog, Responses, Stats, SSE Stream.
"""

import json
import time
import threading
from flask import request, jsonify, Response

from .api_common import check_auth
import os

# v4.10 (MED-5): cap concurrent SSE connections - each one holds a thread in
# Waitress (threads=16) and a disconnected client was never detected before.
_SSE_MAX_CONNECTIONS = int(os.environ.get("GIAMSAT_SSE_MAX", "8"))
_sse_count = 0
_sse_lock = threading.Lock()


def register(app, core):
    """Register event-related routes."""

    @app.route("/api/events")
    def api_events():
        _, err, code = check_auth("api")
        if err: return err, code
        since_h = request.args.get("since")
        since_hours = int(since_h) if since_h and since_h.isdigit() and int(since_h) > 0 else None
        return jsonify(core.db.get_events(
            machine_id=request.args.get("machine_id"),
            event_type=request.args.get("event_type"),
            limit=request.args.get("limit", 100, type=int),
            since_hours=since_hours
        ))

    @app.route("/api/fim")
    def api_fim():
        _, err, code = check_auth("api")
        if err: return err, code
        return jsonify(core.db.get_fim_events(
            machine_id=request.args.get("machine_id"),
            limit=request.args.get("limit", 100, type=int)
        ))

    @app.route("/api/syslog")
    def api_syslog():
        _, err, code = check_auth("api")
        if err: return err, code
        return jsonify(core.db.get_syslog(
            limit=request.args.get("limit", 100, type=int),
            facility=request.args.get("facility"),
            severity=request.args.get("severity"),
            source_ip=request.args.get("source_ip"),
            search=request.args.get("search"),
        ))

    @app.route("/api/responses")
    def api_responses():
        _, err, code = check_auth("api")
        if err: return err, code
        return jsonify(core.db.get_response_results(
            machine_id=request.args.get("machine_id"),
            limit=request.args.get("limit", 100, type=int)
        ))

    @app.route("/api/stats")
    def api_stats():
        _, err, code = check_auth("api")
        if err: return err, code
        return jsonify(core.db.get_stats(machine_id=request.args.get("machine_id")))

    @app.route("/api/event_types")
    def api_event_types():
        _, err, code = check_auth("api")
        if err: return err, code
        return jsonify(core.db.get_event_types(machine_id=request.args.get("machine_id")))

    @app.route("/api/events/stream")
    def api_events_stream():
        _, err, code = check_auth("api")
        if err:
            return Response(f"data: {json.dumps({'error': 'Authentication required'})}\n\n",
                            mimetype="text/event-stream")

        # v4.10 (MED-5): limit concurrent SSE connections
        global _sse_count
        with _sse_lock:
            if _sse_count >= _SSE_MAX_CONNECTIONS:
                print(f"[!] SSE: connection limit reached ({_SSE_MAX_CONNECTIONS}), rejecting")
                return jsonify({"error": "too many SSE connections"}), 503
            _sse_count += 1

        def event_stream():
            global _sse_count
            last_sent = 0
            try:
                while True:
                    with core.sse_queue_lock:
                        if len(core.sse_queue) > last_sent:
                            new_events = core.sse_queue[last_sent:]
                            last_sent = len(core.sse_queue)
                        else:
                            new_events = []
                    if new_events:
                        data = json.dumps(new_events, ensure_ascii=False)
                        yield f"data: {data}\n\n"
                    else:
                        yield "data: []\n\n"
                    time.sleep(2)
            except GeneratorExit:
                pass
            finally:
                # v4.10 (MED-5): release the slot when the client disconnects
                with _sse_lock:
                    global _sse_count
                    _sse_count = max(0, _sse_count - 1)

        return Response(event_stream(), mimetype="text/event-stream",
                        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    @app.route("/api/network")
    def api_network():
        _, err, code = check_auth("api")
        if err: return err, code
        since_h = request.args.get("since")
        since_hours = int(since_h) if since_h and since_h.isdigit() and int(since_h) > 0 else None
        return jsonify(core.db.get_network_traffic(
            machine_id=request.args.get("machine_id"),
            limit=request.args.get("limit", 100, type=int),
            since_hours=since_hours
        ))

    # v2.6.2: Sysmon events from SysmonCollector
    @app.route("/api/sysmon")
    def api_sysmon():
        _, err, code = check_auth("api")
        if err: return err, code
        since_h = request.args.get("since")
        since_hours = int(since_h) if since_h and since_h.isdigit() and int(since_h) > 0 else None
        return jsonify(core.db.get_sysmon_events(
            machine_id=request.args.get("machine_id"),
            limit=request.args.get("limit", 200, type=int),
            since_hours=since_hours,
            event_type=request.args.get("event_type")
        ))

    # v2.6.2: Memory scan events from MemoryScanner
    @app.route("/api/memory")
    def api_memory():
        _, err, code = check_auth("api")
        if err: return err, code
        since_h = request.args.get("since")
        since_hours = int(since_h) if since_h and since_h.isdigit() and int(since_h) > 0 else None
        return jsonify(core.db.get_sysmon_events(
            machine_id=request.args.get("machine_id"),
            limit=request.args.get("limit", 200, type=int),
            since_hours=since_hours,
            event_type="memory_scan_event"
        ))

    # v4.11 (MED): /api/hunt/result, /api/hunt/campaigns, /api/hunt/templates are
    # registered ONLY in api_hunt.py - the duplicates that used to live here
    # shadowed them (dead code) and have been removed.
    # v3.2: IOC Sweep
    @app.route("/api/ioc/sweep", methods=["POST"])
    def api_ioc_sweep():
        _, err, code = check_auth("api")
        if err: return err, code

        from ioc_sweeper import IOCSweeper
        sweeper = IOCSweeper(core.db)

        # Option 1: Upload file (CSV or JSON)
        uploaded_file = request.files.get("file")
        # Option 2: JSON body with iocs array
        body_json = request.get_json(silent=True) or {}

        if uploaded_file and uploaded_file.filename:
            fmt = "csv" if uploaded_file.filename.endswith(".csv") else "json"
            content = uploaded_file.read().decode("utf-8")
            results = sweeper.sweep_from_file(content, file_format=fmt)
        elif body_json.get("iocs"):
            iocs = body_json["iocs"]
            tables = body_json.get("tables", None)
            results = sweeper.sweep(iocs, tables=tables)
        else:
            return jsonify({"error": "No IOC file or JSON body provided"}), 400

        return jsonify({
            "status": "ok",
            "matches": len(results),
            "results": results[:500],  # Limit response size
            "stats": sweeper.get_stats(),
        })

    # v3.1: Sigma Rules Import
    @app.route("/api/rules/import-sigma", methods=["POST"])
    def api_import_sigma():
        _, err, code = check_auth("settings")
        if err: return err, code

        MAX_UPLOAD = 1_000_000  # 1MB
        if request.content_length and request.content_length > MAX_UPLOAD:
            return jsonify({"error": "Upload quá lớn (tối đa 1MB)"}), 413

        from sigma_parser import SigmaParser
        parser = SigmaParser()

        # Option 1: Upload .yml/.yaml file
        uploaded_file = request.files.get("file")
        # Option 2: Raw YAML in POST body
        raw_yaml = request.form.get("yaml") or (request.data.decode("utf-8") if request.data else "")

        rules = []
        if uploaded_file and uploaded_file.filename:
            # Save temp, parse, delete
            tmp_path = os.path.join(os.path.dirname(__file__), "..", "_sigma_upload.tmp")
            try:
                uploaded_file.save(tmp_path)
                rules = parser.parse_file(tmp_path)
                os.remove(tmp_path)
            except Exception as e:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
                return jsonify({"error": f"Failed to parse uploaded file: {e}"}), 400
        elif raw_yaml:
            rules = parser.parse_yaml(raw_yaml)
        else:
            return jsonify({"error": "No file or YAML provided. Use 'file' upload or 'yaml' form field."}), 400

        if not rules:
            return jsonify({"error": "No valid Sigma rules found"}), 400
        if "error" in rules[0]:
            return jsonify({"error": rules[0]["error"]}), 400

        # Append rules to correlation_rules.yaml
        rules_path = os.path.join(os.path.dirname(__file__), "..", "rules", "correlation_rules.yaml")
        try:
            import yaml as _yaml
            with open(rules_path, "r", encoding="utf-8") as f:
                existing = _yaml.safe_load(f) or {}

            existing_rules = existing.get("rules", [])
            existing_ids = {r["id"] for r in existing_rules if isinstance(r, dict) and "id" in r}

            imported_count = 0
            skipped_count = 0
            for rule in rules:
                if isinstance(rule, dict) and "id" in rule:
                    if rule["id"] in existing_ids:
                        skipped_count += 1
                        continue
                    existing_rules.append(rule)
                    existing_ids.add(rule["id"])
                    imported_count += 1

            existing["rules"] = existing_rules
            existing["metadata"]["version"] = f"{float(existing.get('metadata', {}).get('version', '2.0').split('.')[0])}.{int(existing.get('metadata', {}).get('version', '2.0').split('.')[1] or '0') + 1}"
            existing["metadata"]["last_updated"] = __import__('datetime').datetime.now().strftime("%Y-%m-%d")

            with open(rules_path, "w", encoding="utf-8") as f:
                _yaml.dump(existing, f, default_flow_style=False, allow_unicode=True, sort_keys=False)

            return jsonify({
                "status": "ok",
                "imported": imported_count,
                "skipped": skipped_count,
                "total_rules": len(existing_rules),
                "stats": parser.get_stats(),
            })
        except Exception as e:
            return jsonify({"error": f"Failed to save rules: {e}"}), 500
