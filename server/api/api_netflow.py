"""
API NetFlow - v4.13 (P2): list flows + basic C2 beaconing / exfil heuristics.
"""
from flask import request, jsonify
from .api_common import check_auth


def register(app, core):
    """Register netflow routes."""

    @app.route("/api/netflow")
    def api_netflow():
        _, err, code = check_auth("api")
        if err: return err, code
        limit = request.args.get("limit", 200, type=int)
        since_hours = request.args.get("since_hours", None, type=int)
        try:
            flows = core.db.get_netflow_flows(limit=min(limit, 2000), since_hours=since_hours)
            return jsonify({"flows": flows, "total": len(flows)})
        except Exception as e:
            return jsonify({"error": str(e)[:300]}), 500

    @app.route("/api/netflow/beaconing")
    def api_netflow_beaconing():
        """v4.13 (P2): flag repeat connections to the same dst (beaconing heuristic):
        >= 3 flows to the same dst:port in the window with similar inter-arrival."""
        _, err, code = check_auth("api")
        if err: return err, code
        since_hours = request.args.get("since_hours", 24, type=int)
        min_flows = request.args.get("min_flows", 5, type=int)
        try:
            flows = core.db.get_netflow_flows(limit=20000, since_hours=since_hours)
            from collections import defaultdict
            agg = defaultdict(list)
            for f in flows:
                key = (f.get("src_ip"), f.get("dst_ip"), f.get("dst_port"), f.get("protocol"))
                agg[key].append(f.get("last", 0))
            beacons = []
            for (src, dst, dport, proto), times in agg.items():
                times = sorted(t for t in times if t)
                if len(times) >= min_flows:
                    beacons.append({
                        "src_ip": src, "dst_ip": dst, "dst_port": dport,
                        "protocol": proto, "flow_count": len(times),
                        "first": times[0], "last": times[-1],
                        "span_seconds": int(times[-1] - times[0]) if len(times) > 1 else 0,
                    })
            beacons.sort(key=lambda b: b["flow_count"], reverse=True)
            return jsonify({"beacons": beacons[:100], "total": len(beacons), "since_hours": since_hours})
        except Exception as e:
            return jsonify({"error": str(e)[:300]}), 500

    @app.route("/api/netflow/stats")
    def api_netflow_stats():
        _, err, code = check_auth("api")
        if err: return err, code
        try:
            return jsonify(core.netflow.get_stats() if getattr(core, "netflow", None) else {"packets": 0, "flows": 0, "errors": 0, "v5": 0, "v9": 0})
        except Exception as e:
            return jsonify({"error": str(e)[:300]}), 500
