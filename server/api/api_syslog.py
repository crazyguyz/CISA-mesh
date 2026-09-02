"""GIAM-SAT v5.0.4 (Phase3 improvement #1): syslog device -> asset mapping + FW
block <-> agent-event correlation.

  GET  /api/syslog/sources                     auto-learned syslog devices
  POST /api/syslog/sources                     manual add a source
  POST /api/syslog/sources/<ip>/asset          map device IP -> agent machine_id
  DELETE /api/syslog/sources/<ip>
  GET  /api/syslog/correlation?machine_id=..   firewall blocks about a host's IP
                                               + that machine's agent events in the
                                               same window (lateral movement pivot)
"""

from flask import request, jsonify
from .api_common import check_auth


def register(app, core):
    @app.route("/api/syslog/sources")
    def api_syslog_sources():
        _, err, code = check_auth("api")
        if err: return err, code
        srcs = core.db.list_syslog_sources() if hasattr(core.db, "list_syslog_sources") else []
        machines = {}
        try:
            for m in (core.db.get_machines() or []):
                machines[str(m.get("machine_id") or "")] = m.get("hostname") or m.get("machine_id")
        except Exception:
            pass
        out = []
        for s in srcs:
            d = dict(s) if not isinstance(s, dict) else dict(s)
            d["asset_hostname"] = machines.get(str(d.get("machine_id") or ""), "")
            out.append(d)
        return jsonify({"sources": out, "machines": [{"machine_id": k, "hostname": v} for k, v in machines.items()]})

    @app.route("/api/syslog/sources", methods=["POST"])
    def api_syslog_sources_add():
        username, err, code = check_auth("command")
        if err: return err, code
        d = request.json or {}
        ip = (d.get("source_ip") or "").strip()
        if not ip:
            return jsonify({"success": False, "error": "source_ip required"}), 400
        ok = core.db.upsert_syslog_source(ip, d.get("hostname", ""), d.get("device_type", ""))
        if ok:
            core.db.set_syslog_source_asset(ip, d.get("machine_id", ""), d.get("label", ""))
            core.db.insert_audit_log(username, "syslog_source_add", f"source {ip}", request.remote_addr)
        return jsonify({"success": ok})

    @app.route("/api/syslog/sources/<source_ip>/asset", methods=["POST"])
    def api_syslog_sources_asset(source_ip):
        username, err, code = check_auth("command")
        if err: return err, code
        d = request.json or {}
        ok = core.db.set_syslog_source_asset(source_ip, d.get("machine_id", ""), d.get("label", ""))
        if ok:
            core.db.insert_audit_log(username, "syslog_source_asset",
                                     f"map {source_ip} -> {d.get('machine_id', '')}", request.remote_addr)
        return jsonify({"success": ok})

    @app.route("/api/syslog/sources/<source_ip>", methods=["DELETE"])
    def api_syslog_sources_delete(source_ip):
        username, err, code = check_auth("command")
        if err: return err, code
        ok = core.db.delete_syslog_source(source_ip)
        if ok:
            core.db.insert_audit_log(username, "syslog_source_delete", f"source {source_ip}", request.remote_addr)
        return jsonify({"success": ok})

    @app.route("/api/syslog/correlation")
    def api_syslog_correlation():
        """Pivot: a managed host's IP appears in firewall block syslog alerts
        (FW-*) AND the agent is reporting events from the same machine - show both
        side by side for the window so SOC can judge lateral movement/egress."""
        _, err, code = check_auth("api")
        if err: return err, code
        machine_id = (request.args.get("machine_id") or "").strip()
        if not machine_id:
            return jsonify({"error": "machine_id required"}), 400
        try:
            hours = max(1, min(int(request.args.get("hours", 6)), 72))
        except (TypeError, ValueError):
            hours = 6
        machine = None
        try:
            for m in (core.db.get_machines() or []):
                if str(m.get("machine_id") or "") == machine_id:
                    machine = m
                    break
        except Exception:
            machine = None
        if not machine:
            return jsonify({"error": "machine not found"}), 404
        ip = str(machine.get("ip_address") or "")
        blocks = core.db.get_firewall_alerts_about_ip(ip, hours=hours) if (hasattr(core.db, "get_firewall_alerts_about_ip") and ip) else []
        events = []
        if hasattr(core.db, "get_events"):
            try:
                events = core.db.get_events(machine_id=machine_id, since_hours=hours, limit=200) or []
            except Exception:
                events = []
        summary = {
            "machine_id": machine_id,
            "hostname": machine.get("hostname") or machine_id,
            "ip": ip,
            "window_hours": hours,
            "firewall_blocks": len(blocks),
            "agent_events": len(events),
        }
        return jsonify({"machine": summary, "firewall_blocks": blocks, "agent_events": events})
