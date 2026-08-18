"""
GIAM-SAT Incident Investigation Workspace API v1.0.2
Aggregates all evidence related to a threat alert into a single timeline view.

Endpoints:
  GET /api/incident/list  - List all threat alerts (for sidebar)
  GET /api/incident/<id>  - Full timeline with evidence from all sources

Each timeline gathers:
  - Network traffic (in ±15 min window around alert time)
  - Sysmon events (EID 1, 2, 3, 11)
  - Windows Event Logs (4624, 4625, 4672, 4688, 5156, 7045)
  - FIM events
  - Memory/YARA alerts
"""

from flask import request, jsonify
from .api_common import check_auth
from datetime import datetime, timedelta

INCIDENT_TIMEWINDOW_MINUTES = 15  # ±15 minutes around alert time

# Event IDs needed for investigation
SYSMON_EIDS = [1, 2, 3, 11]  # Process Create, Terminate, NetConnect, FileCreate
WINDOWS_EVENT_IDS = {"4624", "4625", "4672", "4688", "5156", "7045"}


def register(app, core):
    """Register incident investigation routes on the Flask app."""

    @app.route("/api/incident/list")
    def api_incident_list():
        """List all threat alerts for the incident workspace sidebar."""
        _, err, code = check_auth("api")
        if err: return err, code
        try:
            limit = request.args.get("limit", 50, type=int)
            severity = request.args.get("severity", None)
            machine_id = request.args.get("machine_id", None)

            # Use the existing DB method
            threats = core.db.get_threat_alerts(
                machine_id=machine_id,
                limit=min(limit, 200)
            )

            if severity and threats:
                threats = [t for t in threats if (t.get("severity") or "").upper() == severity.upper()]

            # Ensure each threat has an id field for the frontend
            for i, t in enumerate(threats or []):
                if "id" not in t:
                    t["id"] = t.get("rule_id", f"threat_{i}")

            return jsonify({
                "incidents": threats or [],
                "total": len(threats) if threats else 0,
            })
        except Exception as e:
            return jsonify({"error": str(e), "incidents": []}), 200

    @app.route("/api/incident/<threat_id>")
    def api_incident_timeline(threat_id):
        """Get full incident timeline for a specific threat alert."""
        _, err, code = check_auth("api")
        if err: return err, code
        db = core.db

        # 1. Find the threat alert
        threat = None
        try:
            # Search by id or rule_id
            threats = db.get_threat_alerts(limit=2000)
            for t in (threats or []):
                tid = str(t.get("id", ""))
                rid = str(t.get("rule_id", ""))
                if tid == str(threat_id) or rid == str(threat_id):
                    threat = t
                    break
        except Exception as e:
            return jsonify({"error": f"Failed to query threats: {str(e)}"}), 500

        if not threat:
            return jsonify({"error": f"Threat {threat_id} not found"}), 404

        # 2. Parse alert time & build time window
        alert_time_str = threat.get("timestamp", "")
        try:
            alert_time = datetime.strptime(alert_time_str[:19], "%Y-%m-%d %H:%M:%S")
        except Exception:
            alert_time = datetime.now()

        window_start = (alert_time - timedelta(minutes=INCIDENT_TIMEWINDOW_MINUTES)).strftime("%Y-%m-%d %H:%M:%S")
        window_end = (alert_time + timedelta(minutes=INCIDENT_TIMEWINDOW_MINUTES)).strftime("%Y-%m-%d %H:%M:%S")

        machine_id = threat.get("machine_id", "")
        rule_id = threat.get("rule_id", "")

        # 3. Gather evidence
        evidence = {}
        timeline_events = []

        # --- Network Traffic ---
        try:
            network_logs = db.get_network_traffic_logs(
                machine_id=machine_id,
                limit=500,
                since=window_start
            )
            if network_logs:
                # Filter by time window client-side since DB method may not support end time
                net_in_window = [
                    n for n in network_logs
                    if window_start <= (n.get("timestamp") or "") <= window_end
                ]
                evidence["network"] = {"count": len(net_in_window), "logs": net_in_window[:500]}
                for log in net_in_window[:500]:
                    timeline_events.append({
                        "type": "network",
                        "icon": "\ud83c\udf10",
                        "timestamp": log.get("timestamp", ""),
                        "severity": "INFO",
                        "title": f"{log.get('protocol','?')} {log.get('src_ip','?')}:{log.get('src_port','?')} \u2192 {log.get('dst_ip','?')}:{log.get('dst_port','?')}",
                        "description": f"State: {log.get('state','?')}",
                        "source": "Network",
                    })
            else:
                evidence["network"] = {"count": 0, "logs": []}
        except Exception as e:
            evidence["network"] = {"error": str(e)[:200], "count": 0, "logs": []}

        # --- Sysmon Events ---
        try:
            sysmon_logs = db.get_sysmon_events(
                machine_id=machine_id,
                limit=500,
                since=window_start
            )
            if sysmon_logs:
                sysmon_in_window = [
                    s for s in sysmon_logs
                    if window_start <= (s.get("timestamp") or "") <= window_end
                    and s.get("sysmon_event_id") in SYSMON_EIDS
                ]
                evidence["sysmon"] = {"count": len(sysmon_in_window), "logs": sysmon_in_window[:500]}
                icon_map = {1: "\ud83d\udfe2", 2: "\ud83d\udfe1", 3: "\ud83c\udf10", 11: "\ud83d\udcc1"}
                titles = {
                    1: "Process Create",
                    2: "Process Terminate",
                    3: "Network Connect",
                    11: "File Create",
                }
                for log in sysmon_in_window[:500]:
                    eid = log.get("sysmon_event_id", 0)
                    timeline_events.append({
                        "type": "sysmon",
                        "icon": icon_map.get(eid, "\ud83d\udccb"),
                        "timestamp": log.get("timestamp", ""),
                        "severity": log.get("severity", "INFO"),
                        "title": f"{titles.get(eid, f'EID {eid}')}: {log.get('process_name','?')}",
                        "description": log.get("description", "")[:200],
                        "source": "Sysmon",
                    })
            else:
                evidence["sysmon"] = {"count": 0, "logs": []}
        except Exception as e:
            evidence["sysmon"] = {"error": str(e)[:200], "count": 0, "logs": []}

        # --- Windows Event Logs ---
        try:
            events = db.get_event_logs(
                machine_id=machine_id,
                limit=500,
                since=window_start
            )
            if events:
                events_in_window = [
                    e for e in events
                    if window_start <= (e.get("timestamp") or e.get("time") or "") <= window_end
                    and str(e.get("event_id", "")) in WINDOWS_EVENT_IDS
                ]
                evidence["events"] = {"count": len(events_in_window), "logs": events_in_window[:500]}
                icon_map = {"4624": "\ud83d\udd11", "4625": "\ud83d\udd12", "4672": "\ud83d\udc51", "4688": "\u26a1", "5156": "\ud83d\udee1\ufe0f", "7045": "\ud83d\udd27"}
                for log in events_in_window[:500]:
                    eid = str(log.get("event_id", "?"))
                    timeline_events.append({
                        "type": "windows_event",
                        "icon": icon_map.get(eid, "\ud83d\udccb"),
                        "timestamp": log.get("timestamp") or log.get("time") or "",
                        "severity": "HIGH" if eid == "4625" else "INFO",
                        "title": f"Event {eid}",
                        "description": (log.get("description") or "")[:200],
                        "source": "Windows Event",
                    })
            else:
                evidence["events"] = {"count": 0, "logs": []}
        except Exception as e:
            evidence["events"] = {"error": str(e)[:200], "count": 0, "logs": []}

        # --- FIM Events ---
        try:
            fim_logs = db.get_fim_events(machine_id=machine_id, limit=200)
            if fim_logs:
                fim_in_window = [
                    f for f in fim_logs
                    if window_start <= (f.get("time") or f.get("timestamp") or "") <= window_end
                ]
                if fim_in_window:
                    evidence["fim"] = {"count": len(fim_in_window), "logs": fim_in_window[:100]}
                    for log in fim_in_window[:100]:
                        timeline_events.append({
                            "type": "fim",
                            "icon": "\ud83d\udcc1",
                            "timestamp": log.get("time") or log.get("timestamp") or "",
                            "severity": "MEDIUM",
                            "title": f"FIM: {log.get('action','?')} {log.get('path','?')}",
                            "description": "",
                            "source": "FIM",
                        })
        except Exception:
            pass

        # --- Memory/YARA Alerts ---
        try:
            yara_logs = db.get_yara_alerts(machine_id=machine_id, limit=200)
            if yara_logs:
                yara_in_window = [
                    y for y in yara_logs
                    if window_start <= (y.get("timestamp") or "") <= window_end
                ]
                if yara_in_window:
                    evidence["memory"] = {"count": len(yara_in_window), "logs": yara_in_window[:50]}
                    for log in yara_in_window[:50]:
                        timeline_events.append({
                            "type": "memory",
                            "icon": "\ud83e\udde0",
                            "timestamp": log.get("timestamp", ""),
                            "severity": "HIGH",
                            "title": f"YARA: {log.get('rule_name','?')}",
                            "description": (log.get("description") or "")[:200],
                            "source": "Memory/YARA",
                        })
        except Exception:
            pass

        # 4. Add threat alert as anchor event
        timeline_events.append({
            "type": "threat_alert",
            "icon": "\ud83d\udd34",
            "timestamp": alert_time_str,
            "severity": threat.get("severity", "UNKNOWN"),
            "title": threat.get("rule_name") or threat.get("rule_id") or "Unknown",
            "description": threat.get("description") or "",
            "source": "Alert",
            "is_anchor": True,
        })

        # 5. Sort by timestamp
        timeline_events.sort(key=lambda x: x.get("timestamp", ""))

        # 6. Related machines for CROSS rules
        related_machines = []
        if rule_id and rule_id.startswith("CROSS-"):
            try:
                all_machines = db.get_machines()
                for m in (all_machines or []):
                    if m.get("machine_id") != machine_id:
                        m["relation"] = "cross_rule_participant"
                        related_machines.append(m)
            except Exception:
                pass

        return jsonify({
            "threat": threat,
            "timewindow": {
                "start": window_start,
                "end": window_end,
                "minutes": INCIDENT_TIMEWINDOW_MINUTES,
            },
            "machine_id": machine_id,
            "hostname": threat.get("hostname", ""),
            "evidence": evidence,
            "timeline_events": timeline_events,
            "related_machines": related_machines[:20],
            "total_events": len(timeline_events),
        })