"""MITRE ATT&CK Matrix API for GIAM-SAT v3.9.3."""
from flask import jsonify, request
import sqlite3
import os
import json
from .api_common import check_auth

MITRE_TACTICS = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact"
]

def register_routes(app, core):
    """Register MITRE ATT&CK API routes."""

    @app.route("/api/mitre/matrix")
    def api_mitre_matrix():
        """Return MITRE ATT&CK matrix data for dashboard visualization."""
        _, err, code = check_auth("api")
        if err: return err, code
        machine_id = request.args.get("machine_id", "")
        # v4.10 (LOW-4): type=int avoids ValueError -> 500 on garbage input
        since_hours = request.args.get("since_hours", 24, type=int)
        
        result = {
            "tactics": MITRE_TACTICS,
            "techniques": [],
            "summary": {
                "total_alerts": 0,
                "highest_severity": "NONE",
                "active_tactics": [],
            },
        }
        
        max_sev_score = 0
        sev_scores = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        
        try:
            if not core.db:
                return jsonify(result)

            # Detect backend: SQLite uses `?` placeholder + datetime(), PostgreSQL uses `%s` + INTERVAL
            is_sqlite = not hasattr(core.db, '_execute')

            # Query threat alerts with MITRE data (use received_at, not timestamp TEXT)
            # v4.6.6: exclude triaged-as-resolved/false-positive alerts so marking an
            # alert handled removes it from the matrix (future identical alerts still
            # appear - this is NOT a suppression rule).
            if is_sqlite:
                q = """SELECT rule_id, rule_name, severity, description, 
                              machine_id, hostname, timestamp,
                              raw_data
                       FROM threat_alerts 
                       WHERE status NOT IN ('resolved', 'false_positive')"""
                params = []
                if machine_id:
                    q += " AND machine_id = ?"
                    params.append(machine_id)
                if since_hours:
                    q += " AND received_at >= datetime('now', ?)"
                    params.append(f'-{since_hours} hours')
                q += " ORDER BY id DESC LIMIT 2000"
            else:
                q = """SELECT rule_id, rule_name, severity, description, 
                              machine_id, hostname, timestamp,
                              raw_data
                       FROM threat_alerts 
                       WHERE status NOT IN ('resolved', 'false_positive')"""
                params = []
                if machine_id:
                    q += " AND machine_id = %s"
                    params.append(machine_id)
                if since_hours:
                    # Use concatenation + cast to avoid %s inside quotes (psycopg2 bug)
                    q += " AND received_at >= NOW() - (%s || ' hours')::INTERVAL"
                    params.append(str(since_hours))
                q += " ORDER BY id DESC LIMIT 2000"

            if is_sqlite:
                cur = core.db.conn.cursor()
                cur.execute(q, tuple(params))
                rows = [dict(r) for r in cur.fetchall()]
            else:
                rows = core.db._execute(q, tuple(params), fetchall=True) or []
        except Exception as e:
            print(f"[-] MITRE API query error: {e}")
            return jsonify(result)
        
        techniques = {}  # technique_id -> {tactic, name, count, max_severity, alerts[]}
        
        for row in rows:
            rule_id = row.get("rule_id") or "UNKNOWN"
            rule_name = row.get("rule_name") or "Unknown Rule"
            severity = row.get("severity") or "INFO"
            description = row.get("description") or ""
            m_id = row.get("machine_id") or ""
            hostname = row.get("hostname") or ""
            timestamp = row.get("timestamp") or ""
            raw_data_val = row.get("raw_data") or {}
            
            # Extract MITRE data from raw_data (may be dict or JSONB string)
            tactic = "Unknown"
            technique_id = "N/A"
            technique_name = ""
            
            # raw_data may already be a dict from PostgreSQL JSONB
            if isinstance(raw_data_val, dict):
                raw = raw_data_val
            elif isinstance(raw_data_val, str):
                try:
                    raw = json.loads(raw_data_val)
                except Exception:
                    raw = {}
            else:
                raw = {}
            
            # Try multiple sources for MITRE mapping
            mitre_tactic = raw.get("mitre_tactic", "")
            mitre_tech_id = raw.get("mitre_technique_id", "")
            mitre_tech_name = raw.get("mitre_technique_name", "")
            
            if mitre_tactic and mitre_tech_id:
                tactic = mitre_tactic
                technique_id = mitre_tech_id
                technique_name = mitre_tech_name
            else:
                # Fallback: derive from rule_name or description (best effort)
                tactic = _infer_tactic(rule_name, description)
                technique_id = rule_id
                technique_name = rule_name
            
            sev = sev_scores.get(severity, 0)
            if sev > max_sev_score:
                max_sev_score = sev
            
            key = technique_id
            if key not in techniques:
                techniques[key] = {
                    "technique_id": technique_id,
                    "technique_name": technique_name or rule_name,
                    "tactic": tactic,
                    "count": 0,
                    "max_severity": severity,
                    "alerts": [],
                }
            
            techniques[key]["count"] += 1
            if sev_scores.get(techniques[key]["max_severity"], 0) < sev:
                techniques[key]["max_severity"] = severity
            
            # Keep last 3 alerts
            if len(techniques[key]["alerts"]) < 3:
                techniques[key]["alerts"].append({
                    "rule_id": rule_id,
                    "rule_name": rule_name,
                    "severity": severity,
                    "machine_id": m_id,
                    "hostname": hostname,
                    "timestamp": timestamp,
                    "description": description[:200],
                })
        
        # Build summary
        sev_map = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "INFO"}
        result["summary"]["highest_severity"] = sev_map.get(max_sev_score, "NONE")
        
        # Count unique tactics
        active_tactics = set(t["tactic"] for t in techniques.values())
        result["summary"]["active_tactics"] = sorted(active_tactics)
        result["summary"]["total_techniques"] = len(techniques)
        
        # Sort by severity then count
        tech_list = list(techniques.values())
        tech_list.sort(key=lambda t: (sev_scores.get(t["max_severity"], 0), t["count"]), reverse=True)
        result["techniques"] = tech_list
        result["summary"]["total_alerts"] = len(rows)
        
        return jsonify(result)

    @app.route("/api/mitre/export/navigator")
    def api_mitre_export_navigator():
        """v5.0.4 (Phase3 improvement #2): attack-navigator layer of the detection
        coverage - every technique the rule library tags is shown; live-hit ones
        are scored by severity, untouched ones are grey 'blind' coverage gaps."""
        _, err, code = check_auth("api")
        if err: return err, code
        try:
            since_hours = max(1, min(int(request.args.get("since_hours", 168)), 720))
        except (TypeError, ValueError):
            since_hours = 168
        sev_order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        active = {}
        try:
            rows = core.db.get_threat_alerts(limit=5000, since_hours=since_hours) or []
            import re as _re
            for r in rows:
                if r.get("status") in ("resolved", "false_positive"):
                    continue
                raw = r.get("raw_data")
                if isinstance(raw, str):
                    try:
                        raw = json.loads(raw)
                    except Exception:
                        raw = {}
                if not isinstance(raw, dict):
                    raw = {}
                tid = str(raw.get("mitre_technique_id") or raw.get("technique_id") or "").strip()
                if not _re.match(r"^(T\d{4}(\.\d{3})?|S\d{4}|G\d{4})$", tid):
                    continue
                ent = active.setdefault(tid, {"count": 0, "max_severity": "LOW"})
                ent["count"] += 1
                sev = str(r.get("severity") or "LOW").upper()
                if sev_order.get(ent["max_severity"], 0) < sev_order.get(sev, 0):
                    ent["max_severity"] = sev
        except Exception:
            pass
        try:
            from mitre_navigator import build_navigator
            layer = build_navigator(active, since_label=f"{since_hours}h")
        except Exception as e:
            return jsonify({"error": str(e)[:200]}), 500
        return jsonify(layer)

    @app.route("/api/mitre/technique/<technique_id>")
    def api_mitre_technique(technique_id):
        """Return all alerts for a specific MITRE technique (backend-agnostic)."""
        _, err, code = check_auth("api")
        if err: return err, code
        result = {"technique_id": technique_id, "alerts": []}
        if not core.db:
            return jsonify(result)
        try:
            rows = core.db.get_threat_alerts(limit=1000) or []
            for r in rows:
                # v4.6.6: skip triaged alerts (resolved / false-positive) - the
                # matrix + detail should only show what still needs attention.
                if r.get("status") in ("resolved", "false_positive"):
                    continue
                raw = r.get("raw_data") or {}
                if isinstance(raw, str):
                    try:
                        raw = json.loads(raw)
                    except Exception:
                        raw = {}
                if not isinstance(raw, dict):
                    raw = {}
                tid = raw.get("mitre_technique_id") or ""
                rid = r.get("rule_id") or ""
                if technique_id and (tid == technique_id or rid == technique_id
                                     or str(technique_id) in json.dumps(raw, default=str)):
                    result["alerts"].append({
                        "id": r.get("id"),
                        "status": r.get("status", "new"),
                        "rule_id": rid, "rule_name": r.get("rule_name", ""),
                        "severity": r.get("severity", ""),
                        "description": r.get("description", "") or "",
                        "machine_id": r.get("machine_id", ""),
                        "hostname": r.get("hostname", ""),
                        "timestamp": r.get("timestamp", ""),
                    })
                    if len(result["alerts"]) >= 100:
                        break
        except Exception:
            pass
        return jsonify(result)


def _infer_tactic(rule_name, description):
    """Best-effort tactic inference from rule name/description."""
    text = (rule_name + " " + description).lower()
    if any(k in text for k in ("brute force", "password", "credential", "lsass")):
        return "Credential Access"
    if any(k in text for k in ("ransomware", "encrypt", "shadow copy", "wiper")):
        return "Impact"
    if any(k in text for k in ("defender", "firewall disable", "defense evas", "uac")):
        return "Defense Evasion"
    if any(k in text for k in ("c2", "beacon", "tunnel", "command and control")):
        return "Command and Control"
    if any(k in text for k in ("lateral", "psexec", "winrm", "wmi", "pass-the")):
        return "Lateral Movement"
    if any(k in text for k in ("persist", "registry run", "startup", "service install")):
        return "Persistence"
    if any(k in text for k in ("privilege", "token", "injection")):
        return "Privilege Escalation"
    if any(k in text for k in ("execut", "powershell", "cmd", "script")):
        return "Execution"
    if any(k in text for k in ("discover", "scan", "enum")):
        return "Discovery"
    if any(k in text for k in ("phish", "exploit", "initial access")):
        return "Initial Access"
    if any(k in text for k in ("exfil", "data exfil", "upload")):
        return "Exfiltration"
    return "Unknown"