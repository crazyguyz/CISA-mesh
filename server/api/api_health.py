"""
API Health & Log-Source Coverage (v5.0.4 Phase1 A2).
GET /api/health/coverage -> per-machine log-source health:
  - sysmon_present / auditpol_enabled / baseline_hardened (from agent heartbeat)
  - event volume last 24h vs 7-day average + drop% (silent log source = attack signal)
"""

import os
from flask import request, jsonify
from .api_common import check_auth


def register(app, core):
    @app.route("/api/health")
    def api_health():
        _, err, code = check_auth("api")
        if err: return err, code
        info = {"db_backend": getattr(core.db, "backend_type", "unknown"),
                "db_connected": getattr(core.db, "_connected", True)}
        return jsonify(info)

    @app.route("/api/health/coverage")
    def api_health_coverage():
        _, err, code = check_auth("api")
        if err: return err, code
        try:
            machines = core.db.get_machines() or []
        except Exception:
            machines = []
        v24 = core.db.get_event_volume(hours=24)
        v168 = core.db.get_event_volume(hours=168)
        # v5.0.4 (Phase3 A10): server agent version for outdated detection
        try:
            _vpath = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "version.txt")
            server_ver = open(_vpath, "r", encoding="utf-8").read().strip() if os.path.exists(_vpath) else ""
        except Exception:
            server_ver = ""
        out = []
        for m in machines:
            mid = m.get("machine_id", "")
            e24 = (v24.get(mid) or {}).get("events", 0) + (v24.get(mid) or {}).get("sysmon", 0)
            e168 = (v168.get(mid) or {}).get("events", 0) + (v168.get(mid) or {}).get("sysmon", 0)
            avg = round(e168 / 7.0, 1) if e168 else 0
            drop = round((1 - (e24 / avg)) * 100, 1) if avg > 0 else 0
            online = bool(m.get("is_online"))
            flags = []
            if online and e24 == 0 and e168 == 0:
                flags.append("no_logs")
            elif avg > 0 and e24 < avg * 0.5:
                flags.append("log_drop")
            if not m.get("sysmon_present"):
                flags.append("no_sysmon")
            if not m.get("auditpol_enabled"):
                flags.append("no_auditpol")
            mver = str(m.get("version") or "")
            update_available = bool(server_ver) and mver != server_ver
            if update_available:
                flags.append("outdated")
            out.append({
                "machine_id": mid,
                "hostname": m.get("hostname", mid),
                "online": online,
                "version": mver,
                "update_available": update_available,
                "sysmon_present": bool(m.get("sysmon_present")),
                "auditpol_enabled": bool(m.get("auditpol_enabled")),
                "baseline_hardened": bool(m.get("baseline_hardened")),
                "event_24h": e24,
                "event_7d_avg": avg,
                "drop_pct": drop,
                "flags": flags,
            })
        out.sort(key=lambda r: (not r["online"], r["hostname"]))
        return jsonify({"machines": out})

    @app.route("/api/agent/onboarding")
    def api_agent_onboarding():
        """v5.0.4 (Phase3 B10): agent install instructions (server info)."""
        _, err, code = check_auth("api")
        if err: return err, code
        host = request.host.split(":")[0] or "127.0.0.1"
        return jsonify({
            "server_host": host,
            "tcp_port": int(os.environ.get("GIAMSAT_TCP_PORT", "6666")),
            "web_port": int(os.environ.get("GIAMSAT_WEB_PORT", "5000")),
            "enrollment_secret": bool(os.environ.get("GIAMSAT_ENROLLMENT_SECRET", "")),
            "install_cmd": f"GiamSatAgent.exe --server {host} --port {int(os.environ.get('GIAMSAT_TCP_PORT', '6666'))}",
            "note": "Chạy lệnh trên máy trạm Windows (copy agent EXE vào C:\\Program Files\\GIAM-SAT hoặc chạy trực tiếp)."
        })
