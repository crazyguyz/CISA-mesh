"""
API FIM Baseline - FIM baseline CRUD, diff, summary with suspicion scoring.
"""

import os
import time
from flask import request, jsonify
from .api_common import check_auth, check_agent_psk

# v3.7.2: In-memory cache for FIM baseline summary
_baseline_summary_cache = {"data": None, "ts": 0}
_BASELINE_SUMMARY_CACHE_TTL = 60  # seconds

# v3.7.2: In-memory cache for per-machine FIM baseline
_machine_baseline_cache = {}  # {machine_id: {"data": ..., "ts": ...}}
_MACHINE_BASELINE_CACHE_TTL = 30  # seconds


def _compute_fim_suspicion_score(fim_entry, threats_count):
    """v2.5.0: Compute suspicion score (0-100) for a FIM file entry."""
    path = (fim_entry.get("path") or "").lower()
    ext = os.path.splitext(path)[1] if "." in path else ""
    change_count = fim_entry.get("change_count", 0) or 0
    last_checked = fim_entry.get("last_checked", "") or ""
    reasons = []
    score = 0

    exec_exts = {".exe", ".dll", ".sys", ".bat", ".ps1", ".vbs", ".scr", ".msi", ".com", ".cmd", ".hta", ".jar"}
    script_exts = {".ps1", ".vbs", ".bat", ".cmd", ".js", ".vba", ".wsf", ".wsh"}
    config_exts = {".ini", ".cfg", ".conf", ".xml", ".yaml", ".yml", ".json"}
    system_exts = {".log", ".tmp", ".temp", ".dat", ".etl", ".cache", ".db", ".sqlite", ".pdb"}

    if ext in exec_exts:
        score += 30
        reasons.append(f"File thực thi ({ext})")
    elif ext in script_exts:
        score += 35
        reasons.append(f"Script file ({ext}) - có thể chứa mã độc")
    elif ext in config_exts:
        score += 10
        reasons.append(f"File cấu hình ({ext})")
    elif ext in system_exts:
        score -= 30
        reasons.append(f"File hệ thống ({ext}) - thường tự thay đổi")
    elif ext == "":
        score += 5

    high_risk_paths = [
        "\\windows\\system32\\", "\\windows\\syswow64\\",
        "\\startup", "\\drivers\\etc\\", "\\windows\\tasks\\",
        "\\programdata\\microsoft\\windows\\start menu\\",
        "\\appdata\\roaming\\microsoft\\windows\\start menu\\",
    ]
    system_paths = [
        "\\windows\\temp\\", "\\temp\\", "%temp%", "\\appdata\\local\\temp\\",
        "\\windows\\logs\\", "\\windows\\prefetch\\", "\\windows\\servicing\\",
        "\\programdata\\microsoft\\crypto\\", "\\ntuser.dat", "\\usrclass.dat",
        "\\iconcache.db", "\\thumbs.db",
    ]

    path_lower = path.replace("/", "\\")
    is_high_risk = any(hp in path_lower for hp in high_risk_paths)
    is_system = any(sp in path_lower for sp in system_paths)

    if is_high_risk:
        score += 25
        reasons.append("Vị trí nhạy cảm (System32/Startup/Hosts)")
    elif is_system:
        score -= 40
        reasons.append("Thư mục temp/cache - hệ thống tự quản lý")

    if change_count >= 10:
        score += 25
        reasons.append(f"Thay đổi {change_count}x - tần suất cao bất thường")
    elif change_count >= 5:
        score += 15
        reasons.append(f"Thay đổi {change_count}x - cần chú ý")
    elif change_count >= 2:
        score += 8
        reasons.append(f"Thay đổi {change_count}x")

    if last_checked:
        try:
            from datetime import datetime as _dt
            t = _dt.strptime(last_checked[:19], "%Y-%m-%d %H:%M:%S")
            hour = t.hour
            if hour >= 22 or hour <= 5:
                score += 12
                reasons.append(f"Thay đổi ngoài giờ hành chính ({hour}h)")
            if t.weekday() >= 5:
                score += 5
                reasons.append("Thay đổi cuối tuần - đáng nghi")
        except Exception:
            pass

    if threats_count > 0:
        score += 20
        reasons.append(f"Máy đang có {threats_count} threat alert - có thể liên quan")

    file_size = fim_entry.get("file_size", 0) or 0
    if file_size == 0:
        score += 15
        reasons.append("File rỗng (0 byte) - có thể bị xóa hoặc trojan")

    score = max(0, min(100, score))
    if score >= 80:
        level = "critical"
    elif score >= 50:
        level = "high"
    elif score >= 25:
        level = "medium"
    else:
        level = "low"

    return {"score": score, "reasons": reasons, "risk_level": level}


def register(app, core):
    """Register FIM baseline routes."""

    @app.route("/api/fim/baseline/summary", methods=["GET"])
    def api_fim_baseline_summary():
        _, err, code = check_auth("api")
        if err: return err, code

        # v3.7.2: Return cached result if still fresh
        global _baseline_summary_cache
        now = time.time()
        if _baseline_summary_cache["data"] is not None and (now - _baseline_summary_cache["ts"]) < _BASELINE_SUMMARY_CACHE_TTL:
            return jsonify({"machines": _baseline_summary_cache["data"], "cached": True})

        machines = core.db.get_machines()
        result = []
        for m in machines:
            mid = m["machine_id"]
            try:
                stats = core.db.get_fim_baseline_stats(mid)
                threats_count = len(core.db.get_threat_alerts(machine_id=mid, limit=100))
                # v3.7.2: Only load changed files for suspicion scoring (not all baseline)
                recent_count = stats.get("changed_files", 0)
                if recent_count <= 100:
                    baseline = core.db.get_fim_baseline(mid, limit=200, only_changed=False)
                else:
                    baseline = core.db.get_fim_baseline(mid, limit=500, only_changed=True)
            except Exception:
                baseline = []
                stats = {}
                threats_count = 0
            counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": stats.get("total_files", 0)}
            if baseline:
                for entry in baseline:
                    score_obj = _compute_fim_suspicion_score(entry, threats_count)
                    level = score_obj.get("risk_level", "low")
                    if level in counts:
                        counts[level] += 1
            else:
                # Fallback: no baseline loaded, use stats only
                pass
            result.append({
                "machine_id": mid,
                "hostname": m.get("hostname", mid),
                "is_online": m.get("is_online", 0),
                "total_files": stats.get("total_files", 0),
                "checked_24h": stats.get("checked_24h", 0),
                "changed_files": stats.get("changed_files", 0),
                "critical": counts["critical"],
                "high": counts["high"],
                "medium": counts["medium"],
                "low": counts["low"],
                "total": counts["total"]
            })

        # v3.7.2: Cache result
        _baseline_summary_cache = {"data": result, "ts": now}
        return jsonify({"machines": result, "cached": False})

    @app.route("/api/fim/baseline/<machine_id>", methods=["GET"])
    def api_fim_baseline(machine_id):
        _, err, code = check_auth("api")
        if err: return err, code

        # v3.7.2: Pagination support
        limit = request.args.get("limit", 200, type=int)
        offset = request.args.get("offset", 0, type=int)
        search = request.args.get("search", "", type=str)
        only_changed = request.args.get("only_changed", "false").lower() == "true"
        sort_by = request.args.get("sort_by", "path")  # path, change_count, last_checked

        # Clamp limit
        limit = min(limit, 1000)

        # v3.7.2: Cache for common first-page requests
        cache_key = f"{machine_id}:{limit}:{offset}:{search}:{only_changed}:{sort_by}"
        global _machine_baseline_cache
        now = time.time()
        if cache_key in _machine_baseline_cache:
            cached = _machine_baseline_cache[cache_key]
            if (now - cached["ts"]) < _MACHINE_BASELINE_CACHE_TTL:
                return jsonify(cached["data"])

        baseline = core.db.get_fim_baseline(
            machine_id, limit=limit, offset=offset,
            search=search, only_changed=only_changed, sort_by=sort_by
        )
        stats = core.db.get_fim_baseline_stats(machine_id)
        threats_count = 0
        try:
            threats_count = len(core.db.get_threat_alerts(machine_id=machine_id, limit=100))
        except Exception:
            pass

        # v3.7.2: Compute suspicion only for returned page (not all baseline)
        for entry in baseline:
            entry["suspicion"] = _compute_fim_suspicion_score(entry, threats_count)

        result_data = {
            "baseline": baseline,
            "stats": stats,
            "threats_count": threats_count,
            "pagination": {"limit": limit, "offset": offset, "total": stats.get("total_files", 0)},
            "cached": False,
        }

        # v3.7.2: Cache first-page results only
        if offset == 0 and not search and not only_changed and sort_by == "path":
            _machine_baseline_cache[cache_key] = {"data": result_data, "ts": now}
            # Cleanup old cache entries
            stale = [k for k, v in _machine_baseline_cache.items() if now - v["ts"] > _MACHINE_BASELINE_CACHE_TTL * 4]
            for k in stale:
                del _machine_baseline_cache[k]

        return jsonify(result_data)

    @app.route("/api/fim/baseline/<machine_id>/diff", methods=["POST"])
    def api_fim_baseline_diff(machine_id):
        data = request.json or {}
        if not check_agent_psk(data):
            return jsonify({"error": "invalid psk"}), 401
        files = data.get("files", [])
        changed = []
        for f in files:
            changed_flag = core.db.upsert_fim_baseline(
                machine_id,
                f.get("path", ""),
                f.get("hash", ""),
                f.get("size", 0),
                f.get("owner", ""),
                f.get("permissions", ""),
                f.get("last_modified", "")
            )
            if changed_flag:
                changed.append(f)
        stats = core.db.get_fim_baseline_stats(machine_id)
        return jsonify({
            "changed_count": len(changed),
            "changed_files": changed[:50],
            "total_tracked": stats.get("total_files", 0)
        })