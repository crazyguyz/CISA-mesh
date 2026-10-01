"""GIAM-SAT fleet operations API - v5.0.8 (Phase C).

    POST /api/fleet/rollout/plan            dry-run: waves + affected machines
    POST /api/fleet/rollout                 create the rollout and launch the canary
    GET  /api/fleet/rollouts                list rollouts
    GET  /api/fleet/rollout/<id>            status (reconciled from machines.version)
    POST /api/fleet/rollout/<id>/advance    health gate -> launch the next wave
    POST /api/fleet/rollout/<id>/rollback   halt + push the previous build back if archived
    GET  /api/health/fleet                  per-machine health + rejected-ingest counters
    POST /api/policies/preview              dry-run of a group policy (diff + waves)

Reads need the "api" permission; anything that touches agents needs "command"
(plus an audit-log entry). The planning/gating maths lives in ../fleet.py.
"""

import os
import time
import uuid

from flask import jsonify, request

import fleet as fl
import fleet_store as store

from .api_common import check_auth

SILENT_MINUTES = 10
ARCHIVE_DIRS = ("dist_archive", "dist/archive")   # optional archived builds (rollback)


def _machines(core, group_id=None, machine_ids=None):
    """Resolve the target machines (optionally restricted to one group)."""
    machines = core.db.get_machines() or []
    if machine_ids:
        wanted = set(machine_ids)
        return [m for m in machines if m.get("machine_id") in wanted]
    if group_id:
        group = core.db.get_agent_group(group_id) or {}
        members = {m.get("machine_id") for m in (group.get("members") or [])}
        return [m for m in machines if m.get("machine_id") in members] if members else []
    return machines


def _ordered_ids(machines, only_outdated=True, target_version=""):
    """Hostname-sorted ids; default = only the machines that need the update."""
    rows = [m for m in machines if m.get("machine_id")]
    if only_outdated and target_version:
        rows = [m for m in rows if str(m.get("version") or "") != str(target_version)]
    rows.sort(key=lambda m: (m.get("hostname") or m.get("machine_id") or ""))
    return [m["machine_id"] for m in rows]


def _send_update(core, machine, target_version):
    """Ask one agent to update; True when the command reached it."""
    mid = machine.get("machine_id")
    hostname = machine.get("hostname") or mid
    ok = False
    try:
        ok = bool(core.tcp_server.send_command(mid, {
            "action": "agent_update", "version": target_version,
            "exec_id": "rollout_%s" % uuid.uuid4().hex[:10]}))
    except Exception:
        ok = False
    try:
        core.db.insert_agent_update_log(
            mid, hostname, machine.get("version") or "?", target_version,
            "pending" if ok else "failed",
            "rollout wave request" if ok else "Agent offline or unreachable", "rollout")
    except Exception:
        pass
    return ok


def _reconcile(core, rollout):
    """Refresh target statuses from the live machines table."""
    targets = store.list_rollout_targets(core.db, rollout["id"])
    changed = fl.reconcile_targets(targets, core.db.get_machines() or [],
                                   rollout.get("target_version"))
    for row in changed:
        store.update_rollout_target(core.db, rollout["id"], row["machine_id"],
                                    status=row["status"], message="version=%s" % row["version"])
    return store.list_rollout_targets(core.db, rollout["id"]) if changed else targets


def _rollout_state(core, rollout):
    """Attach wave counts + machine rows so the UI can render the rollout."""
    targets = _reconcile(core, rollout)
    waves = {}
    for target in targets:
        waves.setdefault(int(target.get("wave") or 0), []).append(target)
    current = int(rollout.get("wave_index") or 0)
    wave_rows = []
    for index in sorted(waves):
        counts = fl.wave_health(targets, index)
        ok, reason = fl.health_gate(counts)
        wave_rows.append({
            "index": index, "machines": waves[index], "counts": counts,
            "healthy": ok, "reason": reason,
            "state": "done" if index < current else ("current" if index == current else "pending"),
        })
    return {"rollout": rollout, "waves": wave_rows, "overall": fl.wave_health(targets),
            "current_wave": current, "targets": targets}


def _archived_build(previous_version):
    """Path of an archived EXE for a version, if the operator kept one."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for folder in ARCHIVE_DIRS:
        candidate = os.path.join(root, folder, "GiamSatAgent-%s.exe" % previous_version)
        if os.path.exists(candidate):
            return candidate
    return None


def register(app, core):
    @app.route("/api/fleet/rollout/plan", methods=["POST"])
    def api_fleet_rollout_plan():
        """Dry-run: who would be updated, in which wave, how many are outdated."""
        _, err, code = check_auth("api")
        if err:
            return err, code
        body = request.json or {}
        target_version = str(body.get("target_version")
                             or core.db.get_server_agent_version() or "")
        machines = _machines(core, body.get("group_id"), body.get("machine_ids"))
        ids = _ordered_ids(machines, body.get("only_outdated", True) is not False, target_version)
        offline = [m.get("hostname") or m.get("machine_id") for m in machines
                   if m.get("machine_id") in ids and not m.get("is_online")]
        return jsonify({
            "target_version": target_version,
            "candidates": len(machines), "affected": len(ids),
            "already_current": len(machines) - len(ids), "offline": len(offline),
            "offline_hosts": offline,
            "waves": fl.plan_waves(ids, body.get("waves")),
            "warning": ("%d máy trong kế hoạch đang offline (sẽ nhận khi online lại)"
                        % len(offline)) if offline else "",
        })

    @app.route("/api/fleet/rollout", methods=["POST"])
    def api_fleet_rollout_create():
        """Create a rollout and immediately launch wave 0 (the canary)."""
        username, err, code = check_auth("command")
        if err:
            return err, code
        body = request.json or {}
        target_version = str(body.get("target_version")
                             or core.db.get_server_agent_version() or "")
        machines = _machines(core, body.get("group_id"), body.get("machine_ids"))
        by_id = {m.get("machine_id"): m for m in machines}
        ids = _ordered_ids(machines, body.get("only_outdated", True) is not False, target_version)
        if not ids:
            return jsonify({"success": False, "error": "không có máy nào cần cập nhật"}), 400
        waves = fl.plan_waves(ids, body.get("waves"))
        rollout_id = store.create_rollout(
            core.db, body.get("name") or ("Cập nhật lên %s" % target_version),
            target_version, str(body.get("previous_version") or ""), waves, ids,
            group_id=str(body.get("group_id") or ""), created_by=username)
        if not rollout_id:
            return jsonify({"success": False, "error": "không tạo được rollout"}), 500
        rows = []
        for wave in waves:
            for mid in wave["machines"]:
                machine = by_id.get(mid) or {}
                rows.append({"machine_id": mid, "hostname": machine.get("hostname") or mid,
                             "wave": wave["index"], "status": "pending",
                             "from_version": machine.get("version") or "",
                             "to_version": target_version})
        store.set_rollout_targets(core.db, rollout_id, rows)

        launched, failed = [], []
        for mid in waves[0]["machines"]:
            sent = _send_update(core, by_id.get(mid) or {"machine_id": mid}, target_version)
            store.update_rollout_target(
                core.db, rollout_id, mid, status="requested" if sent else "failed",
                message="canary" if sent else "agent offline",
                requested_at=time.strftime("%Y-%m-%d %H:%M:%S"))
            (launched if sent else failed).append(mid)
        store.update_rollout(core.db, rollout_id, state="running", wave_index=0)
        core.db.insert_audit_log(
            username, "fleet_rollout_create",
            "rollout #%s -> %s (canary %d/%d máy)" % (rollout_id, target_version,
                                                      len(launched), len(waves[0]["machines"])),
            request.remote_addr)
        return jsonify({"success": True, "id": rollout_id, "target_version": target_version,
                        "canary_sent": launched, "canary_failed": failed, "waves": waves})

    @app.route("/api/fleet/rollouts")
    def api_fleet_rollouts():
        _, err, code = check_auth("api")
        if err:
            return err, code
        items = store.list_rollouts(core.db, limit=int(request.args.get("limit", 50)))
        return jsonify({"items": items, "count": len(items)})

    @app.route("/api/fleet/rollout/<int:rollout_id>")
    def api_fleet_rollout_get(rollout_id):
        _, err, code = check_auth("api")
        if err:
            return err, code
        rollout = store.get_rollout(core.db, rollout_id)
        if not rollout:
            return jsonify({"error": "không tìm thấy rollout #%d" % rollout_id}), 404
        return jsonify(_rollout_state(core, rollout))

    @app.route("/api/fleet/rollout/<int:rollout_id>/advance", methods=["POST"])
    def api_fleet_rollout_advance(rollout_id):
        """Promote to the next wave - only when the current one is healthy."""
        username, err, code = check_auth("command")
        if err:
            return err, code
        rollout = store.get_rollout(core.db, rollout_id)
        if not rollout:
            return jsonify({"error": "không tìm thấy rollout #%d" % rollout_id}), 404
        force = bool((request.json or {}).get("force"))
        state = _rollout_state(core, rollout)
        current = state["current_wave"]
        current_row = next((w for w in state["waves"] if w["index"] == current), None)
        gate_ok = bool(current_row and current_row.get("healthy"))
        gate_reason = (current_row or {}).get("reason") or "chưa có đợt hiện tại"
        if not gate_ok and not force:
            return jsonify({"success": False, "blocked": True, "reason": gate_reason,
                            "wave": current, "counts": (current_row or {}).get("counts")})
        next_row = next((w for w in state["waves"] if w["index"] == current + 1), None)
        if not next_row:
            store.update_rollout(core.db, rollout_id, state="done")
            return jsonify({"success": True, "state": "done", "message": "đã hoàn tất đợt cuối",
                            "gate": gate_reason})
        by_id = {m.get("machine_id"): m for m in (core.db.get_machines() or [])}
        sent, failed = [], []
        for target in next_row["machines"]:
            mid = target.get("machine_id")
            delivered = _send_update(core, by_id.get(mid) or target, rollout.get("target_version"))
            store.update_rollout_target(
                core.db, rollout_id, mid, status="requested" if delivered else "failed",
                message="wave %d" % (current + 1),
                requested_at=time.strftime("%Y-%m-%d %H:%M:%S"))
            (sent if delivered else failed).append(mid)
        store.update_rollout(core.db, rollout_id, wave_index=current + 1, state="running")
        core.db.insert_audit_log(username, "fleet_rollout_advance",
                                 "rollout #%s -> đợt %d (%d gửi, %d lỗi)"
                                 % (rollout_id, current + 1, len(sent), len(failed)),
                                 request.remote_addr)
        return jsonify({"success": True, "wave": current + 1, "sent": sent, "failed": failed,
                        "gate": gate_reason, "forced": force and not gate_ok})

    @app.route("/api/fleet/rollout/<int:rollout_id>/rollback", methods=["POST"])
    def api_fleet_rollout_rollback(rollout_id):
        """Halt the rollout. Optionally restore an archived build onto the fleet."""
        username, err, code = check_auth("command")
        if err:
            return err, code
        rollout = store.get_rollout(core.db, rollout_id)
        if not rollout:
            return jsonify({"error": "không tìm thấy rollout #%d" % rollout_id}), 404
        body = request.json or {}
        previous = str(rollout.get("previous_version") or body.get("previous_version") or "")
        targets = store.list_rollout_targets(core.db, rollout_id)
        touched = [t for t in targets if str(t.get("status")) == "updated"]
        untouched = [t for t in targets if str(t.get("status")) != "updated"]
        for target in untouched:
            store.update_rollout_target(core.db, rollout_id, target.get("machine_id"),
                                        status="skipped", message="rollback: không gửi")
        store.update_rollout(core.db, rollout_id, state="rolled_back")

        archive = _archived_build(previous) if previous else None
        swapped = False
        reverted, failed = [], []
        if archive and body.get("swap_server_build") and touched:
            # Explicit opt-in only: replace the served EXE, then ask the machines that
            # already updated to install the archived (older) build again.
            root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            served = os.path.join(root, "dist", "GiamSatAgent.exe")
            try:
                import shutil
                shutil.copy2(archive, served)
                swapped = True
            except Exception as exc:
                return jsonify({"success": False, "rolled_back": True,
                                "error": "không thay được EXE đang phát: %s"
                                         % str(exc)[:160]}), 500
            by_id = {m.get("machine_id"): m for m in (core.db.get_machines() or [])}
            for target in touched:
                mid = target.get("machine_id")
                delivered = _send_update(core, by_id.get(mid) or target, previous)
                store.update_rollout_target(
                    core.db, rollout_id, mid,
                    status="requested" if delivered else "failed",
                    message="rollback về %s" % previous,
                    requested_at=time.strftime("%Y-%m-%d %H:%M:%S"))
                (reverted if delivered else failed).append(mid)
        core.db.insert_audit_log(
            username, "fleet_rollout_rollback",
            "rollout #%s dừng%s" % (rollout_id, " + phục hồi %s" % previous if swapped else ""),
            request.remote_addr)
        return jsonify({
            "success": True, "rolled_back": True, "state": "rolled_back",
            "previous_version": previous, "archive": archive or "",
            "swapped_server_build": swapped,
            "already_updated": [t.get("machine_id") for t in touched],
            "reverted": reverted, "revert_failed": failed,
            "skipped": [t.get("machine_id") for t in untouched],
            "note": ("Đã phục hồi bản %s cho %d máy" % (previous, len(reverted))) if swapped
                    else ("Không có bản lưu trữ cho %s - đã DỪNG triển khai. Muốn phục hồi hãy "
                          "copy EXE cũ vào dist_archive/GiamSatAgent-<version>.exe rồi gọi lại "
                          "với swap_server_build=true" % (previous or "?")),
        })

    @app.route("/api/health/fleet")
    def api_health_fleet():
        """Per-machine health (silent/outdated/coverage) + rejected-ingest counters."""
        _, err, code = check_auth("api")
        if err:
            return err, code
        silent_minutes = int(request.args.get("silent_minutes", SILENT_MINUTES))
        hours = int(request.args.get("hours", 24))
        machines = core.db.get_machines() or []
        server_version = core.db.get_server_agent_version() or ""
        health = fl.machine_health_rows(machines, store.heartbeat_map(core.db),
                                        server_version, silent_minutes=silent_minutes)
        persisted = fl.aggregate_anomalies(store.list_ingest_anomalies(core.db, hours=hours))
        try:
            pending = fl.aggregate_anomalies(core.tcp_server.ingest_anomalies_snapshot())
        except Exception:
            pending = []
        health["ingest"] = {"persisted": persisted, "pending": pending, "hours": hours,
                            "silent_minutes": silent_minutes}
        health["summary"]["rejected_sources"] = len({i["source_ip"]
                                                     for i in persisted + pending})
        health["summary"]["rejected_messages"] = sum(i["count"] for i in persisted + pending)
        return jsonify(health)

    @app.route("/api/policies/preview", methods=["POST"])
    def api_policies_preview():
        """Dry-run a group policy: who is affected, current state, wave plan."""
        _, err, code = check_auth("api")
        if err:
            return err, code
        import search_engine as se
        body = request.json or {}
        policy_id = body.get("policy_id")
        kind = se.backend_kind(core.db)
        policy = None
        if policy_id is not None:
            rows = se.rows(core.db, "SELECT id, group_id, policy_type, policy_name, config_json, "
                                    "enabled, apply_status FROM group_policies WHERE id = %s"
                           % se.placeholder(kind), (int(policy_id),), kind)
            policy = se.normalize_row(rows[0]) if rows else None
        if not policy:
            return jsonify({"ok": False, "error": "không tìm thấy chính sách"}), 404
        group_id = policy.get("group_id") or body.get("group_id")
        machines = _machines(core, group_id, body.get("machine_ids"))
        try:
            statuses = [se.normalize_row(r) for r in se.rows(
                core.db, "SELECT machine_id, status, message FROM policy_apply_status "
                         "WHERE policy_id = %s" % se.placeholder(kind), (int(policy_id),), kind)]
        except Exception:
            statuses = []
        preview = fl.policy_preview(policy, machines, statuses, body.get("waves"))
        preview["group_id"] = group_id or ""
        return jsonify(preview)
