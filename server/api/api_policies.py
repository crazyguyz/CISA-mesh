"""
Group Policies API v1.0.0 for GIAM-SAT Server v3.9.2
REST API for managing per-group security policies:
  - block_websites: Block specific websites via hosts file + firewall
  - block_software: Block software installation via registry policies
  - block_usb: Block USB storage devices via registry
"""
import json
from datetime import datetime
from flask import request, jsonify
from .api_common import check_auth, check_agent_psk

_POLICY_TYPES = ["block_websites", "block_software", "block_usb"]

def register_routes(app, server_core):
    """Register all policy API routes with the Flask app."""

    @app.route("/api/policies/add", methods=["POST"])
    def api_policy_add():
        """Add a new policy to a group."""
        username, err, code = check_auth("delete")
        if err: return err, code
        data = request.get_json() or {}
        group_id = data.get("group_id")
        policy_type = data.get("policy_type", "")
        policy_name = data.get("policy_name", "")
        config = data.get("config", {})
        enabled = data.get("enabled", True)

        if not group_id:
            return jsonify({"success": False, "error": "group_id is required"}), 400
        if policy_type not in _POLICY_TYPES:
            return jsonify({"success": False, "error": f"Invalid policy_type. Must be one of: {_POLICY_TYPES}"}), 400

        try:
            policy_id = server_core.db.add_policy(
                group_id=int(group_id),
                policy_type=policy_type,
                policy_name=policy_name or f"{policy_type} - {datetime.now().strftime('%H:%M')}",
                config_json=json.dumps(config, ensure_ascii=False),
                enabled=1 if enabled else 0
            )
            server_core.db.insert_audit_log(username, "policy_add",
                f"Tạo policy '{policy_name or policy_type}' cho group {group_id} (id={policy_id})",
                request.remote_addr)
            return jsonify({"success": True, "policy_id": policy_id, "message": "Policy created"})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    @app.route("/api/policies/update/<int:policy_id>", methods=["POST"])
    def api_policy_update(policy_id):
        """Update an existing policy (resets to pending)."""
        username, err, code = check_auth("delete")
        if err: return err, code
        data = request.get_json() or {}
        policy_name = data.get("policy_name")
        config = data.get("config")
        enabled = data.get("enabled")

        config_json = json.dumps(config, ensure_ascii=False) if config is not None else None
        ok = server_core.db.update_policy(
            policy_id,
            policy_name=policy_name,
            config_json=config_json,
            enabled=enabled
        )
        if not ok:
            return jsonify({"success": False, "error": "Policy not found"}), 404
        server_core.db.insert_audit_log(username, "policy_update",
            f"Cập nhật policy id={policy_id} (name='{policy_name}', enabled={enabled})",
            request.remote_addr)
        return jsonify({"success": True, "message": "Policy updated, status reset to pending"})

    @app.route("/api/policies/delete/<int:policy_id>", methods=["POST"])
    def api_policy_delete(policy_id):
        """Delete a policy."""
        username, err, code = check_auth("delete")
        if err: return err, code
        server_core.db.delete_policy(policy_id)
        server_core.db.insert_audit_log(username, "policy_delete",
            f"Xóa policy id={policy_id}", request.remote_addr)
        return jsonify({"success": True, "message": "Policy deleted"})

    @app.route("/api/policies/list")
    def api_policy_list():
        """List policies, optionally filtered by group_id."""
        _, err, code = check_auth("api")
        if err: return err, code
        group_id = request.args.get("group_id", type=int)
        policies = server_core.db.get_policies(group_id=group_id)
        for p in policies:
            try:
                p["config"] = json.loads(p.get("config_json", "{}"))
            except Exception:
                p["config"] = {}
            del p["config_json"]
        return jsonify({"success": True, "policies": policies})

    @app.route("/api/policies/get/<int:policy_id>")
    def api_policy_get(policy_id):
        """Get a single policy by ID."""
        _, err, code = check_auth("api")
        if err: return err, code
        p = server_core.db.get_policy(policy_id)
        if not p:
            return jsonify({"success": False, "error": "Policy not found"}), 404
        try:
            p["config"] = json.loads(p.get("config_json", "{}"))
        except Exception:
            p["config"] = {}
        del p["config_json"]
        return jsonify({"success": True, "policy": p})

    @app.route("/api/policies/status", methods=["POST"])
    def api_policy_status():
        """v5.0.2: record per-machine apply status (agent-reported). Requires agent PSK."""
        data = request.get_json() or {}
        if not check_agent_psk(data):
            return jsonify({"error": "invalid psk"}), 401
        policy_id = data.get("policy_id")
        machine_id = (data.get("machine_id") or "").strip()
        status = data.get("status", "applied")
        message = data.get("message", "")

        if not policy_id:
            return jsonify({"success": False, "error": "policy_id is required"}), 400
        if status not in ("applied", "failed"):
            return jsonify({"success": False, "error": "Invalid status"}), 400

        server_core.db.set_policy_machine_status(int(policy_id), machine_id, status, message[:500])
        return jsonify({"success": True, "message": f"Policy status updated to {status}"})

    @app.route("/api/policies/requeue/<int:policy_id>", methods=["POST"])
    def api_policy_requeue(policy_id):
        """v5.0.2: reset per-machine apply tracking so every machine re-applies the policy."""
        username, err, code = check_auth("delete")
        if err: return err, code
        server_core.db.clear_policy_machine_status(policy_id)
        server_core.db.update_policy_status(policy_id, "pending", "re-queued for all machines")
        server_core.db.insert_audit_log(username, "policy_requeue",
            f"Re-queue policy id={policy_id} cho tất cả máy", request.remote_addr)
        return jsonify({"success": True, "message": "Policy re-queued for all machines"})

    @app.route("/api/policies/status-list")
    def api_policy_status_list():
        """v5.0.2: per-machine apply status for a policy (UI)."""
        _, err, code = check_auth("api")
        if err: return err, code
        policy_id = request.args.get("policy_id", type=int)
        if not policy_id:
            return jsonify({"success": False, "error": "policy_id required"}), 400
        rows = server_core.db.get_policy_machine_status(policy_id)
        return jsonify({"success": True, "rows": rows})

    @app.route("/api/policies/pending/<machine_id>")
    def api_policy_pending(machine_id):
        """v5.0.2: get pending policies for a specific machine (agent PSK - the agent is
        the intended caller; admin reads go through /api/policies/list)."""
        data = request.get_json(silent=True) or {}
        if not check_agent_psk(data):
            return jsonify({"error": "invalid psk"}), 401
        policies = server_core.db.get_pending_policies_for_machine(machine_id)
        for p in policies:
            try:
                p["config"] = json.loads(p.get("config_json", "{}"))
            except Exception:
                p["config"] = {}
            del p["config_json"]
        return jsonify({"success": True, "pending": policies})

    # ------------------------------------------------------------------ #
    # v5.0.8 (Phase D): canary rollout for GROUP POLICIES.
    # The agent only receives a policy when `get_pending_policies_for_machine`
    # returns it, i.e. when its per-machine row is neither 'applied' nor
    # 'blocked'. So a wave rollout is: mark the current wave 'pending' (offered)
    # and every other machine 'blocked' (hidden) - no new table needed.
    # ------------------------------------------------------------------ #
    def _policy_wave_targets(server_core, policy_id):
        """(policy, ids, waves_or_None, statuses_by_machine)."""
        import fleet as fl
        policy = server_core.db.get_policy(policy_id)
        if not policy:
            return None, [], None, {}
        group = server_core.db.get_agent_group(policy.get("group_id")) or {}
        ids = sorted(m.get("machine_id") for m in (group.get("members") or [])
                     if m.get("machine_id"))
        statuses = server_core.db.get_policy_machine_status(policy_id) or []
        by_id = {s.get("machine_id"): str(s.get("status") or "").lower() for s in statuses}
        return policy, ids, fl, by_id

    def _mark_wave(server_core, policy_id, ids, waves, index):
        """Offer `waves[index]` to its machines and block the rest."""
        wave_ids = set(waves[index]["machines"])
        offered, blocked = 0, 0
        for mid in ids:
            if mid in wave_ids:
                server_core.db.set_policy_machine_status(policy_id, mid, "pending",
                                                         "đợt %d/%d" % (index, len(waves)))
                offered += 1
            else:
                server_core.db.set_policy_machine_status(policy_id, mid, "blocked",
                                                         "chờ đợt (đang ở đợt %d)" % index)
                blocked += 1
        return sorted(wave_ids), offered, blocked

    @app.route("/api/policies/wave-apply", methods=["POST"])
    def api_policy_wave_apply():
        """Offer ONE wave of a policy (canary first); the rest stay blocked."""
        username, err, code = check_auth("delete")
        if err: return err, code
        data = request.get_json() or {}
        policy_id = data.get("policy_id")
        index = int(data.get("wave_index") or 0)
        if not policy_id:
            return jsonify({"success": False, "error": "policy_id is required"}), 400
        policy, ids, fl, _by_id = _policy_wave_targets(server_core, policy_id)
        if not policy:
            return jsonify({"success": False, "error": "Policy not found"}), 404
        if not ids:
            return jsonify({"success": False,
                            "error": "nhóm của chính sách chưa có máy nào"}), 400
        waves = fl.plan_waves(ids, data.get("waves"))
        if index < 0 or index >= len(waves):
            return jsonify({"success": False, "error": "đợt %d không tồn tại (có %d đợt)"
                            % (index, len(waves))}), 400
        offered, n_offered, n_blocked = _mark_wave(server_core, policy_id, ids, waves, index)
        server_core.db.insert_audit_log(
            username, "policy_wave_apply",
            "policy %s: đợt %d/%d - %d máy nhận, %d máy chờ"
            % (policy_id, index, len(waves), n_offered, n_blocked), request.remote_addr)
        return jsonify({"success": True, "policy_id": policy_id, "wave": index,
                        "waves": waves, "offered": offered, "count": n_offered,
                        "blocked": n_blocked})

    @app.route("/api/policies/wave-advance", methods=["POST"])
    def api_policy_wave_advance():
        """Advance after the current wave applied the policy (>= 90%, 0 failed)."""
        username, err, code = check_auth("delete")
        if err: return err, code
        data = request.get_json() or {}
        policy_id = data.get("policy_id")
        index = int(data.get("wave_index") or 0)
        force = bool(data.get("force"))
        if not policy_id:
            return jsonify({"success": False, "error": "policy_id is required"}), 400
        policy, ids, fl, by_id = _policy_wave_targets(server_core, policy_id)
        if not policy or not ids:
            return jsonify({"success": False, "error": "không tìm thấy chính sách/nhóm"}), 404
        waves = fl.plan_waves(ids, data.get("waves"))
        if index < 0 or index >= len(waves):
            return jsonify({"success": False, "error": "đợt %d không tồn tại" % index}), 400
        targets = [{"machine_id": mid, "wave": 0,
                    "status": ("updated" if by_id.get(mid) == "applied"
                               else ("failed" if by_id.get(mid) == "failed" else "pending"))}
                   for mid in waves[index]["machines"]]
        counts = fl.wave_health(targets, 0)
        ok, reason = fl.health_gate(counts)
        if not ok and not force:
            return jsonify({"success": False, "blocked": True, "reason": reason,
                            "counts": counts, "wave": index})
        if index + 1 >= len(waves):
            return jsonify({"success": True, "done": True, "gate": reason,
                            "message": "đã ở đợt cuối"})
        offered, n_offered, n_blocked = _mark_wave(server_core, policy_id, ids, waves, index + 1)
        server_core.db.insert_audit_log(
            username, "policy_wave_advance",
            "policy %s: sang đợt %d/%d - %d máy nhận, %d máy chờ (%s)"
            % (policy_id, index + 1, len(waves), n_offered, n_blocked, reason),
            request.remote_addr)
        return jsonify({"success": True, "wave": index + 1, "offered": offered,
                        "count": n_offered, "blocked": n_blocked, "gate": reason,
                        "forced": force and not ok})