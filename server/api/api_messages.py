"""
API Messages - Server + Agent messaging v2.5.11
Admin sends message -> TCP 6666 -> Agent shows dialog -> user replies -> server saves
"""
import json
import uuid
from datetime import datetime
from flask import request, jsonify
from .api_common import check_auth, check_agent_psk

def register(app, core):
    """Register message API routes."""

    @app.route("/api/message/send", methods=["POST"])
    def message_send():
        username, err, code = check_auth("command")
        if err:
            return err, code

        data = request.get_json(force=True, silent=True) or {}
        machine_id = (data.get("machine_id") or "").strip()
        title = (data.get("title") or "Thong bao")[:100]
        message = (data.get("message") or "")[:1000]
        require_reply = data.get("require_reply", True)

        if not machine_id or not message.strip():
            return jsonify({"error": "machine_id and message required"}), 400

        msg_id = str(uuid.uuid4())[:12]
        sender = username or "admin"

        # Save message to DB (table created in db._init_db())
        core.db.conn.execute(
            "INSERT INTO messages (msg_id, machine_id, sender, title, message, require_reply, created_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (msg_id, machine_id, sender, title, message, 1 if require_reply else 0,
             datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        core.db.conn.commit()

        # Queue command for agent delivery (Pull Model with TCP best-effort)
        cmd_json = json.dumps({
            "action": "show_message", "msg_id": msg_id,
            "title": title, "message": message,
            "sender": sender, "require_reply": require_reply,
        }, ensure_ascii=False)
        core.db.add_command(machine_id, "show_message", cmd_json, msg_id)
        print(f"[MSG] Queued message {msg_id} for {machine_id} (pending)")

        # Try TCP push for immediate delivery (best-effort; command stays 'pending'
        # so the agent HTTP poll can re-deliver over unstable Tailscale links)
        tcp_sent = False
        if hasattr(core, 'tcp_server') and core.tcp_server:
            try:
                tcp_sent = core.tcp_server.send_command(machine_id, {
                    "action": "show_message", "msg_id": msg_id,
                    "title": title, "message": message,
                    "sender": sender, "require_reply": require_reply,
                })
                print(f"[MSG] TCP push {'OK' if tcp_sent else 'FAIL'} for {machine_id}")
            except Exception as e:
                print(f"[MSG] TCP push error for {machine_id}: {e}")

        return jsonify({
            "status": "queued",
            "msg_id": msg_id,
            "delivery": "tcp" if tcp_sent else "poll",
            "message": f"Message queued for {machine_id}. Delivery: {'TCP pushed' if tcp_sent else 'will deliver on next agent HTTP poll'}."
        })

    @app.route("/api/message/list/<machine_id>", methods=["GET"])
    def message_list(machine_id):
        _, err, code = check_auth("api")
        if err:
            return err, code

        rows = core.db.conn.execute(
            "SELECT msg_id,sender,title,message,reply,require_reply,status,direction,created_at,replied_at "
            "FROM messages WHERE machine_id=? ORDER BY id DESC LIMIT 50",
            (machine_id,)).fetchall()

        msgs = []
        for r in rows:
            msgs.append({
                "msg_id": r[0], "sender": r[1], "title": r[2], "message": r[3],
                "reply": r[4] or "", "require_reply": bool(r[5]),
                "status": r[6], "direction": r[7] or "server",
                "created_at": r[8] or "", "replied_at": r[9] or ""
            })
        return jsonify({"messages": msgs})

    @app.route("/api/message/delete/<msg_id>", methods=["DELETE"])
    def message_delete(msg_id):
        """Delete a specific message by msg_id.
        v4.11 (HIGH-3): viewer (read-only) must NOT be able to delete data ->
        raised to 'settings' (admin) + audit logged."""
        username, err, code = check_auth("settings")
        if err:
            return err, code

        try:
            core.db.conn.execute("DELETE FROM messages WHERE msg_id=?", (msg_id,))
            core.db.conn.commit()
            core.db.insert_audit_log(username, "delete_message",
                f"Xóa tin nhắn msg_id={msg_id}", request.remote_addr)
            return jsonify({"status": "deleted", "msg_id": msg_id})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/message/clear/<machine_id>", methods=["DELETE"])
    def message_clear_machine(machine_id):
        """Delete ALL messages for a specific machine.
        v4.11 (HIGH-3): raised to 'settings' (admin) + audit logged."""
        username, err, code = check_auth("settings")
        if err:
            return err, code

        try:
            c = core.db.conn.execute("DELETE FROM messages WHERE machine_id=?", (machine_id,))
            core.db.conn.commit()
            core.db.insert_audit_log(username, "clear_message_machine",
                f"Xóa toàn bộ tin nhắn máy {machine_id} ({c.rowcount} bản ghi)",
                request.remote_addr)
            return jsonify({"status": "deleted", "count": c.rowcount})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/message/clear-group/<group_id>", methods=["DELETE"])
    def message_clear_group(group_id):
        """Delete ALL messages for all machines in a group.
        v4.11 (HIGH-3): raised to 'settings' (admin) + audit logged."""
        username, err, code = check_auth("settings")
        if err:
            return err, code

        try:
            group = core.db.get_agent_group(group_id)
            if not group:
                return jsonify({"error": "Group not found"}), 404
            members = core.db._get_group_members(group_id) or []
            member_ids = [m["machine_id"] for m in members]

            if not member_ids:
                return jsonify({"status": "deleted", "count": 0})

            placeholders = ",".join("?" for _ in member_ids)
            c = core.db.conn.execute(
                f"DELETE FROM messages WHERE machine_id IN ({placeholders})",
                member_ids)
            core.db.conn.commit()
            core.db.insert_audit_log(username, "clear_message_group",
                f"Xóa toàn bộ tin nhắn nhóm {group_id} ({c.rowcount} bản ghi)",
                request.remote_addr)
            return jsonify({"status": "deleted", "count": c.rowcount})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/message/group-history/<group_id>", methods=["GET"])
    def message_group_history(group_id):
        """Get all messages for machines in a group (broadcast history)."""
        _, err, code = check_auth("api")
        if err:
            return err, code

        group = core.db.get_agent_group(group_id)
        if not group:
            return jsonify({"error": "Group not found"}), 404
        members = core.db._get_group_members(group_id) or []
        member_ids = [m["machine_id"] for m in members]

        if not member_ids:
            return jsonify({"messages": [], "group_name": group.get("name", "")})

        placeholders = ",".join("?" for _ in member_ids)
        rows = core.db.conn.execute(
            f"SELECT msg_id,sender,title,message,reply,require_reply,status,created_at,replied_at,machine_id "
            f"FROM messages WHERE machine_id IN ({placeholders}) ORDER BY id DESC LIMIT 100",
            member_ids).fetchall()

        msgs = []
        for r in rows:
            msgs.append({
                "msg_id": r[0], "sender": r[1], "title": r[2], "message": r[3],
                "reply": r[4] or "", "require_reply": bool(r[5]),
                "status": r[6], "created_at": r[7] or "", "replied_at": r[8] or "",
                "machine_id": r[9]
            })

        machine_names = {}
        all_machines = core.db.get_machines()
        for m in all_machines:
            machine_names[m.get("machine_id", "")] = m.get("hostname", "") or m.get("machine_id", "")

        return jsonify({"messages": msgs, "group_name": group.get("name", ""), "machine_names": machine_names})

    @app.route("/api/message/broadcast", methods=["POST"])
    def message_broadcast():
        """Send a message to multiple machines at once."""
        # v4.10 (HIGH-5): broadcast reaches every workstation screen - same
        # privilege as /api/message/send ("command"), not viewer.
        username, err, code = check_auth("command")
        if err:
            return err, code

        data = request.get_json(force=True, silent=True) or {}
        machine_ids = data.get("machine_ids") or []
        title = (data.get("title") or "Thong bao")[:100]
        message = (data.get("message") or "")[:1000]
        require_reply = data.get("require_reply", True)
        sender = username or "admin"

        if not machine_ids or not message.strip():
            return jsonify({"error": "machine_ids and message required"}), 400

        results = []
        for mid in machine_ids:
            mid = (mid or "").strip()
            if not mid:
                continue
            msg_id = str(uuid.uuid4())[:12]
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Save to DB
            core.db.conn.execute(
                "INSERT INTO messages (msg_id, machine_id, sender, title, message, require_reply, created_at) "
                "VALUES (?,?,?,?,?,?,?)",
                (msg_id, mid, sender, title, message, 1 if require_reply else 0, now))
            core.db.conn.commit()

            # Queue command as 'pending' (HTTP poll fallback for unstable links)
            cmd_json = json.dumps({
                "action": "show_message", "msg_id": msg_id,
                "title": title, "message": message,
                "sender": sender, "require_reply": require_reply,
            }, ensure_ascii=False)
            core.db.add_command(mid, "show_message", cmd_json, msg_id)

            # Try TCP push (best-effort)
            tcp_sent = False
            if hasattr(core, 'tcp_server') and core.tcp_server:
                try:
                    tcp_sent = core.tcp_server.send_command(mid, {
                        "action": "show_message", "msg_id": msg_id,
                        "title": title, "message": message,
                        "sender": sender, "require_reply": require_reply,
                    })
                except Exception:
                    pass

            results.append({"machine_id": mid, "msg_id": msg_id, "sent": tcp_sent})

        sent_count = sum(1 for r in results if r["sent"])
        return jsonify({
            "status": "completed",
            "total": len(results),
            "sent": sent_count,
            "failed": len(results) - sent_count,
            "results": results
        })

    @app.route("/api/message/from-agent", methods=["POST"])
    def message_from_agent():
        """Agent-initiated message (workstation user -> admin)."""
        data = request.get_json(force=True, silent=True) or {}

        # v4.5.5 SECURITY: require agent PSK (fail-closed + constant-time compare)
        if not check_agent_psk(data):
            return jsonify({"error": "invalid psk"}), 401

        machine_id = (data.get("machine_id") or "").strip()
        hostname = (data.get("hostname") or "").strip()
        message = (data.get("message") or "").strip()[:1000]
        title = (data.get("title") or "Tin nhắn từ máy trạm")[:100]

        if not machine_id or not message:
            return jsonify({"error": "machine_id and message required"}), 400

        u = core.db.get_machine_user(machine_id) or {}
        user_name = (u.get("user_name") or "").strip()
        sender = (user_name or hostname or machine_id)

        msg_id = str(uuid.uuid4())[:12]
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            core.db.conn.execute(
                "INSERT INTO messages (msg_id, machine_id, sender, title, message, require_reply, status, direction, created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (msg_id, machine_id, sender, title, message, 0, 'received', 'agent', now))
            core.db.conn.commit()
            # v4.10: push SSE event so the dashboard nav badge updates immediately
            # (previously the badge was only refreshed while the Messages tab was open)
            try:
                with core.sse_queue_lock:
                    core.sse_queue.append({
                        "type": "agent_message", "msg_id": msg_id,
                        "machine_id": machine_id, "hostname": hostname,
                        "sender": sender, "title": title,
                        "timestamp": now,
                    })
                    if len(core.sse_queue) > 1000:
                        core.sse_queue = core.sse_queue[-500:]
            except Exception:
                pass
            print(f"[MSG] Agent message received: {msg_id} from {machine_id} ({sender})")
        except Exception as e:
            print(f"[-] Failed to save agent message: {e}")
            return jsonify({"error": str(e)}), 500

        return jsonify({"status": "received", "msg_id": msg_id})

    @app.route("/api/message/unread-count", methods=["GET"])
    def message_unread_count():
        """Count agent-initiated messages the admin hasn't read yet."""
        _, err, code = check_auth("api")
        if err:
            return err, code
        try:
            rows = core.db.conn.execute(
                "SELECT COUNT(*) FROM messages WHERE direction='agent' AND status='received'"
            ).fetchall()
            count = rows[0][0] if rows else 0
            return jsonify({"count": count})
        except Exception:
            return jsonify({"count": 0})

    @app.route("/api/message/unread-by-machine", methods=["GET"])
    def message_unread_by_machine():
        """Count unread agent messages grouped by machine (per-machine badge)."""
        _, err, code = check_auth("api")
        if err:
            return err, code
        try:
            rows = core.db.conn.execute(
                "SELECT machine_id, COUNT(*) FROM messages "
                "WHERE direction='agent' AND status='received' GROUP BY machine_id"
            ).fetchall()
            return jsonify({r[0]: r[1] for r in rows})
        except Exception:
            return jsonify({})

    @app.route("/api/message/mark-read", methods=["POST"])
    def message_mark_read():
        """Mark agent messages for a machine as read."""
        _, err, code = check_auth("api")
        if err:
            return err, code
        data = request.get_json(force=True, silent=True) or {}
        machine_id = (data.get("machine_id") or "").strip()
        if not machine_id:
            return jsonify({"success": False, "error": "machine_id required"}), 400
        try:
            core.db.conn.execute(
                "UPDATE messages SET status='read' WHERE machine_id=? AND direction='agent' AND status='received'",
                (machine_id,))
            core.db.conn.commit()
            return jsonify({"success": True})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500