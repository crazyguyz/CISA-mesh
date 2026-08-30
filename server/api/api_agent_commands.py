"""
API Agent Commands - Pull model for sending commands to agents.
Agents poll this endpoint to get pending commands (message, response, policy, etc.).
Avoids the Tailscale TCP asymmetric routing issue where server→agent sendall() fails.

POST /api/agent/pending-commands
  Body: {"machine_id": "...", "version": "..."}
  Returns: {"pending": [{"action": "...", "command": "...", "exec_id": "..."}, ...]}

POST /api/agent/command-result
  Body: {"machine_id": "...", "exec_id": "...", "status": "completed|failed", "output": "...", "error": "..."}
"""
import json
import time
from datetime import datetime, timedelta
from flask import request, jsonify

from .api_common import check_agent_psk
from command_signer import sign_command


def register(app, core):
    """Register agent command polling routes."""

    @app.route("/api/agent/pending-commands", methods=["POST"])
    def api_agent_pending_commands():
        """Agent polls this to get pending commands. Requires agent PSK."""
        data = request.get_json(force=True, silent=True) or {}
        if not check_agent_psk(data):
            return jsonify({"error": "invalid psk"}), 401
        machine_id = (data.get("machine_id") or "").strip()

        if not machine_id:
            return jsonify({"error": "machine_id required"}), 400

        # Update machine online status (heartbeat via HTTP)
        # v4.10 (LOW-3): NOW() is PostgreSQL-only - SQLite raised, the exception
        # was swallowed and HTTP-polled machines were never marked online.
        try:
            now_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            core.db.conn.execute(
                "UPDATE machines SET last_seen=?, is_online=1 WHERE machine_id=?",
                (now_ts, machine_id)
            )
            core.db.conn.commit()
        except Exception:
            pass

        # v5.0.4 (logic bug): a command marked 'sent' (agent fetched it via poll)
        # but never reported back - because the agent went offline/crashed between
        # fetch and result - was stuck in 'sent' forever and never re-delivered.
        # Requeue it as 'pending' after 5 minutes so it is delivered on reconnect.
        # ISO-string comparison is backend-agnostic (SQLite TEXT + PG timestamptz).
        try:
            _cutoff = (datetime.now() - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
            core.db.conn.execute(
                "UPDATE commands SET status='pending' WHERE status='sent' AND executed_at < ?",
                (_cutoff,)
            )
            core.db.conn.commit()
        except Exception:
            pass

        # Get pending commands for this machine
        pending = []
        try:
            rows = core.db.conn.execute(
                "SELECT id, action, command, exec_id, created_at FROM commands "
                "WHERE machine_id=? AND status='pending' ORDER BY id ASC LIMIT 10",
                (machine_id,)
            ).fetchall()

            for row in rows:
                cmd = sign_command({"action": row["action"], "command": row["command"], "exec_id": row["exec_id"], "created_at": str(row["created_at"])})
                pending.append(cmd)
                # Mark as sent (not completed - agent will report completion separately)
                core.db.conn.execute(
                    "UPDATE commands SET status='sent', executed_at=? WHERE exec_id=?",
                    (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), row["exec_id"])
                )
            if pending:
                core.db.conn.commit()
        except Exception as e:
            print(f"[-] Pending commands query error: {e}")

        return jsonify({"pending": pending, "server_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})

    @app.route("/api/agent/command-result", methods=["POST"])
    def api_agent_command_result():
        """Agent reports back command execution result. Requires agent PSK."""
        data = request.get_json(force=True, silent=True) or {}
        if not check_agent_psk(data):
            return jsonify({"error": "invalid psk"}), 401
        machine_id = (data.get("machine_id") or "").strip()
        exec_id = (data.get("exec_id") or "").strip()
        status = (data.get("status") or "completed")
        # v4.5.5 SECURITY: validate status against allowlist (prevent arbitrary values / XSS)
        if status not in ("completed", "failed", "timeout", "error"):
            status = "failed"
        output = (data.get("output") or "")[:5000]
        error = (data.get("error") or "")[:2000]

        if not machine_id or not exec_id:
            return jsonify({"error": "machine_id and exec_id required"}), 400

        try:
            # v2.5.11: Handle message reply from agent
            action = data.get("action", "")
            if action == "show_message" and data.get("msg_replied"):
                try:
                    core.db.conn.execute(
                        "UPDATE messages SET reply=?, status='replied', replied_at=? "
                        "WHERE msg_id=? AND machine_id=? AND (reply IS NULL OR reply='')",
                        (data.get("msg_reply", "")[:500],
                         datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                         data.get("msg_id", ""), machine_id)
                    )
                    core.db.conn.commit()
                    print(f"[*] Message reply saved (HTTP): {exec_id} from {machine_id}")
                except Exception as e:
                    print(f"[-] Failed to save message reply (HTTP): {e}")

            # Update command status
            # v4.5.5 SECURITY: tie exec_id to machine_id (prevent result spoofing across machines)
            core.db.conn.execute(
                "UPDATE commands SET status=?, executed_at=? WHERE exec_id=? AND machine_id=?",
                (status, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), exec_id, machine_id)
            )

            # v5.0.2: policy enforcement result -> per-machine apply tracking.
            # exec_id embeds the policy id: apply => policy_<id>_<machine>, remove => policy_rm_<id>_<machine>.
            # (Fixes BUG: apply_status was never persisted because the agent reports over
            # HTTP while the old policy-status code only existed on the TCP path.)
            if action and (action.startswith("apply_block_") or action.startswith("remove_block_")):
                import re as _re
                _m = _re.match(r"^policy_rm_(\d+)_", exec_id or "")
                if _m:
                    _pid = int(_m.group(1))
                    # removal delivered -> machine back to baseline
                    if status in ("completed",):
                        core.db.mark_policy_removal_sent(_pid, machine_id)
                    print(f"[POLICY] removal result for {machine_id}: policy={_pid} status={status}")
                else:
                    _m = _re.match(r"^policy_(\d+)_", exec_id or "")
                    if _m:
                        _pid = int(_m.group(1))
                        _pstatus = "applied" if status == "completed" else "failed"
                        _msg = (output or error or "")[:500]
                        core.db.set_policy_machine_status(_pid, machine_id, _pstatus, _msg)
                        print(f"[POLICY] apply result for {machine_id}: policy={_pid} -> {_pstatus}")

            # Save response result
            try:
                core.db.insert_response_result({
                    "machine_id": machine_id,
                    "hostname": data.get("hostname", ""),
                    "exec_id": exec_id,
                    "status": status,
                    "output": output,
                    "error": error,
                    "exit_code": data.get("exit_code", 0),
                    "action": action,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                })
            except Exception:
                pass

            core.db.conn.commit()
        except Exception as e:
            print(f"[-] Command result error: {e}")
            return jsonify({"error": str(e)}), 500

        return jsonify({"status": "ok"})

    @app.route("/api/agent/heartbeat", methods=["POST"])
    def api_agent_heartbeat():
        """v3.9.7: HTTP heartbeat endpoint.
        Combines heartbeat update + pending command poll in one request. Requires agent PSK."""
        data = request.get_json(force=True, silent=True) or {}
        if not check_agent_psk(data):
            return jsonify({"error": "invalid psk"}), 401
        machine_id = (data.get("machine_id") or "").strip()
        hostname = (data.get("hostname") or "").strip()
        agent_version = (data.get("version") or "").strip()

        if not machine_id:
            return jsonify({"error": "machine_id required"}), 400

        # Register/update machine if needed
        ip = request.remote_addr or ""
        try:
            core.db.register_machine(machine_id, hostname, ip, "Windows", agent_version)
        except Exception:
            pass

        # Insert heartbeat
        try:
            core.db.insert_heartbeat({
                "machine_id": machine_id,
                "hostname": hostname,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "version": agent_version,
            })
        except Exception:
            pass

        # Check pending commands
        pending = []
        try:
            rows = core.db.conn.execute(
                "SELECT action, command, exec_id, created_at FROM commands "
                "WHERE machine_id=? AND status='pending' ORDER BY id ASC LIMIT 10",
                (machine_id,)
            ).fetchall()

            for row in rows:
                cmd = sign_command({"action": row["action"], "command": row["command"], "exec_id": row["exec_id"], "created_at": str(row["created_at"])})
                pending.append(cmd)
                core.db.conn.execute(
                    "UPDATE commands SET status='sent', executed_at=? WHERE exec_id=?",
                    (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), row["exec_id"])
                )
            if pending:
                core.db.conn.commit()
        except Exception:
            pass

        return jsonify({
            "status": "ok",
            "pending": pending,
            "server_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        })
    # v4.14 (P2): updater watchdog Telegram alerts - PSK-gated agent endpoint.
    # The updater daemon has no user JWT, so it cannot use /api/telegram/send.
    @app.route("/api/agent/telegram-alert", methods=["POST"])
    def api_agent_telegram_alert():
        """Send a Telegram alert on behalf of an agent/updater (watchdog restart etc.)."""
        data = request.get_json(force=True, silent=True) or {}
        if not check_agent_psk(data):
            return jsonify({"error": "invalid psk"}), 401
        message = (data.get("message") or "").strip()
        if not message:
            return jsonify({"success": False, "error": "empty message"}), 400
        try:
            success = core._send_telegram_message(message, data.get("chat_id") or core.telegram_chat_id)
        except Exception as e:
            return jsonify({"success": False, "error": str(e)[:200]}), 500
        return jsonify({"success": bool(success)})

