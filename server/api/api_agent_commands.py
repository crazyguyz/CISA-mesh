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
from datetime import datetime
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
        try:
            core.db.conn.execute(
                "UPDATE machines SET last_seen=NOW(), is_online=1 WHERE machine_id=?",
                (machine_id,)
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