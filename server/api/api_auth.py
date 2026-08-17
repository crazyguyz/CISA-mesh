"""
API Auth - Login, logout, auth check, user management, password change.
"""

import json
import threading
import html as _html_mod
from datetime import datetime
from flask import request, jsonify

from .api_common import _core, check_auth


def register(app, core):
    """Register auth-related routes."""
    _core_module = __import__(__name__)
    # Use local references captured from api_common after register is called

    @app.route("/api/login", methods=["POST"])
    def api_login():
        data = request.json
        if not data or not isinstance(data, dict):
            return jsonify({"success": False, "error": "Invalid request body", "code": "INVALID_REQUEST"}), 400
        username = data.get("username", "")
        password = data.get("password", "")
        # v2.5.2 SECURITY: Strict input validation against JSON injection
        if not isinstance(username, str) or not isinstance(password, str):
            return jsonify({"success": False, "error": "Invalid credentials format", "code": "INVALID_CREDENTIALS"}), 401
        # v2.5.2: Reject empty or whitespace-only usernames/passwords
        username = username.strip()
        if not username or len(username) > 64:
            return jsonify({"success": False, "error": "Invalid username length", "code": "INVALID_CREDENTIALS"}), 401
        if not password or len(password) > 128:
            return jsonify({"success": False, "error": "Invalid password length", "code": "INVALID_CREDENTIALS"}), 401
        # v2.5.2: Reject obviously malicious inputs
        if any(c in username for c in '<>"\';\0\n\r\t'):
            return jsonify({"success": False, "error": "Invalid credentials", "code": "INVALID_CREDENTIALS"}), 401
        result = core.auth.authenticate(username, password)
        if result and result.get("success"):
            core.db.insert_audit_log(username, "login", "User logged in", request.remote_addr)
            resp = jsonify({
                "success": True,
                "token": result["token"],
                "role": result["role"],
                "must_change_password": result.get("must_change_password", False)
            })
            resp.set_cookie("giamsat_token", result["token"], httponly=True, samesite="Strict")
            return resp
        error_msg = result.get("error", "Invalid credentials") if result else "Invalid credentials"
        error_code = result.get("code", "INVALID_CREDENTIALS") if result else "INVALID_CREDENTIALS"
        status = 423 if error_code == "ACCOUNT_LOCKED" else 401
        
        if error_code == "ACCOUNT_LOCKED":
            try:
                alert_msg = (
                    f"🚨 <b>GIAM-SAT Security Alert</b>\n\n"
                    f"<b>Tài khoản bị khóa do brute-force:</b> <code>{_html_mod.escape(username)}</code>\n"
                    f"<b>IP tấn công:</b> <code>{_html_mod.escape(request.remote_addr)}</code>\n"
                    f"<b>Thời gian:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                    f"<b>Hành động:</b> Tài khoản bị khóa 15 phút sau 5 lần đăng nhập sai."
                )
                threading.Thread(target=core._send_telegram_message, args=(alert_msg,), daemon=True).start()
            except Exception:
                pass
        
        return jsonify({"success": False, "error": error_msg, "code": error_code}), status

    @app.route("/api/logout", methods=["POST"])
    def api_logout():
        from .api_common import _get_token_from_request
        token = _get_token_from_request()
        if token:
            core.auth.invalidate_token(token)
        return jsonify({"success": True})

    @app.route("/api/auth/check")
    def api_auth_check():
        from .api_common import _get_token_from_request
        token = _get_token_from_request()
        if token:
            payload = core.auth.verify_token(token)
            if payload:
                return jsonify({"authenticated": True, "username": payload.get("sub"), "role": payload.get("role")})
        return jsonify({"authenticated": False}), 401

    @app.route("/api/users", methods=["GET"])
    def api_users():
        username, err, code = check_auth("settings")
        if err: return err, code
        users = core.auth.get_users()
        core.db.insert_audit_log(username, "list_users", "", request.remote_addr)
        return jsonify(users)

    @app.route("/api/users", methods=["POST"])
    def api_add_user():
        username, err, code = check_auth("settings")
        if err: return err, code
        data = request.json
        result = core.auth.add_user(data.get("username", ""), data.get("password", ""), data.get("role", "viewer"))
        if result and result.get("success"):
            core.db.insert_audit_log(username, "add_user", f"Added user {data.get('username')}", request.remote_addr)
            return jsonify({"success": True})
        error_msg = result.get("error", "Failed to add user") if result else "Failed to add user"
        return jsonify({"success": False, "error": error_msg}), 400

    @app.route("/api/users/<username>", methods=["DELETE"])
    def api_delete_user(username):
        admin, err, code = check_auth("settings")
        if err: return err, code
        result = core.auth.remove_user(username)
        if result:
            core.db.insert_audit_log(admin, "delete_user", f"Deleted user {username}", request.remote_addr)
            return jsonify({"success": True})
        return jsonify({"success": False, "error": "Cannot delete admin or user not found"}), 400

    @app.route("/api/users/password", methods=["POST"])
    def api_change_password():
        username, err, code = check_auth("api")
        if err: return err, code
        data = request.json
        result = core.auth.change_password(username, data.get("old_password", ""), data.get("new_password", ""))
        if result and result.get("success"):
            core.db.insert_audit_log(username, "change_password", "Changed own password", request.remote_addr)
            resp = jsonify({"success": True, "token": result.get("token")})
            if result.get("token"):
                resp.set_cookie("giamsat_token", result["token"], httponly=True, samesite="Strict")
            return resp
        error_msg = result.get("error", "Incorrect old password") if result else "Incorrect old password"
        return jsonify({"success": False, "error": error_msg}), 400

    @app.route("/api/audit", methods=["GET"])
    def api_audit():
        username, err, code = check_auth("settings")
        if err: return err, code
        return jsonify(core.db.get_audit_log(limit=request.args.get("limit", 100, type=int)))