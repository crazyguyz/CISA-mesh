"""
API Common - Shared auth helpers for all route modules.
Mỗi module API imports trực tiếp từ đây để dùng _check_auth.
"""

import json
import os
from datetime import datetime, timezone
from flask import request, jsonify


def localize_utc(s):
    """v4.13: SQLite CURRENT_TIMESTAMP stores UTC strings ('YYYY-MM-DD HH:MM:SS').
    Convert a UTC string to the server's local timezone for correct display
    (e.g. UTC+7 Vietnam). Non-matching values are returned unchanged.
    """
    if not s:
        return s
    try:
        dt = datetime.strptime(str(s)[:19], "%Y-%m-%d %H:%M:%S")
        return dt.replace(tzinfo=timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return s


def register(app, core):
    """Store core instance references for use by other modules."""
    # This is a no-op route registration; just makes core available globally
    # for other modules to import
    import api.api_common as _mod
    _mod._core = core
    _mod._app = app


# Module-level references set by register()
_core = None
_app = None


def _get_token_from_request():
    """Extract JWT token from Authorization header or cookie."""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        token = request.cookies.get("giamsat_token", "")
    return token


def check_auth(permission="api"):
    """Check authentication and permission. Returns (username, None, None) or (None, error_response, status_code).
    v4.5.3 SECURITY: localhost no longer bypasses authentication - every API
    request requires a valid JWT token (login endpoint is open separately).
    v1.13.0 SECURITY: Enforces must_change_password - blocks all API access until password changed."""
    token = _get_token_from_request()
    if not token:
        return None, jsonify({"error": "Authentication required", "code": "AUTH_REQUIRED"}), 401
    payload = _core.auth.verify_token(token)
    if not payload:
        return None, jsonify({"error": "Invalid or expired token", "code": "INVALID_TOKEN"}), 401
    username = payload.get("sub", "")
    
    # v1.13.0 SECURITY: Block API access if must_change_password
    if payload.get("must_change_password"):
        allowed_paths = ["/api/users/password", "/api/logout", "/api/auth/check"]
        if request.path not in allowed_paths:
            return None, jsonify({
                "error": "Phải đổi mật khẩu trước khi sử dụng hệ thống. Vui lòng đổi mật khẩu mặc định.",
                "code": "MUST_CHANGE_PASSWORD",
                "must_change_password": True
            }), 403
    
    if not _core.auth.check_permission(username, permission):
        return None, jsonify({"error": "Insufficient permissions", "code": "FORBIDDEN"}), 403
    return username, None, None


def check_agent_psk(data=None):
    """Verify the agent PSK (shared secret) for agent-facing HTTP endpoints.
    v4.5.5 SECURITY: fail-closed — if GIAMSAT_AGENT_PSK is not configured, reject.
    v5.0.3 (LOW-9): per-machine PSK takes priority when the machine_id has an
    entry in GIAMSAT_PER_MACHINE_PSK / GIAMSAT_PER_MACHINE_PSK_FILE; also
    validates machine_id charset. Constant-time comparison.
    Returns True if valid, False otherwise.
    """
    from agent_auth import verify_agent_psk, validate_machine_id, has_any_psk
    token = ""
    machine_id = ""
    if isinstance(data, dict):
        token = (data.get("psk") or "").strip()
        machine_id = str(data.get("machine_id") or "").strip()
    if not token:
        token = (request.headers.get("X-Agent-PSK") or "").strip()
    if not machine_id:
        machine_id = str(request.headers.get("X-Machine-ID") or "").strip()
    if machine_id and not validate_machine_id(machine_id):
        return False
    # v5.0.4 (MEDIUM-3): per-machine PSK works WITHOUT a global PSK - fail-closed
    # only when the machine has neither a per-machine secret nor the global one.
    if not has_any_psk(machine_id):
        return False
    # v4.5.4 SECURITY: do NOT accept PSK via query string (leaks into access logs).
    expected = os.environ.get("GIAMSAT_AGENT_PSK", "")
    return verify_agent_psk(token, expected, machine_id)