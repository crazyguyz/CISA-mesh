"""GIAM-SAT v5.0.5 - Tailscale authkey management.

Nguon su that: server/.env
    GIAMSAT_TAILSCALE_AUTHKEY          key `tskey-auth-...`
    GIAMSAT_TAILSCALE_AUTHKEY_EXPIRY   ngay het han (YYYY-MM-DD)

Authkey nay duoc:
  - nhap/thay doi qua setup_config.ps1 hoac dashboard (tab Update Agent),
  - doc boi build-agent.ps1 de nhung vao GiamSatAgent.exe (tailscale_auth.txt),
  - dung de agent chay 'tailscale up' lan dau ma KHONG can file Google Drive cong khai.
Dashboard canh bao truoc khi key gan het han de quan tri vien build lai agent.
"""

import os
import re
import tempfile
from datetime import date, datetime

from flask import jsonify, request

from .api_common import check_auth

_ENV_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".env")
_AUTHKEY_RE = re.compile(r"^tskey-auth-[A-Za-z0-9_-]{8,}$")

# Nguong canh bao (ngay): duoi muc nay dashboard hien banner vang/do.
WARN_DAYS = 14
CRIT_DAYS = 7


def _read_env(path=None):
    """Doc server/.env thanh dict (khong phan tich gia tri phuc tap)."""
    path = path or _ENV_FILE
    out = {}
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8-sig") as f:
                for raw in f:
                    line = raw.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, _, v = line.partition("=")
                    out[k.strip()] = v.strip()
    except Exception:
        pass
    return out


def _write_env_keys(updates, path=None):
    """Ghi/Cap nhat cac key vao file .env (atomic: tmp + os.replace)."""
    path = path or _ENV_FILE
    updates = {k: ("" if v is None else str(v).strip()) for k, v in updates.items()}
    try:
        lines = []
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8-sig") as f:
                lines = f.read().splitlines()
        seen = set()
        result = []
        # Cap nhat tai cho neu key da ton tai (giu nguyen comment/vi tri);
        # gia tri RONG = XOA dong do (khong de lai `KEY=` vo nghia)
        for ln in lines:
            stripped = ln.strip()
            matched = False
            if stripped and not stripped.startswith("#") and "=" in stripped:
                k, _, _ = stripped.partition("=")
                if k.strip() in updates:
                    seen.add(k.strip())
                    if updates[k.strip()]:
                        result.append(f"{k.strip()}={updates[k.strip()]}")
                    # else: dong cu bi bo di
                    matched = True
            if not matched:
                result.append(ln)
        # Them key moi o cuoi file (chi khi gia tri khong rong)
        for k, v in updates.items():
            if k not in seen and v:
                if result and result[-1] != "":
                    result.append("")
                result.append(f"{k}={v}")
        if result and result[-1] != "":
            result.append("")
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".env.", suffix=".tmp", dir=d or ".")
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
                f.write("\n".join(result))
            os.replace(tmp, path)
        finally:
            try:
                os.remove(tmp)
            except Exception:
                pass
        # Cap nhat env cua tien trinh dang chay de khong can doc lai file
        for k, v in updates.items():
            if v:
                os.environ[k] = v
            else:
                os.environ.pop(k, None)
        return True, ""
    except Exception as e:
        return False, str(e)[:200]


def _normalize_expiry(raw):
    """Chuan hoa ngay het han ve YYYY-MM-DD (chap nhan dau '/' hoac '-')."""
    if not raw:
        return ""
    s = str(raw).strip()
    if not s:
        return ""
    s = s.split("T")[0].split(" ")[0]
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%m/%d/%Y"):
        try:
            return datetime.strptime(s, fmt).strftime("%Y-%m-%d")
        except ValueError:
            continue
    return ""


def _authkey_state(env=None):
    """Tinh trang authkey hien tai tu .env -> dict cho UI."""
    env = env if env is not None else _read_env()
    key = (env.get("GIAMSAT_TAILSCALE_AUTHKEY") or "").strip()
    exp_raw = (env.get("GIAMSAT_TAILSCALE_AUTHKEY_EXPIRY") or "").strip()
    state = {
        "configured": False,
        "key_valid_format": False,
        "masked": "",
        "last4": "",
        "expires_at": "",
        "days_left": None,
        "state": "not_configured",
        "warn_days": WARN_DAYS,
        "crit_days": CRIT_DAYS,
    }
    if key:
        state["configured"] = True
        state["last4"] = key[-4:] if len(key) > 4 else key
        state["masked"] = (key[:12] + "••••••" + state["last4"]) if len(key) > 20 else "••••" + state["last4"]
        state["key_valid_format"] = bool(_AUTHKEY_RE.match(key))
    if exp_raw:
        state["expires_at"] = exp_raw
        try:
            exp = datetime.strptime(exp_raw, "%Y-%m-%d").date()
            days = (exp - date.today()).days
            state["days_left"] = days
            if not state["configured"]:
                state["state"] = "not_configured"
            elif days < 0:
                state["state"] = "expired"
            elif days <= CRIT_DAYS:
                state["state"] = "expiring_critical"
            elif days <= WARN_DAYS:
                state["state"] = "expiring"
            else:
                state["state"] = "ok"
        except ValueError:
            state["state"] = "bad_expiry" if state["configured"] else "not_configured"
    elif state["configured"]:
        state["state"] = "no_expiry"
    return state

def register(app, core):
    """Register Tailscale authkey routes (Update Agent tab)."""

    @app.route("/api/tailscale/authkey")
    def api_tailscale_authkey_get():
        _, err, code = check_auth("settings")
        if err:
            return err, code
        st = _authkey_state()
        st["note"] = (
            "Authkey duoc nhung vao GiamSatAgent.exe luc build (tailscale_auth.txt). "
            "Xem/cap nhat trong server/.env hoac ngay tai day."
        )
        return jsonify(st)

    @app.route("/api/tailscale/authkey", methods=["PUT"])
    def api_tailscale_authkey_put():
        username, err, code = check_auth("settings")
        if err:
            return err, code
        data = request.json or {}
        authkey = (data.get("authkey") or "").strip()
        expiry_raw = (data.get("expires_at") or "").strip()

        cur_key = (_read_env().get("GIAMSAT_TAILSCALE_AUTHKEY") or "").strip()

        # CẢ key lẫn expiry để trống = xóa cấu hình (nút "Xóa cấu hình" ở UI)
        if not authkey and not expiry_raw:
            ok, e = _write_env_keys({
                "GIAMSAT_TAILSCALE_AUTHKEY": "",
                "GIAMSAT_TAILSCALE_AUTHKEY_EXPIRY": "",
            })
            if not ok:
                return jsonify({"success": False, "error": e}), 500
            core.db.insert_audit_log(username, "tailscale_authkey",
                                     "Cleared Tailscale authkey config", request.remote_addr)
            st = _authkey_state()
            st["success"] = True
            return jsonify(st)

        # Người dùng chỉ sửa ngày hết hạn cho key ĐANG CÓ (không được xóa key hiện hành)
        if not authkey:
            if not cur_key:
                return jsonify({"success": False,
                                "error": "Chua co authkey de gan ngay het han - nhap authkey truoc"}), 400
            authkey = cur_key

        is_new = authkey != cur_key
        if not _AUTHKEY_RE.match(authkey):
            return jsonify({"success": False,
                            "error": "Authkey khong hop le (phai bat dau bang tskey-auth-)"}), 400
        expiry = _normalize_expiry(expiry_raw)
        if expiry_raw and not expiry:
            return jsonify({"success": False,
                            "error": "Ngay het han khong hop le (dinh dang YYYY-MM-DD)"}), 400
        # Chỉ chặn ngày quá khứ khi NHẬP key mới; sửa ngày cho key cũ (đã có thể
        # quá hạn) thì cho phép để phản ánh đúng trạng thái.
        if expiry and is_new:
            try:
                if datetime.strptime(expiry, "%Y-%m-%d").date() < date.today():
                    return jsonify({"success": False,
                                    "error": "Ngay het han da qua khu - kiem tra lai authkey"}), 400
            except ValueError:
                return jsonify({"success": False, "error": "Ngay het han khong hop le"}), 400

        ok, e = _write_env_keys({
            "GIAMSAT_TAILSCALE_AUTHKEY": authkey,
            "GIAMSAT_TAILSCALE_AUTHKEY_EXPIRY": expiry,
        })
        if not ok:
            return jsonify({"success": False, "error": e}), 500
        core.db.insert_audit_log(username, "tailscale_authkey",
                                 (f"Updated Tailscale authkey (expires {expiry or 'none'})" if is_new
                                  else f"Updated Tailscale authkey expiry ({expiry})"),
                                 request.remote_addr)
        st = _authkey_state()
        st["success"] = True
        st["message"] = ("Da luu authkey. Nho BUILD LAI AGENT de nhung authkey moi." if is_new
                         else "Da cap nhat ngay het han authkey.")
        return jsonify(st)

