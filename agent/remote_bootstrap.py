"""GIAM-SAT Agent - remote bootstrap (v5.0.4): auto Tailscale + auto server info.

Nguồn dữ liệu: một file text CỐ ĐỊNH (host trên Google Drive / bất kỳ URL https),
cấu trúc:
  dòng 1  : lệnh kết nối Tailscale, VD  tailscale up --authkey=tskey-auth-...
  dòng 2  : ip-server:<host>[:port]   (hoặc 'ip-server = host', không phân biệt hoa thường)

Agent tự tải file này, đọc cấu hình server từ đó (không cần người dùng điền) và
tự cài/kết nối Tailscale nếu máy chưa có. Có thể đổi URL bằng biến môi trường
GIAMSAT_TAILSCALE_CONF_URL (mặc định là link Drive cố định).

An toàn: lệnh remote chỉ được phép là 'tailscale up ...' (không shell metachar),
không bao giờ thực thi nội dung khác.
"""

import os
import re
import subprocess
import time

# Google Drive "view" link -> "uc?export=download" để tải raw nội dung
_REMOTE_URL = (
    "https://drive.google.com/uc?export=download&id=1dcxpt-F0SN90q0ZUCIc1SWMSVDEvew_o"
)

_TS_CMD_RE = re.compile(r"^tailscale\s+up\b")
_BAD_CHARS = re.compile(r"[&|;`<>$]")


def _conf_path():
    return os.path.join(os.environ.get("PROGRAMDATA", r"C:\ProgramData"),
                        "GIAM-SAT", "Agent", "tailscale-conf.txt")


def _http_get(url, timeout=20):
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def fetch_remote_config(use_cache_fallback=True):
    """Tải + cache file cấu hình từ xa. Trả dict hoặc None.
    keys: auth_command / server_host / server_port / raw"""
    text = None
    url = os.environ.get("GIAMSAT_TAILSCALE_CONF_URL", _REMOTE_URL).strip()
    try:
        text = _http_get(url)
    except Exception:
        text = None
    if not text or not text.strip():
        if use_cache_fallback:
            try:
                with open(_conf_path(), "r", encoding="utf-8") as f:
                    cached = f.read()
                if cached.strip():
                    text = cached
            except Exception:
                pass
    if not text or not text.strip():
        return None
    try:
        os.makedirs(os.path.dirname(_conf_path()), exist_ok=True)
        with open(_conf_path(), "w", encoding="utf-8") as f:
            f.write(text)
    except Exception:
        pass
    return parse_remote_text(text)


def parse_remote_text(text):
    """Parse nội dung file (không phụ thuộc CRLF)."""
    lines = [ln.strip() for ln in (text or "").splitlines() if ln.strip()]
    out = {"auth_command": "", "server_host": "", "server_port": 0,
           "psk": "", "command_key": "", "raw": text[:2000]}
    for i, ln in enumerate(lines):
        if i == 0 and _TS_CMD_RE.match(ln) and not _BAD_CHARS.search(ln):
            out["auth_command"] = ln
            continue
        m = re.match(r"(?i)^\s*(?:ip-server|server)\s*[:=]\s*(\S+)\s*$", ln)
        if m and m.group(1):
            val = m.group(1).strip()
            if ":" in val:
                host, _, port = val.rpartition(":")
                if host and port.isdigit():
                    out["server_host"] = host
                    out["server_port"] = int(port)
                    continue
            out["server_host"] = val
            continue
        # tuỳ chọn (an toàn khi file được host NỘI BỘ): psk / command_key
        sk = re.match(r"(?i)^\s*(psk|command[_-]?key)\s*[:=]\s*(\S+)\s*$", ln)
        if sk:
            key = "command_key" if "key" in sk.group(1).lower() else "psk"
            out[key] = sk.group(2)
    return out



# ------------------------------------------------------------------ Tailscale
def _tailscale_exe():
    try:
        import shutil
        p = shutil.which("tailscale")
        if p:
            return p
    except Exception:
        pass
    cand = os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"),
                        "Tailscale", "tailscale.exe")
    return cand if os.path.exists(cand) else "tailscale.exe"


def _run(cmd, timeout=120):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except Exception as e:
        return -1, str(e)


def is_admin():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def tailscale_status():
    code, out = _run([_tailscale_exe(), "status"], timeout=10)
    return code == 0


def tailscale_has_ip():
    """v4.8.1: máy có IP tailnet thật không (daemon cấp IP)?"""
    code, out = _run([_tailscale_exe(), "ip", "-4"], timeout=10)
    return code == 0 and bool((out or "").strip())


def start_tailscale_service():
    """NoState thường do service 'Tailscale' (tailscaled) bị dừng chứ KHÔNG phải do
    agent kill GUI. Thử khởi động service trước khi quyết định cài lại."""
    if os.name != "nt":
        return False
    try:
        code, out = _run(["sc", "query", "Tailscale"], timeout=10)
        if code != 0:
            return False  # service chưa tồn tại -> cần cài
        code, _ = _run(["sc", "start", "Tailscale"], timeout=15)
        if code == 0:
            _run(["sc", "config", "Tailscale", "start=", "auto"], timeout=10)  # best-effort
        return code == 0
    except Exception:
        return False


def ensure_tailscale_up(auth_command):
    """Đảm bảo Tailscale đã cài + đã up (dùng đúng lệnh trong file)."""
    if not auth_command:
        return False, "khong co auth_command"
    if tailscale_status():
        hide_tray_icon()  # đã up - chỉ cần ẩn icon tray
        mark_enabled()
        return True, "da san sang"
    # NoState / daemon tắt -> thử bật service trước
    if start_tailscale_service():
        import time as _time
        _time.sleep(2)
        if tailscale_status():
            hide_tray_icon()
            mark_enabled()
            return True, "da chay lai service Tailscale"
    return _ensure_up_install(auth_command)


_last_install_ts = None  # debounce: tránh cài lại Tailscale liên tục mỗi phút


def _ensure_up_install(auth_command):
    if tailscale_status():
        hide_tray_icon()
        mark_enabled()
        return True, "da san sang"
    # 1) Kẹt "starting"/NoState (service chạy nhưng daemon chưa lên) -> kick bằng
    #    chính lệnh up, KHÔNG cần cài lại. Đã xác minh thực tế: 'tailscale up' đủ
    #    để daemon hết NoState (sự cố máy trạm 15:26 ngày 06/09/2026).
    code, out = _run(auth_command.split(), timeout=60)
    if code == 0 or tailscale_status():
        hide_tray_icon()
        mark_enabled()
        return True, "tailscale up OK (kick thoat NoState)"
    # 2) Chỉ cài lại khi service biến mất HOẶC lần cài trước đã >10 phút, tránh
    #    "bão msiexec" (mỗi phút tải MSI cài lại) khiến daemon không bao giờ up nổi.
    global _last_install_ts
    now = time.time()
    if _last_install_ts is None or (now - _last_install_ts) > 600:
        _last_install_ts = now
        ok, msg = install_tailscale()
        code, out = _run(auth_command.split(), timeout=90)
        if code == 0 or tailscale_status():
            hide_tray_icon()
            mark_enabled()
            return True, ("cai moi + up OK" if ok else "up OK (khong can cai moi)")
        return False, ("cai/up that bai: " + (out or msg))[:300]
    return False, "vua thu cai gan day - cho 10 phut roi moi cai lai"


def install_tailscale():
    """Cài Tailscale (cần quyền admin). winget trước, fallback MSI trực tiếp."""
    if os.name != "nt":
        return False, "khong phai Windows"
    if not is_admin():
        return False, "can quyen Admin"
    try:
        code, out = _run(["winget", "install", "--id", "Tailscale.Tailscale",
                          "--accept-source-agreements", "--accept-package-agreements",
                          "--silent"], timeout=240)
        if code == 0:
            return True, "winget OK"
    except Exception:
        pass
    try:
        import tempfile
        import urllib.request
        msi = os.path.join(tempfile.gettempdir(), "tailscale-setup-amd64.msi")
        urllib.request.urlretrieve(
            "https://pkgs.tailscale.com/stable/tailscale-setup-latest-amd64.msi", msi)
        code, out = _run(["msiexec", "/i", msi, "/qn", "/norestart"], timeout=300)
        if code == 0:
            return True, "msi OK"
        return False, "msi exit " + str(code)
    except Exception as e:
        return False, str(e)





# ------------------------------------------------------------------ ẩn icon tray + watchdog phục hồi
def _flag_path():
    return os.path.join(os.environ.get("PROGRAMDATA", r"C:\ProgramData"),
                        "GIAM-SAT", "Agent", "tailscale-enabled.flag")


def mark_enabled():
    """Đánh dấu máy này DÙNG cơ chế Tailscale (để watchdog chỉ hoạt động ở đây)."""
    try:
        os.makedirs(os.path.dirname(_flag_path()), exist_ok=True)
        with open(_flag_path(), "w") as f:
            f.write("1")
    except Exception:
        pass


def is_enabled():
    return os.path.exists(_flag_path())


def hide_tray_icon():
    """Ẩn icon/tray Tailscale một cách AN TOÀN (v4.8.2):
    Chỉ xoá shortcut Startup (chặn GUI tự mở lại khi logon). KHÔNG force-kill
    tailscale-ipn.exe vì nhiều máy bị MẤT IP tailnet khi kill GUI (daemon phụ thuộc
    GUI giữ login/session). Muốn kill thật: đặt file 'tailscale-hide-force' trong
    C:\\ProgramData\\GIAM-SAT\\Agent (sẽ tự xoá sau khi dùng)."""
    removed = False
    try:
        # 1) Xoá shortcut Startup (luôn an toàn - chỉ chặn GUI tự mở lại khi logon)
        cands = [
            os.path.join(os.environ.get("APPDATA", ""),
                         r"Microsoft\Windows\Start Menu\Programs\Startup\Tailscale.lnk"),
        ]
        sd = os.environ.get("SystemDrive", "C:")
        users_root = os.path.join(sd, "Users")
        if os.path.isdir(users_root):
            for uname in os.listdir(users_root):
                up = os.path.join(users_root, uname, "AppData", "Roaming",
                                  "Microsoft", "Windows", "Start Menu",
                                  "Programs", "Startup", "Tailscale.lnk")
                if os.path.isdir(os.path.dirname(up) or "."):
                    cands.append(up)
        for p in cands:
            try:
                if p and os.path.exists(p):
                    os.remove(p)
                    removed = True
            except Exception:
                pass
    except Exception:
        pass
    # 2) v4.8.2: KHÔNG force-kill GUI (mặc định). Trên nhiều máy, daemon (service)
    #    phụ thuộc tailscale-ipn giữ login/session -> kill GUI làm MẤT IP tailnet
    #    (đã tái diễn nhiều lần dù có cơ chế khôi phục). Xoá shortcut Startup là đủ
    #    để lần logon sau không có icon. Muốn kill thật: tạo file
    #    ...\Agent\tailscale-hide-force (1 lần, sẽ tự xoá).
    try:
        _fl = os.path.join(os.environ.get("PROGRAMDATA", r"C:\ProgramData"),
                           "GIAM-SAT", "Agent", "tailscale-hide-force")
        if os.path.exists(_fl):
            _run(["taskkill", "/IM", "tailscale-ipn.exe", "/F"], timeout=15)
            try:
                os.remove(_fl)
            except Exception:
                pass
    except Exception:
        pass
    return removed


def watchdog_loop():
    """v5.0.4: chạy nền (main.py) - nếu user vô tình xóa Tailscale / mất kết nối,
    tự cài lại + chạy lại lệnh auth rồi ẩn icon. Chỉ chạy khi máy đang dùng cơ chế
    này (có flag hoặc cache auth command)."""
    import time as _time
    while True:
        _time.sleep(60)
        try:
            if not is_enabled():
                continue
            if tailscale_status():
                continue  # kết nối còn sống
            rc = fetch_remote_config(use_cache_fallback=True)
            if rc and rc.get("auth_command"):
                ok, msg = ensure_tailscale_up(rc["auth_command"])
                if ok:
                    hide_tray_icon()
                    mark_enabled()
        except Exception:
            pass
