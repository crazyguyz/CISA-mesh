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


def ensure_tailscale_up(auth_command):
    """Đảm bảo Tailscale đã cài + đã up (dùng đúng lệnh trong file)."""
    if not auth_command:
        return False, "khong co auth_command"
    if tailscale_status():
        return True, "da san sang"
    ok, msg = install_tailscale()
    if not ok:
        code, out = _run(auth_command.split(), timeout=60)
        if code == 0 or tailscale_status():
            return True, "tailscale up (khong can cai moi)"
        return False, "cai dat that bai: " + msg
    code, out = _run(auth_command.split(), timeout=90)
    if code == 0 or tailscale_status():
        return True, "tailscale up OK"
    return False, ("tailscale up fail: " + out)[:300]
