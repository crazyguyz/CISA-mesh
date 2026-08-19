"""
GIAM-SAT Agent Updater v3.5.0 - Background Daemon
Runs via Task Scheduler ONLOGON (same as Agent), hidden console.

Responsibilities:
  - HTTP server 127.0.0.1:5999 (receives commands from Agent)
  - POST /update  -> Download new EXE, kill old Agent, start new Agent
  - POST /reset-user -> Show config dialog, restart computer
  - Every 15 minutes: check version, auto-download if newer
  - POST /msg    -> Show message box to user

Agent forwards server commands to this Updater via localhost HTTP.
Updater can freely kill/start Agent since they are separate processes.
"""
import os
import sys
import json
import time
import shutil
import tempfile
import urllib.request
import subprocess
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
# v3.7.0: Named Pipe IPC (replaces HTTP localhost for internal Agent ↔ Updater comms)
try:
    from named_pipe_ipc import NamedPipeServer, VALID_COMMANDS
    _HAS_NAMED_PIPE = True
except ImportError:
    _HAS_NAMED_PIPE = False

AGENT_EXE_NAME = "GiamSatAgent.exe"
SERVICE_NAME = "GiamSatAgent"
LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 5999


# ===================================================================
# HELPERS
# ===================================================================

def _detect_agent_dir():
    """Auto-detect directory where GiamSatAgent.exe is located."""
    # 1. Same directory as updater
    my_dir = os.path.dirname(os.path.abspath(sys.executable))
    if os.path.exists(os.path.join(my_dir, AGENT_EXE_NAME)):
        return my_dir
    # 2. Read from Windows Service
    try:
        r = subprocess.run(["sc", "qc", SERVICE_NAME], capture_output=True, text=True,
                           creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0,
                           timeout=10)
        for line in (r.stdout or "").split('\n'):
            if 'BINARY_PATH_NAME' in line.upper():
                path = line.split(':', 1)[-1].strip().strip('"')
                d = os.path.dirname(path)
                if os.path.exists(os.path.join(d, AGENT_EXE_NAME)):
                    return d
    except Exception:
        pass
    return r"C:\Program Files\GIAM-SAT Agent"

INSTALL_DIR = _detect_agent_dir()


def _cfg(key, default=None):
    cfg_path = os.path.join(
        os.environ.get("PROGRAMDATA", r"C:\ProgramData"),
        "GIAM-SAT", "Agent", "agent_config.json")
    try:
        if os.path.exists(cfg_path):
            with open(cfg_path, "r") as f:
                return json.load(f).get(key, default)
    except Exception:
        pass
    return default


def _server_host():
    return _cfg("server_host", "127.0.0.1")


def _updater_auth_token():
    """v4.10 (CRIT-2): shared secret for the localhost:5999 HTTP fallback.
    Derived from command_key (known only to agent + updater on this machine)."""
    key = (_cfg("command_key") or "").strip()
    if not key:
        return ""
    import hashlib
    return hashlib.sha256((key + ":updater").encode()).hexdigest()


def _check_updater_auth(handler):
    expected = _updater_auth_token()
    if not expected:
        return False
    got = handler.headers.get("X-Updater-Token", "")
    import hmac
    return hmac.compare_digest(got, expected)


def _server_port():
    """HTTP web port (always 5000, NOT TCP 6666)."""
    return 5000


def _agent_exe():
    return os.path.join(INSTALL_DIR, AGENT_EXE_NAME)


def _my_exe():
    return sys.executable


def _log(msg):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}", flush=True)
    # Also write to log file
    try:
        log_path = os.path.join(INSTALL_DIR, "updater.log")
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")
    except Exception:
        pass


# ===================================================================
# AGENT CONTROL (kill + start)
# ===================================================================

def kill_agent():
    """Kill agent by any means necessary."""
    # 1. Try service stop
    try:
        subprocess.run(["sc", "stop", SERVICE_NAME], capture_output=True, timeout=15,
                       creationflags=subprocess.CREATE_NO_WINDOW)
        time.sleep(2)
    except Exception:
        pass
    # 2. Force kill process
    try:
        subprocess.run(["taskkill", "/F", "/IM", AGENT_EXE_NAME], capture_output=True, timeout=10,
                       creationflags=subprocess.CREATE_NO_WINDOW)
    except Exception:
        pass
    time.sleep(2)


def _cleanup_runtime_mei():
    """v3.9.7: Clean up old _MEI* dirs from custom runtime_tmpdir before launching agent.
    This prevents unbounded disk growth caused by PyInstaller extractions on every restart."""
    import glob as _glob
    runtime_dir = os.path.join(os.environ.get("PROGRAMDATA", r"C:\ProgramData"),
                               "GIAM-SAT", "Agent", "runtime")
    try:
        if os.path.exists(runtime_dir):
            count = 0
            for meipass in _glob.glob(os.path.join(runtime_dir, "_MEI*")):
                try:
                    shutil.rmtree(meipass, ignore_errors=True)
                    count += 1
                except Exception:
                    pass
            if count > 0:
                _log(f"Cleaned {count} old _MEI runtime(s) before launching agent")
    except Exception:
        pass


def start_agent():
    """Start agent via service or direct launch."""
    # v3.9.7: Clean old _MEI* runtimes before launching to prevent disk bloat
    _cleanup_runtime_mei()
    
    # 1. Try service start
    try:
        r = subprocess.run(["sc", "start", SERVICE_NAME], capture_output=True, timeout=10,
                           creationflags=subprocess.CREATE_NO_WINDOW)
        if r.returncode == 0:
            _log("Agent started via service")
            return
    except Exception:
        pass
    # 2. Direct launch with same server config
    agent_path = _agent_exe()
    if os.path.exists(agent_path):
        host = _server_host()
        port = _cfg("server_port", 6666)
        subprocess.Popen(
            [agent_path, "--server", host, "--port", str(port)],
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
        )
        _log(f"Agent started directly: {agent_path} --server {host} --port {port}")


# ===================================================================
# DOWNLOAD
# ===================================================================

def download_exe(version, host=None, port=None):
    """Download GiamSatAgent.exe from server."""
    host = host or _server_host()
    port = port or _server_port()
    url = f"http://{host}:{port}/api/agent/download"
    try:
        _log(f"Downloading agent {version}...")
        # v4.10 (HIGH-8): version is used in the EXE filename - sanitize before
        # joining to prevent path traversal via version="..\\..\\evil".
        import re as _re
        version = _re.sub(r"[^A-Za-z0-9._-]", "", str(version))[:64] or "unknown"
        # v4.10 (CRITICAL-1): PSK via header, never in URL/query string
        req = urllib.request.Request(url, headers={"X-Agent-PSK": (_cfg("psk") or "")})
        resp = urllib.request.urlopen(req, timeout=120)
        total = int(resp.headers.get("Content-Length", 0))
        expected_sha = (resp.headers.get("X-File-SHA256") or "").strip().lower()
        expected_sig = (resp.headers.get("X-File-Sig") or "").strip().lower()
        tmp = tempfile.gettempdir()
        new_path = os.path.join(tmp, f"{AGENT_EXE_NAME}_{version}.exe")
        downloaded = 0
        with open(new_path, "wb") as f:
            while True:
                chunk = resp.read(8192)
                if not chunk:
                    break
                f.write(chunk)
                downloaded += len(chunk)
                if total > 0 and downloaded % (1024*1024) < 8192:
                    pct = int(downloaded / total * 100) if total > 0 else 0
                    _log(f"  {downloaded//1024}KB / {total//1024}KB ({pct}%)")
        _log(f"Downloaded {downloaded//1024}KB")
        if downloaded < 1000:
            _log("ERROR: File too small")
            return None
        # v4.10 (CRITICAL-1): SHA-256 is MANDATORY + signed (HMAC with command_key)
        if not expected_sha:
            _log("ERROR: Server did not provide X-File-SHA256 - update rejected (fail-closed)")
            try:
                os.remove(new_path)
            except Exception:
                pass
            return None
        import hashlib as _hashlib
        # v4.11 (CRITICAL-1 FIX): signature is MANDATORY - fail-closed. A MITM on
        # the plaintext channel can strip X-File-Sig and send its own (hash, exe)
        # pair; without this check the forged pair would pass verification.
        if not expected_sig:
            _log("ERROR: Server did not provide X-File-Sig - update rejected (fail-closed)")
            try:
                os.remove(new_path)
            except Exception:
                pass
            return None
        import hmac as _hmac
        signing_key = (_cfg("command_key") or "").strip()
        if not signing_key:
            _log("ERROR: No command_key configured to verify update signature - update rejected (fail-closed)")
            try:
                os.remove(new_path)
            except Exception:
                pass
            return None
        calc_sig = _hmac.new(signing_key.encode("utf-8"), expected_sha.encode("utf-8"), _hashlib.sha256).hexdigest()
        if not _hmac.compare_digest(calc_sig, expected_sig):
            _log("ERROR: EXE signature invalid (possible tampering) - update aborted")
            try:
                os.remove(new_path)
            except Exception:
                pass
            return None
        _h = _hashlib.sha256()
        with open(new_path, "rb") as _f:
            for _chunk in iter(lambda: _f.read(65536), b""):
                _h.update(_chunk)
        if _h.hexdigest().lower() != expected_sha:
            _log("ERROR: EXE hash mismatch (possible tampering) - update aborted")
            try:
                os.remove(new_path)
            except Exception:
                pass
            return None
        _log("EXE hash verified OK")
        return new_path
    except Exception as e:
        _log(f"Download failed: {e}")
    return None


def apply_update(new_exe_path):
    """Replace Agent EXE and restart."""
    current = _agent_exe()
    backup = current + ".bak"
    try:
        kill_agent()
        if os.path.exists(current):
            shutil.move(current, backup)
        shutil.copy(new_exe_path, current)
        _log("New EXE copied")
        if os.path.exists(backup):
            os.remove(backup)
        start_agent()
        _log("Update applied")
        return True
    except Exception as e:
        _log(f"Apply failed: {e}")
        if os.path.exists(backup):
            shutil.move(backup, current)
        start_agent()
        return False


# ===================================================================
# CHECK UPDATE (15-min loop)
# ===================================================================

def check_and_update(host=None, port=None):
    """Check version, download + apply if newer."""
    host = host or _server_host()
    port = port or _server_port()
    ver_path = os.path.join(INSTALL_DIR, "agent_version.txt")
    current = "0.0.0"
    try:
        if os.path.exists(ver_path):
            with open(ver_path, "r") as f:
                current = f.read().strip()
    except Exception:
        pass

    url = f"http://{host}:{port}/api/agent/version"
    try:
        req = urllib.request.Request(url, method="POST",
            data=json.dumps({"version": current}).encode(),
            headers={"Content-Type": "application/json"})
        resp = urllib.request.urlopen(req, timeout=15)
        data = json.loads(resp.read().decode())
        if data.get("update_available"):
            new_ver = data.get("server_version")
            _log(f"Update available: {current} -> {new_ver}")
            new_exe = download_exe(new_ver, host, port)
            if new_exe:
                apply_update(new_exe)
        else:
            _log(f"Up to date ({current})")
    except Exception as e:
        _log(f"Check failed: {e}")


# ===================================================================
# RESET USER
# ===================================================================

def reset_user():
    """Show config dialog + restart computer."""
    try:
        import ctypes
        ctypes.windll.user32.MessageBoxW(0,
            "Yeu cau nhap lai thong tin nguoi su dung.\n\n"
            "LUU Y: May tinh se khoi dong lai sau khi nhap.",
            "GIAM-SAT Agent - Canh Bao", 0x30 | 0x1)

        # v4.10 (MED-9): unpredictable temp file name (mkstemp) - the old
        # pid-based name in %TEMP% was predictable/racy for local users.
        _fd, ps_file = tempfile.mkstemp(suffix=".ps1", prefix="giamsat_reset_")
        os.close(_fd)
        result_file = os.path.join(tempfile.gettempdir(), f"giamsat_reset_result_{os.getpid()}.json")

        # Escape host/port for the PowerShell double-quoted string literal
        # (block ' $ " injection via a crafted server_host config).
        host_ps = (str(_server_host()) or "").replace("\\", "\\\\").replace('"', '`"').replace("$", "`$")
        port_ps = (str(_cfg("server_port", 6666)) or "").replace("\\", "\\\\").replace('"', '`"').replace("$", "`$")

        with open(ps_file, "w", encoding="utf-8") as f:
            f.write(r'''
Add-Type -AssemblyName System.Windows.Forms,System.Drawing
$f=New-Object System.Windows.Forms.Form
$f.Text="GIAM-SAT Agent - Cau Hinh Ket Noi"
$f.Size=New-Object System.Drawing.Size(420,540);$f.StartPosition="CenterScreen"
$f.FormBorderStyle="FixedDialog";$f.TopMost=$true
$f.BackColor=[System.Drawing.Color]::FromArgb(15,25,35);$f.ForeColor=[System.Drawing.Color]::White

function Add-Label($t,$y){$l=New-Object System.Windows.Forms.Label;$l.Text=$t;$l.Font=New-Object System.Drawing.Font("Segoe UI",9);$l.ForeColor=[System.Drawing.Color]::FromArgb(200,216,232);$l.AutoSize=$true;$l.Location=New-Object System.Drawing.Point(30,$y);$f.Controls.Add($l);return $y+22}
function Add-TB($t,$y,[int]$w=340){$b=New-Object System.Windows.Forms.TextBox;$b.Font=New-Object System.Drawing.Font("Segoe UI",11);$b.BackColor=[System.Drawing.Color]::FromArgb(26,42,58);$b.ForeColor=[System.Drawing.Color]::FromArgb(238,244,248);$b.Text=$t;$b.Location=New-Object System.Drawing.Point(30,$y);$b.Size=New-Object System.Drawing.Size($w,26);$f.Controls.Add($b);return $b,($y+32)}

$y=78
$y=Add-Label "Dia chi may chu (IP/Hostname):" $y
$txtHost,$y=Add-TB "''' + host_ps + r'''" $y
$y=Add-Label "Cong ket noi:" $y
$txtPort,$y=Add-TB "''' + port_ps + r'''" $y 80
$y+=8
$y=Add-Label "THONG TIN NGUOI SU DUNG" $y
$y=Add-Label "Nguoi su dung:" $y
$txtName,$y=Add-TB "" $y
$y=Add-Label "Ma nhan su:" $y
$txtID,$y=Add-TB "" $y
$y=Add-Label "Email:" $y
$txtEmail,$y=Add-TB "" $y
$y+=12
$ok=New-Object System.Windows.Forms.Button
$ok.Text="Ket noi";$ok.Font=New-Object System.Drawing.Font("Segoe UI",10,[System.Drawing.FontStyle]::Bold)
$ok.BackColor=[System.Drawing.Color]::FromArgb(26,58,42);$ok.ForeColor=[System.Drawing.Color]::FromArgb(136,221,153)
$ok.FlatStyle="Flat";$ok.Location=New-Object System.Drawing.Point(200,$y);$ok.Size=New-Object System.Drawing.Size(80,30)
$ok.DialogResult=[System.Windows.Forms.DialogResult]::OK;$f.AcceptButton=$ok;$f.Controls.Add($ok)
$cancel=New-Object System.Windows.Forms.Button
$cancel.Text="Huy";$cancel.Font=New-Object System.Drawing.Font("Segoe UI",10)
$cancel.BackColor=[System.Drawing.Color]::FromArgb(58,26,26);$cancel.ForeColor=[System.Drawing.Color]::FromArgb(255,136,136)
$cancel.FlatStyle="Flat";$cancel.Location=New-Object System.Drawing.Point(290,$y);$cancel.Size=New-Object System.Drawing.Size(80,30)
$cancel.DialogResult=[System.Windows.Forms.DialogResult]::Cancel;$f.Controls.Add($cancel)
$txtHost.SelectAll();$txtHost.Focus()
$r=$f.ShowDialog()
$d=@{}
if($r -eq [System.Windows.Forms.DialogResult]::OK){$d["host"]=$txtHost.Text.Trim();$d["port"]=$txtPort.Text.Trim();$d["user_name"]=$txtName.Text.Trim();$d["employee_id"]=$txtID.Text.Trim();$d["email"]=$txtEmail.Text.Trim();$d["confirmed"]=$true}else{$d["confirmed"]=$false}
$d|ConvertTo-Json|Out-File -FilePath "''' + result_file.replace('\\', '\\\\') + r'''" -Encoding UTF8 -Force
''')

        subprocess.run(["cmd", "/c", "start", "/wait", "powershell", "-NoProfile",
                        "-ExecutionPolicy", "Bypass", "-WindowStyle", "Normal",
                        "-File", ps_file], timeout=300)

        if os.path.exists(result_file):
            with open(result_file, "r", encoding="utf-8-sig") as f:
                data = json.load(f)
            os.remove(result_file)
            if data.get("confirmed"):
                cfg_path = os.path.join(os.environ.get("PROGRAMDATA", r"C:\ProgramData"),
                                        "GIAM-SAT", "Agent", "agent_config.json")
                cfg = {}
                if os.path.exists(cfg_path):
                    with open(cfg_path, "r") as f:
                        cfg = json.load(f)
                cfg["server_host"] = data.get("host", _server_host())
                try:
                    cfg["server_port"] = int(data.get("port", _cfg("server_port", 6666)))
                except ValueError:
                    pass
                cfg["user_name"] = data.get("user_name", "")
                cfg["employee_id"] = data.get("employee_id", "")
                cfg["email"] = data.get("email", "")
                cfg["configured"] = True
                os.makedirs(os.path.dirname(cfg_path), exist_ok=True)
                with open(cfg_path, "w") as f:
                    json.dump(cfg, f, indent=2)
                _log("Config saved, restarting computer...")
                subprocess.run(["shutdown", "/r", "/t", "20",
                                "/c", "GIAM-SAT: Khoi dong lai de ap dung thong tin nguoi dung moi."],
                               timeout=10)
            else:
                _log("User cancelled, restarting anyway...")
                subprocess.run(["shutdown", "/r", "/t", "20", "/c", "GIAM-SAT: Khoi dong lai."],
                               timeout=10)
        if os.path.exists(ps_file):
            os.remove(ps_file)
    except Exception as e:
        _log(f"Reset user failed: {e}")
        subprocess.run(["shutdown", "/r", "/t", "60"], timeout=10)


# ===================================================================
# SHOW MESSAGE
# ===================================================================

def show_message(title, body):
    """Show message box to user."""
    try:
        import ctypes
        ctypes.windll.user32.MessageBoxW(0, body, title, 0x40 | 0x1)  # MB_ICONINFORMATION | MB_OK
        _log(f"Message shown: {title}")
    except Exception as e:
        _log(f"Show message failed: {e}")


# ===================================================================
# HTTP SERVER (localhost only)
# ===================================================================

class UpdaterHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Suppress default HTTP logging

    def _json(self, data, code=200):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        # v4.10 (CRIT-2): localhost HTTP fallback requires the updater auth token.
        # Any local process without the token is rejected (fail-closed).
        if not _check_updater_auth(self):
            _log("[!] HTTP / rejected: missing or invalid X-Updater-Token")
            self._json({"error": "unauthorized"}, 401)
            return
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length)) if length > 0 else {}

        if self.path.startswith("/update"):
            version = body.get("version", "0.0.0")
            _log(f"HTTP POST /update version={version}")
            threading.Thread(target=self._do_update, args=(version,), daemon=True).start()
            self._json({"status": "accepted"})

        elif self.path.startswith("/reset-user"):
            _log("HTTP POST /reset-user")
            threading.Thread(target=reset_user, daemon=True).start()
            self._json({"status": "accepted"})

        elif self.path.startswith("/msg"):
            title = body.get("title", "GIAM-SAT")
            msg_body = body.get("body", "")
            _log(f"HTTP POST /msg: {title}")
            threading.Thread(target=show_message, args=(title, msg_body), daemon=True).start()
            self._json({"status": "accepted"})

        else:
            self._json({"error": "Not found"}, 404)

    def _do_update(self, version):
        new_exe = download_exe(version)
        if new_exe:
            apply_update(new_exe)
        else:
            _log(f"Update to {version} failed: download error")

    def do_GET(self):
        if self.path == "/health":
            self._json({"status": "ok", "service": "GiamSatUpdater", "version": "3.5.0"})
        else:
            self._json({"error": "Not found"}, 404)


# ===================================================================
# AUTO-REGISTER SCHEDULED TASK
# ===================================================================

def _ensure_scheduled_task():
    """Create Scheduled Task ONLOGON for this updater."""
    task_name = "GiamSatUpdater"
    my_exe = _my_exe()
    try:
        r = subprocess.run(["schtasks", "/Query", "/TN", task_name],
                          capture_output=True, timeout=10,
                          creationflags=subprocess.CREATE_NO_WINDOW)
        if r.returncode == 0:
            _log(f"Scheduled Task '{task_name}' already exists")
            return
    except Exception:
        pass

    try:
        _log(f"Creating Scheduled Task '{task_name}' (ONLOGON)...")
        subprocess.run([
            "schtasks", "/Create",
            "/SC", "ONLOGON",
            "/TN", task_name,
            "/TR", my_exe,
            "/F", "/RL", "HIGHEST", "/DELAY", "0000:30", "/IT"
        ], capture_output=True, timeout=15,
        creationflags=subprocess.CREATE_NO_WINDOW)
        _log("Scheduled Task created")
    except Exception as e:
        _log(f"Failed to create Scheduled Task: {e}")


# ===================================================================
# MAIN
# ===================================================================

def check_loop():
    """Check for updates every 15 minutes."""
    while True:
        time.sleep(900)
        try:
            check_and_update()
        except Exception as e:
            _log(f"Check loop error: {e}")


# ===================================================================
# v3.7.0: Named Pipe Command Dispatcher
# ===================================================================

def _pipe_command_handler(command):
    """Handle commands from Agent via Named Pipe.
    Same logic as HTTP UpdaterHandler but via IPC."""
    action = command.get("action", "")
    
    if action == "update":
        version = command.get("version", "0.0.0")
        _log(f"PIPE /update version={version}")
        threading.Thread(target=lambda: _do_update_from_pipe(version), daemon=True).start()
        return {"status": "accepted"}
    
    elif action == "reset-user":
        _log("PIPE /reset-user")
        threading.Thread(target=reset_user, daemon=True).start()
        return {"status": "accepted"}
    
    elif action == "msg":
        title = command.get("title", "GIAM-SAT")
        msg_body = command.get("body", "")
        _log(f"PIPE /msg: {title}")
        threading.Thread(target=show_message, args=(title, msg_body), daemon=True).start()
        return {"status": "accepted"}
    
    return {"status": "error", "error": f"Unknown action: {action}"}


def _do_update_from_pipe(version):
    """Handle update from pipe command (same as HTTP _do_update)."""
    new_exe = download_exe(version)
    if new_exe:
        apply_update(new_exe)
    else:
        _log(f"Update to {version} failed: download error")


# ===================================================================
# v3.8.0: AGENT WATCHDOG — Auto-restart agent if killed
# ===================================================================

def _agent_watchdog():
    """Monitor agent process and restart if it's not running.
    Checks every 15 seconds. Sends Telegram alert on restart."""
    try:
        import psutil
        _HAS_PSUTIL = True
    except ImportError:
        _HAS_PSUTIL = False
        _log("WATCHDOG: psutil not available, using tasklist fallback")

    _log("Watchdog: started monitoring GiamSatAgent.exe")
    last_restart = 0
    while True:
        time.sleep(15)
        try:
            agent_alive = False
            if _HAS_PSUTIL:
                agent_alive = any(
                    p.name().lower() == "giamsatagent.exe"
                    for p in psutil.process_iter(["name"])
                )
            else:
                # Fallback: use tasklist
                import subprocess
                r = subprocess.run(
                    ["tasklist", "/FI", "IMAGENAME eq GiamSatAgent.exe"],
                    capture_output=True, text=True, timeout=10,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
                )
                agent_alive = "GiamSatAgent.exe" in (r.stdout or "")

            if not agent_alive:
                _log("WATCHDOG: Agent process not found! Restarting...")
                # Prevent restart flood (max once per 60s)
                now = time.time()
                if now - last_restart < 60:
                    _log(f"WATCHDOG: Skipping restart (last restart {now - last_restart:.0f}s ago)")
                    continue
                last_restart = now
                start_agent()
                # Try to send Telegram alert
                try:
                    _send_telegram_alert("⚠️ GIAM-SAT Agent bị kill — đã tự động restart.")
                except Exception:
                    pass
        except Exception as e:
            _log(f"Watchdog error: {e}")


def _send_telegram_alert(msg):
    """Send simple Telegram alert via server API."""
    try:
        host = _server_host()
        port = _server_port()
        url = f"http://{host}:{port}/api/alerts/telegram"
        data = json.dumps({"message": msg, "source": "updater_watchdog"}).encode()
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10)
    except Exception:
        pass


# ===================================================================
# MAIN
# ===================================================================

def main():
    # Hide console window
    try:
        import ctypes
        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if hwnd:
            ctypes.windll.user32.ShowWindow(hwnd, 0)
    except Exception:
        pass

    _log("GIAM-SAT Updater v3.7.0 starting...")

    # Auto-register Scheduled Task ONLOGON
    _ensure_scheduled_task()

    # v3.7.0: Start Named Pipe IPC server (primary, secure)
    pipe_server = None
    http_server = None
    ipc_channel = "none"
    
    if _HAS_NAMED_PIPE:
        try:
            pipe_server = NamedPipeServer(callback_on_command=_pipe_command_handler)
            pipe_thread = threading.Thread(target=pipe_server.serve_forever, daemon=True)
            pipe_thread.start()
            ipc_channel = "named_pipe"
            _log(f"Named Pipe IPC server started (secure, no network port)")
        except Exception as e:
            _log(f"Named Pipe failed: {e}, falling back to HTTP")
    
    # Fallback: HTTP server on localhost (legacy, kept for compatibility)
    if not pipe_server or not pipe_server.running:
        try:
            http_server = HTTPServer((LISTEN_HOST, LISTEN_PORT), UpdaterHandler)
            http_thread = threading.Thread(target=http_server.serve_forever, daemon=True)
            http_thread.start()
            ipc_channel = f"http://{LISTEN_HOST}:{LISTEN_PORT}"
            _log(f"HTTP server (fallback): {LISTEN_HOST}:{LISTEN_PORT}")
        except Exception as e:
            _log(f"HTTP server failed: {e}")
    
    _log(f"IPC channel: {ipc_channel}")

    # Start check loop (separate thread)
    check_thread = threading.Thread(target=check_loop, daemon=True)
    check_thread.start()
    _log("Update check loop started (every 15 min)")

    # v3.8.0: Agent Watchdog — restart agent if it's killed
    watchdog_thread = threading.Thread(target=_agent_watchdog, daemon=True)
    watchdog_thread.start()
    _log("Agent watchdog started (checking every 15s)")

    # Keep main thread alive
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        _log("Shutting down...")
        if pipe_server:
            pipe_server.stop()
        if http_server:
            http_server.shutdown()


if __name__ == "__main__":
    main()