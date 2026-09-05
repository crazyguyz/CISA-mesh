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
# ===== v5.0.2: WINDOWED BUILD - no console flash at boot =====
# Built with console=False (PyInstaller windowed) so Task Scheduler launches show
# no black console window (users can no longer accidentally close the updater).
# In windowed mode sys.stdout/stderr are None - redirect them so the _log() helper
# (print(..., flush=True)) can never crash.
try:
    if getattr(sys, 'frozen', False) and not sys.stdout:
        class _NullWriter:
            def write(self, _s):
                return 0
            def flush(self):
                pass
            def isatty(self):
                return False
        sys.stdout = sys.stderr = _NullWriter()
except Exception:
    pass

# v5.0.4 (console regression fix): hide the console window ACTIVELY at startup.
# console=False in updater.spec is correct, but a machine that still runs an OLD
# dist built with console=True would keep flashing a black box at every logon -
# and users close it not knowing what it is (killing the updater). GetConsoleWindow
# returns the handle even for a console-subsystem exe, so this hides it either way.
try:
    import ctypes
    _user32 = ctypes.windll.user32
    _kernel32 = ctypes.windll.kernel32
    _hwnd = _kernel32.GetConsoleWindow()
    if _hwnd:
        _user32.ShowWindow(_hwnd, 0)  # SW_HIDE
except Exception:
    pass

try:
    from http_client import base as _web_base, _ssl_ctx as _web_ssl_ctx
    def _web_open(req, timeout=15, config=None):
        import urllib.request as _ur
        return _ur.urlopen(req, timeout=timeout, context=_web_ssl_ctx(config))
except ImportError:
    def _web_base(host, port, config=None): return 'http://' + str(host) + ':' + str(port)
    def _web_open(req, timeout=15, config=None):
        import urllib.request as _ur
        return _ur.urlopen(req, timeout=timeout)

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
        _log("[!] HTTP auth: command_key not configured on this machine - updater IPC rejected (fail-closed). "
             "Set 'command_key' in agent_config.json (same as server GIAMSAT_COMMAND_KEY).")
        return False
    got = handler.headers.get("X-Updater-Token", "")
    import hmac
    if not hmac.compare_digest(got, expected):
        _log("[!] HTTP auth: X-Updater-Token mismatch - rejected. agent_config.json command_key differs "
             "from the value the updater was configured with.")
        return False
    return True


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
    This prevents unbounded disk growth caused by PyInstaller extractions on every restart.
    v5.0.4 FIX (LoadLibrary python311.dll crash): never delete a MEI dir that is still
    IN USE by a running agent - the old code rmtree'd every _MEI* including the one a
    concurrently-starting/just-restarted agent needs, which produced
    'Failed to load Python DLL ...runtime_MEIxxxx\\python311.dll'.  A MEI dir that a
    process has files open from CANNOT be renamed on Windows -> the rename probe is
    the in-use test; combined with an age guard (>6h) for extra safety."""
    import glob as _glob
    import time as _time
    runtime_dir = os.path.join(os.environ.get("PROGRAMDATA", r"C:\ProgramData"),
                               "GIAM-SAT", "Agent", "runtime")
    try:
        if os.path.exists(runtime_dir):
            # v5.0.4: if an agent is STILL running (watchdog respawn / update race),
            # skip cleanup entirely - its _MEI dir must not be touched.
            try:
                _proc = subprocess.run(["tasklist", "/FI", "IMAGENAME eq GiamSatAgent.exe", "/NH"],
                                       capture_output=True, timeout=10, text=True,
                                       creationflags=subprocess.CREATE_NO_WINDOW)
                if "GiamSatAgent.exe" in (_proc.stdout or ""):
                    _log("_MEI cleanup skipped: GiamSatAgent.exe is running")
                    return
            except Exception:
                pass
            count = 0
            now = _time.time()
            for meipass in _glob.glob(os.path.join(runtime_dir, "_MEI*")):
                try:
                    # 1) age guard: keep fresh extractions (possibly starting)
                    if now - os.path.getmtime(meipass) < 6 * 3600:
                        continue
                    # 2) in-use probe: renaming fails while a process holds files open
                    probe = meipass + ".probe"
                    os.rename(meipass, probe)
                    os.rename(probe, meipass)
                except Exception:
                    continue  # in use or locked - keep it
                try:
                    shutil.rmtree(meipass, ignore_errors=True)
                    count += 1
                except Exception:
                    pass
            if count > 0:
                _log(f"Cleaned {count} abandoned _MEI runtime(s) before launching agent")
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
    url = f"{_web_base(host, port, None)}/api/agent/download"
    try:
        _log(f"Downloading agent {version}...")
        # v4.10 (HIGH-8): version is used in the EXE filename - sanitize before
        # joining to prevent path traversal via version="..\\..\\evil".
        import re as _re
        version = _re.sub(r"[^A-Za-z0-9._-]", "", str(version))[:64] or "unknown"
        # v4.10 (CRITICAL-1): PSK via header, never in URL/query string
        req = urllib.request.Request(url, headers={"X-Agent-PSK": (_cfg("psk") or "")})
        # v4.13 (P2): use _web_open (TLS-aware) - plain urlopen would skip the
        # pinned-CA verification and fail when the server web port is HTTPS.
        resp = _web_open(req, timeout=120)
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


def apply_update(new_exe_path, version=None):
    """Replace Agent EXE and restart.
    v5.0.4 FIX: (a) writes agent_version.txt next to the exe - the updater reads
    INSTALL_DIR\\agent_version.txt to learn the local version; when that file is
    missing (old installs / dist without the txt) the version reads as 0.0.0 and
    the server keeps offering updates -> endless download+apply loop that raced
    the running exe and produced 'Failed to extract' popups + 'Access is denied'
    on the .bak. (b) verifies the copied file's hash before launching so a
    partial copy can never boot a corrupt agent. (c) backup cleanup is best-effort
    and never aborts the update."""
    import hashlib as _hashlib
    import shutil as _sh
    current = _agent_exe()
    backup = current + ".bak"
    tmp_new = current + ".new"
    new_ver = str(version or "").strip() or "unknown"

    def _sha256(path):
        try:
            h = _hashlib.sha256()
            with open(path, "rb") as f:
                for c in iter(lambda: f.read(65536), b""):
                    h.update(c)
            return h.hexdigest()
        except Exception:
            return None

    src_hash = _sha256(new_exe_path)
    # v5.0.4 (HIGH-1): cross-process update lock - the agent's own .bat updater
    # and the updater.exe can run concurrently; exclusive lock file stops the race
    # (taskkill/copy over each other -> 'Access is denied: .bak' + corrupt launch).
    lock_path = os.path.join(INSTALL_DIR, "update.lock")
    # v5.0.4 (HIGH-4): O_EXCL lock is never released if the updater is killed /
    # the PC reboots mid-update -> agent would be stuck on the old version forever.
    # Reclaim a lock that is older than 10 minutes (crash/reboot leaves it behind).
    _lock_fd = None
    for _lock_try in range(2):
        try:
            _lock_fd = open(lock_path, "x")  # O_EXCL - fails if another updater is running
            break
        except OSError:
            try:
                if time.time() - os.path.getmtime(lock_path) > 600:
                    _log("Reclaiming stale update.lock (>10 min old)")
                    os.remove(lock_path)
                    continue
            except OSError:
                pass
            _log("Update skipped: another update is in progress (update.lock exists)")
            return False
    if _lock_fd is None:
        _log("Update skipped: could not acquire update.lock")
        return False
    try:
        _lock_fd.write(str(os.getpid()))
        _lock_fd.flush()
    except Exception:
        pass
    try:
        # stop the agent BEFORE touching the exe (the watchdog also restarts it,
        # so keep a short wait loop to let the old process release file handles)
        kill_agent()
        time.sleep(1)
        # stage the new exe under a temp name first
        if os.path.exists(tmp_new):
            try:
                os.remove(tmp_new)
            except Exception:
                pass
        _sh.copy2(new_exe_path, tmp_new)
        if src_hash and _sha256(tmp_new) != src_hash:
            _log("ERROR: copied EXE hash mismatch - update aborted (partial copy?)")
            try:
                os.remove(tmp_new)
            except Exception:
                pass
            try:
                _lock_fd.close()
                os.remove(lock_path)
            except Exception:
                pass
            start_agent()
            return False
        # swap current -> backup (best-effort), then install the verified file
        try:
            if os.path.exists(backup):
                os.remove(backup)
        except Exception:
            pass
        try:
            if os.path.exists(current):
                _sh.move(current, backup)
        except Exception as e:
            _log(f"WARN: could not back up current exe: {e}")
        _sh.move(tmp_new, current)
        # v5.0.4 (root cause fix): write the version file so future checks
        # converge and the server stops offering this exact version.
        try:
            vp = os.path.join(INSTALL_DIR, "agent_version.txt")
            with open(vp, "w") as f:
                f.write(new_ver)
        except Exception as e:
            _log(f"WARN: could not write agent_version.txt: {e}")
        _log("New EXE copied")
        # backup cleanup is best-effort (a lingering process may lock the .bak)
        try:
            if os.path.exists(backup):
                os.remove(backup)
        except Exception as e:
            _log(f"WARN: backup cleanup deferred: {e}")
        start_agent()
        _log("Update applied")
        try:
            _lock_fd.close()
            os.remove(lock_path)
        except Exception:
            pass
        return True
    except Exception as e:
        _log(f"Apply failed: {e}")
        # restore the previous exe if the new one never made it
        if not os.path.exists(current) and os.path.exists(backup):
            try:
                _sh.move(backup, current)
                _log("Restored previous agent exe")
            except Exception as e2:
                _log(f"Restore failed: {e2}")
        try:
            _lock_fd.close()
            os.remove(lock_path)
        except Exception:
            pass
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

    url = f"{_web_base(host, port, None)}/api/agent/version"
    try:
        req = urllib.request.Request(url, method="POST",
            data=json.dumps({"version": current}).encode(),
            # v4.14 (FIX): the version endpoint is PSK-gated (check_agent_psk fail-closed)
            # - without X-Agent-PSK the server returns 401 and auto-update never runs.
            headers={"Content-Type": "application/json",
                     "X-Agent-PSK": (_cfg("psk") or "")})
        resp = _web_open(req, timeout=15)
        data = json.loads(resp.read().decode())
        if data.get("update_available"):
            new_ver = data.get("server_version")
            _log(f"Update available: {current} -> {new_ver}")
            new_exe = download_exe(new_ver, host, port)
            if new_exe:
                apply_update(new_exe, version=new_ver)
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
        # v5.0.4 (HIGH-5): result_file must also be unpredictable - the old
        # giamsat_reset_result_<pid>.json was guessable, letting a same-user
        # process plant a fake result that redirected agent_config.json to an
        # attacker server (PSK leak). mkstemp + nonce marker prove ownership.
        _fd2, result_file = tempfile.mkstemp(suffix=".json", prefix="giamsat_reset_result_")
        os.close(_fd2)
        try:
            os.remove(result_file)  # PowerShell Out-File -Force will (re)create it
        except OSError:
            pass
        _nonce = os.urandom(8).hex()

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
$d["_nonce"]="''' + _nonce + r'''"
$d|ConvertTo-Json|Out-File -FilePath "''' + result_file.replace('\\', '\\\\') + r'''" -Encoding UTF8 -Force
''')

        subprocess.run(["cmd", "/c", "start", "/wait", "powershell", "-NoProfile",
                        "-ExecutionPolicy", "Bypass", "-WindowStyle", "Normal",
                        "-File", ps_file], timeout=300)

        if os.path.exists(result_file):
            with open(result_file, "r", encoding="utf-8-sig") as f:
                data = json.load(f)
            os.remove(result_file)
            # v5.0.4 (HIGH-5): only trust a result that carries our nonce - a
            # file planted at a guessable path must never rewrite agent_config.
            if str(data.get("_nonce") or "") != _nonce:
                _log("Reset result missing/invalid nonce - ignoring (possible file planting)")
                return
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
                # v5.0.4 (MEDIUM-13): user pressed Cancel -> do NOT reboot the
                # machine; keep the existing config and stay online.
                _log("User cancelled - no restart, keeping existing config.")
        if os.path.exists(ps_file):
            os.remove(ps_file)
    except Exception as e:
        # v5.0.4 (MEDIUM-13): an error must not reboot the machine either.
        _log(f"Reset user failed: {e}")


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
        # v4.13 (P2): read the request body BEFORE the auth check so the client
        # always receives a clean 401 response (never a connection RST / WinError
        # 10054 caused by closing a socket with an unread body).
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length)) if length > 0 else {}
        if not _check_updater_auth(self):
            _log("[!] HTTP / rejected: missing or invalid X-Updater-Token")
            self._json({"error": "unauthorized"}, 401)
            return

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
            # v5.0.4 (HIGH-1): pass the version so apply_update writes the real
            # value instead of "unknown" (which re-triggered the update loop)
            apply_update(new_exe, version=version)
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
        # v5.0.4 (HIGH-1): pass the version (was "unknown" -> update loop)
        apply_update(new_exe, version=version)
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
        # v4.14 (FIX): /api/alerts/telegram never existed (404). The updater has
        # no user JWT, so it cannot call /api/telegram/send - use the PSK-gated
        # /api/agent/telegram-alert endpoint instead (server sends via its bot).
        url = f"{_web_base(host, port, None)}/api/agent/telegram-alert"
        data = json.dumps({"message": msg, "source": "updater_watchdog"}).encode()
        req = urllib.request.Request(url, data=data,
            headers={"Content-Type": "application/json",
                     "X-Agent-PSK": (_cfg("psk") or "")})
        _web_open(req, timeout=10)
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

