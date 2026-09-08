"""
GIAM-SAT Agent - SIEM Endpoint Agent
Version auto-read from agent_version.txt
"""
import os
import sys

# ===== v5.0.2: WINDOWED BUILD - no console flash at boot =====
# Built with console=False (PyInstaller windowed): Windows never creates a console
# window, so the black box that flashed for up to 10-15s on low-spec machines (and
# that users accidentally closed, killing the agent) is gone. In windowed mode
# sys.stdout/stderr are None - redirect them so print() can never crash.
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

# v5.0.4 (console regression fix): actively hide the console window if the running
# EXE is an older console=True build (same rationale as updater.py).
try:
    import ctypes
    _hwnd = ctypes.windll.kernel32.GetConsoleWindow()
    if _hwnd:
        ctypes.windll.user32.ShowWindow(_hwnd, 0)  # SW_HIDE
except Exception:
    pass

# ===== LINE 1: GET VERSION =====
def _get_version():
    """Read version from agent_version.txt (embedded in EXE via PyInstaller)."""
    try:
        if getattr(sys, 'frozen', False):
            # PyInstaller: agent_version.txt is in sys._MEIPASS
            base = getattr(sys, '_MEIPASS', os.path.dirname(sys.executable))
        else:
            base = os.path.dirname(os.path.abspath(__file__))
        ver_path = os.path.join(base, "agent_version.txt")
        if os.path.exists(ver_path):
            with open(ver_path, "r", encoding="utf-8") as f:
                return f.read().strip()
    except Exception:
        pass
    return "0.0.0"

AGENT_VERSION = _get_version()

# ===== LINE 2: LOG + MESSAGEBOX =====
_APPDATA = os.environ.get("APPDATA", os.path.expanduser("~"))
_LOG_DIR = os.path.join(_APPDATA, "GIAM-SAT", "Agent", "logs")
os.makedirs(_LOG_DIR, exist_ok=True)
_LOG_FILE = os.path.join(_LOG_DIR, "agent_startup.log")

def _log(msg):
    try:
        with open(_LOG_FILE, "a", encoding="utf-8") as f:
            from datetime import datetime
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")
    except Exception:
        pass

# ===== v4.6.5: SINGLE-INSTANCE GUARD =====
# Two agent instances running at once (e.g. watchdog spawned a duplicate while the
# old one was still shutting down) both read the same event logs -> every event was
# double-sent to the server. A named mutex makes the second instance exit immediately.
# v5.0.3 FIX: _log() must be defined BEFORE this block - it was defined after, so a
# duplicate instance hit NameError inside the try, the except swallowed it and the
# second instance KEPT RUNNING (double events - the exact bug the guard was built for).
_MUTEX_NAME = "Global\\GiamSatAgent_SingleInstance"
_MUTEX_HANDLE = None
try:
    import ctypes
    _MUTEX_HANDLE = ctypes.windll.kernel32.CreateMutexW(None, False, _MUTEX_NAME)
    _MUTEX_EXISTS = ctypes.windll.kernel32.GetLastError() == 183  # ERROR_ALREADY_EXISTS
    if _MUTEX_EXISTS:
        _log("Another GiamSatAgent instance is already running - exiting.")
        sys.exit(0)
except Exception:
    _MUTEX_HANDLE = None  # mutex unavailable (non-Windows/dev) - continue anyway

_log("=" * 60)
_log(f"AGENT v{AGENT_VERSION} MODULE-LEVEL START")
_log(f"Python: {sys.version}")
_log(f"Frozen: {getattr(sys, 'frozen', False)}")
_log(f"exe: {sys.executable}")
_log(f"argv: {sys.argv}")
_log(f"cwd: {os.getcwd()}")
_log(f"pid: {os.getpid()}")
_log(f"log: {_LOG_FILE}")

# Now safe imports (no MessageBox spam in production)
try:
    import socket
    import subprocess
    import json
    import io
    import traceback
    import tempfile
    from datetime import datetime
    _log("Core imports OK")
except Exception as _e:
    _log(f"Core import FAIL: {_e}\n{traceback.format_exc()}")

# v2.5.7: Safe stdout redirect (use io.StringIO if None)
if sys.stdout is None:
    sys.stdout = io.StringIO()
    sys.stderr = sys.stdout
    _log("stdout was None → StringIO")

# v2.5.14: Keep print working for logging, only redirect if stdout is unsafe
import builtins
_original_print = builtins.print
# Don't override print globally - let logging work normally
# Only redirect in frozen mode if stdout fails


def _setup_agent_environment():
    try:
        if os.name == "nt":
            programdata = os.environ.get("PROGRAMDATA", "C:\\ProgramData")
            data_dir = os.path.join(programdata, "GIAM-SAT", "Agent")
            log_dir = os.path.join(data_dir, "logs")
        else:
            data_dir = os.path.join(os.path.expanduser("~"), ".giamsat", "agent")
            log_dir = os.path.join(data_dir, "logs")
        os.makedirs(log_dir, exist_ok=True)
        os.makedirs(data_dir, exist_ok=True)
        os.environ["GIAMSAT_DATA_DIR"] = data_dir
        _log(f"Data dir: {data_dir} exists={os.path.exists(data_dir)}")

        import logging
        log_file = os.path.join(log_dir, "agent.log")
        root = logging.getLogger()
        if not root.handlers:
            logging.basicConfig(
                level=logging.INFO,
                format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                handlers=[logging.FileHandler(log_file, encoding="utf-8")]
            )
            _log(f"Logging: {log_file}")
    except Exception as _e:
        _log(f"_setup_agent_environment FAIL: {_e}")

_setup_agent_environment()


def _get_agent_data_dir():
    if os.name == "nt":
        return os.path.join(os.environ.get("PROGRAMDATA", "C:\\ProgramData"), "GIAM-SAT", "Agent")
    return os.environ.get("GIAMSAT_DATA_DIR", os.path.join(os.path.expanduser("~"), ".giamsat", "agent"))


def _get_config_path():
    return os.path.join(_get_agent_data_dir(), "agent_config.json")


def _load_user_fields():
    """v4.9: Load configurable dropdown fields for the user-info dialog.
    Admin edits user_fields.json (agent data dir) to add/remove/rename dropdowns.
    Default: one 'Chi nhanh' (branch) dropdown."""
    default = [{"key": "branch", "label": "Chi nhanh",
                "options": ["Tru so chinh", "Chi nhanh 1", "Chi nhanh 2"]}]
    try:
        path = os.path.join(_get_agent_data_dir(), "user_fields.json")
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8-sig") as f:
                data = json.loads(f.read())
            fields = data.get("fields", []) if isinstance(data, dict) else []
            out = []
            for fld in fields:
                if not isinstance(fld, dict):
                    continue
                key = (fld.get("key") or "").strip()
                label = (fld.get("label") or key).strip()
                options = fld.get("options") or []
                if not key or not label:
                    continue
                out.append({"key": key, "label": label, "options": [str(o) for o in options]})
            if out:
                return out
    except Exception:
        pass
    return default


def _get_boot_tracker_path():
    return os.path.join(_get_agent_data_dir(), "boot_tracker.json")


def _check_first_boot_today():
    today = datetime.now().strftime("%Y-%m-%d")
    path = _get_boot_tracker_path()
    try:
        if os.path.exists(path):
            with open(path, "r") as f:
                data = json.loads(f.read())
            if data.get("date") == today:
                data["count"] = data.get("count", 0) + 1
                # v4.10 (MED-10): persist the counter (was never saved)
                try:
                    with open(path, "w") as f:
                        json.dump(data, f, indent=2)
                except Exception:
                    pass
                return False
            else:
                data = {"date": today, "count": 1}
        else:
            data = {"date": today, "count": 1}
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        return True
    except Exception:
        return True


def _load_config():
    cfg = {"server_host": "127.0.0.1", "server_port": 6666, "user_name": "", "employee_id": "", "email": "", "psk": "", "command_key": "", "branch": "", "user_extra": {}, "net_mode": ""}
    try:
        path = _get_config_path()
        if os.path.exists(path):
            with open(path, "r") as f:
                saved = json.loads(f.read())
            for k in ["server_host", "server_port", "user_name", "employee_id", "email", "psk", "command_key", "branch", "user_extra", "net_mode"]:
                if k in saved:
                    cfg[k] = saved[k]
    except Exception:
        pass
    if not cfg["user_name"].strip():
        try:
            ui_path = _get_user_info_path()
            if os.path.exists(ui_path):
                with open(ui_path, "r") as f:
                    ui = json.loads(f.read())
                for k in ["user_name", "employee_id", "email"]:
                    if k in ui:
                        cfg[k] = ui[k]
        except Exception:
            pass
    return cfg


def _get_user_info_path():
    appdata = os.environ.get("APPDATA", os.path.join(os.path.expanduser("~"), "AppData", "Roaming"))
    d = os.path.join(appdata, "GIAM-SAT", "Agent")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, "user_info.json")


def _generate_machine_id():
    import uuid
    return str(uuid.uuid4())[:8]


def _save_config(host, port, user_name="", employee_id="", email="", psk="", command_key="", branch="", user_extra=None, net_mode=""):
    try:
        path = _get_config_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        data = {}
        if os.path.exists(path):
            try:
                with open(path, "r") as f:
                    data = json.loads(f.read())
            except Exception:
                pass
        if not data.get("machine_id"):
            data["machine_id"] = _generate_machine_id()
        if not data.get("hostname"):
            data["hostname"] = os.environ.get("COMPUTERNAME", socket.gethostname())
        data.update({"server_host": host, "server_port": int(port),
                     "user_name": user_name, "employee_id": employee_id,
                     "email": email, "psk": psk, "command_key": command_key,
                     "branch": branch, "user_extra": user_extra or {}, "configured": True,
                     "net_mode": (net_mode or "").strip().lower()})
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2)
        try:
            os.replace(tmp, path)
        except PermissionError:
            # v4.10 (CRIT-3): NEVER grant BUILTIN\Users read/write on a file that
            # contains command_key/psk/enrollment_token. Fail loud instead.
            print("[!] CONFIG: Cannot replace agent_config.json (PermissionError). "
                  "The GIAM-SAT Agent folder ACL must allow the agent account only.")
            try:
                os.remove(tmp)
            except Exception:
                pass
        # User info to APPDATA
        up = _get_user_info_path()
        ut = up + ".tmp"
        with open(ut, "w") as f:
            json.dump({"user_name": user_name, "employee_id": employee_id, "email": email,
                       "branch": branch, "user_extra": user_extra or {}}, f, indent=2)
        try:
            os.replace(ut, up)
        except PermissionError:
            _log("_save_config FAIL: PermissionError")
            return False
        return True
    except Exception as e:
        _log(f"_save_config FAIL: {e}")
        return False


def _is_service_running():
    try:
        r = subprocess.run(["sc.exe", "query", "GiamSatAgent"],
                           capture_output=True, text=True, timeout=5,
                           creationflags=subprocess.CREATE_NO_WINDOW)
        return "RUNNING" in r.stdout
    except Exception:
        return False


def _has_interactive_console():
    """v4.8.0: có người đang ngồi ở màn hình máy này không (session console tương tác)?
    Dialog chỉ nên bật khi có người thật nhập được; nếu agent chạy session 0/dịch vụ
    (máy chưa ai đăng nhập) thì bỏ qua dialog thay vì bật cửa sổ vô hình."""
    if os.name != "nt":
        return True
    try:
        import ctypes
        sid = ctypes.c_ulong(0)
        ctypes.windll.kernel32.ProcessIdToSessionId(os.getpid(), ctypes.byref(sid))
        cs = ctypes.windll.kernel32.WTSGetActiveConsoleSessionId()
        return bool(sid.value and sid.value != 0xFFFFFFFF and sid.value == cs)
    except Exception:
        return True


def _show_config_dialog(remote=None, preselect_mode=""):
    """Python tkinter config dialog - no PowerShell dependency.
    Works on all Windows machines including those with AppLocker/CLM.
    v5.0.4: khi có remote config (file ip-server từ xa) thì CHỈ hỏi thông tin cá
    nhân - server host/port/psk/command key tự lấy từ remote config/cấu hình cũ."""
    cfg = _load_config()
    # v4.8.0: net_mode = 'lan' (kết nối trực tiếp) hoặc 'tailscale'.
    cfg["net_mode"] = (cfg.get("net_mode") or "").strip().lower()
    if not cfg["net_mode"]:
        cfg["net_mode"] = preselect_mode or (
            "tailscale" if (remote and remote.get("auth_command")) else "lan")
    use_remote = bool(remote and remote.get("server_host"))
    if use_remote:
        cfg["server_host"] = str(remote.get("server_host") or cfg["server_host"])
        if remote.get("server_port"):
            cfg["server_port"] = int(remote["server_port"])
    # psk/command_key có thể được cấp phát qua remote config (file host NỘI BỘ) -
    # nếu có thì dùng làm giá trị mặc định cho dialog (vẫn hiển thị để kiểm tra).
    if remote and remote.get("psk"):
        cfg["psk"] = str(remote["psk"])
    if remote and remote.get("command_key"):
        cfg["command_key"] = str(remote["command_key"])
    result = {"confirmed": False, "host": cfg["server_host"], "port": cfg["server_port"],
              "user_name": cfg["user_name"], "employee_id": cfg["employee_id"], "email": cfg["email"],
              "psk": cfg.get("psk", ""), "command_key": cfg.get("command_key", ""),
              "branch": cfg.get("branch", ""), "user_extra": cfg.get("user_extra", {}) or {},
              "net_mode": cfg["net_mode"]}

    try:
        import os as _os, sys as _sys
        _mei = getattr(_sys, '_MEIPASS', None)
        if _mei:
            _tcl_root = _os.path.join(_mei, 'tcl')
            if _os.path.isdir(_tcl_root):
                _tcl_lib = _os.path.join(_tcl_root, 'tcl8.6')
                _tk_lib = _os.path.join(_tcl_root, 'tk8.6')
                if _os.path.isdir(_tcl_lib):
                    _os.environ['TCL_LIBRARY'] = _tcl_lib
                if _os.path.isdir(_tk_lib):
                    _os.environ['TK_LIBRARY'] = _tk_lib
        import tkinter as tk
        from tkinter import ttk
    except ImportError:
        _log("tkinter not available, using defaults")
        return result["host"], result["port"], result["user_name"], result["employee_id"], result["email"], result.get("psk", ""), result.get("command_key", ""), result.get("branch", ""), result.get("user_extra", {}), result.get("net_mode", "")

    _log("Launching tkinter config dialog...")

    root = tk.Tk()
    root.title("GIAM-SAT Agent - Cau Hinh Ket Noi")
    root.resizable(False, False)
    root.attributes("-topmost", True)

    # Dark theme colors
    BG = "#0F1923"
    FG = "#FFFFFF"
    ENTRY_BG = "#1A2A3A"
    ENTRY_FG = "#EEF4F8"
    ACCENT = "#00D4AA"
    BTN_OK_BG = "#1A3A2A"
    BTN_OK_FG = "#88DD99"
    BTN_CANCEL_BG = "#3A1A1A"
    BTN_CANCEL_FG = "#FF8888"
    LABEL_FG = "#C8D8E8"

    root.configure(bg=BG)

    # Window size and centering
    W = 420
    ws = root.winfo_screenwidth()
    hs = root.winfo_screenheight()
    H = min(640, max(540, hs - 80))
    x = (ws - W) // 2
    y = (hs - H) // 2
    root.geometry(f"{W}x{H}+{x}+{y}")

    # Title
    t = tk.Label(root, text="GIAM-SAT Agent", font=("Segoe UI", 14, "bold"),
                 fg=ACCENT, bg=BG)
    t.place(x=50, y=10)

    t2 = tk.Label(root,
                  text="Chon cach ket noi roi nhap thong tin (LAN = khong can Tailscale)",
                  font=("Segoe UI", 9),
                  fg=LABEL_FG, bg=BG)
    t2.place(x=45, y=38)

    def make_label(text, row_y):
        lbl = tk.Label(root, text=text, font=("Segoe UI", 9), fg=LABEL_FG, bg=BG, anchor="w")
        lbl.place(x=30, y=row_y)

    def make_entry(row_y, width=340, default="", show=None):
        sv = tk.StringVar(value=default)
        e = tk.Entry(root, textvariable=sv, font=("Consolas", 11),
                     bg=ENTRY_BG, fg=ENTRY_FG, insertbackground=ENTRY_FG,
                     relief="flat", bd=1, highlightthickness=1,
                     highlightbackground="#2A3A4A", highlightcolor=ACCENT, show=show)
        e.place(x=30, y=row_y, width=width, height=28)
        return sv

    # v4.8.0: radio chọn chế độ kết nối (gọn - không hint dài)
    make_label("Cach ket noi:", 62)
    mode_var = tk.StringVar(value=cfg["net_mode"] or "lan")

    def _mk_radio(text, val, y):
        rb = tk.Radiobutton(root, text=text, value=val, variable=mode_var,
                            font=("Segoe UI", 9), fg=LABEL_FG, bg=BG,
                            selectcolor=ENTRY_BG, activebackground=BG,
                            activeforeground=ACCENT, anchor="w", justify="left",
                            highlightthickness=0, bd=0)
        rb.place(x=30, y=y, width=375, height=20)
        return y + 22

    y_pos = _mk_radio("1. Ket noi truc tiep (LAN) - nhap IP + cong server ben duoi", "lan", 86)
    y_pos = _mk_radio("2. Qua Tailscale - tu dong cai/ket noi", "tailscale", y_pos)
    y_pos += 4

    # Host/port gom 1 dong: host (trai) + port (phai)
    make_label("Dia chi may chu (IP/Hostname) + Cong:", y_pos)
    y_pos += 20
    sv_host = make_entry(y_pos, 250, cfg["server_host"])
    _sv_port = tk.StringVar(value=str(cfg["server_port"]))
    _e_port = tk.Entry(root, textvariable=_sv_port, font=("Consolas", 11),
                       bg=ENTRY_BG, fg=ENTRY_FG, insertbackground=ENTRY_FG,
                       relief="flat", bd=1, highlightthickness=1,
                       highlightbackground="#2A3A4A", highlightcolor=ACCENT)
    _e_port.place(x=290, y=y_pos, width=90, height=28)
    y_pos += 36

    # Section divider
    sep = tk.Label(root, text="THONG TIN NGUOI SU DUNG", font=("Segoe UI", 8),
                   fg="#648CB4", bg=BG)
    sep.place(x=100, y=y_pos)
    y_pos += 14

    make_label("Nguoi su dung:", y_pos)
    y_pos += 20
    sv_name = make_entry(y_pos, 340, cfg["user_name"])
    y_pos += 30

    make_label("Ma nhan su:", y_pos)
    y_pos += 20
    sv_id = make_entry(y_pos, 340, cfg["employee_id"])
    y_pos += 30

    make_label("Email:", y_pos)
    y_pos += 20
    sv_email = make_entry(y_pos, 340, cfg["email"])
    y_pos += 30

    # v4.9: configurable dropdown fields (admin-editable user_fields.json)
    combo_vars = {}
    for fld in _load_user_fields():
        make_label((fld.get("label") or "") + ":", y_pos)
        y_pos += 20
        opts = fld.get("options") or []
        sv = tk.StringVar(value=opts[0] if opts else "")
        cb = ttk.Combobox(root, textvariable=sv, values=opts, state="readonly",
                          font=("Consolas", 11))
        cb.place(x=30, y=y_pos, width=340, height=28)
        combo_vars[fld["key"]] = sv
        y_pos += 30

    # v4.5.5: PSK + Command Key - LUON hien (server can PSK de xac thuc may tram).
    # Chỉ host/port là tự động từ remote config; psk/command_key vẫn do quản trị
    # cấp phát - có thể điền tay hoặc để trống nếu đã được cấp sẵn trong config.
    make_label("PSK (khoa bao mat - bat buoc trung voi GIAMSAT_AGENT_PSK cua server):", y_pos)
    y_pos += 20
    sv_psk = make_entry(y_pos, 340, cfg.get("psk", ""), show="*")
    y_pos += 30

    make_label("Command Key (khoa ky lenh - trung voi GIAMSAT_COMMAND_KEY):", y_pos)
    y_pos += 20
    sv_ckey = make_entry(y_pos, 340, cfg.get("command_key", ""), show="*")
    y_pos += 30

    def on_ok():
        host = sv_host.get().strip()
        port_str = _sv_port.get().strip()
        try:
            port = int(port_str)
            if port < 1 or port > 65535:
                port = int(cfg["server_port"] or 6666)
        except ValueError:
            port = int(cfg["server_port"] or 6666)
        result["host"] = host
        result["port"] = port
        result["user_name"] = sv_name.get().strip()
        result["employee_id"] = sv_id.get().strip()
        result["email"] = sv_email.get().strip()
        _ux = {k: v.get().strip() for k, v in combo_vars.items()}
        result["user_extra"] = _ux
        result["branch"] = _ux.get("branch", "")
        result["psk"] = sv_psk.get().strip() if sv_psk else cfg.get("psk", "")
        result["command_key"] = sv_ckey.get().strip() if sv_ckey else cfg.get("command_key", "")
        result["net_mode"] = (mode_var.get() or "lan").strip().lower()
        result["confirmed"] = True
        root.destroy()

    def on_cancel():
        root.destroy()

    # OK Button
    btn_ok = tk.Button(root, text="Ket noi", font=("Segoe UI", 10, "bold"),
                       bg=BTN_OK_BG, fg=BTN_OK_FG, activebackground="#2A4A3A",
                       activeforeground="#AAEEBB", relief="flat", bd=0,
                       padx=10, pady=2, cursor="hand2", command=on_ok)
    btn_ok.place(x=200, y=y_pos, width=80, height=30)

    # Cancel Button
    btn_cancel = tk.Button(root, text="Huy", font=("Segoe UI", 10),
                           bg=BTN_CANCEL_BG, fg=BTN_CANCEL_FG, activebackground="#4A2A2A",
                           activeforeground="#FFAAAA", relief="flat", bd=0,
                           padx=10, pady=2, cursor="hand2", command=on_cancel)
    btn_cancel.place(x=290, y=y_pos, width=80, height=30)

    # Bind Enter/Escape
    root.bind("<Return>", lambda e: on_ok())
    root.bind("<Escape>", lambda e: on_cancel())

    # Focus first entry
    root.after(100, lambda: root.focus_force())

    root.mainloop()

    if result["confirmed"]:
        host, port = result["host"], result["port"]
        user_name, employee_id, email = result["user_name"], result["employee_id"], result["email"]
        psk = result.get("psk", "")
        command_key = result.get("command_key", "")
        branch = result.get("branch", "")
        user_extra = result.get("user_extra", {}) or {}
        net_mode = (result.get("net_mode") or "lan").strip().lower()
        _save_config(host, port, user_name, employee_id, email, psk, command_key, branch, user_extra, net_mode)
        _save_runtime_config(host, port)
        _log(f"Config saved via tkinter: {host}:{port} user={user_name} mode={net_mode} psk={'set' if psk else 'empty'}")
        return host, port, user_name, employee_id, email, psk, command_key, branch, user_extra, net_mode

    _log("Config dialog cancelled, using defaults")
    return result["host"], result["port"], result["user_name"], result["employee_id"], result["email"], result.get("psk", ""), result.get("command_key", ""), result.get("branch", ""), result.get("user_extra", {}), (result.get("net_mode") or "lan").strip().lower()


def _save_runtime_config(host, port):
    try:
        d = os.path.dirname(os.path.abspath(__file__))
        p = os.path.join(d, "config.json")
        cfg = {}
        if os.path.exists(p):
            with open(p, "r") as f: cfg = json.loads(f.read())
        cfg["server_host"] = host
        cfg["server_port"] = port
        with open(p, "w") as f: json.dump(cfg, f, indent=2)
    except: pass


def _persist_remote_server(host, port, psk=None, command_key=None):
    """v5.0.4: ghi host/port (+ psk/command_key nếu có) vào agent_config.json nếu đã tồn tại."""
    try:
        path = _get_config_path()
        if not os.path.exists(path):
            return
        with open(path, "r") as f:
            data = json.loads(f.read())
        data["server_host"] = str(host)
        data["server_port"] = int(port)
        if psk:
            data["psk"] = str(psk)
        if command_key:
            data["command_key"] = str(command_key)
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, path)
    except Exception:
        pass


def _ensure_sysmon_installed():
    """v2.6.0: Auto-install Sysmon64 if not already running as Windows service.
    Sysmon64.exe (1.5 MB) is embedded in the EXE via PyInstaller datas.
    """
    import time
    if os.name != "nt":
        return
    # Skip if --no-sysmon flag
    if "--no-sysmon" in sys.argv:
        _log("[Sysmon] Skipped (--no-sysmon flag)")
        return
    # Find embedded Sysmon64.exe and config
    if getattr(sys, "frozen", False):
        sysmon_exe = os.path.join(sys._MEIPASS, "Sysmon64.exe")
        config_xml = os.path.join(sys._MEIPASS, "sysmon_config.xml")
    else:
        agent_dir = os.path.dirname(os.path.abspath(__file__))
        sysmon_exe = os.path.join(agent_dir, "Sysmon64.exe")
        config_xml = os.path.join(agent_dir, "sysmon_config.xml")

    if not os.path.exists(sysmon_exe):
        _log("[Sysmon] Embedded Sysmon64.exe not found")
        return

    # v2.6.3: Always update Sysmon config (fix: onmatch="include" for all events)
    # Even if Sysmon is already installed, apply the latest config
    if os.path.exists(config_xml):
        try:
            _log("[Sysmon] Updating Sysmon64 config...")
            r = subprocess.run([sysmon_exe, "-c", config_xml],
                              capture_output=True, text=True, timeout=30,
                              creationflags=subprocess.CREATE_NO_WINDOW)
            if r.returncode == 0:
                _log("[Sysmon] Config updated successfully")
            else:
                _log(f"[Sysmon] Config update failed (rc={r.returncode}): {r.stderr or r.stdout}")
        except Exception as e:
            _log(f"[Sysmon] Config update error: {e}")

    # Check if already installed
    already_installed = False
    try:
        r = subprocess.run(["sc", "query", "Sysmon64"],
                          capture_output=True, text=True, timeout=5,
                          creationflags=subprocess.CREATE_NO_WINDOW)
        if r.returncode == 0 and "RUNNING" in r.stdout:
            already_installed = True
            _log("[Sysmon] Already installed and running")
    except Exception:
        pass

    if already_installed:
        # v2.6.3: Restart Sysmon64 to pick up new config
        try:
            subprocess.run(["sc", "stop", "Sysmon64"],
                          capture_output=True, timeout=10,
                          creationflags=subprocess.CREATE_NO_WINDOW)
            time.sleep(2)
            subprocess.run(["sc", "start", "Sysmon64"],
                          capture_output=True, timeout=10,
                          creationflags=subprocess.CREATE_NO_WINDOW)
            _log("[Sysmon] Service restarted with new config")
        except Exception as e:
            _log(f"[Sysmon] Restart error: {e}")
        return

    _log("[Sysmon] Installing Sysmon64 service...")
    try:
        cmd = [sysmon_exe, "-accepteula", "-i"]
        if os.path.exists(config_xml):
            cmd.append(config_xml)
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30,
                          creationflags=subprocess.CREATE_NO_WINDOW)
        if r.returncode == 0:
            _log("[Sysmon] Installed successfully")
            subprocess.run(["sc", "start", "Sysmon64"],
                          capture_output=True, timeout=10,
                          creationflags=subprocess.CREATE_NO_WINDOW)
            _log("[Sysmon] Service started")
        else:
            _log(f"[Sysmon] Install failed: {r.stderr or r.stdout}")
    except Exception as e:
        _log(f"[Sysmon] Install error: {e}")
def _ensure_it_support_shortcut():
    """v4.5.5: Auto-create the 'IT support' desktop shortcut so workstation users
    can proactively message the admin. Runs GiamSatAgent.exe --send-message."""
    if os.name != "nt":
        return
    try:
        # Skip when running under a service account (shortcut belongs on the user's desktop)
        import getpass
        u = (getpass.getuser() or "").upper()
        if u in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"):
            return
    except Exception:
        pass
    try:
        import subprocess
        exe = sys.executable if getattr(sys, "frozen", False) else os.path.abspath(sys.argv[0])
        desktop = os.path.join(os.path.expanduser("~"), "Desktop")
        try:
            import ctypes
            buf = ctypes.create_unicode_buffer(1024)
            # CSIDL_DESKTOPDIRECTORY = 0x0010 (handles OneDrive/redirected Desktop)
            if ctypes.windll.shell32.SHGetFolderPathW(None, 0x0010, None, 0, buf) == 0 and buf.value:
                desktop = buf.value
        except Exception:
            pass
        if not desktop or not os.path.isdir(desktop):
            return
        lnk = os.path.join(desktop, "IT support.lnk")
        if os.path.exists(lnk):
            return  # already created
        workdir = os.path.dirname(exe) or os.getcwd()
        ps = (
            "$ws = New-Object -ComObject WScript.Shell; "
            "$s = $ws.CreateShortcut($env:GIAMSAT_LNK); "
            "$s.TargetPath = $env:GIAMSAT_EXE; "
            "$s.Arguments = '--send-message'; "
            "$s.WorkingDirectory = $env:GIAMSAT_DIR; "
            "$s.Description = 'Send message to IT admin'; "
            "$s.Save()"
        )
        env = dict(os.environ)
        env["GIAMSAT_LNK"] = lnk
        env["GIAMSAT_EXE"] = exe
        env["GIAMSAT_DIR"] = workdir
        subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-NonInteractive", "-Command", ps],
            capture_output=True, timeout=20, env=env,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        _log(f"[IT Support] Shortcut created: {lnk}")
    except Exception as e:
        _log(f"[IT Support] Shortcut failed: {e}")



_log("All functions defined. Entering __main__...")


def _cleanup_old_temp_runtimes():
    """v3.9.7: Clean up old PyInstaller _MEI* temp dirs.
    Cleans both %TEMP% and the custom runtime_tmpdir in ProgramData.
    v5.0.4 FIX (HIGH-3): the old code rmtree'd EVERY _MEI* except the current one
    with no age guard / in-use probe - it deleted the runtime of other PyInstaller
    apps of the same user AND (with watchdog/agent starting concurrently) the
    agent's own runtime, causing 'Failed to load Python DLL ...python311.dll'.
    Now mirror updater.py: age guard (>6h) + rename probe (in-use dir cannot be
    renamed on Windows)."""
    import glob as _glob, shutil as _shutil, time as _time

    now = _time.time()

    def _safe_cleanup(base_dir):
        if not base_dir:
            return
        try:
            if not os.path.isdir(base_dir):
                return
            for meipass in _glob.glob(os.path.join(base_dir, "_MEI*")):
                if meipass == current_mei:
                    continue
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
                    _shutil.rmtree(meipass, ignore_errors=True)
                except Exception:
                    pass
        except Exception:
            pass

    # Get current runtime dir (the one this process is using)
    current_mei = getattr(sys, '_MEIPASS', '')

    # 1. Clean %TEMP%
    temp_dir = os.environ.get("TEMP", os.path.join(os.environ.get("USERPROFILE", "C:\\"), "AppData", "Local", "Temp"))
    _safe_cleanup(temp_dir)

    # 2. Clean custom runtime_tmpdir(s). v4.8.1: runtime đặt trong thư mục ĐÃ ĐƯỢC
    #    EXCLUDE của phần mềm bảo mật (C:\Tool\GIAM-SAT\runtime) để Defender không
    #    soi/xoá file đang giải nén (gây 'Failed to load Python DLL ...python311.dll');
    #    vẫn quét thư mục cũ (ProgramData) cho máy đang chạy build cũ.
    for _rd in (r"C:\Tool\GIAM-SAT\runtime",
                os.path.join(os.environ.get("PROGRAMDATA", r"C:\ProgramData"),
                             "GIAM-SAT", "Agent", "runtime")):
        _safe_cleanup(_rd)

# v3.9.7: Cleanup old temp runtimes at startup (before PyInstaller extracts new one)
if os.name == "nt" and getattr(sys, 'frozen', False):
    _cleanup_old_temp_runtimes()

if __name__ == "__main__":
    try:
        _log("__main__ START")

        # IT support: send message to admin (desktop shortcut "IT support")
        if "--send-message" in sys.argv:
            try:
                from agent_core import send_user_message
                send_user_message()
            except Exception as e:
                _log(f"send-message failed: {e}")
                try:
                    import ctypes
                    ctypes.windll.user32.MessageBoxW(0, f"Lỗi gửi tin nhắn: {e}", "IT support", 0x10)
                except Exception:
                    pass
            sys.exit(0)
        # v4.5.5: Auto-create IT support shortcut on the user's desktop
        _ensure_it_support_shortcut()



        # v2.5.23: Task Scheduler uses cmd /c start /MIN to launch.
        # ShowWindow(0) hides the minimized console window immediately.
        # This block is a fallback for manual launch scenarios.
        try:
            import ctypes
            hwnd = ctypes.windll.kernel32.GetConsoleWindow()
            if hwnd:
                ctypes.windll.user32.ShowWindow(hwnd, 0)  # SW_HIDE
                _log("Console hidden (startup)")
        except Exception:
            pass

        # Service mode
        try:
            import servicemanager, win32serviceutil, win32service, win32event
            if any(a in sys.argv for a in ["install","start","stop","remove","update","debug"]):
                from agent_service import GiamSatAgentService
                if len(sys.argv) == 1:
                    import servicemanager
                    servicemanager.Initialize()
                    servicemanager.PrepareToHostSingle(GiamSatAgentService)
                    servicemanager.StartServiceCtrlDispatcher()
                else:
                    win32serviceutil.HandleCommandLine(GiamSatAgentService)
                sys.exit(0)
        except ImportError:
            _log("Service imports skipped")

        # Task Scheduler - v4.8.1: nếu có GiamSatUpdater.exe (Updater daemon quản lý &
        # watchdog restart agent) thì agent KHÔNG tự đăng ký task logon riêng -> tránh
        # 2 nguồn khởi động cùng lúc (double-launch -> PyInstaller giải nén đè nhau,
        # gây 'Failed to load Python DLL'). Máy không có updater vẫn tự đăng ký (legacy).
        _has_updater = False
        try:
            _base = os.path.dirname(os.path.abspath(
                sys.executable if getattr(sys, "frozen", False) else os.path.abspath(__file__)))
            _has_updater = os.path.exists(os.path.join(_base, "GiamSatUpdater.exe"))
        except Exception:
            pass
        try:
            from task_scheduler import ensure_task
            if _has_updater:
                _log("GiamSatUpdater.exe present - khong dang ky AgentStartup (Updater quan ly agent)")
            else:
                ensure_task()
                _log("Task Scheduler OK")
        except Exception as e:
            _log(f"Task Scheduler FAIL: {e}")

        # Service check
        svc = _is_service_running()
        if svc:
            _log("Service running, exit")
            sys.exit(0)

        # Config check
        dd = _get_agent_data_dir()
        ff = os.path.join(dd, "force_config.flag")
        fc = os.path.exists(ff)
        if fc:
            try: os.remove(ff)
            except: pass

        cfg = _load_config()
        un = cfg.get("user_name", "").strip()
        cfg_net = (cfg.get("net_mode") or "").strip().lower()

        try:
            from remote_bootstrap import fetch_remote_config, ensure_tailscale_up
        except Exception:
            fetch_remote_config = ensure_tailscale_up = None

        remote = None
        # v4.8.0: hiện dialog khi máy CHƯA có người dùng (máy mới / copy sang máy khác)
        # hoặc bị ép (force_config.flag) và CÓ người ngồi ở console. Bỏ giới hạn cũ
        # "chỉ hỏi 1 lần/ngày" - chính nó khiến máy mới KHÔNG hiện dialog.
        need_dialog = fc or (un == "" and _has_interactive_console())

        if need_dialog:
            # Prefill cho dialog: chế độ tailscale dùng lệnh dòng 1 + ip-server dòng 2.
            if fetch_remote_config is not None:
                try:
                    remote = fetch_remote_config()
                except Exception as e:
                    _log(f"Remote config prefill fail: {e}")
            _log("Showing config dialog...")
            try:
                result = _show_config_dialog(remote, preselect_mode=cfg_net)
                host, port, user_name, employee_id, email, psk, command_key, branch, user_extra, net_mode = result
                _log(f"Dialog result: host={host}:{port} user={user_name} mode={net_mode}")
            except Exception as e:
                _log(f"Config dialog error ({e}) - dung cau hinh cu, tiep tuc khoi dong")
                host = cfg["server_host"]; port = cfg["server_port"]
                user_name = cfg["user_name"]; employee_id = cfg["employee_id"]; email = cfg["email"]
                psk = cfg.get("psk", ""); command_key = cfg.get("command_key", "")
                branch = cfg.get("branch", ""); user_extra = cfg.get("user_extra", {}) or {}
                net_mode = cfg_net or ("tailscale" if (remote and remote.get("auth_command")) else "lan")
            net_mode = (net_mode or "lan").strip().lower()
            if net_mode == "tailscale":
                # v4.8.0: chọn Tailscale -> tự động chạy đúng lệnh dòng 1 (authkey)
                # để cài/kết nối Tailscale trước khi kết nối server.
                auth = (remote and remote.get("auth_command")) or ""
                if auth:
                    try:
                        _ok_ts, _msg_ts = ensure_tailscale_up(auth)
                        _log(f"Tailscale bootstrap: {_msg_ts}")
                    except Exception as e:
                        _log(f"Tailscale bootstrap fail: {e}")
                else:
                    _log("Tailscale mode but no auth_command in remote file - tailscale up NOT run")
                # Host để trống thì lấy ip-server dòng 2 trong file
                if (not host or host in ("", "127.0.0.1", "localhost")) and remote and remote.get("server_host"):
                    host = str(remote["server_host"])
                    if remote.get("server_port"):
                        port = int(remote["server_port"])
            else:
                _log("LAN mode: khong chay Tailscale, dung host/port nguoi dung nhap")
        else:
            # v4.8.1 guard: máy LAN cũ (config tường minh nhưng chưa có net_mode)
            # KHÔNG được để remote config ghi đè host / kéo sang tailscale.
            _cur_host = (cfg.get("server_host") or "").strip().lower()
            _cfg_explicit = bool(cfg.get("configured")) and _cur_host not in ("", "127.0.0.1", "localhost")
            _host_is_tail = _cur_host.startswith("100.")
            _force_lan_legacy = (cfg_net == "" and _cfg_explicit and not _host_is_tail)
            if cfg_net == "lan" or _force_lan_legacy:
                if _force_lan_legacy:
                    _log(f"Legacy config host={_cur_host} -> giu LAN (khong fetch remote/tailscale)")
                    try:
                        _pcfg = os.path.join(dd, "agent_config.json")
                        if os.path.exists(_pcfg):
                            import json as _json
                            with open(_pcfg, "r", encoding="utf-8") as f:
                                _jc = _json.loads(f.read())
                            _jc["net_mode"] = "lan"
                            with open(_pcfg, "w", encoding="utf-8") as f:
                                _json.dump(_jc, f, indent=2)
                    except Exception:
                        pass
                else:
                    _log("Configured LAN mode - khong fetch remote/tailscale")
                net_mode = "lan"
            else:
                # Legacy / auto-tailscale (hoặc máy headless chưa cấu hình): giữ hành vi cũ
                if fetch_remote_config is not None:
                    try:
                        remote = fetch_remote_config()
                        if remote and remote.get("auth_command"):
                            try:
                                _ok_ts, _msg_ts = ensure_tailscale_up(remote["auth_command"])
                                _log(f"Tailscale bootstrap: {_msg_ts}")
                            except Exception as e:
                                _log(f"Tailscale bootstrap fail: {e}")
                        if remote and remote.get("server_host"):
                            cfg["server_host"] = str(remote["server_host"])
                            if remote.get("server_port"):
                                cfg["server_port"] = int(remote["server_port"])
                            if remote.get("psk"):
                                cfg["psk"] = str(remote["psk"])
                            if remote.get("command_key"):
                                cfg["command_key"] = str(remote["command_key"])
                            _persist_remote_server(cfg["server_host"], cfg["server_port"],
                                                   cfg.get("psk"), cfg.get("command_key"))
                            _log(f"Remote config OK: server={cfg['server_host']}:{cfg['server_port']}")
                    except Exception as e:
                        _log(f"Remote config fail: {e}")
            bp = _get_boot_tracker_path()
            try:
                with open(bp, "r") as f:
                    bd = json.loads(f.read())
            except Exception:
                bd = {}
            _log(f"Skip dialog, boot {bd.get('count', 0)}x today, user={un}")
            host = cfg["server_host"]
            port = cfg["server_port"]
            user_name = cfg["user_name"]
            employee_id = cfg["employee_id"]
            email = cfg["email"]
            psk = cfg.get("psk", "")
            command_key = cfg.get("command_key", "")
            branch = cfg.get("branch", "")
            user_extra = cfg.get("user_extra", {}) or {}
            net_mode = cfg_net
            if not net_mode and remote and remote.get("auth_command"):
                net_mode = "tailscale"  # legacy auto-tailscale
            if not net_mode:
                net_mode = "lan"
            if _force_lan_legacy:
                net_mode = "lan"

        # v5.0.4: watchdog phục hồi Tailscale - chỉ dành cho chế độ tailscale
        # (máy LAN thuần không cần/bị làm phiền bởi watchdog).
        try:
            import threading as _thr
            from remote_bootstrap import watchdog_loop as _ts_watchdog
            from remote_bootstrap import is_enabled as _ts_enabled
            if net_mode != "lan" and ((remote and remote.get("auth_command")) or _ts_enabled()):
                _thr.Thread(target=_ts_watchdog, daemon=True).start()
                _log("Tailscale watchdog started")
        except Exception as e:
            _log(f"Tailscale watchdog start fail: {e}")

        _log(f"Config: dir={dd} exists={os.path.exists(dd)} force={fc} user='{un}' server={host}:{port} mode={net_mode}")
        _log(f"Connecting {host}:{port} user={user_name} mode={net_mode} psk={'set' if psk else 'empty'}")

        _save_runtime_config(host, port)

        # v2.5.9: Console was already hidden at startup (v2.5.20).
        # Keep this block for non-TaskScheduler launch scenarios.
        try:
            import ctypes
            hwnd = ctypes.windll.kernel32.GetConsoleWindow()
            if hwnd:
                ctypes.windll.user32.ShowWindow(hwnd, 0)  # SW_HIDE
        except Exception:
            pass

        # v2.6.0: Auto-install Sysmon if not present
        _ensure_sysmon_installed()

        # v4.11 (HIGH-1): enable the audit/logging sources the detection rules
        # need (auditpol subcategories, 4688 command line, PS ScriptBlockLogging).
        # Runs once per install; requires admin/SYSTEM (agent service context).
        try:
            from baseline_hardening import run_baseline_hardening
            run_baseline_hardening(marker_dir=dd)
        except Exception:
            pass

        from agent_core import AgentCore
        agent = AgentCore(user_name=user_name, employee_id=employee_id, email=email, branch=branch)
        agent.user_extra = user_extra or {}
        agent.start()

    except SystemExit:
        pass
    except Exception as ex:
        _log(f"FATAL: {ex}\n{traceback.format_exc()}")
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(0,
                f"GIAM-SAT Agent Loi:\n{ex}\n\nLog: {_LOG_FILE}",
                "GIAM-SAT Loi", 0x10)
        except: pass
        sys.exit(1)
