"""
Agent Core for GIAM-SAT Agent v3.9.0
Orchestrates all collectors, manages TLS-encrypted TCP connection to server,
and handles commands. Cross-platform: Windows + Linux support.
v3.9.0: Log volume optimization (heartbeat 120s + metrics, network 3-tier aggregation).
"""
import json
import socket
import threading
import time
import sys
import os
import traceback
import ssl
from datetime import datetime
from collections import deque


def _setup_agent_env():
    try:
        if os.name == "nt":
            programdata = os.environ.get("PROGRAMDATA", "C:\\ProgramData")
            data_dir = os.path.join(programdata, "GIAM-SAT", "Agent")
        else:
            data_dir = os.path.join(os.path.expanduser("~"), ".giamsat", "agent")
        log_dir = os.path.join(data_dir, "logs")
        os.makedirs(log_dir, exist_ok=True)
        os.makedirs(data_dir, exist_ok=True)
        os.environ["GIAMSAT_DATA_DIR"] = data_dir
        import logging
        log_file = os.path.join(log_dir, "agent.log")
        root = logging.getLogger()
        if not root.handlers:
            handler = logging.FileHandler(log_file, encoding="utf-8")
            handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
            root.addHandler(handler)
            root.setLevel(logging.INFO)
        # v2.5.15: Also redirect print() to agent.log so ALL output is captured
        import builtins as _bi
        _orig_print = _bi.print
        def _print_to_log(*args, **kwargs):
            try:
                msg = " ".join(str(a) for a in args)
                with open(log_file, "a", encoding="utf-8") as f:
                    from datetime import datetime as _dt
                    f.write(f"[{_dt.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")
            except Exception:
                pass
            # Still attempt original print (may go to hidden console, that's fine)
            try:
                _orig_print(*args, **kwargs)
            except Exception:
                pass
        _bi.print = _print_to_log
    except Exception:
        pass

_setup_agent_env()

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "common"))

_AGENT_VERSION_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent_version.txt")

def _get_agent_version():
    """Read agent version from agent_version.txt shipped with the executable."""
    try:
        with open(_AGENT_VERSION_FILE, "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception:
        return "1.0.0"

AGENT_VERSION = _get_agent_version()

from config_manager import ConfigManager
from responder import Responder
from mitre_mapper import get_mitre_info
from correlation_engine import CorrelationEngine
from threat_intel import ThreatIntel
from vuln_scanner import VulnScanner
from yara_scanner import YaraScanner
from hw_collector import HWCollector
from network_traffic_analyzer import NetworkTrafficAnalyzer
from adaptive_baseline import AdaptiveBaseline
from sysmon_collector import SysmonCollector
from memory_scanner import MemoryScanner
from behavior_collector import BehaviorCollector

# v3.7.0: Named Pipe IPC for secure Agent ↔ Updater communication
try:
    from named_pipe_ipc import UpdaterIPCClient
    _HAS_NAMED_PIPE_IPC = True
except ImportError:
    _HAS_NAMED_PIPE_IPC = False

# TLS support

# v4.13 (P2): HTTPS for web API (server web TLS)
try:
    from http_client import base as _web_base, _ssl_ctx as _web_ssl_ctx
except ImportError:
    def _web_base(host, port, config=None): return 'http://' + str(host) + ':' + str(port)
    def _web_ssl_ctx(config=None): return None
def _web_open(req, timeout=15, config=None):
    import urllib.request as _ur
    return _ur.urlopen(req, timeout=timeout, context=_web_ssl_ctx(config))
try:
    from tls_utils import create_tls_client_socket, get_cert_dir, get_pinned_fingerprint_from_config
    _HAS_TLS = True
except ImportError:
    _HAS_TLS = False

# Encrypted cache
try:
    from encrypted_cache import EncryptedCache
    _HAS_ENCRYPTED_CACHE = True
except ImportError:
    _HAS_ENCRYPTED_CACHE = False
    from log_cache import LogCache

# SCA Scanner
try:
    from sca_scanner import SCAScanner
    _HAS_SCA = True
except ImportError:
    _HAS_SCA = False

# Platform-specific collectors
IS_WINDOWS = os.name == "nt"
if IS_WINDOWS:
    from event_collector import EnhancedEventCollector as EventCollector
    from fim_collector import FIMCollector
    from network_collector import NetworkCollector
else:
    from linux_collector import LinuxEventCollector, LinuxFIMCollector, LinuxHWCollector, LinuxNetworkCollector

# v3.9.0: IP address utilities for network traffic classification
def _is_private_ip(ip):
    """Check if an IP is RFC 1918 private or loopback."""
    if ip in ("127.0.0.1", "::1", "0.0.0.0", "::"):
        return True
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    if a == 10:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    if a == 169 and b == 254:
        return True  # APIPA
    return False

# v4.6.2 (SEC review P1-1): EID 1 pre-filter keyword list - previously the EID 1
# filter read a non-existent field (cmd_line instead of command_line) so every
# system32 process was dropped, and the "powershell -enc" substring could never
# match "powershell.exe -enc". Expanded to cover the common LOLBin families +
# encoded/suspicious PowerShell flags so PowerShell -EncodedCommand, plain
# scripts, cmd/certutil/mshta/schtasks/curl/msiexec... all reach the server.
_SUSPICIOUS_CMD_KEYWORDS = (
    "powershell", "pwsh",  # any PowerShell from system32 is high-signal
    "certutil", "bitsadmin", "wmic", "mshta", "rundll32", "regsvr32",
    "cscript", "wscript",
    "cmd.exe /c", "cmd /c", "schtasks", "forfiles", "pcalua", "curl",
    "msiexec", "net.exe", "net1.exe", "reg.exe", "sc.exe", "taskkill",
    "vssadmin", "esentutl", "wevtutil", "bcdedit", "wsl.exe",
    " -enc", "-encodedcommand", "-windowstyle", "exec bypass", "bypass",
    "iex(", "frombase64", "downloadstring", "downloadfile", "invoke-",
    "net user", " /add", "whoami", "systeminfo", "nslookup", "netstat -ano",
    "arp -a", "route print", "adduser",
)

# v4.6.2 (SEC review A3): EID 7 pre-filter - signed DLLs loaded by script hosts
# / LOLBins from non-system directories are logged (module stomping was fully
# invisible when every signed DLL was dropped).
_SCRIPT_HOST_LOADERS = (
    "powershell", "pwsh", "wscript", "cscript", "mshta", "msbuild",
    "wmic", "regsvr32", "rundll32", "cmd.exe",
)



def send_user_message():
    """IT support: open a structured support-request (ticket) dialog for the workstation
    user. Triggered by running the agent with --send-message (desktop shortcut 'IT support').
    v5.0.1: replaced the free-form chat with a category-based ticket (network/software/
    computer/monitor/printer/phone/other) + a REQUIRED short description + optional
    UltraView remote-support credentials. The machine + user are already known from the
    agent config - the user only picks a category and types what happened."""
    import tkinter as tk
    from tkinter import ttk
    import urllib.request

    cfg = ConfigManager()
    machine_id = cfg.get("machine_id", "")
    hostname = cfg.get("hostname", "") or os.environ.get("COMPUTERNAME", socket.gethostname())
    server_host = cfg.get("server_host", "")
    user_name = cfg.get("user_name", "") or cfg.get("employee_name", "")

    def _msgbox(title, text, icon=0x40):
        try:
            import ctypes as _ct
            _ct.windll.user32.MessageBoxW(0, text, title, icon | 0x0)
        except Exception:
            pass

    if not server_host or server_host == "YOUR_SERVER_IP":
        _msgbox("IT support", "Chưa cấu hình địa chỉ máy chủ (server_host).", 0x10)
        return

    CATS = [("network", "Mạng"), ("software", "Phần mềm"), ("computer", "Máy tính"),
            ("monitor", "Màn hình"), ("printer", "Máy in"), ("phone", "Điện thoại"),
            ("other", "Khác")]

    BG = "#1a2a3a"; FG = "#eef4f8"; ACCENT = "#00d4aa"
    ENTRY_BG = "#0f1923"; ENTRY_FG = "#eef4f8"; MUTED = "#c8d8e8"

    root = tk.Tk()
    root.title("IT support")
    root.configure(bg=BG)
    root.resizable(False, False)
    root.attributes("-topmost", True)

    w, h = 480, 460
    sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
    root.geometry(f"{w}x{h}+{int((sw - w) / 2)}+{int((sh - h) / 2)}")

    tk.Label(root, text="Yêu cầu hỗ trợ IT", font=("Segoe UI", 12, "bold"),
             fg=ACCENT, bg=BG).pack(pady=(14, 2))
    tk.Label(root, text=(f"Người gửi: {user_name} ({hostname})" if user_name else f"Máy: {hostname}"),
             font=("Segoe UI", 9), fg=MUTED, bg=BG).pack(pady=(0, 10))

    form = tk.Frame(root, bg=BG)
    form.pack(padx=18, fill="both", expand=True)

    def row_label(text, r):
        tk.Label(form, text=text, font=("Segoe UI", 9), fg=MUTED, bg=BG,
                 anchor="w", width=16).grid(row=r, column=0, sticky="w", pady=(6, 0))

    # Loại yêu cầu (bắt buộc)
    row_label("Loại yêu cầu *", 0)
    cat_var = tk.StringVar()
    cat_combo = ttk.Combobox(form, textvariable=cat_var, state="readonly", width=28,
                             values=[c[1] for c in CATS], font=("Segoe UI", 10))
    cat_combo.grid(row=0, column=1, sticky="w", pady=(6, 0), padx=(0, 4))
    cat_combo.set("")

    # Mô tả sự việc (bắt buộc - category alone is too vague for triage)
    row_label("Mô tả sự việc *", 1)
    note_entry = tk.Entry(form, font=("Segoe UI", 10), bg=ENTRY_BG, fg=ENTRY_FG,
                          insertbackground=ENTRY_FG, relief="flat", bd=1, width=32)
    note_entry.grid(row=1, column=1, sticky="w", pady=(6, 0), padx=(0, 4))

    # ID UltraView (không bắt buộc)
    row_label("ID UltraView", 2)
    uv_id_entry = tk.Entry(form, font=("Segoe UI", 10), bg=ENTRY_BG, fg=ENTRY_FG,
                           insertbackground=ENTRY_FG, relief="flat", bd=1, width=32)
    uv_id_entry.grid(row=2, column=1, sticky="w", pady=(6, 0), padx=(0, 4))
    tk.Label(form, text="(nếu có)", font=("Segoe UI", 8), fg="#5a6a7a",
             bg=BG).grid(row=2, column=2, sticky="w")

    # Mật khẩu UltraView (không bắt buộc)
    row_label("Mật khẩu", 3)
    uv_pwd_entry = tk.Entry(form, font=("Segoe UI", 10), bg=ENTRY_BG, fg=ENTRY_FG,
                            insertbackground=ENTRY_FG, relief="flat", bd=1, width=32, show="*")
    uv_pwd_entry.grid(row=3, column=1, sticky="w", pady=(6, 0), padx=(0, 4))
    tk.Label(form, text="(nếu có)", font=("Segoe UI", 8), fg="#5a6a7a",
             bg=BG).grid(row=3, column=2, sticky="w")

    status = tk.Label(root, text="", font=("Segoe UI", 9), fg=MUTED, bg=BG)
    status.pack(pady=(8, 0))

    def on_send():
        cat_disp = cat_var.get().strip()
        if not cat_disp:
            status.config(text="Vui lòng chọn loại yêu cầu.", fg="#ffaa88")
            return
        cat_code = next((c[0] for c in CATS if c[1] == cat_disp), "other")
        note = note_entry.get().strip()[:300]
        if not note:
            status.config(text="Vui lòng nhập mô tả sự việc.", fg="#ffaa88")
            return
        uv_id = uv_id_entry.get().strip()[:80]
        uv_pwd = uv_pwd_entry.get().strip()[:80]
        url = f"{_web_base(server_host, 5000, cfg)}/api/message/from-agent"
        try:
            payload = json.dumps({
                "machine_id": machine_id, "hostname": hostname,
                "user_name": user_name, "psk": cfg.get("psk", ""),
                "msg_type": "support_ticket", "category": cat_code,
                "note": note, "ultraview_id": uv_id, "ultraview_password": uv_pwd,
            }, ensure_ascii=False).encode("utf-8")
            req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
            _web_open(req, 15, cfg)
            root.destroy()
            _msgbox("IT support", "Đã gửi yêu cầu hỗ trợ cho quản trị viên IT.", 0x40)
        except Exception as e:
            status.config(text=f"Lỗi gửi: {e}", fg="#ff8888")

    btn_frame = tk.Frame(root, bg=BG)
    btn_frame.pack(pady=(6, 14))
    tk.Button(btn_frame, text="Đóng", font=("Segoe UI", 10), bg="#4A2A2A", fg="#FFAAAA",
              activebackground="#5A3A3A", activeforeground="#FFBBBB", relief="flat", bd=0,
              padx=12, pady=3, cursor="hand2", command=root.destroy).pack(side="left", padx=6)
    tk.Button(btn_frame, text="Gửi yêu cầu", font=("Segoe UI", 10, "bold"), bg="#2A4A3A", fg="#AAEEBB",
              activebackground="#3A5A4A", activeforeground="#BBFFCC", relief="flat", bd=0,
              padx=16, pady=3, cursor="hand2", command=on_send).pack(side="left", padx=6)

    root.bind("<Return>", lambda e: on_send())
    root.after(100, lambda: root.focus_force())
    root.mainloop()


class AgentCore:
    def __init__(self, user_name="", employee_id="", email="", branch=""):
        self.config = ConfigManager()
        self.user_name = user_name
        self.employee_id = employee_id
        self.email = email
        self.branch = branch
        self.user_extra = {}
        self.running = True
        self.sock = None
        self.connected = False
        self.tls_enabled = False
        self.reconnect_interval = 2
        self.max_reconnect_interval = 60
        self._send_lock = threading.Lock()
        self.pending_queue = deque()
        self.pending_lock = threading.Lock()

        def send_to_server(data):
            return self._send_json(data)

        if _HAS_ENCRYPTED_CACHE:
            self.log_cache = EncryptedCache(send_callback=send_to_server)
        else:
            self.log_cache = LogCache(send_callback=send_to_server)

        self.server_host = self.config.get("server_host", "YOUR_SERVER_IP")
        self.server_port = self.config.get("server_port", 6666)
        self.tls_enabled = self.config.get("tls_enabled", True)
        self.machine_id = self.config.get("machine_id", "unknown")
        self.hostname = self.config.get("hostname", os.environ.get("COMPUTERNAME", socket.gethostname()))
        self.platform = "Windows" if IS_WINDOWS else "Linux"
        self.responder = Responder()

        self._batch_buffer = []
        self._batch_lock = threading.Lock()

        def send_data(data):
            self._enrich_and_queue(data)

        # Platform-specific collectors
        if IS_WINDOWS:
            # v4.6.4: SysmonCollector already covers the Sysmon channel with richer
            # fields + engine feed - don't read it twice (double-sent events).
            # v4.6.5: pass agent PID + optional skip_processes so the event collector
            # can drop 4688 for the agent's own routine children (netstat/powershell/
            # conhost) and configured processes (e.g. postgres.exe on the server).
            _skip_procs = list(self.config.get("skip_processes") or [])
            _env_skip = os.environ.get("GIAMSAT_SKIP_PROCESSES", "")
            if _env_skip:
                _skip_procs += [p.strip() for p in _env_skip.split(",") if p.strip()]
            self.event_collector = EventCollector(callback=send_data, collect_sysmon=False,
                                                  agent_pid=os.getpid(), skip_processes=_skip_procs)
            self.fim_collector = FIMCollector(callback=send_data)
            # v5.0.4 (review R7 7.6): inspection_callback carries TLS SNI/JA3 DPI
            # events (network_inspection subtype=tls_sni) on the same channel.
            self.network_collector = NetworkCollector(callback=send_data,
                                                      inspection_callback=send_data)
        else:
            self.event_collector = LinuxEventCollector(callback=send_data)
            self.fim_collector = LinuxFIMCollector(callback=send_data)
            self.network_collector = LinuxNetworkCollector(callback=send_data)

        self.threat_intel = ThreatIntel(callback=lambda t: self._real_send(t))
        self.vuln_scanner = VulnScanner(callback=self._vuln_callback)
        self.yara_scanner = YaraScanner(callback=self._yara_callback)
        self.correlation_engine = CorrelationEngine(alert_callback=lambda a: self._real_send(a))
        self.sca_scanner = None
        if _HAS_SCA:
            self.sca_scanner = SCAScanner(callback=lambda e: self._real_send(e))
        self._hw_config_sent = False

        # Network Traffic Analyzer for anomaly detection
        def on_anomaly(anomaly_data):
            anomaly_data["machine_id"] = self.machine_id
            anomaly_data["hostname"] = self.hostname
            self._real_send(anomaly_data)

        self.traffic_analyzer = NetworkTrafficAnalyzer(callback=on_anomaly)

        # Adaptive Baseline
        def on_baseline_report(report):
            report["machine_id"] = self.machine_id
            report["hostname"] = self.hostname
            self._real_send(report)
            # v4.11 (CN2): surface baseline deviations as threat alerts so they
            # reach the server alerting path (Telegram / admin email / digest)
            # instead of being just a stored baseline_report event.
            deviations = report.get("deviations") or []
            if deviations:
                try:
                    desc = "; ".join(str(d.get("description", "")) for d in deviations[:3])
                    sev = "HIGH" if int(report.get("anomaly_score", 0)) >= 60 else "MEDIUM"
                    alert = {
                        "type": "threat_alert",
                        "rule_id": "BASELINE-001",
                        "rule_name": "Network Baseline Anomaly",
                        "severity": sev,
                        "description": f"Baseline anomaly (score {report.get('anomaly_score', 0)}): {desc}",
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "machine_id": self.machine_id,
                        "hostname": self.hostname,
                    }
                    self._real_send(alert)
                except Exception:
                    pass

        self.adaptive_baseline = AdaptiveBaseline(callback=on_baseline_report)

        # v3.8.0: Sysmon + Memory Scanner
        self.sysmon_collector = SysmonCollector(callback=self._sysmon_callback)
        self._use_sysmon_network = False
        self.memory_scanner = MemoryScanner(callback=lambda e: self._real_send(e))

        # v3.2: Behavior Collector (baseline data for anomaly detection)
        self.behavior_collector = BehaviorCollector(callback=lambda r: self._real_send(r))

        # v3.9.13: Dedup processed commands (avoid double delivery from TCP + HTTP poll)
        self._processed_execs = set()
        self._processed_execs_lock = threading.Lock()
        self._processed_execs_max = 2000  # Cleanup at 2000 to prevent memory leak

        # v5.0.3 (MEDIUM-6): command nonce cache - reject replays inside the
        # timestamp window (each signed command executes at most once).
        self._nonce_cache = {}
        self._nonce_lock = threading.Lock()

        # v3.9.0: Network traffic 3-tier aggregation
        self._net_agg = {}          # key -> {count, first_seen, last_seen, bytes}
        self._net_agg_lock = threading.Lock()
        self._net_agg_interval = 180  # v3.9.6: Flush aggregated every 180s (reduced from 60s for 3x fewer flushes)
        self._internal_baseline = {}  # dst_ip:port -> seen_count
        self._baseline_lock = threading.Lock()
        self._BL_LEARNING = True      # First 24h: build baseline
        self._bl_start = time.time()

        # Suspicious internal ports (lateral movement indicators)
        self._SUS_INTERNAL_PORTS = {22, 23, 135, 139, 445, 3389, 5900, 5985, 5986, 1433, 3306, 5432, 6379, 27017, 8080, 8443, 4444, 5555}

        # Common DNS/resolver process names to dedup aggressively
        self._DNS_PROCESSES = {"svchost.exe", "dns.exe", "named.exe", "systemd-resolved", "systemd-resolve"}

        # v3.9.3: VLAN/Subnet mapping + triggered PCAP for lateral movement
        self._vlan_subnets = {}       # subnet_name -> (network_addr, netmask)
        self._pcap_config = {"enabled": False, "snap_len": 256, "count": 5, "timeout_sec": 3, "capture_ports": []}
        self._pcap_lock = threading.Lock()
        self._load_vlan_config()

        print(f"[*] AgentCore.__init__ START", flush=True)
        print(f"[*]   user_name={self.user_name}", flush=True)
        print(f"[*]   employee_id={self.employee_id}", flush=True)
        print(f"[*]   email={self.email}", flush=True)
        print(f"[*]   server_host={self.server_host}", flush=True)
        print(f"[*]   server_port={self.server_port}", flush=True)
        print(f"[*]   machine_id={self.machine_id}", flush=True)
        print(f"[*]   hostname={self.hostname}", flush=True)
        print(f"[*]   platform={self.platform}", flush=True)
        print(f"[*]   tls_enabled={self.tls_enabled}", flush=True)
        print(f"[*] AgentCore.__init__ DONE", flush=True)

    def _enrich_and_queue(self, data):
        event_type = data.get("type", "")
        mitre = get_mitre_info(data)
        if mitre:
            data["mitre_tactic"] = mitre.get("tactic", "")
            data["mitre_technique_id"] = mitre.get("technique_id", "")
            data["mitre_technique_name"] = mitre.get("technique_name", "")
            data["mitre_severity"] = mitre.get("severity", "")
        if event_type == "network_traffic":
            try:
                self.traffic_analyzer.analyze_packet(data)
                self.adaptive_baseline.feed_packet(data)
            except Exception:
                pass
            dst_ip = data.get("dst_ip", "")
            if dst_ip:
                intel = self.threat_intel.check_ip(dst_ip)
                if intel and intel.get("malicious"):
                    data["threat_intel_match"] = True
                    data["threat_intel_reason"] = intel.get("reason", "")
                    data["threat_intel_tags"] = json.dumps(intel.get("tags", []))
                    data["threat_intel_source"] = intel.get("source", "")
        self.correlation_engine.process_event(data)
        if event_type in ("threat_alert", "vulnerability_alert", "yara_alert", "sca_event",
                          "network_inspection",
                          "machine_config", "register", "heartbeat", "response_result"):
            # v4.1: Enrich alert metadata for Telegram context
            if event_type == "threat_alert":
                # Add missing fields that Telegram template expects
                if "hostname" not in data or not data.get("hostname"):
                    data["hostname"] = self.hostname
                if "machine_id" not in data or not data.get("machine_id"):
                    data["machine_id"] = self.machine_id
                if "ip_address" not in data:
                    try:
                        data["ip_address"] = socket.gethostbyname(self.hostname)
                    except Exception:
                        data["ip_address"] = self.config.get("ip_address", "")
                if "platform" not in data:
                    data["platform"] = self.platform
                # MITRE mapping (re-run if missing)
                if "mitre_tactic" not in data:
                    mitre = get_mitre_info(data)
                    if mitre:
                        data["mitre_tactic"] = mitre.get("tactic", "")
                        data["mitre_technique_id"] = mitre.get("technique_id", "")
                        data["mitre_technique_name"] = mitre.get("technique_name", "")
                        data["mitre_severity"] = mitre.get("severity", "")
                # Process chain from trigger event
                trigger = data.get("trigger_event", {})
                if "process_chain" not in data and trigger.get("process_chain"):
                    data["process_chain"] = trigger["process_chain"]
                # Ensure trigger_event is set
                if not trigger:
                    data["trigger_event"] = {
                        "description": data.get("description", ""),
                        "rule_name": data.get("rule_name", ""),
                        "severity": data.get("severity", ""),
                    }
            self._real_send(data)
            # v3.9.17: Auto-Isolation on Ransomware alerts
            if event_type == "threat_alert":
                rule_id = data.get("rule_id", "")
                if rule_id.startswith("RANSOM-"):
                    self._request_approval_or_execute(
                        rule_id, "isolate_network", data,
                        desc=f"RANSOMWARE: {data.get('rule_name', rule_id)}"
                    )
                # v4.0: Auto-Lock User on Kerberos Golden Ticket attacks
                if rule_id.startswith("KERB-"):
                    self._request_approval_or_execute(
                        rule_id, "lock_account", data,
                        desc=f"KERBEROS ATTACK: {data.get('rule_name', rule_id)}"
                    )
            # v4.0: Auto-Quarantine on YARA alerts with file_path
            if event_type == "yara_alert":
                file_path = data.get("file", "")
                if file_path and os.path.exists(file_path):
                    self._request_approval_or_execute(
                        "YARA", "quarantine_file", data,
                        desc=f"YARA: {data.get('rule_name', 'unknown')}",
                        params={"file_path": file_path, "reason": f"YARA: {data.get('rule_name', 'unknown')}"}
                    )
        elif event_type == "network_traffic":
            # v3.9.3: Route through 3-tier aggregation instead of direct send
            self._classify_and_queue_network(data)
        else:
            with self._batch_lock:
                self._batch_buffer.append(data)

    def _real_send(self, data):
        data["machine_id"] = data.get("machine_id", self.machine_id)
        data["hostname"] = data.get("hostname", self.hostname)
        data["timestamp"] = data.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        if self.connected and self.sock:
            if self._send_json(data):
                return
        self.log_cache.cache(data)
        with self.pending_lock:
            self.pending_queue.append(data)
            if len(self.pending_queue) > 500:
                self.pending_queue.popleft()

    def _batch_flush_loop(self):
        while self.running:
            time.sleep(15)
            with self._batch_lock:
                batch = self._batch_buffer[:]
                self._batch_buffer.clear()
            for data in batch:
                self._real_send(data)

    def _flush_cache(self):
        cached_count = self.log_cache.get_cache_size()
        if cached_count == 0:
            return
        print(f"[*] Flushing {cached_count} cached messages...")
        while self.connected:
            sent = self.log_cache.flush_batch(batch_size=100, delay_ms=200)
            if sent < 100 or not self.connected:
                break

    def _get_hw_config_data(self):
        try:
            if IS_WINDOWS:
                hw = HWCollector()
                hw_data = hw.collect()
            else:
                hw = LinuxHWCollector()
                hw_data = hw.collect()
            hw_data["type"] = "machine_config"
            hw_data["machine_id"] = self.machine_id
            hw_data["hostname"] = self.hostname
            hw_data["platform"] = self.platform
            if "timestamp" not in hw_data:
                hw_data["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            return hw_data
        except Exception as e:
            print(f"[-] HW config failed: {e}")
            return None

    def _log_connect(self, msg):
        """Write connection log to agent_startup.log (same as main.py)."""
        try:
            appdata = os.environ.get("APPDATA", os.path.expanduser("~"))
            log_file = os.path.join(appdata, "GIAM-SAT", "Agent", "logs", "agent_startup.log")
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")
        except Exception:
            pass

    def _connect(self):
        try:
            if self.sock:
                try: self.sock.close()
                except Exception: pass

            self._log_connect(f"Connect: host={self.server_host}:{self.server_port} tls={self.tls_enabled}")

            # TLS connection
            if self.tls_enabled and _HAS_TLS:
                cafile = os.path.join(get_cert_dir(), "ca.crt")
                # v3.9.17: Certificate Pinning — get pinned fingerprint from config
                pinned_fp = get_pinned_fingerprint_from_config(self.config)
                self._log_connect(f"Calling create_tls_client_socket({self.server_host}, {self.server_port}) pinned={bool(pinned_fp)}")
                result = create_tls_client_socket(self.server_host, self.server_port, cafile, pinned_fingerprint=pinned_fp)
                if result and result[0]:
                    self.sock = result[0]
                    self.tls_enabled = result[1]
                    self._log_connect(f"TLS socket OK, tls_enabled={self.tls_enabled}")
                else:
                    # v4.5.4 SECURITY: refuse plaintext fallback when TLS is enabled
                    self._log_connect("TLS connection failed - refusing plaintext fallback (security)")
                    raise ConnectionError("TLS required but connection failed")
            else:
                self._log_connect("TLS disabled, connecting plaintext")
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.settimeout(30)
                self.sock.connect((self.server_host, self.server_port))
                self.sock.settimeout(60)

            self.connected = True
            conn_type = "TLS" if self.tls_enabled else "plaintext"
            self._send_json({"type": "register", "machine_id": self.machine_id, "hostname": self.hostname,
                "platform": self.platform, "version": AGENT_VERSION, "tls": self.tls_enabled,
                "psk": self.config.get("psk", ""),
                "enrollment_token": self.config.get("enrollment_token", ""),
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
            self._log_connect(f"[+] Connected to {self.server_host}:{self.server_port} ({conn_type})")
            print(f"[+] Connected to server {self.server_host}:{self.server_port} ({conn_type})")

            # Send user info if available (v2.2.0)
            if self.user_name or self.employee_id or self.email:
                try:
                    user_msg = {
                        "type": "user_info",
                        "machine_id": self.machine_id,
                        "hostname": self.hostname,
                        "user_name": self.user_name,
                        "employee_id": self.employee_id,
                        "email": self.email,
                        "branch": self.branch,
                        "user_extra": self.user_extra,
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
                    self._send_json(user_msg)
                    self._log_connect(f"[*] User info sent: {self.user_name}")
                    print(f"[*] User info sent: {self.user_name}")
                except Exception as e:
                    self._log_connect(f"[-] Failed to send user info: {e}")

            if not self._hw_config_sent:
                try:
                    hw_data = self._get_hw_config_data()
                    if hw_data:
                        time.sleep(0.5)
                        hw_data["type"] = "machine_config"
                        hw_data["machine_id"] = self.machine_id
                        hw_data["hostname"] = self.hostname
                        msg = json.dumps(hw_data, ensure_ascii=False) + "\n"
                        with self._send_lock:
                            if self.sock and self.connected:
                                self.sock.sendall(msg.encode("utf-8"))
                                self._hw_config_sent = True
                except Exception as e:
                    self._log_connect(f"[-] HW config send failed: {e}")

            # Run SCA scan on first connect
            if self.sca_scanner:
                try:
                    sca_results = self.sca_scanner.run_scan()
                    if sca_results:
                        self._log_connect(f"[*] SCA scan: {len(sca_results)} checks")
                except Exception as e:
                    self._log_connect(f"[-] SCA scan failed: {e}")

            t = threading.Thread(target=self._flush_cache, daemon=True)
            t.start()
            return True
        except Exception as exc_connect:
            self._log_connect(f"[-] CONNECT FAILED: {exc_connect}\n{traceback.format_exc()}")
            self.connected = False
            return False

    def _send_json(self, data):
        if "machine_id" not in data: data["machine_id"] = self.machine_id
        if "hostname" not in data: data["hostname"] = self.hostname
        if "timestamp" not in data: data["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with self._send_lock:
                if self.sock and self.connected:
                    msg = json.dumps(data, ensure_ascii=False) + "\n"
                    self.sock.sendall(msg.encode("utf-8"))
                    return True
        except Exception:
            self.connected = False
        return False

    def _receive_commands(self):
        buffer = ""
        while self.running:
            try:
                if not self.connected or not self.sock:
                    time.sleep(1); continue
                data = self.sock.recv(65536)
                if not data: self.connected = False; continue
                buffer += data.decode("utf-8", errors="ignore")
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1); line = line.strip()
                    if not line: continue
                    try:
                        cmd = json.loads(line)
                        # v4.5.4: handle register ack (per-machine enrollment token)
                        if cmd.get("type") == "register_ack":
                            tok = cmd.get("enrollment_token", "")
                            if tok:
                                try:
                                    self.config.update("enrollment_token", tok)
                                    print("[+] Enrollment token saved")
                                except Exception:
                                    pass
                            continue
                        self._handle_command(cmd)
                    except json.JSONDecodeError: pass
            except socket.timeout: continue
            except Exception: self.connected = False; time.sleep(1)

    def _verify_command_signature(self, cmd):
        """
        v4.5.5: Verify command signature over the ENTIRE command JSON (fail-closed).
        Uses HMAC-SHA256 with shared secret from config (GIAMSAT_COMMAND_KEY env var).
        Server signs commands -> Agent verifies before executing.

        Returns True only if the signature is valid.
        Returns False if signing is not configured or signature is invalid/missing.
        """
        signature = cmd.pop("_sig", None)
        cmd.pop("_sig_data", None)

        import hmac as _hmac
        import hashlib as _hashlib
        import json as _json

        signing_key = os.environ.get("GIAMSAT_COMMAND_KEY", "").strip()
        if not signing_key:
            try:
                signing_key = (self.config.get("command_key") or "").strip()
            except Exception:
                pass

        # Fail-closed: no signing key configured -> reject all commands
        if not signing_key:
            print("[!] SIGNING DISABLED: no GIAMSAT_COMMAND_KEY configured - rejecting command (fail-closed)")
            return False

        # Signing configured but received unsigned command -> reject
        if not signature:
            print(f"[!] SIGNING VIOLATION: Received unsigned command '{cmd.get('action', '?')}' but signing is configured")
            return False

        # Reconstruct signing string: the ENTIRE command JSON (sorted keys)
        try:
            sign_data = _json.dumps(cmd, sort_keys=True, ensure_ascii=False)
            expected_sig = _hmac.new(
                signing_key.encode("utf-8"),
                sign_data.encode("utf-8"),
                _hashlib.sha256
            ).hexdigest()

            if not _hmac.compare_digest(expected_sig, signature):
                print(f"[!] SIGNATURE MISMATCH: Command '{cmd.get('action', '?')}' rejected")
                return False

            # v4.5.4: replay protection - reject commands outside a 5-minute window
            try:
                cmd_ts = int(cmd.get("_ts", 0) or 0)
            except (TypeError, ValueError):
                cmd_ts = 0
            if abs(int(time.time()) - cmd_ts) > 300:
                print(f"[!] REPLAY/STALE: Command '{cmd.get('action', '?')}' timestamp outside 5min window")
                return False

            # v5.0.3 (MEDIUM-6): nonce - reject replays within the timestamp window
            try:
                nonce = str(cmd.get("_nonce", "") or "")
            except Exception:
                nonce = ""
            if not nonce:
                print(f"[!] REPLAY: Command '{cmd.get('action', '?')}' missing nonce - rejected")
                return False
            with self._nonce_lock:
                now = time.time()
                # GC nonces older than the 5-minute validity window
                try:
                    expired = [k for k, t in self._nonce_cache.items() if now - t > 300]
                    for k in expired:
                        self._nonce_cache.pop(k, None)
                except Exception:
                    pass
                if nonce in self._nonce_cache:
                    print(f"[!] REPLAY: Command '{cmd.get('action', '?')}' duplicate nonce - rejected")
                    return False
                self._nonce_cache[nonce] = now
                if len(self._nonce_cache) > 5000:
                    self._nonce_cache = dict(list(self._nonce_cache.items())[-3000:])

            return True
        except Exception as e:
            print(f"[-] Signature verification error: {e}")
            return False

    def _handle_command(self, cmd):
        # v3.9.17: Verify command signature before execution
        if not self._verify_command_signature(cmd):
            print(f"[!] Command rejected due to signature failure: {cmd.get('action', '?')}")
            return
        
        action = cmd.get("action", "")
        if action == "agent_update":
            exec_id = cmd.get("exec_id", "")
            if exec_id and self._is_duplicate(exec_id):
                print(f"[DEDUP] Skipping already processed agent_update ({exec_id})")
            else:
                t = threading.Thread(target=self._handle_agent_update_command, args=(cmd,), daemon=True)
                t.start()
        elif action == "reset_user":
            exec_id = cmd.get("exec_id", "")
            if exec_id and self._is_duplicate(exec_id):
                print(f"[DEDUP] Skipping already processed reset_user ({exec_id})")
            else:
                t = threading.Thread(target=self._handle_reset_user_command, args=(cmd,), daemon=True)
                t.start()
        elif action == "show_message":
            # v3.9.15: Route to ctypes MessageBoxW (no PowerShell dependency)
            # PowerShell forms crash in daemon threads / session 0 / Tailscale context
            # v4.10: dedup by msg_id - the same message may arrive via TCP push AND HTTP poll
            exec_id = cmd.get("msg_id") or cmd.get("exec_id") or ""
            if exec_id and self._is_duplicate(exec_id):
                print(f"[DEDUP] Skipping already processed show_message ({exec_id})")
            else:
                t = threading.Thread(target=self._handle_show_message, args=(cmd,), daemon=True)
                t.start()
        else:
            t = threading.Thread(target=self._execute_and_report, args=(cmd,), daemon=True)
            t.start()

    def _handle_show_message(self, cmd):
        """v4.3.3: Show message using Python tkinter (same as config dialog in main.py).
        No PowerShell dependency — avoids all STA/console/message pump issues.
        Works from daemon threads, Session 0, Tailscale, any context."""
        msg_id = cmd.get("msg_id", "")
        title = cmd.get("title", "Thong bao")
        message = cmd.get("message", "")
        require_reply = cmd.get("require_reply", True)
        sender = cmd.get("sender", "admin")

        print(f"[MSG] Displaying message: msg_id={msg_id} title={title} require_reply={require_reply}")
        msg_replied = False
        msg_reply = ""

        try:
            # v4.5.x: point Tcl/Tk to bundled data (fix 'init.tcl' in PyInstaller build)
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

            root = tk.Tk()
            root.title(f"GIAM-SAT: {title} (tu: {sender})")
            root.resizable(True, True)
            root.attributes("-topmost", True)

            # Dark theme colors
            BG = "#0F1923"
            FG = "#FFFFFF"
            ACCENT = "#00D4AA"
            BTN_OK_BG = "#1A3A2A"
            BTN_OK_FG = "#88DD99"
            BTN_CANCEL_BG = "#3A1A1A"
            BTN_CANCEL_FG = "#FF8888"
            LABEL_FG = "#C8D8E8"
            ENTRY_BG = "#1A2A3A"
            ENTRY_FG = "#EEF4F8"

            root.configure(bg=BG)

            # Window size
            W, H = 500, 300 if require_reply else 200
            ws, hs = root.winfo_screenwidth(), root.winfo_screenheight()
            x, y = (ws - W) // 2, (hs - H) // 2
            root.geometry(f"{W}x{H}+{x}+{y}")

            # Title label
            t = tk.Label(root, text=f"GIAM-SAT: {title}", font=("Segoe UI", 12, "bold"),
                         fg=ACCENT, bg=BG, wraplength=W-30, justify="left")
            t.pack(padx=15, pady=(12, 4), anchor="w")

            # Sender info
            sender_lbl = tk.Label(root, text=f"Tu: {sender}", font=("Segoe UI", 8),
                                  fg="#648CB4", bg=BG, anchor="w")
            sender_lbl.pack(padx=15, pady=(0, 8), anchor="w")

            # Message text
            msg_frame = tk.Frame(root, bg=BG)
            msg_frame.pack(fill="both", expand=True, padx=15, pady=(0, 5))
            msg_text = tk.Text(msg_frame, font=("Segoe UI", 10), bg=ENTRY_BG, fg=ENTRY_FG,
                               wrap="word", relief="flat", bd=0, padx=8, pady=8,
                               height=5, state="disabled")
            msg_text.pack(fill="both", expand=True)
            msg_text.configure(state="normal")
            msg_text.insert("1.0", message)
            msg_text.configure(state="disabled")

            # Reply box (if required)
            reply_var = tk.StringVar()
            if require_reply:
                reply_label = tk.Label(root, text="Phan hoi:",
                                       font=("Segoe UI", 9), fg=LABEL_FG, bg=BG, anchor="w")
                reply_label.pack(padx=15, pady=(8, 2), anchor="w")
                reply_entry = tk.Entry(root, textvariable=reply_var, font=("Segoe UI", 10),
                                       bg=ENTRY_BG, fg=ENTRY_FG, insertbackground=ENTRY_FG,
                                       relief="flat", bd=1)
                reply_entry.pack(padx=15, pady=(0, 10), fill="x")

            # Buttons
            btn_frame = tk.Frame(root, bg=BG)
            btn_frame.pack(pady=(0, 12))
            
            def on_send():
                nonlocal msg_replied, msg_reply
                if require_reply:
                    reply_text = reply_var.get().strip()
                    if reply_text:
                        msg_replied = True
                        msg_reply = reply_text
                root.destroy()

            def on_close():
                root.destroy()

            btn_cancel = tk.Button(btn_frame, text="Đóng", font=("Segoe UI", 10),
                                   bg=BTN_CANCEL_BG, fg=BTN_CANCEL_FG,
                                   activebackground="#4A2A2A", activeforeground="#FFAAAA",
                                   relief="flat", bd=0, padx=10, pady=2, cursor="hand2",
                                   command=on_close)
            btn_cancel.pack(side="left", padx=5)

            if require_reply:
                btn_ok = tk.Button(btn_frame, text="Gửi phản hồi", font=("Segoe UI", 10, "bold"),
                                   bg=BTN_OK_BG, fg=BTN_OK_FG,
                                   activebackground="#2A4A3A", activeforeground="#AAEEBB",
                                   relief="flat", bd=0, padx=10, pady=2, cursor="hand2",
                                   command=on_send)
                btn_ok.pack(side="left", padx=5)

            root.bind("<Return>", lambda e: on_send())
            root.bind("<Escape>", lambda e: on_close())
            root.after(100, lambda: root.focus_force())
            root.mainloop()

            print(f"[MSG] Dialog closed: msg_id={msg_id} replied={msg_replied}")

        except Exception as e:
            print(f"[-] tkinter dialog failed: {e}, falling back to MessageBoxW")
            # Fallback: simple ctypes MessageBoxW (no reply support)
            try:
                import ctypes as _ct
                display_msg = f"{message}\n\nTu: {sender}"
                _ct.windll.user32.MessageBoxW(0, display_msg, f"GIAM-SAT: {title}", 0x40 | 0x1)
            except Exception:
                pass

        # Send response back to server
        try:
            resp = {
                "type": "response_result",
                "machine_id": self.machine_id,
                "hostname": self.hostname,
                "action": "show_message",
                "exec_id": msg_id,
                "status": "completed",
                "output": f"{'Replied' if msg_replied else 'Shown'}: {msg_reply[:200] if msg_replied else 'No reply'}",
                "msg_replied": msg_replied,
                "msg_reply": msg_reply[:500] if msg_replied else "",
                "msg_id": msg_id,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            self._real_send(resp)
            print(f"[MSG] Reply sent: msg_id={msg_id} replied={msg_replied}")
        except Exception as e:
            print(f"[-] Failed to send message response: {e}")

        return {
            "status": "completed",
            "output": msg_reply[:500] if msg_replied else "Message displayed",
            "error": "",
            "exit_code": 0,
            "msg_replied": msg_replied,
            "msg_reply": msg_reply[:500] if msg_replied else "",
            "msg_id": msg_id,
        }

    def _load_user_fields(self):
        """v4.9: Load configurable dropdown fields for the user-info dialog.
        Admin can edit user_fields.json (agent data dir) to add/remove/rename dropdowns.
        Each entry: {"key": "...", "label": "...", "options": ["..."]}.
        Default: a single 'Chi nhanh' (branch) dropdown."""
        import json as _json, os as _os
        default = [{"key": "branch", "label": "Chi nhanh",
                    "options": ["Tru so chinh", "Chi nhanh 1", "Chi nhanh 2"]}]
        try:
            data_dir = self._get_agent_data_dir()
            path = _os.path.join(data_dir, "user_fields.json")
            if _os.path.exists(path):
                with open(path, "r", encoding="utf-8-sig") as f:
                    data = _json.loads(f.read())
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
                    out.append({"key": key, "label": label,
                                "options": [str(o) for o in options]})
                if out:
                    return out
        except Exception:
            pass
        return default

    def _handle_reset_user_command(self, cmd):
        """Handle reset user info command from server.
        v2.5.1 REWRITE: Show warning → config dialog → save → restart COMPUTER (not agent).
        Task Scheduler will auto-start agent after reboot with new info."""
        exec_id = cmd.get("exec_id", f"reset_{int(time.time())}")
        print(f"[🔄] Reset user info command received (exec_id={exec_id})")

        try:
            import subprocess as _sp
            import tempfile as _tmp
            import ctypes as _ct

            _ct.windll.user32.MessageBoxW(0,
                "Yeu cau nhap lai thong tin nguoi su dung may tinh.\n\n"
                "LUU Y: May tinh se can phai khoi dong lai sau khi nhap thong tin.\n"
                "Xin hay luu lai tat ca tai lieu dang mo.",
                "GIAM-SAT Agent - Canh Bao", 0x30 | 0x1)

            saved_machine_id = self.machine_id
            saved_hostname = self.hostname
            print(f"  [*] Preserving machine_id={saved_machine_id} hostname={saved_hostname}")

            data_dir = self._get_agent_data_dir()
            for fname in ["user_info.json", "agent_config.json"]:
                path = os.path.join(data_dir, fname)
                try:
                    if os.path.exists(path):
                        os.remove(path)
                        print(f"  [✓] Deleted: {path}")
                except Exception:
                    pass

            ps_file = os.path.join(_tmp.gettempdir(), f"giamsat_reset_{os.getpid()}.ps1")
            result_file = os.path.join(_tmp.gettempdir(), f"giamsat_reset_result_{os.getpid()}.json")

            # v4.9: configurable user-info dropdown fields (admin-editable user_fields.json)
            import json as _json
            _extra_fields = self._load_user_fields()
            _fields_json = _json.dumps(_extra_fields, ensure_ascii=False).replace("'", "''")

            ps_script = '''
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$form = New-Object System.Windows.Forms.Form
$form.Text = "GIAM-SAT Agent - Cau Hinh Ket Noi"
$form.Size = New-Object System.Drawing.Size(420, 530)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = "FixedDialog"
$form.TopMost = $true
$form.BackColor = [System.Drawing.Color]::FromArgb(15,25,35)
$form.ForeColor = [System.Drawing.Color]::White

$lbl = New-Object System.Windows.Forms.Label
$lbl.Text = "GIAM-SAT Agent"
$lbl.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
$lbl.ForeColor = [System.Drawing.Color]::FromArgb(0,212,170)
$lbl.AutoSize = $true
$lbl.Location = New-Object System.Drawing.Point(50, 15)
$form.Controls.Add($lbl)

$lbl2 = New-Object System.Windows.Forms.Label
$lbl2.Text = "Cau hinh ket noi den may chu"
$lbl2.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$lbl2.ForeColor = [System.Drawing.Color]::FromArgb(200,216,232)
$lbl2.AutoSize = $true
$lbl2.Location = New-Object System.Drawing.Point(85, 42)
$form.Controls.Add($lbl2)

function Add-Label($text, $y) {
    $l = New-Object System.Windows.Forms.Label
    $l.Text = $text
    $l.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $l.ForeColor = [System.Drawing.Color]::FromArgb(200,216,232)
    $l.AutoSize = $true
    $l.Location = New-Object System.Drawing.Point(30, $y)
    $form.Controls.Add($l)
    return $y + 22
}
function Add-TextBox($text, $y, [int]$w=340) {
    $t = New-Object System.Windows.Forms.TextBox
    $t.Font = New-Object System.Drawing.Font("Segoe UI", 11)
    $t.BackColor = [System.Drawing.Color]::FromArgb(26,42,58)
    $t.ForeColor = [System.Drawing.Color]::FromArgb(238,244,248)
    $t.Text = $text
    $t.Location = New-Object System.Drawing.Point(30, $y)
    $t.Size = New-Object System.Drawing.Size($w, 26)
    $form.Controls.Add($t)
    return $t, ($y + 32)
}
function Add-ComboBox($labelText, $opts, $y) {
    $l = New-Object System.Windows.Forms.Label
    $l.Text = $labelText
    $l.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $l.ForeColor = [System.Drawing.Color]::FromArgb(200,216,232)
    $l.AutoSize = $true
    $l.Location = New-Object System.Drawing.Point(30, $y)
    $form.Controls.Add($l)
    $cb = New-Object System.Windows.Forms.ComboBox
    $cb.Font = New-Object System.Drawing.Font("Segoe UI", 11)
    $cb.BackColor = [System.Drawing.Color]::FromArgb(26,42,58)
    $cb.ForeColor = [System.Drawing.Color]::FromArgb(238,244,248)
    $cb.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $cb.Location = New-Object System.Drawing.Point(30, ($y + 20))
    $cb.Size = New-Object System.Drawing.Size(340, 26)
    foreach ($o in $opts) { [void]$cb.Items.Add([string]$o) }
    if ($cb.Items.Count -gt 0) { $cb.SelectedIndex = 0 }
    $form.Controls.Add($cb)
    return $cb, ($y + 52)
}

$y = 78
$txtHost = $null; $txtPort = $null; $txtName = $null; $txtID = $null; $txtEmail = $null
$y = Add-Label "Dia chi may chu (IP/Hostname):" $y
$txtHost, $y = Add-TextBox "''' + self.server_host + '''" $y
$y = Add-Label "Cong ket noi:" $y
$txtPort, $y = Add-TextBox "''' + str(self.server_port) + '''" $y 80
$y += 8
$y = Add-Label "THONG TIN NGUOI SU DUNG" $y
$y = Add-Label "Nguoi su dung:" $y
$txtName, $y = Add-TextBox "" $y
$y = Add-Label "Ma nhan su:" $y
$txtID, $y = Add-TextBox "" $y
$y = Add-Label "Email:" $y
$txtEmail, $y = Add-TextBox "" $y
$fields = @((''' + _fields_json + ''') | ConvertFrom-Json)
$comboControls = @{}
foreach ($f in $fields) {
    $opts = @()
    foreach ($o in $f.options) { $opts += [string]$o }
    $cb, $y = Add-ComboBox ([string]$f.label) $opts $y
    $comboControls[[string]$f.key] = $cb
}
$y += 12

$btnOk = New-Object System.Windows.Forms.Button
$btnOk.Text = "Ket noi"
$btnOk.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$btnOk.BackColor = [System.Drawing.Color]::FromArgb(26,58,42)
$btnOk.ForeColor = [System.Drawing.Color]::FromArgb(136,221,153)
$btnOk.FlatStyle = "Flat"
$btnOk.Location = New-Object System.Drawing.Point(200, $y)
$btnOk.Size = New-Object System.Drawing.Size(80, 30)
$btnOk.DialogResult = [System.Windows.Forms.DialogResult]::OK
$form.Controls.Add($btnOk)
$btnCancel = New-Object System.Windows.Forms.Button
$btnCancel.Text = "Huy"
$btnCancel.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$btnCancel.BackColor = [System.Drawing.Color]::FromArgb(58,26,26)
$btnCancel.ForeColor = [System.Drawing.Color]::FromArgb(255,136,136)
$btnCancel.FlatStyle = "Flat"
$btnCancel.Location = New-Object System.Drawing.Point(290, $y)
$btnCancel.Size = New-Object System.Drawing.Size(80, 30)
$btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$form.Controls.Add($btnCancel)
$form.AcceptButton = $btnOk
$txtHost.Focus()
$txtHost.SelectAll()

$dlgResult = $form.ShowDialog()
$data = @{}
if ($dlgResult -eq [System.Windows.Forms.DialogResult]::OK) {
    $data["host"] = $txtHost.Text.Trim()
    $data["port"] = $txtPort.Text.Trim()
    $data["user_name"] = $txtName.Text.Trim()
    $data["employee_id"] = $txtID.Text.Trim()
    $data["email"] = $txtEmail.Text.Trim()
    $extra = @{}
    foreach ($k in $comboControls.Keys) {
        $extra[$k] = $comboControls[$k].SelectedItem
    }
    $data["user_extra"] = $extra
    $data["branch"] = if ($comboControls.ContainsKey("branch")) { [string]$comboControls["branch"].SelectedItem } else { "" }
    $data["confirmed"] = $true
} else {
    $data["confirmed"] = $false
}
$data | ConvertTo-Json | Out-File -FilePath "''' + result_file.replace('\\', '\\\\') + '''" -Encoding UTF8 -Force
'''

            with open(ps_file, "w", encoding="utf-8") as f:
                f.write(ps_script)

            _sp.run(["cmd", "/c", "start", "/wait", "powershell", "-NoProfile",
                     "-ExecutionPolicy", "Bypass", "-WindowStyle", "Normal",
                     "-File", ps_file], timeout=300)

            user_name = ""
            employee_id = ""
            email = ""
            branch = ""
            user_extra = {}
            host = self.server_host
            port = self.server_port

            if os.path.exists(result_file):
                try:
                    with open(result_file, "r", encoding="utf-8-sig") as f:
                        data = json.loads(f.read())
                    os.remove(result_file)
                    if data.get("confirmed"):
                        host = data.get("host", self.server_host)
                        try:
                            port = int(data.get("port", self.server_port))
                        except ValueError:
                            port = self.server_port
                        user_name = data.get("user_name", "")
                        employee_id = data.get("employee_id", "")
                        email = data.get("email", "")
                        branch = data.get("branch", "")
                        user_extra = data.get("user_extra", {}) or {}
                except Exception:
                    pass
            try:
                os.remove(ps_file)
            except Exception:
                pass

            if user_name:
                cfg_path = os.path.join(data_dir, "agent_config.json")
                cfg = {}
                if os.path.exists(cfg_path):
                    try:
                        with open(cfg_path, "r") as f:
                            cfg = json.loads(f.read())
                    except Exception:
                        pass
                if not cfg.get("machine_id"):
                    cfg["machine_id"] = saved_machine_id
                if not cfg.get("hostname"):
                    cfg["hostname"] = saved_hostname
                cfg["machine_id"] = saved_machine_id
                cfg["hostname"] = saved_hostname
                self.machine_id = saved_machine_id
                self.hostname = saved_hostname
                cfg["server_host"] = host
                cfg["server_port"] = port
                cfg["user_name"] = user_name
                cfg["employee_id"] = employee_id
                cfg["email"] = email
                cfg["branch"] = branch
                cfg["user_extra"] = user_extra or {}
                self.branch = branch
                self.user_extra = user_extra or {}
                cfg["configured"] = True
                os.makedirs(os.path.dirname(cfg_path), exist_ok=True)
                with open(cfg_path, "w") as f:
                    json.dump(cfg, f, indent=2)

                ui_path = os.path.join(data_dir, "user_info.json")
                with open(ui_path, "w") as f:
                    json.dump({"user_name": user_name, "employee_id": employee_id, "email": email,
                               "branch": branch, "user_extra": user_extra or {}}, f, indent=2)

                rt_cfg_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
                try:
                    rt = {}
                    if os.path.exists(rt_cfg_path):
                        with open(rt_cfg_path, "r") as f:
                            rt = json.loads(f.read())
                    rt["server_host"] = host
                    rt["server_port"] = port
                    with open(rt_cfg_path, "w") as f:
                        json.dump(rt, f, indent=2)
                except Exception:
                    pass

                print(f"[✓] Config saved for user: {user_name}")

            resp = {
                "type": "response_result",
                "machine_id": self.machine_id,
                "hostname": self.hostname,
                "action": "reset_user",
                "exec_id": exec_id,
                "status": "completed",
                "output": f"User info updated: {user_name}. Restarting computer..."
                    if user_name else "User canceled or no info entered. Restarting anyway...",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            self._real_send(resp)
            print(f"[✓] Sent reset_user response to server")

            print(f"[*] Restarting computer in 20 seconds...")
            _sp.run(["shutdown", "/r", "/t", "20", "/c",
                     "GIAM-SAT: Khoi dong lai de ap dung thong tin nguoi dung moi."],
                    timeout=10)

        except Exception as e:
            print(f"[-] Reset user info failed: {e}")
            import traceback
            traceback.print_exc()
            resp = {
                "machine_id": self.machine_id, "hostname": self.hostname,
                "type": "response_result", "action": "reset_user",
                "exec_id": exec_id, "status": "error",
                "error": str(e)[:500],
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            self._real_send(resp)

    def _get_agent_data_dir(self):
        if os.name == "nt":
            programdata = os.environ.get("PROGRAMDATA", "C:\\ProgramData")
            return os.path.join(programdata, "GIAM-SAT", "Agent")
        else:
            return os.environ.get("GIAMSAT_DATA_DIR", os.path.join(os.path.expanduser("~"), ".giamsat", "agent"))

    def _execute_and_report(self, cmd):
        """v3.9.13: Execute command from TCP, with dedup against HTTP poll."""
        exec_id = cmd.get("exec_id") or cmd.get("msg_id") or ""
        if self._is_duplicate(exec_id):
            print(f"[DEDUP] TCP skipping already processed: {cmd.get('action')} ({exec_id})")
            return
        result = self.responder.execute_command(cmd)
        result["machine_id"] = self.machine_id; result["hostname"] = self.hostname
        result["action"] = cmd.get("action", "")
        result["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._real_send(result)

    def _handle_agent_update_command(self, cmd):
        server_version = cmd.get("version", "")
        exec_id = cmd.get("exec_id", f"update_{int(time.time())}")
        print(f"[🔄] Agent update command received: version {server_version}")
        response = None

        # v4.13 FIX: use the unified IPC client with http_fallback=True so the
        # HTTP path carries X-Updater-Token (sha256(command_key + ':updater')).
        # The previous raw HTTP fallback omitted the token, so the v4.10+
        # updater (fail-closed) rejected it with HTTP 401 Unauthorized.
        if _HAS_NAMED_PIPE_IPC:
            try:
                ipc = UpdaterIPCClient(http_fallback=True)
                response = ipc.send({"action": "update", "version": server_version, "exec_id": exec_id})
            except Exception as e:
                print(f"[-] Updater IPC error: {e}")
                response = None

        if response and response.get("status") == "accepted":
            print("[✓] Forwarded to Updater via IPC (pipe or HTTP)")
            self._report_update_to_server(AGENT_VERSION, server_version, "accepted",
                "Forwarded to Updater daemon", "push")
            return

        # Final fallback: raw HTTP only when the IPC client module is unavailable.
        # Send the same X-Updater-Token the FallbackHttpClient would send.
        if not _HAS_NAMED_PIPE_IPC:
            try:
                import urllib.request as urlreq
                import hashlib as _hashlib
                _tok = ""
                try:
                    _cfg_path = os.path.join(os.environ.get("PROGRAMDATA", r"C:\ProgramData"),
                                             "GIAM-SAT", "Agent", "agent_config.json")
                    if os.path.exists(_cfg_path):
                        with open(_cfg_path, "r", encoding="utf-8") as _f:
                            _key = (json.load(_f).get("command_key") or "").strip()
                        if _key:
                            _tok = _hashlib.sha256((_key + ":updater").encode()).hexdigest()
                except Exception:
                    pass
                _hdr = {"Content-Type": "application/json"}
                if _tok:
                    _hdr["X-Updater-Token"] = _tok
                req = urlreq.Request(
                    "http://127.0.0.1:5999/update",
                    data=json.dumps({"version": server_version, "exec_id": exec_id}).encode(),
                    headers=_hdr)
                resp = urlreq.urlopen(req, timeout=5)
                print(f"[✓] Forwarded to Updater via HTTP: {resp.read().decode()}")
                self._report_update_to_server(AGENT_VERSION, server_version, "accepted",
                    "Forwarded to Updater daemon via HTTP", "push")
                return
            except Exception as e:
                print(f"[-] Updater unreachable (pipe + HTTP): {e}")

        err = (response or {}).get("error", "updater not reachable") if response else "updater not reachable"
        print(f"[-] Updater unreachable (pipe + HTTP): {err}")
        result = {
            "machine_id": self.machine_id, "hostname": self.hostname,
            "type": "response_result", "action": "agent_update",
            "exec_id": exec_id, "status": "error",
            "error": f"Updater unreachable: {str(err)[:300]}",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        self._real_send(result)

    def _auto_update_check_loop(self):
        while self.running:
            time.sleep(900)
            if self.connected:
                try:
                    self._check_for_update()
                except Exception as e:
                    print(f"[-] Auto-update check failed: {e}")

    def _check_for_update(self):
        try:
            import urllib.request as urlreq
            server_host = self.server_host
            server_web_port = 5000
            url = f"{_web_base(server_host, server_web_port, self.config)}/api/agent/version"
            req = urlreq.Request(url, method="POST",
                data=json.dumps({"version": AGENT_VERSION, "psk": self.config.get("psk", "")}).encode("utf-8"),
                headers={"Content-Type": "application/json"})
            resp = _web_open(req, 15, self.config)
            data = json.loads(resp.read().decode("utf-8"))
            if data.get("update_available"):
                server_version = data.get("server_version", "?")
                print(f"[🔄] New agent version available: {AGENT_VERSION} -> {server_version}")
                self._download_and_apply_update(server_version, f"auto_{int(time.time())}", source="auto")
        except Exception as e:
            print(f"[-] Auto-update check error: {e}")

    def _download_and_apply_update(self, server_version, exec_id, source="auto"):
        import urllib.request as urlreq
        import tempfile
        import subprocess
        import sys
        import re as _re
        # v4.5.5 SECURITY: sanitize server_version (unsigned/attacker-controlled input)
        # to prevent path traversal + shell injection via the update .bat script.
        server_version = _re.sub(r"[^A-Za-z0-9._-]", "", str(server_version))[:64]
        if not server_version:
            server_version = "unknown"
        import glob as _glob

        server_host = self.server_host
        server_web_port = 5000

        try:
            # v3.9.6: Cleanup old temp GiamSatAgent_*.exe files before downloading new one
            temp_dir = tempfile.gettempdir()
            try:
                for old_exe in _glob.glob(os.path.join(temp_dir, "GiamSatAgent_*.exe")):
                    try:
                        os.remove(old_exe)
                        print(f"[*] Cleaned old temp: {os.path.basename(old_exe)}")
                    except Exception:
                        pass
            except Exception:
                pass

            # v4.11 (LOW): machine_id moved out of the URL (it leaked into
            # proxy/access logs); sent via X-Machine-ID header instead.
            download_url = f"{_web_base(server_host, server_web_port, self.config)}/api/agent/download?token=auto"
            print(f"[📥] Downloading agent update from {server_host}:{server_web_port}/api/agent/download...")

            new_exe_path = os.path.join(temp_dir, f"GiamSatAgent_{server_version}.exe")

            # v4.10 (CRITICAL-4): PSK via header, NOT query string (avoids leaking psk in URL/logs)
            req = urlreq.Request(download_url, headers={
                "X-Agent-PSK": self.config.get('psk', ''),
                "X-Machine-ID": str(self.machine_id or ""),
            })
            resp = _web_open(req, 120, self.config)
            total_size = int(resp.headers.get("Content-Length", 0))
            expected_sha = (resp.headers.get("X-File-SHA256") or "").strip().lower()
            expected_sig = (resp.headers.get("X-File-Sig") or "").strip().lower()

            # v3.9.6: Validate minimum size (agent .exe must be >= 20MB)
            if total_size > 0 and total_size < 20 * 1024 * 1024:
                return {
                    "status": "error",
                    "error": f"Server file too small ({total_size} bytes), likely corrupt or not ready",
                    "output": f"Content-Length: {total_size} bytes"
                }

            downloaded = 0
            with open(new_exe_path, "wb") as f:
                while True:
                    chunk = resp.read(8192)
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total_size > 0 and downloaded % (1024 * 1024) < 8192:
                        pct = int(downloaded / total_size * 100) if total_size > 0 else 0
                        print(f"  Downloaded: {downloaded // 1024}KB / {total_size // 1024}KB ({pct}%)")

            print(f"[✓] Downloaded {downloaded // 1024}KB to {new_exe_path}")

            # v3.9.6: Validate minimum size (must be >= 20MB for real agent .exe)
            if downloaded < 20 * 1024 * 1024:
                try:
                    os.remove(new_exe_path)
                except Exception:
                    pass
                return {
                    "status": "error",
                    "error": f"Downloaded file too small ({downloaded} bytes), agent must be >= 20MB",
                    "output": f"Download size: {downloaded} bytes"
                }

            # v4.10 (CRITICAL-1): SHA-256 is MANDATORY and signed by the server
            # with HMAC-SHA256(command_key). v4.11 FIX: the signature itself is
            # also mandatory (fail-closed) - a MITM stripping X-File-Sig must not
            # turn the download into an unsigned one that would be accepted.
            if not expected_sha:
                try:
                    os.remove(new_exe_path)
                except Exception:
                    pass
                return {"status": "error", "error": "Server did not provide X-File-SHA256 - update rejected (fail-closed)", "output": ""}
            if not expected_sig:
                try:
                    os.remove(new_exe_path)
                except Exception:
                    pass
                return {"status": "error", "error": "Server did not provide X-File-Sig - update rejected (fail-closed)", "output": ""}
            signing_key = os.environ.get("GIAMSAT_COMMAND_KEY", "") or self.config.get("command_key", "")
            if not signing_key:
                try:
                    os.remove(new_exe_path)
                except Exception:
                    pass
                return {"status": "error", "error": "No command_key configured - cannot verify update signature (fail-closed)", "output": ""}
            import hmac as _hmac
            import hashlib as _hashlib
            calc_sig = _hmac.new(str(signing_key).encode("utf-8"), expected_sha.encode("utf-8"), _hashlib.sha256).hexdigest()
            if not _hmac.compare_digest(calc_sig, expected_sig):
                try:
                    os.remove(new_exe_path)
                except Exception:
                    pass
                return {"status": "error", "error": "Update file signature invalid (possible tampering)", "output": ""}
            import hashlib as _hashlib
            _h = _hashlib.sha256()
            with open(new_exe_path, "rb") as _f:
                for _chunk in iter(lambda: _f.read(65536), b""):
                    _h.update(_chunk)
            if _h.hexdigest().lower() != expected_sha:
                try:
                    os.remove(new_exe_path)
                except Exception:
                    pass
                return {"status": "error", "error": "Downloaded EXE hash mismatch (possible tampering)", "output": ""}
            print("[+] Update EXE hash verified OK")

            current_exe = sys.executable
            if not getattr(sys, 'frozen', False):
                return {
                    "status": "error",
                    "error": "Agent running as Python script, cannot auto-update.",
                    "output": f"Current: {current_exe}"
                }

            # v3.9.7: _MEI* cleanup was added to the update script to prevent runtime
            # dir bloat - but `rd /s /q runtime\_MEI*` DELETED the extraction dir of
            # an agent that was still starting (watchdog respawn / second instance),
            # causing 'Failed to load Python DLL ..._MEIxxxx\python311.dll' popups.
            # v5.0.4 FIX: the .bat never touches _MEI dirs (the updater's
            # _cleanup_runtime_mei handles abandoned dirs safely with an in-use probe).
            mei_cleanup = ""
            
            # v4.10 (CRIT-4): write the batch with an unpredictable mkstemp name and
            # sanitize server_host/port before interpolating into the .bat.
            import re as _re2
            import tempfile as _tf
            server_host_safe = _re2.sub(r"[^A-Za-z0-9._\-]", "", str(self.server_host))[:255]
            port_safe = _re2.sub(r"[^0-9]", "", str(self.server_port))[:10] or "6666"
            install_dir_safe = os.path.dirname(os.path.abspath(current_exe))
            _fd, update_script = _tf.mkstemp(suffix=".bat", prefix="giamsat_update_")
            os.close(_fd)
            with open(update_script, "w") as f:
                # v5.0.4 (HIGH-1): staged copy (never boot a half-written exe),
                # write agent_version.txt so the version converges, respect the
                # shared update.lock (no race with updater.exe).
                f.write(f'''@echo off
setlocal enabledelayedexpansion
echo GIAM-SAT Agent Update Script
if exist "{install_dir_safe}\\update.lock" (echo Another update in progress - skip & exit /b 0)
type nul > "{install_dir_safe}\\update.lock"
echo Stopping agent...
sc stop GiamSatAgent >nul 2>&1
timeout /t 3 /nobreak >nul
taskkill /F /IM GiamSatAgent.exe >nul 2>&1
timeout /t 3 /nobreak >nul
{mei_cleanup}echo Copying new version (staged)...
copy /Y "{new_exe_path}" "{current_exe}.new" >nul 2>&1
if !errorlevel! equ 0 (
    move /Y "{current_exe}.new" "{current_exe}" >nul 2>&1
)
if !errorlevel! equ 0 (
    echo {server_version}> "{install_dir_safe}\\agent_version.txt"
    echo Update successful! Starting agent...
    sc start GiamSatAgent >nul 2>&1
    if !errorlevel! neq 0 start "" "{current_exe}" --server {server_host_safe} --port {port_safe}
) else (
    echo Update failed! Could not copy file.
    del "{current_exe}.new" >nul 2>&1
    sc start GiamSatAgent >nul 2>&1
    if !errorlevel! neq 0 start "" "{current_exe}" --server {server_host_safe} --port {port_safe}
)
del "{install_dir_safe}\\update.lock" >nul 2>&1
del "%~f0"
''')

            subprocess.Popen(["cmd", "/c", update_script])

            print(f"[✓] Update script started via service (sc stop/start). Agent will restart with version {server_version}.")

            self._report_update_to_server(AGENT_VERSION, server_version, "success",
                f"Updated to {server_version}, restarting via service...", source)

            self.running = False

            return {
                "status": "success",
                "output": f"Updated to version {server_version}, restarting via service...",
                "error": ""
            }

        except Exception as e:
            return {
                "status": "error",
                "error": f"Update failed: {str(e)[:500]}",
                "output": str(e)[:200]
            }

    def _report_update_to_server(self, from_version, to_version, status, message, source):
        try:
            import urllib.request as urlreq
            server_web_port = 5000
            url = f"{_web_base(self.server_host, server_web_port, self.config)}/api/agent/update-report"
            data = json.dumps({
                "machine_id": self.machine_id,
                "hostname": self.hostname,
                "psk": self.config.get("psk", ""),
                "from_version": from_version,
                "to_version": to_version,
                "status": status,
                "message": message,
                "source": source
            }).encode("utf-8")
            req = urlreq.Request(url, data=data, headers={"Content-Type": "application/json"})
            urlreq.urlopen(req, timeout=10)
        except Exception as e:
            print(f"[-] Failed to report update to server: {e}")

    # ================ v3.9.8: HEARTBEAT (120s + system metrics) ================
    def _heartbeat_loop(self):
        """v3.9.8: 120s interval. TCP heartbeat with system metrics.
        HTTP polling is now a SEPARATE independent loop (_http_poll_loop).
        This separation is critical for unstable connections (Tailscale/VPN)
        where TCP drops frequently - heartbeat must not block HTTP poll."""
        _has_psutil = True
        try:
            import psutil as _psu
            _psu.cpu_percent(interval=0)
        except ImportError:
            _has_psutil = False
            _psu = None
        while self.running:
            time.sleep(120)
            if not self.connected:
                continue
            hb = {"type": "heartbeat", "version": AGENT_VERSION}
            try:
                if _has_psutil:
                    hb["cpu_percent"] = round(_psu.cpu_percent(interval=0.1), 1)
                    hb["boot_time"] = int(_psu.boot_time())  # OS boot time (Unix epoch) for exact uptime
                    mem = _psu.virtual_memory()
                    hb["ram_used_mb"] = round(mem.used / (1024 * 1024), 1)
                    hb["ram_total_mb"] = round(mem.total / (1024 * 1024), 1)
                    disk = _psu.disk_usage("C:\\" if os.name == "nt" else "/")
                    hb["disk_free_gb"] = round(disk.free / (1024 ** 3), 1)
                    net = _psu.net_io_counters()
                    hb["net_bytes_sent"] = net.bytes_sent
                    hb["net_bytes_recv"] = net.bytes_recv
            except Exception:
                pass
            self._real_send(hb)

    # ================ v3.9.8: HTTP POLL LOOP (Independent, 30s interval) ================
    def _http_poll_loop(self):
        """v3.9.8: INDEPENDENT HTTP poll loop. Runs every 30s regardless of TCP state.
        Critical for Tailscale VPN where TCP connections drop frequently.
        Does NOT depend on self.connected - HTTP finds its own route to server."""
        import urllib.request as urlreq
        import urllib.error as urlerr

        server_web_port = 5000
        url = f"{_web_base(self.server_host, server_web_port, self.config)}/api/agent/heartbeat"

        while self.running:
            time.sleep(30)  # Poll every 30s independently
            try:
                req_data = json.dumps({
                    "machine_id": self.machine_id,
                    "hostname": self.hostname,
                    "psk": self.config.get("psk", ""),
                    "version": AGENT_VERSION,
                }).encode("utf-8")
                req = urlreq.Request(url, data=req_data,
                                      headers={"Content-Type": "application/json"})
                resp = urlreq.urlopen(req, timeout=10)
                resp_data = json.loads(resp.read().decode("utf-8"))
                pending = resp_data.get("pending", [])

                if pending:
                    print(f"[📥] HTTP poll: received {len(pending)} pending command(s)")
                    for cmd in pending:
                        # v4.10 (CRITICAL-2): verify command signature BEFORE executing
                        # (same fail-closed path as the TCP command handler).
                        if not self._verify_command_signature(cmd):
                            print(f"[!] Command rejected (signature) via HTTP poll: {cmd.get('action', '?')}")
                            continue
                        try:
                            cmd_str = cmd.get("command", "{}")
                            cmd_data = json.loads(cmd_str) if cmd_str else {}
                            # command field is just params; action comes from outer cmd
                            cmd_data["action"] = cmd.get("action", "")
                        except Exception:
                            cmd_data = {"action": cmd.get("action", "")}

                        cmd_data["exec_id"] = cmd.get("exec_id", "")
                        cmd_data["machine_id"] = self.machine_id
                        cmd_data["hostname"] = self.hostname

                        # Execute in background thread
                        threading.Thread(
                            target=self._execute_polled_command,
                            args=(cmd_data, cmd.get("exec_id", ""), cmd.get("action", "")),
                            daemon=True
                        ).start()
            except urlerr.URLError as e:
                pass  # Silently retry - this is expected on unstable connections
            except Exception as e:
                print(f"[-] HTTP poll error: {e}")

    def _is_duplicate(self, exec_id):
        """v3.9.13: Check if exec_id was already processed. Thread-safe dedup."""
        if not exec_id:
            return False
        with self._processed_execs_lock:
            if exec_id in self._processed_execs:
                return True
            self._processed_execs.add(exec_id)
            if len(self._processed_execs) > self._processed_execs_max:
                self._processed_execs = set(list(self._processed_execs)[-1000:])
        return False

    def _execute_polled_command(self, cmd_data, exec_id, action):
        """v3.9.13: Execute a command received via HTTP poll and report result.
        Dedup: skip if already processed (delivered via TCP first)."""
        if self._is_duplicate(exec_id):
            print(f"[DEDUP] Skipping already processed: {action} ({exec_id})")
            return
        try:
            result = self._execute_command_locally(cmd_data)
            self._report_command_result(exec_id=exec_id, action=action, result=result)
        except Exception as e:
            print(f"[-] Execute polled command failed: {e}")

    def _execute_command_locally(self, cmd_data):
        """v3.9.7: Execute a command received via HTTP polling.
        Returns dict with status, output, error, exit_code."""
        action = cmd_data.get("action", "")

        # Handle show_message command
        if action == "show_message":
            return self._handle_show_message(cmd_data)

        # Handle response actions (kill_process, firewall_block, etc.)
        if action in ("kill_process", "firewall_block", "firewall_unblock",
                       "disable_account", "quarantine_file", "restore_file",
                       "isolate_network", "restore_network", "forensic_snapshot",
                       "dump_memory"):
            try:
                params = cmd_data.get("params", {})
                if not params:
                    reserved = {"action", "exec_id", "machine_id", "hostname"}
                    params = {k: v for k, v in cmd_data.items() if k not in reserved}
                result = self.responder.execute_command({"action": action, "params": params})
                return {
                    "status": "completed" if result.get("status") == "completed" else "failed",
                    "output": result.get("output", "")[:5000],
                    "error": result.get("error", "")[:2000],
                    "exit_code": result.get("exit_code", 0),
                }
            except Exception as e:
                return {"status": "failed", "error": str(e)[:2000], "output": "", "exit_code": -1}

        # Handle policy commands (apply_block_port, apply_block_website, etc.)
        if action.startswith(("apply_", "remove_")):
            try:
                params = {}
                if cmd_data.get("command"):
                    try:
                        params = json.loads(cmd_data.get("command", "{}"))
                    except Exception:
                        pass
                result = self.responder.execute_command({"action": action, "command": cmd_data.get("command", ""), "params": params})
                return {
                    "status": "completed" if result.get("status") == "completed" else "failed",
                    "output": result.get("output", "")[:5000],
                    "error": result.get("error", "")[:2000],
                    "exit_code": result.get("exit_code", 0),
                }
            except Exception as e:
                return {"status": "failed", "error": str(e)[:2000], "output": "", "exit_code": -1}

        # v4.10: fallback - let the responder try (ps, get_processes, get_services,
        # get_connections, get_scheduled_tasks, get_startup_programs, restart_computer,
        # shutdown_computer, lock_account, kill_tree, ...) so HTTP-poll delivery
        # supports the same actions as TCP push.
        try:
            params = cmd_data.get("params", {})
            if not params:
                reserved = {"action", "exec_id", "machine_id", "hostname"}
                params = {k: v for k, v in cmd_data.items() if k not in reserved}
            result = self.responder.execute_command({
                "action": action,
                "params": params,
                "command": cmd_data.get("command", ""),
            })
            return {
                "status": "completed" if result.get("status") == "completed" else "failed",
                "output": result.get("output", "")[:5000],
                "error": result.get("error", "")[:2000],
                "exit_code": result.get("exit_code", 0),
            }
        except Exception as e:
            return {"status": "failed", "error": str(e)[:2000], "output": "", "exit_code": -1}

    def _report_command_result(self, exec_id, action, result):
        """v3.9.7: Report command execution result back to server via HTTP."""
        import urllib.request as urlreq
        import urllib.error as urlerr

        if not exec_id:
            return

        server_web_port = 5000
        url = f"{_web_base(self.server_host, server_web_port, self.config)}/api/agent/command-result"

        try:
            report = {
                "machine_id": self.machine_id,
                "hostname": self.hostname,
                "exec_id": exec_id,
                "action": action,
                "status": result.get("status", "completed"),
                "output": result.get("output", "")[:5000],
                "error": result.get("error", "")[:2000],
                "exit_code": result.get("exit_code", 0),
                "msg_replied": result.get("msg_replied", False),
                "msg_reply": result.get("msg_reply", ""),
                "msg_id": result.get("msg_id", ""),
            }
            report["psk"] = self.config.get("psk", "")
            req_data = json.dumps(report).encode("utf-8")
            req = urlreq.Request(url, data=req_data,
                                  headers={"Content-Type": "application/json"})
            _web_open(req, 15, self.config)
            print(f"[✓] Reported result: {action} (exec_id={exec_id}) = {result.get('status')}")
        except Exception as e:
            print(f"[-] Failed to report result for {exec_id}: {e}")

    def _vuln_scan_loop(self):
        time.sleep(30)
        if self.connected:
            try:
                results = self.vuln_scanner.run_scan()
                if results:
                    print(f"[*] Initial vuln scan: {len(results)} issues")
            except Exception: pass
        while self.running:
            time.sleep(3600)
            if self.connected:
                try:
                    results = self.vuln_scanner.run_scan()
                    if results:
                        print(f"[*] Vuln scan: {len(results)} issues")
                except Exception: pass

    def _yara_scan_loop(self):
        time.sleep(60)
        if self.connected:
            try:
                results = self.yara_scanner.run_scan()
                if results: print(f"[*] YARA scan: found {len(results)} suspicious files")
            except Exception: pass
        while self.running:
            time.sleep(86400)
            if self.connected:
                try:
                    results = self.yara_scanner.run_scan()
                    if results: print(f"[*] YARA scan: found {len(results)} suspicious files")
                except Exception: pass

    def _sca_scan_loop(self):
        if not self.sca_scanner:
            print("[SCA] Scanner not available (yaml support missing)")
            return
        time.sleep(120)
        while self.running:
            if self.connected:
                try:
                    print("[SCA] Starting scan...")
                    results = self.sca_scanner.run_scan()
                    if results:
                        fails = sum(1 for r in results if r.get("status") in ("FAIL", "WARN"))
                        passes = sum(1 for r in results if r.get("status") == "PASS")
                        print(f"[SCA] Scan complete: {len(results)} checks ({passes} pass, {fails} issues)")
                        # Send all findings via callback (already sent individually during run_scan)
                        # But also send a summary/sca_scan_complete event for dashboard tracking
                        summary = {
                            "type": "sca_event",
                            "check_id": "SCA-SCAN-COMPLETE",
                            "title": "SCA Scan Complete",
                            "status": "INFO",
                            "severity": "LOW",
                            "description": f"Scan complete: {len(results)} checks, {passes} pass, {fails} issues",
                            "remediation": "",
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        }
                        self._real_send(summary)
                    else:
                        print("[SCA] Scan returned no results")
                except Exception as e:
                    print(f"[SCA] Scan error: {e}")
            time.sleep(86400)

    # ================ v3.9.3: VLAN/SUBNET MAPPING + TRIGGERED PCAP ================

    def _load_vlan_config(self):
        """Load VLAN/subnet mapping and PCAP config from vlan_config.json."""
        cfg_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vlan_config.json")
        try:
            if os.path.exists(cfg_path):
                with open(cfg_path, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                # Parse subnets: "10.0.1.0/24" -> (ip_to_int("10.0.1.0"), 24)
                for name, cidr in cfg.get("subnets", {}).items():
                    parts = cidr.split("/")
                    if len(parts) == 2:
                        net = parts[0]
                        mask = int(parts[1])
                        net_int = self._ip_to_int(net)
                        self._vlan_subnets[name] = (net_int, mask)
                # Load PCAP config
                pcap = cfg.get("pcap", {})
                self._pcap_config = {
                    "enabled": pcap.get("enabled", False),
                    "snap_len": pcap.get("snap_len", 256),
                    "count": pcap.get("count", 5),
                    "timeout_sec": pcap.get("timeout_sec", 3),
                    "capture_ports": set(pcap.get("capture_ports", [])),
                }
                if self._vlan_subnets:
                    print(f"[VLAN] Loaded {len(self._vlan_subnets)} subnet mappings: {list(self._vlan_subnets.keys())}")
                if self._pcap_config["enabled"]:
                    print(f"[PCAP] Triggered capture enabled for ports: {sorted(self._pcap_config['capture_ports'])}")
        except Exception as e:
            print(f"[-] Failed to load VLAN config: {e}")

    @staticmethod
    def _ip_to_int(ip):
        """Convert IPv4 string to 32-bit integer."""
        parts = ip.split(".")
        return (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])

    def _resolve_subnet(self, ip):
        """Map an IP to its VLAN/subnet name. Returns 'UNKNOWN' if no match."""
        try:
            ip_int = self._ip_to_int(ip)
            for name, (net_int, mask) in self._vlan_subnets.items():
                # Check if (ip_int >> (32 - mask)) == (net_int >> (32 - mask))
                if (ip_int >> (32 - mask)) == (net_int >> (32 - mask)):
                    return name
        except Exception:
            pass
        return "UNKNOWN"

    def _capture_suspicious_payload(self, src_ip, dst_ip, dst_port):
        """v3.9.3: Lightweight packet capture for lateral movement ports.
        Uses scapy if available, returns hex dump of first N packets.
        Thread-safe, non-blocking (runs in background thread)."""
        if not self._pcap_config["enabled"]:
            return None
        if dst_port not in self._pcap_config["capture_ports"]:
            return None
        try:
            from scapy.all import sniff as _scapy_sniff
            from scapy.all import IP, TCP, Raw
        except ImportError:
            return None  # Scapy not available
        results = []
        def _capture():
            try:
                bpf = f"host {dst_ip} and port {dst_port}"
                packets = _scapy_sniff(
                    filter=bpf, count=self._pcap_config["count"],
                    timeout=self._pcap_config["timeout_sec"], quiet=True
                )
                for pkt in packets:
                    payload = bytes(pkt[Raw].load) if Raw in pkt else bytes(pkt[TCP].payload) if TCP in pkt else b""
                    results.append(payload[:self._pcap_config["snap_len"]].hex())
            except Exception:
                pass
        t = threading.Thread(target=_capture, daemon=True)
        t.start()
        t.join(timeout=self._pcap_config["timeout_sec"] + 1)
        return "|".join(results) if results else None

    # ================ v4.0: SOC APPROVAL GATE ================
    
    def _request_approval_or_execute(self, rule_id, action, alert_data, desc="", params=None):
        """
        v4.0: Safety Gate for auto-response actions.
        Checks auto-response config: "off" = no action, "auto" = execute immediately,
        "confirm" = send approval request to server (Telegram/Dashboard).
        Default: "off" (safest).
        """
        import urllib.request as _urlreq
        import urllib.error as _urlerr
        
        # Read auto-response config
        auto_cfg = {}
        try:
            auto_cfg = self.config.get("auto_response") or {}
        except Exception:
            pass
        
        mode = auto_cfg.get("mode", "off")
        require_confidence = auto_cfg.get("require_confidence", 90)
        safe_users = auto_cfg.get("safe_users", ["admin", "administrator"])
        safe_machines = auto_cfg.get("safe_machines", [])
        confidence = alert_data.get("confidence_score", 0)
        
        # Check safe lists
        if self.hostname.lower() in [m.lower() for m in safe_machines]:
            print(f"[SAFETY GATE] Machine {self.hostname} is in safe list — skipping {action}")
            return
        if self.user_name.lower() in [u.lower() for u in safe_users]:
            print(f"[SAFETY GATE] User {self.user_name} is in safe list — skipping {action}")
            return
        
        # Check confidence threshold
        if confidence < require_confidence:
            print(f"[SAFETY GATE] Confidence {confidence}% < {require_confidence}% — skipping {action}")
            return
        
        if mode == "off":
            print(f"[SAFETY GATE] Mode=off — skipping {action}")
            return
        
        if mode == "auto":
            print(f"[!] AUTO mode: Executing {action} immediately")
            try:
                cmd = {"action": action}
                if params:
                    cmd["params"] = params
                self.responder.execute_command(cmd)
                alert_data["auto_response"] = "executed_auto"
            except Exception as e:
                print(f"[-] Auto execution failed: {e}")
            return
        
        # mode == "confirm": Send approval request to server
        print(f"[SOC APPROVAL] Requesting SOC approval for: {action} on {self.hostname}")
        try:
            server_web_port = 5000
            pending_url = f"{_web_base(self.server_host, server_web_port, self.config)}/api/alert/add-pending"
            req_data = json.dumps({
                "machine_id": self.machine_id,
                "hostname": self.hostname,
                "psk": self.config.get("psk", ""),
                "action": action,
                "rule_id": rule_id,
                "description": desc,
                "confidence_score": confidence,
                "params": params or {},
            }).encode("utf-8")
            req = _urlreq.Request(pending_url, data=req_data,
                                   headers={"Content-Type": "application/json"})
            _urlreq.urlopen(req, timeout=10)
            print(f"[SOC APPROVAL] Approval request sent to server")
            alert_data["auto_response"] = "pending_approval"
        except _urlerr.URLError:
            print(f"[-] Cannot reach server for SOC approval — skipping {action}")
        except Exception as e:
            print(f"[-] Approval request failed: {e}")

    # ================ v3.9.0: NETWORK 3-TIER AGGREGATION ================

    def _is_internal_suspicious(self, src_ip, dst_ip, dst_port, process_name):
        """Check if an internal connection should be sent as real-time alert.
        Tier 2: New/unusual internal connections → lateral movement detection.
        Returns (is_suspicious: bool, reason: str)."""
        # Always suspicious: lateral movement ports
        if dst_port in self._SUS_INTERNAL_PORTS:
            return True, f"suspicious_port:{dst_port}"

        # Check baseline: is this dst_ip:port new?
        key = f"{dst_ip}:{dst_port}"
        with self._baseline_lock:
            if self._BL_LEARNING:
                # First 24h: build baseline silently
                self._internal_baseline[key] = self._internal_baseline.get(key, 0) + 1
                return False, ""
            else:
                count = self._internal_baseline.get(key, 0)
                if count == 0:
                    # New destination never seen before
                    return True, f"new_dst:{dst_ip}:{dst_port}"
                # Common destinations (>100 seen) are not suspicious
                return False, ""

    def _classify_and_queue_network(self, net_data):
        """v3.9.0: 3-tier network traffic classification.
        Tier 1: Internal common traffic → aggregate into 60s buckets.
        Tier 2: Internal suspicious (new dest/lateral movement ports) → real-time alert.
        Tier 3: External traffic → aggregate 60s + send.

        Also handles DNS dedup (300s for same domain from DNS processes)."""
        src_ip = net_data.get("src_ip", "")
        dst_ip = net_data.get("dst_ip", "")
        dst_port = net_data.get("dst_port", 0)
        process_name = net_data.get("process_name", "").lower()
        process_path = net_data.get("process_path", "").lower()

        # Skip loopback
        if src_ip in ("127.0.0.1", "::1") or dst_ip in ("127.0.0.1", "::1"):
            return

        src_private = _is_private_ip(src_ip)
        dst_private = _is_private_ip(dst_ip)

        # DNS dedup (port 53) for common DNS processes
        if dst_port == 53 and any(p in process_name for p in self._DNS_PROCESSES):
            key = f"dns:{dst_ip}"
            with self._net_agg_lock:
                existing = self._net_agg.get(key)
                if existing:
                    existing["count"] += 1
                    existing["last_seen"] = time.time()
                    return
            # First DNS query in 300s → send as real-time
            self._real_send(net_data)
            with self._net_agg_lock:
                self._net_agg[key] = {"data": net_data, "count": 1, "first_seen": time.time(), "last_seen": time.time()}
            return

        # Both internal → Tier 1 (aggregate) or Tier 2 (real-time suspicious)
        if src_private and dst_private:
            is_sus, reason = self._is_internal_suspicious(src_ip, dst_ip, dst_port, process_name)
            if is_sus:
                # Tier 2: Real-time alert for lateral movement
                net_data["tier"] = "internal_suspicious"
                net_data["suspicious_reason"] = reason
                # v3.9.3: VLAN/Subnet mapping for lateral movement visibility
                if self._vlan_subnets:
                    net_data["src_subnet"] = self._resolve_subnet(src_ip)
                    net_data["dst_subnet"] = self._resolve_subnet(dst_ip)
                # v3.9.3: Triggered PCAP for suspicious ports
                payload_hex = self._capture_suspicious_payload(src_ip, dst_ip, dst_port)
                if payload_hex:
                    net_data["payload_hex"] = payload_hex[:1024]  # Cap at ~1KB hex
                    net_data["payload_size"] = len(bytes.fromhex(payload_hex.replace("|", "")))
                self._real_send(net_data)
                return
            else:
                # Tier 1: Aggregate internal common traffic (v3.9.3: aggregate-only, no first-occurrence)
                agg_key = f"int:{dst_ip}:{dst_port}"
                with self._net_agg_lock:
                    existing = self._net_agg.get(agg_key)
                    if existing:
                        existing["count"] += 1
                        existing["last_seen"] = time.time()
                    else:
                        self._net_agg[agg_key] = {"data": net_data, "count": 1, "first_seen": time.time(), "last_seen": time.time()}
                return

        # External traffic (Tier 3): aggregate by dst_ip (v3.9.6: web ports 80+443 grouped, non-web ports preserved)
        if dst_port in (80, 443):
            agg_key = f"ext:{dst_ip}:web"   # Group all web traffic by IP only
        else:
            agg_key = f"ext:{dst_ip}:{dst_port}"  # Non-web: keep port detail for C2/tunneling detection
        with self._net_agg_lock:
            existing = self._net_agg.get(agg_key)
            if existing:
                existing["count"] += 1
                existing["last_seen"] = time.time()
            else:
                self._net_agg[agg_key] = {"data": net_data, "count": 1, "first_seen": time.time(), "last_seen": time.time()}
        return

    def _net_agg_flush_loop(self):
        """v3.9.3: Flush aggregated counts every 60s.
        Only sends entries with count > 0 (active connections).
        Cleans up stale entries >300s to prevent unbounded growth."""
        while self.running:
            time.sleep(self._net_agg_interval)
            with self._net_agg_lock:
                if not self._net_agg:
                    continue
                items = list(self._net_agg.items())
            now = time.time()
            sent_count = 0
            for agg_key, item in items:
                if item["count"] == 0:
                    continue  # v3.9.3: Skip inactive connections
                agg_data = dict(item["data"])
                agg_data["count"] = item["count"]
                agg_data["first_seen"] = datetime.fromtimestamp(item["first_seen"]).strftime("%Y-%m-%d %H:%M:%S")
                agg_data["last_seen"] = datetime.fromtimestamp(item["last_seen"]).strftime("%Y-%m-%d %H:%M:%S")
                agg_data["aggregated"] = True
                agg_data["agg_window_s"] = self._net_agg_interval
                self._real_send(agg_data)
                sent_count += 1
            # Reset counts but KEEP entries for persistent connections
            with self._net_agg_lock:
                for v in self._net_agg.values():
                    v["count"] = 0
                # v3.9.6: Cleanup stale entries >360s (must be > interval * 1.5)
                stale = [k for k, v in self._net_agg.items() if now - v["last_seen"] > 360]
                for k in stale:
                    del self._net_agg[k]
            if sent_count > 0 or stale:
                print(f"[NET-3TIER] Flushed {sent_count} active connections ({len(stale)} stale cleaned)")
            # Check baseline learning timeout (24h)
            if self._BL_LEARNING and (now - self._bl_start) > 86400:
                self._BL_LEARNING = False
                with self._baseline_lock:
                    bl_size = len(self._internal_baseline)
                print(f"[NET-3TIER] Baseline learning complete. {bl_size} internal destinations learned.")

    # ================ v3.8.0/v3.9.0: SYSMON CALLBACK ================

    def _yara_callback(self, event):
        """
        v4.0: YARA scanner callback that routes through _enrich_and_queue
        (instead of bypassing to _real_send), enabling auto-quarantine.
        v4.11 (runtime fix): yara events carried no 'severity' -> the server
        alerting engine treated them as LOW and NEVER notified (even
        Ransomware_Note was silent). Default to MEDIUM so they reach the daily
        digest; HIGH+ rules can still override via their own severity.
        """
        event["type"] = "yara_alert"
        event.setdefault("severity", "MEDIUM")
        event["machine_id"] = self.machine_id
        event["hostname"] = self.hostname
        self._enrich_and_queue(event)

    def _vuln_callback(self, event):
        """
        v4.1: VulnScanner callback that routes through _enrich_and_queue
        (instead of bypassing to _real_send), enriching CVE alerts with context.
        """
        event["type"] = "vulnerability_alert"
        event["machine_id"] = self.machine_id
        event["hostname"] = self.hostname
        event["platform"] = self.platform
        try:
            event["ip_address"] = socket.gethostbyname(self.hostname)
        except Exception:
            event["ip_address"] = ""
        self._enrich_and_queue(event)

    def _sysmon_callback(self, event):
        """v3.9.0: SysmonCollector callback with 3-tier network aggregation.
        EID 3 (Network Connect) → classify_and_queue (aggregation).
        EID 1/7/11/12/13/14 → pre-filtered before sending.
        Other EIDs → pass through."""
        eid = event.get("sysmon_event_id", 0)

        if eid == 3 and event.get("type") == "network_event":
            src_ip = event.get("src_ip", "")
            dst_ip = event.get("dst_ip", "")
            if src_ip and dst_ip:
                net_data = {
                    "type": "network_traffic",
                    "src_ip": src_ip,
                    "src_port": int(event.get("src_port", 0) or 0),
                    "dst_ip": dst_ip,
                    "dst_port": int(event.get("dst_port", 0) or 0),
                    "protocol": event.get("protocol", "TCP"),
                    "state": "ESTABLISHED",
                    "size": 0,
                    "process_name": event.get("process_name", ""),
                    "process_path": event.get("process_path", ""),
                    "pid": event.get("pid", ""),
                    "source": "sysmon_eid3",
                }
                self._classify_and_queue_network(net_data)
                return

        # v3.9.0: Pre-filter other Sysmon events to reduce noise
        # EID 1 (Process Create): Only send if new EXE or from suspicious path
        if eid == 1:
            proc_path = event.get("process_path", "").lower()
            # v4.6.2 (SEC): field is command_line (cmd_line never existed -> every
            # system32 process was silently dropped); missing cmdline -> fail-open.
            cmd_line = event.get("command_line", "").lower()
            # Skip common system processes
            if "\\windows\\system32\\" in proc_path or "\\windows\\syswow64\\" in proc_path:
                if not cmd_line.strip():
                    pass  # fail-open: cannot judge an empty command line
                elif not any(kw in cmd_line for kw in _SUSPICIOUS_CMD_KEYWORDS):
                    return  # Skip routine system32 processes
            # Skip browser/spooler/office noise
            if any(kw in proc_path for kw in ("\\chrome\\", "\\firefox\\", "\\edge\\", "\\spoolsv\\", "\\office\\")):
                return

        # EID 7 (Image Load): Only send if unsigned DLL, or signed DLL loaded by
        # a script host from a non-system dir (module stomping detection)
        if eid == 7:
            image_path = event.get("dll_path", "").lower() or event.get("image_loaded", "").lower()
            signed = event.get("signed", "true").lower()
            in_system_dir = "\\windows\\system32\\" in image_path or "\\windows\\syswow64\\" in image_path
            if signed == "true":
                # v4.6.2 (SEC): signed third-party DLLs were fully invisible
                if in_system_dir:
                    return  # Skip system-signed DLLs from system dirs
                loader = (event.get("process_name") or "").lower()
                if not any(ph in loader for ph in _SCRIPT_HOST_LOADERS):
                    return
            elif in_system_dir:
                if signed != "false":
                    return  # Skip system dirs with unknown signing state

        # EID 11 (File Create): Only send if in sensitive paths
        if eid == 11:
            target = event.get("file_path", "").lower()
            sensitive_dirs = ("\\windows\\", "\\inetpub\\", "\\perflogs\\",
                              "\\programdata\\", "\\users\\public\\",
                              "\\programdata\\microsoft\\windows\\start menu\\",
                              "\\temp\\", "\\downloads\\", "\\appdata\\local\\temp\\")
            if not any(d in target for d in sensitive_dirs):
                return
            # v4.6.2 (SEC): noise-extension skip ONLY in genuine temp locations -
            # a payload named 'x.tmp' dropped into C:\Users\Public, C:\ProgramData
            # or \windows\ still reaches the server.
            if any(d in target for d in ("\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\temp\\")):
                if target.endswith((".tmp", ".log", ".etl", ".pf")):
                    return

        # EID 12/13/14 (Registry): Only send if key is in sensitive paths
        if eid in (12, 13, 14):
            reg_path = event.get("registry_key", "").lower()
            sensitive_keys = ("run", "runonce", "services", "image file execution",
                              "winlogon", "bootexecute", "appinit", "shell",
                              # v4.6.2 (SEC): COM hijack, WMI subscription, AppCertDLLs,
                              # print monitors, LSA security packages, SBL/transcript keys
                              "clsid", "subscription", "appcertdlls", "monitors",
                              "security packages", "control\\lsa",
                              "scriptblocklogging", "transcriptlogging",
                              # v4.6.4: WDigest plaintext-caching enable (THREAT-070)
                              "wdigest", "securityproviders")
            if not any(k in reg_path for k in sensitive_keys):
                return

        # EID 22 (DNS): Dedup 300s per domain
        if eid == 22:
            domain = event.get("query_name", "")
            if domain:
                key = f"dns:{domain}"
                with self._net_agg_lock:
                    existing = self._net_agg.get(key)
                    if existing:
                        existing["count"] += 1
                        existing["last_seen"] = time.time()
                        return
                    self._net_agg[key] = {"data": event, "count": 1, "first_seen": time.time(), "last_seen": time.time()}
                # First occurrence → send
                self._real_send(event)
                return

        # Pass through all other events
        # v4.6.2 (SEC): route through _enrich_and_queue so sysmon events (EID 10
        # ProcessAccess, EID 6 driver, EID 16/255 tampering, EID 2/23/25...) hit the
        # correlation engine + MITRE mapping instead of going straight to the wire.
        self._enrich_and_queue(event)

    # ================ v3.9.0: NETSTAT POLL WITH AGGREGATION (FALLBACK) ================

    def _simple_network_poll(self):
        """v3.9.0: Netstat poll with 60s aggregation buffer.
        Light dedup (90s per dst_ip:dst_port), noise filter.
        Internal common traffic aggregated, suspicious real-time.
        Only used when Sysmon is unavailable."""
        import subprocess as _sp
        _NOISE_PORTS = {1900, 5353, 5355, 137, 138, 3702, 17500, 57621, 427, 8000, 8008}
        _SUS_PORTS = self._SUS_INTERNAL_PORTS
        _dedup = {}
        _dedup_ttl = 60  # v3.9.2: Match aggregation window to avoid re-triggering first-occurrence
        time.sleep(10)
        _first = True
        _loop_count = 0
        while self.running:
            try:
                if not self.connected:
                    time.sleep(10)
                    continue
                r = _sp.run(["netstat","-an"], capture_output=True, text=True, timeout=10,
                    creationflags=_sp.CREATE_NO_WINDOW if os.name=='nt' else 0)
                count_sent = 0
                skipped_noise = 0
                skipped_dedup = 0
                skipped_loopback = 0
                now = time.time()
                for line in r.stdout.split('\n'):
                    parts = line.split()
                    if len(parts) < 4: continue
                    proto = parts[0]
                    if proto not in ('TCP','UDP'): continue
                    local, remote = parts[1], parts[2]
                    state = parts[3] if len(parts)>3 else ''
                    lp = local.rsplit(':',1)
                    rp = remote.rsplit(':',1)
                    if len(lp)!=2 or len(rp)!=2: continue
                    local_ip = lp[0].strip("[]")
                    remote_ip = rp[0].strip("[]")
                    try:
                        sp = int(lp[1]); dp = int(rp[1])
                    except ValueError: continue
                    if state.upper()=="LISTENING": continue
                    if local_ip in ("0.0.0.0","::"): continue
                    if local_ip in ("127.0.0.1","::1") or remote_ip in ("127.0.0.1","::1"):
                        skipped_loopback += 1
                        continue
                    if proto == "UDP" and remote_ip in ("*", "0.0.0.0", "::"):
                        skipped_noise += 1
                        continue
                    if dp in _NOISE_PORTS and dp not in _SUS_PORTS:
                        skipped_noise += 1
                        continue
                    dedup_key = f"{local_ip}:{remote_ip}:{dp}"
                    last = _dedup.get(dedup_key, 0)
                    if now - last < _dedup_ttl:
                        skipped_dedup += 1
                        continue
                    _dedup[dedup_key] = now
                    if len(_dedup) > 10000:
                        _dedup = {k: v for k, v in _dedup.items() if now - v < _dedup_ttl}

                    data = {"type":"network_traffic","src_ip":local_ip,"src_port":sp,
                            "dst_ip":remote_ip,"dst_port":dp,"protocol":proto,"state":state,"size":0,
                            "source": "netstat_poll"}
                    # Use 3-tier classification
                    self._classify_and_queue_network(data)
                    count_sent += 1
                if _first:
                    print(f"[NET-SIMPLE] First poll: {count_sent} classified, {skipped_noise} noise, {skipped_dedup} dedup, {skipped_loopback} loopback")
                    _first = False
                elif count_sent:
                    print(f"[NET-SIMPLE] Classified {count_sent} (noise:{skipped_noise} dedup:{skipped_dedup} loop:{skipped_loopback})")
            except Exception as e:
                import traceback
                print(f"[NET-SIMPLE] ERROR: {e}\n{traceback.format_exc()}")
            time.sleep(15)

    def start(self):
        if IS_WINDOWS:
            self.event_collector.start()
            self.fim_collector.start()
        print("[*] Collectors started (Events + FIM)")

        # v3.9.0: Start network aggregation flush thread
        threading.Thread(target=self._net_agg_flush_loop, daemon=True).start()
        print("[*] Network 3-tier aggregation started (60s flush)")

        # v3.8.0: Start Sysmon first to decide network source
        sysmon_ok = False
        try:
            sysmon_ok = self.sysmon_collector.start()
            if sysmon_ok:
                print("[*] Sysmon Collector started (network via EID 3)")
        except Exception as e:
            print(f"[-] Sysmon Collector failed to start: {e}")

        if sysmon_ok and self.sysmon_collector.sysmon_available:
            print("[*] Network monitoring: Sysmon EID 3 + netstat fallback (3-tier aggregation)")
            self._use_sysmon_network = True
            # v3.9.1 FIX: Always start netstat polling as fallback
            # Sysmon may be installed but unreadable due to permissions
            threading.Thread(target=self._simple_network_poll, daemon=True).start()
        else:
            # v5.0.4 (review R7 7.6): optional full packet capture (needs Npcap +
            # admin) - enables TLS SNI + JA3 DPI on top of L3/L4. Mutually exclusive
            # with netstat polling (same channel, no duplicates).
            if os.environ.get("GIAMSAT_AGENT_PACKET_CAPTURE", "").strip() == "1":
                try:
                    self.network_collector.start()
                    print("[*] Network monitoring: packet capture mode (SNI/JA3 DPI)")
                except Exception as e:
                    print(f"[-] Packet capture mode failed: {e}")
                    threading.Thread(target=self._simple_network_poll, daemon=True).start()
            else:
                print("[*] Network monitoring: netstat polling (fallback, 3-tier aggregation)")
                threading.Thread(target=self._simple_network_poll, daemon=True).start()

        threading.Thread(target=self._vuln_scan_loop, daemon=True).start()
        threading.Thread(target=self._yara_scan_loop, daemon=True).start()
        threading.Thread(target=self._sca_scan_loop, daemon=True).start()
        threading.Thread(target=self._batch_flush_loop, daemon=True).start()
        threading.Thread(target=self._receive_commands, daemon=True).start()
        threading.Thread(target=self._heartbeat_loop, daemon=True).start()
        threading.Thread(target=self._http_poll_loop, daemon=True).start()
        threading.Thread(target=self._auto_update_check_loop, daemon=True).start()

        try:
            self.memory_scanner.start()
            print("[*] Memory Scanner started")
        except Exception as e:
            print(f"[-] Memory Scanner failed to start: {e}")
        try:
            self.behavior_collector.start()
            print("[*] Behavior Collector started")
        except Exception as e:
            print(f"[-] Behavior Collector failed to start: {e}")

        attempt = 0
        while self.running:
            if not self.connected:
                wait = min(self.reconnect_interval * (2 ** attempt), self.max_reconnect_interval)
                if attempt > 0: print(f"[*] Reconnecting in {wait}s...")
                time.sleep(wait)
                if self._connect(): attempt = 0
                else: attempt += 1
            time.sleep(1)

        if self.sock:
            try: self.sock.close()
            except Exception: pass
        self.log_cache.close()
        print("[*] Agent stopped.")


def _ensure_windows_service():
    """Auto-register as Windows Service if running as Admin."""
    service_name = "GiamSatAgent"
    my_exe = sys.executable

    try:
        import subprocess
        r = subprocess.run(["sc", "query", service_name],
                          capture_output=True, timeout=10,
                          creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        if r.returncode == 0:
            print(f"[*] Service '{service_name}' already exists")
            try:
                subprocess.run(["sc", "start", service_name],
                              capture_output=True, timeout=10,
                              creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
            except Exception:
                pass
            return
    except Exception:
        pass

    try:
        print(f"[*] Creating Windows Service '{service_name}'...")
        subprocess.run([
            "sc", "create", service_name,
            "binPath=", my_exe,
            "start=", "auto",
            "DisplayName=", "GIAM-SAT Agent"
        ], capture_output=True, timeout=15,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        subprocess.run(["sc", "start", service_name],
                      capture_output=True, timeout=10,
                      creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        print(f"[OK] Service '{service_name}' created and started")
    except Exception as e:
        print(f"[-] Failed to create service: {e}")


if __name__ == "__main__":
    _ensure_windows_service()
    agent = AgentCore()
    agent.start()
