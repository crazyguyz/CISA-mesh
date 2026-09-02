"""
Server Core for GIAM-SAT Server v2.5.1
Flask web interface with real-time display, TLS-encrypted TCP server on 6666, Syslog on 514.
v2.5.1 REFACTOR: API routes extracted to api/ modules, server_monitor.py, ai_providers.py.
"""
import json
import threading
import os
import sys
import time
import html as _html
import ssl
import urllib.parse
import urllib.request
from datetime import datetime, timezone

# Load .env file if exists
_ENV_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
if os.path.exists(_ENV_FILE):
    try:
        with open(_ENV_FILE, "r", encoding="utf-8") as _f:
            for _line in _f:
                _line = _line.strip()
                if _line and not _line.startswith("#") and "=" in _line:
                    _key, _val = _line.split("=", 1)
                    _key = _key.strip()
                    _val = _val.strip().strip('"').strip("'")
                    if _key and _val and not os.environ.get(_key):
                        os.environ[_key] = _val
    except Exception:
        pass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "common"))
# Add project root so the `common` package resolves in threads/runtime (`from common.logger import ...`)
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

# v4.5.3: persist all console output to logs/giamsat.log for troubleshooting
try:
    from logger import setup_file_logging
    setup_file_logging()
except Exception:
    pass

try:
    from flask import Flask, render_template, request, jsonify, Response
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False
    print("[!] Flask not installed. Install with: pip install flask")

from db_manager import DatabaseManager
from db_postgres import PostgresDatabase, HAS_POSTGRES
try:
    # v4.10 (CRIT-7): the real class is ElasticsearchBackend, not ElasticsearchDatabase
    from db_elasticsearch import ElasticsearchBackend, HAS_ELASTICSEARCH
except ImportError:
    HAS_ELASTICSEARCH = False
from tcp_server import TCPServer
from syslog_server import SyslogServer
from auth_manager import AuthManager
from alerting_engine import AlertingEngine
from cluster_manager import ClusterManager
from agentless_monitor import AgentlessMonitor
from reporting_engine import ReportingEngine
from server_monitor import ServerMonitor
from ai_providers import call_ai_assistant
from panorama import PanoramaCollector
from network_baseline import NetworkBaseline
from event_queue import EventQueue
from event_worker import EventWorkerPool
from correlation_engine_server import ServerCorrelationEngine
from api_cache import ApiCache
from sigma_updater import SigmaAutoUpdater
from soar_playbooks import SOARPlaybookEngine


class ServerCore:
    def __init__(self, web_host="0.0.0.0", web_port=5000):
        self.web_host = web_host
        self.web_port = web_port
        # v3.0: Select database backend via environment variable
        db_backend = os.environ.get("GIAMSAT_DB_BACKEND", "sqlite").lower()
        self.db_fallback = ""  # v5.0.4: set when the requested backend is not in use
        if db_backend == "elasticsearch" and HAS_ELASTICSEARCH:
            print("[*] Using Elasticsearch backend (search-optimized)")
            self.db = ElasticsearchBackend()
        elif db_backend == "postgres" and HAS_POSTGRES:
            print("[*] Using PostgreSQL backend (scalable)")
            self.db = PostgresDatabase()
            if not getattr(self.db, "_connected", False):
                # v5.0.4 (ops bug): a failed PG connect used to fall back to SQLite
                # with only a console print - the admin never noticed and events
                # silently accumulated in the wrong store. Now: log to file, expose
                # the state via /api/health and a dashboard banner.
                import traceback as _tb
                reason = "PostgreSQL unreachable at startup (check GIAMSAT_PG_* in .env, role/password, service)"
                _dbg = _tb.format_exc()
                print("[!] " + reason + " - falling back to SQLite. /api/health will report db_fallback.")
                self.db_fallback = reason
                try:
                    _logp = os.path.join(os.path.dirname(os.path.abspath(__file__)), "server_error.log")
                    with open(_logp, "a", encoding="utf-8") as _f:
                        _f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} [DB-FALLBACK] {reason}\n{_dbg}\n")
                except Exception:
                    pass
                self.db = DatabaseManager()
        else:
            if db_backend == "postgres" and not HAS_POSTGRES:
                print("[!] PostgreSQL requested but psycopg2 not available, falling back to SQLite")
                self.db_fallback = "PostgreSQL requested but psycopg2 not installed"
            elif db_backend == "elasticsearch" and not HAS_ELASTICSEARCH:
                print("[!] Elasticsearch requested but elasticsearch-py not available, falling back to SQLite")
                self.db_fallback = "Elasticsearch requested but client not installed"
            self.db = DatabaseManager()

        self.auth = AuthManager()

        # SSE event queue (in-memory list for dashboard push)
        self.sse_queue = []
        self.sse_queue_lock = threading.Lock()

        # Telegram Bot config
        self.telegram_bot_token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
        self.telegram_chat_id = os.environ.get("TELEGRAM_CHAT_ID", "")
        self._telegram_lock = threading.Lock()

        # Alerting Engine
        self.alerting = AlertingEngine()

        # AI rate limiter (used by api_ai.py)
        self._ai_rate_limit = {}
        self._ai_rate_lock = threading.Lock()
        self.AI_MAX_TOKENS_CAP = 8192

        def on_message(msg):
            # v3.9.3: Route threat alerts to SOAR engine for auto-response
            if msg.get("type") == "threat_alert" and hasattr(self, 'soar') and self.soar:
                try:
                    self.soar.process_alert(msg)
                except Exception:
                    pass
            # Push to SSE queue for dashboard real-time
            with self.sse_queue_lock:
                self.sse_queue.append(msg)
                if len(self.sse_queue) > 1000:
                    self.sse_queue = self.sse_queue[-500:]

        def on_uptime_alert(mid, hostname, hours):
            """v2.3.0: Called when a machine reaches 24h+ uptime."""
            try:
                user = self.db.get_machine_user(mid)
                email = user.get("email", "") if user else ""
                subject = f"⚠ GIAM-SAT: {hostname} hoạt động liên tục {hours:.0f} giờ"
                body = (
                    f"Kính gửi {user.get('user_name', '')},\n\n"
                    f"Máy trạm {hostname} của bạn đã hoạt động liên tục {hours:.0f} giờ "
                    f"(vượt ngưỡng 24h).\n\n"
                    f"Vui lòng kiểm tra và khởi động lại máy nếu cần.\n\n"
                    f"Trân trọng,\nPhòng IT"
                )
                if email:
                    threading.Thread(target=self._send_email_smtp, args=(email, subject, body), daemon=True).start()
            except Exception as e:
                from common.logger import log_error
                log_error("Uptime alert failed", exc=e, context={"machine_id": mid, "hostname": hostname})

        # v3.0: Event Queue (decouple TCP from DB writes)
        self.event_queue = EventQueue()

        # v2.6.5: Network Baseline must be created BEFORE TCPServer
        self.network_baseline = NetworkBaseline(db_manager=self.db)

        tls_enabled = os.environ.get("GIAMSAT_TLS_ENABLED", "false").lower() == "true"
        tls_context = None
        if tls_enabled:
            try:
                from common.tls_utils import generate_self_signed_cert, create_server_ssl_context
                certfile, keyfile, cafile = generate_self_signed_cert()
                tls_context = create_server_ssl_context(certfile, keyfile, cafile)
                print("[*] TLS enabled for TCP:6666 (mTLS)")
            except Exception as e:
                # v4.11 (HIGH-7 FIX): fail-closed - "TLS bật" mà không dựng được
                # context KHÔNG được âm thầm fallback về plaintext (PSK, heartbeat
                # và lệnh điều khiển sẽ đi trần trong khi admin tin rằng có TLS).
                print(f"[!] FATAL: GIAMSAT_TLS_ENABLED=true but TLS setup failed: {e}")
                print("[!] Fix the TLS configuration, or set GIAMSAT_TLS_ENABLED=false to run WITHOUT TLS.")
                sys.exit(1)

        self.tcp_server = TCPServer(
            host="0.0.0.0", port=6666,
            db_manager=self.db,
            message_callback=on_message,
            alerting_engine=self.alerting,
            tls_enabled=tls_enabled,
            network_baseline=self.network_baseline,
            event_queue=self.event_queue,
            # v4.10 (CRIT-6): hand over the mTLS context instead of dropping it
            tls_context=tls_context
        )
        self.tcp_server._uptime_alert_callback = on_uptime_alert

        # Start Telegram callback poller (needs core for in-process approval)
        try:
            self.alerting.start_telegram_callback_poller(core=self)
        except Exception:
            pass

        self.syslog_server = SyslogServer(
            host="0.0.0.0", port=514,
            db_manager=self.db,
            message_callback=on_message
        )

        # v5.0.4 (Phase3 improvement #1): secure syslog over TCP/TLS (:6514)
        self.syslog_tcp_server = None
        try:
            from syslog_tcp_server import SyslogTCPServer
            self.syslog_tcp_server = SyslogTCPServer(
                host="0.0.0.0", db_manager=self.db, message_callback=on_message)
            print(f"[*] Syslog TCP server ready (:{self.syslog_tcp_server.port}, "
                  f"TLS={bool(__import__('os').environ.get('GIAMSAT_SYSLOG_TLS_CERT', ''))})")
        except Exception as e:
            print(f"[!] Syslog TCP init failed: {e}")

        # v5.0.4 (Phase3 improvement #3): user-defined watchlist matcher (IOC-WATCH-001)
        self.watchlist_matcher = None
        try:
            from watchlist_matcher import WatchlistMatcher
            self.watchlist_matcher = WatchlistMatcher(db_manager=self.db, alerting=self.alerting)
            print("[*] Watchlist matcher ready (IOC-WATCH-001)")
        except Exception as e:
            print(f"[!] Watchlist matcher init failed: {e}")

        # v4.13 (P2): NetFlow collector (v5/v9 from edge switches) - C2/exfil detection
        self.netflow = None
        try:
            from netflow_collector import NetflowCollector
            self.netflow = NetflowCollector(db_manager=self.db)
            print(f"[*] NetFlow Collector ready (UDP :{self.netflow.port})")
        except Exception as e:
            print(f"[!] NetFlow Collector init failed: {e}")

        # v5.0.4 (review R7 7.9): behaviour-based NetFlow alerting - beacon /
        # first-seen / off-hours WITHOUT IP reputation (a cloud VPS IP is benign;
        # the pattern is not).
        self.network_alerting = None
        try:
            from network_alerting import NetworkAlertEngine
            self.network_alerting = NetworkAlertEngine(db_manager=self.db, alerting=self.alerting)
            print("[*] Network Alert Engine ready (NET-BEACON / NET-FIRST / NET-ODD)")
        except Exception as e:
            print(f"[!] Network Alert Engine init failed: {e}")

        # v3.0: Cross-machine correlation engine (lateral movement, multi-host)
        self.correlation = ServerCorrelationEngine(db_manager=self.db, alerting_engine=self.alerting)

        # v3.0: Event Worker Pool (background DB writers)
        self.event_worker_pool = EventWorkerPool(
            event_queue=self.event_queue,
            db_manager=self.db,
            correlation_engine=self.correlation,
            alerting=self.alerting,
            num_workers=int(os.environ.get("GIAMSAT_EVENT_WORKERS", "8")),
            batch_size=100,
            poll_interval=0.5,
        )

        self.cluster = ClusterManager()
        self.agentless = AgentlessMonitor(db_manager=self.db, message_callback=on_message)
        self.reporting = ReportingEngine(db_manager=self.db)

        # Server Self-Monitor
        self.server_monitor = ServerMonitor(self.db)

        # Server Panoramic Monitor
        self.panorama = PanoramaCollector(db_manager=self.db)

        # v3.0: API Cache layer
        self.api_cache = ApiCache(db_manager=self.db)

        # v3.2: Sigma Auto-Updater (weekly sync from SigmaHQ)
        self.sigma_updater = None
        if os.environ.get("GIAMSAT_SIGMA_AUTO", "1") == "1":
            try:
                self.sigma_updater = SigmaAutoUpdater()
            except Exception as e:
                print(f"[!] Sigma Auto-Updater init failed: {e}")

        # v3.9.3: SOAR Playbook Engine with Active Response
        try:
            self.soar = SOARPlaybookEngine(
                callback=None,
                telegram_sender=self._send_telegram_message,
                tcp_server=self.tcp_server,
            )
            self.soar.start_escalation_monitor(interval_seconds=60)
            print("[*] SOAR Engine initialized (6 playbooks, auto-response for CRITICAL alerts)")
        except Exception as e:
            print(f"[!] SOAR Engine init failed: {e}")
            self.soar = None

        self._retention_running = True

    def start(self):
        self.tcp_server.start()
        self.syslog_server.start()
        if self.syslog_tcp_server:
            try:
                self.syslog_tcp_server.start()
            except Exception as e:
                print(f"[!] Syslog TCP server start failed: {e}")
        if self.watchlist_matcher:
            try:
                self.watchlist_matcher.start()
            except Exception as e:
                print(f"[!] Watchlist matcher start failed: {e}")
        if self.netflow:
            try:
                self.netflow.start()
            except Exception as e:
                print(f"[!] NetFlow Collector start failed: {e}")
        if self.network_alerting:
            try:
                self.network_alerting.start()
            except Exception as e:
                print(f"[!] Network Alert Engine start failed: {e}")
        print("[*] Background servers started (TCP:6666, Syslog:514, NetFlow:2055)")
        # v4.5.5 SECURITY: agent HTTP endpoints (pending-commands/heartbeat/command-result/download)
        # transmit the agent PSK in plaintext over HTTP. Warn admins to use a TLS reverse proxy.
        # v4.11 (HIGH-7): banner made prominent - this is a real exposure, not a suggestion.
        if os.environ.get("GIAMSAT_AGENT_PSK", "").strip():
            print("[!] ⚠ SECURITY: Web/API port 5000 is PLAINTEXT HTTP - the agent PSK, heartbeat and")
            print("[!]   commands travel unencrypted on the network. For production put the web server")
            print("[!]   behind a TLS reverse proxy (see README 'TLS' section / server/nginx_tcp_stream.conf)")
            print("[!]   or disable agent HTTP by blocking inbound :5000 from untrusted networks.")

        # v3.0: Start event worker pool
        self.event_worker_pool.start()

        # v3.2: Start Sigma Auto-Updater
        if self.sigma_updater:
            self.sigma_updater.start()

        # v4.11 (P3): daily MEDIUM alert digest email (below Telegram threshold)
        try:
            from daily_digest import start_digest_thread
            start_digest_thread(self, self.alerting.config)
            print("[*] Daily MEDIUM digest thread started (alerting_config.json -> digest)")
        except Exception as e:
            print(f"[!] Digest thread start failed: {e}")

        # v3.0: Setup materialized views (PostgreSQL only) + periodic refresh
        try:
            self.api_cache.setup_materialized_views()
            def refresh_views_loop():
                while self._retention_running:
                    time.sleep(30)
                    try:
                        self.api_cache.refresh_materialized_views()
                    except Exception:
                        pass
            threading.Thread(target=refresh_views_loop, daemon=True).start()
        except Exception:
            pass

        # v2.6.5: Build initial network baseline + periodic rebuild (daily)
        def build_baseline_loop():
            time.sleep(30)  # Wait for services to stabilize
            while self._retention_running:
                try:
                    self.network_baseline.build_baseline()
                except Exception as e:
                    print(f"[-] Network Baseline: Build failed: {e}")
                time.sleep(86400)  # Rebuild daily
        threading.Thread(target=build_baseline_loop, daemon=True).start()

        self.cluster.start_cluster_listener()
        self.cluster.send_heartbeat(tcp_port=6666, web_port=self.web_port)
        self.agentless.start_scheduler()
        self.reporting.schedule_daily_report()
        self.reporting.schedule_weekly_report()

        # Heartbeat timeout checker
        def heartbeat_monitor():
            # v4.13 (P0.2): alert when agents drop offline (previously silent console-only).
            # Dedup per machine with escalation: >5min = MEDIUM, >30min = HIGH.
            _offline_alerted = {}
            while self._retention_running:
                time.sleep(60)
                try:
                    offline_count = self.db.check_heartbeat_timeout(timeout_seconds=120)
                    if offline_count > 0:
                        print(f"[*] Heartbeat monitor: {offline_count} machine(s) marked offline")
                    try:
                        machines = self.db.get_machines()
                        offline_ids = set()
                        now = time.time()
                        for m in machines:
                            if m.get("is_online"):
                                continue
                            mid = m.get("machine_id", "")
                            offline_ids.add(mid)
                            gap_min = 0
                            try:
                                _ts = datetime.strptime(str(m.get("last_seen", ""))[:19], "%Y-%m-%d %H:%M:%S")
                                _ts = _ts.replace(tzinfo=timezone.utc).timestamp()
                                gap_min = max(0, int((now - _ts) / 60))
                            except Exception:
                                # v5.0.3 (LOW-4): machine never heartbeated (last_seen
                                # empty/unparseable) - do NOT alert as if it dropped
                                # offline after being online (was a hardcoded 10min FP)
                                gap_min = 0
                            level = 2 if gap_min > 30 else (1 if gap_min > 5 else 0)
                            if level and _offline_alerted.get(mid, 0) < level:
                                severity = "HIGH" if level == 2 else "MEDIUM"
                                label = m.get("hostname") or mid
                                try:
                                    # v5.0.3 (HIGH-1 FIX): send_alert takes ONE dict, not
                                    # kwargs - the old call raised TypeError on every offline
                                    # check (swallowed), so AGENT-OFFLINE alerts never fired.
                                    self.alerting.send_alert({
                                        "title": f"[AGENT OFFLINE] {label} [{severity}]",
                                        "message": f"Agent '{label}' ({mid}) has no heartbeat for {gap_min} minutes (last seen {m.get('last_seen')}).",
                                        "severity": severity,
                                        "rule_id": "AGENT-OFFLINE",
                                        "machine_id": mid,
                                        "hostname": label,
                                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                    })
                                except Exception:
                                    pass
                                _offline_alerted[mid] = level
                        # Clear dedup state once an agent comes back online
                        for mid in list(_offline_alerted.keys()):
                            if mid not in offline_ids:
                                del _offline_alerted[mid]
                    except Exception:
                        pass
                except Exception as e:
                    from common.logger import log_error
                    log_error("Heartbeat monitor check failed", exc=e)

        threading.Thread(target=heartbeat_monitor, daemon=True).start()

        # v5.0.4 (Phase1 A2): log-source health - alert when an online machine's
        # event volume drops below 50% of its 7-day average (silent source = attack)
        def loghealth_monitor():
            _alerted = {}
            time.sleep(90)
            while self._retention_running:
                time.sleep(600)
                try:
                    v24 = self.db.get_event_volume(hours=24) or {}
                    v168 = self.db.get_event_volume(hours=168) or {}
                    for m in (self.db.get_machines() or []):
                        if not m.get("is_online"):
                            continue
                        mid = m.get("machine_id", "")
                        e24 = (v24.get(mid) or {}).get("events", 0) + (v24.get(mid) or {}).get("sysmon", 0)
                        e168 = (v168.get(mid) or {}).get("events", 0) + (v168.get(mid) or {}).get("sysmon", 0)
                        avg = e168 / 7.0 if e168 else 0
                        if avg > 10 and e24 < avg * 0.5 and not _alerted.get(mid):
                            _alerted[mid] = True
                            label = m.get("hostname") or mid
                            drop = int((1 - e24 / avg) * 100)
                            self.alerting.send_alert({
                                "title": f"[LOG SOURCE DROP] {label} [HIGH]",
                                "message": f"Machine '{label}' ({mid}) event volume dropped "
                                           f"{drop}% below its 7-day average (last 24h: {e24} vs avg {avg:.0f}). "
                                           f"Possible logging disabled by attacker.",
                                "severity": "HIGH",
                                "rule_id": "LOGHEALTH-001",
                                "machine_id": mid,
                                "hostname": label,
                                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            })
                        elif not m.get("is_online") or avg == 0 or e24 >= avg * 0.5:
                            _alerted.pop(mid, None)
                except Exception as e:
                    print(f"[-] Log-health monitor error: {e}")
        threading.Thread(target=loghealth_monitor, daemon=True).start()

        # v5.0.4 (Phase2 A8/B2): kill-chain case auto-detection - cluster open
        # alerts per machine within 1h having >= 2 distinct rules -> one case.
        def case_detector():
            _last_case = {}  # machine_id -> ts of last auto-case
            time.sleep(120)
            while self._retention_running:
                time.sleep(300)
                try:
                    if not hasattr(self.db, "list_cases"):
                        continue
                    # v5.0.4 R9: backend-aware query (PG datetime() failed silently)
                    rows = self.db.get_unresolved_threats_since(hours=1) if hasattr(self.db, "get_unresolved_threats_since") else []
                    from collections import defaultdict
                    clusters = defaultdict(list)
                    for r in rows:
                        clusters[r["machine_id"]].append(r)
                    for mid, alerts in clusters.items():
                        rules = {a["rule_id"] for a in alerts if a["rule_id"]}
                        if len(rules) < 2:
                            continue
                        sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
                        sev = max(alerts, key=lambda a: sev_rank.get(a["severity"] or "LOW", 0))["severity"]
                        now = time.time()
                        if now - _last_case.get(mid, 0) < 3600:
                            continue
                        try:
                            open_cases = [c for c in (self.db.list_cases(limit=500) or [])
                                          if c.get("machine_id") == mid and c.get("status") != "closed"]
                        except Exception:
                            open_cases = []
                        if open_cases:
                            _last_case[mid] = now
                            continue
                        _last_case[mid] = now
                        self.db.create_case(mid, alerts[0]["hostname"],
                                            f"Kill-chain cluster: {len(rules)} rules in 1h",
                                            " | ".join(sorted(rules))[:1900], sev,
                                            [a["id"] for a in alerts], created_by="auto")
                        print(f"[CASE] auto-case created for {mid}: {len(rules)} rules in 1h")
                except Exception as e:
                    print(f"[-] Case detector error: {e}")
        threading.Thread(target=case_detector, daemon=True).start()

        # Retention loop
        def retention_loop():
            while self._retention_running:
                time.sleep(3600)
                try:
                    self.db.apply_retention_policy()
                except Exception as e:
                    from common.logger import log_error
                    log_error("Retention policy failed", exc=e)

        threading.Thread(target=retention_loop, daemon=True).start()

        # PostgreSQL ANALYZE schedule (v4.3): run every 6 hours to keep query planner stats fresh
        def analyze_loop():
            time.sleep(600)  # Wait 10 minutes after startup
            while self._retention_running:
                try:
                    if hasattr(self.db, 'vacuum'):
                        self.db.vacuum()
                        print("[*] PostgreSQL ANALYZE completed")
                except Exception as e:
                    print(f"[-] ANALYZE failed: {e}")
                time.sleep(21600)  # 6 hours
        threading.Thread(target=analyze_loop, daemon=True).start()

        if HAS_FLASK:
            self._start_web()
        else:
            print("[!] Flask not available.")
            while True:
                try:
                    time.sleep(1)
                except KeyboardInterrupt:
                    break

    def _start_web(self):
        app = Flask(__name__, template_folder=os.path.join(os.path.dirname(__file__), "templates"),
                    static_folder=os.path.join(os.path.dirname(__file__), "static"))
        app.config["SECRET_KEY"] = os.environ.get("GIAMSAT_SECRET_KEY", os.urandom(24).hex())
        # v4.6.6: no-cache for static assets - a browser that cached an old JS file
        # after a server update showed stale UI (e.g. "Error parsing MITRE data" from
        # a pre-fix mitre-matrix.js) even after Ctrl+F5 on some setups. Always fresh.
        app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0

        # Block access to sensitive config files (v4.2.1)
        @app.before_request
        def block_sensitive_files():
            path = request.path.lower()
            blocked = ['.env', '.user_key', 'alerting_config.json', '.git', '__pycache__']
            for b in blocked:
                if b in path:
                    from flask import abort
                    abort(404)

        # Security headers
        @app.after_request
        def remove_server_header(response):
            response.headers.pop("Server", None)
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["X-XSS-Protection"] = "1; mode=block"
            return response

        # v4.13 (P2): global API rate limit per IP (in-memory sliding window).
        # Agent-facing endpoints, SSE and health are exempt (they authenticate via PSK).
        _api_rate = {}
        _api_rate_last = {}      # v5.0.3 (MEDIUM-4): ip -> last request ts (idle GC)
        _api_rate_ops = 0
        _api_rate_lock = threading.Lock()
        # v5.0.4: default raised 600 -> 1800/min/IP - the dashboard legitimately
        # bursts on load (machines/stats/event_types/panorama/assets/groups/fim/...)
        # plus multi-tab sessions; 600 tripped on a single admin session (see the
        # SSE loadStats debounce fix in dashboard.js).
        _API_RATE_LIMIT = int(os.environ.get("GIAMSAT_API_RATE_LIMIT", "1800"))
        _API_RATE_WINDOW = 60
        _API_RATE_EXEMPT = ("/api/events/stream", "/api/agent/", "/api/health", "/api/login")

        @app.before_request
        def api_rate_limit():
            # v5.0.3 (FIX): _api_rate_ops is rebound by += so it must be declared
            # nonlocal - otherwise Python treats it as a fresh local and every
            # /api/* request dies with UnboundLocalError (whole web UI 500s).
            nonlocal _api_rate_ops
            path = request.path
            if not path.startswith("/api/") or any(path.startswith(p) for p in _API_RATE_EXEMPT):
                return None
            ip = request.remote_addr or "?"
            now = time.time()
            with _api_rate_lock:
                # v5.0.3 (MEDIUM-4): periodic GC - drop IP keys idle for > window
                _api_rate_ops += 1
                if _api_rate_ops % 500 == 0:
                    idle = [k for k, ts in _api_rate_last.items() if now - ts > _API_RATE_WINDOW]
                    for k in idle:
                        _api_rate.pop(k, None)
                        _api_rate_last.pop(k, None)
                lst = [t for t in _api_rate.get(ip, []) if now - t < _API_RATE_WINDOW]
                if len(lst) >= _API_RATE_LIMIT:
                    _api_rate[ip] = lst
                    _api_rate_last[ip] = now
                    return jsonify({"error": "Rate limit exceeded", "code": "RATE_LIMITED"}), 429
                lst.append(now)
                _api_rate[ip] = lst
                _api_rate_last[ip] = now
            return None

        # Server Self-Monitor middleware
        app.before_request(self.server_monitor.create_middleware())
        app.register_error_handler(404, self.server_monitor.create_404_handler())

        # Static pages
        @app.route("/")
        def index():
            token = request.headers.get("Authorization", "").replace("Bearer ", "")
            if not token:
                token = request.cookies.get("giamsat_token", "")
            if token and self.auth.verify_token(token):
                return render_template("index.html")
            return render_template("login.html")

        @app.route("/login")
        def login_page():
            return render_template("login.html")

        @app.route("/manifest.json")
        def pwa_manifest():
            return render_template("manifest.json"), 200, {"Content-Type": "application/manifest+json"}

        # v2.5.2: Health Check Endpoint
        @app.route("/api/health")
        def api_health():
            try:
                db_status = "ok" if self.db and self.db.conn else "error"
            except Exception:
                db_status = "error"
            # v5.0.4 (ops bug): expose which backend is REALLY in use + fallback reason
            db_backend = os.environ.get("GIAMSAT_DB_BACKEND", "sqlite").lower()
            actual_backend = "sqlite"
            if db_backend == "postgres" and getattr(self.db, "_connected", False):
                actual_backend = "postgres"
            return jsonify({
                "status": "healthy",
                "version": "2.5.2",
                "uptime_seconds": int(time.time()),
                "db_backend": actual_backend,
                "db_fallback": self.db_fallback or "",
                "services": {
                    "web": "ok",
                    "tcp": "ok" if self.tcp_server and self.tcp_server.running else "stopped",
                    "database": db_status
                }
            })

        # Register all API route modules
        import api
        api.register_all_routes(app, self)

        # v4.13 (P2): optional HTTPS on the web port - stops plaintext PSK/session
        # sniffing without an external reverse proxy. Agents must be configured
        # with server_tls=true + trust the CA to talk to an HTTPS web port.
        web_tls = os.environ.get("GIAMSAT_WEB_TLS_ENABLED", "false").lower() == "true"
        web_scheme = "http"
        web_ssl_ctx = None
        if web_tls:
            try:
                from common.tls_utils import generate_self_signed_cert, create_tls_context
                certfile, keyfile, cafile = generate_self_signed_cert()
                web_ssl_ctx = create_tls_context(certfile, keyfile)
                web_scheme = "https"
                print(f"[*] Web TLS enabled ({web_scheme}://localhost:{self.web_port})")
            except Exception as e:
                # v5.0.3 (HIGH-6 FIX): fail-closed - same as TCP. 'TLS on' but the context
                # could not be built must NOT silently downgrade to plaintext (sessions
                # and PSK would travel in clear while the admin believes it is HTTPS).
                print(f"[!] FATAL: GIAMSAT_WEB_TLS_ENABLED=true but TLS setup failed: {e}")
                print("[!] Fix the TLS configuration, or set GIAMSAT_WEB_TLS_ENABLED=false to run WITHOUT HTTPS.")
                sys.exit(1)

        print(f"[*] Web UI: {web_scheme}://localhost:{self.web_port}")
        # v2.5.22: Waitress production server (multi-threaded) thay Flask dev server
        try:
            import waitress
            print(f"[*] Using Waitress production server (threads=16)")
            try:
                if web_ssl_ctx:
                    # v5.0.3 (LOW-2): Waitress has NO ssl_context parameter in any
                    # version (the old code always TypeError'd and fell back to the
                    # Werkzeug dev server). Terminate TLS ourselves by wrapping the
                    # listening socket, then hand the socket to Waitress via _sock.
                    import socket as _sock_mod
                    _lsock = _sock_mod.socket(_sock_mod.AF_INET, _sock_mod.SOCK_STREAM)
                    _lsock.setsockopt(_sock_mod.SOL_SOCKET, _sock_mod.SO_REUSEADDR, 1)
                    _lsock.bind((self.web_host, self.web_port))
                    _lsock.listen(2048)
                    _ssl_listener = web_ssl_ctx.wrap_socket(_lsock, server_side=True)
                    waitress.serve(app, _sock=_ssl_listener, url_scheme="https", threads=16)
                else:
                    waitress.serve(app, host=self.web_host, port=self.web_port, threads=16)
            except TypeError:
                # Older Waitress without _sock support -> last-resort Flask dev server
                if web_ssl_ctx:
                    print("[!] Waitress has no socket-override support - falling back to Flask dev server (HTTPS)")
                    app.run(host=self.web_host, port=self.web_port, debug=False, threaded=True,
                            ssl_context=web_ssl_ctx)
                else:
                    waitress.serve(app, host=self.web_host, port=self.web_port, threads=16)
        except ImportError:
            print("[!] Waitress not installed, falling back to Flask dev server")
            app.run(host=self.web_host, port=self.web_port, debug=False, threaded=True,
                    ssl_context=web_ssl_ctx)

    # ---- AI Assistant bridge (delegates to ai_providers.py) ----
    def _call_ai_assistant(self, question, provider, api_key, model="deepseek-chat"):
        return call_ai_assistant(question, provider, api_key, model)

    # ---- Telegram helpers ----
    def _send_telegram_message(self, message, chat_id=""):
        if not self.telegram_bot_token:
            print("[-] Telegram: No bot token configured")
            return False
        target_chat_id = chat_id or self.telegram_chat_id
        if not target_chat_id:
            try:
                target_chat_id = self._get_telegram_chat_id()
                if not target_chat_id:
                    print("[-] Telegram: No chat_id available. Send /start to the bot first.")
                    return False
                self.telegram_chat_id = target_chat_id
            except Exception as e:
                from common.logger import log_error
                log_error("Telegram: Cannot determine chat_id", exc=e)
                return False

        if len(message) > 4000:
            message = message[:4000] + "\n... (đã cắt bớt)"

        try:
            url = f"https://api.telegram.org/bot{self.telegram_bot_token}/sendMessage"
            escaped = _html.escape(message, quote=False)
            data = urllib.parse.urlencode({
                "chat_id": target_chat_id,
                "text": escaped,
                "parse_mode": "HTML"
            }).encode("utf-8")
            req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"})
            ctx = ssl.create_default_context()
            resp = urllib.request.urlopen(req, timeout=10, context=ctx)
            result = json.loads(resp.read().decode("utf-8"))
            if result.get("ok"):
                print(f"[*] Telegram: Message sent to {target_chat_id}")
                return True
            else:
                print(f"[-] Telegram: Send failed - {result}")
                return False
        except Exception as e:
            from common.logger import log_error
            log_error("Telegram send message failed", exc=e)
            return False

    def _get_telegram_chat_id(self):
        try:
            url = f"https://api.telegram.org/bot{self.telegram_bot_token}/getUpdates?limit=1"
            req = urllib.request.Request(url)
            ctx = ssl.create_default_context()
            resp = urllib.request.urlopen(req, timeout=10, context=ctx)
            result = json.loads(resp.read().decode("utf-8"))
            if result.get("ok") and result.get("result"):
                for update in result["result"]:
                    if "message" in update:
                        return str(update["message"]["chat"]["id"])
                    elif "channel_post" in update:
                        return str(update["channel_post"]["chat"]["id"])
            return ""
        except Exception:
            return ""

    def _send_email_smtp(self, to_email, subject, body):
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        smtp_server = os.environ.get("GIAMSAT_SMTP_HOST", "smtp-mail.outlook.com")
        smtp_port = int(os.environ.get("GIAMSAT_SMTP_PORT", "465"))
        smtp_user = os.environ.get("GIAMSAT_SMTP_USER", "it@example.com")
        smtp_pass = os.environ.get("GIAMSAT_SMTP_PASS", "")
        if not smtp_pass:
            print("[-] Email alert: SMTP password not configured (GIAMSAT_SMTP_PASS env var)")
            return
        from_email = smtp_user
        last_err = None
        # v4.10 FIX: port 465 = implicit SSL (SMTP_SSL); 587/25 = STARTTLS.
        # Previously SMTP()+starttls() on 465 deadlocked (server waits for TLS
        # ClientHello, client waits for banner) -> SMTPServerDisconnected timeout.
        for attempt in range(1, 3):
            server = None
            try:
                msg = MIMEMultipart()
                msg["From"] = from_email
                msg["To"] = to_email
                msg["Subject"] = subject
                msg.attach(MIMEText(body, "plain", "utf-8"))
                if smtp_port == 465:
                    server = smtplib.SMTP_SSL(smtp_server, smtp_port, timeout=20)
                else:
                    server = smtplib.SMTP(smtp_server, smtp_port, timeout=20)
                    server.starttls()
                server.login(smtp_user, smtp_pass)
                server.sendmail(from_email, [to_email], msg.as_string())
                server.quit()
                server = None
                # v4.10: record the send in the local sent-mail log (must never
                # fail the send or trigger the retry below -> duplicate emails)
                try:
                    from sent_mail_log import log_email
                    log_email(to_email, subject, body, source="alert", status="sent")
                except Exception:
                    pass
                try:
                    print(f"[📧] Email sent to {to_email}: {subject}")
                except Exception:
                    pass
                return
            except Exception as e:
                last_err = e
                # v4.10: record the failed attempt too
                try:
                    from sent_mail_log import log_email
                    log_email(to_email, subject, body, source="alert",
                              status="failed", error=str(e))
                except Exception:
                    pass
                if server:
                    try:
                        server.close()
                    except Exception:
                        pass
                if attempt == 1:
                    time.sleep(2)
        try:
            from common.logger import log_error
            log_error("SMTP email send failed", exc=last_err,
                      context={"to": to_email, "subject": subject,
                               "smtp_host": smtp_server, "smtp_port": smtp_port})
        except Exception:
            print(f"[-] Email alert failed to {to_email}: {last_err}")

    def stop(self):
        self._retention_running = False
        self.tcp_server.stop()
        self.syslog_server.stop()
        if self.syslog_tcp_server:
            try:
                self.syslog_tcp_server.stop()
            except Exception:
                pass
        if self.watchlist_matcher:
            try:
                self.watchlist_matcher.stop()
            except Exception:
                pass
        if self.netflow:
            try:
                self.netflow.stop()
            except Exception:
                pass
        if self.network_alerting:
            try:
                self.network_alerting.stop()
            except Exception:
                pass
        self.agentless.stop()
        self.cluster.stop()
        self.event_worker_pool.stop()
        self.db.close()


if __name__ == "__main__":
    core = ServerCore()
    core.start()