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
from datetime import datetime

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
        if db_backend == "elasticsearch" and HAS_ELASTICSEARCH:
            print("[*] Using Elasticsearch backend (search-optimized)")
            self.db = ElasticsearchBackend()
        elif db_backend == "postgres" and HAS_POSTGRES:
            print("[*] Using PostgreSQL backend (scalable)")
            self.db = PostgresDatabase()
            if not getattr(self.db, "_connected", False):
                print("[!] PostgreSQL unreachable - falling back to SQLite database.")
                self.db = DatabaseManager()
        else:
            if db_backend == "postgres" and not HAS_POSTGRES:
                print("[!] PostgreSQL requested but psycopg2 not available, falling back to SQLite")
            elif db_backend == "elasticsearch" and not HAS_ELASTICSEARCH:
                print("[!] Elasticsearch requested but elasticsearch-py not available, falling back to SQLite")
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
                print(f"[!] TLS setup failed: {e}, falling back to non-TLS")
                tls_enabled = False

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

        # v3.0: Cross-machine correlation engine (lateral movement, multi-host)
        self.correlation = ServerCorrelationEngine(db_manager=self.db, alerting_engine=self.alerting)

        # v3.0: Event Worker Pool (background DB writers)
        self.event_worker_pool = EventWorkerPool(
            event_queue=self.event_queue,
            db_manager=self.db,
            correlation_engine=self.correlation,
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
        print("[*] Background servers started (TCP:6666, Syslog:514)")
        # v4.5.5 SECURITY: agent HTTP endpoints (pending-commands/heartbeat/command-result/download)
        # transmit the agent PSK in plaintext over HTTP. Warn admins to use a TLS reverse proxy.
        if os.environ.get("GIAMSAT_AGENT_PSK", "").strip():
            print("[!] SECURITY: Agent HTTP endpoints (port 5000) are plaintext - the agent PSK is sent unencrypted. "
                  "Put the web server behind a TLS reverse proxy (Nginx/Caddy) for production.")

        # v3.0: Start event worker pool
        self.event_worker_pool.start()

        # v3.2: Start Sigma Auto-Updater
        if self.sigma_updater:
            self.sigma_updater.start()

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
            while self._retention_running:
                time.sleep(60)
                try:
                    offline_count = self.db.check_heartbeat_timeout(timeout_seconds=120)
                    if offline_count > 0:
                        print(f"[*] Heartbeat monitor: {offline_count} machine(s) marked offline")
                except Exception as e:
                    from common.logger import log_error
                    log_error("Heartbeat monitor check failed", exc=e)

        threading.Thread(target=heartbeat_monitor, daemon=True).start()

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
            return jsonify({
                "status": "healthy",
                "version": "2.5.2",
                "uptime_seconds": int(time.time()),
                "services": {
                    "web": "ok",
                    "tcp": "ok" if self.tcp_server and self.tcp_server.running else "stopped",
                    "database": db_status
                }
            })

        # Register all API route modules
        import api
        api.register_all_routes(app, self)

        print(f"[*] Web UI: http://localhost:{self.web_port}")
        # v2.5.22: Waitress production server (multi-threaded) thay Flask dev server
        try:
            import waitress
            print(f"[*] Using Waitress production server (threads=16)")
            waitress.serve(app, host=self.web_host, port=self.web_port, threads=16)
        except ImportError:
            print("[!] Waitress not installed, falling back to Flask dev server")
            app.run(host=self.web_host, port=self.web_port, debug=False, threaded=True)

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
                print(f"[📧] Email sent to {to_email}: {subject}")
                return
            except Exception as e:
                last_err = e
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
        self.agentless.stop()
        self.cluster.stop()
        self.event_worker_pool.stop()
        self.db.close()


if __name__ == "__main__":
    core = ServerCore()
    core.start()