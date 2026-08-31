"""
Ingest Server v1.0.0 for GIAM-SAT Server v3.0.0
Standalone TCP server that only handles agent connections and pushes events to the queue.

Purpose: Run multiple instances on different ports behind Nginx load balancer.
  - No Flask/Web dependency — lightweight, minimal memory
  - Shares EventQueue (Redis) with other ingest instances
  - Shares Database (PostgreSQL) for register/heartbeat/machine_config

Usage:
  python ingest_server.py --port 6667 --workers 250
  python ingest_server.py --port 6668 --workers 250
  python ingest_server.py --port 6669 --workers 250
  python ingest_server.py --port 6670 --workers 250

Architecture:
  1000 agents → Nginx TCP LB → 4 ingest servers (ports 6667-6670)
                                  ↓ push_event()
                              EventQueue (Redis)
                                  ↓ pop_batch()
                              EventWorkerPool (main server)
                                  ↓ batch insert
                              Database
"""
import os
import sys
import json
import time
import threading
import socket
import argparse

# Add server dir to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from db_manager import DatabaseManager
from db_postgres import PostgresDatabase, HAS_POSTGRES
from network_baseline import NetworkBaseline
from event_queue import EventQueue
from alerting_engine import AlertingEngine
from rate_limiter import IPRateLimiter

try:
    import ssl
    from tls_utils import create_tls_context, generate_self_signed_cert
    _HAS_TLS = True
except ImportError:
    _HAS_TLS = False


class IngestServer:
    """Lightweight TCP server for agent connections only."""

    def __init__(self, host="0.0.0.0", port=6667, db_manager=None,
                 event_queue=None, tls_enabled=False, psk=None,
                 max_agents=250, rate_limiter=None, tls_context=None):
        self.host = host
        self.port = port
        self.db = db_manager
        self.event_queue = event_queue
        self.tls_enabled = tls_enabled and _HAS_TLS
        # v4.10 (CRIT-6): accept a pre-built mTLS context (CERT_REQUIRED) from
        # the caller instead of always generating a CERT_NONE self-signed one.
        self.tls_context = tls_context
        self.max_agents = max_agents
        self.running = True
        self.clients = {}
        self.client_lock = threading.Lock()
        self.psk = psk or os.environ.get("GIAMSAT_AGENT_PSK", "")

        # v3.1: Rate limiter
        self.rate_limiter = rate_limiter or IPRateLimiter()
        self._rate_limiter_last_log = 0

        # Network baseline for NW-005 suppression
        self.network_baseline = None
        try:
            self.network_baseline = NetworkBaseline(db_manager=db_manager)
        except Exception:
            pass

        # Alerting engine
        self.alerting_engine = AlertingEngine() if False else None  # Skip alerting on ingest

        # Stats
        self.stats = {
            "connections": 0,
            "disconnections": 0,
            "events_pushed": 0,
            "errors": 0,
            "start_time": time.time(),
        }

    def start(self):
        """Start listening for agent connections."""
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((self.host, self.port))
        server_sock.listen(self.max_agents * 2)
        server_sock.settimeout(5)

        if self.tls_enabled:
            if self.tls_context:
                protocol = "mTLS"
            else:
                certfile, keyfile, _ = generate_self_signed_cert()
                if certfile and keyfile:
                    self.tls_context = create_tls_context(certfile, keyfile)
                    protocol = "TLS"
                else:
                    protocol = "plaintext"
        else:
            protocol = "plaintext"

        print(f"[*] Ingest Server #{self.port}: listening on {self.host}:{self.port} ({protocol}, max {self.max_agents} agents)")

        while self.running:
            try:
                client_sock, address = server_sock.accept()

                # v3.1: Rate limit connection
                if self.rate_limiter and not self.rate_limiter.check_connection(address[0]):
                    print(f"[!] Ingest #{self.port}: Rate limit - connection from {address[0]} blocked")
                    try:
                        client_sock.close()
                    except Exception:
                        pass
                    continue

                # Check agent count limit
                with self.client_lock:
                    if len(self.clients) >= self.max_agents:
                        print(f"[!] Ingest #{self.port}: Max agents ({self.max_agents}) reached, rejecting {address[0]}")
                        try:
                            reject = json.dumps({"type": "register_rejected", "reason": "Server at capacity"}) + "\n"
                            client_sock.sendall(reject.encode("utf-8"))
                            client_sock.close()
                        except Exception:
                            pass
                        continue

                # TLS wrap
                if self.tls_context:
                    try:
                        client_sock = self.tls_context.wrap_socket(client_sock, server_side=True)
                    except ssl.SSLError:
                        # v5.0.4 (MEDIUM-3): fail-CLOSED, never fall back to
                        # plaintext (mirrors tcp_server.py) - PSK/register/
                        # heartbeat/commands must not leak in the clear.
                        try:
                            client_sock.close()
                        except Exception:
                            pass
                        continue

                self.stats["connections"] += 1
                print(f"[+] Ingest #{self.port}: Agent connected from {address[0]}:{address[1]} ({len(self.clients)}/{self.max_agents})")

                t = threading.Thread(
                    target=self._handle_client,
                    args=(client_sock, address),
                    daemon=True
                )
                t.start()

            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    print(f"[-] Ingest #{self.port}: Accept error: {e}")

        try:
            server_sock.close()
        except Exception:
            pass
        print(f"[*] Ingest Server #{self.port}: Stopped")

    def stop(self):
        self.running = False

    def _handle_client(self, client_sock, address):
        buffer = ""
        machine_id = None
        hostname = None
        # v4.10 (CRITICAL-5): once a valid register proves the PSK, bind the
        # machine identity to this connection (mirrors tcp_server.py).
        authenticated_machine_id = None

        try:
            client_sock.settimeout(60)
            while self.running:
                try:
                    data = client_sock.recv(65536)
                    if not data:
                        break

                    buffer += data.decode("utf-8", errors="ignore")
                    while "\n" in buffer:
                        line, buffer = buffer.split("\n", 1)
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            msg = json.loads(line)
                            msg["source_ip"] = address[0]
                            msg_type = msg.get("type", "")

                            # v4.10 (CRITICAL-5): enforce PSK on ALL messages, not just register.
                            if self.psk:
                                # Unauthenticated connections may ONLY send a valid register.
                                if msg_type == "register":
                                    if self._handle_register(msg):
                                        authenticated_machine_id = msg.get("machine_id")
                                        machine_id = authenticated_machine_id
                                        hostname = msg.get("hostname", "Unknown")
                                        with self.client_lock:
                                            self.clients[machine_id] = (client_sock, address)
                                    continue  # register fully handled here
                                if authenticated_machine_id is None:
                                    print(f"[!] SECURITY: unauthenticated '{msg_type}' from {address[0]} ignored")
                                    continue
                                if msg.get("machine_id") != authenticated_machine_id:
                                    print(f"[!] SECURITY: machine_id mismatch '{msg.get('machine_id')}' vs '{authenticated_machine_id}' from {address[0]} ignored")
                                    continue
                            # else: Legacy mode, no PSK configured - accept (dev only)

                            self._route_message(msg)

                            if "machine_id" in msg:
                                machine_id = msg["machine_id"]
                                hostname = msg.get("hostname", "Unknown")
                                with self.client_lock:
                                    self.clients[machine_id] = (client_sock, address)

                        except json.JSONDecodeError:
                            pass

                except socket.timeout:
                    continue
                except Exception:
                    break

        finally:
            try:
                client_sock.close()
            except Exception:
                pass
            if machine_id:
                with self.client_lock:
                    self.clients.pop(machine_id, None)
                if self.db:
                    try:
                        self.db.machine_offline(machine_id)
                    except Exception:
                        pass
            self.stats["disconnections"] += 1
            print(f"[-] Ingest #{self.port}: Agent disconnected: {hostname or address[0]}")

    def _route_message(self, msg):
        """Route message to appropriate handler."""
        # v3.1: Rate limit events
        if self.rate_limiter and not self.rate_limiter.check_event(msg.get("source_ip", "0.0.0.0")):
            now = time.time()
            if now - self._rate_limiter_last_log > 300:
                stats = self.rate_limiter.get_stats()
                print(f"[!] Ingest #{self.port} Rate Limiter: blocked_c={stats['blocked_connections']}, "
                      f"blocked_e={stats['blocked_events']}, "
                      f"allowed_c={stats['allowed_connections']}, allowed_e={stats['allowed_events']}")
                self._rate_limiter_last_log = now
                self.rate_limiter.cleanup()
            return

        msg_type = msg.get("type", "")

        # Direct DB writes (critical, low volume)
        if msg_type == "register":
            self._handle_register(msg)
        elif msg_type == "heartbeat":
            self._handle_heartbeat(msg)
        elif msg_type == "machine_config":
            self._handle_machine_config(msg)
        elif msg_type == "response_result":
            self._handle_response(msg)
        elif msg_type == "user_info":
            self._handle_user_info(msg)
        elif msg_type == "network_anomaly":
            self._handle_network_anomaly(msg)
        # Queue-based writes (high volume)
        elif msg_type in ("windows_event", "linux_event", "linux_audit",
                          "fim", "fim_event", "network_traffic",
                          "threat_alert", "vulnerability_alert", "yara_alert",
                          "sca_event", "network_inspection", "baseline_report",
                          "process_event", "network_event", "module_load_event",
                          "process_injection", "process_access", "file_create_event",
                          "dns_query_event", "sysmon_event",
                          "memory_scan_event", "process_hollowing",
                          "registry_event", "cloud_event",
                          "cross_machine_threat"):
            if self.event_queue:
                self.event_queue.push_event(msg)
                self.stats["events_pushed"] += 1
        elif msg.get("action") and (msg.get("status") or msg.get("error")):
            self._handle_response(msg)

    def _handle_register(self, msg):
        # v4.5.5 SECURITY: fail-closed + constant-time PSK comparison
        if not self.psk:
            print("[!] Ingest: Registration rejected - no GIAMSAT_AGENT_PSK configured (fail-closed). "
                  "Set GIAMSAT_AGENT_PSK in .env AND set matching 'psk' in each agent's agent_config.json.")
            return False
        import hmac as _hmac
        agent_psk = msg.get("psk", "")
        if not _hmac.compare_digest(agent_psk, self.psk):
            print(f"[!] Ingest #{self.port}: Registration rejected - invalid/empty PSK from {msg.get('source_ip')}. "
                  "Set the agent's 'psk' (agent_config.json) to match GIAMSAT_AGENT_PSK.")
            return False
        if self.db:
            self.db.register_machine(
                msg.get("machine_id", ""),
                msg.get("hostname", ""),
                msg.get("source_ip", ""),
                msg.get("platform", "Windows"),
                msg.get("version", "1.0.0")
            )
        print(f"[+] Ingest #{self.port}: Registered {msg.get('hostname','?')} ({msg.get('machine_id','?')})")
        return True

    def _handle_heartbeat(self, msg):
        if self.db:
            self.db.insert_heartbeat(msg)
            mid = msg.get("machine_id", "")
            hostname = msg.get("hostname", "")
            self.db.track_machine_uptime(mid, hostname, boot_time=msg.get("boot_time"))

    def _handle_machine_config(self, msg):
        if self.db:
            machine_id = msg.get("machine_id", "")
            hostname = msg.get("hostname", "")
            config_data = {k: v for k, v in msg.items()
                           if k not in ("type", "machine_id", "hostname", "timestamp", "source_ip", "platform", "tls")}
            config_data["hostname"] = hostname
            self.db.save_machine_config(machine_id, config_data)
            # v4.10: mirror main TCP server - keep assets_computers / auto USB printer
            # assets in sync on ingest ports too (registration + disconnect cleanup).
            try:
                user_info = self.db.get_machine_user(machine_id) or {}
                self.db.insert_machine_config(machine_id, config_data, user_info)
            except Exception as _ae:
                print(f"[-] Ingest #{self.port}: insert_machine_config failed: {_ae}")

    def _handle_response(self, msg):
        if self.db:
            self.db.insert_response_result(msg)

    def _handle_user_info(self, msg):
        if self.db:
            self.db.save_machine_user(
                msg.get("machine_id", ""),
                msg.get("hostname", ""),
                msg.get("user_name", ""),
                msg.get("employee_id", ""),
                msg.get("email", "")
            )

    def _handle_network_anomaly(self, msg):
        """NW-005 suppression logic (same as tcp_server.py)."""
        subtype = msg.get("subtype", "anomaly")
        dst_ip = msg.get("dst_ip", "")

        if subtype == "new_country" and self.network_baseline:
            if dst_ip and not self.network_baseline.is_new_country(dst_ip):
                return  # Suppress known destination

        # Push to queue for worker processing
        if self.event_queue:
            self.event_queue.push_event(msg)
            self.stats["events_pushed"] += 1

    def get_stats(self):
        """Return server statistics."""
        with self.client_lock:
            active = len(self.clients)
        result = {
            "port": self.port,
            "active_agents": active,
            "max_agents": self.max_agents,
            "uptime_seconds": int(time.time() - self.stats["start_time"]),
            **{k: v for k, v in self.stats.items() if k != "start_time"},
        }
        # v3.1: Include rate limiter stats
        if self.rate_limiter:
            result["rate_limiter"] = self.rate_limiter.get_stats()
        return result


def main():
    parser = argparse.ArgumentParser(description="GIAM-SAT Ingest Server")
    parser.add_argument("--port", type=int, default=6667, help="TCP port to listen on")
    parser.add_argument("--workers", type=int, default=250, help="Max concurrent agents")
    parser.add_argument("--tls", action="store_true", help="Enable TLS encryption")
    args = parser.parse_args()

    # Database backend
    db_backend = os.environ.get("GIAMSAT_DB_BACKEND", "sqlite").lower()
    if db_backend == "postgres" and HAS_POSTGRES:
        db = PostgresDatabase()
        # v5.0.4 (ops bug): the ingest path previously used a PG object even when
        # the connect had failed - every insert silently no-op'd (data loss).
        if not getattr(db, "_connected", False):
            import traceback as _tb
            print("[!] Ingest server: PostgreSQL unreachable - falling back to SQLite. "
                  "Events will be stored in SQLite. /api/health reports db_fallback.")
            try:
                _logp = os.path.join(os.path.dirname(os.path.abspath(__file__)), "server_error.log")
                with open(_logp, "a", encoding="utf-8") as _f:
                    _f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} [INGEST-DB-FALLBACK] "
                             f"PG connect failed: {_tb.format_exc()}\n")
            except Exception:
                pass
            db = DatabaseManager()
    else:
        db = DatabaseManager()

    # Event queue (shared with main server via Redis or in-memory)
    event_queue = EventQueue()

    server = IngestServer(
        host="0.0.0.0",
        port=args.port,
        db_manager=db,
        event_queue=event_queue,
        max_agents=args.workers,
        tls_enabled=args.tls,
    )

    server.start()

    # Keep running
    try:
        while server.running:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
        server.stop()


if __name__ == "__main__":
    main()