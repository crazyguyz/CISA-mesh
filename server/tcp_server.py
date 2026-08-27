"""
TCP Server for GIAM-SAT Server v1.6.0
Listens on port 6666 for agent connections with optional TLS encryption.
TLS is applied per-client after accept(), not on the listening socket.
"""
import os
import socket
import json
import threading
import time
import ssl
from datetime import datetime

try:
    from tls_utils import create_tls_context, generate_self_signed_cert, get_cert_dir
    _HAS_TLS = True
except ImportError:
    _HAS_TLS = False

from rate_limiter import IPRateLimiter
from command_signer import sign_command


class TCPServer(threading.Thread):
    def __init__(self, host="0.0.0.0", port=6666, db_manager=None, message_callback=None,
                 alerting_engine=None, tls_enabled=True, psk=None, network_baseline=None,
                 event_queue=None, rate_limiter=None, tls_context=None):
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self.db = db_manager
        self.message_callback = message_callback
        self.alerting_engine = alerting_engine
        self.tls_enabled = tls_enabled and _HAS_TLS
        # v4.10 (CRIT-6): server_core passes its mTLS context (CERT_REQUIRED).
        # Previously the context was created and thrown away; TCPServer generated
        # its own CERT_NONE context so mTLS never actually applied.
        self.tls_context = tls_context
        self.running = True
        # v2.6.5: Network baseline for NW-005 false positive reduction
        self.network_baseline = network_baseline
        # v3.0: Event queue (decouple TCP from DB)
        self.event_queue = event_queue
        # v3.1: Rate limiter (connection + event flood protection)
        self.rate_limiter = rate_limiter or IPRateLimiter()
        self._rate_limiter_stats_interval = 300  # Log stats every 5 min
        self._rate_limiter_last_log = 0
        self.clients = {}
        self.client_lock = threading.Lock()
        # v2.0.2 SECURITY: Agent pre-shared key for port 6666 auth
        self.psk = psk or os.environ.get("GIAMSAT_AGENT_PSK", "")
        if self.psk:
            print(f"[*] TCP Server: Agent PSK authentication enabled")
        else:
            print(f"[*] TCP Server: WARNING - No agent PSK set. Set GIAMSAT_AGENT_PSK in .env for production.")

    def run(self):
        # Tạo raw listening socket (KHÔNG TLS)
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((self.host, self.port))
        server_sock.listen(100)
        server_sock.settimeout(5)

        # Chuẩn bị TLS context để wrap từng client connection sau accept
        if self.tls_enabled:
            if self.tls_context:
                print(f"[*] TCP Server listening on {self.host}:{self.port} (mTLS ENCRYPTED)")
            else:
                certfile, keyfile, _ = generate_self_signed_cert()
                if certfile and keyfile:
                    self.tls_context = create_tls_context(certfile, keyfile)
                    print(f"[*] TCP Server listening on {self.host}:{self.port} (TLS ENCRYPTED - dev self-signed, no client cert check)")
                else:
                    self.tls_enabled = False
                    self.tls_context = None
                    print(f"[*] TCP Server listening on {self.host}:{self.port} (plaintext - cert gen failed)")
        else:
            print(f"[*] TCP Server listening on {self.host}:{self.port} (plaintext)")

        while self.running:
            try:
                client_sock, address = server_sock.accept()

                # v3.1: Rate limit connection
                if self.rate_limiter and not self.rate_limiter.check_connection(address[0]):
                    print(f"[!] Rate limit: connection from {address[0]} blocked")
                    try:
                        client_sock.close()
                    except Exception:
                        pass
                    continue

                # Wrap client connection with TLS nếu có context
                # Nếu TLS handshake fail → fallback plaintext (hỗ trợ agent cũ)
                conn_type = "plaintext"
                if self.tls_context:
                    try:
                        client_sock = self.tls_context.wrap_socket(client_sock, server_side=True)
                        conn_type = "TLS"
                    except Exception as e:
                        print(f"[!] SECURITY: rejected non-TLS connection from {address[0]} ({e})")
                        try:
                            client_sock.close()
                        except Exception:
                            pass
                        continue

                print(f"[+] Agent connected from {address[0]}:{address[1]} ({conn_type})")

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
                    print(f"[-] TCP Server error: {e}")

        try:
            server_sock.close()
        except Exception:
            pass
        print("[*] TCP Server stopped.")

    def _handle_client(self, client_sock, address):
        buffer = ""
        machine_id = None
        hostname = None
        # v4.5.4 SECURITY: bind machine identity to this connection after PSK validation
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
                        except json.JSONDecodeError:
                            print(f"[-] Invalid JSON from {address[0]}: {line[:100]}")
                            continue

                        msg_type = msg.get("type", "")
                        msg_machine_id = (msg.get("machine_id") or "").strip()

                        # v4.10 (MED-20): PSK is mandatory - the legacy "accept all
                        # without PSK" mode is removed. _handle_register already
                        # rejects registration when GIAMSAT_AGENT_PSK is unset.
                        if msg_type == "register":
                            if self._process_message(msg, address, client_sock):
                                authenticated_machine_id = msg_machine_id
                                machine_id = msg_machine_id
                                hostname = msg.get("hostname", "Unknown")
                                with self.client_lock:
                                    self.clients[machine_id] = (client_sock, address)
                            # else: rejected — stay unauthenticated
                            continue

                        if authenticated_machine_id is None:
                            print(f"[!] SECURITY: unauthenticated '{msg_type}' from {address[0]} ignored")
                            continue
                        if msg_machine_id != authenticated_machine_id:
                            print(f"[!] SECURITY: machine_id mismatch '{msg_machine_id}' vs '{authenticated_machine_id}' from {address[0]} ignored")
                            continue

                        self._process_message(msg, address, client_sock)
                        machine_id = authenticated_machine_id
                        with self.client_lock:
                            self.clients[machine_id] = (client_sock, address)

                except socket.timeout:
                    continue
                except ssl.SSLError:
                    break
                except Exception as e:
                    print(f"[-] Connection error from {address[0]}: {e}")
                    break

        finally:
            try:
                client_sock.close()
            except Exception:
                pass
            if machine_id and machine_id in self.clients:
                should_offline = False
                with self.client_lock:
                    current_sock, _ = self.clients.get(machine_id, (None, None))
                    # v4.5.4 FIX: only remove the entry if it is still THIS socket.
                    # Otherwise a stale connection's finally could delete a freshly
                    # reconnected agent's socket (race condition).
                    if current_sock is client_sock:
                        del self.clients[machine_id]
                        should_offline = True
                if should_offline and self.db:
                    self.db.machine_offline(machine_id)

            print(f"[-] Agent disconnected: {hostname or address[0]}")

    def _process_message(self, msg, address, client_sock):
        # v3.1: Rate limit events
        if self.rate_limiter and not self.rate_limiter.check_event(address[0]):
            # Log periodically to avoid spam
            now = time.time()
            if now - self._rate_limiter_last_log > self._rate_limiter_stats_interval:
                stats = self.rate_limiter.get_stats()
                print(f"[!] Rate Limiter Stats: blocked_c={stats['blocked_connections']}, "
                      f"blocked_e={stats['blocked_events']}, "
                      f"allowed_c={stats['allowed_connections']}, allowed_e={stats['allowed_events']}")
                self._rate_limiter_last_log = now
                self.rate_limiter.cleanup()
            return False

        msg_type = msg.get("type", "")
        msg["source_ip"] = address[0]

        if msg_type == "register":
            return self._handle_register(msg, client_sock)
        elif msg_type == "machine_config":
            self._handle_machine_config(msg)
        elif msg_type == "heartbeat":
            self._handle_heartbeat(msg)
        elif msg_type in ("windows_event", "linux_event", "linux_audit"):
            self._handle_event(msg)
        elif msg_type in ("fim", "fim_event"):
            self._handle_fim(msg)
        elif msg_type == "network_anomaly":
            self._handle_network_anomaly(msg)
        elif msg_type == "registry_event":
            self._handle_registry_event(msg)
        elif msg_type == "cloud_event":
            self._handle_cloud_event(msg)
        elif msg_type == "cross_machine_threat":
            self._handle_cross_machine_threat(msg)
        elif msg_type == "response_result":
            self._handle_response(msg)
        elif msg_type == "network_traffic":
            self._handle_network(msg)
        elif msg_type == "threat_alert":
            self._handle_threat_alert(msg)
        elif msg_type == "vulnerability_alert":
            self._handle_vuln_alert(msg)
        elif msg_type == "yara_alert":
            self._handle_yara_alert(msg)
        elif msg_type == "sca_event":
            self._handle_sca_event(msg)
        elif msg_type == "network_inspection":
            self._handle_network_inspection(msg)
        elif msg_type == "baseline_report":
            self._handle_baseline_report(msg)
        elif msg_type == "user_info":
            self._handle_user_info(msg)
        # v2.6.2: Sysmon event types from SysmonCollector
        # v4.6.4: + service_state_change (EID4 tampering), process_terminate (EID5),
        # driver_load (EID6 BYOVD), config_change (EID16/255), pipe_created/connected
        # (EID17/18), file_delete (EID23/26 ransomware), process_tampering (EID25
        # hollowing) - these were falling into 'Unknown message type' and dropped.
        elif msg_type in ("process_event", "network_event", "module_load_event",
                          "process_injection", "process_access", "file_create_event",
                          "dns_query_event", "sysmon_event",
                          "memory_scan_event", "process_hollowing",
                          "service_state_change", "process_terminate", "driver_load",
                          "config_change", "pipe_created", "pipe_connected",
                          "file_delete", "process_tampering"):
            self._handle_sysmon_event(msg)
        else:
            if msg.get("action") and (msg.get("status") or msg.get("error")):
                self._handle_response(msg)
            else:
                print(f"[?] Unknown message type: {msg_type} from {address[0]}")

        if self.message_callback:
            self.message_callback(msg)
        return True

    def _handle_register(self, msg, client_sock=None):
        """Validate agent PSK + issue per-machine enrollment token. Returns True if accepted."""
        # v4.5.5 SECURITY: fail-closed + constant-time PSK comparison
        if not self.psk:
            print("[!] REGISTRATION REJECTED: no GIAMSAT_AGENT_PSK configured on server (fail-closed). "
                  "Set GIAMSAT_AGENT_PSK in .env AND set matching 'psk' in each agent's agent_config.json.")
            return False
        machine_id = str(msg.get("machine_id", "") or "").strip()
        hostname = msg.get("hostname", "")
        ip = msg.get("source_ip", "")
        # v5.0.3 (LOW-9): validate the machine_id BEFORE trusting it anywhere
        from agent_auth import verify_agent_psk, validate_machine_id, sanitize_hostname
        if not validate_machine_id(machine_id):
            print(f"[!] REGISTRATION REJECTED: invalid machine_id '{machine_id[:64]}' from {ip}")
            return False
        if not verify_agent_psk(msg.get("psk", ""), self.psk, machine_id):
            print(f"[!] REGISTRATION REJECTED: {hostname} from {ip} - "
                  "Invalid/empty PSK. Set the agent's 'psk' (agent_config.json) to match "
                  "GIAMSAT_AGENT_PSK (or the per-machine secret in GIAMSAT_PER_MACHINE_PSK[_FILE]).")
            return False
        # v5.0.3 (LOW-9): strip HTML/control chars from agent-supplied hostname
        hostname = sanitize_hostname(hostname)
        platform = msg.get("platform", "Windows")
        version = msg.get("version", "1.0.0")
        tls = msg.get("tls", False)
        if self.db:
            self.db.register_machine(machine_id, hostname, ip, platform, version)
        # v4.5.4: issue per-machine enrollment token + send ack to agent
        issued_token = ""
        if self.db and hasattr(self.db, "issue_enrollment_token"):
            try:
                issued_token = self.db.issue_enrollment_token(machine_id)
            except Exception:
                pass
        if issued_token and client_sock:
            try:
                ack = json.dumps({"type": "register_ack", "enrollment_token": issued_token}) + "\n"
                client_sock.sendall(ack.encode("utf-8"))
            except Exception:
                pass
        print(f"[+] Registered: {hostname} ({machine_id}) from {ip} [{platform}] (TLS: {tls})")
        return True

    def _handle_heartbeat(self, msg):
        if self.db:
            self.db.insert_heartbeat(msg)
            # v3.3.5: Sync real agent version from heartbeat
            mid = msg.get("machine_id", "")
            # v5.0.3 (LOW-9): sanitize agent-supplied hostname at every boundary
            try:
                from agent_auth import sanitize_hostname
                hostname = sanitize_hostname(msg.get("hostname", ""))
            except Exception:
                hostname = msg.get("hostname", "")
            agent_version = msg.get("version", "")
            if agent_version:
                try:
                    self.db.conn.execute(
                        "UPDATE machines SET version=? WHERE machine_id=?",
                        (agent_version, mid)
                    )
                    self.db.conn.commit()
                except Exception:
                    pass
            # v2.3.0: Track uptime and check 24h threshold
            uptime_hours, should_alert = self.db.track_machine_uptime(mid, hostname, boot_time=msg.get("boot_time"))
            if should_alert:
                print(f"[!] UPTIME ALERT: {hostname} running {uptime_hours:.1f}h continuously!")
                # Trigger uptime alert callback if available
                if hasattr(self, '_uptime_alert_callback') and self._uptime_alert_callback:
                    try:
                        self._uptime_alert_callback(mid, hostname, uptime_hours)
                    except Exception as e:
                        print(f"[-] Uptime alert callback error: {e}")

            # v3.9.2: Check pending group policies and push to agent
            # v3.9.3 FIX: Push policies in background thread to avoid blocking
            # the heartbeat handler (send_command may block TCP socket for 5s).
            try:
                # Push new/updated policies
                pending = self.db.get_pending_policies_for_machine(mid)
                if pending:
                    threading.Thread(
                        target=self._push_pending_policies,
                        args=(mid, hostname, pending),
                        daemon=True
                    ).start()

                # v3.9.3: Push removal for disabled/deleted policies
                removal = self.db.get_removal_policies_for_machine(mid)
                if removal:
                    threading.Thread(
                        target=self._push_removal_policies,
                        args=(mid, hostname, removal),
                        daemon=True
                    ).start()
            except Exception as e:
                print(f"[-] Policy check error for {hostname}: {e}")

    def _handle_event(self, msg):
        # v3.0: Push to event queue instead of direct DB write
        if self.event_queue:
            self.event_queue.push_event(msg)
        elif self.db:
            self.db.insert_event(msg)  # Fallback when queue not available

    def _handle_fim(self, msg):
        if self.event_queue:
            self.event_queue.push_event(msg)
        elif self.db:
            self.db.insert_fim_event(msg)

    def _handle_response(self, msg):
        if self.db:
            self.db.insert_response_result(msg)
            # v2.5.11: Handle message reply from agent
            if msg.get("action") == "show_message" and msg.get("msg_replied"):
                try:
                    self.db.conn.execute(
                        "UPDATE messages SET reply=?, status='replied', replied_at=? "
                        "WHERE msg_id=? AND machine_id=? AND (reply IS NULL OR reply='')",
                        (msg.get("msg_reply", "")[:500],
                         __import__('datetime').datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                         msg.get("msg_id", ""), msg.get("machine_id", "")))
                    self.db.conn.commit()
                    print(f"[*] Message reply saved: {msg.get('msg_id')} from {msg.get('hostname','?')}")
                except Exception as e:
                    print(f"[-] Failed to save message reply: {e}")
            if msg.get("action") == "agent_update":
                mid = msg.get("machine_id", "")
                hn = msg.get("hostname", "")
                st = "success" if msg.get("status") == "success" else "failed"
                out = msg.get("output") or msg.get("error", "")
                self.db.insert_agent_update_log(mid, hn, "", "", st, out, "push")

            # v3.9.2: Handle policy enforcement results (TCP path - legacy; the primary
            # path is HTTP /api/agent/command-result in api_agent_commands.py)
            action = msg.get("action", "")
            if action and action.startswith(("apply_block_", "remove_block_")):
                exec_id = msg.get("exec_id", "")
                _mid = msg.get("machine_id", "")
                try:
                    import re as _re
                    _m = _re.match(r"^policy_rm_(\d+)_", exec_id or "")
                    if _m:
                        if msg.get("status") == "completed" and _mid:
                            self.db.mark_policy_removal_sent(int(_m.group(1)), _mid)
                            print(f"[POLICY] Removal result on {_mid}: policy={_m.group(1)} done")
                    else:
                        _m = _re.match(r"^policy_(\d+)_", exec_id or "")
                        if _m and _mid:
                            _pst = "applied" if msg.get("status") == "completed" else "failed"
                            self.db.set_policy_machine_status(
                                int(_m.group(1)), _mid, _pst,
                                (msg.get("output") or msg.get("error", ""))[:500])
                            print(f"[POLICY] Apply result on {_mid}: policy={_m.group(1)} -> {_pst}")
                except Exception as e:
                    print(f"[-] POLICY: result parse error: {e}")

    def _handle_network(self, msg):
        if self.event_queue:
            self.event_queue.push_event(msg)
        elif self.db:
            self.db.insert_network_traffic(msg)
        # v4.10 (MED-21): removed per-message print - network traffic is very
        # high-frequency and this spammed the console / blocked on I/O.

    def _handle_threat_alert(self, msg):
        if self.event_queue:
            self.event_queue.push_event(msg)
        elif self.db:
            self.db.insert_threat_alert(msg)
        print(f"[!] THREAT ALERT [{msg.get('severity','?')}] {msg.get('rule_name','')} from {msg.get('hostname','')}: {msg.get('description','')}")
        if self.alerting_engine:
            self.alerting_engine.send_alert(msg)

    def _handle_vuln_alert(self, msg):
        if self.event_queue:
            self.event_queue.push_event(msg)
        elif self.db:
            self.db.insert_vuln_alert(msg)
        print(f"[!] VULN [{msg.get('severity','?')}] {msg.get('cve','')} on {msg.get('hostname','')}")
        if self.alerting_engine:
            self.alerting_engine.send_alert(msg)

    def _handle_network_inspection(self, msg):
        if self.event_queue:
            self.event_queue.push_event(msg)
        elif self.db:
            self.db.insert_network_inspection(msg)

    def _handle_yara_alert(self, msg):
        if self.event_queue:
            self.event_queue.push_event(msg)
        elif self.db:
            self.db.insert_yara_alert(msg)
        print(f"[!] YARA on {msg.get('hostname','')}: {msg.get('rule_name','')}")
        if self.alerting_engine:
            self.alerting_engine.send_alert(msg)

    def _handle_network_anomaly(self, msg):
        """Handle network anomaly event from traffic analyzer.
        Inserts into both events table AND threat_alerts so Attack Overview can see it.
        v2.6.5: Uses network_baseline to suppress NW-005 "new_country" false positives
                for IPs/countries that have been seen in the last 14 days of normal traffic.
        """
        subtype = msg.get("subtype", "anomaly")
        severity = msg.get("severity", "HIGH")
        description = msg.get("description", "")
        dst_ip = msg.get("dst_ip", "")

        # v2.6.5: NW-005 False Positive Reduction via Network Baseline
        if subtype == "new_country" and self.network_baseline:
            if dst_ip and not self.network_baseline.is_new_country(dst_ip):
                # This country/IP has been seen in the 14-day baseline → suppress alert
                print(f"[*] NW-005 Suppressed: {dst_ip} is in network baseline (known destination)")
                return  # Skip inserting threat alert

        # Map anomaly subtypes to rule IDs
        rule_map = {
            "port_scan": ("NW-ANOMALY-001", "Port Scan Detected"),
            "syn_flood": ("NW-ANOMALY-002", "SYN Flood Detected"),
            "dns_exfiltration": ("NW-ANOMALY-003", "DNS Exfiltration/Tunneling"),
            "volume_spike": ("NW-ANOMALY-004", "Traffic Volume Spike"),
            "new_country": ("NW-ANOMALY-005", "New Country Connection"),
        }
        rule_id, rule_name = rule_map.get(subtype, ("NW-ANOMALY-000", f"Network Anomaly: {subtype}"))

        if self.db:
            # Insert into events table (for detailed log) — always log, even if suppressed above
            self.db.insert_event({
                "machine_id": msg.get("machine_id", ""),
                "hostname": msg.get("hostname", ""),
                "type": "windows_event",
                "subtype": "network_anomaly",
                "event_id": subtype,
                "event_type": "WARNING",
                "source": "NetworkTrafficAnalyzer",
                "computer": msg.get("hostname", ""),
                "user": "SYSTEM",
                "category": subtype,
                "time": msg.get("timestamp", ""),
                "description": description,
                "raw_data": json.dumps(msg, ensure_ascii=False),
            })
            # Insert into threat_alerts (so Attack Overview can see it)
            self.db.insert_threat_alert({
                "machine_id": msg.get("machine_id", ""),
                "hostname": msg.get("hostname", ""),
                "rule_id": rule_id,
                "rule_name": rule_name,
                "severity": severity,
                "description": description,
                "timestamp": msg.get("timestamp", ""),
                "source_ip": dst_ip,
            })
        print(f"[!] NETWORK ANOMALY [{severity}] {subtype} - {description}")
        if self.alerting_engine:
            self.alerting_engine.send_alert(msg)

    def _handle_registry_event(self, msg):
        """Handle registry change event from registry collector."""
        if self.db:
            self.db.insert_event({
                "machine_id": msg.get("machine_id", ""),
                "hostname": msg.get("hostname", ""),
                "type": "windows_event",
                "subtype": "registry_event",
                "event_id": msg.get("subtype", "registry"),
                "event_type": "WARNING",
                "source": "RegistryCollector",
                "computer": msg.get("hostname", ""),
                "user": "SYSTEM",
                "category": msg.get("category", ""),
                "time": msg.get("timestamp", ""),
                "description": f"{msg.get('description','')}: {msg.get('details','')}",
                "raw_data": json.dumps(msg, ensure_ascii=False),
            })
        print(f"[!] REGISTRY CHANGE [{msg.get('severity','?')}] {msg.get('key_path','')} - {msg.get('description','')}")

    def _handle_cloud_event(self, msg):
        """Handle cloud/Docker/K8s event from cloud collector."""
        if self.db:
            self.db.insert_event({
                "machine_id": msg.get("machine_id", ""),
                "hostname": msg.get("hostname", ""),
                "type": "windows_event",
                "subtype": msg.get("subtype", "cloud_event"),
                "event_id": "cloud",
                "event_type": "INFO",
                "source": "CloudCollector",
                "computer": msg.get("hostname", ""),
                "user": "SYSTEM",
                "category": msg.get("subtype", ""),
                "time": msg.get("timestamp", ""),
                "description": f"{msg.get('resource','')}: {msg.get('description','')}",
                "raw_data": json.dumps(msg, ensure_ascii=False),
            })
        print(f"[*] CLOUD EVENT [{msg.get('severity','?')}] {msg.get('subtype','')} - {msg.get('resource','')}")

    def _handle_cross_machine_threat(self, msg):
        """Handle cross-machine correlation threat alert."""
        if self.db:
            self.db.insert_threat_alert(msg)
        print(f"[!] CROSS-MACHINE THREAT [{msg.get('severity','?')}] {msg.get('rule_name','')}: {msg.get('description','')[:200]}")
        if self.alerting_engine:
            self.alerting_engine.send_alert(msg)

    def _handle_sca_event(self, msg):
        if self.event_queue:
            self.event_queue.push_event(msg)
        elif self.db:
            try: self.db.insert_sca_event(msg)
            except AttributeError: pass

    def _handle_baseline_report(self, msg):
        """Handle adaptive baseline report from agent."""
        anomaly_score = msg.get("anomaly_score", 0)
        deviations = msg.get("deviations", [])
        if anomaly_score >= 50:  # Significant deviation
            alert = {
                "machine_id": msg.get("machine_id", ""),
                "hostname": msg.get("hostname", ""),
                "rule_id": "BL-ADAPTIVE-001",
                "rule_name": "Adaptive Baseline Deviation",
                "severity": "HIGH" if anomaly_score >= 80 else "MEDIUM",
                "description": f"Anomaly score: {anomaly_score}/100. Deviations: " +
                              "; ".join(d.get("description", "") for d in deviations[:3]),
                "timestamp": msg.get("timestamp", ""),
                "type": "baseline_report_alert",
            }
            if self.event_queue:
                self.event_queue.push_event(alert)
            elif self.db:
                self.db.insert_threat_alert(alert)
        print(f"[*] Baseline report from {msg.get('hostname','?')}: score={anomaly_score}, deviations={len(deviations)}")

    def _handle_sysmon_event(self, msg):
        """v3.0: Push Sysmon events to queue for batch processing by workers."""
        if self.event_queue:
            self.event_queue.push_event(msg)
        elif self.db:
            try:
                self.db.insert_sysmon_event(msg)
            except AttributeError:
                self.db.insert_event({
                    "machine_id": msg.get("machine_id", ""),
                    "hostname": msg.get("hostname", ""),
                    "type": "windows_event",
                    "subtype": msg.get("type", "sysmon"),
                    "event_id": msg.get("sysmon_event_id", 0),
                    "event_type": "INFO",
                    "source": "Sysmon",
                    "computer": msg.get("hostname", ""),
                    "user": msg.get("user", "SYSTEM"),
                    "category": msg.get("type", ""),
                    "time": msg.get("timestamp", ""),
                    "description": json.dumps(msg, ensure_ascii=False, default=str)[:1000],
                    "raw_data": json.dumps(msg, ensure_ascii=False, default=str),
                })
        evt_id = msg.get("sysmon_event_id", 0)
        sev = msg.get("severity", "INFO")
        desc = msg.get("description", msg.get("suspicion_reason", ""))
        proc = msg.get("process_name", "")
        # v4.13 (P2): don't spam the console with empty sysmon messages
        # (no EID, no process name, no description - typically junk/legacy).
        if evt_id or proc or desc:
            print(f"[SYSMON] EID {evt_id} [{sev}] {proc or '?'} - {desc}")

    def _handle_user_info(self, msg):
        """v2.2.0: Save user info reported by agent."""
        if self.db:
            machine_id = msg.get("machine_id", "")
            hostname = msg.get("hostname", "")
            user_name = msg.get("user_name", "")
            employee_id = msg.get("employee_id", "")
            email = msg.get("email", "")
            branch = msg.get("branch", "") or ""
            ux = msg.get("user_extra") or {}
            if not branch and isinstance(ux, dict):
                branch = ux.get("branch", "")
            self.db.save_machine_user(machine_id, hostname, user_name, employee_id, email, branch)
            print(f"[*] User info: {user_name} ({employee_id}) on {hostname}")

    def _handle_machine_config(self, msg):
        if self.db:
            machine_id = msg.get("machine_id", "")
            hostname = msg.get("hostname", "")
            config_data = {k: v for k, v in msg.items()
                           if k not in ("type", "machine_id", "hostname", "timestamp", "source_ip", "platform", "tls")}
            # v4.5.1: keep hostname for asset management
            config_data["hostname"] = hostname
            result = self.db.save_machine_config(machine_id, config_data)
            if result.get("is_first_config"):
                print(f"[+] First hardware config saved for {hostname}")
            elif result.get("has_changes"):
                print(f"[!] Hardware changed for {hostname}: {len(result.get('diffs',[]))} diffs")
            
            # v4.4: Asset Management - insert into assets tables
            try:
                user_info = self.db.get_machine_user(machine_id) or {}
                asset_result = self.db.insert_machine_config(machine_id, config_data, user_info)
                if asset_result.get("changes"):
                    for ch in asset_result["changes"]:
                        ch_type = ch.get("type", "")
                        detail = ch.get("details", {})
                        if ch_type == "hardware_changed":
                            pc = detail.get("computer", hostname)
                            cpu_chg = detail.get("cpu_changed", "")
                            ram_chg = detail.get("ram_changed", "")
                            disk_chg = detail.get("disks_changed", "")
                            parts = []
                            if cpu_chg: parts.append(f"CPU: {cpu_chg}")
                            if ram_chg: parts.append(f"RAM: {ram_chg}")
                            if disk_chg: parts.append(f"Disk: {disk_chg}")
                            desc = "; ".join(parts) if parts else "Hardware hash changed"
                            print(f"[!] ASSET ALERT [hardware_changed] {pc}: {desc}")
                        elif ch_type == "monitor_reassigned":
                            print(f"[!] ASSET ALERT [monitor_reassigned] {detail.get('monitor','')}: "
                                  f"{detail.get('from_computer','?')} → {detail.get('to_computer','?')}")
                        elif ch_type == "monitor_disconnected":
                            print(f"[!] ASSET ALERT [monitor_disconnected] {detail.get('computer','?')}: "
                                  f"{detail.get('monitor','?')} removed")
                        elif ch_type == "printer_disconnected":
                            print(f"[!] ASSET ALERT [printer_disconnected] {detail.get('computer','?')}: "
                                  f"{detail.get('printer','?')} no longer connected")
            except Exception as e:
                print(f"[-] Asset management error: {e}")
                import traceback
                traceback.print_exc()

    def _push_pending_policies(self, mid, hostname, pending):
        """v5.0.2: queue apply_* into the commands table (HTTP-poll fallback so OFFLINE
        machines still get it) + best-effort TCP push when online. exec_id is deterministic
        (policy_<id>_<machine>) so repeated heartbeats are idempotent; per-machine tracking
        stops re-pushing once the machine reports 'applied'."""
        import json as _json
        for policy in pending:
            try:
                policy_type = policy.get("policy_type", "")
                try:
                    config = _json.loads(policy.get("config_json", "{}"))
                except Exception:
                    config = {}
                exec_id = f"policy_{policy.get('id')}_{mid}"
                config_str = _json.dumps(config, ensure_ascii=False)
                cmd_data = {
                    "action": f"apply_{policy_type}",
                    "command": config_str,
                    "exec_id": exec_id,
                    "params": {"policy_id": policy.get("id")},
                }
                # Queue for HTTP poll (exec_id UNIQUE -> duplicate add is a no-op)
                try:
                    self.db.add_command(mid, f"apply_{policy_type}", config_str, exec_id)
                except Exception:
                    pass
                if self.send_command(mid, cmd_data):
                    print(f"[POLICY] Pushed {policy_type} to {hostname} (policy_id={policy.get('id')})")
                else:
                    print(f"[-] POLICY: TCP push failed {policy_type} to {hostname} (queued for HTTP poll)")
            except Exception as e:
                print(f"[-] POLICY: Error pushing policy {policy.get('id')}: {e}")

    def _push_removal_policies(self, mid, hostname, removal):
        """v5.0.2: queue remove_* via commands table + TCP push. The machine's 'applied'
        row is dropped when the agent reports completion (api_agent_commands)."""
        import json as _json
        for policy in removal:
            try:
                policy_type = policy.get("policy_type", "")
                try:
                    config = _json.loads(policy.get("config_json", "{}"))
                except Exception:
                    config = {}
                exec_id = f"policy_rm_{policy.get('id')}_{mid}"
                config_str = _json.dumps(config, ensure_ascii=False)
                cmd_data = {
                    "action": f"remove_{policy_type}",
                    "command": config_str,
                    "exec_id": exec_id,
                    "params": {"policy_id": policy.get("id")},
                }
                try:
                    self.db.add_command(mid, f"remove_{policy_type}", config_str, exec_id)
                except Exception:
                    pass
                if self.send_command(mid, cmd_data):
                    print(f"[POLICY] Removal pushed: {policy_type} to {hostname} (policy_id={policy.get('id')})")
                else:
                    print(f"[-] POLICY: Removal queued for {hostname} (HTTP poll)")
            except Exception as e:
                print(f"[-] POLICY: Error pushing removal {policy.get('id')}: {e}")

    def send_command(self, machine_id, command_data):
        """Send a command to a connected agent via its existing TCP socket.
        Returns True if command was sent successfully, False if agent is offline
        or socket is dead.
        
        NOTE: Does NOT insert into commands table — that is the caller's responsibility.
        Callers should use db.add_command() BEFORE calling this method,
        then mark the command as 'sent' or 'pending' based on the return value."""
        with self.client_lock:
            if machine_id in self.clients:
                client_sock, address = self.clients[machine_id]
                try:
                    # Set short timeout to avoid blocking on dead sockets
                    old_timeout = client_sock.gettimeout()
                    client_sock.settimeout(5)
                    # v4.5.4: sign command before delivery
                    cmd_str = json.dumps(sign_command(command_data), ensure_ascii=False) + "\n"
                    client_sock.sendall(cmd_str.encode("utf-8"))
                    client_sock.settimeout(old_timeout)
                    print(f"[>] TCP push OK: {command_data.get('action', '')} to {machine_id} ({address[0]})")
                    return True
                except (socket.error, BrokenPipeError, ConnectionResetError, OSError) as e:
                    print(f"[-] TCP push FAIL to {machine_id} ({address[0]}): {e}. Removing stale client.")
                    # Remove dead socket from clients so future broadcasts skip it immediately
                    try:
                        client_sock.close()
                    except Exception:
                        pass
                    # v4.10 FIX: client_lock is a plain Lock (not RLock) - re-acquiring
                    # it here deadlocked the whole server on the first dead socket.
                    if machine_id in self.clients:
                        del self.clients[machine_id]
                    if self.db:
                        try:
                            self.db.machine_offline(machine_id)
                        except Exception:
                            pass
                    return False
                except Exception as e:
                    print(f"[-] TCP push FAIL to {machine_id}: {e}")
                    return False
            else:
                print(f"[-] TCP push FAIL: Agent {machine_id} not connected (offline)")
                return False

    def disconnect_client(self, machine_id):
        with self.client_lock:
            if machine_id in self.clients:
                client_sock, address = self.clients[machine_id]
                try: client_sock.close()
                except Exception: pass
                del self.clients[machine_id]
                print(f"[-] Force disconnected: {machine_id} ({address[0]})")
                if self.db: self.db.machine_offline(machine_id)
                return True
        return False

    def stop(self):
        self.running = False