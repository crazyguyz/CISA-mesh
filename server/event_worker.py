"""
Event Worker Pool v1.0.0 for GIAM-SAT Server v3.0.0
Background workers that pull events from Redis/in-memory queue
and batch-write them to the database.

Architecture:
  ┌─────────────┐     ┌──────────────┐     ┌──────────┐
  │ TCP Server  │ ──→ │ Event Queue  │ ──→ │ Workers  │ ──→ Database
  │ (thread/conn)│     │ (Redis/Mem)  │     │ (4-8)   │     │ (batch)
  └─────────────┘     └──────────────┘     └──────────┘     └──────────┘

Key metrics:
  - 1000 agents × 100 events/s = 100,000 events/s pushed to queue
  - 8 workers × 100 events/batch × 10 batches/s = 8,000 events/s written to DB
  - Queue buffer absorbs burst: 100K → 8K sustained throughput
"""
import threading
import time
import json
import os

from event_queue import (
    QUEUE_EVENTS, QUEUE_SYSMON, QUEUE_NETWORK,
    QUEUE_THREATS, QUEUE_HEARTBEATS, QUEUE_FIM, QUEUE_ALERTS
)
from anomaly_detector import AnomalyDetector


class EventWorkerPool:
    """Pool of background threads that pull events from queue and write to DB."""

    def __init__(self, event_queue, db_manager, correlation_engine=None,
                 num_workers=4, batch_size=100, poll_interval=0.5,
                 anomaly_detector=None):
        """
        Args:
            event_queue: EventQueue instance
            db_manager: DatabaseManager or PostgresDatabase instance
            correlation_engine: Optional ServerCorrelationEngine for cross-machine rules
            num_workers: Number of worker threads
            batch_size: Max events to pull per batch
            poll_interval: Seconds between poll cycles
        """
        self.queue = event_queue
        self.db = db_manager
        self.correlation = correlation_engine
        self.anomaly_detector = anomaly_detector or AnomalyDetector()
        self.num_workers = num_workers
        self.batch_size = batch_size
        self.poll_interval = poll_interval
        self.running = False
        self.workers = []
        self._stats = {
            "events_written": 0,
            "sysmon_written": 0,
            "network_written": 0,
            "threats_written": 0,
            "heartbeats_processed": 0,
            "fim_written": 0,
            "alerts_processed": 0,
            "total_batches": 0,
            "errors": 0,
        }
        self._stats_lock = threading.Lock()
        self._batch_buffer = []  # Buffer remaining events for next cycle
        self._buffer_lock = threading.Lock()
        self._anomaly_cooldowns = {}  # v4.3.4: {machine_id: last_alert_time}
        self._anomaly_cooldown_sec = 300  # 5 min between anomaly alerts per machine

        # Queue-to-handler mapping
        self._handlers = {
            QUEUE_EVENTS: self._handle_events,
            QUEUE_SYSMON: self._handle_sysmon,
            QUEUE_NETWORK: self._handle_network,
            QUEUE_THREATS: self._handle_threats,
            QUEUE_HEARTBEATS: self._handle_heartbeats,
            QUEUE_FIM: self._handle_fim,
            QUEUE_ALERTS: self._handle_alerts,
        }

        # Priority order: high-volume queues first
        self._queue_order = [
            QUEUE_SYSMON,    # Highest volume
            QUEUE_EVENTS,     # High volume
            QUEUE_NETWORK,    # High volume
            QUEUE_THREATS,    # Medium
            QUEUE_FIM,        # Medium
            QUEUE_HEARTBEATS, # Lower
            QUEUE_ALERTS,     # Low volume but high urgency
        ]

    def start(self):
        """Start all worker threads."""
        self.running = True
        # v3.9.17: Heartbeat Dead-man's Switch
        threading.Thread(target=self._deadman_checker, daemon=True, name="DeadmanChecker").start()
        print("[*] Heartbeat Dead-man's Switch enabled (300s timeout)")
        # v4.0: IOC Retro Sweeper
        threading.Thread(target=self._retro_ioc_sweeper, daemon=True, name="IOCSweeper").start()
        print("[*] IOC Retroactive Sweeper enabled (hourly)")
        for i in range(self.num_workers):
            t = threading.Thread(
                target=self._worker_loop,
                args=(i,),
                daemon=True,
                name=f"EventWorker-{i}"
            )
            t.start()
            self.workers.append(t)
        print(f"[*] Event Worker Pool: {self.num_workers} workers started (batch={self.batch_size})")

    def stop(self):
        """Stop all workers and flush remaining events."""
        self.running = False
        for t in self.workers:
            t.join(timeout=5)
        # Final flush
        self._flush_all()
        print(f"[*] Event Worker Pool: Stopped. Stats: {self.get_stats()}")

    def _worker_loop(self, worker_id):
        """Main worker loop: pull from queue → process → repeat.
        v3.5.8: Adaptive poll interval (50ms when busy, 500ms when idle for >10s)."""
        last_event_time = time.time()
        while self.running:
            processed_any = False
            for qname in self._queue_order:
                if not self.running:
                    break
                handler = self._handlers.get(qname)
                if not handler:
                    continue

                events = self.queue.pop_batch(qname, batch_size=self.batch_size)
                if events:
                    try:
                        handler(events)
                        processed_any = True
                        last_event_time = time.time()
                    except Exception as e:
                        with self._stats_lock:
                            self._stats["errors"] += 1
                        print(f"[-] EventWorker-{worker_id}: Error processing {qname}: {e}")

            if not processed_any:
                # Adaptive poll: 50ms if recently active, 500ms if idle > 10s
                idle_seconds = time.time() - last_event_time
                sleep_time = 0.05 if idle_seconds < 10 else self.poll_interval
                time.sleep(sleep_time)

    def _flush_all(self):
        """Flush all remaining events in all queues (called on shutdown)."""
        for qname in self._queue_order:
            handler = self._handlers.get(qname)
            if not handler:
                continue
            while True:
                events = self.queue.pop_batch(qname, batch_size=500)
                if not events:
                    break
                try:
                    handler(events)
                except Exception:
                    pass

    # =========================================================================
    # Event Handlers (batch write to DB)
    # =========================================================================

    def _handle_events(self, events):
        """Write events batch to database.
        Routes sca_event → sca_events table, network_anomaly → events table."""
        count = len(events)
        sca_events = []
        regular_events = []
        for e in events:
            if e.get("type") == "sca_event":
                sca_events.append(e)
            else:
                regular_events.append(e)
        # Write SCA events to sca_events table
        for e in sca_events:
            try:
                self.db.insert_sca_event(e)
            except Exception:
                pass
        # Write regular events
        if regular_events:
            if hasattr(self.db, 'batch_insert_events'):
                self.db.batch_insert_events(regular_events)
            else:
                for e in regular_events:
                    try:
                        self.db.insert_event(e)
                    except Exception:
                        pass
        with self._stats_lock:
            self._stats["events_written"] += count
            self._stats["total_batches"] += 1
        # Run correlation engine if available
        if self.correlation:
            for e in events:
                try:
                    # v5.0.3 (HIGH-2 FIX): process_event RETURNS a list of alerts but the
                    # result was discarded - CROSS-* rules burned CPU yet never produced a
                    # visible alert. Persist each triggered alert to threat_alerts (+ SSE).
                    alerts = self.correlation.process_event(e)
                    if alerts:
                        from datetime import datetime as _dt
                        for a in alerts:
                            if not a or not a.get("rule_id"):
                                continue
                            self.db.insert_threat_alert({
                                "machine_id": "CROSS",
                                "hostname": "Cross-Machine Correlation",
                                "rule_id": a.get("rule_id", ""),
                                "rule_name": a.get("rule_name", ""),
                                "description": a.get("description", ""),
                                "severity": a.get("severity", "HIGH"),
                                "timestamp": a.get("timestamp") or _dt.now().strftime("%Y-%m-%d %H:%M:%S"),
                                "mitre": a.get("mitre", ""),
                                "machines_involved": a.get("machines_involved", []),
                            })
                except Exception:
                    pass
        # v3.2: Anomaly detection
        for e in events:
            try:
                result = self.anomaly_detector.check(e)
                if result and result.get("trigger_alert"):
                    self._handle_anomaly_alert(e, result)
            except Exception:
                pass

    def _handle_sysmon(self, events):
        """Write sysmon events batch to database."""
        count = len(events)
        if hasattr(self.db, 'batch_insert_sysmon_events'):
            self.db.batch_insert_sysmon_events(events)
        else:
            for e in events:
                try:
                    self.db.insert_sysmon_event(e)
                except Exception:
                    pass
        with self._stats_lock:
            self._stats["sysmon_written"] += count
            self._stats["total_batches"] += 1

    def _handle_network(self, events):
        """Write network traffic batch to database."""
        count = len(events)
        if hasattr(self.db, 'batch_insert_network_traffic'):
            self.db.batch_insert_network_traffic(events)
        else:
            for e in events:
                try:
                    self.db.insert_network_traffic(e)
                except Exception:
                    pass
        with self._stats_lock:
            self._stats["network_written"] += count
            self._stats["total_batches"] += 1

    def _handle_threats(self, events):
        """Write threat alerts batch to database."""
        count = len(events)
        for e in events:
            try:
                self.db.insert_threat_alert(e)
            except Exception:
                pass
        with self._stats_lock:
            self._stats["threats_written"] += count
            self._stats["total_batches"] += 1

    def _handle_fim(self, events):
        """Write FIM events batch to database."""
        count = len(events)
        if hasattr(self.db, 'batch_insert_fim_events'):
            self.db.batch_insert_fim_events(events)
        else:
            for e in events:
                try:
                    self.db.insert_fim_event(e)
                except Exception:
                    pass
        with self._stats_lock:
            self._stats["fim_written"] += count
            self._stats["total_batches"] += 1

    def _handle_heartbeats(self, events):
        """Process heartbeats (update machine status, don't insert all)."""
        count = len(events)
        for e in events:
            try:
                self.db.insert_heartbeat(e)
            except Exception:
                pass
        with self._stats_lock:
            self._stats["heartbeats_processed"] += count

    def _retro_ioc_sweeper(self):
        """
        v4.0: Background IOC Retro Sweep.
        Every 60 minutes, queries historical network_traffic and events tables
        for any IPs/domains matching known malicious indicators (MISP, OTX).
        Generates retroactive threat_alerts for IOC matches found in past 30 days.
        """
        import time as _time
        _time.sleep(120)  # Wait 2 min for server to fully start
        while self.running:
            try:
                _time.sleep(3600)  # Once per hour
                if not self.db or not hasattr(self.db, 'conn'):
                    continue
                
                # Simple IOC list from MISP cache (if available)
                suspicious_ips = []
                suspicious_domains = []
                try:
                    misp_cache_path = os.environ.get(
                        "GIAMSAT_MISP_CACHE",
                        os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "misp_cache.json")
                    )
                    if os.path.exists(misp_cache_path):
                        with open(misp_cache_path, 'r') as f:
                            misp = json.load(f)
                        suspicious_ips = list(misp.get("malicious_ips", {}).keys())[:100]
                        suspicious_domains = list(misp.get("malicious_domains", {}).keys())[:50]
                except Exception:
                    pass

                if not suspicious_ips and not suspicious_domains:
                    continue

                # Portable 30-day cutoff (works on both SQLite and Postgres TEXT cols)
                from datetime import datetime as _dt, timedelta as _td
                cutoff = (_dt.now() - _td(days=30)).strftime("%Y-%m-%d %H:%M:%S")

                # Query network_traffic for matching IPs (last 30 days)
                if suspicious_ips:
                    for ip in suspicious_ips[:20]:  # Limit to avoid heavy load
                        try:
                            cursor = self.db.conn.execute(
                                "SELECT machine_id, hostname, dst_ip, dst_port, protocol, timestamp "
                                "FROM network_traffic WHERE dst_ip = ? "
                                "AND timestamp >= ? LIMIT 50",
                                (ip, cutoff)
                            )
                            rows = cursor.fetchall()
                            if rows:
                                alert = {
                                    "type": "threat_alert",
                                    "rule_id": "IOC-RETRO-001",
                                    "rule_name": "IOC Retro Match - Network",
                                    "severity": "HIGH",
                                    "description": f"IOC retrospective match: {len(rows)} historical connections to malicious IP {ip}",
                                    "confidence_score": 80,
                                    "timestamp": _time.strftime("%Y-%m-%d %H:%M:%S"),
                                    "machine_id": rows[0]["machine_id"] or "retro",
                                    "hostname": rows[0]["hostname"] or "retro-sweep",
                                }
                                self.db.insert_threat_alert(alert)
                                print(f"[IOC-SWEEP] Found {len(rows)} retro matches for IP {ip}")
                        except Exception:
                            pass

                # Query events/FIM for matching domains
                if suspicious_domains:
                    for domain in suspicious_domains[:10]:
                        try:
                            cursor = self.db.conn.execute(
                                "SELECT machine_id, hostname, description, timestamp "
                                "FROM events WHERE description LIKE ? "
                                "AND timestamp >= ? LIMIT 50",
                                (f"%{domain}%", cutoff)
                            )
                            rows = cursor.fetchall()
                            if rows:
                                alert = {
                                    "type": "threat_alert",
                                    "rule_id": "IOC-RETRO-002",
                                    "rule_name": "IOC Retro Match - Domain",
                                    "severity": "MEDIUM",
                                    "description": f"IOC retrospective match: {len(rows)} historical events referencing domain {domain}",
                                    "confidence_score": 65,
                                    "timestamp": _time.strftime("%Y-%m-%d %H:%M:%S"),
                                    "machine_id": rows[0]["machine_id"] or "retro",
                                    "hostname": rows[0]["hostname"] or "retro-sweep",
                                }
                                self.db.insert_threat_alert(alert)
                                print(f"[IOC-SWEEP] Found {len(rows)} retro matches for domain {domain}")
                        except Exception:
                            pass
            except Exception as e:
                print(f"[-] IOC Retro Sweep error: {e}")

    def _deadman_checker(self):
        """
        v3.9.17: Heartbeat Dead-man's Switch.
        Runs every 60s, checks all non-revoked machines with last_seen > 300s.
        If agent stopped without shutdown signal → CRITICAL alert.
        """
        time.sleep(30)
        # v4.5.1: track already-alerted machines to avoid repeat alerts every 60s
        alerted = {}
        while self.running:
            try:
                time.sleep(60)
                if not self.db:
                    continue
                deadline = time.time() - 300
                cursor = self.db.conn.execute(
                    "SELECT machine_id, hostname, last_seen, is_revoked FROM machines "
                    "WHERE is_revoked = 0"
                )
                dead_machines = []
                for row in cursor.fetchall():
                    mid = row["machine_id"]
                    hostname = row["hostname"]
                    last_seen_str = row["last_seen"] or ""
                    is_revoked = row["is_revoked"] or 0
                    if is_revoked:
                        continue
                    try:
                        from datetime import datetime as _dt, timezone
                        if last_seen_str:
                            # v5.0.4 (MEDIUM-1): PG returns a datetime object
                            # (TIMESTAMPTZ via psycopg2) - .endswith() crashed and
                            # the bare except skipped the machine, so the
                            # dead-man's switch never fired on PostgreSQL.
                            if isinstance(last_seen_str, _dt):
                                last_seen_dt = last_seen_str
                            elif last_seen_str.endswith("Z"):
                                last_seen_dt = _dt.strptime(
                                    last_seen_str[:19], "%Y-%m-%dT%H:%M:%S"
                                ).replace(tzinfo=timezone.utc)
                            else:
                                # SQLite CURRENT_TIMESTAMP stores UTC without tz marker
                                last_seen_dt = _dt.strptime(
                                    last_seen_str[:19], "%Y-%m-%d %H:%M:%S"
                                ).replace(tzinfo=timezone.utc)
                            last_seen_ts = last_seen_dt.timestamp()
                            if last_seen_ts < deadline:
                                offline_secs = int(time.time() - last_seen_ts)
                                dead_machines.append((mid, hostname, offline_secs))
                    except Exception:
                        pass
                for mid, hostname, offline_secs in dead_machines:
                    try:
                        # Skip if already alerted and still offline (prevent spam)
                        if alerted.get(mid):
                            continue
                        alerted[mid] = True
                        alert = {
                            "type": "threat_alert",
                            "machine_id": mid,
                            "hostname": hostname,
                            "rule_id": "HEARTBEAT-001",
                            "rule_name": "Agent Dead-man's Switch Triggered",
                            "severity": "CRITICAL",
                            "description": f"Agent {hostname} ({mid}) has been offline for {offline_secs}s "
                                           f"({offline_secs//60} minutes). No graceful shutdown signal received. "
                                           f"Possible agent kill, system crash, or network isolation.",
                            "confidence_score": 95,
                            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                        }
                        self.db.insert_threat_alert(alert)
                        print(f"[DEADMAN] CRITICAL: {hostname} ({mid}) offline {offline_secs}s")
                    except Exception:
                        pass
                # Clear alert state for machines that are back online
                online_ids = {m[0] for m in (dead_machines or [])}
                for mid in list(alerted.keys()):
                    if mid not in online_ids:
                        del alerted[mid]
            except Exception as e:
                print(f"[-] Deadman checker error: {e}")

    def _handle_alerts(self, events):
        """Process alert events (yara, vuln, baseline)."""
        count = len(events)
        for e in events:
            msg_type = e.get("type", "")
            try:
                if msg_type == "yara_alert":
                    self.db.insert_yara_alert(e)
                elif msg_type == "vulnerability_alert":
                    self.db.insert_vuln_alert(e)
                else:
                    self.db.insert_threat_alert(e)
            except Exception:
                pass
        with self._stats_lock:
            self._stats["alerts_processed"] += count

    def _handle_anomaly_alert(self, event, anomaly_result):
        """v3.2: Insert anomaly alert with cooldown (5min per machine)."""
        machine_id = event.get("machine_id", "")
        hostname = event.get("hostname", "")
        timestamp = event.get("timestamp", "")
        rule_id = f"ANOMALY-{int(time.time()) % 100000}"
        reason_text = " | ".join(anomaly_result["reasons"][:3])
        
        # v4.3.4: Cooldown - skip if same machine had an anomaly alert in last 5 min
        now = time.time()
        last = self._anomaly_cooldowns.get(machine_id, 0)
        if now - last < self._anomaly_cooldown_sec:
            return
        self._anomaly_cooldowns[machine_id] = now

        # Also dedup in DB: skip if same machine+description within cooldown
        try:
            if getattr(self.db, "backend_type", "") == "postgres":
                # PostgreSQL backend
                existing = self.db.conn.execute(
                    "SELECT id FROM threat_alerts WHERE machine_id=? AND description LIKE ? "
                    "AND received_at > NOW() - INTERVAL '10 minutes' LIMIT 1",
                    (machine_id, f"%{reason_text[:80]}%")
                ).fetchone()
            else:
                # SQLite backend
                existing = self.db.conn.execute(
                    "SELECT id FROM threat_alerts WHERE machine_id=? AND description LIKE ? "
                    "AND received_at > datetime('now', '-10 minutes') LIMIT 1",
                    (machine_id, f"%{reason_text[:80]}%")
                ).fetchone()
            if existing:
                return  # Already alerted
        except Exception:
            pass

        alert = {
            "machine_id": machine_id,
            "hostname": hostname,
            "rule_id": rule_id,
            "rule_name": "Anomaly Detection Alert",
            "severity": "HIGH" if anomaly_result["anomaly_score"] >= 75 else "MEDIUM",
            "description": reason_text,
            "timestamp": timestamp,
            "anomaly_score": anomaly_result["anomaly_score"],
        }
        try:
            self.db.insert_threat_alert(alert)
        except Exception:
            pass

    def get_stats(self):
        """Return worker pool statistics."""
        with self._stats_lock:
            return dict(self._stats)
