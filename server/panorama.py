"""
GIAM-SAT Server Panoramic Monitor v2.5.2
Collects server resource metrics: CPU, RAM, Disk, Network, DB stats.
Requires: pip install psutil (fallback to basic info if not installed)
"""
import os
import time
import threading

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    print("[!] psutil not installed. Server resource stats will be limited.")
    print("    Install: pip install psutil")


class PanoramaCollector:
    """Collects server health & resource metrics."""

    def __init__(self, db_manager=None):
        self.db = db_manager
        self._start_time = time.time()
        self._prev_net_io = None
        self._prev_net_time = None
        self._prev_disk_io = None
        self._prev_disk_time = None
        self._lock = threading.Lock()

    def get_resources(self):
        """Get CPU, RAM, Disk, Network stats."""
        result = {
            "cpu_percent": 0.0,
            "cpu_count": os.cpu_count() or 0,
            "ram_total_gb": 0.0,
            "ram_used_gb": 0.0,
            "ram_percent": 0,
            "disk_total_gb": 0.0,
            "disk_used_gb": 0.0,
            "disk_percent": 0,
            "net_bytes_sent": 0,
            "net_bytes_recv": 0,
            "net_speed_mbps": 0.0,
            "uptime_seconds": int(time.time() - self._start_time),
            "psutil_available": HAS_PSUTIL,
        }

        if HAS_PSUTIL:
            try:
                result["cpu_percent"] = round(psutil.cpu_percent(interval=0.5), 1)
                result["cpu_count"] = psutil.cpu_count(logical=True)
                mem = psutil.virtual_memory()
                result["ram_total_gb"] = round(mem.total / (1024 ** 3), 1)
                result["ram_used_gb"] = round(mem.used / (1024 ** 3), 1)
                result["ram_percent"] = int(mem.percent)

                # Disk: get root drive
                root_drive = os.path.splitdrive(os.path.abspath(__file__))[0] or "C:"
                if not root_drive.endswith("\\"):
                    root_drive += "\\"
                try:
                    disk = psutil.disk_usage(root_drive)
                    result["disk_total_gb"] = round(disk.total / (1024 ** 3), 1)
                    result["disk_used_gb"] = round(disk.used / (1024 ** 3), 1)
                    result["disk_percent"] = int(disk.percent)
                except Exception:
                    pass

                # Network throughput
                net_io = psutil.net_io_counters()
                now = time.time()
                with self._lock:
                    if self._prev_net_io and self._prev_net_time:
                        elapsed = now - self._prev_net_time
                        if elapsed > 0:
                            bytes_sent = net_io.bytes_sent - self._prev_net_io.bytes_sent
                            bytes_recv = net_io.bytes_recv - self._prev_net_io.bytes_recv
                            result["net_speed_mbps"] = round(
                                (bytes_sent + bytes_recv) * 8 / elapsed / (1024 ** 2), 2
                            )
                            result["net_bytes_sent"] = bytes_sent
                            result["net_bytes_recv"] = bytes_recv
                    self._prev_net_io = net_io
                    self._prev_net_time = now

            except Exception as e:
                from common.logger import log_error
                log_error("Panorama resource collection failed", exc=e)

        return result

    def get_process_info(self):
        """Get info about GIAM-SAT server process itself."""
        result = {
            "pid": os.getpid(),
            "thread_count": 0,
            "memory_mb": 0.0,
            "open_files": 0,
            "connections": 0,
        }
        if HAS_PSUTIL:
            try:
                proc = psutil.Process(os.getpid())
                result["thread_count"] = proc.num_threads()
                mem_info = proc.memory_info()
                result["memory_mb"] = round(mem_info.rss / (1024 ** 2), 1)
                result["open_files"] = len(proc.open_files())
                result["connections"] = len(proc.connections())
            except Exception:
                pass
        return result

    def get_db_stats(self):
        """Get database statistics."""
        result = {"backend": "unknown", "tables": {}, "total_size_mb": 0.0}
        if self.db:
            result["backend"] = getattr(self.db, "backend_type", "sqlite")
            try:
                # Try to get DB file size
                db_path = getattr(self.db, "db_path", None)
                if db_path and os.path.exists(db_path):
                    result["total_size_mb"] = round(os.path.getsize(db_path) / (1024 ** 2), 1)

                # Row counts for key tables
                if hasattr(self.db, "conn") and self.db.conn:
                    tables = ["events", "fim_events", "threat_alerts", "vuln_alerts",
                              "yara_alerts", "machines", "syslog", "sca_events",
                              "network_traffic", "response_results"]
                    for table in tables:
                        try:
                            cursor = self.db.conn.execute(f"SELECT COUNT(*) FROM {table}")
                            result["tables"][table] = cursor.fetchone()[0]
                        except Exception:
                            pass
            except Exception as e:
                from common.logger import log_error
                log_error("DB stats collection failed", exc=e)
        return result

    def get_attack_stats(self, hours=24):
        """Get server attack statistics for dashboard."""
        result = {
            "total_threats_24h": 0,
            "critical_threats_24h": 0,
            "threats_by_hour": [],
            "top_attackers": [],
            "top_rule_types": [],
            "server_self_attacks": 0,
        }
        if self.db:
            try:
                # Total threats in last N hours
                threats = self.db.get_threat_alerts(limit=1000)
                from datetime import datetime, timedelta as _td
                cutoff = (datetime.now() - _td(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")

                recent = [t for t in threats if t.get("timestamp", "") >= cutoff]
                result["total_threats_24h"] = len(recent)
                result["critical_threats_24h"] = sum(
                    1 for t in recent if (t.get("severity", "")).upper() == "CRITICAL"
                )
                result["server_self_attacks"] = sum(
                    1 for t in recent if (t.get("rule_id", "") or "").startswith("SRV-")
                )

                # By hour (simplified)
                hour_counts = {}
                for t in recent:
                    ts = t.get("timestamp", "")
                    if len(ts) >= 13:
                        hour = ts[11:13]
                        hour_counts[hour] = hour_counts.get(hour, 0) + 1
                result["threats_by_hour"] = [
                    {"hour": h, "count": c} for h, c in sorted(hour_counts.items())
                ]

                # Top attackers
                ip_counts = {}
                for t in recent:
                    ip = t.get("source_ip", "")
                    if ip:
                        ip_counts[ip] = ip_counts.get(ip, 0) + 1
                result["top_attackers"] = sorted(
                    [{"ip": k, "count": v} for k, v in ip_counts.items()],
                    key=lambda x: x["count"], reverse=True
                )[:10]

                # Top rule types
                rule_counts = {}
                for t in recent:
                    rn = t.get("rule_name", "") or t.get("rule_id", "")
                    if rn:
                        rule_counts[rn] = rule_counts.get(rn, 0) + 1
                result["top_rule_types"] = sorted(
                    [{"rule": k, "count": v} for k, v in rule_counts.items()],
                    key=lambda x: x["count"], reverse=True
                )[:8]

            except Exception as e:
                from common.logger import log_error
                log_error("Attack stats collection failed", exc=e)
        return result

    def get_agent_fleet_stats(self):
        """Get aggregate agent fleet statistics."""
        result = {
            "total_agents": 0,
            "online_agents": 0,
            "offline_agents": 0,
            "needs_update": 0,
            "version_distribution": {},
            "top_alerted": [],
            "total_hardware_configs": 0,
        }
        if self.db:
            try:
                machines = self.db.get_machines()
                result["total_agents"] = len(machines)
                result["online_agents"] = sum(1 for m in machines if m.get("is_online") == 1)
                result["offline_agents"] = result["total_agents"] - result["online_agents"]

                # Version distribution
                ver = {}
                current_ver = self.db.get_server_agent_version() if hasattr(self.db, "get_server_agent_version") else "2.5.1"
                for m in machines:
                    v = m.get("version", "unknown")
                    ver[v] = ver.get(v, 0) + 1
                    if v != current_ver and v != "unknown":
                        result["needs_update"] += 1
                result["version_distribution"] = ver

                # Top alerted agents
                threats = self.db.get_threat_alerts(limit=500)
                agent_alert_counts = {}
                for t in threats:
                    mid = t.get("machine_id", "")
                    if mid:
                        agent_alert_counts[mid] = agent_alert_counts.get(mid, 0) + 1
                result["top_alerted"] = sorted(
                    [{"machine_id": k, "hostname": self._get_hostname(k), "count": v}
                     for k, v in agent_alert_counts.items()],
                    key=lambda x: x["count"], reverse=True
                )[:10]

                result["total_hardware_configs"] = sum(
                    1 for m in machines if self.db.get_hardware_info(m.get("machine_id", ""))
                )

            except Exception as e:
                from common.logger import log_error
                log_error("Agent fleet stats collection failed", exc=e)
        return result

    def _get_hostname(self, machine_id):
        """Helper to get hostname from machine_id."""
        if self.db:
            try:
                machines = self.db.get_machines()
                for m in machines:
                    if m.get("machine_id") == machine_id:
                        return m.get("hostname", machine_id)
            except Exception:
                pass
        return machine_id

    def get_full_panorama(self):
        """Get all panoramic data in one call."""
        return {
            "resources": self.get_resources(),
            "process": self.get_process_info(),
            "database": self.get_db_stats(),
            "attacks": self.get_attack_stats(),
            "agent_fleet": self.get_agent_fleet_stats(),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }