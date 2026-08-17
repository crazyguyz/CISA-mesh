"""
Adaptive Baseline Engine for GIAM-SAT Agent v2.5.0
Learns normal traffic/behavior patterns per machine and sends
baseline reports to server for deviation detection.
"""
import json
import time
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta


class AdaptiveBaseline:
    """Learns and tracks baseline behavior for network, process, and file activity."""
    
    def __init__(self, callback=None):
        self.callback = callback
        self._lock = threading.Lock()
        
        # Hourly baseline
        self.hourly_baseline = {
            "dst_ips": set(),
            "dst_ports": defaultdict(int),
            "protocols": defaultdict(int),
            "bytes_out": 0,
            "bytes_in": 0,
            "connections": 0,
            "unique_domains": set(),
        }
        self.current_hour = {
            "dst_ips": set(),
            "dst_ports": defaultdict(int),
            "protocols": defaultdict(int),
            "bytes_out": 0,
            "bytes_in": 0,
            "connections": 0,
            "unique_domains": set(),
            "start_time": time.time(),
        }
        
        # Process baseline
        self.process_baseline = defaultdict(int)  # process_name -> avg_count_per_hour
        self.current_processes = defaultdict(int)
        
        # Deviations detected
        self.deviations = deque(maxlen=100)
        self.last_report_time = 0
        self.report_interval = 300  # 5 minutes
    
    def feed_packet(self, packet_data):
        """Feed a network packet for baseline tracking."""
        now = time.time()
        
        with self._lock:
            self.current_hour["connections"] += 1
            size = packet_data.get("size", 0)
            
            # Direction
            if packet_data.get("direction") == "inbound":
                self.current_hour["bytes_in"] += size
            else:
                self.current_hour["bytes_out"] += size
            
            dst_ip = packet_data.get("dst_ip", "")
            if dst_ip:
                self.current_hour["dst_ips"].add(dst_ip)
            
            dst_port = packet_data.get("dst_port", 0)
            if dst_port:
                self.current_hour["dst_ports"][dst_port] += 1
            
            proto = packet_data.get("protocol", "")
            if proto:
                self.current_hour["protocols"][proto] += 1
            
            # Domain tracking (from DPI)
            domain = packet_data.get("dns_info", {}).get("qname", "") or packet_data.get("http_info", {}).get("host", "")
            if domain:
                self.current_hour["unique_domains"].add(domain)
            
            # Check hourly window reset
            if (now - self.current_hour["start_time"]) > 3600:
                self._rotate_hourly()
            
            # Periodic report to server
            if self.callback and (now - self.last_report_time) > self.report_interval:
                self._send_baseline_report()
                self.last_report_time = now
    
    def feed_process(self, process_name):
        """Track process execution count."""
        with self._lock:
            self.current_processes[process_name] += 1
    
    def _rotate_hourly(self):
        """Rotate hourly window, update long-term baseline."""
        # Update long-term baseline with exponential moving average (alpha=0.3)
        alpha = 0.3
        for key in ["connections", "bytes_out", "bytes_in"]:
            current_val = float(self.current_hour.get(key, 0))
            baseline_val = float(self.hourly_baseline.get(key, 0))
            self.hourly_baseline[key] = int(baseline_val * (1 - alpha) + current_val * alpha)
        
        for key in ["dst_ports", "protocols"]:
            for k, v in self.current_hour.get(key, {}).items():
                self.hourly_baseline[key][k] = int(self.hourly_baseline[key].get(k, 0) * (1 - alpha) + v * alpha)
        
        self.hourly_baseline["dst_ips"] = set(list(self.current_hour["dst_ips"])[-100:])
        self.hourly_baseline["unique_domains"] = set(list(self.current_hour["unique_domains"])[-200:])
        
        # Reset current
        self.current_hour = {
            "dst_ips": set(), "dst_ports": defaultdict(int),
            "protocols": defaultdict(int), "bytes_out": 0, "bytes_in": 0,
            "connections": 0, "unique_domains": set(),
            "start_time": time.time(),
        }
        self.current_processes.clear()
    
    def _send_baseline_report(self):
        """Send baseline stats to server."""
        if not self.callback:
            return
        
        with self._lock:
            current_conns = self.current_hour["connections"]
            baseline_conns = self.hourly_baseline.get("connections", 1)
            
            # Detect deviations
            deviation_ratio = current_conns / max(baseline_conns, 1)
            deviations = []
            
            if baseline_conns > 0:
                # Connection spike
                if deviation_ratio > 5.0 and current_conns > 100:
                    deviations.append({
                        "type": "connection_spike",
                        "current": current_conns,
                        "baseline": baseline_conns,
                        "ratio": round(deviation_ratio, 2),
                        "description": f"Connection spike: {current_conns} vs baseline {baseline_conns}"
                    })
            
            # New destination ports
            new_ports = set(self.current_hour["dst_ports"].keys()) - set(self.hourly_baseline["dst_ports"].keys())
            if len(new_ports) >= 3:
                deviations.append({
                    "type": "new_ports",
                    "ports": list(new_ports)[:10],
                    "count": len(new_ports),
                    "description": f"New destination ports detected: {len(new_ports)}"
                })
            
            # New domains
            new_domains = set(self.current_hour["unique_domains"]) - set(self.hourly_baseline["unique_domains"])
            if len(new_domains) >= 5:
                deviations.append({
                    "type": "new_domains",
                    "domains": list(new_domains)[:10],
                    "count": len(new_domains),
                    "description": f"New domains contacted: {len(new_domains)}"
                })
            
            # Build report
            report = {
                "type": "baseline_report",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "baseline": {
                    "avg_connections_per_hour": baseline_conns,
                    "avg_bytes_out": self.hourly_baseline.get("bytes_out", 0),
                    "avg_bytes_in": self.hourly_baseline.get("bytes_in", 0),
                    "common_ports": sorted(
                        [(p, c) for p, c in self.hourly_baseline["dst_ports"].items() if c > 5],
                        key=lambda x: x[1], reverse=True
                    )[:10],
                    "common_domains_count": len(self.hourly_baseline["unique_domains"]),
                },
                "current_window": {
                    "connections": current_conns,
                    "bytes_out": self.current_hour["bytes_out"],
                    "bytes_in": self.current_hour["bytes_in"],
                    "unique_ips": len(self.current_hour["dst_ips"]),
                    "unique_ports": len(self.current_hour["dst_ports"]),
                    "unique_domains": len(self.current_hour["unique_domains"]),
                },
                "deviations": deviations,
                "anomaly_score": min(100, int(len(deviations) * 20 + max(0, (deviation_ratio - 2) * 10))),
            }
            
            self.callback(report)
    
    def get_stats(self):
        """Get current baseline stats."""
        with self._lock:
            return {
                "baseline": {
                    "connections": self.hourly_baseline["connections"],
                    "common_ports": len(self.hourly_baseline["dst_ports"]),
                    "known_domains": len(self.hourly_baseline["unique_domains"]),
                },
                "current": {
                    "connections": self.current_hour["connections"],
                    "unique_ips": len(self.current_hour["dst_ips"]),
                    "deviation_ratio": round(
                        self.current_hour["connections"] / max(self.hourly_baseline["connections"], 1), 2
                    ),
                }
            }
    
    def close(self):
        pass