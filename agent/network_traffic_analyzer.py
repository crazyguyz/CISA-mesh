"""
Network Traffic Analyzer for GIAM-SAT Agent v1.9.0
Adds GeoIP enrichment and traffic baseline/anomaly detection.

GeoIP: Uses MaxMind GeoLite2 free database to identify country of destination IPs.
Baseline: Tracks normal traffic patterns and detects anomalies (port scans, 
          unusual volume, connections to new countries/IPs).

Requires: geoip2 (pip install geoip2) + GeoLite2-Country.mmdb file
Fallback: Works without GeoIP - just skips enrichment.
"""
import os
import sys
import json
import time
import threading
import math
from collections import defaultdict, deque
from datetime import datetime

# Try importing geoip2
try:
    import geoip2.database
    HAS_GEOIP = True
except ImportError:
    HAS_GEOIP = False

# GeoLite2 database path
GEOIP_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "GeoLite2-Country.mmdb")

# Baseline window (seconds)
BASELINE_WINDOW = 3600  # 1 hour

# Anomaly thresholds
ANOMALY_THRESHOLDS = {
    "new_unique_dst_ips": 0.5,      # More than 50% new destination IPs vs baseline
    "volume_spike_ratio": 3.0,       # 3x normal traffic volume
    "new_country_connections": 1,    # Any connection to a country never seen before
    "port_scan_threshold": 20,       # 20+ unique ports to same IP in 10s
    "syn_flood_threshold": 100,      # 100+ SYN packets in 10s
    "dns_exfiltration_threshold": 5, # DNS queries > 512 bytes (tunneling)
}


class TrafficAnomalyDetector:
    """Detects anomalies in network traffic patterns."""

    def __init__(self):
        # Baseline stats (computed over BASELINE_WINDOW)
        self.baseline = {
            "total_packets": 0,
            "total_bytes": 0,
            "unique_dst_ips": set(),
            "unique_dst_ports": set(),
            "countries_seen": set(),
            "connections_per_minute": [],
            "bytes_per_minute": [],
            "packets_per_protocol": defaultdict(int),
        }
        self.current_window = {
            "packets": 0,
            "bytes": 0,
            "dst_ips": set(),
            "dst_ports": set(),
            "countries": set(),
            "start_time": time.time(),
        }
        # Short-term tracking for scans
        self.dst_ip_port_map = defaultdict(lambda: {"ports": set(), "first_seen": time.time()})
        self.syn_counter = deque()  # (timestamp,) tuples
        self.dns_queries = deque()  # (timestamp, size, query_name) tuples
        self.icmp_packets = deque()  # (timestamp, size, dst_ip) tuples
        self.exfil_bytes = defaultdict(lambda: {"bytes": 0, "first_seen": time.time()})  # dst_ip -> bytes tracker
        self._lock = threading.Lock()

    def feed_packet(self, packet_data):
        """Feed a packet for anomaly analysis. Returns list of detected anomalies."""
        anomalies = []
        now = time.time()

        with self._lock:
            # Update current window
            self.current_window["packets"] += 1
            self.current_window["bytes"] += packet_data.get("size", 0)

            dst_ip = packet_data.get("dst_ip", "")
            dst_port = packet_data.get("dst_port", 0)
            protocol = packet_data.get("protocol", "")
            size = packet_data.get("size", 0)

            if dst_ip:
                self.current_window["dst_ips"].add(dst_ip)
            if dst_port:
                self.current_window["dst_ports"].add(dst_port)

            # Country tracking (from GeoIP enriched data)
            country = packet_data.get("geoip_country", "")
            if country:
                self.current_window["countries"].add(country)

            # Check window reset
            if (now - self.current_window["start_time"]) > BASELINE_WINDOW:
                self._update_baseline()
                self._reset_current_window()

            # ---- Port Scan Detection ----
            if dst_ip and dst_port:
                ip_key = dst_ip
                tracker = self.dst_ip_port_map[ip_key]
                tracker["ports"].add(dst_port)
                # Check within 10 second window
                if (now - tracker["first_seen"]) <= 10 and len(tracker["ports"]) >= ANOMALY_THRESHOLDS["port_scan_threshold"]:
                    anomalies.append({
                        "type": "network_anomaly",
                        "subtype": "port_scan",
                        "dst_ip": dst_ip,
                        "unique_ports": len(tracker["ports"]),
                        "severity": "HIGH",
                        "description": f"Port scan detected: {len(tracker['ports'])} ports to {dst_ip} in 10s",
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    })
                    del self.dst_ip_port_map[ip_key]  # Reset after alert
                elif (now - tracker["first_seen"]) > 30:
                    # Reset if window expired
                    del self.dst_ip_port_map[ip_key]

            # ---- SYN Flood Detection ----
            tcp_flags = packet_data.get("tcp_flags_detail", "")
            if "SYN" in tcp_flags and "ACK" not in tcp_flags:
                self.syn_counter.append(now)
                # Trim old entries
                while self.syn_counter and (now - self.syn_counter[0]) > 10:
                    self.syn_counter.popleft()
                if len(self.syn_counter) >= ANOMALY_THRESHOLDS["syn_flood_threshold"]:
                    anomalies.append({
                        "type": "network_anomaly",
                        "subtype": "syn_flood",
                        "severity": "CRITICAL",
                        "syn_count": len(self.syn_counter),
                        "description": f"SYN flood detected: {len(self.syn_counter)} SYN packets in 10s",
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    })
                    self.syn_counter.clear()

            # ---- DNS Exfiltration Detection (v3.9.16: entropy + tunneling) ----
            dns_query = packet_data.get("dns_query", "")
            if dst_port == 53 or dns_query:
                qname = dns_query or packet_data.get("dst_ip", "")
                qsize = size if size > 0 else len(dns_query or "")
                self.dns_queries.append((now, qsize, qname))
                while self.dns_queries and (now - self.dns_queries[0][0]) > 60:
                    self.dns_queries.popleft()

                # Check for large query + high entropy (DNS tunneling)
                if dns_query:
                    entropy = self._shannon_entropy(dns_query.split(".")[0] if "." in dns_query else dns_query)
                    is_tunnel = (len(dns_query) > 52 and entropy > 4.5) or (qsize > 512)
                    if is_tunnel:
                        # Tag this query for correlation rule EXFIL-001
                        packet_data["description"] = packet_data.get("description", "") + " dns_tunnel entropy_high"

                large_dns = [s for t, s, q in self.dns_queries if s > 512 or (len(q) > 52 and self._shannon_entropy(q.split(".")[0] if "." in q else q) > 4.5)]
                if len(large_dns) >= ANOMALY_THRESHOLDS["dns_exfiltration_threshold"]:
                    anomalies.append({
                        "type": "network_anomaly",
                        "subtype": "dns_tunneling",
                        "severity": "HIGH",
                        "query_count": len(large_dns),
                        "avg_size": int(sum(large_dns) / max(len(large_dns), 1)),
                        "description": f"DNS tunneling suspicion: {len(large_dns)} large/high-entropy queries in 60s",
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    })
                    self.dns_queries.clear()

            # ---- ICMP Exfiltration Detection (v3.9.16) ----
            if protocol.upper() == "ICMP" and dst_ip:
                icmp_size = size if size > 0 else packet_data.get("payload_size", 0)
                self.icmp_packets.append((now, icmp_size, dst_ip))
                while self.icmp_packets and (now - self.icmp_packets[0][0]) > 60:
                    self.icmp_packets.popleft()

                # Normal ICMP: 32-64 bytes. >200 = potential tunneling
                large_icmp = [(t, s, ip) for t, s, ip in self.icmp_packets if s > 200]
                external_icmp = [(t, s, ip) for t, s, ip in large_icmp if not self._is_private(ip)]

                if len(external_icmp) >= 3:
                    anomalies.append({
                        "type": "network_anomaly",
                        "subtype": "icmp_exfiltration",
                        "severity": "HIGH",
                        "packet_count": len(external_icmp),
                        "avg_size": int(sum(s for _, s, _ in external_icmp) / len(external_icmp)),
                        "description": f"ICMP exfiltration suspicion: {len(external_icmp)} large packets to external IPs in 60s",
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    })
                    # Tag for correlation rule EXFIL-002
                    packet_data["description"] = packet_data.get("description", "") + " icmp_exfil large_payload"
                    self.icmp_packets.clear()

            # ---- Data Exfiltration Spike Detection (v3.9.16) ----
            if dst_ip and size > 1024:  # Only track packets > 1KB
                external = _is_public_ip(dst_ip) if "IS_WINDOWS" in dir() else True
                if external:
                    tracker = self.exfil_bytes[dst_ip]
                    tracker["bytes"] += size
                    elapsed = now - tracker["first_seen"]
                    if elapsed >= 300:  # 5 minute window
                        mb_rate = tracker["bytes"] / (1024 * 1024) / (elapsed / 60)
                        if mb_rate > 2:  # > 2MB/min to a single IP
                            anomalies.append({
                                "type": "network_anomaly",
                                "subtype": "exfil_spike",
                                "severity": "MEDIUM",
                                "dst_ip": dst_ip,
                                "total_bytes": tracker["bytes"],
                                "mb_per_min": round(mb_rate, 2),
                                "description": f"Data exfil spike: {round(tracker['bytes']/1048576, 1)}MB to {dst_ip} in {int(elapsed)}s",
                                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            })
                            # Tag for correlation rule EXFIL-003
                            packet_data["description"] = packet_data.get("description", "") + " exfil_spike new_destination"
                            del self.exfil_bytes[dst_ip]
                    elif tracker["bytes"] > 10 * 1024 * 1024:  # > 10MB total
                        anomalies.append({
                            "type": "network_anomaly",
                            "subtype": "exfil_spike",
                            "severity": "HIGH",
                            "dst_ip": dst_ip,
                            "total_bytes": tracker["bytes"],
                            "description": f"Large outbound data to new IP: {round(tracker['bytes']/1048576, 1)}MB to {dst_ip}",
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        })
                        packet_data["description"] = packet_data.get("description", "") + " exfil_spike new_destination"
                        del self.exfil_bytes[dst_ip]

        # ---- Volume Spike vs Baseline ----
        if self.baseline["connections_per_minute"]:
            baseline_avg = sum(self.baseline["connections_per_minute"]) / max(len(self.baseline["connections_per_minute"]), 1)
            current_rate = self.current_window["packets"] / max((now - self.current_window["start_time"]) / 60, 1)
            if baseline_avg > 0 and current_rate > baseline_avg * ANOMALY_THRESHOLDS["volume_spike_ratio"]:
                anomalies.append({
                    "type": "network_anomaly",
                    "subtype": "volume_spike",
                    "severity": "MEDIUM",
                    "current_rate": int(current_rate),
                    "baseline_rate": int(baseline_avg),
                    "description": f"Traffic spike: {int(current_rate)} packets/min (baseline: {int(baseline_avg)})",
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                })

        # ---- New Country Connection ----
        if country and self.baseline["countries_seen"] and country not in self.baseline["countries_seen"]:
            anomalies.append({
                "type": "network_anomaly",
                "subtype": "new_country",
                "severity": "MEDIUM",
                "country": country,
                "dst_ip": dst_ip,
                "description": f"First connection to country: {country} ({dst_ip})",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            })

        return anomalies

    def _update_baseline(self):
        """Move current window stats into baseline."""
        cw = self.current_window
        duration_min = max((time.time() - cw["start_time"]) / 60, 1)

        self.baseline["total_packets"] = cw["packets"]
        self.baseline["total_bytes"] = cw["bytes"]
        self.baseline["unique_dst_ips"] = cw["dst_ips"].copy()
        self.baseline["unique_dst_ports"] = cw["dst_ports"].copy()
        self.baseline["countries_seen"] = cw["countries"].copy()
        self.baseline["connections_per_minute"].append(int(cw["packets"] / duration_min))
        self.baseline["bytes_per_minute"].append(int(cw["bytes"] / duration_min))

        # Keep last 60 entries
        if len(self.baseline["connections_per_minute"]) > 60:
            self.baseline["connections_per_minute"] = self.baseline["connections_per_minute"][-60:]
            self.baseline["bytes_per_minute"] = self.baseline["bytes_per_minute"][-60:]

    def _reset_current_window(self):
        """Reset current window counters."""
        self.current_window = {
            "packets": 0,
            "bytes": 0,
            "dst_ips": set(),
            "dst_ports": set(),
            "countries": set(),
            "start_time": time.time(),
        }

    def _shannon_entropy(self, data):
        """Calculate Shannon entropy of a string (0.0-8.0). Higher = more random (tunneling indicator)."""
        if not data:
            return 0.0
        freq = defaultdict(int)
        for c in data:
            freq[c] += 1
        length = len(data)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    def _is_private(self, ip):
        """Check if an IP is private (RFC 1918) or loopback."""
        try:
            parts = ip.split(".")
            if len(parts) != 4:
                return True
            a, b = int(parts[0]), int(parts[1])
            if a == 10: return True
            if a == 172 and 16 <= b <= 31: return True
            if a == 192 and b == 168: return True
            if a == 127: return True
            if a == 0: return True
            if a == 169 and b == 254: return True
            return False
        except Exception:
            return True

    def get_stats(self):
        """Get current traffic statistics."""
        return {
            "baseline": {
                "avg_conn_per_min": int(sum(self.baseline["connections_per_minute"]) / max(len(self.baseline["connections_per_minute"]), 1)),
                "unique_dst_ips": len(self.baseline["unique_dst_ips"]),
                "countries_seen": list(self.baseline["countries_seen"]),
            },
            "current": {
                "packets": self.current_window["packets"],
                "bytes": self.current_window["bytes"],
                "unique_dst_ips": len(self.current_window["dst_ips"]),
            }
        }


class GeoIPEnricher:
    """Enriches network traffic with GeoIP country data."""

    def __init__(self):
        self.reader = None
        self._init_geoip()

    def _init_geoip(self):
        """Initialize GeoIP database."""
        if not HAS_GEOIP:
            print("[*] GeoIP: geoip2 not installed (pip install geoip2), skipping GeoIP enrichment")
            return
        if not os.path.exists(GEOIP_DB_PATH):
            print(f"[*] GeoIP: Database not found at {GEOIP_DB_PATH}")
            print("[*] GeoIP: Download free GeoLite2-Country.mmdb from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data")
            return
        try:
            self.reader = geoip2.database.Reader(GEOIP_DB_PATH)
            print("[*] GeoIP: MaxMind GeoLite2 database loaded")
        except Exception as e:
            print(f"[-] GeoIP: Failed to load: {e}")

    def enrich_packet(self, packet_data):
        """Add GeoIP country info to packet. Modifies packet_data in-place."""
        if not self.reader:
            return packet_data

        # Check both source and destination IPs
        for ip_key, geo_key in [("src_ip", "geoip_src_country"), ("dst_ip", "geoip_dst_country")]:
            ip = packet_data.get(ip_key, "")
            if ip and self._is_public_ip(ip):
                try:
                    response = self.reader.country(ip)
                    country = response.country.iso_code or ""
                    country_name = response.country.name or ""
                    if country:
                        packet_data[geo_key] = country
                        packet_data[f"{geo_key}_name"] = country_name
                        # Also promote to top-level for anomaly detector
                        if ip_key == "dst_ip":
                            packet_data["geoip_country"] = country
                except Exception:
                    pass

        return packet_data

    def _is_public_ip(self, ip):
        """Check if IP is public (not private/local)."""
        try:
            parts = ip.split(".")
            if len(parts) != 4:
                return False
            a, b = int(parts[0]), int(parts[1])
            if a == 10: return False
            if a == 172 and 16 <= b <= 31: return False
            if a == 192 and b == 168: return False
            if a == 127: return False
            if a == 0: return False
            if a >= 224: return False  # Multicast, reserved
            return True
        except Exception:
            return False

    def close(self):
        if self.reader:
            self.reader.close()


class NetworkTrafficAnalyzer:
    """Unified network traffic analyzer combining GeoIP and anomaly detection."""

    def __init__(self, callback=None):
        self.callback = callback
        self.geoip = GeoIPEnricher()
        self.anomaly = TrafficAnomalyDetector()

    def analyze_packet(self, packet_data):
        """Analyze a packet: enrich with GeoIP, detect anomalies.
        Returns the enriched packet and any anomaly events.
        """
        # Enrich with GeoIP
        enriched = self.geoip.enrich_packet(dict(packet_data))

        # Detect anomalies
        anomalies = self.anomaly.feed_packet(enriched)

        # Send anomaly events
        for anomaly in anomalies:
            if self.callback:
                self.callback(anomaly)

        return enriched, anomalies

    def get_stats(self):
        return self.anomaly.get_stats()

    def close(self):
        self.geoip.close()