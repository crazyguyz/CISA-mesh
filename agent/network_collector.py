"""
Network Packet Collector for GIAM-SAT Agent v2.5.17
REWRITE: Simple direct send, no rate limiting, two modes:
  - Scapy sniffing (full packet capture with DPI)
  - Netstat polling (fallback, connection listing)
"""
import threading
import time
import os
import json
import subprocess
import re
from datetime import datetime

try:
    # Scapy may crash with PermissionError on cache dir when running as SYSTEM
    import os as _os
    _os.environ.setdefault("SCAPY_CACHE_DIR", _os.path.join(_os.environ.get("TEMP", _os.path.expanduser("~")), "scapy_cache"))
    from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, Raw, Ether
    HAS_SCAPY = True
except (ImportError, PermissionError, OSError):
    HAS_SCAPY = False


def _hex_dump(data, max_bytes=256):
    if not data:
        return ""
    data = data[:max_bytes]
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:04x}  {hex_part:<48s}  {ascii_part}")
    return "\n".join(lines)


def _parse_tcp_flags(flags_int):
    names = []
    if flags_int & 0x01: names.append("FIN")
    if flags_int & 0x02: names.append("SYN")
    if flags_int & 0x04: names.append("RST")
    if flags_int & 0x08: names.append("PSH")
    if flags_int & 0x10: names.append("ACK")
    if flags_int & 0x20: names.append("URG")
    return ",".join(names) if names else "NONE"


class NetworkFilter:
    """
    v3.3: Filter noise from netstat output.
    Only send connections that are actually interesting for security monitoring.
    
    v3.4 FIX: Relaxed filters to avoid dropping all network traffic:
      - FIX 1: Removed port 53 from IGNORE_DST_PORTS (DNS is important for monitoring)
      - FIX 2: Expanded TCP states to include TIME_WAIT, CLOSE_WAIT, SYN_SENT etc.
      - FIX 3: UDP no longer blanket-rejected; only skip multicast/broadcast UDP
    """

    # Ports/protocols that are ALWAYS worth reporting
    SUSPICIOUS_PORTS = {
        # Remote access / backdoors
        22, 23, 3389, 5900, 5901, 5985, 5986,
        # Database (direct exposure risky)
        1433, 1521, 3306, 5432, 6379, 27017,
        # File sharing / lateral movement
        135, 139, 445, 139,
        # Unusual HTTP alternatives
        8080, 8443, 8888, 9000, 9090,
        # Cryptomining
        3333, 4444, 5555, 7777, 9999,
    }

    # Ports to IGNORE: common system services, broadcast noise
    # FIX 1: Removed port 53 - DNS queries are important for security monitoring
    IGNORE_DST_PORTS = {
        80,    # HTTP normal browsing
        443,   # HTTPS normal browsing
        123,   # NTP
        137, 138,  # NetBIOS broadcast (noise)
        161, 162,  # SNMP
        427,      # SLP
        1900,     # SSDP (UPnP discovery, huge noise)
        5353,     # mDNS (multicast DNS, huge noise)
        5355,     # LLMNR
        3702,     # WS-Discovery
        8000, 8008,  # Cast/Chromecast
        17500,    # Dropbox LAN sync
        57621,    # Spotify
    }

    # IPs / ranges to ignore
    IGNORE_SRC_IPS = {"127.0.0.1", "::1", "0.0.0.0", "::"}
    IGNORE_DST_IPS = {"0.0.0.0", "::", "255.255.255.255", "224.0.0.0/4", "239.0.0.0/8"}

    @classmethod
    def _is_private_ip(cls, ip):
        """Check if IP is in private range (RFC 1918 + loopback + link-local)."""
        if ip in ("127.0.0.1", "::1", "0.0.0.0", "::"):
            return True
        parts = ip.split(".")
        if len(parts) != 4:
            return True
        try:
            octets = [int(p) for p in parts]
        except ValueError:
            return True
        # 10.0.0.0/8
        if octets[0] == 10:
            return True
        # 172.16.0.0/12
        if octets[0] == 172 and 16 <= octets[1] <= 31:
            return True
        # 192.168.0.0/16
        if octets[0] == 192 and octets[1] == 168:
            return True
        # 169.254.0.0/16 (link-local)
        if octets[0] == 169 and octets[1] == 254:
            return True
        return False

    @classmethod
    def should_report(cls, data):
        """
        Returns True if this network event is worth reporting.
        Strategy: Report only external connections + suspicious internal ports.
        Skip listening ports, internal-to-internal noise, broadcast/multicast.
        """
        src_ip = str(data.get("src_ip", ""))
        dst_ip = str(data.get("dst_ip", ""))
        src_port = int(data.get("src_port", 0))
        dst_port = int(data.get("dst_port", 0))
        state = str(data.get("state", "")).upper()
        protocol = str(data.get("protocol", "")).upper()

        # Rule 1: NEVER report LISTENING ports (noise, no security value)
        if state == "LISTENING":
            return False

        # Rule 2: Skip loopback / source 0.0.0.0
        if src_ip in cls.IGNORE_SRC_IPS:
            return False

        # Rule 3: Skip broadcast/multicast destinations
        if dst_ip.startswith("224.") or dst_ip.startswith("239."):
            return False
        if dst_ip == "255.255.255.255":
            return False
        if dst_ip in cls.IGNORE_DST_IPS:
            return False

        # Rule 4: For TCP, report all meaningful states
        # FIX 2: Was only ESTABLISHED; now includes TIME_WAIT, CLOSE_WAIT, SYN_SENT etc.
        KNOWN_TCP_STATES = {"ESTABLISHED", "ESTAB", "TIME_WAIT", "CLOSE_WAIT",
                            "SYN_SENT", "SYN_RECEIVED", "FIN_WAIT1", "FIN_WAIT2",
                            "LAST_ACK", "CLOSING"}
        if protocol == "TCP" and state and state not in KNOWN_TCP_STATES:
            return False

        # Rule 5: v3.6.2 FIX: Check suspicious ports FIRST (before noise filter)
        # ALWAYS report connections to suspicious ports
        if dst_port in cls.SUSPICIOUS_PORTS:
            return True

        # Rule 6: v3.6.2 FIX: Check external IPs BEFORE noise filter
        # ALWAYS report connections to EXTERNAL IPs (non-private)
        if not cls._is_private_ip(dst_ip):
            return True

        # Rule 7: v3.6.2 FIX: Noise filter ONLY for internal traffic
        # At this point we know dst_ip is private — filter out common noise ports
        if dst_port in cls.IGNORE_DST_PORTS:
            return False

        # Rule 8: v3.6.2 RELAXED - Allow internal-to-internal traffic
        # All remaining internal traffic (non-noise ports) — report it
        if cls._is_private_ip(src_ip) and cls._is_private_ip(dst_ip):
            return True

        # Rule 9: UDP handling
        # FIX 3: No longer blanket-reject UDP. Only skip multicast/broadcast UDP.
        if protocol == "UDP":
            if dst_ip.startswith("224.") or dst_ip.startswith("239."):
                return False
            if dst_ip == "255.255.255.255":
                return False
            # Allow all other UDP (DNS, NTP, syslog, etc.)
            return True

        # Default: report (should be rare)
        return True


class NetworkCollector(threading.Thread):
    def __init__(self, callback):
        super().__init__(daemon=True)
        self.callback = callback
        self.running = True
        self._count = 0
        self._sent_count = 0
        self._filtered_count = 0
        self._dedup = {}  # v3.3: dedup key -> timestamp
        self._dedup_ttl = 30  # v3.6.2: 30s dedup (was 300s) for better visibility

    def _send(self, data):
        """v3.3: Filter + dedup before sending."""
        now_ts = time.time()

        # Step 1: Filter noise
        if not NetworkFilter.should_report(data):
            self._filtered_count += 1
            if self._filtered_count % 200 == 0:
                print(f"[NET] Filter: {self._filtered_count} events filtered, {self._sent_count} sent")
            return

        # Step 2: Dedup (same src_ip:dst_ip:dst_port in 5 min)
        dedup_key = f"{data.get('src_ip','')}:{data.get('dst_ip','')}:{data.get('dst_port',0)}"
        last_seen = self._dedup.get(dedup_key, 0)
        if now_ts - last_seen < self._dedup_ttl:
            return  # Already reported recently
        self._dedup[dedup_key] = now_ts

        # Step 3: Send
        data["type"] = "network_traffic"
        data["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        self._sent_count += 1
        if self._sent_count % 20 == 0:
            print(f"[NET] Sent {self._sent_count} events (filtered {self._filtered_count})")
        self.callback(data)
        # Clean old dedup entries periodically
        if self._sent_count % 100 == 0:
            self._dedup = {k: v for k, v in self._dedup.items() if now_ts - v < self._dedup_ttl}

    # ===== SCAPY MODE =====
    def _packet_handler(self, pkt):
        if not self.running:
            return
        try:
            if IP not in pkt:
                return
            ip = pkt[IP]

            data = {
                "size": len(pkt),
                "src_ip": ip.src,
                "dst_ip": ip.dst,
                "ip_version": ip.version if hasattr(ip, 'version') else 4,
                "ip_ttl": ip.ttl if hasattr(ip, 'ttl') else 64,
                "ip_proto": ip.proto if hasattr(ip, 'proto') else 0,
                "ip_id": ip.id if hasattr(ip, 'id') else 0,
                "ip_flags": str(ip.flags) if hasattr(ip, 'flags') else "",
                "ip_len": ip.len if hasattr(ip, 'len') else 0,
                "protocol": "OTHER",
                "src_port": 0,
                "dst_port": 0,
                "state": "",
            }

            # MAC addresses
            if Ether in pkt:
                data["src_mac"] = pkt[Ether].src if hasattr(pkt[Ether], 'src') else ""
                data["dst_mac"] = pkt[Ether].dst if hasattr(pkt[Ether], 'dst') else ""

            # Payload
            full_payload = b""
            if Raw in pkt:
                full_payload = bytes(pkt[Raw])

            data["payload_hex"] = full_payload[:256].hex() if full_payload else ""
            data["payload_size"] = len(full_payload)
            data["payload_dump"] = _hex_dump(full_payload, 256)

            # TCP / UDP specific
            if TCP in pkt:
                tcp = pkt[TCP]
                flags_int = tcp.flags.value if hasattr(tcp.flags, 'value') else int(tcp.flags)
                data.update({
                    "protocol": "TCP",
                    "src_port": tcp.sport,
                    "dst_port": tcp.dport,
                    "tcp_flags": _parse_tcp_flags(flags_int),
                    "tcp_seq": tcp.seq if hasattr(tcp, 'seq') else 0,
                    "tcp_window": tcp.window if hasattr(tcp, 'window') else 0,
                })
            elif UDP in pkt:
                udp = pkt[UDP]
                data.update({
                    "protocol": "UDP",
                    "src_port": udp.sport,
                    "dst_port": udp.dport,
                })

            # DPI: Application layer
            # DNS
            if DNS in pkt and pkt[DNS].qd and UDP in pkt:
                try:
                    dns = pkt[DNS]
                    qname = dns.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
                    data["protocol_app"] = "DNS"
                    data["dns_query"] = qname
                except:
                    pass

            # HTTP
            if TCP in pkt and Raw in pkt and not data.get("protocol_app"):
                try:
                    payload = bytes(pkt[Raw])
                    first_word = payload.split(b' ')[0] if b' ' in payload[:10] else b''
                    if first_word in (b'GET', b'POST', b'HEAD', b'PUT', b'DELETE', b'PATCH', b'OPTIONS'):
                        text = payload.decode('utf-8', errors='ignore')[:500]
                        data["protocol_app"] = "HTTP"
                        # Extract Host
                        for line in text.split('\r\n'):
                            if line.lower().startswith('host:'):
                                data["http_host"] = line[5:].strip()
                                break
                except:
                    pass

            self._send(data)
        except Exception:
            pass  # Silently skip malformed packets

    def _scapy_loop(self):
        print("[NET] Scapy sniff mode (full packet capture)")
        sniff(prn=self._packet_handler, store=False, filter="ip",
              stop_filter=lambda x: not self.running)

    # ===== NETSTAT FALLBACK =====
    def _netstat_loop(self):
        print("[NET] Netstat polling mode")
        _first_run = True
        while self.running:
            try:
                result = subprocess.run(
                    ["netstat", "-an"],
                    capture_output=True, text=True, timeout=10,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
                )
                lines = result.stdout.split('\n')
                parsed = 0
                for line in lines:
                    if not self.running:
                        break
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    proto = parts[0]
                    if proto not in ('TCP', 'UDP'):
                        continue
                    local, remote = parts[1], parts[2]
                    state = parts[3] if len(parts) > 3 else ''
                    local_parts = local.rsplit(':', 1)
                    remote_parts = remote.rsplit(':', 1)
                    if len(local_parts) == 2 and len(remote_parts) == 2:
                        # FIX 4: Use actual local IP, not hardcoded "0.0.0.0"
                        # Strip brackets from IPv6 addresses (e.g. [::1]:port)
                        local_ip = local_parts[0].strip("[]")
                        data = {
                            "src_ip": local_ip,
                            "src_port": int(local_parts[1]) if local_parts[1].isdigit() else 0,
                            "dst_ip": remote_parts[0],
                            "dst_port": int(remote_parts[1]) if remote_parts[1].isdigit() else 0,
                            "protocol": proto,
                            "size": 0,
                            "state": state,
                        }
                        self._send(data)
                        parsed += 1
                if _first_run:
                    print(f"[NET] Debug: netstat returned {len(lines)} lines, parsed {parsed} connections (first={lines[0].strip() if lines else 'EMPTY'})")
                    _first_run = False
            except Exception as e:
                import traceback
                print(f"[NET] ERROR: {e}\n{traceback.format_exc()}")
            time.sleep(10)

    # ===== MAIN =====
    def run(self):
        # v2.5.18: Force netstat only - scapy requires admin/Npcap permissions
        # which may not be available on all machines
        print("[NET] Network Collector: netstat polling (scapy disabled)")
        self._netstat_loop()

    def stop(self):
        self.running = False