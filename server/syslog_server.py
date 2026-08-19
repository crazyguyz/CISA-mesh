"""
Syslog Server for GIAM-SAT Server
Listens on UDP port 514 for syslog messages from routers/network devices
"""

import socket
import threading
import time
import re
from datetime import datetime


def _safe_print(msg):
    """v4.11: emoji prints crash on cp1252 consoles (UnicodeEncodeError) and
    would abort the syslog processing thread - never let logging kill parsing."""
    try:
        print(msg)
    except Exception:
        pass


class SyslogServer(threading.Thread):
    def __init__(self, host="0.0.0.0", port=514, db_manager=None, message_callback=None):
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self.db = db_manager
        self.message_callback = message_callback
        self.running = True

        # RFC 3164 syslog regex
        self.syslog_pattern = re.compile(
            r'<(\d{1,3})>'  # Priority
            r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})?\s*'  # Timestamp (optional)
            r'(\S+)?\s*'  # Hostname (optional)
            r'(.*)'  # Message
        )

        # v2.0.2 SECURITY: Patterns for DHCP MAC/Hostname redaction
        self._dhcp_mac_pattern = re.compile(r'([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}')
        self._dhcp_hostname_pattern = re.compile(r'(host|via|for)\s+(\S+)', re.IGNORECASE)

        # v2.5.0: Firewall Syslog Deep Parse (Cisco ASA, Palo Alto, Fortinet)
        self._fw_patterns = {
            "cisco_asa_deny": re.compile(r'%ASA-(\d)-(\d+).*Deny\s+(\w+).*src\s+.*?:(\S+).*dst\s+.*?:(\S+)', re.IGNORECASE),
            "palo_alto_threat": re.compile(r'THREAT.*?\((\d+)\).*?from\s+(\S+).*?to\s+(\S+)', re.IGNORECASE),
            "fortinet_deny": re.compile(r'action="deny".*srcip=(\S+).*dstip=(\S+)', re.IGNORECASE),
            "iptables_drop": re.compile(r'DROP.*SRC=(\S+).*DST=(\S+)', re.IGNORECASE),
            "generic_deny": re.compile(r'(denied|blocked|dropped|rejected).*?(\d+\.\d+\.\d+\.\d+).*?(\d+\.\d+\.\d+\.\d+)', re.IGNORECASE),
        }
        # Track blocked IPs to detect port scans
        self._blocked_ips = {}

        # v4.11 (CN1): generic network-device detection (routers, switches, APs,
        # printers - DrayTek Vigor, TP-Link, Ricoh/HP) on top of the firewall
        # deep parse: login failures (brute force from WAN), config changes,
        # interface flaps.
        self._device_patterns = [
            ("NW-LOGIN-001", "Network Device Login Failure",
             r"failed password|authentication failure|login failed|login incorrect|invalid login|unable to login|brute force|too many.*(fail|attempt)|invalid username", "MEDIUM"),
            ("NW-CONFIG-001", "Network Device Config Change",
             r"configuration changed|configuration (file )?saved|running-config|config.*modified|apply.*config|saved configuration|write mem|copy running-config", "HIGH"),
            ("NW-IFACE-001", "Network Interface Flap",
             r"link down|line protocol.*down|interface.*(down|reset)|link up|status changed", "LOW"),
        ]

    def run(self):
        """Start UDP syslog server."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Need admin to bind to port 514
            try:
                sock.bind((self.host, self.port))
                print(f"[*] Syslog Server listening on {self.host}:{self.port} (UDP)")
            except PermissionError:
                print(f"[!] Cannot bind to port {self.port}. Need Administrator privileges.")
                print(f"[!] Fallback: Using port 1514 instead.")
                self.port = 1514
                sock.bind((self.host, self.port))
                print(f"[*] Syslog Server listening on {self.host}:{self.port} (UDP)")

            sock.settimeout(2)

            while self.running:
                try:
                    data, address = sock.recvfrom(8192)
                    t = threading.Thread(
                        target=self._process_syslog,
                        args=(data, address),
                        daemon=True
                    )
                    t.start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        print(f"[-] Syslog receive error: {e}")

            sock.close()

        except Exception as e:
            print(f"[-] Syslog Server error: {e}")

    def _process_syslog(self, data, address):
        """Parse and store syslog message."""
        try:
            raw = data.decode("utf-8", errors="replace").strip()
            source_ip = address[0]

            # Try to parse RFC 3164
            match = self.syslog_pattern.match(raw)
            if match:
                priority = int(match.group(1))
                timestamp_str = match.group(2) or datetime.now().strftime("%b %d %H:%M:%S")
                hostname = match.group(3) or source_ip
                message = match.group(4)

                # Calculate facility and severity
                facility = priority >> 3
                severity = priority & 0x07

                facility_names = {
                    0: "kern", 1: "user", 2: "mail", 3: "daemon",
                    4: "auth", 5: "syslog", 6: "lpr", 7: "news",
                    8: "uucp", 9: "cron", 10: "authpriv", 11: "ftp",
                    16: "local0", 17: "local1", 18: "local2", 19: "local3",
                    20: "local4", 21: "local5", 22: "local6", 23: "local7"
                }
                severity_names = {
                    0: "emergency", 1: "alert", 2: "critical", 3: "error",
                    4: "warning", 5: "notice", 6: "info", 7: "debug"
                }

                facility_name = facility_names.get(facility, f"facility_{facility}")
                severity_name = severity_names.get(severity, f"severity_{severity}")

                # v2.0.2 SECURITY: Redact DHCP MAC addresses and hostnames from syslog
                # Prevent information disclosure of DHCP lease data
                if "DHCP" in message.upper() or "dhcp" in facility_name.lower():
                    message = self._dhcp_mac_pattern.sub("xx:xx:xx:xx:xx:xx", message)
                    message = self._dhcp_hostname_pattern.sub(r'\1 [REDACTED]', message)

                # Store in DB
                if self.db:
                    self.db.insert_syslog(
                        source_ip, hostname, facility_name, severity_name,
                        timestamp_str, message, raw
                    )

                # Notify web UI
                if self.message_callback:
                    self.message_callback({
                        "type": "syslog",
                        "source_ip": source_ip,
                        "hostname": hostname,
                        "facility": facility_name,
                        "severity": severity_name,
                        "timestamp": timestamp_str,
                        "message": message,
                        "raw": raw
                    })

                # v2.5.0: Firewall Deep Parse - detect blocked traffic and scans
                self._parse_firewall_log(source_ip, hostname, message, timestamp_str)

                # v4.11 (CN1): generic device detection - login fail / config
                # change / interface flap from routers, switches, APs, printers
                self._parse_device_alert(source_ip, hostname, message, timestamp_str)

                print(f"[S] Syslog from {hostname} ({source_ip}): {severity_name}/{facility_name}")

            else:
                # Unparseable - store raw
                if self.db:
                    self.db.insert_syslog(
                        source_ip, source_ip, "unknown", "unknown",
                        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        raw, raw
                    )

                print(f"[S] Raw syslog from {source_ip}: {raw[:100]}...")

        except Exception as e:
            print(f"[-] Syslog parse error: {e}")

    def _parse_device_alert(self, source_ip, hostname, message, timestamp_str):
        """v4.11 (CN1): detect login failures, config changes and interface flaps
        from network devices (routers/switches/APs/printers) and surface them as
        threat alerts (they also reach the daily MEDIUM digest automatically)."""
        if not message:
            return
        for rule_id, rule_name, pattern, severity in self._device_patterns:
            if re.search(pattern, message, re.IGNORECASE):
                if self.db:
                    try:
                        self.db.insert_threat_alert({
                            "machine_id": f"NW:{hostname}",
                            "hostname": f"{hostname} ({source_ip})",
                            "rule_id": rule_id,
                            "rule_name": rule_name,
                            "severity": severity,
                            "description": f"[{rule_name}] {message[:250]}",
                            "timestamp": timestamp_str,
                        })
                    except Exception:
                        pass
                _safe_print(f"[🛡] DEVICE ALERT [{rule_id}] {rule_name} on {hostname} ({source_ip})")
                break  # first match only

    def _parse_firewall_log(self, source_ip, hostname, message, timestamp_str):
        """Parse firewall syslog to detect blocked traffic and port scans."""
        for fw_type, pattern in self._fw_patterns.items():
            m = pattern.search(message)
            if m:
                if fw_type == "cisco_asa_deny":
                    src_ip = m.group(4)
                    dst_ip = m.group(5)
                elif fw_type == "palo_alto_threat":
                    src_ip = m.group(2)
                    dst_ip = m.group(3)
                elif fw_type == "fortinet_deny":
                    src_ip = m.group(1)
                    dst_ip = m.group(2)
                elif fw_type == "iptables_drop":
                    src_ip = m.group(1)
                    dst_ip = m.group(2)
                elif fw_type == "generic_deny":
                    src_ip = m.group(2)
                    dst_ip = m.group(3)
                else:
                    continue

                # Track blocked IPs to detect port scans
                now = time.time()
                key = f"{src_ip}_{dst_ip}"
                if key not in self._blocked_ips:
                    self._blocked_ips[key] = {"count": 0, "first_seen": now}
                self._blocked_ips[key]["count"] += 1

                # If same src → dst blocked >= 5 times in 60s → port scan
                if (now - self._blocked_ips[key]["first_seen"]) <= 60 and self._blocked_ips[key]["count"] >= 5:
                    if self.db:
                        self.db.insert_threat_alert({
                            "machine_id": f"FW:{hostname}",
                            "hostname": f"Firewall:{hostname}",
                            "rule_id": "FW-SCAN-001",
                            "rule_name": "Firewall Blocked Port Scan",
                            "severity": "HIGH",
                            "description": f"Port scan from {src_ip} to {dst_ip} ({self._blocked_ips[key]['count']}x blocked by firewall)",
                            "timestamp": timestamp_str,
                        })
                    del self._blocked_ips[key]

                # Single block → store as event  
                if self.db:
                    self.db.insert_threat_alert({
                        "machine_id": f"FW:{hostname}",
                        "hostname": f"Firewall:{hostname}",
                        "rule_id": "FW-BLOCK-001",
                        "rule_name": f"Firewall Block: {fw_type}",
                        "severity": "MEDIUM",
                        "description": f"Traffic blocked: {src_ip} → {dst_ip} [{fw_type}]",
                        "timestamp": timestamp_str,
                    })
                _safe_print(f"[🛡] FIREWALL BLOCK [{fw_type}]: {src_ip} → {dst_ip}")
                break  # Only match first pattern

        # Periodic cleanup of old entries
        now = time.time()
        expired = [k for k, v in self._blocked_ips.items() if now - v["first_seen"] > 300]
        for k in expired:
            del self._blocked_ips[k]

    def stop(self):
        self.running = False
