"""
Syslog Server for GIAM-SAT Server
Listens on UDP port 514 for syslog messages from routers/network devices
"""

import os
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
        # v5.0.4 (Phase1 A1b): RFC5424 structured format.
        # Header: <PRI>1 SP TS SP HOST SP APP SP PROCID SP MSGID SP
        # then STRUCTURED-DATA (one or more [..] elements, possibly with spaces
        # inside, or '-'), then the MSG. Old pattern used \\S+ for SD -> a real
        # SD like `[timeQuality tzKnown="true"]` shifted app_name/message.
        self._rfc5424_pattern = re.compile(
            r'<(\d{1,3})>\s*1\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*)',
            re.DOTALL)

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
        # v5.0.4 R9 (MEDIUM-8c): _blocked_ips is shared across parser threads -
        # mutate it only under this lock (count race + KeyError on concurrent
        # cleanup previously lost messages). Cleanup is throttled to 60s.
        self._blocked_lock = threading.Lock()
        self._last_block_cleanup = 0.0
        # v5.0.4 R9 (MEDIUM-8b): bounded parser workers - the old thread-per-message
        # let a short UDP burst (up to 200 pps) spawn thousands of concurrent DB
        # writers (self-DoS). At most N parsers run; a full pool sheds the flood.
        try:
            _max_workers = int(os.environ.get("GIAMSAT_SYSLOG_MAX_WORKERS", "8"))
        except (TypeError, ValueError):
            _max_workers = 8
        self._parse_slots = threading.BoundedSemaphore(max(2, _max_workers))
        # v5.0.4 (re-review): per-source throttle for syslog_sources upsert - every
        # message doing an INSERT..ON CONFLICT would multiply DB writes (up to the
        # 200pps cap). Once per 60s per source is enough for asset mapping.
        self._note_ts = {}

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
        # v5.0.4 (Phase3 improvement #1): DrayTek Vigor profile - the generic
        # patterns above match but cannot capture the ATTACKER IP that DrayTek
        # embeds in its own syntax ("login fail - user: x from: 1.2.3.4"). These
        # run only when the sender identifies as DrayTek/Vigor, so we can enrich
        # with the source IP for FW-block <-> agent-event correlation.
        self._draytek_patterns = [
            ("NW-LOGIN-002", "DrayTek Login Failure",
             r"(?:login|authentication)\s*(?:fail(?:ure|ed)?|incorrect|invalid).*?(?:from|at|ip\s*[:=])\s*(?P<ip>\d+\.\d+\.\d+\.\d+)", "MEDIUM"),
            ("NW-LOGIN-002", "DrayTek Login Failure",
             r"login fail.*?(?P<ip>\d+\.\d+\.\d+\.\d+)", "MEDIUM"),
            ("NW-LOGIN-002", "DrayTek Login Failure",
             r"(?P<ip>\d+\.\d+\.\d+\.\d+).{0,80}(?:too many|blocked|blacklist|lock\s*out)", "HIGH"),
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

            # v5.0.3 (MEDIUM-11): per-source packet rate limit so an unauthenticated
            # UDP flood cannot spawn unbounded parser threads / DB writes
            _MAX_PPS = int(os.environ.get("GIAMSAT_SYSLOG_MAX_PPS", "200"))
            _rate = {}
            _rate_lock = threading.Lock()

            while self.running:
                try:
                    data, address = sock.recvfrom(8192)
                    src = address[0]
                    with _rate_lock:
                        now = time.time()
                        # periodic GC of idle source keys
                        if len(_rate) > 500:
                            idle = [k for k, v in _rate.items() if now - v[0] > 60]
                            for k in idle:
                                _rate.pop(k, None)
                        w, c = _rate.get(src, (now, 0))
                        if now - w > 1.0:
                            w, c = now, 0
                        c += 1
                        _rate[src] = (w, c)
                        if c > _MAX_PPS:
                            continue  # drop the flood silently
                    # v5.0.4 R9 (MEDIUM-8b): bounded workers - drop when the pool is
                    # busy instead of spawning a thread per message (self-DoS).
                    if self._parse_slots.acquire(timeout=0.25):
                        t = threading.Thread(
                            target=self._worker,
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

    def _worker(self, data, address):
        """v5.0.4 R9 (MEDIUM-8b): bounded pool worker - releases its slot when done."""
        try:
            self._process_syslog(data, address)
        except Exception:
            pass
        finally:
            try:
                self._parse_slots.release()
            except Exception:
                pass

    def _split_sd_msg(self, rest):
        """v5.0.4 R9 (MEDIUM-8a): split RFC5424 STRUCTURED-DATA from the MSG.

        SD may be '-' (nil) or one or more '[..]' elements whose content can
        contain spaces (`[timeQuality tzKnown="true"]`). Returns (sd, msg)."""
        rest = (rest or "")
        # eat the separator space after MSGID
        while rest.startswith(" "):
            rest = rest[1:]
        if rest.startswith("-"):
            return "-", rest[1:].lstrip()
        if rest.startswith("["):
            chunks, i, n = [], 0, len(rest)
            while i < n and rest[i] == "[":
                j = rest.find("]", i)
                if j == -1:
                    break
                chunks.append(rest[i:j + 1])
                i = j + 1
                while i < n and rest[i] == " ":  # separator(s) before next element/MSG
                    i += 1
            return (" ".join(chunks)) if chunks else "-", rest[i:].strip()
        # no SD token at all -> treat everything as MSG
        return "-", rest.strip()

    def _normalize_ts(self, raw_ts):
        """v5.0.4 R9 (MEDIUM-8): device alerts store a FULL datetime. RFC3164 has
        no year ('Oct 11 22:14:15') -> sorting/retention broke; RFC5424 is already
        'YYYY-MM-DDTHH:MM:SS'. Fallback: server receive time."""
        try:
            s = str(raw_ts or "").strip()
            if re.match(r"^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}$", s):
                dt = datetime.strptime(s, "%b %d %H:%M:%S").replace(year=datetime.now().year)
                return dt.strftime("%Y-%m-%d %H:%M:%S")
            if re.match(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}", s):
                return s[:19].replace("T", " ")
        except Exception:
            pass
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def _process_syslog(self, data, address):
        """Parse and store syslog message."""
        try:
            raw = data.decode("utf-8", errors="replace").strip()
            source_ip = address[0]

            # Try to parse RFC 3164
            match = self.syslog_pattern.match(raw)
            if match:
                priority = int(match.group(1))
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

                # ---- v5.0.4 (Phase1 A1b): RFC5424 structured ----
                m5424 = self._rfc5424_pattern.match(raw)
                if m5424:
                    ts_s, hostname, app_name, _proc, _msgid, rest = m5424.groups()
                    facility_name = facility_names.get(priority >> 3, f"facility_{priority >> 3}")
                    severity_name = severity_names.get(priority & 0x07, f"severity_{priority & 0x07}")
                    timestamp_str = ts_s
                    # v5.0.4 R9 (MEDIUM-8a): split STRUCTURED-DATA (may contain
                    # spaces inside the [..]) from the MSG properly.
                    sd, message = self._split_sd_msg(rest)
                    message = (message or "").strip()
                    if "DHCP" in message.upper():
                        message = self._dhcp_mac_pattern.sub("xx:xx:xx:xx:xx:xx", message)
                        message = self._dhcp_hostname_pattern.sub(r'\1 [REDACTED]', message)
                    if self.db:
                        try:
                            self.db.insert_syslog(
                                source_ip, hostname, facility_name, severity_name,
                                datetime.now().strftime("%Y-%m-%d %H:%M:%S"), message, raw,
                                app_name=app_name or "", structured=sd or "-")
                        except Exception:
                            pass
                else:
                    # ---- RFC 3164 ----
                    timestamp_str = match.group(2) or datetime.now().strftime("%b %d %H:%M:%S")
                    hostname = match.group(3) or source_ip
                    message = match.group(4)
                    facility_name = facility_names.get(priority >> 3, f"facility_{priority >> 3}")
                    severity_name = severity_names.get(priority & 0x07, f"severity_{priority & 0x07}")

                    # v2.0.2 SECURITY: Redact DHCP MAC addresses and hostnames from syslog
                    # Prevent information disclosure of DHCP lease data
                    if "DHCP" in message.upper() or "dhcp" in facility_name.lower():
                        message = self._dhcp_mac_pattern.sub("xx:xx:xx:xx:xx:xx", message)
                        message = self._dhcp_hostname_pattern.sub(r'\1 [REDACTED]', message)

                    # Store in DB - use the server receive time (ISO, sortable + cleanable)
                    # instead of the RFC-3164 message timestamp which has NO year and can
                    # never be matched by retention cleanup. The original message time is
                    # kept inside raw_data.
                    if self.db:
                        self.db.insert_syslog(
                            source_ip, hostname, facility_name, severity_name,
                            datetime.now().strftime("%Y-%m-%d %H:%M:%S"), message, raw
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

                # v5.0.4 (Phase3 improvement #1): device source -> asset mapping
                self._note_source(source_ip, hostname)

                # v5.0.4 (Phase3 improvement #1): DrayTek Vigor profile runs FIRST
                # (it captures the attacker IP). If it fired we skip the generic
                # device alert for this message so one event does not create two
                # login-failure rows.
                _draytek_fired = self._parse_draytek(source_ip, hostname, message, timestamp_str)

                # v2.5.0: Firewall Deep Parse - detect blocked traffic and scans
                self._parse_firewall_log(source_ip, hostname, message, timestamp_str)

                # v4.11 (CN1): generic device detection - login fail / config
                # change / interface flap from routers, switches, APs, printers
                if not _draytek_fired:
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

    def _note_source(self, source_ip, hostname):
        """v5.0.4 (Phase3 improvement #1): auto-learn syslog device sources and
        keep them in syslog_sources so an operator can map each device IP to an
        asset (agent machine_id / label) - device logs then correlate with agent
        events on the mapped host. Throttled to once per 60s per source."""
        if not source_ip or not self.db or not hasattr(self.db, "upsert_syslog_source"):
            return
        try:
            _now = time.time()
            if _now - self._note_ts.get(source_ip, 0) < 60:
                return
            self._note_ts[source_ip] = _now
            if len(self._note_ts) > 1000:
                self._note_ts = {k: v for k, v in self._note_ts.items() if _now - v < 3600}
            dev = self._guess_device_type(str(hostname or ""))
            self.db.upsert_syslog_source(str(source_ip), str(hostname or ""), dev)
        except Exception:
            pass

    @staticmethod
    def _guess_device_type(hostname):
        h = hostname.lower()
        if any(k in h for k in ("draytek", "vigor")):
            return "draytek"
        if any(k in h for k in ("fortinet", "fortigate", "forti")):
            return "fortinet"
        if "cisco" in h or h.startswith(("asa", "ios", "cat", "sw", "router")):
            return "cisco"
        if "palo" in h:
            return "paloalto"
        if any(k in h for k in ("sophos", "sonicwall", "watchguard", "opnsense", "pfsense", "pfsense")):
            return "firewall"
        if any(k in h for k in ("ap-", "wlan", "ubiquiti", "ruckus", "aruba")):
            return "ap"
        if any(k in h for k in ("printer", "ricoh", "hp ", "brother", "epson")):
            return "printer"
        return ""

    def _parse_draytek(self, source_ip, hostname, message, timestamp_str):
        """v5.0.4 (Phase3 improvement #1): DrayTek Vigor profile - extract the
        attacker IP and surface a distinct login-failure/brute-force alert that
        the generic NW-LOGIN-001 cannot enrich. Adds NW-LOGIN-002 (Medium/High).
        Returns True when an alert was raised (caller then skips the generic
        device alert so one message never creates two login rows)."""
        if not message or not self.db:
            return False
        low = str(message).lower()
        if "draytek" not in low and "vigor" not in low:
            return False
        ts = self._normalize_ts(timestamp_str)
        fired = False
        for rule_id, rule_name, pattern, severity in self._draytek_patterns:
            m = re.search(pattern, message, re.IGNORECASE)
            if not m:
                continue
            try:
                ip = m.groupdict().get("ip") or m.group(1) or ""
            except Exception:
                ip = ""
            if not ip:
                continue
            try:
                self.db.insert_threat_alert({
                    "machine_id": f"NW:{hostname}",
                    "hostname": f"{hostname} ({source_ip})",
                    "rule_id": rule_id,
                    "rule_name": rule_name,
                    "severity": severity,
                    "description": (f"[{rule_name}] DrayTek source IP {ip} -> {message[:200]} "
                                    f"(mapped to host {hostname}). Correlate with agent events on {ip}."),
                    "timestamp": ts,
                    "source_ip": ip,
                })
                fired = True
            except Exception:
                pass
            break  # one profile alert per message
        return fired

    def _parse_device_alert(self, source_ip, hostname, message, timestamp_str):
        """v4.11 (CN1): detect login failures, config changes and interface flaps
        from network devices (routers/switches/APs/printers) and surface them as
        threat alerts (they also reach the daily MEDIUM digest automatically)."""
        if not message:
            return
        # v5.0.4 R9 (MEDIUM-8): RFC3164 has no year -> normalize so alert sorting
        # and retention work ("Oct 11 22:14:15" previously sorted wrong).
        ts = self._normalize_ts(timestamp_str)
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
                            "timestamp": ts,
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

                # Track blocked IPs to detect port scans (v5.0.4 R9: all access to
                # _blocked_ips is under _blocked_lock - it is shared across parser
                # threads and a concurrent cleanup used to lose messages).
                now = time.time()
                key = f"{src_ip}_{dst_ip}"
                ts = self._normalize_ts(timestamp_str)
                with self._blocked_lock:
                    ent = self._blocked_ips.get(key)
                    if ent is None:
                        ent = {"count": 0, "first_seen": now}
                        self._blocked_ips[key] = ent
                    ent["count"] += 1
                    count = ent["count"]
                    first_seen = ent["first_seen"]

                # If same src → dst blocked >= 5 times in 60s → port scan
                if (now - first_seen) <= 60 and count >= 5:
                    if self.db:
                        try:
                            self.db.insert_threat_alert({
                                "machine_id": f"FW:{hostname}",
                                "hostname": f"Firewall:{hostname}",
                                "rule_id": "FW-SCAN-001",
                                "rule_name": "Firewall Blocked Port Scan",
                                "severity": "HIGH",
                                "description": f"Port scan from {src_ip} to {dst_ip} ({count}x blocked by firewall)",
                                "timestamp": ts,
                            })
                        except Exception:
                            pass
                    with self._blocked_lock:
                        self._blocked_ips.pop(key, None)

                # Single block → store as event
                if self.db:
                    try:
                        self.db.insert_threat_alert({
                            "machine_id": f"FW:{hostname}",
                            "hostname": f"Firewall:{hostname}",
                            "rule_id": "FW-BLOCK-001",
                            "rule_name": f"Firewall Block: {fw_type}",
                            "severity": "MEDIUM",
                            "description": f"Traffic blocked: {src_ip} → {dst_ip} [{fw_type}]",
                            "timestamp": ts,
                        })
                    except Exception:
                        pass
                _safe_print(f"[🛡] FIREWALL BLOCK [{fw_type}]: {src_ip} → {dst_ip}")
                break  # Only match first pattern

        # Periodic cleanup of old entries (throttled - runs at most once a minute)
        now = time.time()
        with self._blocked_lock:
            if now - self._last_block_cleanup > 60:
                self._last_block_cleanup = now
                _expired = [k for k, v in list(self._blocked_ips.items()) if now - v["first_seen"] > 300]
                for k in _expired:
                    self._blocked_ips.pop(k, None)

    def stop(self):
        self.running = False
