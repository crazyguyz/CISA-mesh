"""
Linux Auditd Collector for GIAM-SAT Agent v1.9.0
Collects and parses Linux auditd logs - the primary SIEM data source for Linux.

Auditd monitors: file access, syscalls, user commands, authentication, network activity.
Log format: /var/log/audit/audit.log (standard auditd format, type=SYSCALL msg=audit(...)).

Key event types:
- SYSCALL: System call execution
- EXECVE: Command execution
- CWD: Current working directory
- PATH: File path access
- USER_AUTH/USER_LOGIN/USER_START: Authentication events
- CRED_ACQ/CRED_DISP: Credential acquisition/disposition
- ANOM_*: Anomaly detection events
- CONFIG_CHANGE: Audit configuration changes
- SERVICE_START/SERVICE_STOP: Service lifecycle

Works on Linux only. Silently does nothing on Windows.
"""
import os
import sys
import json
import time
import re
import threading
from datetime import datetime
from collections import defaultdict

IS_LINUX = sys.platform.startswith("linux")
AUDITD_LOG_PATH = "/var/log/audit/audit.log"


class AuditdCollector(threading.Thread):
    """Collects and parses Linux auditd logs."""

    def __init__(self, callback, audit_log_path=None, polling_interval=3):
        super().__init__(daemon=True)
        self.callback = callback
        self.audit_log_path = audit_log_path or AUDITD_LOG_PATH
        self.polling_interval = polling_interval
        self.running = False
        self._last_position = 0

    def start(self):
        """Start auditd collection."""
        if not IS_LINUX:
            print("[*] Auditd Collector: Not Linux, skipping")
            return
        if not os.path.exists(self.audit_log_path):
            print(f"[*] Auditd Collector: {self.audit_log_path} not found, auditd may not be installed")
            return
        self.running = True
        super().start()
        print(f"[*] Auditd Collector: Monitoring {self.audit_log_path}")

    def run(self):
        """Main collection loop."""
        # Start from end of file (skip existing)
        try:
            self._last_position = os.path.getsize(self.audit_log_path)
        except Exception:
            self._last_position = 0

        while self.running:
            try:
                self._read_new_events()
            except Exception as e:
                pass
            time.sleep(self.polling_interval)

    def _read_new_events(self):
        """Read new events from audit log since last position."""
        try:
            current_size = os.path.getsize(self.audit_log_path)
            if current_size < self._last_position:
                # Log rotated - reset position
                self._last_position = 0
            if current_size == self._last_position:
                return

            with open(self.audit_log_path, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(self._last_position)
                for line in f:
                    line = line.strip()
                    if line:
                        event = self._parse_audit_line(line)
                        if event:
                            self.callback(event)
                self._last_position = f.tell()
        except FileNotFoundError:
            pass
        except Exception:
            pass

    def _parse_audit_line(self, line):
        """Parse a single auditd log line into structured event."""
        try:
            # Basic format: type=SYSCALL msg=audit(1234567890.123:4567): ...
            type_match = re.search(r'type=(\w+)', line)
            if not type_match:
                return None
            event_type = type_match.group(1)

            # Skip low-value event types to reduce noise
            skip_types = {
                'PATH', 'CWD', 'PROCTITLE', 'NETFILTER_PKT',
                'SOCKADDR', 'SOCKETCALL', 'MMAP', 'ARCH_FILTER',
                'FS_RELABEL', 'UNKNOWN', 'AVC', 'USER_AVC',
            }
            if event_type in skip_types:
                return None

            # Extract audit timestamp
            ts_match = re.search(r'audit\((\d+\.\d+):(\d+)\)', line)
            timestamp = ""
            event_id = ""
            if ts_match:
                ts_epoch = float(ts_match.group(1))
                timestamp = datetime.fromtimestamp(ts_epoch).strftime("%Y-%m-%d %H:%M:%S")
                event_id = ts_match.group(2)

            # Extract key fields
            parsed = self._extract_key_value_pairs(line)
            parsed["type"] = event_type

            # Build event data
            event_data = {
                "type": "linux_audit",
                "event_type": event_type,
                "event_id": event_id,
                "timestamp": timestamp,
                "description": line[:500],
                "raw_data": line,
            }

            # Extract specific fields based on event type
            if event_type == "SYSCALL":
                event_data.update(self._parse_syscall(parsed))
            elif event_type == "EXECVE":
                event_data.update(self._parse_execve(line, parsed))
            elif event_type in ("USER_AUTH", "USER_LOGIN", "USER_START", "USER_END"):
                event_data.update(self._parse_user_auth(parsed))
            elif event_type in ("CRED_ACQ", "CRED_DISP", "CRED_REFR"):
                event_data.update(self._parse_credential(parsed))
            elif event_type.startswith("ANOM_"):
                event_data.update(self._parse_anomaly(parsed))
            elif event_type == "CONFIG_CHANGE":
                event_data.update(self._parse_config_change(parsed))
            elif event_type in ("SERVICE_START", "SERVICE_STOP"):
                event_data.update(self._parse_service(parsed))

            return event_data
        except Exception:
            return None

    def _extract_key_value_pairs(self, line):
        """Extract key=value pairs from audit log line."""
        parsed = {}
        # Match key=value or key="value" patterns
        for match in re.finditer(r'(\w+)=(?:"([^"]*)"|(\S+))', line):
            key = match.group(1)
            value = match.group(2) if match.group(2) is not None else match.group(3)
            parsed[key] = value
        return parsed

    def _parse_syscall(self, parsed):
        """Parse SYSCALL event."""
        syscall_map = {
            '2': 'open', '3': 'close', '4': 'stat', '5': 'fstat',
            '21': 'access', '56': 'openat', '59': 'execve',
            '257': 'openat2', '49': 'bind', '50': 'listen',
            '41': 'socket', '42': 'connect', '43': 'accept',
        }
        syscall = parsed.get("syscall", "")
        syscall_name = syscall_map.get(syscall, f"syscall_{syscall}")

        return {
            "syscall": syscall_name,
            "pid": parsed.get("pid", ""),
            "ppid": parsed.get("ppid", ""),
            "uid": parsed.get("uid", ""),
            "auid": parsed.get("auid", ""),
            "gid": parsed.get("gid", ""),
            "euid": parsed.get("euid", ""),
            "suid": parsed.get("suid", ""),
            "fsuid": parsed.get("fsuid", ""),
            "comm": parsed.get("comm", ""),
            "exe": parsed.get("exe", ""),
            "success": parsed.get("success", "") == "yes",
            "exit_code": parsed.get("exit", ""),
            "tty": parsed.get("tty", ""),
            "ses": parsed.get("ses", ""),
        }

    def _parse_execve(self, line, parsed):
        """Parse EXECVE event - command execution."""
        # Extract command arguments from the line
        cmd_match = re.search(r'argc=(\d+)', line)
        argc = int(cmd_match.group(1)) if cmd_match else 0
        args = []
        for i in range(argc):
            arg_match = re.search(rf'a{i}=(?:"([^"]*)"|(\S+))', line)
            if arg_match:
                args.append(arg_match.group(1) or arg_match.group(2))
        command = " ".join(args) if args else parsed.get("comm", "")

        return {
            "command": command[:500],
            "argc": argc,
            "pid": parsed.get("pid", ""),
            "uid": parsed.get("uid", ""),
            "auid": parsed.get("auid", ""),
        }

    def _parse_user_auth(self, parsed):
        """Parse authentication events."""
        return {
            "username": parsed.get("acct", parsed.get("uid", "")),
            "uid": parsed.get("uid", ""),
            "auid": parsed.get("auid", ""),
            "pid": parsed.get("pid", ""),
            "hostname": parsed.get("hostname", ""),
            "terminal": parsed.get("terminal", ""),
            "result": parsed.get("res", ""),
            "auth_method": parsed.get("op", ""),
        }

    def _parse_credential(self, parsed):
        """Parse credential events."""
        return {
            "pid": parsed.get("pid", ""),
            "uid": parsed.get("uid", ""),
            "auid": parsed.get("auid", ""),
            "acct": parsed.get("acct", ""),
            "exe": parsed.get("exe", ""),
            "hostname": parsed.get("addr", ""),
            "terminal": parsed.get("terminal", ""),
            "result": parsed.get("res", ""),
        }

    def _parse_anomaly(self, parsed):
        """Parse anomaly detection events."""
        return {
            "severity": "HIGH",
            "pid": parsed.get("pid", ""),
            "uid": parsed.get("uid", ""),
            "exe": parsed.get("exe", ""),
            "comm": parsed.get("comm", ""),
            "sig": parsed.get("sig", ""),
            "anomaly_type": parsed.get("type", ""),
        }

    def _parse_config_change(self, parsed):
        """Parse audit configuration change."""
        return {
            "severity": "MEDIUM",
            "pid": parsed.get("pid", ""),
            "uid": parsed.get("uid", ""),
            "auid": parsed.get("auid", ""),
            "ses": parsed.get("ses", ""),
            "op": parsed.get("op", ""),
            "key": parsed.get("key", ""),
            "list": parsed.get("list", ""),
        }

    def _parse_service(self, parsed):
        """Parse service start/stop event."""
        return {
            "pid": parsed.get("pid", ""),
            "uid": parsed.get("uid", ""),
            "auid": parsed.get("auid", ""),
            "unit": parsed.get("unit", parsed.get("comm", "")),
        }

    def stop(self):
        self.running = False