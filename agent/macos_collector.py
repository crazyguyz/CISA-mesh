"""
macOS Unified Log Collector for GIAM-SAT Agent v1.13.0

Collects macOS system logs from:
  - Unified Log (log stream --style syslog)
  - System Log (/var/log/system.log)
  - Security events (log show --predicate for TCC, auth)
  - Application Firewall logs (alf)

Requirements: macOS 10.12+ with log command access (requires admin/sudo for real-time).
"""

import os
import sys
import subprocess
import json
import time
import threading
import re
from datetime import datetime, timedelta

IS_MACOS = sys.platform == "darwin"
CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0


def _run(cmd, timeout=10, **kwargs):
    """Run a command with timeout."""
    if IS_MACOS:
        kwargs.setdefault("creationflags", CREATE_NO_WINDOW)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, **kwargs)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", "timeout", -1
    except Exception as e:
        return "", str(e), -1


class MacOSLogCollector:
    """Collects macOS security-relevant log events."""

    def __init__(self, callback=None):
        self.callback = callback
        self.running = False
        self.thread = None
        self._last_position = {}  # Track last read position per log source
        self._noise_filter = self._build_noise_filter()

    def _build_noise_filter(self):
        """Build noise filter for common macOS log spam."""
        return [
            re.compile(p, re.IGNORECASE) for p in [
                r"com\.apple\.webkit",           # Browser noise
                r"CoreBrightness",                # Display brightness
                r"IOHIDLib",                      # HID input
                r"com\.apple\.CFNetwork",         # Network framework noise
                r"distnoted",                     # Notification service
                r"mDNSResponder",                 # Bonjour
                r"trustd",                        # Certificate trust
                r"syslogd",                       # Syslog daemon
                r"logd",                          # Log daemon
                r"\.SFLList",                     # Spotlight
            ]
        ]

    def _is_noise(self, line: str) -> bool:
        """Check if a log line is noise."""
        for pattern in self._noise_filter:
            if pattern.search(line):
                return True
        return False

    def _normalize_severity(self, line: str) -> str:
        """Map macOS log severity to GIAM-SAT standard."""
        upper = line.upper()
        if "FAULT" in upper or "CRITICAL" in upper:
            return "CRITICAL"
        if "ERROR" in upper or "FAIL" in upper:
            return "HIGH"
        if "WARN" in upper:
            return "MEDIUM"
        if "INFO" in upper or "DEBUG" in upper:
            return "INFO"
        return "LOW"

    def _parse_unified_log_line(self, line: str) -> dict:
        """Parse a macOS unified log line into structured event."""
        try:
            # Format: 2024-01-15 10:30:45.123456+0700 0x12345  Default  0x0  12345  process: (lib[PID]) <Notice>: message
            timestamp_match = re.match(
                r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})[\.\d+]*\s+\w+\s+\w+\s+\w+\s+\d+\s+([^:]+):\s*(.+)',
                line
            )
            if timestamp_match:
                ts = timestamp_match.group(1)
                process = timestamp_match.group(2).strip()
                message = timestamp_match.group(3)

                severity = self._normalize_severity(message)

                return {
                    "type": "macos_event",
                    "subtype": "unified_log",
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "source_timestamp": ts,
                    "process": process,
                    "description": f"[{process}] {message[:500]}",
                    "severity": severity,
                    "raw_line": line[:1000],
                }
        except Exception:
            pass

        return {
            "type": "macos_event",
            "subtype": "unified_log",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "description": line[:500],
            "severity": "LOW",
            "raw_line": line[:1000],
        }

    def collect(self):
        """Main collection loop - runs in background thread."""
        if not IS_MACOS:
            return

        self.running = True

        # Start real-time log stream
        try:
            # log stream: real-time events
            # Predicate: security-related events only
            predicate = (
                '(subsystem CONTAINS "com.apple.securityd") OR '
                '(subsystem CONTAINS "com.apple.TCC") OR '
                '(subsystem CONTAINS "com.apple.alf") OR '
                '(subsystem CONTAINS "com.apple.auditd") OR '
                '(category CONTAINS "access") OR '
                '(category CONTAINS "auth") OR '
                '(eventMessage CONTAINS "failed") OR '
                '(eventMessage CONTAINS "denied") OR '
                '(eventMessage CONTAINS "error") OR '
                '(eventMessage CONTAINS "throttle")'
            )

            process = subprocess.Popen(
                ["log", "stream", "--style", "syslog", "--predicate", predicate, "--type", "log"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )

            for line in process.stdout:
                if not self.running:
                    break
                line = line.strip()
                if line and not self._is_noise(line):
                    event = self._parse_unified_log_line(line)
                    if event and self.callback:
                        self.callback(event)

        except Exception as e:
            pass

        self.running = False

    def collect_historical(self, hours: int = 1):
        """Collect historical logs from the last N hours."""
        if not IS_MACOS:
            return []

        events = []

        try:
            # log show for historical data
            since = (datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
            predicate = '(eventMessage CONTAINS[cd] "error") OR (eventMessage CONTAINS[cd] "fail")'

            stdout, stderr, rc = _run(
                ["log", "show", "--style", "syslog", "--predicate", predicate,
                 "--start", since, "--info", "--last", "1h"],
                timeout=30
            )

            if stdout:
                for line in stdout.split("\n"):
                    line = line.strip()
                    if line and not self._is_noise(line):
                        event = self._parse_unified_log_line(line)
                        if event:
                            events.append(event)

        except Exception:
            pass

        # Also check system.log
        try:
            if os.path.exists("/var/log/system.log"):
                stdout, stderr, rc = _run(
                    ["tail", "-n", "500", "/var/log/system.log"],
                    timeout=10
                )
                if stdout:
                    for line in stdout.split("\n")[-200:]:
                        line = line.strip()
                        if line and ("error" in line.lower() or "fail" in line.lower() or "denied" in line.lower()):
                            if not self._is_noise(line):
                                events.append({
                                    "type": "macos_event",
                                    "subtype": "system_log",
                                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                    "description": line[:500],
                                    "severity": self._normalize_severity(line),
                                })
        except Exception:
            pass

        return events

    def check_security_config(self) -> list:
        """Check macOS security configurations and report findings."""
        findings = []

        # Check System Integrity Protection (SIP)
        try:
            stdout, stderr, rc = _run(["csrutil", "status"])
            if "enabled" in stdout.lower():
                findings.append({
                    "type": "sca_event",
                    "check_id": "MACOS-SIP",
                    "title": "System Integrity Protection",
                    "status": "PASS",
                    "severity": "LOW",
                    "description": "SIP is enabled",
                })
            else:
                findings.append({
                    "type": "sca_event",
                    "check_id": "MACOS-SIP",
                    "title": "System Integrity Protection",
                    "status": "FAIL",
                    "severity": "CRITICAL",
                    "description": "SIP is disabled - system is vulnerable to rootkits",
                    "remediation": "Boot to Recovery and run: csrutil enable",
                })
        except Exception:
            pass

        # Check Gatekeeper
        try:
            stdout, stderr, rc = _run(["spctl", "--status"])
            if "enabled" in stdout.lower():
                findings.append({
                    "type": "sca_event",
                    "check_id": "MACOS-GATEKEEPER",
                    "title": "Gatekeeper",
                    "status": "PASS",
                    "severity": "LOW",
                    "description": "Gatekeeper is enabled",
                })
        except Exception:
            pass

        # Check Firewall
        try:
            stdout, stderr, rc = _run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
            if "enabled" in stdout.lower() or "on" in stdout.lower():
                findings.append({
                    "type": "sca_event",
                    "check_id": "MACOS-FW",
                    "title": "Application Firewall",
                    "status": "PASS",
                    "severity": "LOW",
                    "description": "macOS Firewall is active",
                })
            else:
                findings.append({
                    "type": "sca_event",
                    "check_id": "MACOS-FW",
                    "title": "Application Firewall",
                    "status": "FAIL",
                    "severity": "HIGH",
                    "description": "macOS Firewall is disabled",
                    "remediation": "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on",
                })
        except Exception:
            pass

        # Check FileVault (encryption)
        try:
            stdout, stderr, rc = _run(["fdesetup", "status"])
            if "on" in stdout.lower():
                findings.append({
                    "type": "sca_event",
                    "check_id": "MACOS-FILEVAULT",
                    "title": "FileVault Encryption",
                    "status": "PASS",
                    "severity": "LOW",
                    "description": "FileVault is enabled",
                })
            else:
                findings.append({
                    "type": "sca_event",
                    "check_id": "MACOS-FILEVAULT",
                    "title": "FileVault Encryption",
                    "status": "FAIL",
                    "severity": "HIGH",
                    "description": "FileVault is disabled",
                    "remediation": "System Preferences > Security & Privacy > FileVault > Turn On",
                })
        except Exception:
            pass

        return findings

    def start(self):
        """Start background collection."""
        if not IS_MACOS:
            return
        self.thread = threading.Thread(target=self.collect, daemon=True)
        self.thread.start()

    def stop(self):
        """Stop background collection."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)