"""
FIM WhoData Collector for GIAM-SAT Agent v1.14.0

Enhances FIM with "who changed what" tracking:
  - Windows: Event ID 4663 (Object Access) + 4656/4658/4660 (Handle operations)
  - Linux: auditd rules for file access (open, write, chmod, chown, delete)

Requirements:
  - Windows: SACL configured on monitored directories (audit object access)
  - Linux: auditd installed and configured with file watch rules
"""

import os
import sys
import subprocess
import json
import re
import threading
import time
from datetime import datetime

IS_WINDOWS = os.name == "nt"
CREATE_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0


def _run_hidden(cmd, timeout=15, **kwargs):
    """Run a subprocess with hidden window on Windows."""
    if IS_WINDOWS:
        kwargs.setdefault("creationflags", CREATE_NO_WINDOW)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, **kwargs)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", "timeout", -1
    except Exception as e:
        return "", str(e), -1


class WhodataFIMCollector:
    """Tracks WHO modified monitored files using OS audit capabilities."""

    def __init__(self, callback=None):
        self.callback = callback
        self.running = False
        self.thread = None
        self._known_events = set()  # Dedup cache
        self._event_cache_size = 1000

    # =========================================================================
    # Windows: SACL-based via Event ID 4663
    # =========================================================================

    def enable_windows_audit(self, paths: list):
        """Enable SACL auditing on specified paths for who-data tracking.
        
        This must be done once (requires admin):
          auditpol /set /subcategory:"File System" /success:enable /failure:enable
          For each path: icacls PATH /setaudit SYSTEM:(OI)(CI)(F) /grant "Everyone":(RX)
        """
        if not IS_WINDOWS:
            return

        try:
            # Enable Object Access auditing
            _run_hidden(["auditpol", "/set", "/subcategory:File System",
                         "/success:enable", "/failure:enable"], timeout=10)
        except Exception:
            pass

    def collect_windows_whodata(self, last_minutes: int = 5) -> list:
        """Collect Windows who-data events (Event ID 4663 - Object Access)."""
        if not IS_WINDOWS:
            return []

        events = []
        try:
            # Query Security event log for object access events
            ps_script = (
                f"$start = (Get-Date).AddMinutes(-{last_minutes}); "
                "Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4663; StartTime=$start} "
                "-MaxEvents 50 -ErrorAction SilentlyContinue | "
                "Select-Object TimeCreated, Id, Message | ConvertTo-Json"
            )
            stdout, stderr, rc = _run_hidden(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
                timeout=30
            )

            if stdout:
                try:
                    data = json.loads(stdout)
                    if isinstance(data, dict):
                        data = [data]

                    for item in data:
                        msg = item.get("Message", "")
                        parsed = self._parse_4663_event(msg, item)
                        if parsed:
                            dedup_key = f"{parsed.get('process')}_{parsed.get('file_path')}_{parsed.get('timestamp')}"
                            if dedup_key not in self._known_events:
                                self._known_events.add(dedup_key)
                                if len(self._known_events) > self._event_cache_size:
                                    self._known_events.clear()
                                events.append(parsed)
                except (json.JSONDecodeError, TypeError):
                    pass
        except Exception:
            pass

        return events

    def _parse_4663_event(self, message: str, raw_item: dict) -> dict:
        """Parse Event ID 4663 message for who-data information."""
        try:
            # Extract Subject (who)
            subject_match = re.search(
                r'Subject:.*?Account Name:\s*(.+?)\s.*?Account Domain:\s*(.+?)\s',
                message, re.DOTALL
            )
            user = subject_match.group(1).strip() if subject_match else "Unknown"

            # Extract Process (which process)
            process_match = re.search(
                r'Process Name:\s*(.+?)\s.*?Process ID:\s*(\w+)',
                message
            )
            process = process_match.group(1).strip() if process_match else "Unknown"
            pid = process_match.group(2).strip() if process_match else "0"

            # Extract Object (what file)
            object_match = re.search(
                r'Object Name:\s*(.+?)\s.*?Handle ID:',
                message, re.DOTALL
            )
            file_path = object_match.group(1).strip() if object_match else "Unknown"

            # Extract Access (what was done)
            access_match = re.search(
                r'Accesses:\s*(.+?)\s.*?Access Mask:',
                message, re.DOTALL
            )
            access = access_match.group(1).strip() if access_match else "Access"

            # Parse access to determine action
            action = self._map_access_to_action(access)

            return {
                "type": "whodata_fim",
                "action": action,
                "user": user,
                "process": process,
                "pid": pid,
                "file_path": file_path,
                "access": access,
                "description": f"[{action}] {user} via {process} (PID:{pid}) -> {file_path}",
                "severity": "HIGH" if action in ("FILE_MODIFIED", "FILE_DELETED") else "MEDIUM",
                "timestamp": str(raw_item.get("TimeCreated", datetime.now())),
                "source": "windows_sacl",
                "event_id": "4663",
            }
        except Exception:
            return None

    def _map_access_to_action(self, access: str) -> str:
        """Map Windows SACL access mask to FIM action."""
        access_upper = access.upper()
        if any(w in access_upper for w in ["WRITE", "APPEND", "MODIFY", "DELETE"]):
            return "FILE_MODIFIED"
        if "DELETE" in access_upper:
            return "FILE_DELETED"
        if "CREATE" in access_upper or "WRITE_DATA" in access_upper:
            return "FILE_CREATED"
        return "FILE_ACCESSED"

    # =========================================================================
    # Linux: auditd rules
    # =========================================================================

    def setup_linux_audit_rules(self, paths: list):
        """Configure auditd rules for who-data FIM.
        
        Requires root. Sets up rules like:
          -a always,exit -F path=/etc/passwd -F perm=wa -k whodata_passwd
        """
        if IS_WINDOWS:
            return

        for path in paths:
            if not os.path.exists(path):
                continue
            rule_key = f"whodata_{os.path.basename(path).replace('.', '_')}"
            try:
                _run_hidden(["auditctl", "-a", "always,exit", "-F",
                             f"path={path}", "-F", "perm=wa", "-k", rule_key],
                            timeout=5)
            except Exception:
                pass

    def collect_linux_whodata(self, last_minutes: int = 5) -> list:
        """Collect Linux who-data events from auditd logs."""
        if IS_WINDOWS:
            return []

        events = []
        try:
            # Use ausearch to query recent audit events
            stdout, stderr, rc = _run_hidden(
                ["ausearch", "-k", "whodata", "-ts", f"recent:{last_minutes}min",
                 "--format", "text"],
                timeout=15
            )

            if stdout:
                events.extend(self._parse_ausearch_output(stdout))
        except Exception:
            pass

        return events

    def _parse_ausearch_output(self, output: str) -> list:
        """Parse ausearch output for who-data events."""
        events = []
        current_event = {}

        for line in output.split("\n"):
            line = line.strip()
            if not line:
                if current_event:
                    events.append(self._format_linux_event(current_event))
                    current_event = {}
                continue

            # Parse key=value pairs
            if "type=" in line:
                current_event["audit_type"] = re.search(r'type=(\w+)', line).group(1) if re.search(r'type=(\w+)', line) else ""

            for key in ["auid", "uid", "comm", "exe", "name", "syscall", "success"]:
                match = re.search(rf'{key}=(\S+)', line)
                if match:
                    current_event[key] = match.group(1).strip('"')

            if "msg=audit" in line:
                current_event["raw"] = line

        # Process last event
        if current_event:
            events.append(self._format_linux_event(current_event))

        return events

    def _format_linux_event(self, event: dict) -> dict:
        """Format Linux auditd event for GIAM-SAT."""
        uid = event.get("uid", "unknown")
        comm = event.get("comm", "unknown")
        exe = event.get("exe", "unknown")
        file_name = event.get("name", "unknown")
        syscall = event.get("syscall", "")
        success = event.get("success", "unknown")

        # Map syscall to action
        action_map = {
            "open": "FILE_ACCESSED", "openat": "FILE_ACCESSED",
            "write": "FILE_MODIFIED", "pwrite64": "FILE_MODIFIED",
            "chmod": "FILE_MODIFIED", "fchmodat": "FILE_MODIFIED",
            "chown": "FILE_MODIFIED", "fchownat": "FILE_MODIFIED",
            "unlink": "FILE_DELETED", "unlinkat": "FILE_DELETED",
            "rename": "FILE_RENAMED", "renameat": "FILE_RENAMED",
            "creat": "FILE_CREATED",
        }
        action = action_map.get(syscall, "FILE_ACCESSED")

        return {
            "type": "whodata_fim",
            "action": action,
            "user": f"uid={uid}",
            "process": comm,
            "exe_path": exe,
            "file_path": file_name,
            "syscall": syscall,
            "success": success == "yes",
            "description": f"[{action}] uid={uid} via {comm} ({exe}) -> {file_name}",
            "severity": "HIGH" if action in ("FILE_MODIFIED", "FILE_DELETED") else "MEDIUM",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "source": "linux_auditd",
            "audit_type": event.get("audit_type", ""),
        }

    # =========================================================================
    # Unified Collection
    # =========================================================================

    def collect_all(self, last_minutes: int = 5) -> list:
        """Collect all who-data FIM events."""
        all_events = []

        if IS_WINDOWS:
            all_events.extend(self.collect_windows_whodata(last_minutes))
        else:
            all_events.extend(self.collect_linux_whodata(last_minutes))

        for ev in all_events:
            if self.callback:
                self.callback(ev)

        return all_events

    def start_background(self, interval_seconds: int = 60):
        """Start background collection thread."""
        self.running = True
        self.thread = threading.Thread(
            target=self._background_loop,
            args=(interval_seconds,),
            daemon=True
        )
        self.thread.start()

    def _background_loop(self, interval_seconds: int):
        """Background collection loop."""
        while self.running:
            try:
                self.collect_all(last_minutes=max(1, interval_seconds // 60))
            except Exception:
                pass
            time.sleep(interval_seconds)

    def stop(self):
        """Stop background collection."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)