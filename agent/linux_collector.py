"""
Linux Collector for GIAM-SAT Agent v1.6.0
Collects logs on Linux: journald, auth.log, syslog, auditd + FIM via inotify.
Uses only stdlib + optional pyinotify. Falls back to polling.
"""
import os
import sys
import json
import time
import threading
import hashlib
import fnmatch
import subprocess
from datetime import datetime

PLATFORM = sys.platform


class LinuxEventCollector:
    """Collects system events on Linux from journald and log files."""

    def __init__(self, callback):
        self.callback = callback
        self.running = True
        self.last_journal_cursor = None
        self._has_journald = self._check_journald()

    def _check_journald(self):
        try:
            subprocess.run(["journalctl", "--version"], capture_output=True, timeout=5)
            return True
        except Exception:
            return False

    def _get_journal_events(self):
        """Read new events from journald since last cursor."""
        events = []
        try:
            args = ["journalctl", "-o", "json", "-n", "200", "--no-pager"]
            if self.last_journal_cursor:
                args.extend(["--after-cursor", self.last_journal_cursor])
            result = subprocess.run(args, capture_output=True, text=True, timeout=10)
            lines = [l.strip() for l in result.stdout.split("\n") if l.strip()]
            for line in lines:
                try:
                    entry = json.loads(line)
                    self.last_journal_cursor = entry.get("__CURSOR", self.last_journal_cursor)
                    event_type = "linux_event"
                    if entry.get("_TRANSPORT") == "audit" or "AUDIT" in entry.get("MESSAGE", ""):
                        event_type = "linux_audit"
                    evt = {
                        "type": event_type,
                        "subtype": entry.get("_SYSTEMD_UNIT", entry.get("SYSLOG_IDENTIFIER", "")),
                        "event_id": entry.get("PRIORITY", "6"),
                        "source": "journald",
                        "user": entry.get("_UID", ""),
                        "time": entry.get("__REALTIME_TIMESTAMP", ""),
                        "description": entry.get("MESSAGE", "")[:2000],
                        "raw_data": json.dumps(entry, ensure_ascii=False),
                    }
                    events.append(evt)
                except json.JSONDecodeError:
                    continue
        except Exception as e:
            pass
        return events

    def _get_logfile_events(self, logfile, last_pos_map):
        """Tail a log file and return new lines."""
        events = []
        if not os.path.exists(logfile):
            return events
        try:
            with open(logfile, "r", errors="ignore") as f:
                last_pos = last_pos_map.get(logfile, 0)
                f.seek(0, 2)
                current_size = f.tell()
                if current_size < last_pos:
                    last_pos = 0
                f.seek(last_pos)
                lines = f.readlines()
                last_pos_map[logfile] = f.tell()
                for line in lines[-500:]:
                    line = line.strip()
                    if line:
                        events.append({
                            "type": "linux_event",
                            "subtype": os.path.basename(logfile),
                            "source": logfile,
                            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "description": line[:2000],
                        })
        except Exception:
            pass
        return events

    def collect_events(self):
        events = []
        if self._has_journald:
            events.extend(self._get_journal_events())
        return events

    def stop(self):
        self.running = False


class LinuxFIMCollector:
    """File Integrity Monitoring on Linux using polling + SHA256."""

    def __init__(self, callback):
        self.callback = callback
        self.running = True
        self.watch_dirs = ["/etc", "/var/www", "/home", "/opt", "/root"]
        self.exclude_patterns = ["*.log", "*.tmp", "*.swp", "__pycache__"]
        self.last_hashes = {}

    def _should_exclude(self, path):
        for pat in self.exclude_patterns:
            if fnmatch.fnmatch(os.path.basename(path), pat):
                return True
        return False

    def _sha256_file(self, path):
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None

    def scan(self):
        events = []
        for watch_dir in self.watch_dirs:
            if not os.path.isdir(watch_dir):
                continue
            for root, dirs, files in os.walk(watch_dir):
                if any(x in root for x in ["/proc", "/sys", "/dev", "/run"]):
                    continue
                for fname in files:
                    fpath = os.path.join(root, fname)
                    if self._should_exclude(fpath):
                        continue
                    try:
                        stat = os.stat(fpath)
                        mtime = stat.st_mtime
                        prev = self.last_hashes.get(fpath)
                        current_hash = None
                        if prev and prev.get("mtime") == mtime:
                            continue
                        current_hash = self._sha256_file(fpath)
                        if not current_hash:
                            continue
                        if prev:
                            if prev.get("sha256") != current_hash:
                                events.append({
                                    "type": "fim", "action": "FILE_MODIFIED",
                                    "path": fpath, "sha256": current_hash,
                                    "old_sha256": prev.get("sha256", ""),
                                    "owner": self._get_owner(fpath),
                                })
                        else:
                            events.append({
                                "type": "fim", "action": "FILE_DISCOVERED",
                                "path": fpath, "sha256": current_hash,
                                "owner": self._get_owner(fpath),
                            })
                        self.last_hashes[fpath] = {"sha256": current_hash, "mtime": mtime}
                    except OSError:
                        continue
        return events

    def _get_owner(self, path):
        try:
            import pwd
            stat = os.stat(path)
            return pwd.getpwuid(stat.st_uid).pw_name
        except Exception:
            return str(os.stat(path).st_uid) if os.path.exists(path) else "unknown"

    def stop(self):
        self.running = False


class LinuxHWCollector:
    """Collects hardware/OS info on Linux."""

    def collect(self):
        data = {
            "os": self._get_os(),
            "cpu": self._get_cpu(),
            "memory": self._get_memory(),
            "disks": self._get_disks(),
            "network": self._get_network(),
            "packages": self._get_packages()[:200],
        }
        return data

    def _get_os(self):
        try:
            result = subprocess.run(["cat", "/etc/os-release"], capture_output=True, text=True, timeout=5)
            lines = {}
            for line in result.stdout.split("\n"):
                if "=" in line:
                    k, v = line.split("=", 1)
                    lines[k] = v.strip('"')
            return {"name": lines.get("PRETTY_NAME", subprocess.run(["uname", "-sr"], capture_output=True, text=True).stdout.strip()),
                    "kernel": subprocess.run(["uname", "-r"], capture_output=True, text=True).stdout.strip()}
        except Exception:
            return {"name": "Linux", "kernel": ""}

    def _get_cpu(self):
        try:
            result = subprocess.run(["lscpu"], capture_output=True, text=True, timeout=5)
            lines = result.stdout.split("\n")
            info = {}
            for line in lines:
                if ":" in line:
                    k, v = line.split(":", 1)
                    info[k.strip()] = v.strip()
            return {"model": info.get("Model name", ""), "cores": info.get("CPU(s)", ""),
                    "threads": info.get("Thread(s) per core", "")}
        except Exception:
            return {}

    def _get_memory(self):
        try:
            result = subprocess.run(["free", "-h"], capture_output=True, text=True, timeout=5)
            return {"total": result.stdout.split("\n")[1].split()[1] if len(result.stdout.split("\n")) > 1 else "unknown"}
        except Exception:
            return {}

    def _get_disks(self):
        try:
            result = subprocess.run(["lsblk", "-o", "NAME,SIZE,TYPE,MOUNTPOINT", "-J"], capture_output=True, text=True, timeout=5)
            return json.loads(result.stdout) if result.stdout else []
        except Exception:
            return []

    def _get_network(self):
        try:
            result = subprocess.run(["ip", "-j", "addr"], capture_output=True, text=True, timeout=5)
            return json.loads(result.stdout) if result.stdout else []
        except Exception:
            return []

    def _get_packages(self):
        try:
            for cmd in [["dpkg", "-l"], ["rpm", "-qa"]]:
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    return result.stdout.strip().split("\n")
                except Exception:
                    continue
        except Exception:
            return []


class LinuxNetworkCollector:
    """Network stats collector for Linux."""

    def __init__(self, callback):
        self.callback = callback
        self.running = True

    def collect_connections(self):
        """Get active network connections from /proc/net/tcp, /proc/net/udp."""
        events = []
        try:
            result = subprocess.run(["ss", "-tunap"], capture_output=True, text=True, timeout=5)
            for line in result.stdout.split("\n")[1:]:
                parts = line.split()
                if len(parts) >= 5:
                    events.append({
                        "type": "network_traffic",
                        "protocol": parts[0].upper(),
                        "src_ip": parts[3].rsplit(":", 1)[0] if len(parts) > 3 else "",
                        "dst_ip": parts[4].rsplit(":", 1)[0] if len(parts) > 4 else "",
                        "src_port": int(parts[3].rsplit(":", 1)[1]) if len(parts) > 3 and ":" in parts[3] else 0,
                        "dst_port": int(parts[4].rsplit(":", 1)[1]) if len(parts) > 4 and ":" in parts[4] else 0,
                        "state": parts[1] if len(parts) > 1 else "UNKNOWN",
                    })
        except Exception:
            pass
        return events

    def stop(self):
        self.running = False