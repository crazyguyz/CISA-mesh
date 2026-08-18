"""
File Integrity Monitoring (FIM) Collector for GIAM-SAT Agent v1.7.0
Real-time file change detection using watchdog (inotify/WinAPI).
Falls back to polling mode when watchdog is not available.
Monitors file creations, modifications, deletions with SHA256 hashing.
"""
import os
import sys
import json
import time
import hashlib
import threading
import getpass
from datetime import datetime
import urllib.request
import socket

IS_WINDOWS = os.name == "nt"

# Try importing watchdog for real-time monitoring
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False


def sha256_file(filepath):
    """Calculate SHA256 hash of a file."""
    try:
        sha = hashlib.sha256()
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                sha.update(chunk)
        return sha.hexdigest()
    except Exception:
        return "UNKNOWN"


def _get_file_info(filepath):
    """Get file metadata."""
    try:
        stat = os.stat(filepath)
        return {
            "size": stat.st_size,
            "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
            "hash": sha256_file(filepath),
        }
    except Exception:
        return {"size": 0, "modified": "", "hash": "UNKNOWN"}


class FIMEventHandler(FileSystemEventHandler):
    """Watchdog event handler for FIM events."""

    def __init__(self, callback, monitored_paths, exclude_patterns=None):
        super().__init__()
        self.callback = callback
        self.monitored_paths = monitored_paths
        self.exclude_patterns = exclude_patterns or []
        self._debounce = {}  # Prevent duplicate events

    def _should_skip(self, path):
        """Check if path should be excluded.
        v4.10 (LOW-10): a pattern starting with '.' is treated as a file
        extension match (endswith) - the old substring match meant '.log'
        excluded every path containing '.log' (e.g. evil.log.ps1)."""
        low = path.lower()
        for pattern in self.exclude_patterns:
            p = str(pattern).lower().strip()
            if not p:
                continue
            if p.startswith("."):
                if low.endswith(p):
                    return True
            elif p in low:
                return True
        return False

    def _should_debounce(self, event_key, debounce_seconds=2):
        """Prevent duplicate events within debounce window."""
        now = time.time()
        if event_key in self._debounce:
            if now - self._debounce[event_key] < debounce_seconds:
                return True
        self._debounce[event_key] = now
        # Clean old entries
        if len(self._debounce) > 1000:
            old_keys = [k for k, v in self._debounce.items() if now - v > 10]
            for k in old_keys:
                del self._debounce[k]
        return False

    def on_created(self, event):
        if event.is_directory:
            return
        if self._should_skip(event.src_path):
            return
        if self._should_debounce(f"created:{event.src_path}"):
            return

        info = _get_file_info(event.src_path)
        data = {
            "type": "fim_event",
            "action": "FILE_CREATED",
            "path": event.src_path,
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "hash": info["hash"],
            "size": info["size"],
        }
        self.callback(data)

    def on_modified(self, event):
        if event.is_directory:
            return
        if self._should_skip(event.src_path):
            return
        if self._should_debounce(f"modified:{event.src_path}"):
            return

        info = _get_file_info(event.src_path)
        data = {
            "type": "fim_event",
            "action": "FILE_MODIFIED",
            "path": event.src_path,
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "hash": info["hash"],
            "size": info["size"],
        }
        self.callback(data)

    def on_deleted(self, event):
        if event.is_directory:
            return
        if self._should_skip(event.src_path):
            return
        if self._should_debounce(f"deleted:{event.src_path}"):
            return

        data = {
            "type": "fim_event",
            "action": "FILE_DELETED",
            "path": event.src_path,
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "hash": "N/A (deleted)",
            "size": 0,
        }
        self.callback(data)

    def on_moved(self, event):
        """File renamed/moved."""
        if event.is_directory:
            return
        if self._should_skip(event.dest_path):
            return

        # Only fire one event for the move
        info = _get_file_info(event.dest_path)
        data = {
            "type": "fim_event",
            "action": "FILE_MODIFIED",
            "path": event.dest_path,
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "hash": info["hash"],
            "size": info["size"],
            "old_path": event.src_path,
        }
        self.callback(data)


class FIMCollector:
    """File Integrity Monitoring Collector - Real-time (watchdog) with polling fallback."""

    DEFAULT_WATCH_PATHS = [
        # Critical Windows paths
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        "C:\\Windows\\Temp",
        # User startup folders (scanned at runtime)
        # User Documents/Desktop (optional, configurable)
    ]

    DEFAULT_LINUX_PATHS = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/sudoers",
        "/etc/ssh/sshd_config",
        "/etc/crontab",
        "/etc/cron.d",
        "/var/spool/cron",
        "/usr/bin",
        "/usr/sbin",
        "/tmp",
    ]

    MAX_FILES_PER_PATH = 500  # v3.7.2: Limit baseline file count per watch path

    def __init__(self, callback, watch_paths=None, polling_interval=10,
                 exclude_patterns=None):
        self.callback = callback
        self.polling_interval = polling_interval
        self.exclude_patterns = exclude_patterns or []
        self.running = False
        self.observer = None
        self._hash_cache = {}
        self._thread = None

        # Determine watch paths
        if watch_paths:
            self.watch_paths = watch_paths
        elif IS_WINDOWS:
            self.watch_paths = list(self.DEFAULT_WATCH_PATHS)
            # Add user profile startup folders
            try:
                users_dir = "C:\\Users"
                if os.path.exists(users_dir):
                    for user in os.listdir(users_dir):
                        startup = os.path.join(users_dir, user,
                                               "AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup")
                        if os.path.exists(startup):
                            self.watch_paths.append(startup)
            except Exception:
                pass
        else:
            self.watch_paths = list(self.DEFAULT_LINUX_PATHS)

        # v3.7.2: Expanded exclude patterns to reduce baseline noise
        if IS_WINDOWS:
            self.exclude_patterns.extend([
                ".log", ".tmp", ".temp", "NTUSER.DAT", "UsrClass.dat",
                "IconCache.db", "Thumbs.db",
                # v3.7.2 additions
                ".etl", ".pf", ".dmp", ".cache", ".db-shm", ".db-wal",
                "\\Prefetch\\", "\\INetCache\\", "\\Local\\Temp\\",
                "\\Windows\\ServiceProfiles\\",
            ])
        else:
            self.exclude_patterns.extend([
                ".log", ".tmp", ".swp", ".swx", "~",
                # v3.7.2 additions
                ".cache", "/var/log/", "/var/cache/", "/tmp/",
            ])

    def start(self):
        """Start FIM monitoring."""
        self.running = True
        if HAS_WATCHDOG:
            self._start_watchdog()
        else:
            self._start_polling()

    def _start_watchdog(self):
        """Start real-time monitoring with watchdog."""
        try:
            self.observer = Observer()
            handler = FIMEventHandler(self.callback, self.watch_paths, self.exclude_patterns)

            # Watch directories separately from single files
            watched_dirs = set()
            for path in self.watch_paths:
                if os.path.isfile(path):
                    watch_dir = os.path.dirname(path)
                elif os.path.isdir(path):
                    watch_dir = path
                else:
                    continue

                if watch_dir not in watched_dirs:
                    try:
                        self.observer.schedule(handler, watch_dir, recursive=True)
                        watched_dirs.add(watch_dir)
                    except Exception:
                        continue

            self.observer.start()
            print(f"[*] FIM: Real-time monitoring ({len(watched_dirs)} directories) via watchdog")
            # v2.1.8 FIX: Build hash cache and send baseline to server (was only in polling mode)
            threading.Thread(target=self._build_hash_cache, daemon=True).start()
        except Exception as e:
            print(f"[!] FIM watchdog failed: {e}, falling back to polling")
            self._start_polling()

    def _start_polling(self):
        """Start interval-based polling (fallback)."""
        print(f"[*] FIM: Polling mode (interval={self.polling_interval}s)")
        self.running = True
        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()

    def _poll_loop(self):
        """Polling loop for file changes."""
        # Build initial hash cache
        self._build_hash_cache()

        while self.running:
            time.sleep(self.polling_interval)
            self._check_changes()

    # v3.7.2: Priority extensions for file hashing (executables first)
    _PRIORITY_EXTS = {".exe", ".dll", ".sys", ".bat", ".ps1", ".vbs", ".scr", ".msi", ".com", ".cmd", ".hta", ".jar",
                      ".py", ".sh", ".pl", ".rb", ".js", ".vba", ".wsf", ".wsh"}

    def _build_hash_cache(self):
        """Build initial hash cache from watch paths (v3.7.2: limited + prioritized)."""
        discovered = []  # (priority, fpath) - lower priority = more important
        for root_path in self.watch_paths:
            try:
                if os.path.isfile(root_path):
                    priority = self._file_priority(root_path)
                    discovered.append((priority, root_path))
                elif os.path.isdir(root_path):
                    for dirpath, dirnames, filenames in os.walk(root_path):
                        for fname in filenames:
                            fpath = os.path.join(dirpath, fname)
                            if any(p in fpath for p in self.exclude_patterns):
                                continue
                            priority = self._file_priority(fpath)
                            discovered.append((priority, fpath))
            except Exception:
                pass
        # Sort: low priority (important) first, then alphabetically
        discovered.sort(key=lambda x: (x[0], x[1]))
        # Limit to MAX_FILES_PER_PATH per path group, overall MAX_FILES_PER_PATH * 4
        max_total = self.MAX_FILES_PER_PATH * max(1, len(self.watch_paths))
        for _, fpath in discovered[:max_total]:
            self._hash_cache[fpath] = sha256_file(fpath)
        print(f"[*] FIM: Hashed {len(self._hash_cache)}/{len(discovered)} files (limit={max_total})")
        # Send initial baseline to server
        self._send_baseline_to_server()

    def _file_priority(self, fpath):
        """v3.7.2: Return priority score for file (0 = highest priority)."""
        path_lower = fpath.lower()
        ext = os.path.splitext(fpath)[1].lower()
        if ext in self._PRIORITY_EXTS:
            return 0  # Highest: executables / scripts
        if "startup" in path_lower or "\\drivers\\etc\\" in path_lower:
            return 1  # High: startup / hosts files
        if "\\windows\\system32\\" in path_lower or "\\windows\\syswow64\\" in path_lower:
            return 2  # Medium-high: system binaries
        if ext in {".ini", ".cfg", ".conf", ".xml", ".yaml", ".yml", ".json"}:
            return 3  # Medium: config files
        if "\\windows\\temp\\" in path_lower or "\\temp\\" in path_lower:
            return 9  # Lowest: temp files
        return 5  # Default: other files

    def _check_changes(self):
        """Check for file changes compared to hash cache."""
        current_files = set()
        detected_changes = []

        for root_path in self.watch_paths:
            try:
                if os.path.isfile(root_path):
                    current_files.add(root_path)
                    if root_path in self._hash_cache:
                        new_hash = sha256_file(root_path)
                        if new_hash != self._hash_cache[root_path]:
                            detected_changes.append({
                                "action": "FILE_MODIFIED",
                                "path": root_path,
                                "hash": new_hash,
                            })
                            self._hash_cache[root_path] = new_hash
                    else:
                        # New file detected
                        detected_changes.append({
                            "action": "FILE_CREATED",
                            "path": root_path,
                            "hash": sha256_file(root_path),
                        })
                        self._hash_cache[root_path] = self._hash_cache.get(root_path, "")
                elif os.path.isdir(root_path):
                    for dirpath, dirnames, filenames in os.walk(root_path):
                        for fname in filenames:
                            fpath = os.path.join(dirpath, fname)
                            if any(p in fpath for p in self.exclude_patterns):
                                continue
                            current_files.add(fpath)
                            if fpath not in self._hash_cache:
                                detected_changes.append({
                                    "action": "FILE_CREATED",
                                    "path": fpath,
                                    "hash": sha256_file(fpath),
                                })
                                self._hash_cache[fpath] = ""
                            else:
                                new_hash = sha256_file(fpath)
                                if new_hash != self._hash_cache[fpath]:
                                    detected_changes.append({
                                        "action": "FILE_MODIFIED",
                                        "path": fpath,
                                        "hash": new_hash,
                                    })
                                    self._hash_cache[fpath] = new_hash
            except Exception:
                pass

        # Check for deleted files
        deleted = set(self._hash_cache.keys()) - current_files
        for fpath in deleted:
            detected_changes.append({
                "action": "FILE_DELETED",
                "path": fpath,
                "hash": "N/A (deleted)",
            })

        # Clean deleted from cache
        for fpath in deleted:
            del self._hash_cache[fpath]

        # Send events
        for change in detected_changes:
            data = {
                "type": "fim_event",
                "action": change["action"],
                "path": change["path"],
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "hash": change["hash"] if change["hash"] else "UNKNOWN",
                "size": os.path.getsize(change["path"]) if os.path.exists(change["path"]) else 0,
            }
            self.callback(data)

    _BASELINE_CHUNK_SIZE = 200  # v3.7.2: Chunk size for baseline sync

    def _send_baseline_to_server(self):
        """Send FIM baseline in chunks to avoid timeout (v3.7.2)."""
        try:
            # Build baseline payload
            baseline_files = []
            current_user = ""
            try:
                current_user = getpass.getuser()
            except Exception:
                pass
            for fpath, fhash in self._hash_cache.items():
                try:
                    stat = os.stat(fpath)
                    baseline_files.append({
                        "path": fpath,
                        "hash": fhash,
                        "size": stat.st_size,
                        "owner": current_user,
                        "permissions": oct(stat.st_mode)[-3:],
                        "last_modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                    })
                except Exception:
                    baseline_files.append({
                        "path": fpath, "hash": fhash, "size": 0,
                        "owner": "", "permissions": "", "last_modified": ""
                    })

            if not baseline_files:
                return

            server_host = "127.0.0.1"
            server_port = 6666
            machine_id = "unknown"
            hostname = socket.gethostname()
            psk = ""

            # Try to get config from agent if available
            try:
                from config_manager import ConfigManager
                cfg = ConfigManager()
                server_host = cfg.get("server_host", server_host)
                server_port = cfg.get("server_port", server_port)
                machine_id = cfg.get("machine_id", machine_id)
                hostname = cfg.get("hostname", hostname)
                psk = cfg.get("psk", "")
            except Exception:
                pass

            # v3.7.2: Send in chunks to avoid timeout with large baselines
            total = len(baseline_files)
            total_changed = 0
            for i in range(0, total, self._BASELINE_CHUNK_SIZE):
                chunk = baseline_files[i:i + self._BASELINE_CHUNK_SIZE]
                payload = json.dumps({
                    "type": "fim_baseline_sync",
                    "machine_id": machine_id,
                    "hostname": hostname,
                    "psk": psk,
                    "files": chunk,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "chunk_index": i // self._BASELINE_CHUNK_SIZE,
                    "chunk_total": (total + self._BASELINE_CHUNK_SIZE - 1) // self._BASELINE_CHUNK_SIZE,
                })
                url = f"http://{server_host}:5000/api/fim/baseline/{machine_id}/diff"
                req = urllib.request.Request(url, data=payload.encode("utf-8"),
                                             headers={"Content-Type": "application/json"})
                resp = urllib.request.urlopen(req, timeout=30)
                result = json.loads(resp.read().decode("utf-8"))
                total_changed += result.get("changed_count", 0)
            print(f"[*] FIM Baseline sent: {total} files in {(total + self._BASELINE_CHUNK_SIZE - 1) // self._BASELINE_CHUNK_SIZE} chunks, {total_changed} changed")
        except Exception as e:
            print(f"[-] FIM Baseline send failed: {e}")

    def stop(self):
        """Stop FIM monitoring."""
        self.running = False
        if self.observer:
            try:
                self.observer.stop()
                self.observer.join(timeout=5)
            except Exception:
                pass
            self.observer = None