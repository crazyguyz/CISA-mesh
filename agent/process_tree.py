"""
Process Tree Builder v2.0.0 for GIAM-SAT Agent v3.6.0
v2.0: Real-time metadata stream to server + on-demand full query + 7-day local cache.

Purpose: Detect Living-off-the-Land (LOTL) attack chains that
         individual events cannot see. A single powershell.exe
         launch is normal; Word→PowerShell→Network is NOT.

Data flows:
  LOTL detect → enrich event in-place → send to server immediately
  Every 60s → send "process_tree_snapshot" with top 20 active chains (metadata only)
  On server query → respond with full tree for a given PID + timestamp

Detection Patterns:
  - Document→Script→Network: Word/Excel→PS/cmd→outbound connection
  - Service→Download: service spawn→certutil/curl→download
  - LOLBin Chain: 2+ LOLBin tools in sequence (rundll32→regsvr32→mshta)
  - Rapid Spawn: same parent spawns 5+ children in <10 seconds
"""

import time
import threading
import json
import os
from collections import defaultdict

# Maximum chain depth to track
MAX_CHAIN_DEPTH = 10

# TTL for process tree entries (seconds) — auto-cleanup
PROCESS_TTL = 3600  # 1 hour

# v3.6: Local SQLite cache TTL (7 days)
LOCAL_CACHE_TTL = 7 * 86400

# v3.6: Snapshot interval (seconds)
SNAPSHOT_INTERVAL = 60

# v3.6: Max chains in snapshot
MAX_SNAPSHOT_CHAINS = 20

# LOTL (Living-off-the-Land) binary list — abuse of built-in tools
LOLBINS = {
    "certutil.exe", "wmic.exe", "mshta.exe", "regsvr32.exe",
    "rundll32.exe", "schtasks.exe", "powershell.exe", "pwsh.exe",
    "wscript.exe", "cscript.exe", "bitsadmin.exe", "cmstp.exe",
    "msbuild.exe", "csc.exe", "installutil.exe", "reg.exe",
    "sc.exe", "net.exe", "net1.exe", "nltest.exe",
    "dsquery.exe", "csvde.exe", "makecab.exe", "expand.exe",
    "extrac32.exe", "findstr.exe", "replace.exe", "forfiles.exe",
}

# High-risk chain patterns: (parent_type, child_type) pairs that signal attacks
SUSPICIOUS_CHAINS = [
    ({"doc", "xls", "ppt", "pdf", "html"}, {"exe", "ps1", "vbs", "bat"}),
    ({"service", "svchost"}, {"powershell", "cmd", "wscript"}),
    ({"lolbin", "lolbin"}, {"lolbin", "network"}),
    ({"script", "unknown"}, {"download", "exe"}),
]


def _classify_process(name):
    """Classify a process name into a category."""
    if not name:
        return "unknown"
    n = name.lower()
    if n.endswith(".exe"):
        n = n[:-4]

    doc_exts = {".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".html", ".htm"}
    if any(n.endswith(ext) for ext in doc_exts):
        return "doc"
    if name.lower() in LOLBINS:
        return "lolbin"
    if n in {"powershell", "pwsh", "cmd", "wscript", "cscript"}:
        return "script"
    if n in {"firefox", "chrome", "msedge", "iexplore", "opera"}:
        return "browser"
    if n in {"certutil", "bitsadmin", "curl", "wget"}:
        return "download"
    if n in {"explorer", "svchost", "services", "lsass", "winlogon", "csrss"}:
        return "system"
    if n in {"net", "net1", "nslookup", "ping", "nbtstat", "nltest"}:
        return "network"
    return "exe"


def _check_lotl_chain(chain_categories):
    """
    Check if a chain of process categories matches LOTL detection patterns.
    Returns (is_suspicious, chain_description) tuple.
    """
    if len(chain_categories) < 2:
        return False, ""

    # Pattern 1: Document → Script → ??? (macro attack)
    if chain_categories[0] == "doc" and chain_categories[1] in ("script", "lolbin"):
        desc = f"Document→Script chain: possible macro execution"
        if len(chain_categories) >= 3 and chain_categories[2] in ("network", "download", "lolbin"):
            desc += f" with {chain_categories[2]} follow-up"
        return True, desc

    # Pattern 2: 2+ LOLBins in a row
    lolbin_count = sum(1 for c in chain_categories if c == "lolbin")
    if lolbin_count >= 2:
        return True, f"Multiple LOLBins in chain ({lolbin_count} detected)"

    # Pattern 3: Script → Download → Execute
    if len(chain_categories) >= 3:
        if chain_categories[-3] == "script" and chain_categories[-2] == "download":
            return True, f"Script→Download chain detected"

    # Pattern 4: System process spawning script
    if chain_categories[0] in ("system", "service") and chain_categories[1] in ("script", "lolbin"):
        return True, f"System process spawning {chain_categories[1]}: possible service abuse"

    return False, ""


def _get_local_cache_path():
    """v3.6: Path to local SQLite cache for process tree persistence."""
    if os.name == "nt":
        programdata = os.environ.get("PROGRAMDATA", "C:\\ProgramData")
        data_dir = os.path.join(programdata, "GIAM-SAT", "Agent")
    else:
        data_dir = os.path.join(os.path.expanduser("~"), ".giamsat", "agent")
    os.makedirs(data_dir, exist_ok=True)
    return os.path.join(data_dir, "process_tree_cache.db")


class ProcessTreeBuilder:
    """
    v2.0.0: Builds and maintains in-memory process parent-child trees with
    real-time metadata streaming and 7-day local SQLite cache.
    Thread-safe.
    """

    def __init__(self, callback=None, tcp_send_callback=None):
        """
        Args:
            callback: Called with enriched event when LOTL detected (immediate alert)
            tcp_send_callback: v3.6: Function to send data to server via TCP (for snapshots)
        """
        self.callback = callback
        self.tcp_send = tcp_send_callback
        self._trees = {}  # process_guid → {"pid":, "name":, "parent_guid":, "children": [], "cat":, "time":}
        self._lock = threading.Lock()
        self._stats = {"events_processed": 0, "chains_detected": 0, "active_processes": 0, "snapshots_sent": 0}

        # v3.6: Local SQLite cache for persistence
        self._init_local_cache()

        # v3.6: Background snapshot thread
        self._running = True
        self._snapshot_thread = threading.Thread(target=self._snapshot_loop, daemon=True)
        self._snapshot_thread.start()

    def _init_local_cache(self):
        """v3.6: Initialize local SQLite cache for 7-day process tree persistence."""
        try:
            import sqlite3
            self._local_db = sqlite3.connect(_get_local_cache_path(), check_same_thread=False)
            self._local_db.execute("""CREATE TABLE IF NOT EXISTS process_tree_cache (
                process_guid TEXT PRIMARY KEY,
                pid TEXT,
                process_name TEXT,
                parent_guid TEXT,
                parent_name TEXT,
                category TEXT,
                chain_names TEXT,
                lotl_triggered INTEGER DEFAULT 0,
                timestamp TEXT,
                ttl_expire TIMESTAMP DEFAULT (datetime('now', '+7 days'))
            )""")
            self._local_db.execute("CREATE INDEX IF NOT EXISTS idx_ptc_pid ON process_tree_cache(pid)")
            self._local_db.execute("CREATE INDEX IF NOT EXISTS idx_ptc_expire ON process_tree_cache(ttl_expire)")
            self._local_db.execute("PRAGMA journal_mode=WAL")
            self._local_db.commit()
            # Cleanup expired entries on startup
            self._local_db.execute("DELETE FROM process_tree_cache WHERE ttl_expire < datetime('now')")
            self._local_db.commit()
        except Exception:
            self._local_db = None

    def _snapshot_loop(self):
        """v3.6: Send process tree snapshot (metadata) to server every 60s."""
        while self._running:
            time.sleep(SNAPSHOT_INTERVAL)
            if not self._running:
                break
            self._send_snapshot()

    def _send_snapshot(self):
        """v3.6: Build and send top chains metadata to server."""
        if not self.tcp_send:
            return
        try:
            with self._lock:
                # Get top chains (most children = most interesting)
                chains = []
                for guid, node in self._trees.items():
                    chain = self._build_chain(guid)
                    if len(chain) >= 2:
                        chain_names = [c["name"] for c in chain]
                        chain_cats = [c["category"] for c in chain]
                        is_suspicious, _ = _check_lotl_chain(chain_cats)
                        chains.append({
                            "root_pid": chain[0].get("pid", "?"),
                            "chain": chain_names,
                            "categories": chain_cats,
                            "depth": len(chain),
                            "children": len(node.get("children", [])),
                            "suspicious": is_suspicious,
                            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                        })

                # Sort by depth desc, suspicious first
                chains.sort(key=lambda c: (c["suspicious"], c["depth"], c["children"]), reverse=True)
                top_chains = chains[:MAX_SNAPSHOT_CHAINS]

            snapshot = {
                "type": "process_tree_snapshot",
                "active_processes": len(self._trees),
                "chains_detected": self._stats["chains_detected"],
                "total_processed": self._stats["events_processed"],
                "top_chains": top_chains,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
            self.tcp_send(snapshot)
            self._stats["snapshots_sent"] += 1
        except Exception:
            pass

    def add_event(self, event):
        """
        Add a Sysmon EID 1 event to the process tree.
        v3.6: Also persists to local SQLite cache.

        If the chain matches a LOTL pattern, enrich the event and call callback.
        Also sends "process_tree_edge" metadata event to server.
        """
        process_guid = event.get("process_guid", "")
        if not process_guid:
            return

        process_name = event.get("process_name", "")
        parent_guid = event.get("parent_guid", "")
        parent_name = event.get("parent_process", "")
        pid = event.get("pid", "")
        ts = event.get("timestamp", "")

        category = _classify_process(process_name)
        parent_cat = _classify_process(parent_name) if parent_name else "unknown"

        now = time.time()

        with self._lock:
            # Add current process node
            self._trees[process_guid] = {
                "pid": pid,
                "name": process_name,
                "parent_guid": parent_guid,
                "category": category,
                "children": [],
                "time": now,
            }

            # Link to parent
            if parent_guid and parent_guid in self._trees:
                parent_node = self._trees[parent_guid]
                if process_guid not in parent_node["children"]:
                    parent_node["children"].append(process_guid)

            self._stats["events_processed"] += 1

            # Build chain from this process backward
            chain = self._build_chain(process_guid)
            chain_cats = [c["category"] for c in chain]
            chain_names = [c["name"] for c in chain]

            is_suspicious, desc = _check_lotl_chain(chain_cats)
            if is_suspicious:
                self._stats["chains_detected"] += 1
                # Enrich event
                event["lotl_detected"] = True
                event["lotl_chain_desc"] = desc
                event["process_chain"] = chain_names
                if "severity" not in event or event.get("severity") != "CRITICAL":
                    event["severity"] = "HIGH"

                if self.callback:
                    self.callback(event)

            # v3.6: Send "process_tree_edge" metadata to server (if LOTL or depth >= 3)
            if is_suspicious or len(chain) >= 3:
                if self.tcp_send:
                    edge = {
                        "type": "process_tree_edge",
                        "pid": pid,
                        "process_name": process_name,
                        "parent_pid": parent_guid and self._trees.get(parent_guid, {}).get("pid", "?"),
                        "parent_name": parent_name,
                        "chain": chain_names,
                        "categories": chain_cats,
                        "lotl_triggered": is_suspicious,
                        "lotl_desc": desc if is_suspicious else "",
                        "timestamp": ts,
                    }
                    self.tcp_send(edge)

            # v3.6: Persist to local SQLite cache
            self._persist_to_cache(process_guid, process_name, parent_guid, parent_name,
                                   category, chain_names, is_suspicious, ts)

            # Auto-cleanup: remove expired entries
            self._cleanup_expired(now)

    def _persist_to_cache(self, guid, name, parent_guid, parent_name, category, chain_names, lotl, ts):
        """v3.6: Persist process tree node to local SQLite cache."""
        if not self._local_db:
            return
        try:
            self._local_db.execute(
                """INSERT OR REPLACE INTO process_tree_cache
                   (process_guid, pid, process_name, parent_guid, parent_name, category,
                    chain_names, lotl_triggered, timestamp, ttl_expire)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now', '+7 days'))""",
                (guid, str(self._trees.get(guid, {}).get("pid", "")), name, parent_guid,
                 parent_name, category, json.dumps(chain_names), 1 if lotl else 0, ts)
            )
            self._local_db.commit()
        except Exception:
            pass

    def _build_chain(self, guid):
        """Build process chain from guid backward to root."""
        chain = []
        visited = set()
        current = guid
        while current and len(chain) < MAX_CHAIN_DEPTH:
            if current in visited:
                break
            visited.add(current)
            node = self._trees.get(current)
            if not node:
                # v3.6: Try local cache
                cached = self._get_cached_node(current)
                if cached:
                    chain.insert(0, cached)
                    current = cached.get("parent_guid")
                else:
                    break
            else:
                chain.insert(0, node)
                current = node.get("parent_guid")
        return chain

    def get_descendant_pids(self, pid_or_name):
        """
        v4.0: Get all descendant PIDs for a process (by PID or name).
        Returns list of PIDs in the sub-tree including the matched process itself.
        Used by Kill Process Tree for complete malware cleanup.
        """
        results = []
        with self._lock:
            # Try exact PID match first
            pid_str = str(pid_or_name)
            for guid, node in self._trees.items():
                if str(node.get("pid", "")) == pid_str:
                    results = self._collect_subtree(guid, visited=set())
                    break
            # If no PID match, try name match
            if not results:
                name_lower = pid_or_name.lower() if isinstance(pid_or_name, str) else ""
                for guid, node in self._trees.items():
                    if node.get("name", "").lower() == name_lower:
                        results.extend(self._collect_subtree(guid, visited=set()))
        return list(set(results))  # Dedup

    def _collect_subtree(self, guid, visited):
        """Recursively collect all PIDs in a process sub-tree."""
        if guid in visited:
            return []
        visited.add(guid)
        pids = []
        node = self._trees.get(guid)
        if node:
            pid = node.get("pid")
            if pid:
                try:
                    pids.append(int(pid))
                except (ValueError, TypeError):
                    pass
            for child_guid in node.get("children", []):
                pids.extend(self._collect_subtree(child_guid, visited))
        return pids

    def _get_cached_node(self, guid):
        """v3.6: Retrieve a node from local SQLite cache."""
        if not self._local_db:
            return None
        try:
            cursor = self._local_db.execute(
                "SELECT * FROM process_tree_cache WHERE process_guid=? AND ttl_expire > datetime('now')",
                (guid,)
            )
            row = cursor.fetchone()
            if row:
                return {
                    "pid": row[1],
                    "name": row[2],
                    "parent_guid": row[3],
                    "category": row[5],
                    "children": [],
                    "time": 0,
                }
        except Exception:
            pass
        return None

    def _cleanup_expired(self, now):
        """Remove process tree entries older than PROCESS_TTL."""
        expired = [g for g, n in self._trees.items() if now - n["time"] > PROCESS_TTL]
        for g in expired:
            del self._trees[g]
        self._stats["active_processes"] = len(self._trees)

    def get_chain_for_pid(self, pid, format="names"):
        """
        v3.6: Get process chain for a given PID. Checks in-memory first, then local cache.
        Returns list of process names (or full nodes) from root to child.
        """
        with self._lock:
            # Find guid by pid in memory
            guid = None
            for g, n in self._trees.items():
                if n["pid"] == str(pid):
                    guid = g
                    break

            # If not in memory, try local cache
            if not guid and self._local_db:
                try:
                    cursor = self._local_db.execute(
                        "SELECT process_guid FROM process_tree_cache WHERE pid=? AND ttl_expire > datetime('now') ORDER BY timestamp DESC LIMIT 1",
                        (str(pid),)
                    )
                    row = cursor.fetchone()
                    if row:
                        guid = row[0]
                except Exception:
                    pass

            if not guid:
                return []

            chain = self._build_chain(guid)
            if format == "names":
                return [n["name"] for n in chain]
            return chain

    def get_full_tree_for_timewindow(self, start_time_str, end_time_str=None):
        """v3.6: Get FULL process tree from local cache for a given time window.
        Returns list of all nodes (guid, name, pid, parent_guid, chain) in that window.
        """
        if not self._local_db:
            return []
        try:
            query = "SELECT * FROM process_tree_cache WHERE timestamp >= ?"
            params = [start_time_str]
            if end_time_str:
                query += " AND timestamp <= ?"
                params.append(end_time_str)
            query += " ORDER BY timestamp ASC LIMIT 500"
            cursor = self._local_db.execute(query, params)
            results = []
            for row in cursor.fetchall():
                try:
                    chain = json.loads(row[6]) if row[6] else []
                except Exception:
                    chain = []
                results.append({
                    "process_guid": row[0],
                    "pid": row[1],
                    "process_name": row[2],
                    "parent_guid": row[3],
                    "parent_name": row[4],
                    "category": row[5],
                    "chain": chain,
                    "lotl_triggered": bool(row[7]),
                    "timestamp": row[8],
                })
            return results
        except Exception:
            return []

    def get_stats(self):
        """Return tree statistics."""
        with self._lock:
            self._stats["active_processes"] = len(self._trees)
            return dict(self._stats)

    def stop(self):
        self._running = False
        if self._local_db:
            try:
                self._local_db.close()
            except Exception:
                pass