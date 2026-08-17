"""Database Manager for GIAM-SAT Server"""
import sqlite3
import os
import threading
import json
import time

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "giamsat_data.db")

# Max seconds without a heartbeat before a machine's uptime session is
# considered ended (agent heartbeats every 120s; a longer gap means the
# machine went offline/rebooted).
_UPTIME_GAP_SECONDS = 600


class DatabaseManager:
    def __init__(self):
        self.write_lock = threading.RLock()
        self.read_lock = threading.RLock()
        self.lock = self.write_lock  # Backward compat: all old code uses self.lock for writes
        self.backend_type = "sqlite"
        self.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._summary_cache = {"data": None, "ts": 0}
        self._init_db()

    def _init_db(self):
        with self.lock:
            c = self.conn.cursor()
            c.execute("""CREATE TABLE IF NOT EXISTS machines (id INTEGER PRIMARY KEY AUTOINCREMENT,machine_id TEXT UNIQUE,hostname TEXT,ip_address TEXT,platform TEXT,version TEXT,first_seen TIMESTAMP,last_seen TIMESTAMP,is_online INTEGER DEFAULT 1,is_revoked INTEGER DEFAULT 0,enrollment_token TEXT DEFAULT '')""")
            # v3.8.0 MIGRATION: Add is_revoked + enrollment_token columns
            for col, col_type in [("is_revoked", "INTEGER DEFAULT 0"), ("enrollment_token", "TEXT DEFAULT ''")]:
                try:
                    c.execute(f"ALTER TABLE machines ADD COLUMN {col} {col_type}")
                except sqlite3.OperationalError:
                    pass
            c.execute("""CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT,machine_id TEXT,hostname TEXT,type TEXT,subtype TEXT,event_id TEXT,event_type TEXT,source TEXT,computer TEXT,user TEXT,category TEXT,time TEXT,description TEXT,raw_data TEXT,received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
            c.execute("""CREATE TABLE IF NOT EXISTS fim_events (id INTEGER PRIMARY KEY AUTOINCREMENT,machine_id TEXT,hostname TEXT,action TEXT,path TEXT,time TEXT,received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
            c.execute("""CREATE TABLE IF NOT EXISTS heartbeats (id INTEGER PRIMARY KEY AUTOINCREMENT,machine_id TEXT,hostname TEXT,timestamp TEXT,received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
            c.execute("""CREATE TABLE IF NOT EXISTS response_results (id INTEGER PRIMARY KEY AUTOINCREMENT,machine_id TEXT,hostname TEXT,exec_id TEXT,status TEXT,output TEXT,error TEXT,exit_code INTEGER,action TEXT,timestamp TEXT,received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
            c.execute("""CREATE TABLE IF NOT EXISTS syslog (id INTEGER PRIMARY KEY AUTOINCREMENT,source_ip TEXT,hostname TEXT,facility TEXT,severity TEXT,timestamp TEXT,message TEXT,raw_data TEXT,received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
            c.execute("""CREATE TABLE IF NOT EXISTS commands (id INTEGER PRIMARY KEY AUTOINCREMENT,machine_id TEXT,action TEXT,command TEXT,exec_id TEXT UNIQUE,status TEXT DEFAULT 'pending',created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,executed_at TIMESTAMP)""")

            # Hardware info: stores current config
            c.execute("""CREATE TABLE IF NOT EXISTS hardware_info (id INTEGER PRIMARY KEY AUTOINCREMENT,machine_id TEXT UNIQUE,hostname TEXT,data_json TEXT,fingerprint TEXT,has_changed INTEGER DEFAULT 0,received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")

            # Hardware baseline: stores first-ever config (baseline) - never updated
            c.execute("""CREATE TABLE IF NOT EXISTS hardware_baseline (id INTEGER PRIMARY KEY AUTOINCREMENT,machine_id TEXT UNIQUE,hostname TEXT,data_json TEXT,fingerprint TEXT,saved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")

            # Network traffic events
            c.execute("""CREATE TABLE IF NOT EXISTS network_traffic (id INTEGER PRIMARY KEY AUTOINCREMENT,machine_id TEXT,hostname TEXT,src_ip TEXT,dst_ip TEXT,src_port INTEGER,dst_port INTEGER,protocol TEXT,size INTEGER,flags TEXT,state TEXT,timestamp TEXT,received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,raw_data TEXT)""")
            # v2.5.17 MIGRATION: Add full packet detail columns
            for col, col_type in [
                ("src_mac", "TEXT DEFAULT ''"),
                ("dst_mac", "TEXT DEFAULT ''"),
                ("ip_ttl", "INTEGER DEFAULT 0"),
                ("ip_proto", "INTEGER DEFAULT 0"),
                ("tcp_flags", "TEXT DEFAULT ''"),
                ("payload_hex", "TEXT DEFAULT ''"),
                ("payload_size", "INTEGER DEFAULT 0"),
                ("protocol_app", "TEXT DEFAULT ''"),
                ("dns_query", "TEXT DEFAULT ''"),
                ("http_host", "TEXT DEFAULT ''"),
                ("payload_dump", "TEXT DEFAULT ''"),
            ]:
                try:
                    c.execute(f"ALTER TABLE network_traffic ADD COLUMN {col} {col_type}")
                except sqlite3.OperationalError:
                    pass  # Column already exists

            # Threat alerts from correlation engine
            c.execute("""CREATE TABLE IF NOT EXISTS threat_alerts (id INTEGER PRIMARY KEY AUTOINCREMENT,machine_id TEXT,hostname TEXT,rule_id TEXT,rule_name TEXT,description TEXT,severity TEXT,timestamp TEXT,raw_data TEXT,received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")

            # Vulnerability alerts
            c.execute("""CREATE TABLE IF NOT EXISTS vuln_alerts (id INTEGER PRIMARY KEY AUTOINCREMENT,machine_id TEXT,hostname TEXT,software TEXT,version TEXT,publisher TEXT,cve TEXT,severity TEXT,description TEXT,timestamp TEXT,received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")

            # Network Deep Inspection results
            c.execute("""CREATE TABLE IF NOT EXISTS network_inspection (id INTEGER PRIMARY KEY AUTOINCREMENT,machine_id TEXT,hostname TEXT,subtype TEXT,domain TEXT,dst_ip TEXT,dst_port INTEGER,src_ip TEXT,src_port INTEGER,protocol TEXT,query_type TEXT,avg_interval_sec REAL,sample_count INTEGER,timestamp TEXT,received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")

            # YARA/Pattern scan alerts
            c.execute("""CREATE TABLE IF NOT EXISTS yara_alerts (id INTEGER PRIMARY KEY AUTOINCREMENT,machine_id TEXT,hostname TEXT,rule_name TEXT,description TEXT,file TEXT,timestamp TEXT,received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")

            # SCA (Security Configuration Assessment) events
            c.execute("""CREATE TABLE IF NOT EXISTS sca_events (id INTEGER PRIMARY KEY AUTOINCREMENT,machine_id TEXT,hostname TEXT,check_id TEXT,title TEXT,status TEXT,severity TEXT,description TEXT,remediation TEXT,timestamp TEXT,received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")

            # Agentless monitoring events
            c.execute("""CREATE TABLE IF NOT EXISTS agentless_events (id INTEGER PRIMARY KEY AUTOINCREMENT,device_name TEXT,ip TEXT,device_type TEXT,data_json TEXT,timestamp TEXT,received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")

            # Audit log for admin actions
            c.execute("""CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT,action TEXT,details TEXT,ip_address TEXT,timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")

            # v2.1.0: Agent Groups for per-group policy management
            c.execute("""CREATE TABLE IF NOT EXISTS agent_groups (id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT UNIQUE,description TEXT,config_json TEXT,created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
            c.execute("""CREATE TABLE IF NOT EXISTS agent_group_members (id INTEGER PRIMARY KEY AUTOINCREMENT,group_id INTEGER,machine_id TEXT UNIQUE,FOREIGN KEY(group_id) REFERENCES agent_groups(id) ON DELETE CASCADE)""")

            # v3.9.2: Group Policies — per-group policy enforcement (block websites, USB, software)
            c.execute("""CREATE TABLE IF NOT EXISTS group_policies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id INTEGER NOT NULL,
                policy_type TEXT NOT NULL,
                policy_name TEXT DEFAULT '',
                config_json TEXT NOT NULL DEFAULT '{}',
                enabled INTEGER DEFAULT 1,
                apply_status TEXT DEFAULT 'pending',
                status_message TEXT DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(group_id) REFERENCES agent_groups(id) ON DELETE CASCADE
            )""")
            for col, col_type in [("policy_name", "TEXT DEFAULT ''"), ("status_message", "TEXT DEFAULT ''")]:
                try:
                    c.execute(f"ALTER TABLE group_policies ADD COLUMN {col} {col_type}")
                except sqlite3.OperationalError:
                    pass

            # v2.1.0: FIM Baseline DB for file integrity tracking
            c.execute("""CREATE TABLE IF NOT EXISTS fim_baseline (id INTEGER PRIMARY KEY AUTOINCREMENT,machine_id TEXT,path TEXT,file_hash TEXT,file_hash_old TEXT,file_size INTEGER,owner TEXT,permissions TEXT,last_modified TEXT,first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,last_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP,change_count INTEGER DEFAULT 0,UNIQUE(machine_id, path))""")
            # v2.1.8 MIGRATION: Add missing columns if upgrading from older schema
            for col, col_type in [("file_hash_old", "TEXT"), ("change_count", "INTEGER DEFAULT 0")]:
                try:
                    c.execute(f"ALTER TABLE fim_baseline ADD COLUMN {col} {col_type}")
                except sqlite3.OperationalError:
                    pass  # Column already exists

            # v2.2.0: Machine user info (agent reports user name, employee ID, email)
            c.execute("""CREATE TABLE IF NOT EXISTS machine_users (machine_id TEXT UNIQUE,hostname TEXT,user_name TEXT,employee_id TEXT,email TEXT,updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")

            # v2.3.0: Machine uptime tracking (daily online duration, alerts for 24h+)
            c.execute("""CREATE TABLE IF NOT EXISTS machine_uptime (machine_id TEXT,date TEXT,session_start TIMESTAMP,last_seen TIMESTAMP,uptime_minutes INTEGER DEFAULT 0,alert_sent_24h INTEGER DEFAULT 0,UNIQUE(machine_id, date, session_start))""")

            # v2.4.0: Agent update log for tracking push updates and auto-updates
            c.execute("""CREATE TABLE IF NOT EXISTS agent_update_log (id INTEGER PRIMARY KEY AUTOINCREMENT,machine_id TEXT,hostname TEXT,from_version TEXT,to_version TEXT,status TEXT,message TEXT,source TEXT,timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")

            # v3.8.0: Alert Suppression for False Positive Tuning (Global Whitelist)
            c.execute("""CREATE TABLE IF NOT EXISTS alert_suppression (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id TEXT NOT NULL,
                machine_id TEXT DEFAULT NULL,
                field_path TEXT DEFAULT NULL,
                field_hash TEXT DEFAULT NULL,
                reason TEXT DEFAULT '',
                created_by TEXT DEFAULT 'admin',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP DEFAULT NULL
            )""")

            # v2.6.2: Sysmon events from SysmonCollector
            c.execute("""CREATE TABLE IF NOT EXISTS sysmon_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                machine_id TEXT,
                hostname TEXT,
                event_type TEXT,
                sysmon_event_id INTEGER,
                process_name TEXT,
                process_path TEXT,
                command_line TEXT,
                pid TEXT,
                parent_process TEXT,
                parent_path TEXT,
                parent_command_line TEXT,
                parent_pid TEXT,
                user TEXT,
                severity TEXT DEFAULT 'INFO',
                description TEXT,
                src_ip TEXT,
                src_port TEXT,
                dst_ip TEXT,
                dst_port TEXT,
                protocol TEXT,
                registry_key TEXT,
                registry_value TEXT,
                dns_query TEXT,
                file_path TEXT,
                file_name TEXT,
                target_process TEXT,
                target_path TEXT,
                target_pid TEXT,
                suspicion_reason TEXT,
                credential_dumping INTEGER DEFAULT 0,
                persistence_detected INTEGER DEFAULT 0,
                suspicious_parent INTEGER DEFAULT 0,
                suspicious_dll INTEGER DEFAULT 0,
                suspicious_file INTEGER DEFAULT 0,
                hashes TEXT,
                integrity_level TEXT,
                signed TEXT,
                injection_type TEXT,
                granted_access TEXT,
                dns_status TEXT,
                dns_results TEXT,
                timestamp TEXT,
                raw_data TEXT,
                received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )""")

            # v2.5.12 MIGRATION: Add notes column for admin annotation
            try:
                c.execute("ALTER TABLE machines ADD COLUMN notes TEXT DEFAULT ''")
            except sqlite3.OperationalError:
                pass

            # v3.9.15: Custom Dashboard Builder (drag-and-drop grid layouts)
            c.execute("""CREATE TABLE IF NOT EXISTS custom_dashboards (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT DEFAULT '',
                layout_json TEXT NOT NULL DEFAULT '[]',
                widgets_json TEXT NOT NULL DEFAULT '[]',
                created_by TEXT DEFAULT 'admin',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )""")

            # v4.5.1: Messages table (chat giữa server và agent)
            c.execute("""CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                msg_id TEXT UNIQUE,
                machine_id TEXT DEFAULT '',
                sender TEXT DEFAULT '',
                title TEXT DEFAULT '',
                message TEXT DEFAULT '',
                reply TEXT DEFAULT '',
                require_reply INTEGER DEFAULT 1,
                status TEXT DEFAULT 'sent',
                direction TEXT DEFAULT 'server',
                created_at TEXT DEFAULT '',
                replied_at TEXT DEFAULT ''
            )""")
            # Migration: add direction column (agent-initiated messages)
            try:
                c.execute("ALTER TABLE messages ADD COLUMN direction TEXT DEFAULT 'server'")
            except sqlite3.OperationalError:
                pass

            # v3.3: Timestamp indexes for cleanup summary (MIN/MAX instant via index)
            _TS_INDEXES = [
                "CREATE INDEX IF NOT EXISTS idx_events_time ON events(time)",
                "CREATE INDEX IF NOT EXISTS idx_fim_events_time ON fim_events(time)",
                "CREATE INDEX IF NOT EXISTS idx_network_traffic_ts ON network_traffic(timestamp)",
                "CREATE INDEX IF NOT EXISTS idx_heartbeats_ts ON heartbeats(timestamp)",
                "CREATE INDEX IF NOT EXISTS idx_syslog_ts ON syslog(timestamp)",
                "CREATE INDEX IF NOT EXISTS idx_sysmon_events_ts ON sysmon_events(timestamp)",
                "CREATE INDEX IF NOT EXISTS idx_yara_alerts_ts ON yara_alerts(timestamp)",
                "CREATE INDEX IF NOT EXISTS idx_sca_events_ts ON sca_events(timestamp)",
                "CREATE INDEX IF NOT EXISTS idx_agentless_events_ts ON agentless_events(timestamp)",
                "CREATE INDEX IF NOT EXISTS idx_threat_alerts_ts ON threat_alerts(timestamp)",
                "CREATE INDEX IF NOT EXISTS idx_vuln_alerts_ts ON vuln_alerts(timestamp)",
            ]
            for idx_sql in _TS_INDEXES:
                try:
                    c.execute(idx_sql)
                except sqlite3.OperationalError:
                    pass

            # v2.5.22: WAL mode + performance PRAGMA
            try:
                c.execute("PRAGMA journal_mode=WAL")
                c.execute("PRAGMA synchronous=NORMAL")
                c.execute("PRAGMA cache_size=-32000")  # 32MB cache
                c.execute("PRAGMA temp_store=MEMORY")
                c.execute("PRAGMA mmap_size=268435456")  # 256MB mmap
            except sqlite3.OperationalError:
                pass

            # v2.5.22: Critical DB indexes for query performance
            _INDEXES = [
                # events - most queried table
                "CREATE INDEX IF NOT EXISTS idx_events_machine ON events(machine_id)",
                "CREATE INDEX IF NOT EXISTS idx_events_time ON events(received_at DESC)",
                "CREATE INDEX IF NOT EXISTS idx_events_type ON events(subtype)",
                # fim_events
                "CREATE INDEX IF NOT EXISTS idx_fim_machine ON fim_events(machine_id)",
                "CREATE INDEX IF NOT EXISTS idx_fim_time ON fim_events(received_at DESC)",
                # network_traffic
                "CREATE INDEX IF NOT EXISTS idx_network_machine ON network_traffic(machine_id)",
                "CREATE INDEX IF NOT EXISTS idx_network_time ON network_traffic(received_at DESC)",
                # threat_alerts
                "CREATE INDEX IF NOT EXISTS idx_threats_machine ON threat_alerts(machine_id)",
                "CREATE INDEX IF NOT EXISTS idx_threats_severity ON threat_alerts(severity)",
                "CREATE INDEX IF NOT EXISTS idx_threats_time ON threat_alerts(id DESC)",
                # vuln_alerts
                "CREATE INDEX IF NOT EXISTS idx_vulns_machine ON vuln_alerts(machine_id)",
                "CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vuln_alerts(severity)",
                "CREATE INDEX IF NOT EXISTS idx_vulns_time ON vuln_alerts(id DESC)",
                # yara_alerts
                "CREATE INDEX IF NOT EXISTS idx_yara_machine ON yara_alerts(machine_id)",
                # sca_events
                "CREATE INDEX IF NOT EXISTS idx_sca_machine ON sca_events(machine_id)",
                # syslog
                "CREATE INDEX IF NOT EXISTS idx_syslog_time ON syslog(received_at DESC)",
                # network_inspection
                "CREATE INDEX IF NOT EXISTS idx_inspection_machine ON network_inspection(machine_id)",
                "CREATE INDEX IF NOT EXISTS idx_inspection_time ON network_inspection(received_at DESC)",
                # response_results
                "CREATE INDEX IF NOT EXISTS idx_response_machine ON response_results(machine_id)",
                "CREATE INDEX IF NOT EXISTS idx_response_time ON response_results(received_at DESC)",
                # heartbeats
                "CREATE INDEX IF NOT EXISTS idx_heartbeat_machine ON heartbeats(machine_id)",
                # agent_update_log
                "CREATE INDEX IF NOT EXISTS idx_update_log_machine ON agent_update_log(machine_id)",
                # commands
                "CREATE INDEX IF NOT EXISTS idx_commands_exec ON commands(exec_id)",
                # v3.7.2: FIM Baseline indexes for fast query
                "CREATE INDEX IF NOT EXISTS idx_fim_baseline_machine ON fim_baseline(machine_id)",
                "CREATE INDEX IF NOT EXISTS idx_fim_baseline_path ON fim_baseline(machine_id, path)",
                "CREATE INDEX IF NOT EXISTS idx_fim_baseline_changed ON fim_baseline(machine_id, change_count)",
            ]
            for idx_sql in _INDEXES:
                try:
                    c.execute(idx_sql)
                except sqlite3.OperationalError:
                    pass  # Index already exists or table not ready

            self.conn.commit()

    def machine_offline(self, machine_id):
        with self.lock:
            self.conn.execute("UPDATE machines SET is_online = 0 WHERE machine_id = ?", (machine_id,))
            self.conn.commit()

    def check_heartbeat_timeout(self, timeout_seconds=60):
        """Mark machines as offline if no heartbeat within timeout_seconds."""
        with self.lock:
            c = self.conn.execute(
                "UPDATE machines SET is_online = 0 WHERE is_online = 1 AND last_seen < datetime('now', ?)",
                (f'-{timeout_seconds} seconds',)
            )
            self.conn.commit()
            return c.rowcount

    def delete_machine(self, machine_id):
        """Delete a machine and all its data."""
        with self.lock:
            for t in ["events","fim_events","heartbeats","response_results","commands","hardware_info","hardware_baseline","network_traffic","threat_alerts","vuln_alerts","network_inspection","yara_alerts"]:
                self.conn.execute(f"DELETE FROM {t} WHERE machine_id=?", (machine_id,))
            self.conn.execute("DELETE FROM machines WHERE machine_id=?", (machine_id,))
            self.conn.commit()

    def register_machine(self, machine_id, hostname, ip_address, platform="Windows", version="1.0.0"):
        with self.lock:
            self.conn.execute("""INSERT INTO machines (machine_id,hostname,ip_address,platform,version,first_seen,last_seen,is_online) VALUES (?,?,?,?,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,1) ON CONFLICT(machine_id) DO UPDATE SET hostname=excluded.hostname,ip_address=excluded.ip_address,last_seen=CURRENT_TIMESTAMP,is_online=1""", (machine_id, hostname, ip_address, platform, version))
            self.conn.commit()

    def update_machine_hostname(self, machine_id, new_hostname):
        """Update the display name (hostname) of a machine. Used for custom renaming."""
        with self.lock:
            self.conn.execute("UPDATE machines SET hostname=? WHERE machine_id=?", (new_hostname, machine_id))
            self.conn.commit()

    # v3.8.0: Enrollment Token & Certificate Revocation
    def is_machine_revoked(self, machine_id):
        """Check if a machine has been revoked."""
        with self.lock:
            row = self.conn.execute(
                "SELECT is_revoked FROM machines WHERE machine_id=?", (machine_id,)
            ).fetchone()
            return bool(row and row["is_revoked"])

    def revoke_machine(self, machine_id):
        """Revoke a machine's certificate, preventing future connections."""
        with self.lock:
            self.conn.execute(
                "UPDATE machines SET is_revoked=1 WHERE machine_id=?", (machine_id,)
            )
            self.conn.commit()
            self.insert_audit_log("admin", "revoke_machine", f"Revoked {machine_id}")
            print(f"[SECURITY] Machine REVOKED: {machine_id}")

    def unrevoke_machine(self, machine_id):
        """Restore a previously revoked machine."""
        with self.lock:
            self.conn.execute(
                "UPDATE machines SET is_revoked=0 WHERE machine_id=?", (machine_id,)
            )
            self.conn.commit()
            self.insert_audit_log("admin", "unrevoke_machine", f"Unrevoked {machine_id}")

    def verify_enrollment_token(self, machine_id, token):
        """v3.8.0: Verify enrollment token during initial agent registration.
        Server checks token against stored enrollment_token for this machine_id."""
        import hmac as _hmac
        ENROLLMENT_SECRET = os.environ.get("GIAMSAT_ENROLLMENT_SECRET", "change-me-enroll-secret")
        expected_token = f"{machine_id}:{ENROLLMENT_SECRET}"
        import hashlib
        expected_hash = hashlib.sha256(expected_token.encode()).hexdigest()[:16]
        # v4.5.4 SECURITY: constant-time compare; no longer accept the raw global
        # secret as a valid token (that let any machine enroll with one shared value).
        if _hmac.compare_digest(token or "", expected_hash):
            return True
        # Fallback: check stored token in DB (constant-time)
        with self.lock:
            row = self.conn.execute(
                "SELECT enrollment_token FROM machines WHERE machine_id=?", (machine_id,)
            ).fetchone()
            if row and _hmac.compare_digest(row["enrollment_token"] or "", token or ""):
                return True
        return False

    def issue_enrollment_token(self, machine_id):
        """Return the existing per-machine enrollment token, or issue a new one."""
        with self.lock:
            row = self.conn.execute(
                "SELECT enrollment_token FROM machines WHERE machine_id=?", (machine_id,)
            ).fetchone()
            if row and row["enrollment_token"]:
                return row["enrollment_token"]
        import uuid as _uuid
        import hashlib as _hashlib
        token = _hashlib.sha256(f"{machine_id}:{_uuid.uuid4().hex}".encode()).hexdigest()[:32]
        with self.lock:
            self.conn.execute(
                "UPDATE machines SET enrollment_token=? WHERE machine_id=?", (token, machine_id)
            )
            self.conn.commit()
        return token
    def _save_baseline(self, machine_id, hostname, config_data):
        """Save the first-ever hardware config as baseline (only if not exists)."""
        with self.lock:
            # Check if baseline already exists
            c = self.conn.execute("SELECT id FROM hardware_baseline WHERE machine_id=?", (machine_id,))
            if c.fetchone():
                return  # Baseline already exists, don't overwrite

            fingerprint = json.dumps(config_data, sort_keys=True, ensure_ascii=False)
            self.conn.execute(
                """INSERT INTO hardware_baseline (machine_id, hostname, data_json, fingerprint, saved_at)
                   VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
                   ON CONFLICT(machine_id) DO NOTHING""",
                (machine_id, hostname, json.dumps(config_data, ensure_ascii=False), fingerprint)
            )
            self.conn.commit()

    def get_baseline(self, machine_id):
        """Get the baseline (first-ever) hardware config."""
        with self.lock:
            c = self.conn.execute("SELECT * FROM hardware_baseline WHERE machine_id=?", (machine_id,))
            row = c.fetchone()
            if row:
                d = dict(row)
                try:
                    d["data"] = json.loads(d.get("data_json", "{}"))
                except Exception:
                    d["data"] = {}
                return d
            return None

    @staticmethod
    def _compute_diff(baseline_data, current_data, prefix=""):
        """
        Recursively compute diff between baseline and current config.
        Returns list of {path, field, baseline_value, current_value, change_type} dicts.
        change_type: "modified", "added", "removed"
        Only returns entries where values differ.
        """
        diffs = []
        if not baseline_data or not current_data:
            return diffs

        all_keys = set(list(baseline_data.keys()) + list(current_data.keys()))

        for key in sorted(all_keys):
            path = f"{prefix}.{key}" if prefix else key
            old_val = baseline_data.get(key)
            new_val = current_data.get(key)

            if isinstance(old_val, dict) and isinstance(new_val, dict):
                diffs.extend(DatabaseManager._compute_diff(old_val, new_val, path))
            elif isinstance(old_val, list) and isinstance(new_val, list):
                # Smart list comparison: match by identity key for dict items
                diffs.extend(DatabaseManager._compute_list_diff(old_val, new_val, path, key))
            elif str(old_val) != str(new_val):
                diffs.append({
                    "path": path,
                    "field": key,
                    "baseline_value": str(old_val) if old_val not in (None, "") else "-",
                    "current_value": str(new_val) if new_val not in (None, "") else "-",
                    "change_type": "modified"
                })

        return diffs

    @staticmethod
    def _compute_list_diff(old_list, new_list, path, key):
        """Compare two lists of dicts by identity key, detecting added/removed/modified items."""
        diffs = []
        if not old_list and not new_list:
            return diffs
        if not old_list:
            for i, item in enumerate(new_list):
                label = DatabaseManager._get_item_label(item, i)
                diffs.append({
                    "path": f"{path}[+{i}]",
                    "field": f"{key} (thêm mới)",
                    "baseline_value": "-",
                    "current_value": label,
                    "change_type": "added"
                })
            return diffs
        if not new_list:
            for i, item in enumerate(old_list):
                label = DatabaseManager._get_item_label(item, i)
                diffs.append({
                    "path": f"{path}[-{i}]",
                    "field": f"{key} (đã xóa)",
                    "baseline_value": label,
                    "current_value": "-",
                    "change_type": "removed"
                })
            return diffs

        # For dict lists, match by identity key
        if isinstance(old_list[0], dict) and isinstance(new_list[0], dict):
            # Find identity key: "name", "model", "product", "part_number", "check_id"
            id_keys = ["name", "model", "product", "part_number", "check_id", "title", "manufacturer"]
            id_key = None
            for k in id_keys:
                if all(k in item for item in old_list + new_list if isinstance(item, dict)):
                    id_key = k
                    break

            if id_key:
                old_by_id = {}
                for item in old_list:
                    item_id = str(item.get(id_key, "")).strip().lower()
                    if item_id:
                        old_by_id[item_id] = item

                new_by_id = {}
                for item in new_list:
                    item_id = str(item.get(id_key, "")).strip().lower()
                    if item_id:
                        new_by_id[item_id] = item

                # Find added items (in new but not old)
                for item_id, new_item in new_by_id.items():
                    if item_id not in old_by_id:
                        label = DatabaseManager._get_item_label(new_item, -1)
                        diffs.append({
                            "path": f"{path}.+{item_id}",
                            "field": f"{key} (thêm mới)",
                            "baseline_value": "-",
                            "current_value": label,
                            "change_type": "added"
                        })

                # Find removed items (in old but not new)
                for item_id, old_item in old_by_id.items():
                    if item_id not in new_by_id:
                        label = DatabaseManager._get_item_label(old_item, -1)
                        diffs.append({
                            "path": f"{path}.-{item_id}",
                            "field": f"{key} (đã xóa)",
                            "baseline_value": label,
                            "current_value": "-",
                            "change_type": "removed"
                        })

                # Find modified items (in both, compare fields)
                for item_id in set(old_by_id.keys()) & set(new_by_id.keys()):
                    old_item = old_by_id[item_id]
                    new_item = new_by_id[item_id]
                    sub_diffs = DatabaseManager._compute_diff(old_item, new_item, f"{path}.{item_id}")
                    for d in sub_diffs:
                        d["change_type"] = "modified"
                    diffs.extend(sub_diffs)

                return diffs

        # Fallback: simple index-based comparison
        if len(old_list) != len(new_list):
            diffs.append({
                "path": path,
                "field": f"{key} (số lượng)",
                "baseline_value": f"{len(old_list)} mục",
                "current_value": f"{len(new_list)} mục",
                "change_type": "modified"
            })
        for i in range(min(len(old_list), len(new_list))):
            old_item = old_list[i]
            new_item = new_list[i]
            if isinstance(old_item, dict) and isinstance(new_item, dict):
                diffs.extend(DatabaseManager._compute_diff(old_item, new_item, f"{path}[{i}]"))
            elif str(old_item) != str(new_item):
                diffs.append({
                    "path": f"{path}[{i}]",
                    "field": f"{key}[{i}]",
                    "baseline_value": str(old_item) if old_item else "-",
                    "current_value": str(new_item) if new_item else "-",
                    "change_type": "modified"
                })
        return diffs

    @staticmethod
    def _get_item_label(item, index):
        """Get a human-readable label for a list item."""
        if isinstance(item, dict):
            name = item.get("name") or item.get("model") or item.get("product") or item.get("title") or item.get("part_number") or ""
            version = item.get("version", "")
            publisher = item.get("publisher", "")
            capacity = item.get("capacity_gb") or item.get("size_gb") or ""
            parts = [name]
            if version:
                parts.append(f"v{version}")
            if publisher:
                parts.append(f"({publisher})")
            if capacity:
                parts.append(f"{capacity}GB")
            return " ".join(parts) if parts else str(item)[:80]
        return str(item)[:80]

    def save_machine_config(self, machine_id, config_data):
        """
        Save hardware config received from agent.
        - First time: saves as baseline + current
        - Subsequent: compares with baseline, saves current, returns detailed diff

        Returns dict with:
          - has_changes: bool
          - is_first_config: bool
          - diffs: list of {path, field, baseline_value, current_value}
        """
        current_fingerprint = json.dumps(config_data, sort_keys=True, ensure_ascii=False)

        # Save or get baseline (first-ever config)
        baseline = self.get_baseline(machine_id)
        is_first = (baseline is None)

        if is_first:
            # First time - save baseline
            baseline_data = config_data
            self._save_baseline(machine_id, config_data.get("os", {}).get("name", ""), config_data)
        else:
            baseline_data = baseline.get("data", {})

        # Compute per-component diff against baseline
        diffs = self._compute_diff(baseline_data, config_data) if not is_first else []
        has_changed = len(diffs) > 0

        # Check if current changed vs last stored current
        previous = self.get_hardware_info(machine_id)
        previous_fingerprint = ""
        if previous:
            previous_fingerprint = previous.get("fingerprint", "")

        if previous_fingerprint == current_fingerprint:
            # No change from last time - just update timestamp
            with self.lock:
                self.conn.execute(
                    "UPDATE hardware_info SET received_at=CURRENT_TIMESTAMP WHERE machine_id=?",
                    (machine_id,)
                )
                self.conn.commit()
        else:
            # Store new current config
            with self.lock:
                self.conn.execute("""INSERT INTO hardware_info (machine_id,hostname,data_json,fingerprint,has_changed,received_at) VALUES (?,?,?,?,?,CURRENT_TIMESTAMP) ON CONFLICT(machine_id) DO UPDATE SET hostname=excluded.hostname,data_json=excluded.data_json,fingerprint=excluded.fingerprint,has_changed=excluded.has_changed,received_at=CURRENT_TIMESTAMP""", (machine_id, config_data.get("os", {}).get("name", ""), json.dumps(config_data, ensure_ascii=False), current_fingerprint, 1 if has_changed else 0))
                self.conn.commit()

        return {
            "has_changes": has_changed,
            "is_first_config": is_first,
            "diffs": diffs
        }

    def get_hardware_info(self, machine_id):
        """Get hardware info for a machine."""
        with self.lock:
            c = self.conn.execute("SELECT * FROM hardware_info WHERE machine_id=?", (machine_id,))
            row = c.fetchone()
            if row:
                d = dict(row)
                try:
                    d["data"] = json.loads(d.get("data_json", "{}"))
                except Exception:
                    d["data"] = {}
                return d
            return None

    def insert_event(self, data):
        with self.lock:
            self.conn.execute("""INSERT INTO events (machine_id,hostname,type,subtype,event_id,event_type,source,computer,user,category,time,description,raw_data) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""", (data.get("machine_id",""), data.get("hostname",""), data.get("type",""), data.get("subtype",""), str(data.get("event_id","")), data.get("event_type",""), data.get("source",""), data.get("computer",""), data.get("user",""), str(data.get("category","")), data.get("time",""), data.get("description",""), data.get("raw_data","")))
            self.conn.commit()

    def insert_fim_event(self, data):
        with self.lock:
            self.conn.execute("""INSERT INTO fim_events (machine_id,hostname,action,path,time) VALUES (?,?,?,?,?)""", (data.get("machine_id",""), data.get("hostname",""), data.get("action",""), data.get("path",""), data.get("time","")))
            self.conn.commit()

    def insert_heartbeat(self, data):
        with self.lock:
            self.conn.execute("""INSERT INTO heartbeats (machine_id,hostname,timestamp) VALUES (?,?,?)""", (data.get("machine_id",""), data.get("hostname",""), data.get("timestamp","")))
            self.conn.execute("""UPDATE machines SET last_seen=CURRENT_TIMESTAMP, is_online=1 WHERE machine_id=?""", (data.get("machine_id",""),))
            self.conn.commit()

    def insert_response_result(self, data):
        with self.lock:
            self.conn.execute("""INSERT INTO response_results (machine_id,hostname,exec_id,status,output,error,exit_code,action,timestamp) VALUES (?,?,?,?,?,?,?,?,?)""", (data.get("machine_id",""), data.get("hostname",""), data.get("exec_id",""), data.get("status",""), data.get("output",""), data.get("error",""), data.get("exit_code",0), data.get("action",""), data.get("timestamp","")))
            self.conn.execute("""UPDATE commands SET status=?, executed_at=CURRENT_TIMESTAMP WHERE exec_id=?""", (data.get("status","completed"), data.get("exec_id","")))
            self.conn.commit()

    def insert_syslog(self, source_ip, hostname, facility, severity, timestamp, message, raw_data):
        with self.lock:
            self.conn.execute("""INSERT INTO syslog (source_ip,hostname,facility,severity,timestamp,message,raw_data) VALUES (?,?,?,?,?,?,?)""", (source_ip, hostname, facility, severity, timestamp, message, raw_data))
            self.conn.commit()

    def add_command(self, machine_id, action, command, exec_id):
        with self.lock:
            self.conn.execute("""INSERT INTO commands (machine_id,action,command,exec_id) VALUES (?,?,?,?)""", (machine_id, action, command, exec_id))
            self.conn.commit()

    def get_machines(self):
        with self.lock:
            c = self.conn.execute("""SELECT * FROM machines ORDER BY hostname ASC""")
            return [dict(row) for row in c.fetchall()]

    def get_events(self, machine_id=None, event_type=None, limit=100, since_hours=None):
        """v2.5.22: Added since_hours to limit scan to recent data only."""
        with self.lock:
            q = "SELECT * FROM events WHERE 1=1"
            p = []
            if machine_id: q += " AND machine_id=?"; p.append(machine_id)
            if event_type: q += " AND subtype=?"; p.append(event_type)
            if since_hours:
                q += " AND received_at >= datetime('now', ?)"; p.append(f'-{since_hours} hours')
            q += " ORDER BY id DESC LIMIT ?"; p.append(limit)
            c = self.conn.execute(q, p)
            return [dict(row) for row in c.fetchall()]

    def get_fim_events(self, machine_id=None, limit=100):
        with self.lock:
            q = "SELECT * FROM fim_events WHERE 1=1"
            p = []
            if machine_id: q += " AND machine_id=?"; p.append(machine_id)
            q += " ORDER BY id DESC LIMIT ?"; p.append(limit)
            c = self.conn.execute(q, p)
            return [dict(row) for row in c.fetchall()]

    def get_syslog(self, limit=100, facility=None, severity=None, source_ip=None, search=None):
        with self.lock:
            q = "SELECT * FROM syslog WHERE 1=1"
            p = []
            if facility:
                q += " AND facility=?"; p.append(facility)
            if severity:
                q += " AND severity=?"; p.append(severity)
            if source_ip:
                q += " AND source_ip=?"; p.append(source_ip)
            if search:
                q += " AND message LIKE ?"; p.append(f"%{search}%")
            q += " ORDER BY id DESC LIMIT ?"; p.append(limit)
            c = self.conn.execute(q, p)
            return [dict(row) for row in c.fetchall()]

    def get_response_results(self, machine_id=None, limit=100):
        with self.lock:
            q = "SELECT * FROM response_results WHERE 1=1"
            p = []
            if machine_id: q += " AND machine_id=?"; p.append(machine_id)
            q += " ORDER BY id DESC LIMIT ?"; p.append(limit)
            c = self.conn.execute(q, p)
            return [dict(row) for row in c.fetchall()]

    def get_stats(self, machine_id=None):
        """v3.7.1: Cache stats for 30s + limit COUNT to recent 24h to avoid full table scan."""
        import time
        now = time.time()
        cache_key = f"stats_{machine_id or 'all'}"
        # Return cached stats if fresh (<30s)
        if self._summary_cache.get(cache_key) and (now - self._summary_cache.get(cache_key + "_ts", 0) < 30):
            return self._summary_cache[cache_key]
        
        with self.lock:
            s = {}
            if machine_id:
                c = self.conn.execute(
                    "SELECT COUNT(*) as cnt FROM events WHERE machine_id=? AND received_at >= datetime('now', '-24 hours')",
                    (machine_id,)); s["events"] = c.fetchone()["cnt"]
                c = self.conn.execute(
                    "SELECT COUNT(*) as cnt FROM fim_events WHERE machine_id=?", (machine_id,)); s["fim_events"] = c.fetchone()["cnt"]
                c = self.conn.execute(
                    "SELECT COUNT(*) as cnt FROM response_results WHERE machine_id=?", (machine_id,)); s["responses"] = c.fetchone()["cnt"]
            else:
                # v3.7.1: COUNT 24h window to avoid scanning 600K+ rows
                for t in ["events","fim_events","response_results","syslog"]:
                    if t == "events":
                        c = self.conn.execute("SELECT COUNT(*) as cnt FROM events WHERE received_at >= datetime('now', '-24 hours')")
                    else:
                        c = self.conn.execute(f"SELECT COUNT(*) as cnt FROM {t}")
                    s[t] = c.fetchone()["cnt"]
                c = self.conn.execute("SELECT COUNT(*) as cnt FROM machines WHERE is_online=1"); s["online_machines"] = c.fetchone()["cnt"]
                c = self.conn.execute("SELECT COUNT(*) as cnt FROM machines"); s["total_machines"] = c.fetchone()["cnt"]
            # Cache stats
            self._summary_cache[cache_key] = s
            self._summary_cache[cache_key + "_ts"] = now
            return s

    def get_event_types(self, machine_id=None):
        """v3.7.1: Limit to 24h window to avoid full table scan."""
        with self.lock:
            if machine_id:
                c = self.conn.execute(
                    """SELECT subtype, COUNT(*) as cnt FROM events
                       WHERE machine_id=? AND received_at >= datetime('now', '-24 hours')
                       GROUP BY subtype ORDER BY cnt DESC LIMIT 10""",
                    (machine_id,))
            else:
                c = self.conn.execute(
                    """SELECT subtype, COUNT(*) as cnt FROM events
                       WHERE received_at >= datetime('now', '-24 hours')
                       GROUP BY subtype ORDER BY cnt DESC LIMIT 10""")
            return [dict(row) for row in c.fetchall()]

    def insert_network_traffic(self, data):
        with self.lock:
            self.conn.execute("""INSERT INTO network_traffic (machine_id,hostname,src_ip,dst_ip,src_port,dst_port,protocol,size,flags,state,timestamp,raw_data,src_mac,dst_mac,ip_ttl,ip_proto,tcp_flags,payload_hex,payload_size,protocol_app,dns_query,http_host,payload_dump) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
                data.get("machine_id",""), data.get("hostname",""),
                data.get("src_ip",""), data.get("dst_ip",""),
                data.get("src_port",0), data.get("dst_port",0),
                data.get("protocol",""), data.get("size",0),
                data.get("flags",""), data.get("state",""),
                data.get("timestamp",""), data.get("raw_data",""),
                data.get("src_mac",""), data.get("dst_mac",""),
                data.get("ip_ttl",0), data.get("ip_proto",0),
                data.get("tcp_flags",""), data.get("payload_hex",""),
                data.get("payload_size",0), data.get("protocol_app",""),
                data.get("dns_query",""), data.get("http_host",""),
                data.get("payload_dump","")
            ))
            self.conn.commit()

    def get_network_traffic(self, machine_id=None, limit=100, since_hours=None):
        with self.lock:
            q = "SELECT * FROM network_traffic WHERE 1=1"
            p = []
            if machine_id: q += " AND machine_id=?"; p.append(machine_id)
            if since_hours:
                q += " AND received_at >= datetime('now', ?)"; p.append(f'-{since_hours} hours')
            q += " ORDER BY id DESC LIMIT ?"; p.append(limit)
            c = self.conn.execute(q, p)
            return [dict(row) for row in c.fetchall()]

    def insert_threat_alert(self, data):
        """v2.1.1: UPSERT dedup - same machine + rule_id updates timestamp instead of duplicate."""
        with self.lock:
            machine_id = data.get("machine_id", "")
            rule_id = data.get("rule_id", "")
            existing = self.conn.execute(
                "SELECT id FROM threat_alerts WHERE machine_id=? AND rule_id=? ORDER BY id DESC LIMIT 1",
                (machine_id, rule_id)
            ).fetchone()
            if existing:
                self.conn.execute(
                    """UPDATE threat_alerts SET hostname=?, rule_name=?, description=?, severity=?, timestamp=?, raw_data=?, received_at=CURRENT_TIMESTAMP WHERE id=?""",
                    (data.get("hostname",""), data.get("rule_name",""), data.get("description",""), data.get("severity",""), data.get("timestamp",""), json.dumps(data, ensure_ascii=False), existing["id"])
                )
            else:
                self.conn.execute("""INSERT INTO threat_alerts (machine_id,hostname,rule_id,rule_name,description,severity,timestamp,raw_data) VALUES (?,?,?,?,?,?,?,?)""", (machine_id, data.get("hostname",""), rule_id, data.get("rule_name",""), data.get("description",""), data.get("severity",""), data.get("timestamp",""), json.dumps(data, ensure_ascii=False)))
            self.conn.commit()

    def get_threat_alerts(self, machine_id=None, limit=100, since_hours=None):
        with self.lock:
            q = "SELECT * FROM threat_alerts WHERE 1=1"
            p = []
            if machine_id: q += " AND machine_id=?"; p.append(machine_id)
            if since_hours:
                q += " AND received_at >= datetime('now', ?)"; p.append(f'-{since_hours} hours')
            q += " ORDER BY id DESC LIMIT ?"; p.append(limit)
            c = self.conn.execute(q, p)
            return [dict(row) for row in c.fetchall()]

    def insert_vuln_alert(self, data):
        """v2.1.1: UPSERT dedup - same machine + cve + software updates timestamp instead of duplicate."""
        with self.lock:
            machine_id = data.get("machine_id", "")
            cve = data.get("cve", "")
            software = data.get("software", "")
            existing = self.conn.execute(
                "SELECT id FROM vuln_alerts WHERE machine_id=? AND cve=? AND software=? ORDER BY id DESC LIMIT 1",
                (machine_id, cve, software)
            ).fetchone()
            if existing:
                self.conn.execute(
                    """UPDATE vuln_alerts SET hostname=?, version=?, publisher=?, severity=?, description=?, timestamp=?, received_at=CURRENT_TIMESTAMP WHERE id=?""",
                    (data.get("hostname",""), data.get("version",""), data.get("publisher",""), data.get("severity",""), data.get("description",""), data.get("timestamp",""), existing["id"])
                )
            else:
                self.conn.execute("""INSERT INTO vuln_alerts (machine_id,hostname,software,version,publisher,cve,severity,description,timestamp) VALUES (?,?,?,?,?,?,?,?,?)""", (machine_id, data.get("hostname",""), software, data.get("version",""), data.get("publisher",""), cve, data.get("severity",""), data.get("description",""), data.get("timestamp","")))
            self.conn.commit()

    def get_vuln_alerts(self, machine_id=None, limit=100, since_hours=None):
        with self.lock:
            q = "SELECT * FROM vuln_alerts WHERE 1=1"
            p = []
            if machine_id: q += " AND machine_id=?"; p.append(machine_id)
            if since_hours:
                q += " AND received_at >= datetime('now', ?)"; p.append(f'-{since_hours} hours')
            q += " ORDER BY id DESC LIMIT ?"; p.append(limit)
            c = self.conn.execute(q, p)
            return [dict(row) for row in c.fetchall()]

    def insert_network_inspection(self, data):
        with self.lock:
            self.conn.execute("""INSERT INTO network_inspection (machine_id,hostname,subtype,domain,dst_ip,dst_port,src_ip,src_port,protocol,query_type,avg_interval_sec,sample_count,timestamp) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""", (data.get("machine_id",""), data.get("hostname",""), data.get("subtype",""), data.get("domain",""), data.get("dst_ip",""), data.get("dst_port",0), data.get("src_ip",""), data.get("src_port",0), data.get("protocol",""), data.get("query_type",""), data.get("avg_interval_sec",0), data.get("sample_count",0), data.get("timestamp","")))
            self.conn.commit()

    def get_network_inspection(self, machine_id=None, subtype=None, limit=100):
        with self.lock:
            q = "SELECT * FROM network_inspection WHERE 1=1"
            p = []
            if machine_id: q += " AND machine_id=?"; p.append(machine_id)
            if subtype: q += " AND subtype=?"; p.append(subtype)
            q += " ORDER BY id DESC LIMIT ?"; p.append(limit)
            c = self.conn.execute(q, p)
            return [dict(row) for row in c.fetchall()]

    def insert_yara_alert(self, data):
        """v2.1.1: UPSERT dedup - same machine + rule_name + file updates timestamp instead of duplicate."""
        with self.lock:
            machine_id = data.get("machine_id", "")
            rule_name = data.get("rule_name", "")
            file_path = data.get("file", "")
            existing = self.conn.execute(
                "SELECT id FROM yara_alerts WHERE machine_id=? AND rule_name=? AND file=? ORDER BY id DESC LIMIT 1",
                (machine_id, rule_name, file_path)
            ).fetchone()
            if existing:
                self.conn.execute(
                    """UPDATE yara_alerts SET hostname=?, description=?, timestamp=?, received_at=CURRENT_TIMESTAMP WHERE id=?""",
                    (data.get("hostname",""), data.get("description",""), data.get("timestamp",""), existing["id"])
                )
            else:
                self.conn.execute("""INSERT INTO yara_alerts (machine_id,hostname,rule_name,description,file,timestamp) VALUES (?,?,?,?,?,?)""", (machine_id, data.get("hostname",""), rule_name, data.get("description",""), file_path, data.get("timestamp","")))
            self.conn.commit()
    def deduplicate_alerts(self):
        """v2.1.1: Clean up duplicate threat/vuln/yara alerts keeping only the latest per key."""
        with self.lock:
            # Remove threat duplicates (keep latest by id per machine_id+rule_id)
            self.conn.execute("DELETE FROM threat_alerts WHERE id NOT IN (SELECT MAX(id) FROM threat_alerts GROUP BY machine_id, rule_id)")
            # Remove vuln duplicates (keep latest by id per machine_id+cve+software)
            self.conn.execute("DELETE FROM vuln_alerts WHERE id NOT IN (SELECT MAX(id) FROM vuln_alerts GROUP BY machine_id, cve, software)")
            # Remove yara duplicates (keep latest by id per machine_id+rule_name+file)
            self.conn.execute("DELETE FROM yara_alerts WHERE id NOT IN (SELECT MAX(id) FROM yara_alerts GROUP BY machine_id, rule_name, file)")
            self.conn.commit()
        print("[*] Deduplication: cleaned duplicate threat/vuln/yara alerts")

    def get_yara_alerts(self, machine_id=None, limit=100, since_hours=None):
        with self.lock:
            q = "SELECT * FROM yara_alerts WHERE 1=1"
            p = []
            if machine_id: q += " AND machine_id=?"; p.append(machine_id)
            if since_hours:
                q += " AND received_at >= datetime('now', ?)"; p.append(f'-{since_hours} hours')
            q += " ORDER BY id DESC LIMIT ?"; p.append(limit)
            c = self.conn.execute(q, p)
            return [dict(row) for row in c.fetchall()]

    # ---- NEW v1.6.0: SCA Events (UPSERT - update if exists) ----
    def insert_sca_event(self, data):
        with self.lock:
            machine_id = data.get("machine_id", "")
            check_id = data.get("check_id", "")
            # Check if this check already exists for this machine
            existing = self.conn.execute(
                "SELECT id FROM sca_events WHERE machine_id=? AND check_id=? ORDER BY id DESC LIMIT 1",
                (machine_id, check_id)
            ).fetchone()
            if existing:
                # Update existing record
                self.conn.execute(
                    """UPDATE sca_events SET hostname=?, title=?, status=?, severity=?, description=?, remediation=?, timestamp=?, received_at=CURRENT_TIMESTAMP WHERE id=?""",
                    (data.get("hostname",""), data.get("title",""), data.get("status",""), data.get("severity",""), data.get("description",""), data.get("remediation",""), data.get("timestamp",""), existing["id"])
                )
            else:
                self.conn.execute(
                    """INSERT INTO sca_events (machine_id,hostname,check_id,title,status,severity,description,remediation,timestamp) VALUES (?,?,?,?,?,?,?,?,?)""",
                    (machine_id, data.get("hostname",""), check_id, data.get("title",""), data.get("status",""), data.get("severity",""), data.get("description",""), data.get("remediation",""), data.get("timestamp",""))
                )
            self.conn.commit()

    def get_sca_events(self, machine_id=None, limit=100):
        with self.lock:
            q = "SELECT * FROM sca_events WHERE 1=1"
            p = []
            if machine_id: q += " AND machine_id=?"; p.append(machine_id)
            q += " ORDER BY id DESC LIMIT ?"; p.append(limit)
            c = self.conn.execute(q, p)
            return [dict(row) for row in c.fetchall()]

    # ---- NEW v1.6.0: Agentless Events ----
    def insert_agentless_event(self, data):
        with self.lock:
            self.conn.execute("""INSERT INTO agentless_events (device_name,ip,device_type,data_json,timestamp) VALUES (?,?,?,?,?)""", (data.get("device_name",""), data.get("ip",""), data.get("device_type",""), json.dumps(data, ensure_ascii=False), data.get("timestamp","")))
            self.conn.commit()

    def get_agentless_events(self, limit=100):
        with self.lock:
            c = self.conn.execute("SELECT * FROM agentless_events ORDER BY id DESC LIMIT ?", (limit,))
            return [dict(row) for row in c.fetchall()]

    def clear_agentless_events(self):
        with self.lock:
            c = self.conn.execute("DELETE FROM agentless_events")
            self.conn.commit()
            return c.rowcount

    # ---- NEW v1.6.0: Audit Log ----
    def insert_audit_log(self, username, action, details="", ip_address=""):
        with self.lock:
            self.conn.execute("""INSERT INTO audit_log (username,action,details,ip_address) VALUES (?,?,?,?)""", (username, action, details, ip_address))
            self.conn.commit()

    def get_audit_log(self, limit=100):
        with self.lock:
            c = self.conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))
            return [dict(row) for row in c.fetchall()]

    # ---- NEW v1.6.0: Retention Policy ----
    def cleanup_old_logs(self, days=30, keep_threats=True):
        """Xóa log cũ hơn N ngày. Nếu keep_threats=True, giữ lại các event liên quan đến threat alerts."""
        deleted_total = 0
        with self.lock:
            if keep_threats:
                # Lấy danh sách machine_id có threat alerts trong khoảng thời gian
                # Giữ lại tất cả events của những máy này
                threat_machines = set()
                c = self.conn.execute(
                    "SELECT DISTINCT machine_id FROM threat_alerts WHERE received_at >= datetime('now', ?)",
                    (f'-{days} days',)
                )
                for row in c.fetchall():
                    threat_machines.add(row[0])

                c = self.conn.execute(
                    "SELECT DISTINCT machine_id FROM vuln_alerts WHERE received_at >= datetime('now', ?)",
                    (f'-{days} days',)
                )
                for row in c.fetchall():
                    threat_machines.add(row[0])

            # Xóa từng bảng
            tables_days = {
                "events": days, "fim_events": days * 3,
                "heartbeats": 7, "syslog": days,
                "network_traffic": days, "network_inspection": days,
                "response_results": days * 2, "commands": days * 2,
            }
            for table, d in tables_days.items():
                try:
                    if keep_threats and threat_machines and table in ("events", "fim_events", "network_traffic", "network_inspection"):
                        # Giữ lại events của máy có threat
                        placeholders = ",".join(["?" for _ in threat_machines])
                        c = self.conn.execute(
                            f"DELETE FROM {table} WHERE received_at < datetime('now', '-{d} days') AND machine_id NOT IN ({placeholders})",
                            list(threat_machines)
                        )
                    else:
                        c = self.conn.execute(
                            f"DELETE FROM {table} WHERE received_at < datetime('now', '-{d} days')"
                        )
                    deleted_total += c.rowcount
                except Exception:
                    pass
            # COMMIT
            self.conn.commit()
        return deleted_total

    def apply_retention_policy(self, event_days=30, fim_days=90, traffic_days=30,
                                threat_days=180, vuln_days=180, syslog_days=30,
                                heartbeat_days=7, sca_days=90):
        """Delete data older than specified days."""
        policies = {
            "events": event_days, "fim_events": fim_days,
            "network_traffic": traffic_days, "threat_alerts": threat_days,
            "vuln_alerts": vuln_days, "syslog": syslog_days,
            "heartbeats": heartbeat_days, "sca_events": sca_days,
        }
        deleted_total = 0
        with self.lock:
            for table, days in policies.items():
                try:
                    c = self.conn.execute(
                        f"DELETE FROM {table} WHERE received_at < datetime('now', '-{days} days')"
                    )
                    deleted_total += c.rowcount
                except Exception:
                    pass
            self.conn.commit()
        if deleted_total > 0:
            print(f"[*] Retention policy: deleted {deleted_total} old records")
        return deleted_total

    # =========================================================================
    # v2.1.0: AGENT GROUPS - Per-group policy management
    # =========================================================================

    def create_agent_group(self, name, description="", config_json="{}"):
        with self.lock:
            c = self.conn.execute(
                "INSERT INTO agent_groups (name, description, config_json) VALUES (?, ?, ?)",
                (name, description, config_json)
            )
            self.conn.commit()
            return c.lastrowid

    def update_agent_group(self, group_id, name=None, description=None, config_json=None):
        with self.lock:
            row = self.conn.execute("SELECT * FROM agent_groups WHERE id=?", (group_id,)).fetchone()
            if not row:
                return False
            updates = []
            params = []
            if name is not None:
                updates.append("name=?"); params.append(name)
            if description is not None:
                updates.append("description=?"); params.append(description)
            if config_json is not None:
                updates.append("config_json=?"); params.append(config_json)
            if updates:
                updates.append("updated_at=CURRENT_TIMESTAMP")
                params.append(group_id)
                self.conn.execute(f"UPDATE agent_groups SET {','.join(updates)} WHERE id=?", params)
                self.conn.commit()
            return True

    def delete_agent_group(self, group_id):
        with self.lock:
            self.conn.execute("DELETE FROM agent_group_members WHERE group_id=?", (group_id,))
            self.conn.execute("DELETE FROM agent_groups WHERE id=?", (group_id,))
            self.conn.commit()

    def get_agent_groups(self):
        with self.lock:
            c = self.conn.execute("SELECT * FROM agent_groups ORDER BY name ASC")
            groups = []
            for row in c.fetchall():
                g = dict(row)
                g["config"] = json.loads(g.get("config_json", "{}")) if g.get("config_json") else {}
                del g["config_json"]
                g["members"] = self._get_group_members(g["id"])
                groups.append(g)
            return groups

    def get_agent_group(self, group_id):
        with self.lock:
            row = self.conn.execute("SELECT * FROM agent_groups WHERE id=?", (group_id,)).fetchone()
            if row:
                g = dict(row)
                g["config"] = json.loads(g.get("config_json", "{}")) if g.get("config_json") else {}
                del g["config_json"]
                g["members"] = self._get_group_members(g["id"])
                return g
            return None

    def add_machine_to_group(self, machine_id, group_id):
        with self.lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO agent_group_members (group_id, machine_id) VALUES (?, ?)",
                (group_id, machine_id)
            )
            self.conn.commit()

    def remove_machine_from_group(self, machine_id, group_id):
        with self.lock:
            self.conn.execute(
                "DELETE FROM agent_group_members WHERE machine_id=? AND group_id=?",
                (machine_id, group_id)
            )
            self.conn.commit()

    def get_machine_group(self, machine_id):
        """Get the group a machine belongs to, if any."""
        with self.lock:
            row = self.conn.execute(
                "SELECT g.* FROM agent_groups g JOIN agent_group_members m ON g.id=m.group_id WHERE m.machine_id=?",
                (machine_id,)
            ).fetchone()
            return dict(row) if row else None

    def get_group_config(self, machine_id):
        """Get effective config for a machine (group config if in group, else None)."""
        with self.lock:
            row = self.conn.execute(
                "SELECT g.config_json FROM agent_groups g JOIN agent_group_members m ON g.id=m.group_id WHERE m.machine_id=?",
                (machine_id,)
            ).fetchone()
            if row and row["config_json"]:
                try:
                    return json.loads(row["config_json"])
                except Exception:
                    pass
            return None

    def _get_group_members(self, group_id):
        """Called internal - caller already holds self.lock"""
        c = self.conn.execute(
            "SELECT m.machine_id, mach.hostname, mach.ip_address, mach.is_online FROM agent_group_members m LEFT JOIN machines mach ON m.machine_id=mach.machine_id WHERE m.group_id=?",
            (group_id,)
        )
        return [dict(row) for row in c.fetchall()]

    # =========================================================================
    # v3.9.2: GROUP POLICIES — Per-group policy enforcement
    # =========================================================================

    def add_policy(self, group_id, policy_type, policy_name="", config_json="{}"):
        """Add a new policy to a group. Returns policy ID."""
        with self.lock:
            c = self.conn.execute(
                """INSERT INTO group_policies (group_id, policy_type, policy_name, config_json)
                   VALUES (?, ?, ?, ?)""",
                (group_id, policy_type, policy_name, config_json)
            )
            self.conn.commit()
            self.insert_audit_log("admin", "add_policy",
                f"group_id={group_id} type={policy_type} name={policy_name}")
            return c.lastrowid

    def update_policy(self, policy_id, policy_name=None, config_json=None, enabled=None):
        """Update policy fields. Returns True if found."""
        with self.lock:
            row = self.conn.execute("SELECT * FROM group_policies WHERE id=?", (policy_id,)).fetchone()
            if not row:
                return False
            updates = []
            params = []
            if policy_name is not None:
                updates.append("policy_name=?"); params.append(policy_name)
            if config_json is not None:
                updates.append("config_json=?"); params.append(config_json)
            if enabled is not None:
                updates.append("enabled=?"); params.append(1 if enabled else 0)
            if updates:
                # If disabling, mark for removal; otherwise mark as new pending apply
                if enabled is not None and not enabled:
                    updates.append("apply_status='pending_removal'")
                else:
                    updates.append("apply_status='pending'")
                updates.append("updated_at=CURRENT_TIMESTAMP")
                params.append(policy_id)
                self.conn.execute(f"UPDATE group_policies SET {','.join(updates)} WHERE id=?", params)
                self.conn.commit()
            return True

    def delete_policy(self, policy_id):
        """Delete a policy by ID."""
        with self.lock:
            self.conn.execute("DELETE FROM group_policies WHERE id=?", (policy_id,))
            self.conn.commit()

    def get_policies(self, group_id=None):
        """Get all policies, optionally filtered by group_id."""
        with self.lock:
            if group_id:
                c = self.conn.execute(
                    "SELECT * FROM group_policies WHERE group_id=? ORDER BY created_at DESC",
                    (group_id,))
            else:
                c = self.conn.execute(
                    "SELECT g.name as group_name, p.* FROM group_policies p "
                    "JOIN agent_groups g ON p.group_id=g.id ORDER BY p.created_at DESC")
            return [dict(row) for row in c.fetchall()]

    def get_policy(self, policy_id):
        """Get single policy by ID."""
        with self.lock:
            row = self.conn.execute("SELECT * FROM group_policies WHERE id=?", (policy_id,)).fetchone()
            return dict(row) if row else None

    def update_policy_status(self, policy_id, status, message=""):
        """Update apply status of a policy."""
        with self.lock:
            self.conn.execute(
                "UPDATE group_policies SET apply_status=?, status_message=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                (status, message, policy_id))
            self.conn.commit()

    def get_pending_policies_for_machine(self, machine_id):
        """Get all pending policies for a machine based on its group membership."""
        with self.lock:
            c = self.conn.execute(
                """SELECT p.* FROM group_policies p
                   JOIN agent_group_members m ON p.group_id=m.group_id
                   WHERE m.machine_id=? AND p.enabled=1 AND p.apply_status='pending'
                   ORDER BY p.created_at ASC""",
                (machine_id,))
            return [dict(row) for row in c.fetchall()]

    def get_removal_policies_for_machine(self, machine_id):
        """Get policies that were applied but now need removal (disabled by admin).
        Returns list of policy dicts that need remove_block_* action."""
        with self.lock:
            c = self.conn.execute(
                """SELECT p.* FROM group_policies p
                   JOIN agent_group_members m ON p.group_id=m.group_id
                   WHERE m.machine_id=? AND p.enabled=0 AND p.apply_status='applied'
                   ORDER BY p.created_at ASC""",
                (machine_id,))
            return [dict(row) for row in c.fetchall()]

    def mark_policy_removal_sent(self, policy_id):
        """Mark a policy as removal-sent (status back to pending)."""
        with self.lock:
            self.conn.execute(
                "UPDATE group_policies SET apply_status='pending', updated_at=CURRENT_TIMESTAMP WHERE id=?",
                (policy_id,))
            self.conn.commit()

    # =========================================================================
    # v2.1.0: FIM BASELINE - File integrity tracking with hash comparison
    # =========================================================================

    def upsert_fim_baseline(self, machine_id, path, file_hash, file_size, owner="", permissions="", last_modified=""):
        """Insert or update a FIM baseline entry. Returns True if changed, False if same."""
        with self.lock:
            existing = self.conn.execute(
                "SELECT file_hash, file_size, change_count FROM fim_baseline WHERE machine_id=? AND path=?",
                (machine_id, path)
            ).fetchone()
            if existing:
                if existing["file_hash"] == file_hash and existing["file_size"] == file_size:
                    # No change, just update last_checked
                    self.conn.execute(
                        "UPDATE fim_baseline SET last_checked=CURRENT_TIMESTAMP WHERE machine_id=? AND path=?",
                        (machine_id, path)
                    )
                    self.conn.commit()
                    return False
                else:
                    # File changed - save old hash, update baseline, increment change_count
                    self.conn.execute(
                        """UPDATE fim_baseline SET file_hash_old=file_hash, file_hash=?, file_size=?, owner=?, permissions=?,
                           last_modified=?, change_count=change_count+1, last_checked=CURRENT_TIMESTAMP
                           WHERE machine_id=? AND path=?""",
                        (file_hash, file_size, owner, permissions, last_modified, machine_id, path)
                    )
                    self.conn.commit()
                    return True
            else:
                # New file in baseline
                self.conn.execute(
                    """INSERT INTO fim_baseline (machine_id, path, file_hash, file_size, owner, permissions, last_modified)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (machine_id, path, file_hash, file_size, owner, permissions, last_modified)
                )
                self.conn.commit()
                return True

    def get_fim_baseline(self, machine_id, limit=1000, offset=0, search="", only_changed=False, sort_by="path"):
        """v3.7.2: Paginated + searchable FIM baseline query."""
        valid_sort = {"path": "path", "change_count": "change_count DESC", "last_checked": "last_checked DESC"}
        order_clause = valid_sort.get(sort_by, "path ASC")
        if sort_by == "path":
            order_clause = "path ASC"
        with self.lock:
            q = "SELECT * FROM fim_baseline WHERE machine_id=?"
            p = [machine_id]
            if search:
                q += " AND path LIKE ?"
                p.append(f"%{search}%")
            if only_changed:
                q += " AND change_count > 0"
            q += f" ORDER BY {order_clause} LIMIT ? OFFSET ?"
            p.extend([limit, offset])
            c = self.conn.execute(q, p)
            return [dict(row) for row in c.fetchall()]

    def get_fim_baseline_stats(self, machine_id):
        with self.lock:
            total = self.conn.execute(
                "SELECT COUNT(*) as cnt FROM fim_baseline WHERE machine_id=?", (machine_id,)
            ).fetchone()["cnt"]
            checked_24h = self.conn.execute(
                "SELECT COUNT(*) as cnt FROM fim_baseline WHERE machine_id=? AND last_checked >= datetime('now', '-1 day')",
                (machine_id,)
            ).fetchone()["cnt"]
            changed_total = self.conn.execute(
                "SELECT COUNT(*) as cnt FROM fim_baseline WHERE machine_id=? AND change_count > 0",
                (machine_id,)
            ).fetchone()["cnt"]
            changed_24h = self.conn.execute(
                "SELECT COUNT(*) as cnt FROM fim_baseline WHERE machine_id=? AND change_count > 0 AND last_checked >= datetime('now', '-1 day')",
                (machine_id,)
            ).fetchone()["cnt"]
            return {
                "total_files": total,
                "checked_24h": checked_24h,
                "changed_files": changed_total,
                "changed_24h": changed_24h,
            }

    # =========================================================================
    # v3.8.0: ALERT SUPPRESSION - Global Whitelist for False Positive Tuning
    # =========================================================================

    def add_suppression(self, rule_id, machine_id=None, field_path=None, field_hash=None, reason="", created_by="admin"):
        """Add a suppression rule. Returns suppression id."""
        with self.lock:
            c = self.conn.execute(
                """INSERT INTO alert_suppression (rule_id, machine_id, field_path, field_hash, reason, created_by)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (rule_id, machine_id, field_path, field_hash, reason, created_by)
            )
            self.conn.commit()
            self.insert_audit_log(created_by, "add_suppression",
                f"rule={rule_id} machine={machine_id or 'all'} path={field_path or '-'} hash={field_hash or '-'}")
            return c.lastrowid

    def remove_suppression(self, suppression_id):
        """Remove a suppression rule by ID."""
        with self.lock:
            self.conn.execute("DELETE FROM alert_suppression WHERE id=?", (suppression_id,))
            self.conn.commit()
            self.insert_audit_log("admin", "remove_suppression", f"id={suppression_id}")

    def get_suppressions(self):
        """Get all active suppressions (not expired)."""
        with self.lock:
            c = self.conn.execute(
                """SELECT * FROM alert_suppression
                   WHERE expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP
                   ORDER BY created_at DESC"""
            )
            return [dict(row) for row in c.fetchall()]

    def is_suppressed(self, rule_id, machine_id=None, event_data=None):
        """v3.8.0: Check if an alert should be suppressed.
        Returns True if the rule+context matches any active suppression.
        event_data: dict with 'path', 'hash' fields for context matching."""
        with self.lock:
            # Check global + machine-specific suppressions
            q = """SELECT * FROM alert_suppression
                   WHERE rule_id=? AND (machine_id IS NULL OR machine_id=?)
                   AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)"""
            rows = self.conn.execute(q, (rule_id, machine_id or "")).fetchall()
            if not rows:
                return False
            if event_data is None:
                return len(rows) > 0  # Rule-only suppression (no field filter)
            for row in rows:
                row_dict = dict(row)
                path_match = row_dict.get("field_path")
                hash_match = row_dict.get("field_hash")
                if path_match and event_data.get("path"):
                    if path_match.lower() in (event_data.get("path") or "").lower():
                        return True
                if hash_match and event_data.get("hash"):
                    if hash_match.lower() == (event_data.get("hash") or "").lower():
                        return True
                if not path_match and not hash_match:
                    return True  # Rule-level suppression, no field filter
            return False

    # =========================================================================
    # v2.2.0: MACHINE USER INFO - Agent reports user_name, employee_id, email
    # =========================================================================

    def save_machine_user(self, machine_id, hostname, user_name="", employee_id="", email=""):
        """Save/update the user info for a machine reported by agent."""
        with self.lock:
            self.conn.execute(
                """INSERT INTO machine_users (machine_id, hostname, user_name, employee_id, email, updated_at)
                   VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                   ON CONFLICT(machine_id) DO UPDATE SET
                       hostname=excluded.hostname,
                       user_name=excluded.user_name,
                       employee_id=excluded.employee_id,
                       email=excluded.email,
                       updated_at=CURRENT_TIMESTAMP""",
                (machine_id, hostname, user_name, employee_id, email)
            )
            self.conn.commit()

    def get_machine_user(self, machine_id):
        """Get user info for a specific machine."""
        with self.lock:
            row = self.conn.execute(
                "SELECT * FROM machine_users WHERE machine_id=?", (machine_id,)
            ).fetchone()
            return dict(row) if row else None

    def get_all_machine_users(self):
        """Get user info for all machines (for dashboard overview)."""
        with self.lock:
            c = self.conn.execute("SELECT * FROM machine_users ORDER BY hostname ASC")
            return [dict(row) for row in c.fetchall()]

    # =========================================================================
    # v2.3.0: MACHINE UPTIME TRACKING - continuous online duration + 24h alerts
    # =========================================================================
    # v4.5.3 FIX: uptime was tracked per calendar day (date=today), so it reset
    # at midnight and a machine online 30h+ only showed the hours since midnight.
    # Sessions are now continuous across midnight and only reset when the machine
    # goes offline/reboots (heartbeat gap > _UPTIME_GAP_SECONDS) or when the
    # agent reports a new OS boot_time.

    def _uptime_session_info(self, machine_id, now, boot_time=None):
        """Return (session_start, last_seen, alerted, active) for the machine's
        current continuous session. Merges contiguous sessions across midnight
        to heal sessions split by the old per-day logic."""
        from datetime import datetime as _dt
        def _parse(s):
            try:
                return _dt.strptime(s, "%Y-%m-%d %H:%M:%S")
            except Exception:
                return None

        # Agent-provided OS boot time is authoritative for the current session.
        if boot_time:
            try:
                bt = _dt.fromtimestamp(int(boot_time)).strftime("%Y-%m-%d %H:%M:%S")
                row = self.conn.execute(
                    "SELECT alert_sent_24h FROM machine_uptime WHERE machine_id=? AND session_start=? LIMIT 1",
                    (machine_id, bt)
                ).fetchone()
                if row:
                    return bt, None, bool(row["alert_sent_24h"]), True
                return bt, None, False, True  # new boot -> new session
            except Exception:
                pass

        rows = self.conn.execute(
            "SELECT session_start, last_seen, alert_sent_24h FROM machine_uptime "
            "WHERE machine_id=? ORDER BY session_start DESC",
            (machine_id,)
        ).fetchall()
        if not rows:
            return None, None, False, False

        newest = rows[0]
        last_dt = _parse(newest["last_seen"])
        active = last_dt is not None and (now - last_dt).total_seconds() <= _UPTIME_GAP_SECONDS
        if not active:
            return newest["session_start"], newest["last_seen"], bool(newest["alert_sent_24h"]), False

        effective_start = newest["session_start"]
        alerted = bool(newest["alert_sent_24h"])
        for older in rows[1:]:
            cur = _parse(effective_start)
            old_last = _parse(older["last_seen"])
            if cur is None or old_last is None:
                break
            if (cur - old_last).total_seconds() <= _UPTIME_GAP_SECONDS:
                effective_start = older["session_start"]
                alerted = alerted or bool(older["alert_sent_24h"])
            else:
                break
        return effective_start, newest["last_seen"], alerted, True

    def track_machine_uptime(self, machine_id, hostname, boot_time=None):
        """Called on each TCP heartbeat. Tracks continuous uptime since the
        machine last came online (crosses midnight). Returns
        (uptime_hours, should_alert_24h) tuple."""
        from datetime import datetime as _dt
        now = _dt.now()
        now_str = now.strftime("%Y-%m-%d %H:%M:%S")
        today = now.strftime("%Y-%m-%d")
        with self.lock:
            session_start, last_seen, alerted, active = self._uptime_session_info(machine_id, now, boot_time)
            if not session_start or not active:
                session_start = now_str
                alerted = False
            row = self.conn.execute(
                "SELECT 1 FROM machine_uptime WHERE machine_id=? AND session_start=? LIMIT 1",
                (machine_id, session_start)
            ).fetchone()
            if row is None:
                # New session (first ever, or new boot/reboot).
                self.conn.execute(
                    "INSERT INTO machine_uptime (machine_id,date,session_start,last_seen,uptime_minutes,alert_sent_24h) VALUES (?,?,?,?,0,0)",
                    (machine_id, today, session_start, now_str)
                )
                if boot_time:
                    # New OS boot: drop stale sessions so readers don't over-merge.
                    self.conn.execute(
                        "DELETE FROM machine_uptime WHERE machine_id=? AND session_start <> ?",
                        (machine_id, session_start)
                    )
            else:
                # Continue session; remove stale split rows newer than it.
                self.conn.execute(
                    "DELETE FROM machine_uptime WHERE machine_id=? AND session_start > ?",
                    (machine_id, session_start)
                )
            try:
                start_dt = _dt.strptime(session_start, "%Y-%m-%d %H:%M:%S")
                uptime_minutes = max(int((now - start_dt).total_seconds() / 60), 0)
            except Exception:
                uptime_minutes = 0
            self.conn.execute(
                "UPDATE machine_uptime SET last_seen=?, uptime_minutes=?, date=? WHERE machine_id=? AND session_start=?",
                (now_str, uptime_minutes, today, machine_id, session_start)
            )
            self.conn.commit()

        uptime_hours = round(uptime_minutes / 60.0, 1) if uptime_minutes else 0.0
        should_alert = uptime_hours >= 24 and not alerted
        if should_alert:
            with self.lock:
                self.conn.execute(
                    "UPDATE machine_uptime SET alert_sent_24h=1 WHERE machine_id=? AND session_start=?",
                    (machine_id, session_start)
                )
                self.conn.commit()
        return uptime_hours, should_alert

    def get_machine_uptime_today(self, machine_id):
        """Get current continuous uptime for a machine (or None if no data)."""
        from datetime import datetime as _dt
        now = _dt.now()
        with self.lock:
            session_start, last_seen, alerted, active = self._uptime_session_info(machine_id, now)
            if not session_start:
                return None
            try:
                if active:
                    end_dt = now
                else:
                    end_dt = _dt.strptime(last_seen, "%Y-%m-%d %H:%M:%S")
                start_dt = _dt.strptime(session_start, "%Y-%m-%d %H:%M:%S")
                minutes = max(int((end_dt - start_dt).total_seconds() / 60), 0)
            except Exception:
                minutes = 0
            return {
                "machine_id": machine_id,
                "session_start": session_start,
                "last_seen": last_seen,
                "uptime_minutes": minutes,
                "uptime_hours": round(minutes / 60.0, 1),
                "alert_sent_24h": 1 if alerted else 0,
            }

    def get_all_machine_uptime_today(self):
        """Get current continuous uptime for all machines."""
        from datetime import datetime as _dt
        now = _dt.now()
        result = {}
        with self.lock:
            mids = [r["machine_id"] for r in self.conn.execute(
                "SELECT DISTINCT machine_id FROM machine_uptime").fetchall()]
            for mid in mids:
                session_start, last_seen, alerted, active = self._uptime_session_info(mid, now)
                if not session_start:
                    continue
                try:
                    if active:
                        end_dt = now
                    else:
                        end_dt = _dt.strptime(last_seen, "%Y-%m-%d %H:%M:%S")
                    start_dt = _dt.strptime(session_start, "%Y-%m-%d %H:%M:%S")
                    minutes = max(int((end_dt - start_dt).total_seconds() / 60), 0)
                except Exception:
                    minutes = 0
                result[mid] = {"uptime_minutes": minutes, "uptime_hours": round(minutes / 60.0, 1)}
        return result

    # =========================================================================
    # v2.4.0: AGENT UPDATE LOG - Track push updates and auto-updates
    # =========================================================================

    def insert_agent_update_log(self, machine_id, hostname, from_version, to_version, status, message="", source="unknown"):
        """Insert a new agent update log entry."""
        with self.lock:
            self.conn.execute(
                """INSERT INTO agent_update_log (machine_id, hostname, from_version, to_version, status, message, source)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (machine_id, hostname, from_version, to_version, status, message, source)
            )
            self.conn.commit()

    def get_agent_update_logs(self, machine_id=None, limit=100):
        """Get agent update logs, optionally filtered by machine_id."""
        with self.lock:
            q = "SELECT * FROM agent_update_log WHERE 1=1"
            p = []
            if machine_id:
                q += " AND machine_id=?"
                p.append(machine_id)
            q += " ORDER BY id DESC LIMIT ?"
            p.append(limit)
            c = self.conn.execute(q, p)
            return [dict(row) for row in c.fetchall()]

    def get_server_agent_version(self):
        """Read the current server-side agent version from version.txt."""
        version_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "version.txt")
        try:
            with open(version_path, "r", encoding="utf-8") as f:
                return f.read().strip()
        except Exception:
            return "1.0.0"

    # =========================================================================
    # v2.5.22: ALERT COUNTS BY MACHINE - Single query for dashboard perf
    # =========================================================================

    def get_alert_counts_by_machine(self):
        """Return dict {machine_id: {threats:N, vulns:N, yara:N}} using COUNT+GROUP BY.
        Replaces 3 separate heavy API calls for the network graph."""
        with self.lock:
            result = {}
            # Threat alerts
            c = self.conn.execute(
                "SELECT machine_id, COUNT(*) as cnt FROM threat_alerts WHERE severity='CRITICAL' GROUP BY machine_id"
            )
            for row in c.fetchall():
                d = dict(row)
                result.setdefault(d["machine_id"], {})["threats"] = d["cnt"]
            # Vuln alerts
            c = self.conn.execute(
                "SELECT machine_id, COUNT(*) as cnt FROM vuln_alerts WHERE severity='CRITICAL' GROUP BY machine_id"
            )
            for row in c.fetchall():
                d = dict(row)
                result.setdefault(d["machine_id"], {})["vulns"] = d["cnt"]
            # YARA alerts
            c = self.conn.execute(
                "SELECT machine_id, COUNT(*) as cnt FROM yara_alerts GROUP BY machine_id"
            )
            for row in c.fetchall():
                d = dict(row)
                result.setdefault(d["machine_id"], {})["yara"] = d["cnt"]
            # Fill defaults
            for mid in result:
                result[mid].setdefault("threats", 0)
                result[mid].setdefault("vulns", 0)
                result[mid].setdefault("yara", 0)
            return result

    # =========================================================================
    # v2.6.2: SYSMON EVENTS - SysmonCollector events from agent
    # =========================================================================

    def insert_sysmon_event(self, data):
        """Insert a Sysmon event from the agent's SysmonCollector."""
        with self.lock:
            self.conn.execute("""INSERT INTO sysmon_events (
                machine_id, hostname, event_type, sysmon_event_id,
                process_name, process_path, command_line, pid,
                parent_process, parent_path, parent_command_line, parent_pid,
                user, severity, description,
                src_ip, src_port, dst_ip, dst_port, protocol,
                registry_key, registry_value, dns_query,
                file_path, file_name,
                target_process, target_path, target_pid,
                suspicion_reason,
                credential_dumping, persistence_detected,
                suspicious_parent, suspicious_dll, suspicious_file,
                hashes, integrity_level, signed,
                injection_type, granted_access,
                dns_status, dns_results,
                timestamp, raw_data
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
                data.get("machine_id", ""),
                data.get("hostname", ""),
                data.get("type", ""),
                data.get("sysmon_event_id", 0),
                data.get("process_name", ""),
                data.get("process_path", ""),
                data.get("command_line", ""),
                str(data.get("pid", "")),
                data.get("parent_process", ""),
                data.get("parent_path", ""),
                data.get("parent_command_line", ""),
                str(data.get("parent_pid", "")),
                data.get("user", ""),
                data.get("severity", "INFO"),
                data.get("description", data.get("suspicion_reason", "")),
                data.get("src_ip", ""),
                str(data.get("src_port", "")),
                data.get("dst_ip", ""),
                str(data.get("dst_port", "")),
                data.get("protocol", ""),
                data.get("registry_key", ""),
                data.get("registry_value", ""),
                data.get("dns_query", ""),
                data.get("file_path", ""),
                data.get("file_name", ""),
                data.get("target_process", ""),
                data.get("target_path", ""),
                str(data.get("target_pid", "")),
                data.get("suspicion_reason", ""),
                1 if data.get("credential_dumping") else 0,
                1 if data.get("persistence_detected") else 0,
                1 if data.get("suspicious_parent") else 0,
                1 if data.get("suspicious_dll") else 0,
                1 if data.get("suspicious_file") else 0,
                data.get("hashes", ""),
                data.get("integrity_level", ""),
                data.get("signed", ""),
                data.get("injection_type", ""),
                data.get("granted_access", ""),
                data.get("dns_status", ""),
                data.get("dns_results", ""),
                data.get("timestamp", ""),
                json.dumps(data, ensure_ascii=False, default=str),
            ))
            self.conn.commit()

    def get_sysmon_events(self, machine_id=None, limit=200, since_hours=None, event_type=None):
        """Get Sysmon events for display in the Sysmon dashboard tab."""
        with self.lock:
            q = "SELECT * FROM sysmon_events WHERE 1=1"
            p = []
            if machine_id:
                q += " AND machine_id=?"
                p.append(machine_id)
            if since_hours:
                q += " AND received_at >= datetime('now', ?)"
                p.append(f'-{since_hours} hours')
            if event_type:
                q += " AND event_type=?"
                p.append(event_type)
            q += " ORDER BY id DESC LIMIT ?"
            p.append(limit)
            c = self.conn.execute(q, p)
            return [dict(row) for row in c.fetchall()]

    # =========================================================================
    # v3.2: DATA RETENTION & CLEANUP
    # =========================================================================

    def cleanup_old_data(self, retention_days=60, types=None, keep_threats=True):
        """
        Delete data older than retention_days from specified tables.
        
        Args:
            retention_days: Number of days to retain (default 60)
            types: List of table types to clean (default all)
                   Options: events, fim_events, network_traffic, sysmon_events,
                           heartbeats, syslog, network_inspection, yara_alerts,
                           sca_events, agentless_events, response_results, audit_log
            keep_threats: If True, don't delete threat_alerts and vuln_alerts
        
        Returns:
            dict: {table_name: deleted_count} for each table
        """
        if types is None:
            types = ["events", "fim_events", "network_traffic", "sysmon_events",
                     "heartbeats", "syslog", "network_inspection", "yara_alerts",
                     "sca_events", "agentless_events", "response_results", "audit_log"]
        
        # Tables with time column named 'time'
        time_tables = {"events": "time", "fim_events": "time"}
        # Tables with 'timestamp' column
        ts_tables = {"network_traffic", "sysmon_events", "heartbeats", "syslog",
                     "network_inspection", "yara_alerts", "sca_events",
                     "agentless_events", "response_results", "audit_log"}
        
        deleted = {}
        
        with self.lock:
            for table in types:
                try:
                    if table in time_tables:
                        col = time_tables[table]
                        where_clause = f"{col} < datetime('now', ?)"
                    elif table in ts_tables:
                        where_clause = f"timestamp < datetime('now', ?)"
                    else:
                        continue
                    
                    # COUNT before DELETE (cursor.rowcount is -1 in Python sqlite3)
                    cnt_cursor = self.conn.execute(
                        f"SELECT COUNT(*) FROM {table} WHERE {where_clause}",
                        (f'-{retention_days} days',)
                    )
                    deleted[table] = cnt_cursor.fetchone()[0]
                    if deleted[table] > 0:
                        self.conn.execute(
                            f"DELETE FROM {table} WHERE {where_clause}",
                            (f'-{retention_days} days',)
                        )
                except Exception as e:
                    print(f"[-] Cleanup error on {table}: {e}")
                    deleted[table] = 0
            
            # Always keep threat/vuln alerts regardless of retention (security audit)
            if not keep_threats and "threat_alerts" in types:
                try:
                    cnt_c = self.conn.execute(
                        "SELECT COUNT(*) FROM threat_alerts WHERE timestamp < datetime('now', ?)",
                        (f'-{retention_days} days',))
                    deleted["threat_alerts"] = cnt_c.fetchone()[0]
                    if deleted["threat_alerts"] > 0:
                        self.conn.execute("DELETE FROM threat_alerts WHERE timestamp < datetime('now', ?)",
                                          (f'-{retention_days} days',))
                except:
                    deleted["threat_alerts"] = 0
            
            if not keep_threats and "vuln_alerts" in types:
                try:
                    cnt_c = self.conn.execute(
                        "SELECT COUNT(*) FROM vuln_alerts WHERE timestamp < datetime('now', ?)",
                        (f'-{retention_days} days',))
                    deleted["vuln_alerts"] = cnt_c.fetchone()[0]
                    if deleted["vuln_alerts"] > 0:
                        self.conn.execute("DELETE FROM vuln_alerts WHERE timestamp < datetime('now', ?)",
                                          (f'-{retention_days} days',))
                except:
                    deleted["vuln_alerts"] = 0
            
            self.conn.commit()
            self._summary_cache["ts"] = 0
            return deleted

    def apply_retention_policy(self, retention_days=60):
        """Automatically clean old data (called by retention loop)."""
        try:
            deleted = self.cleanup_old_data(retention_days=retention_days, keep_threats=True)
            total = sum(deleted.values())
            if total > 0:
                print(f"[*] Retention: Deleted {total} old records (> {retention_days} days)")
                # Log to audit
                self.insert_audit_log("system", "retention_cleanup",
                               f"Deleted {total} records older than {retention_days} days: "
                               + ", ".join(f"{k}={v}" for k, v in deleted.items() if v > 0))
                # Vacuum after significant deletions
                if total > 10000:
                    self.vacuum()
            return deleted
        except Exception as e:
            print(f"[-] Retention policy failed: {e}")
            return {}

    def vacuum(self):
        """Reclaim disk space after large deletes (SQLite VACUUM)."""
        try:
            with self.lock:
                self.conn.execute("VACUUM")
                print("[*] Database VACUUM completed (disk space reclaimed)")
        except Exception as e:
            print(f"[-] VACUUM failed: {e}")

    def get_data_summary(self):
        """Get summary of data sizes for display in cleanup UI. Cached 5 min."""
        CACHE_TTL = 300
        now = time.time()
        if self._summary_cache["data"] is not None and (now - self._summary_cache["ts"]) < CACHE_TTL:
            return self._summary_cache["data"]

        summary = {}
        tables = {
            "events": "events", "fim_events": "fim_events",
            "network_traffic": "network_traffic", "sysmon_events": "sysmon_events",
            "heartbeats": "heartbeats", "syslog": "syslog",
            "yara_alerts": "yara_alerts", "sca_events": "sca_events",
            "agentless_events": "agentless_events",
            "threat_alerts": "threat_alerts", "vuln_alerts": "vuln_alerts",
        }
        with self.lock:
            for label, table in tables.items():
                try:
                    c = self.conn.execute(f"SELECT COUNT(*) as cnt, MIN(timestamp) as oldest, MAX(timestamp) as newest FROM {table}")
                    row = c.fetchone()
                    if row and row[0]:
                        d = dict(row)
                        summary[label] = {
                            "count": d.get("cnt", 0),
                            "oldest": d.get("oldest", ""),
                            "newest": d.get("newest", ""),
                        }
                except:
                    summary[label] = {"count": 0, "oldest": "", "newest": ""}

        self._summary_cache = {"data": summary, "ts": now}
        return summary

    # =========================================================================
    # v3.5.8 PERFORMANCE: Batch INSERT methods (P1 - 1 transaction per batch)
    # =========================================================================

    def batch_insert_events(self, events):
        """Batch insert events in a single transaction. 50-100x faster than per-row commit."""
        if not events:
            return
        with self.write_lock:
            c = self.conn.cursor()
            c.execute("BEGIN IMMEDIATE")
            for e in events:
                c.execute(
                    "INSERT INTO events (machine_id,hostname,type,subtype,event_id,"
                    "event_type,source,computer,user,category,time,description,raw_data) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (e.get("machine_id",""), e.get("hostname",""), e.get("type",""),
                     e.get("subtype",""), str(e.get("event_id","")), e.get("event_type",""),
                     e.get("source",""), e.get("computer",""), e.get("user",""),
                     str(e.get("category","")), e.get("time",""), e.get("description",""),
                     e.get("raw_data","")))
            self.conn.commit()

    def batch_insert_sysmon_events(self, events):
        """Batch insert sysmon events in a single transaction."""
        if not events:
            return
        with self.write_lock:
            c = self.conn.cursor()
            c.execute("BEGIN IMMEDIATE")
            for e in events:
                c.execute("""INSERT INTO sysmon_events (
                    machine_id, hostname, event_type, sysmon_event_id,
                    process_name, process_path, command_line, pid,
                    parent_process, parent_path, parent_command_line, parent_pid,
                    user, severity, description,
                    src_ip, src_port, dst_ip, dst_port, protocol,
                    registry_key, registry_value, dns_query,
                    file_path, file_name,
                    target_process, target_path, target_pid,
                    suspicion_reason,
                    credential_dumping, persistence_detected,
                    suspicious_parent, suspicious_dll, suspicious_file,
                    hashes, integrity_level, signed,
                    injection_type, granted_access,
                    dns_status, dns_results,
                    timestamp, raw_data
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
                    e.get("machine_id", ""), e.get("hostname", ""), e.get("type", ""),
                    e.get("sysmon_event_id", 0), e.get("process_name", ""),
                    e.get("process_path", ""), e.get("command_line", ""),
                    str(e.get("pid", "")), e.get("parent_process", ""),
                    e.get("parent_path", ""), e.get("parent_command_line", ""),
                    str(e.get("parent_pid", "")), e.get("user", ""),
                    e.get("severity", "INFO"), e.get("description", e.get("suspicion_reason", "")),
                    e.get("src_ip", ""), str(e.get("src_port", "")),
                    e.get("dst_ip", ""), str(e.get("dst_port", "")),
                    e.get("protocol", ""), e.get("registry_key", ""),
                    e.get("registry_value", ""), e.get("dns_query", ""),
                    e.get("file_path", ""), e.get("file_name", ""),
                    e.get("target_process", ""), e.get("target_path", ""),
                    str(e.get("target_pid", "")), e.get("suspicion_reason", ""),
                    1 if e.get("credential_dumping") else 0,
                    1 if e.get("persistence_detected") else 0,
                    1 if e.get("suspicious_parent") else 0,
                    1 if e.get("suspicious_dll") else 0,
                    1 if e.get("suspicious_file") else 0,
                    e.get("hashes", ""), e.get("integrity_level", ""),
                    e.get("signed", ""), e.get("injection_type", ""),
                    e.get("granted_access", ""), e.get("dns_status", ""),
                    e.get("dns_results", ""), e.get("timestamp", ""),
                    json.dumps(e, ensure_ascii=False, default=str),
                ))
            self.conn.commit()

    def batch_insert_network_traffic(self, events):
        """Batch insert network traffic in a single transaction."""
        if not events:
            return
        with self.write_lock:
            c = self.conn.cursor()
            c.execute("BEGIN IMMEDIATE")
            for e in events:
                c.execute(
                    "INSERT INTO network_traffic (machine_id,hostname,src_ip,dst_ip,src_port,dst_port,"
                    "protocol,size,flags,state,timestamp,raw_data,src_mac,dst_mac,ip_ttl,ip_proto,"
                    "tcp_flags,payload_hex,payload_size,protocol_app,dns_query,http_host,payload_dump) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (e.get("machine_id",""), e.get("hostname",""),
                     e.get("src_ip",""), e.get("dst_ip",""),
                     e.get("src_port",0), e.get("dst_port",0),
                     e.get("protocol",""), e.get("size",0),
                     e.get("flags",""), e.get("state",""),
                     e.get("timestamp",""), e.get("raw_data",""),
                     e.get("src_mac",""), e.get("dst_mac",""),
                     e.get("ip_ttl",0), e.get("ip_proto",0),
                     e.get("tcp_flags",""), e.get("payload_hex",""),
                     e.get("payload_size",0), e.get("protocol_app",""),
                     e.get("dns_query",""), e.get("http_host",""),
                     e.get("payload_dump","")))
            self.conn.commit()

    def batch_insert_fim_events(self, events):
        """Batch insert FIM events in a single transaction."""
        if not events:
            return
        with self.write_lock:
            c = self.conn.cursor()
            c.execute("BEGIN IMMEDIATE")
            for e in events:
                c.execute(
                    "INSERT INTO fim_events (machine_id,hostname,action,path,time) "
                    "VALUES (?,?,?,?,?)",
                    (e.get("machine_id",""), e.get("hostname",""),
                     e.get("action",""), e.get("path",""), e.get("time","")))
            self.conn.commit()

    # =========================================================================
    # v4.4: Asset Management (Tai san) - SQLite implementation
    # =========================================================================

    def _compute_asset_id(self, raw_string):
        import hashlib
        return hashlib.md5(raw_string.encode("utf-8")).hexdigest()

    def _compute_hardware_hash(self, config_data):
        import hashlib
        fields = json.dumps({
            "mb": config_data.get("motherboard", {}),
            "cpu": config_data.get("cpu", {}),
            "ram": config_data.get("ram", {}),
            "disks": config_data.get("disks", []),
            "gpu": config_data.get("gpu", []),
        }, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(fields.encode()).hexdigest()

    def _compute_monitor_hash(self, mon):
        import hashlib
        s = f"{mon.get('manufacturer','')}|{mon.get('name','')}|{mon.get('resolution','')}"
        return hashlib.sha256(s.encode()).hexdigest()

    def insert_machine_config(self, machine_id, config_data, user_info=None):
        if user_info is None:
            user_info = {}
        import hashlib
        hostname = config_data.get("hostname", "")
        mb = config_data.get("motherboard", {})
        mb_serial = mb.get("serial", "").strip()
        if not mb_serial:
            mb_serial = f"{machine_id}_{hostname}"
        computer_asset_id = self._compute_asset_id(mb_serial)
        hardware_hash = self._compute_hardware_hash(config_data)
        os_info = config_data.get("os", {})
        cpu = config_data.get("cpu", {})
        ram = config_data.get("ram", {})
        bios = config_data.get("bios", {})
        changes = []

        with self.write_lock:
            c = self.conn.cursor()
            try:
                c.execute("""CREATE TABLE IF NOT EXISTS assets_computers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, asset_id TEXT UNIQUE,
                    machine_id TEXT, hostname TEXT, display_id TEXT DEFAULT '',
                    user_name TEXT, employee_id TEXT, email TEXT,
                    os_name TEXT, os_version TEXT,
                    motherboard_manufacturer TEXT, motherboard_product TEXT, motherboard_serial TEXT,
                    bios_manufacturer TEXT, bios_version TEXT,
                    cpu_name TEXT, cpu_cores INTEGER, cpu_max_clock_mhz INTEGER,
                    ram_total_gb REAL, ram_sticks_json TEXT DEFAULT '[]',
                    disks_json TEXT DEFAULT '[]', gpu_json TEXT DEFAULT '[]',
                    monitors_json TEXT DEFAULT '[]', installed_software_json TEXT DEFAULT '[]',
                    printer_json TEXT DEFAULT '[]', hardware_hash TEXT,
                    last_seen TIMESTAMP, first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, is_online INTEGER DEFAULT 0
                )""")
                c.execute("""CREATE TABLE IF NOT EXISTS assets_monitors (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, asset_id TEXT UNIQUE,
                    display_id TEXT DEFAULT '', name TEXT, manufacturer TEXT,
                    model_type TEXT, resolution TEXT, monitor_hash TEXT,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )""")
                c.execute("""CREATE TABLE IF NOT EXISTS assets_relations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    computer_asset_id TEXT, monitor_asset_id TEXT,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(computer_asset_id, monitor_asset_id)
                )""")
                c.execute("""CREATE TABLE IF NOT EXISTS assets_change_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, asset_id TEXT,
                    asset_type TEXT, change_type TEXT,
                    old_hash TEXT DEFAULT '', new_hash TEXT DEFAULT '',
                    details TEXT DEFAULT '{}', is_resolved INTEGER DEFAULT 0,
                    resolved_by TEXT DEFAULT '', resolved_at TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )""")

                # Check existing
                c.execute("SELECT asset_id, hardware_hash, display_id FROM assets_computers WHERE asset_id=?", (computer_asset_id,))
                existing = c.fetchone()
                if not existing and mb_serial and mb_serial != "0":
                    c.execute("SELECT asset_id, hardware_hash, display_id FROM assets_computers WHERE motherboard_serial=? ORDER BY id LIMIT 1", (mb_serial,))
                    existing = c.fetchone()
                    if existing:
                        computer_asset_id = existing[0]

                existing_display_id = existing[2] if existing else ""
                if existing:
                    old_hash = existing[1]
                    if old_hash and old_hash != hardware_hash:
                        detail = {"computer": hostname or machine_id, "old_hash": old_hash[:16], "new_hash": hardware_hash[:16]}
                        c.execute("INSERT INTO assets_change_log (asset_id, asset_type, change_type, old_hash, new_hash, details) VALUES (?,'computer','hardware_changed',?,?,?)",
                                  (computer_asset_id, old_hash, hardware_hash, json.dumps(detail, ensure_ascii=False)))
                        changes.append({"type": "hardware_changed", "asset_id": computer_asset_id, "asset_type": "computer", "details": detail})

                if not existing_display_id:
                    import uuid
                    existing_display_id = f"PC-{uuid.uuid4().hex[:8].upper()}"
                    c.execute("UPDATE assets_computers SET display_id=? WHERE asset_id=?", (existing_display_id, computer_asset_id))

                c.execute("""INSERT OR REPLACE INTO assets_computers (asset_id, machine_id, hostname, display_id,
                    user_name, employee_id, email, os_name, os_version,
                    motherboard_manufacturer, motherboard_product, motherboard_serial,
                    bios_manufacturer, bios_version, cpu_name, cpu_cores, cpu_max_clock_mhz,
                    ram_total_gb, ram_sticks_json, disks_json, gpu_json, monitors_json,
                    installed_software_json, printer_json, hardware_hash, last_seen, updated_at, is_online)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,1)""",
                    (computer_asset_id, machine_id, hostname, existing_display_id,
                     user_info.get("user_name","")[:128], user_info.get("employee_id","")[:64], user_info.get("email","")[:128],
                     os_info.get("name","")[:64], os_info.get("version","")[:64],
                     mb.get("manufacturer","")[:128], mb.get("product","")[:128], mb_serial[:128],
                     bios.get("manufacturer","")[:128], bios.get("version","")[:64],
                     cpu.get("name","")[:256], int(cpu.get("cores",0) or 0), int(cpu.get("max_clock_speed_mhz",0) or 0),
                     float(ram.get("total_gb",0) or 0), json.dumps(ram.get("sticks",[]), ensure_ascii=False),
                     json.dumps(config_data.get("disks",[]), ensure_ascii=False),
                     json.dumps(config_data.get("gpu",[]), ensure_ascii=False),
                     json.dumps(config_data.get("monitors",[]), ensure_ascii=False),
                     json.dumps(config_data.get("installed_software",[]), ensure_ascii=False),
                     json.dumps(config_data.get("printers",[]), ensure_ascii=False),
                     hardware_hash))

                # === MONITOR ASSETS & RELATIONS ===
                monitors = config_data.get("monitors", [])
                current_monitor_ids = set()
                for mon in monitors:
                    mfr = (mon.get("manufacturer") or "").strip()
                    name = (mon.get("name") or "").strip()
                    res = (mon.get("resolution") or "").strip()
                    if not name and not mfr:
                        continue
                    monitor_asset_id = self._compute_asset_id(f"{mfr}|{name}|{res}")
                    monitor_hash = self._compute_monitor_hash(mon)
                    model_type = (mon.get("type") or "Monitor")[:64]
                    current_monitor_ids.add(monitor_asset_id)

                    c.execute("SELECT asset_id, display_id FROM assets_monitors WHERE asset_id=?", (monitor_asset_id,))
                    existing_mon = c.fetchone()
                    if not existing_mon:
                        import uuid as _uuid
                        mon_display_id = f"MN-{_uuid.uuid4().hex[:8].upper()}"
                        c.execute("""INSERT OR IGNORE INTO assets_monitors (asset_id, display_id, name, manufacturer, model_type, resolution, monitor_hash)
                                     VALUES (?,?,?,?,?,?,?)""",
                                  (monitor_asset_id, mon_display_id, name[:256], mfr[:128], model_type, res[:32], monitor_hash))

                    c.execute("SELECT computer_asset_id FROM assets_relations WHERE monitor_asset_id=? ORDER BY last_seen DESC LIMIT 1", (monitor_asset_id,))
                    existing_rel = c.fetchone()
                    if existing_rel:
                        prev_computer = existing_rel[0]
                        if prev_computer and prev_computer != computer_asset_id:
                            c.execute("SELECT hostname FROM assets_computers WHERE asset_id=?", (prev_computer,))
                            old_pc = c.fetchone()
                            old_name = old_pc[0] if old_pc else prev_computer
                            detail = {
                                "monitor": f"{mfr} {name}" if mfr else name,
                                "from_computer": old_name,
                                "to_computer": hostname or machine_id,
                            }
                            c.execute("INSERT INTO assets_change_log (asset_id, asset_type, change_type, details) VALUES (?,'monitor','monitor_reassigned',?)",
                                      (monitor_asset_id, json.dumps(detail, ensure_ascii=False)))
                            changes.append({"type": "monitor_reassigned", "asset_id": monitor_asset_id, "asset_type": "monitor", "details": detail})

                    c.execute("SELECT id FROM assets_relations WHERE computer_asset_id=? AND monitor_asset_id=?", (computer_asset_id, monitor_asset_id))
                    rel_row = c.fetchone()
                    if rel_row:
                        c.execute("UPDATE assets_relations SET last_seen=CURRENT_TIMESTAMP WHERE id=?", (rel_row[0],))
                    else:
                        c.execute("INSERT INTO assets_relations (computer_asset_id, monitor_asset_id, last_seen) VALUES (?,?,CURRENT_TIMESTAMP)",
                                  (computer_asset_id, monitor_asset_id))

                # Detect monitors that were disconnected from this computer
                if current_monitor_ids:
                    c.execute("SELECT monitor_asset_id FROM assets_relations WHERE computer_asset_id=?", (computer_asset_id,))
                    old_monitor_ids = {r[0] for r in c.fetchall()}
                    for missing_id in (old_monitor_ids - current_monitor_ids):
                        c.execute("SELECT name, manufacturer FROM assets_monitors WHERE asset_id=?", (missing_id,))
                        mon_info = c.fetchone()
                        if mon_info:
                            mfr = mon_info[1] or ""
                            mname = mon_info[0] or ""
                            detail = {
                                "computer": hostname or machine_id,
                                "monitor": f"{mfr} {mname}" if mfr else mname,
                                "action": "disconnected",
                            }
                            c.execute("INSERT INTO assets_change_log (asset_id, asset_type, change_type, details) VALUES (?,'computer','monitor_disconnected',?)",
                                      (computer_asset_id, json.dumps(detail, ensure_ascii=False)))
                            changes.append({"type": "monitor_disconnected", "asset_id": computer_asset_id, "asset_type": "computer", "details": detail})


                self.conn.commit()
            except Exception as e:
                print(f"[-] SQLite insert_machine_config error: {e}")
        return {"computer_asset_id": computer_asset_id, "changes": changes}

    def get_asset_computers(self, search=None, limit=200):
        with self.read_lock:
            c = self.conn.cursor()
            try:
                c.execute("SELECT 1 FROM assets_computers LIMIT 1")
            except sqlite3.OperationalError:
                return []
            q = "SELECT * FROM assets_computers WHERE 1=1"
            params = []
            if search:
                q += " AND (hostname LIKE ? OR user_name LIKE ? OR employee_id LIKE ? OR cpu_name LIKE ? OR motherboard_serial LIKE ? OR display_id LIKE ? OR email LIKE ?)"
                s = f"%{search}%"
                params.extend([s]*7)
            q += " ORDER BY last_seen DESC LIMIT ?"
            params.append(limit)
            c.execute(q, params)
            rows = [dict(r) for r in c.fetchall()]
            for r in rows:
                for field in ["ram_sticks_json","disks_json","gpu_json","monitors_json","installed_software_json","printer_json"]:
                    val = r.get(field)
                    if isinstance(val, str):
                        try: r[field] = json.loads(val)
                        except: r[field] = []
            return rows

    def get_asset_monitors(self, search=None, limit=200):
        with self.read_lock:
            c = self.conn.cursor()
            try:
                c.execute("SELECT 1 FROM assets_monitors LIMIT 1")
            except sqlite3.OperationalError:
                return []
            q = """SELECT m.*, r.computer_asset_id, c.hostname as computer_hostname, c.user_name as computer_user
                   FROM assets_monitors m
                   LEFT JOIN assets_relations r ON m.asset_id = r.monitor_asset_id
                   LEFT JOIN assets_computers c ON r.computer_asset_id = c.asset_id
                   WHERE 1=1"""
            params = []
            if search:
                q += " AND (m.name LIKE ? OR m.manufacturer LIKE ?)"
                s = f"%{search}%"
                params.extend([s, s])
            q += " ORDER BY m.updated_at DESC LIMIT ?"
            params.append(limit)
            c.execute(q, params)
            return [dict(r) for r in c.fetchall()]

    def get_asset_change_log(self, limit=100, unresolved_only=False):
        with self.read_lock:
            c = self.conn.cursor()
            try:
                c.execute("SELECT 1 FROM assets_change_log LIMIT 1")
            except sqlite3.OperationalError:
                return []
            q = "SELECT * FROM assets_change_log WHERE 1=1"
            params = []
            if unresolved_only:
                q += " AND is_resolved=0"
            q += " ORDER BY created_at DESC LIMIT ?"
            params.append(limit)
            c.execute(q, params)
            rows = [dict(r) for r in c.fetchall()]
            for r in rows:
                val = r.get("details")
                if isinstance(val, str):
                    try: r["details"] = json.loads(val)
                    except: pass
            return rows

    def resolve_asset_change(self, change_id, resolved_by="admin"):
        with self.write_lock:
            c = self.conn.cursor()
            c.execute("UPDATE assets_change_log SET is_resolved=1, resolved_by=?, resolved_at=CURRENT_TIMESTAMP WHERE id=?", (resolved_by[:128], change_id))
            self.conn.commit()

    def close(self):
        self.conn.close()
