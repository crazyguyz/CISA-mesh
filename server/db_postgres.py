"""
PostgreSQL Database Adapter for GIAM-SAT Server v3.0.0
Full implementation for scalability to 1000+ agents with connection pooling.

Features:
  - psycopg2 ThreadedConnectionPool (min 10, max 50 connections)
  - TimescaleDB hypertable auto-creation for events/sysmon_events/network_traffic
  - Batch insert support (executemany) for high throughput
  - Identical interface to DatabaseManager for drop-in replacement
  - JSONB for raw_data (full query support)
  - Automatic reconnect on connection loss

Configuration via environment variables:
  GIAMSAT_PG_HOST=127.0.0.1
  GIAMSAT_PG_PORT=5432
  GIAMSAT_PG_DBNAME=giamsat
  GIAMSAT_PG_USER=giamsat
  GIAMSAT_PG_PASSWORD=giamsat
  GIAMSAT_PG_POOL_MIN=10
  GIAMSAT_PG_POOL_MAX=50
"""
import os
import threading
import json
import time
from datetime import datetime, timezone

try:
    import psycopg2
    import psycopg2.extras
    from psycopg2 import pool
    HAS_POSTGRES = True
except ImportError:
    HAS_POSTGRES = False

# Max seconds without a heartbeat before a machine's uptime session is
# considered ended (agent heartbeats every 120s; a longer gap means the
# machine went offline/rebooted).
_UPTIME_GAP_SECONDS = 600


def _dict_row(cursor, row):
    """Row factory returning dict (like sqlite3.Row)."""
    if row is None:
        return None
    cols = [desc[0] for desc in cursor.description]
    return dict(zip(cols, row))


class PGCompatRow(dict):
    """Dict-like row that supports index access (like sqlite3.Row)."""
    def __getitem__(self, key):
        if isinstance(key, int):
            return list(self.values())[key]
        return super().__getitem__(key)


class PGCompatCursor:
    """SQLite-compatible cursor wrapper for PostgreSQL.
    Translates `self.db.conn.execute(sql, params)` to `self.db._execute(sql, params)`.
    This eliminates the need to rewrite hundreds of lines in api_*, tcp_server.py, etc.
    """
    def __init__(self, db):
        self._db = db
        self._last_sql = ""
        self._last_params = None
        self._results = []
        self.rowcount = 0
        self.description = None

    def cursor(self):
        """Compatibility: some code calls conn.cursor() - return self as cursor."""
        return self

    def execute(self, sql, params=None):
        """Emulate sqlite3.Cursor.execute(). Converts ? placeholders to %s.
        v4.10 (HIGH-11): '?' is replaced only when it is a real placeholder -
        '?' inside single-quoted literals (e.g. jsonb '?' operator, text values)
        is preserved. Query errors are logged and re-raised instead of being
        silently swallowed into an empty result set.
        Auto-detects SELECT vs mutation to use correct fetch mode."""
        self._last_sql = sql
        self._last_params = params
        import re as _re
        # match '?' only when it is a real parameter placeholder: not inside a
        # single-quoted literal and not the jsonb '?' operator (followed by a
        # quoted value, e.g. `data ? 'key'`).
        _pg_ph = _re.compile(r"\?(?!\s*')(?=(?:[^']*'[^']*')*[^']*$)")
        pg_sql = _pg_ph.sub("%s", sql)
        sql_upper = pg_sql.strip().upper()
        is_select = sql_upper.startswith("SELECT") or sql_upper.startswith("WITH")
        try:
            if is_select:
                result = self._db._execute(pg_sql, params, fetchall=True)
                if result is not None and isinstance(result, list):
                    self._results = [PGCompatRow(r) for r in result]
                    self.rowcount = len(self._results)
                else:
                    self._results = []
                    self.rowcount = 0
            else:
                self.rowcount = self._db._execute(pg_sql, params) or 0
                self._results = []
        except Exception as e:
            self._results = []
            self.rowcount = 0
            print(f"[-] PG query failed: {e}\nSQL: {sql[:300]}")
            raise
        return self

    def fetchone(self):
        if self._results:
            return self._results[0]
        return None

    def fetchall(self):
        return self._results

    def commit(self):
        """No-op: _execute() already commits."""
        pass

    def __getitem__(self, key):
        """v4.11 (MED): index access returns the result row(s) like sqlite3 cursor.
        Previously this called self.values() which PGCompatCursor does not have
        (AttributeError / dead code)."""
        return self._results[key]


class PostgresDatabase:
    """PostgreSQL adapter with same interface as DatabaseManager."""

    def __init__(self, config=None):
        self.lock = threading.Lock()
        self.pool = None
        self._connected = False
        self.backend_type = "postgres"

        cfg = config or {}
        self.config = {
            "host": cfg.get("host") or os.environ.get("GIAMSAT_PG_HOST", "127.0.0.1"),
            "port": cfg.get("port") or int(os.environ.get("GIAMSAT_PG_PORT", "5432")),
            "dbname": cfg.get("dbname") or os.environ.get("GIAMSAT_PG_DBNAME", "giamsat"),
            "user": cfg.get("user") or os.environ.get("GIAMSAT_PG_USER", "giamsat"),
            # v4.10 (MED-18): no public default password - fail with a clear
            # connection error instead of silently using a known credential.
            "password": cfg.get("password") or os.environ.get("GIAMSAT_PG_PASSWORD", ""),
        }
        self.pool_min = int(os.environ.get("GIAMSAT_PG_POOL_MIN", "10"))
        self.pool_max = int(os.environ.get("GIAMSAT_PG_POOL_MAX", "50"))

        if HAS_POSTGRES:
            try:
                self.pool = pool.ThreadedConnectionPool(
                    self.pool_min, self.pool_max,
                    host=self.config["host"],
                    port=self.config["port"],
                    dbname=self.config["dbname"],
                    user=self.config["user"],
                    password=self.config["password"],
                    connect_timeout=10,
                )
                self._connected = True
                print(f"[*] PostgreSQL connected: {self.config['host']}:{self.config['port']}/{self.config['dbname']} (pool: {self.pool_min}-{self.pool_max})")
                self._init_db()
                self._init_timescaledb()
            except Exception as e:
                print(f"[-] PostgreSQL connection failed: {e}")
                self._connected = False
        else:
            print("[!] psycopg2 not installed. Run: pip install psycopg2-binary")
            print("[*] PostgreSQL unavailable, falling back to SQLite.")

    @property
    def conn(self):
        """Compatibility: return a PGCompatCursor to support .execute()/.commit()/.fetchall().
        All legacy SQLite code uses self.db.conn.execute(sql, params)."""
        if not self._connected:
            return None
        return PGCompatCursor(self)

    def _get_conn(self):
        """Get a connection from the pool."""
        if not self._connected or not self.pool:
            raise RuntimeError("PostgreSQL not connected")
        return self.pool.getconn()

    def _put_conn(self, conn):
        """Return a connection to the pool."""
        if self.pool and conn:
            try:
                conn.rollback()  # Clean any uncommitted state
                self.pool.putconn(conn)
            except Exception:
                pass

    def _execute(self, sql, params=None, fetch=False, fetchall=False):
        """Execute SQL with pool connection lifecycle."""
        conn = None
        try:
            conn = self._get_conn()
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(sql, params)
                if fetchall:
                    result = cur.fetchall()
                    result = [dict(r) for r in result]
                elif fetch:
                    row = cur.fetchone()
                    result = dict(row) if row else None
                else:
                    result = cur.rowcount
                conn.commit()
                return result
        except Exception as e:
            if conn:
                try:
                    conn.rollback()
                except Exception:
                    pass
            raise e
        finally:
            if conn:
                self._put_conn(conn)

    def _executemany(self, sql, params_list):
        """Batch execute with multiple parameter sets."""
        if not params_list:
            return
        conn = None
        try:
            conn = self._get_conn()
            with conn.cursor() as cur:
                psycopg2.extras.execute_batch(cur, sql, params_list, page_size=100)
                conn.commit()
        except Exception as e:
            if conn:
                try:
                    conn.rollback()
                except Exception:
                    pass
            raise e
        finally:
            if conn:
                self._put_conn(conn)

    def health_check(self):
        """Check if database is responsive."""
        try:
            if not self._connected:
                return False
            self._execute("SELECT 1", fetch=True)
            return True
        except Exception:
            return False

    # =========================================================================
    # DB Initialization
    # =========================================================================

    def _init_db(self):
        """Create all tables and indexes."""
        if not self._connected:
            return

        tables = {
            "machines": """CREATE TABLE IF NOT EXISTS machines (
                id SERIAL PRIMARY KEY, machine_id TEXT UNIQUE, hostname TEXT DEFAULT '',
                ip_address TEXT DEFAULT '', platform TEXT DEFAULT 'Windows', version TEXT DEFAULT '1.0.0',
                first_seen TIMESTAMP DEFAULT NOW(), last_seen TIMESTAMP DEFAULT NOW(),
                is_online INTEGER DEFAULT 1, notes TEXT DEFAULT ''
            )""",
            "events": """CREATE TABLE IF NOT EXISTS events (
                id SERIAL PRIMARY KEY, machine_id TEXT, hostname TEXT DEFAULT '',
                type TEXT DEFAULT '', subtype TEXT DEFAULT '', event_id TEXT DEFAULT '',
                event_type TEXT DEFAULT '', source TEXT DEFAULT '', computer TEXT DEFAULT '',
                "user" TEXT DEFAULT '', category TEXT DEFAULT '',
                time TEXT DEFAULT '', description TEXT DEFAULT '', raw_data JSONB DEFAULT '{}',
                received_at TIMESTAMPTZ DEFAULT NOW(),
                dedup_key TEXT
            )""",
            "fim_events": """CREATE TABLE IF NOT EXISTS fim_events (
                id SERIAL PRIMARY KEY, machine_id TEXT, hostname TEXT DEFAULT '',
                action TEXT, path TEXT, time TEXT, received_at TIMESTAMPTZ DEFAULT NOW()
            )""",
            "heartbeats": """CREATE TABLE IF NOT EXISTS heartbeats (
                id SERIAL PRIMARY KEY, machine_id TEXT, hostname TEXT DEFAULT '',
                timestamp TEXT, received_at TIMESTAMPTZ DEFAULT NOW()
            )""",
            "response_results": """CREATE TABLE IF NOT EXISTS response_results (
                id SERIAL PRIMARY KEY, machine_id TEXT, hostname TEXT DEFAULT '',
                exec_id TEXT, status TEXT, output TEXT, error TEXT,
                exit_code INTEGER, action TEXT, timestamp TEXT,
                received_at TIMESTAMPTZ DEFAULT NOW()
            )""",
            "syslog": """CREATE TABLE IF NOT EXISTS syslog (
                id SERIAL PRIMARY KEY, source_ip TEXT, hostname TEXT DEFAULT '',
                facility TEXT, severity TEXT, timestamp TEXT,
                message TEXT, raw_data JSONB DEFAULT '{}', received_at TIMESTAMPTZ DEFAULT NOW()
            )""",
            "commands": """CREATE TABLE IF NOT EXISTS commands (
                id SERIAL PRIMARY KEY, machine_id TEXT, action TEXT,
                command TEXT, exec_id TEXT UNIQUE, status TEXT DEFAULT 'pending',
                created_at TIMESTAMPTZ DEFAULT NOW(), executed_at TIMESTAMPTZ
            )""",
            "hardware_info": """CREATE TABLE IF NOT EXISTS hardware_info (
                id SERIAL PRIMARY KEY, machine_id TEXT UNIQUE, hostname TEXT DEFAULT '',
                data_json JSONB DEFAULT '{}', fingerprint TEXT, has_changed INTEGER DEFAULT 0,
                received_at TIMESTAMPTZ DEFAULT NOW()
            )""",
            "hardware_baseline": """CREATE TABLE IF NOT EXISTS hardware_baseline (
                id SERIAL PRIMARY KEY, machine_id TEXT UNIQUE, hostname TEXT DEFAULT '',
                data_json JSONB DEFAULT '{}', fingerprint TEXT, saved_at TIMESTAMPTZ DEFAULT NOW()
            )""",
            "network_traffic": """CREATE TABLE IF NOT EXISTS network_traffic (
                id SERIAL PRIMARY KEY, machine_id TEXT, hostname TEXT DEFAULT '',
                src_ip TEXT, dst_ip TEXT, src_port INTEGER, dst_port INTEGER,
                protocol TEXT, size INTEGER, flags TEXT, state TEXT,
                timestamp TEXT, raw_data JSONB DEFAULT '{}', received_at TIMESTAMPTZ DEFAULT NOW(),
                src_mac TEXT DEFAULT '', dst_mac TEXT DEFAULT '',
                ip_ttl INTEGER DEFAULT 0, ip_proto INTEGER DEFAULT 0,
                tcp_flags TEXT DEFAULT '', payload_hex TEXT DEFAULT '',
                payload_size INTEGER DEFAULT 0, protocol_app TEXT DEFAULT '',
                dns_query TEXT DEFAULT '', http_host TEXT DEFAULT '',
                payload_dump TEXT DEFAULT ''
            )""",
            "threat_alerts": """CREATE TABLE IF NOT EXISTS threat_alerts (
                id SERIAL PRIMARY KEY, machine_id TEXT, hostname TEXT DEFAULT '',
                rule_id TEXT, rule_name TEXT, description TEXT,
                severity TEXT, timestamp TEXT, raw_data JSONB DEFAULT '{}',
                source_ip TEXT DEFAULT '', received_at TIMESTAMPTZ DEFAULT NOW()
            )""",
            "vuln_alerts": """CREATE TABLE IF NOT EXISTS vuln_alerts (
                id SERIAL PRIMARY KEY, machine_id TEXT, hostname TEXT DEFAULT '',
                software TEXT, version TEXT, publisher TEXT, cve TEXT,
                severity TEXT, description TEXT, timestamp TEXT,
                received_at TIMESTAMPTZ DEFAULT NOW()
            )""",
            "network_inspection": """CREATE TABLE IF NOT EXISTS network_inspection (
                id SERIAL PRIMARY KEY, machine_id TEXT, hostname TEXT DEFAULT '',
                subtype TEXT, domain TEXT, dst_ip TEXT, dst_port INTEGER,
                src_ip TEXT, src_port INTEGER, protocol TEXT,
                query_type TEXT, avg_interval_sec REAL, sample_count INTEGER,
                timestamp TEXT, received_at TIMESTAMPTZ DEFAULT NOW()
            )""",
            "yara_alerts": """CREATE TABLE IF NOT EXISTS yara_alerts (
                id SERIAL PRIMARY KEY, machine_id TEXT, hostname TEXT DEFAULT '',
                rule_name TEXT, description TEXT, file TEXT,
                timestamp TEXT, received_at TIMESTAMPTZ DEFAULT NOW()
            )""",
            "sca_events": """CREATE TABLE IF NOT EXISTS sca_events (
                id SERIAL PRIMARY KEY, machine_id TEXT, hostname TEXT DEFAULT '',
                check_id TEXT, title TEXT, status TEXT, severity TEXT,
                description TEXT, remediation TEXT,
                timestamp TEXT, received_at TIMESTAMPTZ DEFAULT NOW()
            )""",
            "agentless_events": """CREATE TABLE IF NOT EXISTS agentless_events (
                id SERIAL PRIMARY KEY, device_name TEXT, ip TEXT, device_type TEXT,
                data_json JSONB DEFAULT '{}', timestamp TEXT, received_at TIMESTAMPTZ DEFAULT NOW()
            )""",
            "audit_log": """CREATE TABLE IF NOT EXISTS audit_log (
                id SERIAL PRIMARY KEY, username TEXT, action TEXT, details TEXT,
                ip_address TEXT, timestamp TIMESTAMPTZ DEFAULT NOW()
            )""",
            "agent_groups": """CREATE TABLE IF NOT EXISTS agent_groups (
                id SERIAL PRIMARY KEY, name TEXT UNIQUE, description TEXT DEFAULT '',
                config_json JSONB DEFAULT '{}',
                created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW()
            )""",
            "agent_group_members": """CREATE TABLE IF NOT EXISTS agent_group_members (
                id SERIAL PRIMARY KEY, group_id INTEGER REFERENCES agent_groups(id) ON DELETE CASCADE,
                machine_id TEXT UNIQUE
            )""",
            "fim_baseline": """CREATE TABLE IF NOT EXISTS fim_baseline (
                id SERIAL PRIMARY KEY, machine_id TEXT, path TEXT, file_hash TEXT,
                file_hash_old TEXT, file_size INTEGER, owner TEXT, permissions TEXT,
                last_modified TEXT, first_seen TIMESTAMPTZ DEFAULT NOW(),
                last_checked TIMESTAMPTZ DEFAULT NOW(), change_count INTEGER DEFAULT 0,
                UNIQUE(machine_id, path)
            )""",
            "machine_users": """CREATE TABLE IF NOT EXISTS machine_users (
                machine_id TEXT UNIQUE, hostname TEXT DEFAULT '',
                user_name TEXT DEFAULT '', employee_id TEXT DEFAULT '',
                email TEXT DEFAULT '', branch TEXT DEFAULT '',
                updated_at TIMESTAMPTZ DEFAULT NOW()
            )""",
            "machine_uptime": """CREATE TABLE IF NOT EXISTS machine_uptime (
                machine_id TEXT, date TEXT, session_start TIMESTAMPTZ,
                last_seen TIMESTAMPTZ, uptime_minutes INTEGER DEFAULT 0,
                alert_sent_24h INTEGER DEFAULT 0, UNIQUE(machine_id, date, session_start)
            )""",
            "agent_update_log": """CREATE TABLE IF NOT EXISTS agent_update_log (
                id SERIAL PRIMARY KEY, machine_id TEXT, hostname TEXT DEFAULT '',
                from_version TEXT DEFAULT '', to_version TEXT DEFAULT '',
                status TEXT DEFAULT '', message TEXT DEFAULT '', source TEXT DEFAULT '',
                timestamp TIMESTAMPTZ DEFAULT NOW()
            )""",
            "sysmon_events": """CREATE TABLE IF NOT EXISTS sysmon_events (
                id SERIAL PRIMARY KEY, machine_id TEXT, hostname TEXT DEFAULT '',
                event_type TEXT DEFAULT '', sysmon_event_id INTEGER DEFAULT 0,
                process_name TEXT DEFAULT '', process_path TEXT DEFAULT '',
                command_line TEXT DEFAULT '', pid TEXT DEFAULT '',
                parent_process TEXT DEFAULT '', parent_path TEXT DEFAULT '',
                parent_command_line TEXT DEFAULT '', parent_pid TEXT DEFAULT '',
                "user" TEXT DEFAULT '', severity TEXT DEFAULT 'INFO',
                description TEXT DEFAULT '', src_ip TEXT DEFAULT '',
                src_port TEXT DEFAULT '', dst_ip TEXT DEFAULT '', dst_port TEXT DEFAULT '',
                protocol TEXT DEFAULT '', registry_key TEXT DEFAULT '',
                registry_value TEXT DEFAULT '', dns_query TEXT DEFAULT '',
                file_path TEXT DEFAULT '', file_name TEXT DEFAULT '',
                target_process TEXT DEFAULT '', target_path TEXT DEFAULT '',
                target_pid TEXT DEFAULT '', suspicion_reason TEXT DEFAULT '',
                credential_dumping INTEGER DEFAULT 0, persistence_detected INTEGER DEFAULT 0,
                suspicious_parent INTEGER DEFAULT 0, suspicious_dll INTEGER DEFAULT 0,
                suspicious_file INTEGER DEFAULT 0, hashes TEXT DEFAULT '',
                integrity_level TEXT DEFAULT '', signed TEXT DEFAULT '',
                injection_type TEXT DEFAULT '', granted_access TEXT DEFAULT '',
                dns_status TEXT DEFAULT '', dns_results TEXT DEFAULT '',
                timestamp TEXT, raw_data JSONB DEFAULT '{}',
                received_at TIMESTAMPTZ DEFAULT NOW()
            )""",
            "messages": """CREATE TABLE IF NOT EXISTS messages (
                id SERIAL PRIMARY KEY, msg_id TEXT UNIQUE, machine_id TEXT DEFAULT '',
                sender TEXT DEFAULT '', title TEXT DEFAULT '', message TEXT DEFAULT '',
                reply TEXT DEFAULT '', require_reply INTEGER DEFAULT 1,
                status TEXT DEFAULT 'sent', direction TEXT DEFAULT 'server',
                created_at TEXT DEFAULT '', replied_at TEXT DEFAULT '',
                msg_type TEXT DEFAULT 'chat', category TEXT DEFAULT '',
                ultraview_id TEXT DEFAULT '', ultraview_password TEXT DEFAULT ''
            )""",
            "custom_dashboards": """CREATE TABLE IF NOT EXISTS custom_dashboards (
                id SERIAL PRIMARY KEY, name TEXT NOT NULL,
                description TEXT DEFAULT '', layout_json JSONB DEFAULT '[]',
                widgets_json JSONB DEFAULT '[]', created_by TEXT DEFAULT 'admin',
                created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW()
            )""",

            "alert_suppression": """CREATE TABLE IF NOT EXISTS alert_suppression (
                id SERIAL PRIMARY KEY, rule_id TEXT NOT NULL, machine_id TEXT DEFAULT NULL,
                field_path TEXT DEFAULT NULL, field_hash TEXT DEFAULT NULL,
                reason TEXT DEFAULT '', created_by TEXT DEFAULT 'admin',
                created_at TIMESTAMPTZ DEFAULT NOW(), expires_at TIMESTAMPTZ DEFAULT NULL
            )""",
            "group_policies": """CREATE TABLE IF NOT EXISTS group_policies (
                id SERIAL PRIMARY KEY, group_id INTEGER NOT NULL,
                policy_type TEXT NOT NULL, policy_name TEXT DEFAULT '',
                config_json JSONB DEFAULT '{}', enabled INTEGER DEFAULT 1,
                apply_status TEXT DEFAULT 'pending', status_message TEXT DEFAULT '',
                created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW(),
                deleted INTEGER DEFAULT 0
            )""",
            "policy_apply_status": """CREATE TABLE IF NOT EXISTS policy_apply_status (
                id SERIAL PRIMARY KEY,
                policy_id INTEGER NOT NULL,
                machine_id TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                message TEXT DEFAULT '',
                updated_at TIMESTAMPTZ DEFAULT NOW(),
                UNIQUE(policy_id, machine_id)
            )""",
            "assets_computers": """CREATE TABLE IF NOT EXISTS assets_computers (
                id SERIAL PRIMARY KEY, asset_id VARCHAR(32) UNIQUE NOT NULL,
                machine_id VARCHAR(64), hostname VARCHAR(128) DEFAULT '',
                user_name VARCHAR(128) DEFAULT '', employee_id VARCHAR(64) DEFAULT '',
                email VARCHAR(128) DEFAULT '', os_name VARCHAR(64) DEFAULT '',
                os_version VARCHAR(64) DEFAULT '',
                motherboard_manufacturer VARCHAR(128) DEFAULT '',
                motherboard_product VARCHAR(128) DEFAULT '',
                motherboard_serial VARCHAR(128) DEFAULT '',
                bios_manufacturer VARCHAR(128) DEFAULT '',
                bios_version VARCHAR(64) DEFAULT '',
                cpu_name VARCHAR(256) DEFAULT '', cpu_cores INT DEFAULT 0,
                cpu_max_clock_mhz INT DEFAULT 0,
                ram_total_gb REAL DEFAULT 0,
                ram_sticks_json JSONB DEFAULT '[]',
                disks_json JSONB DEFAULT '[]',
                gpu_json JSONB DEFAULT '[]',
                monitors_json JSONB DEFAULT '[]',
                installed_software_json JSONB DEFAULT '[]',
                hardware_hash VARCHAR(64) DEFAULT '',
                last_seen TIMESTAMPTZ DEFAULT NOW(),
                first_seen TIMESTAMPTZ DEFAULT NOW(),
                updated_at TIMESTAMPTZ DEFAULT NOW(),
                is_online BOOLEAN DEFAULT FALSE,
                printer_json JSONB DEFAULT '[]'
            )""",
            "assets_monitors": """CREATE TABLE IF NOT EXISTS assets_monitors (
                id SERIAL PRIMARY KEY, asset_id VARCHAR(32) UNIQUE NOT NULL,
                name VARCHAR(256) DEFAULT '', manufacturer VARCHAR(128) DEFAULT '',
                model_type VARCHAR(64) DEFAULT '', resolution VARCHAR(32) DEFAULT '',
                monitor_hash VARCHAR(64) DEFAULT '',
                first_seen TIMESTAMPTZ DEFAULT NOW(),
                updated_at TIMESTAMPTZ DEFAULT NOW()
            )""",
            "assets_relations": """CREATE TABLE IF NOT EXISTS assets_relations (
                id SERIAL PRIMARY KEY,
                computer_asset_id VARCHAR(32),
                monitor_asset_id VARCHAR(32),
                first_seen TIMESTAMPTZ DEFAULT NOW(),
                last_seen TIMESTAMPTZ DEFAULT NOW(),
                UNIQUE(computer_asset_id, monitor_asset_id)
            )""",
            "assets_change_log": """CREATE TABLE IF NOT EXISTS assets_change_log (
                id SERIAL PRIMARY KEY, asset_id VARCHAR(32),
                asset_type VARCHAR(16), change_type VARCHAR(64),
                old_hash VARCHAR(64) DEFAULT '', new_hash VARCHAR(64) DEFAULT '',
                details JSONB DEFAULT '{}',
                is_resolved BOOLEAN DEFAULT FALSE,
                resolved_by VARCHAR(128) DEFAULT '',
                resolved_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ DEFAULT NOW()
            )""",
            "assets_inventory": """CREATE TABLE IF NOT EXISTS assets_inventory (
                id SERIAL PRIMARY KEY, asset_id VARCHAR(32) UNIQUE NOT NULL,
                display_id VARCHAR(32) DEFAULT '', category VARCHAR(32) DEFAULT 'other',
                name VARCHAR(256) DEFAULT '', brand VARCHAR(128) DEFAULT '',
                model VARCHAR(128) DEFAULT '', serial_number VARCHAR(128) DEFAULT '',
                asset_tag VARCHAR(64) DEFAULT '', email VARCHAR(128) DEFAULT '',
                employee_id VARCHAR(64) DEFAULT '', status VARCHAR(24) DEFAULT 'in_stock',
                assigned_to VARCHAR(128) DEFAULT '', computer_asset_id VARCHAR(32) DEFAULT '',
                ip_address VARCHAR(64) DEFAULT '', mac_address VARCHAR(32) DEFAULT '',
                location VARCHAR(128) DEFAULT '', purchase_date VARCHAR(24) DEFAULT '',
                warranty_until VARCHAR(24) DEFAULT '', cost REAL DEFAULT 0, quantity INTEGER DEFAULT 1,
                notes TEXT DEFAULT '', source VARCHAR(16) DEFAULT 'manual',
                extra_json JSONB DEFAULT '{}',
                first_seen TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW()
            )""",
            # v5.0.3: netflow_flows was missing from the PG backend entirely - the NetFlow
            # collector + /api/netflow + /api/netflow/beaconing crashed on PG (AttributeError).
            "netflow_flows": """CREATE TABLE IF NOT EXISTS netflow_flows (
                id SERIAL PRIMARY KEY,
                exporter_ip TEXT, src_ip TEXT, dst_ip TEXT,
                src_port INTEGER, dst_port INTEGER, protocol INTEGER, tcp_flags INTEGER,
                packets INTEGER, bytes INTEGER, first DOUBLE PRECISION, last DOUBLE PRECISION,
                received_at TIMESTAMPTZ DEFAULT NOW()
            )""",
        }

        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_events_machine ON events(machine_id)",
            "CREATE INDEX IF NOT EXISTS idx_events_time ON events(received_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_events_type ON events(subtype)",
            "CREATE INDEX IF NOT EXISTS idx_events_machine_time ON events(machine_id, received_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_fim_machine ON fim_events(machine_id)",
            "CREATE INDEX IF NOT EXISTS idx_fim_time ON fim_events(received_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_network_machine ON network_traffic(machine_id)",
            "CREATE INDEX IF NOT EXISTS idx_network_time ON network_traffic(received_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_network_machine_time ON network_traffic(machine_id, received_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_threats_machine ON threat_alerts(machine_id)",
            "CREATE INDEX IF NOT EXISTS idx_threats_severity ON threat_alerts(severity)",
            "CREATE INDEX IF NOT EXISTS idx_threats_rule ON threat_alerts(rule_id)",
            "CREATE INDEX IF NOT EXISTS idx_threats_time ON threat_alerts(id DESC)",
            "CREATE INDEX IF NOT EXISTS idx_threats_machine_time ON threat_alerts(machine_id, received_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_vulns_machine ON vuln_alerts(machine_id)",
            "CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vuln_alerts(severity)",
            "CREATE INDEX IF NOT EXISTS idx_vulns_time ON vuln_alerts(id DESC)",
            "CREATE INDEX IF NOT EXISTS idx_netflow_dst ON netflow_flows(dst_ip)",
            "CREATE INDEX IF NOT EXISTS idx_netflow_time ON netflow_flows(received_at DESC)",
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_events_dedup ON events(dedup_key) WHERE dedup_key IS NOT NULL",
            "CREATE INDEX IF NOT EXISTS idx_yara_machine ON yara_alerts(machine_id)",
            "CREATE INDEX IF NOT EXISTS idx_sca_machine ON sca_events(machine_id)",
            "CREATE INDEX IF NOT EXISTS idx_syslog_time ON syslog(received_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_syslog_source_ip ON syslog(source_ip)",
            "CREATE INDEX IF NOT EXISTS idx_syslog_facility ON syslog(facility)",
            "CREATE INDEX IF NOT EXISTS idx_syslog_severity ON syslog(severity)",
            "CREATE INDEX IF NOT EXISTS idx_syslog_message ON syslog USING gin(to_tsvector('simple', message))",
            "CREATE INDEX IF NOT EXISTS idx_inspection_machine ON network_inspection(machine_id)",
            "CREATE INDEX IF NOT EXISTS idx_inspection_time ON network_inspection(received_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_response_machine ON response_results(machine_id)",
            "CREATE INDEX IF NOT EXISTS idx_response_time ON response_results(received_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_heartbeat_machine ON heartbeats(machine_id)",
            "CREATE INDEX IF NOT EXISTS idx_update_log_machine ON agent_update_log(machine_id)",
            "CREATE INDEX IF NOT EXISTS idx_commands_exec ON commands(exec_id)",
            "CREATE INDEX IF NOT EXISTS idx_sysmon_machine ON sysmon_events(machine_id)",
            "CREATE INDEX IF NOT EXISTS idx_sysmon_time ON sysmon_events(received_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_sysmon_machine_time ON sysmon_events(machine_id, received_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_sysmon_eid ON sysmon_events(sysmon_event_id)",
            "CREATE INDEX IF NOT EXISTS idx_sysmon_severity ON sysmon_events(severity)",
        ]

        for name, sql in tables.items():
            try:
                self._execute(sql)
            except Exception as e:
                print(f"[-] PG Create table {name}: {e}")

        for sql in indexes:
            try:
                self._execute(sql)
            except Exception as e:
                print(f"[-] PG Create index: {e}")

        # Migration: add missing columns
        alt_cols = [
            ("threat_alerts", "source_ip", "TEXT DEFAULT ''"),
            ("machines", "is_revoked", "INTEGER DEFAULT 0"),
            ("machines", "enrollment_token", "TEXT DEFAULT ''"),
            ("assets_computers", "display_id", "VARCHAR(32) DEFAULT ''"),
            ("assets_monitors", "display_id", "VARCHAR(32) DEFAULT ''"),
            ("assets_inventory", "quantity", "INTEGER DEFAULT 1"),
            ("assets_inventory", "email", "VARCHAR(128) DEFAULT ''"),
            ("assets_inventory", "employee_id", "VARCHAR(64) DEFAULT ''"),
            ("machine_users", "branch", "TEXT DEFAULT ''"),
            ("messages", "direction", "TEXT DEFAULT 'server'"),
            # v5.0.1: support-ticket columns (structured workstation requests)
            ("messages", "msg_type", "TEXT DEFAULT 'chat'"),
            ("messages", "category", "TEXT DEFAULT ''"),
            ("messages", "ultraview_id", "TEXT DEFAULT ''"),
            ("messages", "ultraview_password", "TEXT DEFAULT ''"),
            # v5.0.2: soft-delete flag for group_policies
            ("group_policies", "deleted", "INTEGER DEFAULT 0"),
            # v5.0.3 (HIGH-5): dedup_key for events - same fix as SQLite v4.6.5
            ("events", "dedup_key", "TEXT"),
        ]
        for table, col, col_type in alt_cols:
            try:
                self._execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {col} {col_type}")
            except Exception:
                pass

    def _init_timescaledb(self):
        """Convert high-volume tables to TimescaleDB hypertables for auto-partitioning."""
        if not self._connected:
            return
        hypertable_configs = [
            ("events", "received_at", "1 month"),
            ("sysmon_events", "received_at", "1 month"),
            ("network_traffic", "received_at", "1 month"),
            ("heartbeats", "received_at", "7 days"),
            ("threat_alerts", "received_at", "3 months"),
            ("fim_events", "received_at", "1 month"),
        ]
        for table, time_col, chunk_interval in hypertable_configs:
            try:
                self._execute(f"SELECT create_hypertable('{table}', '{time_col}', "
                              f"chunk_time_interval => INTERVAL '{chunk_interval}', "
                              f"if_not_exists => TRUE)")
                print(f"[*] TimescaleDB hypertable: {table}")
            except Exception as e:
                # TimescaleDB might not be installed — that's OK
                if "function create_hypertable" not in str(e).lower():
                    pass  # Silently ignore if TimescaleDB extension not available

    # =========================================================================
    # Machine Management
    # =========================================================================

    def register_machine(self, machine_id, hostname, ip_address, platform="Windows", version="1.0.0"):
        if not self._connected:
            return
        try:
            self._execute(
                """INSERT INTO machines (machine_id, hostname, ip_address, platform, version, first_seen, last_seen, is_online)
                   VALUES (%s, %s, %s, %s, %s, NOW(), NOW(), 1)
                   ON CONFLICT(machine_id) DO UPDATE SET
                   hostname=EXCLUDED.hostname, ip_address=EXCLUDED.ip_address,
                   platform=EXCLUDED.platform,
                   last_seen=NOW(), is_online=1""",
                (machine_id, hostname, ip_address, platform, version)
            )
        except Exception as e:
            print(f"[-] PG register_machine: {e}")

    def machine_offline(self, machine_id):
        if not self._connected:
            return
        try:
            self._execute("UPDATE machines SET is_online=0 WHERE machine_id=%s", (machine_id,))
        except Exception as e:
            print(f"[-] PG machine_offline: {e}")

    def check_heartbeat_timeout(self, timeout_seconds=120):
        """Mark machines as offline if no heartbeat within timeout_seconds.
        Returns count of machines marked offline."""
        if not self._connected:
            return 0
        try:
            result = self._execute(
                f"UPDATE machines SET is_online=0 WHERE is_online=1 AND last_seen < NOW() - INTERVAL '{timeout_seconds} seconds'"
            )
            return result if result else 0
        except Exception as e:
            print(f"[-] PG check_heartbeat_timeout: {e}")
            return 0

    def delete_machine(self, machine_id):
        if not self._connected:
            return
        tables = ["events", "fim_events", "heartbeats", "response_results", "commands",
                  "hardware_info", "hardware_baseline", "network_traffic", "threat_alerts",
                  "vuln_alerts", "network_inspection", "yara_alerts", "sysmon_events"]
        for t in tables:
            try:
                self._execute(f"DELETE FROM {t} WHERE machine_id=%s", (machine_id,))
            except Exception:
                pass
        try:
            self._execute("DELETE FROM machines WHERE machine_id=%s", (machine_id,))
        except Exception:
            pass

    def get_machines(self):
        if not self._connected:
            return []
        try:
            return self._execute("SELECT * FROM machines ORDER BY last_seen DESC", fetchall=True) or []
        except Exception:
            return []

    def update_machine_hostname(self, machine_id, new_hostname):
        if not self._connected:
            return
        try:
            self._execute("UPDATE machines SET hostname=%s WHERE machine_id=%s", (new_hostname, machine_id))
        except Exception:
            pass

    def save_machine_user(self, machine_id, hostname, user_name, employee_id, email, branch=""):
        if not self._connected:
            return
        try:
            self._execute(
                """INSERT INTO machine_users (machine_id, hostname, user_name, employee_id, email, branch, updated_at)
                   VALUES (%s,%s,%s,%s,%s,%s,NOW())
                   ON CONFLICT(machine_id) DO UPDATE SET
                   hostname=EXCLUDED.hostname, user_name=EXCLUDED.user_name,
                   employee_id=EXCLUDED.employee_id, email=EXCLUDED.email,
                   branch=EXCLUDED.branch,
                   updated_at=NOW()""",
                (machine_id, hostname, user_name, employee_id, email, branch)
            )
        except Exception:
            pass

    def get_machine_user(self, machine_id):
        if not self._connected:
            return {}
        try:
            r = self._execute("SELECT * FROM machine_users WHERE machine_id=%s", (machine_id,), fetch=True)
            return r or {}
        except Exception:
            return {}

    # =========================================================================
    # Event Inserts (high-throughput)
    # =========================================================================

    @staticmethod
    def _normalize_time(t):
        """v4.6.4/v5.0.3: convert C-style asctime ('Mon Aug 24 00:00:00 2026') to ISO
        ('2026-08-24 00:00:00') so cleanup + dedup work consistently on both backends."""
        if not t or not isinstance(t, str):
            return t
        t = t.strip()
        if not t or t[0].isdigit() or t[0] == '-':
            return t
        import re
        m = re.match(r'^\w{3}\s+(\w{3})\s+(\d{1,2})\s+(\d{1,2}):(\d{1,2}):(\d{1,2})\s+(\d{4})$', t)
        if not m:
            return t
        month, day, hh, mi, ss, year = m.group(1), m.group(2).zfill(2), m.group(3).zfill(2), m.group(4).zfill(2), m.group(5).zfill(2), m.group(6)
        MONTHS = {"Jan": "01", "Feb": "02", "Mar": "03", "Apr": "04", "May": "05", "Jun": "06",
                  "Jul": "07", "Aug": "08", "Sep": "09", "Oct": "10", "Nov": "11", "Dec": "12"}
        mm = MONTHS.get(month.capitalize()[:3])
        if not mm:
            return t
        return f"{year}-{mm}-{day} {hh}:{mi}:{ss}"

    @staticmethod
    def _dedup_key(data):
        """v4.6.5/v5.0.3: hash of the fields that identify ONE real event - two agent
        instances reading the same log produce identical rows that must collapse to one."""
        import hashlib
        key = "|".join([
            str(data.get("machine_id", "")),
            str(data.get("event_id", "")),
            str(data.get("source", "")),
            str(data.get("time", "")),
            str(data.get("description", ""))[:500],
        ])
        return hashlib.md5(key.encode("utf-8", errors="ignore")).hexdigest()

    def insert_event(self, msg):
        if not self._connected:
            return
        try:
            self._execute(
                """INSERT INTO events (machine_id, hostname, type, subtype, event_id, event_type,
                   source, computer, "user", category, time, description, raw_data, received_at, dedup_key)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW(),%s)
                   ON CONFLICT (dedup_key) DO NOTHING""",
                (
                    msg.get("machine_id", ""), msg.get("hostname", ""),
                    msg.get("type", ""), msg.get("subtype", ""),
                    msg.get("event_id", ""), msg.get("event_type", ""),
                    msg.get("source", ""), msg.get("computer", ""),
                    msg.get("user", "SYSTEM"), msg.get("category", ""),
                    self._normalize_time(msg.get("time", "")), msg.get("description", "")[:1000],
                    json.dumps(msg, ensure_ascii=False, default=str),
                    self._dedup_key(msg),
                )
            )
        except Exception:
            pass

    def insert_fim_event(self, msg):
        if not self._connected:
            return
        try:
            self._execute(
                "INSERT INTO fim_events (machine_id, hostname, action, path, time) VALUES (%s,%s,%s,%s,%s)",
                (msg.get("machine_id", ""), msg.get("hostname", ""),
                 msg.get("action", ""), msg.get("path", ""), msg.get("time", ""))
            )
        except Exception:
            pass

    def insert_heartbeat(self, msg):
        if not self._connected:
            return
        try:
            mid = msg.get("machine_id", "")
            self._execute(
                "INSERT INTO heartbeats (machine_id, hostname, timestamp) VALUES (%s,%s,%s)",
                (mid, msg.get("hostname", ""), msg.get("timestamp", ""))
            )
            # Update machine online status (matches SQLite behavior)
            self._execute(
                "UPDATE machines SET last_seen=NOW(), is_online=1 WHERE machine_id=%s",
                (mid,)
            )
        except Exception:
            pass

    def insert_response_result(self, msg):
        if not self._connected:
            return
        try:
            eid = msg.get("exec_id", "")
            st = msg.get("status", "completed")
            self._execute(
                """INSERT INTO response_results (machine_id, hostname, exec_id, status, output, error, exit_code, action, timestamp)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (msg.get("machine_id", ""), msg.get("hostname", ""), eid,
                 st, msg.get("output", ""), msg.get("error", ""),
                 msg.get("exit_code", 0), msg.get("action", ""), msg.get("timestamp", ""))
            )
            # Update command status (matches SQLite behavior - marks command as complete)
            if eid:
                self._execute(
                    "UPDATE commands SET status=%s, executed_at=NOW() WHERE exec_id=%s",
                    (st, eid)
                )
        except Exception:
            pass

    def insert_network_traffic(self, msg):
        if not self._connected:
            return
        try:
            self._execute(
                """INSERT INTO network_traffic (machine_id, hostname, src_ip, dst_ip, src_port, dst_port,
                   protocol, size, flags, state, timestamp, raw_data, received_at,
                   src_mac, dst_mac, ip_ttl, ip_proto, tcp_flags, payload_hex,
                   payload_size, protocol_app, dns_query, http_host, payload_dump)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW(),
                           %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (
                    msg.get("machine_id", ""), msg.get("hostname", ""),
                    msg.get("src_ip", ""), msg.get("dst_ip", ""),
                    msg.get("src_port", 0), msg.get("dst_port", 0),
                    msg.get("protocol", ""), msg.get("size", 0),
                    msg.get("flags", ""), msg.get("state", ""),
                    msg.get("timestamp", ""),
                    json.dumps(msg, ensure_ascii=False, default=str),
                    msg.get("src_mac", ""), msg.get("dst_mac", ""),
                    msg.get("ip_ttl", 0), msg.get("ip_proto", 0),
                    msg.get("tcp_flags", ""), msg.get("payload_hex", ""),
                    msg.get("payload_size", 0), msg.get("protocol_app", ""),
                    msg.get("dns_query", ""), msg.get("http_host", ""),
                    msg.get("payload_dump", ""),
                )
            )
        except Exception:
            pass

    def insert_threat_alert(self, msg):
        if not self._connected:
            return
        try:
            self._execute(
                """INSERT INTO threat_alerts (machine_id, hostname, rule_id, rule_name, description,
                   severity, timestamp, raw_data, source_ip, received_at)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW())""",
                (
                    msg.get("machine_id", ""), msg.get("hostname", ""),
                    msg.get("rule_id", ""), msg.get("rule_name", ""),
                    msg.get("description", "")[:1000], msg.get("severity", "HIGH"),
                    msg.get("timestamp", ""),
                    json.dumps(msg, ensure_ascii=False, default=str),
                    msg.get("source_ip", ""),
                )
            )
        except Exception:
            pass

    def insert_vuln_alert(self, msg):
        if not self._connected:
            return
        try:
            mid = msg.get("machine_id", "")
            cve = msg.get("cve", "")
            # v4.3.4: Dedup - skip if same machine+CVE already reported in the last 24h
            if mid and cve:
                existing = self._execute(
                    "SELECT id FROM vuln_alerts WHERE machine_id=%s AND cve=%s "
                    "AND received_at > NOW() - INTERVAL '24 hours' LIMIT 1",
                    (mid, cve), fetch=True
                )
                if existing:
                    return  # Already reported, skip duplicate
            
            self._execute(
                """INSERT INTO vuln_alerts (machine_id, hostname, software, version, publisher, cve,
                   severity, description, timestamp) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (mid, msg.get("hostname", ""),
                 msg.get("software", ""), msg.get("version", ""),
                 msg.get("publisher", ""), cve,
                 msg.get("severity", ""), msg.get("description", ""),
                 msg.get("timestamp", ""))
            )
        except Exception:
            pass

    def insert_network_inspection(self, msg):
        if not self._connected:
            return
        try:
            self._execute(
                """INSERT INTO network_inspection (machine_id, hostname, subtype, domain, dst_ip,
                   dst_port, src_ip, src_port, protocol, query_type, avg_interval_sec,
                   sample_count, timestamp) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (msg.get("machine_id", ""), msg.get("hostname", ""),
                 msg.get("subtype", ""), msg.get("domain", ""),
                 msg.get("dst_ip", ""), msg.get("dst_port", 0),
                 msg.get("src_ip", ""), msg.get("src_port", 0),
                 msg.get("protocol", ""), msg.get("query_type", ""),
                 msg.get("avg_interval_sec", 0), msg.get("sample_count", 0),
                 msg.get("timestamp", ""))
            )
        except Exception:
            pass

    def insert_yara_alert(self, msg):
        if not self._connected:
            return
        try:
            self._execute(
                "INSERT INTO yara_alerts (machine_id, hostname, rule_name, description, file, timestamp) VALUES (%s,%s,%s,%s,%s,%s)",
                (msg.get("machine_id", ""), msg.get("hostname", ""),
                 msg.get("rule_name", ""), msg.get("description", ""),
                 msg.get("file", ""), msg.get("timestamp", ""))
            )
        except Exception:
            pass

    def insert_sca_event(self, msg):
        if not self._connected:
            return
        try:
            self._execute(
                """INSERT INTO sca_events (machine_id, hostname, check_id, title, status, severity,
                   description, remediation, timestamp) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (msg.get("machine_id", ""), msg.get("hostname", ""),
                 msg.get("check_id", ""), msg.get("title", ""),
                 msg.get("status", ""), msg.get("severity", ""),
                 msg.get("description", ""), msg.get("remediation", ""),
                 msg.get("timestamp", ""))
            )
        except Exception:
            pass

    def insert_sysmon_event(self, msg):
        if not self._connected:
            return
        try:
            self._execute(
                """INSERT INTO sysmon_events (
                   machine_id, hostname, event_type, sysmon_event_id,
                   process_name, process_path, command_line, pid,
                   parent_process, parent_path, parent_command_line, parent_pid,
                   "user", severity, description,
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
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (
                    msg.get("machine_id", ""), msg.get("hostname", ""),
                    msg.get("type", ""), msg.get("sysmon_event_id", 0),
                    msg.get("process_name", ""), msg.get("process_path", ""),
                    msg.get("command_line", ""), str(msg.get("pid", "")),
                    msg.get("parent_process", ""), msg.get("parent_path", ""),
                    msg.get("parent_command_line", ""), str(msg.get("parent_pid", "")),
                    msg.get("user", ""), msg.get("severity", "INFO"),
                    msg.get("description", msg.get("suspicion_reason", "")),
                    msg.get("src_ip", ""), str(msg.get("src_port", "")),
                    msg.get("dst_ip", ""), str(msg.get("dst_port", "")),
                    msg.get("protocol", ""), msg.get("registry_key", ""),
                    msg.get("registry_value", ""), msg.get("dns_query", ""),
                    msg.get("file_path", ""), msg.get("file_name", ""),
                    msg.get("target_process", ""), msg.get("target_path", ""),
                    str(msg.get("target_pid", "")), msg.get("suspicion_reason", ""),
                    1 if msg.get("credential_dumping") else 0,
                    1 if msg.get("persistence_detected") else 0,
                    1 if msg.get("suspicious_parent") else 0,
                    1 if msg.get("suspicious_dll") else 0,
                    1 if msg.get("suspicious_file") else 0,
                    msg.get("hashes", ""), msg.get("integrity_level", ""),
                    msg.get("signed", ""), msg.get("injection_type", ""),
                    msg.get("granted_access", ""), msg.get("dns_status", ""),
                    msg.get("dns_results", ""), msg.get("timestamp", ""),
                    json.dumps(msg, ensure_ascii=False, default=str),
                )
            )
        except Exception:
            pass

    def insert_agent_update_log(self, machine_id, hostname, from_version, to_version, status, message, source):
        if not self._connected:
            return
        try:
            self._execute(
                """INSERT INTO agent_update_log (machine_id, hostname, from_version, to_version, status, message, source)
                   VALUES (%s,%s,%s,%s,%s,%s,%s)""",
                (machine_id, hostname, from_version, to_version, status, message, source)
            )
        except Exception:
            pass

    def add_command(self, machine_id, action, command, exec_id):
        if not self._connected:
            return
        try:
            self._execute(
                "INSERT INTO commands (machine_id, action, command, exec_id) VALUES (%s,%s,%s,%s) ON CONFLICT(exec_id) DO NOTHING",
                (machine_id, action, command, exec_id)
            )
        except Exception:
            pass

    # =========================================================================
    # v4.2: Batch Insert Methods (20-50x faster than single insert)
    # Called by event_worker.py via hasattr check
    # =========================================================================

    def batch_insert_events(self, events):
        """Batch insert events (WAL-optimized via _executemany)."""
        if not self._connected or not events:
            return
        try:
            sql = """INSERT INTO events (machine_id, hostname, type, subtype, event_id, event_type,
                       source, computer, "user", category, time, description, raw_data, received_at, dedup_key)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW(),%s)
                       ON CONFLICT (dedup_key) DO NOTHING"""
            params = [(
                e.get("machine_id", ""), e.get("hostname", ""),
                e.get("type", ""), e.get("subtype", ""),
                e.get("event_id", ""), e.get("event_type", ""),
                e.get("source", ""), e.get("computer", ""),
                e.get("user", "SYSTEM"), e.get("category", ""),
                self._normalize_time(e.get("time", "")), e.get("description", "")[:1000],
                json.dumps(e, ensure_ascii=False, default=str),
                self._dedup_key(e),
            ) for e in events]
            self._executemany(sql, params)
        except Exception:
            for e in events:
                try:
                    self.insert_event(e)
                except Exception:
                    pass

    def batch_insert_sysmon_events(self, events):
        """Batch insert sysmon events."""
        if not self._connected or not events:
            return
        try:
            sql = """INSERT INTO sysmon_events (
                       machine_id, hostname, event_type, sysmon_event_id,
                       process_name, process_path, command_line, pid,
                       parent_process, parent_path, parent_command_line, parent_pid,
                       "user", severity, description,
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
                     ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"""
            params = [(
                e.get("machine_id", ""), e.get("hostname", ""),
                e.get("type", ""), e.get("sysmon_event_id", 0),
                e.get("process_name", ""), e.get("process_path", ""),
                e.get("command_line", ""), str(e.get("pid", "")),
                e.get("parent_process", ""), e.get("parent_path", ""),
                e.get("parent_command_line", ""), str(e.get("parent_pid", "")),
                e.get("user", ""), e.get("severity", "INFO"),
                e.get("description", e.get("suspicion_reason", "")),
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
            ) for e in events]
            self._executemany(sql, params)
        except Exception:
            for e in events:
                try:
                    self.insert_sysmon_event(e)
                except Exception:
                    pass

    def batch_insert_network_traffic(self, events):
        """Batch insert network traffic events."""
        if not self._connected or not events:
            return
        try:
            sql = """INSERT INTO network_traffic (machine_id, hostname, src_ip, dst_ip, src_port, dst_port,
                       protocol, size, flags, state, timestamp, raw_data, received_at,
                       src_mac, dst_mac, ip_ttl, ip_proto, tcp_flags, payload_hex,
                       payload_size, protocol_app, dns_query, http_host, payload_dump)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW(),
                               %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"""
            params = [(
                e.get("machine_id", ""), e.get("hostname", ""),
                e.get("src_ip", ""), e.get("dst_ip", ""),
                e.get("src_port", 0), e.get("dst_port", 0),
                e.get("protocol", ""), e.get("size", 0),
                e.get("flags", ""), e.get("state", ""),
                e.get("timestamp", ""),
                json.dumps(e, ensure_ascii=False, default=str),
                e.get("src_mac", ""), e.get("dst_mac", ""),
                e.get("ip_ttl", 0), e.get("ip_proto", 0),
                e.get("tcp_flags", ""), e.get("payload_hex", ""),
                e.get("payload_size", 0), e.get("protocol_app", ""),
                e.get("dns_query", ""), e.get("http_host", ""),
                e.get("payload_dump", ""),
            ) for e in events]
            self._executemany(sql, params)
        except Exception:
            for e in events:
                try:
                    self.insert_network_traffic(e)
                except Exception:
                    pass

    def batch_insert_fim_events(self, events):
        """Batch insert FIM events."""
        if not self._connected or not events:
            return
        try:
            sql = "INSERT INTO fim_events (machine_id, hostname, action, path, time) VALUES (%s,%s,%s,%s,%s)"
            params = [(
                e.get("machine_id", ""), e.get("hostname", ""),
                e.get("action", ""), e.get("path", ""), e.get("time", "")
            ) for e in events]
            self._executemany(sql, params)
        except Exception:
            for e in events:
                try:
                    self.insert_fim_event(e)
                except Exception:
                    pass

    def save_machine_config(self, machine_id, config_data):
        if not self._connected:
            return {}
        try:
            hostname = config_data.get("os", {}).get("computer_name", "")
            fingerprint = json.dumps(config_data, sort_keys=True, ensure_ascii=False)

            # Check baseline
            existing = self._execute(
                "SELECT id FROM hardware_baseline WHERE machine_id=%s", (machine_id,), fetch=True
            )
            is_first = not existing

            if is_first:
                self._execute(
                    """INSERT INTO hardware_baseline (machine_id, hostname, data_json, fingerprint, saved_at)
                       VALUES (%s,%s,%s,%s,NOW()) ON CONFLICT(machine_id) DO NOTHING""",
                    (machine_id, hostname, json.dumps(config_data, ensure_ascii=False), fingerprint)
                )

            # Update current
            self._execute(
                """INSERT INTO hardware_info (machine_id, hostname, data_json, fingerprint, received_at)
                   VALUES (%s,%s,%s,%s,NOW())
                   ON CONFLICT(machine_id) DO UPDATE SET
                   hostname=EXCLUDED.hostname, data_json=EXCLUDED.data_json,
                   fingerprint=EXCLUDED.fingerprint, received_at=NOW()""",
                (machine_id, hostname, json.dumps(config_data, ensure_ascii=False), fingerprint)
            )

            return {"is_first_config": is_first, "has_changes": not is_first}
        except Exception as e:
            print(f"[-] PG save_machine_config: {e}")
            return {}

    def _uptime_session_info(self, machine_id, boot_time=None):
        """Return (session_start, last_seen, alerted, active) for the machine's
        current continuous session, merging sessions across midnight (heals the
        old per-day reset)."""
        if not self._connected:
            return None, None, False, False
        try:
            # Agent-provided OS boot time is authoritative for the current session.
            if boot_time:
                try:
                    bt = datetime.fromtimestamp(int(boot_time), tz=timezone.utc)
                    row = self._execute(
                        "SELECT alert_sent_24h FROM machine_uptime WHERE machine_id=%s AND session_start=%s LIMIT 1",
                        (machine_id, bt), fetch=True
                    )
                    if row:
                        return bt, None, bool(row.get("alert_sent_24h")), True
                    return bt, None, False, True  # new boot -> new session
                except Exception:
                    pass

            rows = self._execute(
                "SELECT session_start, last_seen, alert_sent_24h FROM machine_uptime "
                "WHERE machine_id=%s ORDER BY session_start DESC",
                (machine_id,), fetchall=True
            ) or []
            if not rows:
                return None, None, False, False

            newest = rows[0]
            gap = self._execute(
                "SELECT EXTRACT(EPOCH FROM (NOW() - %s::timestamptz)) AS gap",
                (newest["last_seen"],), fetch=True
            )
            active = ((gap.get("gap") or 0) <= _UPTIME_GAP_SECONDS) if gap else False
            if not active:
                return newest["session_start"], newest["last_seen"], bool(newest.get("alert_sent_24h")), False

            effective_start = newest["session_start"]
            alerted = bool(newest.get("alert_sent_24h"))
            for older in rows[1:]:
                g = self._execute(
                    "SELECT EXTRACT(EPOCH FROM (%s::timestamptz - %s::timestamptz)) AS gap",
                    (effective_start, older["last_seen"]), fetch=True
                )
                gap_sec = (g.get("gap") or 0) if g else None
                if gap_sec is not None and gap_sec <= _UPTIME_GAP_SECONDS:
                    effective_start = older["session_start"]
                    alerted = alerted or bool(older.get("alert_sent_24h"))
                else:
                    break
            return effective_start, newest["last_seen"], alerted, True
        except Exception:
            return None, None, False, False

    def _uptime_minutes(self, session_start, last_seen, active):
        """Compute continuous uptime minutes from a session."""
        try:
            if active:
                r = self._execute(
                    "SELECT EXTRACT(EPOCH FROM (NOW() - %s::timestamptz))/60 AS minutes",
                    (session_start,), fetch=True
                )
            else:
                r = self._execute(
                    "SELECT EXTRACT(EPOCH FROM (%s::timestamptz - %s::timestamptz))/60 AS minutes",
                    (last_seen, session_start), fetch=True
                )
            return int((r.get("minutes") or 0) if r else 0)
        except Exception:
            return 0


    def track_machine_uptime(self, machine_id, hostname, boot_time=None):
        """Track continuous uptime (since the machine last came online), across
        midnight boundaries. Returns (uptime_hours, should_alert_24h)."""
        if not self._connected:
            return 0, False
        try:
            today = datetime.now().strftime("%Y-%m-%d")
            session_start, last_seen, alerted, active = self._uptime_session_info(machine_id, boot_time)
            if not session_start or not active:
                row = self._execute(
                    "INSERT INTO machine_uptime (machine_id, date, session_start, last_seen, uptime_minutes, alert_sent_24h) "
                    "VALUES (%s, %s, NOW(), NOW(), 0, 0) RETURNING session_start",
                    (machine_id, today), fetch=True
                )
                session_start = row["session_start"] if row else None
                alerted = False
            else:
                existing = self._execute(
                    "SELECT 1 FROM machine_uptime WHERE machine_id=%s AND session_start=%s LIMIT 1",
                    (machine_id, session_start), fetch=True
                )
                if existing is None:
                    self._execute(
                        "INSERT INTO machine_uptime (machine_id, date, session_start, last_seen, uptime_minutes, alert_sent_24h) "
                        "VALUES (%s, %s, %s, NOW(), 0, %s)",
                        (machine_id, today, session_start, 1 if alerted else 0)
                    )
                    if boot_time:
                        self._execute(
                            "DELETE FROM machine_uptime WHERE machine_id=%s AND session_start <> %s",
                            (machine_id, session_start)
                        )
                else:
                    self._execute(
                        "DELETE FROM machine_uptime WHERE machine_id=%s AND session_start > %s",
                        (machine_id, session_start)
                    )
            r = self._execute(
                "SELECT EXTRACT(EPOCH FROM (NOW() - %s::timestamptz))/60 AS minutes",
                (session_start,), fetch=True
            )
            uptime_minutes = int((r.get("minutes") or 0) if r else 0)
            self._execute(
                "UPDATE machine_uptime SET last_seen=NOW(), uptime_minutes=%s, date=%s "
                "WHERE machine_id=%s AND session_start=%s",
                (uptime_minutes, today, machine_id, session_start)
            )
        except Exception:
            return 0, False

        uptime_hours = round(uptime_minutes / 60.0, 1) if uptime_minutes else 0.0
        should_alert = uptime_hours >= 24 and not alerted
        if should_alert:
            try:
                self._execute(
                    "UPDATE machine_uptime SET alert_sent_24h=1 WHERE machine_id=%s AND session_start=%s",
                    (machine_id, session_start)
                )
            except Exception:
                pass
        return uptime_hours, should_alert

    # =========================================================================
    # Query Methods
    # =========================================================================

    def get_events(self, machine_id=None, event_type=None, limit=100, since_hours=None):
        if not self._connected:
            return []
        try:
            q = "SELECT * FROM events WHERE 1=1"
            params = []
            if machine_id:
                q += " AND machine_id=%s"
                params.append(machine_id)
            if event_type:
                q += " AND subtype=%s"
                params.append(event_type)
            if since_hours:
                q += " AND received_at >= NOW() - INTERVAL '%s hours'"
                params.append(str(since_hours))
            q += " ORDER BY id DESC LIMIT %s"
            params.append(limit)
            return self._execute(q, tuple(params), fetchall=True) or []
        except Exception:
            return []

    def get_fim_events(self, machine_id=None, limit=100):
        if not self._connected:
            return []
        try:
            q = "SELECT * FROM fim_events WHERE 1=1"
            params = []
            if machine_id:
                q += " AND machine_id=%s"
                params.append(machine_id)
            q += " ORDER BY id DESC LIMIT %s"
            params.append(limit)
            return self._execute(q, tuple(params), fetchall=True) or []
        except Exception:
            return []

    def get_syslog(self, limit=100, facility=None, severity=None, source_ip=None, search=None):
        if not self._connected:
            return []
        try:
            q = "SELECT * FROM syslog WHERE 1=1"
            params = []
            if facility:
                q += " AND facility=%s"
                params.append(facility)
            if severity:
                q += " AND severity=%s"
                params.append(severity)
            if source_ip:
                q += " AND source_ip=%s"
                params.append(source_ip)
            if search:
                q += " AND message ILIKE %s"
                params.append(f"%{search}%")
            q += " ORDER BY id DESC LIMIT %s"
            params.append(limit)
            return self._execute(q, tuple(params), fetchall=True) or []
        except Exception:
            return []

    def get_response_results(self, machine_id=None, limit=100):
        if not self._connected:
            return []
        try:
            q = "SELECT * FROM response_results WHERE 1=1"
            params = []
            if machine_id:
                q += " AND machine_id=%s"
                params.append(machine_id)
            q += " ORDER BY id DESC LIMIT %s"
            params.append(limit)
            return self._execute(q, tuple(params), fetchall=True) or []
        except Exception:
            return []

    def get_threat_alerts(self, machine_id=None, limit=100, since_hours=None):
        if not self._connected:
            return []
        try:
            q = "SELECT * FROM threat_alerts WHERE 1=1"
            params = []
            if machine_id:
                q += " AND machine_id=%s"
                params.append(machine_id)
            if since_hours:
                q += " AND received_at >= NOW() - INTERVAL '%s hours'"
                params.append(str(since_hours))
            q += " ORDER BY id DESC LIMIT %s"
            params.append(limit)
            return self._execute(q, tuple(params), fetchall=True) or []
        except Exception:
            return []

    def get_vuln_alerts(self, machine_id=None, limit=100, since_hours=None):
        if not self._connected:
            return []
        try:
            q = "SELECT * FROM vuln_alerts WHERE 1=1"
            params = []
            if machine_id:
                q += " AND machine_id=%s"
                params.append(machine_id)
            if since_hours:
                q += " AND received_at >= NOW() - INTERVAL '%s hours'"
                params.append(str(since_hours))
            q += " ORDER BY id DESC LIMIT %s"
            params.append(limit)
            return self._execute(q, tuple(params), fetchall=True) or []
        except Exception:
            return []

    def get_network_inspection(self, machine_id=None, subtype=None, limit=100):
        if not self._connected:
            return []
        try:
            q = "SELECT * FROM network_inspection WHERE 1=1"
            params = []
            if machine_id:
                q += " AND machine_id=%s"
                params.append(machine_id)
            q += " ORDER BY id DESC LIMIT %s"
            params.append(limit)
            return self._execute(q, tuple(params), fetchall=True) or []
        except Exception:
            return []

    def get_yara_alerts(self, machine_id=None, limit=100, since_hours=None):
        if not self._connected:
            return []
        try:
            q = "SELECT * FROM yara_alerts WHERE 1=1"
            params = []
            if machine_id:
                q += " AND machine_id=%s"
                params.append(machine_id)
            q += " ORDER BY id DESC LIMIT %s"
            params.append(limit)
            return self._execute(q, tuple(params), fetchall=True) or []
        except Exception:
            return []

    def get_sca_events(self, machine_id=None, limit=200):
        if not self._connected:
            return []
        try:
            q = "SELECT * FROM sca_events WHERE 1=1"
            params = []
            if machine_id:
                q += " AND machine_id=%s"
                params.append(machine_id)
            q += " ORDER BY id DESC LIMIT %s"
            params.append(limit)
            return self._execute(q, tuple(params), fetchall=True) or []
        except Exception:
            return []

    def get_sysmon_events(self, machine_id=None, limit=200, since_hours=None, event_type=None):
        if not self._connected:
            return []
        try:
            q = "SELECT * FROM sysmon_events WHERE 1=1"
            params = []
            if machine_id:
                q += " AND machine_id=%s"
                params.append(machine_id)
            if since_hours:
                q += " AND received_at >= NOW() - INTERVAL '%s hours'"
                params.append(str(since_hours))
            if event_type:
                q += " AND event_type=%s"
                params.append(event_type)
            q += " ORDER BY id DESC LIMIT %s"
            params.append(limit)
            return self._execute(q, tuple(params), fetchall=True) or []
        except Exception:
            return []

    def get_stats(self, machine_id=None):
        if not self._connected:
            return {}
        try:
            total_machines = self._execute("SELECT COUNT(*) as cnt FROM machines", fetch=True)
            online_machines = self._execute("SELECT COUNT(*) as cnt FROM machines WHERE is_online=1", fetch=True)
            total_events = self._execute("SELECT COUNT(*) as cnt FROM events", fetch=True)
            
            # Syslog count: always queried (syslog comes from routers/firewalls, not agents)
            syslog_count = (self._execute(
                "SELECT COUNT(*) as cnt FROM syslog", fetch=True
            ) or {}).get("cnt", 0)

            fim_count = 0
            response_count = 0

            if machine_id:
                fim_count = (self._execute(
                    "SELECT COUNT(*) as cnt FROM fim_events WHERE machine_id=%s", (machine_id,), fetch=True
                ) or {}).get("cnt", 0)
                response_count = (self._execute(
                    "SELECT COUNT(*) as cnt FROM response_results WHERE machine_id=%s", (machine_id,), fetch=True
                ) or {}).get("cnt", 0)

            return {
                "total_machines": (total_machines or {}).get("cnt", 0),
                "online_machines": (online_machines or {}).get("cnt", 0),
                "events": (total_events or {}).get("cnt", 0),
                "fim_events": fim_count,
                "syslog": syslog_count,
                "responses": response_count,
            }
        except Exception:
            return {}

    def get_event_types(self, machine_id=None):
        if not self._connected:
            return []
        try:
            if machine_id:
                rows = self._execute(
                    "SELECT subtype, COUNT(*) as cnt FROM events WHERE machine_id=%s AND received_at > NOW() - INTERVAL '24 hours' GROUP BY subtype ORDER BY cnt DESC LIMIT 10",
                    (machine_id,), fetchall=True
                )
            else:
                rows = self._execute(
                    "SELECT subtype, COUNT(*) as cnt FROM events WHERE received_at > NOW() - INTERVAL '24 hours' GROUP BY subtype ORDER BY cnt DESC LIMIT 10",
                    fetchall=True
                )
            return rows or []
        except Exception:
            return []

    # =========================================================================
    # Hardware Config
    # =========================================================================

    def get_machine_config(self, machine_id):
        if not self._connected:
            return None
        try:
            r = self._execute(
                "SELECT * FROM hardware_info WHERE machine_id=%s ORDER BY id DESC LIMIT 1",
                (machine_id,), fetch=True
            )
            if r:
                raw = r.get("data_json", {})
                if isinstance(raw, dict):
                    r["data"] = raw
                elif isinstance(raw, str):
                    try:
                        r["data"] = json.loads(raw) if raw else {}
                    except Exception:
                        r["data"] = {}
                else:
                    r["data"] = {}
            return r
        except Exception as e:
            print(f"[-] PG get_machine_config: {e}")
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
                diffs.extend(PostgresDatabase._compute_diff(old_val, new_val, path))
            elif isinstance(old_val, list) and isinstance(new_val, list):
                diffs.extend(PostgresDatabase._compute_list_diff(old_val, new_val, path, key))
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
                label = PostgresDatabase._get_item_label(item, i)
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
                label = PostgresDatabase._get_item_label(item, i)
                diffs.append({
                    "path": f"{path}[-{i}]",
                    "field": f"{key} (đã xóa)",
                    "baseline_value": label,
                    "current_value": "-",
                    "change_type": "removed"
                })
            return diffs

        if isinstance(old_list[0], dict) and isinstance(new_list[0], dict):
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

                for item_id, new_item in new_by_id.items():
                    if item_id not in old_by_id:
                        label = PostgresDatabase._get_item_label(new_item, -1)
                        diffs.append({
                            "path": f"{path}.+{item_id}",
                            "field": f"{key} (thêm mới)",
                            "baseline_value": "-",
                            "current_value": label,
                            "change_type": "added"
                        })

                for item_id, old_item in old_by_id.items():
                    if item_id not in new_by_id:
                        label = PostgresDatabase._get_item_label(old_item, -1)
                        diffs.append({
                            "path": f"{path}.-{item_id}",
                            "field": f"{key} (đã xóa)",
                            "baseline_value": label,
                            "current_value": "-",
                            "change_type": "removed"
                        })

                for item_id in set(old_by_id.keys()) & set(new_by_id.keys()):
                    old_item = old_by_id[item_id]
                    new_item = new_by_id[item_id]
                    sub_diffs = PostgresDatabase._compute_diff(old_item, new_item, f"{path}.{item_id}")
                    for d in sub_diffs:
                        d["change_type"] = "modified"
                    diffs.extend(sub_diffs)

                return diffs

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
                diffs.extend(PostgresDatabase._compute_diff(old_item, new_item, f"{path}[{i}]"))
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

    # =========================================================================
    # Retention
    # =========================================================================

    def apply_retention_policy(self, event_days=30, fim_days=90, traffic_days=30,
                                threat_days=180, vuln_days=180, syslog_days=30):
        if not self._connected:
            return
        policies = {
            "events": event_days, "fim_events": fim_days,
            "network_traffic": traffic_days, "threat_alerts": threat_days,
            "vuln_alerts": vuln_days, "syslog": syslog_days,
            "heartbeats": 7, "sysmon_events": event_days
        }
        for table, days in policies.items():
            try:
                self._execute(
                    f"DELETE FROM {table} WHERE received_at < NOW() - (%s || ' days')::INTERVAL",
                    (str(days),)
                )
            except Exception:
                pass

    def close(self):
        if self.pool:
            try:
                self.pool.closeall()
            except Exception:
                pass
            self._connected = False

    # =========================================================================
    # Missing methods from db_manager.py that API calls expect
    # =========================================================================

    def get_all_machine_users(self):
        """Get all machine-user mappings (used by /api/machines)."""
        if not self._connected:
            return []
        try:
            return self._execute(
                "SELECT * FROM machine_users ORDER BY hostname ASC",
                fetchall=True
            ) or []
        except Exception:
            return []

    def _get_group_members(self, group_id):
        """Get member machine_ids for a group (used by api_messages.py)."""
        if not self._connected:
            return []
        try:
            rows = self._execute(
                "SELECT machine_id FROM agent_group_members WHERE group_id=%s",
                (group_id,), fetchall=True
            ) or []
            return [{"machine_id": r["machine_id"]} for r in rows]
        except Exception:
            return []

    def get_agent_groups(self):
        """Get all agent groups with members (used by /api/groups)."""
        if not self._connected:
            return []
        try:
            groups = self._execute(
                "SELECT * FROM agent_groups ORDER BY name ASC",
                fetchall=True
            ) or []
            result = []
            for g in groups:
                g = dict(g)
                g["config"] = json.loads(g.get("config_json", "{}")) if g.get("config_json") else {}
                del g["config_json"]
                # Get members for this group
                members = self._execute(
                    """SELECT m.machine_id, mach.hostname, mach.ip_address, mach.is_online
                       FROM agent_group_members m
                       LEFT JOIN machines mach ON m.machine_id = mach.machine_id
                       WHERE m.group_id = %s""",
                    (g["id"],), fetchall=True
                ) or []
                g["members"] = members
                result.append(g)
            return result
        except Exception:
            return []

    # =========================================================================
    # Additional methods from db_manager.py needed for full API compatibility
    # =========================================================================

    def get_all_machine_uptime_today(self):
        """Get current continuous uptime for all machines."""
        if not self._connected:
            return {}
        result = {}
        try:
            mids = self._execute("SELECT DISTINCT machine_id FROM machine_uptime", fetchall=True) or []
            for row in mids:
                mid = row["machine_id"]
                session_start, last_seen, alerted, active = self._uptime_session_info(mid)
                if not session_start:
                    continue
                minutes = self._uptime_minutes(session_start, last_seen, active)
                result[mid] = {"uptime_minutes": minutes, "uptime_hours": round(minutes / 60.0, 1)}
        except Exception:
            return {}
        return result

    def get_machine_uptime_today(self, machine_id):
        """Get current continuous uptime minutes for a machine."""
        if not self._connected:
            return 0
        try:
            session_start, last_seen, alerted, active = self._uptime_session_info(machine_id)
            if not session_start:
                return 0
            return self._uptime_minutes(session_start, last_seen, active)
        except Exception:
            return 0

    def get_server_agent_version(self):
        """Get current server-side agent version from version.txt."""
        try:
            ver_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "version.txt")
            if os.path.exists(ver_file):
                with open(ver_file, "r") as f:
                    return f.read().strip()
        except Exception:
            pass
        return "1.0.0"

    def get_network_traffic(self, machine_id=None, limit=100, since_hours=None):
        if not self._connected:
            return []
        try:
            q = "SELECT * FROM network_traffic WHERE 1=1"
            params = []
            if machine_id:
                q += " AND machine_id=%s"
                params.append(machine_id)
            if since_hours:
                q += " AND received_at >= NOW() - INTERVAL '%s hours'"
                params.append(str(since_hours))
            q += " ORDER BY id DESC LIMIT %s"
            params.append(limit)
            return self._execute(q, tuple(params), fetchall=True) or []
        except Exception:
            return []

    def get_alert_counts_by_machine(self):
        """Get threat alert counts grouped by machine."""
        if not self._connected:
            return {}
        try:
            rows = self._execute(
                "SELECT machine_id, COUNT(*) as cnt FROM threat_alerts WHERE received_at > NOW() - INTERVAL '24 hours' GROUP BY machine_id",
                fetchall=True
            ) or []
            return {r["machine_id"]: r["cnt"] for r in rows}
        except Exception:
            return {}

    def get_hardware_info(self, machine_id):
        if not self._connected:
            return None
        try:
            r = self._execute("SELECT * FROM hardware_info WHERE machine_id=%s ORDER BY id DESC LIMIT 1", (machine_id,), fetch=True)
            if r:
                raw = r.get("data_json", {})
                if isinstance(raw, dict):
                    r["data"] = raw
                elif isinstance(raw, str):
                    try:
                        r["data"] = json.loads(raw) if raw else {}
                    except Exception:
                        r["data"] = {}
                else:
                    r["data"] = {}
            return r
        except Exception as e:
            print(f"[-] PG get_hardware_info: {e}")
            return None

    def get_baseline(self, machine_id):
        if not self._connected:
            return None
        try:
            r = self._execute("SELECT * FROM hardware_baseline WHERE machine_id=%s", (machine_id,), fetch=True)
            if r:
                raw = r.get("data_json", {})
                if isinstance(raw, dict):
                    r["data"] = raw
                elif isinstance(raw, str):
                    try:
                        r["data"] = json.loads(raw) if raw else {}
                    except Exception:
                        r["data"] = {}
                else:
                    r["data"] = {}
            return r
        except Exception as e:
            print(f"[-] PG get_baseline: {e}")
            return None

    def get_data_summary(self):
        if not self._connected:
            return {}
        try:
            tables = ["events", "fim_events", "network_traffic", "sysmon_events", "heartbeats", "syslog",
                      "yara_alerts", "sca_events", "agentless_events", "threat_alerts", "vuln_alerts"]
            summary = {}
            for table in tables:
                try:
                    r = self._execute(
                        f"SELECT COUNT(*) as cnt, MIN(timestamp) as oldest, MAX(timestamp) as newest FROM {table}",
                        fetch=True
                    )
                    if r:
                        summary[table] = {"count": r.get("cnt", 0), "oldest": r.get("oldest", ""), "newest": r.get("newest", "")}
                except Exception:
                    summary[table] = {"count": 0, "oldest": "", "newest": ""}
            return summary
        except Exception:
            return {}

    def get_fim_baseline(self, machine_id, limit=None, offset=None, search="", only_changed=False, sort_by="path", **kwargs):
        if not self._connected:
            return []
        try:
            return self._execute("SELECT * FROM fim_baseline WHERE machine_id=%s ORDER BY path ASC", (machine_id,), fetchall=True) or []
        except Exception:
            return []

    def get_fim_baseline_stats(self, machine_id):
        if not self._connected:
            return {"total": 0, "changed": 0, "last_scan": ""}
        try:
            total = self._execute("SELECT COUNT(*) as cnt FROM fim_baseline WHERE machine_id=%s", (machine_id,), fetch=True)
            changed = self._execute("SELECT COUNT(*) as cnt FROM fim_baseline WHERE machine_id=%s AND change_count>0", (machine_id,), fetch=True)
            last = self._execute("SELECT MAX(last_checked) as ts FROM fim_baseline WHERE machine_id=%s", (machine_id,), fetch=True)
            return {
                "total": (total.get("cnt") or 0) if total else 0,
                "changed": (changed.get("cnt") or 0) if changed else 0,
                "last_scan": str(last.get("ts") or "") if last else "",
            }
        except Exception:
            return {"total": 0, "changed": 0, "last_scan": ""}

    def upsert_fim_baseline(self, machine_id, path, file_hash, file_size, owner, permissions, last_modified):
        if not self._connected:
            return
        try:
            self._execute(
                """INSERT INTO fim_baseline (machine_id, path, file_hash, file_size, owner, permissions, last_modified, last_checked)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,NOW())
                   ON CONFLICT(machine_id, path) DO UPDATE SET
                   file_hash_old=fim_baseline.file_hash, file_hash=EXCLUDED.file_hash,
                   file_size=EXCLUDED.file_size, owner=EXCLUDED.owner,
                   permissions=EXCLUDED.permissions, last_modified=EXCLUDED.last_modified,
                   last_checked=NOW(), change_count=fim_baseline.change_count+1""",
                (machine_id, path, file_hash, file_size, owner, permissions, last_modified)
            )
        except Exception:
            pass

    def insert_agentless_event(self, data):
        if not self._connected:
            return
        try:
            self._execute(
                "INSERT INTO agentless_events (device_name, ip, device_type, data_json, timestamp) VALUES (%s,%s,%s,%s,%s)",
                (data.get("device_name", ""), data.get("ip", ""), data.get("device_type", ""),
                 json.dumps(data, ensure_ascii=False), data.get("timestamp", ""))
            )
        except Exception:
            pass

    def get_agentless_events(self, limit=100):
        if not self._connected:
            return []
        try:
            return self._execute("SELECT * FROM agentless_events ORDER BY id DESC LIMIT %s", (limit,), fetchall=True) or []
        except Exception:
            return []

    def clear_agentless_events(self):
        if not self._connected:
            return 0
        try:
            result = self._execute("DELETE FROM agentless_events")
            return result if result else 0
        except Exception:
            return 0

    def insert_audit_log(self, username, action, details="", ip_address=""):
        if not self._connected:
            return
        try:
            self._execute(
                "INSERT INTO audit_log (username, action, details, ip_address) VALUES (%s,%s,%s,%s)",
                (username, action, details, ip_address)
            )
        except Exception:
            pass

    def get_audit_log(self, limit=100):
        if not self._connected:
            return []
        try:
            return self._execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT %s", (limit,), fetchall=True) or []
        except Exception:
            return []

    def insert_syslog(self, source_ip, hostname, facility, severity, timestamp, message, raw_data):
        if not self._connected:
            return
        try:
            safe_msg = (message or "")[:4000]
            # raw_data is JSONB column - convert raw string to JSON object
            raw_json = json.dumps({"raw": str(raw_data)[:4000]}, ensure_ascii=False)
            self._execute(
                "INSERT INTO syslog (source_ip, hostname, facility, severity, timestamp, message, raw_data) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                (source_ip, hostname, facility, severity, timestamp, safe_msg, raw_json)
            )
        except Exception as e:
            print(f"[-] insert_syslog ERROR: {e}")

    def get_agent_update_logs(self, machine_id=None, limit=100):
        if not self._connected:
            return []
        try:
            q = "SELECT * FROM agent_update_log WHERE 1=1"
            params = []
            if machine_id:
                q += " AND machine_id=%s"
                params.append(machine_id)
            q += " ORDER BY id DESC LIMIT %s"
            params.append(limit)
            return self._execute(q, tuple(params), fetchall=True) or []
        except Exception:
            return []

    def is_suppressed(self, rule_id, machine_id, event_data):
        if not self._connected:
            return False
        try:
            # Check for active suppressions matching this rule+ machine
            r = self._execute(
                "SELECT id FROM alert_suppression WHERE rule_id=%s AND machine_id=%s AND (expires_at IS NULL OR expires_at > NOW()) LIMIT 1",
                (rule_id, machine_id), fetch=True
            )
            return r is not None
        except Exception:
            return False

    def get_suppressions(self):
        if not self._connected:
            return []
        try:
            return self._execute("SELECT * FROM alert_suppression ORDER BY created_at DESC", fetchall=True) or []
        except Exception:
            return []

    def add_suppression(self, rule_id, machine_id, field_path, field_hash, reason, created_by, expires_at=None):
        if not self._connected:
            return False
        try:
            self._execute(
                """INSERT INTO alert_suppression (rule_id, machine_id, field_path, field_hash, reason, created_by, expires_at)
                   VALUES (%s,%s,%s,%s,%s,%s,%s)""",
                (rule_id, machine_id, field_path, field_hash, reason, created_by, expires_at)
            )
            return True
        except Exception:
            return False

    def remove_suppression(self, suppression_id):
        if not self._connected:
            return
        try:
            self._execute("DELETE FROM alert_suppression WHERE id=%s", (suppression_id,))
        except Exception:
            pass

    def deduplicate_alerts(self, machine_id, rule_id):
        """Dedup: keep latest, delete older duplicates."""
        if not self._connected:
            return
        try:
            self._execute(
                "DELETE FROM threat_alerts WHERE id IN (SELECT id FROM threat_alerts WHERE machine_id=%s AND rule_id=%s ORDER BY id DESC OFFSET 1)",
                (machine_id, rule_id)
            )
        except Exception:
            # OFFSET may not work in subquery on older PG, ignore
            pass

    def cleanup_old_data(self, retention_days=60, keep_threats=True, types=None):
        if not self._connected:
            return {}
        try:
            deleted = {}
            all_tables = {
                "events": "events",
                "fim_events": "fim_events",
                "network_traffic": "network_traffic",
                "sysmon_events": "sysmon_events",
                "heartbeats": "heartbeats",
                "syslog": "syslog",
                "yara_alerts": "yara_alerts",
                "sca_events": "sca_events",
                "agentless_events": "agentless_events",
                # v5.0.3 (MEDIUM-8): these 3 were missing from the PG cleanup - they
                # grew forever on PG while the UI reported them as cleaned.
                "network_inspection": "network_inspection",
                "response_results": "response_results",
                "audit_log": "audit_log",
            }
            # Filter by types if specified
            if types:
                tables_to_clean = {k: v for k, v in all_tables.items() if k in types}
            else:
                tables_to_clean = dict(all_tables)  # All except threats/vulns

            for key, table in tables_to_clean.items():
                try:
                    result = self._execute(
                        f"DELETE FROM {table} WHERE received_at < NOW() - (%s || ' days')::INTERVAL",
                        (str(retention_days),)
                    )
                    deleted[key] = result if result else 0
                except Exception:
                    deleted[key] = 0
            if not keep_threats:
                try:
                    result = self._execute(
                        "DELETE FROM threat_alerts WHERE received_at < NOW() - (%s || ' days')::INTERVAL",
                        (str(retention_days),)
                    )
                    deleted["threat_alerts"] = result if result else 0
                except Exception:
                    pass
            return deleted
        except Exception:
            return {}

    def cleanup_old_logs(self, days=30, keep_threats=True):
        return self.cleanup_old_data(retention_days=days, keep_threats=keep_threats)

    def vacuum(self):
        if not self._connected:
            return
        try:
            self._execute("VACUUM ANALYZE")
        except Exception:
            pass

    # Agent Groups
    def create_agent_group(self, name, description="", config_json="{}"):
        if not self._connected:
            return 0
        try:
            result = self._execute(
                "INSERT INTO agent_groups (name, description, config_json) VALUES (%s,%s,%s) RETURNING id",
                (name, description, config_json), fetch=True
            )
            return result["id"] if result else 0
        except Exception:
            return 0

    def update_agent_group(self, group_id, name=None, description=None, config_json=None):
        if not self._connected:
            return False
        try:
            parts = []
            params = []
            if name is not None:
                parts.append("name=%s"); params.append(name)
            if description is not None:
                parts.append("description=%s"); params.append(description)
            if config_json is not None:
                parts.append("config_json=%s"); params.append(config_json)
            if parts:
                parts.append("updated_at=NOW()")
                params.append(group_id)
                self._execute(f"UPDATE agent_groups SET {','.join(parts)} WHERE id=%s", tuple(params))
            return True
        except Exception:
            return False

    def delete_agent_group(self, group_id):
        if not self._connected:
            return
        try:
            self._execute("DELETE FROM agent_group_members WHERE group_id=%s", (group_id,))
            self._execute("DELETE FROM agent_groups WHERE id=%s", (group_id,))
        except Exception:
            pass

    def get_agent_group(self, group_id):
        if not self._connected:
            return None
        try:
            g = self._execute("SELECT * FROM agent_groups WHERE id=%s", (group_id,), fetch=True)
            if g:
                g = dict(g)
                g["config"] = json.loads(g.get("config_json", "{}")) if g.get("config_json") else {}
                g["members"] = self._execute(
                    """SELECT m.machine_id, mach.hostname, mach.ip_address, mach.is_online
                       FROM agent_group_members m LEFT JOIN machines mach ON m.machine_id=mach.machine_id
                       WHERE m.group_id=%s""",
                    (group_id,), fetchall=True
                ) or []
                return g
            return None
        except Exception:
            return None

    def add_machine_to_group(self, machine_id, group_id):
        if not self._connected:
            return
        try:
            self._execute(
                "INSERT INTO agent_group_members (group_id, machine_id) VALUES (%s,%s) ON CONFLICT(machine_id) DO UPDATE SET group_id=EXCLUDED.group_id",
                (group_id, machine_id)
            )
        except Exception:
            pass

    def remove_machine_from_group(self, machine_id, group_id):
        if not self._connected:
            return
        try:
            self._execute("DELETE FROM agent_group_members WHERE machine_id=%s AND group_id=%s", (machine_id, group_id))
        except Exception:
            pass

    def get_machine_group(self, machine_id):
        if not self._connected:
            return None
        try:
            return self._execute(
                "SELECT g.* FROM agent_groups g JOIN agent_group_members m ON g.id=m.group_id WHERE m.machine_id=%s",
                (machine_id,), fetch=True
            )
        except Exception:
            return None

    def get_group_config(self, machine_id):
        if not self._connected:
            return None
        try:
            r = self._execute(
                "SELECT g.config_json FROM agent_groups g JOIN agent_group_members m ON g.id=m.group_id WHERE m.machine_id=%s",
                (machine_id,), fetch=True
            )
            if r and r.get("config_json"):
                return json.loads(r["config_json"])
            return None
        except Exception:
            return None

    # Policies
    def add_policy(self, group_id, policy_type, policy_name="", config_json="{}", enabled=1):
        if not self._connected:
            return 0
        try:
            result = self._execute(
                "INSERT INTO group_policies (group_id, policy_type, policy_name, config_json, enabled) VALUES (%s,%s,%s,%s,%s) RETURNING id",
                (group_id, policy_type, policy_name, config_json, enabled), fetch=True
            )
            return result["id"] if result else 0
        except Exception:
            return 0

    def update_policy(self, policy_id, policy_name=None, config_json=None, enabled=None):
        if not self._connected:
            return False
        try:
            parts = []
            params = []
            if policy_name is not None:
                parts.append("policy_name=%s"); params.append(policy_name)
            if config_json is not None:
                parts.append("config_json=%s"); params.append(config_json)
            if enabled is not None:
                parts.append("enabled=%s"); params.append(1 if enabled else 0)
                if not enabled:
                    parts.append("apply_status='pending_removal'")
                else:
                    parts.append("apply_status='pending'")
            if parts:
                parts.append("updated_at=NOW()")
                params.append(policy_id)
                self._execute(f"UPDATE group_policies SET {','.join(parts)} WHERE id=%s", tuple(params))
            return True
        except Exception:
            return False

    def delete_policy(self, policy_id):
        """v5.0.2: soft-delete - mark deleted + pending_removal so the enforcement loop
        pushes remove_* to every machine that applied; hard-purged once all removed."""
        if not self._connected:
            return
        try:
            self._execute("UPDATE group_policies SET deleted=1, apply_status='pending_removal', updated_at=NOW() WHERE id=%s AND deleted=0", (policy_id,))
        except Exception:
            pass

    def get_policies(self, group_id=None):
        if not self._connected:
            return []
        try:
            if group_id:
                return self._execute(
                    "SELECT * FROM group_policies WHERE group_id=%s AND deleted=0 ORDER BY created_at DESC",
                    (group_id,), fetchall=True
                ) or []
            return self._execute(
                "SELECT g.name as group_name, p.* FROM group_policies p JOIN agent_groups g ON p.group_id=g.id "
                "WHERE p.deleted=0 ORDER BY p.created_at DESC",
                fetchall=True
            ) or []
        except Exception:
            return []

    def get_policy(self, policy_id):
        if not self._connected:
            return None
        try:
            return self._execute("SELECT * FROM group_policies WHERE id=%s AND deleted=0", (policy_id,), fetch=True)
        except Exception:
            return None

    def update_policy_status(self, policy_id, status, message=""):
        if not self._connected:
            return
        try:
            self._execute("UPDATE group_policies SET apply_status=%s, status_message=%s, updated_at=NOW() WHERE id=%s",
                          (status, message, policy_id))
        except Exception:
            pass

    def get_pending_policies_for_machine(self, machine_id):
        """v5.0.2: per-machine pending - enabled policy the machine has NOT yet applied."""
        if not self._connected:
            return []
        try:
            return self._execute(
                """SELECT p.* FROM group_policies p JOIN agent_group_members m ON p.group_id=m.group_id
                   WHERE m.machine_id=%s AND p.enabled=1 AND p.deleted=0
                     AND NOT EXISTS (
                         SELECT 1 FROM policy_apply_status s
                         WHERE s.policy_id=p.id AND s.machine_id=%s AND s.status='applied'
                     )""",
                (machine_id, machine_id), fetchall=True
            ) or []
        except Exception:
            return []

    def get_removal_policies_for_machine(self, machine_id):
        """v5.0.2: per-machine removal - disabled OR soft-deleted policy the machine applied."""
        if not self._connected:
            return []
        try:
            return self._execute(
                """SELECT p.* FROM group_policies p JOIN agent_group_members m ON p.group_id=m.group_id
                   WHERE m.machine_id=%s AND (p.enabled=0 OR p.deleted=1)
                     AND EXISTS (
                         SELECT 1 FROM policy_apply_status s
                         WHERE s.policy_id=p.id AND s.machine_id=%s AND s.status='applied'
                     )""",
                (machine_id, machine_id), fetchall=True
            ) or []
        except Exception:
            return []

    def set_policy_machine_status(self, policy_id, machine_id, status, message=""):
        """v5.0.2: record per-machine apply status (called when the agent reports)."""
        if not self._connected:
            return
        try:
            self._execute(
                "INSERT INTO policy_apply_status (policy_id, machine_id, status, message, updated_at) "
                "VALUES (%s,%s,%s,%s,NOW()) "
                "ON CONFLICT (policy_id, machine_id) DO UPDATE SET status=EXCLUDED.status, "
                "message=EXCLUDED.message, updated_at=NOW()",
                (policy_id, machine_id, status, message))
        except Exception:
            pass

    def clear_policy_machine_status(self, policy_id):
        """v5.0.2: delete per-machine rows (used by 're-apply to all')."""
        if not self._connected:
            return
        try:
            self._execute("DELETE FROM policy_apply_status WHERE policy_id=%s", (policy_id,))
        except Exception:
            pass

    def get_policy_machine_status(self, policy_id):
        """v5.0.2: per-machine apply status for the UI (joined with machine hostnames)."""
        if not self._connected:
            return []
        try:
            return self._execute(
                """SELECT s.machine_id, s.status, s.message, s.updated_at,
                          COALESCE(mc.hostname, s.machine_id) AS hostname
                   FROM policy_apply_status s
                   LEFT JOIN machines mc ON mc.machine_id=s.machine_id
                   WHERE s.policy_id=%s ORDER BY s.updated_at DESC""",
                (policy_id,), fetchall=True
            ) or []
        except Exception:
            return []

    def mark_policy_removal_sent(self, policy_id, machine_id=None):
        """v5.0.2: after a removal command is delivered, drop that machine's 'applied'
        row (back to baseline). Soft-deleted policies are hard-purged once no machine
        has an 'applied' row."""
        if not self._connected:
            return
        try:
            if machine_id:
                self._execute("DELETE FROM policy_apply_status WHERE policy_id=%s AND machine_id=%s",
                              (policy_id, machine_id))
            else:
                self._execute("DELETE FROM policy_apply_status WHERE policy_id=%s", (policy_id,))
            self._purge_soft_deleted_policies()
        except Exception:
            pass

    def _purge_soft_deleted_policies(self):
        """v5.0.2: hard-delete soft-deleted policies with no remaining 'applied' machines."""
        if not self._connected:
            return
        try:
            rows = self._execute("SELECT id FROM group_policies WHERE deleted=1", fetchall=True) or []
            for r in rows:
                cnt = self._execute(
                    "SELECT COUNT(*) AS c FROM policy_apply_status WHERE policy_id=%s AND status='applied'",
                    (r["id"],), fetch=True)
                if not cnt or cnt["c"] == 0:
                    self._execute("DELETE FROM group_policies WHERE id=%s", (r["id"],))
                    self._execute("DELETE FROM policy_apply_status WHERE policy_id=%s", (r["id"],))
        except Exception:
            pass

    # v5.0.3: triage status methods were missing from the PG backend - on a PG
    # deployment POST /api/threats/<id>/status etc. raised AttributeError (500).
    def set_threat_status(self, threat_id, status):
        if not self._connected:
            return
        try:
            self._execute("UPDATE threat_alerts SET status=%s WHERE id=%s", (status, threat_id))
        except Exception:
            pass

    def set_vuln_status(self, alert_id, status):
        if not self._connected:
            return
        try:
            self._execute("UPDATE vuln_alerts SET status=%s WHERE id=%s", (status, alert_id))
        except Exception:
            pass

    def set_inspection_status(self, alert_id, status):
        if not self._connected:
            return
        try:
            self._execute("UPDATE network_inspection SET status=%s WHERE id=%s", (status, alert_id))
        except Exception:
            pass

    def set_yara_status(self, alert_id, status):
        if not self._connected:
            return
        try:
            self._execute("UPDATE yara_alerts SET status=%s WHERE id=%s", (status, alert_id))
        except Exception:
            pass

    # v5.0.3: NetFlow methods were missing from the PG backend (AttributeError on PG).
    def insert_netflow_flow(self, f):
        if not self._connected:
            return
        try:
            self._execute(
                "INSERT INTO netflow_flows (exporter_ip, src_ip, dst_ip, src_port, dst_port, "
                "protocol, tcp_flags, packets, bytes, first, last) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (f.get("exporter_ip", ""), f.get("src_ip", ""), f.get("dst_ip", ""),
                 f.get("src_port", 0), f.get("dst_port", 0), f.get("protocol", 0),
                 f.get("tcp_flags", 0), f.get("packets", 0), f.get("bytes", 0),
                 f.get("first", 0), f.get("last", 0)))
        except Exception:
            pass

    def batch_insert_netflow(self, flows):
        # v5.0.3: batch insert NetFlow flows.
        if not self._connected or not flows:
            return
        try:
            sql = ('INSERT INTO netflow_flows (exporter_ip, src_ip, dst_ip, src_port, dst_port, '
                   'protocol, tcp_flags, packets, bytes, first, last) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)')
            params = [(f.get("exporter_ip", ""), f.get("src_ip", ""), f.get("dst_ip", ""),
                       f.get("src_port", 0), f.get("dst_port", 0), f.get("protocol", 0),
                       f.get("tcp_flags", 0), f.get("packets", 0), f.get("bytes", 0),
                       f.get("first", 0), f.get("last", 0)) for f in flows]
            self._executemany(sql, params)
        except Exception:
            for f in flows:
                try:
                    self.insert_netflow_flow(f)
                except Exception:
                    pass

    def get_netflow_flows(self, limit=100, since_hours=None):
        if not self._connected:
            return []
        try:
            q = "SELECT * FROM netflow_flows WHERE 1=1"
            p = []
            if since_hours:
                # concatenation + cast avoids psycopg2 %s-inside-quotes bug
                q += " AND received_at >= NOW() - (%s || ' hours')::INTERVAL"
                p.append(str(since_hours))
            q += " ORDER BY id DESC LIMIT %s"
            p.append(int(limit))
            return self._execute(q, tuple(p), fetchall=True) or []
        except Exception:
            return []

    # Revocation
    def revoke_machine(self, machine_id):
        if not self._connected:
            return
        try:
            self._execute("UPDATE machines SET is_revoked=1 WHERE machine_id=%s", (machine_id,))
        except Exception:
            pass

    def unrevoke_machine(self, machine_id):
        if not self._connected:
            return
        try:
            self._execute("UPDATE machines SET is_revoked=0 WHERE machine_id=%s", (machine_id,))
        except Exception:
            pass

    def is_machine_revoked(self, machine_id):
        if not self._connected:
            return False
        try:
            r = self._execute("SELECT is_revoked FROM machines WHERE machine_id=%s", (machine_id,), fetch=True)
            return bool(r.get("is_revoked", 0)) if r else False
        except Exception:
            return False

    def verify_enrollment_token(self, machine_id, token):
        """Enrollment verification - mirrors the SQLite backend (constant-time,
        never accepts the raw shared secret)."""
        import hmac as _hmac
        ENROLLMENT_SECRET = os.environ.get("GIAMSAT_ENROLLMENT_SECRET", "")
        # v4.10 (HIGH-13): fail-closed if the secret is missing or still the
        # public source default - the known value must never be usable.
        if not ENROLLMENT_SECRET or ENROLLMENT_SECRET == "change-me-enroll-secret":
            print("[!] AUTH: Enrollment disabled - GIAMSAT_ENROLLMENT_SECRET missing or default (set a random secret).")
            return False
        import hashlib
        expected = hashlib.sha256(f"{machine_id}:{ENROLLMENT_SECRET}".encode()).hexdigest()[:16]
        if _hmac.compare_digest(token or "", expected):
            return True
        if not self._connected:
            return False
        try:
            r = self._execute("SELECT enrollment_token FROM machines WHERE machine_id=%s", (machine_id,), fetch=True)
            return bool(r and _hmac.compare_digest(r.get("enrollment_token") or "", token or ""))
        except Exception:
            return False

    def issue_enrollment_token(self, machine_id):
        """Return the existing per-machine enrollment token, or issue a new one."""
        if not self._connected:
            return ""
        try:
            r = self._execute("SELECT enrollment_token FROM machines WHERE machine_id=%s", (machine_id,), fetch=True)
            if r and r.get("enrollment_token"):
                return r["enrollment_token"]
        except Exception:
            pass
        import uuid as _uuid
        import hashlib as _hashlib
        token = _hashlib.sha256(f"{machine_id}:{_uuid.uuid4().hex}".encode()).hexdigest()[:32]
        try:
            self._execute("UPDATE machines SET enrollment_token=%s WHERE machine_id=%s", (token, machine_id))
        except Exception:
            pass
        return token

    # =========================================================================
    # v4.4: Asset Management (Tài sản)
    # =========================================================================

    def _compute_asset_id(self, raw_string):
        """Generate a 32-char hex asset_id using MD5."""
        import hashlib
        return hashlib.md5(raw_string.encode("utf-8")).hexdigest()

    def _generate_display_id(self, prefix, table_name):
        """Generate unique display_id using first 8 chars of asset_id hash.
        Avoids race condition and duplicates from sequential numbering."""
        import uuid
        return f"{prefix}-{uuid.uuid4().hex[:8].upper()}"

    def _compute_hardware_hash(self, config_data):
        """Compute SHA256 hash of critical hardware fields for change detection."""
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
        """Compute SHA256 hash for monitor identification."""
        import hashlib
        s = f"{mon.get('manufacturer','')}|{mon.get('name','')}|{mon.get('resolution','')}"
        return hashlib.sha256(s.encode()).hexdigest()

    def insert_machine_config(self, machine_id, config_data, user_info=None):
        """Process machine_config from agent into assets tables.
        Detects hardware changes and monitor relation changes, creates alerts.
        Returns dict with changes detected."""
        if not self._connected:
            return {}
        
        import hashlib
        hostname = config_data.get("hostname", "")
        user_info = user_info or {}
        
        # === COMPUTER ASSET ===
        mb = config_data.get("motherboard", {})
        mb_serial = mb.get("serial", "").strip()
        # Fallback if no motherboard serial
        if not mb_serial:
            mb_serial = f"{machine_id}_{hostname}"
        
        # v4.5.1 FIX: asset_id based solely on motherboard_serial (not machine_id)
        # This ensures the same physical PC is recognized even after agent reinstall
        # (which generates a new machine_id)
        computer_asset_id = self._compute_asset_id(mb_serial)
        hardware_hash = self._compute_hardware_hash(config_data)
        
        os_info = config_data.get("os", {})
        cpu = config_data.get("cpu", {})
        ram = config_data.get("ram", {})
        bios = config_data.get("bios", {})
        
        changes = []
        
        try:
            # Check existing computer record by asset_id (mb_serial-based)
            existing = self._execute(
                "SELECT asset_id, hardware_hash, display_id FROM assets_computers WHERE asset_id=%s",
                (computer_asset_id,), fetch=True
            )
            
            # v4.5.1 FIX: Also check by motherboard_serial for cross-machine_id duplicates
            if not existing and mb_serial and mb_serial != "0":
                existing = self._execute(
                    "SELECT asset_id, hardware_hash, display_id FROM assets_computers WHERE motherboard_serial=%s ORDER BY id LIMIT 1",
                    (mb_serial,), fetch=True
                )
                if existing:
                    # Found existing asset with same motherboard but different asset_id (old logic).
                    # Reuse the existing asset_id and update machine_id.
                    computer_asset_id = existing["asset_id"]
                    print(f"[*] Assets: Reusing existing asset {computer_asset_id[:12]}... for new machine_id {machine_id} (same mb_serial {mb_serial[:20]})")
            existing_display_id = existing.get("display_id", "") if existing else ""
            
            if existing:
                old_hash = existing.get("hardware_hash", "")
                if old_hash and old_hash != hardware_hash:
                    # Hardware change detected!
                    old_data = self._execute(
                        "SELECT cpu_name, ram_total_gb, disks_json, gpu_json, ram_sticks_json FROM assets_computers WHERE asset_id=%s",
                        (computer_asset_id,), fetch=True
                    )
                    detail = {
                        "computer": hostname or machine_id,
                        "old_hash": old_hash[:16],
                        "new_hash": hardware_hash[:16],
                    }
                    # Compute what changed
                    if old_data:
                        try:
                            old_cpu = old_data.get("cpu_name", "")
                            new_cpu = cpu.get("name", "")
                            if old_cpu != new_cpu:
                                detail["cpu_changed"] = f"{old_cpu} → {new_cpu}"
                            
                            old_ram = old_data.get("ram_total_gb", 0)
                            new_ram = ram.get("total_gb", 0)
                            if old_ram != new_ram:
                                detail["ram_changed"] = f"{old_ram}GB → {new_ram}GB"
                            
                            old_disks = old_data.get("disks_json", [])
                            new_disks = config_data.get("disks", [])
                            if isinstance(old_disks, str):
                                try: old_disks = json.loads(old_disks)
                                except: old_disks = []
                            old_disk_models = {d.get("model","") for d in old_disks}
                            new_disk_models = {d.get("model","") for d in new_disks}
                            if old_disk_models != new_disk_models:
                                detail["disks_changed"] = f"Old: {old_disk_models}, New: {new_disk_models}"
                        except Exception:
                            pass
                    
                    self._execute(
                        """INSERT INTO assets_change_log (asset_id, asset_type, change_type, old_hash, new_hash, details)
                           VALUES (%s, 'computer', 'hardware_changed', %s, %s, %s)""",
                        (computer_asset_id, old_hash, hardware_hash, json.dumps(detail, ensure_ascii=False))
                    )
                    changes.append({
                        "type": "hardware_changed",
                        "asset_id": computer_asset_id,
                        "asset_type": "computer",
                        "details": detail
                    })
            
            # Generate display_id if empty
            if not existing_display_id:
                existing_display_id = self._generate_display_id("PC", "assets_computers")
                self._execute("UPDATE assets_computers SET display_id=%s WHERE asset_id=%s",
                              (existing_display_id, computer_asset_id))
            
            # Upsert computer
            self._execute(
                """INSERT INTO assets_computers (asset_id, machine_id, hostname,
                   user_name, employee_id, email,
                   os_name, os_version,
                   motherboard_manufacturer, motherboard_product, motherboard_serial,
                   bios_manufacturer, bios_version,
                   cpu_name, cpu_cores, cpu_max_clock_mhz,
                   ram_total_gb, ram_sticks_json, disks_json, gpu_json, monitors_json,
                   installed_software_json, printer_json,
                   hardware_hash, last_seen, updated_at, is_online)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW(),NOW(),TRUE)
                ON CONFLICT(asset_id) DO UPDATE SET
                   machine_id=EXCLUDED.machine_id, hostname=EXCLUDED.hostname,
                   user_name=EXCLUDED.user_name, employee_id=EXCLUDED.employee_id, email=EXCLUDED.email,
                   os_name=EXCLUDED.os_name, os_version=EXCLUDED.os_version,
                   motherboard_manufacturer=EXCLUDED.motherboard_manufacturer,
                   motherboard_product=EXCLUDED.motherboard_product,
                   motherboard_serial=EXCLUDED.motherboard_serial,
                   bios_manufacturer=EXCLUDED.bios_manufacturer, bios_version=EXCLUDED.bios_version,
                   cpu_name=EXCLUDED.cpu_name, cpu_cores=EXCLUDED.cpu_cores,
                   cpu_max_clock_mhz=EXCLUDED.cpu_max_clock_mhz,
                   ram_total_gb=EXCLUDED.ram_total_gb,
                   ram_sticks_json=EXCLUDED.ram_sticks_json,
                   disks_json=EXCLUDED.disks_json,
                   gpu_json=EXCLUDED.gpu_json,
                   monitors_json=EXCLUDED.monitors_json,
                   installed_software_json=EXCLUDED.installed_software_json,
                   printer_json=EXCLUDED.printer_json,
                   hardware_hash=EXCLUDED.hardware_hash,
                   last_seen=NOW(), updated_at=NOW(), is_online=TRUE
                """,
                (
                    computer_asset_id, machine_id, hostname,
                    user_info.get("user_name", "")[:128],
                    user_info.get("employee_id", "")[:64],
                    user_info.get("email", "")[:128],
                    os_info.get("name", "")[:64],
                    os_info.get("version", "")[:64],
                    mb.get("manufacturer", "")[:128],
                    mb.get("product", "")[:128],
                    mb_serial[:128],
                    bios.get("manufacturer", "")[:128],
                    bios.get("version", "")[:64],
                    cpu.get("name", "")[:256],
                    int(cpu.get("cores", 0) or 0),
                    int(cpu.get("max_clock_speed_mhz", 0) or 0),
                    float(ram.get("total_gb", 0) or 0),
                    json.dumps(ram.get("sticks", []), ensure_ascii=False),
                    json.dumps(config_data.get("disks", []), ensure_ascii=False),
                    json.dumps(config_data.get("gpu", []), ensure_ascii=False),
                    json.dumps(config_data.get("monitors", []), ensure_ascii=False),
                    json.dumps(config_data.get("installed_software", []), ensure_ascii=False),
                    json.dumps(config_data.get("printers", []), ensure_ascii=False),
                    hardware_hash,
                )
            )
            
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
                model_type = mon.get("type", "Monitor")[:64]
                current_monitor_ids.add(monitor_asset_id)
                
                # Check if this monitor already exists
                existing_mon = self._execute(
                    "SELECT asset_id, monitor_hash FROM assets_monitors WHERE asset_id=%s",
                    (monitor_asset_id,), fetch=True
                )
                
                if not existing_mon:
                    # New monitor
                    self._execute(
                        """INSERT INTO assets_monitors (asset_id, name, manufacturer, model_type, resolution, monitor_hash)
                           VALUES (%s,%s,%s,%s,%s,%s)
                           ON CONFLICT(asset_id) DO NOTHING""",
                        (monitor_asset_id, name[:256], mfr[:128], model_type, res[:32], monitor_hash)
                    )
                
                # Check relation: is this monitor previously connected to a DIFFERENT computer?
                existing_rel = self._execute(
                    "SELECT computer_asset_id FROM assets_relations WHERE monitor_asset_id=%s ORDER BY last_seen DESC LIMIT 1",
                    (monitor_asset_id,), fetch=True
                )
                
                if existing_rel:
                    prev_computer = existing_rel.get("computer_asset_id", "")
                    if prev_computer and prev_computer != computer_asset_id:
                        # Monitor reassigned to a different computer!
                        # Get old computer info
                        old_pc = self._execute(
                            "SELECT hostname, user_name FROM assets_computers WHERE asset_id=%s",
                            (prev_computer,), fetch=True
                        )
                        old_name = old_pc.get("hostname", prev_computer) if old_pc else prev_computer
                        new_name = hostname or machine_id
                        detail = {
                            "monitor": f"{mfr} {name}" if mfr else name,
                            "from_computer": old_name,
                            "to_computer": new_name,
                        }
                        self._execute(
                            """INSERT INTO assets_change_log (asset_id, asset_type, change_type, details)
                               VALUES (%s, 'monitor', 'monitor_reassigned', %s)""",
                            (monitor_asset_id, json.dumps(detail, ensure_ascii=False))
                        )
                        changes.append({
                            "type": "monitor_reassigned",
                            "asset_id": monitor_asset_id,
                            "asset_type": "monitor",
                            "details": detail
                        })
                
                # Upsert relation
                self._execute(
                    """INSERT INTO assets_relations (computer_asset_id, monitor_asset_id, last_seen)
                       VALUES (%s,%s,NOW())
                       ON CONFLICT(computer_asset_id, monitor_asset_id) DO UPDATE SET last_seen=NOW()""",
                    (computer_asset_id, monitor_asset_id)
                )
            
            # Check for monitors that were previously connected to this computer but now are NOT
            if current_monitor_ids:
                old_relations = self._execute(
                    "SELECT monitor_asset_id FROM assets_relations WHERE computer_asset_id=%s",
                    (computer_asset_id,), fetchall=True
                ) or []
                old_monitor_ids = {r["monitor_asset_id"] for r in old_relations}
                missing_monitors = old_monitor_ids - current_monitor_ids
                for missing_id in missing_monitors:
                    mon_info = self._execute(
                        "SELECT name, manufacturer FROM assets_monitors WHERE asset_id=%s",
                        (missing_id,), fetch=True
                    )
                    if mon_info:
                        mfr = mon_info.get("manufacturer", "")
                        mname = mon_info.get("name", "")
                        detail = {
                            "computer": hostname or machine_id,
                            "monitor": f"{mfr} {mname}" if mfr else mname,
                            "action": "disconnected",
                        }
                        self._execute(
                            """INSERT INTO assets_change_log (asset_id, asset_type, change_type, details)
                               VALUES (%s, 'computer', 'monitor_disconnected', %s)""",
                            (computer_asset_id, json.dumps(detail, ensure_ascii=False))
                        )
                        changes.append({
                            "type": "monitor_disconnected",
                            "asset_id": computer_asset_id,
                            "asset_type": "computer",
                            "details": detail
                        })
            
            # v4.8: auto-register USB printers as auto assets
            # v4.10: only printers the agent confirms are currently connected are reported,
            # and printers that disappeared from the config get removed below.
            try:
                import hashlib as _hl
                current_usb_names = set()
                for pr in (config_data.get("printers", []) or []):
                    if not isinstance(pr, dict) or pr.get("connection") != "usb":
                        continue
                    pr_name = (pr.get("name") or "").strip()
                    if not pr_name:
                        continue
                    current_usb_names.add(pr_name)
                    usb_key = f"usbprinter|{hostname or machine_id}|{pr_name}"
                    self._execute("""INSERT INTO assets_inventory (
                        asset_id, display_id, category, name, brand, model,
                        serial_number, asset_tag, status, assigned_to, computer_asset_id,
                        ip_address, mac_address, location, purchase_date, warranty_until,
                        cost, quantity, notes, source, extra_json, updated_at)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW())
                        ON CONFLICT(asset_id) DO UPDATE SET
                        name=EXCLUDED.name, model=EXCLUDED.model, status=EXCLUDED.status,
                        assigned_to=EXCLUDED.assigned_to, source=EXCLUDED.source,
                        extra_json=EXCLUDED.extra_json, updated_at=NOW()""",
                        (_hl.md5(usb_key.encode("utf-8")).hexdigest(),
                         _hl.md5(("disp|" + usb_key).encode("utf-8")).hexdigest()[:8].upper(),
                         "printer", pr_name, "", pr_name, "", "", "assigned",
                         hostname or machine_id, computer_asset_id, "", "", "", "", "",
                         0, 1, "USB printer (auto)", "auto",
                         json.dumps({"port": pr.get("port", ""), "driver": pr.get("driver", ""),
                                     "connected": True,
                                     "connected_at": time.strftime("%Y-%m-%d %H:%M:%S")}, ensure_ascii=False)))
                # v4.10: remove auto USB printer assets for this computer that are no
                # longer reported (printer unplugged / not in this machine_config anymore).
                stale = self._execute(
                    "SELECT asset_id, name FROM assets_inventory "
                    "WHERE computer_asset_id=%s AND category='printer' AND source='auto'",
                    (computer_asset_id,), fetch=True)
                for row in (stale or []):
                    an = (row.get("name") or "").strip()
                    if an and an not in current_usb_names:
                        self._execute("DELETE FROM assets_inventory WHERE asset_id=%s", (row["asset_id"],))
                        detail = {"computer": hostname or machine_id, "printer": an, "action": "disconnected"}
                        self._execute("INSERT INTO assets_change_log (asset_id, asset_type, change_type, details) "
                                      "VALUES (%s,'printer','printer_disconnected',%s)",
                                      (row["asset_id"], json.dumps(detail, ensure_ascii=False)))
                        changes.append({"type": "printer_disconnected", "asset_id": row["asset_id"],
                                        "asset_type": "printer", "details": detail})
            except Exception as _pe:
                print(f"[-] PG usb-printer asset: {_pe}")

            # v4.9: auto-sync 'user' assets from computer user info
            try:
                self.sync_user_assets()
            except Exception as _se:
                print(f"[-] PG sync_user_assets: {_se}")

            return {"computer_asset_id": computer_asset_id, "changes": changes}
            
        except Exception as e:
            print(f"[-] PG insert_machine_config: {e}")
            import traceback
            traceback.print_exc()
            return {}

    def get_asset_computers(self, search=None, limit=200):
        """Get all computer assets with optional search."""
        if not self._connected:
            return []
        try:
            q = "SELECT * FROM assets_computers WHERE 1=1"
            params = []
            if search:
                q += " AND (hostname ILIKE %s OR user_name ILIKE %s OR employee_id ILIKE %s OR cpu_name ILIKE %s OR motherboard_serial ILIKE %s OR display_id ILIKE %s OR email ILIKE %s)"
                s = f"%{search}%"
                params.extend([s, s, s, s, s, s, s])
            q += " ORDER BY last_seen DESC LIMIT %s"
            params.append(limit)
            rows = self._execute(q, tuple(params), fetchall=True) or []
            # Parse JSONB fields
            for r in rows:
                for field in ["ram_sticks_json", "disks_json", "gpu_json", "monitors_json",
                              "installed_software_json", "printer_json"]:
                    val = r.get(field)
                    if isinstance(val, str):
                        try: r[field] = json.loads(val)
                        except: r[field] = []
            return rows
        except Exception as e:
            print(f"[-] PG get_asset_computers: {e}")
            return []

    def get_asset_monitors(self, search=None, limit=200):
        """Get all monitor assets with optional search."""
        if not self._connected:
            return []
        try:
            q = """SELECT m.*, r.computer_asset_id, c.hostname as computer_hostname, c.user_name as computer_user
                   FROM assets_monitors m
                   LEFT JOIN assets_relations r ON m.asset_id = r.monitor_asset_id
                   LEFT JOIN assets_computers c ON r.computer_asset_id = c.asset_id
                   WHERE 1=1"""
            params = []
            if search:
                q += " AND (m.name ILIKE %s OR m.manufacturer ILIKE %s)"
                s = f"%{search}%"
                params.extend([s, s])
            q += " ORDER BY m.updated_at DESC LIMIT %s"
            params.append(limit)
            return self._execute(q, tuple(params), fetchall=True) or []
        except Exception as e:
            print(f"[-] PG get_asset_monitors: {e}")
            return []

    def get_asset_change_log(self, limit=100, unresolved_only=False):
        """Get asset change log. If unresolved_only=True, only return unresolved entries."""
        if not self._connected:
            return []
        try:
            q = "SELECT * FROM assets_change_log WHERE 1=1"
            params = []
            if unresolved_only:
                q += " AND is_resolved=FALSE"
            q += " ORDER BY created_at DESC LIMIT %s"
            params.append(limit)
            rows = self._execute(q, tuple(params), fetchall=True) or []
            for r in rows:
                val = r.get("details")
                if isinstance(val, str):
                    try: r["details"] = json.loads(val)
                    except: pass
            return rows
        except Exception as e:
            print(f"[-] PG get_asset_change_log: {e}")
            return []

    def resolve_asset_change(self, change_id, resolved_by="admin"):
        """Mark an asset change as resolved."""
        if not self._connected:
            return False
        try:
            self._execute(
                "UPDATE assets_change_log SET is_resolved=TRUE, resolved_by=%s, resolved_at=NOW() WHERE id=%s",
                (resolved_by[:128], change_id)
            )
            return True
        except Exception:
            return False

    # =========================================================================
    # v4.7: IT asset inventory (manual + auto-discovered)
    # =========================================================================

    def get_asset_inventory(self, category=None, status=None, source=None, search=None, limit=500):
        if not self._connected:
            return []
        try:
            q = "SELECT * FROM assets_inventory WHERE 1=1"
            p = []
            if category:
                q += " AND category=%s"; p.append(category)
            if status:
                q += " AND status=%s"; p.append(status)
            if source:
                q += " AND source=%s"; p.append(source)
            if search:
                q += " AND (name ILIKE %s OR brand ILIKE %s OR model ILIKE %s OR serial_number ILIKE %s OR asset_tag ILIKE %s OR assigned_to ILIKE %s OR display_id ILIKE %s OR ip_address ILIKE %s)"
                s = f"%{search}%"; p.extend([s]*8)
            q += " ORDER BY updated_at DESC LIMIT %s"; p.append(limit)
            rows = self._execute(q, tuple(p), fetchall=True) or []
            for r in rows:
                val = r.get("extra_json")
                if isinstance(val, dict):
                    r["extra"] = val
                elif isinstance(val, str):
                    try: r["extra"] = json.loads(val)
                    except: r["extra"] = {}
            return rows
        except Exception as e:
            print(f"[-] PG get_asset_inventory: {e}")
            return []

    def get_asset_inventory_stats(self):
        if not self._connected:
            return {"by_category": [], "by_status": [], "total": 0}
        try:
            by_category = self._execute("SELECT category, COUNT(*) as cnt FROM assets_inventory GROUP BY category", fetchall=True) or []
            by_status = self._execute("SELECT status, COUNT(*) as cnt FROM assets_inventory GROUP BY status", fetchall=True) or []
            row = self._execute("SELECT COUNT(*) as cnt FROM assets_inventory", fetch=True)
            return {"by_category": by_category, "by_status": by_status,
                    "total": row.get("cnt", 0) if row else 0}
        except Exception as e:
            print(f"[-] PG get_asset_inventory_stats: {e}")
            return {"by_category": [], "by_status": [], "total": 0}

    def _inventory_asset_id(self, data):
        import hashlib, uuid
        asset_id = (data.get("asset_id") or "").strip()
        if asset_id:
            return asset_id
        display_id = (data.get("display_id") or "").strip()
        category = (data.get("category") or "other").strip()
        if display_id:
            return hashlib.md5(f"inv|{category}|{display_id}".encode("utf-8")).hexdigest()
        return hashlib.md5(f"inv|{category}|{uuid.uuid4()}".encode("utf-8")).hexdigest()

    def _new_display_id(self, category):
        import uuid
        prefix = {"printer": "PR", "phone": "DT", "network_device": "NM",
                  "peripheral": "NV", "component": "LK", "other": "TS"}.get(category, "TS")
        return f"TS-{prefix}-{uuid.uuid4().hex[:6].upper()}"

    def upsert_inventory_asset(self, data):
        import json as _json
        extra = data.get("extra") or {}
        asset_id = self._inventory_asset_id(data)
        display_id = (data.get("display_id") or "").strip() or self._new_display_id(data.get("category") or "other")
        try:
            self._execute("""INSERT INTO assets_inventory (
                asset_id, display_id, category, name, brand, model,
                serial_number, asset_tag, email, employee_id, status, assigned_to, computer_asset_id,
                ip_address, mac_address, location, purchase_date, warranty_until,
                cost, quantity, notes, source, extra_json, updated_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW())
                ON CONFLICT(asset_id) DO UPDATE SET
                display_id=EXCLUDED.display_id, category=EXCLUDED.category, name=EXCLUDED.name,
                brand=EXCLUDED.brand, model=EXCLUDED.model, serial_number=EXCLUDED.serial_number,
                asset_tag=EXCLUDED.asset_tag, email=EXCLUDED.email, employee_id=EXCLUDED.employee_id,
                status=EXCLUDED.status, assigned_to=EXCLUDED.assigned_to,
                computer_asset_id=EXCLUDED.computer_asset_id, ip_address=EXCLUDED.ip_address,
                mac_address=EXCLUDED.mac_address, location=EXCLUDED.location,
                purchase_date=EXCLUDED.purchase_date, warranty_until=EXCLUDED.warranty_until,
                cost=EXCLUDED.cost, quantity=EXCLUDED.quantity, notes=EXCLUDED.notes, source=EXCLUDED.source,
                extra_json=EXCLUDED.extra_json, updated_at=NOW()""",
                (asset_id, display_id, data.get("category") or "other", data.get("name") or "",
                 data.get("brand") or "", data.get("model") or "", data.get("serial_number") or "",
                 data.get("asset_tag") or "", data.get("email") or "", data.get("employee_id") or "",
                 data.get("status") or "in_stock",
                 data.get("assigned_to") or "", data.get("computer_asset_id") or "",
                 data.get("ip_address") or "", data.get("mac_address") or "", data.get("location") or "",
                 data.get("purchase_date") or "", data.get("warranty_until") or "",
                 float(data.get("cost") or 0), int(data.get("quantity") or 1),
                 data.get("notes") or "", data.get("source") or "manual",
                 _json.dumps(extra, ensure_ascii=False)))
            return {"asset_id": asset_id, "display_id": display_id}
        except Exception as e:
            print(f"[-] PG upsert_inventory_asset: {e}")
            return {}

    def delete_inventory_asset(self, asset_id):
        try:
            rc = self._execute("DELETE FROM assets_inventory WHERE asset_id=%s", (asset_id,))
            return rc > 0
        except Exception:
            return False

    def adopt_inventory_asset(self, asset_id, data=None):
        data = data or {}
        sets = ["source='manual'", "updated_at=NOW()"]
        p = []
        for col in ["assigned_to", "location", "asset_tag", "status", "notes", "category"]:
            if col in data:
                sets.append(f"{col}=%s")
                p.append(data[col])
        p.append(asset_id)
        try:
            rc = self._execute("UPDATE assets_inventory SET " + ", ".join(sets) + " WHERE asset_id=%s", tuple(p))
            return rc > 0
        except Exception:
            return False

    def sync_user_assets(self):
        """v4.9: auto-create 'user' asset rows from computers (full name, employee id, email)."""
        if not self._connected:
            return 0
        import hashlib
        created = 0
        try:
            rows = self._execute(
                "SELECT DISTINCT c.user_name, c.employee_id, c.email, mu.branch "
                "FROM assets_computers c "
                "LEFT JOIN machine_users mu ON mu.machine_id = c.machine_id "
                "WHERE (c.email <> '' OR c.user_name <> '')", fetchall=True) or []
            for name, emp, mail, branch in rows:
                name = (name or "").strip()
                emp = (emp or "").strip()
                mail = (mail or "").strip().lower()
                branch = (branch or "").strip()
                if not mail and not name:
                    continue
                key = "user|" + (mail or name)
                aid = hashlib.md5(key.encode("utf-8")).hexdigest()
                disp = hashlib.md5(("disp|" + key).encode("utf-8")).hexdigest()[:8].upper()
                self._execute("""INSERT INTO assets_inventory (
                    asset_id, display_id, category, name, email, employee_id,
                    location, status, source, notes, quantity, updated_at)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,1,NOW())
                    ON CONFLICT(asset_id) DO UPDATE SET
                    name=EXCLUDED.name, email=EXCLUDED.email, employee_id=EXCLUDED.employee_id,
                    location=EXCLUDED.location, updated_at=NOW()""",
                    (aid, disp, "user", name, mail, emp, branch, "active", "auto", "auto-synced from assets"))
                created += 1
        except Exception as e:
            print(f"[-] PG sync_user_assets: {e}")
        return created

