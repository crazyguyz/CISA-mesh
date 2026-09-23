#!/usr/bin/env python
"""v5.0.8 - Reset operational data, KEEP the schema (clean reinstall).

Why this exists
---------------
A fresh clone looks "dirty" because the monitoring data does NOT live in the
repo: it lives in PostgreSQL (or SQLite). Wiping the install folder and cloning
again leaves the old database untouched, so the dashboard immediately shows
machines, syslog from weeks ago, alerts and configuration from the previous
deployment. This tool clears that operational data so a reinstall starts empty.

What is kept
------------
- Schema (tables/indexes/materialized views) - the server recreates it anyway,
  this tool only DELETEs/TRUNCATEs rows.
- Dashboard accounts (users.json, encrypted) - NOT in the database.
- server/.env, logs, agents on workstations - none of them are touched.
- With --mode keep-config: watchlist, group_policies, agent_groups,
  custom_dashboards, syslog_sources (the operator's configuration).

Uses the same .env discovery as the server, so PG/SQLite are both supported.
Dry-run by default: it only reports. Nothing is deleted without --apply.

Usage:
  python tools/reset_data.py                      # dry-run, PG/SQLite from server/.env
  python tools/reset_data.py --mode keep-config   # dry-run, keep configuration tables
  python tools/reset_data.py --env D:/test/server/.env
  python tools/reset_data.py --sqlite server/giamsat_data.db
  python tools/reset_data.py --apply --yes        # actually delete (non-interactive)
"""

import argparse
import datetime
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Tables holding the operator's CONFIGURATION (kept with --mode keep-config).
CONFIG_TABLES = (
    "watchlist",
    "group_policies",
    "agent_groups",
    "custom_dashboards",
    "syslog_sources",
)

# Every table the server creates (db_postgres._init_db / db_manager). Used only to
# warn about tables we do not recognise (created by a newer build) - they are
# still cleared, we just tell the operator.
KNOWN_TABLES = (
    "agent_group_members", "agent_groups", "agent_update_log", "agentless_events",
    "alert_suppression", "assets_change_log", "assets_computers", "assets_inventory",
    "assets_monitors", "assets_relations", "audit_log", "cases", "commands",
    "custom_dashboards", "events", "fim_baseline", "fim_events", "group_policies",
    "hardware_baseline", "hardware_info", "heartbeats", "machine_uptime",
    "machine_users", "machines", "messages", "netflow_flows", "network_baseline",
    "network_inspection", "network_traffic", "policy_apply_status",
    "response_results", "sca_events", "syslog", "syslog_sources", "sysmon_events",
    "threat_alerts", "vuln_alerts", "watchlist", "yara_alerts",
)

MATVIEWS = ("mv_dashboard_machines", "mv_dashboard_stats")


def parse_env(path):
    """Parse a .env file into a dict (same rules as the server/other tools)."""
    env = {}
    if not path or not os.path.exists(path):
        return env
    for line in open(path, encoding="utf-8-sig", errors="ignore"):
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        env[k.strip()] = v.strip().strip('"').strip("'")
    return env


def find_env(explicit=None):
    """Locate server/.env: explicit --env, else <root>/server/.env, else ./server/.env."""
    candidates = []
    if explicit:
        candidates.append(explicit)
    candidates.append(os.path.join(ROOT, "server", ".env"))
    candidates.append(os.path.join(os.getcwd(), "server", ".env"))
    for c in candidates:
        if c and os.path.exists(c):
            return c
    return None


class SQLiteBackend:
    PH = "?"
    label = "sqlite"

    def __init__(self, path):
        import sqlite3
        self.path = path
        self.conn = sqlite3.connect(path)

    def describe(self):
        return "SQLite  %s" % self.path

    def tables(self):
        rows = self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%'").fetchall()
        return sorted(r[0] for r in rows)

    def count(self, table):
        try:
            return self.conn.execute('SELECT COUNT(*) FROM "%s"' % table).fetchone()[0]
        except Exception:
            return None

    def clear(self, tables):
        """Return total rows deleted, or False if a table could not be cleared."""
        total = 0
        for t in tables:
            try:
                cur = self.conn.execute('DELETE FROM "%s"' % t)
                total += cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
            except Exception as e:
                print("[-] Could not clear %s: %s" % (t, e))
        # reset AUTOINCREMENT counters so ids start from 1 again
        try:
            self.conn.execute("DELETE FROM sqlite_sequence")
        except Exception:
            pass
        self.conn.commit()
        return total

    def refresh_views(self):
        return []  # SQLite has no materialized views

    def close(self):
        self.conn.close()


class PostgresBackend:
    PH = "%s"
    label = "postgresql"

    def __init__(self, env):
        import psycopg2
        self.env = env
        self.dbname = env.get("GIAMSAT_PG_DBNAME", "giamsat")
        self.conn = psycopg2.connect(
            host=env.get("GIAMSAT_PG_HOST", "127.0.0.1"),
            port=int(env.get("GIAMSAT_PG_PORT", "5432")),
            dbname=self.dbname,
            user=env.get("GIAMSAT_PG_USER", "postgres"),
            password=env.get("GIAMSAT_PG_PASSWORD", ""),
        )
        self.conn.autocommit = True

    def describe(self):
        return "PostgreSQL  %s@%s:%s/%s" % (
            self.env.get("GIAMSAT_PG_USER", "postgres"),
            self.env.get("GIAMSAT_PG_HOST", "127.0.0.1"),
            self.env.get("GIAMSAT_PG_PORT", "5432"),
            self.dbname)

    def tables(self):
        with self.conn.cursor() as cur:
            cur.execute("SELECT table_name FROM information_schema.tables "
                        "WHERE table_schema='public' AND table_type='BASE TABLE' ORDER BY 1")
            return [r[0] for r in cur.fetchall()]

    def count(self, table):
        try:
            with self.conn.cursor() as cur:
                cur.execute('SELECT COUNT(*) FROM "%s"' % table)
                return cur.fetchone()[0]
        except Exception:
            self.conn.rollback()
            return None

    def clear(self, tables):
        if not tables:
            return 0
        # TRUNCATE is orders of magnitude faster than DELETE on high-volume tables
        # (sysmon_events/events/syslog). The schema declares no FK constraints, so
        # CASCADE is harmless; RESTART IDENTITY resets the sequences.
        stmt = 'TRUNCATE TABLE %s RESTART IDENTITY CASCADE' % ", ".join(
            '"%s"' % t for t in tables)
        try:
            with self.conn.cursor() as cur:
                cur.execute("SET lock_timeout = '10s'")
                cur.execute(stmt)
            return True
        except Exception as e:
            self.conn.rollback()
            print("[!] TRUNCATE failed (%s) - falling back to row-by-row DELETE" % e)
        total = 0
        for t in tables:
            try:
                with self.conn.cursor() as cur:
                    cur.execute('DELETE FROM "%s"' % t)
                    total += cur.rowcount or 0
            except Exception as e:
                self.conn.rollback()
                print("[-] Could not clear %s: %s" % (t, e))
        return total

    def refresh_views(self):
        """Dashboard stats are cached in materialized views - refresh them so the
        dashboard does not keep showing the counts of the data we just deleted."""
        done = []
        for mv in MATVIEWS:
            try:
                with self.conn.cursor() as cur:
                    cur.execute('REFRESH MATERIALIZED VIEW "%s"' % mv)
                done.append(mv)
            except Exception:
                self.conn.rollback()
        return done

    def close(self):
        self.conn.close()


def connect(args):
    """Return a backend, or exit with a clear message."""
    if args.sqlite:
        if not os.path.exists(args.sqlite):
            print("[-] SQLite database not found: %s" % args.sqlite)
            sys.exit(2)
        return SQLiteBackend(args.sqlite)

    env_path = find_env(args.env)
    if not env_path:
        print("[-] Could not find server/.env (looked for <root>/server/.env).")
        print("    Run server/setup/setup_config.ps1 first, or pass --env / --sqlite.")
        sys.exit(2)
    env = parse_env(env_path)
    backend = (env.get("GIAMSAT_DB_BACKEND") or "sqlite").strip().lower()
    if backend in ("postgres", "postgresql", "pg"):
        print("[*] Config: %s" % env_path)
        try:
            return PostgresBackend(env)
        except ImportError:
            print("[-] psycopg2 is not installed for this Python interpreter.")
            print("    Install it (pip install psycopg2-binary) or pass --sqlite.")
            sys.exit(2)
        except Exception as e:
            print("[-] Cannot connect to PostgreSQL: %s" % str(e)[:200])
            print("    Check GIAMSAT_PG_* in %s (or run tools\\fix_pg_auth.ps1)." % env_path)
            sys.exit(2)
    db_file = env.get("GIAMSAT_DB_PATH") or "giamsat_data.db"
    if not os.path.isabs(db_file):
        db_file = os.path.join(os.path.dirname(env_path), db_file)
    if not os.path.exists(db_file):
        print("[-] SQLite database not found: %s" % db_file)
        sys.exit(2)
    print("[*] Config: %s (backend=sqlite)" % env_path)
    return SQLiteBackend(db_file)


def main():
    ap = argparse.ArgumentParser(
        description="Clear GIAM-SAT operational data but keep the schema. "
                    "Dry-run by default.")
    ap.add_argument("--mode", choices=("all", "keep-config"), default="all",
                    help="all = wipe every table (default); "
                         "keep-config = keep watchlist/group_policies/agent_groups/"
                         "custom_dashboards/syslog_sources")
    ap.add_argument("--env", help="path to server/.env (PG connection + backend)")
    ap.add_argument("--sqlite", help="path to a SQLite database (overrides .env)")
    ap.add_argument("--apply", action="store_true",
                    help="perform the deletion (default is a dry-run report)")
    ap.add_argument("--yes", action="store_true",
                    help="skip the interactive YES confirmation (for scripts)")
    args = ap.parse_args()

    print("=" * 68)
    print("  GIAM-SAT - Reset operational data (schema is preserved)")
    print("=" * 68)

    backend = connect(args)
    print("[*] Backend: %s" % backend.describe())
    print("[*] Mode   : %s" % args.mode)

    tables = backend.tables()
    keep = [t for t in CONFIG_TABLES if t in tables] if args.mode == "keep-config" else []
    clear = [t for t in tables if t not in keep]
    unknown = [t for t in clear if t not in KNOWN_TABLES]

    print("[i] %d table(s): %d to clear, %d kept" % (len(tables), len(clear), len(keep)))
    if keep:
        print("    kept: %s" % ", ".join(keep))
    if unknown:
        print("[!] unrecognised table(s) (newer build?) - will also be cleared: %s"
              % ", ".join(unknown))
    # agent_group_members links machines -> meaningless once the machines are gone
    if args.mode == "keep-config" and "agent_group_members" in clear:
        print("[i] agent_group_members is cleared (it references the machines being removed)")

    print("-" * 68)
    total = 0
    for t in tables:
        n = backend.count(t)
        if t in keep:
            print("    %-24s %-10s  <-- keep" % (t, n if n is not None else "?"))
        else:
            if n:
                total += n
            print("    %-24s %s" % (t, n if n is not None else "?"))
    print("-" * 68)
    if total == 0:
        # In CA cau "already clean" va dong "still" o moi che do: setup_config.ps1
        # (muc [9]) dua vao 2 chuoi nay de ket luan - thieu 1 trong 2 thi no bao
        # "tim thay du lieu cu (0 dong)" hoac "khong doc duoc ket qua".
        print("[+] Database is already clean - nothing to delete.")
        print("[i] 0 row(s) still in the database.")
        backend.close()
        return 0
    print("[i] %d row(s) would be deleted" % total)

    if not args.apply:
        print("")
        print("[!] DRY RUN - nothing was changed.")
        print("    Re-run with --apply to delete (add --yes for non-interactive).")
        backend.close()
        return 0

    if not args.yes:
        print("")
        try:
            reply = input("Type YES to permanently delete these rows: ").strip()
        except EOFError:
            reply = ""
        if reply != "YES":
            print("[!] Aborted - nothing was deleted.")
            backend.close()
            return 1

    print("")
    result = backend.clear(clear)
    views = backend.refresh_views()
    # setup_config.ps1 (muc 9) doc dong nay de bao "con bao nhieu dong" - giu nguyen
    # chi dem cac bang VUA XOA: bang duoc giu (keep-config) khong phai la "con sot".
    left = sum((backend.count(t) or 0) for t in clear)
    kept_rows = sum((backend.count(t) or 0) for t in keep)
    backend.close()

    print("-" * 68)
    if result is True:
        print("[+] Done - %d table(s) truncated (%d row(s) removed)." % (len(clear), total))
    elif isinstance(result, int):
        print("[+] Done - %s row(s) of %d reported before deletion." % (result, total))
    else:
        print("[+] Done - %d table(s) processed." % len(clear))
    print("[i] %d row(s) still in the database." % left)
    if keep:
        print("[i] Kept by mode (not deleted): %d row(s) in %s." % (kept_rows, ", ".join(keep)))
    if views:
        print("[i] Refreshed %s (dashboard stats cache)." % ", ".join(views))
    print("[i] Schema kept; the server recreates anything missing on next start.")
    print("[i] Refresh / log out of the dashboard to see an empty system.")
    print("[i] Reset at %s" % datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[*] Interrupted.")
        sys.exit(130)
