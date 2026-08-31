#!/usr/bin/env python
"""GIAM-SAT delete_machine Regression Tests (v5.0.4).
Verifies deleting a machine purges machine-scoped tables PLUS the asset
registry (assets_computers/assets_monitors/assets_relations/assets_inventory/
assets_change_log) so the Assets dashboard no longer shows configs of deleted
machines. Usage: python tests/delete_machine_tests.py
Exit code 0 = all passed, 1 = failures found."""

import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "server"))
import db_manager as dm


def _make_db():
    """Fresh DatabaseManager against a temp SQLite file."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    dm.DB_PATH = path
    db = dm.DatabaseManager()
    # assets_* tables are created lazily by insert_machine_config() on the real
    # server; create the same columns here so delete_machine can be tested.
    db.conn.execute("""CREATE TABLE IF NOT EXISTS assets_computers (
        id INTEGER PRIMARY KEY AUTOINCREMENT, asset_id TEXT UNIQUE,
        machine_id TEXT, hostname TEXT, display_id TEXT DEFAULT '',
        user_name TEXT, employee_id TEXT, email TEXT, hardware_hash TEXT,
        last_seen TIMESTAMP, first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, is_online INTEGER DEFAULT 0)""")
    db.conn.execute("""CREATE TABLE IF NOT EXISTS assets_monitors (
        id INTEGER PRIMARY KEY AUTOINCREMENT, asset_id TEXT UNIQUE,
        display_id TEXT DEFAULT '', name TEXT, manufacturer TEXT,
        model_type TEXT, resolution TEXT, monitor_hash TEXT,
        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
    db.conn.execute("""CREATE TABLE IF NOT EXISTS assets_relations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        computer_asset_id TEXT, monitor_asset_id TEXT,
        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(computer_asset_id, monitor_asset_id))""")
    db.conn.execute("""CREATE TABLE IF NOT EXISTS assets_inventory (
        id INTEGER PRIMARY KEY AUTOINCREMENT, asset_id TEXT UNIQUE,
        display_id TEXT DEFAULT '', category TEXT, name TEXT,
        computer_asset_id TEXT, source TEXT DEFAULT 'manual',
        quantity INTEGER DEFAULT 1, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
    db.conn.execute("""CREATE TABLE IF NOT EXISTS assets_change_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT, asset_id TEXT,
        asset_type TEXT, change_type TEXT,
        old_hash TEXT DEFAULT '', new_hash TEXT DEFAULT '',
        details TEXT DEFAULT '{}', is_resolved INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)""")
    db.conn.commit()
    return db, path


def _cnt(db, table):
    return db.conn.execute(f"SELECT COUNT(*) c FROM {table}").fetchone()[0]


def main():
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL") + "  " + name)
        if not cond:
            failures.append(name)

    db, path = _make_db()
    try:
        # Scenario 1: full purge of machine-scoped rows + asset registry
        mid = "PC-OLD-001"
        db.conn.execute("INSERT INTO machines (machine_id,hostname,ip_address) VALUES (?,?,?)",
                        (mid, "old-host", "10.0.0.9"))
        db.conn.execute("INSERT INTO events (machine_id,hostname) VALUES (?,?)", (mid, "old-host"))
        db.conn.execute("INSERT INTO sysmon_events (machine_id,hostname) VALUES (?,?)", (mid, "old-host"))
        db.conn.execute("INSERT INTO sca_events (machine_id,hostname) VALUES (?,?)", (mid, "old-host"))
        db.conn.execute("INSERT INTO policy_apply_status (policy_id,machine_id,status) VALUES (?,?,?)", ("POL-1", mid, "ok"))
        db.conn.execute("INSERT INTO machine_users (machine_id,user_name) VALUES (?,?)", (mid, "u1"))
        db.conn.execute("INSERT INTO alert_suppression (rule_id,machine_id,field_path) VALUES (?,?,?)",
                        ("R1", mid, "hostname"))
        db.conn.execute("INSERT INTO messages (msg_id,machine_id,sender,title) VALUES (?,?,?,?)",
                        ("M1", mid, "server", "hello"))
        db.conn.execute("INSERT INTO assets_computers (asset_id,machine_id,hostname,display_id) VALUES (?,?,?,?)",
                        ("A-PC1", mid, "old-host", "PC-OLD1"))
        db.conn.execute("INSERT INTO assets_computers (asset_id,machine_id,hostname,display_id) VALUES (?,?,?,?)",
                        ("A-PC2", mid, "old-host2", "PC-OLD2"))
        db.conn.execute("INSERT INTO assets_monitors (asset_id,name,display_id) VALUES (?,?,?)",
                        ("MON1", "Dell U2419", "MN-1"))
        db.conn.execute("INSERT INTO assets_monitors (asset_id,name,display_id) VALUES (?,?,?)",
                        ("MON2", "Samsung S24", "MN-2"))
        db.conn.execute("INSERT INTO assets_relations (computer_asset_id,monitor_asset_id) VALUES (?,?)",
                        ("A-PC1", "MON1"))
        db.conn.execute("INSERT INTO assets_relations (computer_asset_id,monitor_asset_id) VALUES (?,?)",
                        ("A-PC2", "MON2"))
        db.conn.execute("""INSERT INTO assets_inventory (asset_id,display_id,category,name,computer_asset_id,source)
                           VALUES (?,?,?,?,?,?)""",
                        ("INV1", "USB-1", "printer", "PrinterX", "A-PC1", "auto"))
        db.conn.execute("""INSERT INTO assets_change_log (asset_id,asset_type,change_type,details)
                           VALUES (?,?,?,?)""", ("A-PC1", "computer", "hardware_changed", "{}"))
        db.conn.execute("""INSERT INTO assets_change_log (asset_id,asset_type,change_type,details)
                           VALUES (?,?,?,?)""", ("INV1", "printer", "printer_disconnected", "{}"))
        db.conn.commit()

        db.delete_machine(mid)


        check("machines purged", _cnt(db, "machines") == 0)
        check("events purged", _cnt(db, "events") == 0)
        check("sysmon_events purged", _cnt(db, "sysmon_events") == 0)
        check("sca_events purged", _cnt(db, "sca_events") == 0)
        check("policy_apply_status purged", _cnt(db, "policy_apply_status") == 0)
        check("machine_users purged", _cnt(db, "machine_users") == 0)
        check("alert_suppression purged", _cnt(db, "alert_suppression") == 0)
        check("messages purged", _cnt(db, "messages") == 0)
        check("assets_computers purged", _cnt(db, "assets_computers") == 0)
        check("assets_relations purged", _cnt(db, "assets_relations") == 0)
        check("assets_monitors purged (no relation left)", _cnt(db, "assets_monitors") == 0)
        check("assets_inventory purged", _cnt(db, "assets_inventory") == 0)
        check("assets_change_log purged", _cnt(db, "assets_change_log") == 0)

        # Scenario 2: a monitor shared with a surviving computer must be kept
        db.conn.execute("INSERT INTO machines (machine_id,hostname,ip_address) VALUES ('PC-A','a','10.0.0.1')")
        db.conn.execute("INSERT INTO machines (machine_id,hostname,ip_address) VALUES ('PC-B','b','10.0.0.2')")
        db.conn.execute("INSERT INTO assets_computers (asset_id,machine_id,hostname,display_id) VALUES ('A-A','PC-A','a','PA')")
        db.conn.execute("INSERT INTO assets_computers (asset_id,machine_id,hostname,display_id) VALUES ('A-B','PC-B','b','PB')")
        db.conn.execute("INSERT INTO assets_monitors (asset_id,name,display_id) VALUES ('MON-S','Shared 27','MS')")
        db.conn.execute("INSERT INTO assets_relations (computer_asset_id,monitor_asset_id) VALUES ('A-A','MON-S')")
        db.conn.execute("INSERT INTO assets_relations (computer_asset_id,monitor_asset_id) VALUES ('A-B','MON-S')")
        db.conn.commit()

        db.delete_machine("PC-A")

        check("shared monitor survives", _cnt(db, "assets_monitors") == 1)
        check("only survivor relation remains", _cnt(db, "assets_relations") == 1)
        check("survivor relation points to PC-B", db.conn.execute(
            "SELECT computer_asset_id FROM assets_relations").fetchone()[0] == "A-B")
    finally:
        db.conn.close()
        try:
            os.unlink(path)
        except OSError:
            pass

    if failures:
        print(f"\nFAILED: {len(failures)} check(s) failed: {failures}")
        return 1
    print("\nAll delete_machine asset-cleanup checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
