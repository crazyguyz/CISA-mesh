#!/usr/bin/env python
"""GIAM-SAT asset code (display_id) regression tests - v5.0.8.

Guards the bug that made the Assets page show a mix of 8-, 11-, 13- and
32-character asset codes:

  * PostgreSQL computers: display_id was written by an UPDATE that ran before
    the INSERT, so a machine only got its code on the SECOND config report.
  * PostgreSQL monitors: display_id was never written at all.
  * the API/UI fell back to the raw 32-char md5 asset_id when the code was empty.

Every code must be `{PREFIX}-{8 hex}` (11 chars) and must be assigned on the
FIRST config report.

Usage:
  python tests/display_id_tests.py          # unit + SQLite (no server needed)
  python tests/display_id_tests.py --pg     # also runs against a THROWAWAY
                                            # PostgreSQL database (created and
                                            # dropped by the test; the real
                                            # database is never touched)
Exit code 0 = all passed, 1 = failures found.
"""

import hashlib
import os
import re
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "server"))

import asset_ids  # noqa: E402
import db_manager as dm  # noqa: E402

CODE_RE = re.compile(r"^[A-Z]{2}-[0-9A-F]{8}$")
RESULTS = []


def check(name, ok, extra=""):
    RESULTS.append((name, bool(ok)))
    line = "PASS  " + name
    if not ok and extra:
        line += "   -> " + str(extra)[:160]
    print(line)


def machine_config(hostname="TEST-PC", serial="SN-TEST-0001", cpu="Core i5-8500",
                   monitor=("DELL", "E2211H", "1920x1080")):
    mfr, mname, res = monitor
    return {
        "hostname": hostname,
        "motherboard": {"manufacturer": "ASUS", "product": "PRIME", "serial": serial},
        "bios": {"manufacturer": "AMI", "version": "1.0"},
        "os": {"name": "Windows", "version": "10 Pro"},
        "cpu": {"name": cpu, "cores": 6, "max_clock_speed_mhz": 2900},
        "ram": {"total_gb": 16.0, "sticks": [{"size_gb": 8}, {"size_gb": 8}]},
        "disks": [{"model": "Samsung 860", "size_gb": 500, "interface": "SATA"}],
        "gpu": [{"name": "Intel UHD 630", "ram_gb": 1}],
        "monitors": [{"manufacturer": mfr, "name": mname, "resolution": res,
                      "type": "Monitor"}],
        "installed_software": [],
        "printers": [],
    }


def test_unit():
    """The shared scheme itself."""
    print("\n-- unit: server/asset_ids.py --")
    codes = {}
    for cat, pfx in (("computer", "PC"), ("monitor", "MN"), ("printer", "PR"),
                     ("phone", "DT"), ("network_device", "NM"), ("peripheral", "NV"),
                     ("component", "LK"), ("user", "US"), ("other", "TS"),
                     ("something-new", "TS"), ("", "TS"), (None, "TS")):
        code = asset_ids.make_display_id(cat)
        codes[cat] = code
        check("prefix %-16s -> %s" % (cat, pfx),
              code.startswith(pfx + "-") and bool(CODE_RE.match(code)) and len(code) == 11,
              code)
    seed = "20f88bd75193daa6a4cbe8111d461163"
    a = asset_ids.make_display_id("computer", seed=seed)
    b = asset_ids.make_display_id("computer", seed=seed)
    check("deterministic with seed (same input -> same code)", a == b, "%s / %s" % (a, b))
    check("derived code matches canonical format", bool(CODE_RE.match(a)), a)
    check("derive_for_asset('monitor', id) prefix", asset_ids.derive_for_asset("monitor", seed).startswith("MN-"))
    check("derive_for_asset with empty asset_id -> ''", asset_ids.derive_for_asset("computer", "") == "")
    check("is_canonical accepts new codes", asset_ids.is_canonical("PC-0887498B"))
    check("is_canonical rejects 32-char md5", not asset_ids.is_canonical(seed))
    check("is_canonical rejects bare 8-hex (old discovery)", not asset_ids.is_canonical("01386692"))
    check("is_canonical rejects old 'TS-PR-1A2B3C'", not asset_ids.is_canonical("TS-PR-1A2B3C"))
    check("100 random codes are unique",
          len({asset_ids.make_display_id("computer") for _ in range(100)}) == 100)


def test_sqlite():
    """SQLite backend: codes exist after the FIRST report and stay stable."""
    print("\n-- sqlite: db_manager.insert_machine_config --")
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    dm.DB_PATH = path
    db = dm.DatabaseManager()
    try:
        cfg = machine_config()
        db.insert_machine_config("m-test-1", cfg, {"user_name": "Nguyen Van A",
                                                  "employee_id": "NV001",
                                                  "email": "a@example.com"})
        cur = db.conn.cursor()
        cur.execute("SELECT asset_id, hostname, display_id FROM assets_computers")
        pcs = [dict(zip(("asset_id", "hostname", "display_id"), r)) for r in cur.fetchall()]
        check("1 computer row created", len(pcs) == 1, pcs)
        pc_code = (pcs[0]["display_id"] or "") if pcs else ""
        check("computer code set on FIRST report (not blank)",
              bool(pc_code) and bool(CODE_RE.match(pc_code)), pc_code)
        check("computer code is PC-XXXXXXXX", pc_code.startswith("PC-"), pc_code)

        cur.execute("SELECT asset_id, name, display_id FROM assets_monitors")
        mons = [dict(zip(("asset_id", "name", "display_id"), r)) for r in cur.fetchall()]
        check("1 monitor row created", len(mons) == 1, mons)
        mon_code = (mons[0]["display_id"] or "") if mons else ""
        check("monitor code set on FIRST report (not blank)",
              bool(mon_code) and bool(CODE_RE.match(mon_code)), mon_code)
        check("monitor code is MN-XXXXXXXX", mon_code.startswith("MN-"), mon_code)

        # a second identical report must NOT re-generate the codes
        db.insert_machine_config("m-test-1", cfg, {"user_name": "Nguyen Van A",
                                                   "employee_id": "NV001",
                                                   "email": "a@example.com"})
        cur.execute("SELECT display_id FROM assets_computers")
        again = (cur.fetchone() or [""])[0]
        check("computer code is stable across reports", again == pc_code,
              "%s vs %s" % (again, pc_code))
        cur.execute("SELECT display_id FROM assets_monitors")
        check("monitor code is stable across reports", (cur.fetchone() or [""])[0] == mon_code)
    except Exception as e:
        check("sqlite section completed", False, e)
    finally:
        try:
            db.close()
        except Exception:
            pass
        try:
            os.remove(path)
        except Exception:
            pass


def test_sqlite_legacy():
    """Legacy rows (empty code) get filled; inventory/users/change-log use the
    same scheme."""
    print("\n-- sqlite: legacy rows, inventory, users, change log --")
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    dm.DB_PATH = path
    db = dm.DatabaseManager()
    try:
        serial = "SN-LEGACY-9"
        legacy_aid = hashlib.md5(serial.encode("utf-8")).hexdigest()
        legacy_mon = hashlib.md5("HP|Z24n|1920x1200".encode("utf-8")).hexdigest()
        db.insert_machine_config("m-legacy", machine_config(
            hostname="LEGACY-PC", serial=serial, monitor=("HP", "Z24n", "1920x1200")),
            {"user_name": "Le Van B", "employee_id": "NV002", "email": "b@example.com"})
        cur = db.conn.cursor()
        # simulate rows written by an older/PG build: code empty
        cur.execute("UPDATE assets_computers SET display_id='' WHERE asset_id=?", (legacy_aid,))
        cur.execute("UPDATE assets_monitors SET display_id='' WHERE asset_id=?", (legacy_mon,))
        db.conn.commit()
        # next report must fill them
        db.insert_machine_config("m-legacy", machine_config(
            hostname="LEGACY-PC", serial=serial, monitor=("HP", "Z24n", "1920x1200")),
            {"user_name": "Le Van B", "employee_id": "NV002", "email": "b@example.com"})
        cur.execute("SELECT display_id FROM assets_computers WHERE asset_id=?", (legacy_aid,))
        fixed_pc = (cur.fetchone() or [""])[0]
        check("legacy computer row with empty code gets filled",
              bool(fixed_pc) and bool(CODE_RE.match(fixed_pc)), fixed_pc)
        cur.execute("SELECT display_id FROM assets_monitors WHERE asset_id=?", (legacy_mon,))
        fixed_mon = (cur.fetchone() or [""])[0]
        check("legacy monitor row with empty code gets filled",
              bool(fixed_mon) and bool(CODE_RE.match(fixed_mon)), fixed_mon)

        db.upsert_inventory_asset({"category": "printer", "name": "HP LJ 1102",
                                  "source": "manual"})
        cur.execute("SELECT display_id FROM assets_inventory WHERE name=?", ("HP LJ 1102",))
        inv = (cur.fetchone() or [""])[0]
        check("inventory printer code is PR-XXXXXXXX",
              bool(inv) and inv.startswith("PR-") and bool(CODE_RE.match(inv)), inv)
        db.sync_user_assets()
        cur.execute("SELECT display_id FROM assets_inventory WHERE category='user'")
        users = [(r[0] or "") for r in cur.fetchall()]
        check("user assets get US-XXXXXXXX codes",
              bool(users) and all(u.startswith("US-") and CODE_RE.match(u) for u in users),
              users)

        # hardware change -> change log must expose a readable code
        db.insert_machine_config("m-legacy", machine_config(
            hostname="LEGACY-PC", serial=serial, cpu="Core i7-9700",
            monitor=("HP", "Z24n", "1920x1200")), {"user_name": "Le Van B"})
        log = db.get_asset_change_log(limit=10)
        check("change log returns rows", bool(log), log)
        if log:
            row = log[0]
            check("change log row exposes display_id",
                  bool((row.get("display_id") or "").strip()), row.get("display_id"))
            check("change log display_id is canonical, not a 32-char md5",
                  bool(CODE_RE.match((row.get("display_id") or "").strip())),
                  row.get("display_id"))

        for table in ("assets_computers", "assets_monitors", "assets_inventory"):
            cur.execute("SELECT display_id FROM %s" % table)
            vals = [(r[0] or "").strip() for r in cur.fetchall()]
            if not vals:
                continue
            check("%s: no empty codes" % table, all(vals), vals)
            check("%s: no 32-char codes" % table, all(len(v) != 32 for v in vals), vals)
            check("%s: codes are unique" % table, len(set(vals)) == len(vals), vals)
    except Exception as e:
        check("legacy section completed", False, e)
    finally:
        try:
            db.close()
        except Exception:
            pass
        try:
            os.remove(path)
        except Exception:
            pass
def test_api_helper():
    """api_assets.asset_code() must never hand out a 32-char md5."""
    print("\n-- api: api_assets.asset_code --")
    try:
        import api.api_assets as aa
    except Exception as e:
        print("SKIP  api_assets could not be imported: %s" % str(e)[:140])
        return
    aid = "20f88bd75193daa6a4cbe8111d461163"
    check("stored code is returned as-is",
          aa.asset_code({"display_id": "PC-0887498B"}, "computer") == "PC-0887498B")
    derived_pc = aa.asset_code({"asset_id": aid}, "computer")
    check("missing code -> derived PC-XXXXXXXX",
          derived_pc.startswith("PC-") and len(derived_pc) == 11, derived_pc)
    check("never returns the 32-char md5", len(derived_pc) != 32, derived_pc)
    check("monitor fallback uses MN-",
          aa.asset_code({"asset_id": aid}, "monitor").startswith("MN-"))
    check("inventory fallback follows the category",
          aa.asset_code({"asset_id": aid}, "printer").startswith("PR-"))
    check("row without any id -> '-'", aa.asset_code({}, "computer") == "-")
    check("derived code is deterministic",
          aa.asset_code({"asset_id": aid}, "computer") == derived_pc)


def _pg_env(env_path=None):
    """PostgreSQL credentials for the throwaway test database."""
    try:
        sys.path.insert(0, os.path.join(ROOT, "tools"))
        from reset_data import find_env, parse_env
        path = find_env(env_path)
        if path:
            env = parse_env(path)
            if env.get("GIAMSAT_PG_PASSWORD"):
                return {
                    "host": env.get("GIAMSAT_PG_HOST", "127.0.0.1"),
                    "port": int(env.get("GIAMSAT_PG_PORT", "5432")),
                    "user": env.get("GIAMSAT_PG_USER", "postgres"),
                    "password": env["GIAMSAT_PG_PASSWORD"],
                }
    except Exception:
        pass
    pwd = os.environ.get("GIAMSAT_PG_PASSWORD")
    if pwd:
        return {
            "host": os.environ.get("GIAMSAT_PG_HOST", "127.0.0.1"),
            "port": int(os.environ.get("GIAMSAT_PG_PORT", "5432")),
            "user": os.environ.get("GIAMSAT_PG_USER", "postgres"),
            "password": pwd,
        }
    return None


def test_pg(env_path=None):
    """PostgreSQL backend against a THROWAWAY database.

    This is the backend that had both bugs, so the checks matter most here: the
    code must exist after the FIRST report, for computers AND for monitors.
    """
    print("\n-- postgres: PostgresDatabase.insert_machine_config (throwaway DB) --")
    env = _pg_env(env_path)
    if not env:
        print("SKIP  no PostgreSQL credentials (pass --env <server/.env> or set GIAMSAT_PG_*)")
        return
    try:
        import psycopg2
    except ImportError:
        print("SKIP  psycopg2 is not installed")
        return

    test_db = "giamsat_didtest"
    admin = dict(env, dbname="postgres")
    try:
        conn = psycopg2.connect(**admin)
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute('DROP DATABASE IF EXISTS "%s"' % test_db)
            cur.execute('CREATE DATABASE "%s"' % test_db)
        conn.close()
    except Exception as e:
        print("SKIP  cannot create a throwaway database: %s" % str(e)[:140])
        print("      (this test never touches the real database)")
        return

    pg = None
    try:
        os.environ.update({
            "GIAMSAT_PG_HOST": env["host"], "GIAMSAT_PG_PORT": str(env["port"]),
            "GIAMSAT_PG_DBNAME": test_db, "GIAMSAT_PG_USER": env["user"],
            "GIAMSAT_PG_PASSWORD": env["password"],
        })
        import importlib
        import db_postgres
        importlib.reload(db_postgres)
        pg = db_postgres.PostgresDatabase()
        if not getattr(pg, "_connected", False):
            check("connected to the throwaway database", False, "not connected")
            return
        check("connected to the throwaway database", True)

        cfg = machine_config(hostname="PG-PC", serial="SN-PG-0001")
        pg.insert_machine_config("m-pg-1", cfg,
                                 {"user_name": "Tran Van C", "employee_id": "NV003",
                                  "email": "c@example.com"})
        pcs = pg.get_asset_computers(limit=10)
        check("1 computer row created (PG)", len(pcs) == 1, pcs)
        pc_code = (pcs[0].get("display_id") or "") if pcs else ""
        check("PG computer code set on FIRST report",
              bool(pc_code) and bool(CODE_RE.match(pc_code)), pc_code or "(empty = bug)")

        mons = pg.get_asset_monitors(limit=10)
        check("1 monitor row created (PG)", len(mons) == 1, mons)
        mon_code = (mons[0].get("display_id") or "") if mons else ""
        check("PG monitor code set on FIRST report",
              bool(mon_code) and bool(CODE_RE.match(mon_code)), mon_code or "(empty = bug)")
        check("PG monitor code is MN-XXXXXXXX", mon_code.startswith("MN-"), mon_code)
        pg.insert_machine_config("m-pg-1", cfg,
                                 {"user_name": "Tran Van C", "employee_id": "NV003",
                                  "email": "c@example.com"})
        pcs2 = pg.get_asset_computers(limit=10)
        check("PG computer code is stable across reports",
              (pcs2[0].get("display_id") if pcs2 else "") == pc_code)
        mons2 = pg.get_asset_monitors(limit=10)
        check("PG monitor code is stable across reports",
              (mons2[0].get("display_id") if mons2 else "") == mon_code)

        # legacy rows with an empty code must be filled by the next report
        aid = hashlib.md5("SN-PG-0001".encode("utf-8")).hexdigest()
        mid = hashlib.md5("DELL|E2211H|1920x1080".encode("utf-8")).hexdigest()
        pg._execute("UPDATE assets_computers SET display_id='' WHERE asset_id=%s", (aid,))
        pg._execute("UPDATE assets_monitors SET display_id='' WHERE asset_id=%s", (mid,))
        pg.insert_machine_config("m-pg-1", cfg, {"user_name": "Tran Van C"})
        row = pg._execute("SELECT display_id FROM assets_computers WHERE asset_id=%s",
                          (aid,), fetch=True)
        got = (row.get("display_id") if isinstance(row, dict) else None)
        check("PG legacy computer row filled", bool(got) and bool(CODE_RE.match(got)), got)
        row = pg._execute("SELECT display_id FROM assets_monitors WHERE asset_id=%s",
                          (mid,), fetch=True)
        got = (row.get("display_id") if isinstance(row, dict) else None)
        check("PG legacy monitor row filled", bool(got) and bool(CODE_RE.match(got)), got)

        pg.insert_machine_config("m-pg-1",
                                 machine_config(hostname="PG-PC", serial="SN-PG-0001",
                                                cpu="Core i7-9700"),
                                 {"user_name": "Tran Van C"})
        log = pg.get_asset_change_log(limit=10)
        check("PG change log returns rows", bool(log), log)
        if log:
            check("PG change log display_id is canonical",
                  bool(CODE_RE.match((log[0].get("display_id") or "").strip())),
                  log[0].get("display_id"))

        for table in ("assets_computers", "assets_monitors", "assets_inventory"):
            rows = pg._execute('SELECT display_id FROM "%s"' % table, fetchall=True) or []
            vals = [((r.get("display_id") if isinstance(r, dict) else r[0]) or "").strip()
                    for r in rows]
            if not vals:
                continue
            check("PG %s: no empty codes" % table, all(vals), vals)
            check("PG %s: no 32-char codes" % table, all(len(v) != 32 for v in vals), vals)
    except Exception as e:
        check("postgres section completed", False, e)
    finally:
        try:
            if pg is not None:
                pg.close()
        except Exception:
            pass
        try:
            import psycopg2 as _p
            conn = _p.connect(**admin)
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute('DROP DATABASE IF EXISTS "%s"' % test_db)
            conn.close()
            print("[i] throwaway database %s dropped" % test_db)
        except Exception as e:
            print("[!] could not drop %s: %s" % (test_db, str(e)[:120]))


def main():
    argv = sys.argv[1:]
    env_path = None
    if "--env" in argv:
        idx = argv.index("--env")
        env_path = argv[idx + 1] if idx + 1 < len(argv) else None
    print("=" * 68)
    print("  GIAM-SAT asset code (display_id) regression tests - v5.0.8")
    print("=" * 68)
    test_unit()
    test_sqlite()
    test_sqlite_legacy()
    test_api_helper()
    if "--pg" in argv:
        test_pg(env_path)
    else:
        print("\n-- postgres --\nSKIP  pass --pg to run the throwaway-database checks")
    failed = [n for n, ok in RESULTS if not ok]
    print("\n" + "=" * 68)
    print("  %d/%d checks passed" % (len(RESULTS) - len(failed), len(RESULTS)))
    for name in failed:
        print("  FAILED: %s" % name)
    print("=" * 68)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

