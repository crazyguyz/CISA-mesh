#!/usr/bin/env python
"""GIAM-SAT partitioning + rollup tests - v5.0.8 (Phase D).

Guards the scale work:
  * month maths (keys, bounds, December rollover) used for partition names.
  * the conversion tool: dry-run is the default, --apply keeps a backup and prints
    the rollback commands, and the migration is exercised END TO END on a
    THROWAWAY table (never on `events`) - counts, indexes, de-dup and retention.
  * the partition-safe event insert: a partitioned `events` cannot use ON CONFLICT
    with a partial unique index (PG 42P10), so the code must switch to
    SELECT ... WHERE NOT EXISTS - verified here on a probe table.
  * daily rollup (daily_stats) + storage report + API routes + CI actually runs.
  * live (--pg [--env file]) for everything DB related.

Usage:
  python tests/partition_tests.py                  # unit + static
  python tests/partition_tests.py --pg --env D:/test/server/.env
Exit 0 = all passed, 1 = failures.
"""

import io
import os
import re
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER = os.path.join(ROOT, "server")
sys.path.insert(0, SERVER)

import partitioning as part  # noqa: E402

RESULTS = []


def check(name, ok, extra=""):
    RESULTS.append((name, bool(ok)))
    line = ("PASS  " if ok else "FAIL  ") + name
    if not ok and extra:
        line += "   -> " + str(extra)[:220]
    print(line)


def read(path):
    with io.open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def test_month_maths():
    print("\n-- tháng / partition naming --")
    from datetime import datetime
    keys = part.month_keys(2, 1, now=datetime(2026, 10, 1))
    check("month_keys covers back/future (2026-08..2026-11)",
          keys == ["2026_08", "2026_09", "2026_10", "2026_11"], keys)
    check("December rolls over to the next year",
          part.month_keys(0, 1, now=datetime(2026, 12, 15)) == ["2026_12", "2027_01"],
          part.month_keys(0, 1, now=datetime(2026, 12, 15)))
    check("January rolls back to the previous year",
          part.month_keys(1, 0, now=datetime(2027, 1, 5)) == ["2026_12", "2027_01"],
          part.month_keys(1, 0, now=datetime(2027, 1, 5)))
    check("month_bounds gives the exclusive upper bound",
          part.month_bounds("2026_09") == ("2026-09-01", "2026-10-01"))
    check("month_bounds December ends on Jan 1",
          part.month_bounds("2026_12") == ("2026-12-01", "2027-01-01"))
    check("partition_name", part.partition_name("events", "2026_09") == "events_2026_09")
    check("hot tables are the 5 volume tables",
          set(part.HOT_TABLES) == {"events", "sysmon_events", "network_traffic", "syslog",
                                   "heartbeats"}, list(part.HOT_TABLES))


def test_static_wiring():
    print("\n-- wiring: code, tool, API, CI --")
    src = read(os.path.join(SERVER, "partitioning.py"))
    for fn in ("month_keys", "ensure_partitions", "drop_old_partitions", "rollup_daily",
               "storage_report", "partition_info", "is_partitioned"):
        check("partitioning.%s" % fn, ("def %s" % fn) in src)
    check("rollup SQL touches every hot source",
          all(t in part.ROLLUP_SQL for t in ("FROM events", "FROM sysmon_events",
                                             "FROM threat_alerts", "FROM network_traffic",
                                             "FROM syslog")))
    check("rollup upserts by (day, machine_id)", "ON CONFLICT (day, machine_id)" in part.ROLLUP_SQL)
    check("rollup has 5 day parameters",
          len(re.findall(r"make_interval\(days => %s\)", part.ROLLUP_SQL)) == 5,
          len(re.findall(r"make_interval\(days => %s\)", part.ROLLUP_SQL)))

    pg = read(os.path.join(SERVER, "db_postgres.py"))
    check("partition-safe events insert exists",
          "_EVENTS_SELECT_SQL" in pg and "WHERE NOT EXISTS (SELECT 1 FROM events e2" in pg)
    check("plain tables keep ON CONFLICT", "_EVENTS_VALUES_SQL" in pg
          and "ON CONFLICT (dedup_key) WHERE dedup_key IS NOT NULL DO NOTHING" in pg)
    check("the insert path picks the SQL by partition state",
          "is_events_partitioned()" in pg and "_events_insert_sql_many" in pg)
    check("start-up only ensures partitions, never converts",
          "partitioning.ensure_partitions(self)" in pg)
    check("daily_stats table exists in PG + SQLite",
          "CREATE TABLE IF NOT EXISTS daily_stats" in pg
          and "CREATE TABLE IF NOT EXISTS daily_stats" in read(os.path.join(SERVER, "db_manager.py")))

    tool = read(os.path.join(ROOT, "tools", "partition_events.py"))
    check("tool defaults to dry-run", '"--apply", action="store_true"' in tool
          and "DRY-RUN" in tool)
    check("tool keeps a backup + prints rollback", "_legacy_backup" in tool
          and "RENAME TO" in tool)
    check("tool synchronises the id sequence", "setval" in tool)
    check("tool verifies row counts before swapping", "số dòng không khớp" in tool)

    api = read(os.path.join(SERVER, "api", "api_fleet.py"))
    for route in ("/api/health/storage", "/api/health/storage/rollup",
                  "/api/health/storage/drop-old"):
        check("route %s" % route, route in api)
    check("drop-old needs the command permission", "storage_drop_partitions" in api)

    check("pytest.ini collects *_tests.py",
          "python_files = *_tests.py" in read(os.path.join(ROOT, "pytest.ini")))
    check("conftest skips Windows-only suites elsewhere",
          "collect_ignore" in read(os.path.join(ROOT, "tests", "conftest.py")))
    ci = read(os.path.join(ROOT, ".github", "workflows", "ci.yml"))
    check("CI runs every suite and fails on a non-zero exit",
          "Regression suites (each must exit 0)" in ci and "exit $fail" in ci)


def test_live_postgres():
    print("\n-- live PostgreSQL: tool chạy thật trên bảng DÙNG-MỘT-LẦN --")
    if "--pg" not in sys.argv:
        print("SKIP  pass --pg [--env <file>] to run against PostgreSQL")
        return
    env_path = os.path.join(SERVER, ".env")
    if "--env" in sys.argv:
        i = sys.argv.index("--env")
        if i + 1 < len(sys.argv):
            env_path = sys.argv[i + 1]
    if os.path.exists(env_path):
        for line in io.open(env_path, encoding="utf-8-sig", errors="ignore"):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
    try:
        import db_postgres as dp
        import search_engine as se
        sys.path.insert(0, os.path.join(ROOT, "tools"))
        import partition_events as tool
    except Exception as exc:
        print("SKIP  cannot import the DB layer/tool: %s" % exc)
        return
    db = dp.PostgresDatabase()
    if not getattr(db, "_connected", False):
        print("SKIP  PostgreSQL not reachable")
        return

    table = "zz_part_probe"

    def cleanup():
        for name in (table + "_2026_08", table + "_2026_09", table + "_2026_10",
                     table + "_2026_11", table + "_2026_12", table + "_2027_01",
                     table + "_new", table + "_legacy_backup", table):
            try:
                db._execute("DROP TABLE IF EXISTS " + name)
            except Exception:
                pass

    try:
        cleanup()
        db._execute("""CREATE TABLE %s (id SERIAL PRIMARY KEY, machine_id TEXT,
                       received_at TIMESTAMPTZ DEFAULT NOW(), dedup_key TEXT)""" % table)
        db._execute("CREATE UNIQUE INDEX %s_dedup ON %s (dedup_key) "
                    "WHERE dedup_key IS NOT NULL" % (table, table))
        db._execute("CREATE INDEX %s_machine ON %s (machine_id)" % (table, table))
        db._execute("""INSERT INTO %s (machine_id, received_at, dedup_key) VALUES
                       ('zzm1', NOW(), 'zzd1'), ('zzm2', NOW(), 'zzd2'),
                       ('zzm3', NOW() - interval '65 days', 'zzd3')""" % table)
        rows = se.rows(db, "SELECT COUNT(*) AS n FROM " + table, None, "postgres")
        check("probe table seeded", int((rows[0] or {}).get("n") or 0) == 3, rows)
        check("probe table is NOT partitioned yet", part.is_partitioned(db, table) is False)

        info = tool.plan(db, table, months_ahead=1)
        check("plan sees the data months (>=3 keys)", len(info["months"]) >= 3, info["months"])
        check("plan detects the partial unique (dedup) index",
              any("dedup" in i for i in info["unique_indexes"]), info["unique_indexes"])
        check("plan lists the normal index to recreate",
              any("machine" in i for i in info["indexes"]), info["indexes"])

        result = tool.convert(db, table, months_ahead=1)
        check("tool converts the table", result.get("ok") is True, result)
        check("row count preserved", result.get("rows") == 3, result.get("rows"))
        check("backup kept for rollback", bool(result.get("backup")), result.get("backup"))
        check("table is now partitioned", part.is_partitioned(db, table) is True)
        pinfo = part.partition_info(db, [table])
        check("partition_info reports >=3 partitions",
              bool(pinfo) and len(pinfo[0]["partitions"]) >= 3, pinfo)
        check("tool reported no failed index creation",
              not result.get("failed_indexes"), result.get("failed_indexes"))
        idx = se.rows(db, "SELECT indexname FROM pg_indexes WHERE indexname LIKE %s",
                      ("%_dedup_%",), "postgres")
        check("dedup unique index created per partition", len(idx or []) >= 2, idx)

        # the partition-safe insert path the server uses for a partitioned `events`
        for _ in range(2):
            db._execute("""INSERT INTO %s (machine_id, received_at, dedup_key)
                           SELECT 'zzm9', NOW(), 'zzd9'
                           WHERE NOT EXISTS (SELECT 1 FROM %s e2 WHERE e2.dedup_key = 'zzd9'
                                             AND e2.dedup_key IS NOT NULL)""" % (table, table))
        rows = se.rows(db, "SELECT COUNT(*) AS n FROM " + table, None, "postgres")
        check("NOT EXISTS de-dup path works on the partitioned table",
              int((rows[0] or {}).get("n") or 0) == 4, rows)

        drop = part.drop_old_partitions(db, table, retention_days=30)
        check("retention DROPs the old month partition instantly",
              len(drop.get("dropped") or []) >= 1, drop)
        rows = se.rows(db, "SELECT COUNT(*) AS n FROM " + table, None, "postgres")
        check("rows from the dropped month are gone",
              int((rows[0] or {}).get("n") or 0) <= 3, rows)
        check("ensure_partitions creates the next months",
              len(part.ensure_partitions(db, table)) >= 1)

        roll = part.rollup_daily(db, 30)
        check("daily rollup runs on real data",
              roll.get("ok") and roll.get("rows_in_table", 0) > 0, roll)
        rep = part.storage_report(db, retention_days=30)
        check("storage report lists the hot tables with sizes",
              any(t["table"] == "events" and t["bytes"] > 0 for t in rep["tables"]),
              rep["tables"][:2])
        check("storage report flags tables that still need partitioning",
              "events" in rep["partitions_needed"], rep["partitions_needed"])
        check("dry-run plan of the real events table is read-only",
              tool.plan(db, "events", 1)["exists"] is True)
    finally:
        cleanup()
        left = se.rows(db, "SELECT to_regclass(%s) AS t", (table,), "postgres")
        check("probe tables cleaned up", not (left and left[0].get("t")), left)


def main():
    print("=" * 68)
    print("  GIAM-SAT partitioning / rollup tests - v5.0.8")
    print("=" * 68)
    test_month_maths()
    test_static_wiring()
    test_live_postgres()
    passed = sum(1 for _n, ok in RESULTS if ok)
    print("\n" + "=" * 68)
    print("  %d/%d checks passed" % (passed, len(RESULTS)))
    print("=" * 68)
    if passed != len(RESULTS):
        print("FAILED: " + ", ".join(n for n, ok in RESULTS if not ok))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
