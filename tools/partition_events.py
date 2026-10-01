#!/usr/bin/env python
"""Convert a hot table to monthly RANGE partitions (received_at) - v5.0.8 (Phase D).

Why: retention on `events` (171 MB / 120k rows here) or `network_traffic` (116 MB)
is a DELETE that bloats the heap and cannot be undone. With monthly partitions the
retention job becomes an instant DROP TABLE, queries prune by month, and the
nightly `daily_stats` rollup keeps year-long questions cheap.

Dry run by default - nothing is touched until --apply. The original table is kept
as `<table>_legacy_backup` so the operator can rename it back.

Usage:
    python tools/partition_events.py --table events
    python tools/partition_events.py --table events --apply
    python tools/partition_events.py --table events --apply --drop-backup

Rollback (also printed after a successful run):
    ALTER TABLE events RENAME TO events_partition_failed;
    ALTER TABLE events_legacy_backup RENAME TO events;
"""

import argparse
import os
import sys

# Console on Windows defaults to cp1252 and the help text is Vietnamese - without
# this, `--help` itself dies with UnicodeEncodeError (caught by tool_cli_tests).
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "server"))

import search_engine as se      # noqa: E402
import partitioning as part     # noqa: E402


def load_env(explicit=None):
    path = explicit or os.path.join(ROOT, "server", ".env")
    if not os.path.exists(path):
        path = os.path.join(os.getcwd(), "server", ".env")
    if os.path.exists(path):
        for line in open(path, encoding="utf-8-sig", errors="ignore"):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
    return path


def connect(env_path=None):
    load_env(env_path)
    import db_postgres as dp
    db = dp.PostgresDatabase()
    if not getattr(db, "_connected", False):
        print("[-] không kết nối được PostgreSQL (kiểm tra server/.env)")
        sys.exit(2)
    return db


def plan(db, table, months_ahead=2):
    """What the conversion would do (no writes)."""
    kind, ph = "postgres", "%s"
    info = {"table": table, "exists": False, "partitioned": False, "rows": 0,
            "months": [], "indexes": [], "unique_indexes": []}
    rows = se.rows(db, "SELECT relkind, reltuples::bigint AS rows FROM pg_class "
                       "WHERE relname = %s" % ph, (table,), kind)
    if not rows:
        return info
    info["exists"] = True
    info["partitioned"] = rows[0].get("relkind") == "p"
    info["rows"] = int(rows[0].get("rows") or 0)
    bounds = se.rows(db, "SELECT MIN(received_at) AS lo, MAX(received_at) AS hi FROM " + table,
                     None, kind)
    keys = []
    if bounds and bounds[0].get("lo"):
        lo = bounds[0]["lo"].strftime("%Y_%m")
        hi = bounds[0]["hi"].strftime("%Y_%m")
        for key in part.month_keys(60, months_ahead):
            if lo <= key <= hi:
                keys.append(key)
        for key in part.month_keys(0, months_ahead):
            if key not in keys:
                keys.append(key)
    else:
        keys = part.month_keys(part.DEFAULT_MONTHS_BACK, months_ahead)
    info["months"] = keys
    pk_names = set()
    try:
        for row in se.rows(db, "SELECT conname FROM pg_constraint WHERE conrelid = %s::regclass "
                               "AND contype = 'p'" % ph, (table,), kind):
            pk_names.add(str(row.get("conname") or ""))
    except Exception:
        pk_names = set()
    info["primary_key"] = sorted(n for n in pk_names if n)
    for row in se.rows(db, "SELECT indexname, indexdef FROM pg_indexes WHERE schemaname='public' "
                           "AND tablename = %s" % ph, (table,), kind):
        name = str(row.get("indexname") or "")
        definition = str(row.get("indexdef") or "")
        # A PRIMARY KEY index (e.g. events_pkey) cannot be recreated on a partitioned
        # parent without including the partition key, and its name is still taken by
        # the backup table - skip it (id stays unique through the sequence).
        if name in pk_names or name.endswith("_pkey"):
            continue
        if "UNIQUE" in definition:
            info["unique_indexes"].append(definition)
        else:
            info["indexes"].append(definition)
    return info


def convert(db, table, months_ahead=2, drop_backup=False):
    """Perform the migration; returns a report with rollback instructions."""
    kind, ph = "postgres", "%s"
    info = plan(db, table, months_ahead)
    if not info["exists"]:
        return {"ok": False, "error": "không có bảng %s" % table}
    if info["partitioned"]:
        return {"ok": True, "already": True, "table": table}
    new, backup = table + "_new", table + "_legacy_backup"
    done = []
    try:
        se.write_sql(db, "DROP TABLE IF EXISTS " + new, None, kind)
        se.write_sql(db, "CREATE TABLE %s (LIKE %s INCLUDING DEFAULTS) "
                         "PARTITION BY RANGE (received_at)" % (new, table), None, kind)
        done.append("tạo bảng cha %s" % new)
        for key in info["months"]:
            start, end = part.month_bounds(key)
            se.write_sql(db, "CREATE TABLE IF NOT EXISTS %s_%s PARTITION OF %s "
                             "FOR VALUES FROM ('%s') TO ('%s')"
                        % (new, key, new, start, end), None, kind)
        done.append("tạo %d partition tháng" % len(info["months"]))
        copied = se.write_sql(db, "INSERT INTO %s SELECT * FROM %s" % (new, table), None, kind)
        done.append("copy dữ liệu (rowcount=%s)" % copied)
        for definition in info["indexes"]:
            se.write_sql(db, definition.replace(" ON %s " % table, " ON %s " % new), None, kind)
        done.append("tạo lại %d index thường" % len(info["indexes"]))
        failed_index = []
        for key in info["months"]:
            child = "%s_%s" % (new, key)
            for definition in info["unique_indexes"]:
                name = definition.split(" ON ")[0].rsplit(" ", 1)[-1]
                if "dedup" in definition.lower():
                    sql = ("CREATE UNIQUE INDEX %s_%s ON %s (dedup_key) "
                           "WHERE dedup_key IS NOT NULL" % (name, key, child))
                else:
                    sql = definition.replace(" ON %s " % table, " ON %s " % child)
                try:
                    if se.write_sql(db, sql, None, kind) is None:
                        failed_index.append("%s (%s)" % (name, key))
                except Exception as exc:
                    failed_index.append("%s: %s" % (name, str(exc)[:80]))
        done.append("unique index (dedup) theo từng partition")
        seq = se.rows(db, "SELECT pg_get_serial_sequence(%s, 'id') AS seq" % ph, (table,), kind)
        if seq and seq[0].get("seq"):
            se.write_sql(db, "SELECT setval('%s', (SELECT COALESCE(MAX(id), 1) FROM %s))"
                        % (seq[0]["seq"], new), None, kind)
            done.append("đồng bộ sequence id")
        counts = {}
        for label, target in (("cũ", table), ("mới", new)):
            hit = se.rows(db, "SELECT COUNT(*) AS n FROM " + target, None, kind)
            counts[label] = int((hit[0] or {}).get("n") or 0)
        if counts["cũ"] != counts["mới"]:
            return {"ok": False, "steps": done,
                    "error": "số dòng không khớp (%s vs %s)" % (counts["cũ"], counts["mới"])}
        se.write_sql(db, "ALTER TABLE %s RENAME TO %s" % (table, backup), None, kind)
        se.write_sql(db, "ALTER TABLE %s RENAME TO %s" % (new, table), None, kind)
        done.append("đổi tên: %s -> %s, %s -> %s" % (table, backup, new, table))
        if drop_backup:
            se.write_sql(db, "DROP TABLE " + backup, None, kind)
            done.append("xoá bảng backup")
        return {"ok": True, "table": table, "rows": counts["mới"],
                "months": len(info["months"]), "steps": done,
                "failed_indexes": failed_index,
                "backup": None if drop_backup else backup}
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:300], "steps": done,
                "rollback": ["ALTER TABLE %s RENAME TO %s_failed;" % (table, table),
                             "ALTER TABLE %s RENAME TO %s;" % (backup, table)]}


def main():
    ap = argparse.ArgumentParser(description="Chuyển bảng nóng sang partition theo tháng.")
    ap.add_argument("--table", default="events", help="bảng cần chuyển (mặc định: events)")
    ap.add_argument("--env", help="đường dẫn server/.env")
    ap.add_argument("--months-ahead", type=int, default=2)
    ap.add_argument("--apply", action="store_true", help="thực sự chuyển (mặc định chỉ xem)")
    ap.add_argument("--drop-backup", action="store_true",
                    help="xoá bảng backup sau khi thành công (không khuyến khích ngay)")
    args = ap.parse_args()
    db = connect(args.env)
    info = plan(db, args.table, args.months_ahead)
    print("=" * 72)
    print("  GIAM-SAT - chuyển %s sang partition theo tháng" % args.table)
    print("=" * 72)
    if not info["exists"]:
        print("[-] không có bảng %s" % args.table)
        return 2
    print("[*] đã partition sẵn: %s | dòng (ước lượng): %s"
          % (info["partitioned"], info["rows"]))
    print("[*] sẽ tạo %d partition: %s%s"
          % (len(info["months"]), ", ".join(info["months"][:6]),
             " ..." if len(info["months"]) > 6 else ""))
    print("[*] index tạo lại trên bảng cha: %d | unique (dedup) theo partition: %d"
          % (len(info["indexes"]), len(info["unique_indexes"])))
    if info.get("primary_key"):
        print("[i] PRIMARY KEY (%s) không tạo lại trên bảng cha: PG yêu cầu khoá partition"
              % ", ".join(info["primary_key"]))
        print("    trong mọi unique/PK, nên id vẫn unique nhờ sequence (đủ cho ingest).")
    if info["unique_indexes"]:
        print("[i] PG không cho ON CONFLICT dùng partial unique index trên bảng cha, nên")
        print("    dedup unique index được tạo trên TỪNG partition và server dùng đường")
        print("    insert riêng cho bảng đã partition (SELECT ... WHERE NOT EXISTS).")
    if not args.apply:
        print("\n[i] DRY-RUN - chưa thay đổi gì. Chạy lại với --apply để thực hiện.")
        return 0
    if info["partitioned"]:
        print("[=] bảng đã partition; chỉ cần tạo thêm tháng mới:")
        print("    " + ", ".join(part.ensure_partitions(db, args.table)))
        return 0
    result = convert(db, args.table, args.months_ahead, args.drop_backup)
    for step in result.get("steps", []):
        print("   + " + str(step))
    if not result.get("ok"):
        print("[-] THẤT BẠI: %s" % result.get("error"))
        for line in result.get("rollback", []):
            print("    " + line)
        return 1
    print("[+] XONG: %s -> partition (%s dòng, %s tháng)"
          % (args.table, result.get("rows"), result.get("months")))
    if result.get("backup"):
        print("[i] bảng cũ vẫn còn tại %s. Ổn rồi thì:  DROP TABLE %s;"
              % (result["backup"], result["backup"]))
        print("[i] Cần quay lại:")
        print("    ALTER TABLE %s RENAME TO %s_partition_failed;" % (args.table, args.table))
        print("    ALTER TABLE %s RENAME TO %s;" % (result["backup"], args.table))
    return 0


if __name__ == "__main__":
    sys.exit(main())


