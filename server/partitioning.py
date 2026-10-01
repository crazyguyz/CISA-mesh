"""GIAM-SAT partitioning + rollups - v5.0.8 (Phase D: scale to a real fleet).

Why: retention today DELETEs rows from the biggest tables (events 117k,
network_traffic 156k on the test box, and it grows fast). DELETE is slow, bloats
the heap and cannot be undone. Monthly RANGE partitions on `received_at` make
retention an instant `DROP TABLE`, keep queries pruned, and let a nightly rollup
answer "how many events did host X send last quarter" without touching the raw
tables.

Nothing here happens automatically on a live database:
  * `ensure_partitions()` (called by the server at start) only creates the NEXT
    months for tables that are ALREADY partitioned - it never converts anything.
  * `convert_to_partitioned()` performs the one-off migration and is only called
    by `tools/partition_events.py` (dry-run by default), which keeps the old
    table as a backup so the operator can rename it back.
"""

from datetime import datetime, timedelta

import search_engine as se

# table -> time column (all TIMESTAMPTZ/TIMESTAMP in PG)
HOT_TABLES = {
    "events": "received_at",
    "sysmon_events": "received_at",
    "network_traffic": "received_at",
    "syslog": "received_at",
    "heartbeats": "received_at",
}
DEFAULT_MONTHS_BACK = 6
DEFAULT_MONTHS_AHEAD = 2


def month_keys(months_back=DEFAULT_MONTHS_BACK, months_ahead=DEFAULT_MONTHS_AHEAD, now=None):
    """['2026_04', ... '2026_12'] covering the window we keep/create."""
    now = now or datetime.now()
    keys = []
    for offset in range(-int(months_back), int(months_ahead) + 1):
        year = now.year + (now.month - 1 + offset) // 12
        month = (now.month - 1 + offset) % 12 + 1
        keys.append("%04d_%02d" % (year, month))
    return keys


def month_bounds(key):
    """'2026_09' -> ('2026-09-01', '2026-10-01') (exclusive upper bound)."""
    year, month = (int(x) for x in str(key).split("_"))
    start = datetime(year, month, 1)
    end = datetime(year + 1, 1, 1) if month == 12 else datetime(year, month + 1, 1)
    return start.strftime("%Y-%m-%d"), end.strftime("%Y-%m-%d")


def partition_name(table, key):
    return "%s_%s" % (table, key)


def is_partitioned(db, table):
    kind = se.backend_kind(db)
    rows = se.rows(db, "SELECT relkind FROM pg_class WHERE relname = %s"
                   % se.placeholder(kind), (table,), kind)
    return bool(rows) and (rows[0].get("relkind") == "p")


def partition_info(db, tables=None):
    """[{table, partitioned, partitions: [{name, rows}], total_rows}]"""
    kind = se.backend_kind(db)
    out = []
    for table in (tables if tables is not None else HOT_TABLES):
        info = {"table": table, "partitioned": False, "partitions": [], "total_rows": 0}
        try:
            info["partitioned"] = is_partitioned(db, table)
            if info["partitioned"]:
                rows = se.rows(db, """
                    SELECT c.relname AS name, c.reltuples::bigint AS rows
                    FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
                    JOIN pg_class p ON p.oid = i.inhparent
                    WHERE p.relname = %s ORDER BY c.relname""" % se.placeholder(kind),
                    (table,), kind)
                info["partitions"] = [{"name": r.get("name"), "rows": int(r.get("rows") or 0)}
                                      for r in (rows or [])]
                info["total_rows"] = sum(p["rows"] for p in info["partitions"])
            else:
                hit = se.rows(db, "SELECT reltuples::bigint AS rows FROM pg_class "
                                  "WHERE relname = %s" % se.placeholder(kind), (table,), kind)
                info["total_rows"] = int((hit[0].get("rows") if hit else 0) or 0)
        except Exception:
            pass
        out.append(info)
    return out


def ensure_partitions(db, table=None, months_back=DEFAULT_MONTHS_BACK,
                      months_ahead=DEFAULT_MONTHS_AHEAD):
    """Create the missing monthly partitions for tables that ARE partitioned."""
    kind = se.backend_kind(db)
    created = []
    for name in ([table] if table else list(HOT_TABLES)):
        try:
            if not is_partitioned(db, name):
                continue
            for key in month_keys(months_back, months_ahead):
                start, end = month_bounds(key)
                try:
                    se.write_sql(db, "CREATE TABLE IF NOT EXISTS %s PARTITION OF %s "
                                     "FOR VALUES FROM ('%s') TO ('%s')"
                                % (partition_name(name, key), name, start, end), None, kind)
                    created.append(partition_name(name, key))
                except Exception:
                    pass
        except Exception:
            continue
    return created


def drop_old_partitions(db, table, retention_days):
    """DROP (instantly) the partitions that are fully older than the window."""
    kind = se.backend_kind(db)
    cutoff = (datetime.now() - timedelta(days=int(retention_days))).strftime("%Y-%m-%d")
    dropped, skipped = [], []
    try:
        if not is_partitioned(db, table):
            return {"table": table, "partitioned": False, "cutoff": cutoff,
                    "dropped": [], "skipped": []}
        rows = se.rows(db, """
            SELECT c.relname AS name FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
            JOIN pg_class p ON p.oid = i.inhparent WHERE p.relname = %s""" % se.placeholder(kind),
            (table,), kind)
        for row in rows or []:
            name = str(row.get("name") or "")
            parts = name.rsplit("_", 2)
            if len(parts) < 3:
                skipped.append(name)
                continue
            try:
                _start, end = month_bounds("%s_%s" % (parts[-2], parts[-1]))
            except Exception:
                skipped.append(name)
                continue
            if end <= cutoff:
                if se.write_sql(db, "DROP TABLE IF EXISTS " + name, None, kind) is not None:
                    dropped.append(name)
                else:
                    skipped.append(name)
            else:
                skipped.append(name)
    except Exception as exc:
        return {"table": table, "error": str(exc)[:160], "dropped": [], "skipped": []}
    return {"table": table, "partitioned": True, "cutoff": cutoff,
            "dropped": dropped, "skipped": skipped}


ROLLUP_SQL = """INSERT INTO daily_stats
    (day, machine_id, hostname, events, sysmon, alerts, traffic, syslog, computed_at)
    SELECT d::date, machine_id, MAX(hostname),
           SUM(CASE WHEN src = 'events' THEN n ELSE 0 END),
           SUM(CASE WHEN src = 'sysmon' THEN n ELSE 0 END),
           SUM(CASE WHEN src = 'alerts' THEN n ELSE 0 END),
           SUM(CASE WHEN src = 'traffic' THEN n ELSE 0 END),
           SUM(CASE WHEN src = 'syslog' THEN n ELSE 0 END),
           NOW()
    FROM (
        SELECT received_at::date AS d, machine_id, hostname, 'events' AS src, COUNT(*) AS n
          FROM events WHERE received_at >= NOW() - make_interval(days => %s) GROUP BY 1,2,3
        UNION ALL
        SELECT received_at::date, machine_id, hostname, 'sysmon', COUNT(*)
          FROM sysmon_events WHERE received_at >= NOW() - make_interval(days => %s) GROUP BY 1,2,3
        UNION ALL
        SELECT received_at::date, machine_id, hostname, 'alerts', COUNT(*)
          FROM threat_alerts WHERE received_at >= NOW() - make_interval(days => %s) GROUP BY 1,2,3
        UNION ALL
        SELECT received_at::date, machine_id, hostname, 'traffic', COUNT(*)
          FROM network_traffic WHERE received_at >= NOW() - make_interval(days => %s) GROUP BY 1,2,3
        UNION ALL
        SELECT received_at::date, COALESCE(NULLIF(source_ip, ''), 'syslog') AS machine_id,
               hostname, 'syslog', COUNT(*)
          FROM syslog WHERE received_at >= NOW() - make_interval(days => %s) GROUP BY 1,2,3
    ) raw
    GROUP BY 1,2
    ON CONFLICT (day, machine_id) DO UPDATE SET
        hostname = EXCLUDED.hostname, events = EXCLUDED.events, sysmon = EXCLUDED.sysmon,
        alerts = EXCLUDED.alerts, traffic = EXCLUDED.traffic, syslog = EXCLUDED.syslog,
        computed_at = NOW()"""


def rollup_daily(db, days=30):
    """Refresh `daily_stats` (per day + machine) from the raw tables.

    Keeps year-long questions ("how many events did host X send last quarter")
    off the raw tables - cheap enough for a nightly job.
    """
    kind = se.backend_kind(db)
    if kind != "postgres":
        return {"ok": False, "error": "rollup cần PostgreSQL"}
    days = max(1, int(days))
    try:
        se.write_sql(db, ROLLUP_SQL, (days, days, days, days, days), kind)
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:200]}
    rows = se.rows(db, "SELECT COUNT(*) AS n FROM daily_stats", None, kind)
    return {"ok": True, "days": days,
            "rows_in_table": int((rows[0] or {}).get("n") or 0) if rows else 0}


def storage_report(db, retention_days=None):
    """Sizes + partition state + retention for the storage/health panel."""
    kind = se.backend_kind(db)
    out = {"backend": kind, "tables": [], "retention_days": retention_days,
           "partitions_needed": []}
    if kind != "postgres":
        return out
    info = {i["table"]: i for i in partition_info(db)}
    for table in list(HOT_TABLES) + ["daily_stats", "case_evidence", "update_rollouts",
                                     "ingest_anomalies"]:
        try:
            rows = se.rows(db, """SELECT pg_size_pretty(pg_total_relation_size(c.oid)) AS size,
                                         pg_total_relation_size(c.oid) AS bytes,
                                         c.reltuples::bigint AS rows, c.relkind
                                  FROM pg_class c WHERE c.relname = %s""" % se.placeholder(kind),
                           (table,), kind)
        except Exception:
            continue
        if not rows:
            continue
        row = rows[0]
        entry = {"table": table, "size": row.get("size"),
                 "bytes": int(row.get("bytes") or 0), "rows": int(row.get("rows") or 0),
                 "partitioned": row.get("relkind") == "p",
                 "partitions": len((info.get(table) or {}).get("partitions") or [])}
        out["tables"].append(entry)
        if table in HOT_TABLES and not entry["partitioned"]:
            out["partitions_needed"].append(table)
    return out


