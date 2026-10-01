"""GIAM-SAT fleet store - v5.0.8 (Phase C).

Rollout + ingest-health persistence for BOTH backends (PostgreSQL and SQLite) on
top of the tiny DB helpers in search_engine.py, so the tables stay declarative in
db_postgres._init_db / db_manager and every query lives in one place.
"""

import json
from datetime import datetime

import search_engine as se

ROLLOUT_COLS = ("id", "name", "target_version", "previous_version", "state", "wave_index",
                "waves_json", "machine_ids_json", "group_id", "created_by", "created_at",
                "updated_at", "notes")
TARGET_COLS = ("id", "rollout_id", "machine_id", "hostname", "wave", "status",
               "from_version", "to_version", "message", "requested_at", "updated_at")


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _new_id(value):
    return value.get("id") if isinstance(value, dict) else value


def create_rollout(db, name, target_version, previous_version, waves, machine_ids,
                   group_id="", created_by=""):
    """Insert a rollout (state='planned') and return its id."""
    kind = se.backend_kind(db)
    ph = se.placeholder(kind)
    sql = ("INSERT INTO update_rollouts (name, target_version, previous_version, state, "
           "wave_index, waves_json, machine_ids_json, group_id, created_by, created_at, "
           "updated_at) VALUES (%s) RETURNING id" % ", ".join([ph] * 11))
    params = (str(name or "")[:120], str(target_version or ""), str(previous_version or ""),
              "planned", 0, json.dumps(waves or []), json.dumps(machine_ids or []),
              str(group_id or ""), str(created_by or ""), _now(), _now())
    return _new_id(se.write_sql(db, sql, params, kind, returning=True))


def get_rollout(db, rollout_id):
    kind = se.backend_kind(db)
    rows = se.rows(db, "SELECT %s FROM update_rollouts WHERE id = %s"
                   % (", ".join(ROLLOUT_COLS), se.placeholder(kind)), (int(rollout_id),), kind)
    return se.normalize_row(rows[0]) if rows else None


def list_rollouts(db, limit=50):
    kind = se.backend_kind(db)
    rows = se.rows(db, "SELECT %s FROM update_rollouts ORDER BY id DESC LIMIT %s"
                   % (", ".join(ROLLOUT_COLS), se.placeholder(kind)), (int(limit),), kind)
    return [se.normalize_row(r) for r in rows]


def update_rollout(db, rollout_id, **fields):
    """Patch state / wave_index / notes / target_version / previous_version."""
    allowed = {"state", "wave_index", "notes", "target_version", "previous_version"}
    patch = {k: v for k, v in fields.items() if k in allowed and v is not None}
    if not patch:
        return False
    kind = se.backend_kind(db)
    ph = se.placeholder(kind)
    sets = ", ".join("%s = %s" % (k, ph) for k in patch)
    sql = "UPDATE update_rollouts SET %s, updated_at = %s WHERE id = %s" % (sets, ph, ph)
    params = list(patch.values()) + [_now(), int(rollout_id)]
    return se.write_sql(db, sql, tuple(params), kind) is not None


def set_rollout_targets(db, rollout_id, rows):
    """Bulk-insert the planned targets (an existing status is kept on re-plan)."""
    kind = se.backend_kind(db)
    ph = se.placeholder(kind)
    sql = ("INSERT INTO update_rollout_targets (rollout_id, machine_id, hostname, wave, "
           "status, from_version, to_version, requested_at, updated_at) VALUES (%s) "
           "ON CONFLICT(rollout_id, machine_id) DO UPDATE SET hostname = EXCLUDED.hostname, "
           "wave = EXCLUDED.wave, to_version = EXCLUDED.to_version" % ", ".join([ph] * 9))
    written = 0
    for row in rows or []:
        ok = se.write_sql(db, sql, (
            int(rollout_id), str(row.get("machine_id") or ""), str(row.get("hostname") or ""),
            int(row.get("wave") or 0), str(row.get("status") or "pending"),
            str(row.get("from_version") or ""), str(row.get("to_version") or ""),
            row.get("requested_at"), _now()), kind)
        written += 1 if ok is not None else 0
    return written


def list_rollout_targets(db, rollout_id, wave=None):
    kind = se.backend_kind(db)
    ph = se.placeholder(kind)
    sql = ("SELECT %s FROM update_rollout_targets WHERE rollout_id = %s"
           % (", ".join(TARGET_COLS), ph))
    params = [int(rollout_id)]
    if wave is not None:
        sql += " AND wave = %s" % ph
        params.append(int(wave))
    sql += " ORDER BY wave, hostname"
    return [se.normalize_row(r) for r in se.rows(db, sql, tuple(params), kind)]


def update_rollout_target(db, rollout_id, machine_id, status=None, message=None,
                          to_version=None, requested_at=None):
    kind = se.backend_kind(db)
    ph = se.placeholder(kind)
    sets, params = [], []
    for column, value in (("status", status), ("message", message), ("to_version", to_version),
                          ("requested_at", requested_at)):
        if value is not None:
            sets.append("%s = %s" % (column, ph))
            params.append(value)
    if not sets:
        return False
    sets.append("updated_at = %s" % ph)
    params.extend([_now(), int(rollout_id), str(machine_id)])
    sql = ("UPDATE update_rollout_targets SET " + ", ".join(sets) +
           " WHERE rollout_id = " + ph + " AND machine_id = " + ph)
    return se.write_sql(db, sql, tuple(params), kind) is not None


def heartbeat_map(db):
    """{machine_id: 'YYYY-mm-dd HH:MM:SS'} of the newest heartbeat per machine."""
    kind = se.backend_kind(db)
    try:
        rows = se.rows(db, "SELECT machine_id, MAX(received_at) AS last_hb FROM heartbeats "
                           "GROUP BY machine_id", None, kind)
    except Exception:
        return {}
    out = {}
    for row in rows:
        row = se.normalize_row(row)
        if row.get("machine_id"):
            out[str(row["machine_id"])] = str(row.get("last_hb") or "")
    return out


def upsert_ingest_anomaly(db, bucket, source_ip, reason, msg_type, count=1):
    """Add `count` rejects for one (bucket, source, reason, msg_type) key."""
    kind = se.backend_kind(db)
    ph = se.placeholder(kind)
    stamp = "NOW()" if kind == "postgres" else "CURRENT_TIMESTAMP"
    sql = ("INSERT INTO ingest_anomalies (bucket, source_ip, reason, msg_type, count, "
           "last_seen) VALUES (" + ", ".join([ph] * 5 + [stamp]) +
           ") ON CONFLICT(bucket, source_ip, reason, msg_type) DO UPDATE SET "
           "count = ingest_anomalies.count + EXCLUDED.count, last_seen = " + stamp)
    return se.write_sql(db, sql, (str(bucket), str(source_ip or ""), str(reason or ""),
                                  str(msg_type or ""), int(count)), kind) is not None


def list_ingest_anomalies(db, hours=24, limit=200):
    kind = se.backend_kind(db)
    ph = se.placeholder(kind)
    if kind == "postgres":
        where, args = ("WHERE last_seen >= NOW() - make_interval(hours => %s)" % ph,
                       [int(hours)])
    else:
        where, args = ("WHERE last_seen >= datetime('now', %s)" % ph, ["-%d hours" % int(hours)])
    args.append(int(limit))
    sql = ("SELECT bucket, source_ip, reason, msg_type, count, last_seen FROM ingest_anomalies "
           "%s ORDER BY count DESC LIMIT %s" % (where, ph))
    return [se.normalize_row(r) for r in se.rows(db, sql, tuple(args), kind)]
