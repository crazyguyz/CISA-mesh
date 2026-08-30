# -*- coding: utf-8 -*-
"""
SQLite -> PostgreSQL migration for GIAM-SAT (v5.0.4).

Usage:
    python tools/migrate_sqlite_to_pg.py --dry          # counts only
    python tools/migrate_sqlite_to_pg.py --run          # migrate everything
    python tools/migrate_sqlite_to_pg.py --run --only events,syslog

- Ensures the PG schema first via PostgresDatabase._init_db (creates missing
  tables/columns/indexes, incl. the v5.0.4 `status` triage columns).
- Copies every SQLite table into the giamsat PG database with type adaptation
  (jsonb/boolean/timestamps, '' -> NULL).
- events: excludes id (PG assigns), dedups via dedup_key (already populated).
- commands: skips 'pending' rows (never re-execute stale commands on agents).
- Natural-key ON CONFLICT where the PG table has one; setval() after each table.
- Credentials: read from server/.env (GIAMSAT_PG_*), else the process env.
"""
import os, sys, sqlite3, json

def load_pg_config():
    env = {}
    for base in (r"E:\giamsat\server", r"D:\test\server"):
        p = os.path.join(base, ".env")
        if os.path.exists(p):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#") or "=" not in line:
                            continue
                        k, _, v = line.partition("=")
                        env[k.strip()] = v.strip().strip('"').strip("'")
                if env.get("GIAMSAT_PG_PASSWORD"):
                    break
            except Exception:
                pass
    def g(k, d=""):
        return os.environ.get(k) or env.get(k) or d
    return dict(
        host=g("GIAMSAT_PG_HOST", "127.0.0.1"),
        port=int(g("GIAMSAT_PG_PORT", "5432")),
        dbname=g("GIAMSAT_PG_DBNAME", "giamsat"),
        user=g("GIAMSAT_PG_USER", "postgres"),
        password=g("GIAMSAT_PG_PASSWORD", ""),
    )

PG = load_pg_config()
SQLITE = os.environ.get("GIAMSAT_SQLITE_DB", r"server\giamsat_data.db")
if not os.path.isabs(SQLITE):
    SQLITE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", SQLITE)
MODE = "--run" in sys.argv

# --- ensure PG schema via the real adapter (creates tables/columns/indexes) ---
os.environ.update({
    "GIAMSAT_PG_HOST": PG["host"], "GIAMSAT_PG_PORT": str(PG["port"]),
    "GIAMSAT_PG_DBNAME": PG["dbname"], "GIAMSAT_PG_USER": PG["user"],
    "GIAMSAT_PG_PASSWORD": PG["password"],
})
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "server"))
from db_postgres import PostgresDatabase
_pd = PostgresDatabase()
if not getattr(_pd, "_connected", False):
    raise SystemExit("PostgresDatabase not connected - aborting")
print("[*] PG schema ensured via PostgresDatabase._init_db")

import psycopg2
sq = sqlite3.connect(SQLITE)
pg = psycopg2.connect(**PG)
pg.autocommit = True
pc = pg.cursor()

ONLY = None
if "--only" in sys.argv:
    ONLY = set(sys.argv[sys.argv.index("--only") + 1].split(","))


# --- natural unique keys for ON CONFLICT ---
NATURAL = {
    "machines": ("machine_id", "UPDATE"),
    "machine_users": ("machine_id", "UPDATE"),
    "agent_groups": ("name", "NOTHING"),
    "messages": ("msg_id", "NOTHING"),
    "agent_group_members": ("machine_id", "NOTHING"),
    "fim_baseline": ("machine_id, path", "NOTHING"),
    "hardware_info": ("machine_id", "NOTHING"),
    "hardware_baseline": ("machine_id", "NOTHING"),
    "custom_dashboards": ("name", "NOTHING"),
    "machine_uptime": ("machine_id, date, session_start", "NOTHING"),
    "assets_computers": ("asset_id", "NOTHING"),
    "assets_monitors": ("asset_id", "NOTHING"),
    "assets_relations": ("computer_asset_id, monitor_asset_id", "NOTHING"),
    "assets_inventory": ("asset_id", "NOTHING"),
}

def pg_types(table):
    pc.execute("""SELECT column_name, data_type FROM information_schema.columns
                  WHERE table_schema='public' AND table_name=%s""", (table,))
    return dict(pc.fetchall())

def sq_cols(table):
    return [(c[1], c[2]) for c in sq.execute('PRAGMA table_info("%s")' % table)]

def adapt(v, pgtype):
    if v is None:
        return None
    if pgtype == "jsonb":
        if isinstance(v, (dict, list)):
            return json.dumps(v, ensure_ascii=False)
        s = str(v).strip()
        if not s:
            return None
        try:
            json.loads(s)
            return s
        except Exception:
            return json.dumps(s, ensure_ascii=False)
    if pgtype == "boolean":
        if str(v).strip() == "":
            return None
        return bool(v)
    if "timestamp" in pgtype:
        s = str(v).strip()
        if not s or s.lower() in ("none", "null"):
            return None
        import re as _re
        m = _re.match(r"^\w{3}\s+(\w{3})\s+(\d{1,2})\s+(\d{1,2}):(\d{1,2}):(\d{1,2})\s+(\d{4})$", s)
        if m:
            MON = {"Jan":"01","Feb":"02","Mar":"03","Apr":"04","May":"05","Jun":"06",
                   "Jul":"07","Aug":"08","Sep":"09","Oct":"10","Nov":"11","Dec":"12"}
            mm = MON.get(m.group(1).capitalize()[:3])
            if mm:
                return f"{m.group(6)}-{mm}-{m.group(2).zfill(2)} {m.group(3)}:{m.group(4)}:{m.group(5)}"
        return s
    return v

def migrate_table(table):
    if table == "commands":
        rows = sq.execute('SELECT * FROM commands WHERE status != "pending"').fetchall()
    else:
        rows = sq.execute('SELECT * FROM "%s"' % table).fetchall()
    if not rows:
        print(f"  {table}: 0 rows - skip")
        return 0
    sq_col = sq_cols(table)
    names = [c[0] for c in sq_col]
    pgt = pg_types(table)
    ins_cols = [n for n in names if n != "id"]
    sqlite_rows = [tuple(r[names.index(n)] for n in ins_cols) for r in rows]

    conflict = ""
    if table == "events":
        conflict = " ON CONFLICT (dedup_key) WHERE dedup_key IS NOT NULL DO NOTHING"
    elif table in NATURAL:
        key, action = NATURAL[table]
        if action == "UPDATE":
            keyset = set(x.strip() for x in key.split(","))
            set_list = ", ".join(f"{c}=EXCLUDED.{c}" for c in ins_cols if c not in keyset)
            conflict = f" ON CONFLICT ({key}) DO UPDATE SET {set_list}"
        else:
            conflict = f" ON CONFLICT ({key}) DO NOTHING"
    cols_sql = ", ".join('"%s"' % c for c in ins_cols)
    ph_sql = ", ".join(["%s"] * len(ins_cols))
    sql = "INSERT INTO \"%s\" (%s) VALUES (%s)%s" % (table, cols_sql, ph_sql, conflict)

    total = 0
    batch = []
    for row in sqlite_rows:
        batch.append(tuple(adapt(v, pgt.get(n, "text")) for v, n in zip(row, ins_cols)))
        if len(batch) >= 1000:
            pc.executemany(sql, batch)
            total += len(batch)
            batch = []
    if batch:
        pc.executemany(sql, batch)
        total += len(batch)
    try:
        pc.execute("SELECT setval(pg_get_serial_sequence('%s','id'), COALESCE((SELECT max(id) FROM \"%s\"),1))" % (table, table))
    except Exception:
        pass
    print(f"  {table}: inserted {total} (sqlite had {len(rows)})")
    return total

def create_network_baseline():
    """v5.0.4: proper PG DDL (was copying the SQLite schema -> id without a
    default). db_postgres._init_db also owns this table now; this is a safety net."""
    pc.execute("""CREATE TABLE IF NOT EXISTS network_baseline (
        id SERIAL PRIMARY KEY,
        dst_ip TEXT NOT NULL,
        country_code TEXT DEFAULT 'UNKNOWN',
        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        hit_count INTEGER DEFAULT 1,
        UNIQUE(dst_ip, country_code)
    )""")
    print("[*] created network_baseline in PG")

sqtables = [r[0] for r in sq.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
if ONLY:
    sqtables = [t for t in sqtables if t in ONLY]

if MODE:
    create_network_baseline()
    print("=== MIGRATING ===")
    grand = 0
    for t in sqtables:
        try:
            grand += migrate_table(t)
        except Exception as e:
            print(f"  !! {t} FAILED: {e}")
    print(f"TOTAL rows migrated: {grand}")
else:
    print("=== DRY RUN - counts only (no writes) ===")
    for t in sqtables:
        n = sq.execute('SELECT COUNT(*) FROM "%s"' % t).fetchone()[0]
        print(f"  {t}: {n}")
    print("(run with --run to migrate)")

sq.close(); pg.close()
