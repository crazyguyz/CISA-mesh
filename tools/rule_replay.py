#!/usr/bin/env python
"""
GIAM-SAT Rule Quality / Replay Tool v5.0.8
Runs recent events through the correlation ruleset and reports per-rule hit
counts so you can tell which rules are DEAD (no matching events even though the
relevant event IDs exist) and which are FP candidates (hit far too often).
Read-only - never modifies the database.

Usage:
    python tools/rule_replay.py                      # PG/SQLite from server/.env
    python tools/rule_replay.py --hours 48 --limit 50000
    python tools/rule_replay.py --env D:/test/server/.env
    python tools/rule_replay.py --sqlite server/giamsat_data.db   # legacy SQLite
    python tools/rule_replay.py --rules server/rules/correlation_rules.yaml

v5.0.8: this tool used to be SQLite-only and hardcoded
`<root>/server/giamsat_data.db`, so on a PostgreSQL install (the default since
v5.0.x) it stopped with "DB not found" even though the server was fine. It now
resolves the backend exactly like the server and the other tools
(GIAMSAT_DB_BACKEND in server/.env: postgres or sqlite); `--db` is kept as a
deprecated alias of `--sqlite`.

Notes:
  - field_contains / path_contains conditions cannot be evaluated against the
    stored events table (parsed fields live on the agent at send time), so
    rules with only field conditions are reported as "field-conditions only"
    rather than matched against text. Use the live engine for full fidelity.
"""
import argparse
import os
import sys

try:
    import yaml
except ImportError:
    print("PyYAML required: pip install pyyaml")
    sys.exit(1)

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_DB = os.path.join(BASE, "server", "giamsat_data.db")
DEFAULT_RULES = os.path.join(BASE, "server", "rules", "correlation_rules.yaml")
# columns we try to read from `events` (older/newer schemas differ)
EVENT_COLS = ("type", "event_id", "description", "action", "subtype", "machine_id")
PG_BACKENDS = ("postgres", "postgresql", "pg")


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
    candidates.append(os.path.join(BASE, "server", ".env"))
    candidates.append(os.path.join(os.getcwd(), "server", ".env"))
    for c in candidates:
        if c and os.path.exists(c):
            return c
    return None


def fetch_sqlite(path, hours, limit):
    import sqlite3
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        cols = [r[1] for r in conn.execute("PRAGMA table_info(events)").fetchall()]
        sel = [c for c in EVENT_COLS if c in cols]
        rows = conn.execute(
            "SELECT " + ", ".join(sel) +
            " FROM events WHERE received_at >= datetime('now', ?) ORDER BY id DESC LIMIT ?",
            ("-%d hours" % hours, limit)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def fetch_postgres(env, hours, limit):
    import psycopg2
    conn = psycopg2.connect(
        host=env.get("GIAMSAT_PG_HOST", "127.0.0.1"),
        port=int(env.get("GIAMSAT_PG_PORT", "5432")),
        dbname=env.get("GIAMSAT_PG_DBNAME", "giamsat"),
        user=env.get("GIAMSAT_PG_USER", "postgres"),
        password=env.get("GIAMSAT_PG_PASSWORD", ""),
    )
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT column_name FROM information_schema.columns "
                        "WHERE table_name='events'")
            cols = {r[0] for r in cur.fetchall()}
            sel = [c for c in EVENT_COLS if c in cols]
            if not sel:
                print("[-] Table `events` not found in the PostgreSQL database "
                      "(start the server once so it creates the schema).")
                sys.exit(2)
            cur.execute("SELECT " + ", ".join(sel) +
                        " FROM events WHERE received_at >= NOW() - make_interval(hours => %s)"
                        " ORDER BY id DESC LIMIT %s", (hours, limit))
            names = [d[0] for d in cur.description]
            return [dict(zip(names, r)) for r in cur.fetchall()]
    finally:
        conn.close()


def connect(args):
    """Resolve the backend like reset_data.py: --sqlite wins, else server/.env."""
    sqlite_path = args.sqlite or args.db
    if sqlite_path:
        if not os.path.exists(sqlite_path):
            print("[-] SQLite database not found: %s" % sqlite_path)
            sys.exit(2)
        return "SQLite  %s" % sqlite_path, fetch_sqlite(sqlite_path, args.hours, args.limit)

    env_path = find_env(args.env)
    if not env_path:
        print("[-] Could not find server/.env (looked for <root>/server/.env).")
        print("    PostgreSQL installs keep the events in the DB, not in a file: pass")
        print("    --env <path to server/.env>, or --sqlite <file> for a SQLite install.")
        sys.exit(2)
    env = parse_env(env_path)
    backend = (env.get("GIAMSAT_DB_BACKEND") or "sqlite").strip().lower()
    if backend in PG_BACKENDS:
        label = "PostgreSQL  %s@%s:%s/%s  (config %s)" % (
            env.get("GIAMSAT_PG_USER", "postgres"),
            env.get("GIAMSAT_PG_HOST", "127.0.0.1"),
            env.get("GIAMSAT_PG_PORT", "5432"),
            env.get("GIAMSAT_PG_DBNAME", "giamsat"), env_path)
        try:
            return label, fetch_postgres(env, args.hours, args.limit)
        except ImportError:
            print("[-] psycopg2 is not installed for this Python interpreter.")
            print("    Install it (pip install psycopg2-binary) or pass --sqlite.")
            sys.exit(2)
        except Exception as e:
            print("[-] Cannot read PostgreSQL: %s" % str(e)[:200])
            print("    Check GIAMSAT_PG_* in %s (or run tools\\fix_pg_auth.ps1)." % env_path)
            sys.exit(2)

    db_file = env.get("GIAMSAT_DB_PATH") or "giamsat_data.db"
    if not os.path.isabs(db_file):
        db_file = os.path.join(os.path.dirname(env_path), db_file)
    if not os.path.exists(db_file):
        print("[-] SQLite database not found: %s (backend=sqlite in %s)" % (db_file, env_path))
        sys.exit(2)
    return ("SQLite  %s  (config %s)" % (db_file, env_path),
            fetch_sqlite(db_file, args.hours, args.limit))


def load_rules(path):
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if isinstance(data, dict):
        return data.get("rules", [])
    return data or []


def match_condition(event, cond):
    """Replica of the server engine's basic condition matching (text level).
    field_contains is skipped (parsed fields are not persisted)."""
    ct = cond.get("type")
    if ct:
        et = event.get("type")
        if ct == "event":
            if et not in ("event", "windows_event"):
                return False
        elif ct != et:
            return False
    ids = cond.get("event_id")
    if ids:
        eid = str(event.get("event_id", ""))
        if isinstance(ids, list):
            if eid not in ids:
                return False
        elif eid != str(ids):
            return False
    dc = cond.get("description_contains")
    if dc:
        desc = str(event.get("description", "")).lower()
        pats = dc if isinstance(dc, list) else [dc]
        if not any(str(p).lower() in desc for p in pats):
            return False
    act = cond.get("action")
    if act and event.get("action", "") != act:
        return False
    return True


def main():
    ap = argparse.ArgumentParser(
        description="GIAM-SAT rule quality replay (read-only): replays recent events "
                    "through the correlation ruleset to find dead rules and FP candidates.")
    ap.add_argument("--env", help="path to server/.env (PG connection + backend)")
    ap.add_argument("--sqlite", help="path to a SQLite database (overrides .env)")
    ap.add_argument("--db", help="deprecated alias of --sqlite (kept for old scripts)")
    ap.add_argument("--rules", default=DEFAULT_RULES)
    ap.add_argument("--hours", type=int, default=24)
    ap.add_argument("--limit", type=int, default=20000)
    ap.add_argument("--min-hits", type=int, default=0, help="only show rules with >= N matches")
    args = ap.parse_args()

    if not os.path.exists(args.rules):
        print("[-] Rules file not found: %s" % args.rules)
        sys.exit(2)

    print("=" * 90)
    print("  GIAM-SAT - rule quality replay (read-only)")
    print("=" * 90)
    label, events = connect(args)
    rules = load_rules(args.rules)
    print("[*] Backend : %s" % label)
    print("[*] Rules   : %d from %s" % (len(rules), args.rules))
    print("[*] Window  : last %dh (limit %d)" % (args.hours, args.limit))
    print("[*] Events  : %d scanned\n" % len(events))

    # scope: how many events carry each (type, event_id)
    scope = {}
    for e in events:
        key = (e.get("type"), str(e.get("event_id", "")))
        scope[key] = scope.get(key, 0) + 1

    report = []
    for rule in rules:
        rid = rule.get("id", "?")
        name = rule.get("name", "?")[:60]
        sev = rule.get("severity", "?")
        conds = rule.get("conditions", [])
        if not conds:
            continue
        has_field_cond = any(c.get("field_contains") or c.get("path_contains") for c in conds)
        # scope = events matching type+event_id of ANY condition
        evt_scope = 0
        for c in conds:
            key = (c.get("type"), str(c.get("event_id", "")))
            evt_scope += scope.get(key, 0)
        # matches = events satisfying at least one condition (text level)
        matches = sum(1 for e in events if any(match_condition(e, c) for c in conds))
        report.append({
            "id": rid, "name": name, "sev": sev,
            "scope": evt_scope, "matches": matches,
            "has_field_cond": has_field_cond,
        })

    report.sort(key=lambda r: r["scope"])

    # Print dead rules first (scope>0 but matches==0 => rule sees events but never fires)
    dead = [r for r in report if r["scope"] > 0 and r["matches"] == 0 and not r["has_field_cond"]]
    fp = [r for r in report if r["matches"] > max(20, args.min_hits)]
    no_data = [r for r in report if r["scope"] == 0]

    print("=" * 90)
    print(f"DEAD rules (events exist but rule never fired): {len(dead)}")
    print("=" * 90)
    for r in dead[:30]:
        print(f"  {r['id']:16s} [{r['sev']:8s}] scope={r['scope']:6d} match={r['matches']:5d}  {r['name']}")

    print("\n" + "=" * 90)
    print(f"FP CANDIDATES (matches > 20): {len(fp)}")
    print("=" * 90)
    for r in fp[:30]:
        print(f"  {r['id']:16s} [{r['sev']:8s}] scope={r['scope']:6d} match={r['matches']:6d}  {r['name']}")

    print("\n" + "=" * 90)
    print(f"NO DATA (no matching event_id in window): {len(no_data)}")
    print("=" * 90)
    for r in no_data[:20]:
        print(f"  {r['id']:16s} [{r['sev']:8s}]  {r['name']}")

    field_only = [r for r in report if r["has_field_cond"]]
    print(f"\nRules with field_contains/path conditions (not text-evaluable here): {len(field_only)}")


if __name__ == "__main__":
    main()
