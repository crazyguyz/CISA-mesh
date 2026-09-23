#!/usr/bin/env python
"""v5.0.8 - Backfill / normalise asset codes (display_id).

Why this exists
---------------
Before v5.0.8 the human-readable asset code was generated in six places with
four different formats, and two of those paths never assigned a code at all:

  PostgreSQL + computers : the code only appeared on the 2nd config report
                           (the UPDATE ran before the row existed and the INSERT
                           had no display_id column)
  PostgreSQL + monitors  : the code was NEVER written
  auto-discovery / users : bare 8-hex hash, no prefix
  manual inventory       : "TS-PR-AB12CD" (12-13 chars)

The Assets page and the Excel export fall back to `asset_id` when display_id is
empty, and asset_id is a 32-character md5 hash - that is why the same column
showed short codes (PC-0887498B) next to very long ones.

What this tool does
-------------------
Gives every row the canonical code `{PREFIX}-{8 hex}` (11 chars):

  assets_computers   -> PC-XXXXXXXX
  assets_monitors    -> MN-XXXXXXXX
  assets_inventory   -> PR/DT/NM/NV/LK/US/TS-XXXXXXXX (from its category)

The value is derived from the row's asset_id, so it is identical to what the
API/dashboard already shows for a missing code and re-running the tool changes
nothing.

Modes
-----
  default      only rows with an EMPTY code (non destructive)
  --normalize  also rewrite codes that do not match the canonical scheme
               (old 8-hex values, "TS-PR-XXXXXX", 13-char codes, ...)

Dry-run by default: nothing is written without --apply.

Usage:
  python tools/backfill_display_ids.py                    # report only
  python tools/backfill_display_ids.py --normalize        # report incl. old formats
  python tools/backfill_display_ids.py --apply --yes      # write (empty rows only)
  python tools/backfill_display_ids.py --normalize --apply --yes
  python tools/backfill_display_ids.py --sqlite server/giamsat_data.db --apply
"""

import argparse
import datetime
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "server"))

# Reuse the exact .env discovery / backends of reset_data.py (same folder, same
# way of being launched), so there is one implementation of "which DB am I on".
from reset_data import SQLiteBackend, PostgresBackend, find_env, parse_env  # noqa: E402
from asset_ids import (make_display_id, derive_for_asset, is_canonical)  # noqa: E402

# (table, fixed category or None = read the row's category column)
TARGETS = (
    ("assets_computers", "computer"),
    ("assets_monitors", "monitor"),
    ("assets_inventory", None),
)
# column used to identify the row in the report
LABEL_COL = {"assets_computers": "hostname",
             "assets_monitors": "name",
             "assets_inventory": "name"}
SAMPLE_LIMIT = 6


def _rows(backend, sql, params=()):
    """SELECT -> list of dicts (works for both backends)."""
    if backend.label == "sqlite":
        cur = backend.conn.execute(sql, params)
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]
    from psycopg2.extras import RealDictCursor
    with backend.conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(sql, params)
        return [dict(r) for r in cur.fetchall()]


def _exec(backend, sql, params=()):
    if backend.label == "sqlite":
        cur = backend.conn.execute(sql, params)
        backend.conn.commit()
        return cur.rowcount or 0
    try:
        with backend.conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.rowcount or 0
    except Exception:
        backend.conn.rollback()
        raise


def _has_column(backend, table, column):
    try:
        if backend.label == "sqlite":
            cols = _rows(backend, 'PRAGMA table_info("%s")' % table)
            return any(c.get("name") == column for c in cols)
        rows = _rows(backend, "SELECT column_name FROM information_schema.columns "
                              "WHERE table_schema='public' AND table_name=%s "
                              "AND column_name=%s", (table, column))
        return bool(rows)
    except Exception:
        return False


def _add_column(backend, table):
    sql = ('ALTER TABLE "%s" ADD COLUMN display_id ' % table) + (
        "VARCHAR(32) DEFAULT ''" if backend.label != "sqlite" else "TEXT DEFAULT ''")
    _exec(backend, sql)


def _label(table, row):
    keys = [LABEL_COL.get(table)] + ["ip_address", "serial_number", "employee_id", "email"]
    for key in keys:
        if not key:
            continue
        val = (row.get(key) or "").strip()
        if val:
            return val[:40]
    return "-"


def _connect(args):
    """Return a backend (reuses reset_data's backends + error handling)."""
    if args.sqlite:
        if not os.path.exists(args.sqlite):
            print("[-] SQLite database not found: %s" % args.sqlite)
            return None, 2
        return SQLiteBackend(args.sqlite), 0
    env_path = find_env(args.env)
    if not env_path:
        print("[-] Could not find server/.env (looked for <root>/server/.env).")
        print("    Pass --env or --sqlite.")
        return None, 2
    env = parse_env(env_path)
    be = (env.get("GIAMSAT_DB_BACKEND") or "sqlite").strip().lower()
    if be in ("postgres", "postgresql", "pg"):
        try:
            return PostgresBackend(env), 0
        except ImportError:
            print("[-] psycopg2 is not installed for this Python interpreter.")
            return None, 2
        except Exception as e:
            print("[-] Cannot connect to PostgreSQL: %s" % str(e)[:200])
            return None, 2
    db_file = env.get("GIAMSAT_DB_PATH") or "giamsat_data.db"
    if not os.path.isabs(db_file):
        db_file = os.path.join(os.path.dirname(env_path), db_file)
    if not os.path.exists(db_file):
        print("[-] SQLite database not found: %s" % db_file)
        return None, 2
    return SQLiteBackend(db_file), 0


def main():
    ap = argparse.ArgumentParser(
        description="Assign the canonical {PREFIX}-{8 hex} asset code to rows whose "
                    "display_id is empty. Dry-run by default.")
    ap.add_argument("--normalize", action="store_true",
                    help="also rewrite codes that do not match the canonical scheme "
                         "(old 8-hex / TS-XX-xxxxxx / 13-char values)")
    ap.add_argument("--only", help="comma list: computers,monitors,inventory")
    ap.add_argument("--env", help="path to server/.env (PG connection + backend)")
    ap.add_argument("--sqlite", help="path to a SQLite database (overrides .env)")
    ap.add_argument("--apply", action="store_true",
                    help="write the changes (default is a dry-run report)")
    ap.add_argument("--yes", action="store_true",
                    help="skip the interactive YES confirmation (for scripts)")
    args = ap.parse_args()

    print("=" * 68)
    print("  GIAM-SAT - Backfill asset codes (display_id)")
    print("=" * 68)
    print("[i] Mode: %s" % ("normalize (empty + non-standard codes)" if args.normalize
                            else "fill empty codes only (--normalize also "
                                 "rewrites old formats)"))

    only = None
    if args.only:
        alias = {"computers": "assets_computers", "monitors": "assets_monitors",
                 "inventory": "assets_inventory"}
        known = [t for t, _ in TARGETS]
        only = set()
        for part in args.only.split(","):
            part = part.strip().lower()
            if not part:
                continue
            name = alias.get(part, part)
            if name not in known:
                print("[-] unknown --only value: %s (use computers,monitors,inventory)" % part)
                return 2
            only.add(name)

    backend, code = _connect(args)
    if not backend:
        return code
    print("[*] Backend: %s" % backend.describe())

    tables = set(backend.tables())
    planned = []          # (table, asset_id, old, new, label)
    added_columns = []

    for table, fixed_cat in TARGETS:
        if only and table not in only:
            continue
        if table not in tables:
            print("[i] %-18s not present in this database - skipped" % table)
            continue
        if not _has_column(backend, table, "display_id"):
            # Very old DB: the server adds this column on startup - do the same.
            print("[!] %-18s has no display_id column - it will be added" % table)
            if not args.apply:
                print("    re-run with --apply to add it and backfill the codes")
                continue
            _add_column(backend, table)
            added_columns.append(table)
        select = "asset_id, display_id" + (", category" if fixed_cat is None else "")
        label_col = LABEL_COL.get(table)
        if label_col:
            select += ", " + label_col
        rows = _rows(backend, 'SELECT %s FROM "%s"' % (select, table))
        used = set((r.get("display_id") or "").strip() for r in rows)
        used.discard("")
        fix_empty = fix_old = 0
        for row in rows:
            asset_id = (row.get("asset_id") or "").strip()
            if not asset_id:
                continue
            old = (row.get("display_id") or "").strip()
            category = (row.get("category") if fixed_cat is None else fixed_cat) or "other"
            if old:
                if not (args.normalize and not is_canonical(old)):
                    continue
                fix_old += 1
            else:
                fix_empty += 1
            new = derive_for_asset(category, asset_id)
            if not new:
                continue
            if new in used:
                # derived code already taken (or an md5 collision) -> random code
                new = make_display_id(category)
            if old:
                used.discard(old)
            used.add(new)
            planned.append((table, asset_id, old, new, _label(table, row)))
        print("[i] %-18s %d row(s): %d empty + %d non-standard -> %d to fix"
              % (table, len(rows), fix_empty, fix_old, fix_empty + fix_old))

    print("-" * 68)
    if not planned:
        print("[+] Nothing to do - every asset already has a canonical code.")
        backend.close()
        return 0
    for table, asset_id, old, new, label in planned[:SAMPLE_LIMIT]:
        print("    %-18s %-12s <- %-34s %s" % (table, new, old or "(empty)", label))
    if len(planned) > SAMPLE_LIMIT:
        print("    ... and %d more" % (len(planned) - SAMPLE_LIMIT))
    print("-" * 68)
    print("[i] %d row(s) would be updated" % len(planned))

    if not args.apply:
        print("")
        print("[!] DRY RUN - nothing was changed.")
        print("    Re-run with --apply to write (add --yes for non-interactive).")
        backend.close()
        return 0

    if not args.yes:
        print("")
        try:
            reply = input("Type YES to update these rows: ").strip()
        except EOFError:
            reply = ""
        if reply != "YES":
            print("[!] Aborted - nothing was changed.")
            backend.close()
            return 1

    ph = backend.PH
    done = failed = 0
    for table, asset_id, old, new, label in planned:
        try:
            # only overwrite an empty value, or exactly the value we read
            done += _exec(backend,
                          'UPDATE "%s" SET display_id=%s WHERE asset_id=%s '
                          "AND COALESCE(display_id,'')=%s" % (table, ph, ph, ph),
                          (new, asset_id, old))
        except Exception as e:
            failed += 1
            print("[-] %s %s: %s" % (table, asset_id[:12], str(e)[:120]))
    backend.close()

    print("")
    print("[+] Done - %d row(s) updated, %d failed." % (done, failed))
    if added_columns:
        print("[i] Added the display_id column to: %s" % ", ".join(added_columns))
    print("[i] Reload the Assets page to see the new codes.")
    print("[i] Codes are stable - re-running this tool changes nothing.")
    print("[i] Backfilled at %s" % datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    return 0 if not failed else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[*] Interrupted.")
        sys.exit(130)
