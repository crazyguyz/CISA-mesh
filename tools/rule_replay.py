#!/usr/bin/env python
"""
GIAM-SAT Rule Quality / Replay Tool v4.11 (A4)
Runs recent events through the correlation ruleset and reports per-rule hit
counts so you can tell which rules are DEAD (no matching events even though the
relevant event IDs exist) and which are FP candidates (hit far too often).
Read-only - never modifies the database.

Usage:
    python tools/rule_replay.py --hours 24 --limit 20000
    python tools/rule_replay.py --rules server/rules/correlation_rules.yaml --db server/giamsat_data.db

Notes:
  - field_contains / path_contains conditions cannot be evaluated against the
    stored events table (parsed fields live on the agent at send time), so
    rules with only field conditions are reported as "field-conditions only"
    rather than matched against text. Use the live engine for full fidelity.
"""
import argparse
import json
import os
import sqlite3
import sys

try:
    import yaml
except ImportError:
    print("PyYAML required: pip install pyyaml")
    sys.exit(1)

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_DB = os.path.join(BASE, "server", "giamsat_data.db")
DEFAULT_RULES = os.path.join(BASE, "server", "rules", "correlation_rules.yaml")


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
    ap = argparse.ArgumentParser(description="GIAM-SAT rule quality replay")
    ap.add_argument("--db", default=DEFAULT_DB)
    ap.add_argument("--rules", default=DEFAULT_RULES)
    ap.add_argument("--hours", type=int, default=24)
    ap.add_argument("--limit", type=int, default=20000)
    ap.add_argument("--min-hits", type=int, default=0, help="only show rules with >= N matches")
    args = ap.parse_args()

    if not os.path.exists(args.db):
        print(f"DB not found: {args.db}")
        sys.exit(1)
    rules = load_rules(args.rules)
    print(f"Rules loaded: {len(rules)} from {args.rules}")
    print(f"Events window: last {args.hours}h (limit {args.limit}) from {args.db}\n")

    conn = sqlite3.connect(args.db)
    conn.row_factory = sqlite3.Row
    # the events table may or may not have an 'action' column depending on schema
    cols = [r[1] for r in conn.execute("PRAGMA table_info(events)").fetchall()]
    sel_cols = [c for c in ("type", "event_id", "description", "action", "subtype", "machine_id") if c in cols]
    rows = conn.execute(
        "SELECT " + ", ".join(sel_cols) +
        " FROM events WHERE received_at >= datetime('now', ?) ORDER BY id DESC LIMIT ?",
        (f"-{args.hours} hours", args.limit)).fetchall()
    events = [dict(r) for r in rows]
    conn.close()
    print(f"Events scanned: {len(events)}\n")

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
