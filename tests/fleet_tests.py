#!/usr/bin/env python
"""GIAM-SAT fleet operations (rollout + health) regression tests - v5.0.8.

Guards Phase C:

  * plan_waves: the canary is always >= 1 machine, percentages are honoured, every
    machine appears exactly once and the last wave absorbs the remainder.
  * wave_health / health_gate: a wave is only "healthy" at >= 90% updated with
    zero failures, so a bad build cannot be promoted to the next wave.
  * reconcile_targets: statuses follow the live `machines.version` values (an
    offline machine is not a failure).
  * machine_health_rows: silent / offline / outdated / coverage flags + summary.
  * aggregate_anomalies + policy_preview (dry-run diff, warnings, bad JSON).
  * wiring: the three new tables exist in BOTH backends, api_fleet is registered,
    tcp_server counts rejected ingest (it used to only print to the log), the UI
    module/panel/i18n keys exist.
  * live (--pg [--env file]): a full rollout round trip on FAKE machine ids
    (create -> targets -> reconcile -> gate -> rollback) and ingest-anomaly
    counters, then everything is deleted again.

Usage:
  python tests/fleet_tests.py                  # unit + static
  python tests/fleet_tests.py --pg --env D:/test/server/.env
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

import fleet as fl  # noqa: E402

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


def test_plan_and_gate():
    print("\n-- wave planning + health gate --")
    ids = ["m%02d" % i for i in range(1, 21)]
    plan = fl.plan_waves(ids)
    sizes = [len(w["machines"]) for w in plan]
    check("default waves are 1% / 10% / rest", sizes == [1, 2, 17], sizes)
    flat = [m for w in plan for m in w["machines"]]
    check("every machine appears exactly once",
          len(flat) == len(ids) and sorted(flat) == sorted(ids), len(flat))
    check("wave 0 is the canary", plan[0]["index"] == 0 and len(plan[0]["machines"]) == 1)
    check("a single machine still gets one wave",
          [len(w["machines"]) for w in fl.plan_waves(["solo"])] == [1])
    check("3 machines -> 3 waves of one",
          [len(w["machines"]) for w in fl.plan_waves(ids[:3])] == [1, 1, 1])
    custom = fl.plan_waves(ids, "5,50")
    check("custom '5,50' honoured (last wave = rest)",
          [w["pct"] for w in custom] == [5.0, 100.0]
          and [len(w["machines"]) for w in custom] == [1, 19], custom)
    check("parse_waves tolerates junk (a single value = one wave covering all)",
          fl.parse_waves("abc,10") == (100.0,)
          and fl.parse_waves("1,50") == (1.0, 100.0)
          and fl.parse_waves(None) == fl.DEFAULT_WAVES)
    check("empty fleet -> no waves", fl.plan_waves([]) == [])

    healthy = [{"machine_id": "a", "wave": 0, "status": "updated"},
               {"machine_id": "b", "wave": 0, "status": "updated"}]
    counts = fl.wave_health(healthy, 0)
    ok, reason = fl.health_gate(counts)
    check("100% updated / 0 failed -> healthy", ok and counts["updated_pct"] == 100.0, reason)
    ok, reason = fl.health_gate(fl.wave_health(
        [{"machine_id": "a", "wave": 0, "status": "requested"}], 0))
    check("a wave that has not reported back is BLOCKED", not ok and "0.0%" in reason, reason)
    ok, reason = fl.health_gate(fl.wave_health(
        [{"machine_id": "a", "wave": 0, "status": "updated"},
         {"machine_id": "b", "wave": 0, "status": "failed"}], 0))
    check("any failure blocks the wave", not ok and "lỗi" in reason, reason)
    check("requested/pending are counted apart",
          fl.wave_health([{"machine_id": "x", "wave": 1, "status": "requested"},
                          {"machine_id": "y", "wave": 1, "status": "pending"}], 1)
          == {"total": 2, "updated": 0, "failed": 0, "pending": 1, "requested": 1,
              "finished": 0, "updated_pct": 0.0})


def test_reconcile_and_health():
    print("\n-- status reconciliation + fleet health --")
    targets = [{"machine_id": "a", "wave": 0, "status": "requested"},
               {"machine_id": "b", "wave": 0, "status": "requested"},
               {"machine_id": "c", "wave": 0, "status": "requested"}]
    machines = [{"machine_id": "a", "version": "6.0.2"},
                {"machine_id": "b", "version": "6.0.1"},
                {"machine_id": "c", "version": "6.0.1"}]
    changed = fl.reconcile_targets(targets, machines, "6.0.2")
    check("only the machine on the target version flips to updated",
          changed == [{"machine_id": "a", "status": "updated", "version": "6.0.2"}], changed)
    check("nothing changed -> empty list",
          fl.reconcile_targets(targets, machines, "6.0.3") == [])

    from datetime import datetime, timedelta
    now = datetime(2026, 10, 1, 12, 0, 0)
    hb = {"a": (now - timedelta(minutes=2)).strftime("%Y-%m-%d %H:%M:%S"),
          "b": (now - timedelta(minutes=90)).strftime("%Y-%m-%d %H:%M:%S")}
    hosts = [
        {"machine_id": "a", "hostname": "A", "version": "6.0.1", "is_online": 1,
         "sysmon_present": 1, "auditpol_enabled": 1, "baseline_hardened": 1},
        {"machine_id": "b", "hostname": "B", "version": "6.0.0", "is_online": 1,
         "sysmon_present": 0},
        {"machine_id": "c", "hostname": "C", "version": "6.0.1", "is_online": 0},
    ]
    health = fl.machine_health_rows(hosts, hb, "6.0.1", now=now, silent_minutes=10)
    summary = health["summary"]
    check("summary counts machines/online/silent/outdated",
          summary["machines"] == 3 and summary["online"] == 2 and summary["silent"] == 1
          and summary["outdated"] == 1, summary)
    by_host = {r["hostname"]: r for r in health["machines"]}
    check("silent agent detected from the heartbeat age",
          by_host["B"]["silent"] and by_host["B"]["heartbeat_age_min"] == 90.0, by_host["B"])
    check("an offline machine is not 'silent'",
          not by_host["C"]["silent"] and "offline" in by_host["C"]["flags"], by_host["C"])
    check("coverage flags attached",
          {"no_sysmon", "no_auditpol", "outdated"} <= set(by_host["B"]["flags"]),
          by_host["B"]["flags"])
    check("a healthy machine has no flags", by_host["A"]["flags"] == [], by_host["A"]["flags"])
    check("silent machines sort first", health["machines"][0]["hostname"] == "B")

    grouped = fl.aggregate_anomalies([
        {"source_ip": "10.0.0.9", "reason": "unauthenticated", "msg_type": "heartbeat",
         "count": 5, "last_seen": "t1"},
        {"source_ip": "10.0.0.9", "reason": "unauthenticated", "msg_type": "heartbeat",
         "count": 3, "last_seen": "t2"},
        {"source_ip": "10.0.0.7", "reason": "unknown_type", "msg_type": "weird",
         "count": 1, "last_seen": "t3"}])
    check("anomalies grouped with summed counts + newest timestamp",
          grouped[0]["source_ip"] == "10.0.0.9" and grouped[0]["count"] == 8
          and grouped[0]["last_seen"] == "t2" and len(grouped) == 2, grouped)

    preview = fl.policy_preview(
        {"id": 7, "policy_name": "Sysmon high", "policy_type": "sysmon", "enabled": 1,
         "config_json": '{"level": "high"}'},
        hosts, [{"machine_id": "a", "status": "applied"}])
    check("policy preview parses config + counts states",
          preview["ok"] and preview["policy"]["config"] == {"level": "high"}
          and len(preview["applied"]) == 1 and len(preview["offline"]) == 1, preview)
    check("policy preview plans waves", len(preview["waves"]) == 3, preview["waves"])
    check("offline machines raise a warning",
          any("offline" in w for w in preview["warnings"]), preview["warnings"])
    bad = fl.policy_preview({"policy_name": "X", "config_json": "{not json"}, hosts, [])
    check("invalid config_json is reported", bad["ok"] is False and "JSON" in bad["error"], bad)
    check("a disabled policy warns",
          any("TẮT" in w for w in fl.policy_preview(
              {"policy_name": "Y", "enabled": 0, "config_json": "{}"}, [], [])["warnings"]))
    check("heartbeat_cutoff is a real timestamp",
          fl.heartbeat_cutoff(10).startswith("20"), fl.heartbeat_cutoff(10))


def test_wiring():
    print("\n-- wiring: tables, API, tcp_server counters, UI --")
    pg = read(os.path.join(SERVER, "db_postgres.py"))
    lite = read(os.path.join(SERVER, "db_manager.py"))
    for table in ("update_rollouts", "update_rollout_targets", "ingest_anomalies"):
        check("PG creates %s" % table, ("CREATE TABLE IF NOT EXISTS %s" % table) in pg)
        check("SQLite creates %s" % table, ("CREATE TABLE IF NOT EXISTS %s" % table) in lite)

    store_src = read(os.path.join(SERVER, "fleet_store.py"))
    for fn in ("create_rollout", "set_rollout_targets", "list_rollout_targets",
               "update_rollout_target", "heartbeat_map", "upsert_ingest_anomaly",
               "list_ingest_anomalies"):
        check("fleet_store.%s" % fn, ("def %s" % fn) in store_src)

    api_init = read(os.path.join(SERVER, "api", "__init__.py"))
    check("api_fleet imported + registered",
          "import api_fleet" in api_init and "api_fleet.register(app, core)" in api_init)
    api_src = read(os.path.join(SERVER, "api", "api_fleet.py"))
    for route in ("/api/fleet/rollout/plan", "/api/fleet/rollout", "/api/fleet/rollouts",
                  "/api/fleet/rollout/<int:rollout_id>/advance",
                  "/api/fleet/rollout/<int:rollout_id>/rollback", "/api/health/fleet",
                  "/api/policies/preview"):
        check("route %s" % route, route in api_src)
    check("rollout writes need the command permission", 'check_auth("command")' in api_src)
    check("reuses the existing push-update command", '"action": "agent_update"' in api_src)
    check("advance respects the health gate", "health_gate" in api_src and "blocked" in api_src)

    tcp = read(os.path.join(SERVER, "tcp_server.py"))
    check("tcp_server counts rejected ingest",
          "def _note_ingest" in tcp and "ingest_anomalies_snapshot" in tcp)
    check("unauthenticated messages are counted", '_note_ingest("unauthenticated"' in tcp)
    check("unknown message types are counted", '_note_ingest("unknown_type"' in tcp)

    tpl = read(os.path.join(SERVER, "templates", "index.html"))
    check("fleet panel exists in the Coverage view", 'id="fleetPanel"' in tpl)
    check("fleet.js loaded", "modules/fleet.js" in tpl)
    dash = read(os.path.join(SERVER, "static", "js", "dashboard.js"))
    check("coverage view initialises the fleet panel", "if (window.fleet) fleet.init()" in dash)
    js = read(os.path.join(SERVER, "static", "js", "modules", "fleet.js"))
    check("UI calls the fleet API", "/api/health/fleet" in js and "/api/fleet/rollout" in js)
    check("UI escapes rendered values", "escapeHtml" in js)

    i18n = read(os.path.join(SERVER, "static", "js", "i18n.js"))
    body = i18n[i18n.index("var DICT = {"):i18n.index("var I18N = ")]
    vi_at, en_at = body.index("vi: {"), body.index("en: {")
    key_re = re.compile(r"^\s*'([A-Za-z0-9_.\-]+)'\s*:", re.M)
    vi_keys = set(key_re.findall(body[vi_at:en_at]))
    en_keys = set(key_re.findall(body[en_at:]))
    for key in ("fleet.title", "fleet.plan", "fleet.start", "fleet.health", "fleet.ingest",
                "fleet.advance", "fleet.rollback", "fleet.blocked"):
        check("i18n key %s in vi+en" % key, key in vi_keys and key in en_keys)


def test_live_postgres():
    print("\n-- live PostgreSQL: rollout round trip + ingest counters --")
    if "--pg" not in sys.argv:
        print("SKIP  pass --pg [--env <file>] to run against PostgreSQL")
        return
    import uuid
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
        import fleet_store as store
    except Exception as e:
        print("SKIP  cannot import the DB layer: %s" % e)
        return
    db = dp.PostgresDatabase()
    if not getattr(db, "_connected", False):
        print("SKIP  PostgreSQL not reachable")
        return

    tag = "zz-fleet-" + uuid.uuid4().hex[:6]
    ids = ["%s-%d" % (tag, i) for i in range(1, 6)]
    rollout_id = None
    try:
        rollout_id = store.create_rollout(db, "ZZTEST rollout", "9.9.9", "9.9.8",
                                         fl.plan_waves(ids), ids, created_by="selftest")
        check("rollout row created", bool(rollout_id), rollout_id)
        rows = [{"machine_id": mid, "hostname": "ZZ%d" % i,
                 "wave": (0 if i == 1 else 1), "status": "pending",
                 "from_version": "9.9.8", "to_version": "9.9.9"}
                for i, mid in enumerate(ids, 1)]
        check("targets written", store.set_rollout_targets(db, rollout_id, rows) == len(ids))
        targets = store.list_rollout_targets(db, rollout_id)
        check("targets read back with wave + hostname",
              len(targets) == len(ids) and targets[0]["hostname"].startswith("ZZ"), targets[:1])
        check("rollout is listed",
              any(r["id"] == rollout_id for r in store.list_rollouts(db, 20)))

        store.update_rollout_target(db, rollout_id, ids[0], status="requested",
                                    message="canary")
        wave0 = store.list_rollout_targets(db, rollout_id, wave=0)
        counts = fl.wave_health(wave0, 0)
        check("wave 0 counts the canary as requested",
              counts["total"] == 1 and counts["requested"] == 1, counts)
        changed = fl.reconcile_targets(wave0, [{"machine_id": ids[0], "version": "9.9.9"}],
                                       "9.9.9")
        check("reconcile flips the canary to updated",
              bool(changed) and changed[0]["status"] == "updated", changed)
        for row in changed:
            store.update_rollout_target(db, rollout_id, row["machine_id"],
                                        status=row["status"], message="version=9.9.9")
        counts = fl.wave_health(store.list_rollout_targets(db, rollout_id, wave=0), 0)
        ok, reason = fl.health_gate(counts)
        check("canary wave is healthy -> gate allows the next wave",
              ok and counts["updated_pct"] == 100.0, reason)

        check("rollback marks untouched machines as skipped",
              store.update_rollout_target(db, rollout_id, ids[1], status="skipped",
                                          message="rollback: không gửi"))
        check("rollout state can be set to rolled_back",
              store.update_rollout(db, rollout_id, state="rolled_back"))
        check("state persisted", store.get_rollout(db, rollout_id)["state"] == "rolled_back")

        store.upsert_ingest_anomaly(db, "ZZTEST", "10.9.9.9", "unauthenticated", "heartbeat", 2)
        store.upsert_ingest_anomaly(db, "ZZTEST", "10.9.9.9", "unauthenticated", "heartbeat", 3)
        anomalies = [a for a in store.list_ingest_anomalies(db, hours=1, limit=50)
                     if a["source_ip"] == "10.9.9.9"]
        check("ingest counters accumulate for the same key",
              bool(anomalies) and int(anomalies[0]["count"]) == 5, anomalies)
        check("heartbeat_map returns a dict", isinstance(store.heartbeat_map(db), dict))
    finally:
        try:
            db._execute("DELETE FROM update_rollout_targets WHERE machine_id LIKE %s",
                        (tag + "%",))
            if rollout_id:
                db._execute("DELETE FROM update_rollouts WHERE id = %s", (int(rollout_id),))
            db._execute("DELETE FROM ingest_anomalies WHERE bucket = 'ZZTEST'")
        except Exception:
            pass
        left = db._execute("SELECT COUNT(*) AS n FROM update_rollout_targets "
                           "WHERE machine_id LIKE %s", (tag + "%",), fetch=True)
        check("test data cleaned up", (left or {}).get("n", 0) == 0, left)


def main():
    print("=" * 68)
    print("  GIAM-SAT fleet operations tests (rollout + health) - v5.0.8")
    print("=" * 68)
    test_plan_and_gate()
    test_reconcile_and_health()
    test_wiring()
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
