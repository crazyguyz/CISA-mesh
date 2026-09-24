#!/usr/bin/env python
"""GIAM-SAT alert-quality / silent-failure regression tests - v5.0.8.

Covers the audit findings of 2026-09-24 (menus Lỗ hổng / NetFlow / Case empty,
duplicated noisy alerts):

1. PostgreSQL backend used the kwarg `fetchone=` with an `_execute()` that only
   accepts fetch=/fetchall= -> TypeError inside `except Exception: pass/return None`
   -> Watchlist stayed empty (0 rows), cases were NEVER created while the log said
   "[CASE] auto-case created" every hour, case detail always 404, get_machine_by_ip
   always None. Guarded by a static scan + a functional test with a stubbed cursor.
2. The case detector reported success without checking the result.
3. MITRE matrix turned `rule_id` into a "technique" when an alert had no MITRE id,
   so 46 of 48 cells were one-off ANOMALY-* garbage.
4. Anomaly alerts used a brand-new rule id per alert (`ANOMALY-<time%100000>`) which
   made them un-groupable/unsuppressible and polluted the matrix.
5. Agent noise controls: 4688 is dropped when Sysmon covers process creation;
   chatty privilege IDs are folded per window.
6. The vuln scanner's CVE cache must live in a writable, persistent directory
   (packaged agent: %PROGRAMDATA%, not the PyInstaller temp dir) - otherwise the
   scanner keeps only ~861 CVEs and finds nothing (empty "Lỗ hổng" dashboard).

Usage: python tests/alert_quality_tests.py      (exit 0 = pass, 1 = failures)
"""

import io
import os
import re
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER = os.path.join(ROOT, "server")
AGENT = os.path.join(ROOT, "agent")
sys.path.insert(0, SERVER)
sys.path.insert(0, AGENT)

RESULTS = []


def check(name, ok, extra=""):
    RESULTS.append((name, bool(ok)))
    line = "PASS  " + name if ok else "FAIL  " + name
    if not ok and extra:
        line += "   -> " + str(extra)[:200]
    print(line)


def read(path):
    with io.open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()



def test_pg_fetchone_bug():
    """Bug 1: `fetchone=` is not a valid kwarg of _execute -> silent failures."""
    print("\n-- db_postgres: invalid fetchone= kwarg (silent failures) --")
    src = read(os.path.join(SERVER, "db_postgres.py"))
    bad = [ln for ln in src.splitlines() if "fetchone=True" in ln or "fetchone=False" in ln]
    check("no `fetchone=` kwarg left in db_postgres.py", not bad, bad[:3])
    m = re.search(r"def _execute\(self,\s*sql,\s*params=None,([^)]*)\)", src)
    sig = m.group(1) if m else ""
    check("_execute() accepts fetch=/fetchall=", "fetch=False" in sig and "fetchall=False" in sig, sig)
    check("_execute() does NOT accept fetchone=", "fetchone" not in sig, sig)

    for method in ("create_case", "get_case", "get_machine_by_ip", "add_watchlist"):
        blk = src[src.index("def %s(" % method):]
        nxt = blk.find("\n    def ", 10)
        blk = blk[:nxt] if nxt > 0 else blk[:2500]
        check("%s() passes fetch=True" % method, "fetch=True" in blk)
        check("%s() surfaces the DB error (print in except)" % method,
              "except Exception" in blk and "print(" in blk, method)


def test_case_detector_reports_truth():
    """Bug 2: the case detector must not claim success without an id."""
    print("\n-- server_core: auto-case detector honesty --")
    src = read(os.path.join(SERVER, "server_core.py"))
    start = src.index("def case_detector()")
    blk = src[start:start + 4200]
    check("detector checks the create_case() return value",
          re.search(r"_case_id\s*=\s*self\.db\.create_case", blk) is not None)
    check("detector prints the created id", "id={_case_id}" in blk)
    check("detector retries when nothing was created",
          "_last_case.pop(mid, None)" in blk)


def test_mitre_matrix_bucketing():
    """Bug 3: only real MITRE ids become techniques."""
    print("\n-- api_mitre: UNMAPPED bucket instead of rule_id cells --")
    import api.api_mitre as am
    check("valid technique ids accepted",
          all(am._MITRE_ID_RE.match(x) for x in ("T1059", "T1059.001", "S0002", "G0001")))
    check("one-off rule ids REJECTED as techniques",
          not any(am._MITRE_ID_RE.match(x) for x in
                  ("ANOMALY-12765", "HEARTBEAT-001", "THREAT-044", "N/A", "")))
    check("UNMAPPED bucket constants exist",
          am.UNMAPPED_TECHNIQUE_ID == "UNMAPPED" and bool(am.UNMAPPED_TECHNIQUE_NAME))
    src = read(os.path.join(SERVER, "api", "api_mitre.py"))
    check("matrix no longer falls back to technique_id = rule_id",
          re.search(r"^\s*technique_id\s*=\s*rule_id\s*$", src, re.M) is None)
    check("technique endpoint resolves the UNMAPPED bucket",
          "technique_id == UNMAPPED_TECHNIQUE_ID" in src)


def test_anomaly_rule_id_stable():
    """Bug 4: anomaly alerts must share ONE stable rule id per reason."""
    print("\n-- event_worker: stable ANOMALY rule id --")
    import event_worker as ew
    f = ew.EventWorkerPool._anomaly_rule_id
    a = f({"reasons": ["CPU spike on host"]})
    b = f({"reasons": ["CPU spike on host"]})
    check("same reason -> same rule id (stable)", a == b, "%s / %s" % (a, b))
    check("id has the ANOMALY- prefix", a.startswith("ANOMALY-"), a)
    check("different reason -> different id",
          f({"reasons": ["Disk queue length high"]}) != a)
    check("empty reasons -> ANOMALY-GENERIC", f({}) == "ANOMALY-GENERIC", f({}))
    check("id is sanitised + bounded",
          re.match(r"^ANOMALY-[A-Z0-9\-]{1,28}$", f({"reasons": ["a" * 200]}) or "") is not None,
          f({"reasons": ["a" * 200]}))
    src = read(os.path.join(SERVER, "event_worker.py"))
    check("no random per-alert id left",
          re.search(r"^\s*rule_id\s*=\s*f?[\"']ANOMALY-\{", src, re.M) is None)


def test_alert_dedup_window():
    """P2: repeated identical alerts are coalesced with a configurable window."""
    print("\n-- alert coalescing window (both backends) --")
    pg = read(os.path.join(SERVER, "db_postgres.py"))
    lite = read(os.path.join(SERVER, "db_manager.py"))
    for name, src in (("db_postgres", pg), ("db_manager", lite)):
        check("%s reads GIAMSAT_ALERT_DEDUP_MINUTES" % name,
              "GIAMSAT_ALERT_DEDUP_MINUTES" in src)
    check("PG insert_threat_alert updates the existing row instead of inserting",
          "UPDATE threat_alerts SET hostname=%s" in pg)
    check("PG no longer swallows alert-write errors",
          "insert_threat_alert failed" in pg)


def test_agent_noise_controls():
    """P2 (agent): 4688 dropped when Sysmon covers it, chatty IDs folded."""
    print("\n-- agent: event-volume controls --")
    import time as _time
    import event_collector as ec

    check("default throttle list is 4670/4673", ec.THROTTLE_EVENT_IDS == {"4670", "4673"},
          ec.THROTTLE_EVENT_IDS)
    check("throttle window default 60s", ec.THROTTLE_WINDOW_S == 60, ec.THROTTLE_WINDOW_S)

    def fake(sysmon=True):
        c = ec.EnhancedEventCollector.__new__(ec.EnhancedEventCollector)
        c._sysmon_available = sysmon
        c._throttle_ts = {}
        c._throttled = {}
        c._dropped_4688 = 0
        return c

    c = fake(True)
    check("4688 dropped when Sysmon is installed",
          c._should_keep_event("4688", "Security") is False)
    check("dropped 4688 counter increments", c._dropped_4688 == 1, c._dropped_4688)
    check("other Security events unaffected", c._should_keep_event("4624", "Security") is True)

    c2 = fake(False)
    check("4688 kept when Sysmon is absent", c2._should_keep_event("4688", "Security") is True)

    c3 = fake(True)
    check("first 4670 kept", c3._should_keep_event("4670", "Security") is True)
    check("following 4670 folded", c3._should_keep_event("4670", "Security") is False)
    check("folded counter tracked", c3._throttled.get(("Security", "4670")) == 1, c3._throttled)
    c3._throttle_ts[("Security", "4670")] = _time.time() - (ec.THROTTLE_WINDOW_S + 1)
    check("4670 kept again after the window",
          c3._should_keep_event("4670", "Security") is True)

    src = read(os.path.join(AGENT, "event_collector.py"))
    check("4688 policy can be overridden by env", "GIAMSAT_KEEP_4688_WITH_SYSMON" in src)
    check("throttle list can be overridden by env", "GIAMSAT_EVENT_THROTTLE_IDS" in src)


def test_sysmon_window_bound():
    """P2 (agent): the Sysmon poll window must be bounded + the watermark advanced."""
    print("\n-- agent: Sysmon poll window --")
    src = read(os.path.join(AGENT, "sysmon_collector.py"))
    check("lookback bound defined", "SYSMON_MAX_LOOKBACK_MINUTES" in src)
    check("window is bounded before the query", "window bounded to the last" in src)
    check("watermark advances on failure", "advancing watermark to" in src)
    import sysmon_collector as sc
    check("bound is a sane number of minutes", 5 <= sc.SYSMON_MAX_LOOKBACK_MINUTES <= 1440,
          sc.SYSMON_MAX_LOOKBACK_MINUTES)


def test_vuln_cache_dir():
    """P1 (agent): the CVE/KEV cache must be writable + persistent when packaged."""
    print("\n-- agent: CVE cache directory --")
    import shutil
    import tempfile
    import vuln_scanner as vs

    check("cache dir helper exists", hasattr(vs, "_writable_cache_dir"))
    d = vs._writable_cache_dir()
    check("cache dir is writable", os.path.isdir(d) and os.access(d, os.W_OK), d)

    tmp = tempfile.mkdtemp(prefix="giamsat_frozen_test_")
    old_frozen = getattr(sys, "frozen", None)
    old_env = os.environ.get("GIAMSAT_DATA_DIR")
    try:
        sys.frozen = True
        os.environ["GIAMSAT_DATA_DIR"] = os.path.join(tmp, "Agent")
        d2 = vs._writable_cache_dir()
        check("packaged agent uses the writable data dir (not the temp bundle)",
              d2.lower().startswith(tmp.lower()), d2)
    finally:
        if old_frozen is None:
            try:
                del sys.frozen
            except Exception:
                pass
        else:
            sys.frozen = old_frozen
        if old_env is None:
            os.environ.pop("GIAMSAT_DATA_DIR", None)
        else:
            os.environ["GIAMSAT_DATA_DIR"] = old_env
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    print("=" * 68)
    print("  GIAM-SAT alert-quality / silent-failure tests - v5.0.8")
    print("=" * 68)
    test_pg_fetchone_bug()
    test_case_detector_reports_truth()
    test_mitre_matrix_bucketing()
    test_anomaly_rule_id_stable()
    test_alert_dedup_window()
    test_agent_noise_controls()
    test_sysmon_window_bound()
    test_vuln_cache_dir()
    failed = [n for n, ok in RESULTS if not ok]
    print("\n" + "=" * 68)
    print("  %d/%d checks passed" % (len(RESULTS) - len(failed), len(RESULTS)))
    for name in failed:
        print("  FAILED: %s" % name)
    print("=" * 68)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

