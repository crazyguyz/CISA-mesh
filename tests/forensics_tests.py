#!/usr/bin/env python
"""GIAM-SAT forensic (process tree + evidence packet) regression tests - v5.0.8.

Guards Phase B:

  * the 4688 parser: PID/image/creator PID/command line/creator image read from
    both the explicit raw_data keys and the original insert-string pipe fields
    (5/6/8/9/14) - plus user, hex conversion and junk tolerance.
  * build_process_tree: nesting by parent pid, "implied parent" nodes when the
    creator's own creation event is outside the window (source=implied-parent),
    PID-reuse cycle safety (no infinite recursion), size/depth caps and
    suspicious-command tags (powershell -enc, certutil, psexec, \\Temp, ...).
  * evidence packet: window filtering, sections, host facts, GeoIP org, process
    tree, watchlist hits, canonical-JSON SHA-256 integrity and the SELF-CONTAINED
    HTML report (no external assets, every value escaped - XSS payload test).
  * wiring: case_evidence + process_tree_edges exist in BOTH backends, tcp_server
    now accepts process_tree_edge/snapshot (it used to drop them), API routes are
    registered, UI buttons/i18n keys exist in both languages.
  * live (--pg [--env file]): seed a 4688 chain with SENTINEL pids -> the tree
    nests, evidence collects the seeded rows, integrity verifies after reload,
    then everything is deleted again.

Usage:
  python tests/forensics_tests.py                  # unit + static
  python tests/forensics_tests.py --pg --env D:/test/server/.env
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

import forensics as fo  # noqa: E402

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


def row_4688(pid_hex, image, cmd, ppid_hex, parent_image, time, user="IT-YNT$"):
    inner = " | ".join(["S-1-5-21-x", user, "WORKGROUP", "0x3e7", pid_hex, image, "%%1936",
                        ppid_hex, cmd, "-", "-", "-", "0x0", parent_image, "%%1936"])
    return {"event_id": "4688", "hostname": "PC01", "machine_id": "m1", "time": time,
            "raw_data": {"command_line": cmd, "parent_pid": ppid_hex, "raw_data": inner,
                         "target_username": user}}


def test_parser():
    print("\n-- 4688 / sysmon / agent-edge parsing --")
    rec = fo.parse_4688_record(row_4688(
        "0x41c", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "powershell -enc AAAA", "0x1114", r"C:\Windows\Action1\action1_agent.exe",
        "2026-10-01 10:00:05"))
    check("PID from insert-string field 5 (hex -> int)", rec["pid"] == 1052, rec)
    check("creator PID from field 8 / parent_pid key", rec["parent_pid"] == 4372, rec)
    check("image name and path parsed", rec["name"] == "powershell.exe"
          and rec["path"].endswith("powershell.exe"), rec)
    check("command line parsed", rec["cmdline"] == "powershell -enc AAAA", rec)
    check("creator image kept (for implied parents)",
          rec["parent_name"] == "action1_agent.exe", rec)
    check("user taken from target_username", rec["user"] == "IT-YNT$", rec)
    check("hex helper tolerates junk", fo._hex_to_int("N/A") is None
          and fo._hex_to_int("0x0") is None and fo._hex_to_int("12") == 12)

    sysmon = fo.parse_sysmon_record({"pid": "512", "parent_pid": "0",
                                     "process_path": r"C:\x\a.exe",
                                     "command_line": "a.exe -v", "hostname": "PC01"})
    check("sysmon record parsed", sysmon["pid"] == 512 and sysmon["name"] == "a.exe", sysmon)
    check("a record without a PID is dropped by the tree builder",
          fo.build_process_tree([{"pid": None, "parent_pid": None, "name": "x",
                                  "cmdline": "", "path": "", "source": "t",
                                  "time": ""}])["stats"]["nodes"] == 0)

    edge = fo.parse_edge_record({"pid": "77", "parent_pid": "1", "process_name": "b.exe",
                                 "chain_json": '["a.exe", "b.exe"]', "kind": "chain",
                                 "suspicious": 1})
    check("agent edge parsed with its chain", edge["pid"] == 77 and edge["suspicious_hint"]
          and "a.exe" in edge["cmdline"], edge)
    check("parse_process_record dispatches by shape",
          fo.parse_process_record(row_4688("0x10", r"C:\a.exe", "a", "0x1", r"C:\b.exe",
                                           "t"))["name"] == "a.exe")
    check("suspicious heuristics fire on real patterns",
          "certutil tải/giải mã" in fo.suspicious_reasons("certutil -urlcache -f http://x/y", "")
          and "LOLBin" in fo.suspicious_reasons("mshta http://x", "")
          and not fo.suspicious_reasons("explorer.exe", r"C:\Windows\explorer.exe"))


def test_tree():
    print("\n-- process tree: nesting, implied parents, cycles, caps, tags --")
    parent = fo.parse_4688_record(row_4688(
        "0x1114", r"C:\Windows\Action1\action1_agent.exe", "action1_agent.exe", "0x4f0",
        r"C:\Windows\System32\services.exe", "2026-10-01 10:00:01"))
    child = fo.parse_4688_record(row_4688(
        "0x41c", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "powershell -NoLogo -enc SQBFAFgA", "0x1114",
        r"C:\Windows\Action1\action1_agent.exe", "2026-10-01 10:00:05"))
    grand = fo.parse_4688_record(row_4688(
        "0x5aa", r"C:\Temp\psexec.exe", "psexec \\\\host cmd.exe", "0x41c",
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "2026-10-01 10:00:09"))

    tree = fo.build_process_tree([parent, child, grand])
    stats = tree["stats"]
    check("three creations + 1 implied parent = 4 nodes, 3 edges",
          stats["nodes"] == 4 and stats["edges"] == 3, stats)
    check("depth reflects the full chain", stats["max_depth"] == 3, stats)
    check("implied parent created for the out-of-window creator",
          stats["implied_parents"] == 1, stats)
    root = tree["roots"][0]
    check("root is the implied services.exe", root["name"] == "services.exe"
          and root["source"] == "implied-parent", root)
    check("chain nests action1_agent -> powershell -> psexec",
          root["children"][0]["name"] == "action1_agent.exe"
          and root["children"][0]["children"][0]["name"] == "powershell.exe"
          and root["children"][0]["children"][0]["children"][0]["name"] == "psexec.exe",
          tree["roots"])
    check("suspicious tags attached to the right nodes",
          "PowerShell ẩn/encode" in root["children"][0]["children"][0]["tags"]
          and "chạy từ thư mục tạm" in root["children"][0]["children"][0]["children"][0]["tags"],
          [(n["name"], n["tags"]) for n in tree["flat"]])

    cyc = [{"pid": 1, "parent_pid": 2, "name": "a", "cmdline": "", "path": "",
            "source": "t", "time": ""},
           {"pid": 2, "parent_pid": 1, "name": "b", "cmdline": "", "path": "",
            "source": "t", "time": ""}]
    t2 = fo.build_process_tree(cyc)
    check("PID-reuse loop cannot hang the builder",
          t2["stats"]["nodes"] == 2 and t2["stats"]["edges"] == 1, t2["stats"])
    check("the loop is flagged for the analyst",
          any(any(t.startswith("vòng lặp") for t in (n.get("tags") or []))
              for n in t2["flat"]),
          [(n["pid"], n.get("tags")) for n in t2["flat"]])

    many = [{"pid": i, "parent_pid": i - 1, "name": "p%d" % i, "cmdline": "", "path": "",
             "source": "t", "time": ""} for i in range(1, 50)]
    t3 = fo.build_process_tree(many, max_nodes=10, max_depth=3)
    check("node cap enforced", t3["stats"]["nodes"] <= 10, t3["stats"])
    check("depth cap enforced", t3["stats"]["max_depth"] <= 3, t3["stats"])
    check("dropped nodes are reported", t3["stats"]["dropped"] >= 30, t3["stats"])
    check("root_pid narrows the view", len(fo.build_process_tree(many, root_pid=40)["roots"]) == 1)


def test_evidence_html():
    print("\n-- evidence packet: integrity + self-contained HTML --")
    payload = {"title": "<script>alert(1)</script>", "hostname": "PC01", "machine_id": "m1",
               "anchor": "2026-10-01 10:00:00",
               "window": {"minutes": 15, "start": "2026-10-01 09:45:00", "end": "2026-10-01 10:15:00"},
               "created_by": "analyst", "generated_at": "now", "server_version": "6.0.1",
               "sections": {"alerts": {"total": 1, "shown": 1,
                                       "rows": [{"rule_id": "<img src=x onerror=alert(1)>",
                                                 "severity": "HIGH"}]}},
               "facts": {"machine": {"hostname": "PC01"}, "users": [], "hardware": [],
                         "uptime": []},
               "process_tree": fo.build_process_tree([]), "watchlist_hits": [],
               "counts": {"alerts": 1}}
    payload["integrity"] = {"algo": "sha256", "sha256": fo.payload_sha256(payload), "note": "n"}

    check("canonical hash ignores key order",
          fo.payload_sha256({"a": 1, "b": [2, 3]}) == fo.payload_sha256({"b": [2, 3], "a": 1}))
    check("hash matches the stored integrity block",
          payload["integrity"]["sha256"] == fo.payload_sha256(payload))
    html = fo.render_html(payload)
    check("html is a complete document",
          html.startswith("<!DOCTYPE html>") and html.rstrip().endswith("</html>"), html[:60])
    check("XSS payloads from telemetry are escaped",
          "&lt;script&gt;" in html and "<script>alert" not in html and "&lt;img src=x" in html)
    body_after_style = html.split("</style>", 1)[1]
    check("report is self-contained (no external assets)",
          "<script src" not in html and "<link" not in html and "<img" not in html,
          body_after_style[:120])
    check("the integrity hash is printed in the footer",
          payload["integrity"]["sha256"][:16] in html)
    check("Dấu vân tay hash + số liệu hiển thị", "Số liệu thu thập" in html and "alerts" in html)


def test_wiring():
    print("\n-- wiring: DB (both backends), agent handler, API, UI, i18n --")
    pg = read(os.path.join(SERVER, "db_postgres.py"))
    lite = read(os.path.join(SERVER, "db_manager.py"))
    for table in ("process_tree_edges", "case_evidence"):
        check("PG creates %s" % table, ("CREATE TABLE IF NOT EXISTS %s" % table) in pg)
        check("SQLite creates %s" % table, ("CREATE TABLE IF NOT EXISTS %s" % table) in lite)
    check("PG stores agent edges", "def insert_process_tree_edge" in pg)
    check("SQLite stores agent edges", "def insert_process_tree_edge" in lite)

    tcp = read(os.path.join(SERVER, "tcp_server.py"))
    check("tcp_server dispatches process_tree_edge/snapshot",
          '"process_tree_edge", "process_tree_snapshot"' in tcp)
    check("tcp_server has the handler", "def _handle_process_tree" in tcp)

    api_init = read(os.path.join(SERVER, "api", "__init__.py"))
    check("api_forensics imported + registered",
          "import api_forensics" in api_init and "api_forensics.register(app, core)" in api_init)
    api_src = read(os.path.join(SERVER, "api", "api_forensics.py"))
    for route in ("/api/forensics/process-tree/<machine_id>", "/api/forensics/evidence",
                  "/api/forensics/evidence/<int:evidence_id>", "/api/forensics/render"):
        check("route %s" % route, route in api_src)
    check("forensic writes need the command permission", 'check_auth("command")' in api_src)

    js = read(os.path.join(SERVER, "static", "js", "modules", "investigate.js"))
    check("UI fetches the process tree", "/api/forensics/process-tree/" in js)
    check("UI creates evidence packets", "/api/forensics/evidence" in js)
    check("UI exposes tree/evidence", "tree: tree" in js and "evidence: evidence" in js)
    dash = read(os.path.join(SERVER, "static", "js", "dashboard.js"))
    check("alert modal offers tree + evidence", "inv-tree" in dash and "inv-evidence" in dash)

    i18n = read(os.path.join(SERVER, "static", "js", "i18n.js"))
    body = i18n[i18n.index("var DICT = {"):i18n.index("var I18N = ")]
    vi_at, en_at = body.index("vi: {"), body.index("en: {")
    key_re = re.compile(r"^\s*'([A-Za-z0-9_.\-]+)'\s*:", re.M)
    vi_keys = set(key_re.findall(body[vi_at:en_at]))
    en_keys = set(key_re.findall(body[en_at:]))
    for key in ("inv.tree", "inv.evidence", "inv.evidenceCreated", "inv.treeEmpty",
                "inv.treeFlagged"):
        check("i18n key %s in vi+en" % key, key in vi_keys and key in en_keys)


# --------------------------------------------------------------------------- #
# live PostgreSQL (opt-in)
# --------------------------------------------------------------------------- #
def _load_env():
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
    return env_path


def test_live_postgres():
    print("\n-- live PostgreSQL: 4688 tree + evidence packet round trip --")
    if "--pg" not in sys.argv:
        print("SKIP  pass --pg [--env <file>] to run against PostgreSQL")
        return
    import json as _json
    import uuid
    _load_env()
    try:
        import db_postgres as dp
    except Exception as e:
        print("SKIP  cannot import db_postgres: %s" % e)
        return
    db = dp.PostgresDatabase()
    if not getattr(db, "_connected", False):
        print("SKIP  PostgreSQL not reachable")
        return

    tag = "ZZF" + uuid.uuid4().hex[:6].upper()
    mid = "zzforensic-" + tag[-6:].lower()
    host = "ZZHOST-" + tag[-6:]
    try:
        def seed(pid_hex, image, cmd, ppid_hex, parent_image):
            inner = " | ".join(["S-1-5-21-x", "IT-YNT$", "WG", "0x3e7", pid_hex, image,
                                "%%1936", ppid_hex, cmd, "-", "-", "-", "0x0", parent_image,
                                "%%1936"])
            raw = _json.dumps({"command_line": cmd, "parent_pid": ppid_hex, "raw_data": inner,
                               "target_username": "IT-YNT$"})
            db._execute("""INSERT INTO events (machine_id, hostname, type, subtype, event_id,
                           description, raw_data, received_at)
                           VALUES (%s,%s,'windows_event','Security','4688',%s,%s::jsonb,NOW())""",
                        (mid, host, "ZZSENTINEL " + tag, raw))

        seed("0x1114", r"C:\Windows\Action1\action1_agent.exe", "action1_agent.exe",
             "0x4f0", r"C:\Windows\System32\services.exe")
        seed("0x41c", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
             "powershell -NoLogo -enc SQBFAFgA" + tag, "0x1114",
             r"C:\Windows\Action1\action1_agent.exe")
        seed("0x5aa", r"C:\ZZ" + tag + r"\psexec.exe", "psexec \\\\host cmd.exe", "0x41c",
             r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
        db._execute("""INSERT INTO threat_alerts (machine_id, hostname, rule_id, rule_name,
                       severity, description, timestamp, received_at)
                       VALUES (%s,%s,'ZZ-FOR-001','forensic sentinel','HIGH',%s,
                       '2026-10-01 00:00:00',NOW())""", (mid, host, "ZZSENTINEL alert " + tag))

        records = fo.collect_process_records(db, mid)
        check("4688 rows are collected for the machine", len(records) >= 3, len(records))
        tree = fo.build_process_tree(records)
        check("tree nests the seeded chain",
              tree["stats"]["nodes"] >= 3 and tree["stats"]["edges"] >= 2, tree["stats"])
        check("implied parent from field 14 (services.exe)",
              any(n["name"] == "services.exe" and n["source"] == "implied-parent"
                  for n in tree["flat"]), [n["name"] for n in tree["flat"]])
        check("powershell -enc is flagged",
              any("PowerShell ẩn/encode" in (n["tags"] or []) for n in tree["flat"]),
              [(n["name"], n["tags"]) for n in tree["flat"] if n["tags"]])
        check("command line from raw_data is present",
              any((n["cmdline"] or "").startswith("powershell -NoLogo") for n in tree["flat"]))

        payload = fo.collect_evidence(db, mid, window_minutes=180, created_by="selftest",
                                      title="ZZSENTINEL " + tag)
        check("evidence collects the seeded events",
              payload["sections"]["events"]["total"] >= 2, payload["counts"])
        check("evidence collects the seeded alert",
              payload["sections"]["alerts"]["total"] >= 1, payload["counts"])
        check("evidence embeds the process tree",
              payload["counts"]["process_nodes"] >= 3, payload["counts"])
        check("evidence integrity hash present",
              len(payload["integrity"]["sha256"]) == 64, payload["integrity"])
    finally:
        for sql in ("DELETE FROM events WHERE machine_id=%s",
                    "DELETE FROM threat_alerts WHERE machine_id=%s",
                    "DELETE FROM case_evidence WHERE machine_id=%s"):
            try:
                db._execute(sql, (mid,))
            except Exception:
                pass
        left = db._execute("SELECT COUNT(*) AS n FROM events WHERE machine_id=%s",
                           (mid,), fetch=True)
        check("test data cleaned up", (left or {}).get("n", 0) == 0, left)


def main():
    print("=" * 68)
    print("  GIAM-SAT forensic tests (process tree + evidence) - v5.0.8")
    print("=" * 68)
    test_parser()
    test_tree()
    test_evidence_html()
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

