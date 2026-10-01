#!/usr/bin/env python
"""GIAM-SAT unified investigation (search + Entity-360) regression tests - v5.0.8.

Guards the new "điều tra 1 chạm" feature:

  * the query DSL: field:value, "quoted phrase", -field:value (negation), OR
    groups, wildcards, numeric comparisons, AND ignored, Windows paths NOT
    mistaken for `field:value` (C:\\Temp used to break the parser).
  * SQL safety: identifiers come only from the scope whitelist and every user
    value is a bind parameter - an injection payload must show up in the params
    list, never in the SQL text.
  * backend awareness: PostgreSQL gets ILIKE + make_interval(), SQLite gets
    LIKE + datetime('now', ...).
  * DB layer: pg_trgm + trigram GIN indexes + saved_searches (static here, live
    with --pg).
  * API/UI wiring: api_investigate registered + view markup + viewMap/iconMap
    entry + pivot attribute contract + i18n keys present in BOTH languages.
  * live (opt-in, --pg [--env <file>]): insert SENTINEL rows, search them, verify
    facets + entity merge + that the trigram index is USABLE (EXPLAIN) + saved
    search CRUD, then delete every row it created.

Usage:
  python tests/search_investigation_tests.py                 # unit + static
  python tests/search_investigation_tests.py --pg --env D:/test/server/.env
Exit code 0 = all passed, 1 = failures found.
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

import search_engine as se  # noqa: E402

RESULTS = []


def check(name, ok, extra=""):
    RESULTS.append((name, bool(ok)))
    line = ("PASS  " if ok else "FAIL  ") + name
    if not ok and extra:
        line += "   -> " + str(extra)[:220]
    print(line)


def read(path):
    with io.open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


def first_group(q):
    ast = se.parse_query(q)
    return ast, (ast["groups"][0] if ast["groups"] else [])


# --------------------------------------------------------------------------- #
# 1) DSL parser
# --------------------------------------------------------------------------- #
def test_dsl_parser():
    print("\n-- query DSL --")
    _ast, c = first_group("cmd:certutil")
    check("field:value", c and c[0]["field"] == "cmd" and c[0]["value"] == "certutil", c)

    _ast, c = first_group('msg:"failed logon"')
    check("quoted value keeps its space", c and c[0]["value"] == "failed logon", c)

    _ast, c = first_group("-user:system")
    check("negation", c and c[0]["negate"] is True, c)

    ast = se.parse_query("user:a OR dst_ip:1.1.1.1")
    check("OR -> two groups", len(ast["groups"]) == 2, ast["groups"])

    _ast, c = first_group("a AND b")
    check("AND is implicit/ignored", len(c) == 2 and all(x["field"] is None for x in c), c)

    _ast, c = first_group("pid:>1000")
    check("numeric >", c and c[0]["op"] == "gt" and c[0]["field"] == "pid", c)

    _ast, c = first_group('"C:\\Temp\\a b"')
    check("windows path is free text, not field 'C'",
          c and c[0]["field"] is None and c[0]["value"].startswith("C:"), c)

    _ast, c = first_group("http://evil.test/x")
    check("URL is free text, not field 'http'", c and c[0]["field"] is None, c)

    _ast, c = first_group("a NOT b")
    check("NOT negates the next token", len(c) == 2 and c[1]["negate"] is True, c)

    ast = se.parse_query("rule:X sev:>=")
    check("missing value is reported, query still usable",
          ast["unknown"] and ast["groups"], ast)

    ast = se.parse_query("")
    check("empty query -> no groups", ast["groups"] == [] and ast["terms"] == 0, ast)


# --------------------------------------------------------------------------- #
# 2) SQL building safety + backend awareness
# --------------------------------------------------------------------------- #
def test_sql_safety_and_backends():
    print("\n-- SQL building: whitelist + parameters --")
    ast = se.parse_query("description:foo'); DROP TABLE events;--")
    where, params = se._build_scope_where(se.SCOPES["events"], ast, "%s", "postgres")
    check("injection payload is NOT in the SQL text",
          "DROP TABLE" not in str(where) and ";" not in str(where), where)
    check("injection payload lives in the params (as data only)",
          any(("DROP" in str(p)) or ("events;--" in str(p)) or ("foo');" in str(p))
              for p in params), params)
    check("no SQL keywords leak into the fragment",
          not re.search(r"\b(select|insert|update|delete|union)\b", str(where).lower()), where)

    ast = se.parse_query("cmd:certutil")
    where, _params = se._build_scope_where(se.SCOPES["events"], ast, "%s", "postgres")
    check("condition for a column the scope lacks is dropped", where is None, where)
    where, params = se._build_scope_where(se.SCOPES["sysmon"], ast, "%s", "postgres")
    check("same condition applies to the scope that has it",
          where and "command_line ILIKE" in where and params == ["%certutil%"], (where, params))

    ast = se.parse_query('"ZZSENTINEL"')
    wp, _ = se._build_scope_where(se.SCOPES["events"], ast, "%s", "postgres")
    ws, _ = se._build_scope_where(se.SCOPES["events"], ast, "?", "sqlite")
    check("PG free text uses ILIKE", "ILIKE" in wp, wp)
    check("SQLite free text uses LIKE + ?", "LIKE" in ws and "?" in ws and "ILIKE" not in ws, ws)

    pg_time, p1 = se.build_time_predicate("postgres", "received_at", 24)
    lite_time, p2 = se.build_time_predicate("sqlite", "received_at", 24)
    check("PG window uses make_interval", "make_interval" in pg_time and p1 == [24], pg_time)
    check("SQLite window uses datetime()",
          "datetime('now'" in lite_time and p2 == ["-24 hours"], lite_time)

    check("wildcards are translated", se.sql_like("cert*") == "cert%")
    check("LIKE metacharacters are escaped", se.sql_like("50%") == "%50\\%%")
    check("plain term becomes a substring match", se.sql_like("certutil") == "%certutil%")

    import datetime as _dt
    row = se.normalize_row({"a": _dt.datetime(2026, 10, 1, 12, 0, 0), "b": {"x": 1}})
    check("datetime -> string, dict untouched",
          row["a"] == "2026-10-01 12:00:00" and row["b"] == {"x": 1}, row)
    csv_text = se.to_csv([{"_time": "t", "_scope": "events", "hostname": "PC1", "description": 'a,"b"'}])
    check("CSV quotes commas/quotes", '"a,""b"""' in csv_text, csv_text)

    check("fields helper lists scopes per alias",
          "sysmon" in (se.all_fields().get("cmd") or {}).get("scopes", []),
          se.all_fields().get("cmd"))
    check("entity kinds are documented", "host" in se.ENTITY_FIELDS and "any" in se.ENTITY_FIELDS)


# --------------------------------------------------------------------------- #
# 3) static wiring (DB + API + UI + i18n)
# --------------------------------------------------------------------------- #
def test_wiring():
    print("\n-- wiring: database, API, UI, i18n --")
    pg_src = read(os.path.join(SERVER, "db_postgres.py"))
    check("PG creates saved_searches", "CREATE TABLE IF NOT EXISTS saved_searches" in pg_src)
    check("PG installs pg_trgm", "CREATE EXTENSION IF NOT EXISTS pg_trgm" in pg_src)
    check("PG indexes command_line/path/description/dns for search",
          all(k in pg_src for k in ("idx_events_desc_trgm", "idx_sysmon_cmd_trgm",
                                    "idx_sysmon_path_trgm", "idx_traffic_dns_trgm")))
    lite_src = read(os.path.join(SERVER, "db_manager.py"))
    check("SQLite creates saved_searches", "CREATE TABLE IF NOT EXISTS saved_searches" in lite_src)

    api_init = read(os.path.join(SERVER, "api", "__init__.py"))
    check("api_investigate imported", "import api_investigate" in api_init)
    check("api_investigate registered", "api_investigate.register(app, core)" in api_init)
    api_src = read(os.path.join(SERVER, "api", "api_investigate.py"))
    for route in ("/api/investigate/search", "/api/investigate/entity/<kind>/<path:value>",
                  "/api/investigate/fields", "/api/investigate/saved",
                  "/api/investigate/export"):
        check("route %s" % route, route in api_src)
    check("reads require auth", 'check_auth("api")' in api_src)
    check("writes require a stronger permission", 'check_auth("command")' in api_src)

    tpl = read(os.path.join(SERVER, "templates", "index.html"))
    check("nav link present", 'data-view="investigate"' in tpl)
    check("view container present", 'id="viewInvestigate"' in tpl)
    check("results + facets containers present",
          'id="invResults"' in tpl and 'id="invFacets"' in tpl)
    check("viewIncident still present (not clobbered)", 'id="viewIncident"' in tpl)
    check("investigate.js loaded", 'modules/investigate.js' in tpl)

    dash = read(os.path.join(SERVER, "static", "js", "dashboard.js"))
    check("viewMap entry", "investigate: { el: 'viewInvestigate'" in dash)
    check("iconMap entry", "'investigate':'search'" in dash)
    check("Ctrl+K understands the DSL", "/api/investigate/search?q=" in dash)
    check("pivot on the alert detail modal",
          'data-pivot-kind="' in dash and "window.pivotEntity" in dash)

    js = read(os.path.join(SERVER, "static", "js", "modules", "investigate.js"))
    check("module exposes the public API",
          all(k in js for k in ("window.investigate", "window.pivotEntity", "entity: entity")))
    check("pivot contract uses data-pivot/data-pivot-kind",
          'data-pivot="' in js and 'data-pivot-kind="' in js)
    check("module escapes values (escapeHtml)", "escapeHtml" in js)

    i18n = read(os.path.join(SERVER, "static", "js", "i18n.js"))
    body = i18n[i18n.index("var DICT = {"):i18n.index("var I18N = ")]
    vi_at, en_at = body.index("vi: {"), body.index("en: {")
    key_re = re.compile(r"^\s*'([A-Za-z0-9_.\-]+)'\s*:", re.M)
    vi_keys = set(key_re.findall(body[vi_at:en_at]))
    en_keys = set(key_re.findall(body[en_at:]))
    used = set(re.findall(r"(?:data-i18n|data-i18n-placeholder|T\()\s*\(?['\"]([a-z]+\.[A-Za-z0-9_.]+)['\"]",
                          tpl + js))
    missing_vi = sorted(k for k in used if k not in vi_keys)
    missing_en = sorted(k for k in used if k not in en_keys)
    check("every new i18n key exists in vi", not missing_vi, missing_vi)
    check("every new i18n key exists in en", not missing_en, missing_en)
    check("inv.* keys translated in both languages",
          any(k.startswith("inv.") for k in vi_keys) and any(k.startswith("inv.") for k in en_keys))
    check("no duplicate inv.* key inside one language",
          len([k for k in vi_keys if k.startswith("inv.")]) ==
          len(re.findall(r"^\s*'inv\.[A-Za-z0-9_.]+'\s*:", body[vi_at:en_at], re.M)))


# --------------------------------------------------------------------------- #
# 4) live PostgreSQL (opt-in) - seeds rows, verifies, then removes them
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
    print("\n-- live PostgreSQL: search, facets, entity-360, index use, saved --")
    if "--pg" not in sys.argv:
        print("SKIP  pass --pg [--env <file>] to run against PostgreSQL")
        return
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

    tag = "ZZSENTINEL" + uuid.uuid4().hex[:6].upper()
    host = "ZZHOST-" + tag[-6:]
    mid = "zzsentinel-" + tag[-6:].lower()
    try:
        ext = db._execute("SELECT extname FROM pg_extension WHERE extname='pg_trgm'", fetch=True)
        check("pg_trgm installed in the live database", bool(ext), ext)
        idx = [r["indexname"] for r in (db._execute(
            "SELECT indexname FROM pg_indexes WHERE schemaname='public' "
            "AND indexname LIKE '%trgm%'", fetchall=True) or [])]
        check("trigram indexes exist in the live database", len(idx) >= 5, idx)

        db._execute("""INSERT INTO events (machine_id, hostname, type, subtype, event_id,
                       description, received_at)
                       VALUES (%s,%s,'event','event','4688',%s,NOW())""",
                    (mid, host, "ZZSENTINEL markdown " + tag))
        db._execute("""INSERT INTO sysmon_events (machine_id, hostname, sysmon_event_id,
                       process_name, command_line, received_at)
                       VALUES (%s,%s,1,'cmd.exe',%s,NOW())""",
                    (mid, host, "cmd.exe /c " + tag))
        db._execute("""INSERT INTO threat_alerts (machine_id, hostname, rule_id, rule_name,
                       severity, description, timestamp, received_at)
                       VALUES (%s,%s,'ZZ-TEST-001','sentinel rule','LOW',%s,
                       '2026-10-01 00:00:00',NOW())""",
                    (mid, host, "ZZSENTINEL alert " + tag))

        out = se.search(db, "host:%s description:%s" % (host, tag), scopes=["events"], hours=1)
        check("search finds the seeded event", out["total"] >= 1 and out["unknown"] == [],
              out.get("total"))
        check("facets expose the host", host in (out["facets"]["host"] or {}), out["facets"]["host"])
        check("results carry _scope/_time",
              all(r.get("_scope") == "events" and r.get("_time") for r in out["results"]),
              out["results"][:1])
        free = se.search(db, tag, scopes=["events", "sysmon", "alerts"], hours=1)
        check("free-text search spans every scope", free["total"] >= 3, free["total"])

        e = se.entity(db, "host", host, hours=1)
        check("entity-360 merges every scope that saw this host",
              {"events", "sysmon", "alerts"} <= set(e["by_scope"]), e["by_scope"])
        check("entity-360 reports its time range",
              bool(e["first_seen"]) and bool(e["last_seen"]), (e["first_seen"], e["last_seen"]))

        db._execute("SET enable_seqscan = off")
        plan = db._execute("EXPLAIN SELECT id FROM events WHERE description ILIKE %s",
                           ("%" + tag + "%",), fetchall=True)
        db._execute("SET enable_seqscan = on")
        plan_text = " ".join(str(list(p.values())[0]) for p in (plan or []))
        check("substring search can use the trigram index",
              "idx_events_desc_trgm" in plan_text, plan_text[:220])

        saved_id = se.save_search(db, "ZZTEST-investigation", "host:%s" % host,
                                  ["events"], 1, "selftest")
        check("saved search upsert returns an id", bool(saved_id), saved_id)
        listing = [s for s in se.list_saved_searches(db) if s["name"] == "ZZTEST-investigation"]
        check("saved search is listed with its query",
              listing and listing[0]["query"] == "host:%s" % host, listing)
        se.save_search(db, "ZZTEST-investigation", "host:%s user:x" % host, ["events"], 1, "selftest")
        listing = [s for s in se.list_saved_searches(db) if s["name"] == "ZZTEST-investigation"]
        check("saving the same name updates instead of duplicating",
              len(listing) == 1 and listing[0]["query"].endswith("user:x"), listing)
        check("delete_saved_search reports success", se.delete_saved_search(db, saved_id))
        check("delete removed the row",
              not [s for s in se.list_saved_searches(db) if s["name"] == "ZZTEST-investigation"])
    finally:
        for sql in ("DELETE FROM events WHERE machine_id=%s",
                    "DELETE FROM sysmon_events WHERE machine_id=%s",
                    "DELETE FROM threat_alerts WHERE machine_id=%s"):
            try:
                db._execute(sql, (mid,))
            except Exception:
                pass
        try:
            db._execute("DELETE FROM saved_searches WHERE name='ZZTEST-investigation'")
        except Exception:
            pass
        left = se.search(db, tag, scopes=["events", "sysmon", "alerts"], hours=24)
        check("test data cleaned up", left["total"] == 0, left.get("total"))


def main():
    print("=" * 68)
    print("  GIAM-SAT investigation search / entity-360 tests - v5.0.8")
    print("=" * 68)
    test_dsl_parser()
    test_sql_safety_and_backends()
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
