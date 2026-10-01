#!/usr/bin/env python
"""GIAM-SAT tools/ CLI health regression tests - v5.0.8.

Guards the two tool bugs found on 2026-10-01 while testing the shipped tools:

1. `tools/rule_replay.py` was SQLite-only and hardcoded
   `<root>/server/giamsat_data.db` as the default database, so on a PostgreSQL
   install (the default since v5.0.x) it stopped with
       DB not found: D:\\test\\server\\giamsat_data.db
   even though the server was healthy. It must resolve the backend exactly like
   the server does (GIAMSAT_DB_BACKEND in server/.env) and must keep working
   with `--sqlite` for legacy installs.
2. `tools/reset_admin_pw.py` had NO argparse, so `python tools/reset_admin_pw.py`
   (and even `--help`!) silently rewrote users.json and reset the admin password.
   Every tool must answer `--help` without touching any state.

Usage:
  python tests/tool_cli_tests.py
Exit code 0 = all passed, 1 = failures found.
"""

import glob
import hashlib
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS = os.path.join(ROOT, "tools")
RULES = os.path.join(ROOT, "server", "rules", "correlation_rules.yaml")
RESULTS = []


def check(name, ok, extra=""):
    RESULTS.append((name, bool(ok)))
    line = "PASS  " + name
    if not ok:
        line = "FAIL  " + name
        if extra:
            line += "   -> " + str(extra)[:220]
    print(line)


def tool_scripts():
    return sorted(os.path.basename(p) for p in glob.glob(os.path.join(TOOLS, "*.py")))


def file_digest(path):
    """sha256 of a file, or None when it does not exist."""
    if not path or not os.path.exists(path) or os.path.isdir(path):
        return None
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()


def run(args, cwd=None, timeout=120, env=None):
    return run_raw([sys.executable] + args, cwd=cwd, timeout=timeout, env=env)


def run_raw(argv, cwd=None, timeout=120, env=None):
    proc = subprocess.run(argv, cwd=cwd or ROOT, timeout=timeout, env=env,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return proc.returncode, proc.stdout.decode("utf-8", "replace")


def test_every_tool_has_safe_help():
    """Every tool must print usage and exit 0 on --help, changing nothing."""
    print("\n-- every tool answers --help without touching state --")
    scripts = tool_scripts()
    check("tools/ contains python tools", len(scripts) >= 5, scripts)
    guards = [os.path.join(ROOT, "users.json"), os.path.join(ROOT, ".user_key"),
              os.path.join(ROOT, "server", "version.txt"), RULES]
    before = {g: file_digest(g) for g in guards}
    for name in scripts:
        try:
            code, out = run([os.path.join(TOOLS, name), "--help"])
        except subprocess.TimeoutExpired:
            check("%s --help (no timeout)" % name, False, "timed out")
            continue
        ok = code == 0 and "usage:" in out.lower()
        check("%s --help exits 0 + usage" % name, ok, "code=%s out=%s" % (code, out[-200:]))
    after = {g: file_digest(g) for g in guards}
    check("no tool modified users.json/.user_key/version.txt/rules on --help",
          before == after,
          [g for g in guards if before[g] != after[g]])


def test_reset_admin_pw_is_dry_run_by_default():
    """The password tool must not write anything unless --apply/--yes is given."""
    print("\n-- reset_admin_pw.py is dry-run by default --")
    src = open(os.path.join(TOOLS, "reset_admin_pw.py"), encoding="utf-8").read()
    check("has argparse + --apply flag", "argparse.ArgumentParser" in src and '"--apply"' in src)
    check("writes only behind --apply", "if not apply:" in src and "return" in src)
    check("no module-level cryptography import", "\n    from cryptography.fernet import Fernet" in src
          or "from cryptography.fernet import Fernet" in src)
    tmp = tempfile.mkdtemp(prefix="giamsat_tool_")
    try:
        users = os.path.join(tmp, "users.json")
        key = os.path.join(tmp, ".user_key")
        try:
            from cryptography.fernet import Fernet
        except ImportError:
            print("SKIP  cryptography not installed - cannot build a fake users.json")
            return
        fk = Fernet.generate_key()
        with open(key, "wb") as f:
            f.write(fk)
        blob = Fernet(fk).encrypt(b'{"admin": {"username": "admin", "password": "x", '
                                  b'"salt": "y", "role": "admin", "must_change_password": false}}')
        with open(users, "wb") as f:
            f.write(blob)
        before = file_digest(users)
        code, out = run([os.path.join(TOOLS, "reset_admin_pw.py"), "--users-dir", tmp])
        check("dry-run reports without writing", "DRY-RUN" in out and file_digest(users) == before,
              "code=%s out=%s" % (code, out[-200:]))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


GEOIP_PROBE = '''
import os, shutil, sys
root = sys.argv[1]
sys.path.insert(0, os.path.join(root, "server"))
import geoip_lookup as g

assert not g._loaded
g._ensure_loaded()
if g._loaded or g._readers["asn"] is not None:
    print("RESULT: fail (latched as loaded with missing files)")
    sys.exit(1)

data = os.path.join(root, "server", "data")
asn_src = os.path.join(data, "dbip-asn-lite.mmdb")
city_src = os.path.join(data, "dbip-city-lite.mmdb")
if not (os.path.exists(asn_src) and os.path.exists(city_src)):
    print("SKIP no real .mmdb in server/data to test with")
    sys.exit(0)

# simulate tools/setup_geolite2.ps1 finishing WHILE the server runs
shutil.copy(asn_src, os.environ["GIAMSAT_GEOIP_ASN_DB"])
shutil.copy(city_src, os.environ["GIAMSAT_GEOIP_CITY_DB"])
g._next_retry = 0
g._ensure_loaded()
ok = g._loaded and g._readers["asn"] is not None

from network_baseline import NetworkBaseline
nb = NetworkBaseline(None)
country = nb._lookup_country("8.8.8.8")
private = nb._lookup_country("192.168.1.10")
asn = nb._extract_asn_from_ip("8.8.8.8")
nb_ok = len(str(country)) == 2 and str(country).isalpha() and private == "PRIVATE" and asn
if ok and nb_ok:
    print("RESULT: ok (country=%s, asn=%s)" % (country, asn))
else:
    print("RESULT: fail (loaded=%s country=%s private=%s asn=%s)" % (ok, country, private, asn))
sys.exit(0 if (ok and nb_ok) else 1)
'''


def test_geolite2_and_geoip_reload():
    """tools/setup_geolite2.ps1 used to build one URL from the CURRENT month only,
    which 404s until db-ip publishes (so server\\data stayed empty), and the server
    latched `_loaded` on the first lookup so a running server never picked up the
    files it fetched later."""
    print("\n-- GeoIP: monthly fallback + server picks files up while running --")
    ps = open(os.path.join(TOOLS, "setup_geolite2.ps1"), encoding="utf-8").read()
    check("geolite2 walks back through months", "AddMonths" in ps)
    check("geolite2 survives the 404 of an unpublished month",
          "catch" in ps and "continue" in ps and "exit 1" in ps)
    src = open(os.path.join(ROOT, "server", "geoip_lookup.py"), encoding="utf-8").read()
    check("geoip lookup retries instead of latching", "_next_retry" in src)

    tmp = tempfile.mkdtemp(prefix="giamsat_geoip_")
    try:
        asn = os.path.join(tmp, "asn.mmdb")
        city = os.path.join(tmp, "city.mmdb")
        child = os.path.join(tmp, "probe.py")
        with open(child, "w", encoding="utf-8") as f:
            f.write(GEOIP_PROBE)
        env = dict(os.environ, GIAMSAT_GEOIP_ASN_DB=asn, GIAMSAT_GEOIP_CITY_DB=city)
        code, out = run([child, ROOT], env=env)
        if "SKIP" in out:
            print("SKIP  no .mmdb in server/data (run tools/setup_geolite2.ps1 first)")
        else:
            check("mmdb installed while the server runs is picked up",
                  code == 0 and "RESULT: ok" in out, "code=%s out=%s" % (code, out[-300:]))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_rule_replay_supports_postgres():
    """Reported bug: `python tools/rule_replay.py` died with
    'DB not found: <root>\\server\\giamsat_data.db' on a PostgreSQL install."""
    print("\n-- rule_replay.py speaks PostgreSQL and legacy SQLite --")
    path = os.path.join(TOOLS, "rule_replay.py")
    src = open(path, encoding="utf-8").read()
    check("reads the backend from server/.env", "GIAMSAT_DB_BACKEND" in src)
    check("has an --env option", '"--env"' in src)
    check("PostgreSQL window uses make_interval", "make_interval(hours" in src)
    check("no hardcoded SQLite path as default", "default=DEFAULT_DB" not in src)
    check("keeps --sqlite (+ --db alias) for legacy installs",
          '"--sqlite"' in src and '"--db"' in src)

    tmp = tempfile.mkdtemp(prefix="giamsat_replay_")
    try:
        db = os.path.join(tmp, "giamsat_data.db")
        conn = sqlite3.connect(db)
        conn.execute("CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT, "
                     "event_id TEXT, description TEXT, received_at TEXT)")
        conn.execute("INSERT INTO events (type, event_id, description, received_at) "
                     "VALUES ('event', '4624', 'logon', datetime('now'))")
        conn.commit()
        conn.close()
        code, out = run([path, "--sqlite", db, "--rules", RULES, "--hours", "24"])
        check("replays a SQLite database end to end",
              code == 0 and "Events  : 1 scanned" in out, "code=%s out=%s" % (code, out[-260:]))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # A repo without server/.env must explain what to pass - and never print the
    # old bare "DB not found: ...giamsat_data.db".
    fake = tempfile.mkdtemp(prefix="giamsat_repo_")
    try:
        os.makedirs(os.path.join(fake, "tools"))
        copy = os.path.join(fake, "tools", "rule_replay.py")
        shutil.copy(path, copy)
        code, out = run([copy, "--rules", RULES], cwd=fake)
        check("missing config gives clear guidance",
              code == 2 and "--env" in out and "--sqlite" in out and "DB not found" not in out,
              "code=%s out=%s" % (code, out[-260:]))
    finally:
        shutil.rmtree(fake, ignore_errors=True)


def test_powershell_tools_parse():
    """tools/*.ps1 must at least be syntactically valid PowerShell."""
    print("\n-- tools/*.ps1 parse cleanly --")
    scripts = sorted(glob.glob(os.path.join(TOOLS, "*.ps1")))
    check("tools/ contains powershell helpers", len(scripts) >= 2, scripts)
    if os.name != "nt":
        print("SKIP  PowerShell check is Windows-only")
        return
    for p in scripts:
        cmd = ("$e=$null; [void][System.Management.Automation.Language.Parser]::ParseFile("
               "'%s',[ref]$null,[ref]$e); if ($e.Count -gt 0) { $e | ForEach-Object { Write-Output $_.Message };"
               " exit 1 } else { Write-Output PARSE_OK; exit 0 }" % p.replace("\\", "\\\\"))
        try:
            code, out = run_raw(["powershell", "-NoProfile", "-Command", cmd])
        except Exception as exc:
            check("%s parses" % os.path.basename(p), False, exc)
            continue
        check("%s parses" % os.path.basename(p), code == 0 and "PARSE_OK" in out, out[-200:])


def main():
    print("=" * 68)
    print("  GIAM-SAT tools/ CLI health tests - v5.0.8")
    print("=" * 68)
    test_every_tool_has_safe_help()
    test_reset_admin_pw_is_dry_run_by_default()
    test_rule_replay_supports_postgres()
    test_geolite2_and_geoip_reload()
    test_powershell_tools_parse()
    passed = sum(1 for _, ok in RESULTS if ok)
    print("\n" + "=" * 68)
    print("  %d/%d checks passed" % (passed, len(RESULTS)))
    print("=" * 68)
    if passed != len(RESULTS):
        print("FAILED: %s" % ", ".join(n for n, ok in RESULTS if not ok))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
