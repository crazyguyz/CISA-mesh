#!/usr/bin/env python
"""GIAM-SAT Threat Hunting regression tests (v5.0.4).

Covers CRIT-2: "contains" queries previously died because the ESCAPE clause
had two characters ('\\\\') -> "ESCAPE expression must be a single character",
the exception was swallowed and hunting silently returned [].

Usage: python tests/hunting_engine_tests.py  (exit 0 = pass)
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "server"))
import db_manager as dm
from hunting_engine import HuntingEngine


def main():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    dm.DB_PATH = path
    db = dm.DatabaseManager()
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL") + "  " + name)
        if not cond:
            failures.append(name)

    try:
        db.conn.execute("INSERT INTO events (machine_id,hostname,description) VALUES ('M1','h1','process lsass.exe dumped memory')")
        db.conn.execute("INSERT INTO events (machine_id,hostname,description) VALUES ('M2','h2','normal login 100% OK')")
        db.conn.execute("INSERT INTO events (machine_id,hostname,description) VALUES ('M3','h3','path C:\\\\tmp\\\\x')")
        db.conn.execute("INSERT INTO events (machine_id,hostname,description) VALUES ('M4','h4','partial_extra')")
        db.conn.commit()

        eng = HuntingEngine(db)
        cond = lambda v: [{"field": "description", "contains": [v]}]
        r1 = eng._scan_table("events", cond("lsass.exe"))
        r2 = eng._scan_table("events", cond("100%"))           # % must match literally
        r3 = eng._scan_table("events", cond("C:\\\\tmp\\\\x"))  # backslashes literal
        r4 = eng._scan_table("events", cond("partial"))         # _ must match literally
        r5 = eng._scan_table("events", cond("nothing-here"))

        check("contains plain text matches", len(r1) == 1 and r1[0]["machine_id"] == "M1")
        check("contains literal % matches exactly", len(r2) == 1 and r2[0]["machine_id"] == "M2")
        check("contains backslash path matches", len(r3) == 1 and r3[0]["machine_id"] == "M3")
        check("contains literal _ does not wildcard", len(r4) == 1 and r4[0]["machine_id"] == "M4")
        check("contains no-match returns empty (no crash)", len(r5) == 0)
    finally:
        db.conn.close()
        try:
            os.unlink(path)
        except OSError:
            pass

    if failures:
        print(f"\nFAILED: {len(failures)}: {failures}")
        return 1
    print("\nAll hunting contains checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
