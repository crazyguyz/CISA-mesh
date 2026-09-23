#!/usr/bin/env python
"""GIAM-SAT HTML report (reporting_engine) regression tests - v5.0.8.

Guards the bug that broke EVERY HTML report as soon as it contained data:

  server/reporting_engine.py imported the stdlib `html` module and defined
      _esc = lambda v: html.escape(str(v), quote=True)
  but the next statement bound a LOCAL variable
      html = f'''<!DOCTYPE html> ...'''
  (the document being built) - from then on the name `html` was a str inside the
  method, so the first _esc(...) call raised

      AttributeError: 'str' object has no attribute 'escape'

  Consequences seen in production: "[-] WEEKLY failed: 'str' object has no
  attribute 'escape'" in logs/giamsat.log, no weekly/daily HTML report, no
  emailed attachment, weekly/daily catch-up broken and generate_pdf_report()
  broken too. With an EMPTY database no row was rendered, _esc() was never
  called and the report was generated - which is why the bug slipped through.

Usage: python tests/reporting_html_tests.py
Exit code 0 = all passed, 1 = failures found.
"""

import os
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "server"))

import reporting_engine  # noqa: E402

RESULTS = []
TMP_DIRS = []


def check(name, ok, extra=""):
    RESULTS.append((name, bool(ok)))
    line = "PASS  " + name if ok else "FAIL  " + name
    if not ok and extra:
        line += "   -> " + str(extra)[:200]
    print(line)


def _clean(text, limit=200):
    return " ".join(str(text).split())[:limit]


class StubDB:
    """Minimal stand-in for DatabaseManager: one row per report section."""

    def __init__(self, rows=True):
        self.rows = rows

    def get_machines(self):
        return [{"hostname": "PC-01", "is_online": True, "os": "Windows 10"}] if self.rows else []

    def get_events(self, limit=500):
        return [{"timestamp": "2026-09-23 10:00:00", "severity": "HIGH", "rule_name": "R1",
                 "hostname": "PC-01", "description": "event"}] if self.rows else []

    def get_threat_alerts(self, limit=100, since_hours=None):
        # XSS payloads: the report must show them ESCAPED, never raw
        return [{"timestamp": "2026-09-23 10:00:00", "severity": "CRITICAL",
                 "rule_name": "<script>alert(1)</script>", "hostname": "PC-01",
                 "description": "x & y \"z\""}] if self.rows else []

    def get_vuln_alerts(self, limit=100):
        return [{"cve": "CVE-2026-0001", "severity": "HIGH", "software": "svc",
                 "version": "1.0", "hostname": "PC-01"}] if self.rows else []

    def get_yara_alerts(self, limit=50):
        return [{"timestamp": "2026-09-23 10:00:00", "rule_name": "Y1",
                 "file": "C:/tmp/a.bin", "hostname": "PC-01"}] if self.rows else []

    def get_sca_events(self, limit=100):
        return [{"check_id": "C1", "title": "T1", "status": "FAIL",
                 "severity": "HIGH"}] if self.rows else []


def _engine(rows=True):
    """ReportingEngine with a stub DB and an isolated output directory."""
    eng = reporting_engine.ReportingEngine(db_manager=StubDB(rows=rows))
    out = tempfile.mkdtemp(prefix="giamsat_report_test_")
    TMP_DIRS.append(out)
    eng.report_dir = out
    return eng


def _read(path):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def test_generate_html_report():
    """The crash path: a report with rows must be produced AND fully escaped."""
    print("\n-- generate_html_report (rows present) --")
    eng = _engine(rows=True)
    try:
        path = eng.generate_html_report(report_type="weekly")
    except Exception as exc:  # the old bug landed here
        check("generate_html_report does not raise", False,
              "%s: %s" % (type(exc).__name__, exc))
        return
    check("generate_html_report does not raise", True)
    check("returned path exists", bool(path) and os.path.exists(path), path)
    if not path or not os.path.exists(path):
        return
    doc = _read(path)
    check("document starts with <!DOCTYPE html>", doc.lstrip().startswith("<!DOCTYPE html>"))
    check("document ends with </html>", doc.rstrip().endswith("</html>"))
    check("threat row rendered (host PC-01)", "PC-01" in doc)
    check("raw <script> payload NOT present (no HTML injection)",
          "<script>" not in doc, _clean(doc))
    check("payload present but escaped (&lt;script&gt;)", "&lt;script&gt;" in doc)
    check("ampersand escaped (x &amp; y)", "x &amp; y" in doc)
    check("double quote escaped (&quot;)", "&quot;" in doc)
    check("vulnerability row rendered", "CVE-2026-0001" in doc)
    check("SCA row rendered", "C1" in doc)
    check("YARA row rendered", "Y1" in doc)
    check("executive summary rendered", "Executive Summary" in doc)


def test_empty_database():
    """An empty DB never called _esc() - that path must keep working."""
    print("\n-- generate_html_report (empty DB) --")
    eng = _engine(rows=False)
    try:
        path = eng.generate_html_report(report_type="daily")
    except Exception as exc:
        check("empty report does not raise", False, "%s: %s" % (type(exc).__name__, exc))
        return
    check("empty report does not raise", True)
    check("empty report file exists", bool(path) and os.path.exists(path), path)
    if path and os.path.exists(path):
        doc = _read(path)
        check("empty report says no threats", "No threats detected" in doc)


def test_pdf_fallback():
    """generate_pdf_report() shares the same code path (fallback = .html file)."""
    print("\n-- generate_pdf_report --")
    eng = _engine(rows=True)
    try:
        path = eng.generate_pdf_report(report_type="weekly")
    except Exception as exc:
        check("generate_pdf_report does not raise", False, "%s: %s" % (type(exc).__name__, exc))
        return
    check("generate_pdf_report does not raise", True)
    check("returns an existing file (.html fallback or .pdf)",
          bool(path) and os.path.exists(path) and path.lower().endswith((".html", ".pdf")), path)


def main():
    print("=" * 68)
    print("  GIAM-SAT HTML report (reporting_engine) regression tests - v5.0.8")
    print("=" * 68)
    try:
        test_generate_html_report()
        test_empty_database()
        test_pdf_fallback()
    finally:
        for d in TMP_DIRS:
            shutil.rmtree(d, ignore_errors=True)
    failed = [n for n, ok in RESULTS if not ok]
    print("\n" + "=" * 68)
    print("  %d/%d checks passed" % (len(RESULTS) - len(failed), len(RESULTS)))
    for name in failed:
        print("  FAILED: %s" % name)
    print("=" * 68)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
