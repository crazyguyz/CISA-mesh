#!/usr/bin/env python
"""GIAM-SAT UI wiring tests - v5.0.8.

Two UI features are guarded here (no JS runtime needed - static wiring checks):

1. "Quét IOC" view now has a second tab "Hướng dẫn" (guide): input structure, the
   table/column matrix per IOC type, the command list with the purpose of each
   command, the result structure and the limits.
2. MITRE ATT&CK: the event/rule name in the technique modal (e.g.
   "MITRE Technique: ANOMALY-12765") is clickable and opens that SPECIFIC alert,
   and offers a jump into the Threats tab filtered by that rule.

Also enforces the i18n contract: every data-i18n/t() key added by these features
must exist in BOTH the vi and en dictionaries, and no dictionary may define the
same key twice (a duplicate silently wins in JS and hides the other value).

Usage: python tests/ui_wiring_tests.py      (exit 0 = pass, 1 = failures)
"""

import os
import re
import sys

# v5.0.8: Vietnamese text in the headers/section names crashed on a cp1252 console
# with UnicodeEncodeError -> exit 1 even when every check passed. Same lesson as
# tests/rule_engine_tests.py: force UTF-8 output.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TPL = os.path.join(ROOT, "server", "templates", "index.html")
JS_DIR = os.path.join(ROOT, "server", "static", "js")
I18N = os.path.join(JS_DIR, "i18n.js")
DASHBOARD = os.path.join(JS_DIR, "dashboard.js")
MITRE = os.path.join(JS_DIR, "modules", "mitre-matrix.js")

RESULTS = []


def check(name, ok, extra=""):
    RESULTS.append((name, bool(ok)))
    line = "PASS  " + name if ok else "FAIL  " + name
    if not ok and extra:
        line += "   -> " + str(extra)[:200]
    print(line)


def read(path):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


# ---------------------------------------------------------------- i18n parsing
KEY_RE = re.compile(r"^\s*'([A-Za-z0-9_.\-]+)'\s*:\s*(['\"])", re.M)


def parse_dicts(text):
    """Return {'vi': {key: count}, 'en': {key: count}} for the two DICT blocks."""
    start = text.index("var DICT = {")
    end = text.index("var I18N = ")
    body = text[start:end]
    vi_at = body.index("vi: {")
    en_at = body.index("en: {")
    out = {}
    for lang, blk in (("vi", body[vi_at:en_at]), ("en", body[en_at:])):
        keys = {}
        for m in KEY_RE.finditer(blk):
            keys[m.group(1)] = keys.get(m.group(1), 0) + 1
        out[lang] = keys
    return out


def main():
    print("=" * 68)
    print("  GIAM-SAT UI wiring tests (IOC guide tab + MITRE alert click) - v5.0.8")
    print("=" * 68)

    tpl = read(TPL)
    dash = read(DASHBOARD)
    mitre = read(MITRE)
    i18n = read(I18N)
    dicts = parse_dicts(i18n)
    vi, en = dicts["vi"], dicts["en"]

    # ---------------------------------------------------------- 1) IOC guide tab
    print("\n-- IOC view: scan tab + guide tab --")
    check("tabs markup present", 'data-tab-ioc="scan"' in tpl and 'data-tab-ioc="guide"' in tpl)
    check("scan tab container present", 'id="tabIocScan"' in tpl)
    check("guide tab container present", 'id="tabIocGuide"' in tpl)
    check("guide tab starts hidden",
          re.search(r'id="tabIocGuide"[^>]*style="display:none;"', tpl) is not None)
    check("switchIocTab() defined in dashboard.js",
          re.search(r"function switchIocTab\s*\(", dash) is not None)
    check("switchIocTab toggles .tab-ioc-content", ".tab-ioc-content" in dash)

    for sec in ("purposeH", "inputH", "matrixH", "cmdH", "resultH", "tipsH"):
        check("guide section '%s' present in the template" % sec, ("ioc.guide.%s\"" % sec) in tpl)

    check("JSON sample documented", '"type": "ip"' in tpl)
    check("CSV sample documented", "type,value,source,confidence" in tpl)
    check("IOC type -> table/column matrix documented",
          "<code>dns_query</code>" in tpl and "<code>file_hash</code>" in tpl)
    for c in ("/api/ioc/sweep", "/api/watchlist", "/api/watchlist/import",
              "/api/watchlist/push-intel", "search_ioc"):
        check("command documented: %s" % c, c in tpl)
    check("12 commands listed in the guide", tpl.count('data-i18n="ioc.guide.c12"') == 1)
    for n in range(1, 13):
        check("purpose text for command %d exists in vi+en" % n,
              ("ioc.guide.c%d" % n) in vi and ("ioc.guide.c%d" % n) in en)

    # ---------------------------------------------------------- 2) MITRE drill-down
    print("\n-- MITRE ATT&CK: clickable event/rule name -> concrete alert --")
    check("alert list cached by index (_mitreAlerts)", "_mitreAlerts" in mitre)
    check("openMitreAlert defined", "window.openMitreAlert" in mitre)
    check("rule cell is a clickable link", 'onclick="openMitreAlert(' in mitre)
    check("alert detail opens the existing rich modal", "showAlertRowDetail" in mitre)
    check("'open in Threats' button per alert row", "openThreatsByRule" in mitre)
    check("modal title is clickable", "mitre-detail-title').innerHTML" in mitre)
    check("dashboard.js defines openThreatsByRule", "function openThreatsByRule" in dash)
    check("dashboard.js defines clearThreatRuleFilter", "function clearThreatRuleFilter" in dash)
    check("loadThreats applies _threatRuleFilter",
          "_threatRuleFilter" in dash and "if (_threatRuleFilter) {" in dash)
    check("filter chip with clear button rendered",
          "clearThreatRuleFilter();return false;" in dash)

    # ---------------------------------------------------------- 3) i18n contract
    print("\n-- i18n contract (vi/en) --")
    dup = [k for k, n in list(vi.items()) + list(en.items()) if n > 1]
    check("no duplicate key in either dictionary", not dup, dup[:6])
    check("vi and en define the same keys", set(vi) == set(en),
          "vi-only=%s en-only=%s" % (sorted(set(vi) - set(en))[:5],
                                     sorted(set(en) - set(vi))[:5]))

    used = set(re.findall(r'data-i18n="([^"]+)"', tpl))
    for js in (dash, mitre):
        used |= set(re.findall(r"t\('([^']+)'\)", js))
    new_keys = {k for k in used if k.startswith("ioc.") or k.startswith("mitre.")
                or k == "tr.filterRule"}
    missing = sorted(k for k in new_keys if k not in vi or k not in en)
    check("every ioc./mitre./tr.filterRule key used by the UI exists in vi+en",
          not missing, missing[:8])
    print("   (%d keys checked)" % len(new_keys))

    failed = [n for n, ok in RESULTS if not ok]
    print("\n" + "=" * 68)
    print("  %d/%d checks passed" % (len(RESULTS) - len(failed), len(RESULTS)))
    for name in failed:
        print("  FAILED: %s" % name)
    print("=" * 68)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
