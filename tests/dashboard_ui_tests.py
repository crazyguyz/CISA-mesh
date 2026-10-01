#!/usr/bin/env python
"""GIAM-SAT dashboard UI coverage tests - v5.0.9.

Answers one question with evidence instead of opinion: "which backend feature is
still invisible in the dashboard?" Every route added by Phases A-D (unified
investigation, forensics / evidence packets, fleet rollouts, storage+partition,
staged policies) must be reachable from the UI - a route nobody calls is a dead
feature. Static analysis only: no Flask, no browser.

Also guards two bugs found in this round:
  * the Investigate view left the framework spinner in #invResults forever when
    no query had been typed yet - init() must ALWAYS settle that container;
  * duplicated i18n keys (in JS the last definition silently wins, hiding the
    other language's value).

Usage: python tests/dashboard_ui_tests.py     (exit 0 = pass, 1 = failures)
"""

import os
import re
import sys

# cp1252 consoles crashed on Vietnamese text in previous suites - force UTF-8.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TPL = os.path.join(ROOT, "server", "templates", "index.html")
JS_DIR = os.path.join(ROOT, "server", "static", "js")
DASHBOARD = os.path.join(JS_DIR, "dashboard.js")
INVESTIGATE = os.path.join(JS_DIR, "modules", "investigate.js")
FLEET = os.path.join(JS_DIR, "modules", "fleet.js")
I18N = os.path.join(JS_DIR, "i18n.js")

RESULTS = []


def check(name, ok, extra=""):
    RESULTS.append((name, bool(ok)))
    line = "PASS  " + name if ok else "FAIL  " + name
    if not ok and extra:
        line += "   -> %s" % (extra,)
    print(line)


def read(path):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def read_all_js():
    """Every served script - routes may be called from any module."""
    chunks = []
    for base, _dirs, files in os.walk(JS_DIR):
        for name in files:
            if name.endswith(".js"):
                chunks.append(read(os.path.join(base, name)))
    return "\n".join(chunks)


def count_key(i18n_text, key):
    """How many times "'key':" is defined (2 = vi + en, >2 = duplicate)."""
    return len(re.findall(r"'%s':" % re.escape(key), i18n_text))


# Every route added in phases A-D and the UI artefact that has to consume it.
ROUTES = [
    ("/api/investigate/search", "unified search box"),
    ("/api/investigate/entity/", "Entity 360 panel"),
    ("/api/investigate/fields", "welcome field/scope hints"),
    ("/api/investigate/saved", "saved-search chips"),
    ("/api/investigate/export", "CSV/JSON export buttons"),
    ("/api/forensics/process-tree/", "process tree button"),
    ("/api/forensics/evidence?limit=20", "evidence packet list"),
    ("/api/forensics/evidence'", "evidence packet create"),
    ("/api/forensics/evidence/' + id", "evidence delete"),
    ("/api/forensics/render", "evidence preview"),
    ("/api/fleet/rollout/plan", "rollout plan button"),
    ("/api/fleet/rollout'", "rollout start button"),
    ("/api/fleet/rollouts", "rollout history picker"),
    ("/api/fleet/rollout/' + id", "rollout detail view"),
    ("/api/fleet/rollout/' + state.rolloutId + '/advance", "next-wave button"),
    ("/api/fleet/rollout/' + state.rolloutId + '/rollback", "rollback button"),
    ("/api/health/fleet", "fleet health table"),
    ("/api/health/ingest/ack", "rejected-source ack button"),
    ("/api/health/storage'", "storage card"),
    ("/api/health/storage/rollup", "rollup now button"),
    ("/api/health/storage/drop-old", "drop-old button"),
    ("/api/health/coverage", "log coverage view"),
    ("/api/agent/onboarding", "coverage onboarding guide"),
    ("/api/policies/list", "staged-policy picker"),
    ("/api/policies/preview", "policy preview button"),
    ("/api/policies/wave-apply", "canary wave button"),
    ("/api/policies/wave-advance", "next-wave policy button"),
    ("/api/policies/status-list", "policy status tab"),
    ("/api/policies/requeue/", "policy requeue button"),
]

# Help text an operator needs in order to understand each new tool.
HINT_KEYS = [
    "inv.welcomeBody", "inv.syntaxBody", "inv.evidenceListHint",
    "fleet.rolloutHint", "fleet.healthHint", "fleet.storageHint",
    "fleet.policyHint",
]

NEW_KEYS = HINT_KEYS + [
    "inv.welcomeTitle", "inv.syntax", "inv.examples", "inv.availableFields",
    "inv.scopes", "inv.evidenceList", "inv.evidenceEmpty", "inv.evidenceDeleted",
    "fleet.storage", "fleet.needPartition", "fleet.partitionHow", "fleet.rollup",
    "fleet.rollupDone", "fleet.dropOld", "fleet.dropOldConfirm", "fleet.dropDone",
    "fleet.policy", "fleet.policyPreview", "fleet.policyCanary",
    "fleet.policyNext", "fleet.policyWaves", "fleet.policyApplied",
    "fleet.policyDone", "fleet.noPolicy",
]


def js_syntax_errors():
    """node --check on every served script.

    A single unescaped quote inside an i18n string took the whole dictionary
    down (both languages) without any Python test noticing, so the JS layer now
    gets the same gate the Python layer has. Skipped when node is unavailable.
    """
    import shutil
    import subprocess
    node = shutil.which("node")
    if not node:
        return None
    broken = []
    for base, _dirs, files in os.walk(JS_DIR):
        for name in files:
            if not name.endswith(".js"):
                continue
            path = os.path.join(base, name)
            proc = subprocess.run([node, "--check", path], capture_output=True,
                                  text=True, encoding="utf-8", errors="replace")
            if proc.returncode != 0:
                broken.append(os.path.relpath(path, ROOT))
    return broken


def main():
    tpl = read(TPL)
    dash = read(DASHBOARD)
    inv = read(INVESTIGATE)
    fleet = read(FLEET)
    i18n = read(I18N)
    ui_sources = "\n".join([tpl, read_all_js()])

    print("\n=== 1. new views are reachable from the dashboard ===")
    check("index.html declares the Investigate view", 'id="viewInvestigate"' in tpl)
    check("index.html declares the result/facet/evidence containers",
          all(x in tpl for x in ('id="invResults"', 'id="invFacets"', 'id="invEvidence"')))
    check("index.html keeps the fleet panel in the coverage view",
          'id="fleetPanel"' in tpl and 'id="coverageList"' in tpl)
    check("viewMap routes investigate -> invResults + investigate.init()",
          re.search(r"investigate:\s*\{[^}]*container:\s*'invResults'[^}]*investigate\.init\(\)",
                    dash, re.S) is not None)
    check("viewMap starts the fleet module when coverage opens",
          re.search(r"coverage:\s*\{[^}]*fleet\.init\(\)", dash) is not None)

    print("\n=== 2. regression: Investigate must never keep the spinner ===")
    start = inv.find("function init()")
    tail = inv[start:]
    end = tail.find("\n  }\n")
    init_body = tail[:end if end > 0 else 2000]
    check("init() always settles #invResults (query -> run, else welcome)",
          "renderWelcome()" in init_body and "state.query" in init_body)
    check("renderWelcome() writes into #invResults",
          "function renderWelcome()" in inv and "el('invResults')" in inv)
    ex = inv[inv.find("var EXAMPLES = ["):inv.find("var EXAMPLES = [") + 400]
    check("welcome offers >=5 clickable example queries",
          len(re.findall(r"^\s*'[^']+',?$", ex, re.M)) >= 5 and "inv-use" in inv)
    check("example chips are wired to the query box",
          "onUseClick" in inv and "data-use" in inv)
    check("welcome documents purpose + syntax",
          "inv.welcomeTitle" in inv and "inv.syntaxBody" in inv)

    print("\n=== 3. every new API route has a UI caller (no dead features) ===")
    missing = ["%s (%s)" % (n, l) for n, l in ROUTES if n not in ui_sources]
    check("all %d new routes are consumed by the front-end" % len(ROUTES),
          not missing, "; ".join(missing[:6]))

    print("\n=== 4. the previously missing panels now exist ===")
    check("fleet.js renders the storage/partition card",
          "fleetStorage" in fleet and "function renderStorage" in fleet)
    check("fleet.js offers rollup + drop-old actions",
          "fleet.rollup()" in fleet and "fleet.dropOld()" in fleet)
    check("fleet.js renders the staged-policy card",
          "fleetPolicyList" in fleet and "function renderPolicies" in fleet)
    check("fleet.js offers preview / canary / next-wave policy actions",
          all(x in fleet for x in ("fleet.policyPreview()", "fleet.policyWave(0)",
                                   "fleet.policyNext()")))
    check("fleet.js has a rollout history picker",
          "fleetRolloutPick" in fleet and "function loadRolloutList" in fleet)
    check("investigate.js lists stored evidence packets",
          "function loadEvidence" in inv and "loadEvidence: loadEvidence" in inv)
    check("evidence list offers HTML + JSON download and delete",
          "?fmt=html" in inv and "delEvidence" in inv)
    check("init() loads the evidence list with the rest of the view",
          "loadEvidence();" in init_body)
    check("evidence card self-mounts when the template is cached",
          "function ensureEvidenceCard" in inv and "ensureEvidenceCard();" in inv)

    print("\n=== 5. every new tool explains itself (help text shipped) ===")
    nohelp = [k for k in HINT_KEYS if count_key(i18n, k) != 2]
    check("hint keys exist in both languages exactly once", not nohelp, nohelp)
    unused = [k for k in HINT_KEYS if ("'%s'" % k) not in ui_sources
              and ('"%s"' % k) not in ui_sources]
    check("hint keys are actually rendered (module or data-i18n)", not unused, unused)

    print("\n=== 6. i18n parity and duplicate-key safety ===")
    bad = ["%s x%d" % (k, count_key(i18n, k)) for k in NEW_KEYS
           if count_key(i18n, k) != 2]
    check("all new keys defined once per language (%d keys)" % len(NEW_KEYS),
          not bad, bad[:8])

    print("\n=== 7. every served script is valid JavaScript ===")
    broken = js_syntax_errors()
    if broken is None:
        print("SKIP  node not found")
    else:
        check("node --check passes for all served JS files", not broken, broken[:5])

    failed = [n for n, ok in RESULTS if not ok]
    print("\n" + "=" * 68)
    print("  %d/%d checks passed" % (len(RESULTS) - len(failed), len(RESULTS)))
    for name in failed:
        print("  FAILED: %s" % name)
    print("=" * 68)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
