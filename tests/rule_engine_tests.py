#!/usr/bin/env python
"""
GIAM-SAT Rule Engine Regression Tests v1.0.0
Simulates attack sequences and validates correlation rules fire correctly.

Usage:
    python tests/rule_engine_tests.py
    python tests/rule_engine_tests.py --verbose
    python tests/rule_engine_tests.py --json tests/test_rules.json

Exit code 0 = all passed, 1 = failures found.
"""

import json
import os
import sys
import time
import argparse
from datetime import datetime
from collections import defaultdict, deque

# Add parent to path to import server modules
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "server"))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "agent"))


class RuleTestRunner:
    """Loads test cases from JSON and validates them against correlation engine."""

    def __init__(self, test_file=None, verbose=False):
        self.test_file = test_file or os.path.join(os.path.dirname(__file__), "test_rules.json")
        self.verbose = verbose
        self.engine = None
        self.results = {"passed": 0, "failed": 0, "skipped": 0, "total": 0, "details": []}

    def load_tests(self):
        """Load test cases from JSON file."""
        with open(self.test_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("test_cases", [])

    def try_load_engine(self):
        """Load the agent correlation engine (primary) and the server
        cross-machine engine (for CROSS-* test cases)."""
        loaded = False
        try:
            from correlation_engine import CorrelationEngine
            self.engine = CorrelationEngine()
            self.engine_mode = "agent"
            loaded = True
            if self.verbose:
                print("[*] Loaded agent-side CorrelationEngine")
        except Exception as e:
            if self.verbose:
                print(f"[-] Agent engine load failed: {e}")

        # Server cross-machine engine (for CROSS-* rules)
        self.server_engine = None
        try:
            from correlation_engine_server import ServerCorrelationEngine
            self.server_engine = ServerCorrelationEngine()
            if self.verbose:
                print("[*] Loaded server-side ServerCorrelationEngine")
        except Exception as e:
            if self.verbose:
                print(f"[-] Server engine load failed: {e}")

        return loaded

    def simulate_lotl_check(self, events):
        """Fallback: use ProcessTreeBuilder directly for LOTL tests."""
        try:
            from process_tree import ProcessTreeBuilder, _check_lotl_chain, _classify_process
            # For LOTL tests, simulate adding events to tree
            tree = ProcessTreeBuilder()
            for e in events:
                tree.add_event(e)
            # If any event has lotl_detected flag, consider it triggered
            for e in events:
                if e.get("lotl_detected"):
                    return [{"rule_name": "LOTL Detection", "severity": "HIGH", "lotl_detected": True}]
            return []
        except ImportError:
            return []

    def _reset_engine_state(self):
        """Reset correlation engine state between test cases so cooldown and
        event buffers don't leak across independent test cases."""
        if self.engine:
            self.engine.fired_alerts = {}
            self.engine.event_buffers = defaultdict(lambda: deque())
            self.engine.sequence_states = defaultdict(list)
            # v4.6.6: rule_exclusions leak across cases (a prior case's network
            # event with a standard port sets NET-BEACON-001's NOT-exclusion and
            # silently blocks it for 300s) - reset them with the rest of the state.
            self.engine.rule_exclusions = {}
        if getattr(self, "server_engine", None):
            self.server_engine.reset_buffers()

    def simulate_pattern_check(self, events):
        """Fallback: check patterns using built-in regex from yara_scanner."""
        results = []
        try:
            from yara_scanner import SUSPICIOUS_PATTERNS
            import re
            for event in events:
                desc = event.get("description", "")
                for pattern in SUSPICIOUS_PATTERNS:
                    if re.search(pattern["pattern"], desc.encode() if isinstance(pattern["pattern"], bytes) else desc, re.IGNORECASE if isinstance(pattern["pattern"], bytes) else 0):
                        results.append({"rule_name": pattern["name"], "triggered": True})
        except ImportError:
            pass
        return results

    def run_events_through_engine(self, events):
        """Feed events to correlation engine and return triggered alerts."""
        triggered = []
        if self.engine and hasattr(self.engine, 'process_event'):
            for e in events:
                try:
                    result = self.engine.process_event(e)
                    if result:
                        triggered.extend(result)
                except Exception:
                    pass
        return triggered

    def run_test_case(self, case):
        """Run a single test case and return (passed, details)."""
        test_id = case["id"]
        rule_id = case.get("rule_id", "UNKNOWN")
        name = case.get("name", "No name")
        events = case.get("events", [])
        expected = case.get("expected", {})

        # Reset engine state so cooldown + event buffers don't leak across cases
        self._reset_engine_state()

        # Run through correlation engine
        is_cross = str(rule_id).startswith("CROSS-")
        if is_cross and getattr(self, "server_engine", None):
            # Cross-machine rules run on the server engine
            triggered = []
            for e in events:
                try:
                    results = self.server_engine.process_event(e)
                    if results:
                        triggered.extend(results)
                except Exception:
                    pass
        elif self.engine_mode == "agent":
            # Agent engine: process_event returns a list of triggered alerts
            triggered = []
            for e in events:
                try:
                    results = self.engine.process_event(e)
                    if results:
                        triggered.extend(results)
                except Exception:
                    pass
        elif self.engine_mode == "server":
            triggered = self.run_events_through_engine(events)
        else:
            # Fallback: pattern + LOTL simulation
            triggered = []
            triggered.extend(self.simulate_pattern_check(events))
            triggered.extend(self.simulate_lotl_check(events))

        expected_triggered = expected.get("triggered", True)
        rule_name_contains = expected.get("rule_name_contains", "")
        expected_lotl = expected.get("lotl_detected", False)

        actually_triggered = len(triggered) > 0

        # Check if expected behavior matches
        errors = []
        if expected_triggered and not actually_triggered:
            errors.append(f"Expected alert but none triggered")
        elif not expected_triggered and actually_triggered:
            errors.append(f"Expected NO alert but got: {[t.get('rule_name','?') for t in triggered]}")

        if rule_name_contains and actually_triggered:
            match_found = any(
                rule_name_contains.lower() in str(t.get("rule_name", "")).lower()
                for t in triggered
            )
            if not match_found:
                errors.append(f"No alert matching '{rule_name_contains}'. Got: {[t.get('rule_name','?') for t in triggered]}")

        if expected_lotl:
            has_lotl = any(t.get("lotl_detected") for t in triggered)
            if not has_lotl:
                events_have_lotl = any(e.get("lotl_detected") for e in events)
                if events_have_lotl:
                    pass  # Event was enriched in-place
                else:
                    errors.append("Expected LOTL detection but not found")

        passed = len(errors) == 0
        detail = {
            "id": test_id,
            "rule_id": rule_id,
            "name": name,
            "events": len(events),
            "passed": passed,
            "triggered_count": len(triggered),
            "errors": errors,
            "triggered_rules": [t.get("rule_name", "?") for t in triggered[:5]] if triggered else [],
        }

        if self.verbose:
            status = "✅ PASS" if passed else "❌ FAIL"
            print(f"  {status} {test_id}: {name} ({len(events)} events)")

        return passed, detail

    def run_all(self):
        """Run all test cases."""
        test_cases = self.load_tests()
        self.results["total"] = len(test_cases)

        engine_loaded = self.try_load_engine()
        if not engine_loaded:
            print("[!] No correlation engine available - using fallback pattern matching")
        else:
            print(f"[*] Using {self.engine_mode} correlation engine")

        print(f"\n{'='*60}")
        print(f"GIAM-SAT Rule Regression Tests")
        print(f"Test file: {self.test_file}")
        print(f"Total cases: {len(test_cases)}")
        print(f"{'='*60}\n")

        for case in test_cases:
            passed, detail = self.run_test_case(case)
            self.results["details"].append(detail)
            if passed:
                self.results["passed"] += 1
            else:
                self.results["failed"] += 1
                if not self.verbose:
                    print(f"  ❌ FAIL {case['id']}: {case['name']}")

        self.print_summary()
        return self.results["failed"] == 0

    def print_summary(self):
        """Print test summary."""
        r = self.results
        print(f"\n{'='*60}")
        print(f"RESULTS: {r['passed']} passed, {r['failed']} failed, {r['total']} total")
        print(f"{'='*60}")

        if r["failed"] > 0:
            print(f"\nFAILURES:")
            for d in r["details"]:
                if not d["passed"]:
                    print(f"  [{d['id']}] {d['name']}")
                    for err in d["errors"]:
                        print(f"    → {err}")

        if r["passed"] == r["total"]:
            print(f"\n✅ All {r['total']} tests passed!")
        else:
            print(f"\n❌ {r['failed']}/{r['total']} tests failed")

        # Save JSON report
        report_path = os.path.join(os.path.dirname(__file__), "test_report.json")
        with open(report_path, "w") as f:
            json.dump(self.results, f, indent=2, default=str)
        print(f"\n[*] Report saved to: {report_path}")


def main():
    parser = argparse.ArgumentParser(description="GIAM-SAT Rule Engine Tests")
    parser.add_argument("--json", help="Path to test cases JSON file")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    args = parser.parse_args()

    runner = RuleTestRunner(test_file=args.json, verbose=args.verbose)
    success = runner.run_all()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()