#!/usr/bin/env python
"""
GIAM-SAT Sigma Re-import Tool v4.11 (P2 / CRITICAL-2)
Regenerates ALL SIGMA-* rules in correlation_rules.yaml with the current
(improved) sigma_parser - so the ~2000 previously-flattened rules become
field-level (field_contains on CommandLine/Image/...) instead of weak
description_contains. Hand-written THREAT-* rules are kept untouched.

Usage:
    python tools/reimport_sigma.py --sigma-dir D:\\CISA-mesh-main\\.sigma_repo --dry-run
    python tools/reimport_sigma.py --sigma-dir .sigma_repo
    python tools/reimport_sigma.py --sigma-dir .sigma_repo --agent-copy  # also rewrite agent/rules/correlation_rules.yaml
"""
import argparse
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_RULES = os.path.join(BASE, "server", "rules", "correlation_rules.yaml")
DEFAULT_SIGMA = os.path.join(BASE, ".sigma_repo")


def main():
    ap = argparse.ArgumentParser(description="Regenerate SIGMA-* rules with the improved parser")
    ap.add_argument("--sigma-dir", default=DEFAULT_SIGMA)
    ap.add_argument("--rules", default=DEFAULT_RULES)
    ap.add_argument("--agent-copy", action="store_true",
                    help="also write agent/rules/correlation_rules.yaml (agents evaluate the rules)")
    ap.add_argument("--dry-run", action="store_true", help="report stats without writing")
    args = ap.parse_args()

    try:
        import yaml
    except ImportError:
        print("PyYAML required: pip install pyyaml")
        sys.exit(1)
    sys.path.insert(0, os.path.join(BASE, "server"))
    from sigma_parser import SigmaParser

    sigma_windows = os.path.join(args.sigma_dir, "rules", "windows")
    if not os.path.isdir(sigma_windows):
        print(f"Sigma windows rules not found: {sigma_windows}")
        sys.exit(1)
    if not os.path.exists(args.rules):
        print(f"Rules file not found: {args.rules}")
        sys.exit(1)

    with open(args.rules, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    old_rules = data.get("rules", [])
    manual = [r for r in old_rules if isinstance(r, dict) and r.get("id", "").startswith("THREAT-")]
    old_sigma = [r for r in old_rules if isinstance(r, dict) and r.get("id", "").startswith("SIGMA-")]
    print(f"Existing: {len(old_rules)} rules (THREAT manual: {len(manual)}, SIGMA auto: {len(old_sigma)})")

    parser = SigmaParser()
    print(f"Parsing {sigma_windows} ...")
    new_sigma = []
    errs = 0
    for root, _dirs, files in os.walk(sigma_windows):
        for fn in files:
            if not fn.endswith((".yml", ".yaml")):
                continue
            path = os.path.join(root, fn)
            try:
                rules = parser.parse_file(path)
            except Exception:
                errs += 1
                continue
            for r in rules or []:
                if isinstance(r, dict) and r.get("id", "").startswith("SIGMA-"):
                    new_sigma.append(r)
    print(f"Parsed {len(new_sigma)} SIGMA rules ({errs} files errored), parser stats: {parser.stats}")

    # stats on condition fidelity
    with_field = sum(1 for r in new_sigma
                     if any(c.get("field_contains") or c.get("field_equals") or c.get("field_regex")
                            for c in r.get("conditions", [])))
    print(f"New rules using field-level conditions: {with_field}/{len(new_sigma)}")

    # dedup by id (last wins)
    seen = {}
    for r in new_sigma:
        seen[r["id"]] = r
    new_sigma = list(seen.values())

    result = data.copy()
    result["rules"] = manual + new_sigma
    print(f"Final: {len(result['rules'])} rules (THREAT {len(manual)} + SIGMA {len(new_sigma)})")

    if args.dry_run:
        print("DRY RUN - nothing written")
        return

    with open(args.rules, "w", encoding="utf-8") as f:
        yaml.safe_dump(result, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
    print(f"Wrote {args.rules}")

    if args.agent_copy:
        agent_path = os.path.join(BASE, "agent", "rules", "correlation_rules.yaml")
        with open(agent_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(result, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
        print(f"Wrote {agent_path}")


if __name__ == "__main__":
    main()
