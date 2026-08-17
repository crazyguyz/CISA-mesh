"""
Sigma Rules Parser v1.0.0 for GIAM-SAT Server v3.1.0
Converts community Sigma rules (YAML) to GIAM-SAT correlation rules format.

Sigma is the generic signature format for SIEM systems:
  https://github.com/SigmaHQ/sigma

Supported Sigma fields:
  - EventID (single or list)
  - Channel / ProviderName
  - CommandLine, Image, ParentImage, TargetFilename
  - field|contains, field|startswith, field|endswith, field|re
  - condition: selection, filter, 1 of them, all of them, not

Output: GIAM-SAT correlation rule dict (ready for correlation_rules.yaml)

Usage:
  from sigma_parser import SigmaParser
  parser = SigmaParser()
  rules = parser.parse_file("sigma_rules/sysmon_malware.yml")
  # Or parse raw YAML string:
  rules = parser.parse_yaml(yaml_string)

  # Converted rules can then be added to correlation_rules.yaml
  # or stored via database/API.
"""

import os
import yaml
import re
import hashlib
from datetime import datetime

# Map Sigma logsource to GIAM-SAT subtypes
LOGSOURCE_MAP = {
    "sysmon": "Sysmon",
    "windows": "windows_event",
    "security": "windows_event",
    "system": "windows_event",
    "application": "windows_event",
    "sysmon_operational": "Sysmon",
}

# Map Sigma fields to GIAM-SAT filter patterns
FIELD_MAP = {
    "EventID": "event_id",
    "CommandLine": "command_line",
    "Image": "process_path",
    "ParentImage": "parent_path",
    "TargetFilename": "file_path",
    "DestinationIp": "dst_ip",
    "DestinationPort": "dst_port",
    "SourceIp": "src_ip",
    "QueryName": "dns_query",
    "TargetObject": "registry_key",
    "ImageLoaded": "dll_path",
    "Hashes": "hashes",
    "User": "user",
    "ProcessId": "pid",
    "ParentProcessId": "parent_pid",
}

# Map Sigma condition modifiers to GIAM-SAT condition types
CONDITION_MODIFIERS = {
    "contains": "description_contains",
    "startswith": "description_contains",
    "endswith": "description_contains",
    "re": "description_contains",
    "base64": "description_contains",
}


def _parse_selection(selection_dict):
    """
    Parse a Sigma selection block into GIAM-SAT condition filter dict.
    Returns dict like {"field": "description_contains", "values": [...], "threshold": 1}
    """
    # v3.6: Guard against list-format selections (Sigma multi-value format)
    if not isinstance(selection_dict, dict):
        return {"field": None, "modifier": "description_contains", "values": [], "threshold": 1, "within_seconds": 60}

    values = []
    giamsat_field = None
    modifier = "description_contains"

    for key, val in selection_dict.items():
        # Handle field|modifier syntax
        if "|" in key:
            field_name, mod = key.split("|", 1)
            modifier = CONDITION_MODIFIERS.get(mod, "description_contains")
        else:
            field_name = key

        giamsat_field = FIELD_MAP.get(field_name, field_name.lower())

        if isinstance(val, list):
            values.extend([str(v) for v in val])
        elif isinstance(val, (int, float)):
            values.append(str(val))
        else:
            # Could be a string with wildcards
            val_str = str(val).replace("*", "").replace("\\", "\\\\")
            values.append(val_str)

    return {
        "field": giamsat_field,
        "modifier": modifier,
        "values": values,
        "threshold": 1,
        "within_seconds": 60,
    }


def _parse_condition(condition_str, selections):
    """
    Parse Sigma condition string into GIAM-SAT conditions list.

    Supported:
      - "selection" → single condition
      - "selection1 and selection2" → multiple conditions (AND logic)
      - "1 of them" → OR logic
      - "all of them" → AND logic
      - "not X" → NOT logic
    """
    conditions = []

    if not condition_str:
        return conditions

    cond_lower = condition_str.lower().strip()

    # Simple case: single selection name
    if cond_lower in selections:
        sel = _parse_selection(selections[cond_lower])
        conditions.append({
            "type": "windows_event",
            "subtype": "Sysmon",
            "event_id": None,
            "field": sel["field"],
            "modifier": sel["modifier"],
            "values": sel["values"],
            "threshold": 1,
            "within_seconds": 60,
        })
        return conditions

    # AND logic: "selection1 and selection2 and ..."
    if " and " in cond_lower:
        parts = cond_lower.split(" and ")
        for part in parts:
            part = part.strip()
            if part in selections:
                sel = _parse_selection(selections[part])
                conditions.append({
                    "type": "windows_event",
                    "subtype": "Sysmon",
                    "event_id": None,
                    "field": sel["field"],
                    "modifier": sel["modifier"],
                    "values": sel["values"],
                    "threshold": 1,
                    "within_seconds": 60,
                })
        return conditions

    # OR logic: "1 of them", "any of them"
    if " of them" in cond_lower or " of selection" in cond_lower:
        for sel_name, sel_dict in selections.items():
            if sel_name.startswith("selection") and isinstance(sel_dict, dict):
                sel = _parse_selection(sel_dict)
                conditions.append({
                    "type": "windows_event",
                    "subtype": "Sysmon",
                    "event_id": None,
                    "field": sel["field"],
                    "modifier": sel["modifier"],
                    "values": sel["values"],
                    "threshold": 1,
                    "within_seconds": 60,
                })
        return conditions

    # NOT logic: "not X" or "selection and not filter"
    not_match = re.search(r'not\s+(\w+)', cond_lower)
    if not_match:
        not_name = not_match.group(1)
        # First add the positive conditions
        remaining = cond_lower.replace(f"not {not_name}", "").replace("and and", "and").strip()
        if remaining in selections:
            sel = _parse_selection(selections[remaining])
            conditions.append({
                "type": "windows_event",
                "subtype": "Sysmon",
                "event_id": None,
                "field": sel["field"],
                "modifier": sel["modifier"],
                "values": sel["values"],
                "threshold": 1,
                "within_seconds": 60,
            })
        # Add NOT filter
        if not_name in selections:
            not_sel = _parse_selection(selections[not_name])
            conditions.append({
                "type": "windows_event",
                "subtype": "Sysmon",
                "event_id": None,
                "field": not_sel["field"],
                "modifier": not_sel["modifier"],
                "values": not_sel["values"],
                "threshold": 0,
                "within_seconds": 60,
                "NOT": True,
            })
        return conditions

    return conditions


class SigmaParser:
    """
    Parse Sigma rules and convert to GIAM-SAT correlation rules format.
    """

    def __init__(self):
        self.stats = {
            "parsed": 0,
            "converted": 0,
            "skipped": 0,
            "errors": 0,
        }

    def parse_yaml(self, yaml_content: str):
        """
        Parse a Sigma rule YAML string into GIAM-SAT rule dicts.
        Returns list of rule dicts compatible with correlation_rules.yaml.
        """
        try:
            sigma = yaml.safe_load(yaml_content)
        except yaml.YAMLError as e:
            self.stats["errors"] += 1
            return [{"error": str(e)}]

        if not sigma or not isinstance(sigma, dict):
            self.stats["skipped"] += 1
            return []

        self.stats["parsed"] += 1
        rules = self._convert_sigma_to_giamsat(sigma)
        self.stats["converted"] += 1
        return rules

    def parse_file(self, filepath: str):
        """
        Parse a Sigma rule file and return GIAM-SAT rule dicts.
        """
        if not os.path.exists(filepath):
            return [{"error": f"File not found: {filepath}"}]

        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()

        return self.parse_yaml(content)

    def parse_directory(self, directory: str):
        """
        Recursively parse all .yml/.yaml files in a directory tree.
        Returns list of all converted GIAM-SAT rules.
        """
        all_rules = []
        for root, dirs, files in os.walk(directory):
            for filename in files:
                if filename.endswith((".yml", ".yaml")):
                    filepath = os.path.join(root, filename)
                    try:
                        rules = self.parse_file(filepath)
                        for rule in rules:
                            if "error" not in rule:
                                all_rules.append(rule)
                    except Exception as e:
                        self.stats["errors"] += 1
                        print(f"[-] SigmaParser: Error parsing {filepath}: {e}")
        return all_rules

    def _convert_sigma_to_giamsat(self, sigma: dict):
        """
        Convert a single Sigma rule (dict) to GIAM-SAT correlation rule format.
        """
        rules = []

        # Extract metadata
        sigma_title = sigma.get("title", "Untitled Sigma Rule")
        sigma_id = sigma.get("id", "")
        sigma_status = sigma.get("status", "experimental")
        sigma_level = sigma.get("level", "medium")
        sigma_author = sigma.get("author", "unknown")
        sigma_description = sigma.get("description", sigma_title)
        sigma_tags = sigma.get("tags", [])
        sigma_date = sigma.get("date", datetime.now().strftime("%Y-%m-%d"))
        sigma_falsepositives = sigma.get("falsepositives", [])

        # Map Sigma level to GIAM-SAT severity
        severity_map = {
            "critical": "CRITICAL",
            "high": "HIGH",
            "medium": "MEDIUM",
            "low": "LOW",
            "informational": "INFO",
        }
        severity = severity_map.get(sigma_level.lower(), "MEDIUM")

        # Parse logsource
        logsource = sigma.get("logsource", {})
        product = logsource.get("product", "windows")
        category = logsource.get("category", "")
        service = logsource.get("service", "")

        giamsat_subtype = LOGSOURCE_MAP.get(
            service or category or product, "windows_event"
        )

        # Generate GIAM-SAT rule ID
        rule_hash = hashlib.md5(
            (sigma_title + (sigma_id or sigma_date)).encode()
        ).hexdigest()[:8].upper()
        giamsat_id = f"SIGMA-{rule_hash}"

        # Parse detection
        detection = sigma.get("detection", {})
        condition_str = detection.get("condition", "")
        # v3.6: Filter out non-dict selections (Sigma rules can have list-format multi-value selections)
        selections = {k: v for k, v in detection.items() if k != "condition" and isinstance(v, dict)}

        # Parse conditions
        conditions = _parse_condition(condition_str, selections)

        # Populate event_id from selections if present
        for sel_dict in selections.values():
            if isinstance(sel_dict, dict):
                event_id = sel_dict.get("EventID")
                if event_id:
                    if isinstance(event_id, list):
                        event_id_val = str(event_id[0]) if event_id else None
                    else:
                        event_id_val = str(event_id)
                    for cond in conditions:
                        if not cond.get("event_id"):
                            cond["event_id"] = event_id_val

        # Map MITRE tactic from tags
        tactic = "Unknown"
        for tag in sigma_tags:
            if tag.startswith("attack.t"):
                tactic = tag
                break

        # Build GIAM-SAT rule
        giamsat_rule = {
            "id": giamsat_id,
            "name": sigma_title[:120],
            "mitre": "",
            "tactic": tactic.replace("attack.", "").upper(),
            "description": (
                f"[Sigma] {sigma_description[:300]} "
                f"(Author: {sigma_author[:50]}, "
                f"Status: {sigma_status}, "
                f"Source: {sigma_id or sigma_date})"
            ),
            "severity": severity,
            "conditions": [],
        }

        # Set MITRE ID from tags
        for tag in sigma_tags:
            if tag.startswith("attack.t"):
                giamsat_rule["mitre"] = tag.replace("attack.", "").upper()
                break

        # Build GIAM-SAT conditions
        for cond in conditions:
            field = cond.get("field", "description")
            values = cond.get("values", [])

            gi_cond = {
                "type": "windows_event",
                "subtype": giamsat_subtype,
                "threshold": cond.get("threshold", 1),
                "within_seconds": cond.get("within_seconds", 60),
            }

            if cond.get("event_id"):
                gi_cond["event_id"] = cond["event_id"]

            if cond.get("NOT"):
                gi_cond["NOT"] = True

            if values:
                # Map field to correct condition type
                actual_field = cond.get("modifier", "description_contains")
                if actual_field == "description_contains":
                    gi_cond["description_contains"] = values
                elif actual_field == "path_contains":
                    gi_cond["path_contains"] = values
                elif actual_field == "field_contains":
                    gi_cond["field_contains"] = {}
                    gi_cond["field_contains"][field] = values
                else:
                    gi_cond["description_contains"] = values

            giamsat_rule["conditions"].append(gi_cond)

        if giamsat_rule["conditions"]:
            rules.append(giamsat_rule)

        return rules

    def to_yaml(self, rules: list):
        """
        Convert GIAM-SAT rules list back to YAML format
        (compatible with correlation_rules.yaml).
        """
        output = {
            "metadata": {
                "name": "GIAM-SAT Sigma Imported Rules",
                "version": "1.0.0",
                "author": "Sigma Parser (auto-imported)",
                "description": "Rules converted from Sigma format",
                "last_updated": datetime.now().strftime("%Y-%m-%d"),
            },
            "rules": rules,
        }
        return yaml.dump(output, default_flow_style=False, allow_unicode=True, sort_keys=False)

    def get_stats(self):
        """Return parser statistics."""
        return dict(self.stats)