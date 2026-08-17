"""
Event Decoder Engine for GIAM-SAT Agent v1.8.0
YAML-based field extraction from raw event descriptions.
Parses Windows Security/Sysmon/Linux auth events into structured fields.

Supports:
- Regex-based field extraction from description text
- JSON-based extraction (Sysmon events)
- Field type normalization (string, integer, ip, list)
- Value mapping (e.g., logon_type 2 → "Interactive")
"""
import os
import re
import json
import yaml

DECODERS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules", "event_decoders.yaml")


def load_decoders():
    """Load event decoders from YAML file."""
    if not os.path.exists(DECODERS_PATH):
        return {"decoders": []}
    try:
        with open(DECODERS_PATH, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            return data or {"decoders": []}
    except Exception:
        return {"decoders": []}


class EventDecoder:
    """Decodes raw event descriptions into structured fields."""

    def __init__(self):
        self.decoder_config = load_decoders()
        self.decoders = self.decoder_config.get("decoders", [])

    def decode_event(self, event_data):
        """Parse an event and extract fields.
        
        Args:
            event_data: dict with 'event_id', 'subtype', 'description', 'type' fields
            
        Returns:
            dict with original event + parsed_fields
        """
        event_id = str(event_data.get("event_id", ""))
        subtype = event_data.get("subtype", "")
        event_type = event_data.get("type", "")
        description = event_data.get("description", "")
        raw_data = event_data.get("raw_data", "")

        # Find matching decoder(s)
        parsed = {}
        matched_decoders = []

        for decoder in self.decoders:
            # Match by event_id
            dec_ids = decoder.get("event_id")
            if dec_ids:
                if isinstance(dec_ids, list):
                    if event_id not in dec_ids:
                        continue
                else:
                    if event_id != str(dec_ids):
                        continue

            # Match by subtype (for Sysmon events)
            dec_subtype = decoder.get("subtype")
            if dec_subtype and dec_subtype != subtype:
                continue

            # Match by event_type (for Linux events)
            dec_evt_type = decoder.get("event_type")
            if dec_evt_type and dec_evt_type != event_type:
                continue

            matched_decoders.append(decoder)

        if not matched_decoders:
            # No matching decoder
            return parsed

        # Apply each matching decoder
        for decoder in matched_decoders:
            fields = decoder.get("fields", [])
            use_json = decoder.get("json_extract", False)

            # Try JSON extraction first (Sysmon events)
            json_obj = None
            if use_json and raw_data:
                try:
                    json_obj = json.loads(raw_data) if isinstance(raw_data, str) else raw_data
                except Exception:
                    pass

            for field_def in fields:
                value = None
                field_name = field_def.get("name", "")

                if use_json and json_obj:
                    # Extract from JSON path
                    json_path = field_def.get("json_path", "")
                    value = self._extract_json_path(json_obj, json_path)
                elif description:
                    # Extract via regex
                    regex = field_def.get("regex", "")
                    group_idx = field_def.get("index", 1)
                    value = self._extract_regex(description, regex, group_idx)

                if value is not None and value != "":
                    # Apply type conversion
                    ftype = field_def.get("type", "string")
                    value = self._convert_type(value, ftype)

                    # Apply value mapping
                    mapping = field_def.get("mapping", {})
                    if mapping and str(value) in mapping:
                        value = mapping[str(value)]

                    if value is not None:
                        parsed[field_name] = value

        return parsed

    def _extract_regex(self, text, pattern, group_idx):
        """Extract value from text using regex pattern."""
        if not text or not pattern:
            return None
        try:
            match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
            if match:
                groups = match.groups()
                if group_idx > 0 and group_idx <= len(groups):
                    return groups[group_idx - 1].strip()
                elif group_idx == 0:
                    return match.group(0).strip()
                elif groups:
                    return groups[0].strip()
        except Exception:
            pass
        return None

    def _extract_json_path(self, obj, path):
        """Extract value from nested JSON using dot notation path.
        E.g., "Event.EventData.Image" → obj["Event"]["EventData"]["Image"]
        """
        if not obj or not path:
            return None
        try:
            parts = path.split(".")
            current = obj
            for part in parts:
                if isinstance(current, dict):
                    current = current.get(part)
                else:
                    return None
                if current is None:
                    return None
            return current
        except Exception:
            return None

    def _convert_type(self, value, ftype):
        """Convert extracted string to target type."""
        if value is None:
            return None
        try:
            if ftype == "integer":
                return int(value)
            elif ftype == "float":
                return float(value)
            elif ftype == "ip":
                # Clean IP: remove ::ffff: prefix if present
                cleaned = str(value).strip()
                if cleaned.startswith("::ffff:"):
                    cleaned = cleaned[7:]
                # Validate basic IP format
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', cleaned):
                    return cleaned
                return str(value).strip()
            elif ftype == "list":
                # Split by newlines or commas
                items = [i.strip() for i in re.split(r'[\n,]+', str(value)) if i.strip()]
                return items if items else [str(value).strip()]
            elif ftype == "boolean":
                return str(value).lower() in ("true", "1", "yes")
            else:
                return str(value).strip()
        except Exception:
            return str(value) if value else None

    def decode_and_annotate(self, event_data):
        """Decode event and return annotated event with parsed fields included."""
        parsed = self.decode_event(event_data)

        # Annotate the event with parsed fields
        result = dict(event_data)
        if parsed:
            result["parsed_fields"] = parsed
            # Also promote key fields to top level for easier searching
            for key in ["username", "source_ip", "process_name", "command_line"]:
                if key in parsed and key not in result:
                    result[key] = parsed[key]

        return result

    def get_event_title(self, event_data):
        """Generate a human-readable title from decoded fields."""
        parsed = self.decode_event(event_data)
        event_id = str(event_data.get("event_id", ""))

        titles = {
            "4624": lambda p: f"Logon: {p.get('username','?')} from {p.get('source_ip','?')} (Type {p.get('logon_type','?')})",
            "4625": lambda p: f"Failed logon: {p.get('username','?')} from {p.get('source_ip','?')} ({p.get('failure_reason','?')})",
            "4688": lambda p: f"Process: {p.get('process_name','?')} by {p.get('username','?')}",
            "4672": lambda p: f"Privileged logon: {p.get('username','?')} ({p.get('privileges','?')})",
            "4769": lambda p: f"Kerberos TGS: {p.get('username','?')} → {p.get('service_name','?')}",
            "4728": lambda p: f"Group add: {p.get('username','?')} → {p.get('group_name','?')}",
            "4732": lambda p: f"Group add: {p.get('username','?')} → {p.get('group_name','?')}",
            "4756": lambda p: f"Group add: {p.get('username','?')} → {p.get('group_name','?')}",
            "4719": lambda p: f"Audit policy changed by {p.get('username','?')}",
            "1102": lambda p: f"Event log cleared by {p.get('username','?')}",
            "7045": lambda p: f"Service installed: {p.get('service_name','?')} by {p.get('service_account','?')}",
            "5001": lambda p: f"Defender disabled: {p.get('feature','?')}",
            "4104": lambda p: f"PowerShell script block: {p.get('path','?')}",
        }
        if event_id == "1" and event_data.get("subtype") == "Sysmon":
            return f"Sysmon Process: {parsed.get('process_name','?')} by {parsed.get('username','?')}"
        if event_id == "3":
            return f"Sysmon Network: {parsed.get('process_name','?')} → {parsed.get('dest_ip','?')}:{parsed.get('dest_port','?')}"
        if event_id == "7":
            return f"Sysmon DLL Load: {parsed.get('image_loaded','?')}"
        if event_id == "8":
            return f"Sysmon Injection: {parsed.get('source_process','?')} → {parsed.get('target_process','?')}"

        handler = titles.get(event_id)
        if handler:
            try:
                return handler(parsed)
            except Exception:
                pass

        return None