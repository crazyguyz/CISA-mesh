"""
Threat Hunting Engine v1.0.0 for GIAM-SAT Server v3.2.0
Hypothesis-driven threat hunting interface.

Purpose: Enable SOC analysts to create hunting campaigns by entering
         hypotheses → auto-generate queries → scan data → track results.

Workflow:
  1. Analyst enters hypothesis (e.g., "Is there LSASS access from Temp?")
  2. Engine maps to SQL/ES query templates
  3. Runs query against DB
  4. Returns results with confidence scoring
  5. Saves campaign for audit trail

API:
  POST /api/hunt/start   → start campaign
  GET  /api/hunt/result/<campaign_id>  → get results
  GET  /api/hunt/campaigns  → list all campaigns
"""

import os
import time
import json
import re
import uuid
import threading
from datetime import datetime

# Import AI provider for hypothesis parsing
try:
    from ai_providers import call_ai_assistant
    HAS_AI = True
except ImportError:
    HAS_AI = False


# v4.10 (HIGH-4): allowlist for hunting queries - AI-generated field/table names
# must be validated before being interpolated into SQL.
ALLOWED_HUNT_TABLES = {
    "events", "sysmon_events", "fim_events", "network_traffic",
    "threat_alerts", "syslog", "sca_events", "vuln_alerts", "yara_alerts",
    "network_inspection",  # v5.0.4: DPI (tls_sni SNI / ja3 fingerprint)
}
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


# Hypothesis templates mapped to SQL-like filter conditions
HYPOTHESIS_TEMPLATES = {
    "credential_access": {
        "label": "Credential Theft",
        "query_hint": "Process access to LSASS, SAM dump, DPAPI",
        "tables": ["sysmon_events", "events"],
        "conditions": [
            {"field": "description", "contains": ["lsass", "sam", "mimikatz", "procdump"]},
            {"field": "credential_dumping", "equals": 1},
            {"field": "event_id", "equals": "4663"},
        ],
    },
    "lateral_movement": {
        "label": "Lateral Movement",
        "query_hint": "SMB/WMI/WinRM connections to new targets",
        "tables": ["network_traffic", "events"],
        "conditions": [
            {"field": "dst_port", "equals": [445, 135, 3389, 5985, 5986]},
            {"field": "description", "contains": ["logon type: 3", "logon type: 10", "wmic", "winrm"]},
        ],
    },
    "persistence": {
        "label": "Persistence Mechanisms",
        "query_hint": "Registry Run keys, Scheduled Tasks, Services",
        "tables": ["sysmon_events", "events"],
        "conditions": [
            {"field": "persistence_detected", "equals": 1},
            {"field": "description", "contains": ["run", "runonce", "scheduled task", "service"]},
            {"field": "registry_key", "contains": ["run", "runonce", "winlogon"]},
        ],
    },
    "c2_communication": {
        "label": "C2 Communication",
        "query_hint": "Outbound to suspicious IPs, beaconing patterns",
        "tables": ["network_traffic", "events"],
        "conditions": [
            {"field": "dst_port", "equals": [4444, 1337, 31337, 8080, 8000, 6666, 9999]},
            {"field": "description", "contains": ["beacon", "heartbeat", "c2", "command and control"]},
        ],
    },
    "exfiltration": {
        "label": "Data Exfiltration",
        "query_hint": "Large outbound transfers, cloud uploads, USB",
        "tables": ["network_traffic", "fim_events", "events"],
        "conditions": [
            {"field": "description", "contains": ["upload", "exfiltrat", "transfer", "pastebin", "ngrok"]},
            {"field": "dst_port", "equals": [21, 22, 443, 8443]},
        ],
    },
    "defense_evasion": {
        "label": "Defense Evasion",
        "query_hint": "Defender disabled, logs cleared, timestomping",
        "tables": ["sysmon_events", "events"],
        "conditions": [
            {"field": "event_id", "equals": ["5001", "1102", "4719"]},
            {"field": "description", "contains": ["disabled", "cleared", "timestomp", "motw"]},
        ],
    },
}


class HuntingEngine:
    """
    Hypothesis-driven threat hunting campaign manager.
    """

    def __init__(self, db_manager):
        self.db = db_manager
        self._campaigns = {}  # campaign_id → {hypothesis, query, results, status, created_at}
        self._lock = threading.Lock()

    def start_campaign(self, hypothesis, tactic=None, custom_conditions=None,
                       tables=None, since_hours=168, use_ai=True):
        """
        Start a new hunting campaign.

        Args:
            hypothesis: Natural language hypothesis (e.g., "Check for LSASS dump")
            tactic: Optional MITRE tactic (maps to template)
            custom_conditions: List of {field, operator, value} dicts
            tables: Optional list of table names
            since_hours: Look back N hours (default: 7 days)
            use_ai: Whether to use AI to parse hypothesis (default True)

        Returns:
            campaign dict with id, status, parsed_query, query info
        """
        campaign_id = str(uuid.uuid4())[:12]
        ai_parsed = None  # Store AI parsing result for transparency

        # Build query from template or custom conditions
        if custom_conditions:
            conditions = custom_conditions
            tables = tables or ["events", "sysmon_events"]
        elif tactic and tactic in HYPOTHESIS_TEMPLATES:
            template = HYPOTHESIS_TEMPLATES[tactic]
            conditions = template["conditions"]
            tables = tables or template["tables"]
        else:
            # Free-text hypothesis: try AI first, fallback to keyword parsing
            if use_ai and HAS_AI:
                ai_result = self._ai_parse_hypothesis(hypothesis)
                if ai_result and ai_result.get("conditions"):
                    conditions = ai_result["conditions"]
                    tables = ai_result.get("tables", ["events", "sysmon_events"])
                    # AI may also suggest since_hours override
                    if ai_result.get("since_hours"):
                        since_hours = ai_result["since_hours"]
                    ai_parsed = ai_result.get("summary", "")
                else:
                    # AI failed or returned empty, fallback to keyword
                    conditions = self._parse_hypothesis(hypothesis)
                    tables = tables or ["events", "sysmon_events"]
            else:
                conditions = self._parse_hypothesis(hypothesis)
                tables = tables or ["events", "sysmon_events"]

        campaign = {
            "id": campaign_id,
            "hypothesis": hypothesis,
            "tactic": tactic or "custom",
            "tables": tables,
            "conditions": conditions,
            "since_hours": since_hours,
            "ai_parsed": ai_parsed,
            "status": "running",
            "results": [],
            "match_count": 0,
            "created_at": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "created_ts": time.time(),  # v5.0.4 (MEDIUM-7): for TTL cleanup
            "completed_at": None,
        }

        with self._lock:
            # v5.0.4 (MEDIUM-7): expire old campaigns so the in-memory dict
            # cannot grow forever on a long-running server.
            _ttl = time.time() - 86400  # 24h
            for _cid in [k for k, c in self._campaigns.items()
                         if c.get("created_ts", 0) < _ttl]:
                del self._campaigns[_cid]
            self._campaigns[campaign_id] = campaign

        # Run query in background
        t = threading.Thread(
            target=self._execute_campaign,
            args=(campaign_id,),
            daemon=True,
        )
        t.start()

        return {
            "campaign_id": campaign_id,
            "status": "running",
            "hypothesis": hypothesis,
            "parsed_query": ai_parsed or self._describe_conditions(conditions),
            "tables_used": tables,
            "since_hours": since_hours,
        }

    def _describe_conditions(self, conditions):
        """Generate human-readable description of parsed conditions."""
        parts = []
        for c in conditions:
            if "contains" in c:
                vals = c["contains"] if isinstance(c["contains"], list) else [c["contains"]]
                parts.append(f"{c['field']} chứa [{', '.join(vals)}]")
            elif "equals" in c:
                vals = c["equals"] if isinstance(c["equals"], list) else [c["equals"]]
                parts.append(f"{c['field']} = [{', '.join(str(v) for v in vals)}]")
        return "; ".join(parts) if parts else "Tìm kiếm toàn văn bản"

    def _ai_parse_hypothesis(self, hypothesis):
        """
        Use AI (DeepSeek) to parse natural language hypothesis into structured query.
        AI is called ONCE per campaign - only at start time.
        Falls back gracefully if AI is unavailable.

        Returns: dict with {tables, conditions, since_hours, summary} or None
        """
        if not HAS_AI:
            return None

        prompt = (
            "Bạn là trợ lý phân tích bảo mật. Nhiệm vụ: chuyển câu hỏi săn mối nguy "
            "thành JSON truy vấn cơ sở dữ liệu.\n\n"
            "Các bảng dữ liệu có sẵn:\n"
            "- events: Windows Event Log (cột: event_id, description, machine_id, timestamp, process_name, process_path)\n"
            "- sysmon_events: Sysmon events (cột: event_id, description, machine_id, timestamp, process_name, process_path, parent_process, registry_key, dst_ip, dst_port)\n"
            "- network_traffic: Lưu lượng mạng (cột: src_ip, dst_ip, dst_port, protocol_app, machine_id, timestamp)\n"
            "- network_inspection: DPI (cột: subtype, domain, dst_ip, dst_port, ja3, machine_id, timestamp - subtype='tls_sni' là SNI của kết nối HTTPS, ja3 là TLS fingerprint)\n"
            "- fim_events: File integrity monitoring (cột: file_path, change_type, machine_id, timestamp)\n"
            "- threat_alerts: Cảnh báo (cột: rule_name, severity, description, machine_id, timestamp, source_ip, mitre)\n\n"
            "Trả về CHỈ JSON (không markdown, không giải thích):\n"
            "{\n"
            '  "tables": ["events", "sysmon_events"],\n'
            '  "conditions": [\n'
            '    {"field": "description", "contains": ["lsass", "mimikatz"]},\n'
            '    {"field": "event_id", "equals": [8, 10]}\n'
            '  ],\n'
            '  "since_hours": 24,\n'
            '  "summary": "Tìm kiếm truy cập LSASS (Sysmon EID 8,10) và mô tả chứa lsass/mimikatz trong 24h"\n'
            "}\n\n"
            f"Câu hỏi: {hypothesis}"
        )

        try:
            response = call_ai_assistant(
                question=prompt,
                provider="deepseek",
                api_key="",  # Will use DEEPSEEK_API_KEY from .env
                model="deepseek-chat"
            )
            # Extract JSON from response (handle markdown code blocks)
            json_match = re.search(r'\{[\s\S]*\}', response)
            if json_match:
                return json.loads(json_match.group(0))
            return None
        except Exception as e:
            print(f"[-] HuntingEngine AI parse error: {e}")
            return None

    def _parse_hypothesis(self, hypothesis):
        """Parse free-text hypothesis into search conditions.
        v3.6: Expanded to 50+ keywords with fuzzy token matching."""
        conditions = []
        hyp_lower = hypothesis.lower()
        # Tokenize into individual words for better matching
        hyp_tokens = set(re.split(r'[\s,;.()\[\]{}]+', hyp_lower))

        keywords_map = {
            # Credential Access
            "lsass": {"field": "description", "contains": ["lsass"]},
            "mimikatz": {"field": "description", "contains": ["mimikatz"]},
            "procdump": {"field": "description", "contains": ["procdump"]},
            "sam": {"field": "description", "contains": ["sam"]},
            "ntds": {"field": "description", "contains": ["ntds", "ntds.dit"]},
            "dump": {"field": "description", "contains": ["dump", "lsass", "sam"]},
            "credential": {"field": "description", "contains": ["credential", "password", "hash"]},
            "brute force": {"field": "description", "contains": ["4625", "failed logon", "brute"]},
            "4625": {"field": "event_id", "equals": ["4625"]},
            "pth": {"field": "description", "contains": ["pth", "pass the hash"]},
            # Execution
            "powershell": {"field": "process_name", "contains": ["powershell"]},
            "cmd": {"field": "process_name", "contains": ["cmd"]},
            "wmic": {"field": "description", "contains": ["wmic"]},
            "wscript": {"field": "process_name", "contains": ["wscript"]},
            "cscript": {"field": "process_name", "contains": ["cscript"]},
            "rundll32": {"field": "process_name", "contains": ["rundll32"]},
            "mshta": {"field": "process_name", "contains": ["mshta"]},
            "download": {"field": "description", "contains": ["download", "webclient", "invoke-webrequest", "certutil"]},
            "encoded": {"field": "description", "contains": ["-enc ", "-encoded"]},
            "base64": {"field": "description", "contains": ["-enc ", "-encoded", "base64"]},
            # Persistence
            "registry": {"field": "registry_key", "contains": ["run", "runonce"]},
            "service": {"field": "description", "contains": ["service", "sc create", "sc config"]},
            "schtask": {"field": "description", "contains": ["schtask", "scheduled task"]},
            "startup": {"field": "description", "contains": ["startup", "start up"]},
            "wmi": {"field": "description", "contains": ["wmi", "__eventfilter", "__eventconsumer"]},
            # Defense Evasion
            "disable": {"field": "description", "contains": ["disable", "defender", "firewall"]},
            "clear": {"field": "description", "contains": ["clear", "cleared", "event log"]},
            "timestomp": {"field": "description", "contains": ["timestomp"]},
            "motw": {"field": "description", "contains": ["motw", "zone.identifier"]},
            "unhook": {"field": "description", "contains": ["unhook", "amsi", "etw"]},
            # Lateral Movement
            "smb": {"field": "dst_port", "equals": [445]},
            "rdp": {"field": "dst_port", "equals": [3389]},
            "winrm": {"field": "description", "contains": ["winrm", "5985", "5986"]},
            "psexec": {"field": "description", "contains": ["psexec"]},
            # C2
            "c2": {"field": "description", "contains": ["c2", "beacon", "heartbeat", "command and control"]},
            "beacon": {"field": "description", "contains": ["beacon"]},
            "dns": {"field": "description", "contains": ["dns", "tunnel"]},
            "tor": {"field": "description", "contains": ["tor", "onion"]},
            # Exfiltration
            "exfiltrat": {"field": "description", "contains": ["upload", "exfiltrat", "transfer", "pastebin", "ngrok"]},
            # Path-based
            "temp": {"field": "process_path", "contains": ["temp", "appdata"]},
            "desktop": {"field": "process_path", "contains": ["desktop"]},
            "downloads": {"field": "process_path", "contains": ["downloads"]},
            # Process Injection
            "injection": {"field": "description", "contains": ["injection", "createremotethread", "virtualallocex"]},
            # Sysmon specific
            "sysmon 1": {"field": "sysmon_event_id", "equals": [1]},
            "sysmon 3": {"field": "sysmon_event_id", "equals": [3]},
            "sysmon 7": {"field": "sysmon_event_id", "equals": [7]},
            "sysmon 8": {"field": "sysmon_event_id", "equals": [8]},
            "sysmon 10": {"field": "sysmon_event_id", "equals": [10]},
            "sysmon 22": {"field": "sysmon_event_id", "equals": [22]},
        }

        # Match by full keyword first, then by individual tokens
        matched_keys = set()
        for keyword, condition in keywords_map.items():
            if " " in keyword:
                # Multi-word keywords: match as phrase
                if keyword in hyp_lower:
                    if keyword not in matched_keys:
                        conditions.append(condition)
                        matched_keys.add(keyword)
            else:
                # Single-word keywords: match in tokens
                if keyword in hyp_tokens:
                    if keyword not in matched_keys:
                        conditions.append(condition)
                        matched_keys.add(keyword)

        if not conditions:
            # Fallback: search description for each significant word in hypothesis
            significant_words = [w for w in hyp_tokens if len(w) > 2 and w not in ('the', 'and', 'for', 'any', 'has', 'was', 'can', 'does')]
            if significant_words:
                conditions.append({"field": "description", "contains": significant_words[:5]})
            else:
                conditions.append({"field": "description", "contains": [hypothesis[:100]]})

        return conditions

    def _execute_campaign(self, campaign_id):
        """Run the query against database tables."""
        with self._lock:
            campaign = self._campaigns.get(campaign_id)
            if not campaign:
                return

        results = []
        tables = campaign["tables"]
        conditions = campaign["conditions"]

        for table in tables:
            try:
                table_results = self._scan_table(table, conditions)
                for r in table_results:
                    r["campaign_id"] = campaign_id
                    r["table"] = table
                results.extend(table_results)
            except Exception as e:
                print(f"[-] HuntingEngine: Error scanning {table}: {e}")

        with self._lock:
            campaign = self._campaigns.get(campaign_id)
            if campaign:
                campaign["results"] = results[:1000]  # Limit output
                campaign["match_count"] = len(results)
                campaign["status"] = "completed"
                campaign["completed_at"] = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")

    def _scan_table(self, table, conditions, use_or_logic=False):
        """
        Scan a DB table with multiple conditions.
        v3.6: Added use_or_logic parameter for free-text hunting (OR gives more results).
        v4.10 (HIGH-4): allowlist table + validate every field identifier before
        building SQL (AI-generated field/table names must not reach the query).
        Returns list of matching rows.
        """
        if not hasattr(self.db, "conn") or not self.db.conn:
            return []
        if table not in ALLOWED_HUNT_TABLES:
            print(f"[HUNT] Blocked scan on non-allowlisted table: {table}")
            return []
        for cond in conditions or []:
            field = cond.get("field", "description")
            if not _SAFE_IDENTIFIER.match(str(field)):
                print(f"[HUNT] Blocked non-allowlisted field: {field}")
                return []

        # Build SQL WHERE clause from conditions
        where_clauses = []
        params = []

        for cond in conditions:
            field = cond.get("field", "description")
            if "contains" in cond:
                values = cond["contains"]
                if isinstance(values, str):
                    values = [values]
                sub_clauses = []
                for v in values:
                    # v5.0.3 (LOW-3): escape LIKE wildcards so user values containing
                    # % or _ match literally instead of matching nearly every row.
                    # v5.0.4 FIX (CRIT): ESCAPE must be exactly ONE character - the
                    # previous '\\\\' produced 2 chars in SQL and every "contains"
                    # query died with "ESCAPE expression must be a single character"
                    # (silently swallowed by the except below -> hunting returned []).
                    ev = str(v).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
                    sub_clauses.append(f"{field} LIKE ? ESCAPE '\\'")
                    params.append(f"%{ev}%")
                where_clauses.append("(" + " OR ".join(sub_clauses) + ")")
            elif "equals" in cond:
                values = cond["equals"]
                if isinstance(values, list):
                    placeholders = ",".join(["?"] * len(values))
                    where_clauses.append(f"{field} IN ({placeholders})")
                    params.extend(values)
                else:
                    where_clauses.append(f"{field} = ?")
                    params.append(values)

        if not where_clauses:
            return []

        # v3.6: Use OR between conditions for free-text hunting (more results)
        join_op = " OR " if use_or_logic else " AND "
        try:
            query = f"SELECT * FROM {table} WHERE {join_op.join(where_clauses)} LIMIT 500"
            cursor = self.db.conn.execute(query, params)
            col_names = [d[0] for d in cursor.description] if cursor.description else []

            results = []
            for row in cursor.fetchall():
                row_dict = dict(zip(col_names, row))
                # Clean up large fields for response
                if "raw_data" in row_dict:
                    row_dict["raw_data"] = str(row_dict["raw_data"])[:200]
                results.append(row_dict)
            return results
        except Exception as e:
            print(f"[-] HuntingEngine: Query error on {table}: {e}")
            return []

    def get_campaign(self, campaign_id):
        """Get campaign details and results."""
        with self._lock:
            campaign = self._campaigns.get(campaign_id)
            if not campaign:
                return None
            return {
                "id": campaign["id"],
                "hypothesis": campaign["hypothesis"],
                "tactic": campaign["tactic"],
                "status": campaign["status"],
                "match_count": campaign["match_count"],
                "results": campaign.get("results", [])[:100],
                "created_at": campaign["created_at"],
                "completed_at": campaign.get("completed_at"),
            }

    def list_campaigns(self):
        """List all campaigns (summary)."""
        with self._lock:
            return [
                {
                    "id": c["id"],
                    "hypothesis": c["hypothesis"],
                    "tactic": c["tactic"],
                    "status": c["status"],
                    "match_count": c["match_count"],
                    "created_at": c["created_at"],
                }
                for c in self._campaigns.values()
            ][-50:]  # Last 50 campaigns

    def get_templates(self):
        """Return available hypothesis templates."""
        return {
            key: {"label": t["label"], "hint": t["query_hint"]}
            for key, t in HYPOTHESIS_TEMPLATES.items()
        }

    def get_stats(self):
        with self._lock:
            total = len(self._campaigns)
            completed = sum(1 for c in self._campaigns.values() if c["status"] == "completed")
            running = sum(1 for c in self._campaigns.values() if c["status"] == "running")
            total_matches = sum(c.get("match_count", 0) for c in self._campaigns.values())
            return {
                "total_campaigns": total,
                "completed": completed,
                "running": running,
                "total_matches": total_matches,
            }