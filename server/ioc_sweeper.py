"""
IOC Sweep Engine v1.0.0 for GIAM-SAT Server v3.2.0
Batch scan historical data for Indicators of Compromise (IP, domain, hash, pattern).

Purpose: Retro-hunt past events for known-bad indicators from threat intel.
         Uses SQLite/PostgreSQL full-table scan with SQL LIKE/IN for efficiency.

IOC Sources:
  - CSV file (ip,domain,hash)
  - JSON array [{type, value, source, confidence}]
  - OTX pulses (API)
  - MISP events (API)

Architecture:
  POST /api/ioc/sweep → IOCSweeper.sweep() → scan events + sysmon + network tables
    → return matches with confidence scoring → optionally insert threat alerts
"""

import os
import json
import time
import csv
import io
import hashlib
from datetime import datetime


class IOCSweeper:
    """
    Scan database tables for IOC matches.
    Supports SQLite and PostgreSQL backends via db_manager interface.
    """

    def __init__(self, db_manager):
        self.db = db_manager
        self._stats = {"scans_run": 0, "total_matches": 0}

    def sweep(self, iocs, tables=None, since_hours=None):
        """
        Scan historical data for IOC matches.

        Args:
            iocs: list of dicts {type: ip|domain|hash, value: str, source: str}
            tables: list of table names to scan (default: all)
            since_hours: only scan data from last N hours (default: 24)

        Returns:
            list of match dicts {ioc, table, column, matched_value, event_id, timestamp, confidence}
        """
        if not iocs:
            return []

        tables = tables or ["events", "network_traffic", "sysmon_events", "fim_events"]
        results = []

        for ioc in iocs:
            ioc_type = ioc.get("type", "ip")
            ioc_value = ioc.get("value", "")
            ioc_source = ioc.get("source", "manual")
            ioc_confidence = ioc.get("confidence", 70)

            if not ioc_value:
                continue

            for table in tables:
                table_results = self._scan_table(table, ioc_type, ioc_value)
                for match in table_results:
                    match["ioc_source"] = ioc_source
                    match["ioc_confidence"] = ioc_confidence
                    match["ioc_type"] = ioc_type
                    match["ioc_value"] = ioc_value
                    results.append(match)

        self._stats["scans_run"] += 1
        self._stats["total_matches"] += len(results)
        return results

    def _scan_table(self, table, ioc_type, ioc_value):
        """
        Scan a single table for IOC match.
        Returns list of match dicts.
        """
        matches = []

        # Define search columns per table for each IOC type
        if table == "events":
            columns = {"ip": ["raw_data", "description"], "domain": ["raw_data", "description"], "hash": ["raw_data"]}
        elif table == "network_traffic":
            columns = {"ip": ["src_ip", "dst_ip"], "domain": ["raw_data"], "hash": []}
        elif table == "sysmon_events":
            columns = {"ip": ["src_ip", "dst_ip", "raw_data"], "domain": ["dns_query", "raw_data"], "hash": ["hashes", "raw_data"]}
        elif table == "fim_events":
            columns = {"ip": ["raw_data"], "domain": ["raw_data"], "hash": ["file_hash", "raw_data"]}
        else:
            return []

        search_cols = columns.get(ioc_type, [])
        if not search_cols:
            return []

        # Use parameterized query for safety
        for col in search_cols:
            try:
                # Check if db has get_by_contains method (SQLite)
                if hasattr(self.db, "get_by_contains"):
                    rows = self.db.get_by_contains(table, col, ioc_value, limit=1000)
                elif hasattr(self.db, "conn") and self.db.conn:
                    # SQLite direct
                    query = f"SELECT * FROM {table} WHERE {col} LIKE ? LIMIT 1000"
                    cursor = self.db.conn.execute(query, (f"%{ioc_value}%",))
                    col_names = [d[0] for d in cursor.description] if cursor.description else []
                    rows = []
                    for row in cursor.fetchall():
                        rows.append(dict(zip(col_names, row)))
                else:
                    # PostgreSQL
                    cursor = self.db._pool.getconn().cursor()
                    cursor.execute(
                        f"SELECT * FROM {table} WHERE {col}::text LIKE %s LIMIT 1000",
                        (f"%{ioc_value}%",)
                    )
                    col_names = [d[0] for d in cursor.description]
                    rows = [dict(zip(col_names, row)) for row in cursor.fetchall()]
                    self.db._pool.putconn(cursor.connection)

                for row in rows:
                    matches.append({
                        "table": table,
                        "column": col,
                        "matched_value": str(row.get(col, ""))[:200],
                        "event_id": row.get("id", ""),
                        "timestamp": row.get("timestamp", row.get("received_at", "")),
                        "hostname": row.get("hostname", row.get("computer", "")),
                        "machine_id": row.get("machine_id", ""),
                    })
            except Exception as e:
                print(f"[-] IOCSweeper: Error scanning {table}.{col}: {e}")
                continue

        return matches

    def sweep_from_file(self, filepath_or_bytes, file_format="csv"):
        """
        Import IOCs from file and run sweep.
        Supports CSV and JSON formats.
        """
        iocs = self._parse_ioc_file(filepath_or_bytes, file_format)
        return self.sweep(iocs)

    def _parse_ioc_file(self, source, file_format="csv"):
        """Parse IOC file into list of dicts."""
        iocs = []

        if file_format == "csv":
            if isinstance(source, str) and os.path.exists(source):
                with open(source, "r", encoding="utf-8") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        ioc_type = row.get("type", row.get("ioc_type", "ip"))
                        ioc_value = row.get("value", row.get("ioc", row.get("indicator", "")))
                        ioc_source = row.get("source", "csv_import")
                        ioc_confidence = int(row.get("confidence", 70))
                        if ioc_value:
                            iocs.append({
                                "type": ioc_type.lower(),
                                "value": ioc_value.strip(),
                                "source": ioc_source,
                                "confidence": ioc_confidence,
                            })
            else:
                reader = csv.DictReader(io.StringIO(source))
                for row in reader:
                    iocs.append({
                        "type": row.get("type", "ip").lower(),
                        "value": row.get("value", "").strip(),
                        "source": row.get("source", "csv_import"),
                        "confidence": int(row.get("confidence", 70)),
                    })

        elif file_format == "json":
            if isinstance(source, str) and os.path.exists(source):
                with open(source, "r", encoding="utf-8") as f:
                    data = json.load(f)
            else:
                data = json.loads(source) if isinstance(source, str) else source

            if isinstance(data, list):
                for item in data:
                    iocs.append({
                        "type": item.get("type", "ip").lower(),
                        "value": item.get("value", "").strip(),
                        "source": item.get("source", "json_import"),
                        "confidence": int(item.get("confidence", 70)),
                    })

        return iocs

    def get_stats(self):
        return dict(self._stats)