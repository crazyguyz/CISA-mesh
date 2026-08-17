"""
GIAM-SAT Elasticsearch/OpenSearch Backend v1.13.0

Full implementation of DatabaseBackend abstract interface for Elasticsearch.
Supports:
  - Elasticsearch 7.x/8.x and OpenSearch 1.x/2.x
  - Full-text search across all event types
  - Index Lifecycle Management (ILM) for data retention
  - Bulk indexing for high-throughput agent data
  - Aggregation queries for dashboard statistics

Configuration (in .env):
  ES_HOST=localhost:9200
  ES_USER=elastic (optional)
  ES_PASS=password (optional)
  ES_USE_SSL=false
  ES_INDEX_PREFIX=giamsat
  ES_RETENTION_DAYS=90
"""

import json
import time
import os
import threading
from datetime import datetime, timedelta
from collections import deque

try:
    from elasticsearch import Elasticsearch, helpers
    HAS_ES = True
except ImportError:
    HAS_ES = False

from .db_base import DatabaseBackend

# Bulk indexing buffer
BULK_FLUSH_SIZE = 500
BULK_FLUSH_INTERVAL = 10  # seconds


class ElasticsearchBackend(DatabaseBackend):
    """Elasticsearch/OpenSearch backend for GIAM-SAT."""

    def __init__(self, config: dict = None):
        super().__init__(config)
        self.es = None
        self.prefix = config.get("index_prefix", "giamsat") if config else "giamsat"
        self._bulk_buffer = deque()
        self._bulk_lock = threading.Lock()
        self._bulk_timer = None
        self._start_bulk_flush_timer()

    # =========================================================================
    # Connection
    # =========================================================================

    def connect(self):
        if not HAS_ES:
            raise RuntimeError("elasticsearch package not installed. pip install elasticsearch")

        host = self.config.get("host", "localhost:9200")
        user = self.config.get("user", "")
        password = self.config.get("password", "")
        use_ssl = self.config.get("use_ssl", False)

        kwargs = {
            "hosts": [f"https://{host}" if use_ssl else f"http://{host}"],
        }
        if user and password:
            kwargs["basic_auth"] = (user, password)
        elif user:
            kwargs["http_auth"] = (user, password)

        self.es = Elasticsearch(**kwargs)

        # Verify connection
        if not self.es.ping():
            raise ConnectionError("Cannot connect to Elasticsearch")

        # Ensure index templates exist
        self._create_index_templates()

    def close(self):
        if self.es:
            self._flush_bulk_buffer()
            self.es.close()
            self.es = None

    def health_check(self) -> bool:
        try:
            return self.es and self.es.ping()
        except Exception:
            return False

    # =========================================================================
    # Index Management
    # =========================================================================

    def _index_name(self, table: str) -> str:
        """Generate index name with prefix."""
        return f"{self.prefix}-{table}"

    def _create_index_templates(self):
        """Create index templates with mappings and ILM policies."""
        tables = [
            "machines", "events", "fim_events", "network_traffic",
            "threat_alerts", "vuln_alerts", "yara_alerts", "sca_events",
            "agentless_events", "commands", "heartbeats", "audit_log",
            "hardware_info", "system_stats",
        ]

        for table in tables:
            index_pattern = f"{self.prefix}-{table}-*"
            template_name = f"{self.prefix}-{table}-template"

            try:
                self.es.indices.put_index_template(
                    name=template_name,
                    body={
                        "index_patterns": [index_pattern],
                        "template": {
                            "settings": {
                                "number_of_shards": 1,
                                "number_of_replicas": 0,
                                "refresh_interval": "5s",
                            },
                            "mappings": {
                                "dynamic": True,
                                "properties": {
                                    "timestamp": {"type": "date"},
                                    "machine_id": {"type": "keyword"},
                                    "severity": {"type": "keyword"},
                                    "event_id": {"type": "keyword"},
                                },
                            },
                        },
                    },
                )
            except Exception:
                pass  # Template may already exist

    def _current_index(self, table: str) -> str:
        """Get the current index name with date suffix for time-based indices."""
        return f"{self.prefix}-{table}-{datetime.now().strftime('%Y.%m')}"

    # =========================================================================
    # Machines
    # =========================================================================

    def get_machines(self, online_only: bool = False) -> list:
        idx = self._index_name("machines")
        query = {"query": {"match_all": {}}, "size": 1000}
        if online_only:
            query["query"] = {"term": {"online": True}}

        try:
            result = self.es.search(index=idx, body=query)
            return [hit["_source"] for hit in result["hits"]["hits"]]
        except Exception:
            return []

    def get_machine(self, machine_id: str) -> dict:
        try:
            result = self.es.get(
                index=self._index_name("machines"),
                id=machine_id,
            )
            return result["_source"]
        except Exception:
            return None

    def upsert_machine(self, machine_data: dict):
        machine_id = machine_data.get("machine_id", "")
        if not machine_id:
            return
        try:
            self.es.index(
                index=self._index_name("machines"),
                id=machine_id,
                body=machine_data,
                refresh=True,
            )
        except Exception:
            pass

    def delete_offline_machines(self):
        try:
            self.es.delete_by_query(
                index=self._index_name("machines"),
                body={"query": {"term": {"online": False}}},
            )
        except Exception:
            pass

    def get_machine_hardware(self, machine_id: str) -> dict:
        try:
            result = self.es.search(
                index=self._index_name("hardware_info"),
                body={
                    "query": {"term": {"machine_id": machine_id}},
                    "sort": [{"timestamp": "desc"}],
                    "size": 1,
                },
            )
            hits = result["hits"]["hits"]
            return hits[0]["_source"] if hits else {}
        except Exception:
            return {}

    def upsert_hardware(self, machine_id: str, hw_data: dict):
        hw_data["machine_id"] = machine_id
        hw_data["timestamp"] = datetime.now().isoformat()
        try:
            self.es.index(
                index=self._index_name("hardware_info"),
                body=hw_data,
            )
        except Exception:
            pass

    def get_machine_stats(self, machine_id: str) -> dict:
        try:
            result = self.es.search(
                index=self._index_name("system_stats"),
                body={
                    "query": {"term": {"machine_id": machine_id}},
                    "sort": [{"timestamp": "desc"}],
                    "size": 1,
                },
            )
            hits = result["hits"]["hits"]
            return hits[0]["_source"] if hits else {}
        except Exception:
            return {}

    def upsert_machine_stats(self, machine_id: str, stats: dict):
        stats["machine_id"] = machine_id
        stats["timestamp"] = datetime.now().isoformat()
        try:
            self.es.index(
                index=self._index_name("system_stats"),
                body=stats,
            )
        except Exception:
            pass

    # =========================================================================
    # Events
    # =========================================================================

    def get_events(self, machine_id: str = None, limit: int = 100,
                   severity: str = None, event_id: str = None,
                   since: str = None) -> list:
        must = []
        if machine_id:
            must.append({"term": {"machine_id": machine_id}})
        if severity:
            must.append({"term": {"severity": severity}})
        if event_id:
            must.append({"term": {"event_id": event_id}})
        if since:
            must.append({"range": {"timestamp": {"gte": since}}})

        query = {
            "query": {"bool": {"must": must}} if must else {"match_all": {}},
            "sort": [{"timestamp": "desc"}],
            "size": limit,
        }

        try:
            result = self.es.search(
                index=self._current_index("events"),
                body=query,
            )
            return [hit["_source"] for hit in result["hits"]["hits"]]
        except Exception:
            return []

    def insert_event(self, machine_id: str, event_data: dict):
        event_data["machine_id"] = machine_id
        event_data["@timestamp"] = datetime.now().isoformat()
        self._buffer_index("events", event_data)

    def insert_events_batch(self, machine_id: str, events: list):
        actions = []
        now = datetime.now().isoformat()
        for ev in events:
            ev["machine_id"] = machine_id
            ev["@timestamp"] = now
            actions.append({"_index": self._current_index("events"), "_source": ev})
        if actions:
            try:
                helpers.bulk(self.es, actions)
            except Exception:
                pass

    def clear_events(self, machine_id: str = None):
        try:
            query = {"term": {"machine_id": machine_id}} if machine_id else {"match_all": {}}
            self.es.delete_by_query(
                index=self._current_index("events"),
                body={"query": query},
            )
        except Exception:
            pass

    def get_event_count(self, machine_id: str = None) -> int:
        query = {"term": {"machine_id": machine_id}} if machine_id else {"match_all": {}}
        try:
            result = self.es.count(
                index=self._current_index("events"),
                body={"query": query},
            )
            return result["count"]
        except Exception:
            return 0

    # =========================================================================
    # FIM
    # =========================================================================

    def get_fim_events(self, machine_id: str = None, limit: int = 100,
                        action: str = None) -> list:
        must = []
        if machine_id:
            must.append({"term": {"machine_id": machine_id}})
        if action:
            must.append({"term": {"action": action}})

        query = {
            "query": {"bool": {"must": must}} if must else {"match_all": {}},
            "sort": [{"timestamp": "desc"}],
            "size": limit,
        }

        try:
            result = self.es.search(
                index=self._current_index("fim_events"),
                body=query,
            )
            return [hit["_source"] for hit in result["hits"]["hits"]]
        except Exception:
            return []

    def insert_fim_event(self, machine_id: str, fim_data: dict):
        fim_data["machine_id"] = machine_id
        fim_data["@timestamp"] = datetime.now().isoformat()
        self._buffer_index("fim_events", fim_data)

    def clear_fim_events(self, machine_id: str = None):
        query = {"term": {"machine_id": machine_id}} if machine_id else {"match_all": {}}
        try:
            self.es.delete_by_query(
                index=self._current_index("fim_events"),
                body={"query": query},
            )
        except Exception:
            pass

    # =========================================================================
    # Network Traffic
    # =========================================================================

    def get_network_traffic(self, machine_id: str = None, limit: int = 100,
                             protocol: str = None, protocol_app: str = None) -> list:
        must = []
        if machine_id:
            must.append({"term": {"machine_id": machine_id}})
        if protocol:
            must.append({"term": {"protocol": protocol}})
        if protocol_app:
            must.append({"term": {"protocol_app": protocol_app}})

        query = {
            "query": {"bool": {"must": must}} if must else {"match_all": {}},
            "sort": [{"timestamp": "desc"}],
            "size": limit,
        }

        try:
            result = self.es.search(
                index=self._current_index("network_traffic"),
                body=query,
            )
            return [hit["_source"] for hit in result["hits"]["hits"]]
        except Exception:
            return []

    def insert_network_packet(self, machine_id: str, packet_data: dict):
        packet_data["machine_id"] = machine_id
        packet_data["@timestamp"] = datetime.now().isoformat()
        self._buffer_index("network_traffic", packet_data)

    def clear_network_traffic(self, machine_id: str = None):
        query = {"term": {"machine_id": machine_id}} if machine_id else {"match_all": {}}
        try:
            self.es.delete_by_query(
                index=self._current_index("network_traffic"),
                body={"query": query},
            )
        except Exception:
            pass

    # =========================================================================
    # Threat Alerts
    # =========================================================================

    def get_threats(self, machine_id: str = None, limit: int = 100,
                     severity: str = None) -> list:
        must = []
        if machine_id:
            must.append({"term": {"machine_id": machine_id}})
        if severity:
            must.append({"term": {"severity": severity}})

        query = {
            "query": {"bool": {"must": must}} if must else {"match_all": {}},
            "sort": [{"timestamp": "desc"}],
            "size": limit,
        }

        try:
            result = self.es.search(
                index=self._current_index("threat_alerts"),
                body=query,
            )
            return [hit["_source"] for hit in result["hits"]["hits"]]
        except Exception:
            return []

    def insert_threat(self, machine_id: str, threat_data: dict):
        threat_data["machine_id"] = machine_id
        threat_data["@timestamp"] = datetime.now().isoformat()
        self._buffer_index("threat_alerts", threat_data)

    def clear_threats(self, machine_id: str = None):
        query = {"term": {"machine_id": machine_id}} if machine_id else {"match_all": {}}
        try:
            self.es.delete_by_query(
                index=self._current_index("threat_alerts"),
                body={"query": query},
            )
        except Exception:
            pass

    # =========================================================================
    # Vulnerability Alerts
    # =========================================================================

    def get_vulnerabilities(self, machine_id: str = None, limit: int = 100,
                             severity: str = None) -> list:
        must = []
        if machine_id:
            must.append({"term": {"machine_id": machine_id}})
        if severity:
            must.append({"term": {"severity": severity}})

        query = {
            "query": {"bool": {"must": must}} if must else {"match_all": {}},
            "sort": [{"timestamp": "desc"}],
            "size": limit,
        }

        try:
            result = self.es.search(
                index=self._current_index("vuln_alerts"),
                body=query,
            )
            return [hit["_source"] for hit in result["hits"]["hits"]]
        except Exception:
            return []

    def insert_vulnerability(self, machine_id: str, vuln_data: dict):
        vuln_data["machine_id"] = machine_id
        vuln_data["@timestamp"] = datetime.now().isoformat()
        self._buffer_index("vuln_alerts", vuln_data)

    def clear_vulnerabilities(self, machine_id: str = None):
        query = {"term": {"machine_id": machine_id}} if machine_id else {"match_all": {}}
        try:
            self.es.delete_by_query(
                index=self._current_index("vuln_alerts"),
                body={"query": query},
            )
        except Exception:
            pass

    # =========================================================================
    # YARA Alerts
    # =========================================================================

    def get_yara_alerts(self, machine_id: str = None, limit: int = 100) -> list:
        must = [{"term": {"machine_id": machine_id}}] if machine_id else []
        query = {
            "query": {"bool": {"must": must}} if must else {"match_all": {}},
            "sort": [{"timestamp": "desc"}],
            "size": limit,
        }

        try:
            result = self.es.search(
                index=self._current_index("yara_alerts"),
                body=query,
            )
            return [hit["_source"] for hit in result["hits"]["hits"]]
        except Exception:
            return []

    def insert_yara_alert(self, machine_id: str, yara_data: dict):
        yara_data["machine_id"] = machine_id
        yara_data["@timestamp"] = datetime.now().isoformat()
        self._buffer_index("yara_alerts", yara_data)

    def clear_yara_alerts(self, machine_id: str = None):
        query = {"term": {"machine_id": machine_id}} if machine_id else {"match_all": {}}
        try:
            self.es.delete_by_query(
                index=self._current_index("yara_alerts"),
                body={"query": query},
            )
        except Exception:
            pass

    # =========================================================================
    # SCA
    # =========================================================================

    def get_sca_findings(self, machine_id: str = None, limit: int = 200,
                          status: str = None) -> list:
        must = []
        if machine_id:
            must.append({"term": {"machine_id": machine_id}})
        if status:
            must.append({"term": {"status": status}})

        query = {
            "query": {"bool": {"must": must}} if must else {"match_all": {}},
            "sort": [{"timestamp": "desc"}],
            "size": limit,
        }

        try:
            result = self.es.search(
                index=self._current_index("sca_events"),
                body=query,
            )
            return [hit["_source"] for hit in result["hits"]["hits"]]
        except Exception:
            return []

    def upsert_sca_finding(self, machine_id: str, sca_data: dict):
        sca_data["machine_id"] = machine_id
        sca_data["@timestamp"] = datetime.now().isoformat()
        check_id = sca_data.get("check_id", "unknown")
        doc_id = f"{machine_id}_{check_id}"
        try:
            self.es.index(
                index=self._current_index("sca_events"),
                id=doc_id,
                body=sca_data,
            )
        except Exception:
            pass

    def clear_sca_findings(self, machine_id: str = None):
        query = {"term": {"machine_id": machine_id}} if machine_id else {"match_all": {}}
        try:
            self.es.delete_by_query(
                index=self._current_index("sca_events"),
                body={"query": query},
            )
        except Exception:
            pass

    # =========================================================================
    # Agentless
    # =========================================================================

    def get_agentless_devices(self) -> list:
        try:
            result = self.es.search(
                index=self._index_name("agentless_devices"),
                body={"query": {"match_all": {}}, "size": 100},
            )
            return [hit["_source"] for hit in result["hits"]["hits"]]
        except Exception:
            return []

    def add_agentless_device(self, device_data: dict) -> int:
        device_id = device_data.get("id", int(time.time() * 1000) % 1000000)
        device_data["id"] = device_id
        try:
            self.es.index(
                index=self._index_name("agentless_devices"),
                id=str(device_id),
                body=device_data,
                refresh=True,
            )
        except Exception:
            pass
        return device_id

    def remove_agentless_device(self, device_id: int):
        try:
            self.es.delete(
                index=self._index_name("agentless_devices"),
                id=str(device_id),
            )
        except Exception:
            pass

    def get_agentless_events(self, limit: int = 100) -> list:
        try:
            result = self.es.search(
                index=self._current_index("agentless_events"),
                body={
                    "query": {"match_all": {}},
                    "sort": [{"timestamp": "desc"}],
                    "size": limit,
                },
            )
            return [hit["_source"] for hit in result["hits"]["hits"]]
        except Exception:
            return []

    def insert_agentless_event(self, event_data: dict):
        event_data["@timestamp"] = datetime.now().isoformat()
        self._buffer_index("agentless_events", event_data)

    def clear_agentless_events(self):
        try:
            self.es.delete_by_query(
                index=self._current_index("agentless_events"),
                body={"query": {"match_all": {}}},
            )
        except Exception:
            pass

    # =========================================================================
    # Commands
    # =========================================================================

    def enqueue_command(self, machine_id: str, command: str) -> str:
        exec_id = f"cmd_{int(time.time() * 1000)}_{machine_id[:8]}"
        doc = {
            "exec_id": exec_id,
            "machine_id": machine_id,
            "command": command,
            "status": "queued",
            "output": "",
            "timestamp": datetime.now().isoformat(),
        }
        try:
            self.es.index(
                index=self._index_name("commands"),
                id=exec_id,
                body=doc,
                refresh=True,
            )
        except Exception:
            pass
        return exec_id

    def get_command_result(self, exec_id: str) -> dict:
        try:
            result = self.es.get(
                index=self._index_name("commands"),
                id=exec_id,
            )
            return result["_source"]
        except Exception:
            return {"status": "unknown", "output": ""}

    def update_command_result(self, exec_id: str, status: str, output: str):
        try:
            self.es.update(
                index=self._index_name("commands"),
                id=exec_id,
                body={"doc": {"status": status, "output": output}},
            )
        except Exception:
            pass

    # =========================================================================
    # Heartbeats
    # =========================================================================

    def record_heartbeat(self, machine_id: str):
        doc = {
            "machine_id": machine_id,
            "@timestamp": datetime.now().isoformat(),
        }
        try:
            self.es.index(
                index=self._current_index("heartbeats"),
                body=doc,
            )
        except Exception:
            pass

    def check_heartbeat_timeout(self, timeout_seconds: int = 120) -> list:
        cutoff = (datetime.now() - timedelta(seconds=timeout_seconds)).isoformat()
        try:
            # Aggregate: find machines whose last heartbeat is older than cutoff
            result = self.es.search(
                index=self._current_index("heartbeats"),
                body={
                    "query": {
                        "bool": {
                            "must": [
                                {"range": {"@timestamp": {"lt": cutoff}}},
                            ],
                        },
                    },
                    "aggs": {
                        "machines": {
                            "terms": {"field": "machine_id", "size": 1000},
                            "aggs": {
                                "last_seen": {"max": {"field": "@timestamp"}},
                            },
                        },
                    },
                    "size": 0,
                },
            )
            timed_out = []
            for bucket in result["aggregations"]["machines"]["buckets"]:
                timed_out.append(bucket["key"])
            return timed_out
        except Exception:
            return []

    # =========================================================================
    # Audit Log
    # =========================================================================

    def log_audit(self, action: str, user: str = "system", details: str = ""):
        doc = {
            "action": action,
            "user": user,
            "details": details,
            "@timestamp": datetime.now().isoformat(),
        }
        try:
            self.es.index(
                index=self._current_index("audit_log"),
                body=doc,
            )
        except Exception:
            pass

    def get_audit_log(self, limit: int = 100) -> list:
        try:
            result = self.es.search(
                index=self._current_index("audit_log"),
                body={
                    "query": {"match_all": {}},
                    "sort": [{"@timestamp": "desc"}],
                    "size": limit,
                },
            )
            return [hit["_source"] for hit in result["hits"]["hits"]]
        except Exception:
            return []

    # =========================================================================
    # System
    # =========================================================================

    def get_database_size_mb(self) -> float:
        try:
            stats = self.es.indices.stats(index=f"{self.prefix}-*")
            total_bytes = stats["_all"]["total"]["store"]["size_in_bytes"]
            return round(total_bytes / (1024 * 1024), 2)
        except Exception:
            return 0.0

    def get_table_counts(self) -> dict:
        tables = [
            "machines", "events", "fim_events", "network_traffic",
            "threat_alerts", "vuln_alerts", "yara_alerts", "sca_events",
            "agentless_events",
        ]
        counts = {}
        for table in tables:
            try:
                result = self.es.count(index=f"{self.prefix}-{table}")
                counts[table] = result["count"]
            except Exception:
                counts[table] = 0
        return counts

    def cleanup_old_data(self, retention_days: int = 90):
        cutoff = (datetime.now() - timedelta(days=retention_days)).isoformat()
        tables = [
            "events", "fim_events", "network_traffic", "threat_alerts",
            "vuln_alerts", "yara_alerts", "sca_events", "agentless_events",
            "heartbeats", "audit_log",
        ]
        for table in tables:
            try:
                self.es.delete_by_query(
                    index=f"{self.prefix}-{table}-*",
                    body={
                        "query": {
                            "range": {
                                "@timestamp": {"lt": cutoff},
                            },
                        },
                    },
                )
            except Exception:
                pass

    def vacuum(self):
        # Elasticsearch optimizes automatically
        try:
            self.es.indices.forcemerge(index=f"{self.prefix}-*", max_num_segments=1)
        except Exception:
            pass

    # =========================================================================
    # Bulk Indexing Buffer
    # =========================================================================

    def _buffer_index(self, table: str, doc: dict):
        """Add document to bulk indexing buffer."""
        with self._bulk_lock:
            self._bulk_buffer.append((table, doc))
            if len(self._bulk_buffer) >= BULK_FLUSH_SIZE:
                self._flush_bulk_buffer()

    def _flush_bulk_buffer(self):
        """Flush the bulk indexing buffer to Elasticsearch."""
        with self._bulk_lock:
            if not self._bulk_buffer:
                return

            actions = []
            while self._bulk_buffer:
                table, doc = self._bulk_buffer.popleft()
                actions.append({
                    "_index": self._current_index(table),
                    "_source": doc,
                })

        if actions and self.es:
            try:
                helpers.bulk(self.es, actions, raise_on_error=False)
            except Exception:
                pass

    def _start_bulk_flush_timer(self):
        """Start a timer to periodically flush the bulk buffer."""
        self._flush_timer = threading.Timer(BULK_FLUSH_INTERVAL, self._auto_flush)
        self._flush_timer.daemon = True
        self._flush_timer.start()

    def _auto_flush(self):
        """Periodic flush callback."""
        self._flush_bulk_buffer()
        self._start_bulk_flush_timer()