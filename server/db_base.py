"""
GIAM-SAT Database Backend Abstraction v1.13.0

Abstract base class defining the standard interface for all database backends.
Supports:
  - SQLite (current default, lightweight)
  - Elasticsearch/OpenSearch (production, scalable)
  - PostgreSQL (future)

All server code queries through this abstract interface.
To switch backend, change BACKEND_TYPE in .env.
"""

from abc import ABC, abstractmethod
from datetime import datetime


class DatabaseBackend(ABC):
    """Abstract interface for GIAM-SAT database operations."""

    def __init__(self, config: dict = None):
        self.config = config or {}

    # =========================================================================
    # Connection
    # =========================================================================
    @abstractmethod
    def connect(self):
        """Establish connection to the database."""
        pass

    @abstractmethod
    def close(self):
        """Close the database connection."""
        pass

    @abstractmethod
    def health_check(self) -> bool:
        """Check if database is responsive."""
        pass

    # =========================================================================
    # Machines
    # =========================================================================
    @abstractmethod
    def get_machines(self, online_only: bool = False) -> list:
        """Get all registered machines."""
        pass

    @abstractmethod
    def get_machine(self, machine_id: str) -> dict:
        """Get a single machine by ID."""
        pass

    @abstractmethod
    def upsert_machine(self, machine_data: dict):
        """Insert or update a machine record."""
        pass

    @abstractmethod
    def delete_offline_machines(self):
        """Remove all offline machines."""
        pass

    @abstractmethod
    def get_machine_hardware(self, machine_id: str) -> dict:
        """Get hardware info for a machine."""
        pass

    @abstractmethod
    def upsert_hardware(self, machine_id: str, hw_data: dict):
        """Insert or update hardware information."""
        pass

    @abstractmethod
    def get_machine_stats(self, machine_id: str) -> dict:
        """Get system stats for a machine."""
        pass

    @abstractmethod
    def upsert_machine_stats(self, machine_id: str, stats: dict):
        """Insert or update system statistics."""
        pass

    # =========================================================================
    # Events
    # =========================================================================
    @abstractmethod
    def get_events(self, machine_id: str = None, limit: int = 100,
                   severity: str = None, event_id: str = None,
                   since: str = None) -> list:
        """Get event logs with optional filters."""
        pass

    @abstractmethod
    def insert_event(self, machine_id: str, event_data: dict):
        """Insert a single event log."""
        pass

    @abstractmethod
    def insert_events_batch(self, machine_id: str, events: list):
        """Insert multiple events in batch."""
        pass

    @abstractmethod
    def clear_events(self, machine_id: str = None):
        """Clear events, optionally for a specific machine."""
        pass

    @abstractmethod
    def get_event_count(self, machine_id: str = None) -> int:
        """Count events."""
        pass

    # =========================================================================
    # FIM (File Integrity Monitoring)
    # =========================================================================
    @abstractmethod
    def get_fim_events(self, machine_id: str = None, limit: int = 100,
                        action: str = None) -> list:
        """Get FIM events."""
        pass

    @abstractmethod
    def insert_fim_event(self, machine_id: str, fim_data: dict):
        """Insert a FIM event."""
        pass

    @abstractmethod
    def clear_fim_events(self, machine_id: str = None):
        """Clear FIM events."""
        pass

    # =========================================================================
    # Network Traffic
    # =========================================================================
    @abstractmethod
    def get_network_traffic(self, machine_id: str = None, limit: int = 100,
                             protocol: str = None, protocol_app: str = None) -> list:
        """Get network traffic logs with application layer data."""
        pass

    @abstractmethod
    def insert_network_packet(self, machine_id: str, packet_data: dict):
        """Insert a network packet."""
        pass

    @abstractmethod
    def clear_network_traffic(self, machine_id: str = None):
        """Clear network traffic."""
        pass

    # =========================================================================
    # Threat Alerts
    # =========================================================================
    @abstractmethod
    def get_threats(self, machine_id: str = None, limit: int = 100,
                     severity: str = None) -> list:
        """Get threat/correlation alerts."""
        pass

    @abstractmethod
    def insert_threat(self, machine_id: str, threat_data: dict):
        """Insert a threat alert."""
        pass

    @abstractmethod
    def clear_threats(self, machine_id: str = None):
        """Clear threat alerts."""
        pass

    # =========================================================================
    # Vulnerability Alerts
    # =========================================================================
    @abstractmethod
    def get_vulnerabilities(self, machine_id: str = None, limit: int = 100,
                             severity: str = None) -> list:
        """Get CVE vulnerability alerts."""
        pass

    @abstractmethod
    def insert_vulnerability(self, machine_id: str, vuln_data: dict):
        """Insert a vulnerability alert."""
        pass

    @abstractmethod
    def clear_vulnerabilities(self, machine_id: str = None):
        """Clear vulnerability alerts."""
        pass

    # =========================================================================
    # YARA Alerts
    # =========================================================================
    @abstractmethod
    def get_yara_alerts(self, machine_id: str = None, limit: int = 100) -> list:
        """Get YARA malware detection alerts."""
        pass

    @abstractmethod
    def insert_yara_alert(self, machine_id: str, yara_data: dict):
        """Insert a YARA alert."""
        pass

    @abstractmethod
    def clear_yara_alerts(self, machine_id: str = None):
        """Clear YARA alerts."""
        pass

    # =========================================================================
    # SCA (Security Configuration Assessment)
    # =========================================================================
    @abstractmethod
    def get_sca_findings(self, machine_id: str = None, limit: int = 200,
                          status: str = None) -> list:
        """Get SCA compliance findings."""
        pass

    @abstractmethod
    def upsert_sca_finding(self, machine_id: str, sca_data: dict):
        """Insert or update an SCA finding (UPSERT by check_id + machine_id)."""
        pass

    @abstractmethod
    def clear_sca_findings(self, machine_id: str = None):
        """Clear SCA findings."""
        pass

    # =========================================================================
    # Agentless Monitoring
    # =========================================================================
    @abstractmethod
    def get_agentless_devices(self) -> list:
        """Get all agentless monitoring devices."""
        pass

    @abstractmethod
    def add_agentless_device(self, device_data: dict) -> int:
        """Add a new agentless device. Returns device ID."""
        pass

    @abstractmethod
    def remove_agentless_device(self, device_id: int):
        """Remove an agentless device."""
        pass

    @abstractmethod
    def get_agentless_events(self, limit: int = 100) -> list:
        """Get agentless monitoring results."""
        pass

    @abstractmethod
    def insert_agentless_event(self, event_data: dict):
        """Insert an agentless monitoring event."""
        pass

    @abstractmethod
    def clear_agentless_events(self):
        """Clear agentless events."""
        pass

    # =========================================================================
    # Commands
    # =========================================================================
    @abstractmethod
    def enqueue_command(self, machine_id: str, command: str) -> str:
        """Queue a command for agent execution. Returns exec_id."""
        pass

    @abstractmethod
    def get_command_result(self, exec_id: str) -> dict:
        """Get command execution result."""
        pass

    @abstractmethod
    def update_command_result(self, exec_id: str, status: str, output: str):
        """Update command execution result."""
        pass

    # =========================================================================
    # Heartbeats
    # =========================================================================
    @abstractmethod
    def record_heartbeat(self, machine_id: str):
        """Record a heartbeat from an agent."""
        pass

    @abstractmethod
    def check_heartbeat_timeout(self, timeout_seconds: int = 120) -> list:
        """Check for machines that have timed out. Returns list of machine_ids."""
        pass

    # =========================================================================
    # Audit Log
    # =========================================================================
    @abstractmethod
    def log_audit(self, action: str, user: str = "system", details: str = ""):
        """Log an administrative action for audit trail."""
        pass

    @abstractmethod
    def get_audit_log(self, limit: int = 100) -> list:
        """Get audit log entries."""
        pass

    # =========================================================================
    # System
    # =========================================================================
    @abstractmethod
    def get_database_size_mb(self) -> float:
        """Get database size in megabytes."""
        pass

    @abstractmethod
    def get_table_counts(self) -> dict:
        """Get row counts for all tables."""
        pass

    @abstractmethod
    def cleanup_old_data(self, retention_days: int = 90):
        """Purge data older than retention period."""
        pass

    @abstractmethod
    def vacuum(self):
        """Optimize database storage."""
        pass


def create_backend(backend_type: str = "sqlite", config: dict = None):
    """Factory function to create the appropriate database backend.

    Args:
        backend_type: 'sqlite', 'elasticsearch', or 'postgresql'
        config: Backend-specific configuration dict

    Returns:
        DatabaseBackend instance
    """
    # v4.10 (HIGH-14): fixed class names + absolute imports (server/ is not a
    # package, so relative imports always raised ImportError). Removed the
    # ClickHouse branch - server/db_clickhouse.py does not exist.
    if backend_type == "elasticsearch":
        from db_elasticsearch import ElasticsearchBackend
        return ElasticsearchBackend(config)
    elif backend_type == "postgresql":
        from db_postgres import PostgresDatabase
        return PostgresDatabase()
    else:
        from db_manager import DatabaseManager
        return DatabaseManager()
