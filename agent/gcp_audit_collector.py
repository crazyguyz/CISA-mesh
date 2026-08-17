"""
GCP Cloud Audit Logs Collector for GIAM-SAT Agent v1.13.0

Collects Google Cloud Platform audit logs via Cloud Logging API:
  - Admin Activity logs (IAM, project changes)
  - Data Access logs (read/write to resources)
  - System Event logs
  - Policy Denied logs (access violations)
  - VPC/Network changes

Requirements:
  - google-cloud-logging installed (pip install google-cloud-logging)
  - GCP credentials configured (GOOGLE_APPLICATION_CREDENTIALS env var or default ADC)
  - logging.logEntries.list permission on monitored projects
"""

import os
import json
import time
from datetime import datetime, timedelta

try:
    from google.cloud import logging as google_logging
    from google.cloud.logging import DESCENDING
    HAS_GCP = True
except ImportError:
    HAS_GCP = False


# High-value audit log method names for security monitoring
SECURITY_METHODS = [
    # IAM
    "SetIamPolicy", "google.iam.admin.v1.CreateServiceAccount",
    "google.iam.admin.v1.DeleteServiceAccount", "google.iam.admin.v1.CreateServiceAccountKey",
    "google.iam.admin.v1.DeleteServiceAccountKey",
    # Storage
    "storage.buckets.setIamPolicy", "storage.buckets.delete",
    "storage.objects.getIamPolicy", "storage.buckets.update",
    # Compute
    "compute.firewalls.insert", "compute.firewalls.delete",
    "compute.firewalls.update", "compute.instances.insert",
    "compute.instances.delete", "compute.networks.insert",
    "compute.networks.delete",
    # Cloud Functions / Cloud Run
    "google.cloud.functions.v1.CloudFunctionsService.CreateFunction",
    "google.cloud.functions.v1.CloudFunctionsService.DeleteFunction",
    # KMS
    "cloudkms.cryptoKeys.create", "cloudkms.cryptoKeys.destroy",
    # Logging
    "logging.sinks.delete", "logging.sinks.update",
    # Organization
    "SetOrgPolicy", "google.cloud.resourcemanager.v3.Organizations.SetIamPolicy",
    "google.cloud.resourcemanager.v3.Projects.SetIamPolicy",
    # Billing
    "billing.accounts.close",
]


class GCPAuditCollector:
    """Collects GCP Cloud Audit Log security events."""

    def __init__(self, callback=None, project_id: str = None,
                 credentials_path: str = None):
        self.callback = callback
        self.project_id = project_id or os.environ.get("GCP_PROJECT", os.environ.get("GOOGLE_CLOUD_PROJECT", ""))
        self.credentials_path = credentials_path or os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", "")
        self.client = None
        self._last_check = datetime.now()

    def connect(self) -> bool:
        """Establish connection to GCP Cloud Logging."""
        if not HAS_GCP:
            return False

        try:
            if self.credentials_path and os.path.exists(self.credentials_path):
                os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = self.credentials_path

            self.client = google_logging.Client(project=self.project_id)
            return True
        except Exception:
            return False

    def _map_severity(self, method_name: str, has_error: bool = False) -> str:
        """Map GCP audit log method to GIAM-SAT severity."""
        critical_methods = [
            "SetIamPolicy", "DeleteServiceAccount", "DeleteServiceAccountKey",
            "sinks.delete", "SetOrgPolicy",
        ]
        high_methods = [
            "CreateServiceAccount", "CreateServiceAccountKey",
            "firewalls.delete", "firewalls.insert",
            "buckets.setIamPolicy", "buckets.delete",
            "instances.delete", "instances.insert",
            "cryptoKeys.destroy",
        ]
        medium_methods = [
            "firewalls.update", "networks.insert", "networks.delete",
            "sinks.update", "buckets.update",
        ]

        if has_error:
            return "HIGH"

        for m in critical_methods:
            if m in method_name:
                return "CRITICAL"
        for m in high_methods:
            if m in method_name:
                return "HIGH"
        for m in medium_methods:
            if m in method_name:
                return "MEDIUM"
        return "LOW"

    def _format_event(self, entry) -> dict:
        """Format GCP LogEntry for GIAM-SAT."""
        proto_payload = entry.proto_payload
        if isinstance(proto_payload, dict):
            payload = proto_payload
        else:
            try:
                payload = json.loads(str(proto_payload))
            except (json.JSONDecodeError, TypeError):
                payload = {}

        # Extract authentication info
        auth_info = payload.get("authenticationInfo", {})
        principal = auth_info.get("principalEmail", "unknown")

        # Extract method name
        method_name = payload.get("methodName", entry.log_name or "unknown")

        # Check for authorization errors
        auth_info = payload.get("authorizationInfo", [])
        has_policy_denied = any(
            info.get("granted") == False for info in auth_info
            if isinstance(info, dict)
        )

        # Extract resource
        resource = entry.resource
        resource_type = getattr(resource, "type", "") if resource else ""

        # Build description
        desc_parts = [f"[GCP] {principal} -> {method_name}"]
        if has_policy_denied:
            desc_parts.append("(PERMISSION DENIED)")
        if resource_type:
            desc_parts.append(f"resource={resource_type}")

        return {
            "type": "cloud_event",
            "subtype": "gcp_audit_log",
            "event_name": method_name,
            "user_identity": principal,
            "resource_type": resource_type,
            "policy_denied": has_policy_denied,
            "description": " | ".join(desc_parts)[:500],
            "severity": self._map_severity(method_name, has_policy_denied),
            "timestamp": entry.timestamp.isoformat() if entry.timestamp else datetime.now().isoformat(),
            "insert_id": entry.insert_id or "",
            "log_name": entry.log_name or "",
        }

    def collect_events(self, lookback_minutes: int = 10, max_results: int = 100) -> list:
        """Collect GCP audit log events from the last N minutes."""
        if not self.client:
            return []

        events = []

        try:
            filter_str = (
                'logName:"cloudaudit.googleapis.com" AND '
                f'timestamp >= "{datetime.utcnow() - timedelta(minutes=lookback_minutes):%Y-%m-%dT%H:%M:%SZ}" AND '
                "severity >= WARNING"
            )

            entries = self.client.list_entries(
                filter_=filter_str,
                order_by=DESCENDING,
                page_size=50,
            )

            count = 0
            for entry in entries:
                if count >= max_results:
                    break

                method_name = ""
                try:
                    proto = entry.proto_payload
                    if isinstance(proto, dict):
                        method_name = proto.get("methodName", "")
                except Exception:
                    pass

                # Check if this is a high-value security event
                is_security_event = (
                    any(m in method_name for m in SECURITY_METHODS) or
                    "policy" in str(getattr(entry, "log_name", "")).lower()
                )

                if is_security_event or "PERMISSION_DENIED" in str(entry.severity).upper():
                    formatted = self._format_event(entry)
                    events.append(formatted)
                    if self.callback:
                        self.callback(formatted)
                    count += 1

                # Always collect access denied events
                if "PERMISSION_DENIED" in str(entry.severity).upper():
                    if not is_security_event:
                        formatted = self._format_event(entry)
                        events.append(formatted)
                        if self.callback:
                            self.callback(formatted)
                        count += 1

        except Exception:
            pass

        self._last_check = datetime.now()
        return events

    def collect_policy_violations(self, lookback_hours: int = 1) -> list:
        """Collect Organization Policy and IAM policy violations."""
        if not self.client:
            return []

        events = []

        try:
            filter_str = (
                'logName:"cloudaudit.googleapis.com" AND '
                "(protoPayload.methodName:SetIamPolicy OR "
                "protoPayload.methodName:SetOrgPolicy OR "
                "protoPayload.authorizationInfo.granted=false) AND "
                f'timestamp >= "{datetime.utcnow() - timedelta(hours=lookback_hours):%Y-%m-%dT%H:%M:%SZ}"'
            )

            entries = self.client.list_entries(
                filter_=filter_str,
                order_by=DESCENDING,
                page_size=30,
            )

            for entry in entries:
                formatted = self._format_event(entry)
                events.append(formatted)
                if self.callback:
                    self.callback(formatted)

        except Exception:
            pass

        return events

    def collect_all(self) -> list:
        """Collect all GCP audit log security events."""
        if not self.connect():
            return []

        all_events = []
        all_events.extend(self.collect_events(lookback_minutes=10))
        all_events.extend(self.collect_policy_violations(lookback_hours=1))
        return all_events