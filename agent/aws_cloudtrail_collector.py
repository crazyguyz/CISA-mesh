"""
AWS CloudTrail Log Collector for GIAM-SAT Agent v1.13.0

Collects AWS CloudTrail events for security monitoring:
  - IAM user/role changes
  - Security group modifications
  - S3 bucket policy changes
  - API activity anomalies
  - Console login events (success/failure)

Requirements:
  - boto3 installed (pip install boto3)
  - AWS credentials configured (env vars, ~/.aws/credentials, or IAM role)
  - cloudtrail:LookupEvents permission
  - IAM Role permissions depend on monitored services
"""

import os
import json
import time
from datetime import datetime, timedelta

try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False


# High-value CloudTrail event names for security monitoring
SECURITY_EVENT_NAMES = [
    # IAM
    "CreateUser", "DeleteUser", "UpdateUser", "CreateAccessKey", "DeleteAccessKey",
    "CreateLoginProfile", "UpdateLoginProfile", "DeleteLoginProfile",
    "AttachUserPolicy", "DetachUserPolicy", "PutUserPolicy", "DeleteUserPolicy",
    "CreateRole", "DeleteRole", "UpdateRole", "AttachRolePolicy", "DetachRolePolicy",
    "CreatePolicy", "DeletePolicy",
    # Console
    "ConsoleLogin",
    # Security Groups
    "AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress",
    "RevokeSecurityGroupIngress", "RevokeSecurityGroupEgress",
    "CreateSecurityGroup", "DeleteSecurityGroup",
    # Network
    "CreateNetworkAclEntry", "DeleteNetworkAclEntry",
    "ReplaceNetworkAclEntry", "ReplaceRoute",
    # S3
    "PutBucketPolicy", "DeleteBucketPolicy", "PutBucketAcl",
    "PutBucketPublicAccessBlock", "DeleteBucketPublicAccessBlock",
    # EC2
    "RunInstances", "TerminateInstances", "StopInstances", "StartInstances",
    # KMS
    "ScheduleKeyDeletion", "DisableKey", "CreateKey",
    # CloudTrail itself
    "StopLogging", "DeleteTrail", "UpdateTrail",
    # GuardDuty / Security Hub
    "CreateDetector", "DeleteDetector",
]


class CloudTrailCollector:
    """Collects AWS CloudTrail security events."""

    def __init__(self, callback=None, aws_region: str = None,
                 aws_access_key: str = None, aws_secret_key: str = None):
        self.callback = callback
        self.aws_region = aws_region or os.environ.get("AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))
        self.aws_access_key = aws_access_key
        self.aws_secret_key = aws_secret_key
        self.client = None
        self._last_check = datetime.now()

    def connect(self) -> bool:
        """Establish connection to AWS CloudTrail."""
        if not HAS_BOTO3:
            return False

        try:
            kwargs = {"region_name": self.aws_region}
            if self.aws_access_key and self.aws_secret_key:
                kwargs["aws_access_key_id"] = self.aws_access_key
                kwargs["aws_secret_access_key"] = self.aws_secret_key

            self.client = boto3.client("cloudtrail", **kwargs)
            # Test connection
            self.client.describe_trails()
            return True
        except (BotoCoreError, ClientError) as e:
            return False
        except Exception:
            return False

    def _map_severity(self, event_name: str, error_code: str = "") -> str:
        """Map CloudTrail event to GIAM-SAT severity."""
        critical_events = [
            "ConsoleLogin", "DeleteTrail", "StopLogging", "ScheduleKeyDeletion",
            "DeleteUser", "DeleteRole", "DeleteBucketPublicAccessBlock",
        ]
        high_events = [
            "CreateUser", "CreateAccessKey", "AuthorizeSecurityGroupIngress",
            "PutBucketPolicy", "DisableKey", "AttachUserPolicy", "AttachRolePolicy",
            "DeleteAccessKey", "CreateLoginProfile",
        ]
        medium_events = [
            "UpdateUser", "CreateRole", "PutUserPolicy", "RunInstances",
            "TerminateInstances", "PutBucketAcl",
        ]

        if error_code and "AccessDenied" in error_code:
            return "HIGH"
        if event_name in critical_events:
            return "CRITICAL" if not error_code else "HIGH"
        if event_name in high_events:
            return "HIGH"
        if event_name in medium_events:
            return "MEDIUM"
        return "LOW"

    def _format_event(self, event: dict) -> dict:
        """Format CloudTrail event for GIAM-SAT."""
        event_name = event.get("EventName", "Unknown")
        event_time = event.get("EventTime", datetime.now())
        user_identity = event.get("UserIdentity", {})
        error_code = event.get("ErrorCode", "")
        error_message = event.get("ErrorMessage", "")
        source_ip = event.get("SourceIPAddress", "")
        user_agent = event.get("UserAgent", "")
        aws_region = event.get("AwsRegion", self.aws_region)

        # Build user info
        user_type = user_identity.get("Type", "Unknown")
        user_name = (
            user_identity.get("UserName") or
            user_identity.get("Arn", "").split("/")[-1] or
            user_type
        )

        # Build description
        desc_parts = [f"[{aws_region}] {user_name} ({user_type}): {event_name}"]
        if source_ip:
            desc_parts.append(f"from {source_ip}")
        if error_code:
            desc_parts.append(f"- {error_code}: {error_message}")
        if user_agent:
            desc_parts.append(f"via {user_agent[:80]}")

        description = " | ".join(desc_parts)

        return {
            "type": "cloud_event",
            "subtype": "aws_cloudtrail",
            "event_name": event_name,
            "source_ip": source_ip,
            "aws_region": aws_region,
            "user_identity": user_name,
            "user_type": user_type,
            "error_code": error_code,
            "description": description[:500],
            "severity": self._map_severity(event_name, error_code),
            "timestamp": event_time.strftime("%Y-%m-%d %H:%M:%S") if isinstance(event_time, datetime) else str(event_time),
            "raw_event_id": event.get("EventId", ""),
            "user_agent": user_agent[:200],
        }

    def collect_events(self, lookback_minutes: int = 10) -> list:
        """Collect CloudTrail events from the last N minutes."""
        if not self.client:
            return []

        events = []
        start_time = datetime.now() - timedelta(minutes=lookback_minutes)

        try:
            paginator = self.client.get_paginator("lookup_events")

            for page in paginator.paginate(
                StartTime=start_time,
                EndTime=datetime.now(),
                MaxResults=50,
            ):
                for event in page.get("Events", []):
                    try:
                        cloudtrail_event = json.loads(event.get("CloudTrailEvent", "{}"))
                        event_name = cloudtrail_event.get("eventName", "")

                        if event_name in SECURITY_EVENT_NAMES or (
                            cloudtrail_event.get("errorCode") and
                            "AccessDenied" in str(cloudtrail_event.get("errorCode", ""))
                        ):
                            formatted = self._format_event(cloudtrail_event)
                            events.append(formatted)
                            if self.callback:
                                self.callback(formatted)
                    except (json.JSONDecodeError, KeyError):
                        pass

        except (BotoCoreError, ClientError) as e:
            pass
        except Exception:
            pass

        self._last_check = datetime.now()
        return events

    def collect_iam_events(self, lookback_hours: int = 1) -> list:
        """Specifically collect IAM-related events."""
        if not self.client:
            return []

        iam_events = []
        start_time = datetime.now() - timedelta(hours=lookback_hours)
        iam_event_names = [
            "CreateUser", "DeleteUser", "UpdateUser",
            "CreateAccessKey", "DeleteAccessKey",
            "CreateLoginProfile", "DeleteLoginProfile",
            "AttachUserPolicy", "DetachUserPolicy",
            "CreateRole", "DeleteRole",
        ]

        try:
            paginator = self.client.get_paginator("lookup_events")
            for page in paginator.paginate(
                StartTime=start_time,
                EndTime=datetime.now(),
                MaxResults=30,
            ):
                for event in page.get("Events", []):
                    try:
                        ct_event = json.loads(event.get("CloudTrailEvent", "{}"))
                        if ct_event.get("eventName") in iam_event_names:
                            formatted = self._format_event(ct_event)
                            iam_events.append(formatted)
                            if self.callback:
                                self.callback(formatted)
                    except Exception:
                        pass
        except Exception:
            pass

        return iam_events

    def collect_console_logins(self, lookback_hours: int = 24) -> list:
        """Collect AWS Console login events (successful and failed)."""
        if not self.client:
            return []

        login_events = []
        start_time = datetime.now() - timedelta(hours=lookback_hours)

        try:
            paginator = self.client.get_paginator("lookup_events")
            for page in paginator.paginate(
                StartTime=start_time,
                EndTime=datetime.now(),
                LookupAttributes=[{
                    "AttributeKey": "EventName",
                    "AttributeValue": "ConsoleLogin",
                }],
                MaxResults=50,
            ):
                for event in page.get("Events", []):
                    try:
                        ct_event = json.loads(event.get("CloudTrailEvent", "{}"))
                        formatted = self._format_event(ct_event)

                        # Enhance severity based on login outcome
                        if ct_event.get("responseElements", {}).get("ConsoleLogin") == "Failure":
                            formatted["severity"] = "HIGH"
                            formatted["description"] = f"FAILED: {formatted['description']}"
                        else:
                            formatted["severity"] = "LOW"

                        login_events.append(formatted)
                        if self.callback:
                            self.callback(formatted)
                    except Exception:
                        pass
        except Exception:
            pass

        return login_events

    def collect_all(self) -> list:
        """Collect all relevant CloudTrail security events."""
        if not self.connect():
            return []

        all_events = []
        all_events.extend(self.collect_events(lookback_minutes=10))
        all_events.extend(self.collect_console_logins(lookback_hours=24))
        return all_events