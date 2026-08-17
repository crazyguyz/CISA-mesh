"""
Kubernetes Audit Log Collector for GIAM-SAT Agent v1.13.0

Collects Kubernetes security events from:
  - Kubernetes Audit Logs (API server audit)
  - Pod security violations
  - RBAC changes
  - Network policy violations
  - Secret access monitoring

Requirements: kubectl configured, or kubeconfig for cluster access.
"""

import os
import sys
import subprocess
import json
import time
import threading
import re
from datetime import datetime, timedelta


def _run(cmd, timeout=15, **kwargs):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, **kwargs)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", "timeout", -1
    except Exception as e:
        return "", str(e), -1


class K8sAuditCollector:
    """Collects Kubernetes security events."""

    def __init__(self, callback=None, kubeconfig_path: str = None):
        self.callback = callback
        self.running = False
        self.thread = None
        self.kubeconfig = kubeconfig_path or os.environ.get("KUBECONFIG", "")
        self._kubectl_base = ["kubectl"]
        if self.kubeconfig:
            self._kubectl_base.extend(["--kubeconfig", self.kubeconfig])

    def _kubectl(self, args, timeout=15):
        """Run kubectl command."""
        return _run(self._kubectl_base + args, timeout=timeout)

    def check_available(self) -> bool:
        """Check if kubectl is accessible."""
        stdout, stderr, rc = self._kubectl(["version", "--client"], timeout=10)
        return rc == 0 and "Client Version" in stdout

    def collect_pod_security_events(self) -> list:
        """Collect pod security context violations."""
        events = []
        try:
            stdout, stderr, rc = self._kubectl([
                "get", "events", "--all-namespaces",
                "--field-selector", "type=Warning",
                "-o", "json",
            ], timeout=20)

            if rc == 0 and stdout:
                data = json.loads(stdout)
                for item in data.get("items", []):
                    ev = {
                        "type": "k8s_event",
                        "subtype": "pod_security",
                        "namespace": item.get("metadata", {}).get("namespace", ""),
                        "name": item.get("metadata", {}).get("name", ""),
                        "reason": item.get("reason", ""),
                        "description": f"[{item.get('involvedObject', {}).get('kind', '')}] {item.get('message', '')}",
                        "severity": "HIGH" if "fail" in item.get("message", "").lower() else "MEDIUM",
                        "timestamp": item.get("lastTimestamp", item.get("metadata", {}).get("creationTimestamp", "")),
                    }
                    events.append(ev)
        except Exception:
            pass
        return events

    def collect_rbac_events(self) -> list:
        """Detect recent RBAC changes."""
        events = []
        try:
            # Check for recent ClusterRoleBinding changes
            stdout, stderr, rc = self._kubectl([
                "get", "events", "--all-namespaces",
                "--field-selector", "reason=ClusterRoleBinding",
                "-o", "json",
            ], timeout=20)

            if rc == 0 and stdout:
                data = json.loads(stdout)
                for item in data.get("items", []):
                    ev = {
                        "type": "k8s_event",
                        "subtype": "rbac_change",
                        "namespace": item.get("metadata", {}).get("namespace", ""),
                        "name": item.get("metadata", {}).get("name", ""),
                        "description": f"RBAC change: {item.get('message', '')}",
                        "severity": "HIGH",
                        "timestamp": item.get("lastTimestamp", ""),
                    }
                    events.append(ev)
        except Exception:
            pass
        return events

    def collect_secret_access(self) -> list:
        """Monitor secret access patterns."""
        events = []
        try:
            stdout, stderr, rc = self._kubectl([
                "get", "events", "--all-namespaces",
                "--field-selector", "involvedObject.kind=Secret",
                "-o", "json",
            ], timeout=20)

            if rc == 0 and stdout:
                data = json.loads(stdout)
                for item in data.get("items", []):
                    ev = {
                        "type": "k8s_event",
                        "subtype": "secret_access",
                        "namespace": item.get("metadata", {}).get("namespace", ""),
                        "name": item.get("involvedObject", {}).get("name", ""),
                        "description": f"[Secret] {item.get('message', '')}",
                        "severity": "CRITICAL" if "access" in item.get("message", "").lower() else "MEDIUM",
                        "timestamp": item.get("lastTimestamp", ""),
                    }
                    events.append(ev)
        except Exception:
            pass
        return events

    def collect_network_policy_violations(self) -> list:
        """Detect network policy violations."""
        events = []
        try:
            stdout, stderr, rc = self._kubectl([
                "get", "events", "--all-namespaces",
                "--field-selector", "reason=NetworkPolicy",
                "-o", "json",
            ], timeout=20)

            if rc == 0 and stdout:
                data = json.loads(stdout)
                for item in data.get("items", []):
                    events.append({
                        "type": "k8s_event",
                        "subtype": "network_policy",
                        "namespace": item.get("metadata", {}).get("namespace", ""),
                        "description": f"[NetworkPolicy] {item.get('message', '')}",
                        "severity": "MEDIUM",
                        "timestamp": item.get("lastTimestamp", ""),
                    })
        except Exception:
            pass
        return events

    def check_cluster_security(self) -> list:
        """Check Kubernetes cluster security posture."""
        findings = []

        # Check for privileged pods
        try:
            stdout, stderr, rc = self._kubectl([
                "get", "pods", "--all-namespaces",
                "-o", "jsonpath={range .items[*]}{.metadata.namespace}{'/'}{.metadata.name}{': '}{.spec.containers[*].securityContext.privileged}{'\\n'}{end}",
            ], timeout=20)

            if stdout:
                privileged = [line for line in stdout.split("\n") if "true" in line.lower()]
                if privileged:
                    findings.append({
                        "type": "sca_event",
                        "check_id": "K8S-PRIVILEGED",
                        "title": "Privileged Pods",
                        "status": "FAIL",
                        "severity": "CRITICAL",
                        "description": f"{len(privileged)} privileged pods running",
                        "remediation": "Remove privileged security context from pods",
                    })
                else:
                    findings.append({
                        "type": "sca_event",
                        "check_id": "K8S-PRIVILEGED",
                        "title": "Privileged Pods",
                        "status": "PASS",
                        "severity": "LOW",
                        "description": "No privileged pods running",
                    })
        except Exception:
            pass

        # Check for pods running as root
        try:
            stdout, stderr, rc = self._kubectl([
                "get", "pods", "--all-namespaces",
                "-o", "jsonpath={range .items[?(@.spec.containers[*].securityContext.runAsNonRoot != true)]}{.metadata.namespace}{'/'}{.metadata.name}{': runAsNonRoot not set'}{'\\n'}{end}",
            ], timeout=20)

            if stdout and stdout.strip():
                root_pods = [l for l in stdout.split("\n") if l.strip()]
                findings.append({
                    "type": "sca_event",
                    "check_id": "K8S-ROOT",
                    "title": "Pods Running as Root",
                    "status": "FAIL",
                    "severity": "HIGH",
                    "description": f"{len(root_pods)} pods may run as root",
                    "remediation": "Set runAsNonRoot: true and runAsUser > 0",
                })
            else:
                findings.append({
                    "type": "sca_event",
                    "check_id": "K8S-ROOT",
                    "title": "Pods Running as Root",
                    "status": "PASS",
                    "severity": "LOW",
                    "description": "All pods have runAsNonRoot configured",
                })
        except Exception:
            pass

        return findings

    def collect_all(self) -> list:
        """Collect all K8s security events."""
        if not self.check_available():
            return []

        all_events = []
        all_events.extend(self.collect_pod_security_events())
        all_events.extend(self.collect_rbac_events())
        all_events.extend(self.collect_secret_access())
        all_events.extend(self.collect_network_policy_violations())
        all_events.extend(self.check_cluster_security())

        for ev in all_events:
            if self.callback:
                self.callback(ev)

        return all_events