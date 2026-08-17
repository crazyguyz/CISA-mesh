"""
Behavior Engine v1.0.0 for GIAM-SAT Server v3.2.0
Server-side baseline calculation and anomaly detection for user/machine behavior.

Receives baseline_report events from agents → calculates 30-day rolling baseline
→ compares real-time data → raises alerts when deviation > 2σ.

Architecture:
  Agent BehaviorCollector → TCP → event_queue → Worker → BehaviorEngine.process_report()
    → update baseline → compare → if anomaly → insert threat alert
"""

import time
import threading
from datetime import datetime, timedelta
from collections import defaultdict


class BehaviorEngine:
    """
    Tracks per-machine/per-user behavior metrics and detects deviations.

    Metrics tracked:
      - top_processes_count: number of running processes
      - established_connections: concurrent network connections
      - process_diversity: unique process names seen
    """

    def __init__(self, db_manager=None, baseline_window=30, anomaly_threshold=2.0):
        self.db = db_manager
        self.baseline_window = baseline_window  # days
        self.anomaly_threshold = anomaly_threshold  # z-score

        # In-memory baseline: {machine_id: {metric: [values], ...}}
        self._baselines = {}
        self._lock = threading.Lock()

    def process_report(self, report):
        """
        Process a baseline_report from agent.
        Returns anomaly alert dict or None.
        """
        machine_id = report.get("machine_id", "")
        hostname = report.get("hostname", "")
        timestamp = report.get("timestamp", "")
        metrics = report.get("metrics", {})

        if not machine_id:
            return None

        with self._lock:
            if machine_id not in self._baselines:
                self._baselines[machine_id] = {
                    "process_count": [],
                    "connection_count": [],
                    "unique_processes": [],
                    "last_updated": timestamp,
                }

            baseline = self._baselines[machine_id]
            alerts = []

            # 1. Process count
            procs = metrics.get("top_processes", [])
            proc_count = len(procs)
            alert = self._check_metric(
                baseline, "process_count", proc_count,
                machine_id, hostname, "process count", timestamp
            )
            if alert:
                alerts.append(alert)

            # 2. Connection count
            conn_count = metrics.get("established_connections", 0)
            alert = self._check_metric(
                baseline, "connection_count", conn_count,
                machine_id, hostname, "network connections", timestamp
            )
            if alert:
                alerts.append(alert)

            # 3. Unique process count (diversity)
            unique_procs = len(set(p.get("name", "") for p in procs if p.get("name")))
            alert = self._check_metric(
                baseline, "unique_processes", unique_procs,
                machine_id, hostname, "unique processes", timestamp
            )
            if alert:
                alerts.append(alert)

            baseline["last_updated"] = timestamp

        if alerts:
            return {
                "machine_id": machine_id,
                "hostname": hostname,
                "rule_id": "BL-ANOMALY-002",
                "rule_name": "Behavior Baseline Deviation",
                "severity": "MEDIUM",
                "description": " | ".join(alerts),
                "timestamp": timestamp,
                "type": "behavior_anomaly",
            }
        return None

    def _check_metric(self, baseline, metric_name, current_value,
                      machine_id, hostname, display_name, timestamp):
        """
        Compare current value against baseline.
        Returns alert string or None.
        """
        values = baseline[metric_name]
        values.append(current_value)

        # Keep max 720 values (30 days * 24 hours if hourly)
        max_samples = 720
        if len(values) > max_samples:
            values[:] = values[-max_samples:]

        # Need at least 5 data points for meaningful baseline
        if len(values) < 5:
            return None

        # Calculate mean and std_dev
        n = len(values)
        mean = sum(values) / n
        variance = sum((v - mean) ** 2 for v in values) / n
        std_dev = variance ** 0.5

        if std_dev == 0:
            return None

        z_score = (current_value - mean) / std_dev

        if abs(z_score) >= self.anomaly_threshold:
            direction = "spike" if current_value > mean else "drop"
            return (
                f"{display_name}: current={current_value} vs baseline "
                f"avg={mean:.1f} std={std_dev:.1f} z-score={z_score:.2f} ({direction})"
            )
        return None

    def get_baseline(self, machine_id, metric_name):
        """Return (mean, std_dev, sample_count) for a metric."""
        with self._lock:
            baseline = self._baselines.get(machine_id, {})
            values = baseline.get(metric_name, [])
            if len(values) < 3:
                return 0, 0, 0
            n = len(values)
            mean = sum(values) / n
            variance = sum((v - mean) ** 2 for v in values) / n
            return mean, variance ** 0.5, n

    def get_stats(self):
        with self._lock:
            return {
                "machines_tracked": len(self._baselines),
                "baselines": {
                    mid: {k: len(v) for k, v in b.items() if k != "last_updated"}
                    for mid, b in self._baselines.items()
                },
            }