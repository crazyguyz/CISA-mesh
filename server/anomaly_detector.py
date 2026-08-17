"""
Anomaly Detection Pipeline v1.0.0 for GIAM-SAT Server v3.2.0
Statistical (z-score) + First-Time detection without signature rules.

Purpose: Detect zero-day threats and behavioral anomalies that
         signature-based rules (THREAT-001..076) cannot catch.

Three detectors:
  1. StatisticalDetector: z-score on time-series metrics
  2. FirstTimeDetector: has this (process, IP, user, machine) been seen before?
  3. AnomalyScoreAggregator: combine scores → single alert

Architecture:
  EventWorker._handle_events() → AnomalyDetector.check(event)
    → if anomaly_score >= 50 → insert_threat_alert(ANOMALY-*)
"""

import time
import threading
from collections import defaultdict


class StatisticalDetector:
    """
    Track rolling metrics (event count, network volume, failed logins)
    and trigger when current value exceeds baseline by z-score > 3.
    """

    def __init__(self, window_seconds=3600, history_buckets=168):
        """
        Args:
            window_seconds: Rolling window for current bucket (default: 1h)
            history_buckets: Number of historical buckets for baseline (default: 168 = 7 days)
        """
        self._window = window_seconds
        self._history_buckets = history_buckets
        self._lock = threading.Lock()

        # {metric_key: {"buckets": [count1, count2, ...], "current": count, "window_start": ts}}
        self._metrics = {}

    def _get_key(self, metric_name, machine_id=None, hostname=None):
        parts = [metric_name]
        if machine_id:
            parts.append(machine_id)
        return ":".join(parts)

    def add_value(self, metric_name, value=1, machine_id=None):
        """
        Record a metric value. Returns (anomaly_score 0-100, reason) or (0, "").
        """
        key = self._get_key(metric_name, machine_id)
        now = time.time()

        with self._lock:
            if key not in self._metrics:
                self._metrics[key] = {
                    "buckets": [],
                    "current": 0,
                    "window_start": now - (now % self._window),
                }

            m = self._metrics[key]

            # Rotate window if needed
            if now - m["window_start"] >= self._window:
                m["buckets"].append(m["current"])
                if len(m["buckets"]) > self._history_buckets:
                    m["buckets"].pop(0)
                m["current"] = 0
                m["window_start"] = now - (now % self._window)

            m["current"] += value

            # Need at least 3 buckets for meaningful baseline
            if len(m["buckets"]) < 3:
                return 0, ""

            # Calculate baseline
            values = m["buckets"]
            n = len(values)
            mean = sum(values) / n
            variance = sum((v - mean) ** 2 for v in values) / n
            std_dev = variance ** 0.5

            if std_dev == 0:
                # No variance — only flagg if value is >2x mean
                if m["current"] > mean * 2 and mean > 0:
                    score = min(100, int(50 + (m["current"] / max(mean, 1) - 2) * 25))
                    return score, (
                        f"{metric_name}: {m['current']} (baseline avg={mean:.1f}, "
                        f"no variance, 2x threshold exceeded)"
                    )
                return 0, ""

            z_score = (m["current"] - mean) / std_dev

            if z_score >= 3.0:
                score = min(100, int(50 + (z_score - 3) * 16))
                return score, (
                    f"{metric_name}: current={m['current']} vs baseline "
                    f"mean={mean:.1f} std={std_dev:.1f} z-score={z_score:.2f}"
                )
            elif z_score >= 2.0:
                score = int(25 + (z_score - 2) * 25)
                return score, (
                    f"{metric_name}: current={m['current']} vs baseline "
                    f"mean={mean:.1f} z-score={z_score:.2f} (mild)"
                )

        return 0, ""

    def get_baseline(self, metric_name, machine_id=None):
        """Return (mean, std_dev, n_buckets) for a metric."""
        key = self._get_key(metric_name, machine_id)
        with self._lock:
            m = self._metrics.get(key)
            if not m or len(m["buckets"]) < 3:
                return 0, 0, 0
            values = m["buckets"]
            n = len(values)
            mean = sum(values) / n
            variance = sum((v - mean) ** 2 for v in values) / n
            return mean, variance ** 0.5, n

    def get_stats(self):
        """Return all tracked metrics for monitoring."""
        with self._lock:
            return {
                key: {
                    "current": m["current"],
                    "buckets": len(m["buckets"]),
                    "baseline_avg": sum(m["buckets"]) / len(m["buckets"]) if m["buckets"] else 0,
                }
                for key, m in self._metrics.items()
            }


class FirstTimeDetector:
    """
    Track if a (machine_id, field_type, field_value) combination
    has been seen before. First occurrence = potential anomaly.
    """

    def __init__(self, max_records=100000):
        self._seen = set()  # {(machine_id, field_type, field_value)}
        self._lock = threading.Lock()
        self._max_records = max_records

    def check(self, machine_id, field_type, field_value):
        """
        Check if this combination is new.
        Returns (is_first_time, anomaly_score, reason) tuple.
        """
        if not field_value or not machine_id:
            return False, 0, ""

        key = (machine_id, field_type, field_value.lower() if isinstance(field_value, str) else field_value)

        with self._lock:
            if key not in self._seen:
                # Prevent memory bloat
                if len(self._seen) < self._max_records:
                    self._seen.add(key)
                return True, 50, (
                    f"First time: {field_type}='{field_value}' on machine {machine_id}"
                )
            return False, 0, ""

    def get_stats(self):
        with self._lock:
            return {"unique_combinations": len(self._seen)}


class AnomalyAggregator:
    """
    Aggregate multiple anomaly scores into a single alert.
    Threshold: anomaly_score >= 50 → trigger alert.
    """

    def __init__(self, alert_threshold=50):
        self.alert_threshold = alert_threshold

    def aggregate(self, statistical_scores, first_time_results):
        """
        Args:
            statistical_scores: list of (score, reason) from StatisticalDetector
            first_time_results: list of (is_first, score, reason) from FirstTimeDetector

        Returns:
            dict or None: {"anomaly_score": int, "reasons": [...], "trigger_alert": bool}
        """
        reasons = []
        total_score = 0

        for score, reason in statistical_scores:
            if score > 0:
                reasons.append(f"[Statistical] {reason}")
                total_score = max(total_score, score)

        for is_first, score, reason in first_time_results:
            if is_first:
                reasons.append(f"[FirstTime] {reason}")
                total_score = max(total_score, score)

        if reasons and total_score >= self.alert_threshold:
            return {
                "anomaly_score": min(100, total_score),
                "reasons": reasons,
                "trigger_alert": True,
            }

        return None


class AnomalyDetector:
    """
    Main entry point: combines Statistical + FirstTime detectors.
    Called from EventWorker after batch DB writes.
    """

    def __init__(self):
        self.statistical = StatisticalDetector()
        self.first_time = FirstTimeDetector()
        self.aggregator = AnomalyAggregator()

    def check(self, event):
        """
        Check a single event for anomalies.
        Returns dict or None: {"anomaly_score", "reasons", "trigger_alert"}
        """
        machine_id = event.get("machine_id", "")
        hostname = event.get("hostname", "")
        msg_type = event.get("type", "")

        # ---- Statistical metrics ----
        stats_scores = []

        # Event count spike (per machine)
        s, r = self.statistical.add_value(
            "event_count", value=1, machine_id=machine_id
        )
        if s > 0:
            stats_scores.append((s, r))

        # Sysmon event spike
        if msg_type in ("process_event", "process_injection", "process_access"):
            s, r = self.statistical.add_value(
                "sysmon_event_count", value=1, machine_id=machine_id
            )
            if s > 0:
                stats_scores.append((s, r))

        # Failed login spike (Event 4625)
        if event.get("event_id") in ("4625", 4625):
            s, r = self.statistical.add_value(
                "failed_login_count", value=1, machine_id=machine_id
            )
            if s > 0:
                stats_scores.append((s, r))

        # Network connection count
        if msg_type == "network_traffic":
            s, r = self.statistical.add_value(
                "network_connections", value=1, machine_id=machine_id
            )
            if s > 0:
                stats_scores.append((s, r))

        # ---- First-time detectors ----
        first_time_results = []

        # First time process on this machine
        process_name = event.get("process_name", "")
        if process_name:
            is_first, score, reason = self.first_time.check(
                machine_id, "process", process_name
            )
            if is_first:
                first_time_results.append((is_first, score, reason))

        # First time destination IP from this machine
        dst_ip = event.get("dst_ip", "")
        if dst_ip:
            is_first, score, reason = self.first_time.check(
                machine_id, "dst_ip", dst_ip
            )
            if is_first:
                first_time_results.append((is_first, score, reason))

        # First time parent→child process combo
        parent = event.get("parent_process", "")
        if parent and process_name:
            combo = f"{parent}→{process_name}"
            is_first, score, reason = self.first_time.check(
                machine_id, "parent_child", combo
            )
            if is_first:
                first_time_results.append((is_first, score, reason))

        # ---- Aggregate ----
        return self.aggregator.aggregate(stats_scores, first_time_results)

    def get_stats(self):
        return {
            "statistical_metrics": self.statistical.get_stats(),
            "first_time_combinations": self.first_time.get_stats(),
        }