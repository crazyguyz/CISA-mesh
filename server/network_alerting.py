"""
Network Behavioral Alert Engine v5.0.4
=======================================
NetFlow-based C2 / exfiltration detection that does NOT rely on IP reputation.

A VPS on AWS/cloud is a perfectly normal IP - no blacklist, no "bad" country,
nothing to see at L3/L4. What IS observable is behaviour:

  - NET-BEACON  a source talking to one fixed external dst:port at a regular,
                low-jitter interval (the textbook C2 beacon signature).
  - NET-FIRST   a machine's FIRST-EVER connection to an external destination
                within N days ("novelty" - the fresh-VPS case).
  - NET-ODD     first-seen external connection during off-hours (00:00-05:00)
                -> higher severity.

The destination IP does not need to be "evil": the pattern is the signal.

Runs every GIAMSAT_NET_ALERT_INTERVAL seconds; scans the last
GIAMSAT_NET_ALERT_WINDOW seconds of NetFlow flows. Alerts are persisted to
threat_alerts (dashboard) and pushed to the alerting engine (Telegram/Email/
Slack) with per-rule cooldowns so a long-running server stays quiet.
"""

import os
import threading
import time
from datetime import datetime


def _is_private_ip(ip):
    """RFC1918 + loopback + link-local + multicast/broadcast (mirrors api_netflow)."""
    if not ip:
        return True
    if ip in ("127.0.0.1", "::1", "0.0.0.0", "::"):
        return True
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    if a == 10:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    if a == 169 and b == 254:
        return True
    if a == 224 or a == 255:
        return True
    return False


class NetworkAlertEngine(threading.Thread):
    """Behaviour-based NetFlow alerting (beaconing / first-seen / off-hours)."""

    SCAN_WINDOW_SEC = int(os.environ.get("GIAMSAT_NET_ALERT_WINDOW", "1800"))
    BEACON_MIN_FLOWS = int(os.environ.get("GIAMSAT_NET_BEACON_MIN_FLOWS", "5"))
    BEACON_MIN_SPAN = 120                 # seconds between first and last flow
    BEACON_MAX_CV = 0.30                  # interval coefficient of variation (jitter)
    FIRST_SEEN_DAYS = int(os.environ.get("GIAMSAT_NET_FIRST_SEEN_DAYS", "14"))
    ODD_HOUR_START, ODD_HOUR_END = 0, 5   # local-time window for NET-ODD

    COOLDOWN = {
        "NET-BEACON": 6 * 3600,
        "NET-FIRST": 24 * 3600,
        "NET-ODD": 24 * 3600,
    }

    def __init__(self, db_manager=None, alerting=None):
        super().__init__(daemon=True)
        self.db = db_manager
        self.alerting = alerting
        self.running = True
        self._cooldowns = {}      # (rule, key) -> last alert ts
        self._ip_cache = {}       # src_ip -> (machine_id, hostname)
        self._ip_cache_ts = 0.0

    def stop(self):
        self.running = False

    def run(self):
        interval = int(os.environ.get("GIAMSAT_NET_ALERT_INTERVAL", "60"))
        time.sleep(20)  # let the NetFlow collector + baseline stabilise first
        while self.running:
            time.sleep(interval)
            try:
                self._scan_once()
            except Exception as e:
                print(f"[-] NetworkAlertEngine scan error: {e}")

    # ------------------------------------------------------------------ utils
    def _resolve_machine(self, src_ip):
        """Map src_ip -> (machine_id, hostname) from machines.ip_address (5-min cache)."""
        now = time.time()
        if now - self._ip_cache_ts > 300:
            try:
                self._ip_cache = {}
                for m in (self.db.get_machines() or []):
                    ip = m.get("ip_address") or ""
                    if ip:
                        self._ip_cache[ip] = (m.get("machine_id", ""),
                                              m.get("hostname", "") or m.get("machine_id", ""))
                self._ip_cache_ts = now
            except Exception:
                pass
        return self._ip_cache.get(src_ip, (src_ip, src_ip))

    def _cooldown_ok(self, rule, key):
        now = time.time()
        last = self._cooldowns.get((rule, key), 0)
        if now - last < self.COOLDOWN.get(rule, 3600):
            return False
        self._cooldowns[(rule, key)] = now
        if len(self._cooldowns) > 2000:  # idle-GC (3 days)
            cutoff = now - 86400 * 3
            self._cooldowns = {k: v for k, v in self._cooldowns.items() if v >= cutoff}
        return True


    def _emit(self, rule_id, rule_name, severity, mid, hostname, description,
              dst_ip, src_ip, dst_port):
        alert = {
            "machine_id": mid,
            "hostname": hostname,
            "rule_id": rule_id,
            "rule_name": rule_name,
            "severity": severity,
            "description": description,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "mitre": "T1071.001" if rule_id == "NET-BEACON" else "T1071",
        }
        try:
            if self.db:
                self.db.insert_threat_alert(alert)
        except Exception:
            pass
        if self.alerting:
            try:
                self.alerting.send_alert({
                    "title": f"[{rule_name}] {hostname} [{severity}]",
                    "message": description,
                    "severity": severity,
                    "rule_id": rule_id,
                    "machine_id": mid,
                    "hostname": hostname,
                    "timestamp": alert["timestamp"],
                })
            except Exception:
                pass

    # ------------------------------------------------------------- scan logic
    def _scan_once(self):
        if not self.db:
            return
        now = time.time()
        win_start = now - self.SCAN_WINDOW_SEC
        try:
            flows = self.db.get_netflow_flows(limit=30000, since_hours=1) or []
        except Exception:
            return
        if not flows:
            return

        from collections import defaultdict
        groups = defaultdict(list)   # (src, dst, dport, proto) -> [first ts, ...]
        pairs = set()                # (src, dst) needing a first-seen check
        for f in flows:
            first = f.get("first") or 0
            if first < win_start - 60:   # 60s tolerance for clock skew
                continue
            dst = f.get("dst_ip") or ""
            if _is_private_ip(dst):
                continue
            key = (f.get("src_ip"), dst, f.get("dst_port"), f.get("protocol"))
            groups[key].append(first)
            pairs.add((f.get("src_ip"), dst))
        if not groups:
            return

        # Has each (src, dst) pair ever been seen BEFORE this window?
        seen_before = {}
        for src, dst in pairs:
            try:
                row = self.db.conn.execute(
                    "SELECT 1 FROM netflow_flows WHERE src_ip=? AND dst_ip=? AND first < ? LIMIT 1",
                    (src, dst, win_start)).fetchone()
                seen_before[(src, dst)] = bool(row)
            except Exception:
                # On DB error do not raise first-seen alerts (avoid FP storm)
                seen_before[(src, dst)] = True

        hour = datetime.now().hour
        for (src, dst, dport, proto), times in groups.items():
            mid, hostname = self._resolve_machine(src)

            # --- Beaconing: periodic low-jitter calls to a fixed dst ---
            times_sorted = sorted(t for t in times if t)
            if len(times_sorted) >= self.BEACON_MIN_FLOWS:
                span = times_sorted[-1] - times_sorted[0]
                if span >= self.BEACON_MIN_SPAN:
                    intervals = [times_sorted[i + 1] - times_sorted[i]
                                 for i in range(len(times_sorted) - 1)]
                    mean_i = sum(intervals) / len(intervals)
                    if mean_i > 0:
                        var_i = sum((x - mean_i) ** 2 for x in intervals) / len(intervals)
                        cv = (var_i ** 0.5) / mean_i
                        if cv <= self.BEACON_MAX_CV and self._cooldown_ok("NET-BEACON", f"{src}|{dst}|{dport}"):
                            self._emit(
                                "NET-BEACON",
                                "Periodic C2 Beacon (regular outbound connections)",
                                "HIGH", mid, hostname,
                                f"Source {src} ({hostname}) -> {dst}:{dport} ({proto}): "
                                f"{len(times_sorted)} connections over {int(span)}s at regular "
                                f"intervals (avg {mean_i:.0f}s, jitter CV {cv:.2f}). The pattern - "
                                f"not the destination IP - is the C2 signature.",
                                dst, src, dport)

            # --- First-seen external destination (novelty) ---
            if not seen_before.get((src, dst), True):
                if self.ODD_HOUR_START <= hour < self.ODD_HOUR_END:
                    if self._cooldown_ok("NET-ODD", f"{src}|{dst}"):
                        self._emit(
                            "NET-ODD",
                            "First-seen external connection in off-hours",
                            "HIGH", mid, hostname,
                            f"Source {src} ({hostname}) made its first-ever connection to "
                            f"external destination {dst}:{dport} ({proto}) during off-hours "
                            f"({hour:02d}:00). Fresh cloud VPS destinations look 'normal' - "
                            f"the never-seen-before timing is the anomaly.",
                            dst, src, dport)
                elif self._cooldown_ok("NET-FIRST", f"{src}|{dst}"):
                    self._emit(
                        "NET-FIRST",
                        "First-seen external destination",
                        "MEDIUM", mid, hostname,
                        f"Source {src} ({hostname}) connected to {dst}:{dport} ({proto}) for "
                        f"the first time in the last {self.FIRST_SEEN_DAYS} days. New external "
                        f"destinations are worth a quick check even when the IP looks benign.",
                        dst, src, dport)
