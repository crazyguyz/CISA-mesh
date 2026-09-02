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

import ipaddress
import os
import threading
import time
from datetime import datetime, timezone


def _is_private_ip(ip):
    """RFC1918/ULA + loopback + link-local + multicast (IPv4 AND IPv6)."""
    if not ip:
        return True
    try:
        addr = ipaddress.ip_address(ip)
        return (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_multicast or addr.is_unspecified or addr.is_reserved)
    except ValueError:
        return True  # unparseable -> do not alert novelty/beacon on it


class NetworkAlertEngine(threading.Thread):
    """Behaviour-based NetFlow alerting (beaconing / first-seen / off-hours)."""

    SCAN_WINDOW_SEC = int(os.environ.get("GIAMSAT_NET_ALERT_WINDOW", "1800"))
    BEACON_MIN_FLOWS = int(os.environ.get("GIAMSAT_NET_BEACON_MIN_FLOWS", "6"))
    BEACON_MIN_SPAN = int(os.environ.get("GIAMSAT_NET_BEACON_MIN_SPAN", "120"))
    BEACON_MAX_CV = float(os.environ.get("GIAMSAT_NET_BEACON_MAX_CV", "0.30"))
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
        # v5.0.4 R8: seen-before pairs cached between scans (DISTINCT query once)
        self._seen = set()
        self._seen_ts = 0.0

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
        """Map src_ip -> (machine_id, hostname, first_seen_ts) from machines.ip_address (5-min cache)."""
        now = time.time()
        if now - self._ip_cache_ts > 300:
            try:
                self._ip_cache = {}
                for m in (self.db.get_machines() or []):
                    ip = m.get("ip_address") or ""
                    if ip:
                        fs = m.get("first_seen") or ""
                        fs_ts = 0.0
                        try:
                            from datetime import datetime as _dt
                            # v5.0.4 R9: first_seen is stored UTC ('YYYY-MM-DD
                            # HH:MM:SS' = CURRENT_TIMESTAMP). .timestamp() would
                            # treat it as LOCAL time, skewing the <48h learning
                            # window by the server TZ offset. Parse as UTC.
                            import calendar as _cal
                            fs_ts = _cal.timegm(_dt.strptime(str(fs)[:19], "%Y-%m-%d %H:%M:%S").timetuple())
                        except Exception:
                            fs_ts = 0.0
                        self._ip_cache[ip] = (m.get("machine_id", ""),
                                              m.get("hostname", "") or m.get("machine_id", ""),
                                              fs_ts)
                self._ip_cache_ts = now
            except Exception:
                pass
        return self._ip_cache.get(src_ip, (src_ip, src_ip, 0.0))

    def _cooldown_check(self, rule, key):
        """v5.0.4 R8 (LOW-2): check-only - cooldown is MARKED after a successful emit,
        so a failed insert/send does not consume the window and the alert retries."""
        now = time.time()
        return now - self._cooldowns.get((rule, key), 0) >= self.COOLDOWN.get(rule, 3600)

    def _cooldown_mark(self, rule, key):
        self._cooldowns[(rule, key)] = time.time()
        if len(self._cooldowns) > 2000:  # idle-GC (3 days)
            cutoff = time.time() - 86400 * 3
            self._cooldowns = {k: v for k, v in self._cooldowns.items() if v >= cutoff}

    def _emit(self, rule_id, rule_name, severity, mid, hostname, description,
              dst_ip, src_ip, dst_port):
        """Persist + notify. Returns True when at least one side succeeded (so the
        cooldown is only marked on success)."""
        ok = False
        # v5.0.4 (Phase2 A9): optional threat-intel enrichment (never blocks emit)
        try:
            from threat_intel_server import check_ip
            tags = check_ip(dst_ip) if dst_ip else []
            if tags:
                description = description + " | Intel: " + ", ".join(tags)[:300]
        except Exception:
            pass
        alert = {
            "machine_id": mid,
            "hostname": hostname,
            "rule_id": rule_id,
            "rule_name": rule_name,
            "severity": severity,
            "description": description,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "mitre": "T1071.001" if rule_id == "NET-BEACON" else "T1071",
        }
        try:
            if self.db:
                self.db.insert_threat_alert(alert)
                ok = True
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
                ok = True
            except Exception:
                pass
        return ok

    # ------------------------------------------------------------- scan logic
    def _seen_before(self, pairs, win_start):
        """v5.0.4 R8 (HIGH-1): ONE DISTINCT query per scan (cached 5 min) instead
        of one query per (src,dst) pair. Cache tolerates staleness - novelty
        detection only needs 'has this pair ever been seen'. Read is done through
        a db method that holds the backend lock (no raw conn poke)."""
        now = time.time()
        if now - self._seen_ts > 300:
            try:
                if hasattr(self.db, "get_netflow_seen_pairs"):
                    rows = self.db.get_netflow_seen_pairs(win_start) or []
                else:
                    rows = self.db.conn.execute(
                        "SELECT DISTINCT src_ip, dst_ip FROM netflow_flows WHERE first < ?",
                        (win_start,)).fetchall()
                self._seen = set()
                for r in rows:
                    try:
                        self._seen.add((r[0], r[1]))
                    except Exception:
                        self._seen.add((r.get("src_ip"), r.get("dst_ip")))
                self._seen_ts = now
            except Exception:
                pass  # keep previous cache
        return {p: (p in self._seen) for p in pairs}

    def _scan_once(self):
        if not self.db:
            return
        now = time.time()
        win_start = now - self.SCAN_WINDOW_SEC
        try:
            # v5.0.4 R8 (LOW-4): filter by first>=win_start server-side instead of
            # a fixed LIMIT that silently dropped old flows on big networks.
            flows = self.db.get_netflow_flows(limit=500000, since_hours=1,
                                              first_since=win_start - 60) or []
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

        # v5.0.4 (Phase2 A6): weekly baseline - a pair is NOT novel if it was seen
        # at the same weekday+hour in a past week (learned baseline), and brand-new
        # machines (< 48h) are in the learning phase (no novelty alerts).
        # Cached 5 min (R9): the DISTINCT history query is too heavy for every 60s scan.
        try:
            if time.time() - self._seen_ts > 300:
                if hasattr(self.db, "get_netflow_seen_windows"):
                    _wk_rows = self.db.get_netflow_seen_windows(win_start) or []
                else:
                    _wk_rows = []
                self._seen = set()
                for r in _wk_rows:
                    try:
                        self._seen.add((r[0], r[1], str(r[2]), str(r[3])))
                    except Exception:
                        self._seen.add((r.get("src_ip"), r.get("dst_ip"), str(r.get("w")), str(r.get("h"))))
                self._seen_ts = time.time()
            _wk = self._seen
        except Exception:
            _wk = set()
        # v5.0.4 R9 (HIGH-2): weekday + hour must be evaluated in the SAME timezone
        # the baseline was stored in. The DB stores UTC epochs and get_netflow_seen_
        # windows normalizes to UTC weekday/hour -> use UTC now, and zero-pad the
        # hour (%H -> '09') to match the DB text keys ('09'), not str(hour)='9'.
        _now_dt = datetime.now(timezone.utc)
        _today_w = str(_now_dt.isoweekday() % 7)  # Sunday=0 (SQLite %w; PG D normalized to 0-6)
        _today_h = _now_dt.strftime("%H")
        hour = _now_dt.hour
        now_ts = time.time()
        for (src, dst, dport, proto), times in groups.items():
            mid, hostname, first_seen_ts = self._resolve_machine(src)
            learning = (now_ts - first_seen_ts) < 48 * 3600 if first_seen_ts else True

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
                        _bk = f"{src}|{dst}|{dport}"
                        if cv <= self.BEACON_MAX_CV and self._cooldown_check("NET-BEACON", _bk):
                            if self._emit(
                                    "NET-BEACON",
                                    "Periodic C2 Beacon (regular outbound connections)",
                                    "HIGH", mid, hostname,
                                    f"Source {src} ({hostname}) -> {dst}:{dport} ({proto}): "
                                    f"{len(times_sorted)} connections over {int(span)}s at regular "
                                    f"intervals (avg {mean_i:.0f}s, jitter CV {cv:.2f}). The pattern - "
                                    f"not the destination IP - is the C2 signature.",
                                    dst, src, dport):
                                self._cooldown_mark("NET-BEACON", _bk)

            # --- First-seen external destination (novelty, weekly-baseline aware) ---
            # v5.0.4 (Phase2 A6): skip for learning machines (<48h) and for pairs
            # already seen at this weekday+hour in a past week.
            if not learning and (src, dst, _today_w, _today_h) not in _wk:
                if self.ODD_HOUR_START <= hour < self.ODD_HOUR_END:
                    _ok = "NET-ODD"
                    if self._cooldown_check(_ok, f"{src}|{dst}"):
                        if self._emit(
                                "NET-ODD",
                                "First-seen external connection in off-hours",
                                "HIGH", mid, hostname,
                                f"Source {src} ({hostname}) made its first-ever connection to "
                                f"external destination {dst}:{dport} ({proto}) during off-hours "
                                f"({hour:02d}:00). Fresh cloud VPS destinations look 'normal' - "
                                f"the never-seen-before timing is the anomaly.",
                                dst, src, dport):
                            self._cooldown_mark(_ok, f"{src}|{dst}")
                elif self._cooldown_check("NET-FIRST", f"{src}|{dst}"):
                    if self._emit(
                            "NET-FIRST",
                            "First-seen external destination",
                            "MEDIUM", mid, hostname,
                            f"Source {src} ({hostname}) connected to {dst}:{dport} ({proto}) for "
                            f"the first time in the last {self.FIRST_SEEN_DAYS} days. New external "
                            f"destinations are worth a quick check even when the IP looks benign.",
                            dst, src, dport):
                        self._cooldown_mark("NET-FIRST", f"{src}|{dst}")
