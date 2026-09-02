"""GIAM-SAT v5.0.4 (Phase3 improvement #3): user-defined watchlist matcher.

Periodically scans recently-ingested rows (events / network_inspection /
sysmon_events) for configured watch items (ip / domain / hash / url) and raises
threat alert IOC-WATCH-001 per indicator (1h cooldown). The items are managed
through /api/watchlist (manual, bulk import or pushed from reports/intel).

Detection is deliberately additive and best-effort - it never alters the row
flow; a match only inserts a threat alert the same way every other engine does.
"""

import os
import re
import time
import threading


class WatchlistMatcher(threading.Thread):
    """Thread-safe matcher loop (30s interval)."""

    def __init__(self, db_manager=None, alerting=None, interval=30, cooldown_sec=3600):
        super().__init__(daemon=True)
        self.db = db_manager
        self.alerting = alerting
        self.interval = max(10, int(interval))
        self.cooldown_sec = max(60, int(cooldown_sec))
        self.running = True
        self._last_alert = {}  # indicator -> last alert ts (1h cooldown per IOC)
        self._lock = threading.Lock()

    @staticmethod
    def _text_blob(row):
        """Flatten a scan row to searchable lowercase text + IP address set."""
        parts = []
        for key in ("description", "command_line", "file_path", "file_name",
                    "subtype", "domain", "dns_query", "process_name", "process_path"):
            v = row.get(key)
            if v:
                parts.append(str(v))
        raw = row.get("raw_data")
        if isinstance(raw, dict):
            try:
                parts.append(str(raw))
            except Exception:
                pass
        elif isinstance(raw, str) and raw:
            parts.append(raw)
        text = " ".join(parts).lower()
        ips = set()
        for k in ("src_ip", "dst_ip", "ip_address"):
            v = str(row.get(k) or "")
            if v:
                ips.add(v.lower())
        for cand in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
            ips.add(cand)
        for cand in re.findall(r"\b[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){2,7}\b", text):
            ips.add(cand.lower())
        return text, ips

    @staticmethod
    def _auto_type(value):
        """Guess ip/domain/hash/url for an indicator (used by bulk import)."""
        v = (value or "").strip().lower()
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", v):
            return "ip"
        if ":" in v and re.match(r"^[0-9a-f:]+$", v):
            return "ip"
        if re.match(r"^[0-9a-f]{32,64}$", v):
            return "hash"
        if v.startswith(("http://", "https://")):
            return "url"
        if "." in v and " " not in v and not v.startswith("http"):
            return "domain"
        return "domain"

    def _matches(self, item_type, indicator, row):
        text, ips = self._text_blob(row)
        ind = str(indicator).strip().lower()
        if not ind:
            return False
        if item_type == "ip":
            if ind in ips:
                return True
            return (" " + ind + " ") in (" " + text + " ")
        if item_type == "hash":
            if len(ind) < 16 or not all(c in "0123456789abcdef" for c in ind):
                return False
            return ind in text
        if item_type == "url":
            return ind in text
        # domain
        if ind in text:
            return True
        d = str(row.get("domain") or row.get("dns_query") or "").strip().lower()
        return bool(d) and (d == ind or d.endswith("." + ind))


    def _scan_once(self):
        items = []
        try:
            if self.db and hasattr(self.db, "get_watchlist_items"):
                items = self.db.get_watchlist_items() or []
        except Exception:
            return
        if not items:
            return
        rows = []
        try:
            if hasattr(self.db, "fetch_watch_scan_rows"):
                rows = self.db.fetch_watch_scan_rows(since_sec=max(60, self.interval * 2), limit=800) or []
        except Exception:
            return
        if not rows:
            return
        now = time.time()
        agg = {}
        for ind, item_type, sev in items:  # items = (indicator, type, severity)
            key = f"{item_type}|{ind}"
            if now - self._last_alert.get(key, 0) < self.cooldown_sec:
                continue
            hits = []
            for row in rows:
                try:
                    if self._matches(item_type, ind, row):
                        hits.append(row)
                        if len(hits) >= 5:
                            break
                except Exception:
                    continue
            if hits:
                agg[key] = (item_type, ind, sev, hits)
        with self._lock:
            for key, (item_type, ind, sev, hits) in agg.items():
                try:
                    self._emit(item_type, ind, sev, hits)
                    self._last_alert[key] = time.time()
                except Exception:
                    pass

    def _emit(self, item_type, ind, sev, hits):
        if not self.db:
            return
        lines = []
        machines = set()
        for h in hits[:5]:
            mid = h.get("machine_id") or ""
            if mid:
                machines.add(mid)
            host = h.get("hostname") or mid or "?"
            rid = h.get("id")
            kind = h.get("kind", "events")
            lines.append(f"[{kind}#{rid}] {host} ({h.get('subtype') or h.get('event_id') or ''})")
        desc = (f"[Watchlist] {item_type.upper()} '{ind}' ({sev}) appeared on: "
                + "; ".join(lines))
        machine_id = ",".join(sorted(machines))[:200] or "WATCHLIST"
        try:
            from datetime import datetime
            self.db.insert_threat_alert({
                "machine_id": machine_id,
                "hostname": (hits[0].get("hostname") or "unknown")[:255],
                "rule_id": "IOC-WATCH-001",
                "rule_name": f"Watchlist hit: {item_type}",
                "severity": sev.upper(),
                "description": desc[:2000],
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "source_ip": str(hits[0].get("src_ip") or ""),
            })
            if self.alerting is not None:
                try:
                    self.alerting.send_alert({
                        "severity": sev.upper(),
                        "rule_id": "IOC-WATCH-001",
                        "rule_name": f"Watchlist hit: {item_type}",
                        "machine_id": machine_id,
                        "hostname": (hits[0].get("hostname") or "unknown")[:255],
                        "description": desc[:2000],
                        "mitre": "T1583.001",
                        "tactic": "Resource Development",
                    })
                except Exception:
                    pass
        except Exception:
            pass

    def run(self):
        while self.running:
            try:
                self._scan_once()
            except Exception:
                pass
            time.sleep(self.interval)

    def stop(self):
        self.running = False
