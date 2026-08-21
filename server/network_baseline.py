"""
Network Baseline Builder v1.0.0 for GIAM-SAT Server v2.6.5
Builds a whitelist of known-good ASN/IP ranges from 14 days of normal traffic.

Problem: NW-005 "New Country" GeoIP rule generates too many false positives
when systems use CDN (Cloudflare, AWS), VPN, or legitimate international services.

Solution: Automatically whitelist ASN/IP ranges seen during 14 days of normal operation.
After 14-day learning period, only TRULY new countries/ASNs trigger alerts.

Usage:
    from network_baseline import NetworkBaseline
    baseline = NetworkBaseline(db_manager)
    baseline.build_baseline()  # Called periodically (e.g., daily)
    is_new = baseline.is_new_country(dst_ip)  # Check before alerting
"""
import os
import re
import json
import time
import sqlite3  # v4.10 FIX: used by the fallback path in _load_baseline_ips
from datetime import datetime, timedelta
from collections import defaultdict

# GeoIP database for country lookup (fallback to simple pattern matching)
# In production, use geoip2.database.Reader with MaxMind GeoLite2-Country.mmdb
try:
    import geoip2.database
    HAS_GEOIP = True
except ImportError:
    HAS_GEOIP = False

# Path to GeoLite2 database (optional)
GEOIP_DB_PATH = os.environ.get("GEOIP_DB_PATH", os.path.join(os.path.dirname(__file__), "GeoLite2-Country.mmdb"))

# How many days of baseline data to collect
BASELINE_DAYS = 14

# Baseline storage (in-memory + SQLite table `network_baseline`)
BASELINE_TABLE = "network_baseline"


class NetworkBaseline:
    """Manages the whitelist of known-good network destinations."""

    def __init__(self, db_manager=None):
        self.db = db_manager
        self.geo_reader = None
        self._whitelist = None  # Cached set of (country_code, asn, ip_prefix)
        self._last_build = 0

        if HAS_GEOIP and os.path.exists(GEOIP_DB_PATH):
            try:
                self.geo_reader = geoip2.database.Reader(GEOIP_DB_PATH)
                print(f"[*] Network Baseline: GeoIP database loaded ({GEOIP_DB_PATH})")
            except Exception as e:
                print(f"[-] Network Baseline: GeoIP load failed: {e}")

    def _lookup_country(self, ip):
        """Look up country code for an IP address.
        Returns country code (e.g., 'US', 'VN') or 'UNKNOWN'.
        """
        if self.geo_reader:
            try:
                response = self.geo_reader.country(ip)
                return response.country.iso_code or "UNKNOWN"
            except Exception:
                pass
        # Fallback: simple private IP detection
        if ip.startswith(("192.168.", "10.", "172.")) and any(
            ip.startswith(f"172.{i}.") for i in range(16, 32)
        ):
            return "PRIVATE"
        if ip.startswith("127."):
            return "LOCALHOST"
        return "UNKNOWN"

    def _extract_asn_from_ip(self, ip):
        """Extract ASN from IP using GeoIP. Returns ASN number or None."""
        if self.geo_reader:
            try:
                response = self.geo_reader.asn(ip)
                return response.autonomous_system_number
            except Exception:
                pass
        return None

    def build_baseline(self):
        """Build/rebuild the whitelist from network events in the last BASELINE_DAYS days.
        Reads dst_ip from events/network_traffic table and resolves country + ASN.
        Stores unique (country_code, ip) pairs in the baseline table.
        """
        if not self.db:
            print("[-] Network Baseline: No db_manager, skipping")
            return

        cutoff = (datetime.now() - timedelta(days=BASELINE_DAYS)).strftime("%Y-%m-%d %H:%M:%S")
        print(f"[*] Network Baseline: Building whitelist from {BASELINE_DAYS}d of traffic (since {cutoff})...")

        # Collect unique destination IPs from events table
        ips = set()
        try:
            # Query network_traffic table (has dst_ip column)
            rows = self.db.conn.execute(
                "SELECT DISTINCT dst_ip FROM network_traffic WHERE timestamp >= ? AND dst_ip IS NOT NULL AND dst_ip != '' LIMIT 50000",
                (cutoff,)
            ).fetchall()
            for row in rows:
                ips.add(row[0])
        except Exception as e:
            print(f"[-] Network Baseline: DB query failed: {e}")
            # Fallback: try sqlite3 directly
            try:
                db_path = os.path.join(os.path.dirname(__file__), "giamsat_data.db")
                if os.path.exists(db_path):
                    conn = sqlite3.connect(db_path)
                    cursor = conn.cursor()
                    cursor.execute(
                        "SELECT DISTINCT dst_ip FROM network_traffic WHERE timestamp >= ? AND dst_ip IS NOT NULL AND dst_ip != '' LIMIT 50000",
                        (cutoff,)
                    )
                    for row in cursor.fetchall():
                        ips.add(row[0])
                    conn.close()
            except Exception:
                pass

        if not ips:
            print("[*] Network Baseline: No network events found in baseline period")
            return

        # Resolve each IP to country + ASN
        baseline_entries = []
        for ip in ips:
            country = self._lookup_country(ip)
            entry = {
                "dst_ip": ip,
                "country_code": country,
            }
            baseline_entries.append(entry)

        # v4.13 (P2): baseline drift guard - flag abnormal one-rebuild expansion
        # (possible baseline poisoning: attacker slowly feeds new destinations so
        # they get whitelisted; or a major environment change). Compare against the
        # previously stored baseline before applying the new one.
        try:
            existing = set()
            try:
                for _row in self.db.conn.execute(f"SELECT dst_ip FROM {BASELINE_TABLE}"):
                    existing.add(_row[0])
            except Exception:
                existing = set()
            new_ips = [e["dst_ip"] for e in baseline_entries if e["dst_ip"] not in existing]
            total = len(existing) + len(new_ips)
            drift_pct = (len(new_ips) * 100.0 / total) if total else 100.0
            _limit = float(os.environ.get("GIAMSAT_BASELINE_DRIFT_LIMIT", "30"))
            if existing and drift_pct > _limit:
                _msg = (f"Network baseline expanded by {drift_pct:.0f}% in one rebuild "
                        f"({len(new_ips)} new destination(s) of {total} total). Possible "
                        f"baseline poisoning or a major environment change - review.")
                print(f"[!] {_msg}")
                try:
                    self.db.insert_threat_alert({
                        "machine_id": "BASELINE",
                        "hostname": "NetworkBaseline",
                        "rule_id": "BASELINE-DRIFT",
                        "rule_name": "Network Baseline Abnormal Expansion",
                        "severity": "HIGH",
                        "description": _msg,
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    })
                except Exception:
                    pass
        except Exception:
            pass

        # Store in database (SQLite-compatible syntax)
        try:
            self.db.conn.execute(f"""
                CREATE TABLE IF NOT EXISTS {BASELINE_TABLE} (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    dst_ip TEXT NOT NULL,
                    country_code TEXT DEFAULT 'UNKNOWN',
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    hit_count INTEGER DEFAULT 1,
                    UNIQUE(dst_ip, country_code)
                )
            """)
            self.db.conn.commit()

            # Upsert entries (INSERT OR REPLACE for SQLite)
            for entry in baseline_entries:
                self.db.conn.execute(f"""
                    INSERT OR REPLACE INTO {BASELINE_TABLE} (id, dst_ip, country_code, first_seen, last_seen, hit_count)
                    VALUES (
                        (SELECT id FROM {BASELINE_TABLE} WHERE dst_ip = ? AND country_code = ?),
                        ?, ?,
                        COALESCE((SELECT first_seen FROM {BASELINE_TABLE} WHERE dst_ip = ? AND country_code = ?), CURRENT_TIMESTAMP),
                        CURRENT_TIMESTAMP,
                        COALESCE((SELECT hit_count FROM {BASELINE_TABLE} WHERE dst_ip = ? AND country_code = ?), 0) + 1
                    )
                """, (entry["dst_ip"], entry["country_code"],
                      entry["dst_ip"], entry["country_code"],
                      entry["dst_ip"], entry["country_code"],
                      entry["dst_ip"], entry["country_code"]))
            self.db.conn.commit()

            # Update in-memory cache
            self._whitelist = None  # Force reload on next check
            self._last_build = time.time()
            print(f"[*] Network Baseline: Whitelist built with {len(baseline_entries)} entries from {len(ips)} unique IPs")
        except Exception as e:
            print(f"[-] Network Baseline: Failed to store baseline: {e}")

    def is_in_baseline(self, dst_ip):
        """Check if an IP (or its country) is in the established baseline.
        Returns True if this destination is known-good (seen before).
        Returns False if truly new (should trigger alert).
        """
        if not self.db:
            return False  # No baseline = everything is "new"

        country = self._lookup_country(dst_ip)

        # PRIVATE/LOCALHOST are always in baseline
        if country in ("PRIVATE", "LOCALHOST"):
            return True

        # Load whitelist cache if needed
        if self._whitelist is None:
            self._load_whitelist()

        # Check exact IP or same country
        key_ip = (country, dst_ip)
        key_country = (country, "*")  # Wildcard for country-level

        if key_ip in self._whitelist or key_country in self._whitelist:
            return True

        return False

    def _load_whitelist(self):
        """Load whitelist from database into memory cache."""
        self._whitelist = set()
        try:
            rows = self.db.conn.execute(
                f"SELECT dst_ip, country_code FROM {BASELINE_TABLE}"
            ).fetchall()
            for row in rows:
                ip, country = row[0], row[1]
                self._whitelist.add((country, ip))
                self._whitelist.add((country, "*"))  # Country-level wildcard
        except Exception:
            pass

    def is_new_country(self, dst_ip):
        """Backward-compatible alias for is_in_baseline (inverted logic).
        Returns True if this country/IP has NOT been seen before → should alert.
        """
        return not self.is_in_baseline(dst_ip)

    def get_stats(self):
        """Return baseline statistics."""
        count = 0
        countries = set()
        try:
            if self.db:
                row = self.db.conn.execute(
                    f"SELECT COUNT(*), COUNT(DISTINCT country_code) FROM {BASELINE_TABLE}"
                ).fetchone()
                if row:
                    count = row[0]
                rows2 = self.db.conn.execute(
                    f"SELECT DISTINCT country_code FROM {BASELINE_TABLE}"
                ).fetchall()
                countries = {r[0] for r in rows2}
        except Exception:
            pass
        return {
            "total_entries": count,
            "unique_countries": len(countries),
            "countries": sorted(countries),
            "last_build": self._last_build,
        }