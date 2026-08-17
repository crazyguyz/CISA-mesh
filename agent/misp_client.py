"""
MISP Threat Intelligence Client v1.0 for GIAM-SAT v3.8.0
Pulls IOCs (IPs, domains, hashes) from MISP server every 60 minutes.
Integrates with existing ThreatIntel class for dynamic IOC lookup.

Usage:
    from misp_client import MISPClient
    misp = MISPClient(url="https://misp.company.com", api_key="xxx")
    misp.start_auto_refresh()  # Background thread, pull every 60 min
    # Then use misp.check_ip(), misp.check_domain(), misp.check_hash()
"""
import json
import time
import os
import threading
import hashlib
from datetime import datetime

try:
    import urllib.request
    import urllib.error
    HAS_URLLIB = True
except ImportError:
    HAS_URLLIB = False

# Local cache file
_CACHE_DIR = os.path.join(
    os.environ.get("GIAMSAT_DATA_DIR", os.path.join(
        os.environ.get("PROGRAMDATA", os.path.expanduser("~")),
        "GIAM-SAT", "Agent")),
    "misp_cache.json"
)


class MISPClient:
    """MISP Threat Intelligence Feed Client.
    Pulls IOCs from MISP REST API and caches locally.
    Falls back to offline cache if MISP unreachable."""

    def __init__(self, url=None, api_key=None, ssl_verify=True, refresh_interval=3600):
        self.url = url or os.environ.get("MISP_URL", "")
        self.api_key = api_key or os.environ.get("MISP_API_KEY", "")
        self.ssl_verify = ssl_verify
        self.refresh_interval = refresh_interval
        self.lock = threading.Lock()
        self._running = False

        # IOC caches
        self._malicious_ips = {}       # ip -> {tags, last_seen, comment}
        self._malicious_domains = {}   # domain -> {tags, last_seen, comment}
        self._malicious_hashes = {}    # md5/sha1/sha256 -> {tags, last_seen, comment}
        self._last_refresh = 0
        self._event_count = 0

        # Load offline cache
        self._load_cache()

    @property
    def configured(self):
        return bool(self.url and self.api_key)

    # ===================================================================
    # CACHE PERSISTENCE
    # ===================================================================

    def _load_cache(self):
        """Load IOCs from local cache file."""
        try:
            if os.path.exists(_CACHE_DIR):
                with open(_CACHE_DIR, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self._malicious_ips = data.get("ips", {})
                self._malicious_domains = data.get("domains", {})
                self._malicious_hashes = data.get("hashes", {})
                self._last_refresh = data.get("last_refresh", 0)
                self._event_count = data.get("event_count", 0)
                print(f"[MISP] Loaded cache: {len(self._malicious_ips)} IPs, "
                      f"{len(self._malicious_domains)} domains, {len(self._malicious_hashes)} hashes")
        except Exception as e:
            print(f"[MISP] Cache load failed: {e}")

    def _save_cache(self):
        """Save IOCs to local cache file."""
        try:
            os.makedirs(os.path.dirname(_CACHE_DIR), exist_ok=True)
            data = {
                "ips": self._malicious_ips,
                "domains": self._malicious_domains,
                "hashes": self._malicious_hashes,
                "last_refresh": self._last_refresh,
                "event_count": self._event_count,
                "saved_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
            with open(_CACHE_DIR, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"[MISP] Cache save failed: {e}")

    # ===================================================================
    # MISP API PULL
    # ===================================================================

    def refresh(self):
        """Pull latest IOCs from MISP server (last 7 days of events)."""
        if not self.configured:
            return False

        with self.lock:
            try:
                headers = {
                    "Authorization": self.api_key,
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                }
                # Pull attributes from recent events (last 7 days)
                url = f"{self.url}/attributes/restSearch"
                payload = json.dumps({
                    "returnFormat": "json",
                    "limit": 5000,
                    "to_ids": 1,  # Only attributes marked "for IDS"
                    "last": "7d",
                    "includeEventTags": 1,
                    "includeContext": 0,
                }).encode("utf-8")

                req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
                if not self.ssl_verify:
                    import ssl
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    resp = urllib.request.urlopen(req, timeout=60, context=ctx)
                else:
                    resp = urllib.request.urlopen(req, timeout=60)

                data = json.loads(resp.read().decode("utf-8"))
                attributes = data.get("response", {}).get("Attribute", [])

                new_ips = {}
                new_domains = {}
                new_hashes = {}
                event_ids = set()

                for attr in attributes:
                    category = attr.get("category", "")
                    attr_type = attr.get("type", "")
                    value = (attr.get("value") or "").strip()
                    tags = [t.get("name", "") for t in attr.get("Tag", [])]
                    comment = attr.get("comment", "")
                    event_id = attr.get("event_id", "")

                    if not value:
                        continue
                    event_ids.add(event_id)

                    if attr_type in ("ip-src", "ip-dst", "ip"):
                        new_ips[value] = {"tags": tags, "comment": comment, "event_id": event_id}
                    elif attr_type in ("domain", "hostname", "url"):
                        # Extract domain from URL
                        domain = value
                        if "://" in domain:
                            from urllib.parse import urlparse
                            try:
                                domain = urlparse(domain).hostname or domain
                            except Exception:
                                pass
                        new_domains[domain] = {"tags": tags, "comment": comment, "event_id": event_id}
                    elif attr_type in ("md5", "sha1", "sha256", "sha512"):
                        new_hashes[value] = {"tags": tags, "comment": comment, "event_id": event_id}

                # Merge with existing cache (keep older entries, dedup by key)
                self._malicious_ips = new_ips
                self._malicious_domains = new_domains
                self._malicious_hashes = new_hashes
                self._last_refresh = time.time()
                self._event_count = len(event_ids)

                print(f"[MISP] Refreshed: {len(new_ips)} IPs, {len(new_domains)} domains, "
                      f"{len(new_hashes)} hashes from {len(event_ids)} events")
                self._save_cache()
                return True

            except Exception as e:
                print(f"[MISP] Refresh failed: {e}")

                # v3.8.0: Offline fallback — if MISP unreachable but has cache, OK
                if self._malicious_ips or self._malicious_domains:
                    print(f"[MISP] Using offline cache ({len(self._malicious_ips)} IPs, "
                          f"{len(self._malicious_domains)} domains)")
                return False

    # ===================================================================
    # IOC LOOKUP
    # ===================================================================

    def check_ip(self, ip):
        """Check if an IP is in MISP IOC database."""
        if not ip:
            return None
        with self.lock:
            entry = self._malicious_ips.get(ip)
            if entry:
                return {
                    "malicious": True,
                    "reason": entry.get("comment", f"MISP tagged: {', '.join(entry.get('tags', [])[:3])}"),
                    "tags": entry.get("tags", []),
                    "source": "MISP",
                    "event_id": entry.get("event_id", ""),
                }
        return None

    def check_domain(self, domain):
        """Check if a domain is in MISP IOC database."""
        if not domain:
            return None
        domain = domain.lower()
        with self.lock:
            # Exact match
            entry = self._malicious_domains.get(domain)
            if entry:
                return {
                    "malicious": True,
                    "reason": entry.get("comment", f"MISP tagged: {', '.join(entry.get('tags', [])[:3])}"),
                    "tags": entry.get("tags", []),
                    "source": "MISP",
                    "event_id": entry.get("event_id", ""),
                }
            # Suffix match (subdomain of known malicious domain)
            for known_domain, known_entry in self._malicious_domains.items():
                if domain.endswith("." + known_domain):
                    return {
                        "malicious": True,
                        "reason": f"Subdomain of MISP-flagged {known_domain}",
                        "tags": known_entry.get("tags", []),
                        "source": "MISP",
                    }
        return None

    def check_hash(self, file_hash):
        """Check if a file hash (MD5/SHA1/SHA256) is in MISP IOC database."""
        if not file_hash:
            return None
        with self.lock:
            entry = self._malicious_hashes.get(file_hash)
            if entry:
                return {
                    "malicious": True,
                    "reason": entry.get("comment", f"MISP tagged: {', '.join(entry.get('tags', [])[:3])}"),
                    "tags": entry.get("tags", []),
                    "source": "MISP",
                    "event_id": entry.get("event_id", ""),
                }
        return None

    # ===================================================================
    # AUTO-REFRESH BACKGROUND THREAD
    # ===================================================================

    def start_auto_refresh(self):
        """Start background thread that refreshes IOCs periodically."""
        if not self.configured:
            print("[MISP] Not configured (set MISP_URL + MISP_API_KEY env vars)")
            return

        def _refresh_loop():
            self._running = True
            print(f"[MISP] Auto-refresh started (every {self.refresh_interval}s)")
            while self._running:
                try:
                    self.refresh()
                except Exception as e:
                    print(f"[MISP] Refresh loop error: {e}")
                # Sleep in chunks to allow clean shutdown
                for _ in range(self.refresh_interval // 10):
                    if not self._running:
                        break
                    time.sleep(10)

        t = threading.Thread(target=_refresh_loop, daemon=True)
        t.start()

    def stop(self):
        self._running = False

    # ===================================================================
    # STATS
    # ===================================================================

    def get_stats(self):
        with self.lock:
            return {
                "configured": self.configured,
                "ips": len(self._malicious_ips),
                "domains": len(self._malicious_domains),
                "hashes": len(self._malicious_hashes),
                "events": self._event_count,
                "last_refresh": datetime.fromtimestamp(self._last_refresh).strftime(
                    "%Y-%m-%d %H:%M:%S") if self._last_refresh else "never",
            }

    # ===================================================================
    # LOCAL IOC IMPORT (for offline / manual feeds)
    # ===================================================================

    def import_local_feeds(self, ips=None, domains=None, hashes=None, tags=None, comment=""):
        """Manually import IOCs from local feeds (e.g., CSV, text files).
        Useful when MISP server is not available but you have IOC lists."""
        with self.lock:
            tags = tags or ["local"]
            for ip in (ips or []):
                self._malicious_ips[ip] = {"tags": tags, "comment": comment, "event_id": "local"}
            for domain in (domains or []):
                self._malicious_domains[domain.lower()] = {"tags": tags, "comment": comment, "event_id": "local"}
            for h in (hashes or []):
                self._malicious_hashes[h] = {"tags": tags, "comment": comment, "event_id": "local"}
            self._save_cache()
            print(f"[MISP] Imported local: {len(ips or [])} IPs, {len(domains or [])} domains, {len(hashes or [])} hashes")