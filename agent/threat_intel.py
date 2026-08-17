"""
Threat Intelligence Module for GIAM-SAT Agent v3.8.0
v3.8.0: MISP integration — pulls IOCs from MISP server every 60 min.
  - MISP (primary, configurable via MISP_URL + MISP_API_KEY env vars)
  - AlienVault OTX (secondary) + AbuseIPDB (fallback) for dynamic IP lookup.
  - Suspicious domain list (specific, high-trust indicators).
  - All results cached: MISP 60 min, OTX 24h.
Falls back to offline MISP cache if no internet.
"""

import json
import time
import os
import threading
from collections import defaultdict

try:
    import urllib.request
    import urllib.error
    HAS_URLLIB = True
except ImportError:
    HAS_URLLIB = False


# Local cache of known malicious IPs (updated from OTX)
THREAT_CACHE = {}  # ip -> {malicious, tags, last_checked}
CACHE_TTL = 86400  # 24 hours

# v1.3.0: REMOVED KNOWN_MALICIOUS_IPS prefix matching entirely.
# IP prefix matching ("45.155.", "185.220.", etc.) was the #1 source of false positives.
# Dynamic lookup via OTX + AbuseIPDB replaces it.

# Known TOR exit nodes (subset - full list would be larger)
TOR_EXIT_NODES_PATTERNS = []

# Suspicious domains/IPs (high-trust threat intel) - kept because these are specific services
SUSPICIOUS_DOMAINS = {
    "pastebin.com": "Data exfiltration / malware staging",
    "ngrok.io": "Tunneling service (potential C2)",
    "requestbin.net": "Data exfiltration via webhook",
    "webhook.site": "Data exfiltration via webhook",
    "discord.com/api/webhooks": "Data exfiltration via Discord",
}


class ThreatIntel:
    def __init__(self, callback=None):
        self.callback = callback  # Called when malicious IP detected
        self.otx_api_key = ""  # Free OTX key (optional, increases rate limit)
        self.abuseipdb_api_key = ""  # v1.3.0: AbuseIPDB API key (optional)
        self.lock = threading.Lock()
        self.check_count = 0
        self.last_reset = time.time()

        # v3.8.0: MISP Threat Intelligence Feed
        self.misp = None
        try:
            from misp_client import MISPClient
            self.misp = MISPClient()
            self.misp.start_auto_refresh()
            print(f"[THREAT-INTEL] MISP initialized: {self.misp.get_stats()}")
        except ImportError:
            print("[THREAT-INTEL] MISP not available (misp_client.py missing)")
        except Exception as e:
            print(f"[THREAT-INTEL] MISP init failed: {e}")

        # v3.1: API rate limit tracking with auto-backoff
        self._api_call_tracker = {
            "otx": {"calls_last_minute": 0, "window_start": time.time(),
                    "limit_per_minute": 60, "backoff_until": 0},  # Free: 60/min
            "abuseipdb": {"calls_last_day": 0, "day_start": time.time(),
                          "limit_per_day": 1000, "backoff_until": 0},  # Free: 1000/day
        }
        self._rate_limit_lock = threading.Lock()

    def check_ip(self, ip, event_context=None):
        """
        Check if an IP address is malicious.
        Returns dict with {malicious: bool, reason: str, tags: list, confidence: int} or None.
        
        v1.3.0: Uses OTX primary + AbuseIPDB fallback. No prefix matching.
        """
        if not ip or ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172."):
            return None  # Skip private IPs

        # Rate limit: max 30 checks per minute
        with self.lock:
            now = time.time()
            if now - self.last_reset > 60:
                self.check_count = 0
                self.last_reset = now
            if self.check_count > 30:
                return None
            self.check_count += 1

        # Check cache first
        cache_key = f"ip:{ip}"
        if cache_key in THREAT_CACHE:
            cached = THREAT_CACHE[cache_key]
            if time.time() - cached.get("last_checked", 0) < CACHE_TTL:
                if cached.get("malicious"):
                    return cached
                else:
                    return None  # Known clean from cache

        # v1.3.0: Check TOR exit nodes (empty by default, can be populated)
        for pattern in TOR_EXIT_NODES_PATTERNS:
            if pattern in ip:
                result = {"malicious": True, "reason": "TOR exit node", "tags": ["tor", "anonymizer"],
                          "source": "local", "confidence": 60}
                self._cache_result(cache_key, result)
                return result

        # v1.3.0: Primary: OTX API
        result = self._check_otx(ip)
        if result:
            if result.get("malicious"):
                result["confidence"] = self._calc_confidence(result)
                self._cache_result(cache_key, result)
                return result

        # v1.3.0: Fallback: AbuseIPDB
        if not result or not result.get("malicious"):
            result2 = self._check_abuseipdb(ip)
            if result2 and result2.get("malicious"):
                result2["confidence"] = self._calc_confidence(result2)
                self._cache_result(cache_key, result2)
                return result2

        # Cache negative result (clean IP)
        self._cache_result(cache_key, {"malicious": False, "reason": "", "tags": [], "source": "multi",
                                        "clean": True, "confidence": 0})
        return None

    def check_domain(self, domain):
        """Check if a domain is suspicious.
        
        v1.3.0: Only returns positive for specific high-trust suspicious domains.
        Does NOT use prefix/substring matching on IPs.
        """
        for sus_domain, reason in SUSPICIOUS_DOMAINS.items():
            if sus_domain in domain.lower():
                return {"malicious": True, "reason": reason, "tags": ["suspicious-domain"],
                        "source": "local", "confidence": 70}
        return None

    def _check_rate_limit(self, source: str) -> bool:
        """
        Check if we're allowed to make an API call to 'source'.
        Returns True if allowed, False if in backoff.
        v3.1: Tracks per-source call counts and honors backoff on rate limits.
        """
        with self._rate_limit_lock:
            tracker = self._api_call_tracker.get(source)
            if not tracker:
                return True

            now = time.time()

            # Check backoff
            if tracker.get("backoff_until", 0) > now:
                return False

            # Check per-minute limit (OTX)
            if "calls_last_minute" in tracker:
                if now - tracker["window_start"] > 60:
                    tracker["calls_last_minute"] = 0
                    tracker["window_start"] = now
                if tracker["calls_last_minute"] >= tracker.get("limit_per_minute", 60):
                    tracker["backoff_until"] = now + 60
                    return False
                tracker["calls_last_minute"] += 1

            # Check per-day limit (AbuseIPDB)
            if "calls_last_day" in tracker:
                if now - tracker["day_start"] > 86400:
                    tracker["calls_last_day"] = 0
                    tracker["day_start"] = now
                if tracker["calls_last_day"] >= tracker.get("limit_per_day", 1000):
                    tracker["backoff_until"] = now + 3600
                    return False
                tracker["calls_last_day"] += 1

            return True

    def _on_rate_limited(self, source: str, retry_after: int = 60):
        """
        Called when API returns 429 Too Many Requests.
        Sets backoff to avoid hammering the API.
        """
        with self._rate_limit_lock:
            tracker = self._api_call_tracker.get(source)
            if tracker:
                tracker["backoff_until"] = time.time() + retry_after
                print(f"[!] ThreatIntel: {source} rate limited, backing off {retry_after}s")

    def get_rate_limit_stats(self):
        """Return current rate limit tracking stats."""
        with self._rate_limit_lock:
            stats = {}
            for src, tracker in self._api_call_tracker.items():
                stats[src] = {
                    "calls_made": tracker.get("calls_last_minute", tracker.get("calls_last_day", 0)),
                    "backoff_active": tracker.get("backoff_until", 0) > time.time(),
                    "backoff_remaining": max(0, tracker.get("backoff_until", 0) - time.time()),
                }
            return stats

    def _check_otx(self, ip):
        """Query AlienVault OTX for IP reputation."""
        if not HAS_URLLIB:
            return None

        # v3.1: Check rate limit before making API call
        if not self._check_rate_limit("otx"):
            return None

        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
            headers = {"User-Agent": "GIAM-SAT/1.3"}
            if self.otx_api_key:
                headers["X-OTX-API-KEY"] = self.otx_api_key

            req = urllib.request.Request(url, headers=headers)
            response = urllib.request.urlopen(req, timeout=5)
            data = json.loads(response.read().decode("utf-8"))

            pulses = data.get("pulse_info", {}).get("pulses", [])
            if pulses:
                tags = []
                total_pulse_count = 0
                for pulse in pulses[:10]:
                    tags.extend(pulse.get("tags", []))
                    total_pulse_count += 1

                # v1.3.0: Only flag as malicious if has multiple pulses or specific tags
                high_confidence_tags = {"malware", "c2", "botnet", "phishing", "ransomware",
                                        "exploit", "trojan", "apt", "backdoor", "rat"}
                has_high_conf = bool(set(tags) & high_confidence_tags)

                if total_pulse_count >= 3 or has_high_conf:
                    return {
                        "malicious": True,
                        "reason": f"OTX: {total_pulse_count} threat pulses",
                        "tags": list(set(tags))[:10],
                        "source": "otx",
                        "pulse_count": total_pulse_count,
                    }
                else:
                    # v1.3.0: Low pulse count, mark as suspicious but not definitely malicious
                    return {
                        "malicious": False,
                        "suspicious": True,
                        "reason": f"OTX: {total_pulse_count} low-confidence pulses",
                        "tags": list(set(tags))[:10],
                        "source": "otx",
                        "pulse_count": total_pulse_count,
                    }
        except urllib.error.HTTPError as e:
            if e.code == 429:
                # v3.1: Rate limited — back off
                self._on_rate_limited("otx", retry_after=120)
            elif e.code == 404:
                pass  # IP not found in OTX
        except Exception:
            pass  # Network error or API issue

        return None

    def _check_abuseipdb(self, ip):
        """Query AbuseIPDB for IP reputation.
        
        v1.3.0: Added as fallback when OTX has no data.
        Free tier: 1000 checks/day without API key (limited).
        """
        if not HAS_URLLIB:
            return None

        # v3.1: Check rate limit before making API call
        if not self._check_rate_limit("abuseipdb"):
            return None

        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            params = f"ipAddress={ip}&maxAgeInDays=90"
            headers = {
                "User-Agent": "GIAM-SAT/1.3",
                "Accept": "application/json",
            }
            if self.abuseipdb_api_key:
                headers["Key"] = self.abuseipdb_api_key

            full_url = f"{url}?{params}"
            req = urllib.request.Request(full_url, headers=headers)
            response = urllib.request.urlopen(req, timeout=5)
            data = json.loads(response.read().decode("utf-8"))

            abuse_data = data.get("data", {})
            abuse_score = abuse_data.get("abuseConfidenceScore", 0)
            total_reports = abuse_data.get("totalReports", 0)

            if abuse_score >= 80 and total_reports >= 5:
                return {
                    "malicious": True,
                    "reason": f"AbuseIPDB: score {abuse_score}% ({total_reports} reports)",
                    "tags": ["abuseipdb"],
                    "source": "abuseipdb",
                    "abuse_score": abuse_score,
                    "report_count": total_reports,
                }
            elif abuse_score >= 50:
                return {
                    "malicious": False,
                    "suspicious": True,
                    "reason": f"AbuseIPDB: moderate score {abuse_score}% ({total_reports} reports)",
                    "tags": ["abuseipdb-suspicious"],
                    "source": "abuseipdb",
                    "abuse_score": abuse_score,
                    "report_count": total_reports,
                }
        except urllib.error.HTTPError as e:
            if e.code == 429:
                self._on_rate_limited("abuseipdb", retry_after=3600)
        except Exception:
            pass

        return None

    def _calc_confidence(self, result):
        """Calculate confidence score 0-100 based on source and indicators."""
        source = result.get("source", "unknown")
        score = 50  # Base

        if source == "otx":
            pulse_count = result.get("pulse_count", 0)
            score = min(90, 40 + pulse_count * 10)
            # Boost for high-confidence tags
            high_tags = {"malware", "c2", "botnet", "ransomware", "apt"}
            tags = set(result.get("tags", []))
            if tags & high_tags:
                score = min(100, score + 15)
        elif source == "abuseipdb":
            abuse_score = result.get("abuse_score", 0)
            score = min(95, 40 + abuse_score // 2)
        elif source == "local":
            score = 60
        elif source == "otx-suspicious":
            score = 30

        return score

    def _cache_result(self, key, result):
        """Cache threat intel result."""
        result["last_checked"] = time.time()
        THREAT_CACHE[key] = result
        # Limit cache size
        if len(THREAT_CACHE) > 10000:
            old_keys = sorted(THREAT_CACHE.keys(), key=lambda k: THREAT_CACHE[k].get("last_checked", 0))[:5000]
            for k in old_keys:
                del THREAT_CACHE[k]

    def get_stats(self):
        """Return threat intel cache stats."""
        with self.lock:
            total = len(THREAT_CACHE)
            malicious = sum(1 for v in THREAT_CACHE.values() if v.get("malicious"))
            suspicious = sum(1 for v in THREAT_CACHE.values() if v.get("suspicious"))
            clean = sum(1 for v in THREAT_CACHE.values() if v.get("clean"))
            return {"total_cached": total, "malicious_cached": malicious,
                    "suspicious_cached": suspicious, "clean_cached": clean}