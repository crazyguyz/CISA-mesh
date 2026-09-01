"""
Threat Intel Enrichment (server-side, v5.0.4 Phase2 A9).
OPTIONAL layer used when a behavioural alert already fired - it never blocks or
drives detection (behaviour stays the primary signal).

Sources (all optional, env-gated, rate-limited):
  - Local file: GIAMSAT_INTEL_FILE (JSON {"ips": {"1.2.3.4": "reason"}, "domains": {...}})
  - OTX/AlienVault: GIAMSAT_OTX_API_KEY (one lookup per IP, throttled)
"""

import os
import threading
import time

_last = {}
_lock = threading.Lock()


def _load_local():
    path = os.environ.get("GIAMSAT_INTEL_FILE", "")
    if not path or not os.path.exists(path):
        return {}, {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            import json
            d = json.load(f)
        return d.get("ips", {}), d.get("domains", {})
    except Exception:
        return {}, {}


def check_ip(ip):
    """Return list of intel tags for an IP (local file + optional OTX). Never raises."""
    tags = []
    if not ip:
        return tags
    ips, _ = _load_local()
    if ip in ips:
        tags.append(f"LOCAL:{ips[ip]}")
    key = os.environ.get("GIAMSAT_OTX_API_KEY", "")
    if key:
        with _lock:
            now = time.time()
            if now - _last.get("otx", 0) < 1.0:
                return tags  # rate limit: 1 lookup/sec
            _last["otx"] = now
        try:
            import urllib.request
            req = urllib.request.Request(
                f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                headers={"X-OTX-API-KEY": key})
            with urllib.request.urlopen(req, timeout=5) as r:
                d = json_loads(r.read().decode("utf-8", "ignore"))
            if d.get("pulse_info", {}).get("count", 0) > 0:
                tags.append(f"OTX:{d['pulse_info']['count']} pulses")
        except Exception:
            pass
    return tags


def json_loads(s):
    import json
    return json.loads(s) if s else {}


def check_domain(domain):
    """Return intel tags for a domain (local file only - cheap)."""
    if not domain:
        return []
    _, domains = _load_local()
    if domain in domains:
        return [f"LOCAL:{domains[domain]}"]
    return []
