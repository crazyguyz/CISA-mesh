"""GeoIP organization lookup for GIAM-SAT v5.0.4 (server-side).

Uses the `maxminddb` reader against free db-ip / MaxMind .mmdb files so the
Network/NetFlow views can show which ORGANIZATION a destination IP belongs to
(whois.com style) without loading the agents.

Files (download once, see tools/setup_geolite2.ps1):
  - server/data/dbip-asn-lite.mmdb   -> ASN + organization
  - server/data/dbip-city-lite.mmdb  -> country + city
Override paths via GIAMSAT_GEOIP_ASN_DB / GIAMSAT_GEOIP_CITY_DB.

Everything is optional: if a DB file is missing the lookup returns None and the
UI simply shows "-" (no crash, no agent changes).
"""
import os
import ipaddress
import threading

try:
    import maxminddb as _maxminddb
    _HAS_MMDB = True
except ImportError:
    _HAS_MMDB = False


_DEFAULT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
ASN_DB = os.environ.get("GIAMSAT_GEOIP_ASN_DB",
                        os.path.join(_DEFAULT_DIR, "dbip-asn-lite.mmdb"))
CITY_DB = os.environ.get("GIAMSAT_GEOIP_CITY_DB",
                         os.path.join(_DEFAULT_DIR, "dbip-city-lite.mmdb"))

_CACHE_LIMIT = 2048
_lock = threading.Lock()
_readers = {"asn": None, "city": None}
_cache = {}
_loaded = False


def _get_reader(kind):
    """Lazily open a reader; returns None when the file is missing/corrupt."""
    path = ASN_DB if kind == "asn" else CITY_DB
    if not os.path.exists(path):
        return None
    try:
        return _maxminddb.open_database(path)
    except Exception:
        return None


def _ensure_loaded():
    global _loaded
    if _loaded or not _HAS_MMDB:
        return
    with _lock:
        if _loaded:
            return
        for k in ("asn", "city"):
            if _readers[k] is None:
                _readers[k] = _get_reader(k)
        _loaded = True


def is_private(ip_str):
    """True for RFC1918/link-local/loopback/multicast/reserved - no geo info."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified)
    except Exception:
        return True


def lookup(ip_str, use_cache=True):
    """Return {asn, org, country_iso, country, city} or None.

    Private/reserved IPs return None fast. Reads are safe from any thread.
    """
    if not ip_str or not _HAS_MMDB:
        return None
    ip_str = str(ip_str).strip()
    if is_private(ip_str):
        return None
    _ensure_loaded()
    if use_cache:
        with _lock:
            hit = _cache.get(ip_str)
        if hit is not None:
            return hit if hit else None
    asn_r = _readers.get("asn")
    city_r = _readers.get("city")
    if not asn_r and not city_r:
        return None
    result = {}
    try:
        if asn_r:
            a = asn_r.get(ip_str) or {}
            if a.get("autonomous_system_organization"):
                result["org"] = a["autonomous_system_organization"]
            if a.get("autonomous_system_number"):
                result["asn"] = a["autonomous_system_number"]
        if city_r:
            c = city_r.get(ip_str) or {}
            cc = c.get("country") or {}
            if cc.get("iso_code"):
                result["country_iso"] = cc["iso_code"]
            names = cc.get("names") or {}
            if names.get("en"):
                result["country"] = names["en"]
            city_names = (c.get("city") or {}).get("names") or {}
            if city_names.get("en"):
                result["city"] = city_names["en"]
    except Exception:
        return None
    if not result:
        result = None
    if use_cache:
        with _lock:
            # v5.0.4 (LOW-1): do NOT cache empty/miss results forever - a cache
            # miss for a stale/missing mmdb entry used to be cached as {} so an
            # updated database was never consulted again.
            if result:
                _cache[ip_str] = result
                if len(_cache) > _CACHE_LIMIT:
                    # drop ~half the oldest entries (dict preserves insertion order)
                    for k in list(_cache.keys())[:_CACHE_LIMIT // 2]:
                        _cache.pop(k, None)
            else:
                _cache.pop(ip_str, None)
    return result


def org_label(ip_str):
    """Short label for UI columns: 'Google LLC (AS15169)' or '-'.

    Falls back to country/city when no ASN org is known.
    """
    info = lookup(ip_str)
    if not info:
        return "-"
    parts = []
    if info.get("org"):
        parts.append(info["org"])
        if info.get("asn"):
            parts.append("AS" + str(info["asn"]))
    elif info.get("country"):
        parts.append(info["country"])
    if info.get("city"):
        parts.append(info["city"])
    return " ".join(parts) if parts else "-"
