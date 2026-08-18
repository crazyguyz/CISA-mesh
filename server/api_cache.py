"""
API Cache Layer v1.0.0 for GIAM-SAT Server v3.0.0
Redis-backed response cache + PostgreSQL materialized views.

Purpose: Reduce database load from dashboard refreshes.
  1000 agents → heavy dashboard queries (stats, machines, event_types)
  Without cache: every API call ← DB query
  With cache:  first call → DB → Redis → serve from Redis for TTL seconds

Usage:
  from api_cache import ApiCache
  cache = ApiCache(db_manager, redis_config=None)  # None = in-memory fallback

  # In API route:
  data = cache.get_or_set("machines_list", lambda: core.db.get_machines(), ttl=15)

Configuration:
  GIAMSAT_CACHE_TTL=15  (default seconds for dashboard cache)
"""
import os
import json
import time
import threading
from collections import OrderedDict

try:
    import redis
    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False


class ApiCache:
    """Redis-backed API response cache with in-memory fallback."""

    def __init__(self, db_manager=None, config=None):
        self.db = db_manager
        self._redis = None
        self._mem_cache = OrderedDict()
        self._mem_lock = threading.Lock()
        self._mem_max_size = 100
        self._stats = {"hits": 0, "misses": 0, "sets": 0}

        cfg = config or {}
        redis_host = cfg.get("host") or os.environ.get("GIAMSAT_REDIS_HOST", "127.0.0.1")
        redis_port = int(cfg.get("port") or os.environ.get("GIAMSAT_REDIS_PORT", "6379"))
        redis_db = int(cfg.get("db") or os.environ.get("GIAMSAT_REDIS_DB", "1"))  # DB 1 for cache
        # v4.10 (MED-15): read Redis password (was silently connecting unauthenticated)
        redis_password = cfg.get("password") or os.environ.get("GIAMSAT_REDIS_PASSWORD", "") or None

        self.default_ttl = int(os.environ.get("GIAMSAT_CACHE_TTL", "15"))

        if HAS_REDIS:
            try:
                self._redis = redis.Redis(
                    host=redis_host, port=redis_port, db=redis_db,
                    password=redis_password,
                    decode_responses=True,
                    socket_connect_timeout=2, socket_timeout=2,
                )
                self._redis.ping()
                print(f"[*] API Cache: Redis connected (DB {redis_db})")
            except Exception:
                self._redis = None

        if not self._redis:
            print("[*] API Cache: Using in-memory fallback")

    def _cache_key(self, prefix, *args):
        """Generate Redis key from prefix and arguments."""
        return f"giamsat:cache:{prefix}:" + ":".join(str(a) for a in args)

    def get_or_set(self, key, factory_fn, ttl=None):
        """Get from cache, or call factory_fn and cache result.
        
        Args:
            key: Cache key string
            factory_fn: Callable that returns data (only called on cache miss)
            ttl: Seconds until expiry (default: self.default_ttl)
        
        Returns:
            Cached data (dict/list) or fresh result from factory_fn
        """
        ttl = ttl or self.default_ttl
        cache_key = self._cache_key("api", key)

        # Try Redis
        if self._redis:
            try:
                cached = self._redis.get(cache_key)
                if cached is not None:
                    self._stats["hits"] += 1
                    return json.loads(cached)
            except Exception:
                pass

        # Try in-memory
        with self._mem_lock:
            if cache_key in self._mem_cache:
                entry = self._mem_cache[cache_key]
                if time.time() - entry["ts"] < ttl:
                    self._mem_cache.move_to_end(cache_key)
                    self._stats["hits"] += 1
                    return entry["data"]

        # Cache miss — call factory
        self._stats["misses"] += 1
        try:
            data = factory_fn()
        except Exception:
            return None

        # Store in cache
        json_data = json.dumps(data, ensure_ascii=False, default=str)
        if self._redis:
            try:
                self._redis.setex(cache_key, ttl, json_data)
            except Exception:
                pass

        with self._mem_lock:
            self._mem_cache[cache_key] = {"data": data, "ts": time.time()}
            self._mem_cache.move_to_end(cache_key)
            if len(self._mem_cache) > self._mem_max_size:
                self._mem_cache.popitem(last=False)
        self._stats["sets"] += 1

        return data

    def invalidate(self, key):
        """Remove a specific cache entry."""
        cache_key = self._cache_key("api", key)
        if self._redis:
            try:
                self._redis.delete(cache_key)
            except Exception:
                pass
        with self._mem_lock:
            self._mem_cache.pop(cache_key, None)

    def invalidate_all(self):
        """Clear all API cache entries."""
        if self._redis:
            try:
                keys = self._redis.keys("giamsat:cache:api:*")
                if keys:
                    self._redis.delete(*keys)
            except Exception:
                pass
        with self._mem_lock:
            self._mem_cache.clear()
        self._stats = {"hits": 0, "misses": 0, "sets": 0}

    def get_stats(self):
        """Return cache statistics."""
        stats = {
            "backend": "redis" if self._redis else "memory",
            "hits": self._stats["hits"],
            "misses": self._stats["misses"],
            "hit_ratio": 0,
        }
        total = self._stats["hits"] + self._stats["misses"]
        if total > 0:
            stats["hit_ratio"] = round(self._stats["hits"] / total * 100, 1)
        if self._redis:
            try:
                stats["redis_keys"] = self._redis.dbsize()
            except Exception:
                stats["redis_keys"] = 0
        else:
            with self._mem_lock:
                stats["mem_entries"] = len(self._mem_cache)
        return stats

    # =========================================================================
    # PostgreSQL Materialized Views (for high-volume stats queries)
    # =========================================================================

    def setup_materialized_views(self):
        """Create PostgreSQL materialized views for dashboard stats.
        These dramatically speed up /api/stats and /api/machines queries.
        Only works with PostgreSQL backend.
        """
        if not self.db or not hasattr(self.db, '_connected'):
            return

        views = {
            "mv_dashboard_machines": """
                CREATE MATERIALIZED VIEW IF NOT EXISTS mv_dashboard_machines AS
                SELECT m.*, 
                       COALESCE(u.user_name, '') as user_name,
                       COALESCE(u.employee_id, '') as employee_id,
                       COALESCE(u.email, '') as email,
                       COALESCE(t.cnt, 0) as alert_threats,
                       COALESCE(v.cnt, 0) as alert_vulns,
                       COALESCE(y.cnt, 0) as alert_yara,
                       NOW() as refreshed_at
                FROM machines m
                LEFT JOIN machine_users u ON m.machine_id = u.machine_id
                LEFT JOIN (
                    SELECT machine_id, COUNT(*) as cnt
                    FROM threat_alerts
                    WHERE received_at > NOW() - INTERVAL '24 hours'
                    GROUP BY machine_id
                ) t ON m.machine_id = t.machine_id
                LEFT JOIN (
                    SELECT machine_id, COUNT(*) as cnt
                    FROM vuln_alerts
                    WHERE received_at > NOW() - INTERVAL '30 days'
                    GROUP BY machine_id
                ) v ON m.machine_id = v.machine_id
                LEFT JOIN (
                    SELECT machine_id, COUNT(*) as cnt
                    FROM yara_alerts
                    WHERE received_at > NOW() - INTERVAL '30 days'
                    GROUP BY machine_id
                ) y ON m.machine_id = y.machine_id
            """,
            "mv_dashboard_stats": """
                CREATE MATERIALIZED VIEW IF NOT EXISTS mv_dashboard_stats AS
                SELECT
                    (SELECT COUNT(*) FROM machines) as total_machines,
                    (SELECT COUNT(*) FROM machines WHERE is_online = 1) as online_machines,
                    (SELECT COUNT(*) FROM events WHERE received_at > NOW() - INTERVAL '24 hours') as events_24h,
                    (SELECT COUNT(*) FROM sysmon_events WHERE received_at > NOW() - INTERVAL '24 hours') as sysmon_24h,
                    (SELECT COUNT(*) FROM threat_alerts WHERE received_at > NOW() - INTERVAL '24 hours') as threats_24h,
                    (SELECT COUNT(*) FROM vuln_alerts) as total_vulns,
                    (SELECT COUNT(*) FROM yara_alerts WHERE received_at > NOW() - INTERVAL '30 days') as yara_30d,
                    NOW() as refreshed_at
            """,
        }

        for name, sql in views.items():
            try:
                self.db._execute(sql)
                # Create unique index for concurrent refresh
                self.db._execute(f"CREATE UNIQUE INDEX IF NOT EXISTS {name}_idx ON {name} (refreshed_at)")
                print(f"[*] API Cache: Materialized view {name} created")
            except Exception as e:
                print(f"[-] API Cache: Failed to create {name}: {e}")

    def refresh_materialized_views(self):
        """Refresh all materialized views concurrently.
        Call periodically (every 30s) from a background thread.
        """
        if not self.db or not hasattr(self.db, '_connected'):
            return
        views = ["mv_dashboard_machines", "mv_dashboard_stats"]
        for name in views:
            try:
                self.db._execute(f"REFRESH MATERIALIZED VIEW CONCURRENTLY {name}")
            except Exception:
                # CONCURRENTLY might fail if no unique index — try non-concurrent
                try:
                    self.db._execute(f"REFRESH MATERIALIZED VIEW {name}")
                except Exception:
                    pass

    def get_dashboard_stats_cached(self):
        """Get dashboard stats from materialized view (PostgreSQL) or direct query (SQLite)."""
        if self.db and hasattr(self.db, '_connected') and self._redis:
            try:
                result = self.db._execute(
                    "SELECT * FROM mv_dashboard_stats ORDER BY refreshed_at DESC LIMIT 1",
                    fetch=True
                )
                if result:
                    return {
                        "total_machines": result.get("total_machines", 0),
                        "online_machines": result.get("online_machines", 0),
                        "events": result.get("events_24h", 0),
                        "sysmon": result.get("sysmon_24h", 0),
                        "threats": result.get("threats_24h", 0),
                        "vulns": result.get("total_vulns", 0),
                        "yara": result.get("yara_30d", 0),
                        "refreshed_at": str(result.get("refreshed_at", "")),
                    }
            except Exception:
                pass
        # Fallback: direct query
        if self.db:
            return self.db.get_stats()
        return {}