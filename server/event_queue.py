"""
Event Queue v1.1.0 for GIAM-SAT Server v3.1.0
Abstract base + Redis-backed event buffer with in-memory fallback.

v3.1: Extracted BaseEventQueue abstract interface so RabbitMQEventQueue
      can also be used via GIAMSAT_QUEUE_BACKEND=rabbitmq.

Purpose: Decouple TCP Server from Database writes.
  1000 agents × 100 events/s each = 100,000 events/s
  Without queue: TCP thread blocked waiting for DB commit (50-200ms) → bottleneck
  With queue:    TCP thread pushes to Redis in <1ms → DB workers pull in batch

Architecture:
  TCP Server → event_queue.push(event) → Redis List → Worker Pool → DB batch write

Configuration:
  GIAMSAT_REDIS_HOST=127.0.0.1   (default)
  GIAMSAT_REDIS_PORT=6379         (default)
  GIAMSAT_REDIS_DB=0              (default)
  GIAMSAT_REDIS_PASSWORD=         (optional)
  
  If Redis is not available, falls back to in-memory deque.
"""
import os
import json
import time
import threading
from abc import ABC, abstractmethod
from collections import deque

try:
    import redis
    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False


# Queue names
QUEUE_EVENTS = "giamsat:queue:events"
QUEUE_SYSMON = "giamsat:queue:sysmon"
QUEUE_NETWORK = "giamsat:queue:network"
QUEUE_THREATS = "giamsat:queue:threats"
QUEUE_HEARTBEATS = "giamsat:queue:heartbeats"
QUEUE_FIM = "giamsat:queue:fim"
QUEUE_ALERTS = "giamsat:queue:alerts"  # yara, vuln, threats

# Default max queue size (in-memory fallback)
MAX_QUEUE_SIZE = 100000


class BaseEventQueue(ABC):
    """Abstract base class for event queue backends (Redis, RabbitMQ, etc.)."""

    @abstractmethod
    def push(self, queue_name, event_data):
        """Push a raw event dict to a named queue."""
        ...

    @abstractmethod
    def push_event(self, event):
        """Route event to the appropriate queue based on event type."""
        ...

    @abstractmethod
    def pop_batch(self, queue_name, batch_size=100, timeout=1):
        """Pop up to batch_size events from a queue. Returns list of dicts."""
        ...

    @abstractmethod
    def get_stats(self):
        """Return queue statistics dict."""
        ...

    @abstractmethod
    def clear_all(self):
        """Purge all queues."""
        ...


class EventQueue(BaseEventQueue):
    """High-performance event buffer with Redis backend and in-memory fallback."""

    def __init__(self, config=None):
        self._redis = None
        self._mem_queues = {
            QUEUE_EVENTS: deque(maxlen=MAX_QUEUE_SIZE),
            QUEUE_SYSMON: deque(maxlen=MAX_QUEUE_SIZE),
            QUEUE_NETWORK: deque(maxlen=MAX_QUEUE_SIZE),
            QUEUE_THREATS: deque(maxlen=MAX_QUEUE_SIZE),
            QUEUE_HEARTBEATS: deque(maxlen=MAX_QUEUE_SIZE // 10),
            QUEUE_FIM: deque(maxlen=MAX_QUEUE_SIZE // 10),
            QUEUE_ALERTS: deque(maxlen=MAX_QUEUE_SIZE // 10),
        }
        self._mem_lock = threading.Lock()
        self._stats = {
            "pushed": 0,
            "popped": 0,
            "dropped": 0,
        }

        cfg = config or {}
        redis_host = cfg.get("host") or os.environ.get("GIAMSAT_REDIS_HOST", "127.0.0.1")
        redis_port = int(cfg.get("port") or os.environ.get("GIAMSAT_REDIS_PORT", "6379"))
        redis_db = int(cfg.get("db") or os.environ.get("GIAMSAT_REDIS_DB", "0"))
        redis_password = cfg.get("password") or os.environ.get("GIAMSAT_REDIS_PASSWORD", None)

        if HAS_REDIS:
            try:
                self._redis = redis.Redis(
                    host=redis_host,
                    port=redis_port,
                    db=redis_db,
                    password=redis_password or None,
                    decode_responses=True,
                    socket_connect_timeout=3,
                    socket_timeout=3,
                )
                self._redis.ping()
                print(f"[*] Event Queue: Redis connected ({redis_host}:{redis_port})")
            except Exception as e:
                print(f"[-] Event Queue: Redis connection failed ({e}), using in-memory fallback")
                self._redis = None
        else:
            print("[*] Event Queue: redis-py not installed, using in-memory fallback")

    @property
    def has_redis(self):
        return self._redis is not None

    def push(self, queue_name, event_data):
        """IMPL: BaseEventQueue — Push an event to the queue."""
        try:
            json_str = json.dumps(event_data, ensure_ascii=False, default=str)
            if self._redis:
                self._redis.rpush(queue_name, json_str)
            else:
                with self._mem_lock:
                    q = self._mem_queues.get(queue_name)
                    if q is not None:
                        q.append(json_str)
            self._stats["pushed"] += 1
        except Exception:
            self._stats["dropped"] += 1
            pass  # Silent fail — don't block the TCP thread

    def push_event(self, event):
        """IMPL: BaseEventQueue — Route event to appropriate queue based on type."""
        msg_type = event.get("type", "")
        if msg_type in ("process_event", "network_event", "module_load_event",
                         "process_injection", "process_access", "file_create_event",
                         "dns_query_event", "sysmon_event",
                         "memory_scan_event", "process_hollowing"):
            self.push(QUEUE_SYSMON, event)
        elif msg_type in ("windows_event", "linux_event", "linux_audit", "registry_event",
                           "cloud_event", "sca_event", "network_anomaly"):
            self.push(QUEUE_EVENTS, event)
        elif msg_type in ("fim", "fim_event"):
            self.push(QUEUE_FIM, event)
        elif msg_type == "network_traffic":
            self.push(QUEUE_NETWORK, event)
        elif msg_type in ("threat_alert", "cross_machine_threat"):
            self.push(QUEUE_THREATS, event)
        elif msg_type in ("yara_alert", "vulnerability_alert", "baseline_report"):
            self.push(QUEUE_ALERTS, event)
        elif msg_type == "heartbeat":
            self.push(QUEUE_HEARTBEATS, event)
        else:
            self.push(QUEUE_EVENTS, event)  # Default

    def pop_batch(self, queue_name, batch_size=100, timeout=1):
        """IMPL: BaseEventQueue — Pop batch of events."""
        results = []
        try:
            if self._redis:
                # Redis BLMOVE-like: pop from left in a loop
                # Using pipeline for atomic batch pop
                pipe = self._redis.pipeline()
                for _ in range(batch_size):
                    pipe.lpop(queue_name)
                values = pipe.execute()
                for v in values:
                    if v:
                        try:
                            results.append(json.loads(v))
                        except json.JSONDecodeError:
                            pass
            else:
                with self._mem_lock:
                    q = self._mem_queues.get(queue_name)
                    if q:
                        for _ in range(min(batch_size, len(q))):
                            try:
                                json_str = q.popleft()
                                results.append(json.loads(json_str))
                            except (json.JSONDecodeError, IndexError):
                                pass
            self._stats["popped"] += len(results)
        except Exception:
            pass
        return results

    def get_stats(self):
        """IMPL: BaseEventQueue — Return queue statistics."""
        stats = {
            "pushed": self._stats["pushed"],
            "popped": self._stats["popped"],
            "dropped": self._stats["dropped"],
            "backend": "redis" if self._redis else "memory",
            "queues": {},
        }
        if self._redis:
            try:
                for qname in [QUEUE_EVENTS, QUEUE_SYSMON, QUEUE_NETWORK,
                               QUEUE_THREATS, QUEUE_HEARTBEATS, QUEUE_FIM, QUEUE_ALERTS]:
                    stats["queues"][qname.split(":")[-1]] = self._redis.llen(qname) or 0
            except Exception:
                pass
        else:
            with self._mem_lock:
                for qname, q in self._mem_queues.items():
                    stats["queues"][qname.split(":")[-1]] = len(q)
        return stats

    def clear_all(self):
        """IMPL: BaseEventQueue — Clear all queues."""
        if self._redis:
            try:
                self._redis.delete(QUEUE_EVENTS, QUEUE_SYSMON, QUEUE_NETWORK,
                                   QUEUE_THREATS, QUEUE_HEARTBEATS, QUEUE_FIM, QUEUE_ALERTS)
            except Exception:
                pass
        else:
            with self._mem_lock:
                for q in self._mem_queues.values():
                    q.clear()
        self._stats = {"pushed": 0, "popped": 0, "dropped": 0}