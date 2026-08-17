"""
Rate Limiter v1.0.0 for GIAM-SAT Server v3.1.0
Sliding window IP-based rate limiting for TCP connections and events.

Protects server from:
  - Connection floods (max 10 connections per minute per IP)
  - Event floods (max 100 events per second per IP)

Thread-safe with RLock.
"""

import time
import threading
from collections import defaultdict, deque


class IPRateLimiter:
    """
    Sliding window rate limiter per IP address.

    Limits:
        connection_limit: max new connections per minute per IP (default: 10)
        connection_window: sliding window for connections in seconds (default: 60)
        event_limit: max events per second per IP (default: 100)
        event_window: sliding window for events in seconds (default: 1.0)
    """

    def __init__(self, connection_limit=10, connection_window=60,
                 event_limit=100, event_window=1.0):
        self._lock = threading.RLock()
        self._connection_limit = connection_limit
        self._connection_window = connection_window
        self._event_limit = event_limit
        self._event_window = event_window

        # IP → list of timestamps (monotonic float)
        self._connections = defaultdict(deque)
        self._events = defaultdict(deque)

        # Stats
        self._blocked_connections = 0
        self._blocked_events = 0
        self._allowed_connections = 0
        self._allowed_events = 0

    # ------------------------------------------------------------------
    # Connection rate limiting
    # ------------------------------------------------------------------
    def check_connection(self, ip: str) -> bool:
        """
        Check if a new TCP connection from `ip` is allowed.
        Returns True if allowed, False if rate limit exceeded.

        Limits: self._connection_limit per self._connection_window seconds.
        """
        now = time.monotonic()
        with self._lock:
            timestamps = self._connections[ip]

            # Purge expired entries (sliding window)
            cutoff = now - self._connection_window
            while timestamps and timestamps[0] < cutoff:
                timestamps.popleft()

            if len(timestamps) >= self._connection_limit:
                self._blocked_connections += 1
                return False

            timestamps.append(now)
            self._allowed_connections += 1
            return True

    # ------------------------------------------------------------------
    # Event rate limiting
    # ------------------------------------------------------------------
    def check_event(self, ip: str) -> bool:
        """
        Check if an event from `ip` is allowed.
        Returns True if allowed, False if rate limit exceeded.

        Limits: self._event_limit per self._event_window seconds.
        """
        now = time.monotonic()
        with self._lock:
            timestamps = self._events[ip]

            # Purge expired entries (sliding window)
            cutoff = now - self._event_window
            while timestamps and timestamps[0] < cutoff:
                timestamps.popleft()

            if len(timestamps) >= self._event_limit:
                self._blocked_events += 1
                return False

            timestamps.append(now)
            self._allowed_events += 1
            return True

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------
    def get_stats(self) -> dict:
        """Return rate limiter statistics."""
        with self._lock:
            return {
                "allowed_connections": self._allowed_connections,
                "blocked_connections": self._blocked_connections,
                "allowed_events": self._allowed_events,
                "blocked_events": self._blocked_events,
                "tracked_ips_connections": len(self._connections),
                "tracked_ips_events": len(self._events),
            }

    def get_blocked_counts(self) -> tuple:
        """Return (blocked_connections, blocked_events) tuple."""
        with self._lock:
            return (self._blocked_connections, self._blocked_events)

    # ------------------------------------------------------------------
    # Maintenance
    # ------------------------------------------------------------------
    def cleanup(self, max_age=300):
        """
        Remove IP tracking entries older than `max_age` seconds.
        Call periodically (e.g., every 5 minutes) to prevent memory bloat.
        """
        now = time.monotonic()
        cutoff = now - max_age
        with self._lock:
            for ip in list(self._connections.keys()):
                ts_list = self._connections[ip]
                while ts_list and ts_list[0] < cutoff:
                    ts_list.popleft()
                if not ts_list:
                    del self._connections[ip]

            for ip in list(self._events.keys()):
                ts_list = self._events[ip]
                while ts_list and ts_list[0] < cutoff:
                    ts_list.popleft()
                if not ts_list:
                    del self._events[ip]