"""
Log Cache for GIAM-SAT Agent
Persists logs to local SQLite when offline, flushes in batches when reconnected.
Uses %PROGRAMDATA%\GIAM-SAT\Agent for writable data (safe in Program Files).
"""

import sqlite3
import os
import json
import threading
import time
from datetime import datetime

# Use %PROGRAMDATA% for writable data, safe when installed in Program Files
def _get_cache_path():
    if os.name == "nt":
        programdata = os.environ.get("PROGRAMDATA", "C:\\ProgramData")
        data_dir = os.path.join(programdata, "GIAM-SAT", "Agent")
    else:
        data_dir = os.path.join(os.path.expanduser("~"), ".giamsat", "agent")
    os.makedirs(data_dir, exist_ok=True)
    return os.path.join(data_dir, "giamsat_cache.db")

CACHE_DB = _get_cache_path()


class LogCache:
    def __init__(self, send_callback=None):
        self.send_callback = send_callback
        self.lock = threading.Lock()
        self.conn = sqlite3.connect(CACHE_DB, check_same_thread=False)
        self._init_db()

    def _init_db(self):
        with self.lock:
            self.conn.execute("""CREATE TABLE IF NOT EXISTS log_cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                data TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )""")
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.commit()

    def cache(self, data):
        """Cache a log entry to local SQLite (thread-safe)."""
        try:
            with self.lock:
                self.conn.execute(
                    "INSERT INTO log_cache (data) VALUES (?)",
                    (json.dumps(data, ensure_ascii=False),)
                )
                self.conn.commit()
        except Exception as e:
            print(f"[-] Cache write error: {e}", flush=True)

    def flush_batch(self, batch_size=100, delay_ms=200):
        """Send cached logs in batches. Returns number sent."""
        total_sent = 0
        while True:
            batch = []
            with self.lock:
                cursor = self.conn.execute(
                    "SELECT id, data FROM log_cache ORDER BY id ASC LIMIT ?",
                    (batch_size,)
                )
                batch = [(row[0], row[1]) for row in cursor.fetchall()]

            if not batch:
                break

            # Send each item in batch
            for row_id, data_str in batch:
                try:
                    data = json.loads(data_str)
                    if self.send_callback and self.send_callback(data):
                        # Remove successfully sent
                        with self.lock:
                            self.conn.execute("DELETE FROM log_cache WHERE id=?", (row_id,))
                            self.conn.commit()
                        total_sent += 1
                    else:
                        # Send failed, stop this batch
                        return total_sent
                except Exception:
                    # Skip corrupted entry
                    with self.lock:
                        self.conn.execute("DELETE FROM log_cache WHERE id=?", (row_id,))
                        self.conn.commit()

            # Small delay between batches to avoid overwhelming server
            time.sleep(delay_ms / 1000)

        return total_sent

    def get_cache_size(self):
        """Get number of cached messages."""
        with self.lock:
            cursor = self.conn.execute("SELECT COUNT(*) FROM log_cache")
            return cursor.fetchone()[0]

    def close(self):
        self.conn.close()