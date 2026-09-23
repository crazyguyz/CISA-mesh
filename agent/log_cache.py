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
    # v5.0.8 (bug that): same bounds as EncryptedCache - an offline agent must not
    # be able to grow the cache file without limit (the affected host reached
    # 13.2M rows / 13GB) and COUNT(*) must not scan the whole table each call.
    MAX_CACHE_ROWS = 200000     # hard cap on cached rows - oldest are trimmed first
    TRIM_CHECK_EVERY = 500      # inserts between cap checks (keeps writes cheap)
    TRIM_BATCH = 50000          # max rows deleted per cap check

    def __init__(self, send_callback=None):
        self.send_callback = send_callback
        self.lock = threading.Lock()
        self.conn = sqlite3.connect(CACHE_DB, check_same_thread=False)
        self._inserts = 0
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
        """Cache a log entry to local SQLite (thread-safe).
        v5.0.8: the cache is BOUNDED (see _enforce_cap)."""
        try:
            with self.lock:
                self.conn.execute(
                    "INSERT INTO log_cache (data) VALUES (?)",
                    (json.dumps(data, ensure_ascii=False),)
                )
                self.conn.commit()
            self._inserts += 1
            if self._inserts % self.TRIM_CHECK_EVERY == 0:
                self._enforce_cap()
        except Exception as e:
            print(f"[-] Cache write error: {e}", flush=True)

    def _enforce_cap(self):
        """v5.0.8: keep at most MAX_CACHE_ROWS rows, dropping the OLDEST first.

        ids are AUTOINCREMENT, so the cutoff `id <= max_id - MAX_CACHE_ROWS` needs no
        COUNT(*) scan; the delete is bounded (TRIM_BATCH) so a host that already
        carries a huge backlog drains it over several checks. Returns rows dropped.
        """
        try:
            with self.lock:
                max_id = self.conn.execute("SELECT COALESCE(MAX(id), 0) FROM log_cache").fetchone()[0]
                if not max_id:
                    return 0
                cutoff = int(max_id) - int(self.MAX_CACHE_ROWS)
                if cutoff <= 0:
                    return 0
                cur = self.conn.execute(
                    "DELETE FROM log_cache WHERE id IN "
                    "(SELECT id FROM log_cache WHERE id <= ? LIMIT ?)",
                    (cutoff, self.TRIM_BATCH)
                )
                dropped = cur.rowcount or 0
                self.conn.commit()
            if dropped:
                print(f"[*] Cache trimmed: dropped {dropped} oldest row(s) "
                      f"(cap {self.MAX_CACHE_ROWS})", flush=True)
            return dropped
        except Exception:
            return 0

    def flush_batch(self, batch_size=100, delay_ms=200):
        """Send cached logs in batches. Returns number sent.

        v5.0.8 (perf bug): previously one DELETE + one COMMIT per row - flushing a
        multi-million row backlog could never catch up. Now each sent batch is
        removed with ONE statement and one commit.
        """
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

            done_ids = []
            stop = False
            for row_id, data_str in batch:
                try:
                    data = json.loads(data_str)
                    if self.send_callback and self.send_callback(data):
                        done_ids.append(row_id)
                        total_sent += 1
                    else:
                        stop = True          # send failed - keep the rows
                        break
                except Exception:
                    done_ids.append(row_id)  # corrupted entry -> drop
            if done_ids:
                with self.lock:
                    self.conn.execute(
                        "DELETE FROM log_cache WHERE id <= ?", (max(done_ids),)
                    )
                    self.conn.commit()
            if stop:
                return total_sent

            # Small delay between batches to avoid overwhelming server
            time.sleep(delay_ms / 1000)

        return total_sent

    def get_cache_size(self, limit=100001):
        """Number of cached messages (v5.0.8: BOUNDED count - returns
        min(rows, limit) so it never scans a multi-GB table)."""
        try:
            with self.lock:
                cursor = self.conn.execute(
                    "SELECT COUNT(*) FROM (SELECT 1 FROM log_cache LIMIT ?)",
                    (int(limit),)
                )
                return cursor.fetchone()[0]
        except Exception:
            return 0

    def close(self):
        self.conn.close()