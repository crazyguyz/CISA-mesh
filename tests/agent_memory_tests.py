#!/usr/bin/env python
"""GIAM-SAT agent memory/cache regression tests - v5.0.8.

Guards the bug chain that made the agent eat GBs of RAM and fill the disk (seen
in production on 2026-09-23: GiamSatAgent 2.8GB working set / 22GB commit, 13.2M
rows / 13.18GB giamsat_cache.db, 413MB agent.log and 95.910 of 114.967 rows in the
server `events` table were false LOG_RESET alerts):

  1. agent/event_collector.py treated "newest record number == watermark" (the
     normal steady state of a channel with no new events) as a log reset - `<=`
     instead of `<` - and then rewound the watermark to 0, so every 3s poll of
     every idle channel re-collected the whole channel and emitted a false HIGH
     alert.  -> is_real_log_reset()
  2. the backwards drain loop read the WHOLE channel each poll (up to 200 x 1024
     = 204.800 win32 objects) -> should_stop_draining() + MAX_EVENTS_PER_POLL
  3. encrypted_cache.verify_integrity() ran `SELECT ... ORDER BY id ASC` +
     fetchall() over the whole table every 30s (13.2M rows) -> windowed,
     incremental, and get_cache_size() is a bounded count now
  4. flush_batch() deleted+committed per row (never caught up) and the cache had
     no cap at all -> batched delete + MAX_CACHE_ROWS trim

Usage: python tests/agent_memory_tests.py
Exit code 0 = all passed, 1 = failures found.
"""

import os
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "agent"))

import event_collector as ec  # noqa: E402
import encrypted_cache as xc  # noqa: E402
import log_cache as lc  # noqa: E402

RESULTS = []
TMP_DIRS = []
TMP_FILES = []


def check(name, ok, extra=""):
    RESULTS.append((name, bool(ok)))
    line = "PASS  " + name if ok else "FAIL  " + name
    if not ok and extra:
        line += "   -> " + str(extra)[:200]
    print(line)


def tmp_path(name):
    d = tempfile.mkdtemp(prefix="giamsat_agent_test_")
    TMP_DIRS.append(d)
    p = os.path.join(d, name)
    TMP_FILES.append(p)
    return p



def test_is_real_log_reset():
    """Bug 1: only a STRICT rewind counts as a log reset."""
    print("\n-- is_real_log_reset (false LOG_RESET storm) --")
    cases = [
        # (newest, last_seen, expected, note)
        (111386, 111386, False, "equal numbers = no new events (was a false alert every 3s)"),
        (111387, 111386, False, "normal new event"),
        (1, 111386, True, "log cleared - numbering restarted at 1"),
        (5, 111386, True, "log cleared, a few events already in"),
        (0, 0, False, "no watermark yet"),
        (5, 0, False, "no watermark yet (steady start)"),
        (None, 111386, False, "missing record number"),
        ("abc", 111386, False, "non-numeric record number"),
    ]
    for newest, seen, expected, note in cases:
        got = ec.is_real_log_reset(newest, seen)
        check("newest=%-8s last_seen=%-8s -> %-5s (%s)"
              % (newest, seen, expected, note), got == expected, "got %s" % got)


def test_should_stop_draining():
    """Bug 2: the drain loop must stop early instead of reading whole channels."""
    print("\n-- should_stop_draining (per-poll memory bound) --")
    check("short chunk (< 1024) => log exhausted",
          ec.should_stop_draining(100, 999999, 111386, 100) is True)
    check("chunk reaches the watermark => stop",
          ec.should_stop_draining(1024, 111386, 111386, 1000) is True)
    check("chunk is older than the watermark => stop",
          ec.should_stop_draining(1024, 111300, 111386, 1000) is True)
    check("chunk still has newer records => keep reading",
          ec.should_stop_draining(1024, 120000, 111386, 1000) is False)
    check("per-poll bound reached => stop",
          ec.should_stop_draining(1024, 120000, 0, ec.MAX_EVENTS_PER_POLL) is True)
    check("no watermark yet => keep reading",
          ec.should_stop_draining(1024, 120000, 0, 10) is False)
    check("unknown oldest record => keep reading",
          ec.should_stop_draining(1024, None, 111386, 10) is False)
    check("MAX_EVENTS_PER_POLL is bounded (<= 50k)",
          ec.MAX_EVENTS_PER_POLL <= 50000, ec.MAX_EVENTS_PER_POLL)


def test_encrypted_cache_bounds():
    """Bug 3: integrity verification and cache size must be BOUNDED."""
    print("\n-- EncryptedCache: bounded verify + bounded count --")
    path = tmp_path("giamsat_cache.db")
    cache = _new_encrypted_cache(path)
    try:
        for i in range(300):
            cache.cache({"type": "windows_event", "n": i})
        check("300 rows cached", cache.get_cache_size() == 300, cache.get_cache_size())
        check("get_cache_size(limit=50) is capped at the limit",
              cache.get_cache_size(limit=50) == 50, cache.get_cache_size(limit=50))

        valid, errors = cache.verify_integrity()
        check("untouched cache verifies OK", valid and not errors, errors)
        check("verify read only the newest window (<= VERIFY_WINDOW rows)",
              cache.last_verified_rows <= cache.VERIFY_WINDOW, cache.last_verified_rows)
        check("verify hashed the whole small table once (299 comparisons)",
              cache.last_verified_rows == 299, cache.last_verified_rows)

        # no new rows -> the next cycle must be free (no IO, nothing to hash)
        cache.verify_integrity()
        check("unchanged cache is skipped (0 rows hashed)", cache.last_verified_rows == 0,
              cache.last_verified_rows)

        # tamper with a row in the middle: data changed, stored chain_hash untouched
        cache.conn.execute("UPDATE log_cache SET data = 'tampered' WHERE id = 11")
        cache.conn.commit()
        cache._last_verify_max_id = None      # force a fresh verification cycle
        valid, errors = cache.verify_integrity()
        check("tampered row is detected", (not valid) and len(errors) == 1, errors)
        check("detected row id reported", errors and errors[0].get("row_id") == 11, errors)

        # cache cap: oldest rows are dropped, newest survive
        old_max, old_check, old_batch = (xc.EncryptedCache.MAX_CACHE_ROWS,
                                         xc.EncryptedCache.TRIM_CHECK_EVERY,
                                         xc.EncryptedCache.TRIM_BATCH)
        xc.EncryptedCache.MAX_CACHE_ROWS = 150
        xc.EncryptedCache.TRIM_CHECK_EVERY = 50
        xc.EncryptedCache.TRIM_BATCH = 100000
        try:
            cap_cache = _new_encrypted_cache(tmp_path("cap.db"))
            try:
                for i in range(400):
                    cap_cache.cache({"type": "windows_event", "n": i})
                size = cap_cache.get_cache_size()
                cap_cache._last_verify_max_id = None
                cap_cache.verify_integrity()
                newest = cap_cache.conn.execute("SELECT MAX(id) FROM log_cache").fetchone()[0]
                check("cache cap keeps ~MAX_CACHE_ROWS rows (got %s of 400)" % size,
                      size <= 200, size)
                check("cache cap keeps the NEWEST rows (id up to %s)" % newest,
                      newest == 400, newest)
                dropped_oldest = cap_cache.conn.execute(
                    "SELECT MIN(id) FROM log_cache").fetchone()[0]
                check("cache cap dropped the oldest rows (min id %s > 1)" % dropped_oldest,
                      dropped_oldest > 1, dropped_oldest)
            finally:
                cap_cache.close()
        finally:
            xc.EncryptedCache.MAX_CACHE_ROWS = old_max
            xc.EncryptedCache.TRIM_CHECK_EVERY = old_check
            xc.EncryptedCache.TRIM_BATCH = old_batch

        # flush_batch removes everything it sent, in batches
        fpath = tmp_path("flush.db")
        sent_counter = {"n": 0}

        def ok_send(data):
            sent_counter["n"] += 1
            return True

        xc._get_cache_path = lambda: fpath      # noqa: E731
        fc = xc.EncryptedCache(send_callback=ok_send)
        try:
            for i in range(250):
                fc.cache({"n": i})
            sent = fc.flush_batch(batch_size=100, delay_ms=0)
            check("flush_batch sent every cached row (250)", sent == 250, sent)
            check("flush_batch emptied the cache", fc.get_cache_size() == 0,
                  fc.get_cache_size())

            # a failing send must keep the unsent rows
            fails_after = {"left": 120}

            def flaky_send(data):
                if fails_after["left"] > 0:
                    fails_after["left"] -= 1
                    return True
                return False

            fc2 = xc.EncryptedCache(send_callback=flaky_send)
            try:
                for i in range(250):
                    fc2.cache({"n": i})
                sent2 = fc2.flush_batch(batch_size=50, delay_ms=0)
                check("failed batch keeps the unsent rows (sent %s, left 130)" % sent2,
                      sent2 == 120 and fc2.get_cache_size() == 130,
                      "sent=%s size=%s" % (sent2, fc2.get_cache_size()))
            finally:
                fc2.close()
        finally:
            fc.close()
    finally:
        cache.close()


def _new_encrypted_cache(path):
    """EncryptedCache bound to a throwaway DB file."""
    xc._get_cache_path = lambda: path      # noqa: E731 - patch the module helper
    return xc.EncryptedCache(send_callback=lambda data: True)


def test_log_cache_bounds():
    """Same bounds for the plaintext fallback cache (LogCache)."""
    print("\n-- LogCache: bounded count + batched flush --")
    path = tmp_path("plain.db")
    lc.CACHE_DB = path
    cache = lc.LogCache(send_callback=lambda data: True)
    try:
        for i in range(120):
            cache.cache({"n": i})
        check("120 rows cached", cache.get_cache_size() == 120, cache.get_cache_size())
        check("bounded count respects limit", cache.get_cache_size(limit=40) == 40,
              cache.get_cache_size(limit=40))
        sent = cache.flush_batch(batch_size=50, delay_ms=0)
        check("flush_batch drained the plaintext cache",
              sent == 120 and cache.get_cache_size() == 0,
              "sent=%s size=%s" % (sent, cache.get_cache_size()))
    finally:
        cache.close()

    old_max, old_check = lc.LogCache.MAX_CACHE_ROWS, lc.LogCache.TRIM_CHECK_EVERY
    lc.LogCache.MAX_CACHE_ROWS = 50
    lc.LogCache.TRIM_CHECK_EVERY = 20
    try:
        lc.CACHE_DB = tmp_path("plain_cap.db")
        cap = lc.LogCache(send_callback=lambda data: True)
        try:
            for i in range(200):
                cap.cache({"n": i})
            size = cap.get_cache_size()
            check("plaintext cache cap trims oldest rows (size %s of 200)" % size,
                  size <= 70, size)
        finally:
            cap.close()
    finally:
        lc.LogCache.MAX_CACHE_ROWS = old_max
        lc.LogCache.TRIM_CHECK_EVERY = old_check


def main():
    print("=" * 68)
    print("  GIAM-SAT agent memory / cache regression tests - v5.0.8")
    print("=" * 68)
    try:
        test_is_real_log_reset()
        test_should_stop_draining()
        test_encrypted_cache_bounds()
        test_log_cache_bounds()
    finally:
        for d in TMP_DIRS:
            shutil.rmtree(d, ignore_errors=True)
    failed = [n for n, ok in RESULTS if not ok]
    print("\n" + "=" * 68)
    print("  %d/%d checks passed" % (len(RESULTS) - len(failed), len(RESULTS)))
    for name in failed:
        print("  FAILED: %s" % name)
    print("=" * 68)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())


