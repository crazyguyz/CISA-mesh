"""
Resource Monitor for GIAM-SAT Agent v3.6.0
CPU/RAM throttling to prevent agent from impacting user applications.

Priority levels:
  NORMAL  - CPU < 30%: full speed scanning
  THROTTLE - CPU 30-50%: increase scan intervals, reduce IO
  PAUSE    - CPU > 50%: pause heavy scans, keep heartbeat + event log only
"""
import time
import threading
import os

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


class ResourceMonitor:
    """Monitors CPU and RAM usage, provides throttling signals to collectors."""

    def __init__(self, cpu_threshold_throttle=30, cpu_threshold_pause=50,
                 ram_threshold_mb=512, check_interval=5):
        self.cpu_threshold_throttle = cpu_threshold_throttle
        self.cpu_threshold_pause = cpu_threshold_pause
        self.ram_threshold_mb = ram_threshold_mb
        self.check_interval = check_interval
        self._current_level = "NORMAL"
        self._cpu_percent = 0
        self._ram_mb_used = 0
        self._last_check = 0
        self._lock = threading.Lock()
        self._running = True
        self._stats = {"normal": 0, "throttled": 0, "paused": 0}

        # Start background monitor thread
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()

    def _monitor_loop(self):
        """Background loop: check CPU/RAM every check_interval seconds."""
        while self._running:
            self._update()
            time.sleep(self.check_interval)

    def _update(self):
        """Read current CPU/RAM and update throttling level."""
        with self._lock:
            if HAS_PSUTIL:
                try:
                    self._cpu_percent = psutil.cpu_percent(interval=0.5)
                    mem = psutil.virtual_memory()
                    self._ram_mb_used = (mem.total - mem.available) / (1024 * 1024)
                except Exception:
                    pass
            else:
                # Fallback: use os.times() for rudimentary CPU check
                try:
                    t = os.times()
                    self._cpu_percent = min(t.user + t.system, 100)
                except Exception:
                    self._cpu_percent = 0

            prev_level = self._current_level
            if self._cpu_percent > self.cpu_threshold_pause:
                self._current_level = "PAUSE"
            elif self._cpu_percent > self.cpu_threshold_throttle:
                self._current_level = "THROTTLE"
            else:
                self._current_level = "NORMAL"

            if prev_level != self._current_level:
                print(f"[ResourceMonitor] Level changed: {prev_level} → {self._current_level} "
                      f"(CPU: {self._cpu_percent:.1f}%, RAM: {self._ram_mb_used:.0f}MB)")

            self._stats[self._current_level.lower()] += 1
            self._last_check = time.time()

    @property
    def level(self):
        """Current throttling level: NORMAL, THROTTLE, or PAUSE."""
        with self._lock:
            return self._current_level

    @property
    def cpu_percent(self):
        with self._lock:
            return self._cpu_percent

    def should_pause_heavy(self):
        """True if heavy scans (YARA, FIM full, Memory) should be paused."""
        return self.level == "PAUSE"

    def should_throttle(self):
        """True if scans should run with increased intervals."""
        return self.level in ("THROTTLE", "PAUSE")

    def get_scan_interval_multiplier(self):
        """Returns interval multiplier: 1.0 (normal), 2.0 (throttle), 10.0 (pause)."""
        if self.level == "PAUSE":
            return 10.0
        elif self.level == "THROTTLE":
            return 2.0
        return 1.0

    def get_max_file_size_mb(self, default=200):
        """Returns max file size for YARA scanning based on resource level."""
        if self.level == "PAUSE":
            return 10
        elif self.level == "THROTTLE":
            return 50
        return default

    def get_stats(self):
        with self._lock:
            return dict(self._stats)

    def stop(self):
        self._running = False