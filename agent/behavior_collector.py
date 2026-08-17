"""
Behavior Collector v1.0.0 for GIAM-SAT Agent v3.2.0
Collects user behavior data for anomaly baseline construction.

Purpose: Build a normal-behavior profile for each user/machine
         to detect deviations (behavioral anomaly detection).

Collected metrics (every 15 minutes):
  - Running processes (top 20 by CPU)
  - Login session info
  - Network connections (established, count)
  - File access count (optional, via FIM data)

Sent to server as 'baseline_report' type (already handled by tcp_server).
"""

import os
import time
import threading
import json
import subprocess

IS_WINDOWS = os.name == "nt"
CREATE_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0


def _run_hidden(cmd, **kwargs):
    kwargs.setdefault("timeout", 15)
    if IS_WINDOWS:
        kwargs.setdefault("creationflags", CREATE_NO_WINDOW)
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)


class BehaviorCollector:
    """Periodic collector of user/machine behavior metrics."""

    def __init__(self, callback=None, interval_seconds=900):
        """
        Args:
            callback: Called with baseline_report dict for sending to server
            interval_seconds: Collection interval (default: 15 minutes)
        """
        self.callback = callback
        self.interval = interval_seconds
        self.running = False
        self.thread = None

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._collect_loop, daemon=True)
        self.thread.start()
        print(f"[*] Behavior Collector: Started (interval={self.interval}s)")

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=10)

    def _collect_loop(self):
        while self.running:
            try:
                report = self._collect()
                if report and self.callback:
                    self.callback(report)
            except Exception as e:
                print(f"[-] Behavior Collector error: {e}")
            time.sleep(self.interval)

    def _collect(self):
        """Gather behavior metrics. Returns baseline_report dict."""
        report = {
            "type": "baseline_report",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "hostname": os.environ.get("COMPUTERNAME", ""),
            "metrics": {},
        }

        # 1. Top processes by working set
        if IS_WINDOWS:
            try:
                ps_script = """
Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First 20 |
ForEach-Object { "$($_.ProcessName):$($_.Id):$($_.WorkingSet64)" }
"""
                r = _run_hidden(["powershell", "-NoProfile", "-Command", ps_script], timeout=15)
                if r.returncode == 0 and r.stdout:
                    procs = []
                    for line in r.stdout.strip().split("\n"):
                        parts = line.strip().split(":")
                        if len(parts) >= 2:
                            procs.append({
                                "name": parts[0],
                                "pid": parts[1] if len(parts) > 1 else "",
                                "memory": int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0,
                            })
                    report["metrics"]["top_processes"] = procs[:20]
            except Exception:
                pass
        else:
            try:
                r = _run_hidden(["ps", "-eo", "pid,comm,rss", "--sort=-rss", "--no-headers"], timeout=10)
                if r.returncode == 0 and r.stdout:
                    procs = []
                    for line in r.stdout.strip().split("\n")[:20]:
                        parts = line.strip().split(None, 2)
                        if len(parts) >= 2:
                            procs.append({
                                "pid": parts[0],
                                "name": parts[1],
                                "memory": int(parts[2]) * 1024 if len(parts) > 2 else 0,
                            })
                    report["metrics"]["top_processes"] = procs
            except Exception:
                pass

        # 2. Network connection count
        if IS_WINDOWS:
            try:
                r = _run_hidden(
                    ["powershell", "-NoProfile", "-Command",
                     "(Get-NetTCPConnection -State Established).Count"],
                    timeout=10
                )
                if r.returncode == 0 and r.stdout.strip().isdigit():
                    report["metrics"]["established_connections"] = int(r.stdout.strip())
            except Exception:
                pass
        else:
            try:
                r = _run_hidden(["ss", "-tn", "state", "established"], timeout=10)
                if r.returncode == 0:
                    count = len([l for l in r.stdout.strip().split("\n") if l.strip()]) - 1
                    report["metrics"]["established_connections"] = max(0, count)
            except Exception:
                pass

        # 3. Login session info
        if IS_WINDOWS:
            try:
                username = os.environ.get("USERNAME", "")
                report["metrics"]["logged_in_user"] = username
                # Check if interactive session
                r = _run_hidden(
                    ["powershell", "-NoProfile", "-Command",
                     "(Get-CimInstance -ClassName Win32_ComputerSystem).UserName"],
                    timeout=10
                )
                if r.returncode == 0 and r.stdout:
                    report["metrics"]["session_user"] = r.stdout.strip()
            except Exception:
                pass

        return report

    def get_stats(self):
        return {"active": self.running, "interval_seconds": self.interval}