"""
Sigma Auto-Update v1.0.0 for GIAM-SAT Server v3.2.0
Weekly background task: pull latest Sigma rules from GitHub, convert, import.

Purpose: Keep detection rules current with community threats.
         Runs as daemon thread, interval 604800s (7 days).

Architecture:
  server_core.py → sigma_updater thread → git pull SigmaHQ/sigma (shallow)
    → SigmaParser.parse_directory("sigma/rules/windows/")
      → append new rules to correlation_rules.yaml (dedup by id)
"""

import os
import time
import json
import subprocess
import threading
from datetime import datetime


class SigmaAutoUpdater:
    """
    Weekly auto-sync of Sigma rules from SigmaHQ GitHub repo.
    Uses shallow clone (depth=1) to minimize disk usage.
    """

    def __init__(self, rules_dir=None, sigma_repo_url=None, interval_seconds=604800):
        """
        Args:
            rules_dir: Path to GIAM-SAT rules directory (where correlation_rules.yaml lives)
            sigma_repo_url: Git URL for Sigma rules (default: SigmaHQ/sigma)
            interval_seconds: Update interval (default: 7 days)
        """
        self.rules_dir = rules_dir or os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "rules"
        )
        self.sigma_repo = sigma_repo_url or "https://github.com/SigmaHQ/sigma.git"
        self.sigma_local = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "..", ".sigma_repo"
        )
        self.interval = interval_seconds
        self.running = False
        self.thread = None
        self._stats = {
            "last_update": None,
            "rules_imported": 0,
            "rules_skipped": 0,
            "errors": 0,
        }
        self._lock = threading.Lock()

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._update_loop, daemon=True)
        self.thread.start()
        print(f"[*] Sigma Auto-Updater: Started (interval={self.interval}s, repo={self.sigma_repo})")

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=10)

    def _update_loop(self):
        """Background loop: pull repo → parse → import."""
        # Initial delay: 60s to let server stabilize
        time.sleep(60)

        while self.running:
            try:
                print("[*] Sigma Auto-Updater: Fetching latest Sigma rules...")
                self._git_pull()
                imported = self._import_rules()
                with self._lock:
                    self._stats["last_update"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    self._stats["rules_imported"] += imported
            except Exception as e:
                with self._lock:
                    self._stats["errors"] += 1
                print(f"[-] Sigma Auto-Updater: Error: {e}")

            # Wait for next interval
            for _ in range(int(self.interval)):
                if not self.running:
                    break
                time.sleep(1)

    def _git_pull(self):
        """Clone or pull the SigmaHQ/sigma repo (shallow, depth=1)."""
        if not os.path.exists(self.sigma_local):
            print(f"[*] Sigma: Cloning {self.sigma_repo} (depth=1)...")
            try:
                subprocess.run(
                    ["git", "clone", "--depth", "1", self.sigma_repo, self.sigma_local],
                    capture_output=True, text=True, timeout=120,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                )
            except FileNotFoundError:
                print("[!] Sigma Auto-Updater: git not found. Install git or disable auto-update.")
                return
            except subprocess.TimeoutExpired:
                print("[-] Sigma: Clone timed out")
                return
        else:
            try:
                subprocess.run(
                    ["git", "-C", self.sigma_local, "pull", "--depth", "1"],
                    capture_output=True, text=True, timeout=60,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                )
            except Exception:
                print("[-] Sigma: Git pull failed, continuing with existing repo")

    def _import_rules(self):
        """Parse all Sigma rules and import into correlation_rules.yaml."""
        windows_rules = os.path.join(self.sigma_local, "rules", "windows")
        if not os.path.exists(windows_rules):
            print("[!] Sigma: rules/windows/ not found in cloned repo")
            return 0

        try:
            from sigma_parser import SigmaParser
            import yaml as _yaml

            parser = SigmaParser()
            rules = parser.parse_directory(windows_rules)
            print(f"[*] Sigma: Parsed {len(rules)} rules from windows/ directory")

            # Load existing rules
            rules_path = os.path.join(self.rules_dir, "correlation_rules.yaml")
            if os.path.exists(rules_path):
                with open(rules_path, "r", encoding="utf-8") as f:
                    existing = _yaml.safe_load(f) or {}
            else:
                existing = {"metadata": {"name": "GIAM-SAT Rules", "version": "1.0"}, "rules": []}

            existing_rules = existing.get("rules", [])
            existing_ids = {r["id"] for r in existing_rules if isinstance(r, dict) and "id" in r}

            imported = 0
            for rule in rules:
                if isinstance(rule, dict) and "id" in rule:
                    if rule["id"] in existing_ids:
                        continue
                    existing_rules.append(rule)
                    existing_ids.add(rule["id"])
                    imported += 1

            if imported > 0:
                existing["rules"] = existing_rules
                existing["metadata"]["last_updated"] = datetime.now().strftime("%Y-%m-%d")

                with open(rules_path, "w", encoding="utf-8") as f:
                    _yaml.dump(existing, f, default_flow_style=False, allow_unicode=True, sort_keys=False)

                print(f"[*] Sigma: Imported {imported} new rules (total: {len(existing_rules)})")
            else:
                print(f"[*] Sigma: No new rules to import (all {len(rules)} already exist)")

            return imported

        except ImportError:
            print("[!] Sigma Auto-Updater: sigma_parser.py or yaml not available")
            return 0
        except Exception as e:
            print(f"[-] Sigma: Import error: {e}")
            return 0

    def get_stats(self):
        with self._lock:
            return dict(self._stats)