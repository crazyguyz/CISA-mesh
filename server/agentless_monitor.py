"""
Agentless Monitor for GIAM-SAT Server v1.6.1
Monitors network devices and systems without installing agents:
- SNMP polling (router/switch/printer)
- SSH command execution (Linux servers)
- ICMP ping monitoring
"""
import json
import subprocess
import threading
import time
from datetime import datetime


class AgentlessMonitor:
    """Agentless monitoring for network devices and remote systems."""

    def __init__(self, db_manager=None, message_callback=None):
        self.db = db_manager
        self.callback = message_callback
        self.running = True
        self.devices = []  # List of device configs
        self._load_devices()

    def _get_config_path(self):
        import os
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), "agentless_devices.json")

    def _load_devices(self):
        path = self._get_config_path()
        if not self.running:
            return
        try:
            import os
            if os.path.exists(path):
                with open(path, "r") as f:
                    self.devices = json.loads(f.read())
        except Exception:
            pass

    def add_device(self, name, ip, device_type="generic", method="ping",
                   snmp_community="public", ssh_user="", ssh_password="",
                   snmp_oids=None, ssh_commands=None, interval_seconds=300):
        device = {
            "name": name, "ip": ip, "device_type": device_type,
            "method": method, "snmp_community": snmp_community,
            "ssh_user": ssh_user, "ssh_password": ssh_password,
            "snmp_oids": snmp_oids or [".1.3.6.1.2.1.1.3.0", ".1.3.6.1.2.1.1.5.0"],
            "ssh_commands": ssh_commands or ["uptime", "df -h", "free -m", "who"],
            "enabled": True, "interval_seconds": interval_seconds,
        }
        self.devices.append(device)
        self._save_devices()

    def _save_devices(self):
        path = self._get_config_path()
        try:
            with open(path, "w") as f:
                json.dump(self.devices, f, indent=2)
        except Exception:
            pass

    def _ping_device(self, device):
        ip = device.get("ip", "")
        try:
            param = "-n" if "win" in __import__("sys").platform else "-c"
            count = "1"
            result = subprocess.run(["ping", param, count, ip],
                                    capture_output=True, text=True, timeout=10)
            success = "TTL=" in result.stdout or "ttl=" in result.stdout.lower()
            return {"reachable": success, "latency_ms": self._parse_ping_latency(result.stdout)}
        except Exception:
            return {"reachable": False, "error": "timeout"}

    def _parse_ping_latency(self, output):
        try:
            import re
            match = re.search(r"time[=<](\d+\.?\d*)\s*ms", output.lower())
            if match:
                return float(match.group(1))
        except Exception:
            pass
        return None

    def _snmp_poll(self, device):
        results = {}
        community = device.get("snmp_community", "public")
        oids = device.get("snmp_oids", [])
        for oid in oids:
            try:
                result = subprocess.run(
                    ["snmpget", "-v2c", "-c", community, device["ip"], oid],
                    capture_output=True, text=True, timeout=10
                )
                results[oid] = result.stdout.strip() if result.returncode == 0 else f"Error: {result.stderr}"
            except FileNotFoundError:
                results[oid] = "snmpget not installed (install net-snmp-utils)"
            except Exception as e:
                results[oid] = f"Error: {e}"
        return results

    def _ssh_execute(self, device):
        results = {}
        import os
        try:
            import paramiko
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            password = device.get("ssh_password", "")
            user = device.get("ssh_user", "root")
            if password:
                client.connect(device["ip"], username=user, password=password, timeout=10)
            else:
                key_path = os.path.expanduser("~/.ssh/id_rsa")
                if os.path.exists(key_path):
                    client.connect(device["ip"], username=user, key_filename=key_path, timeout=10)
                else:
                    return {"error": "No SSH password or key configured"}
            for cmd in device.get("ssh_commands", ["uptime"]):
                try:
                    stdin, stdout, stderr = client.exec_command(cmd, timeout=10)
                    results[cmd] = stdout.read().decode("utf-8", errors="ignore").strip()
                except Exception as e:
                    results[cmd] = f"Error: {e}"
            client.close()
        except ImportError:
            results["error"] = "paramiko not installed (pip install paramiko)"
        except Exception as e:
            results["error"] = str(e)
        return results

    def scan_device(self, device):
        """Scan a single device and return results."""
        if not device.get("enabled", True):
            return None
        method = device.get("method", "ping")
        results = {
            "type": "agentless_event",
            "device_name": device["name"],
            "ip": device["ip"],
            "device_type": device.get("device_type", ""),
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        if method == "ping":
            results["data"] = self._ping_device(device)
            results["data"]["method"] = "ping"
        elif method == "snmp":
            results["data"] = self._snmp_poll(device)
            results["data"]["method"] = "snmp"
        elif method == "ssh":
            results["data"] = self._ssh_execute(device)
            results["data"]["method"] = "ssh"
        elif method == "all":
            results["data"] = {
                "ping": self._ping_device(device),
                "snmp": self._snmp_poll(device),
                "ssh": self._ssh_execute(device),
            }
        return results

    def start_scheduler(self):
        """Start background scheduler for periodic device scanning."""
        def scheduler():
            self._load_devices()
            while self.running:
                for device in self.devices:
                    if not device.get("enabled", True):
                        continue
                    try:
                        result = self.scan_device(device)
                        if result:
                            if self.callback:
                                self.callback(result)
                            if self.db:
                                self._store_result(result)
                    except Exception as e:
                        print(f"[-] Agentless scan error [{device['name']}]: {e}")
                interval = max(60, min(d.get("interval_seconds", 300) for d in self.devices) if self.devices else 300)
                time.sleep(interval)

        t = threading.Thread(target=scheduler, daemon=True)
        t.start()
        print(f"[*] Agentless monitor started ({len(self.devices)} devices)")

    def _store_result(self, result):
        try:
            self.db.insert_agentless_event(result)
        except AttributeError:
            print(f"[-] Agentless DB missing method 'insert_agentless_event'. DB backend: {type(self.db).__name__}")
        except Exception as e:
            print(f"[-] Agentless store failed: {e}")

    def stop(self):
        self.running = False