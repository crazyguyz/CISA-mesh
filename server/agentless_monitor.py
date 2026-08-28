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
        # v5.0.4: per-device runtime status so the UI can show online/offline and
        # the monitor only logs on STATE CHANGE (no more endless repeated events)
        self._device_state = {}
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
                   snmp_oids=None, ssh_commands=None, interval_seconds=300,
                   snmpv3_user="", snmpv3_level="authNoPriv",
                   snmpv3_auth_protocol="SHA", snmpv3_auth_key="",
                   snmpv3_priv_protocol="AES", snmpv3_priv_key=""):
        device = {
            "name": name, "ip": ip, "device_type": device_type,
            "method": method, "snmp_community": snmp_community,
            "ssh_user": ssh_user, "ssh_password": ssh_password,
            "snmp_oids": snmp_oids or [".1.3.6.1.2.1.1.3.0", ".1.3.6.1.2.1.1.5.0"],
            "ssh_commands": ssh_commands or ["uptime", "df -h", "free -m", "who"],
            # v4.6.3 (SEC review note 6): optional SNMPv3 credentials
            "snmpv3_user": snmpv3_user, "snmpv3_level": snmpv3_level,
            "snmpv3_auth_protocol": snmpv3_auth_protocol, "snmpv3_auth_key": snmpv3_auth_key,
            "snmpv3_priv_protocol": snmpv3_priv_protocol, "snmpv3_priv_key": snmpv3_priv_key,
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
        # v4.6.3 (SEC review note 6): default community "public"/"private" is a
        # credential risk - surface it in the result payload and support SNMPv3.
        if community in ("public", "private"):
            results["_warning"] = (f"SNMP community '{community}' is the default - "
                                   "use a strong community or SNMPv3")
        base = ["snmpget"]
        if device.get("snmpv3_user"):
            base += ["-v3", "-u", device["snmpv3_user"],
                     "-l", device.get("snmpv3_level", "authNoPriv")]
            if device.get("snmpv3_auth_protocol") and device.get("snmpv3_auth_key"):
                base += ["-a", device["snmpv3_auth_protocol"], "-A", device["snmpv3_auth_key"]]
            if device.get("snmpv3_priv_protocol") and device.get("snmpv3_priv_key"):
                base += ["-x", device["snmpv3_priv_protocol"], "-X", device["snmpv3_priv_key"]]
        else:
            base += ["-v2c", "-c", community]
        for oid in oids:
            try:
                result = subprocess.run(base + [device["ip"], oid],
                                        capture_output=True, text=True, timeout=10)
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

    def _is_reachable(self, device, data):
        """v5.0.4: decide online/offline from a scan payload."""
        if not data:
            return False
        if "reachable" in data:
            return bool(data.get("reachable"))
        if "error" in data:
            return False
        method = device.get("method", "ping")
        if method == "all":
            for sub in data.values():
                if isinstance(sub, dict) and self._is_reachable({"method": "ping"}, sub):
                    return True
            return False
        # snmp / ssh: reachable when at least one real value came back
        for k, v in data.items():
            if k in ("method", "_warning", "error"):
                continue
            if v and "Error:" not in str(v) and "not installed" not in str(v):
                return True
        return False

    def _persist_status(self, name, st):
        """Write status/last_seen back into agentless_devices.json so the API
        and UI can show live online/offline without any extra storage."""
        try:
            import os
            path = self._get_config_path()
            devs = []
            if os.path.exists(path):
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        devs = json.loads(f.read())
                except Exception:
                    devs = list(self.devices)
            for d in devs:
                if d.get("name") == name:
                    d["status"] = st.get("state")
                    d["last_seen"] = st.get("last_seen")
                    d["last_ok"] = st.get("last_ok")
                    d["last_fail"] = st.get("last_fail")
                    d["last_change"] = st.get("last_change")
                    break
            with open(path, "w", encoding="utf-8") as f:
                json.dump(devs, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def _update_status(self, device, reachable):
        """Track online/offline; returns True when the state CHANGED."""
        name = device["name"]
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        st = self._device_state.get(name, {})
        prev = st.get("state", "unknown")
        state = "online" if reachable else "offline"
        changed = prev != state
        st["state"] = state
        st["last_seen"] = now
        if reachable:
            st["last_ok"] = now
        else:
            st["last_fail"] = now
        if changed:
            st["last_change"] = now
        self._device_state[name] = st
        self._persist_status(name, st)
        return changed, state

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
        """Start background scheduler for periodic device scanning.
        v5.0.4: events are stored/forwarded ONLY when a device's online/offline
        state CHANGES (or the first scan) - steady-state scans just update
        last_seen/status, killing the endless repeated-log spam."""
        def scheduler():
            self._load_devices()
            while self.running:
                for device in self.devices:
                    if not device.get("enabled", True):
                        continue
                    try:
                        result = self.scan_device(device)
                        if result:
                            reachable = self._is_reachable(device, result.get("data") or {})
                            changed, state = self._update_status(device, reachable)
                            if changed:
                                result["status"] = state
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
        print(f"[*] Agentless monitor started ({len(self.devices)} devices) - logs on state change only")

    def _store_result(self, result):
        try:
            self.db.insert_agentless_event(result)
        except AttributeError:
            print(f"[-] Agentless DB missing method 'insert_agentless_event'. DB backend: {type(self.db).__name__}")
        except Exception as e:
            print(f"[-] Agentless store failed: {e}")

    def stop(self):
        self.running = False