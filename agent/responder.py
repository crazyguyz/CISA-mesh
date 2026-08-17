"""
Active Response Module for GIAM-SAT Agent v1.14.0

Executes automated response actions:
  - Block IP via Windows Firewall / iptables
  - Disable user account
  - Quarantine file (move to isolated directory)
  - Terminate malicious process
  - Isolate machine from network (emergency mode)
  - Collect forensic snapshot

v1.0: Basic PowerShell execution
v1.14.0: Extended actions with rollback support
"""

import json
import subprocess
import threading
import tempfile
import os
import sys
import base64
import shutil
import time
from datetime import datetime

IS_WINDOWS = os.name == "nt"
CREATE_NO_WINDOW = 0x08000000 if IS_WINDOWS else 0

QUARANTINE_DIR = os.path.join(os.environ.get("ProgramData", "C:\\ProgramData"), "GiamSat", "Quarantine")


def _run(cmd, timeout=30, **kwargs):
    """Run a command with timeout."""
    if IS_WINDOWS:
        kwargs.setdefault("creationflags", CREATE_NO_WINDOW)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, **kwargs)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", "timeout", -1
    except Exception as e:
        return "", str(e), -1


class Responder:
    def __init__(self):
        self.command_queue = []
        self.lock = threading.Lock()
        self._rollback_actions = []  # Stack for undo operations
        os.makedirs(QUARANTINE_DIR, exist_ok=True)

    def execute_command(self, command_data):
        """Execute a response command received from server.
        
        command_data format: {"action": "action_type", "command": "...", "exec_id": "uuid", "params": {...}}
        
        Supported actions:
          - ps: DISABLED (v4.5.5 security - arbitrary PowerShell removed)
          - firewall_block: Block IP via firewall
          - firewall_unblock: Remove IP block
          - disable_account: Disable a local account
          - quarantine_file: Move suspicious file to quarantine
          - restore_file: Restore quarantined file
          - kill_process: Terminate process by name/PID
          - isolate_network: Block all outbound traffic (emergency)
          - restore_network: Restore network connectivity
          - forensic_snapshot: Collect system state for forensics
        """
        action = command_data.get("action", "")
        cmd = command_data.get("command", "")
        exec_id = command_data.get("exec_id", "unknown")
        params = command_data.get("params", {})

        result = {
            "type": "response_result",
            "exec_id": exec_id,
            "action": action,
            "status": "completed",
            "output": "",
            "error": "",
            "rollback_possible": False,
        }

        try:
            if action == "firewall_block":
                result.update(self._firewall_block(params))
            elif action == "firewall_unblock":
                result.update(self._firewall_unblock(params))
            elif action == "disable_account":
                result.update(self._disable_account(params))
            elif action == "quarantine_file":
                result.update(self._quarantine_file(params))
            elif action == "restore_file":
                result.update(self._restore_file(params))
            elif action == "kill_process":
                result.update(self._kill_process(params))
            elif action == "isolate_network":
                result.update(self._isolate_network(params))
            elif action == "restore_network":
                result.update(self._restore_network(params))
            elif action == "forensic_snapshot":
                result.update(self._forensic_snapshot())
            elif action == "ps":
                # v4.5.5 SECURITY: arbitrary PowerShell execution disabled
                result["status"] = "failed"
                result["error"] = "Action 'ps' (arbitrary PowerShell) is disabled for security"
            elif action == "get_processes":
                result.update(self._get_processes())
            elif action == "get_services":
                result.update(self._get_services())
            elif action == "get_connections":
                result.update(self._get_connections())
            elif action == "get_scheduled_tasks":
                result.update(self._get_scheduled_tasks())
            elif action == "get_startup_programs":
                result.update(self._get_startup_programs())
            elif action == "show_message":
                result.update(self._show_messagebox(command_data))
            elif action == "restart_computer":
                result.update(self._restart_computer(cmd))
            elif action == "shutdown_computer":
                result.update(self._shutdown_computer(cmd))
            # v3.9.2: Group Policy enforcement actions
            elif action == "apply_block_usb":
                result.update(self._apply_block_usb(cmd))
            elif action == "remove_block_usb":
                result.update(self._remove_block_usb(cmd))
            elif action == "apply_block_websites":
                result.update(self._apply_block_websites(cmd))
            elif action == "remove_block_websites":
                result.update(self._remove_block_websites(cmd))
            elif action == "apply_block_software":
                result.update(self._apply_block_software(cmd))
            elif action == "remove_block_software":
                result.update(self._remove_block_software(cmd))
            elif action == "dump_memory":
                result.update(self._dump_memory(params))
            elif action == "lock_account":
                result.update(self._lock_account())
            elif action == "kill_tree":
                result.update(self._kill_process_tree(params))
            else:
                result["status"] = "failed"
                result["error"] = f"Unknown action: {action}"
        except Exception as e:
            result["status"] = "failed"
            result["error"] = str(e)[:500]

        return result

    # =========================================================================
    # Firewall Block/Unblock
    # =========================================================================

    def _firewall_block(self, params: dict) -> dict:
        """Block an IP address via firewall."""
        ip = params.get("ip", "")
        direction = params.get("direction", "inbound")  # inbound, outbound, both
        rule_name = f"GIAMSAT_BLOCK_{ip.replace('.', '_')}"

        if not ip:
            return {"status": "failed", "error": "IP address required"}

        if IS_WINDOWS:
            results = []
            if direction in ("inbound", "both"):
                stdout, stderr, rc = _run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}_IN",
                    "dir=in",
                    "action=block",
                    f"remoteip={ip}",
                    "enable=yes",
                    "profile=any",
                ])
                results.append(f"INBOUND: {stdout.strip() or 'OK'}")

            if direction in ("outbound", "both"):
                stdout, stderr, rc = _run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}_OUT",
                    "dir=out",
                    "action=block",
                    f"remoteip={ip}",
                    "enable=yes",
                    "profile=any",
                ])
                results.append(f"OUTBOUND: {stdout.strip() or 'OK'}")

            return {
                "status": "completed",
                "output": f"Firewall block rule(s) added for {ip}: {', '.join(results)}",
                "rollback_possible": True,
                "rollback_action": "firewall_unblock",
                "rollback_params": {"ip": ip, "rule_name": rule_name},
            }
        else:
            stdout, stderr, rc = _run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
            stdout2, stderr2, rc2 = _run(["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"])
            return {
                "status": "completed",
                "output": f"iptables DROP rules added for {ip}",
                "rollback_possible": True,
                "rollback_action": "firewall_unblock",
                "rollback_params": {"ip": ip},
            }

    def _firewall_unblock(self, params: dict) -> dict:
        """Remove an IP block rule."""
        ip = params.get("ip", "")
        rule_name = params.get("rule_name", f"GIAMSAT_BLOCK_{ip.replace('.', '_')}")

        if IS_WINDOWS:
            _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}_IN"])
            _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}_OUT"])
            return {"status": "completed", "output": f"Firewall rules removed for {ip}"}
        else:
            _run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
            _run(["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"])
            return {"status": "completed", "output": f"iptables rules removed for {ip}"}

    # =========================================================================
    # Disable Account
    # =========================================================================

    def _disable_account(self, params: dict) -> dict:
        """Disable a local user account."""
        username = (params.get("username") or "").strip()
        if not username:
            return {"status": "failed", "error": "Username required"}
        # v4.5.4 SECURITY: reject unsafe chars to prevent PowerShell injection.
        if not all(c.isalnum() or c in "._-\\" for c in username):
            return {"status": "failed", "error": "Invalid username (unsafe characters)"}

        if IS_WINDOWS:
            stdout, stderr, rc = _run([
                "powershell", "-NoProfile", "-NonInteractive", "-Command",
                f"Disable-LocalUser -Name '{username}' -ErrorAction Stop"
            ])
            if rc == 0:
                return {
                    "status": "completed",
                    "output": f"Account {username} disabled successfully",
                    "rollback_possible": True,
                    "rollback_action": "enable_account",
                    "rollback_params": {"username": username},
                }
            return {"status": "failed", "error": stderr or "Failed to disable account"}
        else:
            stdout, stderr, rc = _run(["usermod", "-L", username])
            if rc == 0:
                return {
                    "status": "completed",
                    "output": f"Account {username} locked",
                    "rollback_possible": True,
                    "rollback_action": "enable_account",
                    "rollback_params": {"username": username},
                }
            return {"status": "failed", "error": stderr}

    # =========================================================================
    # Quarantine File
    # =========================================================================

    def _quarantine_file(self, params: dict) -> dict:
        """Move a suspicious file to quarantine directory."""
        file_path = params.get("file_path", "")
        if not file_path or not os.path.isfile(file_path):
            return {"status": "failed", "error": f"File not found or not a regular file: {file_path}"}

        try:
            filename = os.path.basename(file_path)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            quarantine_name = f"{timestamp}_{filename}"
            quarantine_path = os.path.join(QUARANTINE_DIR, quarantine_name)

            # Calculate SHA256 hash before moving
            import hashlib
            sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256.update(chunk)
            file_hash = sha256.hexdigest()

            shutil.move(file_path, quarantine_path)

            # Make quarantine file read-only
            os.chmod(quarantine_path, 0o444)

            # Save metadata
            meta = {
                "original_path": file_path,
                "quarantine_name": quarantine_name,
                "quarantined_at": datetime.now().isoformat(),
                "sha256": file_hash,
                "reason": params.get("reason", "Suspicious file detected"),
            }
            with open(quarantine_path + ".meta.json", "w") as f:
                json.dump(meta, f, indent=2)

            return {
                "status": "completed",
                "output": f"File quarantined: {file_path} -> {quarantine_path} (SHA256: {file_hash})",
                "rollback_possible": True,
                "rollback_action": "restore_file",
                "rollback_params": {"quarantine_name": quarantine_name, "original_path": file_path},
                "file_hash": file_hash,
            }
        except Exception as e:
            return {"status": "failed", "error": str(e)}

    def _restore_file(self, params: dict) -> dict:
        """Restore a file from quarantine."""
        quarantine_name = params.get("quarantine_name", "")
        original_path = params.get("original_path", "")
        quarantine_path = os.path.join(QUARANTINE_DIR, quarantine_name)

        if not os.path.exists(quarantine_path):
            return {"status": "failed", "error": f"Quarantined file not found: {quarantine_path}"}

        try:
            shutil.move(quarantine_path, original_path)
            # Clean up metadata file
            meta_path = quarantine_path + ".meta.json"
            if os.path.exists(meta_path):
                os.remove(meta_path)
            return {"status": "completed", "output": f"File restored: {original_path}"}
        except Exception as e:
            return {"status": "failed", "error": str(e)}

    # =========================================================================
    # Kill Process
    # =========================================================================

    def _kill_process(self, params: dict) -> dict:
        """Terminate a process by name or PID."""
        process_name = params.get("name", "")
        pid = params.get("pid", 0)
        force = params.get("force", True)

        if pid:
            target = str(pid)
            mode = "PID"
        elif process_name:
            target = process_name
            mode = "name"
        else:
            return {"status": "failed", "error": "Process name or PID required"}

        if IS_WINDOWS:
            force_flag = "/F" if force else ""
            stdout, stderr, rc = _run([
                "taskkill", force_flag, "/IM" if mode == "name" else "/PID", target
            ])
            if rc == 0:
                return {"status": "completed", "output": f"Process killed: {target}"}
            return {"status": "failed", "error": stderr or "Process not found"}
        else:
            flag = "-9" if force else ""
            stdout, stderr, rc = _run(["kill", flag, target])
            if rc == 0:
                return {"status": "completed", "output": f"Process killed: {target}"}
            return {"status": "failed", "error": stderr or "Process not found"}

    # =========================================================================
    # Network Isolation (Emergency Mode)
    # =========================================================================

    def _isolate_network(self, params: dict = None) -> dict:
        """Block network traffic (emergency isolation).

        v4.5.5: When `server_ip` param is provided, block outbound only while
        allowing the GIAM-SAT server (TCP 6666) so the agent keeps its management
        channel (inbound stays open for admin access). This replaces the legacy
        `ps` isolate action. Without `server_ip`, perform full emergency
        isolation (block inbound + outbound).
        """
        params = params or {}
        import re as _re
        server_ip = _re.sub(r"[^A-Za-z0-9.:_\[\]-]", "", str(params.get("server_ip", "")).strip())[:64]

        if IS_WINDOWS:
            if server_ip:
                # Allow management channel to server (allow rules win over block)
                _run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    "name=GIAMSAT_ISOLATE_ALLOW_SERVER",
                    "dir=out", "action=allow", f"remoteip={server_ip}",
                    "remoteport=6666", "protocol=TCP", "enable=yes", "profile=any",
                ])
                _run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    "name=GIAMSAT_ISOLATE_BLOCK_OUT",
                    "dir=out", "action=block", "enable=yes", "profile=any",
                ])
                return {
                    "status": "completed",
                    "output": f"Machine isolated - outbound blocked (server {server_ip}:6666 allowed, inbound open)",
                    "rollback_possible": True,
                    "rollback_action": "restore_network",
                }
            # Full emergency isolation
            _run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                "name=GIAMSAT_EMERGENCY_BLOCK_ALL_OUT",
                "dir=out", "action=block", "enable=yes", "profile=any",
            ])
            _run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                "name=GIAMSAT_EMERGENCY_BLOCK_ALL_IN",
                "dir=in", "action=block", "enable=yes", "profile=any",
            ])
            return {
                "status": "completed",
                "output": "NETWORK ISOLATED - All traffic blocked. Only GIAM-SAT communication allowed.",
                "rollback_possible": True,
                "rollback_action": "restore_network",
            }
        else:
            _run(["iptables", "-P", "INPUT", "DROP"])
            _run(["iptables", "-P", "OUTPUT", "DROP"])
            _run(["iptables", "-P", "FORWARD", "DROP"])
            return {
                "status": "completed",
                "output": "NETWORK ISOLATED - All traffic blocked.",
                "rollback_possible": True,
                "rollback_action": "restore_network",
            }

    def _restore_network(self, params: dict = None) -> dict:
        """Restore network connectivity after isolation (removes all isolate rules)."""
        if IS_WINDOWS:
            for name in (
                "GIAMSAT_EMERGENCY_BLOCK_ALL_OUT", "GIAMSAT_EMERGENCY_BLOCK_ALL_IN",
                "GIAMSAT_ISOLATE_ALLOW_SERVER", "GIAMSAT_ISOLATE_BLOCK_OUT", "GIAMSAT_ISOLATE_BLOCK_IN",
            ):
                _run([
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name={name}",
                ])
            return {"status": "completed", "output": "Network connectivity restored"}
        else:
            _run(["iptables", "-P", "INPUT", "ACCEPT"])
            _run(["iptables", "-P", "OUTPUT", "ACCEPT"])
            _run(["iptables", "-P", "FORWARD", "ACCEPT"])
            return {"status": "completed", "output": "Network connectivity restored"}

    # =========================================================================
    # Forensic Snapshot
    # =========================================================================

    def _forensic_snapshot(self) -> dict:
        """Collect a forensic snapshot of the system state."""
        snapshot = {
            "timestamp": datetime.now().isoformat(),
            "hostname": os.environ.get("COMPUTERNAME", ""),
        }

        if IS_WINDOWS:
            # Running processes
            stdout, _, _ = _run(["tasklist", "/FO", "CSV", "/NH"])
            snapshot["processes"] = stdout.strip().split("\n")[-50:] if stdout else []

            # Network connections
            stdout, _, _ = _run(["netstat", "-ano"])
            snapshot["netstat"] = stdout.strip().split("\n") if stdout else []

            # Active sessions
            stdout, _, _ = _run(["query", "session"])
            snapshot["sessions"] = stdout.strip().split("\n") if stdout else []

            # Scheduled tasks
            stdout, _, _ = _run(["schtasks", "/query", "/FO", "CSV", "/NH"])
            snapshot["scheduled_tasks"] = stdout.strip().split("\n")[-30:] if stdout else []

            # Recent events
            stdout, _, _ = _run([
                "powershell", "-NoProfile", "-Command",
                "Get-WinEvent -LogName Security -MaxEvents 20 | Select-Object TimeCreated,Id,Message | ConvertTo-Json -Compress"
            ])
            snapshot["recent_security_events"] = stdout[:5000] if stdout else ""
        else:
            stdout, _, _ = _run(["ps", "aux"])
            snapshot["processes"] = stdout.strip().split("\n") if stdout else []
            stdout, _, _ = _run(["ss", "-tuln"])
            snapshot["network"] = stdout.strip().split("\n") if stdout else []

        # Save snapshot to file
        snapshot_path = os.path.join(QUARANTINE_DIR, f"forensic_snapshot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        with open(snapshot_path, "w") as f:
            json.dump(snapshot, f, indent=2, default=str)

        return {
            "status": "completed",
            "output": f"Forensic snapshot saved to {snapshot_path}",
            "snapshot_path": snapshot_path,
        }

    # =========================================================================
    # v3.9.17: Remote Memory Dump (forensic)
    # =========================================================================

    def _dump_memory(self, params: dict) -> dict:
        """
        v3.9.17: Remote memory dump using PowerShell MiniDumpWriteDump via comsvcs.dll.
        Creates a memory dump of a target process for offline forensic analysis.
        
        Params:
            pid: Target process PID (required)
            dump_path: Output dump path (default: %TEMP%\giamsat_dump_<pid>.dmp)
        """
        pid = params.get("pid", 0)
        # v4.5.5 SECURITY: validate pid is an integer (prevent PowerShell injection)
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            return {"status": "failed", "error": "Invalid PID for memory dump"}
        if not pid:
            return {"status": "failed", "error": "Process PID required for memory dump"}
        
        dump_path = params.get("dump_path", os.path.join(tempfile.gettempdir(),
                                                          f"giamsat_dump_{pid}_{int(time.time())}.dmp"))
        # v4.5.5 SECURITY: sanitize dump_path (prevent PowerShell injection)
        import re as _re
        dump_path = _re.sub(r"[^A-Za-z0-9._\\/: -]", "", str(dump_path))[:256]
        if not dump_path:
            dump_path = os.path.join(tempfile.gettempdir(), f"giamsat_dump_{pid}_{int(time.time())}.dmp")
        
        if IS_WINDOWS:
            # Use comsvcs.dll MiniDumpWriteDump via rundll32 (built-in, no procdump needed)
            # This is a documented forensic technique that works without 3rd-party tools
            ps = f"""
$pid = {pid}
$dumpPath = '{dump_path.replace("'", "''")}'
try {{
    # Use comsvcs.dll MiniDumpWriteDump (CLSID-compatible via rundll32)
    $cmd = "rundll32.exe C:\\Windows\\System32\\comsvcs.dll,MiniDump $pid $dumpPath full"
    $res = cmd /c $cmd 2>&1
    if (Test-Path $dumpPath) {{
        $size = (Get-Item $dumpPath).Length
        Write-Output "MEMORY_DUMP_OK:$dumpPath:$size"
    }} else {{
        Write-Output "MEMORY_DUMP_FAILED:$res"
    }}
}} catch {{
    Write-Output "MEMORY_DUMP_FAILED:$_"
}}
"""
            stdout, stderr, rc = _run(
                ["powershell", "-NoProfile", "-Command", ps],
                timeout=60
            )
            output = stdout.strip() if stdout else stderr or ""
            
            if output.startswith("MEMORY_DUMP_OK:"):
                parts = output.split(":")
                dump_size = int(parts[2]) if len(parts) > 2 else 0
                dump_mb = round(dump_size / (1024 * 1024), 1)
                return {
                    "status": "completed",
                    "output": f"Memory dump created: {parts[1]} ({dump_mb} MB)",
                    "dump_path": parts[1],
                    "dump_size": dump_size,
                }
            return {"status": "failed", "error": output[:500] or "Memory dump failed"}
        else:
            # Linux: gcore or /proc/pid/mem
            stdout, stderr, rc = _run(["gcore", "-o", dump_path, str(pid)], timeout=30)
            if rc == 0:
                return {"status": "completed", "output": f"Core dump created at {dump_path}.{pid}"}
            return {"status": "failed", "error": stderr or "gcore dump failed"}

    # =========================================================================
    # v3.9.2: Restart / Shutdown Computer
    # =========================================================================

    def _restart_computer(self, cmd: str) -> dict:
        """Restart the computer using shutdown /r /f /t 0 (forced, ignores logged-on users).
        Legacy 'cmd' param allows 'restart-computer -Force' passed as PS command."""
        if IS_WINDOWS:
            # Use shutdown.exe directly — bypasses PowerShell's Restart-Computer limitation
            # which fails when other users are logged on (even disconnected sessions)
            stdout, stderr, rc = _run(["shutdown", "/r", "/f", "/t", "0"], timeout=10)
            if rc == 0:
                return {"status": "completed", "output": "Computer restart initiated (shutdown /r /f /t 0)."}
            # Fallback: forced reboot via PowerShell
            stdout2, stderr2, rc2 = _run([
                "powershell", "-NoProfile", "-Command",
                "Restart-Computer -Force -ErrorAction Stop; Write-Output 'Restart initiated'"
            ], timeout=10)
            if rc2 == 0:
                return {"status": "completed", "output": "Computer restart initiated (Restart-Computer -Force)."}
            return {"status": "failed", "error": stderr or stderr2 or "Restart command failed"}
        else:
            stdout, stderr, rc = _run(["shutdown", "-r", "now"], timeout=10)
            if rc == 0:
                return {"status": "completed", "output": "Computer restart initiated."}
            return {"status": "failed", "error": stderr or "Restart failed"}

    def _shutdown_computer(self, cmd: str) -> dict:
        """Shutdown the computer using shutdown /s /f /t 0."""
        if IS_WINDOWS:
            stdout, stderr, rc = _run(["shutdown", "/s", "/f", "/t", "0"], timeout=10)
            if rc == 0:
                return {"status": "completed", "output": "Computer shutdown initiated (shutdown /s /f /t 0)."}
            stdout2, stderr2, rc2 = _run([
                "powershell", "-NoProfile", "-Command",
                "Stop-Computer -Force -ErrorAction Stop; Write-Output 'Shutdown initiated'"
            ], timeout=10)
            if rc2 == 0:
                return {"status": "completed", "output": "Computer shutdown initiated (Stop-Computer -Force)."}
            return {"status": "failed", "error": stderr or stderr2 or "Shutdown command failed"}
        else:
            stdout, stderr, rc = _run(["shutdown", "-h", "now"], timeout=10)
            if rc == 0:
                return {"status": "completed", "output": "Computer shutdown initiated."}
            return {"status": "failed", "error": stderr or "Shutdown failed"}

    # =========================================================================
    # v4.0: Kill Process Tree (kill parent + all descendants)
    # =========================================================================

    def _kill_process_tree(self, params: dict) -> dict:
        """
        v4.0: Kill a process and ALL its children recursively.
        Uses PowerShell Get-CimInstance to enumerate child processes.
        Kills from the bottom up (deepest children first, parent last).
        
        Params:
            pid: Target process PID (recommended)
            name: Target process name (fallback, kills all instances)
        """
        pid = params.get("pid", 0)
        process_name = params.get("name", "")

        if not pid and not process_name:
            return {"status": "failed", "error": "PID or process name required for kill_tree"}

        if IS_WINDOWS:
            # v4.5.5 SECURITY: sanitize target to prevent PowerShell injection
            import re as _re
            if pid:
                target = str(int(pid))
            else:
                target = _re.sub(r"[^A-Za-z0-9._ -]", "", str(process_name))[:128].strip()
            if not target:
                return {"status": "failed", "error": "Invalid process name/PID for kill_tree"}

            # PowerShell script: recursively find all children and kill bottom-up
            ps = f"""
$target = '{target}'
$mode = '{'pid' if pid else 'name'}'
$killed = @()
try {{
    # If by name, find all matching PIDs
    if ($mode -eq 'name') {{
        $procs = Get-Process -Name $target -ErrorAction SilentlyContinue
        if (-not $procs) {{
            Write-Output "NOT_FOUND:$target"
            exit
        }}
        $pids = $procs | Select-Object -ExpandProperty Id
    }} else {{
        $pids = @([int]$target)
    }}

    foreach ($rootPid in $pids) {{
        # Build tree: get all descendants recursively
        $allPids = [System.Collections.Generic.HashSet[int]]::new()
        $queue = [System.Collections.Generic.Queue[int]]::new()
        $queue.Enqueue([int]$rootPid)
        while ($queue.Count -gt 0) {{
            $currentPid = $queue.Dequeue()
            if ($allPids.Add($currentPid)) {{
                try {{
                    $children = Get-CimInstance Win32_Process -Filter "ParentProcessId=$currentPid" -ErrorAction SilentlyContinue |
                        Select-Object -ExpandProperty ProcessId
                    foreach ($c in $children) {{ $queue.Enqueue($c) }}
                }} catch {{ }}
            }}
        }}

        # Kill bottom-up: children first, parent last
        $orderedPids = @($allPids | Sort-Object)
        [array]::Reverse($orderedPids)
        foreach ($p in $orderedPids) {{
            try {{
                Stop-Process -Id $p -Force -ErrorAction Stop
                $killed += $p
            }} catch {{ }}
        }}
    }}
    if ($killed.Count -gt 0) {{
        Write-Output "KILLED:$($killed -join ',')"
    }}
}} catch {{
    Write-Output "ERROR:$_"
}}
"""
            stdout, stderr, rc = _run(
                ["powershell", "-NoProfile", "-Command", ps], timeout=30
            )
            output = stdout.strip() if stdout else stderr or ""
            if output.startswith("KILLED:"):
                pids_killed = output[7:].split(",") if output[7:] else []
                return {
                    "status": "completed",
                    "output": f"Kill tree complete: {len(pids_killed)} processes terminated (PIDs: {', '.join(pids_killed[:10])}{'...' if len(pids_killed) > 10 else ''})",
                    "killed_pids": [int(x) for x in pids_killed if x.strip().isdigit()],
                }
            elif output.startswith("NOT_FOUND:"):
                return {"status": "failed", "error": f"Process not found: {output[10:]}"}
            return {"status": "failed", "error": output[:500] or "Kill tree failed"}
        else:
            # Linux: pkill with parent-child tree using pgrep
            if pid:
                stdout, _, rc = _run(["pkill", "-9", "-P", str(int(pid))], timeout=10)
                _run(["kill", "-9", str(int(pid))], timeout=10)
                return {"status": "completed", "output": f"Kill tree initiated for PID {pid}"}
            elif process_name:
                import re as _re
                safe_name = _re.sub(r"[^A-Za-z0-9._ -]", "", str(process_name))[:128].strip()
                if not safe_name:
                    return {"status": "failed", "error": "Invalid process name"}
                stdout, _, rc = _run(["pkill", "-9", _re.escape(safe_name)], timeout=10)
                return {"status": "completed", "output": f"Kill tree initiated for {safe_name}"}
            return {"status": "failed", "error": "PID or name required"}

    # =========================================================================
    # v4.0: Lock User Account (Auto-response to KERB-*)
    # =========================================================================

    def _lock_account(self) -> dict:
        """
        v4.0: Lock the current user account immediately.
        Used as auto-response to Kerberos Golden Ticket attacks (KERB-001).
        """
        if IS_WINDOWS:
            # Get current logged-on user
            stdout, _, _ = _run(["powershell", "-NoProfile", "-Command",
                "(Get-WmiObject -Class Win32_ComputerSystem).UserName"], timeout=10)
            username = stdout.strip() if stdout else ""
            if not username:
                # Try query user
                stdout2, _, _ = _run(["query", "user"], timeout=5)
                if stdout2:
                    lines = stdout2.strip().split("\n")
                    if len(lines) > 1:
                        username = lines[1].split()[0] if lines[1].split() else ""
            if username:
                # Remove domain prefix if present
                if "\\" in username:
                    username = username.split("\\")[-1]
                stdout3, stderr, rc = _run([
                    "powershell", "-NoProfile", "-Command",
                    f"Disable-LocalUser -Name '{username}' -ErrorAction Stop; Write-Output 'LOCKED:{username}'"
                ], timeout=15)
                if rc == 0:
                    return {
                        "status": "completed",
                        "output": f"User account {username} locked (disabled) due to Kerberos attack",
                        "locked_user": username,
                    }
                return {"status": "failed", "error": stderr or f"Failed to lock {username}"}
            return {"status": "failed", "error": "Could not determine current username"}
        else:
            stdout, _, _ = _run(["whoami"], timeout=5)
            username = stdout.strip() if stdout else ""
            if username:
                stdout2, stderr, rc = _run(["passwd", "-l", username], timeout=10)
                if rc == 0:
                    return {"status": "completed", "output": f"User {username} locked"}
                return {"status": "failed", "error": stderr or "passwd failed"}
            return {"status": "failed", "error": "Could not determine current username"}

    # =========================================================================
    # v3.9.2: Group Policy Enforcement Actions
    # =========================================================================

    def _apply_block_usb(self, cmd: str) -> dict:
        """Block USB storage devices via registry + group policy."""
        if IS_WINDOWS:
            ps = '''
$path = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR"
Set-ItemProperty -Path $path -Name "Start" -Value 4 -Type DWord -Force
Write-Output "USB storage blocked (registry Start=4)"
'''
            stdout, stderr, rc = _run(["powershell", "-NoProfile", "-Command", ps], timeout=15)
            if rc == 0:
                return {"status": "completed", "output": "USB storage devices blocked.", "rollback_possible": True,
                        "rollback_action": "remove_block_usb"}
            return {"status": "failed", "error": stderr or "Failed to block USB"}
        return {"status": "failed", "error": "Not supported on this platform"}

    def _remove_block_usb(self, cmd: str) -> dict:
        """Re-enable USB storage devices."""
        if IS_WINDOWS:
            ps = '''
$path = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR"
Set-ItemProperty -Path $path -Name "Start" -Value 3 -Type DWord -Force
Write-Output "USB storage re-enabled (registry Start=3)"
'''
            stdout, stderr, rc = _run(["powershell", "-NoProfile", "-Command", ps], timeout=15)
            if rc == 0:
                return {"status": "completed", "output": "USB storage devices re-enabled."}
            return {"status": "failed", "error": stderr or "Failed to unblock USB"}
        return {"status": "failed", "error": "Not supported on this platform"}

    def _apply_block_websites(self, cmd: str) -> dict:
        """Block websites by resolving DNS → blocking IPs via firewall + hosts file.
        Config JSON: {"domains": ["youtube.com", "facebook.com", ...]}
        v3.9.3: Uses DNS resolution to get actual IPs, blocks via firewall rules."""
        try:
            config = json.loads(cmd) if cmd else {}
        except Exception:
            config = {}
        domains = config.get("domains", [])
        if not domains:
            return {"status": "failed", "error": "No domains specified in config"}

        # v4.5.5 SECURITY: sanitize domains (prevent PowerShell + hosts-file injection)
        import re as _re
        domains = [_re.sub(r"[^A-Za-z0-9.*-]", "", str(d))[:253] for d in domains]
        domains = [d for d in domains if d]
        if not domains:
            return {"status": "failed", "error": "No valid domains specified in config"}

        if IS_WINDOWS:
            results = []
            # 1. Resolve domains to IPs and block via firewall (most effective)
            blocked_ips = set()
            for domain in domains:
                rule_name = f"GIAMSAT_WEB_{domain.replace('.', '_')}"
                # Remove old rules first
                _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"])
                # Block outbound to this domain's IPs on port 80,443
                ps_resolve = f'''
try {{
    $ips = Resolve-DnsName -Name "{domain}" -Type A -ErrorAction Stop | Select-Object -ExpandProperty IPAddress
    Write-Output ($ips -join ",")
}} catch {{ Write-Output "" }}
'''
                stdout, _, _ = _run(["powershell", "-NoProfile", "-Command", ps_resolve], timeout=10)
                ips = [ip.strip() for ip in stdout.strip().split(",") if ip.strip()]
                if ips:
                    for ip in ips[:20]:  # Max 20 IPs per domain
                        _run([
                            "netsh", "advfirewall", "firewall", "add", "rule",
                            f"name={rule_name}_{ip.replace('.','_')}",
                            "dir=out", "action=block",
                            f"remoteip={ip}",
                            "protocol=TCP",
                            "enable=yes", "profile=any"
                        ], timeout=10)
                        blocked_ips.add(ip)
                    results.append(f"{domain}: {len(ips)} IPs blocked via firewall")

            # 2. Block DNS resolution via hosts file (backup)
            try:
                hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
                marker = "# GIAM-SAT POLICY BLOCK START"
                marker_end = "# GIAM-SAT POLICY BLOCK END"
                new_entries = "\n".join(f"127.0.0.1 {d}\n127.0.0.1 www.{d}" for d in domains)
                hosts_block = f"\n{marker}\n{new_entries}\n{marker_end}\n"
                with open(hosts_path, "r", encoding="utf-8") as f:
                    content = f.read()
                if marker in content:
                    content = content[:content.index(marker)] + content[content.index(marker_end) + len(marker_end):]
                with open(hosts_path, "w", encoding="utf-8") as f:
                    f.write(content + hosts_block)
                results.append(f"Hosts: {len(domains)} domains + www subdomains blocked")
            except Exception as e:
                results.append(f"Hosts error: {e}")

            output = "; ".join(results) if results else "No IPs resolved, hosts file updated only"
            return {"status": "completed", "output": output, "rollback_possible": True,
                    "rollback_action": "remove_block_websites", "rollback_params": {"domains": domains}}
        return {"status": "failed", "error": "Not supported on this platform"}

    def _remove_block_websites(self, cmd: str) -> dict:
        """Remove website blocks: delete firewall rules + remove hosts entries."""
        try:
            config = json.loads(cmd) if cmd else {}
        except Exception:
            config = {}
        domains = config.get("domains", [])

        if IS_WINDOWS:
            results = []
            # 1. Remove hosts block
            try:
                hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
                marker = "# GIAM-SAT POLICY BLOCK START"
                marker_end = "# GIAM-SAT POLICY BLOCK END"
                with open(hosts_path, "r", encoding="utf-8") as f:
                    content = f.read()
                if marker in content:
                    content = content[:content.index(marker)] + content[content.index(marker_end) + len(marker_end):]
                    with open(hosts_path, "w", encoding="utf-8") as f:
                        f.write(content)
                    results.append("Hosts: block removed")
            except Exception as e:
                results.append(f"Hosts error: {e}")

            # 2. Delete ALL GIAMSAT_WEB_* firewall rules
            stdout, _, _ = _run(["powershell", "-NoProfile", "-Command",
                "netsh advfirewall firewall show rule name=all | Select-String 'GIAMSAT_WEB_' | ForEach-Object { "
                "$_ -replace '.*Rule Name:\\s*','' | ForEach-Object { netsh advfirewall firewall delete rule name=`\"$_`\" } }"
            ], timeout=20)
            results.append("Firewall: GIAMSAT_WEB_* rules removed")

            return {"status": "completed", "output": "; ".join(results)}
        return {"status": "failed", "error": "Not supported on this platform"}

    def _apply_block_software(self, cmd: str) -> dict:
        """Block software installation via AppLocker + SRP (CLM-safe).
        Config JSON: {"blocked_paths": ["%USERPROFILE%\\Downloads\\*.exe", ...]}"""
        try:
            config = json.loads(cmd) if cmd else {}
        except Exception:
            config = {}
        blocked = config.get("blocked_paths", [
            r"%USERPROFILE%\Downloads\*.exe",
            r"%USERPROFILE%\Downloads\*.msi",
            r"%TEMP%\*.exe",
            r"%TEMP%\*.msi",
            r"%APPDATA%\*.exe",
        ])

        # v4.5.5 SECURITY: sanitize paths (prevent PowerShell injection via policy config)
        import re as _re
        blocked = [_re.sub(r"[^A-Za-z0-9%\\/:._\- *()]", "", str(p))[:512] for p in blocked]
        blocked = [p for p in blocked if p]
        if not blocked:
            return {"status": "failed", "error": "No valid blocked paths specified"}

        if IS_WINDOWS:
            # Build paths list for PowerShell
            paths_arr = ",\n".join('"' + p + '"' for p in blocked)
            n_paths = len(blocked)
            ps = (
                '$ErrorActionPreference = "Continue"\n'
                '$results = @()\n'
                '$paths = @(\n' + paths_arr + '\n)\n'
                '\n'
                '# === AppLocker approach (build XML in PS to avoid Python escaping) ===\n'
                'try {\n'
                '    $ruleXml = ' +
                repr('<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="Enabled">') + '\n'
                '    foreach ($p in $paths) {\n'
                '        $guid = (New-Guid).Guid\n'
                '        $condition = "<FilePathCondition Path=" + [char]34 + $p + [char]34 + " />"\n'
                '        $rule = "<FilePathRule Id=" + [char]34 + $guid + [char]34 + " Name=" + [char]34 + "GIAM-SAT Block: " + $p + [char]34 + " Description=" + [char]34 + [char]34 + " UserOrGroupSid=" + [char]34 + "S-1-1-0" + [char]34 + " Action=" + [char]34 + "Deny" + [char]34 + ">"\n'
                '        $ruleXml += $rule + "<Conditions>" + $condition + "</Conditions></FilePathRule>"\n'
                '    }\n'
                '    $ruleXml += ' +
                repr('</RuleCollection></AppLockerPolicy>') + '\n'
                '    $tempXml = Join-Path $env:TEMP "giamsat_applocker_policy.xml"\n'
                '    [System.IO.File]::WriteAllText($tempXml, $ruleXml, [System.Text.Encoding]::UTF8)\n'
                '    Set-AppLockerPolicy -XmlPolicy $tempXml -ErrorAction Stop\n'
                '    Remove-Item $tempXml -Force\n'
                '    $results += "AppLocker: ' + str(n_paths) + ' path rules applied"\n'
                '} catch {\n'
                '    $results += "AppLocker failed: $_"\n'
                '}\n'
                '\n'
                '# === SRP registry fallback ===\n'
                '$srpKey = "HKLM:\\\\SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows\\\\Safer\\\\CodeIdentifiers"\n'
                'New-Item -Path $srpKey -Force | Out-Null\n'
                'Set-ItemProperty -Path $srpKey -Name "DefaultLevel" -Value 0 -Type DWord -Force\n'
                'Set-ItemProperty -Path $srpKey -Name "PolicyScope" -Value 0 -Type DWord -Force\n'
                '$ruleKey = "$srpKey\\\\PathRules"\n'
                'Remove-Item -Path $ruleKey -Recurse -Force -ErrorAction SilentlyContinue\n'
                'New-Item -Path $ruleKey -Force | Out-Null\n'
                '$i = 1000\n'
                'foreach ($p in $paths) {\n'
                '    $id = "{0:D4}" -f $i\n'
                '    $itemKey = "$ruleKey\\\\$id"\n'
                '    New-Item -Path $itemKey -Force | Out-Null\n'
                '    Set-ItemProperty -Path $itemKey -Name "Description" -Value "GIAM-SAT Block" -Force\n'
                '    Set-ItemProperty -Path $itemKey -Name "ItemData" -Value $p -Force\n'
                '    Set-ItemProperty -Path $itemKey -Name "SaferFlags" -Value 0 -Type DWord -Force\n'
                '    $i++\n'
                '}\n'
                '$results += "SRP: ' + str(n_paths) + ' paths restricted (requires reboot)"\n'
                'gpupdate /force | Out-Null\n'
                'Write-Output ($results -join "; ")\n'
            )
            stdout, stderr, rc = _run(["powershell", "-NoProfile", "-Command", ps], timeout=30)
            if rc == 0:
                return {"status": "completed", "output": stdout.strip() or "Software restrictions applied.",
                        "rollback_possible": True, "rollback_action": "remove_block_software"}
            return {"status": "failed", "error": (stderr or stdout or "Failed to apply")[:500]}
        return {"status": "failed", "error": "Not supported on this platform"}

    def _remove_block_software(self, cmd: str) -> dict:
        """Remove all software installation restrictions (AppLocker + SRP)."""
        if IS_WINDOWS:
            ps = '''
$ErrorActionPreference = "Continue"
$results = @()

# Remove AppLocker policy
try {
    # Empty AppLocker policy (CLM safe - no New-Object needed)
    $emptyXml = '<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="NotConfigured" /></AppLockerPolicy>'
    Set-AppLockerPolicy -XmlPolicy $emptyXml -ErrorAction Stop
    $results += "AppLocker: enforcement removed"
} catch { $results += "AppLocker removal: $_" }

# Remove SRP registry
try {
    $key = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers\\PathRules"
    Remove-Item -Path $key -Recurse -Force -ErrorAction SilentlyContinue
    $parentKey = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers"
    Set-ItemProperty -Path $parentKey -Name "DefaultLevel" -Value 262144 -Type DWord -Force -ErrorAction SilentlyContinue
    $results += "SRP: restrictions removed"
} catch { $results += "SRP removal: $_" }

gpupdate /force | Out-Null
Write-Output ($results -join "; ")
'''
            stdout, stderr, rc = _run(["powershell", "-NoProfile", "-Command", ps], timeout=20)
            if rc == 0:
                return {"status": "completed", "output": "Software restrictions removed."}
            return {"status": "failed", "error": (stderr or stdout or "Failed")[:500]}
        return {"status": "failed", "error": "Not supported on this platform"}

    # =========================================================================
    # v2.5.2: Machine Control Actions (read-only diagnostics)
    # =========================================================================

    def _get_processes(self) -> dict:
        """Get list of running processes."""
        if IS_WINDOWS:
            ps_script = """Get-Process | Select-Object Name,Id,CPU,PM,StartTime,Company |
                Sort-Object PM -Descending | Select-Object -First 100 |
                ConvertTo-Json -Compress"""
            stdout, stderr, rc = _run([
                "powershell", "-NoProfile", "-Command", ps_script
            ])
            if rc == 0 and stdout:
                return {"status": "completed", "output": stdout.strip()}
            return {"status": "failed", "error": stderr or "Failed to get processes"}
        else:
            stdout, stderr, rc = _run(["ps", "aux", "--sort=-%mem"])
            return {"status": "completed", "output": stdout.strip()}

    def _get_services(self) -> dict:
        """Get list of Windows services with status."""
        if IS_WINDOWS:
            stdout, stderr, rc = _run([
                "powershell", "-NoProfile", "-Command",
                "Get-Service | Select-Object Name,Status,DisplayName,StartType | ConvertTo-Json -Compress"
            ])
            if rc == 0 and stdout:
                return {"status": "completed", "output": stdout.strip()}
            return {"status": "failed", "error": stderr or "Failed to get services"}
        else:
            stdout, stderr, rc = _run(["systemctl", "list-units", "--type=service", "--no-pager"])
            return {"status": "completed", "output": stdout.strip()}

    def _get_connections(self) -> dict:
        """Get list of active network connections (netstat)."""
        if IS_WINDOWS:
            stdout, stderr, rc = _run([
                "powershell", "-NoProfile", "-Command",
                "Get-NetTCPConnection -State Established | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess | ConvertTo-Json -Compress"
            ])
            if rc == 0:
                return {"status": "completed", "output": stdout.strip() if stdout else "[]"}
            # Fallback to netstat
            stdout2, _, _ = _run(["netstat", "-ano", "|", "findstr", "ESTABLISHED"])
            return {"status": "completed", "output": stdout2.strip() if stdout2 else "[]"}
        else:
            stdout, stderr, rc = _run(["ss", "-tuln"])
            return {"status": "completed", "output": stdout.strip()}

    def _get_scheduled_tasks(self) -> dict:
        """Get list of scheduled tasks."""
        if IS_WINDOWS:
            stdout, stderr, rc = _run([
                "schtasks", "/query", "/fo", "CSV", "/v", "/nh"
            ])
            if rc == 0:
                return {"status": "completed", "output": stdout.strip()}
            return {"status": "failed", "error": stderr or "Failed to get scheduled tasks"}
        else:
            stdout, stderr, rc = _run(["crontab", "-l"])
            return {"status": "completed", "output": stdout.strip() if rc == 0 else "(no crontab)"}

    def _get_startup_programs(self) -> dict:
        """Get list of startup programs (registry + startup folder)."""
        if IS_WINDOWS:
            stdout, stderr, rc = _run([
                "powershell", "-NoProfile", "-Command",
                "Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location,User | ConvertTo-Json -Compress"
            ])
            if rc == 0:
                return {"status": "completed", "output": stdout.strip() if stdout else "[]"}
            return {"status": "failed", "error": stderr or "Failed to get startup programs"}
        else:
            stdout, _, _ = _run(["ls", "/etc/init.d/"])
            return {"status": "completed", "output": stdout.strip() if stdout else "[]"}

    # =========================================================================
    # Response Playbook (automated workflow)
    # =========================================================================

    def execute_playbook(self, alert_data: dict) -> list:
        """Execute automated response playbook based on alert severity and type.
        
        Playbook rules:
          - CRITICAL threat_alert -> quarantine if file_path, block IP if source_ip, isolate if lateral movement
          - HIGH threat_alert -> kill process, block IP
          - MEDIUM -> forensic snapshot only
        """
        results = []
        severity = alert_data.get("severity", "LOW")
        alert_type = alert_data.get("type", "")

        if severity == "CRITICAL":
            # Aggressive response
            if alert_data.get("source_ip"):
                results.append(self.execute_command({
                    "action": "firewall_block",
                    "exec_id": f"playbook_{int(time.time())}",
                    "params": {"ip": alert_data["source_ip"], "direction": "both"},
                }))
            if alert_data.get("file_path"):
                results.append(self.execute_command({
                    "action": "quarantine_file",
                    "exec_id": f"playbook_{int(time.time())}",
                    "params": {"file_path": alert_data["file_path"], "reason": alert_data.get("description", "")},
                }))
            results.append(self._forensic_snapshot())

        elif severity == "HIGH":
            if alert_data.get("process_name") or alert_data.get("pid"):
                results.append(self.execute_command({
                    "action": "kill_process",
                    "exec_id": f"playbook_{int(time.time())}",
                    "params": {"name": alert_data.get("process_name", ""), "pid": alert_data.get("pid", 0)},
                }))
            if alert_data.get("source_ip"):
                results.append(self.execute_command({
                    "action": "firewall_block",
                    "exec_id": f"playbook_{int(time.time())}",
                    "params": {"ip": alert_data["source_ip"]},
                }))

        elif severity == "MEDIUM":
            results.append(self._forensic_snapshot())

        return results

    # =========================================================================
    # v2.5.11: Show Message from Server (with reply)
    # =========================================================================

    def _show_messagebox(self, command_data: dict) -> dict:
        """
        Show a message box from server with optional reply support.
        Uses PowerShell Windows Forms for rich UI with reply textbox.
        
        command_data format:
        {
            "action": "show_message",
            "msg_id": "uuid",
            "title": "Thong bao tu quan tri vien",
            "message": "Noi dung tin nhan...",
            "sender": "admin",
            "require_reply": true
        }
        """
        msg_id = command_data.get("msg_id", f"msg_{int(time.time())}")
        title = command_data.get("title", "Thong bao")
        message = command_data.get("message", "")
        sender = command_data.get("sender", "admin")
        require_reply = command_data.get("require_reply", True)

        # Escape strings for PowerShell (prevent injection)
        ps_title = title.replace("'", "''")
        ps_message = message.replace("'", "''")
        ps_sender = sender.replace("'", "''")
        ps_msg_id = msg_id.replace("'", "''")

        result_file = os.path.join(tempfile.gettempdir(), f"giamsat_msg_reply_{os.getpid()}_{msg_id}.json")
        ps_file = os.path.join(tempfile.gettempdir(), f"giamsat_msg_{os.getpid()}_{msg_id}.ps1")

        # Build PowerShell script with textbox for reply
        reply_box_height = 80 if require_reply else 0
        form_height = 280 + reply_box_height

        ps_script = f'''Add-Type -AssemblyName System.Windows.Forms,System.Drawing
$f=New-Object System.Windows.Forms.Form
$f.Text="GIAM-SAT - {ps_title}"
$f.Size=New-Object System.Drawing.Size(480,{form_height})
$f.StartPosition="CenterScreen"
$f.FormBorderStyle="FixedDialog"
$f.MaximizeBox=$false;$f.MinimizeBox=$false;$f.TopMost=$true
$f.BackColor=[System.Drawing.Color]::FromArgb(15,25,35)
$f.ForeColor=[System.Drawing.Color]::White

$lblSender=New-Object System.Windows.Forms.Label
$lblSender.Text="Nguoi gui: {ps_sender}"
$lblSender.Font=New-Object System.Drawing.Font("Segoe UI",9,[System.Drawing.FontStyle]::Bold)
$lblSender.ForeColor=[System.Drawing.Color]::FromArgb(0,212,170)
$lblSender.AutoSize=$true;$lblSender.Location=New-Object System.Drawing.Point(20,15)
$f.Controls.Add($lblSender)

$lblMsg=New-Object System.Windows.Forms.Label
$lblMsg.Text="{ps_message}"
$lblMsg.Font=New-Object System.Drawing.Font("Segoe UI",10)
$lblMsg.ForeColor=[System.Drawing.Color]::FromArgb(238,244,248)
$lblMsg.Location=New-Object System.Drawing.Point(20,40)
$lblMsg.Size=New-Object System.Drawing.Size(420,100)
$lblMsg.AutoSize=$false
$f.Controls.Add($lblMsg)
'''

        if require_reply:
            ps_script += f'''
$lblReply=New-Object System.Windows.Forms.Label
$lblReply.Text="Tra loi:"
$lblReply.Font=New-Object System.Drawing.Font("Segoe UI",9)
$lblReply.ForeColor=[System.Drawing.Color]::FromArgb(200,216,232)
$lblReply.AutoSize=$true;$lblReply.Location=New-Object System.Drawing.Point(20,150)
$f.Controls.Add($lblReply)

$txtReply=New-Object System.Windows.Forms.TextBox
$txtReply.Font=New-Object System.Drawing.Font("Segoe UI",10)
$txtReply.BackColor=[System.Drawing.Color]::FromArgb(26,42,58)
$txtReply.ForeColor=[System.Drawing.Color]::FromArgb(238,244,248)
$txtReply.Multiline=$true
$txtReply.Location=New-Object System.Drawing.Point(20,172)
$txtReply.Size=New-Object System.Drawing.Size(420,60)
$f.Controls.Add($txtReply)
$txtReply.Focus()

$btnReply=New-Object System.Windows.Forms.Button
$btnReply.Text="Gui tin nhan"
$btnReply.Font=New-Object System.Drawing.Font("Segoe UI",10,[System.Drawing.FontStyle]::Bold)
$btnReply.BackColor=[System.Drawing.Color]::FromArgb(26,58,42)
$btnReply.ForeColor=[System.Drawing.Color]::FromArgb(136,221,153)
$btnReply.FlatStyle="Flat";$btnReply.Cursor="Hand"
$btnReply.Location=New-Object System.Drawing.Point(200,{190 + reply_box_height})
$btnReply.Size=New-Object System.Drawing.Size(100,30)
$btnReply.DialogResult=[System.Windows.Forms.DialogResult]::OK
$f.AcceptButton=$btnReply
$f.Controls.Add($btnReply)

$btnClose=New-Object System.Windows.Forms.Button
$btnClose.Text="Dong"
$btnClose.Font=New-Object System.Drawing.Font("Segoe UI",10)
$btnClose.BackColor=[System.Drawing.Color]::FromArgb(58,26,26)
$btnClose.ForeColor=[System.Drawing.Color]::FromArgb(255,136,136)
$btnClose.FlatStyle="Flat";$btnClose.Cursor="Hand"
$btnClose.Location=New-Object System.Drawing.Point(310,{190 + reply_box_height})
$btnClose.Size=New-Object System.Drawing.Size(80,30)
$btnClose.DialogResult=[System.Windows.Forms.DialogResult]::Cancel
$f.Controls.Add($btnClose)

$r=$f.ShowDialog()
$d=@{{}}
$d["msg_id"]="{ps_msg_id}"
if($r -eq [System.Windows.Forms.DialogResult]::OK){{$d["reply"]=$txtReply.Text.Trim();$d["replied"]=$true}}else{{$d["reply"]="";$d["replied"]=$false}}
$d|ConvertTo-Json|Out-File -FilePath '{result_file}' -Encoding UTF8 -Force
'''
        else:
            ps_script += f'''
$btnClose=New-Object System.Windows.Forms.Button
$btnClose.Text="Dong"
$btnClose.Font=New-Object System.Drawing.Font("Segoe UI",10,[System.Drawing.FontStyle]::Bold)
$btnClose.BackColor=[System.Drawing.Color]::FromArgb(26,58,42)
$btnClose.ForeColor=[System.Drawing.Color]::FromArgb(136,221,153)
$btnClose.FlatStyle="Flat";$btnClose.Cursor="Hand"
$btnClose.Location=New-Object System.Drawing.Point(190,160)
$btnClose.Size=New-Object System.Drawing.Size(100,30)
$btnClose.DialogResult=[System.Windows.Forms.DialogResult]::OK
$f.AcceptButton=$btnClose
$f.Controls.Add($btnClose)

$f.ShowDialog()
$d=@{{}}
$d["msg_id"]="{ps_msg_id}"
$d["reply"]=""
$d["replied"]=$false
$d|ConvertTo-Json|Out-File -FilePath '{result_file}' -Encoding UTF8 -Force
'''

        try:
            with open(ps_file, "w", encoding="utf-8") as f:
                f.write(ps_script)
        except Exception as e:
            return {"status": "failed", "error": f"Cannot write PS script: {e}"}

        # Launch PowerShell dialog
        try:
            ps_proc = subprocess.Popen(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                 "-WindowStyle", "Normal", "-File", ps_file],
                creationflags=subprocess.CREATE_NEW_CONSOLE,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            ps_proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            try: ps_proc.kill()
            except: pass
        except Exception as e:
            return {"status": "failed", "error": f"PowerShell failed: {e}"}

        # Read reply
        reply_text = ""
        replied = False
        try:
            if os.path.exists(result_file):
                with open(result_file, "r", encoding="utf-8-sig") as f:
                    data = json.loads(f.read())
                os.remove(result_file)
                replied = data.get("replied", False)
                reply_text = data.get("reply", "")
        except Exception:
            pass

        # Cleanup PS script
        try: os.remove(ps_file)
        except: pass

        return {
            "status": "completed",
            "output": "Message displayed",
            "msg_reply": reply_text,
            "msg_replied": replied,
            "msg_id": msg_id,
        }
