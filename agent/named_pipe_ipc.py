"""
GIAM-SAT Named Pipe IPC v1.0.0
Secure inter-process communication between Agent and Updater using Windows Named Pipes.

Why Named Pipes instead of HTTP localhost:5999?
  - Port Hijacking: Malware can bind to 5999 before Updater starts
  - Local Firewall: Some enterprise policies block loopback ports
  - No Authentication: Any process can send HTTP commands if port is open

Named Pipes provide:
  - Windows ACL: Only allow specific SIDs (SYSTEM + current user)
  - No network stack: Zero port attack surface
  - Kernel-level security: Access control enforced by Windows Object Manager

Usage:
  Updater:  server = NamedPipeServer() → server.serve_forever()
  Agent:    client = NamedPipeClient() → client.send_command({"action": "update", ...})
"""
import os
import json
import time
import threading
import traceback
import subprocess

_HAS_WIN32_PIPE = False
_HAS_WIN32_SECURITY = False

try:
    import pywintypes
    import win32pipe
    import win32file
    import win32event
    import win32security
    import win32api
    import win32con
    import ntsecuritycon as con
    _HAS_WIN32_PIPE = True
    _HAS_WIN32_SECURITY = True
except ImportError:
    try:
        import win32pipe
        import win32file
        _HAS_WIN32_PIPE = True
    except ImportError:
        pass

# Pipe name (well-known, unique to GIAM-SAT)
PIPE_NAME = r"\\.\pipe\GIAMSAT-Updater"

# Commands that flow Agent → Updater
VALID_COMMANDS = {"update", "reset-user", "msg"}

# Timeouts (seconds)
PIPE_TIMEOUT = 5000     # ms - WaitNamedPipe
SEND_TIMEOUT = 10       # Send + receive response
CONNECT_RETRY = 3       # Number of retry attempts
RETRY_DELAY = 1.0       # Seconds between retries


# ============================================================================
# Named Pipe Server (runs inside Updater)
# ============================================================================

class NamedPipeServer:
    """Windows Named Pipe server that receives commands from Agent.
    Replaces HTTPServer on 127.0.0.1:5999."""

    def __init__(self, callback_on_command):
        """
        Args:
            callback_on_command: function(command: dict) -> dict
                Called when Agent sends a command. Returns response dict.
        """
        if not _HAS_WIN32_PIPE:
            raise RuntimeError("win32pipe not available. Install pywin32: pip install pywin32")

        self.callback = callback_on_command
        self.running = True
        self._pipe_handle = None

    def _create_pipe(self):
        """
        v3.9.17: Create a named pipe instance with STRICT ACL.
        Only SYSTEM + current user SID can connect.
        v4.11 (HIGH-5 FIX): FAIL-CLOSED - without win32security the server refuses
        to create the pipe instead of falling back to default (open) security,
        which any local process could connect to.
        """
        if not _HAS_WIN32_SECURITY:
            raise RuntimeError(
                "win32security not available - refusing to create an unprotected "
                "named pipe (fail-closed). Install pywin32."
            )
        return self._create_pipe_with_acl()

    def _create_pipe_with_acl(self):
        """Create pipe with strict ACL: only SYSTEM + current user SID."""
        if not _HAS_WIN32_SECURITY:
            return self._create_pipe()

        try:
            # Get current process token
            token = win32security.OpenProcessToken(
                win32security.GetCurrentProcess(),
                win32security.TOKEN_QUERY
            )
            current_user_sid = win32security.GetTokenInformation(
                token, win32security.TokenUser
            )[0]

            # Get SYSTEM SID
            system_sid = win32security.CreateWellKnownSid(win32security.WinLocalSystemSid)

            # Build DACL granting access to SYSTEM + current user only
            dacl = win32security.ACL()
            dacl.AddAccessAllowedAce(
                win32security.ACL_REVISION,
                con.FILE_GENERIC_READ | con.FILE_GENERIC_WRITE,
                system_sid
            )
            dacl.AddAccessAllowedAce(
                win32security.ACL_REVISION,
                con.FILE_GENERIC_READ | con.FILE_GENERIC_WRITE,
                current_user_sid
            )

            # Create security descriptor
            sd = win32security.SECURITY_DESCRIPTOR()
            sd.SetSecurityDescriptorDacl(1, dacl, 0)

            sa = win32security.SECURITY_ATTRIBUTES()
            sa.SECURITY_DESCRIPTOR = sd
            sa.bInheritHandle = False

            pipe_handle = win32pipe.CreateNamedPipe(
                PIPE_NAME,
                win32pipe.PIPE_ACCESS_DUPLEX,
                win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
                win32pipe.PIPE_UNLIMITED_INSTANCES,
                4096, 4096, 0,
                sa
            )
            return pipe_handle
        except Exception as e:
            # v4.11 (HIGH-5 FIX): fail-closed - ACL build failure must never
            # produce an unprotected pipe.
            raise RuntimeError(f"Failed to build strict pipe ACL (fail-closed): {e}")

    def _process_connection(self, pipe_handle):
        """Handle one client connection on the pipe."""
        try:
            # Wait for client to connect
            win32pipe.ConnectNamedPipe(pipe_handle, None)

            # Read command (JSON, newline-terminated)
            success, data = win32file.ReadFile(pipe_handle, 65536)
            if not success or not data:
                return

            # Parse JSON command
            try:
                command = json.loads(data.decode("utf-8").strip())
            except json.JSONDecodeError:
                self._send_response(pipe_handle, {"status": "error", "error": "Invalid JSON"})
                return

            # Process command
            action = command.get("action", "")
            if action not in VALID_COMMANDS:
                self._send_response(pipe_handle, {"status": "error", "error": f"Unknown action: {action}"})
                return

            # Call callback (e.g., Updater's update handler)
            try:
                response = self.callback(command)
                if response is None:
                    response = {"status": "accepted"}
            except Exception as e:
                response = {"status": "error", "error": str(e)[:500]}

            self._send_response(pipe_handle, response)

        except Exception:
            pass
        finally:
            try:
                win32file.CloseHandle(pipe_handle)
            except Exception:
                pass

    def _send_response(self, pipe_handle, data):
        """Send JSON response back to Agent."""
        try:
            body = json.dumps(data).encode("utf-8")
            win32file.WriteFile(pipe_handle, body)
        except Exception:
            pass

    def serve_forever(self):
        """Main loop: continuously accept pipe connections."""
        print(f"[PIPE] Named Pipe Server listening on {PIPE_NAME}")

        while self.running:
            try:
                pipe_handle = self._create_pipe_with_acl()
                self._pipe_handle = pipe_handle

                # Handle connection in current thread (simple, one-at-a-time)
                # Multiple agents connect sequentially - pipe is fast enough
                self._process_connection(pipe_handle)

            except Exception as e:
                print(f"[PIPE] Error: {e}")
                time.sleep(0.5)

        print("[PIPE] Named Pipe Server stopped")

    def stop(self):
        """Signal the server to stop."""
        self.running = False


# ============================================================================
# Named Pipe Client (runs inside Agent)
# ============================================================================

class NamedPipeClient:
    """Client that sends commands to Updater via Named Pipe.
    Used by AgentCore._forward_to_updater() or _handle_agent_update_command()."""

    def __init__(self, timeout=SEND_TIMEOUT):
        if not _HAS_WIN32_PIPE:
            raise RuntimeError("win32pipe not available. Install pywin32: pip install pywin32")
        self.timeout = timeout

    def send_command(self, command: dict) -> dict:
        """
        Send a command to Updater and return the response.

        Args:
            command: dict with at least {"action": "update"|"reset-user"|"msg", ...}

        Returns:
            dict: {"status": "accepted"|"error", "error": "..."}

        Raises:
            RuntimeError: if pipe is not available after all retries
        """
        if not _HAS_WIN32_PIPE:
            return {"status": "error", "error": "win32pipe not available"}

        action = command.get("action", "")
        if action not in VALID_COMMANDS:
            return {"status": "error", "error": f"Unknown action: {action}"}

        for attempt in range(CONNECT_RETRY):
            try:
                # Wait for pipe to be available
                win32pipe.WaitNamedPipe(PIPE_NAME, PIPE_TIMEOUT)

                # Connect
                handle = win32file.CreateFile(
                    PIPE_NAME,
                    win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                    0,  # No sharing
                    None,  # Default security
                    win32file.OPEN_EXISTING,
                    0,
                    None
                )

                # v4.11 (HIGH-5): verify the pipe SERVER's identity BEFORE sending
                # anything - a malicious same-user process could squat the
                # well-known pipe name (pipe squatting) and intercept/steal the
                # update / reset-user / msg commands.
                try:
                    server_pid = win32pipe.GetNamedPipeServerProcessId(handle)
                    h_proc = win32api.OpenProcess(
                        win32con.PROCESS_QUERY_LIMITED_INFORMATION, False, server_pid)
                    h_token = win32security.OpenProcessToken(h_proc, win32security.TOKEN_QUERY)
                    server_sid = win32security.GetTokenInformation(h_token, win32security.TokenUser)[0]
                    win32api.CloseHandle(h_proc)
                    server_sid_str = win32security.ConvertSidToStringSid(server_sid)
                except Exception:
                    try:
                        win32file.CloseHandle(handle)
                    except Exception:
                        pass
                    raise RuntimeError("Could not verify pipe server identity (GetNamedPipeServerProcessId failed)")
                # Allowed server: current user or SYSTEM
                my_token = win32security.OpenProcessToken(
                    win32security.GetCurrentProcess(), win32security.TOKEN_QUERY)
                my_sid = win32security.GetTokenInformation(my_token, win32security.TokenUser)[0]
                my_sid_str = win32security.ConvertSidToStringSid(my_sid)
                system_sid_str = win32security.ConvertSidToStringSid(
                    win32security.CreateWellKnownSid(win32security.WinLocalSystemSid))
                if server_sid_str not in (my_sid_str, system_sid_str):
                    try:
                        win32file.CloseHandle(handle)
                    except Exception:
                        pass
                    raise RuntimeError(
                        f"Untrusted pipe server (SID {server_sid_str}) - refusing to send command")

                # Send command
                body = json.dumps(command).encode("utf-8")
                try:
                    win32file.WriteFile(handle, body)
                except Exception:
                    try:
                        win32file.CloseHandle(handle)
                    except Exception:
                        pass
                    continue

                # Read response
                try:
                    success, data = win32file.ReadFile(handle, 65536)
                    if success and data:
                        response = json.loads(data.decode("utf-8"))
                        win32file.CloseHandle(handle)
                        return response
                except Exception:
                    pass

                try:
                    win32file.CloseHandle(handle)
                except Exception:
                    pass

                return {"status": "accepted"}

            except Exception as e:
                if attempt < CONNECT_RETRY - 1:
                    time.sleep(RETRY_DELAY)
                else:
                    return {"status": "error", "error": f"Pipe connect failed: {str(e)[:200]}"}

        return {"status": "error", "error": "Pipe not available after retries"}

    def is_available(self) -> bool:
        """Quick check if pipe server is running."""
        try:
            win32pipe.WaitNamedPipe(PIPE_NAME, 100)  # 100ms timeout
            return True
        except Exception:
            return False


# ============================================================================
# Fallback HTTP Client (for when pipes aren't available)
# ============================================================================

class FallbackHttpClient:
    """HTTP client to Updater localhost:5999 - fallback when Named Pipes unavailable."""

    def __init__(self, host="127.0.0.1", port=5999, timeout=10):
        self.host = host
        self.port = port
        self.timeout = timeout

    def _auth_token(self):
        """v4.10 (CRIT-2): token for updater HTTP auth - same derivation as
        updater._updater_auth_token (sha256(command_key + ':updater'))."""
        try:
            cfg_path = os.path.join(os.environ.get("PROGRAMDATA", r"C:\ProgramData"),
                                    "GIAM-SAT", "Agent", "agent_config.json")
            key = ""
            if os.path.exists(cfg_path):
                with open(cfg_path, "r", encoding="utf-8") as f:
                    key = (json.load(f).get("command_key") or "").strip()
            if not key:
                return ""
            import hashlib
            return hashlib.sha256((key + ":updater").encode()).hexdigest()
        except Exception:
            return ""

    def send_command(self, command: dict) -> dict:
        """Send command via HTTP POST to Updater."""
        try:
            import urllib.request as urlreq
            url = f"http://{self.host}:{self.port}/{command.get('action', 'msg')}"
            data = json.dumps(command).encode("utf-8")
            req = urlreq.Request(url, data=data,
                headers={"Content-Type": "application/json",
                         "X-Updater-Token": self._auth_token()})
            resp = urlreq.urlopen(req, timeout=self.timeout)
            return json.loads(resp.read().decode())
        except Exception as e:
            return {"status": "error", "error": f"HTTP fallback failed: {str(e)[:200]}"}


# ============================================================================
# Unified Client: tries Named Pipe first, falls back to HTTP
# ============================================================================

class UpdaterIPCClient:
    """
    Smart client that tries Named Pipe first (secure), then falls back to HTTP.

    Usage:
        ipc = UpdaterIPCClient()
        response = ipc.send({"action": "update", "version": "3.6.9"})
    """

    def __init__(self, http_fallback=True, http_host="127.0.0.1", http_port=5999):
        self.http_fallback = http_fallback
        self.pipe_client = None
        self.http_client = None

        # Try to create pipe client
        if _HAS_WIN32_PIPE:
            try:
                self.pipe_client = NamedPipeClient()
            except Exception:
                pass

        # Try to create HTTP fallback
        if http_fallback:
            try:
                self.http_client = FallbackHttpClient(host=http_host, port=http_port)
            except Exception:
                pass

    def send(self, command: dict) -> dict:
        """
        Send command to Updater. Uses Named Pipe first, falls back to HTTP.

        Returns: {"status": "accepted"|"error", "error": "..."}
        """
        action = command.get("action", "")
        if action not in VALID_COMMANDS:
            return {"status": "error", "error": f"Unknown action: {action}"}

        # Try Named Pipe first (secure, preferred)
        if self.pipe_client:
            response = self.pipe_client.send_command(command)
            if response.get("status") == "accepted":
                return response
            # If pipe failed, try HTTP
            print(f"[IPC] Named Pipe failed: {response.get('error', 'unknown')}, falling back to HTTP")

        # Fallback to HTTP
        if self.http_client:
            return self.http_client.send_command(command)

        return {"status": "error", "error": "No IPC channel available (pipe or HTTP)"}

    def is_updater_running(self) -> bool:
        """Check if Updater is reachable via any channel."""
        if self.pipe_client and self.pipe_client.is_available():
            return True
        if self.http_client:
            try:
                import urllib.request as urlreq
                urlreq.urlopen(f"http://{self.http_client.host}:{self.http_client.port}/health", timeout=2)
                return True
            except Exception:
                pass
        return False


# ============================================================================
# Self-test (run directly: python named_pipe_ipc.py)
# ============================================================================

if __name__ == "__main__":
    import sys

    if "--server" in sys.argv:
        # Test server mode
        def test_callback(cmd):
            print(f"[SERVER] Received: {json.dumps(cmd, indent=2)}")
            return {"status": "accepted", "echo": cmd}

        server = NamedPipeServer(test_callback)
        print("[*] Starting test server. Press Ctrl+C to stop.")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            server.stop()
            print("[*] Server stopped")

    elif "--client" in sys.argv:
        # Test client mode
        client = UpdaterIPCClient(http_fallback=True)

        test_commands = [
            {"action": "msg", "title": "Test", "body": "Hello from IPC test!"},
            {"action": "update", "version": "3.6.9"},
            {"action": "reset-user"},
        ]

        for cmd in test_commands:
            print(f"\n[CLIENT] Sending: {cmd['action']}")
            response = client.send(cmd)
            print(f"[CLIENT] Response: {json.dumps(response, indent=2)}")
            time.sleep(1)

        print(f"\n[*] Updater running: {client.is_updater_running()}")

    else:
        print("GIAM-SAT Named Pipe IPC Module")
        print(f"  Pipe Name: {PIPE_NAME}")
        print(f"  win32pipe available: {_HAS_WIN32_PIPE}")
        print(f"  win32security available: {_HAS_WIN32_SECURITY}")
        print(f"\nUsage:")
        print(f"  python named_pipe_ipc.py --server   # Start test server")
        print(f"  python named_pipe_ipc.py --client   # Run test client")