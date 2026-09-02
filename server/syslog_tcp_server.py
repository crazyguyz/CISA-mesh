"""GIAM-SAT v5.0.4 (Phase3 improvement #1): secure syslog over TCP/TLS.

Listens on GIAMSAT_SYSLOG_TCP_PORT (default 6514). When
GIAMSAT_SYSLOG_TLS_CERT + GIAMSAT_SYSLOG_TLS_KEY are set the listener wraps the
socket in TLS (RFC 5425-style transport for firewalls/appliances). Framing:
RFC 6587 octet-counted "<len> <payload>" and newline-delimited frames.

Parsing is delegated to SyslogServer._process_syslog so UDP :514 and TCP :6514
share every parser (firewall deep-parse, device alerts, DHCP redaction,
RFC3164/RFC5424 + structured data).
"""

import os
import socket
import ssl
import threading


class SyslogTCPServer(threading.Thread):
    def __init__(self, host="0.0.0.0", port=None, db_manager=None, message_callback=None):
        super().__init__(daemon=True)
        self.host = host
        try:
            self.port = int(port or os.environ.get("GIAMSAT_SYSLOG_TCP_PORT", "6514"))
        except (TypeError, ValueError):
            self.port = 6514
        self.disabled = self.port < 1  # GIAMSAT_SYSLOG_TCP_PORT=0 turns the listener off
        self.db = db_manager
        self.message_callback = message_callback
        self.running = True
        self._sock = None
        # Reuse the UDP parser (patterns, deep-parse, DB writes).
        try:
            from syslog_server import SyslogServer
            self._parser = SyslogServer(db_manager=db_manager,
                                        message_callback=message_callback)
        except Exception as e:
            print(f"[!] Syslog TCP: parser init failed: {e}")
            self._parser = None

    def _tls_context(self):
        cert = os.environ.get("GIAMSAT_SYSLOG_TLS_CERT", "")
        key = os.environ.get("GIAMSAT_SYSLOG_TLS_KEY", "")
        if not cert or not key:
            return None
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=cert, keyfile=key)
        return ctx

    def run(self):
        if self.disabled:
            print("[*] Syslog TCP disabled (GIAMSAT_SYSLOG_TCP_PORT < 1)")
            return
        if self._parser is None:
            print("[!] Syslog TCP disabled (parser unavailable)")
            return
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.host, self.port))
            sock.listen(32)
            sock.settimeout(2)
            self._sock = sock
            print(f"[*] Syslog TCP listening on {self.host}:{self.port} "
                  f"({'TLS' if self._tls_context() else 'plaintext'})")
            ctx = self._tls_context()
            while self.running:
                try:
                    conn, addr = sock.accept()
                except socket.timeout:
                    continue
                except OSError:
                    continue
                if ctx is not None:
                    try:
                        conn = ctx.wrap_socket(conn, server_side=True)
                    except Exception:
                        try:
                            conn.close()
                        except Exception:
                            pass
                        continue
                conn.settimeout(2)
                t = threading.Thread(target=self._handle_client,
                                     args=(conn, addr), daemon=True)
                t.start()
        except Exception as e:
            print(f"[-] Syslog TCP server error: {e}")
        finally:
            if self._sock is not None:
                try:
                    self._sock.close()
                except Exception:
                    pass


    # ------------------------------------------------------------- framing
    def _handle_client(self, conn, addr):
        source_ip = addr[0]
        buf = b""
        try:
            while self.running:
                try:
                    chunk = conn.recv(65536)
                except socket.timeout:
                    chunk = b""
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
                while True:
                    frame, buf, partial = self._extract_frame(buf)
                    if frame is None:
                        if partial is False and len(buf) > 65536:
                            buf = b""  # pathological non-newline stream - drop head
                        break
                    if frame:
                        self._dispatch(frame, source_ip)
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    @staticmethod
    def _extract_frame(buf):
        """Return (frame_bytes, rest_buf, partial). frame is None when the buffer
        does not yet hold a complete frame. RFC6587 octet-counting is detected
        first ('<len> SP payload'), newline-delimited framing is the fallback."""
        if not buf:
            return None, buf, True
        if buf[0:1].isdigit():
            sp = buf.find(b" ")
            if 0 < sp <= 7 and buf[:sp].isdigit():
                length = int(buf[:sp])
                payload_start = sp + 1
                if len(buf) >= payload_start + length:
                    payload = buf[payload_start:payload_start + length]
                    return payload, buf[payload_start + length:], False
                return None, buf, True  # wait for more bytes
        idx = buf.find(b"\n")
        if idx == -1:
            return None, buf, False  # not partial-octet; caller may drop if huge
        frame = buf[:idx].rstrip(b"\r").strip()
        return frame, buf[idx + 1:], False

    def _dispatch(self, frame, source_ip):
        try:
            if self._parser is not None:
                self._parser._process_syslog(frame, (source_ip, self.port))
        except Exception:
            pass

    def stop(self):
        self.running = False
        try:
            if self._sock is not None:
                self._sock.close()
        except Exception:
            pass

