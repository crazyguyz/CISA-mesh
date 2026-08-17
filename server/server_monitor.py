"""
Server Self-Monitor - Phát hiện tấn công trực tiếp vào server.
v2.5.0: SQLi, Path Traversal, XSS, Scanner, Endpoint Scan detection middleware.
"""

import time
from datetime import datetime


class ServerMonitor:
    """Middleware-based attack detection for the server itself."""

    def __init__(self, db):
        self.db = db
        self._attack_log = {}  # {ip: {"brute": count, "scan_404": count, "last": time}}

    def _insert_threat(self, rule_id, rule_name, severity, description, ip, command=""):
        """Insert a threat alert for self-monitored server attacks."""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.db.insert_threat_alert({
            "machine_id": f"SERVER:{ip}",
            "hostname": f"Attacker:{ip}",
            "rule_id": rule_id,
            "rule_name": rule_name,
            "severity": severity,
            "description": description,
            "timestamp": now,
            "command": command,
            "source_ip": ip
        })

    def create_middleware(self):
        """Return a Flask @app.before_request function for server self-monitoring."""

        monitor = self

        def detect_server_attacks():
            from flask import request
            ip = request.remote_addr
            path = request.path
            user_agent = request.headers.get("User-Agent", "")
            body = ""
            try:
                if request.data:
                    body = request.data.decode("utf-8", errors="ignore")
                elif request.form:
                    body = str(dict(request.form))
            except Exception:
                pass

            now = time.time()
            if ip not in monitor._attack_log:
                monitor._attack_log[ip] = {"brute": 0, "scan_404": 0, "bad_token": 0, "last": now}
            log = monitor._attack_log[ip]

            # 1. SQL Injection Probe
            sql_patterns = ["' or 1=1", "' or '1'='1", "union select", "drop table",
                           "1=1--", "';--", "xp_cmdshell", "exec xp_", "information_schema",
                           "union/**/select", "or 1=1#", "' or 1=1--"]
            qs = request.query_string.decode("utf-8", errors="ignore").lower()
            for p in sql_patterns:
                if p in qs or p in body.lower():
                    monitor._insert_threat("SRV-SQLI-001", "SQL Injection Probe",
                        "HIGH", f"SQLi pattern '{p}' detected from {ip}", ip,
                        f"SQL Injection via {path}")
                    break

            # 2. Path Traversal
            trav_patterns = ["../", "..%2f", "/etc/passwd", "cmd.exe", "win.ini",
                           "boot.ini", "\\windows\\system32", "c:\\windows", "%00"]
            path_lower = path.lower()
            for p in trav_patterns:
                if p in path_lower:
                    monitor._insert_threat("SRV-PATH-001", "Path Traversal Attempt",
                        "HIGH", f"Path traversal '{p}' detected from {ip}", ip,
                        f"GET {path}")
                    break

            # 3. XSS Probe
            xss_patterns = ["<script", "javascript:", "onerror=", "onload=", "<img", "<svg",
                          "alert(", "prompt(", "confirm(", "document.cookie"]
            for p in xss_patterns:
                if p in qs or p in body.lower() or p in user_agent.lower():
                    monitor._insert_threat("SRV-XSS-001", "XSS Probe",
                        "MEDIUM", f"XSS pattern '{p}' detected from {ip}", ip,
                        f"XSS via {path}")
                    break

            # 4. Scanner User-Agent detection
            scanner_agents = ["nmap", "nikto", "nessus", "burp", "sqlmap", "dirbuster",
                            "gobuster", "hydra", "metasploit", "acunetix", "wpscan"]
            ua_lower = user_agent.lower()
            for sa in scanner_agents:
                if sa in ua_lower:
                    monitor._insert_threat("SRV-SCAN-001", "Scanner Detected",
                        "HIGH", f"Scanner tool '{sa}' detected from {ip}", ip,
                        f"User-Agent contains '{sa}'")
                    break

            # 5. Track 404 for endpoint scanning
            if now - log.get("last", 0) > 3600:
                log["scan_404"] = 0
            log["last"] = now

        return detect_server_attacks

    def create_404_handler(self):
        """Return a Flask 404 error handler that tracks endpoint scanning."""

        monitor = self

        def handle_404(e):
            from flask import request, jsonify
            ip = request.remote_addr
            if ip not in monitor._attack_log:
                return jsonify({"error": "Not found"}), 404
            log = monitor._attack_log[ip]
            log["scan_404"] = log.get("scan_404", 0) + 1
            if log["scan_404"] >= 10:
                monitor._insert_threat("SRV-SCAN-002", "Endpoint Scan Detected",
                    "MEDIUM", f"Endpoint scan from {ip} ({log['scan_404']}x 404)", ip,
                    "Port/Endpoint scanning")
            return jsonify({"error": "Not found"}), 404

        return handle_404