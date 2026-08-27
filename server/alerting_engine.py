"""
Alerting Engine for GIAM-SAT Server v1.6.1
Sends alerts via Email, Slack Webhook, and custom Webhook when threat/vulnerability detected.
v1.6.1: CVE alerts get 1h cooldown, Telegram template uses cve as rule_id fallback.
"""
import json
import os
import threading
import time
import ssl
from datetime import datetime


class AlertingEngine:
    """Handles alert notifications via multiple channels."""

    def __init__(self, config_path=None):
        self.lock = threading.Lock()
        self.config = {
            "enabled": False,
            "email": {"enabled": True, "smtp_host": "", "smtp_port": 465, "username": "", "password": "", "from_addr": "", "to_addrs": []},
            "slack": {"enabled": False, "webhook_url": "", "channel": "#alerts"},
            "webhook": {"enabled": False, "url": "", "headers": {}},
            "telegram": {"enabled": False, "bot_token": "", "chat_id": "", "approval_timeout": 300, "min_severity": "HIGH"},
            "auto_response": {"mode": "off", "require_confidence": 90, "safe_users": ["admin", "administrator"], "safe_machines": []},
            "min_severity": "HIGH",
            "cooldown_seconds": 86400,
            # v4.11 (P3): smart dedup - fingerprint + per-severity cooldowns
            "dedup_fingerprint_fields": ["description", "rule_name", "source_ip", "user", "cve", "event_id"],
            "cooldown_by_severity": {"CRITICAL": 3600, "HIGH": 21600, "MEDIUM": 43200, "LOW": 86400},
            "attempt_retry_seconds": 300,
            "digest": {"enabled": True, "to": [], "hour": 8},
        }
        # v4.10: persisted dedup map (survives server restart).
        # v4.11: key = "<rule_id>|<machine_id>|<event_fingerprint>", value = unix
        # ts of the last SUCCESSFUL send (recorded after a channel actually sent).
        self._last_alerts = {}
        self._last_attempts = {}
        self._load_config(config_path)
        self._load_dedup()
        self._running = True
        self._core = None

    def _load_config(self, config_path):
        if not config_path:
            config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "alerting_config.json")
        if os.path.exists(config_path):
            try:
                with open(config_path, "r") as f:
                    loaded = json.loads(f.read())
                    self.config.update(loaded)
            except Exception:
                pass

    def save_config(self):
        config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "alerting_config.json")
        with open(config_path, "w") as f:
            f.write(json.dumps(self.config, indent=2))

    def _load_dedup(self):
        """v4.10: Load persisted last-sent timestamps (alert dedup across restarts)."""
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "alert_dedup.json")
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    self._last_alerts = {str(k): float(v) for k, v in data.items() if isinstance(v, (int, float))}
        except Exception:
            self._last_alerts = {}

    def _save_dedup(self):
        """v4.11 (MED): persist dedup map atomically (tmp + os.replace so a crash
        mid-write cannot corrupt the file -> dedup reset -> old alerts re-sent).
        The snapshot is taken under self.lock - _mark_sent() can add keys from
        concurrent worker threads (dict changed-size race otherwise)."""
        try:
            path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "alert_dedup.json")
            with self.lock:
                cutoff = time.time() - 86400 * 2
                pruned = {k: v for k, v in self._last_alerts.items() if v >= cutoff}
            os.makedirs(os.path.dirname(path), exist_ok=True)
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(pruned, f)
            os.replace(tmp, path)
        except Exception:
            pass

    def start_telegram_callback_poller(self, web_port=5000, core=None):
        """v4.5.4: Poll Telegram getUpdates for callback queries (inline Approve/Deny
        keyboard) and route them to the local approval endpoint."""
        bot_token = os.environ.get("TELEGRAM_BOT_TOKEN") or self.config.get("telegram", {}).get("bot_token", "")
        if not bot_token:
            print("[!] Telegram callback poller: no bot token configured, skipping")
            return
        self._running = True
        self._core = core

        def _poller():
            import urllib.request
            import urllib.parse
            offset = 0
            while getattr(self, "_running", True):
                try:
                    url = f"https://api.telegram.org/bot{bot_token}/getUpdates?timeout=30&offset={offset}"
                    ctx = ssl.create_default_context()
                    resp = urllib.request.urlopen(url, timeout=45, context=ctx)
                    data = json.loads(resp.read().decode("utf-8"))
                    for upd in data.get("result", []):
                        offset = upd.get("update_id", 0) + 1
                        cb = upd.get("callback_query")
                        if not cb:
                            continue
                        cb_id = cb.get("id", "")
                        callback_data = cb.get("data", "")
                        # Answer the callback (dismiss loading state on the button)
                        try:
                            ans_req = urllib.request.Request(
                                f"https://api.telegram.org/bot{bot_token}/answerCallbackQuery",
                                data=json.dumps({"callback_query_id": cb_id}).encode("utf-8"),
                                headers={"Content-Type": "application/json"})
                            urllib.request.urlopen(ans_req, timeout=10, context=ctx)
                        except Exception:
                            pass
                        # Process the callback in-process (no HTTP round-trip)
                        # v4.10 (LOW-7): only allow SOC users listed in
                        # GIAMSAT_TELEGRAM_SOC_IDS (comma-separated Telegram user
                        # ids) to approve/deny; otherwise anyone in the chat can.
                        if callback_data.startswith("giamsat_"):
                            try:
                                from_user = (cb.get("from") or {}).get("id")
                                allowed = [s.strip() for s in
                                           os.environ.get("GIAMSAT_TELEGRAM_SOC_IDS", "").split(",") if s.strip()]
                                # v5.0.3 (HIGH-7 FIX): fail-closed - if SOC_IDS is NOT
                                # configured, reject ALL approval callbacks (previously the
                                # check was skipped entirely, so anyone in the chat could
                                # Approve/Deny SOAR actions).
                                if not allowed:
                                    print("[!] TELEGRAM: GIAMSAT_TELEGRAM_SOC_IDS not configured - rejecting approval callback (fail-closed)")
                                    continue
                                if from_user not in [int(a) for a in allowed if a.isdigit()]:
                                    print(f"[!] TELEGRAM: callback from unauthorized user {from_user} ignored")
                                    continue
                                if self._core is not None:
                                    from api.api_alert_approval import process_approval
                                    result, status = process_approval(self._core, callback_data, "", "")
                                    print(f"[TELEGRAM] Callback processed: {callback_data} -> {status}")
                                else:
                                    print(f"[-] Telegram callback: no core reference available")
                            except Exception as e:
                                print(f"[-] Telegram callback processing failed: {e}")
                except Exception:
                    pass
                time.sleep(2)

        threading.Thread(target=_poller, daemon=True).start()
        print("[*] Telegram callback poller started")

    def _dedup_key(self, alert_data):
        """v4.11 (P3): key = rule + machine + event fingerprint, so two scans of
        the SAME rule on the SAME machine are NOT collapsed when the underlying
        event differs (fix: '2 lần quét trùng rule trong 24h bị nuốt nhau')."""
        rule_id = (alert_data.get("rule_id")
                   or alert_data.get("cve")
                   or alert_data.get("rule_name")
                   or "unknown")
        machine_id = alert_data.get("machine_id", "")  # source of the alert
        fields = self.config.get("dedup_fingerprint_fields") or []
        if fields:
            import hashlib as _h
            parts = []
            for f in fields:
                v = alert_data.get(f)
                if v is None:
                    parts.append(f"{f}=")
                else:
                    parts.append(f"{f}={json.dumps(v, default=str, sort_keys=True, ensure_ascii=False)}")
            fp = _h.sha256("|".join(parts).encode("utf-8", "replace")).hexdigest()[:16]
            return f"{rule_id}|{machine_id}|{fp}"
        return f"{rule_id}|{machine_id}"

    def _cooldown_for(self, severity):
        cmap = self.config.get("cooldown_by_severity") or {}
        sev = (severity or "LOW").upper()
        if sev in cmap:
            return max(int(cmap[sev]), 1)
        return max(int(self.config.get("cooldown_seconds", 86400)), 1)

    def _should_send(self, alert_data):
        """v4.11 (P3 + HIGH-1): gate WITHOUT recording success.
        - Severity below min_severity -> skip.
        - Identical alert (same rule + machine + event fingerprint) is only
          re-sent after the per-severity cooldown (CRITICAL 1h / HIGH 6h /
          MEDIUM 12h / LOW 24h). Different events of the same rule, or alerts
          from a different machine, send immediately.
        - attempt_retry_seconds stops an immediate resend storm when the previous
          attempt failed; the success timestamp is NOT advanced on failure, so a
          down channel can never swallow an alert for 24h (HIGH-1)."""
        severity_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        min_sev = severity_order.get(self.config.get("min_severity", "HIGH"), 2)
        event_sev = severity_order.get(alert_data.get("severity", "LOW"), 0)
        if event_sev < min_sev:
            return False
        key = self._dedup_key(alert_data)
        now = time.time()
        with self.lock:
            if now - self._last_alerts.get(key, 0) < self._cooldown_for(alert_data.get("severity")):
                return False
            if now - self._last_attempts.get(key, 0) < int(self.config.get("attempt_retry_seconds", 300)):
                return False
            self._last_attempts[key] = now
        return True

    def _mark_sent(self, alert_data):
        """v4.11 (HIGH-1 FIX): advance the dedup timestamp only after at least one
        channel has actually sent successfully."""
        key = self._dedup_key(alert_data)
        with self.lock:
            self._last_alerts[key] = time.time()
            self._last_attempts.pop(key, None)
        self._save_dedup()

    def send_alert(self, alert_data):
        """Send alert through all enabled channels. Runs in thread.
        v4.11 (HIGH-1): dedup is marked only on successful send."""
        if not self.config.get("enabled", False):
            return
        if not self._should_send(alert_data):
            return

        def _runner():
            try:
                if self._send_all_channels(alert_data):
                    self._mark_sent(alert_data)
            except Exception:
                pass

        threading.Thread(target=_runner, daemon=True).start()

    def _send_all_channels(self, alert_data):
        """v4.11: returns True if at least one enabled channel sent successfully.
        If no channel is enabled/attempted the alert is NOT marked as sent."""
        sent_ok = False
        if self.config.get("email", {}).get("enabled"):
            try:
                if self._send_email(alert_data):
                    sent_ok = True
            except Exception:
                pass
        if self.config.get("slack", {}).get("enabled"):
            try:
                if self._send_slack(alert_data):
                    sent_ok = True
            except Exception:
                pass
        if self.config.get("webhook", {}).get("enabled"):
            try:
                if self._send_webhook(alert_data):
                    sent_ok = True
            except Exception:
                pass
        # v4.10: Telegram only for severe alerts (telegram.min_severity, default HIGH)
        t_cfg = self.config.get("telegram", {})
        if t_cfg.get("enabled"):
            sev_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
            t_min = sev_order.get(t_cfg.get("min_severity", "HIGH"), 2)
            if sev_order.get(alert_data.get("severity", "LOW"), 0) >= t_min:
                try:
                    if self._send_telegram(alert_data):
                        sent_ok = True
                except Exception:
                    pass
        return sent_ok

    def _send_email(self, alert_data):
        """v4.11: Send the alert to the ADMIN mailbox (config email block) AND/OR
        fall back to the project's GIAMSAT_SMTP_* env vars when the block is
        empty - so alert emails reuse the same mailbox as the rest of the system
        without duplicating credentials. Recipients default to the SMTP user."""
        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart
            import os as _os

            cfg = self.config.get("email") or {}
            smtp_host = (cfg.get("smtp_host") or "").strip() or _os.environ.get("GIAMSAT_SMTP_HOST", "").strip()
            smtp_port = int(cfg.get("smtp_port") or _os.environ.get("GIAMSAT_SMTP_PORT", "465"))
            smtp_user = (cfg.get("username") or "").strip() or _os.environ.get("GIAMSAT_SMTP_USER", "").strip()
            smtp_pass = (cfg.get("password") or "") or _os.environ.get("GIAMSAT_SMTP_PASS", "")
            from_addr = (cfg.get("from_addr") or "").strip() or smtp_user
            to_addrs = cfg.get("to_addrs") or []
            if not to_addrs and smtp_user:
                to_addrs = [smtp_user]  # default: the admin mailbox itself
            if not smtp_host or not smtp_user or not smtp_pass or not to_addrs:
                print("[-] Email alert: SMTP not configured (alerting_config email block / GIAMSAT_SMTP_* env)")
                return False

            msg = MIMEMultipart()
            msg["From"] = from_addr
            msg["To"] = ", ".join(to_addrs)
            msg["Subject"] = f"[GIAM-SAT] [{alert_data.get('severity','?')}] {alert_data.get('rule_name', alert_data.get('cve', 'Alert'))}"

            body = f"""
GIAM-SAT Alert
===============
Severity: {alert_data.get('severity')}
Rule: {alert_data.get('rule_name', alert_data.get('cve', 'N/A'))}
Host: {alert_data.get('hostname', 'Unknown')}
Machine ID: {alert_data.get('machine_id', 'Unknown')}
Time: {alert_data.get('timestamp', 'N/A')}
Description: {alert_data.get('description', 'N/A')}
"""
            msg.attach(MIMEText(body, "plain"))

            ctx = ssl.create_default_context()
            # v4.10 FIX: port 465 = implicit SSL (SMTP_SSL); 587/25 = STARTTLS.
            if smtp_port == 465:
                with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=20, context=ctx) as server:
                    server.login(smtp_user, smtp_pass)
                    server.sendmail(from_addr, to_addrs, msg.as_string())
            else:
                with smtplib.SMTP(smtp_host, smtp_port, timeout=20) as server:
                    server.ehlo()
                    server.starttls(context=ctx)
                    server.ehlo()
                    server.login(smtp_user, smtp_pass)
                    server.sendmail(from_addr, to_addrs, msg.as_string())
            print(f"[*] Email alert sent to {to_addrs}")
            try:
                from sent_mail_log import log_email
                log_email(", ".join(to_addrs), msg["Subject"], body,
                          source="alerting", status="sent")
            except Exception:
                pass
            return True
        except Exception as e:
            print(f"[-] Email alert failed: {e}")
            try:
                from sent_mail_log import log_email
                log_email(", ".join(to_addrs), msg.get("Subject", ""), body,
                          source="alerting", status="failed", error=str(e))
            except Exception:
                pass
            return False

    def _send_slack(self, alert_data):
        try:
            import urllib.request

            cfg = self.config["slack"]
            color_map = {"LOW": "#36a64f", "MEDIUM": "#ffcc00", "HIGH": "#ff6600", "CRITICAL": "#ff0000"}
            color = color_map.get(alert_data.get("severity", "LOW"), "#999999")

            payload = {
                "channel": cfg.get("channel", "#alerts"),
                "attachments": [{
                    "color": color,
                    "title": f"[{alert_data.get('severity','?')}] {alert_data.get('rule_name', alert_data.get('cve', 'Alert'))}",
                    "text": alert_data.get("description", ""),
                    "fields": [
                        {"title": "Host", "value": alert_data.get("hostname", "Unknown"), "short": True},
                        {"title": "Time", "value": alert_data.get("timestamp", "N/A"), "short": True},
                    ],
                    "footer": "GIAM-SAT Alerting Engine"
                }]
            }
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(cfg["webhook_url"], data=data, headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=10)
            print(f"[*] Slack alert sent")
            return True
        except Exception as e:
            print(f"[-] Slack alert failed: {e}")
            return False

    def _send_telegram(self, alert_data):
        """
        v4.0: Send alert to Telegram with inline approval keyboard.
        SOC can approve/deny auto-response actions directly from Telegram.
        """
        try:
            import urllib.request
            import os as _os
            cfg = self.config["telegram"]
            bot_token = _os.environ.get("TELEGRAM_BOT_TOKEN") or cfg.get("bot_token", "")
            chat_id = _os.environ.get("TELEGRAM_CHAT_ID") or cfg.get("chat_id", "")
            if not bot_token or not chat_id:
                return False

            sev = alert_data.get("severity", "LOW")
            sev_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(sev, "⚪")
            rule_id = alert_data.get("rule_id") or alert_data.get("cve", "?")
            rule_name = alert_data.get("rule_name") or alert_data.get("cve", "Unknown")
            hostname = alert_data.get("hostname", "Unknown")
            machine_id = alert_data.get("machine_id", "")
            desc = alert_data.get("description", "")[:200]
            confidence = alert_data.get("confidence_score", 0)
            pending_action = alert_data.get("pending_action", "")

            # Enrich with context
            trigger_event = alert_data.get("trigger_event", {})
            process_chain = trigger_event.get("process_chain", []) or alert_data.get("process_chain", [])
            mitre_tactic = alert_data.get("mitre_tactic", trigger_event.get("mitre_tactic", ""))
            mitre_tech = alert_data.get("mitre_technique_id", trigger_event.get("mitre_technique_id", ""))
            mitre_sev = alert_data.get("mitre_severity", "")
            event_count_24h = alert_data.get("event_count_24h", 0)
            machine_ip = alert_data.get("ip_address", "")
            platform = alert_data.get("platform", "")
            
            # Build rich message text
            text = f"{sev_emoji} *{sev} ALERT* — {hostname}\n"
            text += f"Rule: `{rule_id}` — {rule_name}\n"
            if mitre_tactic:
                text += f"MITRE: {mitre_tactic}"
                if mitre_tech: text += f" ({mitre_tech})"
                text += "\n"
            text += f"Confidence: {confidence}%"
            if mitre_sev: text += f" | MITRE Severity: {mitre_sev}"
            text += "\n"
            text += f"Machine: `{machine_id}`"
            if machine_ip: text += f" ({machine_ip})"
            if platform: text += f" [{platform}]"
            text += "\n"
            text += f"Description: {desc}\n"
            
            # Process chain context
            if process_chain:
                chain_str = " → ".join(process_chain[-5:])
                text += f"Process Chain: `{chain_str}`\n"
            
            if event_count_24h > 0:
                text += f"Events 24h: {event_count_24h}\n"
            
            server_url = self.config.get("server_url", f"http://{hostname}:5000")
            text += f"\n📊 [Open Dashboard]({server_url}/#incident)"

            reply_markup = None
            if pending_action:
                timeout = cfg.get("approval_timeout", 300)
                mins = timeout // 60
                text += f"\n⚠️ Proposed action: *{pending_action}*\n⏰ Auto-deny in {mins}:00"
                callback_data = f"giamsat_approve|{machine_id}|{pending_action}|{rule_id}"
                reply_markup = {
                    "inline_keyboard": [[
                        {"text": "✅ Approve", "callback_data": callback_data},
                        {"text": "❌ Deny", "callback_data": f"giamsat_deny|{machine_id}|{pending_action}"}
                    ]]
                }

            url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
            payload = {
                "chat_id": chat_id,
                "text": text,
                "parse_mode": "Markdown",
            }
            if reply_markup:
                payload["reply_markup"] = json.dumps(reply_markup)

            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=10)
            print(f"[*] Telegram alert sent to {chat_id}")
            return True
        except Exception as e:
            print(f"[-] Telegram alert failed: {e}")
            return False

    def _send_webhook(self, alert_data):
        try:
            import urllib.request

            cfg = self.config["webhook"]
            data = json.dumps(alert_data).encode("utf-8")
            headers = {"Content-Type": "application/json"}
            headers.update(cfg.get("headers", {}))
            req = urllib.request.Request(cfg["url"], data=data, headers=headers)
            urllib.request.urlopen(req, timeout=10)
            print(f"[*] Webhook alert sent")
            return True
        except Exception as e:
            print(f"[-] Webhook alert failed: {e}")
            return False

    def set_config(self, key, value):
        keys = key.split(".")
        cfg = self.config
        for k in keys[:-1]:
            cfg = cfg.setdefault(k, {})
        cfg[keys[-1]] = value
        self.save_config()