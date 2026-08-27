"""GIAM-SAT Daily Alert Digest v4.11
MEDIUM-severity alerts (below the HIGH threshold that triggers Telegram) are
summarized and emailed once per day - so MEDIUM events are still surfaced
without spamming Telegram. Runs as a background thread on the server.
Controlled by alerting_config.json -> "digest":
  {
    "enabled": true,
    "to": [],                    # empty -> falls back to GIAMSAT_SMTP_USER
    "hour": 8                    # send after this hour of the day (server local)
  }
NOTE: no mailbox is hardcoded - recipients always come from the admin's own
setup_config.ps1 / .env (GIAMSAT_SMTP_USER) or the digest.to list.
"""
import os
import json
import time
import threading
from datetime import datetime

STATE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "digest_state.json")


def _load_state():
    try:
        with open(STATE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_state(state):
    try:
        os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
        tmp = STATE_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(state, f)
        os.replace(tmp, STATE_PATH)
    except Exception:
        pass


def _build_body(alerts):
    lines = [
        "GIAM-SAT: Tổng hợp cảnh báo mức MEDIUM trong 24h qua",
        "==================================================",
        "",
    ]
    if not alerts:
        lines.append("Không có cảnh báo MEDIUM nào trong 24h qua.")
        lines.append("")
        lines.append("Trân trọng,\nGIAM-SAT")
        return "\n".join(lines)
    for a in alerts[:100]:
        host = a.get("hostname") or a.get("computer") or "?"
        rule = a.get("rule_name") or a.get("rule_id") or a.get("cve") or "?"
        ts = a.get("timestamp") or a.get("received_at") or "?"
        desc = (a.get("description") or "")[:200]
        lines.append(f"- [{ts}] {host} ({a.get('machine_id', '?')}): {rule} - {desc}")
    lines.append("")
    lines.append(f"Tổng cộng: {len(alerts)} cảnh báo MEDIUM trong 24h qua.")
    lines.append("")
    lines.append("Trân trọng,\nGIAM-SAT")
    return "\n".join(lines)


def run_digest(core, alerting_cfg):
    """Collect MEDIUM alerts from the last 24h and email them (once per day)."""
    cfg = (alerting_cfg or {}).get("digest") or {}
    if not cfg.get("enabled", True):
        return False
    now = datetime.now()
    if now.hour < int(cfg.get("hour", 8)):
        return False  # not yet due today
    state = _load_state()
    today = now.strftime("%Y-%m-%d")
    if state.get("last_run_day") == today:
        return False  # already sent today
    recipients = [str(r).strip() for r in (cfg.get("to") or []) if str(r).strip()]
    if not recipients:
        self_addr = os.environ.get("GIAMSAT_SMTP_USER", "").strip()
        if self_addr:
            recipients = [self_addr]
    if not recipients:
        print("[DIGEST] No recipients configured (digest.to / GIAMSAT_SMTP_USER) - skip")
        return False
    try:
        # v5.0.3 (MEDIUM-5): raise the collection cap so >200 alerts/day are not
        # silently dropped from the summary; _build_body still displays 100 lines
        # but reports the real total.
        alerts = core.db.get_threat_alerts(limit=2000, since_hours=24) or []
        medium = [a for a in alerts if (a.get("severity") or "").upper() == "MEDIUM"]
        # v4.11 (runtime fix): YARA and MEDIUM vuln alerts were never surfaced
        # anywhere (Telegram only takes HIGH+; the digest only read threat_alerts).
        # Include them here. yara_alerts has no severity column -> all are included.
        yara_fn = getattr(core.db, "get_yara_alerts", None)
        if yara_fn:
            try:
                medium += yara_fn(limit=2000, since_hours=24) or []
            except Exception:
                pass
        vuln_fn = getattr(core.db, "get_vuln_alerts", None)
        if vuln_fn:
            try:
                vulns = vuln_fn(limit=2000, since_hours=24) or []
                medium += [a for a in vulns if (a.get("severity") or "").upper() == "MEDIUM"]
            except Exception:
                pass
        # newest first; _build_body displays 100 lines but reports the real total
        medium.sort(key=lambda a: str(a.get("timestamp") or a.get("received_at") or ""), reverse=True)
        if not medium:
            # v4.11 (runtime fix): never send an empty "0 alerts" email - this was
            # spamming the admin mailbox on every server start during the day.
            print("[DIGEST] No MEDIUM/YARA alerts in the last 24h - skip (no email sent)")
            return False
        body = _build_body(medium)
        from email_alerts import send_email_smtp
        ok = send_email_smtp(", ".join(recipients),
                             "GIAM-SAT: Digest cảnh báo MEDIUM hôm nay",
                             body, source="digest")
        if ok:
            state["last_run_day"] = today
            _save_state(state)
            print(f"[DIGEST] Sent MEDIUM digest ({len(medium)} alerts) to {recipients}")
        else:
            print("[DIGEST] Email send failed - will retry next cycle")
        return ok
    except Exception as e:
        print(f"[-] DIGEST failed: {e}")
        return False


def run_weekly_report(core, alerting_cfg):
    """v4.13 (E3): generate the weekly HTML summary report and email it as an
    attachment. Config: alerting_config.json -> weekly {enabled, day (0=Mon),
    hour, to}. Once per week."""
    cfg = (alerting_cfg or {}).get("weekly") or {}
    if not cfg.get("enabled", True):
        return False
    now = datetime.now()
    # v5.0.3 (MEDIUM-5): run on ANY day on/after the scheduled weekday so a
    # server that was down on the exact day still sends the report that week
    # (still once per ISO week via state["last_week"]).
    if now.weekday() < int(cfg.get("day", 0)) or now.hour < int(cfg.get("hour", 8)):
        return False
    state = _load_state()
    week = now.strftime("%Y-%W")
    if state.get("last_week") == week:
        return False
    recipients = [str(r).strip() for r in (cfg.get("to") or []) if str(r).strip()]
    if not recipients:
        self_addr = os.environ.get("GIAMSAT_SMTP_USER", "").strip()
        if self_addr:
            recipients = [self_addr]
    if not recipients:
        print("[WEEKLY] No recipients configured (weekly.to / GIAMSAT_SMTP_USER) - skip")
        return False
    try:
        filepath = core.reporting.generate_html_report(report_type="weekly")
        if not filepath or not os.path.exists(filepath):
            print("[WEEKLY] Report generation failed")
            return False
        summary = (
            "GIAM-SAT: Báo cáo an ninh tuần<br>"
            "<p>Báo cáo tổng hợp HTML đính kèm (mở bằng trình duyệt để in/chia sẻ).</p>"
            "<p><em>Weekly security summary - HTML report attached (open in a browser).</em></p>"
        )
        from email_alerts import send_email_smtp
        ok = send_email_smtp(", ".join(recipients),
                             f"GIAM-SAT: Báo cáo an ninh tuần ({now.strftime('%d/%m/%Y')})",
                             summary, source="weekly", attachment_path=filepath)
        if ok:
            state["last_week"] = week
            _save_state(state)
            print(f"[WEEKLY] Sent weekly report to {recipients}")
        return ok
    except Exception as e:
        print(f"[-] WEEKLY failed: {e}")
        return False


def start_digest_thread(core, alerting_cfg, check_every_seconds=300):
    """Background thread: check periodically whether today's digest / weekly report is due."""
    def _loop():
        while True:
            try:
                run_digest(core, alerting_cfg)
            except Exception:
                pass
            try:
                run_weekly_report(core, alerting_cfg)
            except Exception:
                pass
            time.sleep(check_every_seconds)
    threading.Thread(target=_loop, daemon=True, name="daily-digest").start()
