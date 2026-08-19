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
        alerts = core.db.get_threat_alerts(limit=200, since_hours=24) or []
        medium = [a for a in alerts if (a.get("severity") or "").upper() == "MEDIUM"]
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


def start_digest_thread(core, alerting_cfg, check_every_seconds=300):
    """Background thread: check periodically whether today's digest is due."""
    def _loop():
        while True:
            try:
                run_digest(core, alerting_cfg)
            except Exception:
                pass
            time.sleep(check_every_seconds)
    threading.Thread(target=_loop, daemon=True, name="daily-digest").start()
