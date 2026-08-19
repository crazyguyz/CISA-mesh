"""
GIAM-SAT Sent Mail Log v1.0.0
Local log of all emails GIAM-SAT has sent (stored on the server itself, under
server/data/sent_emails.json). Independent of the mail server and of the DB
backend - sending via plain SMTP never creates a "Sent" record on the mail
server, so this log is the project's own "Sent items" copy. Admins can view
and delete records via the dashboard (Email tab -> Mail đã gửi).
"""
import json
import os
import threading
from datetime import datetime

LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
LOG_PATH = os.path.join(LOG_DIR, "sent_emails.json")
MAX_RECORDS = 1000   # keep the newest N records, auto-prune the rest
MAX_BODY_CHARS = 20000  # avoid bloating the log with huge bodies

_lock = threading.RLock()


def _load():
    try:
        with open(LOG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception:
        return []


def _save(records):
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
    except OSError:
        pass
    tmp = LOG_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(records, f, ensure_ascii=False, indent=1)
    os.replace(tmp, LOG_PATH)


def log_email(to_email, subject, body="", machine_id="", template_id="",
              source="", status="sent", error=""):
    """Record one email send attempt (status: 'sent' | 'failed').
    Returns the new record id."""
    with _lock:
        records = _load()
        seq = max((r.get("seq", 0) for r in records), default=0) + 1
        body_short = (body or "")[:MAX_BODY_CHARS]
        record = {
            "id": f"em_{int(datetime.now().timestamp() * 1000)}_{seq}",
            "seq": seq,
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "to": str(to_email or ""),
            "subject": str(subject or ""),
            "body": body_short,
            "machine_id": machine_id or "",
            "template_id": template_id or "",
            "source": source or "",
            "status": status,
            "error": str(error or ""),
        }
        records.insert(0, record)
        if len(records) > MAX_RECORDS:
            records = records[:MAX_RECORDS]
        _save(records)
        return record["id"]


def list_emails(limit=200):
    """Return the newest `limit` records (newest first)."""
    with _lock:
        return _load()[:limit]


def delete_email(email_id):
    """Delete one record by id. Returns True if found and removed."""
    with _lock:
        records = _load()
        remaining = [r for r in records if r.get("id") != email_id]
        if len(remaining) == len(records):
            return False
        _save(remaining)
        return True


def clear_emails():
    """Delete all sent-email records. Returns number removed."""
    with _lock:
        n = len(_load())
        _save([])
        return n


def count_emails():
    with _lock:
        return len(_load())
