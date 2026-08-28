"""v5.0.3 (LOW-9): per-machine PSK + machine_id/hostname validation.

A single shared PSK for every agent means anyone holding it can impersonate
any machine (the root source of the stored-XSS rows: attacker feeds a hostname
containing HTML). This module adds:

  1. Per-machine PSK: GIAMSAT_PER_MACHINE_PSK (inline JSON) or
     GIAMSAT_PER_MACHINE_PSK_FILE (path to JSON) maps machine_id -> secret.
     A machine with an entry MUST present that secret (constant-time); machines
     without an entry fall back to the global GIAMSAT_AGENT_PSK.
  2. machine_id charset validation (blocks path/URL/whitespace injection).
  3. hostname sanitization (control chars + HTML metacharacters removed) so
     agent-supplied display names cannot carry stored XSS payloads.
"""
import os
import json
import hmac
import re

_MACHINE_ID_RE = re.compile(r"^[A-Za-z0-9._:%-]{1,64}$")

_per_machine = None
_cache_key = None


def _load_per_machine_psk():
    """v5.0.4 (MEDIUM-3): the cache is keyed on (env content, file path + mtime)
    so editing GIAMSAT_PER_MACHINE_PSK / the file while the server runs takes
    effect (previously a bad first load cached {} forever)."""
    global _per_machine, _cache_key
    env_raw = os.environ.get("GIAMSAT_PER_MACHINE_PSK", "").strip()
    path = os.environ.get("GIAMSAT_PER_MACHINE_PSK_FILE", "").strip()
    mtime = None
    if path and os.path.exists(path):
        try:
            mtime = (os.path.getmtime(path), os.path.getsize(path))
        except Exception:
            mtime = None
    key = (env_raw, path, mtime)
    if _cache_key == key and _per_machine is not None:
        return _per_machine
    data = {}
    if env_raw and env_raw.startswith("{"):
        try:
            data.update(json.loads(env_raw))
        except Exception:
            pass
    if path and os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data.update(json.load(f))
        except Exception:
            pass
    _per_machine = data
    _cache_key = key
    return data


def machine_psk(machine_id):
    """Per-machine secret for `machine_id`, or None (fall back to global)."""
    return _load_per_machine_psk().get(str(machine_id or ""))


def has_any_psk(machine_id=""):
    """v5.0.4 (MEDIUM-3): True when the machine has a per-machine secret OR the
    global PSK is set - used to decide fail-closed BEFORE picking the key."""
    if machine_id and machine_psk(machine_id):
        return True
    return bool(os.environ.get("GIAMSAT_AGENT_PSK", "").strip())


def verify_agent_psk(presented, global_psk, machine_id=""):
    """Constant-time PSK check: per-machine secret wins, else global secret.
    Returns False when neither is configured for this machine."""
    per = machine_psk(machine_id) if machine_id else None
    expected = per if per is not None else global_psk
    if expected is None or str(expected) == "":
        return False
    return hmac.compare_digest(str(presented or ""), str(expected))


def validate_machine_id(machine_id):
    """1-64 chars from a safe charset. Rejects empty/whitespace/control/HTML."""
    return bool(_MACHINE_ID_RE.match(str(machine_id or "")))


def sanitize_hostname(hostname, default="Unknown"):
    """Strip control chars + HTML metacharacters, cap at 128 chars."""
    if not hostname:
        return default
    s = str(hostname)
    s = "".join(ch for ch in s if ord(ch) >= 32 and ch not in "<>\"'`")
    s = s.strip()
    if not s:
        return default
    return s[:128]


def sanitize_text(text, max_len=120, default=""):
    """v5.0.4 (HIGH-2): sanitize any agent-supplied TEXT field (user_name, email,
    employee_id, branch...) - strips control/HTML metacharacters and caps length.
    Wider than sanitize_hostname (keeps unicode/emoji), so identity fields cannot
    smuggle stored-XSS payloads into the UI."""
    if text is None:
        return default
    s = str(text)
    s = "".join(ch for ch in s if ord(ch) >= 32 and ch not in "<>\"'`")
    s = s.strip()
    if not s:
        return default
    return s[:max_len]
