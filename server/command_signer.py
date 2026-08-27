"""
Command Signing for server->agent commands (v4.5.4).
Uses HMAC-SHA256 with GIAMSAT_COMMAND_KEY (shared secret).

Server signs every command before delivery (TCP push + HTTP poll).
Agent verifies before executing (_verify_command_signature).
"""
import os
import json
import hmac
import hashlib
import secrets
import time


def _get_key():
    return os.environ.get("GIAMSAT_COMMAND_KEY", "").strip()


def sign_command(command_data):
    """Sign a server->agent command (v4.5.5: sign the ENTIRE command JSON).

    Returns a copy of command_data with `_sig` added.
    If GIAMSAT_COMMAND_KEY is not configured, returns the input unchanged
    (the agent will reject unsigned commands in fail-closed mode).
    """
    key = _get_key()
    if not key:
        return command_data
    cmd = dict(command_data)
    cmd.pop("_sig", None)
    cmd.pop("_sig_data", None)
    # v4.5.4: add timestamp for replay protection (agent rejects stale commands)
    cmd["_ts"] = int(time.time())
    # v5.0.3 (MEDIUM-6): per-command nonce so the agent can reject replays even
    # inside the timestamp window (a captured command is executed only once).
    cmd["_nonce"] = secrets.token_hex(16)
    # Sign the whole command (all fields) so params/version/message cannot be tampered
    sign_data = json.dumps(cmd, sort_keys=True, ensure_ascii=False)
    sig = hmac.new(key.encode("utf-8"), sign_data.encode("utf-8"), hashlib.sha256).hexdigest()
    cmd["_sig"] = sig
    return cmd
