"""
Agent HTTP client helper - v4.13 (P2): supports HTTPS when the server web port
uses TLS (GIAMSAT_WEB_TLS_ENABLED on the server side). When enabled, requests
verify the server certificate against the same pinned CA the agent TCP channel
uses, so a MITM cannot strip the encryption.
"""
import os
import json
import ssl
import urllib.request

_CACHE_CTX = None


def _tls_from_env_or_config(config=None):
    """Web-TLS flag: env override wins, else agent config 'web_tls'."""
    env = os.environ.get("GIAMSAT_SERVER_TLS", "").strip().lower()
    if env in ("1", "true", "yes"):
        return True
    if env in ("0", "false", "no"):
        return False
    try:
        if config and config.get("web_tls"):
            return True
    except Exception:
        pass
    return False


def scheme(config=None):
    return "https" if _tls_from_env_or_config(config) else "http"


def base(host, port, config=None):
    return f"{scheme(config)}://{host}:{port}"


def _ssl_ctx(config=None):
    global _CACHE_CTX
    if scheme(config) == "http":
        return None
    if _CACHE_CTX is not None:
        return _CACHE_CTX
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    try:
        from tls_utils import get_cert_dir, get_pinned_fingerprint_from_config
        cert_dir = get_cert_dir()
        ca_file = os.path.join(cert_dir, "ca.crt") if cert_dir else ""
        if ca_file and os.path.exists(ca_file):
            ctx.load_verify_locations(ca_file)
    except Exception:
        ctx = None
    _CACHE_CTX = ctx
    return ctx


def urlopen(url, data=None, headers=None, timeout=10, config=None):
    """urlopen with the right scheme context. Raises on error (caller handles)."""
    req = urllib.request.Request(url, data=data, headers=headers or {"Content-Type": "application/json"})
    ctx = _ssl_ctx(config)
    return urllib.request.urlopen(req, timeout=timeout, context=ctx)


def post_json(url, payload, timeout=10, config=None):
    body = json.dumps(payload).encode("utf-8")
    return urlopen(url, data=body, timeout=timeout, config=config)
