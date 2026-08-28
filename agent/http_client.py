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
import urllib.parse

_CACHE_CTX = {}


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


def _is_ip_literal(host):
    try:
        import ipaddress
        ipaddress.ip_address(host or "")
        return True
    except Exception:
        return False


def _host_from_url(url):
    try:
        return urllib.parse.urlparse(url).hostname
    except Exception:
        return None


def _ssl_ctx(config=None, host=None, _no_name_check=False):
    global _CACHE_CTX
    if scheme(config) == "http":
        return None
    key = (host, _no_name_check)
    if _CACHE_CTX.get(key) is not None:
        return _CACHE_CTX[key]
    ctx = ssl.create_default_context()
    # v5.0.3 (LOW-6): enable hostname verification for DNS-name connections
    # (the generated cert carries DNSName SANs for hostname/giamsat-server).
    # IP-literal connections keep CA-pinned verification only (the cert has no
    # IP SAN beyond 127.0.0.1); the no-host default preserves legacy callers.
    ctx.check_hostname = False if (host is None or _no_name_check or _is_ip_literal(host)) else True
    try:
        from tls_utils import get_cert_dir, get_pinned_fingerprint_from_config
        cert_dir = get_cert_dir()
        ca_file = os.path.join(cert_dir, "ca.crt") if cert_dir else ""
        if ca_file and os.path.exists(ca_file):
            ctx.load_verify_locations(ca_file)
    except Exception:
        ctx = None
    _CACHE_CTX[key] = ctx
    return ctx


def urlopen(url, data=None, headers=None, timeout=10, config=None):
    """urlopen with the right scheme context. Raises on error (caller handles)."""
    req = urllib.request.Request(url, data=data, headers=headers or {"Content-Type": "application/json"})
    host = _host_from_url(url)
    ctx = _ssl_ctx(config, host)
    try:
        return urllib.request.urlopen(req, timeout=timeout, context=ctx)
    except ssl.SSLCertVerificationError as e:
        # v5.0.4 (MEDIUM-1 FIX): a hostname mismatch (verify_code 62) with an
        # otherwise CA-pinned chain previously fell back to name-check-off
        # SILENTLY, making check_hostname a no-op. Now it fails hard unless the
        # admin explicitly opts in (and then it logs loudly).
        if getattr(e, "verify_code", None) == 62:
            allow = os.environ.get("GIAMSAT_ALLOW_INSECURE_HOSTNAME_FALLBACK", "").strip().lower()
            if allow in ("1", "true", "yes"):
                print("[!] TLS: hostname verification bypassed via GIAMSAT_ALLOW_INSECURE_HOSTNAME_FALLBACK - "
                      "MITM on the name is NOT detected (insecure)")
                ctx2 = _ssl_ctx(config, host, _no_name_check=True)
                return urllib.request.urlopen(req, timeout=timeout, context=ctx2)
            print("[!] TLS: hostname verification failed for %s - set "
                  "GIAMSAT_ALLOW_INSECURE_HOSTNAME_FALLBACK=1 to bypass (not recommended)" % host)
        raise


def post_json(url, payload, timeout=10, config=None):
    body = json.dumps(payload).encode("utf-8")
    return urlopen(url, data=body, timeout=timeout, config=config)
