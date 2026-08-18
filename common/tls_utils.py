"""
TLS Utilities for GIAM-SAT v1.6.0
SSL/TLS wrapping for agent-server communication with certificate-based mutual authentication.
"""
import os
import ssl
import socket
import time


def get_cert_dir():
    if os.name == "nt":
        base = os.path.join(os.environ.get("PROGRAMDATA", "C:\\ProgramData"), "GIAM-SAT", "certs")
    else:
        base = os.path.join(os.path.expanduser("~"), ".giamsat", "certs")
    return base


def generate_self_signed_cert(cert_dir=None, hostname="giamsat-server"):
    cert_dir = cert_dir or get_cert_dir()
    os.makedirs(cert_dir, exist_ok=True)
    certfile = os.path.join(cert_dir, "server.crt")
    keyfile = os.path.join(cert_dir, "server.key")
    cafile = os.path.join(cert_dir, "ca.crt")

    if os.path.exists(certfile) and os.path.exists(keyfile):
        return certfile, keyfile, cafile if os.path.exists(cafile) else None

    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
        import datetime as dt

        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "GIAM-SAT CA")])
        ca_cert = (x509.CertificateBuilder()
            .subject_name(ca_name).issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(dt.datetime.utcnow() - dt.timedelta(days=1))
            .not_valid_after(dt.datetime.utcnow() + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(ca_key, hashes.SHA256()))

        server_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
        server_cert = (x509.CertificateBuilder()
            .subject_name(server_name).issuer_name(ca_name)
            .public_key(server_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(dt.datetime.utcnow() - dt.timedelta(days=1))
            .not_valid_after(dt.datetime.utcnow() + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(ca_key, hashes.SHA256()))

        ca_keyfile = os.path.join(cert_dir, "ca.key")
        with open(cafile, "wb") as f: f.write(ca_cert.public_bytes(Encoding.PEM))
        with open(ca_keyfile, "wb") as f: f.write(ca_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
        with open(certfile, "wb") as f: f.write(server_cert.public_bytes(Encoding.PEM))
        with open(keyfile, "wb") as f: f.write(server_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))

        print(f"[*] TLS certificates generated in {cert_dir}")
        return certfile, keyfile, cafile
    except ImportError:
        print("[!] 'cryptography' package not installed. Run: pip install cryptography")
        return None, None, None
    except Exception as e:
        print(f"[-] Certificate generation failed: {e}")
        return None, None, None


def create_tls_context(certfile, keyfile):
    """Create SSL context for server-side TLS wrapping of individual client connections."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile, keyfile)
    ctx.verify_mode = ssl.CERT_NONE
    ctx.check_hostname = False
    return ctx


def create_mtls_context(certfile, keyfile, cafile=None):
    """
    v3.1: Create mTLS (mutual TLS) context.
    Server presents its certificate AND requires client certificates
    signed by the CA. Only agents with valid per-agent certs can connect.
    """
    cert_dir = os.path.dirname(certfile)
    if not cafile:
        cafile = os.path.join(cert_dir, "ca.crt")

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile, keyfile)

    # Require client certificate signed by our CA
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = False  # Agents connect by IP
    ctx.load_verify_locations(cafile)
    ctx.verify_flags = ssl.VERIFY_X509_STRICT

    return ctx


def create_server_ssl_context(certfile, keyfile, cafile=None):
    """v4.10: Server-side TLS context for TCP:6666.

    server_core imports this name; it was previously MISSING from this module,
    so the import always failed and TLS silently fell back to plaintext.
    Now it enforces mTLS (CERT_REQUIRED signed by our CA) - the same policy the
    code advertises - instead of silently downgrading to plaintext.
    """
    return create_mtls_context(certfile, keyfile, cafile)


def gen_agent_cert(agent_id, cert_dir=None):
    """
    v3.1: Generate a per-agent certificate signed by GIAM-SAT CA.
    
    Each agent gets a unique cert (agent_<id>.crt + agent_<id>.key)
    that the server can validate for mutual TLS authentication.
    
    Args:
        agent_id: Unique agent identifier (e.g., machine_id or hostname)
        cert_dir: Certificate directory (default: get_cert_dir())
    
    Returns:
        (certfile, keyfile, cafile) or (None, None, None) on failure
    """
    cert_dir = cert_dir or get_cert_dir()
    os.makedirs(cert_dir, exist_ok=True)

    cafile = os.path.join(cert_dir, "ca.crt")
    ca_keyfile = os.path.join(cert_dir, "ca.key")
    agent_certfile = os.path.join(cert_dir, f"agent_{agent_id}.crt")
    agent_keyfile = os.path.join(cert_dir, f"agent_{agent_id}.key")

    # Check if existing agent cert
    if os.path.exists(agent_certfile) and os.path.exists(agent_keyfile):
        return agent_certfile, agent_keyfile, cafile

    # Check CA exists
    if not os.path.exists(cafile) or not os.path.exists(ca_keyfile):
        print(f"[!] mTLS: CA not found. Run generate_self_signed_cert() first.")
        return None, None, None

    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PrivateFormat, NoEncryption,
            load_pem_private_key,
        )
        import datetime as dt

        # Load CA key
        with open(ca_keyfile, "rb") as f:
            ca_key = load_pem_private_key(f.read(), password=None)
        with open(cafile, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())

        # Generate agent private key
        agent_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        # Build agent certificate
        agent_name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, f"agent-{agent_id}"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "GIAM-SAT Agent"),
        ])
        agent_cert = (
            x509.CertificateBuilder()
            .subject_name(agent_name)
            .issuer_name(ca_cert.subject)
            .public_key(agent_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(dt.datetime.utcnow() - dt.timedelta(days=1))
            .not_valid_after(dt.datetime.utcnow() + dt.timedelta(days=365))
            .add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False,
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .sign(ca_key, hashes.SHA256())
        )

        # Write agent cert + key
        with open(agent_certfile, "wb") as f:
            f.write(agent_cert.public_bytes(Encoding.PEM))
        with open(agent_keyfile, "wb") as f:
            f.write(agent_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))

        print(f"[*] mTLS: Agent cert generated for {agent_id} in {cert_dir}")
        return agent_certfile, agent_keyfile, cafile

    except ImportError:
        print("[!] 'cryptography' package not installed. Run: pip install cryptography")
        return None, None, None
    except Exception as e:
        print(f"[-] Agent cert generation failed: {e}")
        return None, None, None


def verify_server_cert_fingerprint(pinned_fingerprint, cert_der):
    """
    v3.9.17: Certificate Pinning — verify server cert fingerprint matches known-good value.
    Prevents Man-in-the-Middle attacks where attacker presents fake cert.
    
    Args:
        pinned_fingerprint: Expected SHA-256 fingerprint (hex string, e.g. "A1:B2:C3:...")
        cert_der: Server certificate in DER bytes
    
    Returns:
        True if fingerprint matches, False if mismatch (potential MitM)
    """
    import hashlib
    actual = hashlib.sha256(cert_der).hexdigest()
    expected = pinned_fingerprint.replace(":", "").lower()
    return actual == expected


def get_pinned_fingerprint_from_config(config=None):
    """
    v3.9.17: Read pinned server cert fingerprint from config or environment.
    Priority: 1) config.json field 2) GIAMSAT_SERVER_FINGERPRINT env var 3) None (skip pinning)
    
    Returns:
        Fingerprint string or None if not configured
    """
    import os
    # Check environment variable first (for quick testing)
    env_fp = os.environ.get("GIAMSAT_SERVER_FINGERPRINT", "").strip()
    if env_fp:
        return env_fp
    
    # Check config dict if provided
    if config and isinstance(config, dict):
        fp = (config.get("server_fingerprint") or 
              config.get("pinned_fingerprint") or 
              config.get("cert_fingerprint") or "")
        if fp:
            return fp.strip()
    return None


def create_tls_client_socket(host, port, cafile=None, pinned_fingerprint=None):
    """
    Create a TLS-wrapped client socket for agent.
    v3.9.17: Certificate Pinning — validates server cert fingerprint to prevent MitM.
    v2.5.10 FIX: check_hostname=False for Tailscale/VPN IP connections.
    Timeout 30s + 3 retries for slow VPN links.
    
    Args:
        host: Server IP/hostname
        port: Server port
        cafile: Path to CA cert (optional, for mTLS)
        pinned_fingerprint: Expected SHA-256 fingerprint of server cert (hex string with colons)
    
    Returns:
        (socket, True) on success, (None, False) on failure
    """
    max_retries = 3
    last_error = None

    # v3.9.17: Certificate Pinning — always check server identity
    for attempt in range(1, max_retries + 1):
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            # v4.10 (CRIT-5): enable hostname verification when connecting by
            # hostname and we have a CA to verify against (agents usually connect
            # by IP, where check_hostname is not meaningful without IP SANs).
            try:
                import ipaddress as _ipaddr
                _is_ip = True
                _ipaddr.ip_address(host)
            except Exception:
                _is_ip = False
            have_ca = bool(cafile) and os.path.exists(cafile)
            ctx.check_hostname = have_ca and not _is_ip
            if have_ca:
                # v4.10 (CRITICAL-3): verify server cert against CA - no CERT_NONE.
                ctx.verify_mode = ssl.CERT_REQUIRED
                ctx.load_verify_locations(cafile)
            elif pinned_fingerprint:
                # No CA: custom fingerprint check below is the identity verification.
                ctx.verify_mode = ssl.CERT_NONE
            else:
                # v4.10 (CRIT-5): fail-closed - never connect with zero server
                # identity verification (a MITM could impersonate the server).
                print(f"[!] TLS: no CA certificate or pinned fingerprint configured for {host} - refusing insecure connection", flush=True)
                return None, False

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)
            tls_sock = ctx.wrap_socket(sock, server_hostname=host)
            print(f"[*] TLS connect attempt {attempt}/{max_retries} to {host}:{port}...", flush=True)
            tls_sock.connect((host, port))
            tls_sock.settimeout(60)

            # v3.9.17: Certificate Pinning verification
            if pinned_fingerprint:
                try:
                    server_cert_der = tls_sock.getpeercert(binary_form=True)
                    if server_cert_der:
                        if verify_server_cert_fingerprint(pinned_fingerprint, server_cert_der):
                            print(f"[+] TLS connected + cert pinned OK to {host}:{port}", flush=True)
                        else:
                            print(f"[!] CERTIFICATE MISMATCH! Possible Man-in-the-Middle attack on {host}:{port}", flush=True)
                            print(f"[!] Expected fingerprint: {pinned_fingerprint}", flush=True)
                            try: tls_sock.close()
                            except: pass
                            return None, False
                    else:
                        print(f"[!] Warning: Server sent no certificate (unusual)", flush=True)
                except Exception as e:
                    print(f"[!] Certificate verification error: {e}", flush=True)
                    try: tls_sock.close()
                    except: pass
                    return None, False
            else:
                print(f"[+] TLS connected to {host}:{port} (no cert pinning configured)", flush=True)
            
            return tls_sock, True
        except ssl.SSLError as e:
            last_error = e
            print(f"[-] TLS error (attempt {attempt}): {e}", flush=True)
            if attempt < max_retries:
                time.sleep(2)  # Wait before retry
        except socket.timeout:
            last_error = f"Timeout connecting to {host}:{port} (attempt {attempt})"
            print(f"[-] {last_error}", flush=True)
            if attempt < max_retries:
                time.sleep(2)
        except OSError as e:
            last_error = e
            print(f"[-] OS error (attempt {attempt}): {e}", flush=True)
            if attempt < max_retries:
                time.sleep(2)
        except Exception as e:
            last_error = e
            print(f"[-] Connection error (attempt {attempt}): {e}", flush=True)
            if attempt < max_retries:
                time.sleep(2)

    # All TLS attempts failed - v4.10 (CRITICAL-3): NO plaintext fallback.
    # The caller (agent) already refuses plaintext when TLS is enabled; returning
    # a plaintext socket here would silently defeat that guard.
    print(f"[-] FATAL: All {max_retries} TLS attempts to {host}:{port} failed: {last_error} (no plaintext fallback)", flush=True)
    return None, False


def create_mtls_client_socket(host, port, agent_certfile, agent_keyfile, cafile=None):
    """
    v3.1: Create mTLS client socket for agent.
    Agent presents its issued certificate to the server for mutual auth.

    Args:
        host: Server IP/hostname
        port: Server port (6666)
        agent_certfile: Path to agent_X.crt
        agent_keyfile: Path to agent_X.key
        cafile: Path to ca.crt (for server verification, optional)

    Returns:
        (socket, True) on success, (None, False) on failure
    """
    max_retries = 3
    last_error = None

    for attempt in range(1, max_retries + 1):
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False

            # Load agent's client certificate
            ctx.load_cert_chain(agent_certfile, agent_keyfile)

            # Verify server cert (optional, but recommended with CA)
            if cafile and os.path.exists(cafile):
                ctx.verify_mode = ssl.CERT_REQUIRED
                ctx.load_verify_locations(cafile)
            else:
                ctx.verify_mode = ssl.CERT_NONE

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30)
            tls_sock = ctx.wrap_socket(sock, server_hostname=host)
            print(f"[*] mTLS connect attempt {attempt}/{max_retries} to {host}:{port}...", flush=True)
            tls_sock.connect((host, port))
            tls_sock.settimeout(60)
            print(f"[+] mTLS connected to {host}:{port}", flush=True)
            return tls_sock, True
        except ssl.SSLError as e:
            last_error = e
            print(f"[-] mTLS error (attempt {attempt}): {e}", flush=True)
            if attempt < max_retries:
                time.sleep(2)
        except socket.timeout:
            last_error = f"Timeout connecting to {host}:{port}"
            if attempt < max_retries:
                time.sleep(2)
        except Exception as e:
            last_error = e
            if attempt < max_retries:
                time.sleep(2)

    print(f"[-] mTLS: All {max_retries} attempts failed: {last_error}", flush=True)
    return None, False
