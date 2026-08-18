"""Asset Discovery for GIAM-SAT Server - auto-discover printers, IP phones,
network devices WITHOUT an agent, stored into assets_inventory (source=auto)."""
import socket
import threading
import subprocess
import time

PRINTER_PORTS = [9100, 631, 515]
OID_SYSDESCR = "1.3.6.1.2.1.1.1.0"
OID_SYSNAME = "1.3.6.1.2.1.1.5.0"
PRINTER_SERIAL_OIDS = ["1.3.6.1.2.1.43.5.1.1.16.1",
                       "1.3.6.1.2.1.43.5.1.1.17.1",
                       "1.3.6.1.2.1.43.5.1.1.15.1"]

# v4.10: expanded signatures to stop network devices being lumped into 'phone'.
# Only vendor names / model prefixes that are strongly printer-associated.
PRINTER_KEYWORDS = [
    "jetdirect", "laserjet", "officejet", "deskjet", "photosmart", "pixma",
    "printer", "ipp", "brother", "ricoh", "lexmark", "kyocera", "imagedrive",
    "konica", "minolta", "xerox", "zebra", "datamax", "okidata", "tallygenicom",
    "epson", "canon", "hp laserjet", "hp officejet", "samsung sl-",
]
PHONE_KEYWORDS = [
    "yealink", "sip-t", "grandstream", "polycom", "snom", "linkus",
    "cisco spa", "cisco ip phone", "cisco cp-", "fanvil",
    "audiocodes", "avaya", "nortel", "obihai", "vtech",
]


def parse_cidr(cidr):
    try:
        import ipaddress
        if "/" in cidr:
            net, bits = cidr.split("/")
            return [str(ip) for ip in
                    ipaddress.IPv4Network("%s/%s" % (net.strip(), bits), strict=False)]
        if "-" in cidr:
            a, b = cidr.split("-")
            s = int(ipaddress.IPv4Address(a.strip()))
            e = int(ipaddress.IPv4Address(b.strip()))
            return [str(ipaddress.IPv4Address(i)) for i in range(s, min(e + 1, s + 65536))]
        return [cidr.strip()]
    except Exception:
        return []


def tcp_open(ip, port, timeout=0.6):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.close()
        return True
    except Exception:
        return False


def http_text(ip, port=80, timeout=1.5):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        data = b""
        while True:
            c = s.recv(4096)
            if not c:
                break
            data += c
            if len(data) > 65536:
                break
        s.close()
        return data.decode("utf-8", "ignore").lower()
    except Exception:
        return ""


def snmp_get(ip, oid, community="public", timeout=1.0):
    try:
        r = subprocess.run(
            ["snmpget", "-v2c", "-c", community, "-t", str(int(timeout)), "-r", "0",
             "udp:%s:161" % ip, oid],
            capture_output=True, text=True, timeout=int(timeout) + 2,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return r.stdout.strip() if r.returncode == 0 else ""
    except Exception:
        return ""


def clean(value):
    if not value:
        return ""
    value = value.replace('"', "")
    for m in ["STRING: ", "OCTET STRING: ", "Hex-STRING: "]:
        if m in value:
            value = value.split(m, 1)[1]
            break
    return value.strip()


def https_text(ip, port=443, timeout=2.0):
    """Fetch HTTPS page body (lowercased) for devices with HTTPS-only web UI."""
    try:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        tls = ctx.wrap_socket(s, server_hostname=ip)
        tls.connect((ip, port))
        tls.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        data = b""
        while True:
            c = tls.recv(4096)
            if not c:
                break
            data += c
            if len(data) > 65536:
                break
        tls.close()
        return data.decode("utf-8", "ignore").lower()
    except Exception:
        return ""


def classify(ip, timeout):
    """v4.10: classify a device with printer-first, signature-based checks.
    Order of evidence (strong → weak):
      1. Printer raw/IPP/LPD port open
      2. Specific phone vendor/model signature in web UI (HTTP/HTTPS)
      3. Printer signature in web UI
      4. SNMP sysDescr: printer/phone signature or generic network device
      5. HTTP present but no signature → network device (best effort)
      6. SIP port 5060 alone → likely IP phone/ATA"""
    if any(tcp_open(ip, p, timeout) for p in PRINTER_PORTS):
        return ("printer", {"method": "printer_ports"})
    title = http_text(ip, 80, timeout + 1.0)
    if not title and tcp_open(ip, 443, timeout):
        title = https_text(ip, 443, timeout + 1.0)
    if any(h in title for h in PHONE_KEYWORDS):
        return ("phone", {"method": "phone_http"})
    if any(h in title for h in PRINTER_KEYWORDS):
        return ("printer", {"method": "printer_http"})
    desc = snmp_get(ip, OID_SYSDESCR)
    name = snmp_get(ip, OID_SYSNAME)
    if desc:
        d = clean(desc).lower()
        if any(h in d for h in PRINTER_KEYWORDS):
            return ("printer", {"method": "printer_snmp"})
        if any(h in d for h in PHONE_KEYWORDS):
            return ("phone", {"method": "phone_snmp"})
        return ("network_device", {"sysdescr": clean(desc), "sysname": clean(name)})
    if title:
        return ("network_device", {"sysdescr": "", "sysname": ""})
    if tcp_open(ip, 5060, timeout):
        return ("phone", {"method": "phone_sip"})
    return None


def run_scan(cidr, db=None, max_threads=64, timeout=0.6):
    ips = parse_cidr(cidr)
    summary = {"range": cidr, "scanned": len(ips), "found": 0,
               "printer": 0, "phone": 0, "network_device": 0}
    if not ips:
        summary["error"] = "Invalid IP range"
        return summary
    results = []
    sem = threading.Semaphore(max_threads)

    def worker(ip):
        with sem:
            r = classify(ip, timeout)
            if r:
                results.append((ip, r[0], r[1]))

    threads = []
    for ip in ips:
        t = threading.Thread(target=worker, args=(ip,))
        threads.append(t)
        t.start()
        if len(threads) >= max_threads:
            for x in threads:
                x.join()
            threads = []
    for x in threads:
        x.join()

    if db is not None and hasattr(db, "upsert_inventory_asset"):
        for ip, cat, info in results:
            serial = ""
            if cat == "printer":
                for oid in PRINTER_SERIAL_OIDS:
                    serial = clean(snmp_get(ip, oid))
                    if serial:
                        break
            model = info.get("sysdescr") or clean(
                snmp_get(ip, "1.3.6.1.2.1.25.3.2.1.3.1"))
            try:
                # v4.10: stable id per (category, ip) - prevents duplicate assets
                # on every scan run (previously a fresh uuid was generated each time).
                import hashlib as _hl
                disc_key = f"discovered|{cat}|{ip}"
                db.upsert_inventory_asset({
                    "asset_id": _hl.md5(disc_key.encode("utf-8")).hexdigest(),
                    "display_id": f"{_hl.md5(('disp|' + disc_key).encode('utf-8')).hexdigest()[:8].upper()}",
                    "category": cat, "name": "%s @ %s" % (cat, ip), "model": model,
                    "brand": "", "serial_number": serial, "status": "online",
                    "ip_address": ip, "source": "auto", "notes": "auto",
                    "extra": {"method": info.get("method", cat),
                              "detected_at": time.strftime("%Y-%m-%d %H:%M:%S")}})
                summary[cat] += 1
                summary["found"] += 1
            except Exception as e:
                print("[-] asset discovery %s: %s" % (ip, e))
    return summary
