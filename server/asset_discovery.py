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


def classify(ip, timeout):
    printer = any(tcp_open(ip, p, timeout) for p in PRINTER_PORTS)
    title = http_text(ip, 80, timeout + 1.0)
    if printer or any(h in title for h in
                      ["jetdirect", "laserjet", "printer", "brother", "ricoh",
                       "lexmark", "ipp", "canon", "epson", "kyocera", "imagedrive"]):
        return ("printer", {"method": "printer"})
    if any(h in title for h in
           ["yealink", "sip-t", "grandstream", "polycom", "snom", "linkus",
            "cisco spa", "fanvil"]):
        return ("phone", {"method": "phone"})
    desc = snmp_get(ip, OID_SYSDESCR)
    name = snmp_get(ip, OID_SYSNAME)
    if desc or title:
        return ("network_device", {"sysdescr": clean(desc), "sysname": clean(name)})
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
                db.upsert_inventory_asset({
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
