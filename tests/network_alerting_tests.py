#!/usr/bin/env python
"""GIAM-SAT Network Behavioral Alert tests (v5.0.4).

Covers:
  - NET-BEACON / NET-FIRST / NET-ODD from NetFlow flows (behaviour, not IP
    reputation - the "cloud VPS C2" case).
  - TLS ClientHello parser -> SNI + JA3.

Usage: python tests/network_alerting_tests.py  (exit 0 = pass)
"""

import os
import struct
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "server"))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "agent"))

import db_manager as dm
from network_alerting import NetworkAlertEngine


def build_client_hello(sni, ciphers=(0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F)):
    """Build a minimal valid TLS 1.2 ClientHello record (as a client would send)."""
    hello = bytearray()
    hello += b"\x03\x03"                                    # legacy_version TLS1.2
    hello += bytes(range(32))                               # random
    hello += b"\x00"                                        # no session id
    hello += struct.pack("!H", len(ciphers) * 2)            # cipher suites len
    for c in ciphers:
        hello += struct.pack("!H", c)
    hello += b"\x01\x00"                                    # compression: null
    # extensions
    exts = bytearray()
    sni_b = sni.encode("utf-8")
    servername = b"\x00" + struct.pack("!H", len(sni_b)) + sni_b   # host_name entry
    sn_ext = struct.pack("!H", 0x0000) + struct.pack("!H", 2 + len(servername)) + struct.pack("!H", len(servername)) + servername
    groups = struct.pack("!HHHH", 0x000a, 6, 4, 0x001d) + struct.pack("!HH", 0x0017, 0x0018)
    ecpf = struct.pack("!HHB", 0x000b, 2, 1) + b"\x00"
    exts += sn_ext + groups + ecpf
    hello += struct.pack("!H", len(exts)) + exts
    hs = b"\x01" + len(hello).to_bytes(3, "big") + bytes(hello)
    rec = b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs
    return rec


def main():
    failures = []

    def check(name, cond):
        print(("PASS" if cond else "FAIL") + "  " + name)
        if not cond:
            failures.append(name)

    # ------------------------------------------------------------------ 1. TLS
    from network_collector import _parse_tls_client_hello
    ch = build_client_hello("evil-c2.vps.example.com")
    sni, ja3 = _parse_tls_client_hello(ch)
    check("TLS SNI extracted", sni == "evil-c2.vps.example.com")
    check("TLS JA3 is md5 hex", len(ja3) == 32 and all(c in "0123456789abcdef" for c in ja3))
    check("non-TLS payload rejected", _parse_tls_client_hello(b"GET / HTTP/1.1\r\n") == ("", ""))
    check("short payload rejected", _parse_tls_client_hello(b"\x16\x03") == ("", ""))

    # v5.0.4 R8 (MEDIUM-2): IPv6 private/ULA/link-local must not be treated as external
    from network_alerting import _is_private_ip
    check("IPv6 ULA is private", _is_private_ip("fd00::1"))
    check("IPv6 link-local is private", _is_private_ip("fe80::1"))
    check("IPv6 public is external", not _is_private_ip("2001:4860:4860::8888"))
    check("IPv4 192.168 is private", _is_private_ip("192.168.1.5"))

    # -------------------------------------------------------------- 2. Alerts
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    dm.DB_PATH = path
    db = dm.DatabaseManager()
    try:
        db.conn.execute("INSERT INTO machines (machine_id,hostname,ip_address) VALUES ('M1','PC1','192.168.1.10')")
        now = time.time()
        dst = "52.0.0.1"   # a perfectly normal-looking AWS IP
        # regular beacon: 6 flows, 30s apart, inside the scan window, no history
        for i in range(6):
            db.conn.execute(
                "INSERT INTO netflow_flows (exporter_ip,src_ip,dst_ip,src_port,dst_port,protocol,packets,bytes,first,last) "
                "VALUES ('1.1.1.1','192.168.1.10',?,'12345',443,'TCP',10,900,?,?)",
                (dst, now - 1200 + i * 30, now - 1200 + i * 30))
        # a known destination (has history) -> only beacon should fire
        for i in range(6):
            db.conn.execute(
                "INSERT INTO netflow_flows (exporter_ip,src_ip,dst_ip,src_port,dst_port,protocol,packets,bytes,first,last) "
                "VALUES ('1.1.1.1','192.168.1.10','8.8.8.8','12345',53,'UDP',3,200,?,?)",
                (now - 1500 + i * 60, now - 1500 + i * 60))
        db.conn.execute(
            "INSERT INTO netflow_flows (exporter_ip,src_ip,dst_ip,src_port,dst_port,protocol,packets,bytes,first,last) "
            "VALUES ('1.1.1.1','192.168.1.10','8.8.8.8','12345',53,'UDP',3,200,?,?)",
            (now - 86400 * 10, now - 86400 * 10))  # history for the 8.8.8.8 pair
        db.conn.commit()

        eng = NetworkAlertEngine(db_manager=db)
        eng._scan_once()

        rows = db.conn.execute("SELECT rule_id, COUNT(*) n FROM threat_alerts GROUP BY rule_id").fetchall()
        rules = {r["rule_id"]: r["n"] for r in rows}
        check("NET-BEACON fired", rules.get("NET-BEACON", 0) == 1)
        check("NET-FIRST or NET-ODD fired for new dst", (rules.get("NET-FIRST", 0) + rules.get("NET-ODD", 0)) == 1)
        check("no alert for destination with history", rules.get("NET-FIRST", 0) + rules.get("NET-ODD", 0) <= 1)

        # cooldown: a second scan must NOT duplicate alerts
        eng._scan_once()
        rows2 = db.conn.execute("SELECT rule_id, COUNT(*) n FROM threat_alerts GROUP BY rule_id").fetchall()
        rules2 = {r["rule_id"]: r["n"] for r in rows2}
        check("cooldown prevents duplicate alerts", rules2 == rules)
    finally:
        db.conn.close()
        try:
            os.unlink(path)
        except OSError:
            pass

    if failures:
        print(f"\nFAILED: {len(failures)}: {failures}")
        return 1
    print("\nAll network alerting checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
