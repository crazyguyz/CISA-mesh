"""
NetFlow Collector v1.0.0 - v4.13 (P2)
Receives NetFlow v5 / v9 exports on UDP 2055 from edge switches/routers and
stores conversation records for C2 beaconing / exfiltration / lateral movement
detection.

  - NetFlow v5: fixed 48-byte header + 24-byte records
  - NetFlow v9: template-based (caches templates per exporter)

Start: netflow.start()  Stop: netflow.stop()
"""
import os
import socket
import struct
import threading
import time
from datetime import datetime

LISTEN_PORT = int(os.environ.get("GIAMSAT_NETFLOW_PORT", "2055"))


class NetflowCollector(threading.Thread):
    """UDP collector for NetFlow v5/v9 (IPv4)."""

    def __init__(self, db_manager=None, host="0.0.0.0", port=LISTEN_PORT):
        super().__init__(daemon=True)
        self.db = db_manager
        self.host = host
        self.port = port
        self.running = True
        self.sock = None
        # v9 template cache: (exporter_ip, source_id) -> {template_id: [(field_type, field_len), ...]}
        self._templates = {}
        self._stats = {"packets": 0, "flows": 0, "errors": 0, "v5": 0, "v9": 0}

    # ------------------------------------------------------------------ setup
    def run(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.host, self.port))
            self.sock.settimeout(1.0)
            print(f"[*] NetFlow Collector listening on {self.host}:{self.port} (UDP)")
        except Exception as e:
            print(f"[!] NetFlow Collector: cannot bind {self.host}:{self.port} - {e}")
            return
        while self.running:
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except Exception:
                if not self.running:
                    break
                continue
            self._handle(data, addr[0])

    def stop(self):
        self.running = False
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass

    # ------------------------------------------------------------ dispatcher
    def _handle(self, data, exporter_ip):
        self._stats["packets"] += 1
        try:
            if len(data) < 20:
                return
            version = struct.unpack("!H", data[:2])[0]
            if version == 5:
                self._stats["v5"] += 1
                flows = self._parse_v5(data, exporter_ip)
            elif version == 9:
                self._stats["v9"] += 1
                flows = self._parse_v9(data, exporter_ip)
            else:
                return
            for f in flows:
                self._insert(f)
        except Exception:
            self._stats["errors"] += 1

    # --------------------------------------------------------------- NetFlow v5
    def _parse_v5(self, data, exporter_ip):
        """v5 header 24B: version,count,sysuptime,unix_secs,unix_nsecs,flow_sequence,
        engine_type,engine_id,sampling_interval + count x 48B records."""
        if len(data) < 24:
            return []
        _, count, _, unix_secs, _, _, _, _, _ = struct.unpack("!HHIIIIBBH", data[:24])
        base_time = float(unix_secs)
        flows = []
        off = 24
        for _ in range(min(count, 100)):
            if off + 48 > len(data):
                break
            rec = struct.unpack("!IIIHHIIIIHHBBBBHHBBH", data[off:off + 48])
            (src, dst, _nh, _in, _out, pkts, octets, first, last,
             srcp, dstp, _p1, flags, proto, tos, _sas, _das, _sm, _dm, _p2) = rec
            flows.append({
                "exporter_ip": exporter_ip,
                "src_ip": socket.inet_ntoa(struct.pack("!I", src)),
                "dst_ip": socket.inet_ntoa(struct.pack("!I", dst)),
                "src_port": srcp, "dst_port": dstp,
                "protocol": proto, "tcp_flags": flags,
                "packets": pkts, "bytes": octets,
                "first": base_time + first / 1000.0,
                "last": base_time + last / 1000.0,
            })
            off += 48
        self._stats["flows"] += len(flows)
        return flows

    # --------------------------------------------------------------- NetFlow v9
    def _parse_v9(self, data, exporter_ip):
        """v9 header 20B: version,count,sysuptime,unix_secs,sequence,source_id.
        Flowset id 0 = templates, id>0 = data using cached templates."""
        _, _, _, unix_secs, _, source_id = struct.unpack("!HHIIII", data[:20])
        key = (exporter_ip, source_id)
        off = 20
        flows = []
        while off + 4 <= len(data):
            fs_id, fs_len = struct.unpack("!HH", data[off:off + 4])
            if fs_len < 4 or off + fs_len > len(data):
                break
            body = data[off + 4:off + fs_len]
            if fs_id == 0:
                self._parse_v9_templates(key, body)
            else:
                templ = self._templates.get(key, {}).get(fs_id)
                if templ:
                    flows.extend(self._decode_v9_records(templ, body, unix_secs, exporter_ip))
            off += fs_len
        self._stats["flows"] += len(flows)
        return flows

    def _parse_v9_templates(self, key, body):
        pos = 0
        while pos + 4 <= len(body):
            tid, fcount = struct.unpack("!HH", body[pos:pos + 4])
            pos += 4
            if pos + fcount * 4 > len(body):
                break
            fields = []
            for _ in range(fcount):
                ftype, flen = struct.unpack("!HH", body[pos:pos + 4])
                pos += 4
                fields.append((ftype, flen))
            self._templates.setdefault(key, {})[tid] = fields

    def _decode_v9_records(self, fields, body, unix_secs, exporter_ip):
        """Decode data records from a template. Variable-length (0xFFFF) fields
        abort the current record (rare in IPv4 flow exports)."""
        pos = 0
        rows = []
        while pos < len(body):
            row = {"exporter_ip": exporter_ip}
            skip_row = False
            for ftype, flen in fields:
                if flen == 0xFFFF or pos + flen > len(body):
                    skip_row = True
                    break
                raw = body[pos:pos + flen]
                pos += flen
                val = self._v9_field(ftype, raw)
                if val is not None:
                    row[val[0]] = val[1]
            if skip_row:
                break
            if "src_ip" in row and "dst_ip" in row:
                row["first"] = unix_secs + (row.get("first_ms", 0) / 1000.0)
                row["last"] = unix_secs + (row.get("last_ms", 0) / 1000.0)
                rows.append(row)
        return rows

    def _v9_field(self, ftype, raw):
        if ftype == 8 and len(raw) == 4:
            return ("src_ip", socket.inet_ntoa(raw))
        if ftype == 12 and len(raw) == 4:
            return ("dst_ip", socket.inet_ntoa(raw))
        if ftype == 7 and len(raw) == 2:
            return ("src_port", struct.unpack("!H", raw)[0])
        if ftype == 11 and len(raw) == 2:
            return ("dst_port", struct.unpack("!H", raw)[0])
        if ftype == 4 and len(raw) == 1:
            return ("protocol", raw[0])
        if ftype == 6 and len(raw) == 1:
            return ("tcp_flags", raw[0])
        if ftype == 2 and len(raw) == 4:
            return ("packets", struct.unpack("!I", raw)[0])
        if ftype == 1 and len(raw) == 4:
            return ("bytes", struct.unpack("!I", raw)[0])
        if ftype == 21 and len(raw) == 4:
            return ("first_ms", struct.unpack("!I", raw)[0])
        if ftype == 22 and len(raw) == 4:
            return ("last_ms", struct.unpack("!I", raw)[0])
        return None

    # ------------------------------------------------------------------- store
    def _insert(self, f):
        if not self.db:
            return
        try:
            self.db.insert_netflow_flow(f)
        except Exception:
            pass

    def get_stats(self):
        return dict(self._stats)

