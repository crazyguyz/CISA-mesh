"""GIAM-SAT forensics module - v5.0.8 (Phase B: cây tiến trình + hồ sơ điều tra).

Two capabilities that Wazuh/Elastic make you assemble by hand:

1. PROCESS TREE from whatever process-creation telemetry the deployment really
   has, merged from three sources in this order of richness:
     * `process_tree_edges` - agent Sysmon EID1 chains (process_tree.py sends
       `process_tree_edge` when a chain reaches depth 3 or looks like LOTL, plus a
       60s `process_tree_snapshot`). The server used to DROP both messages as
       "Unknown message type", so this module also fixes that data loss.
     * `sysmon_events` - Sysmon EID1 rows (columns pid/parent_pid/...).
     * `events` + event_id 4688 - Windows process creation: raw_data holds
       `command_line`, `parent_pid` and the original insert-string pipe fields
       (5 = new process id, 6 = image, 8 = creator pid, 9 = command line,
       14 = creator image). ~19k such rows already exist on the test box, so the
       tree works TODAY even though Sysmon is not deployed.

2. EVIDENCE PACKET: one call collects everything +/- N minutes around an anchor
   (alerts, events, sysmon, traffic with GeoIP org, netflow, FIM, SCA, YARA,
   response actions, host facts, watchlist hits, process tree), stores it with a
   SHA-256 of the canonical JSON and renders a SELF-CONTAINED HTML file (inline
   CSS, every value escaped) that can be handed to a manager/customer as-is.

Read-only except the evidence store (`case_evidence`) and the process-edge store.
"""

import hashlib
import json
import re
from datetime import datetime, timedelta

import search_engine as se

# --------------------------------------------------------------------------- #
# Suspicious-command heuristics (rendered as tags on tree nodes)
# --------------------------------------------------------------------------- #
SUSPICIOUS_PATTERNS = (
    (re.compile(r"powershell.*(-enc|-e |-encodedcommand|frombase64string|hidden|bypass)", re.I),
     "PowerShell ẩn/encode"),
    (re.compile(r"-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/]{40,}={0,2}", re.I), "payload base64"),
    (re.compile(r"certutil.*(-urlcache|-decode|-split|-f\b)", re.I), "certutil tải/giải mã"),
    (re.compile(r"\b(mshta|rundll32|regsvr32|wscript|cscript|installutil|msbuild)\b", re.I), "LOLBin"),
    (re.compile(r"(\\\\temp\\\\|\\temp\\|appdata\\local\\temp|/tmp/)", re.I),
     "chạy từ thư mục tạm"),
    (re.compile(r"\bnet(\.exe)?\s+(user|localgroup|share|view)\b", re.I),
     "truy vấn tài khoản/chia sẻ"),
    (re.compile(r"\b(vssadmin|wbadmin|bcdedit|wevtutil\s+cl|netsh\s+advfirewall)\b", re.I),
     "chống điều tra / xoá log"),
    (re.compile(r"\b(psexec|wmic\s+/node|winrs|schtasks\s+/create|sc\.exe\s+create)\b", re.I),
     "di chuyển ngang / tạo nhiệm vụ"),
    (re.compile(r"\b(bitsadmin|invoke-webrequest|iwr|curl|wget|downloadstring)\b", re.I),
     "tải từ Internet"),
    (re.compile(r"\b(nltest|dsquery|samrdump|rubeus|mimikatz|procdump|lsass)\b", re.I),
     "truy cập thông tin xác thực"),
)


def _base_name(path):
    if not path:
        return ""
    txt = str(path).strip().strip('"')
    for sep in ("\\", "/"):
        if sep in txt:
            txt = txt.rsplit(sep, 1)[-1]
    return txt


def _hex_to_int(value):
    """'0x41c' / '1052' -> int, tolerant of junk (N/A, -, 0x0)."""
    if value is None:
        return None
    txt = str(value).strip()
    if not txt or txt in ("-", "N/A", "n/a", "0x0"):
        return None
    try:
        return int(txt, 16) if txt.lower().startswith("0x") else int(txt)
    except ValueError:
        return None


def pipe_fields(raw):
    """The original Windows insert-string blob ('a | b | c') as a list."""
    inner = (raw or {}).get("raw_data")
    if isinstance(inner, str):
        return [p.strip() for p in inner.split("|")]
    if isinstance(inner, (list, tuple)):
        return [str(p).strip() for p in inner]
    return []


def _field(fields, n):
    """1-based access into the insert-string fields."""
    return fields[n - 1] if len(fields) >= n else ""


def suspicious_reasons(cmdline, path):
    """Tags for a command line / image path (empty list when clean)."""
    hay = "%s %s" % (cmdline or "", path or "")
    out = []
    for rx, label in SUSPICIOUS_PATTERNS:
        if rx.search(hay) and label not in out:
            out.append(label)
    return out


# --------------------------------------------------------------------------- #
# Record parsers (one per telemetry source)
# --------------------------------------------------------------------------- #
def parse_4688_record(row):
    """Windows process creation (events.event_id 4688) -> process record."""
    raw = row.get("raw_data") or {}
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except Exception:
            raw = {}
    fields = pipe_fields(raw)
    pid = _hex_to_int(_field(fields, 5)) or _hex_to_int(raw.get("new_process_id"))
    image = _field(fields, 6) or str(raw.get("new_process_name") or "")
    cmdline = str(raw.get("command_line") or _field(fields, 9) or "")
    ppid = _hex_to_int(raw.get("parent_pid")) or _hex_to_int(_field(fields, 8))
    parent_name = _field(fields, 14) or str(raw.get("parent_process_name") or "")
    user = str(raw.get("target_username") or raw.get("subject_user_name") or _field(fields, 2)
               or row.get("user") or "")
    if user in ("N/A", "-"):
        user = ""
    if pid is None and not image:
        return None
    return {
        "pid": pid, "parent_pid": ppid, "name": _base_name(image), "path": image,
        "cmdline": cmdline, "user": user, "parent_name": _base_name(parent_name),
        "parent_path": parent_name, "time": row.get("time") or row.get("received_at") or "",
        "hostname": row.get("hostname") or "", "machine_id": row.get("machine_id") or "",
        "source": "event4688",
    }


def parse_sysmon_record(row):
    """sysmon_events row (or a sysmon payload dict) -> process record."""
    path = str(row.get("process_path") or "")
    if not path and row.get("process_name"):
        path = str(row.get("process_name"))
    return {
        "pid": _hex_to_int(row.get("pid")), "parent_pid": _hex_to_int(row.get("parent_pid")),
        "name": _base_name(path) or str(row.get("process_name") or ""), "path": path,
        "cmdline": str(row.get("command_line") or ""), "user": str(row.get("user") or ""),
        "parent_name": _base_name(row.get("parent_path")) or str(row.get("parent_process") or ""),
        "parent_path": str(row.get("parent_path") or ""),
        "time": row.get("timestamp") or row.get("received_at") or "",
        "hostname": row.get("hostname") or "", "machine_id": row.get("machine_id") or "",
        "hashes": str(row.get("hashes") or ""), "source": "sysmon",
    }


def parse_edge_record(row):
    """process_tree_edges row (agent process_tree_edge / snapshot chain)."""
    chain = row.get("chain_json")
    if isinstance(chain, str) and chain:
        try:
            chain = json.loads(chain)
        except Exception:
            chain = None
    name = str(row.get("process_name") or "")
    cmdline = ""
    if isinstance(chain, list) and chain:
        name = name or str(chain[-1])
        cmdline = " → ".join(str(c) for c in chain)
    return {
        "pid": _hex_to_int(row.get("pid")), "parent_pid": _hex_to_int(row.get("parent_pid")),
        "name": _base_name(name) or name, "path": "", "cmdline": cmdline, "user": "",
        "parent_name": str(row.get("parent_name") or ""),
        "time": row.get("ts") or row.get("received_at") or "",
        "hostname": row.get("hostname") or "", "machine_id": row.get("machine_id") or "",
        "suspicious_hint": bool(row.get("suspicious")),
        "source": "agent-%s" % (row.get("kind") or "edge"),
    }


def parse_process_record(row):
    """Pick the right parser for a row coming from any scope."""
    if row.get("event_id") in ("4688", 4688) and row.get("raw_data"):
        return parse_4688_record(row)
    if "process_name" in row and "process_path" in row:
        return parse_sysmon_record(row)
    if "kind" in row or "chain_json" in row:
        return parse_edge_record(row)
    return None


# --------------------------------------------------------------------------- #
# Process tree
# --------------------------------------------------------------------------- #
def build_process_tree(records, root_pid=None, max_nodes=600, max_depth=12,
                       create_implied_parents=True):
    """Merge process records into a parent -> children tree.

    When a creation event names its creator (4688 field 14 carries the parent
    image) but that creator's own creation event is outside the window, an
    "implied parent" node is synthesised so the tree still nests correctly
    (source = 'implied-parent'). Cycle safe and size capped. Returns:
      {'roots': [node...], 'stats': {...}, 'flat': [node...]}
    """
    nodes, order = {}, []
    for rec in records or []:
        if not rec or rec.get("pid") is None:
            continue
        key = str(rec["pid"])
        node = nodes.get(key)
        if node is None:
            node = {
                "pid": rec["pid"], "name": rec.get("name") or "", "path": rec.get("path") or "",
                "cmdline": rec.get("cmdline") or "", "user": rec.get("user") or "",
                "parent_pid": rec.get("parent_pid"), "parent_name": rec.get("parent_name") or "",
                "parent_path": rec.get("parent_path") or "",
                "source": rec.get("source") or "", "count": 0, "children": [],
                "first_seen": "", "last_seen": "", "depth": 0, "tags": [],
                "hashes": rec.get("hashes") or "", "truncated_children": 0,
            }
            nodes[key] = node
            order.append(key)
        node["count"] += 1
        for field in ("path", "cmdline", "user", "hashes"):
            if rec.get(field) and not node.get(field):
                node[field] = rec[field]
        stamp = str(rec.get("time") or "")
        if stamp:
            if not node["first_seen"] or stamp < node["first_seen"]:
                node["first_seen"] = stamp
            if stamp > node["last_seen"]:
                node["last_seen"] = stamp
        for tag in suspicious_reasons(node["cmdline"], node["path"]):
            if tag not in node["tags"]:
                node["tags"].append(tag)
        if rec.get("suspicious_hint") and "agent: chuỗi đáng ngờ" not in node["tags"]:
            node["tags"].append("agent: chuỗi đáng ngờ")

    implied = 0
    if create_implied_parents:
        for key in list(order):
            node = nodes[key]
            ppid = node.get("parent_pid")
            if ppid is None or not node.get("parent_name"):
                continue
            pkey = str(ppid)
            if pkey in nodes:
                continue
            nodes[pkey] = {
                "pid": ppid, "name": node["parent_name"], "path": node.get("parent_path") or "",
                "cmdline": "", "user": "", "parent_pid": None, "parent_name": "",
                "parent_path": "", "source": "implied-parent", "count": 0, "children": [],
                "first_seen": "", "last_seen": "", "depth": 0, "tags": [],
                "hashes": "", "truncated_children": 0,
            }
            order.append(pkey)
            implied += 1

    # Single-parent map: one parent per node => the result is a FOREST, so a
    # parent/child loop (PID reuse) can never make us recurse forever.
    parent_of = {}
    for key in order:
        parent = nodes[key].get("parent_pid")
        pkey = str(parent) if parent is not None else None
        parent_of[key] = pkey if (pkey and pkey in nodes and pkey != key) else None

    for key in order:  # cut one edge of any loop so every chain reaches a root
        chain, cur = set(), key
        while cur is not None and cur not in chain:
            chain.add(cur)
            cur = parent_of.get(cur)
        if cur is not None and cur in parent_of:
            parent_of[cur] = None
            if "vòng lặp PID (PID bị tái sử dụng)" not in nodes[cur]["tags"]:
                nodes[cur]["tags"].append("vòng lặp PID (PID bị tái sử dụng)")

    children_of = {k: [] for k in order}
    roots = []
    for key in order:
        parent = parent_of.get(key)
        if parent and parent in children_of:
            children_of[parent].append(key)
        else:
            roots.append(key)

    if root_pid is not None:
        wanted = str(root_pid)
        if wanted in nodes:
            roots = [wanted]

    # depth by BFS from the roots, then cap the size in BFS order
    seen, visible, queue = set(), [], [(k, 0) for k in roots]
    while queue and len(visible) < max_nodes:
        key, depth = queue.pop(0)
        if key in seen:
            continue
        seen.add(key)
        visible.append(key)
        nodes[key]["depth"] = depth
        if depth < max_depth:
            children_of[key].sort(key=lambda c: nodes[c].get("first_seen") or "")
            for child in children_of[key]:
                if child not in seen:
                    queue.append((child, depth + 1))

    visible_set = set(visible)
    for key in visible:
        kids = [c for c in children_of[key] if c in visible_set]
        if nodes[key]["depth"] >= max_depth and kids:
            nodes[key]["truncated_children"] = len(kids)
            kids = []
        nodes[key]["children"] = kids

    def export(key):
        node = nodes[key]
        return {
            "pid": node["pid"], "name": node["name"], "path": node["path"],
            "cmdline": node["cmdline"], "user": node["user"], "hashes": node["hashes"],
            "parent_pid": node["parent_pid"], "parent_name": node["parent_name"],
            "source": node["source"], "count": node["count"], "tags": node["tags"],
            "first_seen": node["first_seen"], "last_seen": node["last_seen"],
            "depth": node["depth"], "truncated_children": node["truncated_children"],
            "children": [export(c) for c in node["children"]],
        }

    edges = sum(len(nodes[k]["children"]) for k in visible)
    suspicious = [k for k in visible if nodes[k]["tags"]]
    flat = sorted((export(k) for k in visible),
                  key=lambda n: (-len(n["tags"]), -n["count"], n["name"]))
    for item in flat:
        item["children"] = []
    return {
        "roots": [export(k) for k in roots if k in visible_set],
        "stats": {
            "records": len(records or []), "nodes": len(visible), "edges": edges,
            "dropped": max(0, len(nodes) - len(visible)),
            "implied_parents": implied,
            "max_depth": max((nodes[k]["depth"] for k in visible), default=0),
            "suspicious_nodes": len(suspicious),
        },
        "flat": flat[:60],
    }


# --------------------------------------------------------------------------- #
# Collection helpers
# --------------------------------------------------------------------------- #
def collect_process_records(db, machine_id, start=None, end=None, limit=2000):
    """Merge every available process-creation source for one machine.

    1. process_tree_edges (agent Sysmon EID1 chains + snapshots)
    2. sysmon_events with sysmon_event_id = 1 (when Sysmon is deployed)
    3. events event_id = 4688 (Windows process creation - works today)
    """
    kind = se.backend_kind(db)
    ph = se.placeholder(kind)
    window = ""
    window_params = []
    if start and end:
        window = " AND received_at >= %s AND received_at <= %s" % (ph, ph)
        window_params = [start, end]
    records = []

    try:
        for row in se.rows(db, "SELECT * FROM process_tree_edges WHERE machine_id = %s%s "
                               "ORDER BY id DESC LIMIT %s" % (ph, window, ph),
                           [machine_id] + window_params + [limit], kind):
            rec = parse_edge_record(se.normalize_row(row))
            if rec.get("pid") is not None:
                records.append(rec)
    except Exception:
        pass

    try:
        for row in se.rows(db, "SELECT * FROM sysmon_events WHERE machine_id = %s "
                               "AND sysmon_event_id = 1%s ORDER BY id DESC LIMIT %s"
                           % (ph, window, ph),
                           [machine_id] + window_params + [limit], kind):
            rec = parse_sysmon_record(se.normalize_row(row))
            if rec.get("pid") is not None:
                records.append(rec)
    except Exception:
        pass

    try:
        for row in se.rows(db, "SELECT machine_id, hostname, event_id, time, received_at, raw_data "
                               "FROM events WHERE machine_id = %s AND event_id = '4688'%s "
                               "ORDER BY id DESC LIMIT %s" % (ph, window, ph),
                           [machine_id] + window_params + [limit], kind):
            rec = parse_4688_record(se.normalize_row(row))
            if rec:
                records.append(rec)
    except Exception:
        pass

    return records


def _machine_ip(db, machine_id):
    hit = se.rows(db, "SELECT ip_address FROM machines WHERE machine_id = %s"
                  % se.placeholder(se.backend_kind(db)), (machine_id,), se.backend_kind(db))
    return (hit[0].get("ip_address") or "") if hit else ""


def _parse_dt(value):
    """Accept a datetime, 'YYYY-mm-dd HH:MM:SS', ISO with T/Z, or None."""
    if isinstance(value, datetime):
        return value
    txt = str(value or "").strip().replace("T", " ").rstrip("Z")
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            return datetime.strptime(txt[:len(fmt) + 2].strip(), fmt)
        except ValueError:
            continue
    return None


def _server_version():
    import os
    try:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "version.txt")
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read().strip()
    except Exception:
        return ""


def canonical_json(payload):
    """Stable JSON of the payload without the integrity block."""
    clean = {k: v for k, v in (payload or {}).items() if k != "integrity"}
    return json.dumps(clean, ensure_ascii=False, sort_keys=True, default=str)


def payload_sha256(payload):
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


# (key, table, columns, cap) - every section is filtered by machine_id + window
EVIDENCE_SECTIONS = (
    ("alerts", "threat_alerts",
     "id, hostname, rule_id, rule_name, severity, description, source_ip, timestamp, "
     "received_at, status, assignee", 200),
    ("events", "events",
     "id, event_id, subtype, source, computer, \"user\", category, time, description, received_at", 300),
    ("sysmon", "sysmon_events",
     "id, sysmon_event_id, process_name, process_path, command_line, pid, parent_process, "
     "parent_pid, user, severity, description, dst_ip, dns_query, file_path, received_at", 200),
    ("traffic", "network_traffic",
     "id, src_ip, dst_ip, src_port, dst_port, protocol, dns_query, http_host, state, "
     "timestamp, received_at", 200),
    ("fim", "fim_events", "id, action, path, time, received_at", 100),
    ("sca", "sca_events", "id, check_id, title, status, severity, timestamp, received_at", 100),
    ("yara", "yara_alerts", "id, rule_name, description, file, timestamp, received_at", 50),
    ("responses", "response_results",
     "id, exec_id, action, status, exit_code, output, error, timestamp, received_at", 30),
)


def collect_evidence(db, machine_id, anchor=None, window_minutes=15, title="",
                     created_by="", include_tree=True):
    """Collect everything visible +/- window_minutes around the anchor."""
    kind = se.backend_kind(db)
    ph = se.placeholder(kind)
    anchor_dt = _parse_dt(anchor) or datetime.now()
    window_minutes = int(window_minutes or 15)
    start_s = (anchor_dt - timedelta(minutes=window_minutes)).strftime("%Y-%m-%d %H:%M:%S")
    end_s = (anchor_dt + timedelta(minutes=window_minutes)).strftime("%Y-%m-%d %H:%M:%S")

    host_rows = se.rows(db, "SELECT * FROM machines WHERE machine_id = %s" % ph,
                        (machine_id,), kind)
    host = se.normalize_row(host_rows[0]) if host_rows else {}
    hostname = host.get("hostname") or ""

    sections = {}
    for key, table, cols, cap in EVIDENCE_SECTIONS:
        rows = []
        try:
            rows = [se.normalize_row(r) for r in se.rows(
                db, "SELECT %s FROM %s WHERE machine_id = %s AND received_at >= %s "
                    "AND received_at <= %s ORDER BY received_at DESC LIMIT %s"
                    % (cols, table, ph, ph, ph, ph),
                (machine_id, start_s, end_s, cap), kind)]
        except Exception:
            rows = []
        try:
            total = (se.rows(db, "SELECT COUNT(*) AS n FROM %s WHERE machine_id = %s "
                                 "AND received_at >= %s AND received_at <= %s"
                           % (table, ph, ph, ph),
                           (machine_id, start_s, end_s), kind) or [{}])[0].get("n", len(rows))
        except Exception:
            total = len(rows)
        sections[key] = {"total": total, "shown": len(rows), "rows": rows}

    _attach_geoip(sections.get("traffic", {}).get("rows", []))
    sections["netflow"] = _netflow_section(db, machine_id, host, start_s, end_s)
    facts = _host_facts(db, machine_id, host)
    tree = build_process_tree(
        collect_process_records(db, machine_id, start_s, end_s)) if include_tree \
        else {"roots": [], "flat": [], "stats": {}}

    payload = {
        "title": title or ("Hồ sơ điều tra %s ±%d phút"
                           % (hostname or machine_id, window_minutes)),
        "machine_id": machine_id,
        "hostname": hostname,
        "anchor": anchor_dt.strftime("%Y-%m-%d %H:%M:%S"),
        "window": {"minutes": window_minutes, "start": start_s, "end": end_s},
        "created_by": created_by,
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "server_version": _server_version(),
        "sections": sections,
        "facts": facts,
        "process_tree": tree,
    }
    payload["watchlist_hits"] = _watchlist_hits(db, sections, tree)
    payload["counts"] = {k: v.get("total", 0) for k, v in sections.items()}
    payload["counts"]["process_nodes"] = tree.get("stats", {}).get("nodes", 0)
    payload["integrity"] = {"algo": "sha256", "sha256": payload_sha256(payload),
                            "note": "SHA-256 của payload JSON (không tính trường integrity)"}
    return payload


def _attach_geoip(rows):
    try:
        from geoip_lookup import org_label
    except Exception:
        return
    for row in rows:
        try:
            row["dst_org"] = org_label(row.get("dst_ip") or "")
        except Exception:
            row["dst_org"] = ""


def _netflow_section(db, machine_id, host, start_s, end_s):
    kind = se.backend_kind(db)
    ph = se.placeholder(kind)
    ip = host.get("ip_address") or _machine_ip(db, machine_id)
    out = {"total": 0, "shown": 0, "rows": [], "filter_ip": ip}
    if not ip:
        return out
    try:
        rows = [se.normalize_row(r) for r in se.rows(
            db, "SELECT id, src_ip, dst_ip, src_port, dst_port, protocol, packets, bytes, "
                "first, last, received_at FROM netflow_flows WHERE (src_ip = %s OR dst_ip = %s) "
                "AND received_at >= %s AND received_at <= %s ORDER BY received_at DESC LIMIT 100"
                % (ph, ph, ph, ph), (ip, ip, start_s, end_s), kind)]
        out.update({"total": len(rows), "shown": len(rows), "rows": rows})
    except Exception:
        pass
    return out


def _host_facts(db, machine_id, host):
    kind = se.backend_kind(db)
    ph = se.placeholder(kind)
    facts = {"machine": host}
    for key, table, cols in (
            ("hardware", "hardware_info", "data_json, fingerprint, has_changed, received_at"),
            ("users", "machine_users", "user_name, employee_id, email, branch, updated_at"),
            ("uptime", "machine_uptime", "date, session_start, last_seen, uptime_minutes")):
        try:
            facts[key] = [se.normalize_row(r) for r in se.rows(
                db, "SELECT %s FROM %s WHERE machine_id = %s ORDER BY 1 DESC LIMIT 10"
                    % (cols, table, ph), (machine_id,), kind)]
        except Exception:
            facts[key] = []
    for hw in facts.get("hardware", []):
        data = hw.get("data_json")
        if isinstance(data, str):
            try:
                hw["data_json"] = json.loads(data)
            except Exception:
                pass
    return facts


def _watchlist_hits(db, sections, tree):
    kind = se.backend_kind(db)
    try:
        items = se.rows(db, "SELECT indicator, type, severity, label FROM watchlist "
                            "WHERE enabled = 1", None, kind)
    except Exception:
        return []
    haystack = []
    for key, fields in (("traffic", ("dst_ip", "dns_query", "http_host")),
                        ("alerts", ("source_ip",)),
                        ("sysmon", ("dst_ip", "dns_query"))):
        for row in sections.get(key, {}).get("rows", []):
            haystack.extend(str(row.get(f) or "") for f in fields)
    haystack.extend(str(node.get("cmdline") or "") for node in tree.get("flat", []))
    blob = " | ".join(h.lower() for h in haystack if h)
    hits = []
    for item in items or []:
        indicator = str(item.get("indicator") or "").strip().lower()
        if indicator and indicator in blob:
            hits.append({"indicator": item.get("indicator"), "type": item.get("type"),
                         "severity": item.get("severity"), "label": item.get("label")})
    return hits[:20]


# --------------------------------------------------------------------------- #
# Self-contained HTML report (no external assets, every value escaped)
# --------------------------------------------------------------------------- #
def _esc(value):
    return (str("" if value is None else value)
            .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;").replace("'", "&#39;"))


HTML_CSS = """
body{font-family:Segoe UI,Tahoma,Arial,sans-serif;background:#0f1419;color:#d7dee6;
     margin:0;padding:18px;font-size:13px}
h1{font-size:19px;margin:0 0 4px 0;color:#7fd1a6}
h2{font-size:14px;margin:18px 0 6px 0;color:#8fc7ff;border-bottom:1px solid #24313d;padding-bottom:3px}
h3{font-size:12px;margin:10px 0 4px 0;color:#c9d4de}
table{border-collapse:collapse;width:100%;margin:4px 0 10px 0}
th,td{border:1px solid #24313d;padding:3px 6px;vertical-align:top;font-size:11.5px;
      word-break:break-word}
th{background:#182029;color:#9fb3c8;text-align:left;white-space:nowrap}
tr:nth-child(even) td{background:#131a21}
.meta{background:#182029;border:1px solid #24313d;border-radius:6px;padding:10px;margin-bottom:6px}
.kv{display:inline-block;margin-right:16px}
.kv b{color:#9fb3c8;font-weight:600}
.badge{display:inline-block;padding:1px 6px;border-radius:10px;font-size:10.5px;margin-left:4px}
.b-red{background:#7f1d1d;color:#ffd7d7}.b-amber{background:#78350f;color:#ffe8cc}
.b-blue{background:#1e3a8a;color:#dbeafe}.b-grey{background:#2a3a4a;color:#cbd5e1}
.tag{background:#7f1d1d;color:#ffe4e6;padding:0 5px;border-radius:8px;font-size:10px;margin-left:4px}
ul.tree{list-style:none;margin:0;padding-left:14px}
ul.tree li{margin:1px 0}
.cmd{color:#9fd6a6;font-family:Consolas,monospace;font-size:11px}
.hash{font-family:Consolas,monospace;font-size:11px;color:#9fb3c8;word-break:break-all}
.foot{margin-top:18px;color:#7f8fa6;font-size:10.5px;border-top:1px solid #24313d;padding-top:6px}
"""


def _html_table(rows, columns=None, max_rows=60):
    if not rows:
        return "<p class='cmd'>-</p>"
    cols = columns or list(rows[0].keys())[:9]
    out = ["<table><thead><tr>"]
    out += ["<th>%s</th>" % _esc(c) for c in cols]
    out.append("</tr></thead><tbody>")
    for row in rows[:max_rows]:
        out.append("<tr>")
        for c in cols:
            val = row.get(c)
            if isinstance(val, (dict, list)):
                val = json.dumps(val, ensure_ascii=False)[:300]
            out.append("<td>%s</td>" % _esc(val))
        out.append("</tr>")
    out.append("</tbody></table>")
    if len(rows) > max_rows:
        out.append("<p class='cmd'>… còn %d dòng nữa (xem JSON để đầy đủ)</p>"
                   % (len(rows) - max_rows))
    return "".join(out)


def _tree_html(nodes):
    if not nodes:
        return "<p class='cmd'>Không có dữ liệu tiến trình trong khoảng thời gian này.</p>"
    out = ["<ul class='tree'>"]
    for node in nodes:
        tags = "".join("<span class='tag'>%s</span>" % _esc(t) for t in node.get("tags") or [])
        out.append("<li><b>%s</b> <span class='cmd'>(PID %s%s)</span>%s"
                   % (_esc(node.get("name") or "?"), _esc(node.get("pid")),
                      ", cha %s" % _esc(node.get("parent_pid")) if node.get("parent_pid") else "",
                      tags))
        if node.get("cmdline"):
            out.append("<div class='cmd'>%s</div>" % _esc(str(node["cmdline"])[:400]))
        if node.get("user"):
            out.append("<div class='cmd'>user: %s</div>" % _esc(node["user"]))
        if node.get("truncated_children"):
            out.append("<div class='cmd'>… %d tiến trình con bị lược bớt</div>"
                       % node["truncated_children"])
        if node.get("children"):
            out.append(_tree_html(node["children"]))
        out.append("</li>")
    out.append("</ul>")
    return "".join(out)


def render_html(payload):
    """Self-contained HTML an analyst can send to a manager/customer."""
    p = payload or {}
    sections = p.get("sections") or {}
    counts = p.get("counts") or {}
    facts = p.get("facts") or {}
    tree = p.get("process_tree") or {}
    stats = tree.get("stats") or {}
    window = p.get("window") or {}
    integrity = p.get("integrity") or {}

    out = ["<!DOCTYPE html><html lang='vi'><head><meta charset='utf-8'>",
           "<title>%s</title>" % _esc(p.get("title") or "GIAM-SAT evidence"),
           "<style>%s</style></head><body>" % HTML_CSS]
    out.append("<h1>%s</h1>" % _esc(p.get("title") or "Hồ sơ điều tra"))
    out.append("<div class='meta'>")
    for label, value in (("Máy", "%s (%s)" % (p.get("hostname") or "?", p.get("machine_id") or "?")),
                         ("Mốc điều tra", p.get("anchor")),
                         ("Cửa sổ", "±%s phút — %s → %s" % (window.get("minutes"),
                                                          window.get("start"), window.get("end"))),
                         ("Người tạo", p.get("created_by")),
                         ("Tạo lúc", p.get("generated_at")),
                         ("Phiên bản", p.get("server_version"))):
        out.append("<span class='kv'><b>%s:</b> %s</span>" % (_esc(label), _esc(value)))
    out.append("</div>")

    out.append("<h2>Số liệu thu thập</h2><table><thead><tr><th>Nguồn</th>"
               "<th>Số dòng trong cửa sổ</th></tr></thead><tbody>")
    for key in sorted(counts):
        out.append("<tr><td>%s</td><td>%s</td></tr>" % (_esc(key), _esc(counts[key])))
    out.append("</tbody></table>")

    hits = p.get("watchlist_hits") or []
    if hits:
        out.append("<h2>Khớp danh sách theo dõi (watchlist) — %d</h2>" % len(hits))
        out.append(_html_table(hits))

    out.append("<h2>Cây tiến trình — %s node / %s cạnh / sâu %s cấp / %s node đáng ngờ</h2>"
               % (_esc(stats.get("nodes", 0)), _esc(stats.get("edges", 0)),
                  _esc(stats.get("max_depth", 0)), _esc(stats.get("suspicious_nodes", 0))))
    out.append(_tree_html(tree.get("roots") or []))
    suspicious = [n for n in (tree.get("flat") or []) if n.get("tags")]
    if suspicious:
        out.append("<h3>Tiến trình bị gắn cờ</h3>")
        out.append(_html_table(suspicious, columns=("pid", "name", "cmdline", "tags", "user")))

    out.append("<h2>Thông tin máy tại thời điểm điều tra</h2>")
    machine = facts.get("machine") or {}
    out.append(_html_table([machine]) if machine else "<p class='cmd'>-</p>")
    for key, label in (("users", "Người dùng đăng nhập"), ("hardware", "Phần cứng"),
                       ("uptime", "Phiên làm việc / uptime")):
        out.append("<h3>%s</h3>" % _esc(label))
        out.append(_html_table(facts.get(key) or []))

    for key in ("alerts", "events", "sysmon", "traffic", "netflow", "fim", "sca", "yara",
                "responses"):
        sec = sections.get(key) or {}
        out.append("<h2>%s — %s dòng (hiển thị %s)</h2>"
                   % (_esc(key), _esc(sec.get("total", 0)), _esc(sec.get("shown", 0))))
        out.append(_html_table(sec.get("rows") or []))

    out.append("<div class='foot'>GIAM-SAT — hồ sơ bằng chứng tự chứa (không cần công cụ ngoài).<br>"
               "SHA-256 payload: <span class='hash'>%s</span><br>%s</div>"
               % (_esc(integrity.get("sha256")), _esc(integrity.get("note"))))
    out.append("</body></html>")
    return "".join(out)


# --------------------------------------------------------------------------- #
# Evidence store (case_evidence)
# --------------------------------------------------------------------------- #
EVIDENCE_META_COLS = ("id", "machine_id", "hostname", "title", "anchor_time",
                      "window_minutes", "created_by", "created_at", "sha256", "case_id")


def save_evidence(db, payload, created_by="", case_id=None, alert_id=None):
    """Persist a payload; returns the new row id (or None)."""
    kind = se.backend_kind(db)
    ph = se.placeholder(kind)
    body = json.dumps(payload, ensure_ascii=False, default=str)
    cols = ("(machine_id, hostname, title, anchor_time, window_minutes, created_by, sha256, "
            "payload_json, case_id, alert_id, created_at)")
    values = "(%s)" % ", ".join([ph] * 10 + (["NOW()"] if kind == "postgres"
                                             else ["CURRENT_TIMESTAMP"]))
    sql = "INSERT INTO case_evidence %s VALUES %s RETURNING id" % (cols, values)
    params = (
        payload.get("machine_id"), payload.get("hostname"), payload.get("title"),
        payload.get("anchor"), (payload.get("window") or {}).get("minutes") or 0,
        created_by or payload.get("created_by") or "",
        (payload.get("integrity") or {}).get("sha256") or "", body, case_id, alert_id,
    )
    new_id = se.write_sql(db, sql, params, kind, returning=True)
    if isinstance(new_id, dict):
        new_id = new_id.get("id")
    return new_id


def list_evidence(db, machine_id=None, limit=100):
    kind = se.backend_kind(db)
    ph = se.placeholder(kind)
    sql = "SELECT %s FROM case_evidence" % ", ".join(EVIDENCE_META_COLS)
    params = []
    if machine_id:
        sql += " WHERE machine_id = %s" % ph
        params.append(machine_id)
    sql += " ORDER BY id DESC LIMIT %s" % ph
    params.append(int(limit))
    return [se.normalize_row(r) for r in se.rows(db, sql, tuple(params), kind)]


def load_evidence(db, evidence_id):
    """Return the stored payload with an integrity verdict, or None."""
    kind = se.backend_kind(db)
    rows = se.rows(db, "SELECT %s, payload_json FROM case_evidence WHERE id = %s"
                   % (", ".join(EVIDENCE_META_COLS), se.placeholder(kind)),
                   (int(evidence_id),), kind)
    if not rows:
        return None
    row = se.normalize_row(rows[0])
    raw = row.get("payload_json")
    try:
        payload = json.loads(raw) if isinstance(raw, str) else (raw or {})
    except Exception:
        payload = {}
    payload["_stored"] = {k: row.get(k) for k in EVIDENCE_META_COLS}
    clean = {k: v for k, v in payload.items() if not k.startswith("_")}
    stored_hash = (clean.get("integrity") or {}).get("sha256")
    payload["_integrity_ok"] = bool(stored_hash) and stored_hash == payload_sha256(clean)
    return payload


def delete_evidence(db, evidence_id):
    kind = se.backend_kind(db)
    return se.write_sql(db, "DELETE FROM case_evidence WHERE id = %s" % se.placeholder(kind),
                        (int(evidence_id),), kind) is not None



