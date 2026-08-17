"""
Attack Overview Engine v3 for GIAM-SAT
Combines: Server self-monitor + Agent data (threat_alerts, yara, vulns, fim, inspection, syslog, audit_log)
"""
import json, re
from datetime import datetime
from collections import defaultdict

def build_attack_graph(db):
    machines = db.get_machines()
    machine_map = {m["machine_id"]: m for m in machines}
    chains = []
    timeline = []
    nodes = []
    edges = []
    chain_idx = [0]
    node_ids = set()

    def eid(prefix, key):
        return f"{prefix}:{key}"

    def add_node(node_id, node_type, label, chain_id="", severity="none", threat_count=0, ip=""):
        if node_id not in node_ids:
            node_ids.add(node_id)
            nodes.append({"id": node_id, "type": node_type, "label": label,
                          "chain_id": chain_id, "severity": severity,
                          "threat_count": threat_count, "ip": ip})

    def add_edge(src, tgt, edge_type, severity, label=""):
        edges.append({"source": src, "target": tgt, "type": edge_type,
                      "severity": severity, "label": label})

    # Add SERVER as an entity
    add_node("SERVER", "machine", "GIAM-SAT Server", "", "none", 0)
    
    # Add all machines
    for m in machines:
        add_node(eid("MACHINE", m["machine_id"]), "machine",
                 m.get("hostname", m["machine_id"]),
                 ip=m.get("ip_address", ""))

    def new_chain(root_machine, root_hostname, steps, severity, beacon_target=None):
        chain_idx[0] += 1
        c = {
            "id": f"CHAIN-{chain_idx[0]:03d}",
            "root_machine": root_machine,
            "root_hostname": root_hostname,
            "steps": steps,
            "severity": severity,
            "threat_count": len(steps)
        }
        if beacon_target:
            c["beaconing_target"] = beacon_target
        chains.append(c)
        return c

    # ================================================================
    # 1. THREAT ALERTS (from agent correlation engine + server self-monitor)
    # ================================================================
    alerts = []
    try:
        alerts = db.get_threat_alerts(limit=500)
    except Exception:
        pass

    machine_alerts = defaultdict(list)
    for a in alerts:
        mid = a.get("machine_id", "")
        machine_alerts[mid].append(a)

    for mid, malerts in machine_alerts.items():
        has_lsass = any(str(a.get("rule_id", "")) == "THREAT-009" for a in malerts)
        has_brute = any(str(a.get("rule_id", "")) == "THREAT-001" for a in malerts)
        has_ransom = any(str(a.get("rule_id", "")) == "THREAT-002" for a in malerts)
        has_c2 = any(str(a.get("rule_id", "")) == "THREAT-006" for a in malerts)
        is_server_alert = mid.startswith("SERVER:")

        if has_lsass or has_brute or has_ransom or has_c2 or is_server_alert:
            hostname = machine_map.get(mid, {}).get("hostname", mid) if not is_server_alert else mid.replace("SERVER:", "Attacker:")
            steps = []
            for a in malerts:
                rid = str(a.get("rule_id", ""))
                cmd_map = {
                    "THREAT-001": "Brute Force - Multiple Failed Logon (4625)",
                    "THREAT-002": "Ransomware - Mass File Modification",
                    "THREAT-005": "Defense Evasion - Windows Defender Disabled",
                    "THREAT-006": "C2 Communication - Outbound to Known C2 Port",
                    "THREAT-009": "Credential Dumping - LSASS Memory Access (mimikatz)",
                    "THREAT-017": "PowerShell Download Cradle - Remote Payload",
                }
                steps.append({
                    "machine_id": mid, "hostname": hostname, "type": "threat_alert",
                    "rule_id": rid, "rule_name": a.get("rule_name", ""),
                    "severity": a.get("severity", ""), "time": a.get("timestamp", ""),
                    "command": cmd_map.get(rid, a.get("description", "")[:100]),
                })
                timeline.append({
                    "time": a.get("timestamp", ""), "machine_id": mid, "hostname": hostname,
                    "type": "threat", "rule_id": rid, "severity": a.get("severity", ""),
                    "label": a.get("rule_name", rid)
                })

            sev = "CRITICAL" if (has_lsass or has_ransom) else "HIGH"
            add_node(eid("MACHINE", mid) if not is_server_alert else eid("IP", mid.replace("SERVER:", "")),
                     "compromised" if not is_server_alert else "attacker", hostname, "", sev, len(steps))

            if is_server_alert:
                ip = mid.replace("SERVER:", "")
                add_node(eid("IP", ip), "attacker", ip, "", "HIGH", len(steps), ip=ip)
                add_edge(eid("IP", ip), "SERVER", "server_attack", sev, "Attacking Server")

            new_chain(mid, hostname, steps, sev)

    # ================================================================
    # 2. YARA ALERTS (malware detected by agent)
    # ================================================================
    try:
        yara_alerts = db.get_yara_alerts(limit=200)
    except Exception:
        yara_alerts = []

    yara_by_machine = defaultdict(list)
    for y in yara_alerts:
        yara_by_machine[y.get("machine_id", "")].append(y)

    for mid, ylist in yara_by_machine.items():
        hostname = machine_map.get(mid, {}).get("hostname", mid)
        steps = []
        for y in ylist:
            steps.append({
                "machine_id": mid, "hostname": hostname, "type": "yara_alert",
                "rule_name": y.get("rule_name", ""), "file": y.get("file", ""),
                "severity": "HIGH", "time": y.get("timestamp", ""),
                "command": f"YARA: {y.get('rule_name', '?')} on {y.get('file', '?')}",
                "description": y.get("description", "")
            })
            timeline.append({"time": y.get("timestamp", ""), "machine_id": mid,
                           "hostname": hostname, "type": "yara",
                           "severity": "HIGH", "label": f"YARA: {y.get('rule_name', '?')}"})
        add_node(eid("MACHINE", mid), "compromised", hostname, "", "HIGH", len(steps))
        new_chain(mid, hostname, steps, "HIGH")

    # ================================================================
    # 3. VULN ALERTS (CVE detected by agent)
    # ================================================================
    try:
        vuln_alerts = db.get_vuln_alerts(limit=200)
    except Exception:
        vuln_alerts = []

    vuln_by_machine = defaultdict(list)
    for v in vuln_alerts:
        if (v.get("severity") or "").upper() in ("CRITICAL", "HIGH"):
            vuln_by_machine[v.get("machine_id", "")].append(v)

    for mid, vlist in vuln_by_machine.items():
        hostname = machine_map.get(mid, {}).get("hostname", mid)
        steps = []
        for v in vlist[:5]:  # Max 5 CVEs per machine
            steps.append({
                "machine_id": mid, "hostname": hostname, "type": "vuln_alert",
                "cve": v.get("cve", ""), "software": v.get("software", ""),
                "severity": v.get("severity", ""), "time": v.get("timestamp", ""),
                "command": f"CVE: {v.get('cve', '?')} on {v.get('software', '?')}",
            })
            timeline.append({"time": v.get("timestamp", ""), "machine_id": mid,
                           "hostname": hostname, "type": "vuln",
                           "severity": v.get("severity", ""),
                           "label": f"CVE: {v.get('cve', '?')}"})

    # ================================================================
    # 4. NETWORK INSPECTION (DPI beaconing)
    # ================================================================
    try:
        inspection = db.get_network_inspection(limit=200)
    except Exception:
        inspection = []

    for insp in inspection:
        if insp.get("subtype") == "beaconing":
            mid = insp.get("machine_id", "")
            dst_ip = insp.get("dst_ip", "")
            domain = insp.get("domain", "")
            interval = insp.get("avg_interval_sec", 0)
            hostname = machine_map.get(mid, {}).get("hostname", mid)
            target = domain or dst_ip

            add_node(eid("IP", dst_ip), "c2_server", target, ip=dst_ip)
            add_edge(eid("MACHINE", mid), eid("IP", dst_ip), "c2_beaconing", "CRITICAL",
                     f"Beacon every {interval}s")

            steps = [{"machine_id": mid, "hostname": hostname, "type": "beaconing",
                      "dst_ip": dst_ip, "domain": domain, "avg_interval_sec": interval,
                      "severity": "CRITICAL", "time": insp.get("timestamp", ""),
                      "command": f"Beaconing to {target} every {interval}s"}]
            timeline.append({"time": insp.get("timestamp", ""), "machine_id": mid,
                           "hostname": hostname, "type": "beaconing", "dst": target,
                           "severity": "CRITICAL", "label": f"C2 Beacon to {target}"})
            add_node(eid("MACHINE", mid), "compromised", hostname, "", "CRITICAL", 1)
            new_chain(mid, hostname, steps, "CRITICAL", beacon_target=target)

    # ================================================================
    # 5. FIM EVENTS (file changes, potential ransomware/backdoor)
    # ================================================================
    try:
        fim_events = db.get_fim_events(limit=100)
    except Exception:
        fim_events = []

    fim_by_machine = defaultdict(list)
    for f in fim_events:
        path = f.get("path", "").lower()
        # Flag suspicious file changes
        suspicious_paths = ["system32", "syswow64", "windows\\temp", "startup",
                           "powershell", "wscript", "cscript", ".exe", ".dll", ".ps1"]
        for sp in suspicious_paths:
            if sp in path:
                fim_by_machine[f.get("machine_id", "")].append(f)
                break

    for mid, flist in fim_by_machine.items():
        if len(flist) >= 3:  # Multiple suspicious file changes
            hostname = machine_map.get(mid, {}).get("hostname", mid)
            steps = []
            for f in flist[:10]:
                steps.append({
                    "machine_id": mid, "hostname": hostname, "type": "fim_event",
                    "action": f.get("action", ""), "path": f.get("path", ""),
                    "severity": "MEDIUM", "time": f.get("time", ""),
                    "command": f"FIM: {f.get('action', '?')} {f.get('path', '?')}",
                })
                timeline.append({"time": f.get("time", ""), "machine_id": mid,
                               "hostname": hostname, "type": "fim",
                               "severity": "MEDIUM", "label": f"FIM: {f.get('action', '?')}"})

    # ================================================================
    # 6. SYSLOG (from router/firewall - port scan, blocked connections)
    # ================================================================
    try:
        syslog_entries = db.get_syslog(limit=200)
    except Exception:
        syslog_entries = []

    # Detect port scans from firewall logs
    scan_candidates = defaultdict(lambda: defaultdict(int))
    for s in syslog_entries:
        msg = (s.get("message", "") or "").lower()
        if any(kw in msg for kw in ["scan", "port scan", "denied", "dropped", "blocked"]):
            src_ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', s.get("message", "") or "")
            if src_ip_match:
                src_ip = src_ip_match.group(1)
                scan_candidates[src_ip]["count"] += 1

    for src_ip, data in scan_candidates.items():
        if data["count"] >= 5:
            add_node(eid("IP", src_ip), "attacker", src_ip, ip=src_ip)
            add_edge(eid("IP", src_ip), "SERVER", "scan", "HIGH",
                     f"Port scan detected ({data['count']}x denied)")
            timeline.append({"time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                           "machine_id": f"IP:{src_ip}", "hostname": src_ip,
                           "type": "scan", "severity": "HIGH",
                           "label": f"Port scan from {src_ip}"})

    # ================================================================
    # 7. SYSMON EVENTS (credential dumping, process injection, persistence)
    # ================================================================
    try:
        sysmon_events = db.get_sysmon_events(limit=500)
    except Exception:
        sysmon_events = []

    for e in sysmon_events:
        sysmon_eid = e.get("sysmon_event_id", 0)
        cred_dump = e.get("credential_dumping") == 1 or e.get("credential_dumping") == "1"
        injection = sysmon_eid == 8
        persistence = e.get("persistence_detected") == 1 or e.get("persistence_detected") == "1"
        lsass_access = sysmon_eid == 10 and e.get("target_process", "").lower().find("lsass") >= 0

        if cred_dump or injection or persistence or lsass_access:
            mid = e.get("machine_id", "")
            hostname = machine_map.get(mid, {}).get("hostname", mid)
            sev = "CRITICAL" if (cred_dump or lsass_access) else "HIGH"
            desc = e.get("description", e.get("suspicion_reason", ""))
            proc = e.get("process_name", "?")
            target = e.get("target_process", "")
            steps = [{
                "machine_id": mid, "hostname": hostname, "type": "sysmon",
                "event_id": sysmon_eid, "severity": sev, "time": e.get("timestamp", ""),
                "command": f"Sysmon EID {sysmon_eid}: {proc}" + (f" → {target}" if target else "") + (f" - {desc[:60]}" if desc else ""),
                "description": desc
            }]
            timeline.append({"time": e.get("timestamp", ""), "machine_id": mid,
                           "hostname": hostname, "type": "sysmon", "event_id": sysmon_eid,
                           "severity": sev, "label": f"Sysmon EID {sysmon_eid}: {desc[:40] if desc else proc}"})
            add_node(eid("MACHINE", mid), "compromised", hostname, "", sev, len(steps))
            new_chain(mid, hostname, steps, sev)

    # ================================================================
    # 8. MEMORY SCAN (process hollowing, name spoofing)
    # ================================================================
    try:
        memory_events = db.get_sysmon_events(event_type="memory_scan_event", limit=200)
    except Exception:
        memory_events = []

    for e in memory_events:
        mid = e.get("machine_id", "")
        hostname = machine_map.get(mid, {}).get("hostname", mid)
        sev = e.get("severity", "HIGH")
        desc = e.get("description", e.get("suspicion_reason", "Memory anomaly detected"))
        proc = e.get("process_name", "?")
        steps = [{
            "machine_id": mid, "hostname": hostname, "type": "memory_scan",
            "severity": sev, "time": e.get("timestamp", ""),
            "command": f"Memory: {proc} - {desc[:80]}",
            "description": desc
        }]
        timeline.append({"time": e.get("timestamp", ""), "machine_id": mid,
                       "hostname": hostname, "type": "memory", "severity": sev,
                       "label": f"Memory: {desc[:50]}"})
        add_node(eid("MACHINE", mid), "compromised", hostname, "", sev, len(steps))
        new_chain(mid, hostname, steps, sev)

    # ================================================================
    # 9. AUDIT LOG (brute force on server itself)
    # ================================================================
    try:
        audit_entries = db.get_audit_log(limit=200)
    except Exception:
        audit_entries = []

    failed_logins = defaultdict(int)
    for entry in audit_entries:
        if entry.get("action") == "login" and "failed" in (entry.get("details") or "").lower():
            ip = entry.get("ip_address", "")
            if ip:
                failed_logins[ip] += 1

    for ip, count in failed_logins.items():
        if count >= 3:  # Brute force attempt detected from audit logs
            add_node(eid("IP", ip), "attacker", ip, ip=ip)
            add_edge(eid("IP", ip), "SERVER", "brute_force", "HIGH",
                     f"Brute force detected ({count}x failed login)")

    # ================================================================
    # 8. COMPUTE STATS
    # ================================================================
    critical_chains = sum(1 for c in chains if c["severity"] == "CRITICAL")
    high_chains = sum(1 for c in chains if c["severity"] == "HIGH")
    total_steps = sum(len(c["steps"]) for c in chains)

    return {
        "nodes": nodes,
        "edges": edges,
        "chains": chains,
        "timeline": sorted(timeline, key=lambda x: x.get("time", ""), reverse=True)[:50],
        "stats": {
            "total_chains": len(chains),
            "critical_chains": critical_chains,
            "high_chains": high_chains,
            "total_steps": total_steps,
            "total_machines": len(machines),
            "compromised_count": sum(1 for n in nodes if n["type"] == "compromised"),
            "c2_count": sum(1 for n in nodes if n["type"] == "c2_server"),
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
    }


def build_graph_v2(db, since_hours=None, until_hours=None):
    """
    v3.2: D3.js-ready force-directed graph data with MITRE tactic colors.
    
    Returns format compatible with D3 force simulation:
      { "nodes": [{id, group, label, severity, tactic, ...}],
        "links": [{source, target, type, value}],
        "timeline": [...] }
    
    Groups (D3 color categories):
      1 = machine (blue)
      2 = compromised (red)
      3 = attacker (dark red)
      4 = c2_server (orange)
      5 = process (green)
      6 = network_ip (purple)
    """
    # MITRE tactic → D3 group mapping
    TACTIC_GROUP = {
        "Initial Access": 3,
        "Execution": 5,
        "Persistence": 2,
        "Privilege Escalation": 4,
        "Defense Evasion": 2,
        "Credential Access": 2,
        "Discovery": 5,
        "Lateral Movement": 2,
        "Collection": 5,
        "Command and Control": 4,
        "Exfiltration": 4,
        "Impact": 2,
    }

    machines = db.get_machines() or []
    machine_map = {m["machine_id"]: m for m in machines}

    nodes = []
    links = []
    timeline = []
    node_ids = set()

    def add_node(nid, group, label, severity="none", tactic=None, ip=""):
        if nid not in node_ids:
            node_ids.add(nid)
            g = group
            if tactic and tactic in TACTIC_GROUP:
                g = TACTIC_GROUP[tactic]
            nodes.append({
                "id": nid, "group": g, "label": label,
                "severity": severity, "tactic": tactic or "", "ip": ip,
            })

    def add_link(src, tgt, link_type, value=1):
        links.append({"source": src, "target": tgt, "type": link_type, "value": value})

    # Add all machines as group 1 (normal)
    for m in machines:
        add_node(m["machine_id"], 1, m.get("hostname", m["machine_id"]),
                 ip=m.get("ip_address", ""))

    # ---- Threat Alerts → compromised nodes + links ----
    alerts = []
    try: alerts = db.get_threat_alerts(limit=500)
    except: pass

    for a in alerts:
        mid = a.get("machine_id", "")
        if not mid: continue
        rid = a.get("rule_id", "")
        sev = a.get("severity", "MEDIUM")
        tactic = a.get("tactic", a.get("mitre_tactic", ""))
        add_node(mid, 2, machine_map.get(mid, {}).get("hostname", mid), sev, tactic)
        timeline.append({
            "time": a.get("timestamp", ""), "machine_id": mid,
            "type": "threat", "label": a.get("rule_name", rid), "severity": sev,
        })

    # ---- Network Traffic → process-to-IP links ----
    try:
        traffic = db.get_network_traffic(limit=200)
        for t in traffic:
            mid = t.get("machine_id", "")
            dst_ip = t.get("dst_ip", "")
            proc = t.get("process_name", "")
            if mid and dst_ip:
                add_node(dst_ip, 6, dst_ip, ip=dst_ip)
                if proc:
                    pid_n = f"{mid}:{proc}:{t.get('pid','')}"
                    add_node(pid_n, 5, proc)
                    add_link(pid_n, dst_ip, "network_conn")
                    add_link(mid, pid_n, "runs")
                else:
                    add_link(mid, dst_ip, "network_conn")
                timeline.append({
                    "time": t.get("timestamp", ""), "machine_id": mid,
                    "type": "network", "label": f"→ {dst_ip}", "severity": "INFO",
                })
    except: pass

    # ---- Sysmon Events → process parent-child edges ----
    try:
        sysmon = db.get_sysmon_events(limit=300)
        for s in sysmon:
            mid = s.get("machine_id", "")
            proc = s.get("process_name", "")
            parent = s.get("parent_process", "")
            if mid and proc and parent:
                pid_n = f"{mid}:{proc}:{s.get('pid','')}"
                ppid_n = f"{mid}:{parent}:{s.get('parent_pid','')}"
                add_node(pid_n, 5, proc)
                add_node(ppid_n, 5, parent)
                add_link(ppid_n, pid_n, "spawned")
    except: pass

    return {
        "nodes": nodes,
        "links": links,
        "timeline": sorted(timeline, key=lambda x: x.get("time", ""), reverse=True)[:100],
        "stats": {
            "total_nodes": len(nodes),
            "total_links": len(links),
            "compromised": sum(1 for n in nodes if n["group"] == 2),
            "generated_at": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
        },
    }
