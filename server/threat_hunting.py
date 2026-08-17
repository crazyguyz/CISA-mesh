"""
Threat Hunting Module for GIAM-SAT v2.0.0
Proactive threat hunting capabilities:
  - IOC search engine (IP, hash, domain, file pattern)
  - Timeline analysis
  - Threat graph (entity relationships)
  - MITRE ATT&CK technique pivot
  - Statistical anomaly detection
"""

import json, re, time
from datetime import datetime, timedelta
from collections import defaultdict

class ThreatHunter:
    def __init__(self, db_manager):
        self.db = db_manager

    # =========================================================================
    # IOC Search Engine
    # =========================================================================
    def search_ioc(self, ioc_value: str, ioc_type: str = "auto") -> list:
        """Search for IOC across all data sources. Types: ip, hash, domain, file, auto"""
        results = []
        if ioc_type == "auto":
            ioc_type = self._detect_ioc_type(ioc_value)

        # Search in events
        events = self.db.get_events(limit=500)
        for ev in events:
            desc = ev.get("description", "")
            if ioc_value.lower() in desc.lower():
                results.append({"source": "events", "match": desc[:200], "machine": ev.get("machine_id"), "timestamp": ev.get("timestamp")})

        # Search in network traffic
        net = self.db.get_network_traffic(limit=500)
        for pkt in net:
            if ioc_value in str(pkt.get("src_ip","")) or ioc_value in str(pkt.get("dst_ip","")):
                results.append({"source": "network", "match": f"{pkt.get('src_ip')}:{pkt.get('src_port')} -> {pkt.get('dst_ip')}:{pkt.get('dst_port')}", "machine": pkt.get("machine_id"), "timestamp": pkt.get("timestamp")})

        # Search in threats
        threats = self.db.get_threat_alerts(limit=200)
        for t in threats:
            if ioc_value.lower() in str(t.get("description","")).lower():
                results.append({"source": "threats", "match": t.get("rule_name",""), "machine": t.get("machine_id"), "severity": t.get("severity"), "timestamp": t.get("timestamp")})

        return results

    def _detect_ioc_type(self, value: str) -> str:
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value): return "ip"
        if re.match(r'^[a-fA-F0-9]{32,64}$', value): return "hash"
        if '.' in value and not '/' in value: return "domain"
        return "auto"

    # =========================================================================
    # Timeline Analysis
    # =========================================================================
    def build_timeline(self, machine_id: str = None, hours: int = 24) -> list:
        timeline = []
        cutoff = (datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
        
        for ev in self.db.get_events(machine_id=machine_id, limit=500):
            if ev.get("timestamp", "") >= cutoff:
                timeline.append({"type": "event", "subtype": ev.get("event_id",""), "desc": ev.get("description","")[:200], "ts": ev.get("timestamp"), "machine": ev.get("machine_id")})
        
        for t in self.db.get_threat_alerts(machine_id=machine_id, limit=200):
            if t.get("timestamp", "") >= cutoff:
                timeline.append({"type": "threat", "severity": t.get("severity"), "desc": t.get("rule_name",""), "ts": t.get("timestamp"), "machine": t.get("machine_id")})
        
        for v in self.db.get_vuln_alerts(machine_id=machine_id, limit=100):
            if v.get("timestamp", "") >= cutoff:
                timeline.append({"type": "vuln", "severity": v.get("severity"), "desc": v.get("cve_id",""), "ts": v.get("timestamp"), "machine": v.get("machine_id")})
        
        for y in self.db.get_yara_alerts(machine_id=machine_id, limit=100):
            if y.get("timestamp", "") >= cutoff:
                timeline.append({"type": "yara", "severity": y.get("severity"), "desc": y.get("rule_name",""), "ts": y.get("timestamp"), "machine": y.get("machine_id")})
        
        for n in self.db.get_network_traffic(machine_id=machine_id, limit=500):
            if n.get("timestamp", "") >= cutoff:
                timeline.append({"type": "network", "desc": f"{n.get('src_ip')}:{n.get('src_port')} -> {n.get('dst_ip')}:{n.get('dst_port')} {n.get('protocol_app','')}", "ts": n.get("timestamp"), "machine": n.get("machine_id")})
        
        timeline.sort(key=lambda x: x["ts"], reverse=True)
        return timeline

    # =========================================================================
    # Threat Graph
    # =========================================================================
    def build_threat_graph(self, root_machine: str = None) -> dict:
        nodes, edges = [], []
        machines = self.db.get_machines()
        for m in machines:
            mid = m.get("machine_id","")
            nodes.append({"id": mid, "label": f"{m.get('hostname',mid)}\n{m.get('ip','')}", "group": "machine", "online": m.get("online")})
        
        threats = self.db.get_threat_alerts(limit=500)
        ip_mapping = defaultdict(set)
        for t in threats:
            desc = t.get("description","")
            if t.get("source_ip"):
                ip_mapping[t["machine_id"]].add(t["source_ip"])
                src_label = t["source_ip"]; sid = f"ip_{src_label}"
                if not any(n["id"]==sid for n in nodes): nodes.append({"id": sid, "label": src_label, "group": "ip", "threat": True})
                edges.append({"from": t["machine_id"], "to": sid, "label": t.get("rule_name","")[:30], "severity": t.get("severity")})
        
        return {"nodes": nodes, "edges": edges}

    # =========================================================================
    # Statistical Anomaly Detection
    # =========================================================================
    def detect_anomalies(self, machine_id: str = None) -> list:
        anomalies = []
        events = self.db.get_events(machine_id=machine_id, limit=200)
        event_counts = defaultdict(int)
        for ev in events:
            event_counts[ev.get("event_id","")] += 1
        
        # Detect spikes (>3x average)
        if event_counts:
            avg = sum(event_counts.values()) / len(event_counts)
            for eid, cnt in event_counts.items():
                if cnt > avg * 3 and cnt > 10:
                    anomalies.append({"type": "event_spike", "event_id": eid, "count": cnt, "avg": avg, "machine": machine_id})
        
        return anomalies

    # =========================================================================
    # MITRE Pivot
    # =========================================================================
    def mitre_pivot(self, technique_id: str) -> list:
        threats = self.db.get_threat_alerts(limit=500)
        return [t for t in threats if technique_id.upper() in (t.get("mitre","") or "").upper()]

    # =========================================================================
    # Full Hunt Report
    # =========================================================================
    def hunt_report(self, machine_id: str = None, hours: int = 24) -> dict:
        return {
            "summary": {
                "total_events": len(self.db.get_events(machine_id=machine_id, limit=1000)),
                "total_threats": len(self.db.get_threat_alerts(machine_id=machine_id, limit=500)),
                "total_vulns": len(self.db.get_vuln_alerts(machine_id=machine_id, limit=200)),
                "anomalies": len(self.detect_anomalies(machine_id)),
            },
            "timeline": self.build_timeline(machine_id, hours)[:50],
            "anomalies": self.detect_anomalies(machine_id),
            "graph": self.build_threat_graph(machine_id),
        }