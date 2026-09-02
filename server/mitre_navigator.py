"""GIAM-SAT v5.0.4 (Phase3 improvement #2): MITRE ATT&CK Navigator export.

Builds an attack-navigator layer JSON from the server's own detection library
(the YAML rules in server/rules/correlation_rules.yaml + the CROSS-* server-side
rules). Every technique a rule tags shows up - green/high when live alerts hit
it, grey/low when it is 'blind' (rule exists but nothing fired in the window),
so SOC can see coverage gaps immediately. The layer is 100% MITRE-Attack
Navigator compatible (import via https://mitre-attack.github.io/attack-navigator).
"""

import re


_T_RE = re.compile(r"T\d{4}(?:\.\d{3})?")
_SEV_SCORE = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
_COLORS = {0: "#bdbdbd", 1: "#ffd54f", 2: "#ffb74d", 3: "#ff7043", 4: "#e53935"}


def _extract_techniques(mitre_value):
    """A rule's mitre field may be a scalar ('T1059.001'), a list, or a chain
    like 'T1110 -> T1021' (server CROSS rules). Return the set of technique ids."""
    out = set()
    if not mitre_value:
        return out
    if isinstance(mitre_value, list):
        for item in mitre_value:
            out |= _extract_techniques(item)
        return out
    out |= set(_T_RE.findall(str(mitre_value)))
    return out


def _load_rule_library():
    """Detection library techniques -> {technique_id: [rule_ids]} from the server
    rules YAML + the CROSS_* rules, together with their tactics."""
    techniques = {}
    try:
        import os
        import yaml
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "rules", "correlation_rules.yaml")
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        for rule in (data.get("rules") or []):
            rid = rule.get("id") or rule.get("rule_id") or "?"
            tactic = rule.get("tactic") or ""
            for tid in _extract_techniques(rule.get("mitre")):
                e = techniques.setdefault(tid, {"rules": set(), "tactics": set(), "severity": rule.get("severity", "")})
                e["rules"].add(str(rid))
                if tactic:
                    e["tactics"].add(str(tactic))
                if not e["severity"]:
                    e["severity"] = rule.get("severity", "")
    except Exception:
        pass
    try:
        from correlation_engine_server import CROSS_MACHINE_RULES
        for rule in CROSS_MACHINE_RULES:
            rid = rule.get("id") or "?"
            for tid in _extract_techniques(rule.get("mitre")):
                e = techniques.setdefault(tid, {"rules": set(), "tactics": set(), "severity": ""})
                e["rules"].add(str(rid))
    except Exception:
        pass
    return techniques


def build_navigator(active_techniques, since_label=""):
    """active_techniques: {technique_id: {count, max_severity}} from live alerts.
    Returns an attack-navigator layer (dict) ready for jsonify."""
    library = _load_rule_library()
    techniques = []
    meta_hits = 0
    seen = set()

    # live-hit techniques first (even ones outside the local library, so nothing
    # that fired is lost)
    for tid, info in (active_techniques or {}).items():
        if tid in seen:
            continue
        seen.add(tid)
        count = info.get("count", 0)
        sev = info.get("max_severity", "LOW")
        score = _SEV_SCORE.get(str(sev).upper(), 1)
        comment = f"{count} alert(s), max {sev}"
        lib = library.get(tid)
        if lib:
            comment += " | rules: " + ", ".join(sorted(lib["rules"])[:5])
        techniques.append({
            "techniqueID": tid,
            "score": score,
            "color": _COLORS.get(score, "#ffb74d"),
            "comment": comment,
            "enabled": True,
        })
        meta_hits += count

    # blind techniques from the detection library (coverage gap)
    for tid, lib in sorted(library.items()):
        if tid in seen:
            continue
        seen.add(tid)
        tactics = ", ".join(sorted(lib["tactics"])) if lib["tactics"] else "?"
        techniques.append({
            "techniqueID": tid,
            "score": 0,
            "color": _COLORS[0],
            "comment": f"0 alerts (blind) | tactic: {tactics} | rules: " + ", ".join(sorted(lib["rules"])[:8]),
            "enabled": True,
        })

    techniques.sort(key=lambda t: (t["score"] == 0, -t["score"]))
    return {
        "name": "GIAM-SAT detection coverage" + (f" ({since_label})" if since_label else ""),
        "versions": {"attack": "v15.0", "navigator": "4.9.2", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": (f"Live-hit techniques ({meta_hits} alerts) plus every technique the "
                        f"GIAM-SAT rule library tags but that has not fired (coverage gaps)."),
        "techniques": techniques,
        "gradient": {"colors": ["#bdbdbd", "#ffd54f", "#ffb74d", "#ff7043", "#e53935"],
                     "min": 0, "max": 4},
        "legendItems": [
            {"label": "0 - blind (no alerts)", "color": _COLORS[0]},
            {"label": "1 - LOW", "color": _COLORS[1]},
            {"label": "2 - MEDIUM", "color": _COLORS[2]},
            {"label": "3 - HIGH", "color": _COLORS[3]},
            {"label": "4 - CRITICAL", "color": _COLORS[4]},
        ],
        "metadata": [{"name": "generated_by", "value": "GIAM-SAT server"}],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "layout": {"layout": "side", "showID": True, "showName": True,
                   "showAggregateScores": True, "countUnscored": False},
    }
