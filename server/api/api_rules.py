"""
API Rules - Correlation rule CRUD, deploy, reload, test, download.
"""

import json
import os
import sys
import time
from flask import request, jsonify

from .api_common import check_auth


_RULES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "rules", "correlation_rules.yaml")


def _load_rules_yaml():
    try:
        import yaml
    except ImportError:
        return None
    if not os.path.exists(_RULES_PATH):
        return None
    with open(_RULES_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _save_rules_yaml(data):
    with open(_RULES_PATH, "w", encoding="utf-8") as f:
        import yaml
        yaml.dump(data, f, allow_unicode=True, default_flow_style=False, sort_keys=False)


def register(app, core):
    """Register rule management routes."""

    @app.route("/api/rules", methods=["GET"])
    def api_get_rules():
        _, err, code = check_auth("api")
        if err: return err, code
        try:
            data = _load_rules_yaml()
            if not data:
                return jsonify({"success": False, "error": "Rules file not found"}), 500
            rules = data.get("rules", [])
            from correlation_engine_server import CROSS_MACHINE_RULES
            return jsonify({
                "rules": rules, "count": len(rules), "cross_machine_rules": len(CROSS_MACHINE_RULES),
                # v5.0.3 (P2#11): detection architecture is documented - the YAML rule
                # set runs AGENT-side (each machine evaluates its own events); the
                # server-side engine runs ONLY the CROSS-* machine rules below.
                "detection_point": "agent",
                "note": f"{len(rules)} YAML rules chạy trên từng AGENT (mỗi máy tự đánh giá sự kiện local); server chỉ chạy {len(CROSS_MACHINE_RULES)} rule CROSS-* (tương quan liên máy). Deploy = 'Cập nhật Rules' -> copy YAML + reload agents."
            })
        except Exception as e:
            return jsonify({"success": False, "error": str(e)[:200]}), 500

    @app.route("/api/rules", methods=["POST"])
    def api_create_rule():
        u, err, code = check_auth("settings")
        if err: return err, code
        data = request.json or {}
        rule = data.get("rule")
        if not rule or not rule.get("id"):
            return jsonify({"success": False, "error": "Rule with 'id' required"}), 400
        try:
            yaml_data = _load_rules_yaml()
            if not yaml_data:
                return jsonify({"success": False, "error": "Rules file not found"}), 500
            rules = yaml_data.get("rules", [])
            if any(r.get("id") == rule["id"] for r in rules):
                return jsonify({"success": False, "error": f"Rule {rule['id']} already exists. Use PUT to update."}), 409
            rules.append(rule)
            yaml_data["rules"] = rules
            _save_rules_yaml(yaml_data)
            core.db.insert_audit_log(u, "rule_create", f"Created rule {rule.get('id')}", request.remote_addr)
            return jsonify({"success": True, "rule_count": len(rules)})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)[:200]}), 500

    @app.route("/api/rules/<rule_id>", methods=["PUT"])
    def api_update_rule(rule_id):
        u, err, code = check_auth("settings")
        if err: return err, code
        data = request.json or {}
        rule = data.get("rule")
        if not rule:
            return jsonify({"success": False, "error": "Rule data required"}), 400
        try:
            yaml_data = _load_rules_yaml()
            if not yaml_data:
                return jsonify({"success": False, "error": "Rules file not found"}), 500
            rules = yaml_data.get("rules", [])
            found = False
            for i, r in enumerate(rules):
                if r.get("id") == rule_id:
                    rules[i] = rule
                    found = True
                    break
            if not found:
                return jsonify({"success": False, "error": f"Rule {rule_id} not found"}), 404
            yaml_data["rules"] = rules
            _save_rules_yaml(yaml_data)
            core.db.insert_audit_log(u, "rule_update", f"Updated rule {rule_id}", request.remote_addr)
            return jsonify({"success": True})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)[:200]}), 500

    @app.route("/api/rules/<rule_id>", methods=["DELETE"])
    def api_delete_rule(rule_id):
        u, err, code = check_auth("settings")
        if err: return err, code
        try:
            yaml_data = _load_rules_yaml()
            if not yaml_data:
                return jsonify({"success": False, "error": "Rules file not found"}), 500
            rules = yaml_data.get("rules", [])
            new_rules = [r for r in rules if r.get("id") != rule_id]
            if len(new_rules) == len(rules):
                return jsonify({"success": False, "error": f"Rule {rule_id} not found"}), 404
            yaml_data["rules"] = new_rules
            _save_rules_yaml(yaml_data)
            core.db.insert_audit_log(u, "rule_delete", f"Deleted rule {rule_id}", request.remote_addr)
            return jsonify({"success": True, "rule_count": len(new_rules)})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)[:200]}), 500

    @app.route("/api/rules/download", methods=["GET"])
    def api_rules_download():
        _, err, code = check_auth("api")
        if err: return err, code
        if not os.path.exists(_RULES_PATH):
            return jsonify({"error": "Rules file not found"}), 500
        with open(_RULES_PATH, "r", encoding="utf-8") as f:
            content = f.read()
        return content, 200, {"Content-Type": "application/x-yaml", "Content-Disposition": "attachment; filename=correlation_rules.yaml"}

    @app.route("/api/rules/deploy", methods=["POST"])
    def api_deploy_rules():
        u, err, code = check_auth("settings")
        if err: return err, code
        agent_rules_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "agent", "rules", "correlation_rules.yaml")
        import shutil
        shutil.copy2(_RULES_PATH, agent_rules_path)
        machines = core.db.get_machines()
        online_count = 0
        for m in machines:
            if m.get("is_online") == 1:
                core.tcp_server.send_command(m["machine_id"], {
                    "action": "reload_rules",
                    "exec_id": f"deploy_rules_{int(time.time())}"
                })
                online_count += 1
        core.db.insert_audit_log(u, "rules_deploy", f"Deployed rules to {online_count} agents", request.remote_addr)
        return jsonify({"success": True, "agents_notified": online_count})

    @app.route("/api/rules/reload", methods=["POST"])
    def api_reload_rules():
        u, err, code = check_auth("settings")
        if err: return err, code
        try:
            import importlib
            agent_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "agent")
            sys.path.insert(0, agent_path)
            import correlation_engine as ce
            importlib.reload(ce)
            rules = ce.load_correlation_rules()
            from correlation_engine_server import CROSS_MACHINE_RULES
            core.db.insert_audit_log(u, "rules_reload", f"Reloaded {len(rules)} agent rules + {len(CROSS_MACHINE_RULES)} cross-machine rules", request.remote_addr)
            return jsonify({
                "success": True,
                "agent_rules": len(rules),
                "cross_machine_rules": len(CROSS_MACHINE_RULES)
            })
        except Exception as e:
            return jsonify({"success": False, "error": str(e)[:200]}), 500

    @app.route("/api/rules/test", methods=["POST"])
    def api_test_rule():
        _, err, code = check_auth("api")
        if err: return err, code
        data = request.json or {}
        rule = data.get("rule")
        test_event = data.get("event")
        if not rule or not test_event:
            return jsonify({"success": False, "error": "rule and event required"}), 400
        try:
            agent_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "agent")
            sys.path.insert(0, agent_path)
            from correlation_engine import CorrelationEngine
            engine = CorrelationEngine()
            import correlation_engine as ce
            original_rules = ce.CORRELATION_RULES
            ce.CORRELATION_RULES = [rule]
            try:
                triggered = engine.process_event(test_event)
            finally:
                ce.CORRELATION_RULES = original_rules
            return jsonify({
                "success": True,
                "triggered": len(triggered) > 0,
                "alerts": triggered
            })
        except Exception as e:
            return jsonify({"success": False, "error": str(e)[:300]}), 500