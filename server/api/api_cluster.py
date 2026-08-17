"""
API Cluster - Cluster nodes, Telegram notifications.
"""

import json
from flask import request, jsonify
from .api_common import check_auth


def register(app, core):
    """Register cluster and telegram routes."""

    @app.route("/api/cluster/nodes")
    def api_cluster_nodes():
        _, err, code = check_auth("api")
        if err: return err, code
        return jsonify({
            "node_id": core.cluster.node_id,
            "is_master": core.cluster.is_master,
            "nodes": core.cluster.get_all_active_nodes()
        })

    @app.route("/api/telegram/send", methods=["POST"])
    def api_telegram_send():
        _, err, code = check_auth("api")
        if err: return err, code
        data = request.json
        message = data.get("message", "")
        chat_id = data.get("chat_id", core.telegram_chat_id)
        if not message:
            return jsonify({"success": False, "error": "Tin nhắn trống"}), 400
        success = core._send_telegram_message(message, chat_id)
        return jsonify({"success": success})