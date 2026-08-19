"""
API Email - Email templates, send, config, test.
"""

import os
from flask import request, jsonify

from .api_common import check_auth


def register(app, core):
    """Register email-related routes."""

    # Import locally to avoid circular dependency at module level
    from email_alerts import send_email_alert, get_smtp_config, get_templates_list, send_email_smtp

    @app.route("/api/email/templates", methods=["GET"])
    def api_email_templates():
        _, err, code = check_auth("api")
        if err: return err, code
        return jsonify({"templates": get_templates_list()})

    @app.route("/api/email/send", methods=["POST"])
    def api_email_send():
        username, err, code = check_auth("settings")
        if err: return err, code
        data = request.json
        machine_id = data.get("machine_id", "")
        if not machine_id:
            return jsonify({"success": False, "error": "Thiếu machine_id"}), 400
        result = send_email_alert(
            core.db, machine_id,
            template_id=data.get("template_id", ""),
            subject=data.get("subject", ""),
            body=data.get("body", ""),
            to_email=data.get("to_email", "")
        )
        if result.get("success"):
            core.db.insert_audit_log(username, "send_email_alert",
                f"To: {result.get('to')}, Machine: {machine_id}, Template: {data.get('template_id', 'custom')}",
                request.remote_addr)
        return jsonify(result)

    @app.route("/api/email/config", methods=["GET"])
    def api_email_config():
        _, err, code = check_auth("settings")
        if err: return err, code
        return jsonify(get_smtp_config())

    @app.route("/api/email/sent", methods=["GET"])
    def api_email_sent_list():
        """v4.10: List emails GIAM-SAT has sent (local sent-mail log)."""
        _, err, code = check_auth("settings")
        if err: return err, code
        from sent_mail_log import list_emails
        try:
            limit = min(max(int(request.args.get("limit", 200)), 1), 1000)
        except Exception:
            limit = 200
        return jsonify({"emails": list_emails(limit)})

    @app.route("/api/email/sent/<email_id>", methods=["DELETE"])
    def api_email_sent_delete(email_id):
        """v4.10: Delete one sent-email record (admin cleanup)."""
        username, err, code = check_auth("settings")
        if err: return err, code
        from sent_mail_log import delete_email
        if delete_email(email_id):
            core.db.insert_audit_log(username, "delete_sent_email",
                f"Xóa bản ghi mail đã gửi: {email_id}", request.remote_addr)
            return jsonify({"success": True})
        return jsonify({"success": False, "error": "Không tìm thấy bản ghi"}), 404

    @app.route("/api/email/sent/clear", methods=["POST"])
    def api_email_sent_clear():
        """v4.10: Delete all sent-email records (admin cleanup)."""
        username, err, code = check_auth("settings")
        if err: return err, code
        from sent_mail_log import clear_emails
        n = clear_emails()
        core.db.insert_audit_log(username, "clear_sent_emails",
            f"Xóa toàn bộ log mail đã gửi ({n} bản ghi)", request.remote_addr)
        return jsonify({"success": True, "deleted": n})

    @app.route("/api/email/test", methods=["POST"])
    def api_email_test():
        _, err, code = check_auth("settings")
        if err: return err, code
        data = request.json or {}
        test_to = data.get("to", os.environ.get("GIAMSAT_SMTP_USER", "it@example.com"))
        try:
            send_email_smtp(test_to, "GIAM-SAT: Email Test",
                "Đây là email test từ hệ thống GIAM-SAT.\n\n"
                "Nếu bạn nhận được email này, cấu hình SMTP đã hoạt động chính xác.\n\n"
                "Trân trọng,\nPhòng IT")
            return jsonify({"success": True, "message": f"Email test đã được gửi đến {test_to}"})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500