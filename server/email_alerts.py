"""
GIAM-SAT Email Alerts v2.4.0
Proactive alert dispatch from dashboard via Outlook SMTP.
Contains email templates and send logic.
"""
import os
import json
import threading
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

# ============================================================
# EMAIL TEMPLATES
# ============================================================
EMAIL_TEMPLATES = {
    "uptime_24h": {
        "name": "⚠️ Cảnh báo thiết bị hoạt động liên tục quá 24h",
        "subject": "[GIAM-SAT] Cảnh báo thiết bị hoạt động liên tục quá 24h",
        "body": (
            "Bộ phận IT gửi cảnh báo\n\n"
            "Thiết bị [{hostname}] thuộc quyền sử dụng của nhân sự [{employee_id} - {user_name}]\n"
            "Đã hoạt động liên tục quá 24h!\n\n"
            "Để đảm bảo tuổi thọ thiết bị, nhân sự vui lòng kết thúc công việc đang dang dở "
            "và tắt nguồn thiết bị trong vài giờ trước khi khởi động lại để làm việc tiếp.\n\n"
            "Trân trọng,\nPhòng IT"
        )
    },
    "brute_force": {
        "name": "🚨 Cảnh báo tấn công Brute Force",
        "subject": "[GIAM-SAT] CẢNH BÁO KHẨN: Phát hiện tấn công Brute Force",
        "body": (
            "Bộ phận IT gửi cảnh báo KHẨN\n\n"
            "Hệ thống GIAM-SAT phát hiện dấu hiệu tấn công Brute Force trên thiết bị [{hostname}]\n"
            "thuộc quyền sử dụng của nhân sự [{employee_id} - {user_name}].\n\n"
            "⚠️ HÀNH ĐỘNG CẦN THỰC HIỆN NGAY:\n"
            "1. Ngắt kết nối mạng của thiết bị (rút dây mạng / tắt Wi-Fi)\n"
            "2. KHÔNG nhập bất kỳ mật khẩu nào cho đến khi có thông báo từ IT\n"
            "3. Liên hệ ngay bộ phận IT qua số nội bộ hoặc email it@example.com\n\n"
            "Bộ phận IT sẽ tiến hành kiểm tra và xử lý trong thời gian sớm nhất.\n\n"
            "Trân trọng,\nPhòng IT"
        )
    },
    "malware_detected": {
        "name": "🦠 Cảnh báo phát hiện Malware/Virus",
        "subject": "[GIAM-SAT] CẢNH BÁO KHẨN: Phát hiện phần mềm độc hại",
        "body": (
            "Bộ phận IT gửi cảnh báo KHẨN\n\n"
            "Hệ thống GIAM-SAT đã phát hiện phần mềm độc hại (malware/virus) trên thiết bị [{hostname}]\n"
            "thuộc quyền sử dụng của nhân sự [{employee_id} - {user_name}].\n\n"
            "⚠️ HÀNH ĐỘNG CẦN THỰC HIỆN NGAY:\n"
            "1. Ngắt kết nối mạng của thiết bị ngay lập tức\n"
            "2. KHÔNG mở bất kỳ file hoặc ứng dụng nào\n"
            "3. KHÔNG cắm USB hoặc thiết bị ngoại vi vào máy\n"
            "4. Liên hệ ngay bộ phận IT qua số nội bộ hoặc email it@example.com\n\n"
            "Bộ phận IT sẽ tiến hành cách ly và làm sạch thiết bị.\n\n"
            "Trân trọng,\nPhòng IT"
        )
    },
    "phishing_alert": {
        "name": "🎣 Cảnh báo tấn công Phishing / Lừa đảo",
        "subject": "[GIAM-SAT] Cảnh báo: Phát hiện dấu hiệu tấn công Phishing",
        "body": (
            "Bộ phận IT gửi cảnh báo\n\n"
            "Hệ thống GIAM-SAT phát hiện dấu hiệu tấn công Phishing (lừa đảo qua email/website)\n"
            "liên quan đến thiết bị [{hostname}] của nhân sự [{employee_id} - {user_name}].\n\n"
            "⚠️ LƯU Ý QUAN TRỌNG:\n"
            "1. KHÔNG click vào link hoặc mở file đính kèm trong email nghi ngờ\n"
            "2. KHÔNG nhập thông tin đăng nhập vào các trang web lạ\n"
            "3. Xóa ngay email nghi ngờ và báo cáo cho bộ phận IT\n"
            "4. Nếu đã lỡ nhập mật khẩu, đổi mật khẩu NGAY trên tất cả hệ thống\n\n"
            "Vui lòng liên hệ it@example.com nếu cần hỗ trợ.\n\n"
            "Trân trọng,\nPhòng IT"
        )
    },
    "unauthorized_access": {
        "name": "🔓 Cảnh báo truy cập trái phép",
        "subject": "[GIAM-SAT] CẢNH BÁO: Phát hiện truy cập trái phép",
        "body": (
            "Bộ phận IT gửi cảnh báo KHẨN\n\n"
            "Hệ thống GIAM-SAT phát hiện truy cập trái phép vào thiết bị [{hostname}]\n"
            "thuộc quyền sử dụng của nhân sự [{employee_id} - {user_name}].\n\n"
            "⚠️ HÀNH ĐỘNG CẦN THỰC HIỆN:\n"
            "1. Khóa màn hình thiết bị ngay lập tức (Windows Key + L)\n"
            "2. Kiểm tra xem có ai đang sử dụng máy của bạn không\n"
            "3. Đổi mật khẩu đăng nhập ngay khi có thể\n"
            "4. Báo cáo sự việc cho bộ phận IT\n\n"
            "Trân trọng,\nPhòng IT"
        )
    },
    "vulnerability_found": {
        "name": "🛡️ Cảnh báo lỗ hổng bảo mật nghiêm trọng",
        "subject": "[GIAM-SAT] Cảnh báo: Phát hiện lỗ hổng bảo mật nghiêm trọng",
        "body": (
            "Bộ phận IT gửi cảnh báo\n\n"
            "Hệ thống GIAM-SAT đã phát hiện lỗ hổng bảo mật nghiêm trọng trên thiết bị [{hostname}]\n"
            "thuộc quyền sử dụng của nhân sự [{employee_id} - {user_name}].\n\n"
            "Lỗ hổng này có thể bị kẻ tấn công khai thác để xâm nhập hệ thống.\n\n"
            "Bộ phận IT sẽ liên hệ để lên lịch cập nhật bản vá trong thời gian sớm nhất.\n"
            "Vui lòng không tự ý cài đặt phần mềm lạ hoặc tắt các biện pháp bảo mật.\n\n"
            "Trân trọng,\nPhòng IT"
        )
    },
    "suspicious_connection": {
        "name": "🌐 Cảnh báo kết nối đến địa chỉ độc hại",
        "subject": "[GIAM-SAT] CẢNH BÁO: Phát hiện kết nối đến địa chỉ độc hại",
        "body": (
            "Bộ phận IT gửi cảnh báo KHẨN\n\n"
            "Hệ thống GIAM-SAT phát hiện thiết bị [{hostname}] của nhân sự [{employee_id} - {user_name}]\n"
            "đã kết nối đến một địa chỉ IP được xác định là độc hại.\n\n"
            "Địa chỉ này có thể liên quan đến máy chủ điều khiển mã độc (C2), lừa đảo, "
            "hoặc phát tán phần mềm độc hại.\n\n"
            "⚠️ HÀNH ĐỘNG CẦN THỰC HIỆN:\n"
            "1. KHÔNG tiếp tục sử dụng ứng dụng đang kết nối đến địa chỉ này\n"
            "2. Ngắt kết nối mạng nếu có thể\n"
            "3. Liên hệ ngay bộ phận IT để được hướng dẫn\n\n"
            "Trân trọng,\nPhòng IT"
        )
    },
    "fim_alert": {
        "name": "📁 Cảnh báo thay đổi file hệ thống trái phép",
        "subject": "[GIAM-SAT] Cảnh báo: Phát hiện thay đổi file hệ thống",
        "body": (
            "Bộ phận IT gửi cảnh báo\n\n"
            "Hệ thống GIAM-SAT phát hiện thay đổi file hệ thống quan trọng trên thiết bị [{hostname}]\n"
            "thuộc quyền sử dụng của nhân sự [{employee_id} - {user_name}].\n\n"
            "Thay đổi file hệ thống có thể là dấu hiệu của phần mềm độc hại hoặc tấn công.\n\n"
            "Bộ phận IT đang tiến hành xác minh. Vui lòng không thay đổi cài đặt hệ thống.\n\n"
            "Trân trọng,\nPhòng IT"
        )
    },
    "policy_violation": {
        "name": "📋 Cảnh báo vi phạm chính sách bảo mật",
        "subject": "[GIAM-SAT] Cảnh báo: Vi phạm chính sách bảo mật",
        "body": (
            "Bộ phận IT gửi cảnh báo\n\n"
            "Hệ thống GIAM-SAT phát hiện hành vi vi phạm chính sách bảo mật trên thiết bị [{hostname}]\n"
            "thuộc quyền sử dụng của nhân sự [{employee_id} - {user_name}].\n\n"
            "Vui lòng tuân thủ chính sách bảo mật của tổ chức để đảm bảo an toàn "
            "cho toàn bộ hệ thống mạng.\n\n"
            "Nếu cần giải thích thêm, vui lòng liên hệ bộ phận IT.\n\n"
            "Trân trọng,\nPhòng IT"
        )
    },
    "general_warning": {
        "name": "⚠️ Cảnh báo bảo mật chung",
        "subject": "[GIAM-SAT] Cảnh báo bảo mật",
        "body": (
            "Bộ phận IT gửi cảnh báo\n\n"
            "Kính gửi nhân sự [{employee_id} - {user_name}],\n\n"
            "Hệ thống GIAM-SAT đã ghi nhận cảnh báo bảo mật liên quan đến thiết bị [{hostname}].\n\n"
            "Vui lòng liên hệ bộ phận IT qua email it@example.com để biết thêm chi tiết "
            "và được hướng dẫn xử lý.\n\n"
            "Trân trọng,\nPhòng IT"
        )
    },
}

# ============================================================
# SMTP SEND
# ============================================================

def send_email_smtp(to_email, subject, body, machine_id="", template_id="", source=""):
    """Send email via SMTP. Supports SSL (465) and STARTTLS (587).
    v4.10: every attempt is recorded in the local sent-mail log
    (server/data/sent_emails.json) with status 'sent' or 'failed'."""
    smtp_server = os.environ.get("GIAMSAT_SMTP_HOST", "smtp-mail.outlook.com")
    smtp_port = int(os.environ.get("GIAMSAT_SMTP_PORT", "587"))
    smtp_user = os.environ.get("GIAMSAT_SMTP_USER", "it@example.com")
    smtp_pass = os.environ.get("GIAMSAT_SMTP_PASS", "")
    if not smtp_pass:
        print("[-] Email alert: SMTP password not configured (GIAMSAT_SMTP_PASS env var)")
        return False
    from_email = smtp_user
    try:
        msg = MIMEMultipart()
        msg["From"] = from_email
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain", "utf-8"))
        # Port 465 uses implicit SSL; other ports use STARTTLS
        if smtp_port == 465:
            server = smtplib.SMTP_SSL(smtp_server, smtp_port, timeout=15)
        else:
            server = smtplib.SMTP(smtp_server, smtp_port, timeout=15)
            server.starttls()
        server.login(smtp_user, smtp_pass)
        server.sendmail(from_email, [to_email], msg.as_string())
        server.quit()
        # v4.10: record the send in the local sent-mail log (must never fail the send)
        try:
            from sent_mail_log import log_email
            log_email(to_email, subject, body, machine_id=machine_id,
                      template_id=template_id, source=source, status="sent")
        except Exception:
            pass
        try:
            print(f"[📧] Email sent to {to_email}: {subject}")
        except Exception:
            pass
        return True
    except Exception as e:
        try:
            print(f"[-] Email send failed: {e}")
        except Exception:
            pass
        try:
            from sent_mail_log import log_email
            log_email(to_email, subject, body, machine_id=machine_id,
                      template_id=template_id, source=source, status="failed", error=str(e))
        except Exception:
            pass
        return False


def send_email_alert(db_manager, machine_id, template_id=None, subject="", body="", to_email=""):
    """
    Send email alert to a machine user.
    
    Args:
        db_manager: DatabaseManager instance
        machine_id: Machine ID
        template_id: Template ID from EMAIL_TEMPLATES (or None for custom)
        subject: Custom subject (overrides template)
        body: Custom body (overrides template)
        to_email: Override recipient email
    
    Returns:
        dict: {"success": bool, "error": str, "to": str}
    """
    # Get machine user info
    user_info = db_manager.get_machine_user(machine_id) or {}
    recipient = to_email or user_info.get("email", "")
    user_name = user_info.get("user_name", "")
    employee_id = user_info.get("employee_id", "")
    hostname = "Unknown"
    
    # Get hostname from machines table
    machines = db_manager.get_machines()
    for m in machines:
        if m.get("machine_id") == machine_id:
            hostname = m.get("hostname", "Unknown")
            break

    if not recipient:
        return {"success": False, "error": "Không tìm thấy email của người dùng máy trạm này."}

    # If template selected, use template subject/body with variable substitution
    if template_id and template_id in EMAIL_TEMPLATES:
        tpl = EMAIL_TEMPLATES[template_id]
        subject = subject or tpl["subject"]
        body = body or tpl["body"]
    else:
        if not subject:
            subject = "[GIAM-SAT] Thông báo từ bộ phận IT"
        if not body:
            return {"success": False, "error": "Nội dung email không được để trống"}

    # Variable substitution
    body = body.replace("{hostname}", hostname)
    body = body.replace("{user_name}", user_name)
    body = body.replace("{employee_id}", employee_id)

    # Validate SMTP config
    smtp_pass = os.environ.get("GIAMSAT_SMTP_PASS", "")
    if not smtp_pass:
        return {"success": False, "error": "SMTP chưa được cấu hình. Vui lòng cấu hình GIAMSAT_SMTP_PASS trong file .env trên server."}

    # Send email in background thread
    def _send_thread():
        send_email_smtp(recipient, subject, body, machine_id=machine_id,
                        template_id=template_id or "custom", source="dashboard")

    threading.Thread(target=_send_thread, daemon=True).start()

    print(f"[📧] Manual email alert sent to {recipient} ({user_name}, {hostname})")
    return {
        "success": True,
        "to": recipient,
        "subject": subject,
        "message": f"Email đã được gửi đến {recipient}"
    }


def get_smtp_config():
    """Get current SMTP configuration status."""
    return {
        "smtp_host": os.environ.get("GIAMSAT_SMTP_HOST", "smtp-mail.outlook.com"),
        "smtp_port": os.environ.get("GIAMSAT_SMTP_PORT", "587"),
        "smtp_user": os.environ.get("GIAMSAT_SMTP_USER", "it@example.com"),
        "smtp_configured": bool(os.environ.get("GIAMSAT_SMTP_PASS", "")),
        "from_email": os.environ.get("GIAMSAT_SMTP_USER", "it@example.com")
    }


def get_templates_list():
    """Get list of available email templates."""
    return [
        {"id": tid, "name": tpl["name"], "subject": tpl["subject"], "body": tpl["body"]}
        for tid, tpl in EMAIL_TEMPLATES.items()
    ]