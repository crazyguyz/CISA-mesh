"""
API AI - AI Assistant chat, float chat, AI toggle/status.
"""

import json
import os
import threading
import time
from datetime import datetime
from flask import request, jsonify

from .api_common import check_auth


def register(app, core):
    """Register AI-related routes."""

    DEEPSEEK_API_KEY = os.environ.get("DEEPSEEK_API_KEY", "")

    @app.route("/api/float_ai_chat", methods=["POST"])
    def api_float_ai_chat():
        if os.environ.get("GIAMSAT_DISABLE_AI", "0") == "1" or getattr(core, "_ai_disabled", False):
            return jsonify({"success": False, "error": "AI Assistant đã bị vô hiệu hóa bởi quản trị viên."}), 403
        _, err, code = check_auth("api")
        if err: return err, code

        if not DEEPSEEK_API_KEY:
            return jsonify({"success": False, "error": "AI Assistant chưa được cấu hình. Vui lòng đặt DEEPSEEK_API_KEY environment variable trên server."}), 503

        client_ip = request.remote_addr
        now = time.time()
        AI_RATE_LIMIT_MAX = 5
        AI_RATE_LIMIT_WINDOW = 60
        with core._ai_rate_lock:
            if client_ip not in core._ai_rate_limit:
                core._ai_rate_limit[client_ip] = []
            core._ai_rate_limit[client_ip] = [t for t in core._ai_rate_limit[client_ip] if now - t < AI_RATE_LIMIT_WINDOW]
            if len(core._ai_rate_limit[client_ip]) >= AI_RATE_LIMIT_MAX:
                return jsonify({"success": False, "error": f"Rate limit exceeded. Tối đa {AI_RATE_LIMIT_MAX} requests mỗi {AI_RATE_LIMIT_WINDOW}s."}), 429
            core._ai_rate_limit[client_ip].append(now)

        data = request.json
        model = data.get("model", "deepseek-chat")
        messages = data.get("messages", [])
        temperature = min(float(data.get("temperature", 0.7)), 1.5)
        max_tokens = min(int(data.get("max_tokens", 4096)), core.AI_MAX_TOKENS_CAP if hasattr(core, 'AI_MAX_TOKENS_CAP') else 8192)

        if not messages or not isinstance(messages, list):
            return jsonify({"error": "No messages"}), 400
        if len(messages) > 20:
            return jsonify({"error": "Too many messages (max 20)"}), 400
        for msg in messages:
            if not isinstance(msg, dict) or "role" not in msg or "content" not in msg:
                return jsonify({"error": "Invalid message format"}), 400
            if msg.get("role") not in ("system", "user", "assistant"):
                return jsonify({"error": f"Invalid role: {msg.get('role')}"}), 400
            content = str(msg.get("content", ""))
            if len(content) > 32000:
                return jsonify({"error": "Message content too long (max 32KB)"}), 400

        user_messages = [m.get("content", "") for m in messages if m.get("role") == "user"]
        injection_keywords = [
            "ignore previous", "ignore all", "system prompt", "you are now",
            "pretend you are", "act as if", "new instructions", "forget everything",
            "do anything now", "dan mode", "developer mode", "jailbreak",
            "you are an unrestricted", "without restrictions",
        ]
        for um in user_messages:
            um_lower = str(um).lower()
            for kw in injection_keywords:
                if kw in um_lower:
                    core.db.insert_audit_log("ai_user", "float_ai_chat_blocked",
                        f"IP: {client_ip}, reason: prompt_injection", client_ip)
                    return jsonify({"success": False, "error": "Yêu cầu bị từ chối do vi phạm chính sách bảo mật."}), 403

        core.db.insert_audit_log("ai_user", "float_ai_chat", f"IP: {client_ip}, model: {model}, msgs: {len(messages)}", client_ip)

        try:
            import urllib.request, ssl as _ssl
            ctx = _ssl.create_default_context()
            req = urllib.request.Request(
                "https://api.deepseek.com/chat/completions",
                data=json.dumps({
                    "model": model,
                    "messages": messages,
                    "max_tokens": max_tokens,
                    "temperature": temperature
                }).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {DEEPSEEK_API_KEY}"
                }
            )
            resp = urllib.request.urlopen(req, timeout=60, context=ctx)
            result = json.loads(resp.read().decode("utf-8"))
            if result.get("choices") and len(result["choices"]) > 0:
                return jsonify({
                    "success": True,
                    "content": result["choices"][0]["message"]["content"]
                })
            return jsonify({"success": False, "error": result.get("error", {}).get("message", "No response")})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)[:300]})

    @app.route("/api/ai/toggle", methods=["POST"])
    def api_ai_toggle():
        username, err, code = check_auth("settings")
        if err: return err, code
        data = request.json or {}
        core._ai_disabled = data.get("disabled", False)
        core.db.insert_audit_log(username, "ai_toggle", f"AI disabled: {core._ai_disabled}", request.remote_addr)
        return jsonify({"success": True, "ai_disabled": core._ai_disabled})

    @app.route("/api/ai/status", methods=["GET"])
    def api_ai_status():
        _, err, code = check_auth("api")
        if err: return err, code
        env_disabled = os.environ.get("GIAMSAT_DISABLE_AI", "0") == "1"
        return jsonify({"ai_disabled": env_disabled or getattr(core, "_ai_disabled", False), "env_disabled": env_disabled, "runtime_disabled": getattr(core, "_ai_disabled", False)})

    @app.route("/api/assistant", methods=["POST"])
    def api_assistant():
        _, err, code = check_auth("command")
        if err: return err, code
        data = request.json
        question = data.get("question", "")
        provider = data.get("provider", "deepseek")
        api_key = data.get("api_key", "")
        context_data = data.get("context_data", "")
        max_context = min(int(data.get("max_context", 28000) or 28000), 8000)

        if not question:
            return jsonify({"response": "Vui lòng nhập câu hỏi."})

        # v4.1: Rich system prompt for AI to understand GIAM-SAT context
        system_prompt = (
            "Bạn là trợ lý bảo mật GIAM-SAT, một hệ thống SIEM giám sát an ninh mạng tập trung. "
            "Nhiệm vụ của bạn là phân tích dữ liệu giám sát và đưa ra đánh giá, cảnh báo, đề xuất bằng tiếng Việt.\n\n"
            "Hệ thống GIAM-SAT thu thập các loại dữ liệu sau:\n"
            "- events: Windows Event Log (Security, System, PowerShell, WMI, RDP, Defender, Firewall...)\n"
            "- sysmon: Sysmon Events (EID 1-18,22) - Process Create, Network, DLL Load, Injection, Registry, DNS\n"
            "- network: Network Traffic (TCP/UDP connections, có process context từ Sysmon EID 3)\n"
            "- threats: Threat Alerts (correlation rules: RANSOM, KERB, EXFIL, INJ, EVASION, THREAT)\n"
            "- fim: File Integrity Monitoring (thay đổi file hệ thống)\n"
            "- vulns: Vulnerability Alerts (CVE)\n"
            "- yara: YARA/Pattern Scan (phát hiện mã độc)\n"
            "- sca: Security Configuration Assessment (CIS compliance)\n"
            "- memory: Memory Scan (process hollowing, injection, unsigned DLL)\n"
            "- syslog: Syslog từ router/thiết bị mạng\n"
            "- inspection: Deep Packet Inspection (DNS, TLS, HTTP, Beaconing detection)\n"
            "- agentless: Agentless Monitoring (ping/SNMP/SSH)\n"
            "- machines: Danh sách máy trạm (online/offline, IP, OS, user)\n"
            "- system_stats: Thống kê hệ thống (tổng máy, events, threats 24h)\n"
            "- attack_overview: Tổng quan tấn công (chains, timeline, MITRE ATT&CK)\n\n"
            "Khi phân tích, hãy:\n"
            "1. Tóm tắt tổng quan (bao nhiêu máy, bao nhiêu alerts, severity cao nhất)\n"
            "2. Liệt kê các mối đe dọa CRITICAL/HIGH đang hoạt động\n"
            "3. Phân tích MITRE ATT&CK tactics đang bị khai thác\n"
            "4. Đề xuất hành động cụ thể (cô lập máy, khóa tài khoản, điều tra thêm)\n"
            "5. Cảnh báo nếu phát hiện dấu hiệu ransomware, data exfiltration, lateral movement\n"
            "Trả lời ngắn gọn, có cấu trúc, ưu tiên các mối đe dọa nghiêm trọng nhất."
        )

        full_prompt = question
        if context_data:
            ctx = str(context_data)
            # Add summary stats for quick overview
            ctx_header = ""
            try:
                import json as _json
                parsed = _json.loads(ctx) if ctx.startswith("{") else {}
                meta = parsed.get("_meta", {})
                if meta:
                    ctx_header = (
                        f"=== TỔNG QUAN NHANH ===\n"
                        f"Thời điểm: {meta.get('collected_at', '?')}\n"
                        f"Tổng máy: {meta.get('total_machines', '?')}\n"
                        f"Số records: {_json.dumps(meta.get('record_counts', {}), ensure_ascii=False)}\n"
                        f"Period: {meta.get('period_minutes', '?')} phút\n\n"
                    )
            except Exception:
                pass

            if len(ctx) > max_context:
                ctx = ctx[:max_context] + f"\n... (đã cắt bớt, tổng {len(context_data)} bytes)"
            full_prompt = (
                f"{system_prompt}\n\n"
                f"{ctx_header}"
                f"=== DỮ LIỆU LOG CHI TIẾT ===\n"
                f"```json\n{ctx}\n```\n\n"
                f"CÂU HỎI: {question}"
            )
        else:
            full_prompt = f"{system_prompt}\n\nCÂU HỎI: {question}"

        try:
            start_time = time.time()
            response_text = core._call_ai_assistant(full_prompt, provider, api_key)
            elapsed_ms = int((time.time() - start_time) * 1000)
            core.db.insert_audit_log(
                "ai_user", "agent_assistant",
                f"Provider: {provider}, "
                f"Question: {len(question)} chars, "
                f"Context: {len(str(context_data)) if context_data else 0} bytes, "
                f"Response: {len(response_text)} chars, "
                f"Time: {elapsed_ms}ms, "
                f"Status: success",
                request.remote_addr
            )
            return jsonify({"response": response_text, "context_size": len(str(context_data)) if context_data else 0})
        except Exception as e:
            core.db.insert_audit_log(
                "ai_user", "agent_assistant_error",
                f"Provider: {provider}, "
                f"Question: {len(question)} chars, "
                f"Context: {len(str(context_data)) if context_data else 0} bytes, "
                f"Error: {str(e)[:200]}",
                request.remote_addr
            )
            return jsonify({"response": f"AI Assistant error: {str(e)}"})