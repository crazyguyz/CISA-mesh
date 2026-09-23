"""
Rules IO helper (v5.0.8)

Vấn đề: `yaml.safe_dump()` / `yaml.dump()` KHÔNG giữ được comment. Vì vậy mọi
lần ghi `server/rules/correlation_rules.yaml` qua màn hình Rules (thêm/sửa/xoá
rule), qua upload Sigma, hay qua auto-import Sigma hàng tuần đều **xoá mất khối
comment header** ở đầu file. Hệ quả thực tế:
  - File này được git track -> sau mỗi lần cài dùng, repo luôn hiện "dirty"
    (`git status` báo file rules đã sửa dù người dùng không sửa gì).
  - Mất luôn phần hướng dẫn vận hành ghi trong header (deploy rule thế nào,
    vì sao server không chạy 2000+ rule này server-side...).

Fix: `dump_preserving_header()` đọc khối comment đầu file TRƯỚC khi ghi, dump
YAML ra file tạm rồi gộp lại thành `header + yaml` và `os.replace()` (atomic,
không để lại file rác nếu ghi lỗi giữa đường).

Không phụ thuộc package nào ngoài stdlib + PyYAML, import an toàn từ cả
`server/` (sigma_updater) và `server/api/` (api_rules, api_events).
"""

import os
import tempfile

# Header chuẩn - dùng khi file chưa có header (file mới / bị xoá header).
DEFAULT_HEADER = """\
# ============================================================================
# GIAM-SAT Correlation Rules — DETECTION POINT: AGENT-SIDE
# Bộ rule YAML này chạy trên TỪNG AGENT: mỗi máy tự nạp CORRELATION_RULES ở
# agent/correlation_engine.py và đánh giá sự kiện LOCAL của chính nó.
# SERVER chỉ chạy các rule CROSS-* (hardcode trong
# server/correlation_engine_server.py) để tương quan LIÊN MÁY.
# Deploy bản mới: màn hình Rules -> "Cập nhật Rules" (copy YAML sang
# agent/rules/ + gửi lệnh reload_rules cho các agent) rồi restart server.
# Không chạy bộ rule này server-side để tránh trùng cảnh báo (agent + server
# cùng bắn) và FP storm — agent đã là nơi detect từng host.
# ============================================================================
"""


def read_header(path):
    """Trả về khối comment/blank ở đầu file (giữ nguyên cả newline).

    Dừng ngay tại dòng đầu tiên KHÔNG phải comment và KHÔNG rỗng (tức dòng
    dữ liệu YAML đầu tiên). File không tồn tại / lỗi đọc -> chuỗi rỗng.
    """
    header = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if stripped.startswith("#") or stripped == "":
                    header.append(line)
                else:
                    break
    except Exception:
        return ""
    # Bỏ các dòng trống ở cuối để không phình file mỗi lần ghi
    while header and header[-1].strip() == "":
        header.pop()
    if not header:
        return ""
    # .rstrip() de khong them 1 dong trong du moi dong comment da co '\n'
    return "".join(header).rstrip("\r\n") + "\n"


def dump_preserving_header(path, data, header=None):
    """Ghi YAML vào `path` nhưng GIỮ khối comment header.

    Args:
        path:   đường dẫn correlation_rules.yaml
        data:   dict đã load (metadata + rules)
        header: header chỉ định; None -> đọc từ file hiện có, nếu không có
                thì dùng `DEFAULT_HEADER`.
    """
    import yaml

    if header is None:
        header = read_header(path) or DEFAULT_HEADER

    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".rules_", suffix=".yaml.tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(header)
            yaml.dump(data, f, default_flow_style=False, allow_unicode=True,
                      sort_keys=False)
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.remove(tmp_path)
        except Exception:
            pass
        raise
