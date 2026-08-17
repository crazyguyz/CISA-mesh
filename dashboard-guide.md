# HƯỚNG DẪN SỬ DỤNG DASHBOARD — DASHBOARD USER GUIDE

Tài liệu song ngữ (Việt - Anh) hướng dẫn chức năng và cách sử dụng từng menu của dashboard GIAM-SAT.
Bilingual (Vietnamese - English) guide to the functions and usage of each GIAM-SAT dashboard menu.

## Đăng nhập — Log in

- **VI:** Mở trình duyệt, truy cập địa chỉ máy chủ (mặc định `http://<địa-chỉ-server>:5000`) rồi đăng nhập bằng tài khoản admin.
- **EN:** Open a browser, go to the server address (default `http://<server-ip>:5000`) and log in with an admin account.

---

## NHÓM 1: GIÁM SÁT — MONITORING

### Tổng quan (Overview)

- **VI:** Trang chính hiển thị tổng trạng thái hệ thống: số máy online/offline, tổng sự kiện, cảnh báo gần đây và biểu đồ. Là màn hình đầu tiên sau khi đăng nhập.
- **EN:** Main page showing overall system status: online/offline machines, event totals, recent alerts and charts. First screen after login.

### Dashboard (Custom Dashboards)

- **VI:** Tạo và bố trí các dashboard tùy chỉnh (thêm widget, sắp xếp bố cục) để theo dõi các chỉ số riêng theo nhu cầu.
- **EN:** Create and lay out custom dashboards (add widgets, arrange layout) to track your own metrics.

### Event Log

- **VI:** Xem nhật ký sự kiện Windows/Linux (Security, System, Application...) do agent thu thập; lọc theo máy, mức nghiêm trọng, Event ID.
- **EN:** View Windows/Linux event logs (Security, System, Application...) collected by agents; filter by machine, severity and Event ID.

### FIM (File Integrity Monitoring)

- **VI:** Xem cảnh báo thay đổi file/thư mục quan trọng (tạo, sửa, xóa) — phát hiện chỉnh sửa trái phép.
- **EN:** View alerts for changes to critical files/folders (create, modify, delete) — detect unauthorized modifications.

### Syslog

- **VI:** Xem log syslog nhận từ thiết bị mạng (router, switch, firewall) gửi về cổng 514.
- **EN:** View syslog messages received from network devices (routers, switches, firewalls) on port 514.

### Response

- **VI:** Thực thi hành động phản hồi lên máy trạm (cách ly mạng, kill tiến trình, chặn IP, cách ly file) để xử lý sự cố.
- **EN:** Run response actions on endpoints (isolate network, kill process, block IP, quarantine file) to handle incidents.

### Network

- **VI:** Theo dõi lưu lượng mạng: kết nối TCP/UDP, truy vấn DNS, lưu lượng bất thường giữa các máy.
- **EN:** Monitor network traffic: TCP/UDP connections, DNS queries, suspicious traffic between machines.

### Threats

- **VI:** Xem cảnh báo mối đe dọa do correlation engine phát hiện (theo rule, có ánh xạ MITRE ATT&CK và độ tin cậy).
- **EN:** View threat alerts detected by the correlation engine (rule-based, with MITRE ATT&CK mapping and confidence).

### Vulns

- **VI:** Xem kết quả quét lỗ hổng (CVE) của phần mềm đã cài trên máy trạm, kèm mức độ nghiêm trọng.
- **EN:** View vulnerability scan results (CVEs) for installed software, with severity levels.

### YARA

- **VI:** Xem kết quả quét mã độc bằng rule YARA (phát hiện file nghi ngờ, mã độc đã biết).
- **EN:** View malware scan results using YARA rules (detect suspicious files, known malware).

### SCA (Security Configuration Assessment)

- **VI:** Xem đánh giá cấu hình bảo mật theo chuẩn (CIS, PCI-DSS, ISO 27001, HIPAA, GDPR) — trạng thái PASS/FAIL/WARN.
- **EN:** View security configuration assessment against standards (CIS, PCI-DSS, ISO 27001, HIPAA, GDPR) — PASS/FAIL/WARN status.

### Agentless

- **VI:** Theo dõi thiết bị không cài agent (server, gateway, máy in...) qua ping/SNMP — trạng thái online/offline.
- **EN:** Monitor devices without an agent (servers, gateways, printers...) via ping/SNMP — online/offline status.

### Agent Assistant

- **VI:** Trò chuyện với trợ lý AI (DeepSeek/OpenAI/Gemini/Groq) để phân tích sự kiện, cảnh báo và nhận gợi ý xử lý.
- **EN:** Chat with the AI assistant (DeepSeek/OpenAI/Gemini/Groq) to analyze events/alerts and get remediation suggestions.

### Sysmon

- **VI:** Xem log Sysmon chi tiết (tạo tiến trình, kết nối mạng, ghi file, registry, DLL load) để điều tra sâu.
- **EN:** View detailed Sysmon logs (process creation, network, file, registry, DLL load) for deep investigation.

### Memory

- **VI:** Xem kết quả quét bộ nhớ (process hollowing, injection, giả mạo tên tiến trình) — phát hiện mã độc ẩn trong tiến trình.
- **EN:** View memory scan results (process hollowing, injection, name spoofing) — detect malware hidden in processes.

---

## NHÓM 2: PHÂN TÍCH & ĐIỀU TRA — ANALYSIS & INVESTIGATION

### Điều tra (Incident)

- **VI:** Xem dòng thời gian điều tra sự cố — tổng hợp mọi sự kiện (Network, Sysmon, Events, FIM, Memory) quanh một cảnh báo trong ±15 phút.
- **EN:** View an incident investigation timeline — all events (Network, Sysmon, Events, FIM, Memory) around an alert within ±15 minutes.

### Attack Overview

- **VI:** Xem tổng quan chuỗi tấn công — kỹ thuật MITRE đã bị phát hiện và chuỗi tiến trình (process chain) của cuộc tấn công.
- **EN:** View the attack chain overview — detected MITRE techniques and the process chain of the attack.

### Threat Hunting

- **VI:** Chủ động tìm kiếm mối đe dọa trong dữ liệu lịch sử bằng các bộ lọc/truy vấn tùy chỉnh.
- **EN:** Proactively hunt for threats across historical data using custom filters/queries.

### Anomaly

- **VI:** Xem phát hiện bất thường hành vi (độ lệch so với baseline đã học) — dấu hiệu tấn công chưa có rule.
- **EN:** View behavior anomaly detections (deviations from learned baselines) — signs of attacks not yet covered by rules.

### IOC Sweep

- **VI:** Quét toàn bộ máy trạm theo Indicator of Compromise (IP/domain/hash) để tìm dấu vết xâm nhập.
- **EN:** Sweep all machines against Indicators of Compromise (IP/domain/hash) to find signs of compromise.

### MITRE ATT&CK

- **VI:** Xem ma trận MITRE ATT&CK — các kỹ thuật/tactic đã được phát hiện trên hệ thống.
- **EN:** View the MITRE ATT&CK matrix — techniques/tactics detected on the system.

---

## NHÓM 3: QUẢN TRỊ — ADMINISTRATION

### Tin nhắn (Messages)

- **VI:** Nhắn tin hai chiều giữa admin và người dùng máy trạm (thông báo, yêu cầu hỗ trợ).
- **EN:** Two-way messaging between admin and workstation users (announcements, support requests).

### Agent Groups

- **VI:** Quản lý nhóm agent — gom máy theo nhóm để áp dụng chính sách chung.
- **EN:** Manage agent groups — group machines together to apply common policies.

### Update Agent

- **VI:** Quản lý bản cập nhật agent — xem phiên bản, đẩy cập nhật agent mới xuống các máy trạm.
- **EN:** Manage agent updates — view versions and push new agent updates to workstations.

### FIM Baseline

- **VI:** Quản lý baseline FIM — chọn file/thư mục cần giám sát toàn vẹn (tối đa 500 mục).
- **EN:** Manage FIM baselines — choose files/folders to monitor for integrity (up to 500 items).

### Quản lý Rules

- **VI:** Quản lý correlation rules — bật/tắt, xem chi tiết các rule phát hiện tấn công.
- **EN:** Manage correlation rules — enable/disable and view details of attack-detection rules.

### Email Alerts

- **VI:** Cấu hình cảnh báo qua email (SMTP, người nhận, mức nghiêm trọng tối thiểu).
- **EN:** Configure email alert notifications (SMTP, recipients, minimum severity).

### Tài sản (Assets)

- **VI:** Quản lý tài sản IT với nhiều sub-tab: **Máy tính**, **Màn hình**, **Máy in**, **Điện thoại**, **Thiết bị mạng**, **Ngoại vi**, **Kho** và **Cảnh báo thay đổi**.
  - **Tự phát hiện:** nút **"🔍 Quét tự động"** → nhập dải IP (VD `192.168.1.0/24`) để dò máy in (SNMP/JetDirect), điện thoại IP (VD Yealink), router/switch/AP rồi tự nạp vào kho với nhãn **"Tự động"** (kèm serial, địa chỉ IP).
  - **Nhập tay:** tab **Kho** → **"＋ Thêm tài sản"** để quản lý tồn kho (chuột, bàn phím, điện thoại, linh kiện dự phòng...) với: loại, hãng, model, serial, mã số tài sản, trạng thái (Còn hàng/Đã cấp/Đang sửa/Thanh lý), người đang dùng, vị trí/phòng, ngày mua, bảo hành, giá, ghi chú. Sửa/xoá trực tiếp.
  - **Adopt:** tài sản tự phát hiện có nút **"Đưa vào kho"** để gán người/vị trí/mã TS (chuyển từ Tự động → Nhập tay).
  - **Xuất Excel đa sheet:** `May tinh`, `Man hinh`, `May in`, `Dien thoai`, `Thiet bi mang`, `Ngoai vi`, `Kho`.
  - Theo dõi **thay đổi phần cứng** và lịch sử xử lý (đã xác nhận/chưa xử lý).
- **EN:**
  - **Computers / Monitors / Printers / Phones / Network devices / Peripherals / Inventory / Changes** tabs.
  - **"🔍 Auto scan"** → enter an IP range to auto-discover printers (SNMP/JetDirect), IP phones (e.g. Yealink), routers/switches/APs; found items are added to inventory as **"Auto"** (with serial, IP).
  - **Inventory** tab → **"＋ Add asset"** to manage stock manually (mice, keyboards, phones, spare components...) with: category, brand, model, serial, asset tag, status (in stock/assigned/in repair/disposed), assignee, location, purchase date, warranty, cost, notes; edit/delete.
  - **Adopt** button turns an auto-discovered asset into a manually-managed one.
  - **Multi-sheet Excel export:** Computers, Monitors, Printers, Phones, Network, Peripherals, Inventory.
  - Tracks **hardware changes** with resolved/unresolved status.

---

## NHÓM 4: HỆ THỐNG — SYSTEM

### Dọn dẹp dữ liệu (Cleanup)

- **VI:** Dọn dẹp dữ liệu cũ theo thời gian lưu trữ (retention) để giải phóng dung lượng cơ sở dữ liệu.
- **EN:** Clean up old data according to retention settings to free database space.

---

*Mẹo: các menu đều hỗ trợ tìm kiếm, lọc và cập nhật theo thời gian thực (SSE).*
*Tip: all menus support search, filtering and real-time updates (SSE).*


