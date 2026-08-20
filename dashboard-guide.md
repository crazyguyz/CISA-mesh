# HƯỚNG DẪN SỬ DỤNG DASHBOARD — DASHBOARD USER GUIDE

Tài liệu song ngữ (Việt - Anh) hướng dẫn chi tiết chức năng và cách sử dụng từng menu của dashboard GIAM-SAT.
Bilingual (Vietnamese - English) detailed guide to every function and how to use each GIAM-SAT dashboard menu.

> **🆕 MỚI / NEW:** Các chức năng mới bổ sung gần đây được đánh dấu **🆕** — xem chi tiết hơn ở cuối mỗi mục.
> Newly added features are marked **🆕** — each gets extra detail below.

---

## Đăng nhập — Log in

- **VI:**
  1. Mở trình duyệt (Chrome/Edge/Firefox), truy cập `http://<địa-chỉ-server>:5000`.
  2. Nhập tên đăng nhập **admin** và mật khẩu (đặt khi cài đặt server, hoặc tự tạo ở lần chạy đầu tiên).
  3. Nhấn **Đăng nhập**. Nếu hệ thống yêu cầu **đổi mật khẩu** (lần đầu), hãy đổi ngay trước khi dùng.
  4. Đổi ngôn ngữ bất kỳ lúc nào: góc trên phải → nút 🌐 → chọn **🇻🇳 Tiếng Việt** hoặc **🇬🇧 English**. Giao diện chuyển ngay, không cần tải lại.
- **EN:**
  1. Open a browser (Chrome/Edge/Firefox) and go to `http://<server-ip>:5000`.
  2. Log in with the **admin** account (set at install, or auto-generated on first run).
  3. If asked to **change the password** (first login), do it before proceeding.
  4. Switch language anytime: top-right → 🌐 button → **🇻🇳 Tiếng Việt** or **🇬🇧 English**. No reload needed.

## Mẹo chung — Common tips

- **VI:** Mọi danh sách đều có ô **tìm kiếm**, nút **Tải lại** 🔄, và tự cập nhật thời gian thực (SSE). Click **tiêu đề cột** để sắp xếp bảng (ngày/số/chữ). Nút 🔄 góc trên phải tải lại toàn trang.
- **EN:** Every list has a **search box**, a **Reload** 🔄 button, and real-time updates (SSE). Click **column headers** to sort. The top-right 🔄 reloads the whole page.
- **VI:** Bấm máy trạm bên trái → trang chi tiết máy với các tab: **Nhật ký sự kiện / FIM / Phản hồi / Cấu hình / Kiểm soát / SSH từ xa**.
- **EN:** Click a machine on the left → its detail page with tabs: **Event Log / FIM / Response / Config / Control / Remote SSH**.

---

## NHÓM 1: GIÁM SÁT — MONITORING

### Tổng quan (Overview)

- **VI:** Màn hình đầu tiên sau khi đăng nhập.
  - Bên trái: bảng **toàn cảnh Server Health & Security** (tự làm mới mỗi 15 giây).
  - Bên phải: thẻ **Tổng máy trạm / Đang online / Sự kiện / Syslog**; bảng **Máy trạm đã đăng ký** (bấm tiêu đề để mở/đóng; có nút **Dọn log cũ** và **Xóa offline**); biểu đồ **Phân loại sự kiện**; thẻ **📊 Báo Cáo Tài Sản** (đường tắt mở cửa sổ xuất báo cáo — xem mục *Báo Cáo Tài Sản* bên dưới).
- **EN:** First screen after login.
  - Left: **Server Health & Security panorama** (auto-refresh every 15s).
  - Right: **Total machines / Online / Events / Syslog** stat cards; **Registered machines** table (click header to expand — buttons **Clean old logs**, **Delete offline**); **Event types** chart; **📊 Asset Report** card (shortcut to the export dialog — see *Asset Report* below).

### Dashboard (Custom Dashboards)

- **VI:** Tạo dashboard tùy chỉnh với các widget (số liệu, bảng, biểu đồ) từ nhiều nguồn dữ liệu.
  1. Vào menu **Dashboard** (biểu tượng lưới).
  2. Nhập tên dashboard vào ô tên (mặc định `My Dashboard`).
  3. Nhấn **＋ Thêm Widget** → chọn **Nguồn dữ liệu** (stats, events, threats...), **Loại widget** (số/stat, bảng/table, biểu đồ cột/đường/tròn), chọn **trường dữ liệu**, nhập **Tiêu đề**, **Độ rộng** (1–12 cột), **Tự làm mới** (giây; 0 = tắt).
  4. Nhấn **Thêm** → widget hiện trên lưới; có thể xóa từng widget (❌) hoặc **Xóa hết** (💨).
  5. Nhấn **Lưu** để lưu; nhấn **Mở** để xem danh sách dashboard đã lưu.
- **EN:** Build custom dashboards with widgets (numbers, tables, charts) from multiple data sources.
  1. Open the **Dashboards** menu (grid icon).
  2. Type a name in the name box (default `My Dashboard`).
  3. Click **＋ Add Widget** → pick **Data source** (stats, events, threats...), **Widget type** (stat, table, bar/line/pie chart), choose **data field(s)**, set **Title**, **Width** (1–12 columns), **Refresh seconds** (0 = off).
  4. Click **Add** — the widget appears; delete it with ❌ or **Clear all** (💨).
  5. Click **Save** to store it, or **Open** to list saved dashboards.

- **VI — 🆕 Xóa dashboard tùy chỉnh:**
  1. Nhấn **Mở** trong Dashboard Builder.
  2. Trong cửa sổ danh sách, mỗi dashboard có nút **Xóa** (đỏ) bên phải.
  3. Nhấn **Xóa** → xác nhận → dashboard bị xóa vĩnh viễn (không thể hoàn tác). Hành động được ghi vào Nhật ký kiểm toán.
- **EN — 🆕 Delete a custom dashboard:**
  1. Click **Open** in the Dashboard Builder.
  2. In the list dialog every dashboard row has a red **Delete** button on the right.
  3. Click **Delete** → confirm → permanently removed (cannot be undone). The action is recorded in the Audit Log.
### Event Log (Nhật ký sự kiện)

- **VI:** Xem nhật ký sự kiện Windows/Linux do agent thu thập.
  1. Chọn máy trạm bên trái (hoặc menu **Event Log** để xem tất cả máy).
  2. Dùng ô **Tìm kiếm** lọc theo text; click **tiêu đề cột** để sắp xếp.
  3. Click một dòng để xem **chi tiết đầy đủ** (raw data + thời gian nhận).
- **EN:** View Windows/Linux event logs collected by agents.
  1. Select a machine on the left (or the **Event Log** menu for all machines).
  2. Use **Search** to filter; click **column headers** to sort.
  3. Click a row for **full details** (raw data + received time).

### FIM (File Integrity Monitoring)

- **VI:** Theo dõi thay đổi file/thư mục quan trọng.
  - Chọn máy (hoặc menu **FIM** cho tất cả máy) → danh sách hành động **Tạo / Sửa / Xóa** trên file được giám sát.
  - Mỗi dòng hiện: đường dẫn, hành động, thời gian, máy. Bấm dòng để xem chi tiết; nút **JSON** xuất dữ liệu.
- **EN:** Monitor changes to critical files/folders.
  - Pick a machine (or the **FIM** menu for all) — a list of **Create / Modify / Delete** actions.
  - Each row shows: path, action, time, machine. Click a row for details; **JSON** exports data.

### Syslog

- **VI:** Log từ thiết bị mạng (router/switch/firewall) qua cổng 514.
  - Chọn **Syslog** → danh sách log với **Nguồn IP, Facility, Severity, Thời gian, Nội dung**.
  - Ô tìm kiếm lọc theo IP nguồn hoặc nội dung.
  - *Lưu ý:* server phải mở UDP 514 và thiết bị phải được cấu hình gửi log về.
- **EN:** Logs from network devices (routers/switches/firewalls) on port 514.
  - Open **Syslog** — logs with **Source IP, Facility, Severity, Timestamp, Message**.
  - Search filters by source IP or message.
  - *Note:* server must listen on UDP 514 and devices must send logs to it.

### Response (Phản hồi)

- **VI:** Xem kết quả các **hành động phản hồi** (Active Response) đã thực thi trên máy trạm: cách ly mạng, kill tiến trình, chặn IP, cách ly file...
  - Vào menu **Response** (hoặc tab **Phản hồi** trong trang máy).
  - Mỗi dòng: máy, hành động, trạng thái (thành công/lỗi), output, mã thoát.
  - *Để GỬI hành động mới:* dùng tab **Kiểm soát** (Control) trong trang máy.
- **EN:** View results of **Active Response** actions executed on endpoints: isolate network, kill process, block IP, quarantine file...
  - Open **Response** (menu or machine tab).
  - Each row: machine, action, status (success/error), output, exit code.
  - *To SEND new actions:* use the **Control** tab on a machine page.

### Network

- **VI:** Theo dõi lưu lượng mạng giữa các máy.
  - Chọn **Network** → biểu đồ kết nối + danh sách kết nối TCP/UDP, truy vấn DNS, lưu lượng bất thường.
  - Lọc theo máy nguồn/đích, cổng, giao thức; bấm vào một kết nối để xem chi tiết.
- **EN:** Monitor network traffic between machines.
  - Open **Network** → connection graph + list of TCP/UDP connections, DNS queries, suspicious traffic.
  - Filter by source/destination machine, port, protocol; click a connection for details.

### Threats

- **VI:** Cảnh báo mối đe dọa do correlation engine phát hiện.
  - Mỗi dòng: tên rule, mức độ (CRITICAL/HIGH/MEDIUM/LOW), máy bị ảnh hưởng, thời gian, độ tin cậy.
  - Bấm vào dòng để xem **chi tiết + hành động đề xuất**; có thể **Điều tra** (mở dòng thời gian Incident).
- **EN:** Threat alerts detected by the correlation engine.
  - Each row: rule name, severity (CRITICAL/HIGH/MEDIUM/LOW), affected machine, time, confidence.
  - Click a row for **details + suggested actions**; you can **Investigate** (open the incident timeline).

### Vulns

- **VI:** Kết quả quét lỗ hổng (CVE) phần mềm đã cài.
  - Chọn máy hoặc xem tất cả → danh sách CVE với **CVE ID, mức nghiêm trọng, phần mềm, bản vá**.
  - Lọc theo severity (CRITICAL/HIGH...) để ưu tiên xử lý.
- **EN:** Vulnerability scan results (CVEs) of installed software.
  - Pick a machine or view all → list of CVEs with **CVE ID, severity, software, patch**.
  - Filter by severity (CRITICAL/HIGH...) to prioritize.

### YARA

- **VI:** Kết quả quét mã độc bằng rule YARA.
  - Xem file nghi ngờ: **rule YARA khớp, máy, đường dẫn file, thời gian**.
  - *Lưu ý:* rule YARA quản lý trên server; nếu chưa có rule nào, tab sẽ trống.
- **EN:** Malware scan results using YARA rules.
  - View suspicious files: **matched rule, machine, file path, time**.
  - *Note:* rules are managed on the server; if none are defined the tab is empty.

### SCA (Security Configuration Assessment)

- **VI:** Đánh giá cấu hình bảo mật theo chuẩn (CIS, PCI-DSS, ISO 27001, HIPAA, GDPR).
  - Chọn máy → checklist với trạng thái **PASS / FAIL / WARN**, kèm mô tả và gợi ý khắc phục.
- **EN:** Security configuration assessment against standards (CIS, PCI-DSS, ISO 27001, HIPAA, GDPR).
  - Pick a machine → checklist with **PASS / FAIL / WARN** status, description and remediation hints.

### Agentless

- **VI:** Giám sát thiết bị KHÔNG cài agent (server cũ, gateway, máy in, thiết bị mạng) qua ping/SNMP.
  - Danh sách thiết bị: **IP, loại thiết bị, trạng thái online/offline, thời gian phản hồi**.
- **EN:** Monitor devices WITHOUT an agent (legacy servers, gateways, printers, network gear) via ping/SNMP.
  - Device list: **IP, type, online/offline status, response time**.

### Sysmon

- **VI:** Log Sysmon chi tiết (tạo tiến trình, kết nối mạng, ghi file, registry, DLL load) để điều tra sâu.
  - Chọn máy → lọc theo **Event ID, process, đường dẫn**.
  - Hữu ích khi truy tìm chuỗi tấn công (parent → child process).
- **EN:** Detailed Sysmon logs (process creation, network, file writes, registry, DLL load) for deep investigation.
  - Pick a machine → filter by **Event ID, process, path**.
  - Useful for tracing attack chains (parent → child process).

### Memory

- **VI:** Kết quả quét bộ nhớ tiến trình: phát hiện **process hollowing, injection, giả mạo tên tiến trình**.
  - Mỗi dòng: **máy, tiến trình, kỹ thuật nghi ngờ, mức độ, thời gian**.
- **EN:** Memory scan results: detect **process hollowing, injection, process-name spoofing**.
  - Each row: **machine, process, suspected technique, severity, time**.

### 🆕 Cluster Status (Trạng thái Cluster)

- **VI:** Xem trạng thái các node của cluster GIAM-SAT (khi triển khai nhiều node).
  1. Vào menu **Cluster**.
  2. Phần trên: 3 thẻ **Node ID** (node hiện tại), **Vai trò** (👑 Master / Slave), **Số node** đang online.
  3. Bảng bên dưới liệt kê từng node: **Node ID, IP, cổng TCP, cổng Web, số agent, vai trò, trạng thái, lần cuối kết nối** (hiển thị giờ địa phương).
  4. Nhấn **Tải lại** để cập nhật.
  - *Lưu ý:* chạy 1 server vẫn thấy node của chính mình với vai trò Master.
- **EN:** View the status of each node in a GIAM-SAT cluster (multi-node deployments).
  1. Open the **Cluster** menu.
  2. Top cards: **Node ID** (current), **Role** (👑 Master / Slave), **Online node count**.
  3. The table lists every node: **Node ID, IP, TCP port, Web port, agent count, role, status, last seen** (local time).
  4. Click **Reload** to refresh.
  - *Note:* on a single-server install you still see your own node as Master.

---

## NHÓM 2: PHÂN TÍCH & ĐIỀU TRA — ANALYSIS & INVESTIGATION

### Điều tra (Incident)

- **VI:** Dòng thời gian điều tra sự cố quanh một cảnh báo.
  1. Vào menu **Incident** → danh sách cảnh báo bên trái.
  2. Chọn một cảnh báo → bên phải hiện **dòng thời gian** tổng hợp mọi sự kiện (Network, Sysmon, Events, FIM, Memory) trong **±15 phút** quanh thời điểm cảnh báo.
  3. Bấm từng sự kiện để xem chi tiết; dùng để xác định chuỗi tấn công.
- **EN:** Incident investigation timeline around an alert.
  1. Open **Incident** → alert list on the left.
  2. Select an alert → the right side shows a **timeline** of all events (Network, Sysmon, Events, FIM, Memory) within **±15 minutes** of the alert.
  3. Click events for details; use it to reconstruct the attack chain.

### Attack Overview

- **VI:** Tổng quan chuỗi tấn công.
  - Xem **các kỹ thuật MITRE ATT&CK** đã phát hiện và **chuỗi tiến trình** (process chain) của cuộc tấn công.
  - Dùng menu **Attack** → bảng tóm tắt + sơ đồ chuỗi; bấm vào từng mắt xích để xem chi tiết.
- **EN:** Attack chain overview.
  - View **detected MITRE ATT&CK techniques** and the **process chain** of the attack.
  - Use the **Attack** menu → summary + chain diagram; click each link for details.

### Săn tìm đe dọa (Threat Hunting)

- **VI:** Chủ động săn tìm mối đe dọa trong dữ liệu lịch sử.
  1. Vào menu **Hunting**.
  2. Nhập **Giả thuyết** (VD: "Có process nào dump LSASS trong 24h qua không?").
  3. (Tùy chọn) chọn **Tactic** mẫu: Credential Theft, Lateral Movement, Persistence, C2 Communication, Exfiltration, Defense Evasion.
  4. Chọn **Thời gian (giờ)** cần quét (mặc định 168 giờ = 7 ngày).
  5. Nhấn **Bắt đầu Săn tìm đe dọa** → kết quả hiện bên dưới (kèm Campaign ID để theo dõi).
- **EN:** Proactively hunt for threats in historical data.
  1. Open **Hunting**.
  2. Type a **Hypothesis** (e.g. "Any process dumping LSASS in the last 24h?").
  3. (Optional) pick a **Tactic** template: Credential Theft, Lateral Movement, Persistence, C2 Communication, Exfiltration, Defense Evasion.
  4. Set the **Time window (hours)** to scan (default 168 h = 7 days).
  5. Click **Start Threat Hunt** → results appear below (with a Campaign ID).

### Anomaly

- **VI:** Phát hiện bất thường hành vi (độ lệch so với baseline đã học).
  - 4 thẻ tổng: **Tổng Anomaly Alerts / High / Medium / First-Time Events**.
  - Danh sách bên dưới: mô tả bất thường, máy, mức độ, thời gian.
  - Bấm vào dòng để xem chi tiết và đánh giá xem có cần chặn hay không.
- **EN:** Behavior anomaly detections (deviations from learned baselines).
  - 4 summary cards: **Total / High / Medium / First-Time Events**.
  - List below: anomaly description, machine, severity, time.
  - Click a row for details and decide whether to block.

### Quét IOC (IOC Sweep)

- **VI:** Quét toàn bộ máy trạm theo Indicators of Compromise.
  1. Vào menu **IOC Sweep**.
  2. Dán JSON IOC vào ô **JSON IOCs** (định dạng: `[{"type":"ip","value":"1.2.3.4","source":"OTX"}, ...]`) — hoặc chọn file để upload.
  3. Nhấn **Quét IOC** → kết quả: máy nào khớp với IOC nào, đường dẫn file/hash.
  4. Theo dõi tổng số khớp ở góc phải (**iocStats**).
- **EN:** Sweep all machines against Indicators of Compromise.
  1. Open **IOC Sweep**.
  2. Paste IOC JSON into **JSON IOCs** (format: `[{"type":"ip","value":"1.2.3.4","source":"OTX"}, ...]`) — or upload a file.
  3. Click **Scan IOC** → results: which machine matched which IOC, file path/hash.
  4. Watch the match counter on the right (**iocStats**).

### MITRE ATT&CK

- **VI:** Ma trận MITRE ATT&CK các kỹ thuật đã phát hiện.
  - Chọn khoảng thời gian (1h/6h/24h/72h/7 ngày) rồi nhấn **Tải lại**.
  - Ma trận hiện tactic (cột) × kỹ thuật (hàng); kỹ thuật đã phát hiện được tô màu — bấm để xem chi tiết.
- **EN:** MITRE ATT&CK matrix of detected techniques.
  - Pick a period (1h/6h/24h/72h/7 days) then click **Reload**.
  - Matrix shows tactics (columns) × techniques (rows); detected ones are highlighted — click for details.

### Agent Assistant (Trợ lý AI)

- **VI:** Hỏi-đáp với trợ lý AI để phân tích sự kiện/cảnh báo.
  1. Vào menu **Assistant**.
  2. Chọn **Hãng API** (DeepSeek / OpenAI / Gemini / Groq / xAI) và mô hình tương ứng.
  3. Chọn **Phạm vi** (toàn hệ thống / máy cụ thể) rồi gõ câu hỏi (VD: "Tóm tắt 5 mối đe dọa nghiêm trọng nhất").
  4. Nhấn gửi → AI trả lời kèm dữ liệu hệ thống thực. Có cửa sổ AI nổi (⚡ góc dưới phải) dùng mọi lúc.
- **EN:** Ask the AI assistant to analyze events/alerts.
  1. Open **Assistant**.
  2. Pick the **API provider** (DeepSeek / OpenAI / Gemini / Groq / xAI) and matching model.
  3. Choose **Scope** (whole system / a specific machine) and type a question (e.g. "Summarize the 5 most severe threats").
  4. Send — the AI replies with real system data. A floating AI widget (⚡ bottom-right) is available everywhere.

- **VI — 🆕 Bật/Tắt AI (quản trị):**
  - Trên cùng khung Assistant có **badge trạng thái** (xanh = AI đang bật, đỏ = AI bị tắt) và nút **Bật/Tắt AI** (biểu tượng nguồn ⏻).
  - Nhấn nút → xác nhận → AI bật/tắt ngay lập tức cho toàn hệ thống; badge đổi màu tương ứng.
  - Khi tắt: mọi yêu cầu AI (kể cả cửa sổ AI nổi) sẽ bị từ chối.
  - *Lưu ý:* nếu server đặt biến môi trường `GIAMSAT_DISABLE_AI=1`, nút Bật không ghi đè được — AI vẫn bị tắt (an toàn tuyệt đối theo yêu cầu quản trị).
- **EN — 🆕 Enable/Disable AI (admin):**
  - The Assistant header has a **status badge** (green = AI enabled, red = AI disabled) and a **Toggle AI** button (power icon ⏻).
  - Click it → confirm → AI toggles instantly system-wide; the badge updates.
  - When disabled, all AI requests (including the floating widget) are refused.
  - *Note:* if the server sets `GIAMSAT_DISABLE_AI=1`, the Enable button cannot override it — AI stays off (admin-level guarantee).

---

## NHÓM 3: QUẢN TRỊ — ADMINISTRATION

### Tin nhắn (Messages)

- **VI:** Nhắn tin hai chiều giữa admin và người dùng máy trạm.
  1. Vào menu **Messages** → danh sách hội thoại theo máy.
  2. Chọn máy → gõ tin nhắn và gửi; agent hiển thị thông báo cho người dùng (popup / bong bóng).
  3. Dùng để gửi thông báo bảo mật, yêu cầu hỗ trợ hoặc cảnh báo nội bộ.
- **EN:** Two-way messaging between admin and workstation users.
  1. Open **Messages** → conversations per machine.
  2. Pick a machine → type and send; the agent shows it to the user (popup/bubble).
  3. Use for security announcements, support requests, internal alerts.

### Agent Groups (Nhóm máy trạm)

- **VI:** Gom máy theo nhóm để áp dụng chính sách chung.
  1. Vào menu **Groups** → danh sách nhóm.
  2. **Tạo nhóm mới** (đặt tên + mô tả), **thêm máy vào nhóm**, **xóa máy khỏi nhóm**.
  3. Có thể gán **Group Policy** (chặn website, chặn USB, chặn phần mềm) cho từng nhóm.
- **EN:** Group machines to apply common policies.
  1. Open **Groups** → list of groups.
  2. **Create a group** (name + description), **add/remove machines**.
  3. Optionally assign **Group Policies** (block websites, block USB, block software) per group.

### Cập nhật Agent (Update Agent)

- **VI:** Quản lý phiên bản và đẩy cập nhật agent xuống máy trạm.
  1. Vào menu **Update Agent** → 2 tab: **📋 Trạng thái Agent** và **📜 Nhật ký Update**.
  2. Trạng thái: xem **phiên bản agent trên server**, danh sách máy theo nhóm với phiên bản đang chạy.
  3. Nhấn **Push Update Tất cả** để đẩy agent mới cho toàn bộ máy; hoặc push từng nhóm/máy.
  4. Nút **Reset User Info All** xóa thông tin người dùng trên agent (máy sẽ phải khai báo lại).
  5. Tab **Nhật ký Update** theo dõi kết quả cập nhật từng máy.
- **EN:** Manage agent versions and push updates to endpoints.
  1. Open **Update Agent** → 2 tabs: **📋 Agent Status** and **📜 Update Log**.
  2. Status: **server agent version**, per-group machine list with running versions.
  3. Click **Push Update All** to deploy the new agent everywhere, or push per group/machine.
  4. **Reset User Info All** wipes user info on agents (they must be re-declared).
  5. The **Update Log** tab tracks the result per machine.

### FIM Baseline

- **VI:** Chọn file/thư mục cần giám sát toàn vẹn (tối đa 500 mục).
  1. Vào menu **FIM Baseline** → danh sách máy với số mục đã giám sát.
  2. Chọn máy → mở bảng chi tiết: **thêm mục** (đường dẫn file/thư mục, loại: file/registry), **xóa mục**.
  3. Baseline = cấu hình giám sát; mọi thay đổi sau đó sẽ tạo cảnh báo FIM.
- **EN:** Choose files/folders to monitor for integrity (up to 500 items).
  1. Open **FIM Baseline** → machine list with monitored-item counts.
  2. Pick a machine → detail table: **add items** (path, type: file/registry), **remove items**.
  3. The baseline is your monitoring config; any later change raises a FIM alert.

### Quản lý Rule (Correlation Rules)

- **VI:** Quản lý các rule phát hiện tấn công.
  1. Vào menu **Rules** → bảng danh sách rule với trạng thái bật/tắt.
  2. **Bật/Tắt rule**: dùng switch/button trên mỗi dòng.
  3. **Tạo/Sửa rule**: chọn rule (hoặc nút **📋 Template**) → sửa JSON trong ô bên phải → **Lưu Rule**.
  4. **Test rule**: dán JSON rule + JSON event mẫu → **Test Rule** → xem kết quả TRIGGERED hay không.
  5. **Deploy to Agents** đẩy rule xuống agent; **Hot-reload** nạp lại rule từ server mà không cần khởi động lại.
- **EN:** Manage attack-detection rules.
  1. Open **Rules** → rule list with enable/disable state.
  2. **Toggle** rules on/off per row.
  3. **Create/Edit**: select a rule (or **📋 Template**) → edit JSON → **Save Rule**.
  4. **Test**: paste rule JSON + sample event JSON → **Test Rule** → see TRIGGERED or not.
  5. **Deploy to Agents** pushes rules down; **Hot-reload** reloads from the server without restart.

### 🆕 Chặn cảnh báo giả (Suppression Manager)

- **VI:** Dùng để "chặn lặp" — bỏ qua cảnh báo từ một **rule** (và tuỳ chọn: một **máy**) khi nó là dương tính giả (false positive) đã được xác nhận. Rule bị chặn sẽ **không tạo cảnh báo mới** nữa.

  **Thêm suppression:**
  1. Vào menu **Chặn cảnh báo giả (False-Positive Suppression)**.
  2. Ô **Rule ID**: gõ hoặc chọn từ danh sách gợi ý (nạp từ các rule hiện có, VD `THREAT-001`, `SIGMA-*`).
  3. **Máy trạm**: chọn máy cụ thể, hoặc để **"(Tất cả máy)"** để áp dụng cho mọi máy.
  4. **Lý do** (khuyến nghị ghi rõ): VD "Cảnh báo giả - phần mềm nội bộ quét file lúc 2h sáng".
  5. Nhấn **Thêm suppression** → dòng mới xuất hiện trong danh sách bên dưới.

  **Xóa suppression:**
  - Trong danh sách, dòng muốn bỏ → nút **Xóa** (đỏ) → xác nhận. Rule được phép cảnh báo trở lại.

  **Bảng danh sách:** ID, Rule ID, Máy (trống = tất cả), Đường dẫn/Hash (nếu có), Lý do, Người tạo, Thời gian tạo.
  - Đếm tổng ở góc phải tiêu đề: *"Tổng cộng: N suppression"*.
  - Nút **Tải lại** 🔄 để cập nhật danh sách.

  *Lưu ý:* chặn theo rule + máy là chính xác nhất; chặn "tất cả máy" cho một rule phổ biến có thể che giấu tấn công thật — hãy giới hạn máy và ghi rõ lý do.

- **EN:** Used to **suppress repeated alerts** from a **rule** (optionally scoped to one **machine**) once it is confirmed as a false positive. A suppressed rule **no longer creates new alerts**.

  **Add a suppression:**
  1. Open the **Suppression Manager** menu.
  2. **Rule ID**: type or pick from the suggestion list (populated from existing rules, e.g. `THREAT-001`, `SIGMA-*`).
  3. **Machine**: choose a specific one, or leave **"(All machines)"** to apply everywhere.
  4. **Reason** (recommended): e.g. "False positive — internal software scans files at 2 AM".
  5. Click **Add suppression** — the row appears in the list below.

  **Delete a suppression:**
  - In the list, click the row's **Delete** (red) button → confirm. The rule may alert again.

  **List columns:** ID, Rule ID, Machine (blank = all), Path/Hash (if any), Reason, Created by, Created at.
  - Total counter in the header: *"Total: N suppression(s)"*.
  - **Reload** 🔄 refreshes the list.

  *Note:* suppressing by rule+machine is most precise; a global rule suppression for a common rule can hide real attacks — scope it and always state the reason.

### ⏳ Phê duyệt đang chờ (Pending Approvals)

- **VI:** Khi một rule cảnh báo có hành động **tự động yêu cầu phê duyệt** (cách ly mạng, khóa tài khoản, cách ly file), hệ thống sẽ đưa vào hàng đợi **chờ duyệt**.
  - **Cách 1 — Tự động:** cứ **30 giây** hệ thống kiểm tra; có yêu cầu mới → **cửa sổ phê duyệt tự hiện** kèm chi tiết: **Máy, Hành động, Rule, Mô tả**.
  - **Cách 2 — Thủ công:** badge đỏ **⏳ (số lượng)** trên menu **Bảng điều khiển** (góc trái sidebar) → nhấn vào → danh sách chờ hiện ra.
  - **Duyệt (✅):** cho phép thực thi hành động trên máy đó. **Từ chối (❌):** hủy — không thực thi.
  - Sau khi xử lý, hệ thống báo kết quả (đã duyệt / đã từ chối).
- **EN:** When an alert rule includes an action that **requires approval** (isolate network, lock account, quarantine file), it goes into the **pending queue**.
  - **Automatic:** every **30 seconds** the system checks; a new request **auto-opens the approval dialog** with details: **Machine, Action, Rule, Description**.
  - **Manual:** the red badge **⏳ (count)** on the **Dashboards** menu (left sidebar) → click it → pending list opens.
  - **Approve (✅):** allows the action to run on that machine. **Deny (❌):** cancels it.
  - The system then reports the result (approved / denied).


### Email Alerts (Cảnh báo Email)

- **VI:** 3 tab: **📧 Soạn Email**, **⚙ Cấu hình SMTP**, **📤 Mail đã gửi**.
  1. **Soạn Email**: chọn **mẫu cảnh báo** có sẵn (uptime 24h, brute force, malware, phishing, truy cập trái phép, lỗ hổng, kết nối độc hại, FIM, cảnh báo chung) → hệ thống tự điền tiêu đề/nội dung; chọn máy (tự lấy email người dùng), sửa nếu cần → **Gửi Email**. Biến có sẵn trong nội dung: `{hostname}`, `{user_name}`, `{employee_id}`.
  2. **Cấu hình SMTP**: thông tin **chỉ đọc** từ biến môi trường server (`GIAMSAT_SMTP_HOST/PORT/USER/PASS`); bấm **Gửi Email Test** để kiểm tra.
  3. **Mail đã gửi**: lịch sử gửi (thời gian, người nhận, tiêu đề, trạng thái); **Xóa tất cả** để dọn.
- **EN:** 3 tabs: **📧 Compose**, **⚙ SMTP Config**, **📤 Sent Mail**.
  1. **Compose**: pick a **template** (uptime 24h, brute force, malware, phishing, unauthorized access, vulnerability, suspicious connection, FIM, general) → subject/body auto-fill; pick a machine (user email auto-loaded), edit if needed → **Send Email**. Body variables: `{hostname}`, `{user_name}`, `{employee_id}`.
  2. **SMTP Config**: **read-only** values from server env (`GIAMSAT_SMTP_HOST/PORT/USER/PASS`); use **Send Test Email** to verify.
  3. **Sent Mail**: send history (time, recipient, subject, status); **Clear all** empties it.

### Tài sản (Assets)

- **VI:** Quản lý tài sản IT với 8 sub-tab: **Máy tính, Màn hình, Máy in, Điện thoại, Thiết bị mạng, Ngoại vi, Kho, Cảnh báo thay đổi**.
  - **Tự phát hiện:** nút **"🔍 Quét tự động"** → nhập dải IP (VD `192.168.1.0/24`) → server dò máy in (SNMP/JetDirect), điện thoại IP (VD Yealink), router/switch/AP → tự nạp vào kho nhãn **"Tự động"** (kèm serial, IP).
  - **Nhập tay:** tab **Kho** → **"＋ Thêm tài sản"** → loại, hãng, model, serial, mã số tài sản, trạng thái (Còn hàng/Đã cấp/Đang sửa/Thanh lý), người dùng, vị trí/phòng, ngày mua, bảo hành, giá, ghi chú. Sửa/xóa trực tiếp từng dòng.
  - **Adopt:** tài sản tự phát hiện có nút **"Đưa vào kho"** để gán người/vị trí/mã TS (chuyển từ Tự động → Nhập tay).
  - **Xuất Excel đa sheet:** `May tinh, Man hinh, May in, Dien thoai, Thiet bi mang, Ngoai vi, Kho`.
  - Theo dõi **thay đổi phần cứng** (đã xác nhận / chưa xử lý).
- **EN:** IT asset management with 8 sub-tabs: **Computers, Monitors, Printers, Phones, Network devices, Peripherals, Inventory, Changes**.
  - **Auto scan:** **"🔍 Auto scan"** → enter an IP range → discovers printers (SNMP/JetDirect), IP phones (e.g. Yealink), routers/switches/APs → added as **"Auto"** (with serial, IP).
  - **Manual:** **Inventory** tab → **"＋ Add asset"** → category, brand, model, serial, asset tag, status (in stock/assigned/in repair/disposed), assignee, location, purchase date, warranty, cost, notes; edit/delete inline.
  - **Adopt:** converts an auto-discovered asset into a manually-managed one (assign user/location/tag).
  - **Multi-sheet Excel export:** Computers, Monitors, Printers, Phones, Network, Peripherals, Inventory.
  - Tracks **hardware changes** (resolved/unresolved).

### 🆕 Nhật ký kiểm toán (Audit Log)

- **VI:** Xem toàn bộ **lịch sử hành động của người dùng** trên dashboard (ai làm gì, khi nào, từ IP nào) — phục vụ kiểm toán bảo mật và truy vết thao tác quản trị.
  1. Vào menu **Nhật ký kiểm toán (Audit Trail Log)**.
  2. Ô **Tìm kiếm** lọc nhanh theo **người dùng / hành động / chi tiết / IP** (lọc ngay khi gõ, không cần nhấn Enter).
  3. Chọn **số bản ghi** hiển thị (50 / 100 / 200 / 500) → danh sách tự tải lại.
  4. Bảng hiển thị: **Thời gian, Người dùng, Hành động** (badge), **Chi tiết, IP**.
  - *Mẹo:* các thao tác quan trọng (thêm/xóa suppression, tạo báo cáo, bật/tắt AI, xóa dashboard, cập nhật rule...) đều được ghi ở đây — dùng tab Audit để kiểm tra ai đã thay đổi cấu hình.
- **EN:** View the full **audit trail of user actions** on the dashboard (who did what, when, from which IP) — for security auditing and admin-activity forensics.
  1. Open the **Audit Trail Log** menu.
  2. The **Search** box filters live by **user / action / details / IP** (no Enter needed).
  3. Pick a **record limit** (50 / 100 / 200 / 500) — the list reloads.
  4. Columns: **Time, User, Action** (badge), **Details, IP**.
  - *Tip:* important actions (add/remove suppression, generate report, toggle AI, delete dashboard, update rules...) are all logged here — use it to verify who changed what.

### 🆕 Quản lý người dùng & phân quyền (User Management)

- **VI:** Tạo/xóa tài khoản và phân quyền trực tiếp trên dashboard (menu **👥 Quản lý người dùng** — **chỉ hiển thị với tài khoản Admin**).
  1. **Tạo tài khoản:** nhập **Tên đăng nhập** + **Mật khẩu** (tối thiểu 12 ký tự gồm chữ hoa, chữ thường, số, ký tự đặc biệt) → chọn **Vai trò** → **Tạo tài khoản**.
     - **Viewer (chỉ xem):** chỉ xem dữ liệu, không gửi lệnh, không đổi cấu hình — *vai trò mặc định (an toàn nhất)*.
     - **Operator (điều hành):** xem + gửi hành động phản hồi, lệnh SSH, dùng AI.
     - **Admin (toàn quyền):** mọi thứ kể cả quản lý người dùng, xóa dữ liệu, bật/tắt AI.
  2. **Đổi vai trò:** ở bảng danh sách, chọn vai trò mới trong dropdown của từng tài khoản.
  3. **Đặt lại mật khẩu:** nút **Đặt lại mật khẩu** → nhập mật khẩu mới → người dùng sẽ **phải đổi mật khẩu** ở lần đăng nhập kế tiếp.
  4. **Xóa tài khoản:** nút **Xóa** → xác nhận. Tài khoản `admin` **không thể xóa hoặc hạ quyền** (bảo vệ chống khóa hệ thống).
  5. **Đổi mật khẩu của tôi + Đăng xuất:** góc trên phải → nút 👤 tên tài khoản → **Đổi mật khẩu** (nhập mật khẩu cũ + mới + xác nhận) hoặc **Đăng xuất**.
  - *Bảo mật:* mọi thao tác (tạo/xóa/đổi vai trò/reset mật khẩu) đều được ghi vào **Nhật ký kiểm toán**.
- **EN:** Create/delete accounts and assign roles right in the dashboard (menu **👥 User Management** — **only visible to Admin accounts**).
  1. **Add a user:** enter **Username** + **Password** (min 12 chars with upper, lower, digit, special) → pick **Role** → **Add User**.
     - **Viewer (read-only):** view-only, no commands, no config — *default role (safest)*.
     - **Operator (operate):** view + response actions, SSH commands, AI.
     - **Admin (full access):** everything including user management, data cleanup, AI toggle.
  2. **Change role:** in the user list, pick the new role in each account's dropdown.
  3. **Reset password:** click **Reset Password** → enter a new password → the user **must change it** at their next login.
  4. **Delete account:** click **Delete** → confirm. The `admin` account **cannot be deleted or demoted** (prevents locking yourself out).
  5. **Change my password + Logout:** top-right 👤 button → **Change Password** (old + new + confirm) or **Logout**.
  - *Security:* all actions (create/delete/role/reset) are recorded in the **Audit Log**.

---

## NHÓM 4: HỆ THỐNG — SYSTEM

### Dọn dẹp dữ liệu (Cleanup)

- **VI:** Giải phóng dung lượng cơ sở dữ liệu.
  1. Vào menu **Dọn dẹp dữ liệu cũ**.
  2. Xem **thống kê dung lượng** từng bảng (events, fim, syslog, response, network...).
  3. Chọn các bảng cần dọn và nhấn **Dọn dẹp** (xóa dữ liệu cũ hơn số ngày cấu hình, mặc định giữ lại dữ liệu liên quan threat).
  - *Cảnh báo:* dữ liệu đã xóa **không thể khôi phục**. Nên chạy sau khi đã xuất/lưu trữ báo cáo.
- **EN:** Free up database space.
  1. Open **Cleanup old data**.
  2. Review **size stats** per table (events, fim, syslog, response, network...).
  3. Select tables and click **Clean** (removes data older than the retention days; threat-related data is kept by default).
  - *Warning:* deleted data **cannot be recovered**. Run it after exporting/archiving reports.

### 🆕 Báo Cáo Tài Sản (Asset Report)

- **VI:** Xuất **báo cáo chi tiết cấu hình máy trạm** (phần cứng, phần mềm đã cài, thông tin người dùng) dạng **Excel (.xlsx)** hoặc **HTML (.html)** — hồ sơ quản lý tài sản/máy trạm.
  1. Menu sidebar → **📊 Báo Cáo Tài Sản** (nằm ngay dưới mục Tổng quan).
  2. Chọn **Định dạng** (Excel hoặc HTML).
  3. Tích/bỏ các mục muốn xuất: **Cấu hình máy / Danh sách phần mềm / Thông tin người dùng**.
  4. Nhấn **Xuất Báo Cáo Tài Sản** → file tự tải về (VD `GIAM-SAT_Config_Report.xlsx`).
  - *Mẹo:* thẻ **"📊 Báo Cáo Tài Sản"** trên trang Tổng quan vẫn mở cửa sổ cấu hình tương tự — đường tắt nhanh.
- **EN:** Export a **detailed machine configuration report** (hardware, installed software, user info) as **Excel (.xlsx)** or **HTML (.html)** — for asset/machine records.
  1. Sidebar → **📊 Asset Report** (right below Overview).
  2. Pick **Format** (Excel or HTML).
  3. Tick the sections to include: **Machine config / Software list / User info**.
  4. Click **Export Asset Report** → the file downloads automatically (e.g. `GIAM-SAT_Config_Report.xlsx`).
  - *Tip:* the **"📊 Asset Report"** card on Overview opens the same configuration dialog as a shortcut.

### 🆕 Báo Cáo Tổng Hợp (Summary Report)

- **VI:** Xuất **báo cáo HTML tổng hợp toàn hệ thống** (máy, sự kiện, mối đe dọa, lỗ hổng, SCA, YARA...) — cho báo cáo cuối ngày/tuần hoặc lưu hồ sơ.
  1. Menu sidebar → **📊 Báo Cáo Tổng Hợp** (nằm ngay dưới Báo Cáo Tài Sản).
  2. Nhấn **📅 Báo cáo ngày** (daily) hoặc **📅 Báo cáo tuần** (weekly).
  3. Xác nhận → server tạo file HTML trong vài giây → trình duyệt **tự tải về** (VD `giamsat_report_daily_20260820_110423.html`).
  4. Mở bằng trình duyệt: báo cáo có cấu trúc (tổng quan, mối đe dọa, lỗ hổng, khuyến nghị) — sẵn sàng in PDF/chia sẻ.
  - *Phân biệt:* **Báo Cáo Tài Sản** = chi tiết 1 máy; **Báo Cáo Tổng Hợp** = toàn hệ thống.
- **EN:** Generate an automated **system-wide summary HTML report** (machines, events, threats, vulnerabilities, SCA, YARA...) — for end-of-day/week reporting or records.
  1. Sidebar → **📊 Summary Report** (right below Asset Report).
  2. Click **📅 Daily report** or **📅 Weekly report**.
  3. Confirm → the server builds the HTML file in seconds → the browser **downloads it automatically** (e.g. `giamsat_report_daily_20260820_110423.html`).
  4. Open it in a browser: structured report (overview, threats, vulnerabilities, recommendations) — ready to print to PDF or share.
  - *Difference:* **Asset Report** = one machine's detail; **Summary Report** = the whole system.

---

## Bảng quyền nhanh — Quick permission reference

- **VI:** Một số hành động nhạy cảm yêu cầu quyền nâng cao (xem/quản lý tại menu **👥 Quản lý người dùng** — chỉ admin):
  - **Viewer:** xem tất cả (không gửi lệnh điều khiển, không đổi cấu hình).
  - **Operator (+):** gửi hành động phản hồi, gửi lệnh SSH, dùng AI.
  - **Admin:** mọi thứ — quản lý rule, suppression, người dùng, xóa dữ liệu, bật/tắt AI, xóa dashboard, cấu hình.
- **EN:** Some sensitive actions require elevated permissions (view/manage them under **👥 User Management** — admin only):
  - **Viewer:** read-only (no response/control commands, no config changes).
  - **Operator (+):** send response actions, SSH commands, use AI.
  - **Admin:** everything — rules, suppression, users, data cleanup, AI toggle, dashboard delete, config.

---

*Mẹo cuối: mọi menu đều hỗ trợ tìm kiếm, lọc, sắp xếp và cập nhật thời gian thực (SSE). Nếu một thao tác "không chạy", kiểm tra tab **Nhật ký kiểm toán** xem lệnh đã được ghi nhận chưa.*
*Final tip: every menu supports search, filter, sorting and real-time updates (SSE). If an action "does nothing", check the **Audit Log** to see whether the command was recorded.*

