# HƯỚNG DẪN DASHBOARD GIAM-SAT — SÁCH CHI TIẾT CHO NGƯỜI MỚI

> **Dành cho ai?** Sinh viên / nhân viên SOC mới bước vào hệ thống giám sát an ninh mạng.
> Mỗi mục trong tài liệu trả lời đúng 5 câu hỏi:
> **(1)** Menu này để làm gì → **(2)** Dữ liệu lấy từ đâu (nút bấm → API → hàm Python → bảng DB) → **(3)** Vì sao lại CÓ dòng dữ liệu / cảnh báo đó (nguyên lý) → **(4)** Người dùng thao tác thế nào (từng bước) → **(5)** Ví dụ THẬT.
>
> **Các con số trong tài liệu là số thật** đo ngày **2026-10-01** trên máy test (`D:\test`,
> backend PostgreSQL, database `giamsat`, 2 máy trạm: `IT-YSNT`, `ADMINZ`, 1 router syslog `Vigor`).
> Bạn có thể tự kiểm chứng lại bằng các lệnh ở Phụ lục A.
>
> *English: a deep, beginner-friendly walkthrough of every GIAM-SAT dashboard menu — purpose,
> data provenance (button → API → Python function → DB table), why an alert exists, exact steps,
> and real examples from the live test deployment.*

## Mục lục

| # | Chương | Dành cho ai |
|---|---|---|
| 0 | Cách đọc tài liệu này | Tất cả |
| 1 | Hệ thống gồm những gì, dữ liệu đi đường nào | Muốn hiểu kiến trúc |
| 2 | **Vì sao lại có cảnh báo?** (rule, anomaly, heartbeat, scan, IOC) | Muốn hiểu nguyên lý phát hiện |
| 3 | **Chi tiết từng menu** (39 menu, mỗi menu 1 mục) | Người dùng hằng ngày |
| 4 | Năm câu chuyện điều tra thật (walkthrough có số liệu) | Học cách điều tra |
| 5 | “Không thấy dữ liệu” — gỡ lỗi theo 7 lớp + bảng chẩn đoán | Khi hệ thống im lặng |
| 6 | Vận hành & bảo trì (dung lượng, partition, rollup, backup) | Quản trị viên |
| A–E | Phụ lục: bảng API, thuật ngữ, bài tập 7 ngày, FAQ, checklist báo lỗi | Tất cả |

---

## Chương 0 — Đọc tài liệu này thế nào (5 phút)

| Bạn đang cần… | Đọc mục |
|---|---|
| Biết hệ thống có những thành phần nào | 1.1 – 1.3 |
| Hiểu “tại sao máy này lại sinh cảnh báo kia” | Chương 2 (2.1–2.5) |
| Dùng một menu cụ thể (ví dụ tab Đe dọa) | Chương 3 — tra theo đúng tên menu trên thanh trái |
| Tập điều tra như thật | Chương 4 (4 câu chuyện có số liệu) |
| Dashboard quay mãi / trắng / không thấy dữ liệu | Chương 5 |
| Máy trạm không gửi log nữa | 5.2 (bảng triệu chứng → nguyên nhân → cách sửa) |
| Muốn hiểu các bảng dữ liệu | 1.3 + Phụ lục B (thuật ngữ) |

**Ba quy ước viết trong tài liệu:**

- `code` = tên file/tham số thật, bạn mở được trong repo.
- **Đậm** = tên nút / tên cột bạn nhìn thấy trên màn hình.
- `→` = luồng nhân–quả: *cái này xảy ra ⇒ cái kia xuất hiện*.

---

## Chương 1 — Hệ thống gồm những gì, dữ liệu đi đường nào

### 1.1 Sơ đồ luồng dữ liệu (nhìn 1 lần là hiểu cả hệ thống)

```
  (A) MÁY TRẠM                      (B) CỔNG VÀO                    (C) SERVER XỬ LÝ                 (D) LƯU TRỮ        (E) HIỂN THỊ
  ─────────────────                 ────────────                    ────────────────                 ───────────        ───────────
  Windows Event Log ─┐
  Sysmon (proc/net) ─┤                                                                                    
  File Integrity  ───┤  agent/event_collector.py                                                                   
  YARA/AV/Yara scan ─┤  agent/fim_collector.py        TCP 6666 (TLS + PSK)                                     
  Kiểm tra bản vá ───┤  agent/behavior_collector.py ─────► tcp_server.py ───┐                                       
  RAM (memory scan) ─┤  agent/correlation_engine.py                        │                                        
  Auditpol/hardening┘  (2062 rule chạy TẠI ĐÂY)                              ▼                                        
                                                        ┌──── event_queue.py (hàng đợi) ───► event_worker.py ◄────────┐   
  Router/Switch ─── UDP 514 syslog ──► syslog_server.py ─┤                                    │                        │   
  Router/Switch ─── UDP 2055 netflow ► netflow_collector.py                                    ▼                        │   
  Cảnh báo email/n8n ◄── daily_digest.py / email_alerts.py   anomaly_detector.py ──► INSERT INTO ...                       
                                                                     │                        │                        
                                                                     ▼                        ▼                        
                                                        correlation_engine_server.py   PostgreSQL `giamsat` (49 bảng)   
                                                        network_alerting.py            → events 123.864 dòng / 172 MB   
                                                        network_baseline.py            → network_traffic 159.026 / 116 MB 
                                                        server_monitor.py (tự giám sát) → syslog 47.017 / 34 MB           
                                                                                          → threat_alerts 199 dòng        
                                                                                                │                        
                                                                                                ▼                        
  Trình duyệt (Chrome)  ◄──── HTTP :5000 ──── server_core.py + server/api/*.py (REST/JSON) ──── (đọc DB)                  
  static/js/dashboard.js + modules/*.js (vẽ bảng, biểu đồ, SSE realtime) ◄────────────────────────────────────────────────────┘
```

**Đọc sơ đồ theo 3 câu:**

1. *Cái gì sinh ra dữ liệu?* Phần lớn là **agent** cài trên máy Windows (thu log, tự chạy rule)
   và **thiết bị mạng** (router Vigor gửi syslog, switch gửi NetFlow).
2. *Cái gì biến dữ liệu thành cảnh báo?* `event_worker.py` (xử lý từng message),
   `anomaly_detector.py` (bất thường thống kê), `correlation_engine_server.py` (tương quan liên máy),
   `network_alerting.py`, `server_monitor.py` (tự bảo vệ server).
3. *Cái gì cho bạn nhìn thấy?* Flask REST API (`server/api/*.py`) đọc PostgreSQL → trả JSON →
   `static/js/dashboard.js` (và các module `static/js/modules/*.js`) vẽ ra HTML.

> **EN:** Agents detect locally and push over TLS/PSK; the server also ingests syslog (UDP 514),
> NetFlow (UDP 2055) and correlates; everything lands in PostgreSQL and is served as JSON to the
> dashboard JS. No agent-side data ever goes straight to the browser.
### 1.2 Bảng thành phần — file code nào làm việc gì

| # | Thành phần | File / hàm chính | Cổng, cơ chế | Nhiệm vụ tóm gọn |
|---|---|---|---|---|
| 1 | Agent thu log | `agent/event_collector.py`, `agent/agent_service.py` | Đọc Windows Event Log API | Gom event theo batch, gắn `machine_id`, gửi về server |
| 2 | Agent thu bổ trợ | `agent/fim_collector.py`, `agent/behavior_collector.py`, `agent/hw_collector.py`, `agent/linux_auditd_collector.py` | Cùng kênh agent | FIM (file thay đổi), hành vi, phần cứng, auditors |
| 3 | Agent tự phát hiện | `agent/correlation_engine.py` + `server/rules/correlation_rules.yaml` (**2.062 rule**) | Chạy LOCAL trên từng máy | Máy tự khớp rule → gửi thẳng cảnh báo `THREAT-*` |
| 4 | Kênh vận chuyển agent → server | `tcp_server.py` (mặc định **TCP 6666**, TLS + PSK) | TLS | Xác thực agent, nhận event/heartbeat/alert, đẩy vào hàng đợi |
| 5 | Chống flood | `rate_limiter.py` | — | Giới hạn kết nối/sự kiện theo IP, chống DoS |
| 6 | Hàng đợi & xử lý | `event_queue.py` → `event_worker.py` | Trong RAM | Phân loại message, ghi DB, sinh cảnh báo |
| 7 | Phát hiện bất thường | `anomaly_detector.py` | z-score > 3, điểm ≥ 50 | Sinh `ANOMALY-*` (first-time, thống kê) |
| 8 | Tương quan liên máy | `correlation_engine_server.py` (**11 rule `CROSS-*`**) | Định kỳ | Ghép nhiều máy/nhiều rule → 1 cảnh báo kill-chain |
| 9 | Giám sát thiết bị mạng | `syslog_server.py` (UDP **514**, fallback 1514), `syslog_tcp_server.py` (**6514**), `netflow_collector.py` (**UDP 2055**) | UDP/TCP | Nhận log router, luồng NetFlow |
| 10 | Cảnh báo mạng | `network_alerting.py` (`NET-*`), `network_baseline.py` (`BASELINE-DRIFT`) | Định kỳ | Phát hiện DNS/port/C2 bất thường so với nền tảng |
| 11 | Danh sách đen | `watchlist_matcher.py` (`IOC-*`), `ioc_sweeper.py` | Khi có event / theo lệnh | Khớp IOC tĩnh + sai khiến agent quét IOC |
| 12 | Tự bảo vệ server | `server_monitor.py` (`SRV-SCAN-001/002`) | Đọc log nginx/truy cập | Phát hiện quét endpoint (404 hàng loạt) |
| 13 | Dead-man switch | `event_worker.py::_deadman_checker` (`HEARTBEAT-001`, timeout **300s**) | Thread nền | Máy mất liên lạc → cảnh báo CRITICAL |
| 14 | Lưu trữ | `db_postgres.py` (PostgreSQL) / `db_manager.py` (SQLite) | SQL | Cùng API `insert_*`/`get_*`, chọn bằng `GIAMSAT_DB_BACKEND` |
| 15 | Truy vấn hợp nhất | `search_engine.py` | SQL động | DSL tìm kiếm đa nguồn, Entity-360, facet |
| 16 | Điều tra & bằng chứng | `forensics.py` (cây tiến trình, gói bằng chứng), `api/api_forensics.py` | SQL + HTML | Dựng timeline ±15 phút quanh một sự kiện |
| 17 | Vận hành đội máy | `fleet.py`, `fleet_store.py` | SQL | Rollout theo đợt, sức khỏe, nguồn bị từ chối |
| 18 | Dung lượng | `partitioning.py`, `tools/partition_events.py` | DDL | Chia bảng theo tháng, DROP nhanh, rollup `daily_stats` |
| 19 | REST API | `server/api/*.py` (40 file) | HTTP :5000 | Mọi thứ dashboard gọi đều đi qua đây (đều có `check_auth`) |
| 20 | Giao diện | `server/templates/index.html`, `static/js/dashboard.js`, `static/js/modules/*.js` | Trình duyệt | Vẽ bảng/biểu đồ, SSE realtime, song ngữ `i18n.js` |
| 21 | Báo cáo & thông báo | `reporting_engine.py`, `daily_digest.py`, `email_alerts.py`, `alerting_engine.py` | SMTP/Telegram | Xuất báo cáo, gửi mail/Telegram theo mức |
| 22 | Trợ lý AI | `ai_providers.py` (+ `/api/assistant`) | DeepSeek API | Hỏi đáp, tóm tắt sự kiện (tắt bằng `GIAMSAT_DISABLE_AI`) |
| 23 | Định vị địa lý | `geoip_lookup.py` | GeoLite2 `.mmdb` | Gắn quốc gia cho IP nước ngoài |
| 24 | Người dùng & phiên | `auth_manager.py`, `users.json` | — | Đăng nhập, phân quyền 4 mức, 2FA |
| 25 | Nhiều máy chủ | `cluster_manager.py`, `cluster_config.json` | — | Tab Cluster (nhiều instance chung DB) |

> **EN:** One table per moving part: agents collect + detect locally, TCP 6666 (TLS/PSK) carries data,
> `event_worker.py`/`anomaly_detector.py`/`*_alerting.py` create alerts, PostgreSQL stores,
> `server/api/*.py` serves JSON to `dashboard.js`.

### 1.3 Dữ liệu nằm ở đâu — nhớ 14 bảng là đủ dùng

Số dòng là số **thật** đo 2026-10-01 trên `D:\test` (lệnh xem ở Phụ lục A).

| Bảng | Chứa gì (1 dòng = ?) | Do code nào ghi | Xem ở menu | Số dòng |
|---|---|---|---|---|
| `threat_alerts` | **1 cảnh báo** (rule, mức, mô tả) | `db.insert_threat_alert()` — gọi từ `event_worker.py`, `network_alerting.py`, `server_monitor.py`, `network_baseline.py` | **Đe dọa**, Cases, Tổng quan | 199 |
| `events` | **1 dòng Windows Event** | `tcp_server.py` → `event_worker.py` → `db.insert_event()` | **Nhật ký sự kiện** | 123.864 |
| `network_traffic` | 1 phiên kết nối mạng của agent (5-tuple) | agent → `event_worker.py` | **Mạng** | 159.026 |
| `syslog` | 1 dòng log router/thiết bị | `syslog_server.py`, `syslog_tcp_server.py` | **Syslog** | 47.017 |
| `fim_events` | 1 thay đổi file (`FILE_CREATED/MODIFIED/DELETED`) | `fim_collector.py` → `insert_fim_event()` | **FIM** | 1.744 |
| `sca_events` | 1 kết quả kiểm tra cấu hình (`PASS/FAIL/WARN`) | agent SCA | **SCA** | 1.379 |
| `yara_alerts` | 1 kết quả quét YARA | agent YARA | **YARA** | 214 |
| `vuln_alerts` | 1 lỗ hổng phần mềm / CVE | agent inventory | **Lỗ hổng** | 0 (chưa có) |
| `sysmon_events` | Sự kiện Sysmon / kết quả quét RAM (`memory_scan_event`) | `get_sysmon_events()` | **Sysmon**, **Bộ nhớ** | 1.170 |
| `heartbeats` | 1 nhịp tim của agent | `tcp_server.py` (message heartbeat) | Tổng quan, Coverage | 25.565 |
| `machines` | 1 máy trạm đã đăng ký | `insert/update_machine()` khi agent đăng ký | Danh sách máy trái | 2 |
| `daily_stats` | Tổng hợp **1 ngày × 1 máy** | `partitioning.py` → `/api/health/storage/rollup` | Báo cáo, biểu đồ | 26 |
| `cases` / `case_evidence` | Hồ sơ điều tra / gói bằng chứng | `api/api_incident.py`, `forensics.py` | **Cases**, tab Điều tra | 2 / 2 |
| `ingest_anomalies` | Nguồn bị **từ chối** (sai PSK, flood…) | `tcp_server._note_ingest()` → `fleet_store.py` | Coverage → “nguồn bị từ chối” | 0 (đã xử lý) |
| `update_rollouts`, `update_rollout_targets` | Đợt cập nhật agent + từng máy trong đợt | `fleet_store.py` | Cập nhật Agent, Coverage | 1 / 1 |
| `saved_searches`, `process_tree_edges`, `audit_log`, `alert_suppression` | Truy vấn đã lưu, cạnh cây tiến trình, nhật ký thao tác, luật chặn FP | `search_engine.py`, `forensics.py`, `db.insert_audit_log()`, `api_suppression.py` | Điều tra hợp nhất / Kiểm toán / Chặn FP | 0 / 0 / **165** / 0 |

> **Ba bảng bạn sẽ hỏi nhiều nhất:** `threat_alerts` (vì sao? xem 2.1–2.5), `events`
> (máy này làm gì lúc đó?), `network_traffic` (nó nói chuyện với ai?).
> `mv_dashboard_stats`, `mv_dashboard_machines` là **view vật liệu hoá** (materialized view) —
> bảng “đóng băng” để vẽ dashboard cho nhanh; muốn số mới nhất phải refresh.
### 1.4 Từ một dòng log đến màn hình (ví dụ số thật)

Giả sử bạn thấy trên tab **Nhật ký sự kiện** dòng `event_id = 4688` (tạo tiến trình).
Đường đi đầy đủ của nó:

1. **Windows ghi event 4688** vào Security log của `IT-YSNT`.
2. `agent/event_collector.py` đọc log, chọn các trường (`event_id`, `computer`, `user`,
   `description`, `raw_data`), gắn `machine_id = f196aff3`, gửi batch qua **TCP 6666 (TLS)**.
3. `agent/correlation_engine.py` **chạy 2.062 rule ngay tại máy**. Nếu khớp (ví dụ rule
   `THREAT-044` — tiến trình chạy từ thư mục lạ), agent gửi thêm 1 message loại **alert**.
4. `tcp_server.py` xác thực PSK → `event_queue.py` → `event_worker.py`.
5. `event_worker.py` ghi `events` (`db.insert_event()`, chống trùng bằng `dedup_key`) và,
   nếu là alert, ghi `threat_alerts` (`db.insert_threat_alert()`).
   Đồng thời nó **đẩy sự kiện vào `anomaly_detector.py`** để tính điểm bất thường.
6. Trình duyệt của bạn: tab **Nhật ký sự kiện** gọi `GET /api/events` →
   `server/api/api_events.py` → `db.get_events()` → `SELECT ... FROM events` → JSON → `dashboard.js` vẽ bảng.
   Nếu bạn mở tab **Đe dọa**, `GET /api/threats` → `db.get_threat_alerts()` → đọc `threat_alerts`.

**Vì sao điều này quan trọng?** Khi dashboard “không thấy dữ liệu”, bạn gỡ lỗi đúng theo thứ tự này:
agent có chạy → có gửi (PSK/TLS) → server có nhận (`ingest_anomalies`) → có ghi DB (`COUNT(*)`)
→ API có trả (`curl /api/events`) → JS có vẽ (F12 Console). Sai ở bước nào thì sửa ở bước đó.

### 1.5 Tài khoản, quyền và cấu hình

- **Đăng nhập**: mở `http://<ip-server>:5000`, tài khoản tạo trong `server/.env`
  (`GIAMSAT_ADMIN_USER`, `GIAMSAT_ADMIN_PASSWORD`) → lần đầu hệ thống bắt **đổi mật khẩu**.
- **Bốn mức quyền** (menu **Người dùng**): `admin` (toàn quyền), `analyst` (xem + xử lý cảnh báo),
  `viewer` (chỉ xem), `command` (được gửi lệnh xuống máy). Server kiểm tra bằng `check_auth("api" | "command" | …)`
  ở **mọi** route — nên nếu bạn không thấy tab hoặc bị `403`, hầu như luôn là **thiếu quyền**, không phải lỗi hệ thống.
- **File cấu hình quan trọng**:

| File | Nội dung | Sửa khi nào |
|---|---|---|
| `server/.env` | DB, PSK agent (`GIAMSAT_AGENT_PSK`), SMTP, Tailscale, admin | Đổi mật khẩu/đổi DB/thêm mail |
| `server/rules/correlation_rules.yaml` | 2.062 rule phía agent | Thêm rule mới (màn hình **Quản lý Rules**) |
| `server/version.txt`, `agent/agent_version.txt` | Phiên bản server/agent | Trước khi phát hành bản mới |
| `C:\ProgramData\GIAM-SAT\Agent\agent_config.json` | PSK, địa chỉ server **trên máy trạm** | Khi máy trạm bị “từ chối” |
| `cluster_config.json` | Danh sách node cluster | Khi chạy nhiều server |

> **EN:** Follow one log end-to-end: Windows → agent → TLS 6666 → queue → worker → PostgreSQL →
> REST API → dashboard.js. Debug in that same order.
---

## Chương 2 — Vì sao lại có cảnh báo? (nguyên lý phát hiện)

Có **6 nguồn sinh cảnh báo** trong `threat_alerts`. Nhìn vào `rule_id` của một cảnh báo là biết ngay nó thuộc loại nào:

| Tiền tố `rule_id` | Sinh bởi | Ý nghĩa | Ví dụ thật trong DB |
|---|---|---|---|
| `THREAT-*` | Agent (`agent/correlation_engine.py` + 2.062 rule YAML) | Khớp mẫu tấn công đã biết theo MITRE | `THREAT-044` (8 cảnh báo) |
| `ANOMALY-*` | `event_worker.py` → `anomaly_detector.py` | Hành vi/khối lượng lạ, không cần chữ ký | `ANOMALY-FIRSTTIME-FIRST-TIME-PROCESS` (19) |
| `CROSS-*` | `correlation_engine_server.py` (11 rule) | Tương quan **liên máy** (kill-chain) | `CROSS-*` |
| `NET-*` | `network_alerting.py` | Bất thường mạng (DNS/port/C2) | `NET-*` |
| `HEARTBEAT-001` | `event_worker.py::_deadman_checker` | Máy mất liên lạc > **300s** | 15 cảnh báo CRITICAL |
| `SRV-SCAN-*`, `BASELINE-DRIFT`, `IOC-*` | `server_monitor.py`, `network_baseline.py`, `watchlist_matcher.py` | Server bị quét / nền tảng mạng phình to / khớp IOC | `SRV-SCAN-002` (36) |

### 2.1 Loại 1 — Rule chạy TẠI MÁY TRẠM (`THREAT-*`)

Đây là loại bạn gặp nhiều nhất. Rule nằm trong `server/rules/correlation_rules.yaml`, nhưng **được đẩy xuống từng agent** và chạy ở đó (dòng đầu file ghi rõ: *DETECTION POINT: AGENT-SIDE*).

**Một rule thật (THREAT-001, nguyên văn):**

```yaml
- id: THREAT-001
  name: Brute Force Attack Detected fast
  mitre: T1110s                 # mã kỹ thuật MITRE ATT&CK
  tactic: Credential Access     # chiến thuật của kẻ tấn công
  severity: HIGH                # mức → quyết định có gửi Telegram/Email hay không
  description: Multiple failed login attempts (Event ID 4625) from same source within 60 seconds
  conditions:
  - type: windows_event         # loại sự kiện cần soi
    event_id: '4625'            # 4625 = đăng nhập thất bại
    group_by: source_ip         # gom nhóm theo từng IP nguồn riêng biệt
    threshold: 10               # ≥ 10 lần …
    within_seconds: 30          # … trong 30 giây
```

**Đọc rule này ra tiếng người:** *“Nếu trong 30 giây có ≥ 10 sự kiện 4625 đến TỪ CÙNG MỘT `source_ip` thì đó là Brute Force.”*

**Bốn thành phần bạn cần hiểu:**

1. `conditions` — điều kiện khớp. Ngoài `event_id` còn có:
   - `description_contains: ["lsass.exe"]` → nội dung sự kiện phải chứa chuỗi này
     (rule `THREAT-009` — *Credential Dumping – LSASS Access*, `severity: CRITICAL`, MITRE `T1003.001`).
   - `subtype: Sysmon` → lấy từ Sysmon (ví dụ `THREAT-075` — *Timestomping*, EID 2 + CreationUtcTime sai lệch).
   - `event_id: ['7045','4697']` → danh sách ID (rule cài service lạ).
2. `threshold` + `within_seconds` + `group_by` — **bộ đếm theo cửa sổ thời gian**. Đây là lý do vì sao
   bạn thấy **1** cảnh báo chứ không phải 10: agent đếm rồi mới bắn, chứ không bắn từng dòng.
3. `severity` + `mitre` + `tactic` — dùng để (a) tô màu/sắp xếp trên tab **Đe dọa**,
   (b) gửi thông báo (`alerting_engine.py` chỉ gửi Telegram/Email từ mức HIGH trở lên),
   (c) vẽ ma trận **MITRE ATT&CK**.
4. `id` — chính là cột `rule_id` bạn thấy trên dashboard. Có `rule_id` = tra được ngay file rule.

**Vì sao chạy ở agent mà không chạy ở server?** (chép từ header file rule)

- Mỗi máy chỉ cần soi log **của chính nó** → nhẹ, nhanh, chạy được cả khi mất mạng.
- Nếu server chạy lại 2.062 rule đó → **mỗi cảnh báo bị bắn 2 lần** và dễ tạo bão cảnh báo giả.
- Server chỉ giữ **11 rule `CROSS-*`** lo việc tương quan giữa nhiều máy (việc agent không thể làm).

**Ví dụ thật — và một “bẫy” kinh điển:**

```
rule_id   THREAT-044   severity HIGH   hostname ADMINZ
rule_name Suspicious Process NOT From System32
mô tả     Process created from non-standard path (NOT System32 or Program Files)
timestamp 2026-09-29 18:30:34
```

Vì sao có? Agent thấy một tiến trình được tạo từ đường dẫn không thuộc `System32`/`Program Files`.
Đây là **hành vi hợp lệ với phần mềm tự viết / trình cài đặt** (ví dụ agent GIAM-SAT chạy từ `D:\dist\`),
nhưng cũng đúng với malware chạy từ `%TEMP%`. ⇒ **Kết luận mẫu cho sinh viên:** cảnh báo nói *“có chuyện bất thường”*,
**không** nói *“chắc chắn là virus”*. Việc của bạn là kiểm chứng bằng dữ liệu khác (tab Nhật ký,
Điều tra hợp nhất, Entity-360) rồi đổi **Trạng thái** sang `resolved` hoặc `false_positive`.
### 2.2 Loại 2 — Rule tương quan LIÊN MÁY (`CROSS-*`, chạy ở server)

Một máy không thể biết “máy khác cũng đang bị tấn công cùng lúc”. Vì vậy 10 nhóm rule sau nằm trong
`server/correlation_engine_server.py` và chạy định kỳ trên server, đọc dữ liệu **của tất cả** máy:

| `rule_id` | Tên | Kịch bản phát hiện |
|---|---|---|
| `CROSS-001` | Lateral Movement – Brute Force Followed by Successful Logon | Brute force trên máy A, **sau đó** đăng nhập thành công trên máy B từ cùng IP nguồn |
| `CROSS-002` | Lateral Movement – PsExec Detected Across Machines | PsExec cài service trên A, rồi có logon mới trên B từ IP của A |
| `CROSS-003` | Lateral Movement – Remote Desktop Spread | RDP (logon Type 10) trên nhiều máy từ cùng nguồn trong thời gian ngắn |
| `CROSS-004` | Credential Theft Cascade – LSASS Dump Then Lateral Spread | Dump LSASS ở A, sau đó nhiều máy khác đăng nhập bằng cùng tài khoản |
| `CROSS-005` | Pass-the-Hash Attack Across Machines | Logon NTLM (Type 3) xuất hiện lần lượt trên B, C… |
| `CROSS-006` | Privilege Escalation Then Lateral Spread | Đặc quyền tăng ở A → logon admin ở B |
| `CROSS-007` | Coordinated C2 Communication Across Hosts | Nhiều máy cùng kết nối **một IP ngoài** (hạ tầng C2) |
| `CROSS-008` | Ransomware Behavior Spreading Across Hosts | Sửa file hàng loạt trên nhiều máy trong thời gian ngắn |
| `CROSS-009` | Suspicious Service Creation Across Hosts | Cài service mới trên nhiều máy từ cùng IP ngoài / cùng user |
| `CROSS-010` | Multi-Host Data Exfiltration | Nhiều máy cùng đẩy dữ liệu lớn ra một IP ngoài |

**Vì sao phải tương quan?** Riêng lẻ, mỗi sự kiện có thể vô hại (một người đăng nhập RDP là chuyện thường).
Ghép **thời gian + nguồn + nhiều máy** lại thì đó là *điểm mấu chốt của tấn công lan truyền*.
Bạn thấy cảnh báo `CROSS-*` ⇒ **ưu tiên xử lý cao nhất**, vì nó là cảnh báo tổng hợp nhiều bằng chứng.

### 2.3 Loại 3 — Bất thường mạng (`NET-*`, `network_alerting.py`)

Ba rule mạng, mỗi rule có **thời gian chờ (cooldown)** để không bắn lặp liên tục:

| `rule_id` | Phát hiện gì | Cách phát hiện (dễ hiểu) | Cooldown |
|---|---|---|---|
| `NET-BEACON` | Máy “gọi về nhà” định kỳ (C2 beacon) | Tính **hệ số biến thiên** của khoảng cách giữa các lần kết nối; nếu quá đều đặn (`BEACON_MAX_CV`) thì là máy móc, không phải người | 6 giờ |
| `NET-FIRST` | Lần đầu thấy điểm đích mới | Đích chưa từng xuất hiện trong lịch sử máy đó | 24 giờ |
| `NET-ODD` | Kết nối tới cổng “lạ” | Cổng hiếm/rủi ro cao đối với máy trạm | 24 giờ |

**Ví dụ đọc số:** công cụ hợp pháp (Windows Update) kết nối lệch giờ liên tục → `CV` cao → **không** báo.
Malware hẹn giờ 60 giây/lần → `CV` rất thấp → **báo `NET-BEACON`**.
*Lưu ý dữ liệu thật:* `network_traffic` của bạn có 85.312 kết nối tới cổng **443 (HTTPS)** — đa số là bình thường,
vì vậy `NET-*` **không** bắn theo khối lượng, mà bắn theo **hình dạng thời gian/điểm đích mới**.

### 2.4 Loại 4 — Bất thường không cần chữ ký (`ANOMALY-*`, `anomaly_detector.py`)

File này mở đầu bằng câu: *“Phát hiện zero-day và bất thường hành vi mà rule chữ ký (THREAT-001..076)
không bắt được”*. Có 3 bộ dò:

1. **`StatisticalDetector` (z-score)** — mỗi chỉ số (số event, lượng mạng, số lần đăng nhập sai…)
   được đếm theo **cửa sổ 1 giờ**, so với **168 mốc (7 ngày)** lịch sử.
   Nếu giá trị hiện tại lệch khỏi trung bình **hơn 3 độ lệch chuẩn (z > 3)** → bất thường.
   *Nói dễ hiểu:* máy bạn thường 200 event/giờ, tự nhiên có 5.000 event/giờ → báo.
2. **`FirstTimeDetector`** — *“đã từng thấy cái này chưa?”* (process, IP, user, machine).
   Lần đầu thấy → báo. **Đây là nguồn cảnh báo giả nhiều nhất**, ví dụ thật trong DB:

   ```
   2026-10-01 13:19:20  IT-YSNT  ANOMALY-FIRSTTIME-FIRST-TIME-PROCESS  MEDIUM
   [FirstTime] First time: process='D:\dist\GiamSatAgent.exe' on machine f196aff3
   ```
   ⇒ Hoàn toàn vô hại: đó là **chính agent GIAM-SAT** vừa được nâng cấp/copy sang đường dẫn mới.
   Cách xử lý đúng: **Trạng thái → `false_positive`** kèm ghi chú, và nếu lặp lại thì dùng
   **Chặn cảnh báo giả (Suppression)** để chặn theo `rule_id` + `machine_id`.
3. **`AnomalyScoreAggregator`** — cộng điểm các bộ dò lại; **chỉ ghi cảnh báo khi điểm ≥ 50**
   (ngưỡng này khai báo ngay trong docstring của file). Điểm < 50 bị bỏ ⇒ bạn **không** thấy.

**Vì sao thiết kế như vậy?** Rule chữ ký chỉ bắt cái đã biết; kẻ tấn công mới (zero-day) sẽ lộ diện
qua **hành vi lạ** và **khối lượng lạ**. Đổi lại, loại này có nhiều cảnh báo giả → cần người phân tích
(đúng vai của bạn) chứ không thể tự động hoá hoàn toàn.
### 2.5 Loại 5 — Máy “im lặng”: Dead-man switch (`HEARTBEAT-001`)

Máy mất log = SOC bị **mù** đúng vào lúc kẻ tấn công cần (chúng thường diệt agent trước).
Vì vậy `event_worker.py` chạy một thread tên `_deadman_checker` (**`_deadman_checker` tại dòng 403**),
khởi động cùng server và in ra log: `[ *] Heartbeat Dead-man's Switch enabled (300s timeout)`.

**Nguyên lý:** mỗi agent gửi **heartbeat** (nhịp tim) định kỳ ⇒ ghi vào bảng `heartbeats`
(hiện có 25.565 dòng). Nếu `now - lần heartbeat cuối > 300 giây` **và** không có tín hiệu tắt máy “tử tế”
(graceful shutdown) ⇒ sinh cảnh báo:

```
rule_id    HEARTBEAT-001              severity CRITICAL            hostname ADMINZ
rule_name  Agent Dead-man's Switch Triggered
timestamp  2026-10-01 13:20:38
description Agent ADMINZ (2136a2eb) has been offline for 144271s (2404 minutes).
            No graceful shutdown signal received. Possible agent kill, system crash,
            or network isolation.
```

**Đọc ví dụ này ra sao?** `ADMINZ` gửi nhịp cuối lúc `2026-09-29 21:16`, cảnh báo bật lúc `2026-10-01 13:20`
⇒ máy đã tắt/hibernate gần **40 giờ**. Ba khả năng được nêu ngay trong mô tả: (1) agent bị diệt,
(2) máy crash/tắt, (3) mất mạng. Việc của bạn: kiểm tra máy còn sống không (`ping`, tab **Tổng quan**),
kiểm tra dịch vụ `GIAM-SAT Agent` trong Services, xem `machines.last_seen`.
**Đây cũng là lý do** bảng `daily_stats` ngày 2026-10-01 của ADMINZ có `events = 0`.

> **Bài học thiết kế:** đừng bao giờ chỉ kiểm tra “có cảnh báo xấu không” — phải kiểm tra cả
> *“có còn nhận được dữ liệu không”*. Đó chính là mục đích tab **Log Coverage**.

### 2.6 Loại 6 — Server tự bảo vệ, “nền tảng” mạng và IOC

**a) Quét thư mục trên chính server — `SRV-SCAN-001/002` (`server_monitor.py`)**

Server đọc log truy cập web; nếu một IP tạo nhiều HTTP **404** trong thời gian ngắn ⇒ đó là dấu hiệu
**quét/ dò thư mục**. Cảnh báo thật trong DB:

```
SRV-SCAN-002   Endpoint scan from 192.168.1.248 (13x 404)   hostname: Attacker:192.168.1.248   MEDIUM
```
Chú ý: cột `hostname` bị đặt là `Attacker:192.168.1.248` để bạn thấy ngay **ai** đang quét.
Trong môi trường lab, chính **công cụ kiểm thử của bạn** sinh ra cảnh báo này (36 cảnh báo trong DB)
⇒ đây là ví dụ thật cho “cảnh báo đúng kỹ thuật nhưng vô hại về nghiệp vụ”: xử lý bằng
`false_positive` + ghi chú, hoặc tạo **Suppression** để lần sau không báo nữa.

**b) “Đầu độc nền tảng” — `BASELINE-DRIFT` (`network_baseline.py`)**

Hệ thống **học** danh sách điểm đích mạng bình thường của bạn (bảng `network_baseline`, 7.095 dòng,
ví dụ `204.79.197.222` gặp 14 lần). Khi xây lại nền tảng, nếu số điểm đích **mới** vượt
`GIAMSAT_BASELINE_DRIFT_LIMIT` (mặc định **30%**) ⇒ cảnh báo HIGH:
*“Network baseline expanded by X% in one rebuild … Possible baseline poisoning”*.

*Vì sao lại quan trọng?* Nếu kẻ tấn công khiến nền tảng “học” luôn IP của chúng, thì lần sau IP đó
**không** còn là bất thường nữa ⇒ mất khả năng phát hiện. Cảnh báo này chính là hàng rào chống lại thủ thuật đó.

**c) Danh sách theo dõi (IOC) — `IOC-WATCH-001`, `IOC-RETRO-001/002` (`watchlist_matcher.py`, `ioc_sweeper.py`)**

- `IOC-WATCH-001`: mỗi chỉ dấu (IP/domain/hash) khớp với danh sách theo dõi ⇒ 1 cảnh báo, **cooldown 1 giờ**.
- `IOC-RETRO-*`: sau khi bạn “quét IOC”, hệ thống tìm **ngược trong dữ liệu cũ** xem IP/domain đó
  đã từng xuất hiện chưa ⇒ bằng chứng xâm nhập đã có trước đó.
- Bảng `watchlist` hiện **0 dòng** ⇒ muốn thấy loại cảnh báo này, bạn phải tự thêm IOC (menu **Quét IOC** / Watchlist).

> **EN:** Six alert-producing mechanisms with real IDs/numbers: agent rules, cross-machine rules,
> network heuristics (CV ≤ 0.30 ⇒ beacon), statistical/first-time anomalies (score ≥ 50),
> 300-second dead-man switch, server self-monitoring + baseline-drift + watchlist.
### 2.7 Vì sao không thấy cảnh báo trùng lặp? (4 cơ chế chống nhiễu)

| Cơ chế | Ở đâu | Cách hoạt động | Bạn thấy được gì |
|---|---|---|---|
| **Chống trùng khi ghi** | `events.dedup_key` + `INSERT … ON CONFLICT` | Cùng một sự kiện gửi lại 2 lần ⇒ chỉ 1 dòng | Tab Nhật ký sự kiện không nhân đôi |
| **Cooldown theo rule** | `network_alerting.py`, `watchlist_matcher.py`, `_cooldown_check()` | Ví dụ `NET-BEACON` chờ 6h, `NET-FIRST`/`NET-ODD` 24h, `IOC-WATCH-001` 1h | Một cảnh báo chứ không phải hàng trăm |
| **Chặn cảnh báo giả** | bảng `alert_suppression` (menu **Chặn cảnh báo giả**) | Chặn theo `rule_id` + `machine_id` + trường dữ liệu, có `expires_at` | Cảnh báo đó biến mất khỏi danh sách |
| **Chỉ thông báo từ mức HIGH** | `alerting_engine.py`, `daily_digest.py` | Telegram/Email chỉ gửi HIGH/CRITICAL | MEDIUM vẫn nằm trên dashboard, không làm phiền bạn |

### 2.8 Đọc một cảnh báo cho đúng (giải phẫu bảng `threat_alerts`)

| Cột | Ý nghĩa | Bạn dùng nó để làm gì |
|---|---|---|
| `rule_id`, `rule_name` | Nguồn phát hiện | Tra rule trong `correlation_rules.yaml` ⇒ hiểu **vì sao** có cảnh báo |
| `severity` | MEDIUM / HIGH / CRITICAL | Quyết định thứ tự xử lý (CRITICAL trước) |
| `machine_id`, `hostname` | Máy bị ảnh hưởng | Nếu `hostname = Attacker:…` ⇒ đó là **kẻ tấn công**, không phải nạn nhân |
| `description` | Câu giải thích bằng tiếng người | Bằng chứng sơ bộ |
| `timestamp` | Lúc **sự việc xảy ra** (theo máy/nguồn) | Xây timeline |
| `received_at` | Lúc **server ghi nhận** | Nếu lệch `timestamp` nhiều ⇒ máy chậm giờ hoặc gửi bù |
| `raw_data` (JSONB) | Dữ liệu gốc | Xem chi tiết đầy đủ khi bấm mở cảnh báo |
| `status` | `new` → `resolved` / `false_positive` | Vòng đời điều tra; DB thật: **191 new, 5 resolved, 3 false_positive** |
| `assignee`, `comment`, `due_at`, `updated_by` | Người xử lý, ghi chú, hạn (SLA), người sửa cuối | Bàn giao ca trực |

**Quy tắc vàng cho sinh viên:** mọi cảnh báo đều phải kết thúc bằng **một trong hai** trạng thái
`resolved` (đã xử lý thật) hoặc `false_positive` (đã kiểm chứng là vô hại) + **một dòng ghi chú**.
Để nguyên `new` nghĩa là “chưa ai làm gì” — và không ai biết bạn đã xem hay chưa.

> **EN:** Four anti-noise mechanisms (dedup, cooldowns, suppression, HIGH-only notifications) and the
> anatomy of a `threat_alerts` row with a real example.
---

## Chương 3 — Chi tiết từng menu (tra theo tên trên thanh trái)

### 3.0 Bảng tra nhanh: bấm gì → gọi API nào → đọc bảng nào

Menu (thanh trái) → mã view → hàm JS → API → bảng DB:

| Menu | `data-view` | Hàm JS (`dashboard.js` / `modules/*.js`) | API | Bảng chính |
|---|---|---|---|---|
| Tổng quan | `overview` | `loadOverviewPanorama`, `loadStats`, `loadMachines`, `connectSSE` | `/api/panorama`, `/api/stats`, `/api/event_types`, `/api/machines`, `/api/events/stream` | `machines`, `events`, `threat_alerts` |
| Báo cáo tài sản | `report-asset` | (khung tĩnh — bấm nút **Xuất** trong khung) | `/api/assets/export`, `/api/reports/machine-config-html`, `/api/reports/machine-config-export` | `assets_inventory`, `assets_computers`, `hardware_info` |
| Báo cáo tổng hợp | `report-summary` | `generateSummaryReport` | `/api/reports/generate` | tổng hợp nhiều bảng |
| **Log Coverage** | `coverage` | `loadCoverage` + `fleet.init()` | `/api/risk/hosts`, `/api/health/fleet`, `/api/health/storage`, `/api/policies/list`, `/api/fleet/*` | `machines`, `heartbeats`, `ingest_anomalies`, `update_rollouts` |
| Cases | `cases` | `loadCases`, `openCaseDetail` | `/api/cases`, `/api/cases/<id>` | `cases`, `case_evidence` |
| Bảng điều khiển | `dashboards` | `loadDashboardList`, `loadDashboardTemplate` | `/api/dashboard/list`, `/api/dashboard/render` | `custom_dashboards`, view vật liệu hoá |
| Nhật ký sự kiện | `events` | `loadAllEvents` | `/api/events` | `events` |
| FIM | `fim` | `loadAllFim` | `/api/fim` | `fim_events` |
| Syslog | `syslog` | `loadSyslog` | `/api/syslog` | `syslog`, `syslog_sources` |
| Phản hồi | `response` | `loadAllResponses`, `loadResponseActions`, `executeResponseAction` | `/api/responses`, `/api/response/actions`, `/api/response/execute` | `response_results`, `commands` |
| Mạng | `network` | `loadNetwork`, `loadInspection` | `/api/network`, `/api/inspection` | `network_traffic`, `network_inspection` |
| NetFlow | `netflow` | `loadNetflow` | `/api/netflow/stats` | `netflow_flows` |
| Đe dọa | `threats` | `loadThreats`, `loadThreatsGrouped`, `setThreatStatus`, `assignThreat` | `/api/threats`, `/api/threats/grouped`, `/api/threats/<id>` | `threat_alerts` |
| Lỗ hổng | `vulns` | `loadVulns` | `/api/vulns` | `vuln_alerts` |
| YARA | `yara` | `loadYara` | `/api/yara` | `yara_alerts` |
| SCA | `sca` | `loadSca` | `/api/sca` | `sca_events` |
| Không cài agent | `agentless` | `loadAgentless` | `/api/agentless/devices` | `agentless_events` |
| Trợ lý Agent | `assistant` | `sendToAssistant` | `/api/assistant`, `/api/ai/status` | (AI, không ghi DB) |
| Sysmon | `sysmon` | `loadSysmon` | `/api/sysmon` | `sysmon_events` |
| Bộ nhớ | `memory` | `loadMemory` | `/api/memory` | `sysmon_events` (`memory_scan_event`) |
| **Điều tra hợp nhất** | `investigate` | `modules/investigate.js` | `/api/investigate/search|entity|fields|saved|export`, `/api/forensics/*` | **mọi bảng** (qua `search_engine.py`) |
| Điều tra (1 cảnh báo) | `incident` | `loadIncidentTimeline` | `/api/incident/list`, `/api/incident/<threat_id>` | `events`, `network_traffic`, `fim_events`, `yara_alerts` |
| Tổng quan tấn công | `attack` | `loadAttackOverview` | `/api/attack/overview`, `/api/risk/killchain` | `threat_alerts` |
| Săn tìm đe dọa | `hunting` | `startHunting`, `loadHunting`, `loadHuntStats` | `/api/hunt/start|result|templates|stats|campaigns` | `events`, `sysmon_events` |
| Bất thường | `anomaly` | `loadAnomaly` | `/api/threats` (lọc `ANOMALY-*`) | `threat_alerts` |
| Quét IOC | `ioc` | `sweepIoc` | `/api/ioc/sweep` | `watchlist`, lệnh xuống agent |
| MITRE ATT&CK | `mitre` | `modules/mitre-matrix.js` | `/api/mitre/*` | `threat_alerts` (map `mitre`) |
| Tin nhắn | `messages` | `refreshMessageBadge` | `/api/message/unread-count`, `/api/messages` | `messages` |
| Nhóm agent | `groups` | `modules/group-policies.js` | `/api/groups`, `/api/policies/*` | `agent_groups`, `group_policies`, `policy_apply_status` |
| Cập nhật Agent | `agentupdate` | `loadAgentUpdateView`, `pushUpdateToMachine` | `/api/agent/version|push-update|update-log|reset-user` | `agent_update_log`, `update_rollouts` |
| FIM Baseline | `fimbaseline` | `loadFimBaselineMachines` | `/api/fim/baseline/summary` | `fim_baseline` |
| Quản lý Rules | `rules` | `loadRules`, `deployRules`, `reloadRules`, `testRule` | `/api/rules`, `/api/rules/deploy|reload|test` | `server/rules/correlation_rules.yaml` |
| Chặn cảnh báo giả | `suppression` | `loadSuppressions`, `addSuppression` | `/api/suppression/list|add|remove` | `alert_suppression` |
| Cảnh báo Email | `email` | `loadEmailView`, `saveAlertingConfig`, `testEmailConfig` | `/api/email/*`, `/api/alerting/config` | `sent_mail_log`, file cấu hình |
| Tài sản | `assets` | `loadAssets*` | `/api/assets/*` | `assets_inventory`, `assets_monitors`, `assets_change_log` |
| Quản lý người dùng | `users` | `loadUsers`, `changeUserRole`, `manage2fa` | `/api/users*`, `/api/auth/check` | `users.json` |
| Dọn dẹp dữ liệu | `cleanup` | `loadCleanupSummary`, `runCleanup` | `/api/cleanup/summary`, `/api/cleanup` | mọi bảng (xoá theo tuổi) |
| Nhật ký kiểm toán | `audit` | `loadAudit` | `/api/audit` | `audit_log` (165 dòng) |
| Cluster | `cluster` | `loadCluster` | `/api/cluster/nodes` | `cluster_config.json` |

### 3.1 Tổng quan (`overview`) — “sức khoẻ tức thời của cả hệ thống”

**Để làm gì:** câu trả lời cho *“hệ thống tôi đang ổn hay không?”* trước khi đi sâu vào từng tab.

**Dữ liệu:** thẻ số liệu lấy `GET /api/stats` (số máy/sự kiện/syslog/cảnh báo),
biểu đồ phân loại lấy `GET /api/event_types`, bảng máy lấy `GET /api/machines`,
và **SSE** `GET /api/events/stream` đẩy sự kiện mới realtime (bạn không cần bấm F5).

**Cách dùng:**

1. Nhìn 4 thẻ trên cùng: **Tổng máy trạm / Đang online / Sự kiện / Syslog**.
   `Sự kiện` tăng đều = đường ống agent thông; đứng im = dữ liệu đang tắc (sang Chương 5).
2. Bảng **Máy trạm đã đăng ký**: mỗi dòng 1 máy (`hostname`, phiên bản, `last_seen`, `is_online`).
   Bấm tiêu đề cột để sắp xếp; bấm tên máy để mở trang chi tiết máy.
3. Nút **Dọn log cũ** (gọi `/api/cleanup`) và **Xoá offline** (xoá máy đã tắt khỏi danh sách).
4. Biểu đồ **Phân loại sự kiện** — nhìn nhanh loại log nào đang nhiều.

**Hiểu số liệu thật của bạn:** `machines` chỉ có **2 dòng** — `IT-YSNT` (bản `6.0.1`, đang online,
`sysmon_present = 1`) và `ADMINZ` (bản `6.0.0`, **offline** từ 29/09, `sysmon = 0`, `auditpol = 0`).
⇒ Từ đó suy ra ngay: máy nào khoẻ, máy nào cần bật lại, máy nào thiếu Sysmon (thiếu dữ liệu tiến trình).

**Vì sao “Đang online” khác “im lặng”?** `is_online` là cờ do server cập nhật khi nhận dữ liệu;
vector “im lặng” (silent) là khái niệm của tab Coverage: online nhưng **không còn gửi log** — nguy hiểm hơn.
### 3.2 Báo cáo tài sản (`report-asset`)

**Để làm gì:** in/xuất danh sách máy + cấu hình phần cứng ra Excel/HTML để báo cáo hoặc bàn giao.
**Dữ liệu:** `/api/assets/export` (Excel nhiều sheet), `/api/reports/machine-config-html`
(HTML cấu hình **một** máy) hoặc `/api/reports/machine-config-export`, và `/api/assets/inventory/stats`
(số lượng theo loại). *Lưu ý kỹ thuật thật:* trong `dashboard.js`, view `report-asset` được khai báo
`load: function () {}` — nghĩa là menu **không tự gọi API khi mở**, bạn phải **bấm nút xuất** trong khung báo cáo.
**Cách dùng:** bấm menu → chọn phạm vi (tất cả / một nhóm / một máy) → chọn định dạng → **Xuất**.
File tải về nằm trong thư mục `reports/` của server, tải lại bằng `/api/reports/download/<tên-file>`.
**Lưu ý thực tế:** số liệu lấy từ `assets_computers` (1 dòng), `hardware_info` (1 dòng) —
hiện chỉ có 1 máy gửi đủ thông tin phần cứng, nên báo cáo sẽ mỏng cho tới khi `ADMINZ` bật lại.

### 3.3 Báo cáo tổng hợp (`report-summary`)

**Để làm gì:** sinh báo cáo tình hình an ninh theo kỳ (số cảnh báo, mức độ, top rule, top máy).
**Dữ liệu:** `POST /api/reports/generate` → `server/reporting_engine.py` đọc `threat_alerts`,
`events`, `daily_stats` rồi dựng file HTML/PDF. Nếu bảng `daily_stats` đã được rollup (xem 6.3) thì
báo cáo chạy rất nhanh vì không phải quét bảng thô.
**Cách dùng:** chọn khoảng thời gian → **Tạo báo cáo** → **Tải về**.
**Vì sao đọc `daily_stats` thay vì `events`?** `events` có 123.864 dòng và tăng liên tục; muốn hỏi
“30 ngày qua có bao nhiêu sự kiện/ ngày” thì đếm sẵn một lần (rollup) rồi đọc kết quả rẻ hơn hàng trăm lần.

### 3.4 Log Coverage (`coverage`) — “ai đang gửi log, ai đã im lặng, ai bị chặn”

Đây là tab quan trọng nhất về **vận hành**. Nó gồm 2 phần rất khác nhau:

#### Phần A — Bảng điểm rủi ro máy (`loadCoverage` → `GET /api/risk/hosts`)

`api_analytics.py` tính **điểm rủi ro 0–100 cho từng máy**: cộng trọng số theo mức cảnh báo
(CRITICAL nặng hơn HIGH, HIGH nặng hơn MEDIUM) rồi **giảm dần theo thời gian** (cảnh báo cũ ít nặng hơn).

- **Cách đọc:** máy điểm cao = đang có nhiều/vừa có cảnh báo nặng ⇒ ưu tiên xem trước.
- **Vì sao “giảm dần theo thời gian”?** Nếu không giảm, một sự cố cũ từ tháng trước sẽ mãi giữ máy
  ở mức đỏ, che mất sự cố mới.
- **Ví dụ thật:** `IT-YSNT` có 137 cảnh báo (trong đó nhiều `ANOMALY-FIRSTTIME` MEDIUM) nên điểm cao;
  `ADMINZ` có 25 cảnh báo nhưng **1 CRITICAL** (`HEARTBEAT-001`) ⇒ điểm vẫn đáng chú ý.

#### Phần B — Panel “Triển khai & Sức khỏe” (`modules/fleet.js`)

Bốn khối, mỗi khối có một dòng chú thích ngay trên đầu:

| Khối | Nguồn dữ liệu | Trả lời câu hỏi | Nút bấm |
|---|---|---|---|
| **Triển khai theo đợt** | `GET /api/fleet/rollouts`, `POST /api/fleet/rollout/plan`, `POST /api/fleet/rollout` | Nâng cấp agent theo từng đợt canary→10%→100% | **Xem kế hoạch**, **Bắt đầu (canary)** |
| **Sức khỏe đội máy** | `GET /api/health/fleet` | Máy nào im lặng/cũ/thiếu Sysmon; nguồn nào bị **từ chối** | **Xử lý** (mở hướng dẫn rồi ẩn cảnh báo) |
| **Dung lượng & partition** | `GET /api/health/storage`, `POST /api/health/storage/rollup`, `POST /api/health/storage/drop-old` | Bảng nào nặng, đã chia theo tháng chưa, dữ liệu quá hạn | **Rollup ngay**, **DROP dữ liệu quá hạn** |
| **Chính sách theo đợt** | `GET /api/policies/list`, `POST /api/policies/preview|wave-apply|wave-advance` | Áp chính sách theo đợt máy, xem trước không gửi gì | **Xem trước**, **Áp đợt canary**, **Sang đợt kế** |

**“Nguồn bị TỪ CHỐI” nghĩa là gì?** Đây là dữ liệu *suýt* vào được hệ thống nhưng bị chặn
(xem 5.1): agent sai/thiếu PSK, message sai định dạng, hoặc bị `rate_limiter.py` chặn vì flood.
`tcp_server.py` đếm trong bộ nhớ (`_note_ingest()`), `fleet_store.py` lưu vào `ingest_anomalies`.
Bấm **Xử lý** để xem: nguồn IP, máy nào, lý do, và các bước khắc phục; sau đó hệ thống ẩn cảnh báo đó
(ghi nhận đã xử lý) — nhưng **dữ liệu đã mất thì không lấy lại được**, phải sửa cấu hình agent rồi chờ log mới.

**Vì sao phải tách “silent” khỏi “offline”?**

- *offline*: máy không gửi nhịp tim (máy tắt) → bình thường, có thể chấp nhận.
- *silent* (im lặng): máy **vẫn online** nhưng khối lượng log tụt bất thường → **dấu hiệu tấn công**
  (kẻ tấn công tắt log/Sysmon/agent để che dấu vết). Vì vậy Coverage là tab “phòng chống bị bịt mắt”.
- Công thức trong `/api/health/coverage`: lấy khối lượng 24h so với trung bình 7 ngày;
  nếu `24h < 50%` của trung bình ⇒ cờ `log_drop`; nếu có máy online mà 0 log ⇒ `no_logs`;
  thiếu Sysmon ⇒ `no_sysmon`; không bật auditpol ⇒ `no_auditpol`; phiên bản khác server ⇒ `outdated`.

### 3.5 Cases (`cases`) — gom nhiều cảnh báo thành một vụ việc

**Để làm gì:** một sự cố thực tế luôn gồm nhiều cảnh báo rời rạc. Case là **hồ sơ** gom chúng lại
để bàn giao, theo dõi tới khi kết thúc.

**Dữ liệu:** `GET/POST /api/cases`, `GET /api/cases/<id>`, `POST /api/cases/<id>/status` →
bảng `cases` (cột `alert_ids` là **mảng JSON** các `threat_alerts.id` liên quan) và
`case_evidence` (gói bằng chứng tạo từ tab Điều tra hợp nhất).

**Cách dùng:**
1. Vào **Đe dọa** → tích chọn các cảnh báo cùng một sự việc → **Tạo case** (điền tiêu đề, mức, mô tả).
2. Sang **Cases** → mở case → xem timeline, thêm bằng chứng (**📄 Hồ sơ ±15 phút** trong Điều tra).
3. Đổi **Trạng thái** khi xong: `open → investigating → closed`.
4. Nút badge vàng cạnh menu **Cases** đếm số case đang mở.

**Ví dụ thật trong DB:** case `#4` — `Kill-chain cluster: 2 rules in 1h`, mức HIGH, đang `open`.
Đúng như tên: hệ thống thấy **2 rule khác nhau nổ trong 1 giờ trên cùng ngữ cảnh** ⇒ gom thành 1 case.
### 3.6 Bảng điều khiển (`dashboards`) — tự dựng dashboard riêng

**Để làm gì:** ghép các widget (bảng/biểu đồ/số liệu) bạn quan tâm thành một màn hình riêng,
thay vì mở nhiều tab.
**Dữ liệu:** `GET /api/dashboard/list` (danh sách dashboard đã lưu — bảng `custom_dashboards`),
`POST /api/dashboard/render` (dựng widget theo JSON), `POST /api/dashboard/import` (nạp file JSON mẫu).
Các widget lấy số từ **view vật liệu hoá** `mv_dashboard_stats`, `mv_dashboard_machines` để vẽ nhanh.
**Cách dùng:** **Tạo dashboard** → đặt tên → **Thêm widget** → chọn nguồn dữ liệu và loại hiển thị →
**Lưu** → chọn dashboard ở danh sách để xem.
**Hiện trạng thật:** `custom_dashboards` = **0 dòng** ⇒ bạn sẽ tạo từ số 0; widget đầu tiên nên là
“Cảnh báo theo mức” và “Số máy online” — đó là 2 thứ cần nhìn mỗi sáng.

### 3.7 Nhật ký sự kiện (`events`) — “máy này đã làm gì?”

**Để làm gì:** tra cứu thô toàn bộ Windows Event mà agent gửi về. Đây là **bằng chứng gốc**
(sự kiện trên bảng Đe dọa chỉ là *kết luận*).
**Dữ liệu:** `GET /api/events` → `api_events.py` → `db.get_events()` → `SELECT … FROM events`.
Hỗ trợ lọc theo máy, `type`, `event_id`, khoảng thời gian, từ khoá; sắp xếp theo cột; xuất JSON.
**Cách dùng:**
1. Chọn **máy** ở cột trái (hoặc để “tất cả”), gõ từ khoá (ví dụ `powershell`), chọn `event_id`.
2. Bấm dòng để xem `raw_data` (toàn bộ bản ghi gốc) và **mở timeline** của máy đó.
3. Dùng nút xuất JSON khi cần đưa bằng chứng ra ngoài.
**Hiểu dữ liệu thật (123.864 dòng):** các `event_id` nhiều nhất là
`4673` (25.923 – thao tác đặc quyền), `4689` (21.083 – tiến trình kết thúc), `4688` (19.217 – **tạo tiến trình**),
`4670` (10.233 – đổi quyền file/registry), `4674` (1.640), `4672` (1.268 – gán đặc quyền), `4624` (1.049 – đăng nhập).

Theo `subtype`, phần lớn là kênh **Security (81.150)**; tiếp theo là **PowerShell/Operational (3.592)**, System (3.441), Application (2.434), **Windows Defender/Operational (2.309)**, RDP LocalSessionManager (2.286).

**Mẹo nghề:** muốn tìm dấu vết kẻ tấn công, hãy nghĩ theo *câu chuyện*, không theo tên event:

| Bạn muốn biết | `event_id` / từ khoá | Ý nghĩa |
|---|---|---|
| Có chương trình gì vừa chạy? | `4688`, lọc `powershell`, `cmd`, `wmic`, `certutil` | Tạo tiến trình + dòng lệnh |
| Tài khoản được cấp quyền cao? | `4672`, `4674` | Đặc quyền được gán / dùng |
| Có đăng nhập vào máy? | `4624` (thành công), `4625` (thất bại) | Nguồn: `source_ip`, loại logon |
| Ai đổi quyền file/registry? | `4670` | Leo thang đặc quyền |
| Kẻ tấn công đọc script PowerShell? | subtype `Microsoft-Windows-PowerShell/Operational` | Script block (mã nguồn) |
| Máy có bị xoá log? | `LOG_RESET` (đây là **ALERT**, `category = Tampering`) | Dấu hiệu che dấu vết |

**Vì sao sự kiện không bị nhân đôi?** Mỗi dòng có `dedup_key` (băm nội dung + máy + thời gian);
khi ghi dùng `INSERT … ON CONFLICT` nên gửi lại cùng sự kiện ⇒ **không** tạo dòng mới.

### 3.8 FIM (`fim`) — File Integrity Monitoring

**Để làm gì:** biết **file nào vừa bị tạo/sửa/xoá**, trên đường dẫn nào — dấu hiệu mạnh của ransomware,
webshell, thay đổi cấu hình.
**Dữ liệu:** `GET /api/fim` → bảng `fim_events`; nền tảng so sánh ở bảng `fim_baseline` (262 dòng) và
menu **FIM Baseline**.
**Cách dùng:** lọc theo máy/hành động/đường dẫn → đối chiếu với **FIM Baseline**
(những file *được phép* thay đổi). Nếu file quan trọng bị đổi mà bạn không làm gì ⇒ điều tra ngay.
**Số liệu thật:** 1.744 sự kiện, trong đó `FILE_MODIFIED` **977**, `FILE_DELETED` **437**, `FILE_CREATED` **334**.

- Tỷ lệ `FILE_CREATED` + `FILE_MODIFIED` cao là bình thường với máy đang cập nhật/cài đặt.
- Tỷ lệ `FILE_DELETED` tăng vọt **trên nhiều thư mục cùng lúc** = dấu hiệu ransomware ⇒ phải kiểm tra ngay.
- Trên agent Windows còn có collector **fim_whodata** (ghi cả *tiến trình nào* đã sửa file) — dùng `raw_data` để truy.

### 3.9 Syslog (`syslog`) — log từ router/thiết bị mạng

**Để làm gì:** xem log của thiết bị **không cài được agent**: router, firewall, switch, NAS.
Đây thường là nơi chứa bằng chứng quan trọng nhất (ai vào VPN, luật firewall nào bị chặn, DHCP cấp IP nào).
**Dữ liệu:** `GET /api/syslog` → bảng `syslog`. Nhận vào bằng `syslog_server.py` (UDP **514**, nếu không có quyền bind sẽ tự chuyển 1514) và `syslog_tcp_server.py` (**TCP 6514** cho thiết bị chỉ hỗ trợ TCP).
Danh sách nguồn nằm ở `syslog_sources` (1 dòng).
**Cách dùng:** lọc theo `facility`/`severity`/IP nguồn; gõ từ khoá (`deny`, `vpn`, `login`).
**Số liệu thật:** 47.017 dòng; nguồn `Vigor:` với các cặp facility/severity:
`local1/notice` 22.899 · `daemon/info` 17.864 · `local5/info` 4.382 · `daemon/notice` 1.213 · `user/notice` 254;
**394 dòng trong 1 giờ** gần nhất ⇒ đường syslog đang chạy tốt.
**Giải thích format syslog (để bạn không bị “ngợp”):** mỗi thông điệp bắt đầu bằng `<PRI>`,
trong đó `PRI = facility × 8 + severity`. `facility` = *loại nguồn* (local1 = tự định nghĩa, daemon = dịch vụ hệ thống),
`severity` = *mức* (info < notice < warning < err …). Vì vậy “`local1/notice`” nghĩa là
*router tự định nghĩa mức thông báo bình thường* — không phải lỗi.
> **Ví dụ thật đáng học — `LOG_RESET` (37.219 dòng, nhiều nhất của bạn):**
> dòng này **không** phải log Windows thường mà là **cảnh báo do agent tự sinh**:
> ```
> event_id LOG_RESET | event_type ALERT | category Tampering | computer ADMINZ
> description  Event log 'Directory Service' was CLEARED or reset
>              (record number dropped from 19254 to 19254). Possible log tampering
> ```
> Cơ chế: agent nhớ *số thứ tự bản ghi* của từng kênh log; khi số đó **giảm** (log bị xoá) ⇒ báo.
> Nhưng khi log **cuộn vòng** (vòng xoay do đầy) số cũng “nhảy”, nên rule này bắn rất nhiều ⇒
> bài học thực tế số 1 về **cảnh báo giả do logic đúng nhưng ngữ cảnh sai**. Cách xử lý:
> kiểm tra 2–3 dòng (`record number dropped from X to Y`, `X == Y` ⇒ thường là nhiễu),
> rồi đặt **false_positive** và tạo **Suppression** cho `rule_id = LOG_RESET` trên máy đó.

### 3.10 Phản hồi (`response`) — ra tay với máy trạm

**Để làm gì:** gửi **hành động** xuống máy trạm đang bị nghi nhiễm (cô lập, diệt tiến trình, cách ly file…)
và xem kết quả.
**Dữ liệu:**
- `GET /api/response/actions` — danh sách hành động khả dụng (`loadResponseActions`).
- `POST /api/response/execute` — gửi lệnh (`executeResponseAction`).
- `GET /api/responses` — lịch sử đã chạy (bảng `response_results`, `commands`).

**Cách dùng (runbook 4 bước):**
1. Xác định đúng máy (dùng `machine_id`, không đoán theo tên hiển thị).
2. Chọn hành động **ít xâm lấn trước** (kill process → quarantine file → cuối cùng mới **isolate**).
3. Bấm thực thi, rồi sang tab xem **kết quả** (thành công/thất bại + thông báo của agent).
4. Ghi lại bằng chứng (kết quả + thời điểm) vào **comment** của cảnh báo hoặc **case**.

**Vì sao phải cẩn thận?** Lệnh đi qua kênh TLS/PSK và chạy **bằng quyền hệ thống** trên máy trạm:
- `isolate` (cô lập) có thể làm **mất luôn log** của máy đó (máy không gửi về được) ⇒ phải có người tại máy.
- Mọi lệnh đều yêu cầu quyền **`command`** và **được ghi vào `audit_log`** (ai gửi, gửi gì, lúc nào).
- Nếu agent đã bị tắt, lệnh sẽ nằm chờ trong bảng `commands` tới khi máy sống lại — kiểm tra trạng thái trước khi kết luận “lệnh không chạy”.

### 3.11 Mạng (`network`) — agent thấy máy đang nói chuyện với ai

**Để làm gì:** nhìn toàn bộ **phiên kết nối** (5-tuple: `src_ip`, `src_port`, `dst_ip`, `dst_port`, `protocol`)
kèm số byte/gói, hướng, tên miền (`dns_query`), thông tin HTTP (`http_host`).
**Dữ liệu:** `GET /api/network` → bảng `network_traffic` (159.026 dòng, 116 MB — bảng nặng thứ 2);
`GET /api/inspection` → `network_inspection` (hiện 0 dòng, dành cho gói được phân tích sâu).
**Cách dùng:** lọc theo máy → sắp xếp theo **bytes** hoặc **Kết nối** → soi các dòng lạ
(IP ngoài, cổng hiếm, chữ ký DNS dài bất thường).
**Số liệu thật & cách đọc:** cổng đích nhiều nhất là `443` **85.312** (HTTPS — bình thường),
`5228` 6.766 (Google/Android push), `80` 6.121 (HTTP thô — cần chú ý vì không mã hoá),
`6666` **3.801 (chính là kênh agent→server của bạn — bình thường)**, `7778` 3.597,
`1514`/`1515` ~3.590 (syslog — router), `49668` 3.594.
⇒ Hai cổng **`7778` và `49668`** là ví dụ điển hình “số lạ cần điều tra”: hãy lọc theo 2 cổng đó
để xem máy nào nói chuyện, với IP nào, và đối chiếu tab **Điều tra hợp nhất** (`dst_ip:` …).
**Cách đọc một dòng network_traffic:**

| Cột | Nghĩa | Dùng để |
|---|---|---|
| `src_ip` / `dst_ip` | Ai gọi ai | Nếu `dst_ip` ở nước ngoài ⇒ mở **Định vị IP** (`geoip_lookup.py`) |
| `dst_port` | Cổng dịch vụ | 443=web mã hoá, 445=SMB (nguy hiểm ra ngoài), 3389=RDP |
| `bytes`, `packets` | Khối lượng | Dòng `bytes` cực lớn ⇒ nghi **rút dữ liệu ra ngoài** |
| `dns_query` | Tên miền đã truy vấn | DGA/miền mới đăng ký |
| `http_host`, `http_url` | Host/URL HTTP | Tải file từ nguồn lạ |

**Liên hệ với cảnh báo:** `NET-FIRST` sinh ra chính vì cột `dst_ip` xuất hiện lần đầu;
`network_baseline` học **danh sách `dst_ip` hợp lệ** của bạn — nên khi bạn thấy `dst_ip` mới mà
hợp lý (máy in mới, dịch vụ mới), hãy xử lý cảnh báo cho sạch, đừng để nó trôi.

### 3.12 NetFlow (`netflow`) — nhìn mạng ở tầng thiết bị

**Để làm gì:** xem luồng dữ liệu do **router/switch** xuất (NetFlow v5/v9) — kể cả các thiết bị
không cài agent (máy in, IP phone, IoT, camera).
**Dữ liệu:** `GET /api/netflow/stats` → bảng `netflow_flows`; nhận vào bằng `netflow_collector.py`
(**UDP 2055**, đổi bằng `GIAMSAT_NETFLOW_PORT`).
**Hiện trạng thật:** `netflow_flows` = **0 dòng** ⇒ chưa thiết bị nào xuất NetFlow.
**Cách bật (3 bước):**
1. Trên router/switch: bật NetFlow/IPFIX và trỏ `exporter` về IP server, cổng **2055**.
2. Kiểm tra firewall cho phép UDP 2055 từ thiết bị tới server.
3. Đợi 1–2 phút rồi xem lại tab (hoặc `SELECT COUNT(*) FROM netflow_flows;`).
**Khác gì `network_traffic`?** `network_traffic` = *máy trạm tự khai* (chỉ có máy có agent);
`netflow_flows` = *thiết bị mạng khai* (thấy cả lưu lượng giữa hai thiết bị không có agent).
Hai nguồn bổ sung nhau: thiếu log NetFlow ⇒ mù phần thiết bị mạng.
### 3.13 Đe dọa (`threats`) — bảng làm việc chính của bạn

**Để làm gì:** đây là **hàng đợi công việc**: mọi cảnh báo trong `threat_alerts` đều phải được xử lý ở đây.
**Dữ liệu:** `GET /api/threats` (danh sách), `GET /api/threats/grouped` (gom nhóm cùng `rule_id` + máy),
`POST /api/threats/<id>/status|assign|comment` (đổi trạng thái, giao người, ghi chú).

**Số liệu thật của bạn (199 cảnh báo) — hãy đọc như một bản tin:**

| `rule_id` | Tên | Mức | Số lượng | Phải hiểu là |
|---|---|---|---|---|
| `SRV-SCAN-002` | Endpoint Scan Detected | MEDIUM | 36 | Chính công cụ test của bạn quét server (`192.168.1.248`) ⇒ **FP theo ngữ cảnh** |
| `ANOMALY-FIRSTTIME-FIRST-TIME-PROCESS` | Anomaly Detection Alert | MEDIUM | 19 | Lần đầu thấy tiến trình (ví dụ `D:\dist\GiamSatAgent.exe`) ⇒ phần lớn **vô hại** |
| `HEARTBEAT-001` | Agent Dead-man's Switch | **CRITICAL** | 15 | Máy mất liên lạc > 300s (`ADMINZ` offline ~40 giờ) ⇒ **thật sự cần xử lý** |
| `THREAT-044` | Process NOT From System32 | HIGH | 8 | Tiến trình chạy ngoài thư mục hệ thống ⇒ kiểm chứng bằng `4688` |
| `ANOMALY-STATISTICAL-EVENT-COUNT-CURR…` | Anomaly (z-score) | MEDIUM | 2 | Khối lượng sự kiện vượt baseline > 3σ |
| `ANOMALY-<số ngẫu nhiên>` | Anomaly Detection Alert | MEDIUM | 1 mỗi mã | Điểm bất thường tổng hợp ≥ 50 |

Phân bố mức: **MEDIUM 171 · CRITICAL 15 · HIGH 13**. Trạng thái: **new 191 · resolved 5 · false_positive 3**.
Phân bố theo máy: `IT-YSNT` 137 · `Attacker:192.168.1.248` 36 · `ADMINZ` 25 · `NetworkBaseline` 1.

**Đọc bảng này ra kết luận:** 191 cảnh báo còn `new` nghĩa là **hàng đợi chưa được dọn** — một SOC nhỏ
mỗi ngày chỉ cần dọn tới khi hết `new` theo thứ tự **CRITICAL → HIGH → MEDIUM mới nhất**.

**Quy trình 6 bước xử lý một cảnh báo (nên in ra dán cạnh bàn):**
1. **Sắp xếp** theo mức rồi theo `timestamp`; bắt đầu từ CRITICAL mới nhất.
2. **Đọc `rule_id`** → tra trong Chương 2 để biết *vì sao* nó nổ.
3. **Kiểm chứng bằng dữ liệu gốc**: mở tab **Nhật ký sự kiện** (lọc đúng máy + thời điểm ±5 phút),
   hoặc dùng **Điều tra hợp nhất** (`hostname:…`, `event_id:…`) để thấy bức tranh lớn.
4. **Kết luận**: `resolved` (có thật, đã xử lý) hoặc `false_positive` (vô hại) — **luôn kèm 1 dòng ghi chú**
   (ví dụ: “GiamSatAgent.exe sau khi nâng cấp lên 6.0.1 — hợp lệ”).
5. Nếu là sự việc lớn: tạo **Case**, đính **gói bằng chứng** (📄 ±15 phút), giao **Assignee**.
6. Nếu cùng loại FP lặp lại nhiều lần: tạo **Chặn cảnh báo giả** (mục 3.33) để không mất thời gian lần sau.

**Đừng nhầm** tab **Đe dọa** (mọi cảnh báo) với tab **Bất thường** (chỉ `ANOMALY-*`) và **Tổng quan tấn công**
(bức tranh kill-chain). Ba tab dùng chung một bảng `threat_alerts`, chỉ khác cách lọc/hiển thị.

### 3.14 Lỗ hổng (`vulns`) — phần mềm lỗi thời, CVE

**Để làm gì:** biết máy nào đang chạy phần mềm có lỗ hổng đã biết (kèm mã CVE) để vá.
**Dữ liệu:** `GET /api/vulns` → bảng `vuln_alerts` (`software`, `version`, `publisher`, `cve`, `severity`).
**Hiện trạng thật:** **0 dòng** — nghĩa là *chưa* có dữ liệu (agent phải gửi inventory phần mềm).
**Cách dùng khi có dữ liệu:** lọc theo `severity`/`cve` → xử lý theo thứ tự CRITICAL trước →
đánh dấu trạng thái sau khi vá → đối chiếu lại.
**Vì sao tab này trống mà không phải lỗi?** Agent mới chỉ cài trên 2 máy, trong đó `ADMINZ` đã tắt;
và việc thu thập danh sách phần mềm cần bật trong cấu hình agent. Kiểm tra bằng
`agent/hw_collector.py` / `behavior_collector.py` và mục **Cấu hình máy** trên agent.

### 3.15 YARA (`yara`) — quét file bằng chữ ký YARA

**Để làm gì:** phát hiện file/dữ liệu khớp **chữ ký YARA** (web shell, mã khai thác, ransomware note…).
**Dữ liệu:** `GET /api/yara` → bảng `yara_alerts`; đổi trạng thái `POST /api/yara/<id>`.
**Số liệu thật (214 dòng):** ví dụ `PowerShell_WebClient`, `Ransomware_Note`, `WMI_Persistence` trên `IT-YSNT`.
**Cách dùng:** mở từng dòng → xem `file` (đường dẫn), `rule_name`, thời điểm →
**đối chiếu với FIM** xem file đó có phải do bạn tạo không → kết luận `resolved`/`false_positive`.
**Vì sao tên rule như `Ransomware_Note` lại có?** YARA khớp **mẫu văn bản** (ví dụ dòng “Your files are encrypted”)
— kể cả khi đó chỉ là **file mẫu/bài lab**, YARA vẫn báo. Đây là ví dụ cho nguyên tắc:
*chữ ký cho biết “có mẫu này”, không cho biết “có thảm hoạ”*.

### 3.16 SCA (`sca`) — kiểm tra cấu hình bảo mật

**Để làm gì:** chấm điểm máy theo danh sách kiểm tra cấu hình (có bật auditpol/PowerShell logging, có tắt
SMBv1, có bật Windows Firewall, độ mạnh mật khẩu…).
**Dữ liệu:** `GET /api/sca` → `sca_events` (`check_id`, `title`, `status`, `severity`, `remediation`).
Agent chạy `agent/baseline_hardening.py` và báo cáo; cột `baseline_hardened` trên bảng `machines` ghi nhận.
**Số liệu thật (1.379 dòng):** `PASS` **1.117** · `FAIL` **247** · `INFO` 14 · `WARN` 1.
**Cách dùng:** lọc `status = FAIL` → đọc cột `remediation` (hướng dẫn sửa) → sửa trên máy →
cho agent chạy lại kiểm tra → xác nhận chuyển `PASS`.
**Vì sao 247 FAIL không phải thảm hoạ?** SCA đo **mức sẵn sàng**, mỗi FAIL là *một việc cần cải thiện*.
Ví dụ `auditpol = 0` trên cả 2 máy ⇒ bạn đã mất khả năng ghi log một số loại sự kiện bảo mật
(⇒ cũng chính là lý do tab Nhật ký có thể thiếu một số `event_id`).
### 3.17 Không cài agent (`agentless`) — giám sát thiết bị không thể cài agent

**Để làm gì:** theo dõi máy in, switch, camera, Linux quá cũ… bằng cách **chủ động kết nối tới chúng**
(SSH/WMI/SNMP) thay vì cài phần mềm.
**Dữ liệu:** `GET/POST/DELETE /api/agentless/devices` (khai báo thiết bị + tài khoản),
`POST /api/agentless/clear` (xoá log), engine chạy nền `server/agentless_monitor.py`,
dữ liệu thu được → bảng `agentless_events` (hiện **0 dòng**),
danh sách thiết bị lưu ở `agentless_devices.json` + bảng `assets_monitors`.
**Cách dùng:** **Thêm thiết bị** → điền IP, loại (OS/SSH/SNMP), tài khoản → lưu → đợi engine quét.
**Vì sao dùng?** Có thiết bị không thể cài agent (máy in, camera IP) nhưng vẫn cần biết
“còn sống không?”, “có phần mềm lạ không?”. Tab này là cầu nối duy nhất cho nhóm đó.
**Cảnh báo an ninh:** tài khoản dùng ở đây sẽ **được lưu trong cấu hình**; hãy dùng tài khoản
chỉ-đọc, riêng biệt, không phải tài khoản admin dùng chung.

### 3.18 Trợ lý Agent (`assistant`) — hỏi đáp bằng AI

**Để làm gì:** hỏi bằng tiếng Việt về dữ liệu đang có (“máy nào sắp hết dung lượng?”,
“tóm tắt các sự kiện 4688 lúc 8h sáng nay”) và nhận câu trả lời tổng hợp.
**Dữ liệu:** `POST /api/assistant` → `server/ai_providers.py`; trạng thái bật/tắt qua
`GET /api/ai/status`, `POST /api/ai/toggle`; khoá API nằm ở `server/.env` (`DEEPSEEK_API_KEY`),
tắt hoàn toàn bằng `GIAMSAT_DISABLE_AI`.
**Cách dùng:** chọn **phạm vi** (máy/khoảng thời gian) ở `loadAssistScope`, đặt câu hỏi, đọc câu trả lời;
nhấn mạnh phạm vi càng hẹp thì câu trả lời càng đúng và càng ít dữ liệu bị gửi đi.
**Ghi chú quan trọng cho môi trường thật:** nội dung log **được gửi ra dịch vụ AI bên ngoài**.
Nếu tổ chức không cho phép rời dữ liệu ⇒ tắt (toggle OFF) hoặc đặt `GIAMSAT_DISABLE_AI=1`.
AI trả lời bằng *suy luận*, không phải bằng *dữ liệu thô* — hãy luôn kiểm chứng lại ở tab Nhật ký/Đe dọa.

### 3.19 Sysmon (`sysmon`) — dữ liệu tiến trình chi tiết

**Để làm gì:** Sysmon cho thông tin mà Windows Event mặc định **không có**: dòng lệnh đầy đủ,
tiến trình cha, hash, thao tác registry, truy vấn DNS, kết nối mạng theo từng tiến trình.
**Dữ liệu:** `GET /api/sysmon` → `db.get_sysmon_events()` → bảng `sysmon_events`
(**45 cột**: `process_name`, `process_path`, `command_line`, `pid`, `parent_process`,
`parent_command_line`, `registry_key`, `dns_query`, `file_path`, `severity`…),
lọc theo `machine_id`, `event_type`, `since`, `limit`.
**Hiện trạng thật đáng chú ý:** `sysmon_events` có **1.170 dòng, tất cả `event_type = memory_scan_event`**
(tức là dữ liệu của tab **Bộ nhớ**, không phải sự kiện Sysmon tiến trình). Vì sao?
- Cột `machines.sysmon_present = 1` chỉ nói *agent thấy có Sysmon*, chưa chắc **collector Sysmon** đã bật.
- Sự kiện Sysmon dạng process (EID 1) hiện chảy vào bảng `events` (subtype `Sysmon`)—
  bạn vẫn dùng **Điều tra hợp nhất** để tìm chúng (`cmdline:` hoặc `path:`).
**Cách bật đầy đủ:** trên máy trạm cài **Sysmon** (Sysinternals) + cấu hình XML,
bật collector trong agent → restart dịch vụ → kiểm tra `SELECT event_type, COUNT(*) FROM sysmon_events GROUP BY 1;`
phải xuất hiện các giá trị như `process_create`, `network_connect`, `dns_query`.
**Vì sao nên bật?** Thiếu Sysmon ⇒ chỉ thấy “có tiến trình X” mà không thấy **ai gọi nó, chạy lệnh gì**
— đó chính là thứ quyết định cảnh báo thật hay giả.

### 3.20 Bộ nhớ (`memory`) — quét RAM

**Để làm gì:** phát hiện mã độc **chỉ sống trong RAM** (không có file trên đĩa — malware “fileless”).
**Dữ liệu:** `GET /api/memory` → `get_sysmon_events(event_type='memory_scan_event')`
→ chính các dòng `sysmon_events` nói trên (1.170 dòng).
**Cách dùng:** mở từng dòng → xem tiến trình/vùng nhớ bị đánh dấu → đối chiếu tab **Đe dọa** và
**Điều tra hợp nhất** → nếu khả nghi: **Phản hồi → kill process / isolate**.
**Vì sao quan trọng?** Kẻ tấn công hiện đại dùng PowerShell/C# in-memory (không ghi đĩa) nên AV và quét file
đều “mù”; quét RAM là lớp phát hiện cuối cùng. Đổi lại nó **tốn CPU** trên máy trạm ⇒ nên hẹn giờ
(chạy ngoài giờ làm việc) thay vì quét liên tục.
### 3.21 Tổng quan tấn công (`attack`) — nối các điểm rời thành câu chuyện

**Để làm gì:** hiển thị cảnh báo theo **chuỗi tấn công (kill chain)**: từ trinh sát → xâm nhập →
leo thang → lan truyền → thu thập → rút dữ liệu.
**Dữ liệu:** `GET /api/attack/overview` và `GET /api/risk/killchain` →
`server/attack_overview.py` (đọc `threat_alerts` 500 cảnh báo gần nhất + dữ liệu agent:
YARA, lỗ hổng, FIM, inspection, syslog, và cả **tự giám sát server**).
**Cách dùng:**
1. Nhìn các cột/giai đoạn: cột nào có số ⇒ có cảnh báo ở giai đoạn đó.
2. Bấm vào giai đoạn để xem cảnh báo cụ thể.
3. Nếu **một máy xuất hiện ở nhiều giai đoạn** ⇒ rất có thể đang bị xâm nhập thật ⇒ mở Case.
**Vì sao phải xem tab này?** Một cảnh báo = một **điểm**; kill-chain = **đường**. Kẻ tấn công giỏi giữ
mỗi hành vi ở mức “chưa đủ nặng”; chỉ khi xếp cạnh nhau bạn mới thấy đó là một cuộc tấn công.
**Ví dụ liên hệ:** cảnh báo `SRV-SCAN-002` (quét) thường nằm ở giai đoạn **Reconnaissance**,
`THREAT-009` (LSASS) ở **Credential Access**, `CROSS-007` (C2) ở **Command & Control** …

### 3.22 Săn tìm đe dọa (`hunting`) — chủ động tìm, không ngồi đợi

**Để làm gì:** tự đặt câu hỏi điều tra trên **dữ liệu đã có** (không chỉ cảnh báo mới) rồi chạy
thành một **chiến dịch (campaign)** để lưu & so sánh.
**Dữ liệu:** `POST /api/hunt/start` (tạo campaign + chạy), `GET /api/hunt/result/<campaign_id>`
(kết quả), `GET /api/hunt/templates` (mẫu có sẵn), `GET /api/hunt/stats`, `GET /api/hunt/campaigns`;
engine: `server/hunting_engine.py`, `server/threat_hunting.py` (đọc `events`, `sysmon_events`…).
**Cách dùng:** mở tab → chọn **mẫu** (ví dụ: *tải file bằng certutil*, *truy cập LSASS*,
*SMB ngang hàng*, *PowerShell mã hoá base64*) → chỉnh tham số/thời gian → **Chạy** →
đọc bảng kết quả → **Lưu thành campaign** để lần sau chạy lại và so sánh.
**Vì sao cần?** Cảnh báo chỉ bắt cái **đã được viết rule**. Hunting giúp tìm cái **chưa có rule**
(đúng tinh thần “assume breach”). Đây cũng là cách tốt nhất để sinh viên học nhanh: mỗi lần chạy một mẫu,
bạn học được một kỹ thuật MITRE cụ thể.

### 3.23 Bất thường (`anomaly`) — chỉ xem `ANOMALY-*`

**Để làm gì:** gom riêng các cảnh báo *không có chữ ký* để bạn tinh chỉnh (chống “ngộp” cảnh báo giả).
**Dữ liệu:** `GET /api/threats` rồi lọc `rule_id LIKE 'ANOMALY-%'` (cùng bảng `threat_alerts`).
**Số liệu thật:** `ANOMALY-FIRSTTIME-FIRST-TIME-PROCESS` **19** (nhiều nhất — toàn bộ là “lần đầu thấy tiến trình/đường dẫn”)
và `ANOMALY-STATISTICAL-EVENT-COUNT-CURR…` **2** (khối lượng vượt baseline).
**Vì sao nhiều FP ở nhóm này?** Vì máy nào cũng có “lần đầu”: cài phần mềm mới, copy agent sang `D:\dist`,
người dùng chạy công cụ mới… Bộ dò **không biết** đó là bạn ⇒ nó báo theo thiết kế.
**Ba cách làm sạch, theo thứ tự nên dùng:**
1. Nếu là hành vi của bạn ⇒ `false_positive` + ghi chú (để lịch sử nói rằng đã kiểm chứng).
2. Nếu lặp lại hằng ngày (ví dụ path `D:\dist\GiamSatAgent.exe`) ⇒ **Suppression** theo `rule_id` + `machine_id`.
3. Nếu số lượng quá lớn ⇒ xem lại ngưỡng trong `anomaly_detector.py`
   (điểm ghi cảnh báo **≥ 50**, cooldown **300 giây/máy** — hai tham số này là “núm vặn” chính).

### 3.24 Quét IOC (`ioc`) — “máy nào từng dính chỉ dấu này?”

**Để làm gì:** khi có chỉ dấu độc hại (IP/domain/hash) từ báo cáo/tình báo mối đe doạ,
bạn quét **ngược trong lịch sử** và **xuống tận máy trạm** để tìm.
**Dữ liệu:** `POST /api/ioc/sweep` → `server/ioc_sweeper.py` +
`agent/` (lệnh quét trên máy) và `watchlist_matcher.py` (`IOC-WATCH-001` khi máy chạm chỉ dấu).
Các cảnh báo hậu kiểm mang mã `IOC-RETRO-001` (theo IP) / `IOC-RETRO-002` (theo domain).
**Cách dùng (4 bước):**
1. Nạp chỉ dấu vào danh sách theo dõi (menu **Quét IOC** / Watchlist).
   *Hiện `watchlist` = 0 dòng ⇒ phải thêm trước, không thì không có gì để khớp.*
2. Chọn loại chỉ dấu + phạm vi máy → **Quét**.
3. Đọc kết quả: máy/đường dẫn/tiến trình khớp.
4. Nếu có khớp ⇒ tạo **Case** + gói bằng chứng, cân nhắc **Phản hồi → isolate**.
**Vì sao phải quét ngược lịch sử?** Kẻ tấn công thường đã chạm chỉ dấu đó **trước khi** bạn biết nó độc.
Nếu chỉ chặn từ hôm nay, bạn sẽ bỏ sót toàn bộ giai đoạn xâm nhập trước đó.
### 3.25 Điều tra hợp nhất (`investigate`) — MỘT ô tìm kiếm cho cả hệ thống

**Để làm gì:** thay vì mở 10 tab để ghép dữ liệu, bạn gõ **một truy vấn** và nhận kết quả từ **11 nguồn**
cùng lúc, rồi bấm vào bất kỳ giá trị nào để xem “mọi thứ về giá trị đó” (Entity 360).
**Dữ liệu:** `GET /api/investigate/search` → `server/search_engine.py` (dựng SQL động trên nhiều bảng),
`/api/investigate/entity/<loại>/<giá trị>` (Entity 360), `/api/investigate/fields` (gợi ý trường/nguồn),
`/api/investigate/saved` (lưu truy vấn → `saved_searches`), `/api/investigate/export` (CSV/JSON),
và `/api/forensics/*` (cây tiến trình + gói bằng chứng).

**11 nguồn (scopes):** `alerts` (cảnh báo), `events` (Windows Event), `sysmon`, `traffic` (kết nối mạng),
`syslog`, `fim`, `sca`, `yara`, `vulns`, `netflow`, `cases`. Bốn nguồn mặc định là
`alerts`, `events`, `sysmon`, `traffic` (nhanh nhất); bấm chip nguồn để thêm/bớt.

**Cách dùng (từng bước):**
1. Mở tab → bạn luôn thấy **bảng hướng dẫn** (mục đích, cú pháp, 6 truy vấn mẫu bấm được,
danh sách trường). Nếu bạn từng thấy tab này “xoay mãi không ra gì”, đó là lỗi cũ đã được sửa —
nhớ **Ctrl+F5** để nạp lại JavaScript.
2. Bấm một chip mẫu **hoặc** gõ truy vấn rồi **Enter**.
3. Kết quả trả về kèm **facet** (số lượng theo nguồn/mức/máy) — nhìn facet trước để biết nên khoanh vùng ở đâu.
4. Bấm vào **giá trị** trong kết quả (hostname, IP, user, hash…) ⇒ mở **Entity 360**.
5. Trong Entity 360: nút **🌳** = cây tiến trình, **📄** = tạo **gói bằng chứng ±15 phút**,
   **👁** = **xem trước gói bằng chứng mà KHÔNG lưu** (gọi `POST /api/forensics/render?fmt=html`
   và mở HTML trong tab mới) — hãy xem trước để chắc chắn gói có đủ bằng chứng rồi mới bấm 📄 để tạo hồ sơ.
6. Muốn dùng lại truy vấn: **Lưu** (hiện thành chip) hoặc **Xuất CSV/JSON** để đưa ra ngoài.

**Cú pháp (đủ để bạn điều tra mọi thứ):**

| Cú pháp | Ý nghĩa | Ví dụ |
|---|---|---|
| `trường:giá trị` | Lọc theo trường | `hostname:IT-YSNT` |
| `-trường:giá trị` | **Loại trừ** | `user:SYSTEM -hostname:ADMINZ` |
| `"cụm từ"` | Tìm nguyên cụm | `"failed logon"` |
| `A OR B` | Một trong hai | `dst_ip:8.8.8.8 OR dst_ip:1.1.1.1` |
| `*` | Thay thế nhiều ký tự | `cmdline:*`, `dns:*` |
| `giờ` ngầm định | Không ghi thì mặc định 24h; `hours:168` = 7 ngày | `sev:HIGH hours:168` |

**Sáu ví dụ mẫu trong giao diện — số kết quả THẬT trên hệ thống của bạn:**

| Truy vấn | Kết quả | Nó chứng minh điều gì |
|---|---|---|
| `hostname:IT-YSNT` | **634** | Máy này có “dấu chân” ở hầu hết các nguồn |
| `user:SYSTEM -hostname:ADMINZ` | **234** | Cú pháp loại trừ hoạt động |
| `sev:HIGH hours:168` | **209** | Lọc theo mức + khung 7 ngày |
| `event_id:4625` | **28** | Đăng nhập thất bại trên toàn hệ thống |
| `dst_ip:8.8.8.8 OR dst_ip:1.1.1.1` | **22** | Truy vấn nhiều IP một lúc |
| `"powershell"` | **200** | Tìm tự do theo từ khoá trong nội dung |

**Vì sao có truy vấn ra 0 kết quả?** (bài học thực tế từ chính tài liệu này)

- `cmd:powershell` = **0** dù `"powershell"` = **200**: vì `cmd` trỏ tới cột `command_line`,
  còn chữ “powershell” trong dữ liệu của bạn nằm ở cột khác (`process_path`/mô tả cảnh báo).
- `name:IT-YSNT`, `machine:IT-YSNT`, `cve:*`, `facility:daemon` = 0: **sai tên trường**.
  Hãy dùng danh sách **“Trường dùng được”** hiển thị ngay trong panel hướng dẫn
  (`action, by, bytes, cat, cmd, cmdline, computer, cve, dns, domain, dst_ip, eid, event_id, file, hash, host…`).
⇒ **Quy tắc:** kết quả 0 **không** có nghĩa là hệ thống hỏng; hãy thử `*` hoặc bỏ bớt 1 điều kiện để kiểm tra.

**Entity 360 (bấm vào một giá trị) — nó trả về gì?**
`/api/investigate/entity/<loại>/<giá trị>`, `<loại>` ∈ `host, ip, user, hash, file, domain, rule, cve, any`.
Kết quả gồm: `by_scope` (số theo từng nguồn), `hosts`/`ips`/`users`/`rules` (các giá trị liên quan kèm số lần),
`first_seen`/`last_seen`, `total`, `took_ms`, và `results` (timeline).
*Ví dụ thật:* `host/IT-YSNT` trong 168 giờ ⇒ **total 1.686**, `took_ms 127`, `first_seen 2026-09-24 13:34:45`,
`last_seen 2026-10-01 13:28:19`, có trong `hosts`, `ips` (6 IP), `rules` (nhiều `ANOMALY-*`), `users: admin`.
⇒ Chỉ với 1 cú bấm, bạn có **đúng** bức tranh về một máy.

**Cây tiến trình (🌳):** `/api/forensics/process-tree/<machine_id>` → trả `roots` + `flat` + `stats`.
Dữ liệu lấy từ `process_tree_edges` (cạnh cha–con) và sự kiện tiến trình.
*Hiện `process_tree_edges` = 0 dòng* ⇒ cây sẽ trống cho tới khi có Sysmon/collector tiến trình
(xem 3.19). Khi trống, hãy dùng tab **Nhật ký sự kiện** với `event_id:4688` để xem chuỗi tiến trình.

**Gói bằng chứng (📄) — “ảnh chụp” để trình bày:** `POST /api/forensics/evidence`
gom dữ liệu trong **±15 phút** quanh thời điểm bạn chọn (cảnh báo, event, FIM, mạng, Sysmon, YARA/RAM)
thành một gói, **băm SHA-256** để chứng minh không bị sửa, lưu vào bảng `case_evidence`, và cho tải
1 file HTML (in/đính kèm báo cáo) hoặc JSON (cho máy khác đọc).
*Ví dụ thật:* `#4 IT-YSNT – “Hồ sơ ±15p 2026-10-01 10:24:17”`, `window_minutes = 15`,
`sha256 = c8f4161686876a1e…`, người tạo `admin`; `#5` tương tự.
Card **Hồ sơ bằng chứng đã lưu** ngay dưới khung kết quả cho bạn xem lại – tải – xoá (**✕**).

### 3.26 Điều tra (`incident`) — timeline quanh MỘT cảnh báo

**Để làm gì:** khi bạn đã chọn được một cảnh báo nghiêm trọng, tab này dựng **toàn bộ bằng chứng
xung quanh nó** thành một dòng thời gian, để trả lời “chuyện gì đã xảy ra trước/sau?”.
**Dữ liệu:** `GET /api/incident/list` (danh sách cảnh báo cho thanh bên) và `GET /api/incident/<id>`.
`api_incident.py` lấy cửa sổ **±15 phút** quanh thời điểm cảnh báo và gom:
- **Mạng**: phiên kết nối trong cửa sổ đó (`network_traffic`)
- **Sysmon**: EID `1` (tạo tiến trình), `2` (tiến trình đổi tên/thời gian), `3` (kết nối mạng), `11` (tạo file)
- **Windows Event**: `4624` (đăng nhập), `4625` (thất bại), `4672` (đặc quyền), `4688` (tạo tiến trình),
  `5156` (kết nối bị lọc), `7045` (cài service)
- **FIM**, **RAM/YARA**
**Cách dùng:** chọn cảnh báo ở thanh bên → đọc timeline theo thứ tự thời gian → khi thấy mốc đáng ngờ,
bấm sang **Điều tra hợp nhất** với `hostname:` + `event_id:` để đào sâu, hoặc tạo **gói bằng chứng**.
**Vì sao cửa sổ lại là ±15 phút?** Vì hầu hết chuỗi tấn công (tải công cụ → chạy → kết nối ra ngoài)
diễn ra trong vài phút; mở rộng thêm chỉ làm nhiễu.

### 3.27 MITRE ATT&CK (`mitre`) — nhìn theo “bản đồ kỹ thuật”

**Để làm gì:** xếp cảnh báo lên **ma trận ATT&CK** theo `tactic`/`technique` (`T1110s`, `T1003.001`…)
để thấy hệ thống đang phát hiện được gì và **mù** ở đâu.
**Dữ liệu:** `GET /api/mitre/matrix` (ma trận + số cảnh báo mỗi ô), `GET /api/mitre/technique/<id>`
(chi tiết một kỹ thuật), `GET /api/mitre/export/navigator` (tải JSON để nạp vào
*MITRE ATT&CK Navigator*). Giao diện: `static/js/modules/mitre-matrix.js`.
Nguồn dữ liệu là cột `mitre` trong `correlation_rules.yaml` + `threat_alerts`.
**Cách dùng:** chọn ô (tactic × technique) → xem danh sách cảnh báo → bấm tên luật trong modal để
mở đúng cảnh báo đó (tính năng này được kiểm thử trong `tests/ui_wiring_tests.py`).
**Hai điều cần hiểu:**
- Ô **“Unknown/Other”** = rule **không khai báo `mitre`**. Nó không có nghĩa “không nguy hiểm”.
- Muốn phủ rộng ma trận ⇒ viết rule mới có `mitre`/`tactic` (mục 3.32) rồi **Cập nhật Rules**.
### 3.28 Tin nhắn (`messages`) — kênh nói chuyện với người dùng máy trạm

**Để làm gì:** gửi thông báo/yêu cầu tới **người ngồi trước máy** (ví dụ: “máy bạn đang bị cách ly,
liên hệ SOC”) và nhận trả lời.
**Dữ liệu:** `POST /api/message/send`, `/api/message/broadcast` (toàn bộ),
`/api/message/from-agent` (máy trả lời), `GET /api/message/list/<machine_id>` (lịch sử),
`/api/message/unread-count` (số chưa đọc — badge đỏ cạnh menu), `POST /api/message/mark-read`;
bảng `messages` (hiện 0 dòng) và `agent/messages` (dialog trên máy Windows).
**Cách dùng:** chọn máy hoặc **Broadcast** → gõ nội dung → **Gửi**. Tin hiện trên máy trạm dưới dạng hộp thoại;
người dùng có thể trả lời, và câu trả lời quay lại đây.
**Lưu ý vận hành:** tin nhắn **không** gửi được khi agent offline (nó nằm chờ trong bảng `commands`/hàng đợi);
đừng dùng tin nhắn khi máy đã mất liên lạc — hãy liên hệ qua kênh khác (điện thoại).

### 3.29 Nhóm agent (`groups`) — gom máy để làm việc theo nhóm

**Để làm gì:** gom máy thành **nhóm** (theo phòng/khu/vai trò) để: gửi lệnh, cập nhật, áp chính sách,
gửi tin nhắn, xuất báo cáo — theo nhóm thay vì từng máy.
**Dữ liệu:** `GET/POST /api/groups`, `DELETE /api/groups/<id>` (bảng `agent_groups`, `agent_group_members`);
phần **chính sách** do `static/js/modules/group-policies.js` gọi `/api/policies/list|add|update|delete`,
`/api/policies/status-list`, `/api/policies/requeue/<id>`, `/api/policies/preview`, `/api/policies/wave-apply`,
`/api/policies/wave-advance` → bảng `group_policies`, `policy_apply_status`.
**Cách dùng:**
1. **Tạo nhóm** → tích chọn máy → **Thêm vào nhóm**.
2. Tạo **chính sách** (ví dụ: bật auditpol, thêm loại trừ Defender, tần suất quét RAM) rồi gán cho nhóm.
3. Sang tab **Trạng thái chính sách** để xem từng máy đã nhận chưa (`policy_apply_status`);
   máy lỗi/không nhận ⇒ bấm **Gửi lại** (`requeue`).
4. Muốn áp **từng đợt** (an toàn hơn): dùng khối **Chính sách theo đợt** ở tab Coverage (mục 3.4).
**Vì sao cần trạng thái theo từng máy?** Chính sách coi như “gửi xong” khi mọi máy báo `applied`;
nếu chỉ nhìn “đã gửi” bạn sẽ tin nhầm là cả fleet đã tuân thủ.

### 3.30 Cập nhật Agent (`agentupdate`) — nâng cấp phần mềm an toàn

**Để làm gì:** phát hành bản agent mới và theo dõi từng máy đã lên bản chưa.
**Dữ liệu:** `GET /api/agent/version` (bản server đang phát), `POST /api/agent/push-update`
(đẩy cập nhật cho 1 máy / nhóm / toàn bộ), `GET /api/agent/update-log` (bảng `agent_update_log`),
`POST /api/agent/reset-user` (xoá dữ liệu người dùng gắn với máy), `/api/tailscale/authkey` (khoá mạng nội bộ),
và các bảng `update_rollouts`, `update_rollout_targets` (đợt cập nhật).
**Cách dùng chuẩn (khuyến nghị):**
1. Kiểm tra `server/version.txt` = `agent/agent_version.txt` = bản build thật (lệch nhau ⇒ agent cập nhật vòng lặp vô hạn).
2. Vào tab **Cập nhật Agent** → **Xem kế hoạch** (`/api/fleet/rollout/plan`) để biết bao nhiêu máy cần lên bản.
3. Nâng theo **đợt**: đợt 1 = **canary** (1 máy) → theo dõi 1 ngày → đợt 2 (10%) → đợt 3 (100%).
   Nút **Sang đợt kế** sẽ **bị chặn** nếu đợt hiện tại < 90% thành công hoặc có máy lỗi — đây là cơ chế bảo vệ bạn.
4. Máy báo phiên bản **đúng** `target_version` mới tính là xong; máy lỗi xem `update_rollout_targets.message`.
**Ví dụ thật trong DB (rất đáng học):** đợt `#5` nhắm bản `6.0.1`, `waves = [1 máy: 2136a2eb]`,
trạng thái **`rolled_back`**; dòng mục tiêu: `ADMINZ – wave 0 – status skipped – 6.0.0 → 6.0.1`.
⇒ Cách đọc: máy `ADMINZ` **đang offline** nên bị `skipped` ⇒ đợt không đạt ⇒ bạn đã chủ động rollback.
Kết luận nghiệp vụ: *không thể cập nhật máy đã tắt* — hãy xử lý `HEARTBEAT-001` trước, rồi chạy lại đợt.
**Vì sao phải theo đợt thay vì “đẩy tất cả”?** Một bản agent lỗi đẩy cho 100% máy trong 1 phút sẽ làm
bạn **mất toàn bộ khả năng giám sát** cùng lúc. Canary khiến bạn phát hiện lỗi khi chỉ mất 1 máy.

### 3.31 FIM Baseline (`fimbaseline`) — định nghĩa “file nào được phép thay đổi”

**Để làm gì:** giảm cảnh báo nhiễu FIM bằng cách **ghi nhận trạng thái chuẩn** của các file quan trọng
(hash/kích thước/thời gian), sau đó chỉ báo khi lệch khỏi chuẩn.
**Dữ liệu:** `GET /api/fim/baseline/summary` (máy nào có baseline), `GET /api/fim/baseline/<machine_id>`
(chi tiết) → bảng `fim_baseline` (262 dòng).
**Cách dùng:** chọn máy → xem cây thư mục đang được theo dõi → **Tạo/cập nhật baseline**
(sau khi đã xác nhận máy đang sạch) → từ đó mọi thay đổi ngoài baseline là đáng ngờ.
**Nguyên tắc vàng:** **tạo baseline chỉ khi máy đang SẠCH**. Nếu bạn tạo baseline lúc máy đã nhiễm,
bạn đã “hợp thức hoá” luôn file của kẻ tấn công — và nó sẽ không bao giờ bị báo nữa.
### 3.32 Quản lý Rules (`rules`) — bộ não phát hiện, và cách bạn sửa nó

**Để làm gì:** xem/thêm/sửa rule, **thử** rule trên dữ liệu mẫu, và **phát hành** cho toàn bộ agent.
**Dữ liệu:** `GET /api/rules` + `/api/rules/stats` (danh sách + thống kê),
`POST /api/rules/test` (chạy thử), `POST /api/rules/deploy` (copy YAML xuống `agent/rules/` + gửi lệnh
`reload_rules`), `POST /api/rules/reload`. File gốc: **`server/rules/correlation_rules.yaml`**
(**2.062 rule**, `metadata.version: 2.1.0`, `last_updated 2026-09-23`). Việc ghi file do `server/rules_io.py`
thực hiện theo cách đặc biệt: **giữ nguyên phần comment header** rồi ghi YAML vào sau (vì thư viện YAML
thường xoá sạch comment).

**Cấu trúc một rule (nhắc lại gọn):** `id`, `name`, `mitre`, `tactic`, `severity`, `description`, `conditions[]`
trong đó mỗi condition có `type` (`windows_event`/`sysmon`…), `event_id`, `description_contains`,
`subtype`, và bộ đếm `threshold` + `within_seconds` + `group_by`.

**Quy trình thêm một rule mới (5 bước, đúng nghiệp vụ):**
1. **Viết rule** trên màn hình (điền các trường như trên).
2. **Test** bằng `/api/rules/test` với một sự kiện mẫu — phải thấy “match”. Nếu không match, rule chưa đúng.
3. **Deploy** (`/api/rules/deploy`) — file được ghi vào repo và đẩy xuống máy trạm; agent cần nhận `reload_rules`.
4. **Kiểm chứng trên máy**: xem log agent (đã nhận rule mới), và đợi cảnh báo đầu tiên.
5. **Theo dõi 24 giờ**: nếu tỷ lệ cảnh báo giả cao ⇒ *nâng* `threshold`, *tăng* `within_seconds`,
   hoặc **Suppression** (3.33). Đừng để một rule ồn ào che các rule khác.

**Ba điều phải nhớ — đây là “luật chơi” của hệ thống:**

1. **2.062 rule chạy ở AGENT, không chạy ở server** (ghi rõ trong header file). Nếu bạn bật chúng ở server
   ⇒ mỗi cảnh báo sinh **2 lần** và tạo bão cảnh báo giả. Vì vậy màn hình Rules chỉ *quản lý* rule,
   còn *thực thi* là ở agent.
2. **11 rule `CROSS-*` chạy ở server** (`correlation_engine_server.py`). Muốn sửa nhóm này bạn phải sửa **code**
   rồi **khởi động lại server**, không thể sửa qua giao diện.
3. Sau khi deploy rule mới, cần **restart server** nếu rule đó cũng được dùng để phân tích phía server,
   và luôn kiểm tra `agent/rules/` trên máy trạm đã có file mới chưa.

**Ví dụ thật đáng học:** rule `LOG_RESET` (phát hiện xoá log) hiện chiếm **37.219 dòng** dữ liệu.
Cách xử lý đúng không phải “viết lại rule” mà là (a) xác nhận nhiễu, (b) **Suppression**,
(c) nếu cần thì nâng ngưỡng logic so sánh số bản ghi bằng code. Đây chính là kỹ năng **tuning** mà
sinh viên cần học trước khi học viết rule mới.

### 3.33 Chặn cảnh báo giả (`suppression`) — công cụ chống “alert fatigue”

**Để làm gì:** khai báo “cảnh báo loại này trên máy này là đã biết, đừng báo nữa” — có thời hạn và lý do.
**Dữ liệu:** `GET /api/suppression/list`, `POST /api/suppression/add`, `DELETE /api/suppression/remove/<id>`
→ bảng `alert_suppression` (`rule_id`, `machine_id`, `field_path`, `field_hash`, `reason`, `expires_at`).
**Cách dùng:**
1. Từ một cảnh báo đã xác nhận là FP, bấm **Thêm vào chặn** (form tự điền `rule_id`/máy).
2. **Ghì đúng mức**: chặn theo **rule + máy** (không chặn cả rule cho toàn hệ thống).
3. Ghi **lý do rõ ràng** (“GiamSatAgent path D:\dist sau nâng cấp 6.0.1, xác nhận bởi …”).
4. Đặt **thời hạn** (`expires_at`) — chặn vĩnh viễn là cách tạo điểm mù vĩnh viễn.
5. Định kỳ (mỗi tháng) mở danh sách chặn và **rà lại**: rule còn phù hợp không? máy còn tồn tại không?
**Ví dụ FP nên chặn trên hệ thống thật của bạn:**
- `ANOMALY-FIRSTTIME-FIRST-TIME-PROCESS` cho đường dẫn `D:\dist\GiamSatAgent.exe` (chính agent của bạn).
- `SRV-SCAN-002` từ IP `192.168.1.248` (máy kiểm thử của bạn quét server).
- `LOG_RESET` trên `ADMINZ` nếu xác nhận do log cuộn vòng.
**Cảnh báo đạo đức nghề nghiệp:** chặn cảnh báo để “cho sạch dashboard” mà **không xác minh** là sai.
Mỗi dòng trong `alert_suppression` phải trả lời được: *ai xác minh, bằng chứng nào, hết hạn khi nào*.

### 3.34 Cảnh báo Email (`email`) — đưa cảnh báo tới người trực

**Để làm gì:** cấu hình nơi nhận cảnh báo ngoài dashboard: **Email (SMTP)** và **Telegram**.
**Dữ liệu:** `GET /api/email/templates` (mẫu thư), `GET/POST /api/email/config`, `POST /api/email/test`,
`POST /api/email/send` (gửi ngay), `GET /api/email/sent` (lịch sử gửi), `GET/POST /api/alerting/config`
(cấu hình mức nào thì gửi). Cấu hình nằm ở `server/.env` (`GIAMSAT_SMTP_HOST/PORT/USER/PASS`,
`TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`); hàm gửi: `server/email_alerts.py`, tổng hợp ngày: `server/daily_digest.py`.
**Cách dùng:** điền tài khoản SMTP → **Gửi thử** (bắt buộc phải thấy thư) → chọn ngưỡng (mặc định **HIGH+**) → lưu.
**Vì sao mặc định chỉ gửi từ HIGH?** Vì `threat_alerts` có tới **171/199 cảnh báo mức MEDIUM**;
ếu gửi hết, người trực sẽ bỏ qua hộp thư trong 1 tuần — đó là *alert fatigue*, nguyên nhân số 1 khiến
SOC bỏ sót sự cố thật. MEDIUM để lại dashboard, HIGH/CRITICAL mới “réo”.
**Kinh nghiệm cấu hình:** dùng **email riêng cho cảnh báo** + nhãn/lọc tự động;
Telegram phù hợp cho ca trực nhanh; và **luôn kiểm tra lại** `GET /api/email/sent` sau khi cấu hình
để chắc chắn hệ thống thực sự gửi được (test thành công ≠ gửi thật thành công khi có sự cố).
### 3.35 Tài sản (`assets`) — bạn đang quản lý cái gì?

**Để làm gì:** lập **sổ tài sản** (máy tính, máy in, điện thoại IP, thiết bị mạng) — cả thiết bị do agent báo
lẫn thiết bị bạn tự nhập/quét được.
**Dữ liệu:**
- `GET /api/assets/computers` — máy do agent báo (bảng `assets_computers`)
- `GET /api/assets/monitors` — thiết bị giám sát không agent (bảng `assets_monitors`)
- `GET/POST/PUT/DELETE /api/assets/inventory` (+ `/stats`) — kho tài sản nhập tay (bảng `assets_inventory`)
- `POST /api/assets/inventory/<id>/adopt` — “nhận” một thiết bị do hệ thống tự phát hiện thành tài sản chính thức
- `POST /api/assets/discovery/scan` — quét mạng để **tự phát hiện** thiết bị (SNMP + dò chữ ký cổng)
- `GET /api/assets/changes` + `POST /api/assets/changes/<id>/resolve` — **thay đổi phần cứng** (bảng `assets_change_log`)
- `POST /api/assets/users/sync` — đồng bộ danh bạ người dùng
- `GET /api/assets/export` — xuất Excel nhiều sheet
**Cách dùng:** **Quét phát hiện** → xem danh sách “tự phát hiện” → **Adopt** các thiết bị thật →
gán mã hiển thị (`display_id`, ví dụ `PC-001`, `MN-001`) → theo dõi tab **Thay đổi** → xuất Excel khi bàn giao.
**Hiện trạng thật:** `assets_inventory` 0 · `assets_computers` 1 · `assets_change_log` 0 ⇒ bạn đang ở
giai đoạn đầu; đây là việc “nhàm chán nhưng bắt buộc”: **không biết mình có gì thì không bảo vệ được gì**.
**Vì sao theo dõi thay đổi phần cứng?** Đổi mainboard/serial là dấu hiệu **máy bị thay ruột**
hoặc một thiết bị lạ đội lốt máy cũ (MAC/serial bị giả) — chuyện có thật trong môi trường doanh nghiệp.

### 3.36 Quản lý người dùng (`users`) — ai được làm gì

**Để làm gì:** tạo/khoá tài khoản, phân quyền, bật 2FA, đổi mật khẩu, xem phiên.
**Dữ liệu:** `GET/POST/DELETE /api/users`, `POST /api/users/<id>` (đổi vai trò/mật khẩu),
`/api/users/password` (tự đổi), `POST /api/users/<id>/2fa` + `confirm2fa` + `disable2fa`,
`GET /api/auth/check`, `POST /api/logout` → lưu trong `users.json` (thư mục gốc server) + `auth_manager.py`.
**Bốn vai trò (nhớ kỹ):**

| Vai trò | Được làm | Không được làm |
|---|---|---|
| `admin` | Tất cả (kể cả quản lý người dùng, rules, cleanup) | — |
| `analyst` | Xem, xử lý cảnh báo, tạo case, chạy hunting | Quản lý người dùng/rules |
| `command` | Gửi **lệnh phản hồi** xuống máy trạm | Thay đổi cấu hình hệ thống |
| `viewer` | Chỉ xem | Mọi thao tác thay đổi dữ liệu |

**Cách dùng:** **Thêm người dùng** → chọn vai trò theo **nguyên tắc quyền tối thiểu**
(đừng cấp `admin` cho người chỉ cần xem) → yêu cầu người dùng **đổi mật khẩu + bật 2FA** ngay lần đầu.
**Vì sao phải bật 2FA?** Dashboard này điều khiển được **toàn bộ máy trạm** (cô lập, diệt tiến trình);
một mật khẩu bị lộ = mất cả hệ thống. 2FA biến một sự cố rò rỉ mật khẩu thành… một sự cố nhỏ.
**Mọi thao tác quan trọng đều vào `audit_log`** (mục 3.38) ⇒ đừng dùng chung 1 tài khoản cho nhiều người,
vì như vậy bạn mất khả năng truy trách nhiệm.

### 3.37 Dọn dẹp dữ liệu (`cleanup`) — giữ dung lượng trong tầm kiểm soát

**Để làm gì:** xem dung lượng từng bảng và xoá dữ liệu cũ theo tuổi (retention).
**Dữ liệu:** `GET /api/cleanup/summary` (bảng + dung lượng + số dòng), `POST /api/cleanup` (chạy dọn),
`api_cleanup.py` → xoá theo `received_at` của từng bảng.
**Số liệu thật để bạn quyết định:** `events` **172 MB / 123.864 dòng** ·
`network_traffic` **116 MB / 159.026 dòng** · `syslog` **34 MB / 47.017 dòng**
· `heartbeats` 3,9 MB · `sysmon_events` 2,9 MB · `sca_events` 2,0 MB.

| Bảng | Nên giữ bao lâu (gợi ý) | Lý do |
|---|---|---|
| `events` | 30–90 ngày | Điều tra gần đây; dài hơn thì nên rollup (`daily_stats`) |
| `network_traffic` | 30 ngày | Nặng nhất, ít dùng lại sau 1 tháng |
| `syslog` | 30–90 ngày | Tuỳ quy định lưu log của tổ chức |
| `heartbeats` | 7–14 ngày | Chỉ để tính uptime/coverage |
| `threat_alerts`, `cases`, `case_evidence` | **Lâu dài** | Bằng chứng điều tra — **không** dọn tuỳ tiện |

**Cách dùng:** mở tab → đọc bảng tổng hợp → chọn bảng + số ngày → **Dọn** → xem lại summary để xác nhận.
**Ba lưu ý quan trọng:**
1. Dọn bằng `DELETE` trên bảng lớn **rất chậm** và để lại “rác” cho tới khi PostgreSQL `VACUUM`;
   vì vậy với `events`/`network_traffic` hãy chia bảng theo tháng rồi **DROP** (Chương 6) — nhanh hơn hàng chục lần.
2. **Sao lưu trước khi dọn** (`server/backup_pg.bat`) nếu bạn chưa chắc.
3. Đừng dọn bảng bằng chứng/cảnh báo: dữ liệu đó là “trí nhớ” của SOC và cũng là thứ bạn cần khi bị kiểm tra.

### 3.38 Nhật ký kiểm toán (`audit`) — ai đã làm gì, lúc nào

**Để làm gì:** tra lại **mọi thao tác** trên hệ thống — bắt buộc có trong môi trường thật.
**Dữ liệu:** `GET /api/audit` → bảng `audit_log` (**165 dòng** hiện có); mọi route quan trọng gọi
`db.insert_audit_log(username, action, detail, ip)` (xem ví dụ trong `api_forensics.py`:
`evidence_delete`, hoặc gửi lệnh phản hồi, sửa rule, đổi mật khẩu…).
**Cách dùng:** lọc theo **người dùng / hành động / khoảng thời gian**; khi có sự cố, tra theo mốc thời gian
trước/sau để dựng lại diễn biến.
**Vì sao quan trọng với sinh viên?** Đây là *kỹ năng điều tra ngược*: khi không biết hệ thống bị làm gì,
nhật ký kiểm toán là nơi đầu tiên cần xem — kể cả để trả lời “có ai vừa tắt cảnh báo này không?”
(đặc biệt hữu ích khi rà lại **Suppression**: ai thêm, ai xoá).

### 3.39 Cluster (`cluster`) — nhiều máy chủ cùng phục vụ

**Để làm gì:** theo dõi tình trạng các **node** khi bạn chạy nhiều instance server (cùng một DB) để chịu tải
hoặc dự phòng.
**Dữ liệu:** `GET /api/cluster/nodes` → `server/cluster_manager.py`, cấu hình trong `cluster_config.json`
(danh sách node: tên, địa chỉ, vai trò).
**Cách dùng:** khai báo các node trong `cluster_config.json` → mở tab để xem node nào sống/chết, tải ra sao.
**Vì sao cần?** Agent và dashboard có thể rất nhiều; một node chết làm một phần hệ thống “im”.
Với hệ thống nhỏ (2 máy trạm như lab này), tab này chỉ mang tính chuẩn bị.
---

## Chương 4 — Năm câu chuyện điều tra thật (làm theo được ngay)

### Câu chuyện 1 — “Vì sao `IT-YSNT` có tới 137 cảnh báo?”

**Bối cảnh:** mở tab **Đe dọa**, thấy danh sách theo máy: `IT-YSNT` 137 · `Attacker:192.168.1.248` 36 · `ADMINZ` 25.

**Các bước điều tra:**

1. Tab **Coverage** → bảng điểm rủi ro: `IT-YSNT` điểm cao. Nhìn cột phiên bản: **6.0.1** (mới hơn `ADMINZ` 6.0.0).
   ⇒ Gợi ý: máy này vừa được nâng cấp.
2. Tab **Đe dọa** → nhóm theo `rule_id` (hoặc **Đe dọa → gom nhóm**): phần lớn là
   `ANOMALY-FIRSTTIME-FIRST-TIME-PROCESS` (19 cảnh báo), mức MEDIUM.
3. Mở một cảnh báo gần nhất:
   ```
   2026-10-01 13:19:20  IT-YSNT
   [FirstTime] First time: process='D:\dist\GiamSatAgent.exe' on machine f196aff3
   ```
4. Tab **Điều tra hợp nhất** → gõ `hostname:IT-YSNT event_id:4688 hours:24` ⇒ xem tiến trình đó do cái gì gọi,
   có chữ ký số không, có kết nối ra ngoài không.
5. Kết luận: **FP theo ngữ cảnh** — chính bản agent mới cài ở `D:\dist\` lần đầu chạy.

**Hành động đúng:**
- Đặt 1 cảnh báo thành `false_positive`, ghi chú: *“GiamSatAgent.exe 6.0.1 sau nâng cấp, xác nhận bởi …”*.
- Vì cùng loại sẽ lặp lại mỗi lần cập nhật ⇒ tạo **Suppression** cho
  `rule_id = ANOMALY-FIRSTTIME-FIRST-TIME-PROCESS` + `machine_id = f196aff3`, hết hạn sau 30 ngày.
- Nếu bạn **không** kiểm tra mà chặn cả rule `ANOMALY-FIRSTTIME` cho toàn hệ thống ⇒ bạn vừa tạo **điểm mù**
  cho mọi máy khác — đây là lỗi nghiêm trọng nhất mà người mới hay mắc.

### Câu chuyện 2 — “`ADMINZ` biến mất 40 giờ”

**Bối cảnh:** tab **Đe dọa** có 15 cảnh báo **CRITICAL** `HEARTBEAT-001`.

```
Agent ADMINZ (2136a2eb) has been offline for 144271s (2404 minutes). No graceful
shutdown signal received. Possible agent kill, system crash, or network isolation.
```

**Các bước điều tra:**
1. Tab **Tổng quan** → máy `ADMINZ` hiện `is_online = 0`, `last_seen = 2026-09-29 21:16`; `sysmon_present = 0`.
2. Tab **Coverage → Sức khỏe đội máy** → `ADMINZ` thuộc nhóm offline (không phải silent).
3. Kiểm tra dữ liệu: `daily_stats` ngày 2026-10-01 của `ADMINZ`: `events = 0`, `alerts = 4`, `syslog = 0`.
   ⇒ Máy **không gửi gì** trong ngày; 4 cảnh báo là do dead-man switch tự sinh.
4. Tab **Cập nhật Agent** → đợt `#5` bản `6.0.1` có dòng `ADMINZ – skipped` ⇒ đúng lúc đợt chạy thì máy đã tắt.
5. Vật lý: máy có được bật? dịch vụ `GIAM-SAT Agent` còn không? mạng/VPN còn không?

**Kết luận:** không phải tấn công — máy tắt. Nhưng nếu đây là **máy trọng yếu**, việc mất log 40 giờ
vẫn là **sự cố nghiêm trọng về giám sát**.
**Hành động:** bật lại máy + kiểm tra service → xác nhận log quay lại (Coverage hết offline) →
trả các cảnh báo `HEARTBEAT-001` về `resolved`. Nếu máy đã bỏ hẳn: dùng **Xoá offline** ở tab Tổng quan
(ghi chú lý do) để dashboard không nhiễu.

### Câu chuyện 3 — “Nguồn `192.168.1.101` (`LAPTOP-14`) bị từ chối 311 message”

**Bối cảnh:** tab **Coverage → Sức khỏe đội máy** hiện cảnh báo **nguồn bị TỪ CHỐI**: IP `192.168.1.101`,
đã xác định là máy `LAPTOP-14`, tổng **311 message bị chặn** (206 `network_traffic`, 30 `windows_event`,
30 `heartbeat`, 17 `sca_event`).

**Chuyện gì đã xảy ra (nguyên nhân → kết quả):**
- Agent cài trên `LAPTOP-14` đọc trong file cấu hình **PSK sai hoặc rỗng**,
  trong khi server kiểm tra `GIAMSAT_AGENT_PSK` khi agent đăng ký.
- `tcp_server.py` **từ chối** mỗi message ⇒ agent thử lại liên tục ⇒ số bị chặn tăng dần.
- Vì bị chặn ở bước xác thực, dữ liệu **không bao giờ** vào bảng `events`/`network_traffic`
  ⇒ tab Nhật ký/Mạng **không thấy máy này**, và nó cũng không xuất hiện ở danh sách máy trạm.

**Hành động (5 bước):**
1. Trên `LAPTOP-14`, mở `C:\ProgramData\GIAM-SAT\Agent\agent_config.json`.
2. Đặt trường PSK **giống hệt** `GIAMSAT_AGENT_PSK` trong `server/.env` (không thừa khoảng trắng, không đổi hoa–thường).
3. Khởi động lại dịch vụ agent **và updater** (updater dùng cùng cấu hình).
4. Xác nhận dữ liệu vào: xem `heartbeats`/`events` tăng, máy xuất hiện trong **Coverage**.
5. Bấm **Xử lý** trên cảnh báo để xem hướng dẫn rồi ẩn cảnh báo (hệ thống ghi nhận đã xử lý).

**Bài học:** *“Không thấy máy trong dashboard”* khác *“máy không hoạt động”*. Việc đầu tiên là
mở **Coverage** xem có nguồn bị từ chối — vì đó là chỗ duy nhất nói cho bạn biết *dữ liệu đã bị chặn*.

### Câu chuyện 4 — “Đọc một đợt cập nhật bị rollback”

**Dữ liệu thật:** đợt `#5` → `target_version = 6.0.1`, `state = rolled_back`,
`waves_json = [{"index":0,"pct":1.0,"machines":["2136a2eb"]}]` (đợt 1 = 1 máy canary) và dòng mục tiêu
`ADMINZ · wave 0 · status skipped · 6.0.0 → 6.0.1`.
**Đọc:** canary chọn máy `ADMINZ` (id `2136a2eb`) — nhưng máy đang offline nên bị **bỏ qua** ⇒
đợt không đạt ngưỡng ⇒ hệ thống **chặn** việc sang đợt tiếp và người vận hành đã **rollback**.
**Kết luận:** đây là hệ thống **hoạt động đúng** — nó ngăn bạn đẩy bản mới cho 100% máy khi canary chưa xác nhận.
**Hành động:** chọn máy canary **đang online** (ví dụ `IT-YSNT`), chạy lại đợt 1, theo dõi 24h, rồi mới sang đợt 2.

### Câu chuyện 5 — “Vì sao 37.219 dòng `LOG_RESET`?” (bài học tuning)

1. Vào **Nhật ký sự kiện** → lọc `event_id = LOG_RESET` → thấy đây là bản ghi **ALERT**, `category = Tampering`:
   *“Event log 'X' was CLEARED or reset (record number dropped from 19254 to 19254)”*.
2. Nhận xét: `19254 → 19254` (**không giảm**) ⇒ **không** phải bị xoá; chỉ là log cuộn vòng.
3. Vì vậy: rule đúng logic nhưng **ngữ cảnh sai** ⇒ phần lớn là nhiễu.
4. Hành động: xác nhận trên 2–3 kênh log, đặt `false_positive`, rồi **Suppression** theo rule + máy;
   nếu muốn triệt để: sửa điều kiện để chỉ báo khi số bản ghi **thực sự giảm**.
**Bài học:** con số lớn **không** đồng nghĩa với tấn công lớn. Trước khi hoảng, hãy đọc **1 dòng dữ liệu gốc**.
---

## Chương 5 — “Không thấy dữ liệu”: gỡ lỗi theo 7 lớp

**Nguyên tắc:** dữ liệu phải đi qua 7 lớp. Sai ở lớp nào thì sửa ở lớp đó — **đừng nhảy lớp**.

| Lớp | Kiểm tra thế nào | Nếu lớp này hỏng |
|---|---|---|
| 1. Agent chạy | Services trên máy trạm có `GIAM-SAT Agent`; tab Tổng quan có máy | Không có máy nào trong danh sách |
| 2. Xác thực (PSK/TLS) | Tab **Coverage → nguồn bị từ chối**; log agent | Coverage báo nguồn bị từ chối (Câu chuyện 3) |
| 3. Server nhận | Log `logs/giamsat.log` có dòng mới; `heartbeats` tăng | Bảng trống, không log |
| 4. Ghi DB | `SELECT COUNT(*) FROM events;` tăng theo thời gian | Số không đổi dù agent gửi |
| 5. API trả | `curl /api/events` (đã đăng nhập) thấy JSON | Dashboard trắng, API 401/403/500 |
| 6. JS vẽ | F12 → Console xem có lỗi đỏ không | Bảng “quay mãi”, ô trống |
| 7. Cache trình duyệt | **Ctrl+F5** | Vẫn thấy giao diện cũ dù server đã cập nhật |

### 5.1 Bảng chẩn đoán: triệu chứng → nguyên nhân → cách xử lý

| Triệu chứng bạn thấy | Nguyên nhân hay gặp | Cách kiểm tra | Cách sửa |
|---|---|---|---|
| Máy không xuất hiện trong danh sách | Agent chưa cài/chưa chạy, hoặc bị từ chối PSK | Coverage → nguồn bị từ chối; Services trên máy | Sửa PSK trong `agent_config.json`, restart agent + updater |
| Máy có trong danh sách nhưng **không có log** | Bị `rate_limiter` chặn vì flood, hoặc firewall, hoặc log bị tắt | Coverage cờ `no_logs`/`log_drop`; `ingest_anomalies` | Sửa cấu hình, kiểm tra firewall, tăng tần suất gửi |
| Số dòng ngừng tăng | Agent chết (đúng lúc đó thường có `HEARTBEAT-001`) | Tab Đe dọa; `machines.last_seen` | Bật lại máy/dịch vụ |
| Tab **Nhật ký sự kiện** trống dù có máy | Truy vấn sai bộ lọc (máy/thời gian) hoặc `events` chưa có dữ liệu | Bỏ hết bộ lọc; `SELECT COUNT(*) FROM events;` | Xoá bộ lọc; kiểm tra agent gửi loại event nào |
| **Điều tra hợp nhất** “quay mãi” | Giao diện cũ còn cache (lỗi đã sửa ở v5.0.9) | F12 Console; xem file JS có `renderWelcome` | **Ctrl+F5**; nếu server chưa cập nhật thì deploy lại `static/js` |
| Truy vấn trả **0 kết quả** | Sai tên trường (ví dụ `cmd:` thay vì `cmdline:`) hoặc khoảng thời gian quá hẹp | So với danh sách **Trường dùng được** trong panel hướng dẫn | Bỏ 1 điều kiện, thử `*`, tăng `hours:` |
| Tab **Sysmon** trống | Chưa cài Sysmon/bật collector (bảng chỉ có `memory_scan_event`) | `SELECT event_type, COUNT(*) FROM sysmon_events GROUP BY 1;` | Cài Sysmon + cấu hình XML + bật collector, restart agent |
| Tab **NetFlow** trống | Thiết bị chưa xuất NetFlow | `SELECT COUNT(*) FROM netflow_flows;` | Bật NetFlow trên switch/router, trỏ về UDP **2055** |
| Tab **Lỗ hổng** trống | Agent chưa gửi inventory phần mềm | `SELECT COUNT(*) FROM vuln_alerts;` | Bật thu thập phần mềm trong cấu hình agent |
| Bảng “quay mãi” ở tab cũ khác | JS không tải được (404/ lỗi cú pháp) | F12 → Network/Console | Kiểm tra file trong `static/js/modules/`, chạy `python tests/dashboard_ui_tests.py` |
| Dashboard hiện chữ “lạ”/tiếng Anh lẫn tiếng Việt | Thiếu key i18n / key trùng | `python tests/ui_wiring_tests.py` | Thêm key vào **cả** `vi` và `en` trong `i18n.js` |
| Giao diện không đổi dù đã sửa file | Server cache template hoặc trình duyệt cache JS | Xem HTML trả về (`curl /`) | Ctrl+F5; khởi động lại server nếu sửa `templates/` |
| Lỗi ghi dữ liệu khi bảng đã partition | `ON CONFLICT` không hoạt động trên bảng partition (PostgreSQL) | Log server có `42P10` | Server đã tự phát hiện `is_events_partitioned()` và dùng `INSERT … WHERE NOT EXISTS` |
| Cảnh báo mới không hiện dù rule đã deploy | Agent chưa nhận `reload_rules` | Log agent | Deploy lại (**Cập nhật Rules**), kiểm tra `agent/rules/` |
| Ổ đĩa đầy / DB chậm | `events` 172 MB, `network_traffic` 116 MB tăng liên tục | `/api/health/storage` | Cleanup + **partition theo tháng** + rollup (Chương 6) |

### 5.2 Ba câu hỏi vàng trước khi báo lỗi cho người khác

1. **Lỗi ở lớp nào trong 7 lớp?** (đã “tách” được chưa? đừng báo chung “dashboard không chạy”)
2. **Có bản ghi nào trong DB không?** (`SELECT COUNT(*) …`) — nếu DB có mà màn hình không có ⇒ lỗi lớp 5–7.
3. **Thay đổi gần nhất là gì?** (nâng cấp agent? deploy rule? sửa `.env`?) — 80% sự cố đến từ thay đổi gần nhất.

---

## Chương 6 — Vận hành & bảo trì

### 6.1 Chiến lược dữ liệu: ngắn hạn ở bảng thô, dài hạn ở rollup

**Vấn đề:** `events` 172 MB và `network_traffic` 116 MB — cứ hỏi “30 ngày qua thế nào” bằng cách quét bảng thô
là tự làm chậm hệ thống. **Giải pháp 3 tầng:**

| Tầng | Là gì | Giữ bao lâu | Dùng để |
|---|---|---|---|
| Thô | `events`, `network_traffic`, `syslog` | 30–90 ngày | Điều tra chi tiết, trích bằng chứng |
| Tổng hợp | `daily_stats` (1 dòng = 1 ngày × 1 máy) | **vĩnh viễn** | Báo cáo, biểu đồ, câu hỏi dài hạn |
| Hồ sơ | `threat_alerts`, `cases`, `case_evidence` | **vĩnh viễn** | Bằng chứng, trách nhiệm giải trình |

### 6.2 Chia bảng theo tháng (partition) — để xoá dữ liệu “tức thì”

- **Vì sao?** Xoá 1 tháng dữ liệu bằng `DELETE` trên bảng lớn rất chậm; nếu bảng chia theo tháng thì
  **DROP** cả phân vùng chỉ mất vài giây.
- **Công cụ:** `server/partitioning.py` + `tools/partition_events.py`.
- **Cách làm (đúng quy trình):**
  1. **Thử (không đổi gì):** `python tools\partition_events.py --table events`
  2. Đọc kế hoạch (bao nhiêu dòng sẽ chuyển), chọn **giờ thấp điểm**.
  3. **Áp dụng:** `python tools\partition_events.py --table events --apply`
  4. Kiểm tra lại ở tab **Coverage → Dung lượng & partition** (cột “Partition” phải hiện *N tháng*).
- **Lưu ý PostgreSQL:** bảng partition **không cho `PRIMARY KEY` đặt trên bảng cha** như bảng thường;
  hệ thống đã xử lý (và ghi lại bài học này trong `tests/partition_tests.py`).
- **Hiện trạng:** chưa bảng nào được partition ⇒ cột “Partition” đang hiện *chưa* và có dòng cảnh báo
  nhắc bạn — đó là gợi ý hành động, không phải lỗi.
### 6.3 Rollup `daily_stats` — sinh số liệu tổng hợp để hỏi nhanh

- **Là gì:** gom dữ liệu thô của 1 ngày thành 1 dòng/máy: `events`, `sysmon`, `alerts`, `traffic`, `syslog`.
- **Gọi từ đâu:** nút **Rollup ngay** ở Coverage → `POST /api/health/storage/rollup` (tham số `days`).
- **Hiện có:** **26 dòng** thật (ví dụ `2026-10-01 · IT-YSNT · events 1.670 · sysmon 26 · alerts 5 · traffic 13.030`
  và `2026-10-01 · Vigor: · syslog 3.890`).
- **Nên hẹn lịch:** mỗi ngày 01:00 chạy rollup cho ngày hôm trước (Task Scheduler gọi
  `curl -X POST /api/health/storage/rollup -d '{"days":2}'` với tài khoản admin).
- **Lợi ích đo được:** báo cáo 30 ngày đọc 26–900 dòng thay vì quét 123.864 dòng.

### 6.4 DROP dữ liệu quá hạn (chỉ an toàn khi đã partition)

- Nút **DROP dữ liệu quá hạn** → `POST /api/health/storage/drop-old` với `retention_days`.
- Cơ chế: chỉ xoá **các phân vùng** cũ hơn số ngày cho phép; bảng chưa partition ⇒ không làm gì (an toàn).
- Quy trình: bật partition (6.2) → chờ 1 tháng dữ liệu mới → đặt lịch DROP hằng tháng → luôn **sao lưu trước** lần đầu.

### 6.5 Sao lưu & phục hồi

- Script có sẵn: `server/backup_pg.bat` (dump PostgreSQL). **Tần suất gợi ý:** hằng ngày (giữ 14 bản)
  + 1 bản mỗi tuần giữ 3 tháng.
- **Quan trọng nhất:** phải **thử phục hồi** ít nhất 1 lần.
  Một bản backup chưa từng phục hồi = *giả định*, không phải *sao lưu*.
- Trước các thao tác nguy hiểm (partition, cleanup, drop-old, nâng cấp): chạy backup.

### 6.6 Lịch vận hành định kỳ (in ra dán tường)

| Chu kỳ | Việc | Ở đâu | Tiêu chí “ổn” |
|---|---|---|---|
| Mỗi ngày | Dọn hàng đợi cảnh báo: hết `new` | Đe dọa | 0 cảnh báo CRITICAL `new` |
| Mỗi ngày | Xem **Coverage**: có nguồn bị từ chối? máy im lặng? | Coverage | Không nguồn bị từ chối; mọi máy có log |
| Mỗi ngày | Kiểm tra dung lượng + rollup | Coverage → Dung lượng | Dung lượng tăng chậm, `daily_stats` có dòng mới |
| Mỗi tuần | Rà `HEARTBEAT-001`, máy offline | Đe dọa / Tổng quan | Máy tắt đã được xử lý hoặc xoá khỏi danh sách |
| Mỗi tuần | Rà **Suppression** còn phù hợp? | Chặn cảnh báo giả | Không có mục hết hạn mà còn treo |
| Mỗi tuần | Rà SCA `FAIL` + vá phần mềm | SCA / Lỗ hổng | Số FAIL giảm dần |
| Mỗi tháng | Backup + thử phục hồi; DROP phân vùng cũ | Ngoài giao diện + Coverage | Phục hồi thành công; dung lượng giảm |
| Mỗi tháng | Cập nhật agent theo đợt; đổi mật khẩu/PSK định kỳ | Cập nhật Agent / .env | 100% máy đúng phiên bản |

### 6.7 Nâng cấp an toàn (quy tắc bất di bất dịch)

1. Đồng bộ **`server/version.txt` = `agent/agent_version.txt`** = bản build thật. Lệch nhau ⇒ agent cập nhật vòng lặp vô hạn.
2. Build agent → thử trên **1 máy canary** → theo dõi 24h (`Coverage` + `Nhật ký`).
3. Chỉ khi canary khoẻ (≥ 90% đạt, 0 lỗi) mới **Sang đợt kế**.
4. Nâng cấp server khi đã có backup; sau nâng cấp kiểm tra: đăng nhập, 1 truy vấn Điều tra, 1 cảnh báo mới, rollup.

### 6.8 Bảo mật hệ thống (checklist)

- Mật khẩu admin **không** để mặc định; bật **2FA** cho mọi tài khoản có quyền `command`.
- `GIAMSAT_AGENT_PSK` và `GIAMSAT_COMMAND_KEY` là **khoá bí mật** — không đưa vào tài liệu/ảnh chụp.
- Agent nối bằng **TLS**; không mở cổng 6666 ra Internet (chỉ LAN/VPN).
- Đổi PSK định kỳ ⇒ khi đổi phải cập nhật **toàn bộ** agent (nếu không sẽ ra Câu chuyện 3).
- Tắt **trợ lý AI** nếu không được phép gửi dữ liệu ra ngoài (`GIAMSAT_DISABLE_AI`).
- Xem `audit_log` sau mỗi ca trực: *“hôm nay ai đã gửi lệnh, ai đã chặn cảnh báo?”*.
---

## Phụ lục A — Bảng API theo nhóm (để tra khi cần)

Tất cả đều yêu cầu đăng nhập (`check_auth`), chạy ở `http://<server>:5000`.

| Nhóm | Endpoint chính |
|---|---|
| Xác thực & người dùng | `POST /api/login`, `/api/logout`, `GET /api/auth/check`, `/api/users`, `/api/users/<id>`, `/api/users/password`, `/api/users/<id>/2fa` |
| Máy trạm | `GET /api/machines`, `/api/stats`, `/api/event_types`, `/api/machine/<id>/config`, `/api/machine/<id>/stop|delete`, `/api/machine/<id>/isolate|unisolate` |
| Sự kiện & log | `/api/events`, `/api/events/stream` (SSE), `/api/fim`, `/api/syslog`, `/api/sysmon`, `/api/memory` |
| Mạng | `/api/network`, `/api/netflow/stats`, `/api/inspection` |
| Cảnh báo | `/api/threats`, `/api/threats/grouped`, `/api/threats/<id>/status|assign|comment`, `/api/vulns`, `/api/yara`, `/api/sca` |
| Điều tra | `/api/investigate/search`, `/api/investigate/entity/<kind>/<value>`, `/api/investigate/fields`, `/api/investigate/saved`, `/api/investigate/export` |
| Pháp y | `/api/forensics/process-tree/<machine_id>`, `/api/forensics/evidence` (GET/POST), `/api/forensics/evidence/<id>` (GET/DELETE), `/api/forensics/render` |
| Sự việc | `/api/incident/list`, `/api/incident/<id>`, `/api/cases`, `/api/cases/<id>`, `/api/cases/<id>/status` |
| Săn tìm | `/api/hunt/start`, `/api/hunt/result/<campaign>`, `/api/hunt/templates`, `/api/hunt/stats`, `/api/hunt/campaigns`, `/api/ioc/sweep` |
| Phân tích | `/api/attack/overview`, `/api/risk/killchain`, `/api/risk/hosts`, `/api/mitre/matrix`, `/api/mitre/technique/<id>`, `/api/mitre/export/navigator` |
| Phản hồi | `/api/response/actions`, `/api/response/execute`, `/api/responses`, `/api/command` |
| Nhóm & chính sách | `/api/groups`, `/api/policies/list`, `/api/policies/preview`, `/api/policies/wave-apply`, `/api/policies/wave-advance`, `/api/policies/status-list`, `/api/policies/requeue/<id>` |
| Cập nhật agent | `/api/agent/version`, `/api/agent/push-update`, `/api/agent/update-log`, `/api/agent/reset-user`, `/api/tailscale/authkey` |
| Đội máy & dung lượng | `/api/health/fleet`, `/api/health/coverage`, `/api/health/ingest/ack`, `/api/health/storage`, `/api/health/storage/rollup`, `/api/health/storage/drop-old` |
| Rollout | `/api/fleet/rollout/plan`, `/api/fleet/rollout`, `/api/fleet/rollouts`, `/api/fleet/rollout/<id>`, `/api/fleet/rollout/<id>/advance|rollback` |
| Rules | `/api/rules`, `/api/rules/stats`, `/api/rules/test`, `/api/rules/deploy`, `/api/rules/reload` |
| Chống nhiễu | `/api/suppression/list`, `/api/suppression/add`, `/api/suppression/remove/<id>` |
| Thông báo | `/api/email/templates`, `/api/email/config`, `/api/email/test`, `/api/email/send`, `/api/email/sent`, `/api/alerting/config`, `/api/telegram/send` |
| Tin nhắn | `/api/message/send`, `/api/message/broadcast`, `/api/message/list/<machine_id>`, `/api/message/unread-count`, `/api/message/mark-read` |
| Tài sản | `/api/assets/computers`, `/api/assets/monitors`, `/api/assets/inventory`, `/api/assets/inventory/stats`, `/api/assets/discovery/scan`, `/api/assets/changes`, `/api/assets/export` |
| Không agent | `/api/agentless/devices`, `/api/agentless/clear`, `/api/agent/onboarding` |
| Báo cáo | `/api/reports/generate`, `/api/reports/download/<file>`, `/api/reports/machine-config-html` |
| Hệ thống | `/api/cleanup/summary`, `/api/cleanup`, `/api/audit`, `/api/cluster/nodes`, `/api/ai/status`, `/api/ai/toggle`, `/api/dashboard/list`, `/api/dashboard/render` |

**Kiểm tra nhanh bằng 1 script Python** (dùng đúng cách hệ thống đang làm — chú ý thư viện `utf-8-sig` cho `.env`):

```python
import io, requests
env = {}
for line in io.open(r"server\.env", encoding="utf-8-sig"):
    line = line.strip()
    if "=" in line and not line.startswith("#"):
        k, _, v = line.partition("="); env[k.strip()] = v.strip().strip('"')
B = "http://127.0.0.1:5000"
s = requests.Session()
s.post(B + "/api/login", json={"username": env["GIAMSAT_ADMIN_USER"],
                               "password": env["GIAMSAT_ADMIN_PASSWORD"]}, timeout=20)
print(s.get(B + "/api/threats", timeout=30).json())
```

**Đếm dữ liệu trực tiếp trong PostgreSQL** (thay cho việc đoán số):

```sql
SELECT COUNT(*) FROM events;                                 -- 123.864
SELECT rule_id, COUNT(*) FROM threat_alerts GROUP BY 1 ORDER BY 2 DESC LIMIT 10;
SELECT severity, status, COUNT(*) FROM threat_alerts GROUP BY 1,2;
SELECT COUNT(*) FROM syslog WHERE received_at > NOW() - INTERVAL '1 hour';
SELECT event_type, COUNT(*) FROM sysmon_events GROUP BY 1;
SELECT * FROM pg_stat_user_tables ORDER BY n_live_tup DESC LIMIT 10;
```

## Phụ lục B — Thuật ngữ (cho người mới)

| Thuật ngữ | Nghĩa dễ hiểu |
|---|---|
| **Agent** | Chương trình cài trên máy trạm, thu log và tự phát hiện |
| **PSK** | Khoá chia sẻ trước: “mật khẩu” giữa agent và server |
| **TLS** | Kênh mã hoá giữa agent và server |
| **Heartbeat** | Nhịp tim agent gửi định kỳ để chứng minh còn sống |
| **Dead-man switch** | Cơ chế báo động khi **mất** nhịp tim (>300s) |
| **Rule / signature** | Điều kiện “nếu … thì báo” cho mẫu đã biết |
| **Correlation** | Ghép nhiều sự kiện (theo thời gian/nguồn/máy) thành một cảnh báo |
| **z-score** | Số độ lệch chuẩn so với trung bình ⇒ đo “lạ đến mức nào” |
| **Baseline** | Trạng thái “bình thường” đã học (mạng, tiến trình, log) |
| **FP (false positive)** | Cảnh báo giả: máy báo nhưng thực tế vô hại |
| **FN (false negative)** | Bỏ sót: có tấn công mà không báo |
| **Triage** | Phân loại ưu tiên cảnh báo |
| **Kill chain** | Chuỗi giai đoạn của một cuộc tấn công |
| **MITRE ATT&CK** | Bản đồ kỹ thuật tấn công (tactic/technique) |
| **IOC** | Chỉ dấu xâm nhập (IP, domain, hash…) |
| **Retro hunt** | Quét ngược thời gian khi mới biết một IOC |
| **FIM** | Giám sát toàn vẹn file |
| **SCA** | Chấm điểm cấu hình bảo mật của máy |
| **Sysmon** | Công cụ Sysinternals ghi sự kiện tiến trình/mạng chi tiết |
| **NetFlow** | Số liệu luồng mạng do thiết bị mạng xuất |
| **Syslog** | Chuẩn log mà router/thiết bị gửi ra |
| **Partition** | Chia bảng thành nhiều phần theo tháng để xoá/quản lý nhanh |
| **Rollup** | Tổng hợp sẵn dữ liệu (ngày × máy) để hỏi nhanh |
| **Retention** | Thời gian giữ dữ liệu trước khi xoá |
| **Suppression** | Chặn có thời hạn một loại cảnh báo đã biết là nhiễu |
| **Coverage** | Mức độ phủ dữ liệu: máy nào còn gửi log, thiếu nguồn nào |
| **Evidence packet** | Gói bằng chứng ±15 phút quanh một thời điểm, có SHA-256 |
## Phụ lục C — Bài tập 7 ngày cho sinh viên mới

Mỗi ngày 30–45 phút, đều dùng dữ liệu **thật** trên hệ thống test.

| Ngày | Mục tiêu | Việc làm cụ thể | Kết quả phải đạt |
|---|---|---|---|
| 1 | Hiểu kiến trúc & dữ liệu | Đọc Chương 1; mở tab **Nhật ký sự kiện**; tìm 1 `event_id` = `4688`; ghi ra: agent nào, bảng nào, API nào | Vẽ lại được sơ đồ 1.1 bằng tay |
| 2 | Hiểu cảnh báo | Mở tab **Đe dọa**; chọn 3 cảnh báo khác loại (`THREAT-044`, `ANOMALY-FIRSTTIME…`, `HEARTBEAT-001`); với mỗi cái nêu **nguồn sinh ra** theo Chương 2 | Giải thích được *vì sao* mỗi cảnh báo tồn tại |
| 3 | Điều tra một máy | Tab **Điều tra hợp nhất** → `hostname:IT-YSNT` → bấm vào hostname để mở **Entity 360**; đọc `by_scope`, `first_seen`, top rules | Trả lời: máy này “ồn” ở nguồn nào nhất? |
| 4 | Xử lý cảnh báo | Chọn 5 cảnh báo MEDIUM ⇒ kiểm chứng bằng Nhật ký ⇒ đặt `false_positive`/`resolved` + ghi chú | Hàng đợi `new` giảm; biết dùng comment |
| 5 | Bằng chứng | Tạo **gói bằng chứng 📄** cho 1 cảnh báo; tải HTML; kiểm tra đủ 4 nguồn (mạng, Sysmon/Event, FIM, cảnh báo) | Trình bày được 1 sự việc trong 1 file |
| 6 | Vận hành | Tab **Coverage**: đọc nguồn bị từ chối, cờ `no_sysmon`/`no_auditpol`; bấm **Rollup ngay** ở khối Dung lượng; xem `daily_stats` | Chỉ ra được 1 việc cần sửa cho `ADMINZ` |
| 7 | Chủ động | Tab **Săn tìm đe dọa**: chạy 1 mẫu; xem **MITRE ATT&CK** và tìm rule tương ứng trong `correlation_rules.yaml` | Nêu 1 kỹ thuật MITRE và rule phát hiện nó |

**Bài tập nâng cao (tự chọn):** viết 1 rule mới (mục 3.32) phát hiện `certutil -urlcache`;
thử `/api/rules/test`; deploy; theo dõi 24h và **ghi lại tỉ lệ cảnh báo giả** — đây chính là công việc thật của SOC engineer.

## Phụ lục D — Câu hỏi thường gặp (FAQ)

**1. Dashboard không có dữ liệu, tôi nên bắt đầu từ đâu?**
Tab **Coverage**. Nếu có **nguồn bị từ chối** ⇒ sửa PSK (Câu chuyện 3). Nếu không, đi theo 7 lớp ở Chương 5.

**2. Vì sao máy báo “online” mà vẫn không có log?**
Vì có nhịp tim nhưng không có sự kiện: kiểm tra cờ `no_logs`/`log_drop`; có thể log bị tắt, bị `rate_limiter` chặn,
hoặc máy không có gì để ghi (ví dụ auditpol tắt ⇒ một số loại event không bao giờ sinh ra).

**3. Vì sao cùng một sự việc mà tôi thấy cả `THREAT-044` lẫn `ANOMALY-FIRSTTIME`?**
Vì hai cơ chế độc lập: một cái theo **chữ ký** (đường dẫn lạ), một cái theo **hành vi lần đầu**.
Đó là *thiết kế* (hai lưới an toàn), không phải lỗi. Hãy gộp thành 1 **Case** thay vì xử lý rời.

**4. Tôi có nên xoá hết cảnh báo cũ cho sạch dashboard?**
Không. Hãy **xử lý** (`resolved`/`false_positive` + ghi chú) để giữ lịch sử. Xoá dữ liệu cảnh báo/case
là mất bằng chứng — chỉ dùng **Cleanup** cho bảng log thô (`events`, `network_traffic`, `syslog`).

**5. Vì sao 37.219 dòng `LOG_RESET`?**
Đó là cảnh báo **xoá log** do agent sinh (category `Tampering`), và phần lớn là **nhiễu do log cuộn vòng**
(ví dụ “record number dropped from 19254 to 19254”). Xử lý: xác minh 2–3 dòng → `false_positive` → Suppression.

**6. Truy vấn Điều tra hợp nhất trả 0, có phải hệ thống hỏng?**
Không. Kiểm tra 3 thứ: **tên trường** (dùng danh sách “Trường dùng được”), **khoảng thời gian** (`hours:`),
và **thử rộng hơn** (`*`). Ví dụ thật: `cmd:powershell` = 0 nhưng `"powershell"` = 200.

**7. Vì sao tôi không thấy Sysmon dù `sysmon_present = 1`?**
Vì cờ đó chỉ nói *có Sysmon trên máy*; **collector** phải được bật để đẩy sự kiện vào `sysmon_events`.
Hiện bảng chỉ có `memory_scan_event` ⇒ bật collector Sysmon (mục 3.19).

**8. Có nên bật trợ lý AI?**
Chỉ khi tổ chức cho phép **nội dung log được gửi ra ngoài**. Nếu không, tắt (`GIAMSAT_DISABLE_AI`).

**9. Muốn đổi mật khẩu/PSK thì đổi ở đâu, ảnh hưởng gì?**
Mật khẩu: màn hình **Người dùng** hoặc `/api/users/password`. PSK: `server/.env` ⇒ **phải cập nhật toàn bộ agent**
(`agent_config.json`) nếu không sẽ tạo ra “nguồn bị từ chối”.

**10. Dashboard chậm?**
Kiểm tra 3 nghi phạm: bảng lớn chưa partition (`events` 172 MB), chưa rollup, và truy vấn không giới hạn thời gian.
Ưu tiên: rollup → partition → tăng `hours` hẹp lại khi điều tra.

## Phụ lục E — Checklist trước khi báo lỗi + Tính năng mới

**Khi báo lỗi cho người vận hành/quản trị, gửi kèm 6 thông tin sau** (thiếu là phải hỏi lại):
1. Tab/menu nào, máy nào (`hostname`), thời điểm (giờ máy trạm **và** giờ server).
2. Ảnh chụp màn hình (kèm F12 → Console nếu là lỗi giao diện).
3. Kết quả 2 câu SQL: `SELECT COUNT(*) FROM events;` và `SELECT COUNT(*) FROM threat_alerts;`
4. Nguồn bị từ chối? (ảnh chụp tab Coverage → Sức khỏe đội máy).
5. Thay đổi gần nhất (cập nhật agent? deploy rule? sửa `.env`?).
6. Phiên bản: `server/version.txt` + phiên bản agent của máy đó (cột `version` ở tab Tổng quan).

**Tính năng mới cần biết (v5.0.9) — đúng những gì tài liệu này mô tả chi tiết:**

| Tính năng | Ở đâu | Mục |
|---|---|---|
| **Điều tra hợp nhất** (1 ô tìm kiếm, 11 nguồn) + Entity 360 + cây tiến trình + gói bằng chứng | Menu **Điều tra hợp nhất** | 3.25 |
| **Log Coverage** + panel Triển khai & Sức khỏe (rollout, sức khoẻ, dung lượng, chính sách theo đợt) | Menu **Log Coverage** | 3.4 |
| **Cases** | Menu **Cases** | 3.5 |
| Sửa lỗi “Điều tra quay mãi không ra dữ liệu” (spinner treo) | Menu **Điều tra hợp nhất** | 3.25 + Chương 5 |

---

## Ghi chú về tài liệu này

- **Nguồn số liệu:** đo trực tiếp trên `D:\test` lúc 2026-10-01 bằng cách đọc PostgreSQL
  (`pg_stat_user_tables` + `SELECT` mẫu) và đọc mã nguồn tại `E:\giamsat`.
- **Mọi tên file, hàm, tham số, tiền tố rule (`THREAT-`, `ANOMALY-`, `CROSS-`, `NET-`, `HEARTBEAT-`, `SRV-SCAN-`, `IOC-`)**
  đều lấy từ mã nguồn thật; mọi con số đều từ dữ liệu thật.
- **Cách tự kiểm chứng:** chạy `python tests\dashboard_ui_tests.py` (kiểm tra mọi API mới đều có giao diện gọi),
  `python tests\ui_wiring_tests.py` (i18n + wiring), và các câu SQL ở Phụ lục A.
- **Bản hướng dẫn cài đặt/agent song ngữ** nằm trong `README.md`; tài liệu này là bản **chi tiết dạy học** cho toàn bộ dashboard
  (đọc kèm `summary.md` để biết lịch sử thay đổi theo phiên bản).