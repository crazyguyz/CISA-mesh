# GIAM-SAT Roadmap — Kế hoạch triển khai (từ Review vòng 8, 2026-09-01)

> Nguồn: `review.txt` (R8) — đối chiếu với code HEAD `6f10e0e` (2026-09-01).
> Các finding Phần 2 (HIGH-1/2, MEDIUM-1/2/3, LOW-1..6) **đã fix hết** ở commit
> `6f10e0e`. Phần còn lại = cải tiến chiều sâu (Phần 4: A1-A10, B1-B12).
>
> **Cập nhật 2026-09-01: PHASE 1 ĐÃ TRIỂN KHAI XONG** (commit triển khai Phase 1) —
> A2 log-health, A1b syslog RFC5424, B3 grouping, B1 triage queue, B7 pagination, A3b coverage report.

---

## 0) Trạng thái đối chiếu (đã verify trực tiếp trên code)

| Mục | Review nói | Thực tế code hiện tại | Kết luận |
|---|---|---|---|
| A1 Syslog ingestion | "không có UDP receiver" | `syslog_server.py` **đã có** UDP 514 + RFC3164 parser + severity/facility + PPS rate-limit + tab Syslog UI | ⚠️ Đã có ~70% — thiếu RFC5424/MITRE/alert-rules/TCP-TLS |
| A3 Detection enablement | "chỉ check, không enable" | `agent/baseline_hardening.py` **đã ENABLE** (auditpol /set + PS ScriptBlock/Module + 4688 cmdline), chạy 1 lần qua marker `.baseline_hardened` (main.py:833) | ✅ Đã có — **outdated**, chỉ thiếu báo trạng thái về server |
| A9 Threat intel | "misp_client + threat_intel local đã có" | `agent/misp_client.py` + `agent/threat_intel.py` tồn tại (IOC sweep agent-side) | ⚠️ Đã có agent-side; thiếu server-side enrichment lúc alert |
| B8 Audit log UI | "chưa có view tra cứu" | `/api/audit` + menu `viewAudit` + `loadAudit()` + search + limit | ✅ Đã có — **outdated** |
| B5 Report | "weekly chỉ chạy khi online đúng ngày" | `schedule_weekly_report` chạy Mon 08:00 đúng, **không catch-up** | ❌ Chưa có catch-up |
| A2 Log source health | "chưa có" | Không có | ❌ Chưa có |
| A4 DNS ETW | "chưa có" | Không có | ❌ Chưa có |
| A5 Rule replay / dead-rule | "chưa có" | Không có | ❌ Chưa có |
| A6 Baseline học tuần | "14 ngày cố định" | NET-FIRST 14 ngày cố định; anomaly z-score theo giờ | ⚠️ Một phần |
| A7 Risk scoring | "chưa có" | Không có | ❌ Chưa có |
| A8 Kill-chain cross-alert | "có process_chain từng alert" | attack_overview có chain diagram + process_chain | ⚠️ Một phần |
| A10 Agent version/coverage | "chưa có" | máy có version, chưa view spread/push-group | ⚠️ Một phần |
| B1 Triage workflow | "status rời rạc" | triage dropdown (new/in_progress/resolved/fp) đã có | ⚠️ Một phần — thiếu queue+assign+SLA |
| B2 Case management | "chưa có" | Không có | ❌ Chưa có |
| B3 Alert grouping | "chưa có" | Không có | ❌ Chưa có |
| B4 Global search | "chưa có" | Không có | ❌ Chưa có |
| B7 Events pagination | "limit 100" | limit 100, chưa pagination/sort thật | ⚠️ Một phần |
| B9 Dashboard cá nhân hóa | "template đã có" | dashboard-builder đã có | ⚠️ Layout theo user chưa |
| B10 Onboarding agent | "chưa có" | Không có | ❌ Chưa có |
| B11 RBAC analyst | "chưa có" | viewer/operator/admin | ❌ Chưa có |
| B12 i18n + compact | "thiếu key" | i18n vi/en đã có; thiếu key + compact | ⚠️ Một phần |

---

## 1) PHASE 1 — "SIEM cơ bản" (ưu tiên cao nhất, giá trị/chi phí tốt nhất) — ✅ DONE 2026-09-01

### 1.1 A2 — Log source health / coverage dashboard  【Server + UI · M】✅
- API `/api/health/coverage` (file mới `api_health.py`): per-machine `sysmon_present`, `auditpol_enabled`, `baseline_hardened`, `event_count_24h`, `event_count_7d_avg`, `delta%`, flags.
- UI: menu **Log Coverage** + view: bảng máy + badge "🚫 Không log" / "📉 Log sụt" / "Sysmon?" / "Auditpol?".
- Rule `LOGHEALTH-001` (server_core loghealth_monitor, 10 phút): volume 24h < 50% TB 7 ngày → alert HIGH.

### 1.2 A1b — Syslog nâng cấp  【Server · M】✅
- RFC5424 structured parser trong `syslog_server.py` (`<PRI>1 TS HOST APP PID MSGID [SD] MSG`).
- Lưu `app_name`, `structured` (cột mới SQLite+PG); RFC3164 giữ nguyên.
- (TCP 514/TLS 6514 để sau — UDP đủ cho LAN; firewall/device patterns đã có sẵn.)

### 1.3 B3 — Alert grouping theo rule  【Server + UI · M】✅
- `get_threat_alerts_grouped` (SQLite `strftime` bucket / PG `date_trunc`): 1 row/rule/10-min + machine_count + machines list.
- API `/api/threats/grouped`; UI toggle "📊 Nhóm theo rule" trong tab Đe dọa.

### 1.4 B1 — SOC triage queue  【Server + UI · L】✅
- Cột mới `assignee`, `comment`, `updated_by`, `due_at`, `updated_at` (SQLite+PG).
- Lifecycle: `new → investigating → contained → in_progress → resolved/false_positive`; SLA `due_at` (24h/48h).
- API `/api/threats/<id>/assign`, `/comment`, `/status` (ghi audit).
- UI: nút 👤 gán / 💬 ghi chú + badge assignee trên từng alert.

### 1.5 B7 — Events table: pagination  【Server + UI · S】✅
- `get_events(offset, sort_by, order)` (cả 2 backend); `/api/events?offset=&sort_by=`; UI 100/trang + nút Trước/Sau.

### 1.6 A3b — Agent báo trạng thái hardening  【Agent + Server · S】✅ (cần rebuild agent)
- Agent `_coverage_state()` gửi `baseline_hardened/sysmon_present/auditpol_enabled` qua TCP heartbeat + HTTP poll.
- Server lưu `update_machine_coverage` (cả 2 path: TCP heartbeat + `/api/agent/heartbeat`).
- **Bonus fix:** requeue HIGH-6 đặt nhầm ở `/api/agent/pending-commands` (endpoint agent KHÔNG gọi) → **đã chuyển sang `/api/agent/heartbeat`** (endpoint thật).

---

## 2) PHASE 2 — "Chiều sâu phát hiện"

### 2.1 A5 — Rule replay / dead-rule report  【Server · M】
- Tool `tools/rule_replay.py`: chạy toàn bộ rules (Sigma + built-in) lên 7 ngày `events/sysmon_events` (SQL), report rule có 0 hit + lý do (thiếu field → field drift).
- UI tab **Rules**: cột "Hits 7d" + nút "Tắt rule chết".

### 2.2 A4 — DNS query logging qua ETW  【Agent · L】
- Module đọc `Microsoft-Windows-DNS-Client/Operational` (EID 3008/3020) — agent đã có reading; bật log + gửi `dns_query` events.
- Server: `network_inspection` subtype `dns_query` đã có UI badge — chỉ cần nguồn dữ liệu.

### 2.3 A7 — Risk scoring host  【Server + UI · M】
- Điểm 0-100/máy = f(severity, tần suất, MITRE tactic count, freshness) — chạy 5 phút.
- API `/api/risk/hosts`; dashboard thêm card "Top Risk Hosts".

### 2.4 A6 — Baseline học theo tuần  【Server · M】
- Nâng NET-FIRST: thay 14 ngày cố định bằng baseline 4 tuần (dst/port/giờ) — máy mới không FP.
- Lưu baseline mới trong `network_baseline` (thêm cột `weekday`, `hour`).

### 2.5 A8 — Kill-chain cross-alert  【Server + UI · M】
- Gộp alert cùng máy theo cửa sổ 1h → chuỗi tactic (Initial Access → ...); dùng `mitre` field đã có trên alert.

### 2.6 A9 — Threat intel enrichment server-side  【Server · S】
- Khi alert mới (rule liên quan mạng/lệnh), lookup `dst_ip`/`domain`/`hash` qua OTX/abuse.ch (tùy chọn, có rate-limit) → thêm `intel` vào alert `raw_data` + hiển thị badge.

---

## 3) PHASE 3 — "Trải nghiệm SOC / Vận hành"

- **B2 Case management** — gom alert liên quan thành case + timeline (L).
- **B4 Global search (Ctrl+K)** — 1 ô tìm host/alert/event (M).
- **B5 Report catch-up + email** — khi server down đúng lịch → chạy bù + gửi email (M).
- **B6 Notification per-user + quiet hours** — admin nhận alert theo group + giờ yên tĩnh (M).
- **B10 Onboarding agent UX** — link tải EXE + lệnh cài + test kết nối trong UI (S).
- **B11 RBAC analyst role** — quyền đọc + triage nhưng không xóa/execute (S).
- **B12 i18n hoàn thiện + compact mode** — key còn thiếu (LOW-5 R7) + layout mật độ cao (S).
- **A10 Agent version/coverage bảng** — version spread + push update theo group (M).

---

## 4) Thứ tự khuyến nghị

1. **Phase 1.1 (A2)** → 1.2 (A1b) → 1.3 (B3) → 1.4 (B1) — bộ 4 này biến hệ thống thành
   SIEM dùng được: biết agent nào mù, bắt log mạng, hết nhiễu, quy trình xử lý.
2. Phase 2 theo thứ tự A5 → A4 → A7 → A6 → A8 → A9.
3. Phase 3 theo nhu cầu vận hành (B8 đã có sẵn rồi).

**Ghi chú:** agent-side thay đổi (1.6, A4) cần rebuild agent + bump version; mọi thay đổi
khác là server-side, deploy bằng restart + Ctrl+F5.

