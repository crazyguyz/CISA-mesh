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

## 2) PHASE 2 — "Chiều sâu phát hiện" — ✅ DONE 2026-09-01

### 2.1 A5 — Rule replay / dead-rule report  【Server · M】✅
- Tool `tools/rule_replay.py` (đã có v4.11, giữ) + **`/api/rules/stats`** mới: hit 7 ngày theo rule + danh sách rule 0 hit (dead) + tổng rule.

### 2.2 A4 — DNS query logging qua ETW  【Agent · L】✅ (cần rebuild agent)
- Agent đã đọc channel `Microsoft-Windows-DNS Client/Operational`; thêm parser **EID 3008/3009** → route thành `network_inspection` subtype `dns_query` (domain) — domain-based C2 hunting chạy được trên mọi máy, không cần Npcap.

### 2.3 A7 — Risk scoring host  【Server + UI · M】✅
- `get_risk_scores` (severity-weighted + decay + rule-coverage bonus, 0-100) + `/api/risk/hosts` + card **🔥 Top Risk Hosts** trong Log Coverage.

### 2.4 A6 — Baseline học theo tuần  【Server · M】✅
- `get_netflow_seen_windows` (SQLite `%w/%H` / PG `D/HH24`): NET-FIRST/NET-ODD chỉ fire khi (src,dst,weekday,hour) **chưa từng thấy** + máy mới < 48h ở **learning phase** (không alert novelty).

### 2.5 A8 — Kill-chain cross-alert  【Server + UI · M】✅
- **Case auto-detector** (server_core, 5 phút): gom alert mở cùng máy trong 1h, ≥ 2 rule riêng → tạo case (severity cao nhất, kèm alert_ids).

### 2.6 A9 — Threat intel enrichment server-side  【Server · S】✅
- `threat_intel_server.py`: local file `GIAMSAT_INTEL_FILE` + OTX (`GIAMSAT_OTX_API_KEY`, rate-limit 1/s); gắn tag vào alert NET-* khi có kết quả — chỉ enrich, không bao giờ chặn emit.

## 3) PHASE 3 — "Trải nghiệm SOC / Vận hành" — ✅ DONE 2026-09-01

- **B2 Case management** ✅ — bảng `cases` (SQLite+PG) + `/api/cases` + menu **Cases** (badge số case mở) + status lifecycle + auto-cluster.
- **B4 Global search (Ctrl+K)** ✅ — `/api/search` + overlay Ctrl+K (máy/alert/event).
- **B5 Report catch-up + email** ✅ — state file `report_state.json`; daily/weekly tự **catch-up** khi server down đúng lịch.
- **B6 Notification quiet hours** ✅ — `quiet_hours_enabled/start/end` trong alerting_config: chặn MEDIUM/LOW trong cửa sổ (CRITICAL/HIGH luôn qua).
- **B10 Onboarding agent UX** ✅ — `/api/agent/onboarding` + nút "＋ Cài Agent" (lệnh cài + cổng).
- **B11 RBAC analyst role** ✅ — role `analyst` (read + triage, không delete/execute/settings); 6 triage endpoint → `threat_triage`; UI role dropdown.
- **B12 i18n + compact mode** ✅ — keys đã đủ; thêm nút **⇅ Compact mode** (lưu localStorage).
- **A10 Agent version/coverage bảng** ✅ — Coverage thêm cột Version + badge "outdated" (lệch `server/version.txt`).


---

## 4) Thứ tự khuyến nghị

1. **Phase 1.1 (A2)** → 1.2 (A1b) → 1.3 (B3) → 1.4 (B1) — bộ 4 này biến hệ thống thành
   SIEM dùng được: biết agent nào mù, bắt log mạng, hết nhiễu, quy trình xử lý.
2. Phase 2 theo thứ tự A5 → A4 → A7 → A6 → A8 → A9.
3. Phase 3 theo nhu cầu vận hành (B8 đã có sẵn rồi).

**Ghi chú:** agent-side thay đổi (1.6, A4) cần rebuild agent + bump version; mọi thay đổi
khác là server-side, deploy bằng restart + Ctrl+F5.

