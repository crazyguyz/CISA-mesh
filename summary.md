# GIAM-SAT v5.0.4 — Hệ Thống Giám Sát Bảo Mật Tập Trung

> KIẾN TRÚC AGENT-SERVER ● 1000+ AGENTS ● 4 DATABASE BACKENDS ● HUMAN-IN-THE-LOOP ● PHÂN LOẠI CẢNH BÁO (TRIAGE) ● MADE IN VIETNAM 🇻🇳

---

## 0. v5.0.4 — Cập nhật gần nhất (2026-08)

### Bảo mật & lõi (Round 6 review — CRITICAL/HIGH/MEDIUM/LOW)
| # | Nội dung | File |
|---|----------|------|
| CRITICAL-1 | PG `ON CONFLICT` thiếu predicate partial index (42P10) → fix + log lỗi thay vì `except:pass` nuốt | `db_postgres.py` |
| CRITICAL-2 | XSS modal packet/detail (escape toàn bộ field network) | `dashboard.js` |
| HIGH-1 | Update-loop: version derive từ binary (`dist/agent_version.txt`), `update.lock` chống race, `.bat` staging copy, MEI cleanup an toàn | `db_manager.py`, `updater.py`, `agent_core.py`, `build-agent.ps1` |
| HIGH-2 | Sanitize `user_name/email/employee_id` server-side + esc UI | `agent_auth.py`, `message-chat.js` |
| HIGH-3 | Hồi sinh ~1.900 rule Sigma chết: alias lowercase, `process_path`, `scriptblock_text`, field_regex cho re/startswith/endswith | `correlation_engine.py`, `sigma_parser.py`, `event_collector.py`, `field_aliases.yaml` |
| MEDIUM-1 | TLS hostname fail-hard (không fallback im lặng) | `http_client.py` |
| MEDIUM-2 | escJs asset_id trong onclick | `assets.js` |
| MEDIUM-3 | Per-machine PSK độc lập + cache theo (env, mtime) | `agent_auth.py`, `api_common.py`, `tcp_server.py` |
| LOW-1/2 | 2FA-fail TTL 30' + ACCOUNT_LOCKED kèm username | `auth_manager.py` |

### PostgreSQL chính thức
- **Khôi phục PG:** role/db `giamsat` được tạo đúng (lỗi trước: setup chỉ ghi `.env`, role `admin` chưa từng tồn tại → server âm thầm chạy SQLite nhiều ngày).
- **Tool migrate SQLite→PG:** `tools/migrate_sqlite_to_pg.py` (`--dry/--run/--only`) — migrate 36 bảng ~160k rows, dedup qua `dedup_key`, skip command pending, setval sequence (verify 0 issues).
- **PG parity:** `network_baseline` DDL/upsert backend-aware; `status` filter cho threat/vuln/yara/inspection; schema `status` cột cho alert tables; materialized views dashboard dùng index đúng (machine_id / (1)) + tự drop-stale + recreate.
- **Fallback hiển thị:** khi PG không kết nối được → banner đỏ + `server_error.log` + `/api/health` báo `db_fallback` — không còn âm thầm.

### UI
- Săn tìm đe dọa: template chips + dropdown tactic tự nạp + stats + **Lịch sử chiến dịch**.
- Email→Cấu hình: panel **Kênh Cảnh báo** (Telegram/Slack/Webhook).
- Response: thẻ **Hành động phản hồi khả dụng** (8 SOAR action).
- Ổn định: fix lũ 429 (SSE loadStats debounce + rate limit 1800/min), fix TypeError khi click tab Email/Assets/Agentless.

### Hotfix — Xóa máy trạm dọn sạch asset registry
- **Bug:** `delete_machine()` trước đây chỉ xóa events/alerts/... — KHÔNG xóa bảng Assets → máy đã xóa vẫn hiện **Máy tính/Màn hình** trên dashboard Tài sản (cấu hình orphan).
- **Fix (cả SQLite + PG):** `delete_machine()` giờ xóa thêm 22 bảng machine-scoped (`sysmon_events`, `sca_events`, `messages`, `policy_apply_status`, `machine_users`, `machine_uptime`, `agent_update_log`, `alert_suppression`, `fim_baseline`, `agent_group_members`...) + toàn bộ asset registry theo thứ tự: `assets_computers` → `assets_relations` → `assets_monitors` (giữ màn hình còn được máy khác dùng) → `assets_inventory` → `assets_change_log`.
- **Tool dọn orphan cũ:** `tools/cleanup_orphan_assets.py` (dry-run mặc định, `--apply` để xóa; hỗ trợ SQLite/PG từ `.env`) — đã chạy trên PG production: xóa **3 cấu hình máy tính** (LAPTOP-14, IT-YSNT, YSNTBK) + 3 màn hình + 3 relation + 17 messages + 5 machine_users + 1 uptime + 1831 agent_update_log + 759 fim_baseline.
- **Test:** `tests/delete_machine_tests.py` (16 check: purge toàn bộ + màn hình shared còn sống).

### Round 7 — Review 2026-08-31 (đã verify + fix)
| # | Nội dung | Fix |
|---|----------|-----|
| CRIT-1 | Watermark LOG_RESET: đọc BACKWARDS nhưng so `min(batch)` (record CŨ nhất) với `last_seen` → **alert giả mỗi poll** + tua ngược watermark → **trùng lặp event ồ ạt** | `event_collector.py`: so **record MỚI nhất** (`event_records[0]`) — reset chỉ khi `newest <= last_seen` |
| CRIT-2 | `ESCAPE '\\\\'` = **2 ký tự** trong SQL → mọi query hunting **"contains"** chết (exception bị nuốt → `[]` âm thầm) trên cả SQLite lẫn PG | `hunting_engine.py`: `ESCAPE '\'` (1 ký tự) + test `tests/hunting_engine_tests.py` |
| CRIT-3 | Stored XSS `renderHuntResults` (hypothesis/description/raw_data/machine_id nối thẳng innerHTML) | `dashboard.js`: `escapeHtml()` toàn bộ sink |
| HIGH-1 | Stored XSS SOC Approval modal (hostname lưu THÔ + sink `showPendingList`/`showApprovalModal`, modal tự mở 30s) | `api_alert_approval.py` `sanitize_hostname` + 2 sink escape |
| HIGH-2 | Stored XSS qua `/rename` (không sanitize) + sink `loadMachines`/`loadGroups` không escape | `api_machines.py` sanitize + escape 2 sink |
| HIGH-3 | `main.py` xóa MỌI `_MEI*` không age-guard → xóa runtime app khác + agent khởi động song song → **python311.dll lỗi** (fix v5.0.4 chỉ ở updater) | `main.py`: copy logic age-guard (>6h) + rename probe |
| HIGH-4 | `update.lock` O_EXCL không stale-reclaim → crash/reboot giữa update = **agent kẹt version vĩnh viễn** | `updater.py`: lock cũ >10' → reclaim |
| HIGH-5 | `reset_user` result_file theo PID (predictable) + đọc lại không verify chủ → **file planting → lộ PSK** | `updater.py`: mkstemp + nonce marker verify |
| HIGH-6 | Requeue 'sent' sau 5' có thể **giao lại lệnh destructive đang chạy** (executed_at = lúc GIAO) | `api_agent_commands.py`: chỉ requeue khi máy OFFLINE |
| MEDIUM-1 | Deadman `endswith("Z")` crash trên PG (datetime) → **HEARTBEAT-001 không bao giờ chạy** | `event_worker.py`: isinstance datetime |
| MEDIUM-2 | PG retention THIẾU 6 bảng so SQLite → phình vô hạn trên prod | `db_postgres.py`: + network_inspection/yara/sca/agentless/response_results/audit_log |
| MEDIUM-3 | Ingest TLS fail-OPEN (`except ssl.SSLError: pass`) | `ingest_server.py`: đóng kết nối, không fallback |
| MEDIUM-4 | Telegram parse_mode Markdown: agent control → link giả `[x](evil)` vào kênh SOC | `alerting_engine.py`: parse_mode **HTML** + escape mọi field |
| MEDIUM-5 | AI rate-limit dict không GC → memory leak (xoay IP) | `api_ai.py`: idle-GC |
| MEDIUM-6 | `version/platform` lưu RAW (LOW-9 chỉ sanitize hostname) | `tcp_server.py`: `sanitize_text` |
| MEDIUM-7 | Hunting `_campaigns` không expire → memory leak | `hunting_engine.py`: TTL 24h |
| MEDIUM-13 | reset_user **Cancel vẫn reboot** + exception reboot máy | `updater.py`: bỏ shutdown cả 2 case |
| MEDIUM-15 | SSE đẩy raw_data >100KB → treo UI | `api_events.py`: cắt raw_data 2000 |
| MEDIUM-16 | assets.js onclick asset_id raw | `escJs()` |
| MEDIUM-17 | Dashboard template name raw trong option value | escapeHtml |
| MEDIUM-19 | `int(since_hours/limit)` không bẫy → 500 | clamp + try/except |
| LOW-1 | GeoIP cache miss `{}` vĩnh viễn → file mới không bao giờ đọc | chỉ cache khi có kết quả |
| LOW-3 | approval_id trùng giây → ghi đè | + uuid nonce |

**Để lại (cần agent rebuild / quyết định):** MEDIUM-9 (process_name full-path vs basename — Sigma), MEDIUM-10 (sysmon drain inclusive timestamp), MEDIUM-11 (command_key plaintext → DPAPI), MEDIUM-12 (show_message HTTP poll thiếu field), MEDIUM-14 (sca shlex), MEDIUM-18 (sanitize sâu các trường text — defense-in-depth), MEDIUM-20/21 ([CẦN XÁC MINH] múi giờ, FIM escJs), LOW-2 (CROSS machine), LOW-4 (dead code module), LOW-5 (i18n key).

### Phát hiện C2 theo HÀNH VI (không dựa IP reputation)
> Ý kiến: "IP đích ở AWS là bình thường → L3/L4 không phát hiện được." Đúng về reputation, sai về hành vi — đã triển khai tầng phát hiện theo pattern:
- **`server/network_alerting.py`** — engine quét NetFlow mỗi 60s, 3 rule **không cần biết IP đích có "xấu" hay không**:
  - **NET-BEACON** (HIGH): ≥5 kết nối tới 1 đích ngoài cố định, chu kỳ đều (CV jitter ≤0.30) — chữ ký C2 kinh điển. MITRE T1071.001.
  - **NET-FIRST** (MEDIUM): máy kết nối **lần đầu tiên** tới đích ngoài trong 14 ngày (novelty — case "VPS AWS mới toanh").
  - **NET-ODD** (HIGH): first-seen + giờ 00:00–05:00.
  - Cooldown riêng (6h/24h/24h) + ghi `threat_alerts` + đẩy Telegram/Email/Slack.
  - Env: `GIAMSAT_NET_ALERT_INTERVAL` (60), `GIAMSAT_NET_ALERT_WINDOW` (1800), `GIAMSAT_NET_BEACON_MIN_FLOWS` (5), `GIAMSAT_NET_FIRST_SEEN_DAYS` (14).
- **Anomaly → alerting**: `anomaly_detector` (z-score + first-time) trước đây chỉ ghi dashboard — giờ **bắn cả Telegram/Email/Slack** qua alerting engine (event_worker nhận `alerting`).
- **TLS SNI + JA3** (agent DPI): `network_collector.py` scapy path parse ClientHello → SNI + JA3 (md5), gửi dạng `network_inspection` subtype `tls_sni` (UI đã có badge) — **cần** `GIAMSAT_AGENT_PACKET_CAPTURE=1` + Npcap + admin; cột `ja3` thêm vào cả SQLite lẫn PG. Hunting AI biết bảng `network_inspection` để truy vấn SNI/JA3.
- **EID agent**: bỏ skip **4689** (process termination, giá trị cao, ít nhiễu); các EID ồn (5156/5158/4656/4658/4660) bật theo host qua `GIAMSAT_COLLECT_EXTRA_IDS="4656,4658,4660,5156,5158"`.
- Sysmon EID 3 đã là nguồn network chính (netstat chỉ fallback) — xác nhận đúng thứ tự ưu tiên.
- **Test:** `tests/network_alerting_tests.py` (8 check: SNI/JA3 parse + beacon + first-seen + cooldown).

### Rà soát kỹ — lượt quét toàn diện (bug/UI)
**Đã verify ổn (không lỗi):** JS↔Python endpoint khớp 100% (143 call / 168 route); mọi onclick handler đều được định nghĩa (không nút chết); sink XSS trong detail modals đã escape đủ; `/api/reports/download` + `/api/dashboard/import` chống path traversal; email dùng lib chuẩn (không SMTP header injection); `cleanup_old_data` chỉ cho xóa bảng trong allowlist; PGCompatCursor có fetchone (network_alerting chạy được trên PG).
**Bug đã fix:**
- **`int()`/`float()` không guard → 500:** `api_assets` (limit ×3), `api_cleanup` (days), `api_ai` (temperature/max_tokens/max_context), `upsert_inventory_asset` SQLite+PG (cost/quantity) — thêm clamp + try/except.
- **`insert_threat_alert` SQLite dedup (machine,rule) VÔ HẠN:** mọi alert cùng rule+cùng máy bị gộp 1 dòng (mất lịch sử, NET-* hiển thị sai, PG thì luôn insert mới → 2 backend lệch nhau). Fix: dedup chỉ trong **cửa sổ 10 phút** — chống spam correlation, giữ lịch sử alert riêng. (Đã test: 2 alert cùng giây → 1 dòng; alert sau 20 phút → dòng mới.)
- **`/api/events` trả raw_data >100KB** → treo UI: cắt còn 2000 ký tự (SSE đã cắt ở lượt trước).
**UI thiếu đã bổ sung:**
- Hiển thị **JA3** trong danh sách Deep Packet Inspection (2 chỗ: modal packet detail + tab inspection) cho subtype `tls_sni`.
- `.env.example` thêm 4 biến network-alert.
**Ghi nhận (chưa sửa, quyết định):** deadman `alerted` chỉ fire 1 lần/phiên/rule (chống spam — chấp nhận được); MEDIUM-20 múi giờ vẫn [CẦN XÁC MINH]; agent-side fixes cần rebuild.

### Round 8 — Review 2026-09-01 (verify 7 cũ + findings mới, đã fix)
**Verify Round 7:** 22/22 đã fix đúng (CRIT-1 newest-record, ESCAPE 1 ký tự đã chạy SQL thật, XSS sinks escape, _MEI age-guard, update.lock reclaim, reset_user nonce, requeue, MEDIUM-1..19, LOW-1/3).
**Findings mới — đối chiếu:**
| # | Kết quả | Fix |
|---|---------|-----|
| HIGH-1 | ✅ Đúng — N+1 query theo từng cặp (src,dst) + poke `conn` không lock | 1 query `SELECT DISTINCT src_ip,dst_ip` + cache 5 phút (`get_netflow_seen_pairs` SQLite+PG) |
| HIGH-2 | ⚠️ **False positive** phần "escape trước cắt" — code thật là `_html.escape(str(...)[:200])` = cắt trước, escape sau (đúng). **Nhưng callback_data >64 bytes → Telegram mất nút Approve/Deny là THẬT** | callback bỏ `rule_id` (matcher không dùng) + **hash machine_id 12 ký tự** (giữ khớp chính xác qua hash), action giữ raw → 41 bytes < 64. Matcher `process_approval` so hash |
| MEDIUM-1 | ✅ Đúng — dedup 10' là rolling window: update refresh `received_at` → rule nóng gộp mãi | UPDATE **không refresh** `received_at` — window neo tại lần đầu |
| MEDIUM-2 | ✅ Đúng — `_is_private_ip` bỏ qua IPv6 (fd00/fe80 → coi là external → FP) | dùng `ipaddress.ip_address().is_private/is_link_local/...` (cả 2 họ) |
| MEDIUM-3 | ✅ Đúng — requeue fail-OPEN khi `tcp_server` lỗi → `online=set()` → requeue tất cả | **fail-closed**: không lấy được online → không requeue |
| LOW-1 | ✅ Đúng — BEACON_MIN_SPAN hardcode + CV nhạy | env `GIAMSAT_NET_BEACON_MIN_SPAN` / `GIAMSAT_NET_BEACON_MAX_CV`, min flows 6 |
| LOW-2 | ✅ Đúng — cooldown set TRƯỚC khi emit → emit fail vẫn bị cooldown (mất alert) | tách `_cooldown_check`/`_cooldown_mark` — mark chỉ sau emit thành công |
| LOW-3 | ✅ Đúng — timestamp local vs DB UTC | `datetime.now(timezone.utc)` |
| LOW-4 | ✅ Đúng — LIMIT 30000 cắt flow cũ trong window | `get_netflow_flows(first_since=...)` filter `first >= ?` (SQLite+PG) |
| LOW-5 | ✅ Đúng — sniff `filter="ip"` bỏ IPv6 | `"ip or ip6"` + `IPv6` parse |
| LOW-6 | ✅ Đúng — dedup inspection thiếu dst_port | key `(sni, dst_ip, dst_port)` |
**Test:** thêm 4 check IPv6 vào `network_alerting_tests` (12 total) + verify callback hash roundtrip (41 bytes, khớp).

### Phase 1 — SIEM cơ bản (ROADMAP.md mục 1) ✅ đã triển khai
- **A2 Log-source health** — `/api/health/coverage` (file mới `api_health.py`) + menu **Log Coverage**: per-machine `sysmon_present/auditpol_enabled/baseline_hardened`, event 24h vs TB 7 ngày, badge "🚫 Không log / 📉 Log sụt / Sysmon? / Auditpol?"; rule **LOGHEALTH-001** (server_core, 10 phút): volume < 50% TB → alert HIGH.
- **A1b Syslog RFC5424** — parser `syslog_server.py` `<PRI>1 TS HOST APP PID MSGID [SD] MSG`; lưu `app_name` + `structured` (cột mới SQLite+PG).
- **B3 Alert grouping** — `get_threat_alerts_grouped` (bucket 10 phút) + `/api/threats/grouped` + toggle "📊 Nhóm theo rule" trong tab Đe dọa (1 rule × N máy → 1 row + count).
- **B1 SOC triage queue** — cột `assignee/comment/updated_by/due_at/updated_at`; lifecycle `new→investigating→contained→in_progress→resolved/fp` + SLA due_at; API `/assign`, `/comment`, `/status`; UI nút 👤/💬 + badge assignee.
- **B7 Events pagination** — `get_events(offset, sort_by, order)` + `/api/events?offset=` + UI 100/trang.
- **A3b Agent coverage** — `_coverage_state()` gửi hardening/sysmon/auditpol qua heartbeat (cần rebuild agent); `update_machine_coverage` 2 path.
- **Bonus fix:** requeue HIGH-6 nằm ở `/api/agent/pending-commands` — **endpoint agent không bao giờ gọi** → đã chuyển sang `/api/agent/heartbeat` (endpoint thật, fail-closed).

### Phase 2+3 — Chiều sâu phát hiện + Trải nghiệm SOC ✅
- **A5 Rule stats** — `/api/rules/stats` (hit 7 ngày + dead-rule list); tool `rule_replay.py` đã có.
- **A4 DNS ETW** — parser EID 3008/3009 → `network_inspection` subtype `dns_query` (domain C2 hunting không cần Npcap; cần rebuild agent).
- **A7 Risk score** — `get_risk_scores` + `/api/risk/hosts` + card "🔥 Top Risk Hosts" trong Log Coverage.
- **A6 Baseline tuần** — `get_netflow_seen_windows` (weekday+hour): NET-FIRST/ODD chỉ fire khi (src,dst,thứ,giờ) mới + máy < 48h học baseline (không FP).
- **A8+B2 Kill-chain/Case** — bảng `cases` (SQLite+PG) + auto-detector (5 phút, ≥2 rule/1h/máy → case) + menu **Cases** + `/api/cases`.
- **A9 Intel enrich** — `threat_intel_server.py` (local file + OTX, rate-limit 1/s), chỉ enrich alert NET-*.
- **B4 Ctrl+K search** — `/api/search` + overlay (máy/alert/event).
- **B5 Report catch-up** — `report_state.json`, daily/weekly tự chạy bù khi server down.
- **B6 Quiet hours** — chặn MEDIUM/LOW trong `quiet_hours_*` (CRITICAL/HIGH luôn qua).
- **B10 Onboarding** — `/api/agent/onboarding` + nút "＋ Cài Agent".
- **B11 RBAC analyst** — role `analyst` (read+triage); 6 triage endpoint dùng `threat_triage`.
- **B12 i18n+compact** — keys đủ; nút ⇅ Compact mode.
- **A10 Version coverage** — cột Version + badge "outdated" trong Log Coverage.

---

## 1. Cấu Trúc Dự Án & Chức Năng

```
E:\giamsat\
├── agent/                          ← Agent Windows (.exe ~23MB)
│   ├── agent_core.py               ← v3.9.3: 12 collectors, TCP TLS, heartbeat 120s+metrics, network 3-tier aggregation
│   ├── updater.py                  ← v3.8.0: Updater daemon (HTTP :5999) + Agent Watchdog (tự restart khi bị kill)
│   ├── named_pipe_ipc.py           ← v3.7: Named Pipe IPC (thay HTTP localhost)
│   ├── misp_client.py              ← v3.8.0: MISP Threat Intel Feed (pull + cache + auto-refresh 60ph)
│   ├── sysmon_collector.py         ← v3.9.16: Sysmon EID 1-18,22 + v3.9.0: EID pre-filter noise reduction
│   ├── memory_scanner.py           ← Process Hollowing, name spoofing, injection
│   ├── correlation_engine.py       ← v3.9.16: 93 threat rules on-agent (PPID spoofing, 5 new categories)
│   ├── network_collector.py        ← NetworkFilter 9 rules + 30s dedup
│   ├── yara_scanner.py             ← Adaptive scan + entropy detection
│   ├── fim_collector.py            ← v3.7.2: FIM + Priority Hashing (EXE/DLL ưu tiên) + Chunk Sync
│   ├── process_tree.py             ← v3.6: Real-time process tree + 7-day local cache
│   ├── encrypted_cache.py          ← v3.6: DPAPI + Merkle Chain + Tamper Guard
│   ├── resource_monitor.py         ← v3.6: CPU/RAM throttling (NORMAL/THROTTLE/PAUSE)
│   └── ... (17 collectors tổng cộng)
│
├── server/                          ← Server trung tâm (Flask + Waitress)
│   ├── server_core.py              ← Entry point, backend selector, SSE push
│   ├── db_manager.py               ← v3.9.0: SQLite backend (30+ indexes, WAL, FIM baseline, heartbeat metrics, timeout 300s)
│   ├── db_postgres.py              ← PostgreSQL + TimescaleDB (20-500 agents)
│   ├── db_elasticsearch.py         ← Elasticsearch 8.x (500+ agents, full-text search)
│   ├── db_clickhouse.py            ← v3.7: ClickHouse columnar — ⚠️ ROADMAP, CHƯA code (xem §10.7)
│   ├── db_base.py                  ← Abstract interface (60+ methods)
│   ├── tcp_server.py               ← TCP :6666, rate limiter, event queue push
│   ├── event_queue.py              ← 7 priority queues (Redis/memory)
│   ├── event_worker.py             ← 4-8 threads, batch 100, adaptive poll 50-500ms
│   ├── correlation_engine_server.py ← 11 cross-machine rules
│   ├── alerting_engine.py          ← Email/Slack/Webhook/Telegram alerts
│   ├── api/                        ← 22 API modules (REST + SSE)
│   │   ├── api_incident.py         ← v3.7: Incident Investigation timeline ±15ph
│   │   ├── api_fim_baseline.py     ← v3.7.2: FIM Baseline CRUD + pagination + 60s cache
│   │   ├── api_suppression.py      ← v3.8.0: Alert Suppression (Global Whitelist) CRUD
│   │   ├── api_events.py           ← Events, FIM, Network, Threat, Vuln, YARA, SCA...
│   │   └── ...
│   ├── static/js/dashboard.js      ← 23 tabs, SSE real-time, lazy-load
│   └── templates/index.html        ← Bootstrap 5 dark theme
│
├── common/                          ← TLS utilities, logger
├── tests/                           ← Rule regression tests (15 cases)
└── build-agent.ps1                  ← 7-step automated build
```

### Dashboard Tabs (23 tabs, 5 nhóm)

| Nhóm | Tabs |
|------|------|
| **Giám sát** | Tổng quan, Event Log, FIM, Syslog, Response, Network, Vulns, YARA, SCA, Agentless, Agent Assistant, Sysmon, Memory |
| **Phân tích & Điều tra** | Điều tra (Incident), Attack Overview, Threat Hunting, Anomaly, IOC Sweep |
| **Quản trị** | Tin nhắn, Agent Groups, Update Agent, FIM Baseline, Quản lý Rules, Email Alerts, Suppression |
| **Hệ thống** | Dọn dẹp dữ liệu |

### Tính năng nổi bật

| Tính năng | Phiên bản | Chi tiết |
|-----------|-----------|---------|
| Network via Sysmon EID 3 | v3.8.0 | Kernel-level network monitoring, real-time process context, thay netstat polling |
| Alert Suppression | v3.8.0 | Global Whitelist (rule_id + machine_id + field_path/hash), CRUD API |
| Agent Watchdog | v3.8.0 | updater.py tự restart GiamSatAgent.exe nếu bị kill (15s check) + Telegram alert |
| MISP Threat Intel | v3.8.0 | REST API pull IOCs (IP/domain/hash) mỗi 60ph, cache offline, local feed import |
| Enrollment & Revocation | v3.8.0 | Enrollment token xác thực agent mới + Certificate Revocation (is_revoked flag) |
| Sysmon Collector | v3.9.16 | 16 EID (1-18,22) + Timestomping + MOTW Evasion + Tampering Detection |
| Memory Scanner | v3.8.0 | Process Hollowing, name spoofing, system process injection |
| Correlation Engine | v1.0 | **2062 rules chạy AGENT-side** (mỗi máy tự evaluate sự kiện local) + **11 CROSS-machine rules chạy SERVER-side** (tương quan liên máy), MITRE ATT&CK mapped |
| FIM + Whodata | v3.7.2 | Real-time watchdog + Priority Hashing (EXE/DLL đỉnh) + Chunk Sync 200 |
| Network 3-Tier Aggregation | v3.9.0 | T1 internal (60s agg) + T2 suspicious (real-time) + T3 external (agg) + baseline 24h |
| Network Smart Aggregation | v3.9.3 | Aggregate-only T1+T3 (bỏ first-occurrence), flush chỉ active (count>0), cleanup TTL 300s | 90K→~3,750/day (**96%↓**) |
| SCA Reporting Fix | v3.9.3 | Gửi tất cả findings (PASS+FAIL+WARN), sca_event real-time, summary event mỗi scan |
| Heartbeat Throttling | v3.9.0 | 120s interval (was 20s) + CPU/RAM/Disk/Net metrics → 93% reduction |
| Sysmon Pre-Filter | v3.9.0 | EID 1/7/11/12/13/14 noise reduction + EID 22 DNS dedup 300s → 60% reduction |
| Network Monitor (Legacy) | v2.5.17 | _simple_network_poll() netstat → noise filter → dedup (fallback khi không có Sysmon) |
| FIM Baseline | v3.7.2 | MAX 500 file/path, exclude noise (.etl/.pf/Prefetch), pagination dashboard |
| Incident Workspace | v3.7 | Timeline điều tra tổng hợp ±15ph (Network+Sysmon+Events+FIM+Memory) |
| Named Pipe IPC | v3.7 | Windows Named Pipes thay HTTP localhost:5999, ACL phân quyền |
| AI Assistant | v3.5 | DeepSeek/OpenAI/Gemini/Groq/xAI + Floating Widget |
| Sigma Rules | v3.4 | Import community rules (3000+ rules), auto-updater |
| Agent Self-Update | v3.3 | 2 EXE (Agent + Updater daemon), auto 15 phút |
| SOAR | v3.2 | 6 automated playbooks + Telegram alerts |
| PWA Dashboard | v3.0 | Bootstrap 5 dark theme, SSE real-time |

---

## 2. Cấu Trúc Code — Các Module Chính

### 2.1 Agent (`agent/agent_core.py`)

```python
class AgentCore:
    def __init__(self, user_name="", employee_id="", email=""):
        # 12 collectors: EventCollector, FIMCollector, NetworkCollector,
        #               SysmonCollector, MemoryScanner, BehaviorCollector,
        #               ThreatIntel, VulnScanner, YaraScanner, SCAScanner
        # Correlation Engine (76 rules on-agent)
        # Network Traffic Analyzer (5 anomaly types)
        # Adaptive Baseline (behavior learning)
        # v3.9.0: Network 3-tier aggregation buffer + internal baseline (24h learning)

    def start(self):
        # → _net_agg_flush_loop()        v3.9.0: flush aggregated network every 60s
        # → sysmon_collector.start()      v3.8.0: Sysmon EID 3 → real-time network (priority)
        # → _simple_network_poll()        v3.9.0: netstat fallback with 3-tier aggregation
        # → _vuln_scan_loop()             mỗi 1h
        # → _yara_scan_loop()             mỗi 24h
        # → _sca_scan_loop()              mỗi 24h
        # → _batch_flush_loop()           flush buffer mỗi 15s
        # → _receive_commands()           TCP recv → dispatch
        # → _heartbeat_loop()             v3.9.0: mỗi 120s + CPU/RAM/Disk/Net metrics
        # → _auto_update_check_loop()     mỗi 15 phút
    
    def _sysmon_callback(event):          # v3.9.0: Sysmon event handler with pre-filter
    def _classify_and_queue_network():    # v3.9.0: 3-tier network traffic classification
    def _is_internal_suspicious():        # v3.9.0: lateral movement detection (new dst/suspicious ports)
    def _simple_network_poll():           # v3.9.0: netstat with 3-tier + 90s dedup (Sysmon fallback)
    def _handle_agent_update_command():   # v3.7: Named Pipe IPC → fallback HTTP
    def _enrich_and_queue(data):          # MITRE mapping + ThreatIntel check → _real_send()
    def _real_send(data):                 # TCP send or cache offline
```

### 2.2 v3.9.3: Network 3-Tier Aggregation (`agent_core.py`)

```python
# v3.9.3: 3-tier network traffic classification — giảm 96% log volume
# T1 — Internal Common Traffic: Aggregate-only (60s bucket, NO first-occurrence)
# T2 — Internal Suspicious: Real-time alert (lateral movement detection) — GIỮ NGUYÊN
# T3 — External Traffic: Aggregate-only (60s bucket, NO first-occurrence)

_SUS_INTERNAL_PORTS = {22, 23, 135, 139, 445, 3389, 5900, 5985, 5986,
                       1433, 3306, 5432, 6379, 27017, 8080, 8443, 4444, 5555}

def _classify_and_queue_network(self, net_data):
    # Skip loopback
    # DNS dedup: port 53 từ DNS processes → 300s dedup per domain (real-time)
    # Internal → check suspicious port OR new destination (baseline-based)
    #           → suspicious: real-time send với tier="internal_suspicious"
    #           → common: aggregate by dst_ip:dst_port, KHÔNG gửi first-occurrence
    # External → aggregate by dst_ip:dst_port, KHÔNG gửi first-occurrence

def _net_agg_flush_loop(self):
    # v3.9.3: Every 60s: flush ONLY active connections (count>0)
    # Cleanup stale entries >300s to prevent unbounded growth
    # After 24h: switch baseline from LEARNING → ACTIVE mode
```

### 2.3 v3.9.0: Sysmon Pre-Filter (`agent_core.py`)

```python
# v3.9.0: Agent-side Sysmon event filtering — giảm 60% sysmon volume
def _sysmon_callback(self, event):
    eid = event.get("sysmon_event_id", 0)
    
    # EID 3 (Network Connect): → _classify_and_queue_network() (3-tier)
    # EID 1 (Process Create):  Skip system32/syswow64 trừ khi có cmdline suspicious
    #                           (powershell -enc, certutil, bitsadmin, wmic, mshta...)
    #                           Skip browser/spooler/office noise
    # EID 7 (Image Load):      Skip signed DLLs, skip system32/syswow64
    # EID 11 (File Create):    Chỉ báo nếu trong sensitive dirs (Windows, Temp, Downloads, Startup)
    #                           Skip .tmp/.log/.etl/.pf
    # EID 12/13/14 (Registry): Chỉ báo nếu key thuộc RUN, Services, Image File Execution, Winlogon...
    # EID 22 (DNS):            Dedup 300s per domain
```

### 2.4 v3.8.0: MISP Threat Intel (`agent/misp_client.py` + `agent/threat_intel.py`)

```python
# v3.8.0: MISP REST API client (260 dòng) — IOC feed integration
class MISPClient:
    def __init__(self, url=os.environ.get("MISP_URL"), api_key=os.environ.get("MISP_API_KEY")):
        # Auto-refresh thread: pull IOCs every 60 minutes
        # Cache: misp_cache.json (offline fallback)
    
    def refresh(self):        # Pull latest IOCs (IPs, domains, hashes) từ MISP
    def check_ip(ip):         # Check if IP is in MISP threat list
    def check_domain(domain): # Check if domain is in MISP threat list
    def check_hash(hash):     # Check if file hash is in MISP threat list
    def import_local_feeds():  # Import local threat feeds (CSV/JSON)

# Integration in threat_intel.py: MISP (priority) → OTX → AbuseIPDB
```

### 2.5 v3.8.0: Agent Watchdog (`agent/updater.py`)

```python
# v3.8.0: Tự động restart agent nếu bị kill — bảo vệ tính liên tục
def _agent_watchdog():
    while True:
        time.sleep(15)
        # Check if GiamSatAgent.exe is running
        # psutil.pid_exists() → nếu có psutil
        # tasklist /FI "IMAGENAME eq GiamSatAgent.exe" → fallback
        if not agent_running:
            subprocess.Popen([agent_exe_path, ...])
            _send_telegram_alert("⚠️ Agent restarted by watchdog")

def _send_telegram_alert(msg):
    # POST to server API → Telegram notification
```

### 2.6 v3.8.0: Alert Suppression (`server/db_manager.py` + `server/api/api_suppression.py`)

```python
# v3.8.0: Global Whitelist — giảm false positive alerts
TABLE alert_suppression (
    id, rule_id, machine_id, field_path, field_hash,
    reason, created_by, created_at, expires_at
)

# API routes:
# GET  /api/suppression/list        — list all active suppressions
# POST /api/suppression/add         — add suppression (rule_id + context)
# POST /api/suppression/remove/<id> — remove suppression

# db_manager.is_suppressed(rule_id, machine_id, event_data):
#   → Check rule-level, machine-level, path-match, hash-match
```

### 2.7 v3.8.0: Enrollment & Revocation (`server/db_manager.py`)

```python
# Certificate Revocation: is_revoked flag trên machines table
def revoke_machine(machine_id):    # Block agent connection
def unrevoke_machine(machine_id):  # Restore
def is_machine_revoked(machine_id):
def verify_enrollment_token(machine_id, token):  # Xác thực agent mới
```

### 2.8 FIM Pipeline (`agent/fim_collector.py` + `server/api/api_fim_baseline.py`)

```python
# v3.7.2: Agent-side FIM with priority hashing + chunk sync
class FIMCollector:
    MAX_FILES_PER_PATH = 500

    def _build_hash_cache(self):
        discovered = []
        for root_path in self.watch_paths:
            for fpath in os.walk(root_path):
                if excluded: continue
                priority = _file_priority(fpath)  # 0=EXE/DLL, 1=Startup, 9=Temp
                discovered.append((priority, fpath))
        discovered.sort()  # Priority first
        for _, fpath in discovered[:max_total]:
            self._hash_cache[fpath] = sha256_file(fpath)

    def _send_baseline_to_server(self):
        # Chia baseline thành chunk 200 files → sync tuần tự, 30s/chunk
        for chunk in chunks(baseline_files, 200):
            POST /api/fim/baseline/<mid>/diff

# v3.7.2: Server-side API with pagination + cache
# GET /api/fim/baseline/<mid>?limit=200&offset=0&search=&only_changed=false&sort_by=path
# GET /api/fim/baseline/summary  (cached 60s)
```

### 2.9 Server Event Pipeline (`server/`)

```python
# server_core.py: Khởi tạo
class ServerCore:
    def __init__(self):
        self.db = DatabaseManager()  # or PostgresDatabase / ElasticsearchDatabase (ClickHouse: roadmap)
        self.event_queue = EventQueue()           # 7 priority queues
        self.tcp_server = TCPServer(..., event_queue=self.event_queue)
        self.event_worker_pool = EventWorkerPool(event_queue, db, num_workers=8, batch_size=100)
        self.alerting = AlertingEngine()
        self.correlation = ServerCorrelationEngine()  # 11 CROSS rules

# tcp_server.py: Nhận event → push queue
class TCPServer:
    def _handle_event(self, msg):
        self.event_queue.push_event(msg)   # Không ghi DB trực tiếp!

# event_worker.py: Pop batch → ghi DB → correlation
class EventWorkerPool:
    def _worker_loop(self):
        for qname in [QUEUE_SYSMON, QUEUE_EVENTS, QUEUE_NETWORK, ...]:
            events = self.queue.pop_batch(qname, batch_size=100)
            handler(events)                    # Batch insert + correlation check
            time.sleep(0.05 if recently_active else 0.5)  # Adaptive poll
```

### 2.10 Database Backend Interface (`server/db_base.py`)

```python
class DatabaseBackend(ABC):
    @abstractmethod def get_events(machine_id, limit, severity, event_id, since) -> list
    @abstractmethod def insert_events_batch(machine_id, events)
    @abstractmethod def get_network_traffic(machine_id, limit, protocol)
    @abstractmethod def get_threats(machine_id, limit, severity) -> list
    @abstractmethod def get_fim_events(machine_id, limit, action) -> list
    # ... 60+ methods
```

### 2.11 Dashboard (Frontend)

```javascript
// dashboard.js - 3700 dòng
var viewMap = {
    overview, events, fim, syslog, response, network,
    vulns, yara, sca, agentless, assistant, sysmon, memory,
    incident, attack, hunting, anomaly, ioc,     // Phân tích & Điều tra
    groups, fimbaseline, rules, agentupdate, messages, email,  // Quản trị
    cleanup                                          // Hệ thống
};
function loadIncidentView()    { ... }  // v3.7: Incident sidebar + timeline
function loadIncidentTimeline(id) { ... }
function connectSSE()          { ... }  // EventSource real-time push
```

---

## 3. Logic Cảnh Báo

### 3.1 93 THREAT Rules (76 + 17 v3.9.16)

| Category | Số rules | Ví dụ |
|----------|---------|-------|
| Credential Access | 8 | Brute Force (4625×5), LSASS Dump, Kerberoasting, DCSync |
| Defense Evasion | 9 | Defender Disabled, Event Log Cleared, Timestomping (EID 2) |
| Impact/Ransomware | 5 | Mass File Mod, Ransom Note, Shadow Copy Delete |
| Execution | 6 | PowerShell Download, Encoded Command, Suspicious Process |
| Persistence | 8 | Service Install, Registry Run, WMI Event, Startup Folder |
| Lateral Movement | 5 | Pass-the-Hash, PsExec, WinRM, External Network Logon |
| C2 | 6 | C2 Ports, DNS Tunneling, TOR Exit |
| Privilege Escalation | 4 | Process Injection, Token Manip, UAC Bypass |
| Discovery | 4 | Port Scan, System Enum |
| Anomaly + Sigma | 21 | First-time events, behavior baseline, imported Sigma rules |

### 3.2 Rule Engine Capabilities
```
AND/OR/NOT nested conditions
Sequence rules: thứ tự sự kiện bắt buộc (3-stage attack chains)
Frequency rules: threshold + within_seconds + group_by
Distinct count: count_distinct username, dst_port, dst_ip
Field contains: path_contains, description_contains, field_contains + wildcards
Sigma auto-import: POST /api/rules/import-sigma → chuyển Sigma YAML → GIAM-SAT format
```

### 3.3 Alert Pipeline
```
Agent Event → TCP (mTLS) → Rate Limiter → EventQueue.push_event()
  → EventWorker.pop_batch(100)
    → DB batch INSERT
    → CorrelationEngine.check_against_rules()
      → Match: insert_threat_alert() + AlertingEngine.send_alert()
        → Email/Slack/Webhook/Telegram + SSE push → Dashboard real-time
```

### 3.4 Incident Investigation (v3.7)
Khi có threat alert, tab Điều tra tự động gom evidence trong ±15 phút:
```
🌐 Network traffic     (src_ip:dst_ip:dst_port)
🖥 Sysmon EID 1,2,3,11  (Process Create/Terminate/NetConnect/FileCreate)
📋 Windows Events       (4624,4625,4672,4688,5156,7045)
📁 FIM changes          (file modified/created/deleted)
🧠 Memory/YARA alerts   (suspicious modules, injections)
```

---

## 4. Công Nghệ Chịu Tải

### 4.1 Kiến trúc scale 1000+ agents
```
1000 Agents → Nginx TCP LB (least_conn, port 6666)
  → 4 Ingest Servers (ports 6667-6670, rate limit 10 conn/min/ip)
    → Event Queue Layer (Redis/RabbitMQ)
      → 8 Worker Threads (batch 100, adaptive poll)
        → Database (SQLite/Postgres+TimescaleDB/Elasticsearch; ClickHouse = roadmap)
          → Flask+Waitress (8 threads) + API Cache → Dashboard SSE
```

### 4.2 Các lớp tối ưu

| Lớp | Công nghệ | Tác dụng |
|-----|-----------|----------|
| **TCP LB** | Nginx stream, least_conn | Phân phối 1000 kết nối |
| **Rate Limiter** | IP sliding window | 10 conn/min, 100 evt/s per IP |
| **Event Queue** | Redis List / RabbitMQ (durable, DLX) | Decouple TCP accept khỏi DB write |
| **Worker Pool** | Python threads, batch=100, BEGIN IMMEDIATE | 100 INSERT trong 1 transaction (50-100x nhanh hơn) |
| **WAL Mode** | PRAGMA journal_mode=WAL, cache 32MB, mmap 256MB | SQLite read+write đồng thời |
| **DB Indexes** | 30+ indexes (machine_id, timestamp, severity) + v3.7.2 FIM baseline 3 indexes | Query <10ms thay vì full scan |
| **API Cache** | Redis GET/SET + PostgreSQL Materialized Views + v3.7.2 FIM 60s cache | Giảm tải DB cho dashboard |
| **ClickHouse** *(roadmap)* | Columnar ZSTD, TTL auto-cleanup, LowCardinality | Nén 5-10x, query 10-100x nhanh hơn — CHƯA code |
| **Dashboard Polling** | v3.7.1: 120s stats, 60s panorama, 300s active view | Giảm 75-80% query định kỳ |
| **Stats COUNT** | v3.7.1: chỉ đếm 24h + cache 30s | COUNT(*) 600K → 50K rows |
| **FIM Agent Limit** | v3.7.2: Priority hashing (EXE>DLL>System32>Config>Temp) + MAX 500/path + chunk sync 200 | Baseline 5000+ files → ≤500 prioritized |
| **FIM Baseline API** | v3.7.2: Pagination 200/page + summary cache 60s + search/sort | Dashboard load FIM tab <2s |
| **Sysmon EID 3 Network** | v3.8.0: Kernel-level network events thay netstat polling + process context (name/PID) | Real-time, không polling, chính xác hơn |
| **Alert Suppression** | v3.8.0: Global Whitelist (rule_id + machine_id + field context) | Giảm false positive alerts |
| **Agent Watchdog** | v3.8.0: Updater tự restart agent nếu bị kill (15s check) + Telegram alert | Đảm bảo agent luôn chạy |
| **MISP Threat Intel** | v3.8.0: REST API pull IOCs mỗi 60ph, cache offline, local feed | Threat intelligence từ community |
| **Enrollment & Revocation** | v3.8.0: Token xác thực agent mới + Certificate Revocation flag | Bảo mật enrollment |
| **Heartbeat Throttling** | v3.9.0: 20s→120s interval + kèm CPU/RAM/Disk/Net metrics | 10,000→720/day/máy (**93%↓**) |
| **Network 3-Tier Aggregation** | v3.9.0: T1 internal (60s agg) + T2 suspicious (real-time) + T3 external (agg) + baseline 24h | 100,000→~3,500/day/máy (**96%↓**) |
| **Sysmon Pre-Filter** | v3.9.0: EID 1/7/11/12/13/14 noise reduction + EID 22 DNS dedup 300s | 4,000→~1,600/day/máy (**60%↓**) |
| **DB Heartbeat Tuning** | v3.9.0: Heartbeat timeout 60s→300s + metrics columns (cpu/ram/disk/net) | DB size ổn định cho 200 máy |

### 4.3 Database Backend Selection

| Backend | Agents | RAM | Ưu điểm |
|---------|--------|-----|---------|
| SQLite (WAL) | <50 | 32MB | Zero config, single file |
| PostgreSQL+TimescaleDB | 50-500 | 2-8GB | Hypertable, connection pool, materialized views |
| Elasticsearch | 500+ | 16-32GB | Full-text search, Kibana, ILM |
| **ClickHouse** *(roadmap)* | 500+ | 2-4GB | Columnar, nén ZSTD, TTL — CHƯA code |

### 4.4 Performance Metrics

| Chỉ số | SQLite (WAL) | PostgreSQL | ClickHouse *(roadmap)* |
|--------|-------------|------------|------------|
| Events/s write | 5K-10K | 10K-50K | 50K-100K |
| Dashboard load | <1s (v3.9.0) | <500ms | <200ms |
| DB size 1 ngày/agent | ~2MB (v3.9.0) | ~10MB | ~2MB |
| Retention | 7-30 ngày | 90 ngày | 90 ngày (TTL auto) |

### 4.5 v3.9.0 Impact — Log Volume Optimization

| Loại Event | Trước (1 máy/ngày) | Sau (1 máy/ngày) | 200 máy/ngày | Tiết kiệm |
|------------|-------------------|-----------------|-------------|-----------|
| Heartbeat | 10,000 | 720 | 144K | **93%** |
| Network Traffic | 100,000 | ~3,500 | 700K | **96%** |
| Sysmon Events | 4,000 | ~1,600 | 320K | **60%** |
| **TOTAL** | **114,000** | **~5,820** | **~1.16M** | **95%** |

```
Trước v3.9.0: 200 máy × 114K = 22.8M events/ngày → SQLite không thể chịu nổi
Sau  v3.9.0: 200 máy × 5.8K = 1.16M events/ngày → SQLite hoạt động ổn định
```

---

## 5. Lịch Sử Phiên Bản

| Version | Date | Thay đổi chính |
|---------|------|---------------|
| **v5.0.3** | **2026-08** | **Security P1+P2: NetFlow DoS hardening (rate-limit/exporter + template TTL + batch insert), 2FA rate-limit+lockout+compare_digest+admin reset, nonce chống replay command, che ultraview_password khỏi viewer, rate-limit/blacklist GC, syslog UDP rate-limit, engine server = agent (subtype/dst_port/field_equals/field_regex/FIELD_ALIASES), PSK per-machine + validate machine_id + sanitize hostname (triệt stored-XSS nguồn), dedup_key theo normalized time, hunting LIKE escape, digest cap 200→2000 + weekly catch-up, CDN SRI, agent check_hostname, agent version 4.6.6** |
| v3.9.3 | 2026-07 | Network Smart Aggregation (aggregate-only, flush count>0, TTL 300s → 96%↓), SCA Fix (PASS+FAIL+WARN reporting, real-time sca_event) |
| v3.9.0 | 2026-07 | Log Volume Optimization: Heartbeat 120s+metrics, Network 3-Tier Aggregation, Sysmon Pre-Filter, DB heartbeat timeout 300s |
| v3.8.0 | 2026-07 | Sysmon EID 3 Network, Alert Suppression, Agent Watchdog, MISP Threat Intel, Enrollment & Revocation |
| v3.7.2 | 2026-07 | FIM Baseline: Priority Hashing + Chunk Sync + Pagination + Cache |
| v3.7.1 | 2026-07 | Dashboard Performance: 24h window, cache, reduced polling |
| v3.7.0 | 2026-07 | Named Pipe IPC, Incident Investigation, ClickHouse backend *(kế hoạch — không ra mắt)* |
| v3.6.8 | 2026-06 | Network log pipeline fix, dashboard dropdown |
| **v3.9.16** | **2026-08** | **5 cải thiện bảo mật: +4 Sysmon EID (4,16,17,18), +17 correlation rules (Ransomware, Kerberos, Exfil, Injection Chain, ETW Tampering), DNS/ICMP entropy analyzer, ProcessTreeBuilder tích hợp CorrelationEngine** |
| **v3.9.17** | **2026-08** | **5 security hardening: Certificate Pinning, Dead-man's Switch, Auto-Isolation Ransomware, IPC ACL Fix, Command Signing (HMAC), Remote Memory Dump** |
| **v4.0** | **2026-08** | **5 auto-response playbooks: Auto-Quarantine YARA, Kill Process Tree, Auto-Lock Kerberos, DPAPI-NG + TPM, IOC Retroactive Sweeper** |
| **v4.1** | **2026-08** | **Human-in-the-Loop Approval System: Telegram inline keyboard [Approve/Deny], Safety Gate 3 modes (off/confirm/auto), rich context Telegram alerts (MITRE+Process Chain+Events 24h)** |
| **v4.2** | **2026-08** | **PostgreSQL Migration: psycopg2 connection pool 10-50, 24 tables auto-migrate, 4 batch_insert methods (events/sysmon/network/fim), 10K-50K events/s write, PGCompatCursor bridge (SQLite→PostgreSQL auto-translate ? → %s)** |
| **v4.2.1** | **2026-08** | **PostgreSQL Compatibility Bugfixes: syslog JSONB fix, MITRE raw_data dict/string handling, email auto-fill fallback, modal UI expansion, syslog API error handling, agentless JSONB normalization** |
| **v4.3** | **2026-08-07** | **Production Hardening: mTLS toggle (GIAMSAT_TLS_ENABLED), syslog filter UI (facility/severity/IP/search), PostgreSQL indexes (threats.rule_id, syslog.* GIN full-text), ANALYZE schedule 6h, pg_dump backup script, UI layout 50-50, /api/health endpoint** |
| **v4.3.1** | **2026-08-08** | **PostgreSQL Compatibility Bugfixes: Hardware Config không hiển thị (JSONB json.loads fix), _compute_diff missing → 500 error, Smart List Diff (phát hiện thêm/xóa/sửa cụ thể), Dashboard Config UI highlight từng dòng thay đổi** |
| **v4.4** | **2026-08** | **PHA 1 (Audit): fix pre-filter sai field name (command_line/file_path/registry_key), thêm HashAlgorithms, gỡ browser/IP excludes, mở rộng thu thập EID 10/6/16/23/25/26/255, +4 rules (THREAT-077..080)** |
| **v4.4.1** | **2026-08** | **PHA 2: enable_windows_audit.ps1 + audit_policy.inf + gpo_deploy -EnableAudit** |
| **v4.5** | **2026-08** | **PHA 2.5: +THREAT-081/082/083 + NET-BEACON-001, memory-scanner name-spoof rewrite, SNMPv3 support** |
| **v4.5.1** | **2026-08** | **Bugfix run: undefined fmtBytes/escapeHtml, i18n hardcoded strings, beaconing lọc private IPs** |
| **v4.5.2** | **2026-08** | **Dedup sysmon double-send, repoint 8 dead subtype:Sysmon rules, fix engine FP (NOT+threshold) fire mọi event, fix tcp_server drop 8 sysmon types (BYOVD EID6, file-delete 23/26, hollowing 25...)** |
| **v4.5.3** | **2026-08** | **Fix retention cleanup không khớp C-time rows (_normalize_time + migration), dedup 150k events/ngày (dedup_key + INSERT OR IGNORE + agent mutex), fix 4688 StringInserts map, agent self-noise filter + skip_processes** |
| **v4.5.4** | **2026-08** | **Fix MITRE 'Error parsing MITRE data': tắt static-asset cache (SEND_FILE_MAX_AGE_DEFAULT=0), fix var t shadowing global t() trong renderMatrix** |
| **v5.0.0** | **2026-08-24** | **Phân loại cảnh báo (Triage) toàn diện: Threats (MITRE matrix + detail modal nút ✓ Xử lý), YARA, Network Inspection, Vulns — dropdown Phân loại mỗi dòng + toggle 'Hiện đã xử lý'; alert resolved/false_positive ẩn khỏi dashboard mặc định nhưng tái phát vẫn hiện lại (KHÔNG phải suppression); fix dashboard treo sau khi bấm ✓ (double bootstrap backdrop); re-detection reset status='new' cho YARA/Vulns; audit log đầy đủ (ai/IP/khi nào)** |
| **v5.0.1** | **2026-08-24** | **Ticket yêu cầu hỗ trợ có cấu trúc (thay chat tự do từ máy trạm): hộp thoại 'Yêu cầu hỗ trợ IT' — loại yêu cầu (Mạng/Phần mềm/Máy tính/Màn hình/Máy in/Điện thoại/Khác) + mô tả sự việc BẮT BUỘC + ID/pass UltraView (tùy chọn); máy + người gửi tự định danh từ agent config; messages table + 4 cột (msg_type/category/ultraview_id/ultraview_password); dashboard render ticket dạng 🎫 badge màu + hộp UltraView; từ server → máy trạm vẫn chat như cũ** |
| **v5.0.2** | **2026-08-24** | **Đại tu Group Policies (fix 5 bug critical): bảng policy_apply_status theo dõi theo TỪNG MÁY (fix first-machine-wins + trạng thái không bao giờ ghi nhận → re-push loop); policy đẩy qua commands table (máy offline vẫn nhận khi reconnect) + TCP push; agent báo policy_id qua command-result → ghi nhận applied/failed theo máy; disable/delete → tự đẩy remove_* cho mọi máy đã áp (soft-delete + purge, thống nhất cả 2 backend — fix SQLite removal không hoạt động); /api/policies/status + pending chuyển sang check_agent_psk; UI: nút 👁 trạng thái theo máy + ↻ áp lại tất cả, thêm policy tôn trọng checkbox Kích hoạt, ẩn danh sách nhóm khi mở tab policy, không đè config khi sửa; fix esc() (Messages tab lỗi 'Lỗi tải dữ liệu máy trạm/nhóm' — group id dạng số làm crash + esc không hề escape HTML)** |
| **v5.0.3** | **2026-08-24** | **Agent/Updater chạy ẩn (windowed build): GiamSatAgent.spec + updater.spec chuyển console=False → Task Scheduler khởi động KHÔNG hiện cửa sổ console đen (trước đây flash 10-15s trên máy cấu hình thấp, người dùng vô ý đóng → agent/updater tắt); main.py + updater.py redirect stdout/stderr khi windowed (tránh print() crash); build-agent.ps1 bỏ guard chặn console=False. Fix single-instance guard main.py (_log gọi trước khi định nghĩa → NameError bị nuốt → instance thứ 2 vẫn chạy = gửi trùng event). PG backend parity: thêm set_threat/yara/vuln/inspection_status + bảng netflow_flows + insert/get_netflow_flows (thiếu → triage + NetFlow 500 trên PG)** |
| v3.6.1 | 2026-06 | Initial release |

---

## 6. v3.9.16: 5 Cải Thiện Bảo Mật (2026-08)

### Tổng quan

Nâng điểm MITRE ATT&CK từ **6.6/10 → 7.8/10**, bổ sung khả năng phát hiện Ransomware, Defense Evasion (Sysmon Tampering), Kerberos Attacks, DNS/ICMP Exfiltration, và Cross-Process Injection Chains.

| Cải thiện | File sửa | Rules mới | Mức độ |
|---|---|---|---|
| 1. ETW/Sysmon Tampering | `sysmon_collector.py`, `correlation_engine.py` | THREAT-EVASION-001, 002 | CRITICAL |
| 2. Ransomware Detection | `correlation_engine.py` | RANSOM-001→005 | CRITICAL |
| 3. Kerberos Attack Detection | `correlation_engine.py` | KERB-001→003 | CRITICAL |
| 4. DNS/ICMP Exfiltration | `network_traffic_analyzer.py`, `correlation_engine.py` | EXFIL-001→003 | HIGH |
| 5. Process Injection Chain | `correlation_engine.py` | INJ-001, 002 | CRITICAL |

### 6.1 Sysmon EID Mở Rộng

```python
# sysmon_collector.py: +4 EID mới
4:  "service_state_change",  # Sysmon Service State → Tampering Detection
16: "config_change",         # Sysmon Config Change → Rule Modification
17: "pipe_created",          # Named Pipe Created → IPC Monitoring
18: "pipe_connected",        # Named Pipe Connected → IPC Monitoring
```

### 6.2 17 Correlation Rules Mới

| Rule ID | Tên | Trigger | Confidence |
|---|---|---|---|
| **THREAT-EVASION-001** | Sysmon Service Stopped | EID 4 + "stopped" | 95 |
| **THREAT-EVASION-002** | Sysmon Config Modified | EID 16 | 90 |
| **RANSOM-001** | VSSADMIN Shadow Copy Delete | Event 4688 + "vssadmin delete shadows" | 98 |
| **RANSOM-002** | WMIC Shadow Copy Delete | Event 4688 + "wmic shadowcopy delete" | 98 |
| **RANSOM-003** | BCDEDIT Boot Config Tamper | Event 4688 + "bcdedit /set" | 95 |
| **RANSOM-004** | Ransom Note Files Created | FIM + .hta/README/DECRYPT patterns | 90 |
| **RANSOM-005** | Multiple Services Stopped | Event 7036 + "stopped" ×5 in 60s | 75 |
| **KERB-001** | Golden Ticket (RC4 TGS) | Event 4769 + "0x17" + "krbtgt" | 95 |
| **KERB-002** | Kerberos Pre-Auth Attack | Event 4771 ×10 distinct src_ip | 80 |
| **KERB-003** | DCSync/Ticket Harvesting | Event 4768 ×20 in 60s | 70 |
| **EXFIL-001** | DNS Tunneling | network_traffic + dns_tunnel+entropy_high | 85 |
| **EXFIL-002** | ICMP Exfiltration | network_traffic + icmp_exfil+large_payload | 80 |
| **EXFIL-003** | Data Exfil Spike | network_traffic + exfil_spike | 60 |
| **INJ-001** | System→User Process Chain | sysmon_event + injection_chain | 90 |
| **INJ-002** | Deep Process Tree (Depth>4) | sysmon_event + deep_chain+sig_mismatch | 75 |

### 6.3 DNS/ICMP Exfiltration Analyzer

```python
# network_traffic_analyzer.py
class TrafficAnomalyDetector:
    def _shannon_entropy(self, data):
        """Shannon entropy 0.0-8.0. DNS tunneling >4.5."""
    
    # DNS tunneling: query > 52 chars + entropy > 4.5 OR size > 512 bytes
    # ICMP exfiltration: payload > 200 bytes → external IPs ×3 in 60s
    # Data exfil spike: > 2MB/min or > 10MB total to new external IP
```

### 6.4 Process Tree Integration

```python
# correlation_engine.py
from process_tree import ProcessTreeBuilder

class CorrelationEngine:
    def __init__(self):
        self.process_tree = ProcessTreeBuilder()  # 7-day cache, LOTL detection
    
    def process_event(self, event_data):
        # Feed Sysmon EID 1 into process tree before rule processing
        if self.process_tree and event is process_create:
            chain_alert = self.process_tree.add_event(event_data)
            if chain_alert:
                event_data["description"] += chain_alert  # Tags for INJ rules
```

### 6.5 Hướng dẫn xem trên Dashboard

| Bạn muốn xem... | Tab nào | Chi tiết |
|---|---|---|
| **Tất cả alerts** (Ransom, Kerberos, Exfil...) | **Threats** tab | Các alert hiện ra dạng bảng, lọc theo severity: CRITICAL sẽ là các rule RANSOM-*, KERB-001 |
| **Sysmon EID 4,16,17,18 raw events** | **Sysmon** tab | EID mới hiển thị cùng các EID khác, có `severity`, `description` |
| **Dashboard Builder** | **Dashboard** tab | Thêm widget từ nguồn "Sysmon Events" hoặc "Threat Alerts" → chọn Bar Chart/Pie Chart → nhóm theo severity |
| **Incident Investigation** | **Điều tra** tab | Khi có RANSOM-* alert, click vào sẽ thấy timeline ±15ph gồm Sysmon + Events + Network |

### 6.6 Kiểm tra nhanh alerts mới

```bash
# Kiểm tra alerts mới qua API
curl http://localhost:5000/api/threats?limit=20 | findstr "RANSOM KERB EXFIL INJ EVASION"

# Hoặc mở browser → Threats tab → tìm trong bảng
```

---

## 7. v3.9.17: Security Hardening & Active Defense (2026-08)

### 7.1 Tổng Quan

8 cải thiện bảo mật nâng cao, bảo vệ agent khỏi bị vô hiệu hóa, phát hiện MitM, chống fake command, tự động phản ứng với ransomware, memory dump từ xa.

| # | Cải thiện | File sửa | Mức độ | Dòng code |
|---|---|---|---|---|
| 1 | **Certificate Pinning** | `tls_utils.py`, `agent_core.py` | CRITICAL | +85 |
| 2 | **Heartbeat Dead-man's Switch** | `event_worker.py` | CRITICAL | +55 |
| 3 | **Auto-Isolation Ransomware** | `agent_core.py` | CRITICAL | +10 |
| 4 | **IPC ACL Fix** | `named_pipe_ipc.py` | HIGH | +5 |
| 5 | **Command Signing (HMAC)** | `agent_core.py` | CRITICAL | +50 |
| 6 | **Remote Memory Dump** | `responder.py`, `agent_core.py` | MEDIUM | +55 |
| 7 | **MITRE ATT&CK Heatmap** | `api_mitre.py`, `mitre-matrix.js` | UX | Đã có sẵn |
| 8 | **Kill & Quarantine UI** | `dashboard.js`, `api_response.py` | UX | Đã có sẵn |

### 7.2 Cấu hình kích hoạt

```bash
# Certificate Pinning: Chống Man-in-the-Middle
export GIAMSAT_SERVER_FINGERPRINT="A1:B2:C3:D4:E5:F6:..."

# Command Signing: Chống fake server command
export GIAMSAT_COMMAND_KEY="your-secret-shared-key-at-least-32-chars"

# Heartbeat Dead-man's Switch: 300s timeout (tự động, không cần cấu hình)
# Auto-Isolation Ransomware: Tự động khi RANSOM-* alert (tự động)
# IPC ACL: Tự động, chỉ SYSTEM + current user (tự động)
```

### 7.3 Certificate Pinning — MitM Protection

```python
# common/tls_utils.py → verify_server_cert_fingerprint()
# Agent kết nối TLS → lấy SHA-256 fingerprint của server cert
# So sánh với giá trị pinned trong GIAMSAT_SERVER_FINGERPRINT
# Nếu không khớp → ngắt kết nối + cảnh báo MitM
```

### 7.4 Heartbeat Dead-man's Switch

```python
# server/event_worker.py → _deadman_checker()
# Chạy mỗi 60s, kiểm tra máy online có last_seen > 300s
# Nếu máy mất kết nối không có shutdown signal → CRITICAL alert
# Rule HEARTBEAT-001: Agent Compromise / Forcibly Stopped
```

### 7.5 Command Signing — HMAC-SHA256

```python
# agent/agent_core.py → _verify_command_signature()
# Mỗi lệnh từ Server phải kèm _sig (HMAC-SHA256)
# Agent verify bằng shared secret GIAMSAT_COMMAND_KEY
# Lệnh không ký hoặc sai chữ ký → từ chối thực thi
```

### 7.6 Remote Memory Dump — Forensic

```python
# agent/responder.py → _dump_memory(params)
# Dùng comsvcs.dll MiniDumpWriteDump (built-in Windows, không cần procdump)
# Gửi command từ Server: {"action": "dump_memory", "params": {"pid": 1234}}
# Kết quả: file .dmp tạo trong %TEMP%, thông báo kích thước
```

### 7.7 IPC ACL Fix

```python
# agent/named_pipe_ipc.py → _create_pipe()
# Trước: None (default security) → bất kỳ process nào cũng có thể connect
# Sau: _create_pipe_with_acl() → chỉ SYSTEM + current user SID
```

### 7.8 MITRE ATT&CK Coverage Improvement

| Tactic | Trước v3.9.16 | Sau v3.9.17 |
|---|---|---|
| Defense Evasion | ⚠️ Thiếu | ✅ Sysmon Tampering (EID 4,16) |
| Impact (Ransomware) | ⚠️ Yếu | ✅ 5 rule RANSOM-* + Auto-Isolation |
| Credential Access | ✅ Tốt | ✅ +3 Kerberos rules |
| Exfiltration | ⚠️ Yếu | ✅ DNS/ICMP entropy + 3 EXFIL rules |
| Process Injection | ✅ Tốt | ✅ ProcessTreeBuilder tích hợp |
| Communication Security | ❌ Không có | ✅ TLS Pin + Command Signing |
| Agent Self-Protection | ❌ Không có | ✅ Dead-man + IPC ACL |
| **Tổng điểm** | **6.6/10** | **7.8/10** |

### 7.9 Files đã sửa (tổng cộng)

| File | v3.9.16 | v3.9.17 | Tổng |
|---|---|---|---|
| `sysmon_collector.py` | +4 EID | — | +4 dòng |
| `correlation_engine.py` | +17 rules | — | +140 dòng |
| `network_traffic_analyzer.py` | DNS/ICMP entropy | — | +130 dòng |
| `event_queue.py` | +4 event types | — | +3 dòng |
| `tls_utils.py` | — | Cert pinning | +85 dòng |
| `agent_core.py` | — | Pin + Isolation + Signing | +60 dòng |
| `event_worker.py` | — | Dead-man checker | +55 dòng |
| `named_pipe_ipc.py` | — | IPC ACL | +5 dòng |
| `responder.py` | — | Memory dump | +55 dòng |
| `summary.md` | ✓ | ✓ | +350 dòng |
| **TỔNG** | **~330 dòng** | **~260 dòng** | **~590 dòng** |

---

## 8. v4.0: Auto-Response Playbooks & Advanced Defense (2026-08)

### 8.1 Tổng Quan

5 auto-defense playbooks nâng cao, tự động phản ứng với malware, chặn tài khoản khi bị tấn công Kerberos, bảo vệ cache với TPM, quét IOC lịch sử.

| # | Cải thiện | File sửa | Trigger | Dòng code |
|---|---|---|---|---|
| 1 | **Auto-Quarantine YARA** | `agent_core.py` | YARA alert + file_path | +15 |
| 2 | **Kill Process Tree (BFS)** | `process_tree.py`, `responder.py` | Command kill_tree qua TCP/HTTP | +120 |
| 3 | **Auto-Lock Kerberos Account** | `agent_core.py`, `responder.py` | KERB-* alert | +60 |
| 4 | **DPAPI-NG + TPM Cache** | `encrypted_cache.py` | Tự động (LocalMachine) | +30 |
| 5 | **IOC Retro Sweeper** | `event_worker.py` | Hourly, 30-day history | +75 |

### 8.2 Auto-Quarantine YARA Alerts

```python
# agent/agent_core.py → _yara_callback() → _enrich_and_queue()
# Khi YARA scanner phát hiện file độc → tự động move vào quarantine
# SHA256 hash + metadata lưu trong C:\ProgramData\GiamSat\Quarantine\
```

### 8.3 Kill Process Tree

```python
# agent/responder.py → _kill_process_tree(params)
# PowerShell BFS: Get-CimInstance Win32_Process theo ParentProcessId
# Kill từ dưới lên (children → parent) để tránh orphan processes
# Command: {"action": "kill_tree", "params": {"pid": 1234}}
```

### 8.4 Auto-Lock Account on Kerberos Attack

```python
# agent/agent_core.py → _enrich_and_queue()
# Khi rule_id bắt đầu bằng "KERB-" → tự động Disable-LocalUser
# agent/responder.py → _lock_account()
```

### 8.5 IOC Retroactive Sweeper

```python
# server/event_worker.py → _retro_ioc_sweeper()
# Chạy hourly: đọc MISP cache → quét network_traffic 30 ngày → tạo alert
# 2 rule: IOC-RETRO-001 (IP match), IOC-RETRO-002 (domain match)
```

### 8.6 Files đã sửa (tổng cộng 3 phiên bản)

| File | v3.9.16 | v3.9.17 | v4.0 | Tổng |
|---|---|---|---|---|
| `sysmon_collector.py` | +4 EID | — | — | +4 |
| `correlation_engine.py` | +17 rules | — | — | +140 |
| `network_traffic_analyzer.py` | DNS/ICMP | — | — | +130 |
| `tls_utils.py` | — | Cert pinning | — | +85 |
| `agent_core.py` | — | Pin+Isolation+Signing | Quarantine+Lock | +85 |
| `event_worker.py` | — | Dead-man | IOC sweeper | +130 |
| `named_pipe_ipc.py` | — | IPC ACL | — | +5 |
| `responder.py` | — | Memory dump | Kill tree + Lock | +175 |
| `process_tree.py` | — | — | get_descendant_pids | +25 |
| `encrypted_cache.py` | — | — | DPAPI-NG+TPM | +30 |
| `mitre-matrix.js` | — | — | Heatmap gradient | +25 |
| `event_queue.py` | +4 types | — | — | +3 |
| `summary.md` | ✓ | ✓ | ✓ | +350 |
| **TỔNG** | **~330** | **~260** | **~400** | **~990** |

---

## 9. v4.1: Human-in-the-Loop Approval System (2026-08)

### 9.1 Tổng Quan

SOC không còn lo false positive gây hậu quả ngoài ý muốn. Mọi auto-response (cô lập mạng, khóa tài khoản, quarantine file) đều phải được SOC phê duyệt trước khi thực thi — qua Telegram hoặc Dashboard.

| # | Cải thiện | File sửa | Mức độ | Dòng code |
|---|---|---|---|---|
| 1 | **Safety Gate Framework** | `agent_core.py` | CRITICAL | +65 |
| 2 | **Telegram Inline Keyboard** | `alerting_engine.py` | HIGH | +50 |
| 3 | **Approval API** | `api_alert_approval.py` (MỚI) | CRITICAL | +130 |
| 4 | **Rich Context Alerts** | `alerting_engine.py` | UX | +30 |
| 5 | **Auto-Deny Cleanup** | `api_alert_approval.py` | MEDIUM | +10 |

### 9.2 Flow Hoạt Động

```
Agent phát hiện RANSOM-001 (vssadmin delete shadows)
  → _request_approval_or_execute("RANSOM-001", "isolate_network")
  → Kiểm tra config: mode = "confirm"
  → POST /api/alert/add-pending → server queue
  → Server gửi Telegram alert với inline keyboard [Approve] [Deny]
  → Dashboard poll /api/alert/pending → hiện popup
  → SOC bấm Approve trên Telegram:
      → POST /api/alert/approve?callback_data=giamsat_approve|WS-01|isolate_network
      → Server gửi command xuống agent → execute
  → SOC bấm Deny hoặc timeout 5 phút:
      → Auto-deny
```

### 9.3 3 Chế Độ Auto-Response

| Mode | Hành vi | Dùng khi |
|---|---|---|
| `"off"` **(mặc định)** | Không tự động gì. Chỉ gửi alert. | Mới triển khai, chưa test kỹ |
| `"confirm"` | Gửi Telegram + Dashboard → chờ SOC approve → execute | Đã test, SOC sẵn sàng |
| `"auto"` | Tự động thực thi ngay | Hệ thống đã ổn định, ít false positive |

### 9.4 Cấu Hình

```json
// agent/config.json
{
  "_auto_response_modes": {
    "off": "Không tự động hành động (mặc định - an toàn nhất). Chỉ gửi alert.",
    "confirm": "Gửi alert → chờ SOC approve qua Telegram/Dashboard → execute",
    "auto": "Tự động thực thi ngay lập tức (chỉ dùng khi đã test kỹ)"
  },
  "auto_response": {
    "mode": "off",
    "require_confidence": 90,
    "safe_users": ["admin", "administrator"],
    "safe_machines": ["DC01"]
  }
}
```

```json
// server/alerting_config.json
{
  "telegram": {
    "enabled": true,
    "bot_token": "YOUR_BOT_TOKEN",
    "chat_id": "123456789",
    "approval_timeout": 300
  }
}
```

### 9.5 Telegram Alert Rich Context

SOC nhận được alert với đầy đủ context để đánh giá thật/giả:

```
🔴 CRITICAL ALERT — WS-01
Rule: RANSOM-001 — VSSADMIN Shadow Copy Delete
MITRE: Impact (T1490)              ← Biết giai đoạn tấn công
Confidence: 98%                     ← Độ tin cậy
Machine: WS-01 (10.0.0.10)  ← IP + OS
Process Chain: svchost → cmd → vssadmin  ← Ai chạy lệnh?
Events 24h: 1                       ← Tần suất

💡 Verify: Check if user did system maintenance
📊 Open Dashboard                   ← Link Incident tab

[✅ Approve Isolation] [❌ Deny]
```

### 9.6 API Endpoints

| Endpoint | Method | Mục đích |
|---|---|---|
| `/api/alert/add-pending` | POST | Agent gửi yêu cầu approve |
| `/api/alert/approve` | POST | SOC approve/deny (Telegram callback hoặc Dashboard) |
| `/api/alert/pending` | GET | Dashboard poll danh sách pending |

### 9.7 Files Mới (v4.1)

| File | Thay đổi | Dòng |
|---|---|---|
| `agent/agent_core.py` | +`_request_approval_or_execute()` Safety Gate | +65 |
| `server/alerting_engine.py` | +Telegram inline keyboard + rich context | +80 |
| `server/api/api_alert_approval.py` | **MỚI** — 3 endpoints + auto-deny thread | +130 |
| `server/api/__init__.py` | Route registration | +2 |
| `server/alerting_config.json` | **MỚI** — Telegram + auto_response config | +35 |
| `agent/config.json` | Section auto_response + comment modes | +15 |
| **TỔNG** | | **~327 dòng** |

---

## 10. Khả Năng Chịu Tải Server — i5-12400 / 16GB RAM

### 10.1 Cấu Hình Server Hiện Tại

| Thành phần | Cấu hình |
|------------|----------|
| CPU | Intel Core i5-12400 (6 core, 12 threads, 2.5-4.4 GHz) |
| RAM | 16GB DDR4 |
| OS | Windows 11 |
| Python | Single process, GIL-bound |
| Database | SQLite WAL (single writer) |
| Web Server | Waitress 16 threads |
| Event Workers | 8 threads (GIAMSAT_EVENT_WORKERS) |

### 10.2 Luồng Dữ Liệu & Bottleneck

```
N Agents ──TCP──> TCP Server (1 thread/connection) ──> Event Queue (in-memory)
  → 8 Event Workers ──> SQLite WAL (single writer, RLock)
    → Correlation Engine (per-event) → Anomaly Detector
```

**Bottleneck chính: SQLite single-insert (KHÔNG batch)**

Từ phân tích code `event_worker.py` và `db_manager.py`:
- `event_worker.py` dùng `hasattr(self.db, 'batch_insert_events')` → SQLite `db_manager.py` **không có** batch insert → fallback `insert_event()` từng event một
- Mỗi INSERT mất ~1ms (SQLite WAL + RLock + SSD) → **~1.000 events/s** thực tế
- Nếu nâng cấp batch insert: **~20.000-50.000 events/s**

### 10.3 Tải Dữ Liệu Mỗi Máy Trạm/Ngày

| Loại Event | Events/Ngày/Máy | % |
|------------|-----------------|---|
| Heartbeat (120s) | 720 | 12% |
| Network Traffic (3-tier agg) | 3.500 | 60% |
| Sysmon Events (pre-filter) | 1.600 | 28% |
| Windows Events + FIM + YARA + SCA + Vuln | ~200 | <1% |
| **TỔNG** | **~5.820** | 100% |

| Chỉ số | Giá trị |
|--------|---------|
| Events/s trung bình/máy | 0.067 |
| Events/burst (agent flush 15s) | ~60 events |
| DB size/ngày/máy | ~2 MB |
| RAM/agent (TCP thread) | ~10 MB |

### 10.4 Đánh Giá Theo Số Lượng Máy

| Số Máy | Retention | DB Size | Events/s TB | Burst | Đánh Giá |
|--------|-----------|---------|-------------|-------|----------|
| **10-30** | 90 ngày | 2-5 GB | 2/s | 1.800 | ✅ **Thoải mái** — Dashboard <1s, query nhanh |
| **30-50** | 30 ngày | 2-3 GB | 3/s | 3.000 | ✅ **Tốt** — SQLite ổn định, RAM ~500MB cho TCP |
| **50-100** | 7 ngày | 1-1.4 GB | 7/s | 6.000 | ⚠️ **Chấp nhận được** — Dashboard có thể chậm giờ cao điểm, cần batch insert |
| **100-200** | 3-7 ngày | 1-3 GB | 14/s | 12.000 | ⚠️ **Giới hạn** — Bắt buộc nâng cấp batch insert, TCP thread ~2GB RAM |
| **200+** | 3 ngày | 2GB+ | 14+/s | 12.000+ | ❌ **Cần PostgreSQL/ClickHouse** — SQLite không chịu nổi |

### 10.5 Giới Hạn Cụ Thể

| Giới hạn | Nguyên nhân | Con số |
|----------|-------------|--------|
| **SQLite write** | Single writer, RLock, insert từng event | ~1.000 events/s |
| **Python GIL** | 1 thread chạy Python code tại một thời điểm | ~1.5 core hiệu quả |
| **RAM (TCP threads)** | Mỗi connection ~10MB stack | ~1.200 agents tuyệt đối, ~800 thực tế |
| **CPU (correlation)** | Per-event anomaly + correlation check | ~5.000 events/s/core |
| **Dashboard query** | API cache 30s, view polling 120-300s | 500+ agents có thể chậm |
| **DB size** | SQLite <10GB để query <2s | ~50 máy × 90 ngày hoặc ~200 máy × 7 ngày |

### 10.6 Khuyến Nghị

| Trường hợp | Giải pháp | Chi phí |
|------------|-----------|--------|
| **<50 máy** (hiện tại tổ chức của bạn) | SQLite + batch insert | 0đ — thêm 30 dòng code |
| **50-200 máy** | PostgreSQL + TimescaleDB | 0đ — cài PostgreSQL trên cùng máy |
| **200-500 máy** | PostgreSQL server riêng (8GB RAM) | Máy chủ riêng hoặc VPS |
| **500+ máy** | ClickHouse + Nginx TCP LB *(roadmap)* | 2-4GB RAM cho ClickHouse |

### 10.7 Backend Database Hiện Có — Thực Trạng Code

| Backend | File | Trạng thái | Batch Insert | TimescaleDB |
|---------|------|------------|-------------|-------------|
| **SQLite** | `db_manager.py` (1832 dòng) | ✅ Hoàn thiện | ❌ Thiếu → ghi từng event | N/A |
| **PostgreSQL** | `db_postgres.py` (1208 dòng) | ✅ Hoàn thiện | ❌ Thiếu → có sẵn `_executemany()` nhưng chưa expose | ✅ Hypertable auto |
| **ClickHouse** | `db_clickhouse.py` | ❌ **Chưa code** — chỉ có trong plan | N/A | N/A |
| **Elasticsearch** | `db_elasticsearch.py` | ❌ **Chưa code** — chỉ có trong plan | N/A | N/A |

> **Cả 3 backend đều dùng chung `event_worker.py`** checked `hasattr(self.db, 'batch_insert_events')` → fallback `insert_event()` từng cái một.
> Chỉ cần thêm `batch_insert_events()` vào bất kỳ backend nào là throughput tăng 20-50x ngay.

### 10.8 PostgreSQL — Đã Triển Khai ✅ (2026-08-05)

**Quá trình triển khai:**
1. Cài `psycopg2-binary` → OK
2. PostgreSQL 16 đã có sẵn (port 5432)
3. Tạo database `giamsat` → OK
4. Cấu hình `.env`: `GIAMSAT_DB_BACKEND=postgres` + connection pool 10-50
5. 24 bảng tự động migrate qua `_init_db()` → OK
6. Thêm 4 `batch_insert_*` methods dùng `_executemany()` → throughput 10K-50K events/s
7. Thêm 49 method còn thiếu từ `db_manager.py` + sửa 27 signature mismatches
8. Fix 2 logic bugs:
   - `insert_heartbeat` không update `machines.last_seen` → máy không hiển thị online
   - `insert_response_result` không update `commands.status` → nhắn tin lỗi kết nối
9. Thêm migration columns: `machines.is_revoked`, `machines.enrollment_token`, `threat_alerts.source_ip`

**Lợi ích đạt được:**
- Write: 10K-50K events/s (vs SQLite 1K) — nhanh hơn 10-50x
- Connection pool 10-50 → không bị lock như SQLite RLock single writer
- JSONB raw_data → query linh hoạt hơn
- Retention: 90+ ngày không vấn đề
- RAM dùng thêm: ~500MB → tổng ~3.5GB/16GB

**Không cần rebuild agent** — PostgreSQL migration là 100% server-side. Agent chỉ gửi JSON qua TCP:6666.
**Chỉ cần restart server** (`python main.py`) để kích hoạt.

**Cấu hình `.env` hiện tại:**
```env
GIAMSAT_DB_BACKEND=postgres
GIAMSAT_PG_HOST=127.0.0.1
GIAMSAT_PG_PORT=5432
GIAMSAT_PG_DBNAME=giamsat
GIAMSAT_PG_USER=postgres
GIAMSAT_PG_PASSWORD=postgres
GIAMSAT_PG_POOL_MIN=10
GIAMSAT_PG_POOL_MAX=50
```

### 10.9 So Sánh Nhanh Các Giải Pháp

| Giải pháp | Công sức | Write/s | Máy tối đa | Retention | Phù hợp |
|-----------|----------|---------|------------|-----------|---------|
| SQLite hiện tại | 0 | 1K | 50 | 7-30 ngày | ✅ Dùng ngay |
| SQLite + batch insert | 30 dòng | 50K | 200 | 7-30 ngày | ✅ 1 giờ |
| PostgreSQL | 1 giờ + cài đặt | 50K | 500+ | 90+ ngày | ✅ Tốt nhất |
| ClickHouse | Chưa code | N/A | N/A | N/A | ❌ Chưa làm |

### 10.10 Cải Thiện Nhanh (0đ, 30 dòng code)

Thêm `batch_insert_events()` vào `db_manager.py`:
- 100 INSERT trong 1 transaction → nhanh 20-50x
- SQLite write: 1.000 → 20.000-50.000 events/s
- Hỗ trợ 200+ máy với SQLite
- Dashboard vẫn dùng cache có sẵn

### 10.11 Kết Luận

> **Với SQLite hiện tại + i5-12400 + 16GB RAM:**
> - **30-50 máy trạm** → hoạt động ổn định trong **30-90 ngày** retention
> - **50-100 máy** → nên giảm retention xuống **7 ngày**, thêm batch insert
> - **100-200 máy** → cần PostgreSQL + TimescaleDB (miễn phí, cài cùng máy)
>
> **Dung lượng ổ cứng:** 50 máy × 2MB/ngày × 30 ngày = **~3GB** → chiếm rất ít
>
> **RAM sử dụng thực tế cho 50 máy:**
> - Python process: ~500MB (50 TCP threads × 10MB)
> - SQLite cache: ~256MB (PRAGMA cache_size)
> - Hệ điều hành + background: ~2GB
> - **Tổng: ~3GB / 16GB** → còn dư nhiều
>
> **CPU i5-12400:**
> - Idle: <5% với SQLite
> - Giờ cao điểm (tất cả agent flush đồng thời): ~15-20%
> - 6 core dư sức cho 50-200 máy

---

## 11. v4.2.1: PostgreSQL Compatibility Bugfixes (2026-08-06)

### 11.1 Tổng Quan

Sau khi migrate từ SQLite sang PostgreSQL, nhiều bug phát sinh do khác biệt giữa 2 database engine. Đợt bugfix này giải quyết 8 vấn đề chính.

| # | Bug | Root Cause | Fix | File |
|---|---|---|---|---|
| 1 | **Syslog không lưu vào DB** | `insert_syslog` gửi raw string vào JSONB column → PostgreSQL throw exception bị nuốt | Convert raw string → `json.dumps({"raw": str})` | `db_postgres.py` |
| 2 | **MITRE ATT&CK Matrix trống** | `raw_data` từ PostgreSQL JSONB đã là `dict`, code gọi `json.loads(dict)` → TypeError | Kiểm tra `isinstance(raw_data_val, dict)` trước khi parse | `api_mitre.py` |
| 3 | **Email không tự động điền** | `onEmailTemplateChange()` đọc DOM element `emailTemplatesData` không tồn tại | Dùng `emailTemplates` array từ API, fallback DOM | `dashboard.js` |
| 4 | **Modal Attack Chains quá nhỏ** | `max-height:70vh` không đủ hiển thị nội dung | Tăng lên `85vh`, thêm `max-width:90vw` | `index.html` |
| 5 | **Agentless "Lỗi tải dữ liệu"** | PostgreSQL trả về `data_json` (JSONB) nhưng frontend expect `data` | Normalize `data_json` → `data` trong API | `api_agentless.py` |
| 6 | **MITRE API query error** | SQL dùng `?` placeholder (SQLite syntax) trên PostgreSQL | Đổi `?` → `%s`, `LIKE ?` → `raw_data::text LIKE %s` | `api_mitre.py` |
| 7 | **PGCompatCursor thiếu `.cursor()`** | Một số code gọi `conn.cursor()` nhưng PGCompatCursor không có method này | Thêm `def cursor(self): return self` | `db_postgres.py` |
| 8 | **UI Layout tổng quan** | Panorama chiếm 8/12 cột, máy trạm chỉ 4/12 | Đổi thành 6/12 mỗi bên (50-50) | `index.html` |

### 11.2 Chi Tiết Kỹ Thuật

#### 11.2.1 PGCompatCursor Bridge

```python
class PGCompatCursor:
    """SQLite-compatible cursor wrapper for PostgreSQL.
    Translates `self.db.conn.execute(sql, params)` to `self.db._execute(sql, params)`.
    Auto-converts ? placeholders to %s, detects SELECT vs mutation.
    """
    def __init__(self, db):
        self._db = db
        self._results = []
        self.rowcount = 0

    def cursor(self):
        """Compatibility: some code calls conn.cursor() - return self as cursor."""
        return self

    def execute(self, sql, params=None):
        pg_sql = sql.replace("?", "%s")
        is_select = pg_sql.strip().upper().startswith("SELECT")
        if is_select:
            result = self._db._execute(pg_sql, params, fetchall=True)
            self._results = [PGCompatRow(r) for r in result]
        else:
            self.rowcount = self._db._execute(pg_sql, params) or 0
        return self

    def fetchone(self): return self._results[0] if self._results else None
    def fetchall(self): return self._results
```

#### 11.2.2 Syslog JSONB Fix

```python
# Trước (v4.2 - BUG):
def insert_syslog(self, source_ip, hostname, facility, severity, timestamp, message, raw_data):
    self._execute(
        "INSERT INTO syslog (...) VALUES (%s,...,%s)",
        (..., raw_data)  # ← raw string vào JSONB column → ERROR!
    )

# Sau (v4.2.1 - FIX):
def insert_syslog(self, source_ip, hostname, facility, severity, timestamp, message, raw_data):
    raw_json = json.dumps({"raw": str(raw_data)[:4000]}, ensure_ascii=False)
    self._execute(
        "INSERT INTO syslog (...) VALUES (%s,...,%s)",
        (..., raw_json)  # ← JSON object → OK
    )
```

#### 11.2.3 MITRE raw_data Handling

```python
# PostgreSQL JSONB column → psycopg2 tự động parse thành dict
# Code cũ gọi json.loads() trên dict → TypeError

# Fix: kiểm tra type trước khi parse
if isinstance(raw_data_val, dict):
    raw = raw_data_val       # PostgreSQL JSONB → đã là dict
elif isinstance(raw_data_val, str):
    raw = json.loads(raw_data_val)  # SQLite TEXT → cần parse
else:
    raw = {}
```

### 11.3 Files Đã Sửa (v4.2.1)

| File | Thay đổi | Dòng |
|---|---|---|
| `server/db_postgres.py` | PGCompatCursor.cursor(), insert_syslog JSONB fix | +10 |
| `server/api/api_mitre.py` | `?` → `%s`, raw_data dict/string handling | +15 |
| `server/static/js/dashboard.js` | onEmailTemplateChange API fallback, loadSyslog error handling | +30 |
| `server/templates/index.html` | Modal 70vh→85vh, layout col-md-8/4→6/6 | +5 |
| `server/api/__init__.py` | Revert api_syslog import (đã có trong api_events.py) | -2 |
| **TỔNG** | | **~60 dòng** |

---

## 12. Đề Xuất Phương Án Cải Tiến

### 12.1 Ưu Tiên CAO (ĐÃ HOÀN THÀNH ✅)

| # | Cải tiến | Lợi ích | Trạng thái |
|---|---|---|---|
| 1 | **Bật TLS cho Agent-Server** | Mã hóa toàn bộ traffic TCP:6666, chống sniffing | ✅ `GIAMSAT_TLS_ENABLED=true` |
| 2 | ~~Thêm batch_insert_events vào SQLite~~ | Đã migrate sang PostgreSQL, có sẵn batch insert | N/A |
| 3 | **Health Check & Auto-Restart** | `/api/health` endpoint, ANALYZE schedule 6h | ✅ |
| 4 | **Backup tự động PostgreSQL** | `backup_pg.bat` với nén zip, rotation 30 ngày | ✅ |
| 5 | **Syslog Dashboard filter & search** | Filter UI: Facility, Severity, Source IP, Search + GIN index | ✅ |

### 12.2 Ưu Tiên TRUNG BÌNH (nên làm trong tháng)

| # | Cải tiến | Lợi ích | Công sức |
|---|---|---|---|
| 6 | **ClickHouse Backend** | Columnar storage, nén 5-10x, query 10-100x nhanh hơn PostgreSQL | 3 ngày |
| 7 | **Dashboard Builder nâng cao** | Kéo thả widget, custom dashboard cho từng role (SOC/Manager/IT) | 5 ngày |
| 8 | **API Rate Limiting** | Chống abuse API, bảo vệ server khỏi query nặng | 2h |
| 9 | **Audit Log đầy đủ** | Ghi log mọi thao tác admin (xóa máy, gửi lệnh, đổi config) | 3h |
| 10 | **Email Alert Templates có thể chỉnh sửa** | Cho phép admin tạo/sửa template email qua Web UI thay vì hardcode | 4h |
| 11 | **Mobile App PWA** | Push notification khi có CRITICAL alert, xem dashboard trên điện thoại | 3 ngày |

### 12.3 Ưu Tiên THẤP (cân nhắc dài hạn)

| # | Cải tiến | Lợi ích | Công sức |
|---|---|---|---|
| 12 | **Multi-Tenant Support** | Một server phục vụ nhiều công ty, phân quyền theo tenant | 2 tuần |
| 13 | **Distributed Deployment** | Nginx TCP LB + 4 ingest servers + 1 DB server | 1 tuần |
| 14 | **AI SOC Analyst** | Tự động phân tích alert, đề xuất response, học từ historical data | 2 tuần |
| 15 | **Integration với SIEM (Splunk/ELK)** | Forward alert sang SIEM qua Syslog/HTTP Webhook | 1 ngày |
| 16 | **Agent cho Linux** | Hỗ trợ giám sát Linux servers (Ubuntu/CentOS) | 2 tuần |
| 17 | **Compliance Reports (PCI-DSS, ISO 27001)** | Tự động sinh báo cáo tuân thủ định kỳ | 1 tuần |

### 12.4 Kiến Trúc Đề Xuất Cho 200+ Máy

```
                        ┌──────────────────────┐
                        │   Nginx TCP LB       │
                        │   (least_conn)       │
                        │   port 6666          │
                        └──────┬───────────────┘
                               │
               ┌───────────────┼───────────────┐
               │               │               │
        ┌──────▼──────┐ ┌──────▼──────┐ ┌──────▼──────┐
        │ Ingest #1   │ │ Ingest #2   │ │ Ingest #3   │
        │ Flask+WS    │ │ Flask+WS    │ │ Flask+WS    │
        │ port 6667   │ │ port 6668   │ │ port 6669   │
        └──────┬──────┘ └──────┬──────┘ └──────┬──────┘
               │               │               │
               └───────────────┼───────────────┘
                               │
                        ┌──────▼──────┐
                        │   Redis     │
                        │  (Queue)    │
                        └──────┬──────┘
                               │
                        ┌──────▼──────┐
                        │ PostgreSQL  │
                        │ +TimescaleDB│
                        │ (Primary)   │
                        └──────┬──────┘
                               │
                        ┌──────▼──────┐
                        │  pg_dump    │
                        │  nightly    │
                        │  backup     │
                        └─────────────┘
```

### 12.5 Lộ Trình Đề Xuất (Cập nhật 2026-08-07)

| Giai đoạn | Thời gian | Mục tiêu | Trạng thái |
|---|---|---|---|
| **Phase 1: Ổn định** | ~~Tuần 1-2~~ | Fix bugs, TLS toggle, backup, health check, syslog filter, PostgreSQL optimize | ✅ **HOÀN THÀNH** |
| **Phase 2: Tối ưu** | Tuần 3-4 | ClickHouse POC, API rate limiting, audit log, email template manager | ⏳ Tiếp theo |
| **Phase 3: Mở rộng** | Tháng 2 | Dashboard builder, mobile PWA, MITRE interactive | 📅 |
| **Phase 4: Chuyên nghiệp** | Tháng 3+ | Multi-tenant, distributed deployment, AI SOC analyst | 📅 |

### 12.6 v4.3 Production Hardening — Đã Hoàn Thành (2026-08-07)

| # | Cải tiến | File | Chi tiết |
|---|---|---|---|
| 1 | **mTLS Toggle** | `server_core.py` | `GIAMSAT_TLS_ENABLED=true` trong `.env` → tự động generate cert + bật TLS cho TCP:6666 |
| 2 | **Syslog Filter UI** | `index.html`, `dashboard.js`, `api_events.py`, `db_postgres.py` | Filter bar: Facility dropdown (19 loại), Severity (8 mức), Source IP input, Full-text search + GIN index |
| 3 | **PostgreSQL Indexes** | `db_postgres.py` | `idx_threats_rule`, `idx_syslog_source_ip`, `idx_syslog_facility`, `idx_syslog_severity`, `idx_syslog_message` (GIN) |
| 4 | **ANALYZE Schedule** | `server_core.py` | Background thread chạy `VACUUM ANALYZE` mỗi 6h |
| 5 | **Backup Script** | `server/backup_pg.bat` (MỚI) | pg_dump + nén zip + rotation 30 ngày, dùng với Task Scheduler |
| 6 | **UI Layout** | `index.html` | Panorama + Máy trạm 50-50 (col-md-6/6) |
| 7 | **Health Check** | `server_core.py` | `GET /api/health` → web, tcp, database status |

### 12.7 v4.3.1 PostgreSQL Compatibility Bugfixes — Đã Hoàn Thành (2026-08-08)

| # | Bugfix | File | Chi tiết |
|---|---|---|---|
| 1 | **Hardware Config không hiển thị** | `db_postgres.py` | `get_hardware_info()`, `get_baseline()`, `get_machine_config()`: JSONB column được psycopg2 auto-parse thành `dict`, code gọi `json.loads(dict)` → `TypeError` bị `try/except` nuốt → trả về `None` → dashboard hiển thị "Chưa có cấu hình" |
| 2 | **Lỗi tải cấu hình (500 error)** | `db_postgres.py` | `_compute_diff()` hoàn toàn thiếu trong `db_postgres.py`, API `/api/machine/<mid>/config` gọi `core.db._compute_diff()` → `AttributeError` → 500 |
| 3 | **Smart List Diff** | `db_manager.py`, `db_postgres.py` | `_compute_diff()` cũ chỉ so sánh số lượng (95 mục → 98 mục). Mới: So sánh từng phần tử bằng identity key (`name`/`model`/`part_number`) → phát hiện **thêm mới** 🟢, **đã xóa** 🔴, **thay đổi** 🟡 cho từng phần mềm/thiết bị cụ thể |
| 4 | **Dashboard Config UI** | `dashboard.js` | `loadMachineConfig()` hiển thị ⚠️ icon trên từng dòng bị thay đổi với tooltip "Trước: X → Hiện tại: Y", border-left vàng cho section bị ảnh hưởng, highlight nền vàng nhạt cho hàng bị thay đổi, bảng tổng hợp 📋 Chi tiết thay đổi ở đầu tab |

### 12.8 v4.3.2 Agent Messaging Bugfix — Đã Hoàn Thành (2026-08-10)

| # | Bugfix | File | Chi tiết |
|---|---|---|---|
| 5 | **Tin nhắn không hiển thị trên máy trạm** | `agent_core.py` | **Triệu chứng**: Server TCP push OK, agent log có `[MSG] Displaying message` và `[MSG] Reply sent` cùng một giây (07:48:37) nhưng người dùng không thấy dialog. **Nguyên nhân**: `_sp.CREATE_NO_WINDOW` (0x08000000) trong `subprocess.run()` chặn Windows Forms message pump, khiến `ShowDialog()` return ngay lập tức mà không hiển thị UI. **Fix**: Bỏ `creationflags=_sp.CREATE_NO_WINDOW` — agent chạy trong user session (Session 1) nên GUI được phép hiển thị. |
| 6 | **Command dedup** | `agent_core.py` | Thêm `_is_duplicate()` check trong `_execute_polled_command()` để tránh execute 2 lần khi command đến qua cả TCP và HTTP poll. |
| 7 | **F-string syntax fix** | `agent_core.py` | Python 3.11+ không cho backslash trong f-string expression. Fix: extract `reply_file_path_esc` ra biến riêng trước khi dùng trong f-string. |

### 12.9 Lịch Sử Phiên Bản

| Phiên bản | Ngày | Thay đổi chính |
|---|---|---|
| v4.1 | 2026-07 | SOC Approval Gate, CVE Alert enrichment, Auto-Isolation (Ransomware/Kerberos/YARA) |
| v4.3 | 2026-08-07 | mTLS toggle, syslog filter UI, PostgreSQL indexes, ANALYZE schedule, backup script |
| v4.3.1 | 2026-08-08 | PostgreSQL JSONB compatibility (dict vs json.loads), Smart List Diff, Dashboard Config UI |
| v4.3.2 | 2026-08-10 | Agent Message GUI fix (CREATE_NO_WINDOW removal), command dedup, f-string fix |
| v4.3.3 | 2026-08-10 | Vuln alert dedup (24h), Anomaly alert dedup (5min cooldown), Dashboard Builder JSONB+clearAll fix |
| v4.3.4 | 2026-08-10 | Agent Message GUI tkinter rewrite (PowerShell → Python), Syslog=0 fix, EXE deployment fix |
| **v4.4** | **2026-08-11** | **Module Quản lý Tài sản: 4 bảng mới, display_id, hardware change detection, monitor reassign, REST API, 3-tab UI** |
| **v4.5** | **2026-08-11** | **Mã TS PC-001/MN-001, cột Mainboard, xuất Excel 2 sheet, tìm kiếm mở rộng (display_id + email), bộ cài setup đầy đủ** |
| **v4.5.1** | **2026-08-12** | **Open-source release: dọn dẹp repo, .gitignore, README.md, LICENSE MIT, setup_config.ps1, fix SQLite asset methods, fix hardcoded paths, fix INTERVAL syntax (cleanup/retention), fix uptime tracking, fix asset_id (mb_serial), fix display_id (hash 8 ký tự), fix build scripts (relative paths, ConstrainedLanguage), xóa dữ liệu cá nhân** |
| **v4.7** | **2026-08-17** | **Quan ly tai san IT mo rong: kho nhap tay + tu phat hien (may in / dien thoai IP / thiet bi mang qua SNMP+port fingerprint), bang assets_inventory, tinh nang adopt (auto->manual), xuat Excel 7 sheet** |
| **v4.8** | **2026-08-17** | **So luong ton kho (quantity), may in USB tu gan source=auto tu agent, sua MITRE ATT&CK matrix hien thi canh bao tactic chua map (Unknown/Other)** |

