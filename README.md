# GIAM-SAT v5.0.4 — Hệ thống Giám sát An ninh Mạng Nội bộ

> **GIAM-SAT** (GIAM SÁT) là hệ thống giám sát an ninh mạng mã nguồn mở, kiến trúc **Agent-Server**, hỗ trợ giám sát Windows/Linux endpoint, phân tích threat theo MITRE ATT&CK, quản lý tài sản CNTT, và cảnh báo thời gian thực qua Telegram/Email.

---

## 🔄 Cập nhật phiên bản từ GitHub (không cần tải lại ZIP) — Update from GitHub (no ZIP re-download)

> Hướng dẫn song ngữ (Việt - Anh) — Bilingual (Vietnamese - English).

**VI:** Sau khi đã chạy dự án trên server, bạn có thể cập nhật lên bản mới nhất trực tiếp từ GitHub bằng Git — **không cần xóa bản cũ, không cần tải lại file ZIP**.
**EN:** Once the project is running on your server, update to the latest version directly from GitHub with Git — **no need to delete the old copy or re-download the ZIP**.

Trên server (làm 1 lần) — On the server (one-time setup):

```powershell
cd C:\giamsat
git init
git remote add origin https://github.com/crazyguyz/CISA-mesh.git
git fetch origin main
git reset --hard origin/main      # ← lấy đúng bản mới nhất (get the exact latest version)
```

Mỗi lần có bản mới — Every time a new version is released:

```powershell
git pull
```

**Lưu ý — Notes:**
- Chỉ thay đổi giao diện (`server\templates\`, `server\static\`) → **không cần restart**, chỉ cần **Ctrl+F5** trên trình duyệt.
- Only UI files changed (`server\templates\`, `server\static\`) → **no restart needed**, just press **Ctrl+F5** in the browser.
- Có thay đổi mã Python (`*.py`) → **restart server** để áp dụng (agent sẽ tự kết nối lại sau vài giây).
- Python files changed (`*.py`) → **restart the server** to apply (agents reconnect automatically within a few seconds).
- Sao lưu trước khi cập nhật: `server\giamsat_data.db`, `users.json`, `.env` (nếu có). Với PostgreSQL: `pg_dump -U admin -d giamsat > backup.sql`.
- Back up before updating: `server\giamsat_data.db`, `users.json`, `.env` (if present).
- ⚠️ `server\version.txt` là **phiên bản agent-build** — server dùng nó để so sánh với phiên bản agent báo lên (`update_available = agent_version != version.txt`). Phải để **khớp với bản GiamSatAgent.exe đang phát hành**, nếu không agent sẽ tải đi tải lại mãi (vòng lặp update). `build-agent.ps1` tự ghi đúng vào cả 2 file mỗi lần build.
- ⚠️ `server\version.txt` is the **agent-build version** — the server compares it to the version each agent reports (`update_available = agent_version != version.txt`). It MUST match the shipped `GiamSatAgent.exe`, otherwise agents loop forever (update loop). `build-agent.ps1` writes the correct value to both files on every build.
- 💡 **Agent/Updater chạy ẩn hoàn toàn (v5.0.2+):** cả 2 EXE được build **windowed (`console=False`)** → Task Scheduler khởi động mà **không hiện cửa sổ console đen** nữa (người dùng không thể vô ý đóng khiến agent/updater tắt). `main.py` + `updater.py` tự redirect stdout/stderr khi chạy windowed. Khi build mới, `build-agent.ps1` sẽ báo `console=False (windowed - no console flash)`.
- 🛡️ **v5.0.4 (fix console sót trên máy cũ):** nếu một máy trạm vẫn chạy bản **GiamSatUpdater.exe cũ được build `console=True`**, cửa sổ console đen sẽ bật lại mỗi lần logon và người dùng hay vô tình tắt (giết chết updater). Từ **agent 4.6.7**, `main.py`/`updater.py` **chủ động gọi `GetConsoleWindow()+ShowWindow(SW_HIDE)` ngay khi khởi động** → dù EXE cũ loại console vẫn bị ẩn sau ~vài chục ms; bản build mới (`console=False`) thì không bao giờ có console. **Sau khi cập nhật agent lên 4.6.7 trên các máy vướng, kiểm tra lại Task Scheduler** (`GiamSatUpdater`, `GiamSatAgent`) để chắc task cũ không còn trỏ vào EXE cũ.

- 🔐 **v5.0.3 (2026-08):** NetFlow DoS hardening (rate-limit/exporter + template cache TTL + batch insert), 2FA rate-limit+lockout & audit username & re-enroll cần mã cũ + admin reset, nonce chống replay lệnh ký, che `ultraview_password` khỏi viewer, rate-limit dict GC + blacklist evict theo hạn, syslog UDP rate-limit, engine server đồng bộ agent (subtype/dst_port/field_equals/field_regex/FIELD_ALIASES), **PSK per-machine** (`GIAMSAT_PER_MACHINE_PSK[_FILE]`) + validate `machine_id` + sanitize hostname ở mọi ngưỡng — triệt tiêu nguồn gốc stored-XSS. Agent version bump → **4.6.6** (phải KHỚP với dist\GiamSatAgent.exe thật — lệch version = vòng lặp update vô hạn) (cần rebuild agent + push qua "Cập nhật Agent").
- 🗄️ **v5.0.4 (2026-08) — PostgreSQL chính thức:** khôi phục role/DB PG đúng (role `admin` SUPERUSER + DB `giamsat` owner admin), **tool migrate SQLite→PG** `tools/migrate_sqlite_to_pg.py` (36 bảng ~160k rows, verify 0 issues), PG parity (ON CONFLICT predicate, `network_baseline`, `status` filter, materialized views dashboard). Nếu PG không kết nối được server **fallback SQLite có banner đỏ** + `server_error.log` + `/api/health` báo `db_fallback` — không còn âm thầm. Fix lũ 429 (SSE loadStats debounce + rate limit 1800/min), fix TypeError click tab Email/Assets/Agentless, UI hunting campaigns/history + Alerting Channels panel (Telegram/Slack/Webhook) + danh sách 8 SOAR action. Xem `dashboard-guide.md` + `summary.md`.

---

## 🏗️ Kiến trúc

```
┌─────────────┐     TCP:6666      ┌──────────────┐
│   AGENT      │◄────────────────►│    SERVER     │
│  (Windows)   │   heartbeat +    │  (Python 3)   │
│  collector   │   events/config  │  Flask+SSE    │
└─────────────┘                   └──────┬───────┘
                                         │
                                  ┌──────┴───────┐
                                  │  PostgreSQL   │
                                  │  (or SQLite)  │
                                  └──────────────┘
```

- **Agent** (Windows EXE): Thu thập sự kiện, Sysmon, network traffic, FIM, SCA, heartbeat
- **Server**: Flask REST API + Web UI, SSE real-time, JWT auth
- **Database**: PostgreSQL (khuyến nghị) hoặc SQLite

---

## 📋 Yêu cầu hệ thống

| Thành phần | Yêu cầu |
|---|---|
| **Server OS** | Windows Server 2016+ / Windows 10/11 / Linux |
| **Python** | 3.11+ |
| **Database** | PostgreSQL 16 (khuyến nghị) hoặc SQLite |
| **Agent OS** | Windows 10/11, Windows Server 2016+ |
| **Npcap** | Tùy chọn — chỉ cho bắt gói tin chi tiết khi có lưu lượng nghi ngờ |

---

## 🚀 Cài đặt Server (Windows)

### Cách 1: Tự động (khuyến nghị)

```powershell
# Mở PowerShell với quyền Administrator
cd server\setup
powershell -ExecutionPolicy Bypass -File install_all.ps1
```

Script sẽ tự động:
1. Cài đặt Python 3.11 (nếu chưa có)
2. Nâng cấp pip
3. Cài đặt 13 Python packages (Flask, PostgreSQL, Waitress...)
4. (Tùy chọn) Cài đặt Npcap — dành cho máy trạm Agent bắt gói tin chi tiết
5. Cài đặt Git (cập nhật Sigma rules)

### Cách 2: Thủ công

```cmd
# Cài Python 3.11+ từ https://python.org
# Cài PostgreSQL 16 từ https://postgresql.org

cd server
pip install -r setup\requirements.txt

# Tạo role + database PostgreSQL (nếu dùng PG) — LỆNH ĐẦY ĐỦ (v5.0.4)
# Thiếu 1 trong 2 lệnh dưới → server âm thầm fallback SQLite (banner đỏ khi chạy)
psql -U postgres -c "CREATE ROLE admin LOGIN SUPERUSER PASSWORD 'Mat_khau_Admin_2026!';"
psql -U postgres -c "CREATE DATABASE giamsat OWNER admin;"
# Sau đó nhớ: PG >=15 mặc định SCRAM-SHA-256 (pg_hba.conf) — đừng đổi thành md5.
# Rồi đặt .env: GIAMSAT_DB_BACKEND=postgres, GIAMSAT_PG_USER=admin, GIAMSAT_PG_PASSWORD=<mật khẩu trên>.
```

### Cấu hình Server

```powershell
# Sinh file .env từ mẫu
cd server
copy .env.example .env
notepad .env

# Or use the interactive script (recommended) — asks for language (vi/en) first
powershell -ExecutionPolicy Bypass -File setup\setup_config.ps1
```

### Chạy Server

```cmd
cd server
python main.py
# Web UI: http://localhost:5000
# Tạo tài khoản admin: chạy setup\setup_config.ps1 — script sẽ hỏi tên đăng nhập
# + mật khẩu admin rồi ghi vào .env (GIAMSAT_ADMIN_USER / GIAMSAT_ADMIN_PASSWORD).
# Nếu không cấu hình: server tự tạo admin với MẬT KHẨU NGẪU NHIÊN
# được in ra console/log (logs/giamsat.log) một lần duy nhất.
# (Đổi mật khẩu ngay sau lần đăng nhập đầu tiên)
```

---

## 🖥️ Build Agent (Windows)

Agent được build thành file `.exe` bằng PyInstaller, chạy trên máy trạm để giám sát.

### Yêu cầu build

- Python 3.11+
- PyInstaller: `pip install pyinstaller`
- **Code Agent** nằm trong thư mục `agent/`

### Build
```PS
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
.\build-agent.ps1
```

```cmd
REM Build Windows Agent + Updater
build-agent.cmd 4.5.4
REM Output: dist\GiamSatAgent.exe, dist\GiamSatUpdater.exe
```

### Cài đặt Agent lên máy trạm

```cmd
REM Sao chép Agent.exe đến máy trạm
REM Chạy với tham số server IP
GiamSatAgent.exe --server 192.168.1.10 --port 6666
```

### Cấu hình thông tin người dùng (dropdown "Chi nhánh" / tuỳ chỉnh)

Trước khi build Agent, dialog nhập thông tin người dùng có các **dropdown tuỳ chỉnh** (VD "Chi nhánh"). Quản trị viên có thể **thêm/bớt/sửa tên dropdown và danh sách lựa chọn**, bằng cách sửa file:

```
\Agent\user_fields.json
```

Mỗi dropdown có cấu trúc:

```json
{
  "key": "branch",
  "label": "Chi nhánh",
  "options": ["Trụ sở chính", "Chi nhánh 1", "Chi nhánh 2"]
}
```

- `key`    : mã định danh (dùng để lưu + gửi lên server). Key **`branch`** sẽ được lưu vào trường **"Văn phòng/chi nhánh"** của tài sản **Người dùng** trên server.
- `label`  : nhãn hiển thị trên dialog.
- `options`: danh sách lựa chọn (array chuỗi).

Muốn thêm dropdown mới (VD "Phòng ban"), chỉ cần thêm một đối tượng vào mảng `fields`. Lưu ý: lưu file mã **UTF-8**, tránh dùng dấu nháy đơn `'` trong label/options.

---

## 🔧 Cấu hình chi tiết (.env)

| Key | Mô tả | Bắt buộc |
|---|---|---|
| `GIAMSAT_DB_BACKEND` | `sqlite` hoặc `postgres` | Có |
| `GIAMSAT_PG_*` | PostgreSQL connection | Chỉ khi dùng PG |
| `DEEPSEEK_API_KEY` | AI Assistant & Auto-Monitor | Không (optional) |
| `TELEGRAM_BOT_TOKEN` | Bot token Telegram | Không (optional) |
| `TELEGRAM_CHAT_ID` | Chat ID nhận cảnh báo | Không (optional) |
| `GIAMSAT_SMTP_*` | SMTP email alerts | Không (optional) |
| `GIAMSAT_ENROLLMENT_SECRET` | Token xác thực Agent | Có (có mặc định) |
| `GIAMSAT_AGENT_PSK` | Pre-shared key xác thực Agent qua TCP | Có (khuyến nghị) |
| `GIAMSAT_COMMAND_KEY` | Khóa ký lệnh gửi tới Agent (HMAC-SHA256) | Có (khuyến nghị) |
| `GIAMSAT_PER_MACHINE_PSK` | JSON `{"machine_id":"secret"}` — PSK riêng từng máy (thắng global) | Không (optional) |
| `GIAMSAT_PER_MACHINE_PSK_FILE` | Đường dẫn file JSON chứa map PSK per-machine | Không (optional) |
| `GIAMSAT_SECRET_KEY` | Khóa ký phiên Flask/JWT | Có (tự sinh nếu trống) |
| `GIAMSAT_NET_ALERT_INTERVAL` | Chu kỳ quét NetFlow hành vi (s) — mặc định 60 | Không |
| `GIAMSAT_NET_ALERT_WINDOW` | Cửa sổ quét beacon/first-seen (s) — mặc định 1800 | Không |
| `GIAMSAT_NET_BEACON_MIN_FLOWS` | Số flow tối thiểu để gọi là beacon — mặc định 5 | Không |
| `GIAMSAT_NET_BEACON_MAX_CV` | Jitter tối đa coi là beacon (0.0–1.0) — mặc định 0.35 | Không |
| `GIAMSAT_NET_BEACON_MIN_SPAN` | Span tối thiểu (s) tính beacon — mặc định 300 | Không |
| `GIAMSAT_NET_FIRST_SEEN_DAYS` | Số ngày "chưa từng thấy" cho NET-FIRST — mặc định 14 | Không |
| `GIAMSAT_SYSLOG_TCP_PORT` | Syslog TCP (RFC6587/newline) — mặc định 6514; đặt `0` để tắt | Không |
| `GIAMSAT_SYSLOG_TLS_CERT` / `..._KEY` | Bật TLS cho syslog TCP (phải set đủ 2 biến) | Không |
| `GIAMSAT_WEB_TLS_ENABLED` | HTTPS ngay trên cổng web 5000 (self-signed; agent cần `server_tls=true`) | Không |
| `GIAMSAT_INTEL_FILE` | File IOC local (ips/domains) — Watchlist > "Push vào intel file" ghi file này | Không |
| `GIAMSAT_OTX_API_KEY` | AlienVault OTX enrichment (threat intel) | Không |
| `GIAMSAT_AGENT_PACKET_CAPTURE` | **Agent:** `1` = bật DPI scapy (TLS SNI + JA3) — cần Npcap + admin | Không |
| `GIAMSAT_COLLECT_EXTRA_IDS` | **Agent:** bật thêm EID ồn, VD `"4656,4658,4660,5156,5158"` | Không |

> **Lưu ý:** Danh sách đầy đủ (kèm comment tiếng Việt) nằm trong **`server\.env.example`** — chép thành `.env` rồi chỉnh, hoặc chạy `setup\setup_config.ps1`. Script này **giữ nguyên mọi key phụ** đã có trong `.env`/example (không làm rơi cấu hình) và ghi **UTF-8 không BOM**. Có thể thêm API keys bất cứ lúc nào — chỉ cần sửa `.env` và restart server.

## 🔐 Bảo mật vận hành (TLS / bắt buộc cho production)

**1. Kênh TCP Agent ↔ Server (cổng 6666):**
- Đặt `GIAMSAT_TLS_ENABLED=true` trong `.env` để bật mTLS (tự sinh self-signed CA).
- ⚠️ Từ v4.11: nếu bật mà không dựng được TLS, server **từ chối khởi động** (fail-closed) — không bao giờ âm thầm quay về plaintext.

**2. Web/API (cổng 5000):**
- **Tùy chọn A — HTTPS tích hợp sẵn (v4.13):** đặt `GIAMSAT_WEB_TLS_ENABLED=true` trong `.env` để server tự phục vụ HTTPS trên cổng 5000 bằng self-signed CA (không cần reverse proxy). Browser sẽ hiện cảnh báo chứng chỉ (self-signed) — cài `server\certs\ca.crt` vào trusted store để hết cảnh báo. Khi bật, agent cần đặt `"web_tls": true` trong `agent_config.json` (hoặc env `GIAMSAT_SERVER_TLS=true`) để gọi HTTPS bằng kênh này (verify theo CA).
- **Tùy chọn B — reverse proxy (nginx/Caddy):** agent PSK, heartbeat và lệnh điều khiển đi qua cổng 5000 — nếu không bật A thì **bắt buộc** đặt sau TLS reverse proxy khi triển khai thật:
```nginx
# nginx stream (file có sẵn: server/nginx_tcp_stream.conf)
stream {
    server {
        listen 5000 ssl;
        ssl_certificate     /etc/nginx/certs/giamsat.crt;
        ssl_certificate_key /etc/nginx/certs/giamsat.key;
        proxy_pass 127.0.0.1:5000;   # waitress (http) ở phía sau
    }
}
```
Hoặc dùng Caddy: `https://giamsat.example.com { reverse_proxy 127.0.0.1:5000 }`.

**3. `GIAMSAT_COMMAND_KEY` là BẮT BUỘC cho auto-update agent** (từ v4.11):
- Server **từ chối** phục vụ file update nếu chưa cấu hình key này.
- Agent **từ chối** file update nếu thiếu chữ ký `X-File-Sig` hoặc thiếu `command_key` — kẻ đứng giữa mạng không thể thay EXE (HMAC-SHA256, fail-closed).
- Agent phải có `command_key` giống server (cấp lúc enroll / trong config agent).

**4. Đồng bộ thời gian (NTP/UTC) — v4.13 (P1.4):**
- Mọi host (server + agent + thiết bị mạng) phải đồng bộ **NTP** và lưu log theo **UTC** để correlation window (so sánh thời gian giữa các máy) có ý nghĩa.
- Windows Server/client: bật service `W32Time`:
  ```powershell
  w32tm /config /syncfromflags:manual /manualpeerlist:"time.windows.com,0x8 pool.ntp.org,0x8"
  w32tm /config /update
  Restart-Service w32time
  ```
- Router/switch/firewall (DrayTek, TP-Link...): cấu hình NTP client trỏ về cùng nguồn thời gian.

**5. Lưu trữ phân tầng & mở rộng (v4.13 P2):**
- **Hot** (SQLite/PG) 30 ngày → **Warm** 90 ngày → **Cold** 12 tháng (archive file/parquet). Hàm `apply_retention_policy` (server_core.py) đã có — chỉ cần cấu hình số ngày phù hợp.
- Chuyển sang **PostgreSQL** khi EPS > ~1.000 (backend `db_postgres.py` đã có sẵn; đặt `GIAMSAT_DB_BACKEND=postgres`).
- **NetFlow (v4.13 — đã có):** collector UDP 2055 (v5+v9), tab NetFlow trên dashboard (stats v5/v9, cảnh báo C2 beaconing, bảng flows). Sửa sFlow (UDP 6343) là mục tiêu nếu switch chỉ export sFlow. Cần bật flow export trên switch edge trước.

---

## 📸 Tính năng chính

| Tính năng | Mô tả |
|---|---|
| **Dashboard** | Tổng quan: máy trạm online/offline, events, threats, vulns |
| **MITRE ATT&CK** | Ma trận kỹ thuật tấn công, lọc theo thời gian |
| **Events** | Windows Event Logs, Sysmon, chi tiết process/network |
| **Network Traffic** | Giám sát kết nối TCP/UDP (netstat); bắt gói tin chi tiết là tùy chọn (cần Npcap) |
| **FIM** | Giám sát thay đổi file (File Integrity Monitoring) |
| **SCA** | Đánh giá cấu hình bảo mật (Security Configuration Assessment) |
| **Vulnerabilities** | Quét CVE từ installed software |
| **Threat Alerts** | Cảnh báo dựa trên correlation rules — kèm **phân loại (triage)** mỗi dòng (Mới / Đang xử lý / Đã xử lý / Báo động giả) |
| **Threat Hunting** | Săn tìm chủ động theo giả thuyết + tactic MITRE ATT&CK, template chips, **lịch sử chiến dịch + thống kê** (v5.0.4) |
| **Network Behavior Alerts** | **NET-BEACON / NET-FIRST / NET-ODD** (v5.0.4): phát hiện C2 theo **hành vi** từ NetFlow (chu kỳ đều đặn, first-seen, giờ lạ) — không cần IP reputation (VPS cloud vẫn bị bắt vì *pattern*, không phải vì IP) |
| **Alerting Channels** | Email (SMTP + mẫu), **Telegram / Slack / Webhook** — panel cấu hình kênh cảnh báo (severity/cooldown/retry, v5.0.4) |
| **Response (SOAR)** | 8 hành động phản hồi (kill process, chặn firewall/IP, khóa tài khoản, cách ly file/mạng, forensic snapshot...) + danh sách action khả dụng (v5.0.4) |
| **Tài sản** | Quản lý tài sản IT: máy tính, màn hình, **máy in**, **điện thoại IP**, **thiết bị mạng**, **tồn kho (chuột/bàn phím/linh kiện/điện thoại)**. **Tự phát hiện** qua SNMP/port fingerprint (máy in, điện thoại Yealink, router/switch/AP) + **nhập tay theo kho**; phát hiện thay đổi phần cứng; **xuất Excel đa sheet**.
| **Messages** | Chat trực tiếp với agent; máy trạm chủ động nhắn tin (IT support) |
| **Agent Update** | Auto-update agent qua server |

---

## 📁 Cấu trúc thư mục

```
giamsat/
├── README.md
├── LICENSE
├── .gitignore
├── build-agent.cmd          # Build script cho Windows Agent
├── build-agent.ps1
├── server/                   # Server code
│   ├── main.py               # Entry point
│   ├── tcp_server.py         # TCP server cho Agent kết nối
│   ├── db_postgres.py        # PostgreSQL adapter
│   ├── db_manager.py         # SQLite adapter
│   ├── auth_manager.py       # JWT Authentication
│   ├── api/                  # REST API endpoints
│   ├── static/               # CSS, JS
│   ├── templates/            # HTML templates
│   ├── rules/                # Correlation rules (YAML)
│   ├── setup/                # Installer scripts
│   │   ├── install_all.ps1
│   │   ├── setup_config.ps1
│   │   └── requirements.txt
│   └── .env.example
├── agent/                    # Agent source code
├── tests/                    # Unit tests
└── tools/                    # Utility scripts
```

---

## 🤝 Đóng góp

Mọi đóng góp đều được hoan nghênh! Vui lòng:

1. Fork repository
2. Tạo feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Mở Pull Request

---

## 📄 License

MIT License — xem file [LICENSE](LICENSE)

---

## 🌐 Ngôn ngữ

Giao diện song ngữ **tiếng Việt / tiếng Anh** — chuyển đổi qua dropdown ở thanh điều hướng.
