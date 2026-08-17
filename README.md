# GIAM-SAT v4.5.4 — Hệ thống Giám sát An ninh Mạng Nội bộ

> **GIAM-SAT** (GIAM SÁT) là hệ thống giám sát an ninh mạng mã nguồn mở, kiến trúc **Agent-Server**, hỗ trợ giám sát Windows/Linux endpoint, phân tích threat theo MITRE ATT&CK, quản lý tài sản CNTT, và cảnh báo thời gian thực qua Telegram/Email.

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

# Tạo database PostgreSQL (nếu dùng PG)
psql -U postgres -c "CREATE DATABASE giamsat"
```

### Cấu hình Server

```powershell
# Sinh file .env từ mẫu
cd server
copy .env.example .env
notepad .env

# Hoặc dùng script tương tác (khuyên dùng)
powershell -ExecutionPolicy Bypass -File setup\setup_config.ps1
```

### Chạy Server

```cmd
cd server
python main.py
# Web UI: http://localhost:5000
# Login mặc định: admin / admin
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
| `GIAMSAT_SECRET_KEY` | Khóa ký phiên Flask/JWT | Có (tự sinh nếu trống) |

> **Lưu ý:** Có thể thêm API keys bất cứ lúc nào — chỉ cần sửa `.env` và restart server.

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
| **Threat Alerts** | Cảnh báo dựa trên correlation rules |
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
