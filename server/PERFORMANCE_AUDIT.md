# GIAM-SAT v3.5.8 - Kiểm Tra Chịu Tải & Đề Xuất Cải Tiến

**Ngày:** 2026-07-24 | **Phiên bản:** v3.5.8

> **📌 Trạng thái triển khai — cập nhật 2026-08 (v5.0.4):**
> - ✅ **P1 — Batch INSERT 1 transaction:** `batch_insert_events()` / `batch_insert_sysmon_events()` / `batch_insert_network_traffic()` (db_manager.py) đã có.
> - ✅ **P4 — Worker count:** mặc định **8 workers** (`GIAMSAT_EVENT_WORKERS`, server_core.py:232) — có thể tăng thêm qua `.env`.
> - ✅ **PostgreSQL production:** `db_postgres.py` + pool (10-50) + **materialized views dashboard** (api_cache.py — detect staleness, drop-stale + recreate với index đúng) + migrate 36 bảng ~160k rows (`tools/migrate_sqlite_to_pg.py`). DB backend có thể chuyển đổi lúc chạy; fallback SQLite có banner đỏ + `/api/health`.
> - ✅ **Rate limit Web/API:** mặc định **1800 req/min/IP** (`GIAMSAT_API_RATE_LIMIT`, v5.0.4) — sửa lũ 429 do SSE `loadStats` gọi liên tục (debounce 10s trong dashboard.js).
> - ⬜ **P2/P3 (đọc/write lock tách, adaptive poll):** chưa triển khai riêng — ít quan trọng khi đã chạy PG.
> - ⬜ **P5/P7 (Redis queue/pub-sub):** chưa bắt buộc — chỉ khi mở rộng >500 agents.

---

## 1. Tổng Quan Hiện Trạng

| Thành phần | Cấu hình hiện tại | Ghi chú |
|------------|-------------------|---------|
| Web Server | Waitress, threads=8 | Ổn cho API + Dashboard |
| TCP Server | 1 thread/connection | Đã có rate limiter (10 conn/min, 100 evt/s) |
| Event Queue | In-memory deque, max 100K | Redis sẵn sàng nhưng không bắt buộc |
| Event Workers | 4 threads, batch=100, poll=0.5s | SQLite fallback: INSERT từng dòng |
| Database | SQLite WAL, 1 connection + 1 lock | 32MB cache, 256MB mmap, 20+ indexes |
| SSE Queue | In-memory list, max 1000 | Cắt còn 500 khi đầy |

---

## 2. Bottleneck Phân Tích

### 🔴 CRITICAL: SQLite Single-Writer Bottleneck

```
Tất cả write request → self.lock (1 lock duy nhất)
  ├── 4 Event Workers (INSERT events/sysmon/network/fim/heartbeats...)
  ├── TCP heartbeat handler (UPDATE machines)
  ├── Web API requests (INSERT messages, audit_log...)
  ├── Heartbeat monitor (UPDATE machines SET is_online=0)
  └── Retention policy (DELETE old records)
```

**Tác động:** 1 writer tại một thời điểm. SQLite WAL giúp read không block write, nhưng write vẫn tuần tự. Với 4 workers × 100 events/batch = 400 events cần write mỗi 0.5s, lock contention rất cao.

**Đo lường ước tính:**
- Mỗi INSERT riêng lẻ + commit: ~5-15ms (tùy disk)
- 4 workers × 7 queues × batch=100: lên đến 2800 INSERT mỗi chu kỳ
- 2800 × 10ms = 28 giây cho 1 chu kỳ → workers block nhau

### 🟠 HIGH: INSERT Từng Dòng + Commit Từng Dòng

```python
# event_worker.py line 162-166 - SQLite fallback
for e in events:
    try:
        self.db.insert_event(e)  # Mỗi lần: acquire lock → INSERT → commit → release lock
    except Exception:
        pass
```

`insert_event()` (db_manager.py line 416-419):
```python
def insert_event(self, data):
    with self.lock:
        self.conn.execute("INSERT INTO events (...) VALUES (...)")
        self.conn.commit()  # <-- COMMIT RIÊNG MỖI DÒNG!
```

**Tác động:** 100 events = 100 transactions = 100 lần fsync (hoặc WAL checkpoint). Nên gộp thành 1 transaction.

### 🟠 HIGH: 1 Lock Cho 7 Queues

```python
# event_queue.py line 138
with self._mem_lock:  # 1 lock cho TẤT CẢ 7 queues
    q = self._mem_queues.get(queue_name)
    if q is not None:
        q.append(json_str)
```

**Tác động:** Khi 1 worker đang pop_batch từ queue events, TCP thread muốn push vào queue sysmon phải đợi. Tuy nhiên, thao tác với deque rất nhanh (<1μs) nên không nghiêm trọng bằng DB bottleneck.

### 🟡 MEDIUM: Poll Interval 0.5s

Khi queue rỗng, worker ngủ 0.5s → event mới đến phải đợi tối đa 0.5s mới được xử lý. Có thể giảm xuống 0.1s hoặc dùng `select/epoll` pattern.

### 🟡 MEDIUM: Correlation + Anomaly Trên Từng Event

```python
# event_worker.py line 171-184
if self.correlation:
    for e in events:
        self.correlation.process_event(e)  # Có thể nặng với complex rules
for e in events:
    result = self.anomaly_detector.check(e)  # Anomaly check
```

Tốt hơn: nên chạy trong thread riêng hoặc batch processing.

### 🟡 MEDIUM: SSE Queue In-Memory

- Mất dữ liệu khi restart server
- Giới hạn 1000 items → dashboard có thể bỏ lỡ event khi cao tải
- Nên dùng Redis pub/sub cho SSE

---

## 3. Đề Xuất Cải Tiến (Ưu Tiên Từ Dễ Đến Khó)

### ✅ Priority 1: Batch INSERT với 1 Transaction (DỄ - Hiệu Quả Cao Nhất)

**File:** `db_manager.py` — Thêm method `batch_insert_events()`

```python
def batch_insert_events(self, events):
    """Batch insert events in 1 transaction."""
    if not events:
        return
    with self.lock:
        c = self.conn.cursor()
        c.execute("BEGIN IMMEDIATE")
        for e in events:
            c.execute(
                "INSERT INTO events (machine_id,hostname,type,subtype,event_id,"
                "event_type,source,computer,user,category,time,description,raw_data) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (e.get("machine_id",""), e.get("hostname",""), e.get("type",""),
                 e.get("subtype",""), str(e.get("event_id","")), e.get("event_type",""),
                 e.get("source",""), e.get("computer",""), e.get("user",""),
                 str(e.get("category","")), e.get("time",""), e.get("description",""),
                 e.get("raw_data",""))
            )
        self.conn.commit()
```

**Áp dụng tương tự cho:** `batch_insert_sysmon_events()`, `batch_insert_network_traffic()`, `batch_insert_fim_events()`

**Lợi ích:** Giảm 100 transactions → 1 transaction = nhanh hơn 50-100 lần

---

### ✅ Priority 2: Giảm Lock Contention - Tách Read/Write Lock

**File:** `db_manager.py`

```python
from threading import Lock, RLock

class DatabaseManager:
    def __init__(self):
        self.write_lock = threading.Lock()  # Cho INSERT/UPDATE/DELETE
        self.read_lock = threading.Lock()   # Cho SELECT
        self.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
```

- Read operations (SELECT) dùng `read_lock` → nhiều reader đồng thời
- Write operations (INSERT/UPDATE/DELETE) dùng `write_lock` → 1 writer
- WAL mode cho phép read + write đồng thời

---

### ✅ Priority 3: Giảm Poll Interval + Thêm Backpressure

**File:** `event_worker.py`

```python
# Hiện tại
poll_interval=0.5  # 500ms

# Cải tiến
poll_interval=0.05  # 50ms khi có event gần đây
poll_interval=0.5   # 500ms khi idle > 10s
```

Thêm adaptive poll interval: nếu có event trong 10 giây qua → poll nhanh; nếu không → poll chậm.

---

### ✅ Priority 4: Tăng Worker Count Cho High-Volume Queues

```python
# server_core.py
num_workers=int(os.environ.get("GIAMSAT_EVENT_WORKERS", "8"))  # Tăng từ 4 lên 8
```

Hoặc tách worker pool riêng cho high-volume queues:
- **4 workers** cho QUEUE_SYSMON + QUEUE_EVENTS + QUEUE_NETWORK
- **2 workers** cho QUEUE_THREATS + QUEUE_FIM + QUEUE_ALERTS + QUEUE_HEARTBEATS

---

### ✅ Priority 5: Redis Queue (Bắt Buộc Cho >50 Agents)

**File:** `.env`
```bash
GIAMSAT_REDIS_HOST=127.0.0.1
GIAMSAT_REDIS_PORT=6379
GIAMSAT_QUEUE_BACKEND=redis
```

**Lợi ích:**
- Queue không mất khi restart server
- Redis RPUSH/LPOP atomic, không cần lock Python
- Có thể scale nhiều server instance cùng đọc 1 Redis queue
- Persistent với RDB/AOF

---

### ✅ Priority 6: Move Correlation + Anomaly Sang Worker Riêng

```python
# Tách riêng 1-2 worker threads chỉ cho correlation + anomaly
class CorrelationWorker(threading.Thread):
    def run(self):
        while self.running:
            events = self.queue.pop_batch(QUEUE_EVENTS, batch_size=50, timeout=1)
            for e in events:
                self.correlation.process_event(e)
                self.anomaly_detector.check(e)
```

DB workers chỉ làm nhiệm vụ INSERT, correlation/anomaly chạy async.

---

### ✅ Priority 7: SSE Qua Redis Pub/Sub

```
TCP Event → Redis PUBLISH giamsat:sse → Flask SSE thread SUBSCRIBE → push to clients
```

Thay vì `self.sse_queue` list in-memory, dùng Redis pub/sub để:
- Không mất event khi restart
- Nhiều server instance share cùng SSE stream
- Không giới hạn 1000 items

---

## 4. Bảng Tổng Hợp

| Priority | Cải tiến | Độ khó | Tác động | File ảnh hưởng |
|----------|----------|--------|----------|-----------------|
| **P1** | Batch INSERT 1 transaction | Dễ | 🔥🔥🔥🔥🔥 | db_manager.py, event_worker.py |
| **P2** | Tách read/write lock | Dễ | 🔥🔥🔥 | db_manager.py |
| **P3** | Adaptive poll interval | Dễ | 🔥🔥 | event_worker.py |
| **P4** | Tăng worker count | Dễ | 🔥🔥 | server_core.py |
| **P5** | Redis queue (bắt buộc >50 agents) | Trung bình | 🔥🔥🔥🔥 | .env, event_queue.py |
| **P6** | Correlation worker riêng | Trung bình | 🔥🔥 | event_worker.py |
| **P7** | SSE qua Redis pub/sub | Khó | 🔥🔥 | server_core.py |

---

## 5. Ước Tính Hiệu Năng Sau Cải Tiến

| Chỉ số | Hiện tại | Sau P1-P4 | Sau P1-P7 |
|--------|----------|-----------|-----------|
| Events/s write | ~500-1000 | ~5,000-10,000 | ~50,000+ |
| Max agents (SQLite) | ~20-30 | ~50-100 | N/A (switch Postgres) |
| Max agents (Postgres) | ~200-500 | ~500-1000 | ~2000+ |
| Dashboard refresh | 1-3s (cache miss) | <500ms | <200ms |
| SSE latency | 0.5-1s | 50-200ms | <50ms |
| DB lock wait | 50-200ms | <10ms | <1ms |

---

## 6. Khuyến Nghị Triển Khai

### Giai đoạn 1: Ngay lập tức (không cần thay đổi hạ tầng)
- [ ] P1: Thêm `batch_insert_events()` + `batch_insert_sysmon_events()` + `batch_insert_network_traffic()`
- [ ] P2: Tách read/write lock trong db_manager.py
- [ ] P3: Adaptive poll interval trong event_worker.py
- [ ] P4: Tăng GIAMSAT_EVENT_WORKERS=8

### Giai đoạn 2: Khi >50 agents (cần Redis)
- [ ] P5: Cài Redis, enable queue backend
- [ ] P6: Tách correlation worker

### Giai đoạn 3: Khi >500 agents (cần PostgreSQL)
- [ ] P7: SSE Redis pub/sub
- [ ] Switch sang PostgreSQL + TimescaleDB
- [ ] Multi-instance ingest servers