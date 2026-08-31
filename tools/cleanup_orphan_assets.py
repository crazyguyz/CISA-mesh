#!/usr/bin/env python
"""One-time maintenance: purge rows left behind by machines that were deleted
before v5.0.4 (when delete_machine() did not clean the asset-registry tables),
so the Assets dashboard stops showing "Máy tính / Màn hình" of deleted hosts.

Supports SQLite and PostgreSQL. Always report first; use --apply to delete.

Usage:
  python tools/cleanup_orphan_assets.py                 # dry-run (default), PG via server/.env
  python tools/cleanup_orphan_assets.py --sqlite server/giamsat_data.db
  python tools/cleanup_orphan_assets.py --env D:/test/server/.env
  python tools/cleanup_orphan_assets.py --apply         # actually delete
"""

import argparse
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def parse_env(path):
    """Parse a .env file into a dict."""
    env = {}
    if not os.path.exists(path):
        return env
    for line in open(path, encoding="utf-8", errors="ignore"):
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        env[k.strip()] = v.strip().strip('"').strip("'")
    return env


class SQLiteBackend:
    PH = "?"
    PAGE = 1000

    def __init__(self, path):
        import sqlite3
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row

    def query(self, sql, params=None):
        return self.conn.execute(sql, params or ()).fetchall()

    def delete(self, sql, params=None):
        cur = self.conn.execute(sql, params or ())
        return cur.rowcount

    def commit(self):
        self.conn.commit()

    def close(self):
        self.conn.close()


class PostgresBackend:
    PH = "%s"
    PAGE = 1000

    def __init__(self, env):
        import psycopg2
        import psycopg2.extras
        self.psycopg2 = psycopg2
        self.conn = psycopg2.connect(
            host=env.get("GIAMSAT_PG_HOST", "127.0.0.1"),
            port=int(env.get("GIAMSAT_PG_PORT", "5432")),
            dbname=env.get("GIAMSAT_PG_DBNAME", "giamsat"),
            user=env.get("GIAMSAT_PG_USER", "postgres"),
            password=env.get("GIAMSAT_PG_PASSWORD", ""),
        )

    def query(self, sql, params=None):
        with self.conn.cursor(cursor_factory=self.psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, params or ())
            return cur.fetchall()

    def delete(self, sql, params=None):
        with self.conn.cursor() as cur:
            cur.execute(sql, params or ())
            return cur.rowcount

    def commit(self):
        self.conn.commit()

    def close(self):
        self.conn.close()


# (step, table, where, description) — run in this order; PH is the backend placeholder.
STEPS = [
    ("assets_computers",
     "machine_id IS NOT NULL AND machine_id != '' AND machine_id NOT IN "
     "(SELECT machine_id FROM machines)",
     "máy tính (cấu hình) của máy trạm đã bị xóa"),
    ("assets_relations",
     "computer_asset_id NOT IN (SELECT asset_id FROM assets_computers)",
     "liên kết máy tính <-> màn hình trỏ tới asset không còn tồn tại"),
    ("assets_monitors",
     "NOT EXISTS (SELECT 1 FROM assets_relations r WHERE r.monitor_asset_id = assets_monitors.asset_id)",
     "màn hình không còn thuộc máy tính nào"),
    ("assets_inventory",
     "computer_asset_id IS NOT NULL AND computer_asset_id != '' AND "
     "computer_asset_id NOT IN (SELECT asset_id FROM assets_computers)",
     "tồn kho (máy in USB auto...) gắn với máy tính đã xóa"),
    ("assets_change_log",
     "asset_id NOT IN (SELECT asset_id FROM assets_computers) AND "
     "asset_id NOT IN (SELECT asset_id FROM assets_monitors) AND "
     "asset_id NOT IN (SELECT asset_id FROM assets_inventory)",
     "nhật ký thay đổi phần cứng của asset đã xóa"),
    ("messages",
     "machine_id NOT IN (SELECT machine_id FROM machines)",
     "tin nhắn của máy trạm đã xóa"),
    ("policy_apply_status",
     "machine_id NOT IN (SELECT machine_id FROM machines)",
     "trạng thái áp chính sách của máy trạm đã xóa"),
    ("machine_users",
     "machine_id NOT IN (SELECT machine_id FROM machines)",
     "người dùng máy trạm đã xóa"),
    ("machine_uptime",
     "machine_id NOT IN (SELECT machine_id FROM machines)",
     "uptime máy trạm đã xóa"),
    ("agent_update_log",
     "machine_id NOT IN (SELECT machine_id FROM machines)",
     "log cập nhật agent của máy trạm đã xóa"),
    ("alert_suppression",
     "machine_id IS NOT NULL AND machine_id != '' AND "
     "machine_id NOT IN (SELECT machine_id FROM machines)",
     "luật tắt cảnh báo theo máy trạm đã xóa"),
    ("fim_baseline",
     "machine_id NOT IN (SELECT machine_id FROM machines)",
     "FIM baseline máy trạm đã xóa"),
    ("agent_group_members",
     "machine_id NOT IN (SELECT machine_id FROM machines)",
     "thành viên nhóm của máy trạm đã xóa"),
    ("sysmon_events",
     "machine_id NOT IN (SELECT machine_id FROM machines)",
     "sysmon events máy trạm đã xóa"),
    ("sca_events",
     "machine_id NOT IN (SELECT machine_id FROM machines)",
     "SCA events máy trạm đã xóa"),
]


def main():
    # Console trên Windows mặc định cp1252 — ép UTF-8 để in tiếng Việt.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description="Dọn dữ liệu orphan sau khi xóa máy trạm (v5.0.4)")
    ap.add_argument("--sqlite", help="đường dẫn file SQLite (mặc định dùng PG từ server/.env)")
    ap.add_argument("--env", default=os.path.join(ROOT, "server", ".env"), help="đường dẫn .env cho PG")
    ap.add_argument("--apply", action="store_true", help="thực sự xóa (mặc định chỉ báo cáo)")
    args = ap.parse_args()

    backend = None
    if args.sqlite:
        backend = SQLiteBackend(args.sqlite)
        conn_name = args.sqlite
    else:
        env = parse_env(args.env)
        if not env.get("GIAMSAT_PG_PASSWORD"):
            sys.exit(f"Không đọc được PG config từ {args.env}. Dùng --sqlite <db> hoặc --env <file>.")
        backend = PostgresBackend(env)
        conn_name = f"postgres://{env.get('GIAMSAT_PG_USER')}@{env.get('GIAMSAT_PG_HOST')}:{env.get('GIAMSAT_PG_PORT')}/{env.get('GIAMSAT_PG_DBNAME')}"

    print(f"Backend: {conn_name}")
    print(f"Mode: {'APPLY (sẽ XÓA)' if args.apply else 'DRY-RUN (chỉ báo cáo)'}")
    print("=" * 70)

    total = 0
    try:
        for table, cond, desc in STEPS:
            try:
                count = backend.query(f"SELECT COUNT(*) AS n FROM {table} WHERE {cond}")[0]["n"] or 0
            except Exception as e:
                print(f"SKIP  {table:20s} (không tồn tại?): {e}")
                continue
            if count:
                if args.apply:
                    backend.delete(f"DELETE FROM {table} WHERE {cond}")
                total += count
                print(f"{'DEL' if args.apply else 'ORPH'}{'':4s}{table:20s} {count:>6d}  {desc}")
        backend.commit()
        print("=" * 70)
        if args.apply:
            print(f"Đã xóa {total} dòng orphan. Giờ bấm Ctrl+F5 dashboard Tài sản để kiểm tra.")
        else:
            print(f"Phát hiện {total} dòng orphan. Chạy lại với --apply để xóa.")
    finally:
        backend.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
