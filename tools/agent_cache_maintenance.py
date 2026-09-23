#!/usr/bin/env python
"""Bao tri cache offline cua agent GIAM-SAT (giamsat_cache.db).

Vi sao can: khi agent khong gui duoc su kien (server tat / qua tai) no luu vao
%PROGRAMDATA%\\GIAM-SAT\\Agent\\giamsat_cache.db. Truoc v5.0.8 file nay KHONG co
gioi han, nen tren may bi nhieu LOG_RESET (bug v5.0.8) no da phinh toi ~13GB /
13,2 trieu dong => ton o dia va lam agent cham. Tool nay xem kich thuoc / so dong
roi cat bot hoac xoa sach + VACUUM de lay lai dung luong.

Luon bao cao truoc; chi ghi khi co --apply.

Usage:
  python tools/agent_cache_maintenance.py                        # chi bao cao
  python tools/agent_cache_maintenance.py --trim 100000 --apply   # giu 100k dong moi nhat
  python tools/agent_cache_maintenance.py --purge --apply --vacuum
  python tools/agent_cache_maintenance.py --db D:/khac/giamsat_cache.db
Luu y: NEN DUNG agent truoc khi sua (file dang mo -> co the bao 'database is locked').
"""

import argparse
import os
import shutil
import sqlite3
import sys

BATCH = 50000   # rows deleted per transaction (bounded WAL)


def default_db_path():
    if os.name == "nt":
        base = os.environ.get("PROGRAMDATA", "C:\\ProgramData")
        return os.path.join(base, "GIAM-SAT", "Agent", "giamsat_cache.db")
    return os.path.join(os.path.expanduser("~"), ".giamsat", "agent", "giamsat_cache.db")


def human(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return "%.2f %s" % (n, unit)
        n /= 1024.0


def report(conn, db_path):
    size = os.path.getsize(db_path) if os.path.exists(db_path) else 0
    print("DB file      : %s" % db_path)
    print("Size on disk : %s (%d bytes)" % (human(size), size))
    page_size = conn.execute("PRAGMA page_size").fetchone()[0]
    page_count = conn.execute("PRAGMA page_count").fetchone()[0]
    freelist = conn.execute("PRAGMA freelist_count").fetchone()[0]
    print("SQLite pages : %d x %d = %s (freelist %d pages = %s)"
          % (page_count, page_size, human(page_size * page_count), freelist,
             human(freelist * page_size)))
    try:
        min_id = conn.execute("SELECT MIN(id) FROM log_cache").fetchone()[0]
        max_id = conn.execute("SELECT MAX(id) FROM log_cache").fetchone()[0]
    except sqlite3.Error:
        print("log_cache    : (chua co bang - agent chua chay lan nao)")
        return 0
    rows = conn.execute("SELECT COUNT(*) FROM (SELECT 1 FROM log_cache LIMIT ?)",
                        (200001,)).fetchone()[0]
    approx = "at least " if rows > 200000 else ""
    print("log_cache    : %s%d row(s)  (id %s..%s)" % (approx, rows, min_id, max_id))
    if size:
        print("Avg per row  : %s" % human(size / max(rows, 1)))
    return rows


def delete_chunked(conn, where_sql, params):
    """DELETE in bounded chunks; returns total rows removed."""
    total = 0
    while True:
        cur = conn.execute(
            "DELETE FROM log_cache WHERE id IN "
            "(SELECT id FROM log_cache WHERE %s LIMIT ?)" % where_sql,
            tuple(params) + (BATCH,)
        )
        n = cur.rowcount or 0
        conn.commit()
        total += n
        if n:
            print("   removed %d row(s) (total %d)" % (n, total))
        if n < BATCH:
            break
    return total


def main():
    ap = argparse.ArgumentParser(description="Bao tri cache offline cua agent GIAM-SAT")
    ap.add_argument("--db", default=None,
                    help="duong dan giamsat_cache.db (mac dinh: %%PROGRAMDATA%%\\GIAM-SAT\\Agent)")
    ap.add_argument("--trim", type=int, metavar="N", help="giu N dong MOI NHAT, xoa phan cu hon")
    ap.add_argument("--purge", action="store_true", help="xoa TOAN BO dong cache")
    ap.add_argument("--vacuum", action="store_true",
                    help="VACUUM de thu hoi dung luong sau khi xoa")
    ap.add_argument("--apply", action="store_true", help="thuc su ghi (mac dinh chi bao cao)")
    args = ap.parse_args()

    db_path = args.db or default_db_path()
    if not os.path.exists(db_path):
        sys.exit("Khong tim thay DB: %s" % db_path)
    if args.trim is not None and args.trim < 0:
        sys.exit("--trim phai >= 0")

    print("=" * 68)
    print("  GIAM-SAT agent cache maintenance")
    print("=" * 68)
    print("Mode: %s" % ("APPLY (se XOA du lieu)" if args.apply else "DRY-RUN (chi bao cao)"))

    try:
        conn = sqlite3.connect(db_path, timeout=15)
    except sqlite3.Error as exc:
        sys.exit("Khong mo duoc DB: %s" % exc)

    try:
        report(conn, db_path)

        if args.trim is None and not args.purge:
            print("\nKhong co --trim/--purge => chi bao cao, khong sua gi.")
            if args.vacuum:
                print("(--vacuum can --apply de chay)")
            return 0

        if not args.apply:
            if args.purge:
                print("\n[DRY-RUN] se XOA TOAN BO dong log_cache")
            else:
                max_id = conn.execute("SELECT COALESCE(MAX(id),0) FROM log_cache").fetchone()[0]
                print("\n[DRY-RUN] se giu %d dong moi nhat (xoa id <= %d)"
                      % (args.trim, max(0, max_id - args.trim)))
            print("[DRY-RUN] them --apply de thuc hien.")
            return 0

        print("")
        try:
            if args.purge:
                print("[*] Xoa toan bo cache...")
                removed = delete_chunked(conn, "1=1", [])
            else:
                max_id = conn.execute("SELECT COALESCE(MAX(id),0) FROM log_cache").fetchone()[0]
                cutoff = max(0, max_id - args.trim)
                print("[*] Giu %d dong moi nhat (xoa id <= %d)..." % (args.trim, cutoff))
                removed = delete_chunked(conn, "id <= ?", [cutoff])
            print("[+] Da xoa %d dong." % removed)
        except sqlite3.OperationalError as exc:
            print("[-] Loi ghi DB: %s" % exc)
            print("    -> Hay DUNG agent (task GiamSatUpdater/GiamSatAgent) roi chay lai.")
            return 2

        if args.vacuum:
            free = shutil.disk_usage(os.path.dirname(db_path)).free
            need = os.path.getsize(db_path)
            print("\n[*] VACUUM (can ~%s trong, con trong %s)..." % (human(need), human(free)))
            if free < need * 1.1:
                print("[-] Khong du dung luong trong de VACUUM - bo qua (chay lai sau khi don o dia).")
                return 2
            try:
                conn.isolation_level = None
                conn.execute("VACUUM")
                conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            except sqlite3.OperationalError as exc:
                print("[-] VACUUM that bai: %s (thu lai khi agent da dung)" % exc)
                return 2
            print("[+] VACUUM xong: %s" % human(os.path.getsize(db_path)))

        print("\n--- After ---")
        report(conn, db_path)
        return 0
    finally:
        try:
            conn.close()
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())

