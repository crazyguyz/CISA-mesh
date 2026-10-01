"""
TEST AGENT - smoke test cho PyInstaller (build thu EXE con chay duoc khong).
v5.0.8: them argparse de `--help` chi in usage (truoc day go --help la bat luon
MessageBox). Mac dinh van hien MessageBox nhu cu; dung --silent de chi ghi log.

Dung:
    python tools/test_agent.py            # ghi log + hien MessageBox
    python tools/test_agent.py --silent   # chi ghi log (may khong co man hinh)
"""
import argparse
import ctypes
import os
import sys

ap = argparse.ArgumentParser(description="GIAM-SAT build smoke test (log + MessageBox).")
ap.add_argument("--silent", action="store_true", help="khong hien MessageBox, chi ghi log")
args = ap.parse_args()

# ===== DONG 1: GHI LOG + MESSAGEBOX =====
appdata = os.environ.get("APPDATA", os.path.expanduser("~"))
LOG_DIR = os.path.join(appdata, "GIAM-SAT", "Agent", "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_PATH = os.path.join(LOG_DIR, "test_startup.log")

def log(msg):
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(f"{msg}\n")
    except Exception:
        pass

log("=== TEST AGENT STARTED ===")
log(f"Python: {sys.version}")
log(f"Frozen: {getattr(sys, 'frozen', False)}")
log(f"Executable: {sys.executable}")
log(f"argv: {sys.argv}")
log(f"PID: {os.getpid()}")
log(f"APPDATA: {appdata}")
log(f"Log: {LOG_PATH}")

if args.silent:
    log("silent mode - MessageBox skipped")
else:
    try:
        ctypes.windll.user32.MessageBoxW(0,
            "TEST AGENT CHAY THANH CONG!\n\n"
            f"Log: {LOG_PATH}\n"
            f"PID: {os.getpid()}\n"
            f"Frozen: {getattr(sys, 'frozen', False)}",
            "GIAM-SAT TEST OK", 0x40)
        log("MessageBox OK")
    except Exception as e:
        log(f"MessageBox FAILED: {e}")

log("=== TEST AGENT COMPLETED ===")