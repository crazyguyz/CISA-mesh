"""
TEST SCRIPT - Verify PyInstaller works
This is THE simplest possible agent to check if EXE even runs.
"""
import os
import sys
import ctypes

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