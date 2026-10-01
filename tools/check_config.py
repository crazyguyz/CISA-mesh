"""
Kiem tra cau hinh agent tren may dang chay (boot_tracker / agent_config /
force_config.flag) va mo phong logic hien dialog thu thap ten nguoi dung.
v5.0.8: them argparse de `--help` an toan (truoc day go --help la chay luon phan
kiem tra va crash tren may khong co %PROGRAMDATA%).

Dung:
    python tools/check_config.py
    python tools/check_config.py --agent-dir "C:\\ProgramData\\GIAM-SAT\\Agent"
    python tools/check_config.py --json
"""
import argparse
import json
import os
from datetime import datetime

ap = argparse.ArgumentParser(description="In cau hinh + quyet dinh hien dialog cua agent.")
ap.add_argument("--agent-dir", default=os.path.join(os.environ.get("PROGRAMDATA", "."),
                                                    "GIAM-SAT", "Agent"),
                help="thu muc du lieu agent (mac dinh: %%PROGRAMDATA%%\\GIAM-SAT\\Agent)")
ap.add_argument("--json", action="store_true", help="in ket qua dang JSON")
args = ap.parse_args()

d = args.agent_dir

for n in ["boot_tracker.json", "agent_config.json"]:
    f = os.path.join(d, n)
    print(f"=== {n} ===")
    if os.path.exists(f):
        with open(f, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()
        print(content[:300])
    else:
        print("NOT FOUND")
    print()

# Simulate dialog decision logic
today = datetime.now().strftime("%Y-%m-%d")
bt_path = os.path.join(d, "boot_tracker.json")
cfg_path = os.path.join(d, "agent_config.json")
force_path = os.path.join(d, "force_config.flag")

fc = os.path.exists(force_path)

if os.path.exists(bt_path):
    with open(bt_path, "r", encoding="utf-8", errors="replace") as f:
        bd = json.loads(f.read())
    fb = bd.get("date") != today
    print(f"boot_tracker date: {bd.get('date')}, today: {today}, first_boot: {fb}")
else:
    fb = True
    print("boot_tracker NOT FOUND, first_boot: True")

cfg = {}
if os.path.exists(cfg_path):
    with open(cfg_path, "r", encoding="utf-8", errors="replace") as f:
        cfg = json.loads(f.read())

un = str(cfg.get("user_name", "")).strip()
should_show = fc or (fb and not un)

print(f"\nfc (force_flag): {fc}")
print(f"fb (first_boot): {fb}")
print(f'un (user_name): "{un}"')
print(f"SHOULD SHOW DIALOG: {should_show}")

if args.json:
    print(json.dumps({"agent_dir": d, "force_flag": fc, "first_boot": fb,
                      "user_name": un, "should_show_dialog": bool(should_show)},
                     ensure_ascii=False, indent=2))