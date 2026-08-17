import os, json
from datetime import datetime

p = os.environ['PROGRAMDATA']
d = os.path.join(p, 'GIAM-SAT', 'Agent')

for n in ['boot_tracker.json', 'agent_config.json']:
    f = os.path.join(d, n)
    print(f'=== {n} ===')
    if os.path.exists(f):
        with open(f, 'r') as fh:
            content = fh.read()
        print(content[:300])
    else:
        print('NOT FOUND')
    print()

# Simulate dialog decision logic
today = datetime.now().strftime('%Y-%m-%d')
bt_path = os.path.join(d, 'boot_tracker.json')
cfg_path = os.path.join(d, 'agent_config.json')
force_path = os.path.join(d, 'force_config.flag')

fc = os.path.exists(force_path)

if os.path.exists(bt_path):
    with open(bt_path, 'r') as f:
        bd = json.loads(f.read())
    fb = bd.get('date') != today
    print(f"boot_tracker date: {bd.get('date')}, today: {today}, first_boot: {fb}")
else:
    fb = True
    print("boot_tracker NOT FOUND, first_boot: True")

cfg = {}
if os.path.exists(cfg_path):
    with open(cfg_path, 'r') as f:
        cfg = json.loads(f.read())

un = cfg.get('user_name', '').strip()
should_show = fc or (fb and not un)

print(f'\nfc (force_flag): {fc}')
print(f'fb (first_boot): {fb}')
print(f'un (user_name): "{un}"')
print(f'SHOULD SHOW DIALOG: {should_show}')