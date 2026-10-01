"""
Reset admin password trong users.json (Fernet encrypted).

v5.0.8 (an toan): truoc day tool KHONG co argparse nen go
`python tools/reset_admin_pw.py` la reset NGAY, va ca `--help` cung reset luon
mat khau admin. Gio mac dinh la DRY-RUN: chi bao cao, KHONG ghi gi; phai truyen
--apply (hoac --yes) moi thuc su doi mat khau.

Dung:
    python tools/reset_admin_pw.py                              # dry-run
    python tools/reset_admin_pw.py --apply                      # admin / admin
    python tools/reset_admin_pw.py --user admin --password Abc@123 --apply
    python tools/reset_admin_pw.py --users-dir D:\\test --apply  # users.json o cho khac
"""
import argparse
import hashlib
import json
import os
import secrets
import sys

PBKDF2_ITERATIONS = 100000
PBKDF2_HASH_NAME = "sha256"
PBKDF2_SALT_BYTES = 32

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# auth_manager._get_key_dir(): GIAMSAT_DATA_DIR neu co, khong thi goc repo.
DEFAULT_DIR = os.environ.get("GIAMSAT_DATA_DIR") or BASE_DIR


def load_fernet(key_path, apply):
    """Tra ve Fernet, hoac None neu thieu cryptography (chi tu cai khi --apply)."""
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        if not apply:
            print("[-] Thieu thu vien cryptography - khong doc duoc users.json.")
            print("    Cai dat: pip install cryptography")
            return None
        print("[-] Thieu cryptography. Dang cai dat...")
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", "cryptography", "-q"])
        from cryptography.fernet import Fernet
    with open(key_path, "rb") as f:
        return Fernet(f.read())


def hash_password(password: str) -> tuple:
    salt = secrets.token_bytes(PBKDF2_SALT_BYTES)
    pw_hash = hashlib.pbkdf2_hmac(PBKDF2_HASH_NAME, password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return pw_hash.hex(), salt.hex()

def main():
    ap = argparse.ArgumentParser(
        description="Reset a GIAM-SAT dashboard password in users.json "
                    "(dry-run by default: nothing is written without --apply).")
    ap.add_argument("--user", default="admin", help="tai khoan can reset (mac dinh: admin)")
    ap.add_argument("--password", default="admin",
                    help="mat khau moi (mac dinh: admin, se bat buoc doi khi dang nhap)")
    ap.add_argument("--users-dir", default=DEFAULT_DIR,
                    help="thu muc chua users.json/.user_key (mac dinh: goc repo)")
    ap.add_argument("--apply", action="store_true", help="thuc su ghi users.json")
    ap.add_argument("--yes", action="store_true", help="alias cua --apply (cho script)")
    args = ap.parse_args()
    apply = args.apply or args.yes

    users_path = os.path.join(args.users_dir, "users.json")
    key_path = os.path.join(args.users_dir, ".user_key")
    mode = "APPLY" if apply else "DRY-RUN"

    print("=" * 62)
    print("  GIAM-SAT - reset dashboard password  [%s]" % mode)
    print("=" * 62)
    print("[*] users.json : %s" % users_path)
    print("[*] tai khoan  : %s" % args.user)

    if not os.path.exists(key_path):
        print("[-] KHONG TIM THAY .user_key tai %s" % key_path)
        sys.exit(1)
    if not os.path.exists(users_path):
        print("[-] KHONG TIM THAY users.json tai %s" % users_path)
        sys.exit(1)

    fernet = load_fernet(key_path, apply)
    if fernet is None:
        print("[i] Ke hoach: dat mat khau moi cho '%s' (can cryptography de doc users.json)" % args.user)
        sys.exit(0)

    with open(users_path, "rb") as f:
        encrypted = f.read()
    print("[*] Da doc %d bytes encrypted" % len(encrypted))

    try:
        users = json.loads(fernet.decrypt(encrypted).decode("utf-8"))
    except Exception as e:
        print("[-] Giai ma that bai: %s" % e)
        sys.exit(1)
    print("[*] Users hien tai: %s" % list(users.keys()))
    if args.user not in users:
        print("[!] '%s' chua ton tai - se duoc TAO MOI voi vai tro admin." % args.user)

    pw_hash, salt = hash_password(args.password)
    users[args.user] = {
        "username": args.user,
        "password": pw_hash,
        "salt": salt,
        "role": "admin",
        "must_change_password": True,
    }
    print("[*] Mat khau moi cho '%s' -> '%s' (must_change_password=True)" % (args.user, args.password))
    print("    Hash: %s..." % pw_hash[:32])

    if not apply:
        print("-" * 62)
        print("[i] DRY-RUN - chua ghi gi. Chay lai voi --apply de thuc hien:")
        print("    python tools/reset_admin_pw.py --user %s --password '%s' --apply"
              % (args.user, args.password))
        print("=" * 62)
        return

    new_json = json.dumps(users, indent=2, ensure_ascii=False)
    encrypted_new = fernet.encrypt(new_json.encode("utf-8"))

    backup_path = users_path + ".bak"
    with open(backup_path, "wb") as f:
        f.write(encrypted)
    print("[*] Backup cu -> %s" % backup_path)

    with open(users_path, "wb") as f:
        f.write(encrypted_new)
    print("[+] DA GHI users.json MOI (%d bytes encrypted)" % len(encrypted_new))
    print()
    print("=" * 62)
    print("  HOAN TAT! Hay restart server va dang nhap:")
    print("  Username: %s" % args.user)
    print("  Password: %s" % args.password)
    print("  (Se bat buoc doi mat khau sau khi dang nhap)")
    print("=" * 62)

if __name__ == "__main__":
    main()