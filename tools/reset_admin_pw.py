"""
Reset admin password trong users.json (Fernet encrypted)
Dung: python reset_admin_pw.py
"""
import os
import sys
import hashlib
import secrets
import json

# Fernet
try:
    from cryptography.fernet import Fernet
    HAS_FERNET = True
except ImportError:
    HAS_FERNET = False
    print("[-] Thieu cryptography. Dang cai dat...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "cryptography", "-q"])
    from cryptography.fernet import Fernet
    HAS_FERNET = True

PBKDF2_ITERATIONS = 100000
PBKDF2_HASH_NAME = "sha256"
PBKDF2_SALT_BYTES = 32

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
USERS_PATH = os.path.join(BASE_DIR, "users.json")
KEY_PATH = os.path.join(BASE_DIR, ".user_key")

def hash_password(password: str) -> tuple:
    salt = secrets.token_bytes(PBKDF2_SALT_BYTES)
    pw_hash = hashlib.pbkdf2_hmac(PBKDF2_HASH_NAME, password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return pw_hash.hex(), salt.hex()

def main():
    # 1. Doc key
    if not os.path.exists(KEY_PATH):
        print(f"[-] KHONG TIM THAY .user_key tai {KEY_PATH}")
        sys.exit(1)
    with open(KEY_PATH, "rb") as f:
        key = f.read()
    print(f"[*] KEY: {key.decode()}")
    
    fernet = Fernet(key)
    
    # 2. Doc + giai ma users.json
    if not os.path.exists(USERS_PATH):
        print(f"[-] KHONG TIM THAY users.json tai {USERS_PATH}")
        sys.exit(1)
    
    with open(USERS_PATH, "rb") as f:
        encrypted = f.read()
    print(f"[*] Da doc {len(encrypted)} bytes encrypted")
    
    try:
        json_data = fernet.decrypt(encrypted).decode("utf-8")
    except Exception as e:
        print(f"[-] Giai ma that bai: {e}")
        sys.exit(1)
    
    users = json.loads(json_data)
    print(f"[*] Users hien tai: {list(users.keys())}")
    
    # 3. Reset admin password
    new_pw = "admin"
    pw_hash, salt = hash_password(new_pw)
    
    users["admin"] = {
        "username": "admin",
        "password": pw_hash,
        "salt": salt,
        "role": "admin",
        "must_change_password": True
    }
    print(f"[*] Da reset admin password -> '{new_pw}' (must_change_password=True)")
    print(f"    Hash: {pw_hash[:32]}...")
    print(f"    Salt: {salt[:32]}...")
    
    # 4. Ma hoa + ghi lai
    new_json = json.dumps(users, indent=2, ensure_ascii=False)
    encrypted_new = fernet.encrypt(new_json.encode("utf-8"))
    
    # Backup
    backup_path = USERS_PATH + ".bak"
    with open(backup_path, "wb") as f:
        f.write(encrypted)
    print(f"[*] Backup cu -> {backup_path}")
    
    with open(USERS_PATH, "wb") as f:
        f.write(encrypted_new)
    print(f"[+] DA GHI users.json MOI ({len(encrypted_new)} bytes encrypted)")
    print()
    print("=" * 60)
    print("  HOAN TAT! Hay restart server va dang nhap:")
    print("  Username: admin")
    print("  Password: admin")
    print("  (Se bat buoc doi mat khau sau khi dang nhap)")
    print("=" * 60)

if __name__ == "__main__":
    main()