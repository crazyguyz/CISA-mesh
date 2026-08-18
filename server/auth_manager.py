"""
Authentication Manager for GIAM-SAT Server v1.6.0
JWT-based authentication for API + Web UI with RBAC support.
v2.5.3: Fixed import bug, salted SHA256, encrypted users.json, no default admin on restart.
"""
import os
import hashlib
import secrets
import threading
import re
import json as _json
from datetime import datetime, timedelta

# v2.5.2 SECURITY: PBKDF2-HMAC-SHA256 (100k iterations) instead of plain SHA256
_PBKDF2_ITERATIONS = 100000
_PBKDF2_HASH_NAME = "sha256"
_PBKDF2_SALT_BYTES = 32

_HAS_JWT = False
try:
    import jwt as pyjwt
    _HAS_JWT = True
except ImportError:
    import base64
    import hmac

_HAS_FERNET = False
try:
    from cryptography.fernet import Fernet
    _HAS_FERNET = True
except ImportError:
    _HAS_FERNET = False

USER_ROLES = {"admin": ["api", "ui", "command", "delete", "settings"],
              "operator": ["api", "ui", "command"],
              "viewer": ["api", "ui"]}

# Default admin password hash (pre-computed for backward compat)
_DEFAULT_ADMIN_PW = hashlib.sha256("admin".encode()).hexdigest()

# Password policy: min 12 chars, at least 1 uppercase, 1 lowercase, 1 digit, 1 special char
PASSWORD_POLICY = {
    "min_length": 12,
    "require_uppercase": True,
    "require_lowercase": True,
    "require_digit": True,
    "require_special": True,
}

# Brute-force protection
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15

# v2.5.3: Default admin - will only be used if no users exist on first run
_first_run_admin_password = None


def _make_default_admin():
    """v4.10: Create first-run admin (only when no users exist yet).
    - If GIAMSAT_ADMIN_USER / GIAMSAT_ADMIN_PASSWORD are set (written by
      setup_config.ps1), use them — the administrator chose the password.
    - Otherwise fall back to a RANDOM password (printed once to console/log)
      so there is never a known default credential (fixes CRITICAL-6)."""
    global _first_run_admin_password
    salt = secrets.token_bytes(_PBKDF2_SALT_BYTES)
    env_user = os.environ.get("GIAMSAT_ADMIN_USER", "").strip()
    env_pw = os.environ.get("GIAMSAT_ADMIN_PASSWORD", "")
    if env_user and env_pw:
        username = env_user
        pw = env_pw
        must_change = False  # admin picked this password in setup_config.ps1
    else:
        username = "admin"
        pw = secrets.token_urlsafe(16)
        _first_run_admin_password = pw
        must_change = True
    pw_hash = hashlib.pbkdf2_hmac(_PBKDF2_HASH_NAME, pw.encode(), salt, _PBKDF2_ITERATIONS)
    return {
        "username": username,
        "password": pw_hash.hex(),
        "salt": salt.hex(),
        "role": "admin",
        "must_change_password": must_change
    }

def _jwt_fallback_encode(payload, secret):
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b'=').decode()
    payload_enc = base64.urlsafe_b64encode(_json.dumps(payload).encode()).rstrip(b'=').decode()
    sig = hmac.new(secret.encode(), f"{header}.{payload_enc}".encode(), hashlib.sha256).digest()
    sig_enc = base64.urlsafe_b64encode(sig).rstrip(b'=').decode()
    return f"{header}.{payload_enc}.{sig_enc}"

def _jwt_fallback_decode(token, secret):
    parts = token.split(".")
    if len(parts) != 3:
        return None
    header, payload_enc, sig = parts
    expected_sig = base64.urlsafe_b64encode(hmac.new(secret.encode(), f"{header}.{payload_enc}".encode(), hashlib.sha256).digest()).rstrip(b'=').decode()
    if not hmac.compare_digest(sig, expected_sig):
        return None
    payload_enc = payload_enc + "=" * (-len(payload_enc) % 4)  # v4.10 (LOW-15): correct padding
    payload = _json.loads(base64.urlsafe_b64decode(payload_enc))
    if payload.get("exp", 0) < datetime.utcnow().timestamp():
        return None
    return payload


class AuthManager:
    def __init__(self):
        # v4.5.4 FIX: honor GIAMSAT_SECRET_KEY so JWT tokens survive restarts and
        # multi-instance deployments share the same signing key (fallback random).
        self.secret = os.environ.get("GIAMSAT_SECRET_KEY", "") or secrets.token_hex(32)
        self.lock = threading.Lock()
        self.users = {}
        self.sessions = {}
        self.token_blacklist = {}
        self.brute_force = {}  # {username: {"attempts": N, "locked_until": datetime}}
        self._brute_lock = threading.Lock()

        # v2.5.3: File encryption key (persists across restarts)
        self._file_key = self._get_or_create_file_key()

        # Load users from encrypted file
        self._load_users()

        # v2.5.3: Only create default admin if no users exist at all
        if not self.users:
            default_admin = _make_default_admin()
            self.users[default_admin["username"]] = default_admin
            self._save_users()
            if _first_run_admin_password:
                print("[!] AUTH: No users found - created first-run admin (must change password).")
                print(f"[!] AUTH: FIRST-RUN ADMIN PASSWORD (keep it safe): {_first_run_admin_password}")
            else:
                print(f"[!] AUTH: No users found - created first-run admin "
                      f"'{default_admin['username']}' from setup_config.ps1 (.env).")
        else:
            # v2.5.3: Migrate old unsalted passwords to salted format
            self._migrate_passwords()

    def _hash_password(self, password, salt=None):
        """v2.5.2 SECURITY: Hash with PBKDF2-HMAC-SHA256 (100k iterations).
        Returns (hash_hex, salt_hex). Salt is 32 random bytes."""
        if salt is None:
            salt = secrets.token_bytes(_PBKDF2_SALT_BYTES)
        elif isinstance(salt, str):
            # If called with existing salt string, convert back to bytes
            try:
                salt = bytes.fromhex(salt)
            except Exception:
                salt = salt.encode("utf-8")[:32]
        pw_hash = hashlib.pbkdf2_hmac(
            _PBKDF2_HASH_NAME,
            password.encode("utf-8"),
            salt,
            _PBKDF2_ITERATIONS
        )
        return pw_hash.hex(), salt.hex()

    def _verify_password(self, password, stored_hash, salt=None):
        """v2.5.2: Verify password. Supports PBKDF2 (new), old salted SHA256, and legacy."""
        if salt:
            # PBKDF2 format: salt is 64+ char hex string (32 bytes)
            if len(salt) >= 32:
                try:
                    salt_bytes = bytes.fromhex(salt) if len(salt) >= 64 else salt.encode("utf-8")[:32]
                except Exception:
                    salt_bytes = salt.encode("utf-8")[:32]
                pw_hash = hashlib.pbkdf2_hmac(
                    _PBKDF2_HASH_NAME,
                    password.encode("utf-8"),
                    salt_bytes,
                    _PBKDF2_ITERATIONS
                )
                if pw_hash.hex() == stored_hash:
                    return True
            # Old salted SHA256 fallback (16 char hex salt)
            if len(salt) < 32:
                salted = salt + password
                if hashlib.sha256(salted.encode()).hexdigest() == stored_hash:
                    return True
            return False
        else:
            # Legacy unsalted SHA256
            return hashlib.sha256(password.encode()).hexdigest() == stored_hash

    def _migrate_passwords(self):
        """v2.5.3: Migrate any unsalted password hashes to salted format."""
        migrated = 0
        for username, user in self.users.items():
            if "salt" not in user or not user.get("salt"):
                # Legacy password - can't reverse it, so we re-hash admin's default only
                if username == "admin" and user.get("password") == _DEFAULT_ADMIN_PW:
                    # v4.5.4 FIX: use standard PBKDF2 (64-hex salt) so _verify_password
                    # works. Old code used token_hex(16) (32 hex chars) + sha256, which
                    # fell into the PBKDF2 branch (len(salt)>=32) but the stored hash was
                    # SHA256 -> admin could never log in after migration.
                    pw_hash, salt_hex = self._hash_password("admin")
                    user["password"] = pw_hash
                    user["salt"] = salt_hex
                    user["must_change_password"] = True
                    migrated += 1
        if migrated > 0:
            print(f"[*] AUTH: Migrated {migrated} password(s) to salted hash")
            self._save_users()

    # ---- File Encryption (v2.5.3) ----

    def _get_key_dir(self):
        data_dir = os.environ.get("GIAMSAT_DATA_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
        return data_dir

    def _get_users_path(self):
        return os.path.join(self._get_key_dir(), "users.json")

    def _get_key_path(self):
        return os.path.join(self._get_key_dir(), ".user_key")

    def _get_or_create_file_key(self):
        """Get or create the encryption key for users.json. Persists across restarts."""
        key_path = self._get_key_path()
        if os.path.exists(key_path):
            try:
                with open(key_path, "rb") as f:
                    key = f.read()
                if len(key) >= 32:
                    return key
            except Exception:
                pass
        # Create new key
        if _HAS_FERNET:
            key = Fernet.generate_key()
        else:
            key = secrets.token_bytes(32)
        try:
            os.makedirs(os.path.dirname(key_path), exist_ok=True)
            with open(key_path, "wb") as f:
                f.write(key)
            # Try to restrict permissions on key file (Windows: hidden + read-only)
            try:
                import stat
                os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)
            except Exception:
                pass
            print(f"[*] AUTH: Created user file encryption key at {key_path}")
        except Exception as e:
            print(f"[-] AUTH: Failed to save file key: {e}")
        return key

    def _encrypt(self, data: str) -> bytes:
        """Encrypt data with file key."""
        if _HAS_FERNET:
            f = Fernet(self._file_key)
            return f.encrypt(data.encode("utf-8"))
        else:
            # v4.10 (LOW-14): cryptography is mandatory - the XOR fallback was
            # trivially breakable and the plaintext key leaked to disk.
            raise RuntimeError("cryptography library required to protect users.json - run: pip install cryptography")

    def _decrypt(self, data: bytes) -> str:
        """Decrypt data with file key."""
        if _HAS_FERNET:
            f = Fernet(self._file_key)
            return f.decrypt(data).decode("utf-8")
        else:
            # v4.10 (LOW-14): see _encrypt - no weak XOR fallback.
            raise RuntimeError("cryptography library required to protect users.json - run: pip install cryptography")

    def _load_users(self):
        path = self._get_users_path()
        if not os.path.exists(path):
            print("[*] AUTH: No users.json found - will create default admin on first run")
            return
        try:
            with open(path, "rb") as f:
                encrypted = f.read()
            if not encrypted:
                return
            json_data = self._decrypt(encrypted)
            loaded = _json.loads(json_data)
            self.users.update(loaded)
            print(f"[*] AUTH: Loaded {len(self.users)} user(s) from encrypted users.json")
        except Exception as e:
            print(f"[!] AUTH: Failed to load/decrypt users.json: {e}")
            print("[!] AUTH: Starting with empty user database. Default admin will be created.")

    def _save_users(self):
        try:
            path = self._get_users_path()
            os.makedirs(os.path.dirname(path), exist_ok=True)
            json_data = _json.dumps(self.users, indent=2, ensure_ascii=False)
            encrypted = self._encrypt(json_data)
            with open(path, "wb") as f:
                f.write(encrypted)
            print(f"[*] AUTH: Saved {len(self.users)} user(s) to encrypted users.json")
        except Exception as e:
            print(f"[-] AUTH: Failed to save users.json: {e}")

    # ---- Password Policy (unchanged) ----

    @staticmethod
    def validate_password_policy(password):
        """Validate password against policy. Returns (True, None) or (False, error_message)."""
        if len(password) < PASSWORD_POLICY["min_length"]:
            return False, f"Mật khẩu phải có ít nhất {PASSWORD_POLICY['min_length']} ký tự."
        if PASSWORD_POLICY["require_uppercase"] and not re.search(r"[A-Z]", password):
            return False, "Mật khẩu phải chứa ít nhất 1 chữ hoa (A-Z)."
        if PASSWORD_POLICY["require_lowercase"] and not re.search(r"[a-z]", password):
            return False, "Mật khẩu phải chứa ít nhất 1 chữ thường (a-z)."
        if PASSWORD_POLICY["require_digit"] and not re.search(r"[0-9]", password):
            return False, "Mật khẩu phải chứa ít nhất 1 chữ số (0-9)."
        if PASSWORD_POLICY["require_special"] and not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?`~]", password):
            return False, "Mật khẩu phải chứa ít nhất 1 ký tự đặc biệt (!@#$%^&*...)."
        return True, None

    # ---- Brute Force Protection (unchanged) ----

    def _check_brute_force(self, username, ip=""):
        """Check if username/IP is locked due to brute-force.
        v4.10 (MED-19): also lock by client IP so an attacker cannot DoS a shared
        account (and cannot keep trying from one IP with different usernames)."""
        with self._brute_lock:
            for key in (username, f"ip:{ip}"):
                if not key:
                    continue
                if key in self.brute_force:
                    bf = self.brute_force[key]
                    if "locked_until" in bf:
                        locked_until = bf["locked_until"]
                        if datetime.utcnow() < locked_until:
                            remaining = int((locked_until - datetime.utcnow()).total_seconds() / 60) + 1
                            return True, remaining
                        else:
                            del self.brute_force[key]
        return False, 0

    def _record_failed_attempt(self, username, ip=""):
        with self._brute_lock:
            for key in (username, f"ip:{ip}"):
                if not key:
                    continue
                if key not in self.brute_force:
                    self.brute_force[key] = {"attempts": 1}
                else:
                    self.brute_force[key]["attempts"] = self.brute_force[key].get("attempts", 0) + 1
                if self.brute_force[key]["attempts"] >= MAX_LOGIN_ATTEMPTS:
                    self.brute_force[key]["locked_until"] = datetime.utcnow() + timedelta(minutes=LOCKOUT_DURATION_MINUTES)

    def _clear_brute_force(self, username, ip=""):
        with self._brute_lock:
            for key in (username, f"ip:{ip}"):
                if key and key in self.brute_force:
                    del self.brute_force[key]

    # ---- Authentication (v2.5.3: salted verification) ----

    def authenticate(self, username, password, ip=""):
        """Authenticate user. Returns dict with token/error/must_change_password, or None."""
        # Check brute-force lockout (v4.10 MED-19: per-username + per-IP)
        is_locked, remaining = self._check_brute_force(username, ip)
        if is_locked:
            return {"success": False, "error": f"Tài khoản bị khóa do đăng nhập sai nhiều lần. Vui lòng thử lại sau {remaining} phút.", "code": "ACCOUNT_LOCKED"}

        user = self.users.get(username)
        if not user:
            self._record_failed_attempt(username, ip)
            remaining_attempts = MAX_LOGIN_ATTEMPTS - self.brute_force.get(username, {}).get("attempts", 0)
            return {"success": False, "error": f"Sai tên đăng nhập hoặc mật khẩu. Còn {remaining_attempts} lần thử.", "code": "INVALID_CREDENTIALS"}

        # v2.5.3: Verify with salt if available, fallback to unsalted (legacy)
        if not self._verify_password(password, user.get("password", ""), user.get("salt")):
            self._record_failed_attempt(username, ip)
            remaining_attempts = MAX_LOGIN_ATTEMPTS - self.brute_force.get(username, {}).get("attempts", 0)
            return {"success": False, "error": f"Sai tên đăng nhập hoặc mật khẩu. Còn {remaining_attempts} lần thử.", "code": "INVALID_CREDENTIALS"}

        # Success - clear brute-force
        self._clear_brute_force(username, ip)

        # v2.5.3: Auto-migrate legacy unsalted password on successful login
        # v4.10 FIX (HIGH-1): use PBKDF2 _hash_password (64-hex salt). The old
        # token_hex(16) salt is exactly 32 chars, which _verify_password treats as
        # the PBKDF2 branch -> the migrated user could never log in again.
        if "salt" not in user or not user.get("salt"):
            new_hash, new_salt = self._hash_password(password)
            with self.lock:
                self.users[username]["password"] = new_hash
                self.users[username]["salt"] = new_salt
                self._save_users()
            print(f"[*] AUTH: Auto-migrated {username}'s password to PBKDF2 salted hash")

        must_change = user.get("must_change_password", False)
        token = self._generate_token(username, user.get("role", "viewer"), must_change)
        result = {"success": True, "token": token, "role": user.get("role", "viewer")}

        if must_change:
            result["must_change_password"] = True
            result["message"] = "BẮT BUỘC ĐỔI MẬT KHẨU: Token sẽ hết hạn sau 15 phút."
        return result

    def _generate_token(self, username, role, must_change_password=False):
        now = datetime.utcnow()
        payload = {"sub": username, "role": role, "iat": int(now.timestamp()), "exp": int((now + timedelta(hours=12)).timestamp()), "jti": secrets.token_hex(16), "must_change_password": must_change_password}
        if _HAS_JWT:
            token = pyjwt.encode(payload, self.secret, algorithm="HS256")
            if isinstance(token, bytes):
                token = token.decode()
        else:
            token = _jwt_fallback_encode(payload, self.secret)
        self.sessions[username] = {"token": token, "expires": datetime.utcnow() + timedelta(hours=12), "role": role}
        return token

    def verify_token(self, token):
        if token in self.token_blacklist:
            return None
        try:
            if _HAS_JWT:
                payload = pyjwt.decode(token, self.secret, algorithms=["HS256"])
            else:
                payload = _jwt_fallback_decode(token, self.secret)
            if not payload:
                return None
            username = payload.get("sub", "")
            if username not in self.users:
                return None
            return payload
        except Exception:
            return None

    def invalidate_token(self, token):
        # v4.10 (LOW-6): store the token's expiry (when decodable) so blacklisted
        # tokens are evicted by expiration instead of just by oldest-insert.
        exp_ts = None
        try:
            payload = self.verify_token(token)
            exp_ts = payload.get("exp", 0) if payload else None
        except Exception:
            pass
        self.token_blacklist[token] = exp_ts if isinstance(exp_ts, (int, float)) else True
        # evict expired entries
        now = datetime.utcnow().timestamp()
        expired = [k for k, v in self.token_blacklist.items()
                   if isinstance(v, (int, float)) and v < now]
        for k in expired:
            self.token_blacklist.pop(k, None)
        # cap size (oldest-first fallback)
        if len(self.token_blacklist) > 1000:
            for _ in range(len(self.token_blacklist) - 900):
                try:
                    self.token_blacklist.pop(next(iter(self.token_blacklist)))
                except (StopIteration, KeyError):
                    break

    def check_permission(self, username, permission):
        user = self.users.get(username, {})
        role = user.get("role", "viewer")
        permissions = USER_ROLES.get(role, [])
        return permission in permissions

    # ---- User Management (v2.5.3: always save with salt) ----

    def add_user(self, username, password, role="viewer"):
        if role not in USER_ROLES:
            role = "viewer"
        # Validate password policy
        valid, error = self.validate_password_policy(password)
        if not valid:
            return {"success": False, "error": error}
        pw_hash, salt = self._hash_password(password)
        with self.lock:
            self.users[username] = {
                "username": username,
                "password": pw_hash,
                "salt": salt,
                "role": role,
                "must_change_password": False
            }
            self._save_users()
        return {"success": True}

    def remove_user(self, username):
        if username == "admin":
            return False
        with self.lock:
            if username in self.users:
                del self.users[username]
                self._save_users()
                return True
        return False

    def change_password(self, username, old_password, new_password):
        user = self.users.get(username)
        if not user:
            return {"success": False, "error": "Người dùng không tồn tại."}
        if not self._verify_password(old_password, user.get("password", ""), user.get("salt")):
            return {"success": False, "error": "Mật khẩu cũ không đúng."}
        # Validate password policy
        valid, error = self.validate_password_policy(new_password)
        if not valid:
            return {"success": False, "error": error}
        pw_hash, salt = self._hash_password(new_password)
        with self.lock:
            self.users[username]["password"] = pw_hash
            self.users[username]["salt"] = salt
            self.users[username]["must_change_password"] = False
            self._save_users()
        new_token = self._generate_token(username, user.get("role", "viewer"), must_change_password=False)
        return {"success": True, "token": new_token}

    def get_users(self):
        return {u: {"username": u, "role": d["role"], "must_change_password": d.get("must_change_password", False)} for u, d in self.users.items()}

    @staticmethod
    def require_permission(permission):
        """Decorator for Flask routes to check permission."""
        def decorator(f):
            def wrapper(*args, **kwargs):
                from flask import request, g, jsonify
                token = request.headers.get("Authorization", "").replace("Bearer ", "")
                if not token:
                    token = request.cookies.get("giamsat_token", "")
                if not token:
                    return jsonify({"error": "Authentication required", "code": "AUTH_REQUIRED"}), 401
                auth = getattr(g, "auth_manager", None)
                if not auth:
                    return jsonify({"error": "Auth not initialized"}), 500
                payload = auth.verify_token(token)
                if not payload:
                    return jsonify({"error": "Invalid or expired token", "code": "INVALID_TOKEN"}), 401
                username = payload.get("sub", "")
                if not auth.check_permission(username, permission):
                    return jsonify({"error": "Insufficient permissions", "code": "FORBIDDEN"}), 403
                g.username = username
                g.role = payload.get("role", "viewer")
                return f(*args, **kwargs)
            wrapper.__name__ = f.__name__
            return wrapper
        return decorator