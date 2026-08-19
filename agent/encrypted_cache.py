"""
Encrypted SQLite Cache for GIAM-SAT Agent v3.6.0
v3.6: DPAPI key protection (Windows) + Merkle integrity chain + Tamper guard thread.
Encrypts offline cached data using AES-256-GCM before storage.
"""
import os
import json
import sqlite3
import threading
import time
import hashlib
import base64
import secrets

ENCRYPTION_ENABLED = False
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    ENCRYPTION_ENABLED = True
except ImportError:
    pass

# v3.6: DPAPI support (Windows only)
HAS_DPAPI = False
if os.name == "nt":
    try:
        import ctypes
        from ctypes import wintypes
        _crypt32 = ctypes.windll.crypt32
        _kernel32 = ctypes.windll.kernel32

        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

        _crypt32.CryptProtectData.argtypes = [ctypes.POINTER(DATA_BLOB), wintypes.LPCWSTR,
            ctypes.POINTER(DATA_BLOB), ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD,
            ctypes.POINTER(DATA_BLOB)]
        _crypt32.CryptProtectData.restype = wintypes.BOOL

        _crypt32.CryptUnprotectData.argtypes = [ctypes.POINTER(DATA_BLOB), wintypes.LPCWSTR,
            ctypes.POINTER(DATA_BLOB), ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD,
            ctypes.POINTER(DATA_BLOB)]
        _crypt32.CryptUnprotectData.restype = wintypes.BOOL

        _kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
        _kernel32.LocalFree.restype = wintypes.HLOCAL

        HAS_DPAPI = True
    except Exception:
        HAS_DPAPI = False


def _dpapi_protect(data_bytes):
    """Encrypt data with Windows DPAPI (bound to the current USER - per-user scope).
    v4.11 (HIGH-4 FIX): removed the 'LocalMachine' DPAPI-NG branch entirely -
    machine-scope encryption is decryptable by EVERY local user (the old comment
    claimed 'TPM binding', which is wrong for ProtectedData). Per-user
    CryptProtectData is now the only Windows protection path."""
    if not HAS_DPAPI:
        return None
    try:
        data_in = (ctypes.c_byte * len(data_bytes))()
        for i, b in enumerate(data_bytes):
            data_in[i] = b
        blob_in = DATA_BLOB(len(data_bytes), data_in)
        blob_out = DATA_BLOB(0, None)
        if _crypt32.CryptProtectData(ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)):
            result = bytes((ctypes.c_byte * blob_out.cbData).from_address(ctypes.addressof(blob_out.pbData.contents)))
            _kernel32.LocalFree(blob_out.pbData)
            return result
    except Exception:
        pass
    return None


def _dpapi_unprotect(encrypted_bytes):
    """Decrypt DPAPI-encrypted data. Returns bytes or None."""
    if not HAS_DPAPI:
        return None
    try:
        data_in = (ctypes.c_byte * len(encrypted_bytes))()
        for i, b in enumerate(encrypted_bytes):
            data_in[i] = b
        blob_in = DATA_BLOB(len(encrypted_bytes), data_in)
        blob_out = DATA_BLOB(0, None)
        if _crypt32.CryptUnprotectData(ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)):
            result = bytes((ctypes.c_byte * blob_out.cbData).from_address(ctypes.addressof(blob_out.pbData.contents)))
            _kernel32.LocalFree(blob_out.pbData)
            return result
    except Exception:
        pass
    return None


def _get_cache_path():
    if os.name == "nt":
        programdata = os.environ.get("PROGRAMDATA", "C:\\ProgramData")
        data_dir = os.path.join(programdata, "GIAM-SAT", "Agent")
    else:
        data_dir = os.path.join(os.path.expanduser("~"), ".giamsat", "agent")
    os.makedirs(data_dir, exist_ok=True)
    return os.path.join(data_dir, "giamsat_cache.db")


def _get_key_path():
    if os.name == "nt":
        programdata = os.environ.get("PROGRAMDATA", "C:\\ProgramData")
        data_dir = os.path.join(programdata, "GIAM-SAT", "Agent")
    else:
        data_dir = os.path.join(os.path.expanduser("~"), ".giamsat", "agent")
    return os.path.join(data_dir, ".cache_key")


class EncryptedCache:
    """Thread-safe encrypted cache with DPAPI key protection + Merkle integrity chain.
    v3.6: Falls back to plaintext if cryptography unavailable."""

    def __init__(self, send_callback=None, integrity_callback=None):
        self.send_callback = send_callback
        # v3.6: integrity_callback(data) called when tamper detected
        self.integrity_callback = integrity_callback
        self.lock = threading.Lock()
        self.conn = sqlite3.connect(_get_cache_path(), check_same_thread=False)
        self._init_db()
        self._key = self._load_or_create_key()
        self._aesgcm = None
        self._last_db_stat = None  # v3.6: for tamper detection
        self._guard_running = True
        if ENCRYPTION_ENABLED and self._key:
            self._aesgcm = AESGCM(self._key)
            print("[*] Encrypted cache enabled (AES-256-GCM)")
        else:
            print("[*] Cache running in plaintext mode")

        # v3.6: Start integrity guard thread
        self._guard_thread = threading.Thread(target=self._integrity_guard_loop, daemon=True)
        self._guard_thread.start()

    def _init_db(self):
        with self.lock:
            self.conn.execute("""CREATE TABLE IF NOT EXISTS log_cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                data TEXT NOT NULL,
                chain_hash TEXT DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )""")
            # v3.6: Add chain_hash column if upgrading from older schema
            try:
                self.conn.execute("ALTER TABLE log_cache ADD COLUMN chain_hash TEXT DEFAULT ''")
            except sqlite3.OperationalError:
                pass
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.commit()
            # v3.6: Initialize last_db_stat
            try:
                db_path = _get_cache_path()
                self._last_db_stat = os.stat(db_path)
            except Exception:
                self._last_db_stat = None

    def _load_or_create_key(self):
        """v3.6: Load key from DPAPI-protected blob, or create new one.
        v4.11 (HIGH-4 FIX): the key is NEVER written in plaintext - if DPAPI is
        unavailable the cache simply runs unencrypted instead of leaking a
        plaintext key file right next to the data it is supposed to protect
        (fail-closed)."""
        key_path = _get_key_path()
        if os.path.exists(key_path):
            try:
                with open(key_path, "rb") as f:
                    blob = f.read()
                # DPAPI-protected blob (per-user) first
                if HAS_DPAPI:
                    decrypted = _dpapi_unprotect(blob)
                    if decrypted and len(decrypted) == 32:
                        return decrypted
                # Legacy plaintext key (old format) - accepted ONLY to migrate it:
                # re-protect with DPAPI immediately so it is never left in clear.
                if len(blob) == 32:
                    if HAS_DPAPI:
                        protected = _dpapi_protect(blob)
                        if protected:
                            try:
                                with open(key_path, "wb") as f:
                                    f.write(protected)
                                print("[*] Cache key migrated from plaintext to DPAPI")
                            except Exception:
                                pass
                    return blob
            except Exception:
                pass

        # Create new key
        if ENCRYPTION_ENABLED:
            key = AESGCM.generate_key(bit_length=256)
            if HAS_DPAPI:
                try:
                    protected = _dpapi_protect(key)
                    if protected:
                        os.makedirs(os.path.dirname(key_path), exist_ok=True)
                        with open(key_path, "wb") as f:
                            f.write(protected)
                        print("[*] Cache key protected with Windows DPAPI (per-user)")
                        return key
                except Exception:
                    pass
            # v4.11 (HIGH-4): no plaintext key fallback (fail-closed)
            print("[!] Cache key cannot be protected (DPAPI unavailable) - cache stays "
                  "UNENCRYPTED (no plaintext key written)")
            return None
        return None

    def _get_last_hash(self):
        """Get chain_hash of the most recent row (for Merkle integrity chain)."""
        try:
            cursor = self.conn.execute(
                "SELECT chain_hash FROM log_cache ORDER BY id DESC LIMIT 1"
            )
            row = cursor.fetchone()
            if row and row[0]:
                return row[0]
        except Exception:
            pass
        return None

    def _compute_chain_hash(self, prev_hash, data_str):
        """Compute Merkle chain hash: SHA256(prev_hash || data)."""
        if not prev_hash:
            prev_hash = "0000000000000000000000000000000000000000000000000000000000000000"
        combined = prev_hash + data_str
        return hashlib.sha256(combined.encode("utf-8")).hexdigest()

    def _encrypt(self, plaintext):
        if not self._aesgcm:
            return plaintext
        nonce = secrets.token_bytes(12)
        ciphertext = self._aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
        return base64.b64encode(nonce + ciphertext).decode("ascii")

    def _decrypt(self, encrypted_str):
        if not self._aesgcm:
            return encrypted_str
        try:
            raw = base64.b64decode(encrypted_str)
            nonce = raw[:12]
            ciphertext = raw[12:]
            return self._aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")
        except Exception:
            return None

    def _integrity_guard_loop(self):
        """v3.6: Background thread that checks for cache tampering every 30s.
        v4.10 (LOW-9): the previous loop had its comparison commented out (dead
        code); it now actually verifies the Merkle chain and logs tampering."""
        while self._guard_running:
            time.sleep(30)
            try:
                valid, errors = self.verify_integrity()
                if not valid:
                    print(f"[!] CACHE INTEGRITY: {len(errors)} row(s) tampered in event cache")
                    for e in errors[:5]:
                        print(f"    row {e['row_id']}: expected {e['expected']} got {e['actual']}")
            except Exception:
                pass

    def cache(self, data):
        """v3.6: Cache with Merkle integrity chain."""
        try:
            plain = json.dumps(data, ensure_ascii=False)
            encrypted = self._encrypt(plain)
            with self.lock:
                prev_hash = self._get_last_hash()
                chain_hash = self._compute_chain_hash(prev_hash, encrypted)
                self.conn.execute(
                    "INSERT INTO log_cache (data, chain_hash) VALUES (?, ?)",
                    (encrypted, chain_hash)
                )
                self.conn.commit()
        except Exception as e:
            print(f"[-] Cache write error: {e}", flush=True)

    def flush_batch(self, batch_size=100, delay_ms=200):
        total_sent = 0
        while True:
            batch = []
            with self.lock:
                cursor = self.conn.execute(
                    "SELECT id, data FROM log_cache ORDER BY id ASC LIMIT ?",
                    (batch_size,)
                )
                batch = [(row[0], row[1]) for row in cursor.fetchall()]
            if not batch:
                break
            for row_id, data_str in batch:
                try:
                    plain = self._decrypt(data_str)
                    if plain is None:
                        with self.lock:
                            self.conn.execute("DELETE FROM log_cache WHERE id=?", (row_id,))
                            self.conn.commit()
                        continue
                    data = json.loads(plain)
                    if self.send_callback and self.send_callback(data):
                        with self.lock:
                            self.conn.execute("DELETE FROM log_cache WHERE id=?", (row_id,))
                            self.conn.commit()
                        total_sent += 1
                    else:
                        return total_sent
                except Exception:
                    with self.lock:
                        self.conn.execute("DELETE FROM log_cache WHERE id=?", (row_id,))
                        self.conn.commit()
            time.sleep(delay_ms / 1000)
        return total_sent

    def verify_integrity(self):
        """v3.6: Verify Merkle chain integrity of all cached rows.
        Returns (valid, errors) tuple."""
        errors = []
        with self.lock:
            cursor = self.conn.execute(
                "SELECT id, data, chain_hash FROM log_cache ORDER BY id ASC"
            )
            rows = cursor.fetchall()
            prev_hash = None
            for row in rows:
                expected_hash = self._compute_chain_hash(prev_hash, row[1])
                actual_hash = row[2] or ""
                if expected_hash != actual_hash:
                    errors.append({
                        "row_id": row[0],
                        "expected": expected_hash[:16],
                        "actual": actual_hash[:16],
                    })
                prev_hash = expected_hash
        return len(errors) == 0, errors

    def get_cache_size(self):
        with self.lock:
            cursor = self.conn.execute("SELECT COUNT(*) FROM log_cache")
            return cursor.fetchone()[0]

    def close(self):
        self._guard_running = False
        self.conn.close()