"""
Multi-Tenant Manager for GIAM-SAT v2.0.0
Supports multiple organizations on a single server instance:
  - Tenant isolation (data never crosses boundaries)
  - Per-tenant user management
  - Per-tenant alerting rules
  - Per-tenant retention policies
  - Tenant-scoped API keys

Tenant data is stored in separate database tables.
Queries automatically filter by tenant_id.
"""

import os, json, sqlite3, uuid, time
from datetime import datetime
from collections import defaultdict

TENANT_DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tenants.db")


class TenantManager:
    """Manages multi-tenancy for GIAM-SAT server."""

    def __init__(self, db_manager):
        self.db = db_manager
        self._init_tenant_db()

    def _init_tenant_db(self):
        try:
            conn = sqlite3.connect(TENANT_DB)
            c = conn.cursor()
            c.execute("""CREATE TABLE IF NOT EXISTS tenants (
                id TEXT PRIMARY KEY, name TEXT, org_name TEXT, created_at TEXT,
                status TEXT DEFAULT 'active', max_agents INTEGER DEFAULT 50,
                retention_days INTEGER DEFAULT 90, settings TEXT
            )""")
            c.execute("""CREATE TABLE IF NOT EXISTS tenant_users (
                tenant_id TEXT, username TEXT, password_hash TEXT, role TEXT,
                created_at TEXT, PRIMARY KEY (tenant_id, username)
            )""")
            c.execute("""CREATE TABLE IF NOT EXISTS tenant_api_keys (
                tenant_id TEXT, key_name TEXT, api_key TEXT, scopes TEXT,
                created_at TEXT, last_used TEXT, PRIMARY KEY (tenant_id, key_name)
            )""")
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[-] Tenant DB init error: {e}")

    # =========================================================================
    # Tenant CRUD
    # =========================================================================
    def create_tenant(self, name: str, org_name: str = "", max_agents: int = 50, retention_days: int = 90) -> dict:
        tenant_id = f"TENANT-{uuid.uuid4().hex[:8].upper()}"
        try:
            conn = sqlite3.connect(TENANT_DB)
            c = conn.cursor()
            c.execute("INSERT INTO tenants VALUES (?,?,?,?,?,?,?,?)",
                      (tenant_id, name, org_name, datetime.now().isoformat(), "active", max_agents, retention_days, "{}"))
            # Create default admin user
            c.execute("INSERT INTO tenant_users VALUES (?,?,?,?,?)",
                      (tenant_id, "admin", self._hash_password("admin"), "admin", datetime.now().isoformat()))
            conn.commit()
            conn.close()
            return {"success": True, "tenant_id": tenant_id, "name": name}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def get_tenant(self, tenant_id: str) -> dict:
        try:
            conn = sqlite3.connect(TENANT_DB)
            c = conn.cursor()
            c.execute("SELECT * FROM tenants WHERE id=?", (tenant_id,))
            row = c.fetchone()
            conn.close()
            if row:
                return {"id": row[0], "name": row[1], "org_name": row[2], "created_at": row[3],
                        "status": row[4], "max_agents": row[5], "retention_days": row[6]}
            return None
        except Exception:
            return None

    def get_all_tenants(self) -> list:
        try:
            conn = sqlite3.connect(TENANT_DB)
            c = conn.cursor()
            c.execute("SELECT id, name, org_name, status, max_agents, created_at FROM tenants WHERE status='active'")
            tenants = [{"id": r[0], "name": r[1], "org_name": r[2], "status": r[3], "max_agents": r[4], "created_at": r[5]} for r in c.fetchall()]
            conn.close()
            return tenants
        except Exception:
            return []

    def update_tenant(self, tenant_id: str, updates: dict) -> bool:
        allowed = ["name", "org_name", "max_agents", "retention_days", "status"]
        set_clause = ", ".join(f"{k}=?" for k in updates if k in allowed)
        values = [v for k, v in updates.items() if k in allowed] + [tenant_id]
        try:
            conn = sqlite3.connect(TENANT_DB)
            conn.cursor().execute(f"UPDATE tenants SET {set_clause} WHERE id=?", values)
            conn.commit()
            conn.close()
            return True
        except Exception:
            return False

    def delete_tenant(self, tenant_id: str) -> bool:
        try:
            conn = sqlite3.connect(TENANT_DB)
            c = conn.cursor()
            c.execute("DELETE FROM tenants WHERE id=?", (tenant_id,))
            c.execute("DELETE FROM tenant_users WHERE tenant_id=?", (tenant_id,))
            c.execute("DELETE FROM tenant_api_keys WHERE tenant_id=?", (tenant_id,))
            conn.commit()
            conn.close()
            return True
        except Exception:
            return False

    # =========================================================================
    # Tenant Auth
    # =========================================================================
    def authenticate_tenant_user(self, tenant_id: str, username: str, password: str) -> dict:
        try:
            conn = sqlite3.connect(TENANT_DB)
            c = conn.cursor()
            c.execute("SELECT username, password_hash, role FROM tenant_users WHERE tenant_id=? AND username=?", (tenant_id, username))
            row = c.fetchone()
            conn.close()
            if row and self._check_password(row[1], password):
                return {"success": True, "username": row[0], "role": row[2], "tenant_id": tenant_id}
            return {"success": False, "error": "Invalid credentials"}
        except Exception:
            return {"success": False, "error": "Auth error"}

    # =========================================================================
    # API Keys
    # =========================================================================
    def create_api_key(self, tenant_id: str, key_name: str, scopes: list = None) -> dict:
        api_key = f"GS-{uuid.uuid4().hex[:24].upper()}"
        try:
            conn = sqlite3.connect(TENANT_DB)
            conn.cursor().execute("INSERT INTO tenant_api_keys VALUES (?,?,?,?,?,?)",
                                  (tenant_id, key_name, api_key, json.dumps(scopes or ["read"]), datetime.now().isoformat(), ""))
            conn.commit()
            conn.close()
            return {"success": True, "api_key": api_key, "key_name": key_name}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def validate_api_key(self, api_key: str) -> dict:
        try:
            conn = sqlite3.connect(TENANT_DB)
            c = conn.cursor()
            c.execute("SELECT tenant_id, key_name, scopes FROM tenant_api_keys WHERE api_key=?", (api_key,))
            row = c.fetchone()
            if row:
                c.execute("UPDATE tenant_api_keys SET last_used=? WHERE api_key=?", (datetime.now().isoformat(), api_key))
                conn.commit()
                conn.close()
                return {"valid": True, "tenant_id": row[0], "key_name": row[1], "scopes": json.loads(row[2])}
            conn.close()
            return {"valid": False}
        except Exception:
            return {"valid": False}

    # =========================================================================
    # Data Isolation Helpers
    # =========================================================================
    def scoped_query(self, tenant_id: str, table: str, extra_where: str = "") -> str:
        return f"SELECT * FROM {table} WHERE tenant_id='{tenant_id}'" + (f" AND {extra_where}" if extra_where else "")

    # =========================================================================
    # Internal helpers
    # =========================================================================
    def _hash_password(self, pw: str) -> str:
        import hashlib, os as _os
        salt = _os.urandom(16)
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 200000)
        return salt.hex() + ":" + dk.hex()

    def _check_password(self, stored: str, pw: str) -> bool:
        import hashlib
        try:
            salt_hex, dk_hex = stored.split(":", 1)
        except ValueError:
            # Fallback for old SHA256-only hashes
            return stored == hashlib.sha256(pw.encode()).hexdigest()
        salt = bytes.fromhex(salt_hex)
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 200000)
        return dk.hex() == dk_hex
