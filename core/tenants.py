"""Multi-tenancy support.

Design choice: instead of one shared database with a `tenant_id` column
(one missing WHERE clause away from leaking Client A's data to Client B),
every tenant gets a **physically separate SQLite file** plus its own
sample-data/report folders. This is the simplest isolation model that is
also the hardest to get wrong.
"""
import hashlib
import hmac
import os
import secrets
import yaml
from dataclasses import dataclass
from typing import Optional

PBKDF2_ITERATIONS = 200_000


def hash_access_code(code: str, salt_hex: str | None = None) -> tuple[str, str]:
    """Returns (digest_hex, salt_hex). Used to generate `access_code_hash` /
    `access_code_salt` for config/tenants.yaml - run this locally (it never
    sends the code anywhere) and paste the two resulting values into the
    tenant's entry instead of a plaintext access_code:

        python -c "from core.tenants import hash_access_code; print(hash_access_code('your-code'))"
    """
    salt_hex = salt_hex or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", code.encode("utf-8"), bytes.fromhex(salt_hex), PBKDF2_ITERATIONS)
    return digest.hex(), salt_hex


@dataclass
class Tenant:
    id: str
    name: str
    access_code: str = ""          # plaintext - fine for local demo tenants only
    access_code_hash: str = ""     # PBKDF2-HMAC-SHA256 hex digest - use for real clients
    access_code_salt: str = ""


class TenantRegistry:
    def __init__(self, tenants_file: str = "config/tenants.yaml"):
        self.tenants_file = tenants_file
        self._tenants: dict[str, Tenant] = {}
        self._load()

    def _load(self):
        if not os.path.exists(self.tenants_file):
            # Single-tenant fallback so the tool still works out of the box.
            self._tenants = {
                "default": Tenant(id="default", name="Default Organization")
            }
            return
        with open(self.tenants_file, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
        for t in raw.get("tenants", []):
            tenant = Tenant(
                id=t["id"], name=t.get("name", t["id"]),
                access_code=t.get("access_code", ""),
                access_code_hash=t.get("access_code_hash", ""),
                access_code_salt=t.get("access_code_salt", ""),
            )
            self._tenants[tenant.id] = tenant
        if not self._tenants:
            self._tenants = {
                "default": Tenant(id="default", name="Default Organization")
            }

    def list_tenants(self) -> list[Tenant]:
        return list(self._tenants.values())

    def get(self, tenant_id: str) -> Optional[Tenant]:
        return self._tenants.get(tenant_id)

    def verify(self, tenant_id: str, access_code: str) -> bool:
        tenant = self.get(tenant_id)
        if tenant is None:
            return False
        if tenant.access_code_hash:
            if not tenant.access_code_salt:
                return False
            digest, _ = hash_access_code(access_code, tenant.access_code_salt)
            return hmac.compare_digest(digest, tenant.access_code_hash)
        if tenant.access_code == "":
            return True
        return hmac.compare_digest(tenant.access_code, access_code)


def tenant_paths(tenant_id: str) -> dict:
    """Every filesystem path that must stay isolated per tenant."""
    return {
        "database_file": os.path.join("data", tenant_id, "soc.db"),
        "sample_data_dir": os.path.join("sample_data", tenant_id),
        "reports_dir": os.path.join("reports", tenant_id),
    }


def ensure_tenant_dirs(tenant_id: str):
    paths = tenant_paths(tenant_id)
    os.makedirs(os.path.dirname(paths["database_file"]), exist_ok=True)
    os.makedirs(paths["sample_data_dir"], exist_ok=True)
    os.makedirs(paths["reports_dir"], exist_ok=True)
    return paths
