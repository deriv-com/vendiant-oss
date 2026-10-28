"""
Auto-applied database schema changes.

Runs on backend startup after QA/prod deploy. The backend pod already reaches
the configured PostgreSQL database on backend startup; nothing to run by hand.

Idempotent: safe to run on every pod start (CREATE IF NOT EXISTS).
"""

from __future__ import annotations

import json
import logging

try:
    from Dashboard.db_config import DatabaseConnection
except ImportError:
    from db_config import DatabaseConnection

logger = logging.getLogger(__name__)

# Keep in sync with frontend/lib/rbac.ts ROLE_PERMISSIONS for system roles.
_SYSTEM_ROLES = (
    {
        "name": "Admin",
        "slug": "admin",
        "permissions": [
            "view_vendors",
            "view_security_scans",
            "manage_vendors",
            "delete_vendors",
            "add_vendors",
            "run_full_scans",
            "check_all_certifications",
            "view_certifications",
            "view_incidents",
            "view_pwn_monitor",
            "view_admin_features",
            "manage_access_management",
            "manage_additional_domains",
            "view_subdomains",
            "add_subdomains",
            "exclude_subdomains",
            "view_vendor_reports",
            "export_vendor_reports",
            "view_internal_breaches",
            "query_internal_breaches",
            "view_audit_logs",
            "view_portfolios",
            "create_portfolios",
            "manage_portfolios",
            "delete_portfolios",
            "view_api_keys",
            "manage_api_keys",
        ],
    },
    {
        "name": "Extended",
        "slug": "user-extended",
        "permissions": [
            "view_vendors",
            "view_subdomains",
            "view_vendor_reports",
            "view_portfolios",
            "view_internal_breaches",
            "view_certifications",
            "view_incidents",
            "view_pwn_monitor",
        ],
    },
    {
        "name": "Viewer",
        "slug": "user-basic",
        "permissions": [
            "view_vendors",
            "view_subdomains",
            "view_vendor_reports",
            "view_portfolios",
            "view_certifications",
            "view_incidents",
            "view_pwn_monitor",
        ],
    },
)

_CREATE_DASHBOARD_USER_PERMISSIONS = """
CREATE TABLE IF NOT EXISTS dashboard_user_permissions (
    id                SERIAL PRIMARY KEY,
    user_email        TEXT NOT NULL,
    user_name         TEXT,
    iam_unique_id     TEXT,
    role_preset       TEXT,
    permissions       JSONB NOT NULL DEFAULT '[]'::jsonb
                      CHECK (jsonb_typeof(permissions) = 'array'),
    is_active         BOOLEAN NOT NULL DEFAULT TRUE,
    assigned_by_email TEXT,
    assigned_by_name  TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT dashboard_user_permissions_email_unique UNIQUE (user_email)
)
"""

_CREATE_DASHBOARD_ROLES = """
CREATE TABLE IF NOT EXISTS dashboard_roles (
    id                SERIAL PRIMARY KEY,
    name              TEXT NOT NULL,
    slug              TEXT NOT NULL,
    is_system         BOOLEAN NOT NULL DEFAULT FALSE,
    permissions       JSONB NOT NULL DEFAULT '[]'::jsonb
                      CHECK (jsonb_typeof(permissions) = 'array'),
    created_by_email  TEXT,
    created_by_name   TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT dashboard_roles_slug_unique UNIQUE (slug),
    CONSTRAINT dashboard_roles_name_unique UNIQUE (name)
)
"""

_CREATE_INDEXES = (
    """
    CREATE UNIQUE INDEX IF NOT EXISTS idx_dup_email_lower
        ON dashboard_user_permissions (LOWER(TRIM(user_email)))
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_dup_permissions_gin
        ON dashboard_user_permissions USING GIN (permissions)
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_dup_active
        ON dashboard_user_permissions (is_active)
        WHERE is_active = TRUE
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_dashboard_roles_system
        ON dashboard_roles (is_system)
    """,
)

_table_ready = False
_roles_ready = False


def ensure_dashboard_user_permissions() -> bool:
    """Create dashboard_user_permissions (+ indexes) if missing."""
    global _table_ready
    if _table_ready:
        return True
    try:
        with DatabaseConnection() as db:
            if not db.execute_insert(_CREATE_DASHBOARD_USER_PERMISSIONS):
                logger.error("Failed to create dashboard_user_permissions table")
                return False
            for stmt in _CREATE_INDEXES[:3]:
                if not db.execute_insert(stmt):
                    logger.error("Failed to create dashboard_user_permissions index")
                    return False
        _table_ready = True
        logger.info("dashboard_user_permissions table verified/created")
        return True
    except Exception as exc:
        logger.error("ensure_dashboard_user_permissions failed: %s", exc, exc_info=True)
        return False


def ensure_dashboard_roles() -> bool:
    """Create dashboard_roles, role_id FK column, and seed system roles."""
    global _roles_ready
    if _roles_ready:
        return True
    if not ensure_dashboard_user_permissions():
        return False
    try:
        with DatabaseConnection() as db:
            if not db.execute_insert(_CREATE_DASHBOARD_ROLES):
                logger.error("Failed to create dashboard_roles table")
                return False
            if not db.execute_insert(_CREATE_INDEXES[3]):
                logger.error("Failed to create dashboard_roles index")
                return False
            # Add role_id if missing (Postgres ADD COLUMN IF NOT EXISTS)
            db.execute_insert(
                """
                ALTER TABLE dashboard_user_permissions
                    ADD COLUMN IF NOT EXISTS role_id INTEGER
                    REFERENCES dashboard_roles(id) ON DELETE SET NULL
                """
            )
            db.execute_insert(
                """
                CREATE INDEX IF NOT EXISTS idx_dup_role_id
                    ON dashboard_user_permissions (role_id)
                """
            )
            for role in _SYSTEM_ROLES:
                db.execute_insert(
                    """
                    INSERT INTO dashboard_roles (name, slug, is_system, permissions)
                    VALUES (%s, %s, TRUE, %s::jsonb)
                    ON CONFLICT (slug) DO UPDATE SET
                        name = EXCLUDED.name,
                        permissions = EXCLUDED.permissions,
                        updated_at = NOW()
                    """,
                    (role["name"], role["slug"], json.dumps(role["permissions"])),
                )
            # Link legacy assignments (role_preset) to seeded system roles
            db.execute_insert(
                """
                UPDATE dashboard_user_permissions p
                SET role_id = r.id
                FROM dashboard_roles r
                WHERE p.role_id IS NULL
                  AND p.role_preset IS NOT NULL
                  AND p.role_preset = r.slug
                """
            )
            # Keep member snapshots aligned with system role definitions
            db.execute_insert(
                """
                UPDATE dashboard_user_permissions p
                SET permissions = r.permissions,
                    updated_at = NOW()
                FROM dashboard_roles r
                WHERE p.role_id = r.id
                  AND r.is_system = TRUE
                  AND p.is_active = TRUE
                """
            )
        _roles_ready = True
        logger.info("dashboard_roles table verified/seeded")
        return True
    except Exception as exc:
        logger.error("ensure_dashboard_roles failed: %s", exc, exc_info=True)
        return False


def ensure_vendor_scan_cursor() -> bool:
    """Add vendors.last_full_scan_at -- the scan scheduler's cursor.

    Scan order used to be derived from the `scores` table by finding the most
    recent row labelled 'full_scan_all'. That was unreliable: `scores` is written
    by several code paths (including, until recently, a report read), and
    scan_format was inherited from whichever row was written last, so an
    unrelated request could move the scanner's position.

    vendors.last_scanned cannot be reused for this -- it is stamped by
    update_vendor_overall_score, which several non-scan paths reach.

    This column is written in exactly one place: when a vendor's full scan
    completes every step. That makes "scan whoever is stalest" trivially correct
    and self-healing -- a vendor whose scan dies stays stalest and is retried
    first, with no checkpoint to get stuck on.
    """
    try:
        with DatabaseConnection() as db:
            db.execute_insert(
                """
                ALTER TABLE vendors
                ADD COLUMN IF NOT EXISTS last_full_scan_at TIMESTAMPTZ
                """
            )
            db.execute_insert(
                """
                CREATE INDEX IF NOT EXISTS idx_vendors_last_full_scan_at
                ON vendors (last_full_scan_at ASC NULLS FIRST)
                """
            )
        logger.info("vendors.last_full_scan_at ensured")
        return True
    except Exception as exc:
        logger.error("ensure_vendor_scan_cursor failed: %s", exc)
        return False


def apply_pending_migrations() -> None:
    """Run all auto migrations. Called from FastAPI startup on every deploy."""
    ensure_dashboard_user_permissions()
    ensure_dashboard_roles()
    ensure_vendor_scan_cursor()
