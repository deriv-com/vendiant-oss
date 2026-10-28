-- Migration 002: Dashboard user permissions (per-user entity RBAC)
-- Stores which dashboard users have which permissions.
-- Separate from SSO groups (login) and from access_groups (API keys).
--
-- AUTO-APPLIED: Dashboard/db_migrations.py runs this on backend pod startup
-- after QA/prod Cloud Deploy (via cloud-sql-proxy sidecar). No manual psql.
--
-- Audit: do NOT use a separate audit table — write assign/update/clear events
-- to existing audit_logs with details:
--   { "user": "<name>", "user_email": "<email>", "permissions": [...], "role_preset": "<preset|null>" }
--
-- Rollback:
--   DROP TABLE IF EXISTS dashboard_user_permissions;

BEGIN;

CREATE TABLE IF NOT EXISTS dashboard_user_permissions (
    id                SERIAL PRIMARY KEY,

    user_email        TEXT NOT NULL,
    user_name         TEXT,
    iam_unique_id     TEXT,

    -- Optional UI preset label (e.g. admin, vendor-management); gates use permissions
    role_preset       TEXT,

    -- Source of truth for dashboard entity access (Permission strings from rbac.ts)
    permissions       JSONB NOT NULL DEFAULT '[]'::jsonb
                      CHECK (jsonb_typeof(permissions) = 'array'),

    is_active         BOOLEAN NOT NULL DEFAULT TRUE,

    assigned_by_email TEXT,
    assigned_by_name  TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT dashboard_user_permissions_email_unique UNIQUE (user_email)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_dup_email_lower
    ON dashboard_user_permissions (LOWER(TRIM(user_email)));

CREATE INDEX IF NOT EXISTS idx_dup_permissions_gin
    ON dashboard_user_permissions USING GIN (permissions);

CREATE INDEX IF NOT EXISTS idx_dup_active
    ON dashboard_user_permissions (is_active)
    WHERE is_active = TRUE;

COMMENT ON TABLE dashboard_user_permissions IS
    'Per-user dashboard RBAC permissions. Assignment changes are logged to audit_logs.';
COMMENT ON COLUMN dashboard_user_permissions.permissions IS
    'JSONB array of Permission strings (e.g. manage_vendors, add_vendors).';
COMMENT ON COLUMN dashboard_user_permissions.role_preset IS
    'Optional preset label for UI; not the source of truth for permission checks.';

COMMIT;
