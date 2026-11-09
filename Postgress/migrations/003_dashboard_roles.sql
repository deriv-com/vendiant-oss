-- Migration 003: Dashboard roles (named RBAC roles + user membership)
-- System roles: Admin, Extended, Viewer (is_system=true, not deletable).
-- Custom roles: created via Access Management UI.
--
-- AUTO-APPLIED: Dashboard/db_migrations.py on backend startup.

BEGIN;

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
);

CREATE INDEX IF NOT EXISTS idx_dashboard_roles_system
    ON dashboard_roles (is_system);

-- Link user assignments to a role (permissions stay denormalized for fast reads)
ALTER TABLE dashboard_user_permissions
    ADD COLUMN IF NOT EXISTS role_id INTEGER REFERENCES dashboard_roles(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_dup_role_id
    ON dashboard_user_permissions (role_id);

COMMIT;
