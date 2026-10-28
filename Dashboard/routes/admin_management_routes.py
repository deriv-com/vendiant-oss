"""
Admin Management — user directory lookup + per-user dashboard permission CRUD.

Endpoints:
  GET  /api/admin/directory/users         — user directory (see Dashboard/user_directory.py)
  GET  /api/admin/permissions             — all rows in dashboard_user_permissions
  GET  /api/admin/permissions/{email}     — single user's record (404 if absent)
  PUT  /api/admin/permissions             — upsert a user's permissions (create or update)
  DELETE /api/admin/permissions/{email}   — clear/deactivate a user's permissions
"""

from __future__ import annotations

import json
import logging
import os
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, field_validator

try:
    from Dashboard.user_directory import list_directory_users
    from Dashboard.db_config import DatabaseConnection
    from Dashboard.db_migrations import ensure_dashboard_user_permissions
    from Dashboard.effective_permissions import invalidate_permission_cache
except ImportError:
    from user_directory import list_directory_users
    from db_config import DatabaseConnection
    from db_migrations import ensure_dashboard_user_permissions
    from effective_permissions import invalidate_permission_cache

router = APIRouter()
logger = logging.getLogger(__name__)


def _require_permissions_table() -> None:
    """Ensure dashboard_user_permissions exists (created on deploy/startup)."""
    if not ensure_dashboard_user_permissions():
        raise HTTPException(
            status_code=503,
            detail="Permissions table is not ready yet; retry in a moment",
        )

VALID_PERMISSIONS = {
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
}

VALID_PRESETS = {"admin", "vendor-management", "user-extended", "user-basic", "custom", None}


# ---------------------------------------------------------------------------
# Auth guard
# ---------------------------------------------------------------------------

# SSO group whose members may use Access Management (must match the
# frontend's NEXT_PUBLIC_SSO_GROUP_ADMIN).
ADMIN_SSO_GROUP = (os.getenv("SSO_GROUP_ADMIN") or "vendiant-admin").strip().lower()


async def require_admin(request: Request) -> None:
    """Only members of the admin SSO group may proceed."""
    role = (request.headers.get("X-User-Role") or "").strip().lower()
    if role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")

    groups_raw = request.headers.get("X-User-Groups") or ""
    groups = [g.strip().lower() for g in groups_raw.split(",") if g.strip()]
    if ADMIN_SSO_GROUP not in groups:
        raise HTTPException(status_code=403, detail="Admin access required")


def _caller_identity(request: Request) -> dict:
    return {
        "email": (request.headers.get("X-User-Email") or "").strip(),
        "name": (request.headers.get("X-User-Name") or "").strip(),
    }


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class PermissionUpsertRequest(BaseModel):
    user_email: str
    user_name: Optional[str] = None
    iam_unique_id: Optional[str] = None
    role_preset: Optional[str] = None
    permissions: list[str]

    @field_validator("permissions")
    @classmethod
    def validate_permissions(cls, v: list[str]) -> list[str]:
        invalid = set(v) - VALID_PERMISSIONS
        if invalid:
            raise ValueError(f"Unknown permission(s): {', '.join(sorted(invalid))}")
        return list(set(v))

    @field_validator("role_preset")
    @classmethod
    def validate_preset(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in VALID_PRESETS:
            raise ValueError(f"Unknown role preset: {v}")
        return v

    @field_validator("user_email")
    @classmethod
    def normalise_email(cls, v: str) -> str:
        v = v.strip().lower()
        if not v or "@" not in v:
            raise ValueError("Invalid email address")
        return v


# ---------------------------------------------------------------------------
# User directory
# ---------------------------------------------------------------------------

@router.get("/api/admin/directory/users")
async def list_directory(_: None = Depends(require_admin)):
    """User directory for the Access Management picker — name and email only."""
    try:
        employees = list_directory_users()
        return {"success": True, "employees": employees, "count": len(employees)}
    except RuntimeError as exc:
        logger.error("Directory list failed: %s", exc)
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        logger.error("Directory list error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Directory list failed") from exc


# ---------------------------------------------------------------------------
# Permission records
# ---------------------------------------------------------------------------

@router.get("/api/admin/permissions")
async def list_permissions(_: None = Depends(require_admin)):
    """Return all active dashboard_user_permissions rows, with last login from audit_logs."""
    _require_permissions_table()
    query = """
        SELECT p.id, p.user_email, p.user_name, p.iam_unique_id, p.role_preset,
               p.permissions, p.is_active, p.assigned_by_email, p.assigned_by_name,
               p.created_at, p.updated_at,
               a.last_login_at
        FROM dashboard_user_permissions p
        LEFT JOIN (
            SELECT LOWER(TRIM(user_email)) AS email_key,
                   MAX(created_at) AS last_login_at
            FROM audit_logs
            WHERE user_email IS NOT NULL AND TRIM(user_email) <> ''
            GROUP BY LOWER(TRIM(user_email))
        ) a ON a.email_key = LOWER(TRIM(p.user_email))
        ORDER BY p.user_name ASC NULLS LAST, p.user_email ASC
    """
    try:
        with DatabaseConnection() as db:
            rows = db.execute_query(query)
        results = []
        for row in (rows or []):
            r = dict(row)
            if isinstance(r.get("permissions"), str):
                r["permissions"] = json.loads(r["permissions"])
            r["created_at"] = str(r["created_at"]) if r.get("created_at") else None
            r["updated_at"] = str(r["updated_at"]) if r.get("updated_at") else None
            r["last_login_at"] = str(r["last_login_at"]) if r.get("last_login_at") else None
            results.append(r)
        return {"success": True, "records": results, "count": len(results)}
    except Exception as exc:
        logger.error("list_permissions error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to list permissions") from exc


@router.get("/api/admin/permissions/{email:path}")
async def get_permission(email: str, _: None = Depends(require_admin)):
    """Return one user's permission record, or 404."""
    _require_permissions_table()
    email = email.strip().lower()
    query = """
        SELECT id, user_email, user_name, iam_unique_id, role_preset,
               permissions, is_active, assigned_by_email, assigned_by_name,
               created_at, updated_at
        FROM dashboard_user_permissions
        WHERE LOWER(TRIM(user_email)) = %s
    """
    try:
        with DatabaseConnection() as db:
            row = db.execute_single_query(query, (email,))
        if not row:
            raise HTTPException(status_code=404, detail="No permission record for this user")
        r = dict(row)
        if isinstance(r.get("permissions"), str):
            r["permissions"] = json.loads(r["permissions"])
        r["created_at"] = str(r["created_at"]) if r.get("created_at") else None
        r["updated_at"] = str(r["updated_at"]) if r.get("updated_at") else None
        return {"success": True, "record": r}
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("get_permission error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to fetch permission") from exc


@router.put("/api/admin/permissions")
async def upsert_permission(
    body: PermissionUpsertRequest,
    request: Request,
    _: None = Depends(require_admin),
):
    """Create or update a user's dashboard permissions. Writes an audit_logs entry."""
    _require_permissions_table()
    caller = _caller_identity(request)

    upsert_query = """
        INSERT INTO dashboard_user_permissions
            (user_email, user_name, iam_unique_id, role_preset, permissions,
             is_active, assigned_by_email, assigned_by_name)
        VALUES (%s, %s, %s, %s, %s::jsonb, TRUE, %s, %s)
        ON CONFLICT (user_email) DO UPDATE SET
            user_name        = EXCLUDED.user_name,
            iam_unique_id    = EXCLUDED.iam_unique_id,
            role_preset      = EXCLUDED.role_preset,
            permissions      = EXCLUDED.permissions,
            is_active        = TRUE,
            assigned_by_email = EXCLUDED.assigned_by_email,
            assigned_by_name = EXCLUDED.assigned_by_name,
            updated_at       = NOW()
    """

    fetch_query = """
        SELECT id, user_email, user_name, role_preset, permissions, is_active,
               assigned_by_email, assigned_by_name, created_at, updated_at
        FROM dashboard_user_permissions
        WHERE LOWER(TRIM(user_email)) = %s
    """

    audit_query = """
        INSERT INTO audit_logs (user_id, user_email, user_name, user_role, action, resource_type, details)
        VALUES (%s, %s, %s, 'admin', 'permission_assign', 'dashboard_user_permissions', %s::jsonb)
    """

    try:
        with DatabaseConnection() as db:
            # execute_insert commits the transaction
            ok = db.execute_insert(
                upsert_query,
                (
                    body.user_email,
                    body.user_name,
                    body.iam_unique_id,
                    body.role_preset,
                    json.dumps(body.permissions),
                    caller["email"],
                    caller["name"],
                ),
            )
            if not ok:
                raise HTTPException(status_code=500, detail="DB write failed")

            audit_details = json.dumps({
                "user": body.user_name or body.user_email,
                "user_email": body.user_email,
                "permissions": body.permissions,
                "role_preset": body.role_preset,
            })
            db.execute_insert(
                audit_query,
                (
                    caller["email"] or "admin",
                    caller["email"],
                    caller["name"],
                    audit_details,
                ),
            )

            # Fetch the saved row to return to the client
            row = db.execute_single_query(fetch_query, (body.user_email.lower(),))

        if not row:
            raise HTTPException(status_code=500, detail="Record saved but could not be retrieved")
        invalidate_permission_cache(body.user_email)
        r = dict(row)
        if isinstance(r.get("permissions"), str):
            r["permissions"] = json.loads(r["permissions"])
        r["created_at"] = str(r["created_at"]) if r.get("created_at") else None
        r["updated_at"] = str(r["updated_at"]) if r.get("updated_at") else None
        return {"success": True, "record": r}
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("upsert_permission error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to save permissions") from exc


@router.delete("/api/admin/permissions/{email:path}")
async def delete_permission(
    email: str,
    request: Request,
    _: None = Depends(require_admin),
):
    """
    Revoke Access Management grants for a user.

    Keeps an *active* row with permissions=[] so SSO role defaults do not
    re-grant access (e.g. view_vendors). Deactivating the row would fall back
    to role defaults and undo the revoke.
    """
    _require_permissions_table()
    email = email.strip().lower()
    caller = _caller_identity(request)

    clear_query = """
        UPDATE dashboard_user_permissions
        SET permissions = '[]'::jsonb,
            role_preset = NULL,
            is_active   = TRUE,
            assigned_by_email = %s,
            assigned_by_name  = %s,
            updated_at  = NOW()
        WHERE LOWER(TRIM(user_email)) = %s
    """
    check_exists_query = """
        SELECT id FROM dashboard_user_permissions WHERE LOWER(TRIM(user_email)) = %s
    """
    audit_query = """
        INSERT INTO audit_logs (user_id, user_email, user_name, user_role, action, resource_type, details)
        VALUES (%s, %s, %s, 'admin', 'permission_clear', 'dashboard_user_permissions', %s::jsonb)
    """
    try:
        with DatabaseConnection() as db:
            exists = db.execute_single_query(check_exists_query, (email,))
            if not exists:
                raise HTTPException(status_code=404, detail="No permission record for this user")
            db.execute_insert(clear_query, (caller["email"], caller["name"], email))
            audit_details = json.dumps({
                "user_email": email,
                "action": "cleared",
            })
            db.execute_insert(
                audit_query,
                (
                    caller["email"] or "admin",
                    caller["email"],
                    caller["name"],
                    audit_details,
                ),
            )
        invalidate_permission_cache(email)
        return {"success": True, "cleared_email": email}
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("delete_permission error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to clear permissions") from exc
