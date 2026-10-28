"""
Access Management — named roles CRUD + member assignment.

Endpoints:
  GET    /api/admin/roles
  POST   /api/admin/roles
  PUT    /api/admin/roles/{role_id}
  DELETE /api/admin/roles/{role_id}
  PUT    /api/admin/roles/{role_id}/members
"""

from __future__ import annotations

import json
import logging
import re
import secrets
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, field_validator

try:
    from Dashboard.audit_service import log_request_action
    from Dashboard.db_config import DatabaseConnection
    from Dashboard.db_migrations import ensure_dashboard_roles
    from Dashboard.effective_permissions import (
        VALID_PERMISSIONS,
        invalidate_permission_cache,
        require_permission,
    )
    from Dashboard.routes.admin_management_routes import require_admin
except ImportError:
    from audit_service import log_request_action
    from db_config import DatabaseConnection
    from db_migrations import ensure_dashboard_roles
    from effective_permissions import (
        VALID_PERMISSIONS,
        invalidate_permission_cache,
        require_permission,
    )
    from routes.admin_management_routes import require_admin

router = APIRouter()
logger = logging.getLogger(__name__)

# Mutations require write-level Access Management; listing is SSO-admin + view.
require_manage_roles = require_permission("manage_access_management")


def _require_roles_table() -> None:
    if not ensure_dashboard_roles():
        raise HTTPException(
            status_code=503,
            detail="Roles table is not ready yet; retry in a moment",
        )


def _caller_identity(request: Request) -> dict:
    return {
        "email": (request.headers.get("X-User-Email") or "").strip(),
        "name": (request.headers.get("X-User-Name") or "").strip(),
    }


def _describe_user(email: str, name: Optional[str]) -> str:
    """
    Identify the person an action was performed on.

    Audit rows must say *who* was affected, not just how many, so members are
    recorded as "Alice Smith (alice@example.com)" -- readable in the log list
    and still greppable by email.
    """
    email = (email or "").strip().lower()
    name = (name or "").strip()
    return f"{name} ({email})" if name and name.lower() != email else email


def _slugify(name: str) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", name.strip().lower()).strip("-") or "role"
    return f"{base}-{secrets.token_hex(3)}"


def _parse_permissions(raw) -> list[str]:
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            return []
    if not isinstance(raw, list):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for item in raw:
        perm = str(item or "").strip()
        if not perm or perm not in VALID_PERMISSIONS or perm in seen:
            continue
        seen.add(perm)
        out.append(perm)
    return out


def _serialize_role(row: dict, members: Optional[list] = None) -> dict:
    perms = row.get("permissions")
    if isinstance(perms, str):
        perms = json.loads(perms)
    return {
        "id": row["id"],
        "name": row["name"],
        "slug": row["slug"],
        "is_system": bool(row.get("is_system")),
        "permissions": perms if isinstance(perms, list) else [],
        "member_count": int(row.get("member_count") or 0),
        "members": members if members is not None else [],
        "created_by_email": row.get("created_by_email"),
        "created_by_name": row.get("created_by_name"),
        "created_at": str(row["created_at"]) if row.get("created_at") else None,
        "updated_at": str(row["updated_at"]) if row.get("updated_at") else None,
    }


class RoleCreateRequest(BaseModel):
    name: str
    permissions: list[str] = []

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        v = (v or "").strip()
        if len(v) < 2 or len(v) > 80:
            raise ValueError("Role name must be 2–80 characters")
        return v

    @field_validator("permissions")
    @classmethod
    def validate_permissions(cls, v: list[str]) -> list[str]:
        invalid = set(v) - set(VALID_PERMISSIONS)
        if invalid:
            raise ValueError(f"Unknown permission(s): {', '.join(sorted(invalid))}")
        return list(set(v))


class RoleUpdateRequest(BaseModel):
    name: Optional[str] = None
    permissions: Optional[list[str]] = None

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        v = v.strip()
        if len(v) < 2 or len(v) > 80:
            raise ValueError("Role name must be 2–80 characters")
        return v

    @field_validator("permissions")
    @classmethod
    def validate_permissions(cls, v: Optional[list[str]]) -> Optional[list[str]]:
        if v is None:
            return v
        invalid = set(v) - set(VALID_PERMISSIONS)
        if invalid:
            raise ValueError(f"Unknown permission(s): {', '.join(sorted(invalid))}")
        return list(set(v))


class RoleMember(BaseModel):
    email: str
    name: Optional[str] = None

    @field_validator("email")
    @classmethod
    def normalise_email(cls, v: str) -> str:
        v = v.strip().lower()
        if not v or "@" not in v:
            raise ValueError("Invalid email address")
        return v


class RoleMembersRequest(BaseModel):
    members: list[RoleMember]


def _fetch_role_members(db, role_id: int) -> list[dict]:
    rows = db.execute_query(
        """
        SELECT user_email, user_name, is_active, updated_at
        FROM dashboard_user_permissions
        WHERE role_id = %s AND is_active = TRUE
        ORDER BY user_name ASC NULLS LAST, user_email ASC
        """,
        (role_id,),
    )
    return [
        {
            "email": r["user_email"],
            "name": r.get("user_name"),
            "updated_at": str(r["updated_at"]) if r.get("updated_at") else None,
        }
        for r in (rows or [])
    ]


def _get_role_row(db, role_id: int) -> Optional[dict]:
    return db.execute_single_query(
        """
        SELECT r.id, r.name, r.slug, r.is_system, r.permissions,
               r.created_by_email, r.created_by_name, r.created_at, r.updated_at,
               (
                 SELECT COUNT(*) FROM dashboard_user_permissions p
                 WHERE p.role_id = r.id AND p.is_active = TRUE
               ) AS member_count
        FROM dashboard_roles r
        WHERE r.id = %s
        """,
        (role_id,),
    )


@router.get("/api/admin/roles")
async def list_roles(_: None = Depends(require_admin)):
    """List all roles with member counts."""
    _require_roles_table()
    query = """
        SELECT r.id, r.name, r.slug, r.is_system, r.permissions,
               r.created_by_email, r.created_by_name, r.created_at, r.updated_at,
               (
                 SELECT COUNT(*) FROM dashboard_user_permissions p
                 WHERE p.role_id = r.id AND p.is_active = TRUE
               ) AS member_count
        FROM dashboard_roles r
        ORDER BY r.is_system DESC, r.name ASC
    """
    try:
        with DatabaseConnection() as db:
            rows = db.execute_query(query) or []
            results = []
            for row in rows:
                members = _fetch_role_members(db, row["id"])
                results.append(_serialize_role(dict(row), members))
        return {"success": True, "roles": results, "count": len(results)}
    except Exception as exc:
        logger.error("list_roles error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to list roles") from exc


@router.post("/api/admin/roles")
async def create_role(
    body: RoleCreateRequest,
    request: Request,
    _: None = Depends(require_admin),
    __: None = Depends(require_manage_roles),
):
    """Create a custom (non-system) role."""
    _require_roles_table()
    caller = _caller_identity(request)
    slug = _slugify(body.name)
    try:
        with DatabaseConnection() as db:
            existing = db.execute_single_query(
                "SELECT id FROM dashboard_roles WHERE LOWER(TRIM(name)) = %s",
                (body.name.lower(),),
            )
            if existing:
                raise HTTPException(status_code=409, detail="A role with this name already exists")
            ok = db.execute_insert(
                """
                INSERT INTO dashboard_roles
                    (name, slug, is_system, permissions, created_by_email, created_by_name)
                VALUES (%s, %s, FALSE, %s::jsonb, %s, %s)
                """,
                (
                    body.name,
                    slug,
                    json.dumps(body.permissions),
                    caller["email"],
                    caller["name"],
                ),
            )
            if not ok:
                raise HTTPException(status_code=500, detail="Failed to create role")
            row = db.execute_single_query(
                "SELECT * FROM dashboard_roles WHERE slug = %s",
                (slug,),
            )
            # member_count for serialize
            row = dict(row)
            row["member_count"] = 0
        log_request_action(
            request,
            action="CREATE",
            resource_type="access_role",
            resource_id=body.name,
            details={
                "role_name": body.name,
                "permissions_granted": sorted(body.permissions),
                "permission_count": len(body.permissions),
            },
        )
        return {"success": True, "role": _serialize_role(row, [])}
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("create_role error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to create role") from exc


@router.put("/api/admin/roles/{role_id}")
async def update_role(
    role_id: int,
    body: RoleUpdateRequest,
    request: Request,
    _: None = Depends(require_admin),
    __: None = Depends(require_manage_roles),
):
    """Update role name and/or permissions. Syncs member permission snapshots."""
    _require_roles_table()
    if body.name is None and body.permissions is None:
        raise HTTPException(status_code=400, detail="Nothing to update")
    try:
        with DatabaseConnection() as db:
            current = _get_role_row(db, role_id)
            if not current:
                raise HTTPException(status_code=404, detail="Role not found")

            new_name = body.name if body.name is not None else current["name"]
            # System roles keep fixed names (Admin / Extended / Viewer)
            if current.get("is_system") and body.name is not None and body.name != current["name"]:
                raise HTTPException(status_code=400, detail="System role names cannot be changed")

            new_perms = (
                body.permissions
                if body.permissions is not None
                else _parse_permissions(current.get("permissions"))
            )

            if body.name is not None:
                clash = db.execute_single_query(
                    """
                    SELECT id FROM dashboard_roles
                    WHERE LOWER(TRIM(name)) = %s AND id <> %s
                    """,
                    (new_name.lower(), role_id),
                )
                if clash:
                    raise HTTPException(status_code=409, detail="A role with this name already exists")

            db.execute_insert(
                """
                UPDATE dashboard_roles
                SET name = %s,
                    permissions = %s::jsonb,
                    updated_at = NOW()
                WHERE id = %s
                """,
                (new_name, json.dumps(new_perms), role_id),
            )

            # Sync denormalized permissions for all members of this role
            members = db.execute_query(
                """
                SELECT user_email FROM dashboard_user_permissions
                WHERE role_id = %s AND is_active = TRUE
                """,
                (role_id,),
            ) or []
            for m in members:
                db.execute_insert(
                    """
                    UPDATE dashboard_user_permissions
                    SET permissions = %s::jsonb,
                        role_preset = %s,
                        updated_at = NOW()
                    WHERE LOWER(TRIM(user_email)) = %s
                    """,
                    (
                        json.dumps(new_perms),
                        current["slug"] if current.get("is_system") else "custom",
                        m["user_email"].strip().lower(),
                    ),
                )
                invalidate_permission_cache(m["user_email"])

            row = _get_role_row(db, role_id)
            member_list = _fetch_role_members(db, role_id)

        old_perms = set(_parse_permissions(current.get("permissions")))
        added = sorted(set(new_perms) - old_perms)
        removed = sorted(old_perms - set(new_perms))
        renamed = body.name is not None and new_name != current["name"]
        # The dashboard PUTs the role's current name and permissions whenever it
        # saves, so a no-op update is the common case; only record real changes.
        if renamed or added or removed:
            audit_details = {
                "role_name": new_name,
                "members_synced": len(members),
            }
            if renamed:
                audit_details["renamed_from"] = current["name"]
            if added:
                audit_details["permissions_added"] = added
            if removed:
                audit_details["permissions_removed"] = removed
            log_request_action(
                request,
                action="UPDATE",
                resource_type="access_role",
                resource_id=new_name,
                details=audit_details,
            )
        return {"success": True, "role": _serialize_role(dict(row), member_list)}
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("update_role error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to update role") from exc


@router.delete("/api/admin/roles/{role_id}")
async def delete_role(
    role_id: int,
    request: Request,
    _: None = Depends(require_admin),
    __: None = Depends(require_manage_roles),
):
    """Delete a custom role. System roles cannot be deleted."""
    _require_roles_table()
    try:
        with DatabaseConnection() as db:
            current = _get_role_row(db, role_id)
            if not current:
                raise HTTPException(status_code=404, detail="Role not found")
            if current.get("is_system"):
                raise HTTPException(status_code=400, detail="System roles cannot be deleted")

            members = db.execute_query(
                """
                SELECT user_email, user_name FROM dashboard_user_permissions
                WHERE role_id = %s
                """,
                (role_id,),
            ) or []

            # Clear members to empty active assignment (deny), then drop role
            for m in members:
                email = m["user_email"].strip().lower()
                db.execute_insert(
                    """
                    UPDATE dashboard_user_permissions
                    SET role_id = NULL,
                        permissions = '[]'::jsonb,
                        role_preset = NULL,
                        is_active = TRUE,
                        updated_at = NOW()
                    WHERE LOWER(TRIM(user_email)) = %s
                    """,
                    (email,),
                )
                invalidate_permission_cache(email)

            db.execute_insert("DELETE FROM dashboard_roles WHERE id = %s", (role_id,))

        unassigned = sorted(
            _describe_user(m["user_email"], m.get("user_name")) for m in members
        )
        log_request_action(
            request,
            action="DELETE",
            resource_type="access_role",
            resource_id=current["name"],
            details={
                "role_name": current["name"],
                "permissions_removed": sorted(_parse_permissions(current.get("permissions"))),
                "members_unassigned": unassigned,
                "member_count": len(unassigned),
            },
        )
        return {"success": True, "deleted_id": role_id}
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("delete_role error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to delete role") from exc


@router.put("/api/admin/roles/{role_id}/members")
async def set_role_members(
    role_id: int,
    body: RoleMembersRequest,
    request: Request,
    _: None = Depends(require_admin),
    __: None = Depends(require_manage_roles),
):
    """Replace the set of users assigned to this role."""
    _require_roles_table()
    caller = _caller_identity(request)
    try:
        with DatabaseConnection() as db:
            current = _get_role_row(db, role_id)
            if not current:
                raise HTTPException(status_code=404, detail="Role not found")

            perms = _parse_permissions(current.get("permissions"))
            preset = current["slug"] if current.get("is_system") else "custom"
            wanted = {m.email: m.name for m in body.members}

            existing = db.execute_query(
                """
                SELECT user_email, user_name FROM dashboard_user_permissions
                WHERE role_id = %s
                """,
                (role_id,),
            ) or []
            existing_emails = {r["user_email"].strip().lower() for r in existing}
            # Names of current members, so a removal can say who was removed.
            existing_names = {
                r["user_email"].strip().lower(): (r.get("user_name") or "").strip()
                for r in existing
            }

            # Remove users no longer in the role
            for email in existing_emails - set(wanted.keys()):
                db.execute_insert(
                    """
                    UPDATE dashboard_user_permissions
                    SET role_id = NULL,
                        permissions = '[]'::jsonb,
                        role_preset = NULL,
                        is_active = TRUE,
                        assigned_by_email = %s,
                        assigned_by_name = %s,
                        updated_at = NOW()
                    WHERE LOWER(TRIM(user_email)) = %s
                    """,
                    (caller["email"], caller["name"], email),
                )
                invalidate_permission_cache(email)

            # Upsert wanted members onto this role
            for email, name in wanted.items():
                db.execute_insert(
                    """
                    INSERT INTO dashboard_user_permissions
                        (user_email, user_name, role_preset, permissions,
                         is_active, assigned_by_email, assigned_by_name, role_id)
                    VALUES (%s, %s, %s, %s::jsonb, TRUE, %s, %s, %s)
                    ON CONFLICT (user_email) DO UPDATE SET
                        user_name = EXCLUDED.user_name,
                        role_preset = EXCLUDED.role_preset,
                        permissions = EXCLUDED.permissions,
                        is_active = TRUE,
                        assigned_by_email = EXCLUDED.assigned_by_email,
                        assigned_by_name = EXCLUDED.assigned_by_name,
                        role_id = EXCLUDED.role_id,
                        updated_at = NOW()
                    """,
                    (
                        email,
                        name,
                        preset,
                        json.dumps(perms),
                        caller["email"],
                        caller["name"],
                        role_id,
                    ),
                )
                invalidate_permission_cache(email)

            row = _get_role_row(db, role_id)
            member_list = _fetch_role_members(db, role_id)

        added = sorted(set(wanted.keys()) - existing_emails)
        removed = sorted(existing_emails - set(wanted.keys()))
        # Saving a role re-submits its whole member list, so most calls change
        # nothing. An audit row for an unchanged list says nothing and buries
        # the rows that do matter.
        if added or removed:
            audit_details = {
                "role_name": current["name"],
                "member_count": len(wanted),
            }
            if added:
                audit_details["members_added"] = [
                    _describe_user(email, wanted.get(email)) for email in added
                ]
            if removed:
                audit_details["members_removed"] = [
                    _describe_user(email, existing_names.get(email)) for email in removed
                ]
            log_request_action(
                request,
                action="UPDATE MEMBERS",
                resource_type="access_role",
                resource_id=current["name"],
                details=audit_details,
            )
        return {"success": True, "role": _serialize_role(dict(row), member_list)}
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("set_role_members error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to update role members") from exc
