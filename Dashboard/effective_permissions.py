"""
Effective dashboard permissions for the authenticated caller.

Resolution order:
  1. Active row in ``dashboard_user_permissions`` for X-User-Email (Access Management)
  2. Else default permission set for X-User-Role (SSO group mapping)

A user with no row at all is auto-provisioned on first session hydration
(``GET /api/me/permissions``) with the system role matching their SSO role,
falling back to Viewer (view-only). See ``provision_default_assignment``.

Must stay aligned with frontend/lib/rbac.ts ROLE_PERMISSIONS.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

from fastapi import HTTPException, Request

try:
    from Dashboard.db_config import DatabaseConnection
    from Dashboard.db_migrations import ensure_dashboard_roles
except ImportError:
    from db_config import DatabaseConnection
    from db_migrations import ensure_dashboard_roles

logger = logging.getLogger(__name__)

VALID_PERMISSIONS: FrozenSet[str] = frozenset({
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
})

ROLE_DEFAULT_PERMISSIONS: Dict[str, FrozenSet[str]] = {
    "admin": frozenset(VALID_PERMISSIONS),
    "vendor-management": frozenset({
        "view_vendors",
        "manage_vendors",
        "delete_vendors",
        "add_vendors",
        "view_subdomains",
        "add_subdomains",
        "exclude_subdomains",
        "manage_additional_domains",
        "view_vendor_reports",
        "export_vendor_reports",
        "view_certifications",
        "view_incidents",
        "view_pwn_monitor",
    }),
    "user-extended": frozenset({
        "view_vendors",
        "view_subdomains",
        "view_vendor_reports",
        "view_portfolios",
        "view_internal_breaches",
        "view_certifications",
        "view_incidents",
        "view_pwn_monitor",
    }),
    "user-basic": frozenset({
        "view_vendors",
        "view_subdomains",
        "view_vendor_reports",
        "view_portfolios",
        "view_certifications",
        "view_incidents",
        "view_pwn_monitor",
    }),
}

# Role every first-time user falls back to: "Viewer" in dashboard_roles — view only.
DEFAULT_ROLE_SLUG = "user-basic"

# Short TTL cache: email -> (expires_at, has_assignment, permissions, role_preset)
_CACHE: Dict[str, Tuple[float, bool, List[str], Optional[str]]] = {}
_CACHE_TTL_SEC = 30.0
_CACHE_MISS_TTL_SEC = 10.0


def _normalize_permissions(raw: Any) -> List[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            return []
    if not isinstance(raw, list):
        return []
    out: List[str] = []
    seen: Set[str] = set()
    for item in raw:
        perm = str(item or "").strip()
        if not perm or perm not in VALID_PERMISSIONS or perm in seen:
            continue
        seen.add(perm)
        out.append(perm)
    return out


def fetch_active_assignment(email: str) -> Optional[Dict[str, Any]]:
    """
    Return active Access Management assignment for ``email``, or None.

    Cached briefly to avoid a DB round-trip on every request.
    """
    key = (email or "").strip().lower()
    if not key or "@" not in key:
        return None

    now = time.time()
    cached = _CACHE.get(key)
    if cached and cached[0] > now:
        has_assignment, perms, preset = cached[1], cached[2], cached[3]
        if not has_assignment:
            return None
        return {
            "permissions": list(perms),
            "role_preset": preset,
            "has_assignment": True,
        }

    query = """
        SELECT permissions, role_preset, is_active
        FROM dashboard_user_permissions
        WHERE LOWER(TRIM(user_email)) = %s
        LIMIT 1
    """
    try:
        with DatabaseConnection() as db:
            row = db.execute_single_query(query, (key,))
    except Exception as exc:
        logger.warning("fetch_active_assignment DB error for %s: %s", key, exc)
        # Fail closed for assignment lookup — fall back to role defaults (no cache poison)
        return None

    if not row or not row.get("is_active"):
        _CACHE[key] = (now + _CACHE_MISS_TTL_SEC, False, [], None)
        return None

    perms = _normalize_permissions(row.get("permissions"))
    preset = row.get("role_preset")
    if isinstance(preset, str):
        preset = preset.strip() or None
    else:
        preset = None

    _CACHE[key] = (now + _CACHE_TTL_SEC, True, perms, preset)
    return {
        "permissions": perms,
        "role_preset": preset,
        "has_assignment": True,
    }


def invalidate_permission_cache(email: Optional[str] = None) -> None:
    """Drop cached assignment(s). Call after Access Management writes."""
    if email is None:
        _CACHE.clear()
        return
    key = email.strip().lower()
    _CACHE.pop(key, None)


def permissions_for_role(role: str) -> Set[str]:
    return set(ROLE_DEFAULT_PERMISSIONS.get((role or "").strip().lower(), frozenset()))


def effective_permissions_for_request(request: Request) -> Set[str]:
    """Resolved permission set for the current request."""
    email = (request.headers.get("X-User-Email") or "").strip().lower()
    role = (request.headers.get("X-User-Role") or "").strip().lower()

    assignment = fetch_active_assignment(email) if email else None
    if assignment and assignment.get("has_assignment"):
        return set(assignment.get("permissions") or [])

    return permissions_for_role(role)


def request_has_permission(request: Request, permission: str) -> bool:
    return permission in effective_permissions_for_request(request)


def require_permission(*required: str):
    """FastAPI dependency factory: caller must have all listed permissions."""

    async def _dependency(request: Request) -> None:
        granted = effective_permissions_for_request(request)
        missing = [p for p in required if p not in granted]
        if missing:
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions",
            )

    return _dependency


def _default_role_slug_for(role: str) -> str:
    """
    System role a first-time user should be provisioned with.

    Their SSO role decides it, so an admin or vendor manager is not silently
    downgraded on first login. Anything unrecognised (or missing) lands on the
    view-only default.
    """
    slug = (role or "").strip().lower()
    return slug if slug in ROLE_DEFAULT_PERMISSIONS else DEFAULT_ROLE_SLUG


def _audit_default_assignment(
    email: str, name: Optional[str], role: Optional[str], slug: str, permissions: List[str]
) -> None:
    """Record the auto-assignment so Access Management shows where the role came from."""
    try:
        try:
            from Dashboard.audit_service import log_user_action
        except ImportError:
            from audit_service import log_user_action

        log_user_action(
            user_id="system",
            user_email=email,
            user_name=name or email,
            user_role=role or None,
            action="ASSIGN DEFAULT ROLE",
            resource_type="access_role",
            resource_id=slug,
            details={
                "user": name or email,
                "user_email": email,
                "role_preset": slug,
                "permissions": permissions,
                "source": "first_login_default",
            },
        )
    except Exception as exc:  # never fail the request over an audit row
        logger.warning("Default-role audit write failed for %s: %s", email, exc)


def provision_default_assignment(
    email: str,
    role: Optional[str] = None,
    name: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """
    Give a brand-new dashboard user their default role, once.

    Only applies when the user has *no* row in ``dashboard_user_permissions``.
    A row with an empty permission list is a deliberate revoke (see
    ``DELETE /api/admin/permissions/{email}``) and is never re-provisioned.

    Returns the resulting assignment dict, or None when nothing was created.
    """
    key = (email or "").strip().lower()
    if not key or "@" not in key:
        return None
    if not ensure_dashboard_roles():
        return None

    slug = _default_role_slug_for(role or "")
    try:
        with DatabaseConnection() as db:
            existing = db.execute_single_query(
                """
                SELECT id FROM dashboard_user_permissions
                WHERE LOWER(TRIM(user_email)) = %s
                LIMIT 1
                """,
                (key,),
            )
            if existing:
                return None

            role_row = db.execute_single_query(
                "SELECT id, permissions FROM dashboard_roles WHERE slug = %s",
                (slug,),
            )
            if role_row:
                role_id = role_row["id"]
                permissions = _normalize_permissions(role_row.get("permissions"))
            else:
                # No named role for this SSO role (e.g. vendor-management):
                # keep the role's default permissions, unlinked.
                role_id = None
                permissions = sorted(permissions_for_role(slug))

            inserted = db.execute_insert(
                """
                INSERT INTO dashboard_user_permissions
                    (user_email, user_name, role_preset, permissions, is_active,
                     assigned_by_email, assigned_by_name, role_id)
                VALUES (%s, %s, %s, %s::jsonb, TRUE, %s, %s, %s)
                ON CONFLICT (user_email) DO NOTHING
                """,
                (
                    key,
                    (name or "").strip() or None,
                    slug,
                    json.dumps(permissions),
                    "system",
                    "Automatic provisioning",
                    role_id,
                ),
            )
            if not inserted:
                return None
    except Exception as exc:
        logger.warning("provision_default_assignment failed for %s: %s", key, exc)
        return None

    invalidate_permission_cache(key)
    assignment = fetch_active_assignment(key)
    if not assignment:
        # Lost a race (row created concurrently) or the row is inactive — no audit.
        return None

    _audit_default_assignment(key, name, role, slug, assignment.get("permissions") or [])
    logger.info("Provisioned default role '%s' for new dashboard user %s", slug, key)
    return assignment


def me_permissions_payload(request: Request) -> Dict[str, Any]:
    """Payload for GET /api/me/permissions (frontend session hydration)."""
    email = (request.headers.get("X-User-Email") or "").strip().lower()
    role = (request.headers.get("X-User-Role") or "").strip().lower()
    name = (request.headers.get("X-User-Name") or "").strip()
    assignment = fetch_active_assignment(email) if email else None

    # First time this user reaches the dashboard: give them their default role
    # so they show up in Access Management with an explicit (view-only) grant.
    if not assignment and email:
        assignment = provision_default_assignment(email, role=role, name=name)

    if assignment and assignment.get("has_assignment"):
        perms = list(assignment.get("permissions") or [])
        return {
            "success": True,
            "has_assignment": True,
            "source": "assignment",
            "role": role or None,
            "role_preset": assignment.get("role_preset"),
            "permissions": perms,
        }

    perms = sorted(permissions_for_role(role))
    return {
        "success": True,
        "has_assignment": False,
        "source": "role_default",
        "role": role or None,
        "role_preset": role or None,
        "permissions": perms,
    }
