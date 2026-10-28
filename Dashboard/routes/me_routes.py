"""
Current-user session endpoints (no admin required).

  GET /api/me/permissions — effective permissions for the caller
"""

from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, HTTPException, Request

try:
    from Dashboard.effective_permissions import me_permissions_payload
except ImportError:
    from effective_permissions import me_permissions_payload

router = APIRouter(prefix="/api/me", tags=["me"])


@router.get("/permissions")
async def get_my_permissions(request: Request) -> Dict[str, Any]:
    """
    Return effective permissions for the authenticated dashboard user.

    Identity comes from proxy-injected X-User-* headers. When Access Management
    has an active assignment for the email, that permission list is used;
    otherwise SSO role defaults apply.
    """
    email = (request.headers.get("X-User-Email") or "").strip()
    if not email:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return me_permissions_payload(request)
