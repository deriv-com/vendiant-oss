from fastapi import APIRouter, HTTPException, Request, Query, Body, Depends
from typing import Optional
import logging
import os
import sys

# Add path for Dashboard module imports
dashboard_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if dashboard_path not in sys.path:
    sys.path.append(dashboard_path)

# Import audit_service from Dashboard module
from audit_service import audit_service, _client_ip

router = APIRouter()

try:
    from Dashboard.effective_permissions import require_permission
except ImportError:
    from effective_permissions import require_permission

# view_audit_logs — admin only (reading the full audit trail)
require_view_audit_logs = require_permission("view_audit_logs")
# view_vendors — the minimum permission held by every SSO-authenticated role;
# used as a "logged-in" gate on the write endpoint (all roles already have it).
require_logged_in = require_permission("view_vendors")

@router.get('/api/audit-logs')
async def get_audit_logs(
    request: Request,
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0),
    action_filter: Optional[str] = Query(default=None),
    resource_type_filter: Optional[str] = Query(default=None),
    days_back: Optional[int] = Query(default=30),
    user_email_filter: Optional[str] = Query(default=None),
    user_name_filter: Optional[str] = Query(default=None),
    _: None = Depends(require_view_audit_logs),
):
    """
    Get audit logs with optional filtering
    """
    try:
        # Get user info from headers (set by frontend middleware)
        requesting_user_email = request.headers.get('X-User-Email')
        
        logs = audit_service.get_user_audit_logs(
            user_email=user_email_filter,
            user_name=user_name_filter,
            limit=limit,
            offset=offset,
            action_filter=action_filter,
            resource_type_filter=resource_type_filter,
            days_back=days_back
        )
        
        total_count = audit_service.get_audit_logs_count(
            user_email=user_email_filter,
            user_name=user_name_filter,
            action_filter=action_filter,
            resource_type_filter=resource_type_filter,
            days_back=days_back
        )
        
        return {
            'logs': logs,
            'total': total_count,
            'limit': limit,
            'offset': offset,
            'has_more': offset + len(logs) < total_count
        }
        
    except Exception as e:
        logging.error(f"Error retrieving audit logs: {e}")
        raise HTTPException(status_code=500, detail="Error retrieving audit logs")


@router.get('/api/audit-logs/stats')
async def get_audit_stats(
    request: Request,
    days_back: int = Query(default=30),
    _: None = Depends(require_view_audit_logs),
):
    """
    Get audit statistics for the dashboard
    """
    try:
        stats = audit_service.get_audit_stats(days_back=days_back)
        return stats
        
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error retrieving audit stats: {e}")
        raise HTTPException(status_code=500, detail="Error retrieving audit stats")


@router.post('/api/audit-logs/log')
async def manual_log_action(
    request: Request,
    data: dict = Body(...),
    _: None = Depends(require_logged_in),
):
    """
    Manually log an action (for frontend-only actions)
    """
    try:
        # Get user info from headers
        user_id = request.headers.get('X-User-ID', 'unknown')
        user_email = request.headers.get('X-User-Email')
        user_name = request.headers.get('X-User-Name')
        user_role = request.headers.get('X-User-Role')
        
        if not user_email:
            raise HTTPException(status_code=400, detail="User email required for audit logging")
        
        # Extract action details from request body
        action = data.get('action')
        resource_type = data.get('resource_type')
        resource_id = data.get('resource_id')
        details = data.get('details', {})
        
        if not action:
            raise HTTPException(status_code=400, detail="Action is required")
        
        # Get client info
        ip_address = _client_ip(request)
        user_agent = request.headers.get('User-Agent')
        
        # Log the action
        success = audit_service.log_action(
            user_id=user_id,
            user_email=user_email,
            action=action,
            user_name=user_name,
            user_role=user_role,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        if success:
            return {'success': True, 'message': 'Action logged successfully'}
        else:
            raise HTTPException(status_code=500, detail="Failed to log action")
            
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error logging manual action: {e}")
        raise HTTPException(status_code=500, detail="Error logging action")