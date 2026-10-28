from fastapi import APIRouter, HTTPException, Request, Query
from typing import Optional
import logging
from api_audit_service import api_audit_service

router = APIRouter()

@router.get('/api/api-audit-logs')
async def get_api_audit_logs(
    request: Request,
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0),
    credential_id: Optional[int] = Query(default=None),
    key_name: Optional[str] = Query(default=None),
    endpoint_filter: Optional[str] = Query(default=None),
    method_filter: Optional[str] = Query(default=None),
    success_filter: Optional[bool] = Query(default=None),
    days_back: Optional[int] = Query(default=30)
):
    """
    Get API audit logs from request_audit_log table with optional filtering
    """
    try:
        # Import here to avoid circular imports
        from api_audit_service import api_audit_service
        
        # Get user info from headers (set by frontend middleware)
        requesting_user_email = request.headers.get('X-User-Email')
        # Note: Frontend RBAC already restricts access to this endpoint
        # No additional role checking needed here
        
        logs = api_audit_service.get_api_audit_logs(
            credential_id=credential_id,
            key_name=key_name,
            endpoint_filter=endpoint_filter,
            method_filter=method_filter,
            success_filter=success_filter,
            limit=limit,
            offset=offset,
            days_back=days_back
        )
        
        total_count = api_audit_service.get_api_audit_logs_count(
            credential_id=credential_id,
            key_name=key_name,
            endpoint_filter=endpoint_filter,
            method_filter=method_filter,
            success_filter=success_filter,
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
        logging.error(f"Error retrieving API audit logs: {e}")
        raise HTTPException(status_code=500, detail=f"Error retrieving API audit logs: {str(e)}")


@router.get('/api/api-audit-logs/stats')
async def get_api_audit_stats(
    request: Request,
    days_back: int = Query(default=30)
):
    """
    Get API audit statistics for the dashboard
    """
    try:
        # Import here to avoid circular imports
        from api_audit_service import api_audit_service
        
        # Note: Frontend RBAC already restricts access to this endpoint
        # No additional role checking needed here
        
        stats = api_audit_service.get_api_audit_stats(days_back=days_back)
        return stats
        
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error retrieving API audit stats: {e}")
        raise HTTPException(status_code=500, detail=f"Error retrieving API audit stats: {str(e)}")