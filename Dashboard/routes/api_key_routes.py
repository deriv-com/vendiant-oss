from fastapi import APIRouter, HTTPException, Request, Body
from typing import Optional, List
from pydantic import BaseModel
import logging
import os
import sys
from datetime import datetime

# Add path for api_layer module imports
api_layer_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'api_layer'))
if api_layer_path not in sys.path:
    sys.path.append(api_layer_path)

# Add path for Dashboard module imports
dashboard_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if dashboard_path not in sys.path:
    sys.path.append(dashboard_path)

# Import API key manager from api_layer
from auth.api_key_manager import APIKeyManager, VALID_SCOPES, validate_finegrained_scopes
from middleware.audit_logger import AuditLogger
from config.settings import get_config

# Import audit service
from audit_service import log_request_action

router = APIRouter()
logger = logging.getLogger(__name__)


def _find_api_key(key_id: int) -> dict:
    """
    Current stored state of an API key, or {} if it cannot be read.

    Audit rows need the key's name and access level *before* a change, so
    revoke/delete/update all look the key up first.
    """
    try:
        if not api_key_manager:
            return {}
        for key in api_key_manager.list_api_keys(include_disabled=True):
            if key.get('id') == key_id:
                return dict(key)
    except Exception as e:
        logger.debug(f"Could not read API key {key_id} for audit: {e}")
    return {}


def _access_detail(group_name, finegrained_scopes) -> dict:
    """
    Describe what an API key is allowed to do.

    An audit row saying only "API key Reporting Bot created" cannot answer the
    question that matters -- how much access was just handed out -- so the
    group and, for finegrained keys, the exact scopes are recorded.
    """
    scopes = [str(s) for s in (finegrained_scopes or []) if str(s or '').strip()]
    detail = {'access_level': group_name or 'read_only'}
    if scopes:
        detail['scopes'] = sorted(scopes)
        detail['scope_count'] = len(scopes)
    return detail


def _expiry_detail(expires_at, expires_days=None) -> dict:
    """Record whether a key is permanent, and when it lapses if not."""
    if expires_at:
        return {'expires_at': str(expires_at)}
    if expires_days:
        return {'expires_in_days': expires_days}
    # A key that never expires is the riskier case; say so explicitly rather
    # than recording a null the log UI would render as nothing.
    return {'validity': 'never expires'}

# Pydantic models for request validation
class CreateAPIKeyRequest(BaseModel):
    name: str
    description: Optional[str] = None
    created_by: Optional[str] = None
    # permission_mode: "group" (read_only/admin) or "finegrained"
    permission_mode: str = "group"
    group_name: Optional[str] = "read_only"
    finegrained_scopes: Optional[List[str]] = None
    expires_days: Optional[int] = None

class RevokeAPIKeyRequest(BaseModel):
    key_id: int
    action: str = "revoke"  # "revoke" or "unrevoke"

class UpdateAPIKeyRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    permission_mode: str  # "group" or "finegrained"
    group_name: Optional[str] = "read_only"
    finegrained_scopes: Optional[List[str]] = None
    access_type: Optional[str] = None   # "temporary" or "permanent"
    expires_days: Optional[int] = None

# Initialize managers
try:
    api_key_manager = APIKeyManager()
    audit_logger = AuditLogger()
    config = get_config()
except Exception as e:
    logger.error(f"Error initializing API key manager: {e}")
    api_key_manager = None
    audit_logger = None
    config = None

@router.get("/api/api-keys/list")
async def list_api_keys(request: Request, include_disabled: bool = False):
    """List all API keys"""
    try:
        if not api_key_manager:
            raise HTTPException(status_code=500, detail="API key manager not initialized")
        
        keys = api_key_manager.list_api_keys(include_disabled=include_disabled)
        
        # Format the response
        formatted_keys = []
        for key in keys:
            formatted_keys.append({
                'id': key['id'],
                'credential_hash': key['credential_hash'][:50] + '...' if len(key['credential_hash']) > 50 else key['credential_hash'],
                'name': key['name'],
                'description': key.get('description', ''),
                'request_limit': key['request_limit'],
                'is_enabled': key['is_enabled'],
                'created_at': key['created_at'].isoformat() if isinstance(key['created_at'], datetime) else key['created_at'],
                'expires_at': key['expires_at'].isoformat() if key.get('expires_at') and isinstance(key['expires_at'], datetime) else key.get('expires_at'),
                'created_by': key.get('created_by', 'Unknown'),
                'group_name': key.get('group_name', 'read_only'),
                'finegrained_scopes': key.get('finegrained_scopes') or [],
                'last_accessed': key['last_accessed'].isoformat() if key.get('last_accessed') and isinstance(key['last_accessed'], datetime) else None
            })
        
        # Audit logging handled by middleware
        
        return {
            'success': True,
            'keys': formatted_keys,
            'count': len(formatted_keys)
        }
        
    except Exception as e:
        logger.error(f"Error listing API keys: {e}")
        raise HTTPException(status_code=500, detail=f"Error listing API keys: {str(e)}")

@router.post("/api/api-keys/create")
async def create_api_key(request: Request, data: CreateAPIKeyRequest = Body(...)):
    """Create a new API key"""
    try:
        if not api_key_manager or not config:
            raise HTTPException(status_code=500, detail="API key manager not initialized")
        
        # Resolve group_name and scopes from permission_mode
        if data.permission_mode == "finegrained":
            if not data.finegrained_scopes:
                raise HTTPException(status_code=400, detail="finegrained_scopes must be a non-empty list for finegrained keys")
            invalid = [s for s in data.finegrained_scopes if s not in VALID_SCOPES]
            if invalid:
                raise HTTPException(status_code=400, detail=f"Invalid scopes: {invalid}")
            try:
                validate_finegrained_scopes(data.finegrained_scopes)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            group_name = "finegrained"
            finegrained_scopes = data.finegrained_scopes
        else:
            group_name = data.group_name or "read_only"
            finegrained_scopes = None

        # Determine request limit based on group
        if group_name == "admin":
            request_limit = config.ADMIN_RATE_LIMIT
        else:
            request_limit = config.READ_ONLY_RATE_LIMIT

        expires_days = data.expires_days

        # Generate the API key
        api_key, credential_id = api_key_manager.generate_api_key(
            name=data.name,
            description=data.description,
            created_by=data.created_by or request.headers.get('X-User-Name', 'system'),
            expires_days=expires_days,
            request_limit=request_limit,
            group_name=group_name,
            finegrained_scopes=finegrained_scopes
        )
        
        log_request_action(
            request,
            action='CREATE',
            resource_type='API Key',
            resource_id=data.name,
            details={
                'api_key_name': data.name,
                'credential_id': credential_id,
                'request_limit': request_limit,
                **_access_detail(group_name, finegrained_scopes),
                **_expiry_detail(None, expires_days),
            },
        )
        
        return {
            'success': True,
            'api_key': api_key,
            'credential_id': credential_id,
            'name': data.name,
            'permission_mode': data.permission_mode,
            'group_name': group_name,
            'finegrained_scopes': finegrained_scopes,
            'expires_days': expires_days,
            'request_limit': request_limit
        }
        
    except Exception as e:
        logger.error(f"Error creating API key: {e}")
        raise HTTPException(status_code=500, detail=f"Error creating API key: {str(e)}")

@router.post("/api/api-keys/revoke")
async def revoke_api_key(request: Request, data: RevokeAPIKeyRequest = Body(...)):
    """Revoke or unrevoke an API key"""
    try:
        if not api_key_manager:
            raise HTTPException(status_code=500, detail="API key manager not initialized")
        
        # Validate action
        if data.action not in ["revoke", "unrevoke"]:
            raise HTTPException(status_code=400, detail="Action must be 'revoke' or 'unrevoke'")
        
        # Read the key first: after revoking we still want to record what it was.
        existing_key = _find_api_key(data.key_id)
        api_key_name = existing_key.get('name')
        
        # Perform the appropriate action
        if data.action == "revoke":
            success = api_key_manager.revoke_api_key(data.key_id)
            action_message = "revoked"
            audit_action = "REVOKED"
        else:  # unrevoke
            success = api_key_manager.unrevoke_api_key(data.key_id)
            action_message = "unrevoked"
            audit_action = "ACTIVATED"
        
        if success:
            log_request_action(
                request,
                action=audit_action,
                resource_type='API Key',
                resource_id=api_key_name or str(data.key_id),
                details={
                    'api_key_name': api_key_name or 'Unknown',
                    'credential_id': data.key_id,
                    'created_by': existing_key.get('created_by'),
                    **_access_detail(
                        existing_key.get('group_name'),
                        existing_key.get('finegrained_scopes'),
                    ),
                },
            )

            return {
                'success': True,
                'message': f'API key {action_message} successfully'
            }
        else:
            if data.action == "revoke":
                error_detail = f"API key {data.key_id} not found or could not be revoked"
            else:
                error_detail = f"API key {data.key_id} not found, already enabled, or expired"
            raise HTTPException(status_code=400, detail=error_detail)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error {data.action}ing API key: {e}")
        raise HTTPException(status_code=500, detail=f"Error {data.action}ing API key: {str(e)}")

@router.delete("/api/api-keys/delete/{key_id}")
async def delete_api_key(request: Request, key_id: int):
    """Permanently delete an API key"""
    try:
        if not api_key_manager:
            raise HTTPException(status_code=500, detail="API key manager not initialized")
        
        # Read the key first; once deleted its name and scopes are unrecoverable.
        existing_key = _find_api_key(key_id)
        api_key_name = existing_key.get('name')
        
        result = api_key_manager.delete_api_key(key_id)
        
        if result:
            log_request_action(
                request,
                action='DELETE',
                resource_type='API Key',
                resource_id=api_key_name or str(key_id),
                details={
                    'api_key_name': api_key_name or 'Unknown',
                    'credential_id': key_id,
                    'created_by': existing_key.get('created_by'),
                    **_access_detail(
                        existing_key.get('group_name'),
                        existing_key.get('finegrained_scopes'),
                    ),
                },
            )

            return {
                'success': True,
                'message': 'API key deleted successfully'
            }
        else:
            raise HTTPException(status_code=404, detail="API key not found")
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting API key: {e}")
        raise HTTPException(status_code=500, detail=f"Error deleting API key: {str(e)}")

@router.get("/api/api-keys/audit-stats")
async def get_audit_stats(request: Request, days: int = 7):
    """Get audit statistics for API key usage"""
    try:
        if not audit_logger:
            raise HTTPException(status_code=500, detail="Audit logger not initialized")
        
        stats = audit_logger.get_audit_stats(days=days)
        
        # Audit logging handled by middleware
        
        return {
            'success': True,
            'stats': stats,
            'days': days
        }
        
    except Exception as e:
        logger.error(f"Error getting audit stats: {e}")
        raise HTTPException(status_code=500, detail=f"Error getting audit stats: {str(e)}")

@router.get("/api/api-keys/scopes")
async def get_available_scopes(request: Request):
    """Return all valid granular scopes for use in the frontend picker."""
    return {
        'success': True,
        'scopes': [
            {'key': key, 'description': desc}
            for key, desc in VALID_SCOPES.items()
        ]
    }


@router.get("/api/api-keys/available-groups")
async def get_available_groups(request: Request):
    """Get list of available permission groups"""
    try:
        if not api_key_manager:
            raise HTTPException(status_code=500, detail="API key manager not initialized")

        # Get groups with descriptions from APIKeyManager
        groups = api_key_manager._get_available_groups()

        return {
            'success': True,
            'groups': groups
        }

    except Exception as e:
        logger.error(f"Error getting available groups: {e}")
        raise HTTPException(status_code=500, detail=f"Error getting available groups: {str(e)}")


@router.put("/api/api-keys/update/{key_id}")
async def update_api_key(request: Request, key_id: int, data: UpdateAPIKeyRequest = Body(...)):
    """Update permissions of an existing API key"""
    try:
        if not api_key_manager:
            raise HTTPException(status_code=500, detail="API key manager not initialized")

        if data.permission_mode == "finegrained":
            if not data.finegrained_scopes:
                raise HTTPException(status_code=400, detail="finegrained_scopes must be non-empty for finegrained keys")
            invalid = [s for s in data.finegrained_scopes if s not in VALID_SCOPES]
            if invalid:
                raise HTTPException(status_code=400, detail=f"Invalid scopes: {invalid}")
            try:
                validate_finegrained_scopes(data.finegrained_scopes)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            group_name = "finegrained"
            finegrained_scopes = data.finegrained_scopes
        else:
            group_name = data.group_name or "read_only"
            finegrained_scopes = None

        # Resolve expiry
        from datetime import timedelta
        clear_expiry = data.access_type == 'permanent'
        expires_at = None
        if data.access_type == 'temporary' and data.expires_days is not None:
            expires_at = datetime.now() + timedelta(days=data.expires_days)

        # Snapshot the current access level so the audit row can show the change
        # rather than just the end state.
        previous_key = _find_api_key(key_id)

        success = api_key_manager.update_api_key_permissions(
            credential_id=key_id,
            group_name=group_name,
            finegrained_scopes=finegrained_scopes,
            name=data.name,
            description=data.description,
            expires_at=expires_at,
            clear_expiry=clear_expiry,
        )

        if not success:
            raise HTTPException(status_code=404, detail=f"API key {key_id} not found")

        # The row must name the key, not just its id, and say what changed.
        old_name = previous_key.get('name')
        key_name = data.name or old_name
        old_group = previous_key.get('group_name')
        old_scopes = {str(sc) for sc in (previous_key.get('finegrained_scopes') or [])}
        new_scopes = {str(sc) for sc in (finegrained_scopes or [])}

        audit_details = {
            'api_key_name': key_name or 'Unknown',
            'credential_id': key_id,
            **_access_detail(group_name, finegrained_scopes),
            **_expiry_detail(expires_at, data.expires_days if not clear_expiry else None),
        }
        if data.name and old_name and data.name != old_name:
            audit_details['renamed_from'] = old_name

        if old_group and old_group != group_name:
            # Switching between a scoped key and a group key: the level change is
            # the story. Reporting the dropped scope list as "revoked" would read
            # as a reduction in access even when the key was escalated to admin.
            audit_details['access_level_was'] = old_group
            if old_scopes and group_name != 'finegrained':
                audit_details['previous_scopes'] = sorted(old_scopes)
        else:
            scopes_added = sorted(new_scopes - old_scopes)
            scopes_removed = sorted(old_scopes - new_scopes)
            if scopes_added:
                audit_details['scopes_added'] = scopes_added
            if scopes_removed:
                audit_details['scopes_removed'] = scopes_removed
        if clear_expiry and previous_key.get('expires_at'):
            audit_details['expiry_cleared_from'] = str(previous_key['expires_at'])

        log_request_action(
            request,
            action='UPDATE',
            resource_type='API Key',
            resource_id=key_name or str(key_id),
            details=audit_details,
        )

        return {'success': True, 'message': 'API key permissions updated successfully'}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating API key {key_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Error updating API key: {str(e)}")

