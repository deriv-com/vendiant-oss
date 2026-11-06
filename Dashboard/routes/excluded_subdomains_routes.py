from fastapi import APIRouter, HTTPException, Request, Query, Body, Depends
from typing import Optional
import logging

# Import required functions from db_service
from db_service import (
    get_excluded_subdomains_for_vendor,
    add_subdomain_to_exclusion_list,
    remove_subdomain_from_exclusion_list,
    get_vendor_by_id
)

# Import cache invalidation function from shared_config to avoid circular imports
from shared_config import invalidate_subdomain_cache

router = APIRouter()

try:
    from Dashboard.effective_permissions import require_permission
except ImportError:
    from effective_permissions import require_permission

require_view_subdomains    = require_permission("view_subdomains")
require_exclude_subdomains = require_permission("view_subdomains", "exclude_subdomains")

@router.get('/api/vendors/{vendor_id}/excluded-subdomains')
async def get_excluded_subdomains_api(vendor_id: int, _: None = Depends(require_view_subdomains)):
    """Get all excluded subdomains for a vendor"""
    try:
        result = get_excluded_subdomains_for_vendor(vendor_id)
        
        if result['success']:
            return result
        else:
            raise HTTPException(status_code=400, detail=result.get('error', 'Failed to get excluded subdomains'))
            
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error retrieving excluded subdomains for vendor {vendor_id}: {e}")
        raise HTTPException(status_code=500, detail='Internal server error')

@router.post('/api/vendors/{vendor_id}/excluded-subdomains')
async def add_excluded_subdomain_api(
    vendor_id: int,
    data: dict = Body(...),
    _: None = Depends(require_exclude_subdomains),
):
    """Add a subdomain to the exclusion list"""
    try:
        subdomain = data.get('subdomain', '').strip()
        
        if not subdomain:
            raise HTTPException(status_code=400, detail='Subdomain is required')
        
        # Add to exclusion list
        result = add_subdomain_to_exclusion_list(vendor_id, subdomain)
        
        if result['success']:
            # Invalidate subdomain cache to reflect changes
            vendor = get_vendor_by_id(vendor_id)
            if vendor:
                invalidate_subdomain_cache(vendor['domain'])
            
            return result
        else:
            raise HTTPException(status_code=400, detail=result.get('error', 'Failed to add excluded subdomain'))
            
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error adding excluded subdomain for vendor {vendor_id}: {e}")
        raise HTTPException(status_code=500, detail='Internal server error')

@router.delete('/api/vendors/{vendor_id}/excluded-subdomains/{subdomain}')
async def remove_excluded_subdomain_api(
    vendor_id: int,
    subdomain: str,
    _: None = Depends(require_exclude_subdomains),
):
    """Remove a subdomain from the exclusion list"""
    try:
        if not subdomain or not subdomain.strip():
            raise HTTPException(status_code=400, detail='Subdomain cannot be empty')
        
        subdomain = subdomain.strip()
        
        # Remove from exclusion list
        result = remove_subdomain_from_exclusion_list(vendor_id, subdomain)
        
        if result['success']:
            # Invalidate subdomain cache to reflect changes
            vendor = get_vendor_by_id(vendor_id)
            if vendor:
                invalidate_subdomain_cache(vendor['domain'])
            
            return result
        else:
            raise HTTPException(status_code=400, detail=result.get('error', 'Failed to remove excluded subdomain'))
            
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error removing excluded subdomain {subdomain} for vendor {vendor_id}: {e}")
        raise HTTPException(status_code=500, detail='Internal server error')