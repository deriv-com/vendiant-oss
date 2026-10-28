from fastapi import APIRouter, HTTPException, Request, Query, Body
from typing import Optional
import logging
import os
import sys

# Add path for db_service import
dashboard_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if dashboard_path not in sys.path:
    sys.path.append(dashboard_path)

# Import get_vendor_by_id function
from db_service import get_vendor_by_id

pawned_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'pawned'))
if pawned_path not in sys.path:
    sys.path.append(pawned_path)
try:
    from pawn_check import HaveIBeenPwnedChecker
    logging.info("Successfully imported HaveIBeenPwnedChecker")
except ImportError as e:
    logging.warning(f"Could not import breach checker: {e}")
    HaveIBeenPwnedChecker = None

# Create router instance
router = APIRouter()

@router.get('/api/breaches/check')  
async def check_vendor_breaches():
    """
    API endpoint to check for breaches affecting vendors
    Fetches latest Have I Been Pwned data and compares with vendor database
    """
    try:
        if not HaveIBeenPwnedChecker:
            raise HTTPException(
                status_code=500,
                detail='Breach checker not available'
            )
        
        # Initialize breach checker and run check
        checker = HaveIBeenPwnedChecker()
        results = checker.check_breaches()
        
        # Format response for frontend
        response = {
            'status': 'success' if results['success'] else 'error',
            'message': results.get('error', 'Breach check completed'),
            'data': {
                'total_breaches': results.get('total_breaches', 0),
                'total_vendors': results.get('total_vendors', 0),
                'matches_found': len(results.get('matches', [])),
                'matches': results.get('matches', []),
                'last_checked': results.get('last_checked'),
                'summary': ""
            }
        }
        
        # Log the check
        logging.info(f"Breach check completed: {len(results.get('matches', []))} matches found")
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error in breach check API: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f'Internal server error: {str(e)}'
        )

@router.get('/api/breaches/matches/{vendor_id}')
async def get_vendor_breach_matches(vendor_id: int):
    """
    API endpoint to get breach matches for a specific vendor
    """
    try:
        if not HaveIBeenPwnedChecker:
            raise HTTPException(
                status_code=500,
                detail='Breach checker not available'
            )
        
        # Get vendor info first
        vendor = get_vendor_by_id(vendor_id)
        if not vendor:
            raise HTTPException(
                status_code=404,
                detail=f'Vendor with ID {vendor_id} not found'
            )
        
        # Run breach check and filter for this vendor
        checker = HaveIBeenPwnedChecker()
        results = checker.check_breaches()
        
        if not results['success']:
            raise HTTPException(
                status_code=500,
                detail=results.get('error', 'Failed to check breaches')
            )
        
        # Filter matches for this specific vendor
        vendor_matches = [
            match for match in results.get('matches', [])
            if match['vendor']['id'] == vendor_id
        ]
        
        return {
            'status': 'success',
            'vendor': {
                'id': vendor['id'],
                'name': vendor['vendor_name'],
                'domain': vendor['domain']
            },
            'matches_found': len(vendor_matches),
            'matches': vendor_matches,
            'last_checked': results.get('last_checked')
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error getting vendor breach matches: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f'Internal server error: {str(e)}'
        )
