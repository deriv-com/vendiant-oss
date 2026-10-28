from fastapi import APIRouter, HTTPException, Request, Body
from typing import Optional
import logging
import os
import sys
import re
from datetime import datetime

# Add path for Dashboard module imports
dashboard_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if dashboard_path not in sys.path:
    sys.path.append(dashboard_path)

# Import required functions from db_service and cache_service
from db_service import get_vendor_by_id
from cache_service import invalidate_vendors_cache
from audit_service import audit_service, _client_ip

router = APIRouter()

def update_vendor_in_database(vendor_id, vendor_name, domain, tier, portfolio, industry):
    """Update vendor information in the database
    
    Args:
        vendor_id: The ID of the vendor to update
        vendor_name: The updated name of the vendor
        domain: The updated domain of the vendor
        tier: The updated tier of the vendor
        portfolio: The updated portfolio of the vendor
        industry: The updated industry of the vendor
    
    Returns:
        dict: Result with success status and updated vendor data or error message
    """
    try:
        from db_config import DatabaseConnection
        
        with DatabaseConnection() as db:
            # Check if vendor exists
            check_query = "SELECT id, vendor_name, domain FROM vendors WHERE id = %s"
            existing_vendor = db.execute_single_query(check_query, (vendor_id,))
            
            if not existing_vendor:
                return {
                    'success': False,
                    'error': f'Vendor with ID {vendor_id} not found'
                }
            
            # Check if domain is being changed and if new domain already exists
            if existing_vendor['domain'] != domain:
                domain_check_query = "SELECT id, vendor_name FROM vendors WHERE domain = %s AND id != %s"
                existing_domain = db.execute_single_query(domain_check_query, (domain, vendor_id))
                
                if existing_domain:
                    return {
                        'success': False,
                        'error': f'Domain {domain} is already used by vendor "{existing_domain["vendor_name"]}"'
                    }
            
            # Check if vendor name is being changed and if new name already exists
            if existing_vendor['vendor_name'] != vendor_name:
                name_check_query = "SELECT id, domain FROM vendors WHERE LOWER(vendor_name) = LOWER(%s) AND id != %s"
                existing_name = db.execute_single_query(name_check_query, (vendor_name, vendor_id))
                
                if existing_name:
                    return {
                        'success': False,
                        'error': f'Vendor name "{vendor_name}" is already used by domain "{existing_name["domain"]}"'
                    }
            
            # Update vendor information
            update_query = """
            UPDATE vendors 
            SET vendor_name = %s, 
                domain = %s, 
                tier = %s, 
                portfolio = %s, 
                industry = %s
            WHERE id = %s
            """
            
            success = db.execute_insert(update_query, (vendor_name, domain, tier, portfolio, industry, vendor_id))
            
            if success:
                # Get updated vendor information
                updated_vendor_query = """
                SELECT id, vendor_name, domain, tier, portfolio, industry, 
                       overall_score_current, grade, added_at
                FROM vendors 
                WHERE id = %s
                """
                updated_vendor = db.execute_single_query(updated_vendor_query, (vendor_id,))
                
                logging.info(f"Successfully updated vendor ID {vendor_id}: {vendor_name} ({domain})")
                
                return {
                    'success': True,
                    'message': f'Vendor "{vendor_name}" updated successfully',
                    'vendor': {
                        'id': updated_vendor['id'],
                        'name': updated_vendor['vendor_name'],
                        'domain': updated_vendor['domain'],
                        'tier': updated_vendor['tier'],
                        'portfolio': updated_vendor['portfolio'],
                        'industry': updated_vendor['industry'],
                        'securityScore': updated_vendor['overall_score_current'] or 0,
                        'grade': updated_vendor['grade'],
                        'added_at': updated_vendor['added_at'].isoformat() if updated_vendor['added_at'] else None
                    }
                }
            else:
                return {
                    'success': False,
                    'error': 'Failed to update vendor in database'
                }
                
    except Exception as e:
        logging.error(f"Error updating vendor ID {vendor_id}: {str(e)}")
        return {
            'success': False,
            'error': f'Database error: {str(e)}'
        }

@router.get('/api/vendors/{vendor_id}/details')
async def get_vendor_details(vendor_id: int):
    """Get detailed vendor information for editing"""
    try:
        logging.info(f"Fetching details for vendor ID: {vendor_id}")
        
        # Get vendor information using existing function
        vendor = get_vendor_by_id(vendor_id)
        
        if not vendor:
            raise HTTPException(
                status_code=404,
                detail=f'Vendor with ID {vendor_id} not found'
            )
        
        # Format vendor data for frontend
        vendor_details = {
            'id': vendor['id'],
            'vendor_name': vendor.get('vendor_name') or vendor.get('name', ''),
            'domain': vendor['domain'],
            'tier': vendor.get('tier', ''),
            'portfolio': vendor.get('portfolio', ''),
            'industry': vendor.get('industry', ''),
            'security_score': vendor.get('securityScore', 0),
            'grade': vendor.get('grade', 'N/A'),
            'added_at': vendor.get('added_at'),
            'logo': vendor.get('logo', f'https://www.google.com/s2/favicons?domain={vendor["domain"]}&sz=32')
        }
        
        logging.info(f"Successfully retrieved details for vendor: {vendor_details['vendor_name']}")
        
        return {
            'status': 'success',
            'vendor': vendor_details
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error fetching vendor details for ID {vendor_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f'Failed to fetch vendor details: {str(e)}'
        )

@router.put('/api/vendors/{vendor_id}/update')
async def update_vendor_details(vendor_id: int, data: dict = Body(...)):
    """Update vendor information"""
    try:
        logging.info(f"Received request to update vendor ID: {vendor_id}")
        logging.info(f"Update data: {data}")
        
        if not data:
            logging.warning("No JSON data provided in request")
            raise HTTPException(
                status_code=400,
                detail='No JSON data provided'
            )
        
        vendor_name = data.get('vendor_name', '').strip()
        domain = data.get('domain', '').strip()
        tier = data.get('tier', '').strip()
        portfolio = data.get('portfolio', '').strip()
        industry = data.get('industry', '').strip() if data.get('industry') else ''
        
        logging.info(f"Attempting to update vendor ID {vendor_id}: {vendor_name} with domain: {domain}, tier: {tier}, portfolio: {portfolio}, industry: {industry}")
        
        # Validate input
        if not vendor_name:
            logging.warning("Vendor name is missing")
            raise HTTPException(
                status_code=400,
                detail='Vendor name is required'
            )
        
        if not domain:
            logging.warning("Domain is missing")
            raise HTTPException(
                status_code=400,
                detail='Domain is required'
            )
        
        if not tier:
            logging.warning("Tier is missing")
            raise HTTPException(
                status_code=400,
                detail='Tier is required'
            )
        
        if not portfolio:
            logging.warning("Portfolio is missing")
            raise HTTPException(
                status_code=400,
                detail='Portfolio is required'
            )
        
        # Enhanced domain validation to support second-level domains (e.g., .co.uk, .org.uk)
        domain_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]*\.([a-zA-Z]{2,}\.)?[a-zA-Z]{2,}$'
        if not re.match(domain_pattern, domain):
            logging.warning(f"Invalid domain format: {domain}")
            raise HTTPException(
                status_code=400,
                detail='Invalid domain format. Supported formats: example.com, example.co.uk, etc.'
            )
        
        # Update vendor using database function
        logging.info("Calling update_vendor_in_database function")
        result = update_vendor_in_database(vendor_id, vendor_name, domain, tier, portfolio, industry)
        logging.info(f"update_vendor_in_database result: {result}")
        
        if result['success']:
            # Invalidate cache to ensure fresh data on next load
            invalidate_vendors_cache()
            
            # Log the vendor update action
            try:
                user_id = request.headers.get('X-User-ID', 'unknown')
                user_email = request.headers.get('X-User-Email')
                user_name = request.headers.get('X-User-Name')
                user_role = request.headers.get('X-User-Role')
                ip_address = _client_ip(request)
                user_agent = request.headers.get('User-Agent')
                
                if user_email:
                    audit_service.log_action(
                        user_id=user_id,
                        user_email=user_email,
                        action='UPDATE',
                        user_name=user_name,
                        user_role=user_role,
                        resource_type='vendor',
                        resource_id=str(vendor_id),
                        details={
                            'action_type': 'update_vendor',
                            'vendor_id': vendor_id,
                            'vendor_name': vendor_name,
                            'domain': domain,
                            'tier': tier,
                            'portfolio': portfolio,
                            'industry': industry,
                            'timestamp': datetime.now().isoformat()
                        },
                        ip_address=ip_address,
                        user_agent=user_agent
                    )
                    logging.info(f"Audit log created for vendor update: {vendor_name} (ID: {vendor_id})")
            except Exception as audit_error:
                logging.warning(f"Failed to log vendor update audit: {audit_error}")
                # Don't fail the update if audit logging fails
            
            logging.info(f"Successfully updated vendor ID {vendor_id}: {vendor_name} ({domain})")
            
            return {
                'status': 'success',
                'message': result['message'],
                'vendor': result['vendor']
            }
        else:
            logging.warning(f"Failed to update vendor: {result['error']}")
            status_code = 409 if 'already' in result['error'].lower() else 500
            raise HTTPException(
                status_code=status_code,
                detail=result['error']
            )
            
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error updating vendor ID {vendor_id}: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f'Server error: {str(e)}'
        )

@router.get('/api/vendors/{vendor_id}/validate-domain')
async def validate_domain_for_update(vendor_id: int, domain: str):
    """Validate if a domain can be used for updating a vendor"""
    try:
        from db_config import DatabaseConnection
        
        # Enhanced domain format validation to support second-level domains (e.g., .co.uk, .org.uk)
        domain_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]*\.([a-zA-Z]{2,}\.)?[a-zA-Z]{2,}$'
        if not re.match(domain_pattern, domain):
            return {
                'valid': False,
                'message': 'Invalid domain format. Supported formats: example.com, example.co.uk, etc.'
            }
        
        with DatabaseConnection() as db:
            # Check if domain is already used by another vendor
            check_query = "SELECT id, vendor_name FROM vendors WHERE domain = %s AND id != %s"
            existing_vendor = db.execute_single_query(check_query, (domain, vendor_id))
            
            if existing_vendor:
                return {
                    'valid': False,
                    'message': f'Domain is already used by vendor "{existing_vendor["vendor_name"]}"'
                }
            
            return {
                'valid': True,
                'message': 'Domain is available'
            }
            
    except Exception as e:
        logging.error(f"Error validating domain for vendor {vendor_id}: {str(e)}")
        return {
            'valid': False,
            'message': 'Error validating domain'
        }

@router.get('/api/vendors/{vendor_id}/validate-name')
async def validate_name_for_update(vendor_id: int, name: str):
    """Validate if a vendor name can be used for updating a vendor"""
    try:
        from db_config import DatabaseConnection
        
        if not name or not name.strip():
            return {
                'valid': False,
                'message': 'Vendor name is required'
            }
        
        with DatabaseConnection() as db:
            # Check if name is already used by another vendor (case-insensitive)
            check_query = "SELECT id, domain FROM vendors WHERE LOWER(vendor_name) = LOWER(%s) AND id != %s"
            existing_vendor = db.execute_single_query(check_query, (name.strip(), vendor_id))
            
            if existing_vendor:
                return {
                    'valid': False,
                    'message': f'Vendor name is already used by domain "{existing_vendor["domain"]}"'
                }
            
            return {
                'valid': True,
                'message': 'Vendor name is available'
            }
            
    except Exception as e:
        logging.error(f"Error validating vendor name for vendor {vendor_id}: {str(e)}")
        return {
            'valid': False,
            'message': 'Error validating vendor name'
        }
