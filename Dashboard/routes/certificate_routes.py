from fastapi import APIRouter, HTTPException, Request, Query, Body
from typing import Optional
import logging
import os
import sys
import time

# Add path for Dashboard module imports
dashboard_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if dashboard_path not in sys.path:
    sys.path.append(dashboard_path)

# Import required functions from db_service
from audit_service import log_request_action
from db_service import (
    get_vendors_by_certifications,
    get_certification_statistics,
    get_vendors_from_database,
    update_vendor_certifications
)

router = APIRouter()

@router.get('/api/certifications')
async def get_certifications(
    iso_27001: Optional[str] = Query(default=None),
    soc2: Optional[str] = Query(default=None),
    both_certifications: Optional[str] = Query(default=None)
):
    """Get all vendors with certification filtering"""
    try:
        # Convert string to boolean if provided
        iso_filter = None
        if iso_27001 is not None:
            iso_filter = iso_27001.lower() == 'true'
        
        soc2_filter = None
        if soc2 is not None:
            soc2_filter = soc2.lower() == 'true'
            
        both_filter = None
        if both_certifications is not None:
            both_filter = both_certifications.lower() == 'true'
        
        # Get filtered vendors
        vendors = get_vendors_by_certifications(iso_27001=iso_filter, soc2=soc2_filter, both_certifications=both_filter)
        
        # Get certification statistics
        stats = get_certification_statistics()
        
        # Debug logging
        logging.info(f"Certification API: Found {len(vendors)} vendors")
        if vendors:
            sample_vendor = vendors[0]
            logging.info(f"Sample vendor certification data: {sample_vendor.get('certifications', {})}")
        logging.info(f"Certification statistics: {stats}")
        
        return {
            'vendors': vendors,
            'statistics': stats,
            'filters_applied': {
                'iso_27001': iso_filter,
                'soc2': soc2_filter,
                'both_certifications': both_filter
            }
        }
        
    except Exception as e:
        logging.error(f"Error getting certifications: {str(e)}")
        # Return error but with 200 status like original
        return {
            'error': 'Failed to retrieve certification data',
            'vendors': [],
            'statistics': {}
        }

@router.get('/api/certifications/statistics')
async def get_cert_statistics():
    """Get certification statistics"""
    try:
        stats = get_certification_statistics()
        return stats
    except Exception as e:
        logging.error(f"Error getting certification statistics: {str(e)}")
        raise HTTPException(status_code=500, detail='Failed to retrieve statistics')

@router.post('/api/certifications/check')
async def check_certifications(data: dict = Body(default={})):
    """Start certification check for vendors as background task"""
    try:
        domains = data.get('domains', [])
        check_all = data.get('check_all', False)
        
        if check_all:
            # Get all vendor domains
            all_vendors = get_vendors_from_database()
            domains = [vendor['domain'] for vendor in all_vendors]
        
        if not domains:
            raise HTTPException(
                status_code=400,
                detail='No domains specified for certification check'
            )
        
        logging.info(f"Starting background certification check for {len(domains)} domains")
        
        # Generate a job ID for tracking
        import uuid
        job_id = f"cert_check_{int(time.time())}_{str(uuid.uuid4())[:8]}"
        
        # Start background task
        import threading
        def run_certification_background():
            try:
                # Import and use the single agent certification checker
                import sys
                import os
                
                # Add the certificates directory to path
                cert_path = os.path.join(os.path.dirname(__file__), '..','..','certificates')
                if os.path.exists(cert_path):
                    sys.path.insert(0, cert_path)
                    from agent_certification import SingleAgentCertificationChecker
                else:
                    logging.error('Certification checker module not found')
                    return
                
                logging.info(f"Background certification check {job_id} starting...")
                
                # Initialize and run the single agent certification checker using database
                checker = SingleAgentCertificationChecker(
                    use_database=True,  # Use database instead of temp file
                    max_workers=1,  # Single worker to avoid overwhelming
                    batch_size=2    # Small batch size
                )
                
                # Run the scan
                checker.run_complete_scan()
                
                # Update database with results
                updated_count = 0
                for result in checker.results:
                    domain = result['domain']
                    
                    # Extract only the essential certification data
                    cert_data = {
                        'iso_27001': result.get('iso_27001', {}).get('certified', False),
                        'soc2': result.get('soc2', {}).get('certified', False)
                    }
                    
                    # Log the certification status for debugging
                    iso_status = "YES" if cert_data['iso_27001'] else "NO"
                    soc2_status = "YES" if cert_data['soc2'] else "NO"
                    logging.info(f"Certifications for {domain}: ISO 27001: {iso_status}, SOC 2: {soc2_status}")
                    
                    # Update vendor in database with simplified data
                    success = update_vendor_certifications(domain, cert_data)
                    if success:
                        updated_count += 1
                
                logging.info(f"Background certification check {job_id} completed: {updated_count} vendors updated")
                        
                # except Exception as e:
                #     logging.error(f"Background certification check {job_id} failed: {e}")
                    
            except Exception as e:
                logging.error(f"Background certification task failed: {e}")
        
        # Start the background thread
        thread = threading.Thread(target=run_certification_background, daemon=True)
        thread.start()
        
        # Return immediately with job ID
        return {
            'status': 'started',
            'message': f'Certification check started in background for {len(domains)} domains',
            'job_id': job_id,
            'domains_count': len(domains),
            'note': 'Check logs for progress updates. Results will be updated in the database automatically.'
        }
            
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error starting certification check: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f'Failed to start certification check: {str(e)}'
        )

@router.get('/api/certifications/status')
async def get_certification_status():
    """Get status of certification checks"""
    try:
        import threading
        active_threads = threading.active_count()
        
        return {
            'status': 'success',
            'active_background_tasks': active_threads - 1,  # Subtract main thread
            'message': 'Certification checks run in background. Check logs for detailed progress.'
        }
    except Exception as e:
        logging.error(f"Error getting certification status: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f'Failed to get certification status: {str(e)}'
        )

@router.put('/api/certifications/{domain}')
async def update_vendor_certification(domain: str, request: Request, data: dict = Body(...)):
    """Update certifications for a specific vendor by domain"""
    try:
        # Validate input
        if not domain:
            raise HTTPException(
                status_code=400,
                detail='Domain is required'
            )
        
        # Extract certification data from request body
        iso_27001 = data.get('iso_27001', False)
        soc2 = data.get('soc2', False)
        
        # Validate that at least one boolean value is provided
        if not isinstance(iso_27001, bool) or not isinstance(soc2, bool):
            raise HTTPException(
                status_code=400,
                detail='iso_27001 and soc2 must be boolean values'
            )
        
        # Prepare certification data
        cert_data = {
            'iso_27001': bool(iso_27001),
            'soc2': bool(soc2)
        }
        
        # Update vendor certifications (manually_added=True since this is via the button)
        success = update_vendor_certifications(domain, cert_data, manually_added=True)
        
        if success:
            logging.info(f"Successfully updated certifications for {domain}: ISO 27001={iso_27001}, SOC 2={soc2}")
            log_request_action(
                request,
                action='UPDATE',
                resource_type='certifications',
                resource_id=domain,
                details={
                    'domain': domain,
                    'iso_27001': cert_data['iso_27001'],
                    'soc2': cert_data['soc2'],
                    'certifications_held': [
                        label for label, held in (('ISO 27001', iso_27001), ('SOC 2', soc2)) if held
                    ],
                    'manually_added': True,
                },
            )
            return {
                'status': 'success',
                'message': f'Certifications updated successfully for {domain}',
                'domain': domain,
                'certifications': cert_data
            }
        else:
            raise HTTPException(
                status_code=500,
                detail=f'Failed to update certifications for {domain}'
            )
            
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error updating certifications for {domain}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f'Failed to update certifications: {str(e)}'
        )