from fastapi import APIRouter, Body, HTTPException, Query, Depends
from datetime import datetime, timedelta
import logging
import sys
import os
import threading
import concurrent.futures
from typing import Optional
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
import atexit

# Import cache service
from cache_service import get_vendors_cached

# Import database services
from db_service import NewsService, VendorService

# Import incidents module for AI-powered news scanning
incidents_path = os.path.join(os.path.dirname(__file__), '..', 'Recent Incidents')
sys.path.insert(0, incidents_path)  # Insert at beginning to prioritize this path

print(f"[News Routes] Attempting to import incidents module from {incidents_path}")

try:
    from incidents import query_incidents_json
    INCIDENTS_MODULE_AVAILABLE = True
    print(f"Successfully imported incidents module")
    print(f"   query_incidents_json function: {query_incidents_json is not None}")
    logging.info(f"Successfully imported incidents module from {incidents_path}")
except ImportError as e:
    print(f" Could not import incidents module: {e}")
    print(f"   This is likely due to .env file access restrictions in sandbox environment")
    print(f"   News scans will not work, but other dashboard features will")
    INCIDENTS_MODULE_AVAILABLE = False
    query_incidents_json = None
    logging.warning(f"Incidents module not available: {e}")
except Exception as e:
    print(f"Unexpected error importing incidents module: {e}")
    INCIDENTS_MODULE_AVAILABLE = False
    query_incidents_json = None
    logging.error(f"Unexpected error importing incidents module: {e}")

print(f"[News Routes] Module loaded - INCIDENTS_MODULE_AVAILABLE: {INCIDENTS_MODULE_AVAILABLE}")
logging.info(f"News routes module loaded - INCIDENTS_MODULE_AVAILABLE: {INCIDENTS_MODULE_AVAILABLE}")

router = APIRouter()

try:
    from Dashboard.effective_permissions import require_permission
except ImportError:
    from effective_permissions import require_permission

# view_incidents — user-basic and above (read-only news/incidents data)
require_view_incidents = require_permission("view_incidents")
# run_full_scans  — admin only; triggers expensive AI API calls per vendor
require_run_scans     = require_permission("run_full_scans")
# view_admin_features — admin only (scheduler internals)
require_view_admin    = require_permission("view_admin_features")

# Global variables for news scanning
news_scan_jobs = {}  # Format: {job_id: {'status': 'running', 'progress': 0, 'type': 'news_scan', ...}}
news_job_counter = 0
scheduler = BackgroundScheduler()
scheduler_initialized = False

@router.post('/api/incidents')
async def post_incidents(req: dict = Body(default={}), _: None = Depends(require_view_incidents)):
    """POST endpoint for incidents"""
    try:
        domain = req.get('domain')
        months = int(req.get('months', 12))
        force_refresh = req.get('force_refresh', False)
        
        if not domain:
            raise HTTPException(status_code=400, detail="Missing 'domain'")
        
        return await _handle_incidents(domain, months, force_refresh)
        
    except HTTPException:
        raise
    except Exception as e:
        logging.exception("Error fetching security incidents")
        raise HTTPException(status_code=500, detail="Internal server error")

async def _handle_incidents(domain: str, months: int, force_refresh: bool):
    """Common handler for incidents endpoints"""
    # Clean domain name
    domain = domain.strip().lower()
    domain = domain.replace('https://', '').replace('http://', '').replace('www.', '').split('/')[0]
    
    # Initialize news service
    from db_service import NewsService
    news_service = NewsService()
    
    # Get data from database only (pure filter function)
    db_data = news_service.get_news_for_domain(domain, months)
    
    logging.info(f"Returning news data for {domain}: {db_data['total_count']} items (database only)")
    
    return {
        "status": "success", 
        "source": "database",
        "domain": domain,
        "incidents": db_data['incidents'],
        "news": db_data['news'],
        "summary": f"Retrieved {db_data['total_count']} items from database (last {months} months)",
        "last_scan": db_data.get('last_scan_time'),
        "notes": "Data retrieved from local database only. Use background scan to fetch latest data."
    }


@router.get('/api/news/all')
async def get_all_recent_news(
    months: int = Query(default=12),
    domain: Optional[str] = Query(default=None, alias='domain'),
    _: None = Depends(require_view_incidents),
):
    """Get all recent news items across all domains"""
    try:
        from db_service import NewsService
        news_service = NewsService()
        
        if domain:
            # Get news for specific domain
            domain_data = news_service.get_news_for_domain(domain, months)
            return {
                "status": "success",
                "domain": domain,
                "incidents": domain_data['incidents'],
                "news": domain_data['news'],
                "summary": f"Retrieved {domain_data['total_count']} items from database (last {months} months)",
                "last_scan": domain_data.get('last_scan_time'),
                "notes": "Data retrieved from local database cache"
            }
        else:
            # Get all news items
            news_data = news_service.get_all_news(months=months)
            news_items = news_data.get('items', [])
            
            # Separate incidents and news
            incidents = [item for item in news_items if item.get('type', '').lower() == 'incident']
            news = [item for item in news_items if item.get('type', '').lower() == 'news']
            
            return {
                "status": "success",
                "incidents": incidents,
                "news": news,
                "summary": f"Retrieved {len(news_items)} items from database across all domains (last {months} months)",
                "last_scan": news_data.get('last_scan_time'),
                "notes": "Data from all domains in database cache",
                "total_count": len(news_items)
            }
        
    except Exception as e:
        logging.exception("Error retrieving all news")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post('/api/news/scan-all')
async def scan_all_domains_for_news(
    data: dict = Body(default={}),
    _: None = Depends(require_run_scans),
):
    """Start background scan for all domains for fresh news and incidents"""
    try:
        months = data.get('months', 12)
        
        from db_service import VendorService
        vendor_service = VendorService()
        
        # Get all vendor domains
        vendors = vendor_service.get_all_vendors()
        
        if not vendors:
            raise HTTPException(
                status_code=400,
                detail="No vendor domains found"
            )
        
        # Generate unique job ID
        global news_job_counter
        news_job_counter += 1
        job_id = f"news_scan_{news_job_counter}_{int(datetime.now().timestamp())}"
        
        # Initialize news scan job (separate from security scans)
        news_scan_jobs[job_id] = {
            'status': 'starting',
            'progress': 0,
            'start_time': datetime.now(),
            'total_domains': len(vendors),
            'current_domain': None,
            'completed': [],
            'failed': [],
            'total_stored': 0,
            'months': months,
            'logs': [f"Starting news scan for {len(vendors)} domains"],
            'type': 'manual_news_scan'
        }
        
        # Start background thread
        thread = threading.Thread(
            target=run_news_scan_background,
            args=(job_id, vendors, months)
        )
        thread.daemon = True
        thread.start()
        
        return {
            "status": "success",
            "message": f"Started background news scan for {len(vendors)} domains",
            "job_id": job_id,
            "total_domains": len(vendors),
            "estimated_time": "1-2 hours"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logging.exception("Error starting bulk news scan")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get('/api/news/scheduler-status')
async def get_scheduler_status(_: None = Depends(require_view_admin)):
    """Get status of the news scheduler"""
    try:
        jobs = scheduler.get_jobs()
        scheduled_job = None
        for job in jobs:
            if job.id == 'news_scan_job':
                scheduled_job = job
                break
        
        return {
            "scheduler_running": scheduler.running,
            "scheduler_initialized": scheduler_initialized,
            "scheduled_job": {
                "exists": scheduled_job is not None,
                "next_run_time": scheduled_job.next_run_time.isoformat() if scheduled_job and scheduled_job.next_run_time else None,
                "job_id": scheduled_job.id if scheduled_job else None,
                "name": scheduled_job.name if scheduled_job else None
            } if scheduled_job else None,
            "active_jobs_count": len(news_scan_jobs),
            "total_scheduled_jobs": len(jobs)
        }
    except Exception as e:
        logging.exception("Error getting scheduler status")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get('/api/news/scan-status/{job_id}')
async def get_news_scan_status(job_id: str, _: None = Depends(require_view_incidents)):
    """Get status of background news scan job"""
    try:
        if job_id not in news_scan_jobs:
            raise HTTPException(
                status_code=404,
                detail='Job not found'
            )
        
        job = news_scan_jobs[job_id]
        
        # Calculate runtime
        start_time = job.get('start_time')
        runtime = None
        estimated_remaining = None
        
        if start_time:
            if job['status'] == 'completed' and job.get('end_time'):
                runtime_delta = job['end_time'] - start_time
            else:
                runtime_delta = datetime.now() - start_time
            runtime = str(runtime_delta).split('.')[0]
            
            # Estimate remaining time based on progress
            if job['status'] == 'running' and job['progress'] > 0:
                elapsed_seconds = runtime_delta.total_seconds()
                estimated_total_seconds = elapsed_seconds * (100 / job['progress'])
                remaining_seconds = estimated_total_seconds - elapsed_seconds
                estimated_remaining = str(timedelta(seconds=int(remaining_seconds))).split('.')[0]
        
        return {
            'status': 'success',
            'job': {
                'job_id': job_id,
                'status': job['status'],
                'progress': job['progress'],
                'current_domain': job.get('current_domain'),
                'total_domains': job.get('total_domains', 0),
                'completed_count': len(job.get('completed', [])),
                'failed_count': len(job.get('failed', [])),
                'total_stored': job.get('total_stored', 0),
                'runtime': runtime,
                'estimated_remaining': estimated_remaining,
                'start_time': start_time.isoformat() if start_time else None,
                'end_time': job.get('end_time').isoformat() if job.get('end_time') else None,
                'error': job.get('error'),
                'logs': job.get('logs', [])[-10:],  # Last 10 log entries
                'type': job.get('type', 'news_scan')
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error getting news scan status: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail='Failed to get scan status'
        )

# News scanning background function
# Scheduled news scanning function
def scheduled_news_scan():
    """Scheduled function that runs news scanning once per day"""
    import time
    scheduled_start_time = time.time()
    
    try:
        logging.info("═══════════════════════════════════════════════════════════════")
        logging.info("SCHEDULED NEWS SCAN TRIGGERED")
        logging.info("═══════════════════════════════════════════════════════════════")
        logging.info(f"Trigger time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        logging.info("Scan frequency: Once per day")
        
        # Get all vendors from database
        logging.info("Fetching vendors from cache...")
        vendor_fetch_start = time.time()
        from db_service import NewsService
        news_service = NewsService()
        vendors = get_vendors_cached()
        vendor_fetch_time = time.time() - vendor_fetch_start
        logging.info(f"✓ Fetched {len(vendors)} vendors in {vendor_fetch_time:.2f}s")
        
        if not vendors:
            logging.warning("⚠️  No vendors found for scheduled news scan")
            return
        
        # Create a news scan job for tracking (separate from security scans)
        global news_job_counter
        news_job_counter += 1
        job_id = f"scheduled_news_{news_job_counter}"
        
        # Initialize job tracking in separate news_scan_jobs dictionary
        news_scan_jobs[job_id] = {
            'status': 'running',
            'progress': 0,
            'start_time': datetime.now(),
            'end_time': None,
            'current_domain': None,
            'completed': [],
            'failed': [],
            'logs': [f"Scheduled news scan started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"],
            'total_stored': 0,
            'type': 'scheduled_news_scan'
        }
        
        # Run the news scan in a separate thread to avoid blocking the scheduler
        logging.info(f"Starting background scan thread with job ID: {job_id}")
        logging.info(f"Scan parameters: {len(vendors)} vendors, 12 months lookback")
        
        thread = threading.Thread(
            target=run_news_scan_background,
            args=(job_id, vendors, 12),  # Scan for 12 months of news
            name=f"NewsScan-{job_id}"
        )
        thread.daemon = True
        thread.start()
        
        scheduled_setup_time = time.time() - scheduled_start_time
        logging.info(f"✓ Scheduled news scan thread started successfully")
        logging.info(f"  Job ID: {job_id}")
        logging.info(f"  Thread name: {thread.name}")
        logging.info(f"  Thread alive: {thread.is_alive()}")
        logging.info(f"  Setup time: {scheduled_setup_time:.2f}s")
        logging.info(f"═══════════════════════════════════════════════════════════════")
        
    except Exception as e:
        scheduled_setup_time = time.time() - scheduled_start_time if 'scheduled_start_time' in locals() else 0
        logging.error(f"═══════════════════════════════════════════════════════════════")
        logging.error(f"FAILED TO START SCHEDULED NEWS SCAN")
        logging.error(f"═══════════════════════════════════════════════════════════════")
        logging.error(f"Error: {str(e)}")
        logging.error(f"Setup time before failure: {scheduled_setup_time:.2f}s")
        logging.exception(f"Full exception traceback:")
        logging.error(f"═══════════════════════════════════════════════════════════════")

def run_news_scan_background(job_id, vendors, months):
    """Run news scanning for all domains in background"""
    import time
    scan_start_time = time.time()
    
    try:
        logging.info(f"═══════════════════════════════════════════════════════════════")
        logging.info(f"NEWS SCAN JOB STARTED: {job_id}")
        logging.info(f"═══════════════════════════════════════════════════════════════")
        logging.info(f"Total vendors to scan: {len(vendors)}")
        logging.info(f"Lookback period: {months} months")
        logging.info(f"Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        logging.info(f"═══════════════════════════════════════════════════════════════")
        
        from db_service import NewsService
        news_service = NewsService()
        logging.info(f"NewsService initialized successfully")
        
        # Use the incidents module (already imported at top of file)
        if not INCIDENTS_MODULE_AVAILABLE:
            error_msg = "Incidents module not available - cannot fetch AI data. Check that Recent_Incidents/incidents.py is accessible and .env file is readable."
            logging.error(f"[{job_id}] ❌ {error_msg}")
            logging.error(f"[{job_id}] INCIDENTS_MODULE_AVAILABLE: {INCIDENTS_MODULE_AVAILABLE}")
            logging.error(f"[{job_id}] query_incidents_json: {query_incidents_json}")
            news_scan_jobs[job_id]['status'] = 'failed'
            news_scan_jobs[job_id]['logs'].append(error_msg)
            return
        
        logging.info(f"[{job_id}] Incidents module available: {INCIDENTS_MODULE_AVAILABLE}")
        logging.info(f"[{job_id}] query_incidents_json function available: {query_incidents_json is not None}")
        
        news_scan_jobs[job_id]['status'] = 'running'
        news_scan_jobs[job_id]['logs'].append(f"Starting scan of {len(vendors)} domains")
        logging.info(f"[{job_id}] Scan status set to 'running'")
        
        total_stored = 0
        processed_domains = 0
        skipped_domains = 0
        failed_domains = 0
        successful_domains = 0
        
        for i, vendor in enumerate(vendors):
            domain_start_time = time.time()
            domain = vendor.get('domain')
            if not domain:
                logging.warning(f"[{job_id}] Vendor {i+1} has no domain, skipping")
                continue
            
            try:
                # Update current domain and progress
                news_scan_jobs[job_id]['current_domain'] = domain
                progress = int((processed_domains / len(vendors)) * 100)
                news_scan_jobs[job_id]['progress'] = progress
                
                logging.info(f"───────────────────────────────────────────────────────────────")
                logging.info(f"[{job_id}] Processing domain {processed_domains + 1}/{len(vendors)}: {domain}")
                logging.info(f"[{job_id}] Progress: {progress}% | Tier: {vendor.get('tier', 'Not set')}")
                
                # Check if domain already has recent news (last 24 hours - covers the daily schedule window)
                recent_check_start = time.time()
                has_recent = news_service.has_recent_news(domain, hours=24)
                recent_check_time = time.time() - recent_check_start
                logging.info(f"[{job_id}] Recent news check for {domain}: {has_recent} (took {recent_check_time:.2f}s)")
                
                if has_recent:
                    logging.info(f"[{job_id}] ✓ Domain {domain} already has recent news (last 24h), skipping AI fetch")
                    skipped_domains += 1
                    # Add to completed list with 0 new items
                    news_scan_jobs[job_id]['completed'].append({
                        'domain': domain,
                        'stored_items': 0,
                        'incidents': 0,
                        'news': 0,
                        'skipped': True,
                        'reason': 'Recent news exists (last 3h)'
                    })
                    processed_domains += 1
                    domain_time = time.time() - domain_start_time
                    logging.info(f"[{job_id}] Domain {domain} completed in {domain_time:.2f}s (skipped)")
                    continue
                
                # Fetch fresh data from AI only if no recent news exists
                if not INCIDENTS_MODULE_AVAILABLE or query_incidents_json is None:
                    error_msg = f"Incidents module not available - cannot fetch AI data for {domain}. Module status: available={INCIDENTS_MODULE_AVAILABLE}, function={query_incidents_json is not None}"
                    logging.error(f"[{job_id}] ❌ {error_msg}")
                    failed_domains += 1
                    news_scan_jobs[job_id]['failed'].append({
                        'domain': domain,
                        'error': error_msg
                    })
                    processed_domains += 1
                    continue
                
                # Call query_incidents_json with timeout to prevent hanging
                # Use ThreadPoolExecutor to implement timeout since signal doesn't work well in threads
                ai_data = None
                timeout_seconds = 120  # 2 minute timeout per domain
                
                try:
                    # Get tier from vendor data if available (avoid DB lookup in hot path)
                    tier = vendor.get('tier')
                    logging.info(f"[{job_id}] 🔄 Fetching AI data for {domain}")
                    logging.info(f"[{job_id}]    Model selection: Tier={tier}, Months={months}")
                    logging.info(f"[{job_id}]    Timeout: {timeout_seconds}s")
                    
                    api_call_start = time.time()
                    
                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                        future = executor.submit(query_incidents_json, domain=domain, months=months, tier=tier)
                        try:
                            ai_data = future.result(timeout=timeout_seconds)
                            api_call_time = time.time() - api_call_start
                            logging.info(f"[{job_id}] ✅ Successfully fetched AI data for {domain} (took {api_call_time:.2f}s)")
                            
                            # Log response summary
                            if ai_data:
                                incidents_count = len(ai_data.get('incidents', []))
                                news_count = len(ai_data.get('news', []))
                                logging.info(f"[{job_id}]    Response: {incidents_count} incidents, {news_count} news items")
                            else:
                                logging.warning(f"[{job_id}]    Response: Empty data returned")
                                
                        except concurrent.futures.TimeoutError:
                            api_call_time = time.time() - api_call_start
                            error_msg = f"Timeout after {timeout_seconds}s while fetching AI data for {domain}"
                            logging.error(f"[{job_id}] ⏱️  {error_msg} (waited {api_call_time:.2f}s)")
                            failed_domains += 1
                            news_scan_jobs[job_id]['failed'].append({
                                'domain': domain,
                                'error': error_msg
                            })
                            processed_domains += 1
                            continue
                        except Exception as api_error:
                            api_call_time = time.time() - api_call_start
                            error_msg = f"API error for {domain}: {str(api_error)}"
                            logging.error(f"[{job_id}] ❌ {error_msg} (after {api_call_time:.2f}s)")
                            logging.exception(f"[{job_id}] Full error traceback for {domain}:")
                            failed_domains += 1
                            news_scan_jobs[job_id]['failed'].append({
                                'domain': domain,
                                'error': error_msg
                            })
                            processed_domains += 1
                            continue
                            
                except Exception as timeout_error:
                    error_msg = f"Unexpected error with timeout wrapper for {domain}: {str(timeout_error)}"
                    logging.error(f"[{job_id}] ❌ {error_msg}")
                    logging.exception(f"[{job_id}] Full error traceback:")
                    failed_domains += 1
                    news_scan_jobs[job_id]['failed'].append({
                        'domain': domain,
                        'error': error_msg
                    })
                    processed_domains += 1
                    continue
                
                if not ai_data:
                    error_msg = f"No data returned from AI for {domain}"
                    logging.warning(f"[{job_id}] ⚠️  {error_msg}")
                    failed_domains += 1
                    news_scan_jobs[job_id]['failed'].append({
                        'domain': domain,
                        'error': error_msg
                    })
                    processed_domains += 1
                    continue
                
                # Store the fetched data in database
                logging.info(f"[{job_id}] 💾 Storing data in database for {domain}")
                store_start = time.time()
                
                stored_incidents = 0
                stored_news = 0
                
                if ai_data.get('incidents'):
                    incidents_to_store = len(ai_data['incidents'])
                    logging.info(f"[{job_id}]    Storing {incidents_to_store} incidents...")
                    stored_incidents = news_service.store_news_batch(domain, ai_data['incidents'])
                    logging.info(f"[{job_id}]    ✓ Stored {stored_incidents} incidents")
                
                if ai_data.get('news'):
                    news_to_store = len(ai_data['news'])
                    logging.info(f"[{job_id}]    Storing {news_to_store} news items...")
                    stored_news = news_service.store_news_batch(domain, ai_data['news'])
                    logging.info(f"[{job_id}]    ✓ Stored {stored_news} news items")
                
                store_time = time.time() - store_start
                logging.info(f"[{job_id}]    Database storage completed in {store_time:.2f}s")
                
                domain_total = stored_incidents + stored_news
                total_stored += domain_total
                successful_domains += 1
                
                # Add to completed list
                news_scan_jobs[job_id]['completed'].append({
                    'domain': domain,
                    'stored_items': domain_total,
                    'incidents': stored_incidents,
                    'news': stored_news
                })
                news_scan_jobs[job_id]['total_stored'] = total_stored
                
                processed_domains += 1
                domain_time = time.time() - domain_start_time
                
                logging.info(f"[{job_id}] ✓ Domain {domain} completed successfully")
                logging.info(f"[{job_id}]    Stored: {domain_total} items ({stored_incidents} incidents, {stored_news} news)")
                logging.info(f"[{job_id}]    Total time: {domain_time:.2f}s")
                
                # Log progress every 5 domains (more frequent updates)
                if processed_domains % 5 == 0:
                    progress_pct = (processed_domains / len(vendors)) * 100
                    elapsed_time = time.time() - scan_start_time
                    avg_time_per_domain = elapsed_time / processed_domains if processed_domains > 0 else 0
                    remaining_domains = len(vendors) - processed_domains
                    estimated_remaining_time = avg_time_per_domain * remaining_domains
                    
                    log_msg = f"📊 Progress Update: {processed_domains}/{len(vendors)} domains ({progress_pct:.1f}%)"
                    log_msg += f" | Success: {successful_domains} | Skipped: {skipped_domains} | Failed: {failed_domains}"
                    log_msg += f" | Stored: {total_stored} items"
                    log_msg += f" | Elapsed: {elapsed_time/60:.1f}m | Est. remaining: {estimated_remaining_time/60:.1f}m"
                    
                    news_scan_jobs[job_id]['logs'].append(log_msg)
                    logging.info(f"[{job_id}] {log_msg}")
                
            except Exception as domain_error:
                domain_time = time.time() - domain_start_time
                error_msg = f"Failed to scan {domain}: {str(domain_error)}"
                logging.error(f"[{job_id}] ❌ {error_msg} (after {domain_time:.2f}s)")
                logging.exception(f"[{job_id}] Full exception traceback for {domain}:")
                failed_domains += 1
                news_scan_jobs[job_id]['failed'].append({
                    'domain': domain,
                    'error': str(domain_error)
                })
                news_scan_jobs[job_id]['logs'].append(error_msg)
                processed_domains += 1
                continue
        
        # Mark as completed
        scan_end_time = time.time()
        total_scan_time = scan_end_time - scan_start_time
        
        news_scan_jobs[job_id]['status'] = 'completed'
        news_scan_jobs[job_id]['progress'] = 100
        news_scan_jobs[job_id]['end_time'] = datetime.now()
        news_scan_jobs[job_id]['current_domain'] = None
        
        logging.info(f"═══════════════════════════════════════════════════════════════")
        logging.info(f"NEWS SCAN JOB COMPLETED: {job_id}")
        logging.info(f"═══════════════════════════════════════════════════════════════")
        logging.info(f"Total domains processed: {processed_domains}/{len(vendors)}")
        logging.info(f"  ✓ Successful: {successful_domains}")
        logging.info(f"  ⊘ Skipped: {skipped_domains}")
        logging.info(f"  ✗ Failed: {failed_domains}")
        logging.info(f"Total items stored: {total_stored}")
        logging.info(f"Total scan time: {total_scan_time/60:.2f} minutes ({total_scan_time:.2f} seconds)")
        if processed_domains > 0:
            logging.info(f"Average time per domain: {total_scan_time/processed_domains:.2f} seconds")
        logging.info(f"End time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        logging.info(f"═══════════════════════════════════════════════════════════════")
        
        completion_msg = f"Completed news scan: {processed_domains} domains processed ({successful_domains} success, {skipped_domains} skipped, {failed_domains} failed), {total_stored} items stored in {total_scan_time/60:.1f} minutes"
        news_scan_jobs[job_id]['logs'].append(completion_msg)
        
    except Exception as e:
        scan_end_time = time.time()
        total_scan_time = scan_end_time - scan_start_time if 'scan_start_time' in locals() else 0
        
        logging.error(f"═══════════════════════════════════════════════════════════════")
        logging.error(f"NEWS SCAN JOB FAILED: {job_id}")
        logging.error(f"═══════════════════════════════════════════════════════════════")
        logging.error(f"Error: {str(e)}")
        logging.error(f"Processed before failure: {processed_domains} domains")
        logging.error(f"Total scan time before failure: {total_scan_time:.2f} seconds")
        logging.exception(f"Full exception traceback:")
        logging.error(f"═══════════════════════════════════════════════════════════════")
        
        news_scan_jobs[job_id]['status'] = 'failed'
        news_scan_jobs[job_id]['error'] = str(e)
        news_scan_jobs[job_id]['end_time'] = datetime.now()
        error_msg = f"News scan job failed: {str(e)}"
        news_scan_jobs[job_id]['logs'].append(error_msg)

def initialize_news_scheduler():
    """Initialize the news scheduler only once"""
    global scheduler_initialized
    
    if scheduler_initialized:
        logging.info("News scheduler already initialized, skipping")
        return
        
    try:
        # Start the scheduler
        if not scheduler.running:
            scheduler.start()
            logging.info("News scheduler started successfully")

        # Run immediately first, then schedule once per day
        logging.info("Running initial news scan now...")
        initial_thread = threading.Thread(
            target=scheduled_news_scan,
            daemon=True
        )
        initial_thread.start()
        logging.info("Initial news scan started in background thread")

        # Add the scheduled job to run once per day (starting tomorrow, since we run immediately above)
        scheduler.add_job(
            func=scheduled_news_scan,
            trigger=IntervalTrigger(days=1, start_date=datetime.now() + timedelta(days=1)),
            id='news_scan_job',
            name='Scheduled News Scan',
            replace_existing=True
        )
        
        scheduler_initialized = True
        logging.info("News scheduler initialized - running now, then once per day")
        logging.info("Next scheduled news scan will occur in 24 hours from now")
        
        # Log current jobs for debugging
        jobs = scheduler.get_jobs()
        for job in jobs:
            logging.info(f"Scheduled job: {job.id} - Next run: {job.next_run_time}")
        
    except Exception as e:
        logging.error(f"Failed to initialize news scheduler: {str(e)}")

# Shutdown scheduler gracefully on app exit
def shutdown_scheduler():
    """Safely shutdown scheduler on app exit"""
    global scheduler
    if scheduler and scheduler.running:
        try:
            scheduler.shutdown()
            logging.info("News scheduler shut down successfully")
        except Exception as e:
            logging.warning(f"Scheduler shutdown error (safe to ignore): {e}")

atexit.register(shutdown_scheduler)

