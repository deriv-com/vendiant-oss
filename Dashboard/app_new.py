from datetime import datetime, timedelta
import time
import json
import threading
import subprocess
import sys
import os
from dotenv import load_dotenv
import logging
from fastapi import FastAPI, Request, HTTPException, Body, Query
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.exceptions import RequestValidationError
import atexit
import re

# Additional common FastAPI imports
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
import uvicorn  # For running the app

# Import database services
from db_service import (
    get_vendors_from_database, get_vendor_by_domain, get_vendor_by_id, get_vendor_statistics, 
    save_subdomains_for_domain, add_new_subdomains_for_domain, replace_all_subdomains_for_domain, get_subdomains_for_domain,
    save_subdomains_with_status_detection,  # New status-aware subdomain save function
    save_website_score, save_domain_reputation_score, save_dns_score, save_network_score, save_encryption_score, save_email_score,
    save_website_vulnerabilities, save_domain_reputation_vulnerabilities, save_dns_vulnerabilities, save_network_vulnerabilities, save_encryption_vulnerabilities, save_email_vulnerabilities,
    get_scores_for_domain, get_vulnerabilities_for_domain, check_domain_has_subdomains,
    mark_vendor_full_scan_complete, get_vendors_for_full_scan,  # Scan cursor: stamp + stalest-first ordering
    add_new_vendor,  # New function for adding vendors
    delete_vendor_by_id,  # New function for deleting vendors
    get_vendor_additional_domains,  # New function for getting additional domains
    cleanup_duplicate_vulnerabilities,  # New function for cleaning up duplicates
    add_subdomain_to_exclusion_list, remove_subdomain_from_exclusion_list, get_excluded_subdomains_for_vendor, get_excluded_subdomains_set,  # Subdomain exclusion functions
    add_manual_subdomain_to_database,  # Manual subdomain addition function
    get_vendors_by_certifications, update_vendor_certifications, update_vendor_certifications_simple, get_certification_statistics,  # Certification functions
    update_vendor_overall_score  # Function to update overall score in vendors table
)
from db_config import test_connection
from app_paths import app_join, get_app_root
from scan_health_notifier import notify_scan_step_failure, notify_scan_overall_failure, notify_score_update_failure


# Import unified scoring system
from unified_scoring_config import get_unified_scoring, calculate_overall_vendor_score, update_vendor_overall_score_after_scan, get_severity_weights, calculate_scan_score

# Import cache service
from cache_service import (
    get_vendors_cached, invalidate_vendors_cache,
    get_subdomains_cached, invalidate_subdomain_cache,
    get_dashboard_stats_cached, invalidate_dashboard_cache,
    get_ai_insights_cache, invalidate_ai_insights_cache, AI_CACHE_DURATION
)

# Import scheduler manager
from scheduler_manager import initialize_threaded_schedulers

# Import incidents functionality
sys.path.append(app_join('Recent Incidents'))
from incidents import query_incidents_json

# Import audit logging functionality
from audit_service import audit_service, log_user_action, log_request_action

# Load environment variables from the root .env file
env_path = app_join('.env')
if os.path.exists(env_path):
    load_dotenv(env_path)

#Route Inserts
from routes.api_audit_routes import router as api_audit_router
from routes.audit_routes import router as audit_router
from routes.ai_insights_routes import router as ai_insights_router
from routes.critical_alerts_routes import router as critical_alerts_router
from routes.excluded_subdomains_routes import router as excluded_subdomains_router
from routes.breach_routes import router as breach_router
from routes.certificate_routes import router as certificate_router
from routes.analytics_routes import router as analytics_router
from routes.report_routes import router as report_router
from routes.news_routes import router as news_router, initialize_news_scheduler
from routes.dashboard_card_routes import router as dashboard_card_router
from routes.portfolio_routes import router as portfolio_router
from routes.vendor_management_routes import router as vendor_management_router
from routes.api_key_routes import router as api_key_router
from routes.slack_routes import router as slack_router
from routes.breach_monitor_routes import router as breach_monitor_router
from routes.breach_monitor_webhook_routes import router as breach_monitor_webhook_router
from routes.admin_management_routes import router as admin_management_router
from routes.admin_roles_routes import router as admin_roles_router
from routes.me_routes import router as me_router

def generate_encryption_vulnerability_title(vuln_id, finding_text):
    """
    Generate a human-readable vulnerability title for grouping based on testssl.sh vulnerability ID and finding text.
    This helps group similar vulnerabilities together in reports and tables.
    """
    # Common vulnerability patterns and their human-readable titles
    vuln_patterns = {
        # Protocol vulnerabilities
        'ssl_': 'SSL Protocol Vulnerability',
        'tls_': 'TLS Protocol Vulnerability', 
        'protocol_': 'Protocol Configuration Issue',
        
        # Certificate issues
        'cert_': 'Certificate Validation Issue',
        'certificate_': 'Certificate Validation Issue',
        'chain_': 'Certificate Chain Issue',
        'ca_': 'Certificate Authority Issue',
        
        # Cipher suite issues
        'cipher_': 'Cipher Suite Configuration',
        'encryption_': 'Encryption Configuration Issue',
        'weak_cipher': 'Weak Cipher Suite',
        'null_cipher': 'Null Cipher Suite Vulnerability',
        
        # Vulnerability-specific issues
        'heartbleed': 'Heartbleed Vulnerability',
        'beast': 'BEAST Vulnerability',
        'crime': 'CRIME Vulnerability', 
        'breach': 'BREACH Vulnerability',
        'poodle': 'POODLE Vulnerability',
        'sweet32': 'Sweet32 Vulnerability',
        'freak': 'FREAK Vulnerability',
        'logjam': 'Logjam Vulnerability',
        'drown': 'DROWN Vulnerability',
        'lucky13': 'Lucky13 Vulnerability',
        
        # HSTS and header issues
        'hsts': 'HTTP Strict Transport Security Issue',
        'header_': 'Security Header Issue',
        
        # Renegotiation issues
        'renegot': 'SSL/TLS Renegotiation Issue',
        'renego': 'SSL/TLS Renegotiation Issue',
        
        # Compression issues
        'compression': 'SSL/TLS Compression Issue',
        
        # Key exchange issues
        'dhe': 'DHE Key Exchange Issue',
        'ecdhe': 'ECDHE Key Exchange Issue',
        'rsa': 'RSA Key Exchange Issue',
    }
    
    # Convert to lowercase for pattern matching
    vuln_id_lower = vuln_id.lower()
    finding_lower = finding_text.lower() if finding_text else ''
    
    # Check for specific patterns in vulnerability ID
    for pattern, title in vuln_patterns.items():
        if pattern in vuln_id_lower:
            return title
    
    # Check for patterns in finding text
    for pattern, title in vuln_patterns.items():
        if pattern in finding_lower:
            return title
    
    # Extract meaningful words from finding text for grouping
    if finding_text and len(finding_text) > 10:
        # Look for key security terms in the finding text
        if any(term in finding_lower for term in ['certificate', 'cert']):
            return 'Certificate Issue'
        elif any(term in finding_lower for term in ['cipher', 'encryption']):
            return 'Cipher Configuration Issue'
        elif any(term in finding_lower for term in ['protocol', 'ssl', 'tls']):
            return 'Protocol Configuration Issue'
        elif any(term in finding_lower for term in ['vulnerable', 'vulnerability']):
            return 'SSL/TLS Vulnerability'
        elif any(term in finding_lower for term in ['weak', 'insecure']):
            return 'Weak Security Configuration'
        elif any(term in finding_lower for term in ['missing', 'not found']):
            return 'Missing Security Feature'
        else:
            # Use first part of finding text, cleaned up
            words = finding_text.split()[:4]  # Take first 4 words
            clean_title = ' '.join(words).strip()
            if len(clean_title) > 50:
                clean_title = clean_title[:47] + '...'
            return clean_title or 'SSL/TLS Security Issue'
    
    # Fallback to a generic but groupable title
    return 'SSL/TLS Security Issue'

# Add parent directories to path for importing security tools
sys.path.append(app_join('Subdomains'))
sys.path.append(app_join('Header_Vulnerabilities'))
sys.path.append(app_join('Domain Reputation'))
sys.path.append(app_join('Network'))
sys.path.append(app_join('Recent Incidents'))
sys.path.append(app_join('Encryption', 'LOCAL'))

try:
    from incidents import query_incidents_json, DEFAULT_API_BASE as INCIDENTS_API_BASE, DEFAULT_API_KEY as INCIDENTS_API_KEY, DEFAULT_MODEL as INCIDENTS_MODEL
except Exception as e:
    logging.warning(f"Could not import incidents module: {e}")

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = FastAPI(title="Security Scanner API")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    # Comma-separated list of allowed browser origins (CORS_ORIGINS in .env)
    allow_origins=[o.strip() for o in os.getenv("CORS_ORIGINS", "http://localhost:3005,http://localhost:8081").split(",") if o.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add audit logging middleware
# Audit rows are written by the create/update/delete route that makes the
# change (audit_service.log_request_action) so each row can describe *what*
# changed. There is deliberately no request-level audit middleware: it could
# only ever record method + URL, which produced uninformative rows for real
# edits and noise rows for reads shaped as POST (search, export, compare).

#Route Includes
app.include_router(api_audit_router) #API Audit 
app.include_router(audit_router) #Audit Routes
app.include_router(ai_insights_router) #AI Insights Routes
app.include_router(critical_alerts_router) #Critical Alerts Routes
app.include_router(excluded_subdomains_router) #Excluded Subdomains Routes
app.include_router(breach_router) #Breach Routes
app.include_router(certificate_router) #Certificate Routes
app.include_router(analytics_router) #Analytics Routes
app.include_router(report_router) #Report Routes
app.include_router(news_router) #News Routes
app.include_router(dashboard_card_router) #Dashboard Card Routes
app.include_router(portfolio_router) #Portfolio Routes
app.include_router(vendor_management_router) #Vendor Management Routes
app.include_router(api_key_router) #API Key Routes
app.include_router(slack_router) #Slack Routes
app.include_router(breach_monitor_webhook_router)
app.include_router(breach_monitor_router) # Breach Monitor breach intelligence
app.include_router(admin_management_router) # Admin Management (user directory + role assignments)
app.include_router(admin_roles_router) # Access Management named roles
app.include_router(me_router) # Current-user effective permissions


# Global error handler for 500 errors
@app.exception_handler(500)
async def handle_internal_error(request: Request, exc: Exception):
    logging.error(f"Internal server error: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={
            'status': 'error',
            'message': 'Internal server error occurred',
            'error_type': 'internal_server_error'
        }
    )

# Handler for 404 errors
@app.exception_handler(404)
async def handle_not_found(request: Request, exc: Exception):
    return JSONResponse(
        status_code=404,
        content={
            'status': 'error',
            'message': 'Endpoint not found',
            'error_type': 'not_found'
        }
    )

# Handler for Starlette HTTP exceptions (includes 404, etc.)
@app.exception_handler(StarletteHTTPException)
async def handle_starlette_exception(request: Request, exc: StarletteHTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            'status': 'error',
            'message': exc.detail,
            'error_type': 'http_exception'
        }
    )

# Handler for validation errors
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={
            'status': 'error',
            'message': 'Validation error',
            'error_type': 'validation_error',
            'details': exc.errors()
        }
    )

# General exception handler for all other unhandled exceptions
@app.exception_handler(Exception)
async def handle_exception(request: Request, exc: Exception):
    logging.error(f"Unhandled exception: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            'status': 'error',
            'message': f'An unexpected error occurred: {str(exc)}',
            'error_type': 'unhandled_exception'
        }
    )

# Configuration
RESULTS_DIR = app_join('Results')

# Global dictionaries to track scans
active_scans = {}
scan_results = {}
active_vulnerability_scans = {}  # Track vulnerability scans specifically
active_subdomain_scans = {}  # Track subdomain discovery scans

# Background job tracking for full domain scans (Postgres — shared across pods)
from background_job_store import background_jobs, generate_job_id

# Note: News scanning jobs and scheduler are now handled in routes/news_routes.py


# Helper functions for scoring and vendor management
def determine_risk_level(score):
    """Determine risk level based on security score (950-point system)"""
    if score >= 800:
        return 'low'     # 800-950 points - Low Risk
    elif score >= 600:
        return 'medium'  # 600-799 points - Medium Risk  
    elif score >= 400:
        return 'high'    # 400-599 points - High Risk
    else:
        return 'critical' # 0-399 points - Critical Risk

def get_all_domains_for_discovery(domain):
    """Get all domains (main + additional) for subdomain discovery"""
    try:
        # Start with the main domain
        domains_to_scan = [domain]
        
        # Get vendor info to fetch additional domains
        vendor = get_vendor_by_domain(domain)
        if vendor:
            vendor_id = vendor.get('id')
            if vendor_id:
                # Get additional domains
                additional_domains_result = get_vendor_additional_domains(vendor_id)
                if additional_domains_result.get('success'):
                    additional_domains = additional_domains_result.get('additional_domains', [])
                    if additional_domains:
                        domains_to_scan.extend(additional_domains)
                        logging.info(f"Found {len(additional_domains)} additional domains for {domain}: {additional_domains}")
        
        logging.info(f"Total domains for subdomain discovery: {len(domains_to_scan)} - {domains_to_scan}")
        return domains_to_scan
        
    except Exception as e:
        logging.error(f"Error getting domains for discovery for {domain}: {e}")
        # Return at least the main domain
        return [domain]

def filter_subdomains_by_patterns(domain, all_subdomains, all_domains=None):
    """Filter subdomains based on common patterns and generate missing combinations for all domains"""
    
    # If all_domains not provided, use just the main domain for backward compatibility
    if all_domains is None:
        all_domains = [domain]
    
    # Common subdomain patterns based on typical enterprise infrastructure
    target_patterns = [
        # Corporate/Business
        'info', 'corp', 'corporate', 'about',
        
        # Support/Help
        'support', 'help', 'knowledge', 'kb', 'community', 'wiki',
        
        # Products/Apps
        'app', 'login', 'secure', 'portal', 'admin', 'api', 'developers', 'dev', 
        'test', 'qa', 'staging', 'shop', 'store', 'mail', 'crm', 'erp',
        
        # Content/Marketing
        'blog', 'news', 'press', 'marketing', 'resources',
        
        # Careers
        'jobs', 'careers', 'hiring',
        
        # Technical/Infrastructure
        'www', 'ftp', 'cdn', 'static', 'assets', 'media', 'img', 'images',
        'download', 'files', 'docs', 'vpn', 'remote', 'ssl', 'secure',
        'backup', 'db', 'database', 'mysql', 'postgres', 'redis',
        'cache', 'queue', 'worker', 'cron', 'scheduler',
        
        # Regional/Language
        'en', 'us', 'uk', 'ca', 'au', 'de', 'fr', 'es', 'it', 'jp', 'cn',
        'asia', 'europe', 'america', 'global', 'international',
        
        # Environment specific
        'prod', 'production', 'live', 'demo', 'sandbox', 'preview',
        'beta', 'alpha', 'rc', 'release', 'staging', 'development',
        
        # Services
        'email', 'smtp', 'pop', 'imap', 'webmail', 'mx', 'ns', 'dns',
        'ldap', 'ad', 'auth', 'sso', 'oauth', 'saml',
        
        # Monitoring/Analytics
        'monitor', 'stats', 'analytics', 'metrics', 'logs', 'kibana',
        'grafana', 'prometheus', 'nagios', 'zabbix',
        
        # Cloud/Hosting
        'cloud', 'aws', 'azure', 'gcp', 'k8s', 'kubernetes', 'docker',
        'jenkins', 'ci', 'cd', 'build', 'deploy'
    ]
    
    # Convert all subdomains to lowercase for matching
    all_subdomains_lower = [sub.lower() for sub in all_subdomains]
    
    # Filter existing subdomains that match our patterns (for any of the domains)
    filtered_subdomains = []
    found_patterns_per_domain = {}
    all_found_patterns = set()
    
    # Initialize found patterns tracking for each domain
    for target_domain in all_domains:
        found_patterns_per_domain[target_domain] = set()
    
    for subdomain in all_subdomains:
        subdomain_lower = subdomain.lower()
        
        # Check against all domains to see which one this subdomain belongs to
        for target_domain in all_domains:
            if '.' + target_domain.lower() in subdomain_lower:
                subdomain_prefix = subdomain_lower.replace('.' + target_domain.lower(), '')
                
                # Check if this subdomain matches any of our target patterns
                # Only match exact patterns or direct subdomains (no nested subdomains)
                for pattern in target_patterns:
                    if pattern == subdomain_prefix:
                        # Exact match: app.box.com -> app
                        filtered_subdomains.append(subdomain)
                        found_patterns_per_domain[target_domain].add(pattern)
                        all_found_patterns.add(pattern)
                        break
                    elif '.' not in subdomain_prefix and subdomain_prefix == pattern:
                        # Direct subdomain match (redundant check but explicit)
                        filtered_subdomains.append(subdomain)
                        found_patterns_per_domain[target_domain].add(pattern)
                        all_found_patterns.add(pattern)
                        break
                break  # Found the matching domain, no need to check others
    
    # Generate missing combinations for patterns not found across all domains
    missing_combinations = []
    missing_patterns = set(target_patterns) - all_found_patterns
    
    # Generate combinations for each domain that doesn't have certain patterns
    for target_domain in all_domains:
        domain_found_patterns = found_patterns_per_domain[target_domain]
        domain_missing_patterns = set(target_patterns) - domain_found_patterns
        
        for pattern in domain_missing_patterns:
            potential_subdomain = f"{pattern}.{target_domain}"
            missing_combinations.append(potential_subdomain)
    
    # Combine filtered existing subdomains with generated combinations
    all_target_subdomains = filtered_subdomains + missing_combinations
    
    logging.info(f"Enhanced subdomain filtering results for {len(all_domains)} domains {all_domains}:")
    logging.info(f"  - Total input subdomains: {len(all_subdomains)}")
    logging.info(f"  - Filtered existing subdomains: {len(filtered_subdomains)}")
    logging.info(f"  - Generated missing combinations: {len(missing_combinations)}")
    logging.info(f"  - Total target subdomains to check: {len(all_target_subdomains)}")
    
    # Log per-domain statistics
    for target_domain in all_domains:
        domain_found = found_patterns_per_domain[target_domain]
        domain_missing = set(target_patterns) - domain_found
        logging.info(f"  - {target_domain}: {len(domain_found)} patterns found, {len(domain_missing)} combinations generated")
    
    return {
        'filtered_existing': filtered_subdomains,
        'generated_combinations': missing_combinations,
        'all_target_subdomains': all_target_subdomains,
        'found_patterns': list(all_found_patterns),
        'missing_patterns': list(missing_patterns),
        'found_patterns_per_domain': {domain: list(patterns) for domain, patterns in found_patterns_per_domain.items()}
    }


def get_favicon_url(domain):
    """Generate favicon URL for a domain using various favicon services"""
    # Clean domain
    clean_domain = domain.replace('https://', '').replace('http://', '').replace('www.', '').split('/')[0]
    
    # Try multiple favicon services for better reliability
    favicon_services = [
        f'https://www.google.com/s2/favicons?domain={clean_domain}&sz=32',  # Google's favicon service
        f'https://favicons.githubusercontent.com/favicon.ico?domain={clean_domain}',  # GitHub's service
        f'https://{clean_domain}/favicon.ico',  # Direct domain favicon
        f'https://api.faviconkit.com/{clean_domain}/32',  # FaviconKit service
    ]
    
    # Return the primary Google favicon service (most reliable)
    return favicon_services[0]

from fastapi import Body

@app.get('/')
async def index():
    """Redirect to modern Next.js frontend"""
    return {
        'message': 'Use the Next.js frontend on port 3005', 
        'frontend_url': 'http://localhost:3005'
    }

@app.get('/health')
async def health_check():
    """Health check endpoint for Docker"""
    return {
        'status': 'healthy', 
        'service': 'vendiant-backend', 
        'timestamp': datetime.now().isoformat()
    }

@app.get('/api/vendors')
async def get_vendors():
    """Get all vendors"""
    return {'vendors': get_vendors_cached()}

@app.get('/api/vendors/{vendor_id}')
async def get_vendor(vendor_id: int):
    """Get specific vendor by ID"""
    vendors_list = get_vendors_cached()
    vendor = next((v for v in vendors_list if v['id'] == vendor_id), None)
    if vendor:
        return {'vendor': vendor}
    raise HTTPException(status_code=404, detail='Vendor not found')

@app.post('/api/vendors/reload')
async def reload_vendors():
    """Reload vendors from PostgreSQL database"""
    try:
        # Invalidate cache first to force fresh reload
        invalidate_vendors_cache()
        
        # Get fresh vendors data (this will load from PostgreSQL and cache it)
        vendors = get_vendors_cached()
        
        return {
            'status': 'success',
            'message': f'Successfully reloaded {len(vendors)} vendors from PostgreSQL database',
            'vendor_count': len(vendors)
        }
    except Exception as e:
        logging.error(f"Error reloading vendors: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f'Failed to reload vendors: {str(e)}'
        )


@app.post('/api/vendors/add')
async def add_vendor(data: dict = Body(...)):
    """Add a new vendor to the database"""
    try:
        logging.info("Received request to add new vendor")
        logging.info(f"Request data: {data}")
        
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
        # Honour DEFAULT_AUTO_SCAN_ON_VENDOR_ADD env var; fall back to the
        # request body's auto_scan field, then to True if neither is set.
        _env_auto_scan = os.getenv('DEFAULT_AUTO_SCAN_ON_VENDOR_ADD', '').strip().lower()
        if _env_auto_scan in ('0', 'false', 'no', 'off'):
            auto_scan = False
        elif _env_auto_scan in ('1', 'true', 'yes', 'on'):
            auto_scan = True
        else:
            auto_scan = data.get('auto_scan', True)
        logging.info(f"Attempting to add vendor: {vendor_name} with domain: {domain}, tier: {tier}, portfolio: {portfolio}, industry: {industry}, auto_scan: {auto_scan}")
        
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
        
        # Enhanced domain validation to support second-level domains (e.g., .co.uk, .org.uk)
        import re
        # Updated pattern to allow:
        # - Standard domains: example.com, example.org
        # - Second-level domains: example.co.uk, example.org.uk, example.com.au
        # - Subdomains: sub.example.com (though we clean these out)
        domain_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]*\.([a-zA-Z]{2,}\.)?[a-zA-Z]{2,}$'
        if not re.match(domain_pattern, domain):
            logging.warning(f"Invalid domain format: {domain}")
            raise HTTPException(
                status_code=400,
                detail='Invalid domain format. Supported formats: example.com, example.co.uk, etc.'
            )
        
        # Add vendor using database service
        logging.info("Calling add_new_vendor function")
        result = add_new_vendor(vendor_name, domain, tier, portfolio, industry)
        logging.info(f"add_new_vendor result: {result}")
        
        if result['success']:
            # Invalidate cache to ensure fresh data on next load
            invalidate_vendors_cache()
            
            logging.info(f"Successfully added vendor: {vendor_name} ({domain})")
            
            # Only start automatic scan if auto_scan is True
            if auto_scan:
                # Automatically start a full scan for the new vendor
                try:
                    scan_job_id = generate_job_id("auto")
                    
                    # Initialize job tracking for the automatic scan
                    background_jobs[scan_job_id] = {
                        'job_id': scan_job_id,
                        'status': 'starting',
                        'progress': 0,
                        'start_time': datetime.now(),
                        'current_domain': domain,
                        'stage': 'initializing',
                        'domains': [domain],
                        'total_domains': 1,
                        'completed': [],
                        'failed': [],
                        'logs': [f'Automatic full scan starting for new vendor: {vendor_name} ({domain})'],
                        'include_subdomains': True,
                        'auto_scan': True  # Flag to indicate this is an automatic scan
                    }
                    
                    # Start background scan in thread
                    scan_thread = threading.Thread(
                        target=run_background_single_domain_scan,
                        args=(scan_job_id, domain, True)  # True for include_subdomains
                    )
                    scan_thread.daemon = True
                    scan_thread.start()
                    
                    # Update status to running
                    background_jobs[scan_job_id]['status'] = 'running'
                    background_jobs[scan_job_id]['logs'].append(f'Automatic scan started for {domain}')
                    
                    logging.info(f"Automatic full scan initiated for new vendor {vendor_name} ({domain}) with job ID: {scan_job_id}")
                    
                    response_data = {
                        'success': True,
                        'message': f'Vendor "{vendor_name}" added successfully. Full security scan initiated automatically.',
                        'vendor': result['vendor'],
                        'scan_job_id': scan_job_id,
                        'auto_scan_started': True
                    }
                    
                except Exception as scan_error:
                    logging.warning(f"Failed to start automatic scan for new vendor {vendor_name} ({domain}): {str(scan_error)}")
                    # Don't fail the vendor addition if scan fails to start
                    response_data = {
                        'success': True,
                        'message': f'Vendor "{vendor_name}" added successfully. Note: Automatic scan could not be started.',
                        'vendor': result['vendor'],
                        'auto_scan_started': False,
                        'scan_error': str(scan_error)
                    }
            else:
                # No automatic scan requested
                response_data = {
                    'success': True,
                    'message': f'Vendor "{vendor_name}" added successfully. No automatic scan initiated.',
                    'vendor': result['vendor'],
                    'auto_scan_started': False
                }
                logging.info(f"Vendor {vendor_name} ({domain}) added without automatic scan as requested")
            
            logging.info(f"Sending response: {response_data}")
            return response_data
        else:
            logging.warning(f"Failed to add vendor: {result['error']}")
            status_code = 409 if 'already exists' in result['error'] else 500
            raise HTTPException(
                status_code=status_code,
                detail=result['error']
            )
            
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error adding vendor: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f'Server error: {str(e)}'
        )

@app.delete('/api/vendors/{vendor_id}')
async def delete_vendor(vendor_id: int):
    """Delete a vendor from the database"""
    try:
        logging.info(f"Received request to delete vendor with ID: {vendor_id}")
        
        # Delete the vendor using the database service
        success = delete_vendor_by_id(vendor_id)
        
        if success:
            # Invalidate the vendor cache to force reload
            invalidate_vendors_cache()
            
            logging.info(f"Successfully deleted vendor with ID: {vendor_id}")
            return {
                'success': True,
                'message': f'Vendor deleted successfully'
            }
        else:
            logging.warning(f"Failed to delete vendor with ID: {vendor_id}")
            raise HTTPException(
                status_code=404,
                detail='Failed to delete vendor. Vendor may not exist.'
            )
            
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error deleting vendor with ID {vendor_id}: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f'Server error: {str(e)}'
        )

@app.post('/api/vendors/refresh-scores')
async def refresh_vendor_scores():
    """Refresh security scores for all vendors using unified scoring system"""
    try:
        vendors_list = get_vendors_cached()
        updated_count = 0
        updated_vendors = []
        
        for vendor in vendors_list:
            try:
                old_score = vendor.get('securityScore', 0)
                
                # Use unified scoring system first
                try:
                    overall_score_response = calculate_vendor_overall_score(vendor['id'])
                    if hasattr(overall_score_response, 'get_json'):
                        overall_result = overall_score_response.get_json()
                        if overall_result.get('status') == 'success':
                            new_score = overall_result['overall_score']
                            if new_score != old_score:
                                vendor['securityScore'] = new_score
                                vendor['riskLevel'] = determine_risk_level(new_score)
                                vendor['lastScan'] = vendor.get('last_scan_date', 'Not scanned')
                                updated_count += 1
                                updated_vendors.append({
                                    'name': vendor['name'],
                                    'domain': vendor['domain'],
                                    'old_score': old_score,
                                    'new_score': new_score,
                                    'method': 'unified'
                                })
                                logging.info(f"Updated {vendor['name']} using unified scoring: {old_score} -> {new_score}")
                                continue
                except Exception as unified_error:
                    logging.warning(f"Unified scoring failed for {vendor['name']}: {unified_error}. Skipping vendor.")
                    
            except Exception as vendor_error:
                logging.error(f"Error updating vendor {vendor['name']}: {vendor_error}")
                continue
        
        # Invalidate cache to ensure fresh data
        if updated_count > 0:
            invalidate_vendors_cache()
        
        return {
            'status': 'success',
            'message': f'Successfully updated scores for {updated_count} vendors',
            'updated_count': updated_count,
            'total_vendors': len(vendors_list),
            'updated_vendors': updated_vendors
        }
    except Exception as e:
        logging.error(f"Error refreshing vendor scores: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f'Failed to refresh scores: {str(e)}'
        )

@app.post('/api/vendors/{vendor_id}/refresh-score')
async def refresh_vendor_score(vendor_id: int):
    """Refresh security score for a specific vendor using unified scoring system"""
    try:
        vendors_list = get_vendors_cached()
        vendor = next((v for v in vendors_list if v['id'] == vendor_id), None)
        if not vendor:
            raise HTTPException(status_code=404, detail='Vendor not found')
        
        domain = vendor['domain']
        old_score = vendor.get('securityScore', 0)
        
        # Use the unified scoring system to calculate overall score
        try:
            # Call the overall score calculation endpoint internally
            overall_score_response = calculate_vendor_overall_score(vendor_id)
            
            if hasattr(overall_score_response, 'get_json'):
                overall_result = overall_score_response.get_json()
                if overall_result.get('status') == 'success':
                    new_score = overall_result['overall_score']
                    
                    # Update vendor in cache
                    vendor['securityScore'] = new_score
                    vendor['riskLevel'] = determine_risk_level(new_score)
                    vendor['lastScan'] = vendor.get('last_scan_date', 'Not scanned')
                    
                    # Invalidate cache to ensure fresh data on next load
                    invalidate_vendors_cache()
                    
                    logging.info(f"Successfully updated score for {vendor['name']}: {old_score} -> {new_score}")
                    
                    return {
                        'status': 'success',
                        'message': f'Score updated for {vendor["name"]} using unified scoring',
                        'vendor': vendor,
                        'old_score': old_score,
                        'new_score': new_score,
                        'unified_scoring_used': True
                    }
                else:
                    return {
                        'status': 'info',
                        'message': f'Unified scoring returned no result for {vendor["name"]}',
                        'vendor': vendor
                    }
            
        except Exception as unified_error:
            logging.error(f"Unified scoring failed for {domain}: {unified_error}")
            raise HTTPException(status_code=500, detail=f"Failed to calculate score: {str(unified_error)}")
        
        # No score could be calculated
        return {
            'status': 'info',
            'message': f'No scan results found for {vendor["name"]}. Run security scans first.',
            'vendor': vendor
        }
            
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error refreshing score for vendor {vendor_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f'Failed to refresh score: {str(e)}'
        )



@app.post('/api/subdomains/discover-async')
async def discover_subdomains_async(data: dict = Body(...)):
    """Start asynchronous subdomain discovery for a given domain"""
    try:
        domain = data.get('domain')
        force_rediscovery = data.get('force_rediscovery', False)
        
        if not domain:
            raise HTTPException(
                status_code=400,
                detail='Domain is required'
            )
        
        # Clean domain name
        domain = domain.strip().lower()
        domain = domain.replace('https://', '').replace('http://', '').replace('www.', '').split('/')[0]
        
        # Generate scan ID
        scan_id = f"subdomain_{domain}_{int(time.time())}"
        
        # Check if subdomains already exist in database (for non-forced scans)
        if not force_rediscovery:
            try:
                logging.info(f"Checking if subdomains already exist for {domain} in database")
                has_existing_subdomains = check_domain_has_subdomains(domain)
                
                if has_existing_subdomains:
                    # Get existing subdomains from database with status information
                    existing_subdomains = get_subdomains_for_domain(domain)
                    
                    # Separate active and inactive subdomains
                    active_subdomains = []
                    inactive_subdomains = []
                    subdomain_details = []
                    
                    for item in existing_subdomains:
                        subdomain = item['subdomain']
                        status = item.get('status', 'Inactive')
                        
                        if status == 'Active':
                            active_subdomains.append(subdomain)
                            subdomain_details.append({'subdomain': subdomain, 'status': 'alive'})
                        else:
                            inactive_subdomains.append(subdomain)
                            subdomain_details.append({'subdomain': subdomain, 'status': 'inactive'})
                    
                    total_count = len(existing_subdomains)
                    active_count = len(active_subdomains)
                    inactive_count = len(inactive_subdomains)
                    success_rate = (active_count / total_count * 100) if total_count > 0 else 0
                    
                    logging.info(f"Found {total_count} existing subdomains for {domain} in database - {active_count} active, {inactive_count} inactive - skipping discovery")
                    
                    return {
                        'status': 'completed',
                        'scan_id': scan_id,
                        'domain': domain,
                        'method': 'Database (existing subdomains with status)',
                        'skipped_discovery': True,
                        'message': f'Using {total_count} existing subdomains from database ({active_count} active, {inactive_count} inactive). Use force_rediscovery=true to run new discovery.',
                        'statistics': {
                            'total': total_count,
                            'alive': active_count,
                            'inactive': inactive_count,
                            'success_rate': round(success_rate, 2),
                            'from_database': True
                        },
                        'subdomains': subdomain_details,
                        'database_saved': True
                    }
            except Exception as db_error:
                logging.warning(f"Error checking existing subdomains for {domain}: {db_error}")
                # Continue with discovery if database check fails
        
        # Initialize scan tracking
        active_subdomain_scans[scan_id] = {
            'domain': domain,
            'status': 'starting',
            'progress': 0,
            'start_time': datetime.now(),
            'force_rediscovery': force_rediscovery,
            'stage': 'initializing',
            'logs': ['Starting subdomain discovery...']
        }
        
        # Start scan in background thread
        thread = threading.Thread(target=run_subdomain_discovery_background, args=(scan_id, domain, force_rediscovery))
        thread.daemon = True
        thread.start()
        
        return {
            'status': 'started',
            'scan_id': scan_id,
            'message': f'Subdomain discovery started for {domain}',
            'domain': domain
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error starting subdomain discovery: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f'Failed to start subdomain discovery: {str(e)}'
        )


@app.get('/api/subdomains/discover-status/{scan_id}')
async def get_subdomain_discovery_status(scan_id: str):
    """Get the status of an ongoing subdomain discovery scan"""
    try:
        if scan_id not in active_subdomain_scans:
            raise HTTPException(status_code=404, detail='Scan not found')
        
        scan_info = active_subdomain_scans[scan_id]
        return scan_info
        
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error getting subdomain scan status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post('/api/subdomains/discover-stop/{scan_id}')
async def stop_subdomain_discovery(scan_id: str):
    """Stop an ongoing subdomain discovery scan"""
    try:
        if scan_id not in active_subdomain_scans:
            raise HTTPException(status_code=404, detail='Scan not found')
        
        # Mark scan as stopped
        active_subdomain_scans[scan_id]['status'] = 'stopped'
        active_subdomain_scans[scan_id]['logs'].append('Scan stopped by user')
        
        return {
            'status': 'success',
            'message': 'Subdomain discovery scan stopped'
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error stopping subdomain scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post('/api/subdomains/add')
async def add_subdomains_to_existing(data: dict = Body(...)):
    """Add new subdomains to existing subdomain list for a domain"""
    try:
        domain = data.get('domain')
        new_subdomains = data.get('subdomains', [])
        
        if not domain:
            raise HTTPException(
                status_code=400,
                detail='Domain is required'
            )
        
        if not new_subdomains:
            raise HTTPException(
                status_code=400,
                detail='Subdomains list is required'
            )
        
        # Clean domain name
        domain = domain.strip().lower()
        domain = domain.replace('https://', '').replace('http://', '').replace('www.', '').split('/')[0]
        
        logging.info(f"Adding {len(new_subdomains)} new subdomains for {domain}")
        
        # Add only new subdomains
        success = add_new_subdomains_for_domain(domain, new_subdomains)
        
        if success:
            # Invalidate cache after successful addition
            invalidate_subdomain_cache(domain)
            # Get updated count
            updated_subdomains = get_subdomains_for_domain(domain)
            
            return {
                'status': 'success',
                'domain': domain,
                'message': f'Successfully added new subdomains for {domain}',
                'added_count': len(new_subdomains),
                'total_count': len(updated_subdomains)
            }
        else:
            raise HTTPException(
                status_code=500,
                detail=f'Failed to add subdomains for {domain}'
            )
        
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error adding subdomains: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f'Failed to add subdomains: {str(e)}'
        )

@app.get('/api/subdomains/check/{domain}')
async def check_subdomains_status(domain: str):
    """Check if a domain has subdomains in the database and provide recommendations"""
    try:
        # Clean domain name
        domain = domain.strip().lower()
        domain = domain.replace('https://', '').replace('http://', '').replace('www.', '').split('/')[0]
        
        # Check if domain exists in vendors table
        vendor = get_vendor_by_domain(domain)
        if not vendor:
            raise HTTPException(
                status_code=404,
                detail='Domain not found in vendors table'
            )
        
        # Check if subdomains exist
        has_subdomains = check_domain_has_subdomains(domain)
        
        if has_subdomains:
            # Get subdomain details
            subdomains = get_subdomains_for_domain(domain)
            subdomain_count = len(subdomains)
            
            return {
                'domain': domain,
                'vendor_exists': True,
                'has_subdomains': True,
                'subdomain_count': subdomain_count,
                'message': f'Domain has {subdomain_count} subdomains in database',
                'recommendation': 'Ready for security scans. Subdomains will be used automatically.',
                'discovery_needed': False
            }
        else:
            return {
                'domain': domain,
                'vendor_exists': True,
                'has_subdomains': False,
                'subdomain_count': 0,
                'message': 'No subdomains found in database',
                'recommendation': 'Run subdomain discovery first for comprehensive security scans.',
                'discovery_needed': True
            }
            
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error checking subdomain status for {domain}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post('/api/vendors/{vendor_id}/subdomains/manual')
async def add_manual_subdomain(vendor_id: int, data: dict = Body(...)):
    """Add a manual subdomain for a specific vendor that persists through rediscovery"""
    try:
        subdomain = data.get('subdomain', '').strip()
        
        if not subdomain:
            raise HTTPException(
                status_code=400,
                detail='Subdomain is required'
            )
        
        # Get vendor information
        vendor = get_vendor_by_id(vendor_id)
        if not vendor:
            raise HTTPException(
                status_code=404,
                detail=f'Vendor with ID {vendor_id} not found'
            )
        
        domain = vendor.get('domain')
        vendor_name = vendor.get('vendor_name')
        
        # Clean and validate subdomain
        subdomain = subdomain.lower()
        subdomain = subdomain.replace('https://', '').replace('http://', '').replace('www.', '').split('/')[0]
        
        # Validate subdomain format (basic validation)
        if not subdomain or '.' not in subdomain:
            raise HTTPException(
                status_code=400,
                detail='Invalid subdomain format'
            )
        
        # Check if subdomain already exists
        existing_subdomains = get_subdomains_for_domain(domain)
        if any(sub.get('subdomain') == subdomain for sub in existing_subdomains):
            raise HTTPException(
                status_code=409,
                detail=f'Subdomain "{subdomain}" already exists for {vendor_name}'
            )
        
        # Check if subdomain is in excluded list
        excluded_subdomains = get_excluded_subdomains_set(vendor_id)
        if subdomain in excluded_subdomains:
            raise HTTPException(
                status_code=409,
                detail=f'Subdomain "{subdomain}" is in the excluded list. Please remove it from exclusions first.'
            )
        
        # Add manual subdomain to database
        success = add_manual_subdomain_to_database(vendor_id, domain, subdomain)
        
        if success:
            # Invalidate cache after successful addition
            invalidate_subdomain_cache(domain)
            
            # Get updated subdomain count
            updated_subdomains = get_subdomains_for_domain(domain)
            
            logging.info(f"Successfully added manual subdomain '{subdomain}' for vendor {vendor_name} (ID: {vendor_id})")
            
            return {
                'status': 'success',
                'message': f'Successfully added manual subdomain "{subdomain}" for {vendor_name}',
                'subdomain': subdomain,
                'vendor_id': vendor_id,
                'vendor_name': vendor_name,
                'domain': domain,
                'total_subdomains': len(updated_subdomains),
                'manually_added': True
            }
        else:
            raise HTTPException(
                status_code=500,
                detail=f'Failed to add manual subdomain "{subdomain}" for {vendor_name}'
            )
            
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error adding manual subdomain for vendor {vendor_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f'Failed to add manual subdomain: {str(e)}'
        )


@app.get('/api/subdomains/{domain}')
async def get_subdomains_by_domain(domain: str):
    """Get stored subdomains for a domain from database"""
    try:
        # Get subdomains from cache or database
        logging.info(f"Retrieving subdomains for {domain} from cache/database")
        subdomains_data = get_subdomains_cached(domain)
        
        # Extract just the subdomain names for the response
        all_subdomains = [item['subdomain'] for item in subdomains_data]
        
        # Separate active and inactive subdomains for proper display
        active_subdomains = []
        inactive_subdomains = []
        
        for item in subdomains_data:
            subdomain = item['subdomain']
            status = item.get('status', 'Inactive')
            
            if status == 'Active':
                active_subdomains.append(subdomain)
            else:
                inactive_subdomains.append(subdomain)
        
        # Return database results with proper status filtering
        return {
            'domain': domain,
            'subdomains': {
                'alive': active_subdomains,  # Only Active subdomains
                'all': all_subdomains,      # All subdomains
                'inactive': inactive_subdomains,  # Only Inactive subdomains
                'details': subdomains_data  # Include detailed data with IDs and status
            },
            'count': {
                'alive': len(active_subdomains),
                'inactive': len(inactive_subdomains),
                'total': len(all_subdomains)
            },
            'source': 'database'
        }
    
    except Exception as e:
        logging.error(f"Error getting subdomains for {domain}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get('/api/vendors/{vendor_id}/subdomains')
async def get_subdomains_by_vendor_id(vendor_id: int):
    """Get all subdomains for a specific vendor"""
    try:
        from db_service import get_subdomains_for_vendor
        
        logging.info(f"Retrieving subdomains for vendor ID {vendor_id} from database")
        subdomains_data = get_subdomains_for_vendor(vendor_id)
        
        return {
            'vendor_id': vendor_id,
            'subdomains': subdomains_data,
            'count': len(subdomains_data)
        }
    
    except Exception as e:
        logging.error(f"Error getting subdomains for vendor {vendor_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get('/api/vendors/{vendor_id}/additional-domains')
async def get_vendor_additional_domains_api(vendor_id: int):
    """Get additional domains for a vendor"""
    try:
        from db_service import get_vendor_additional_domains
        
        result = get_vendor_additional_domains(vendor_id)
        
        if result['success']:
            return {
                'status': 'success',
                'vendor_id': vendor_id,
                'vendor_name': result['vendor_name'],
                'primary_domain': result['primary_domain'],
                'additional_domains': result['additional_domains']
            }
        else:
            status_code = 404 if result['error'] == 'Vendor not found' else 400
            raise HTTPException(status_code=status_code, detail=result['error'])
            
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error getting additional domains for vendor {vendor_id}: {e}")
        raise HTTPException(status_code=500, detail=f'Server error: {str(e)}')

@app.post('/api/vendors/{vendor_id}/additional-domains')
async def add_additional_domain_api(vendor_id: int, data: dict = Body(...)):
    """Add an additional domain to a vendor"""
    try:
        from db_service import add_additional_domain_to_vendor
        
        if not data or 'domain' not in data:
            raise HTTPException(status_code=400, detail='Domain is required')
        
        new_domain = data['domain']
        result = add_additional_domain_to_vendor(vendor_id, new_domain)
        
        if result['success']:
            return {
                'status': 'success',
                'message': result['message'],
                'vendor_id': vendor_id,
                'additional_domains': result['additional_domains']
            }
        else:
            raise HTTPException(status_code=400, detail=result['error'])
            
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error adding additional domain to vendor {vendor_id}: {e}")
        raise HTTPException(status_code=500, detail=f'Server error: {str(e)}')

@app.delete('/api/vendors/{vendor_id}/additional-domains/{domain}')
async def remove_additional_domain_api(vendor_id: int, domain: str):
    """Remove an additional domain from a vendor"""
    try:
        from db_service import remove_additional_domain_from_vendor
        
        result = remove_additional_domain_from_vendor(vendor_id, domain)
        
        if result['success']:
            return {
                'status': 'success',
                'message': result['message'],
                'vendor_id': vendor_id,
                'additional_domains': result['additional_domains']
            }
        else:
            raise HTTPException(status_code=400, detail=result['error'])
            
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error removing additional domain from vendor {vendor_id}: {e}")
        raise HTTPException(status_code=500, detail=f'Server error: {str(e)}')


@app.post('/api/vulnerabilities/scan')
async def start_vulnerability_scan(data: dict = Body(...)):
    """Start a vulnerability scan for a domain"""
    try:
        domain = data.get('domain')
        scan_id = data.get('scan_id', f'vuln_{int(time.time())}')
        
        if not domain:
            raise HTTPException(status_code=400, detail='Domain is required')
        
        # Clean domain name
        domain = domain.strip().lower()
        domain = domain.replace('https://', '').replace('http://', '').replace('www.', '').split('/')[0]
        
        logging.info(f"Starting vulnerability scan for {domain} with scan ID {scan_id}")
        
        # Track this scan
        active_vulnerability_scans[scan_id] = {
            'domain': domain,
            'started': time.time(),
            'stopped': False
        }
        
        # Import and use the vulnerability scanner
        sys.path.append(app_join('Header_Vulnerabilities'))
        from header_vulnerabilities import process_domain, check_header_vulnerabilities, get_http_headers
        
        # Check if domain has subdomains in database first
        try:
            logging.info(f"Checking if {domain} has subdomains in database for vulnerability scan")
            has_subdomains = check_domain_has_subdomains(domain)
            
            if has_subdomains:
                # Get subdomains from database - ONLY ACTIVE ONES
                logging.info(f"Using existing Active subdomains from database for vulnerability scan - skipping subdomain discovery")
                db_subdomains = get_subdomains_for_domain(domain)
                
                if db_subdomains:
                    # Extract only Active subdomain names from database results
                    active_subdomains = [item['subdomain'] for item in db_subdomains if item.get('status') == 'Active']
                    
                    # Always include the main domain (assume it's active)
                    if domain not in active_subdomains:
                        active_subdomains.insert(0, domain)
                    
                    subdomains = active_subdomains
                    total_db_subdomains = len(db_subdomains)
                    active_count = len(active_subdomains) - (1 if domain in active_subdomains else 0)  # Exclude main domain from count
                    
                    logging.info(f"Loaded {len(subdomains)} Active subdomains from database for vulnerability scan (including main domain)")
                    logging.info(f"Filtered from {total_db_subdomains} total subdomains to {active_count} Active subdomains + main domain")
                else:
                    # Unexpected case - has_subdomains was True but no subdomains returned
                    subdomains = [domain]
                    logging.warning(f"Subdomain check indicated subdomains exist but none retrieved for {domain}")
            else:
                # No subdomains in database - suggest running subdomain discovery first
                logging.warning(f"No subdomains found in database for {domain}. Consider running subdomain discovery first for better coverage.")
                logging.info(f"Scanning main domain only for vulnerability scan: {domain}")
                subdomains = [domain]
                
        except Exception as db_error:
            logging.error(f"Error checking/fetching subdomains from database for vulnerability scan: {db_error}")
            # Fallback to main domain only on database error
            subdomains = [domain]
            logging.info(f"Database error, scanning main domain only: {domain}")
        
        # Initialize vulnerability scan tracking - database integration only
        total_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        initial_score = 950
        severity_weights = get_severity_weights('WEBSITE')
        
        subdomain_scores = []
        processed_subdomains = 0
        vulnerabilities_found = []
        individual_scores = []  # Track individual subdomain scores for detailed logging
        
        for sub in subdomains:
            # Check if scan has been stopped
            if scan_id in active_vulnerability_scans and active_vulnerability_scans[scan_id]['stopped']:
                logging.info(f"Vulnerability scan {scan_id} was stopped by user")
                break
            
            try:
                logging.info(f"Processing subdomain: {sub}")
                response = get_http_headers(sub)
                
                if not response:
                    logging.info(f"No HTTP response for {sub}, skipping")
                    continue
                
                vulnerabilities = check_header_vulnerabilities(response)
                severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
                
                if vulnerabilities:
                    for vuln in vulnerabilities:
                        severity = vuln.get('severity', 'UNKNOWN')
                        desc = vuln.get('desc', 'Unknown vulnerability')
                        vuln_id = vuln.get('id', 'UNKNOWN_ID')
                        
                        if severity in severity_counts:
                            severity_counts[severity] += 1
                            total_counts[severity] += 1
                        
                        # Store for JSON response
                        vulnerabilities_found.append({
                            'subdomain': sub,
                            'id': vuln_id,
                            'description': desc,
                            'severity': severity
                        })
                
                # Calculate score for this subdomain
                subdomain_score = initial_score
                score_deductions = {}
                total_deducted = 0
                
                for severity, count in severity_counts.items():
                    if count > 0:
                        deduction = count * severity_weights.get(severity, 0)
                        score_deductions[severity] = deduction
                        total_deducted += deduction
                        subdomain_score -= deduction
                
                subdomain_score = max(0, subdomain_score)
                subdomain_scores.append(subdomain_score)
                processed_subdomains += 1
                
                # Store individual score data
                individual_scores.append({
                    'subdomain': sub,
                    'score': subdomain_score,
                    'vulnerabilities': severity_counts,
                    'deductions': score_deductions,
                    'total_deducted': total_deducted
                })
                
                # Enhanced logging for this subdomain
                severity_breakdown = ', '.join([f"{sev}: {count}" for sev, count in severity_counts.items() if count > 0])
                deduction_breakdown = ', '.join([f"{sev}: -{deduction}" for sev, deduction in score_deductions.items()])
                
                logging.info(f"Subdomain: {sub}")
                logging.info(f"   Starting Score: {initial_score}")
                logging.info(f"   Vulnerabilities: {severity_breakdown or 'None'}")
                logging.info(f"   Score Deductions: {deduction_breakdown or 'None'}")
                logging.info(f"   Total Deducted: -{total_deducted}")
                logging.info(f"   Final Score: {subdomain_score}/{initial_score}")
                
            except Exception as e:
                logging.error(f"Error processing subdomain {sub}: {e}")
                continue
        
        # Calculate final score
        if subdomain_scores:
            final_score = round(sum(subdomain_scores) / len(subdomain_scores))
        else:
            final_score = initial_score
            
        # Log detailed final score calculation
        logging.info(f"VULNERABILITY SCAN - FINAL SCORE CALCULATION:")
        logging.info(f"   Subdomains Scanned: {processed_subdomains}")
        
        if subdomain_scores:
            # Log individual scores summary
            logging.info(f"   Individual Subdomain Scores:")
            for score_data in individual_scores:
                subdomain_name = score_data['subdomain']
                subdomain_score = score_data['score']
                total_vulns = sum(score_data['vulnerabilities'].values())
                deducted = score_data['total_deducted']
                logging.info(f"     • {subdomain_name}: {subdomain_score}/{initial_score} ({total_vulns} vulns, -{deducted} points)")
            
            # Log final calculation
            total_score_sum = sum(subdomain_scores)
            logging.info(f"   Total Score Sum: {total_score_sum}")
            logging.info(f"   Average Calculation: {total_score_sum} ÷ {processed_subdomains} = {total_score_sum / processed_subdomains:.2f}")
            logging.info(f"   Final Score (rounded): {final_score}/{initial_score}")
            
            # Log score distribution analysis
            min_score = min(subdomain_scores)
            max_score = max(subdomain_scores)
            score_range = max_score - min_score
            logging.info(f"   Score Range: {min_score} to {max_score} (spread: {score_range})")
        else:
            logging.info(f"   No subdomains scanned, using initial score: {final_score}")
        
        # Check if scan was stopped
        scan_stopped = scan_id in active_vulnerability_scans and active_vulnerability_scans[scan_id]['stopped']
        
        # Clean up scan tracking
        if scan_id in active_vulnerability_scans:
            del active_vulnerability_scans[scan_id]
        
        if scan_stopped:
            logging.info(f"Vulnerability scan {scan_id} was stopped before completion")
            return {
                'status': 'stopped',
                'domain': domain,
                'message': 'Scan was stopped by user',
                'subdomains_processed': processed_subdomains,
                'vulnerabilities': vulnerabilities_found
            }
        
        # Save results to database
        try:
            # Save the website score
            logging.info(f"Saving Website score {final_score} for {domain} to database")
            score_saved = save_website_score(domain, final_score)
            
            # Invalidate dashboard cache when scores are updated
            if score_saved:
                invalidate_dashboard_cache()
            
            # Prepare vulnerabilities for database storage
            vuln_data_for_db = []
            for vuln in vulnerabilities_found:
                vuln_data_for_db.append({
                    'subdomain': vuln['subdomain'],
                    'title': vuln['id'],
                    'description': vuln['description'],
                    'severity': vuln['severity']
                })
            
            # Save vulnerabilities to database
            if vuln_data_for_db:
                logging.info(f"Saving {len(vuln_data_for_db)} Website vulnerabilities for {domain} to database")
                vuln_saved = save_website_vulnerabilities(domain, vuln_data_for_db, update_existing=True)
            else:
                # Clear stale Website vulnerabilities if none found this run
                logging.info(f"No Website vulnerabilities found - clearing existing entries for {domain}")
                vuln_saved = save_website_vulnerabilities(domain, [], update_existing=True)
            
            db_status = 'success' if (score_saved and vuln_saved) else 'partial_failure'
            
        except Exception as db_error:
            logging.error(f"Error saving vulnerability scan results to database for {domain}: {db_error}")
            db_status = 'failed'
        
        # Log vulnerability scan summary for transparency
        logging.info(f"VULNERABILITY SCAN SUMMARY:")
        logging.info(f"   Vendor Domain: {domain}")
        logging.info(f"   Severity Weights Used: {severity_weights}")
        logging.info(f"   Subdomains Scanned: {processed_subdomains}")
        logging.info(f"   Total Vulnerabilities Found: {len(vulnerabilities_found)}")
        logging.info(f"   Global Severity Breakdown: {total_counts}")
        logging.info(f"   Final Vendor Score: {final_score}/{initial_score} ({(final_score/initial_score)*100:.1f}%)")
        
        logging.info(f"Vulnerability scan completed for {domain}. Final score: {final_score}/{initial_score}")
        
        # Auto-update overall vendor score after scan completion
        try:
            update_vendor_overall_score_after_scan(domain)
        except Exception as auto_update_error:
            logging.warning(f"Failed to auto-update overall score for {domain}: {auto_update_error}")
        
        return {
            'status': 'success',
            'domain': domain,
            'final_score': final_score,
            'max_score': initial_score,
            'subdomains_processed': processed_subdomains,
            'vulnerabilities': vulnerabilities_found,
            'summary': {
                'total_vulnerabilities': len(vulnerabilities_found),
                'by_severity': total_counts,
                'score_breakdown': {
                    'final_score': final_score,
                    'max_score': initial_score,
                    'percentage': round((final_score / initial_score) * 100, 2)
                }
            },
            'database_status': db_status
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error in vulnerability scan: {str(e)}")
        raise HTTPException(status_code=500, detail=f'Vulnerability scan failed: {str(e)}')


@app.post('/api/reputation/scan')
async def start_reputation_scan(data: dict = Body(...)):
    """Start a domain reputation scan"""
    try:
        domain = data.get('domain')
        scan_id = data.get('scan_id', f'rep_{int(time.time())}')
        
        if not domain:
            raise HTTPException(
                status_code=400,
                detail='Domain is required'
            )
        
        # Clean domain name
        domain = domain.strip().lower()
        domain = domain.replace('https://', '').replace('http://', '').replace('www.', '').split('/')[0]
        
        logging.info(f"Starting reputation scan for {domain} with scan ID {scan_id}")
        
        # Track this scan
        active_vulnerability_scans[scan_id] = {
            'domain': domain,
            'started': time.time(),
            'stopped': False
        }
        
        # Import and use the domain reputation scanner
        sys.path.append(app_join('Domain Reputation'))
        from domain_hybrid import scan_domain_reputation
        
        # Domain reputation scan - database integration only (no file generation)
        # Use the single domain reputation scan function (database integration only)
        logging.info(f"Starting domain reputation scan for single domain: {domain}")
        result = scan_domain_reputation(domain, None)
        
        if not result:
            raise HTTPException(
                status_code=500,
                detail='Reputation scan failed - API key not available'
            )
        
        # Clean up scan tracking
        if scan_id in active_vulnerability_scans:
            del active_vulnerability_scans[scan_id]
        
        # AbuseIPDB lookup failed — don't overwrite the stored score/findings with a placeholder
        if not result.get('checked', True):
            logging.warning(f"Reputation for {domain} not checked ({result.get('error')}) - keeping existing results")
            raise HTTPException(
                status_code=503,
                detail='Reputation lookup unavailable (AbuseIPDB) - existing results kept, please retry later'
            )
        
        # Save results to database
        try:
            # Save the domain reputation score
            logging.info(f"Saving Domain Reputation score {result['final_score']} for {domain} to database")
            score_saved = save_domain_reputation_score(domain, result['final_score'])
            
            # Prepare vulnerabilities for database storage
            vuln_data_for_db = []
            for issue in result['issues_found']:
                vuln_data_for_db.append({
                    'subdomain': issue.get('domain', domain),
                    'title': issue.get('issue_type', 'Reputation Issue'),
                    'description': issue.get('description', 'Domain reputation issue detected'),
                    'severity': issue.get('severity', 'Medium')
                })
            
            # Save vulnerabilities to database
            if vuln_data_for_db:
                logging.info(f"Saving {len(vuln_data_for_db)} Domain Reputation vulnerabilities for {domain} to database")
                vuln_saved = save_domain_reputation_vulnerabilities(domain, vuln_data_for_db, update_existing=True)
            else:
                logging.info(f"No Domain Reputation vulnerabilities found - clearing existing entries for {domain}")
                vuln_saved = save_domain_reputation_vulnerabilities(domain, [], update_existing=True)
            
            db_status = 'success' if (score_saved and vuln_saved) else 'partial_failure'
            
        except Exception as db_error:
            logging.error(f"Error saving reputation scan results to database for {domain}: {db_error}")
            db_status = 'failed'
        
        # Log reputation scan summary for transparency
        logging.info(f"REPUTATION SCAN SUMMARY:")
        logging.info(f"   Vendor Domain: {domain}")
        logging.info(f"   Domains Scanned: 1 (main domain only)")
        logging.info(f"   Total Issues Found: {len(result['issues_found'])}")
        logging.info(f"   Total Weight Deducted: {result['total_weight_deducted']}")
        logging.info(f"   Final Vendor Score: {result['final_score']}/{result['max_score']} ({(result['final_score']/result['max_score'])*100:.1f}%)")
        
        logging.info(f"Reputation scan completed for {domain}. Final score: {result['final_score']}/{result['max_score']}")
        
        # Auto-update overall vendor score after scan completion
        try:
            update_vendor_overall_score_after_scan(domain)
        except Exception as auto_update_error:
            logging.warning(f"Failed to auto-update overall score for {domain}: {auto_update_error}")
        
        return {
            'status': 'success',
            'domain': result['domain'],
            'final_score': result['final_score'],
            'max_score': result['max_score'],
            'vulnerabilities': result['issues_found'],
            'statistics': {
                'domains_processed': 1,
                'total_weight_deducted': result['total_weight_deducted']
            },
            'summary': {
                'total_issues': len(result['issues_found']),
                'total_weight_deducted': result['total_weight_deducted'],
                'score_breakdown': {
                    'final_score': result['final_score'],
                    'max_score': result['max_score'],
                    'percentage': round((result['final_score'] / result['max_score']) * 100, 2)
                }
            },
            'report_file': result['report_file'],
            'database_status': db_status
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error in reputation scan: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f'Reputation scan failed: {str(e)}'
        )


@app.post('/api/network/scan')
async def start_network_scan(data: dict = Body(...)):
    """Start a network ports scan"""
    try:
        if not data:
            raise HTTPException(status_code=400, detail='No data provided')
        
        domain = data.get('domain')
        if not domain:
            raise HTTPException(status_code=400, detail='Domain is required')
        
        # Clean domain name
        domain = domain.strip().lower()
        domain = domain.replace('https://', '').replace('http://', '').replace('www.', '').split('/')[0]
        
        # Generate scan ID
        scan_id = f"network_{domain}_{int(time.time())}"
        
        # Initialize scan tracking
        active_vulnerability_scans[scan_id] = {
            'domain': domain,
            'type': 'network',
            'status': 'running',
            'progress': 0,
            'logs': [],
            'start_time': datetime.now().isoformat()
        }
        
        # Start scan in thread
        scan_thread = threading.Thread(
            target=run_network_scan_api,
            args=(scan_id, domain)
        )
        scan_thread.daemon = True
        scan_thread.start()
        
        return {
            'scan_id': scan_id,
            'status': 'started',
            'message': f'Network scan started for {domain}'
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error starting network scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get('/api/network/scan/{scan_id}/status')
async def get_network_scan_status(scan_id: str):
    """Get the status of a network scan"""
    try:
        if scan_id not in active_vulnerability_scans:
            raise HTTPException(status_code=404, detail='Scan not found')
        
        scan_info = active_vulnerability_scans[scan_id]
        return scan_info
        
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error getting network scan status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post('/api/encryption/scan')
async def start_encryption_scan(data: dict = Body(...)):
    """Start an encryption scan for a domain"""
    try:
        domain = data.get('domain')
        scan_id = data.get('scan_id', f'enc_{int(time.time())}')
        
        if not domain:
            raise HTTPException(
                status_code=400,
                detail='Domain is required'
            )
        
        # Clean domain name
        domain = domain.strip().lower()
        domain = domain.replace('https://', '').replace('http://', '').replace('www.', '').split('/')[0]
        
        logging.info(f"Starting encryption scan for {domain} with scan ID {scan_id}")
        
        # Track this scan
        active_vulnerability_scans[scan_id] = {
            'domain': domain,
            'started': time.time(),
            'stopped': False,
            'status': 'starting',
            'progress': 0,
            'logs': ['Encryption scan started...'],
            'start_time': datetime.now().isoformat()
        }
        
        # Start scan in thread to make it asynchronous
        scan_thread = threading.Thread(
            target=run_encryption_scan_async,
            args=(scan_id, domain)
        )
        scan_thread.daemon = True
        scan_thread.start()
        
        return {
            'scan_id': scan_id,
            'status': 'started',
            'message': f'Encryption scan started for {domain}'
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error starting encryption scan: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f'Failed to start encryption scan: {str(e)}'
        )
    
def run_encryption_scan_async(scan_id, domain):
    """Run encryption scan asynchronously"""
    # Initialize output_filename to None (no file generation by default)
    output_filename = None
    
    try:
        # Import and use the encryption scanner
        from vendor_risk_scanner_local import VendorRiskScanner
        
        # Update progress
        active_vulnerability_scans[scan_id]['progress'] = 10
        active_vulnerability_scans[scan_id]['logs'].append("Checking subdomains...")
        active_vulnerability_scans[scan_id]['status'] = 'running'
        
        # Check if domain has Active subdomains in database first
        try:
            subdomains = get_subdomains_for_domain(domain)
            if subdomains:
                # Filter for only Active subdomains
                active_subdomains = [subdomain['subdomain'] for subdomain in subdomains if subdomain.get('status') == 'Active']
                
                if active_subdomains:
                    # Always include the main domain (assume it's active)
                    if domain not in active_subdomains:
                        active_subdomains.insert(0, domain)
                    
                    domains_to_scan = active_subdomains
                    total_count = len(subdomains)
                    active_count = len(active_subdomains) - (1 if domain in active_subdomains else 0)  # Exclude main domain from count
                    
                    logging.info(f"Found {len(domains_to_scan)} Active subdomains for {domain} encryption scan (including main domain)")
                    logging.info(f"Filtered from {total_count} total subdomains to {active_count} Active subdomains + main domain")
                else:
                    logging.info(f"No Active subdomains found for {domain} in database, scanning main domain only")
                    domains_to_scan = [domain]
            else:
                logging.info(f"No subdomains found for {domain} in database, scanning main domain only")
                domains_to_scan = [domain]
        except Exception as e:
            logging.warning(f"Error fetching subdomains from database: {e}")
            domains_to_scan = [domain]
        
        # Initialize scanner
        current_dir = app_join('Encryption', 'LOCAL')
        testssl_path = os.path.join(current_dir, "testssl.sh", "testssl.sh")
        scanner = VendorRiskScanner(testssl_path=testssl_path)
        
        scan_results = []
        vulnerabilities = []
        total_score = 0
        domain_count = 0
        total_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        initial_score = 950
        severity_weights = get_severity_weights('ENCRYPTION')
        individual_scores = []  # Track individual domain scores for detailed logging
        
        total_domains = len(domains_to_scan)
        for i, scan_domain in enumerate(domains_to_scan):
            if active_vulnerability_scans.get(scan_id, {}).get('stopped', False):
                logging.info(f"Encryption scan {scan_id} was stopped")
                break
            
            try:
                # Update progress based on domain being scanned
                progress = 20 + (i * 60 // total_domains)  # Progress from 20% to 80%
                active_vulnerability_scans[scan_id]['progress'] = progress
                active_vulnerability_scans[scan_id]['logs'].append(f"Scanning {scan_domain} for SSL/TLS vulnerabilities...")
                
                logging.info(f"Scanning {scan_domain} for encryption vulnerabilities (domain {i+1}/{total_domains})")
                
                # Perform encryption scan
                result = scanner.scan_domain(scan_domain, full_scan=True)
                scan_results.append(result)
                
                # Initialize domain-specific vulnerability count tracking
                domain_severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
                domain_count += 1
                
                # Extract testssl vulnerabilities
                testssl_results = result.get('testssl', {})
                logging.info(f"TestSSL results for {scan_domain}: {testssl_results}")
                if 'vulnerabilities' in testssl_results:
                    testssl_vulnerabilities = testssl_results['vulnerabilities']
                    logging.info(f"Found {len(testssl_vulnerabilities)} testssl vulnerabilities for {scan_domain}")
                    for vuln_name, vuln_data in testssl_vulnerabilities.items():
                        severity = vuln_data.get('severity', 'MEDIUM').upper()
                        if not severity:  # Handle empty severity
                            severity = 'MEDIUM'
                        
                        # Generate better vulnerability title for grouping
                        finding_text = vuln_data.get('finding', 'SSL/TLS vulnerability detected')
                        vulnerability_title = generate_encryption_vulnerability_title(vuln_name, finding_text)
                        
                        logging.info(f"TestSSL vulnerability: {vuln_name} - {severity} - {vuln_data}")
                        vulnerabilities.append({
                            'domain': scan_domain,
                            'vulnerability': vulnerability_title,
                            'severity': severity,
                            'description': finding_text,
                            'category': 'Encryption'
                        })
                        # Count by severity
                        if severity in total_counts:
                            total_counts[severity] += 1
                            domain_severity_counts[severity] += 1
                else:
                    logging.info(f"No testssl vulnerabilities found for {scan_domain}")
                    if 'error' in testssl_results:
                        logging.warning(f"TestSSL error for {scan_domain}: {testssl_results['error']}")
                
                # Extract enhanced security check issues
                enhanced_checks = result.get('enhanced_security_checks', {})
                logging.info(f"Enhanced security checks for {scan_domain}: {enhanced_checks}")
                if enhanced_checks and 'error' not in enhanced_checks:
                    # Check each security check for issues
                    check_names = {
                        'ssl_availability': 'SSL not available',
                        'hostname_certificate_match': 'The site hostname does not match the SSL certificate',
                        'http_to_https_redirect': 'HTTP does not redirect to HTTPS', 
                        'https_redirect_support': 'HTTPS redirect not supported',
                        'ssl_expired': 'SSL expired',
                        'untrusted_ssl_certificate': 'Untrusted SSL certificate (Provisional)',
                        'diffie_hellman_strength': 'Common Diffie-Hellman prime used in key exchange',
                        'hsts_enforcement': 'HTTP Strict Transport Security (HSTS) not enforced',
                        'insecure_cipher_suites': 'Insecure cipher suite supported',
                        'insecure_ssl_versions': 'Insecure SSL/TLS versions available',
                        'weak_tls12_ciphers': 'Only weak cipher suites supported in TLS 1.2',
                        'ssl_certificate_chain': 'SSL certificate chain missing from server response',
                        'ssl_expiration_period': 'SSL expiration period longer than 398 days',
                        'ssl_expires_soon': 'SSL expires within 20 days',
                        'weak_ssl_algorithm': 'Weak SSL algorithm',
                        'hsts_preload_list': 'Domain was not found on the HSTS preload list',
                        'hsts_includesubdomains': 'HSTS header does not contain includeSubDomains',
                        'weak_dh_key_exchange': 'Weak Diffie-Hellman prime used in key exchange',
                        'weak_public_key_length': 'Weak public certificate key length',
                        'revoked_certificate': 'Revoked certificate in use'
                    }
                    
                    # Map each check to its severity based on the rubric
                    severity_mapping = {
                        'ssl_availability': 'CRITICAL',
                        'hostname_certificate_match': 'HIGH', 
                        'http_to_https_redirect': 'HIGH',
                        'https_redirect_support': 'MEDIUM',
                        'ssl_expired': 'HIGH',
                        'untrusted_ssl_certificate': 'HIGH',
                        'diffie_hellman_strength': 'MEDIUM',
                        'hsts_enforcement': 'MEDIUM',
                        'insecure_cipher_suites': 'MEDIUM',
                        'insecure_ssl_versions': 'MEDIUM',
                        'weak_tls12_ciphers': 'MEDIUM',
                        'ssl_certificate_chain': 'MEDIUM',
                        'ssl_expiration_period': 'MEDIUM',
                        'ssl_expires_soon': 'MEDIUM',
                        'weak_ssl_algorithm': 'MEDIUM',
                        'hsts_preload_list': 'LOW',
                        'hsts_includesubdomains': 'LOW',
                        'weak_dh_key_exchange': 'LOW',
                        'weak_public_key_length': 'LOW',
                        'revoked_certificate': 'CRITICAL'
                    }
                    
                    for check_key, check_name in check_names.items():
                        if check_key in enhanced_checks and check_key != 'summary':
                            check_result = enhanced_checks[check_key]
                            if check_result.get('issue'):
                                # Get severity from mapping
                                severity = severity_mapping.get(check_key, 'MEDIUM')
                                
                                vulnerabilities.append({
                                    'domain': scan_domain,
                                    'vulnerability': check_name,
                                    'severity': severity,
                                    'description': check_result['issue'],
                                    'category': 'Encryption'
                                })
                                # Count by severity
                                if severity in total_counts:
                                    total_counts[severity] += 1
                                    domain_severity_counts[severity] += 1
                    
                    # Additional certificate-based vulnerability checks
                    cert_details = result.get('certificate_details', {})
                    if cert_details and 'error' not in cert_details:
                        # Check SSL expiration
                        days_until_expiry = cert_details.get('days_until_expiry')
                        if isinstance(days_until_expiry, int):
                            if days_until_expiry <= 0:
                                vulnerabilities.append({
                                    'domain': scan_domain,
                                    'vulnerability': 'SSL expired',
                                    'severity': 'HIGH',
                                    'description': 'SSL certificate has expired',
                                    'category': 'Encryption'
                                })
                                total_counts['HIGH'] += 1
                                domain_severity_counts['HIGH'] += 1
                            elif days_until_expiry <= 20:
                                vulnerabilities.append({
                                    'domain': scan_domain,
                                    'vulnerability': 'SSL expires within 20 days',
                                    'severity': 'MEDIUM',
                                    'description': f'SSL certificate expires in {days_until_expiry} days',
                                    'category': 'Encryption'
                                })
                                total_counts['MEDIUM'] += 1
                                domain_severity_counts['MEDIUM'] += 1
                            elif days_until_expiry > 398:
                                vulnerabilities.append({
                                    'domain': scan_domain,
                                    'vulnerability': 'SSL expiration period longer than 398 days',
                                    'severity': 'MEDIUM',
                                    'description': f'SSL certificate validity period exceeds 398 days',
                                    'category': 'Encryption'
                                })
                                total_counts['MEDIUM'] += 1
                                domain_severity_counts['MEDIUM'] += 1
                        
                        # Check weak SSL algorithm
                        key_algorithm = cert_details.get('key_algorithm', '').lower()
                        if any(weak_alg in key_algorithm for weak_alg in ['md5', 'sha1', 'des']):
                            vulnerabilities.append({
                                'domain': scan_domain,
                                'vulnerability': 'Weak SSL algorithm',
                                'severity': 'MEDIUM',
                                'description': f'Certificate uses weak signature algorithm: {key_algorithm}',
                                'category': 'Encryption'
                            })
                            total_counts['MEDIUM'] += 1
                            domain_severity_counts['MEDIUM'] += 1
                        
                        # Check weak public key length
                        key_size = cert_details.get('key_size', '')
                        if 'bits' in key_size:
                            try:
                                key_bits = int(key_size.split()[0])
                                if key_bits < 2048:
                                    vulnerabilities.append({
                                        'domain': scan_domain,
                                        'vulnerability': 'Weak public certificate key length',
                                        'severity': 'LOW',
                                        'description': f'Certificate key size ({key_bits} bits) is below recommended 2048 bits',
                                        'category': 'Encryption'
                                    })
                                    total_counts['LOW'] += 1
                                    domain_severity_counts['LOW'] += 1
                            except (ValueError, IndexError):
                                pass
                    
                    # Check HSTS-specific issues from enhanced checks
                    hsts_check = enhanced_checks.get('hsts_enforcement', {})
                    if hsts_check.get('hsts_enforced') and not hsts_check.get('preload', False):
                        vulnerabilities.append({
                            'domain': scan_domain,
                            'vulnerability': 'Domain was not found on the HSTS preload list',
                            'severity': 'LOW',
                            'description': 'HSTS header lacks preload directive',
                            'category': 'Encryption'
                        })
                        total_counts['LOW'] += 1
                        domain_severity_counts['LOW'] += 1
                    
                    if hsts_check.get('configuration_issues'):
                        for issue in hsts_check['configuration_issues']:
                            if 'includeSubDomains' in issue:
                                vulnerabilities.append({
                                    'domain': scan_domain,
                                    'vulnerability': 'HSTS header does not contain includeSubDomains',
                                    'severity': 'LOW',
                                    'description': issue,
                                    'category': 'Encryption'
                                })
                                total_counts['LOW'] += 1
                                domain_severity_counts['LOW'] += 1
                                break
                
                # Calculate domain score based on severity weights
                domain_score = initial_score
                score_deductions = {}
                total_deducted = 0
                
                for severity, count in domain_severity_counts.items():
                    if count > 0:
                        deduction = count * severity_weights.get(severity, 0)
                        score_deductions[severity] = deduction
                        total_deducted += deduction
                        domain_score -= deduction
                
                domain_score = max(0, domain_score)  # Ensure score doesn't go below 0
                total_score += domain_score
                
                # Store individual score data
                individual_scores.append({
                    'domain': scan_domain,
                    'score': domain_score,
                    'vulnerabilities': domain_severity_counts,
                    'deductions': score_deductions,
                    'total_deducted': total_deducted
                })
                
                # Enhanced logging for this domain
                severity_breakdown = ', '.join([f"{sev}: {count}" for sev, count in domain_severity_counts.items() if count > 0])
                deduction_breakdown = ', '.join([f"{sev}: -{deduction}" for sev, deduction in score_deductions.items()])
                
                logging.info(f" Domain: {scan_domain}")
                logging.info(f"   Starting Score: {initial_score}")
                logging.info(f"   Vulnerabilities: {severity_breakdown}")
                logging.info(f"   Score Deductions: {deduction_breakdown}")
                logging.info(f"   Total Deducted: -{total_deducted}")
                logging.info(f"   Final Score: {domain_score}/{initial_score}")
                
            except Exception as e:
                logging.error(f"Error scanning {scan_domain}: {e}")
                continue
        
        logging.info(f"Total vulnerabilities found across all domains: {len(vulnerabilities)}")
        logging.info(f"Severity breakdown: {total_counts}")
        
        # Log detailed final score calculation
        logging.info(f" FINAL SCORE CALCULATION:")
        logging.info(f"   Domains Scanned: {domain_count}")
        
        if domain_count > 0:
            # Log individual scores summary
            logging.info(f"   Individual Domain Scores:")
            for score_data in individual_scores:
                domain_name = score_data['domain']
                domain_score = score_data['score']
                total_vulns = sum(score_data['vulnerabilities'].values())
                deducted = score_data['total_deducted']
                logging.info(f"     • {domain_name}: {domain_score}/{initial_score} ({total_vulns} vulns, -{deducted} points)")
            
            # Log final calculation
            logging.info(f"   Total Score Sum: {total_score}")
            logging.info(f"   Average Calculation: {total_score} ÷ {domain_count} = {total_score / domain_count:.2f}")
            final_score = int(total_score / domain_count)
            logging.info(f"   Final Score (rounded): {final_score}/{initial_score}")
            
            # Log score distribution analysis
            scores_only = [s['score'] for s in individual_scores]
            min_score = min(scores_only)
            max_score = max(scores_only)
            score_range = max_score - min_score
            logging.info(f"   Score Range: {min_score} to {max_score} (spread: {score_range})")
        else:
            final_score = initial_score
            logging.info(f"   No domains scanned, using initial score: {final_score}")
        
        # Check if scan was stopped
        scan_stopped = scan_id in active_vulnerability_scans and active_vulnerability_scans[scan_id]['stopped']
        
        if scan_stopped:
            logging.info(f"Encryption scan {scan_id} was stopped before completion")
            active_vulnerability_scans[scan_id].update({
                'status': 'stopped',
                'progress': 100,
                'logs': active_vulnerability_scans[scan_id]['logs'] + ['Scan was stopped by user'],
                'end_time': datetime.now().isoformat(),
                'results': {
                    'status': 'stopped',
                    'domain': domain,
                    'message': 'Scan was stopped by user',
                    'domains_processed': domain_count,
                    'vulnerabilities': vulnerabilities
                }
            })
            return
        
        # Update progress for database saving
        active_vulnerability_scans[scan_id]['progress'] = 85
        active_vulnerability_scans[scan_id]['logs'].append("Saving scan results to database...")
        
        # Save results to database
        db_status = "success"
        try:
            save_encryption_score(domain, final_score)
            
            # Prepare vulnerabilities for database storage with proper subdomain mapping
            vuln_data_for_db = []
            for vuln in vulnerabilities:
                vuln_data_for_db.append({
                    'subdomain': vuln.get('domain', domain),  # Use 'domain' field from vuln as 'subdomain' for DB
                    'title': vuln.get('vulnerability', 'SSL/TLS Security Issue'),
                    'description': vuln.get('description', 'Encryption security issue detected'),
                    'severity': vuln.get('severity', 'MEDIUM')
                })
            
            if vuln_data_for_db:
                logging.info(f"Saving {len(vuln_data_for_db)} Encryption vulnerabilities for {domain} to database")
                save_encryption_vulnerabilities(domain, vuln_data_for_db, update_existing=True)
            else:
                logging.info(f"No Encryption vulnerabilities found - clearing existing entries for {domain}")
                save_encryption_vulnerabilities(domain, [], update_existing=True)
            
            logging.info(f"Saved encryption scan results for {domain} to database")
        except Exception as e:
            logging.error(f"Error saving encryption results to database: {e}")
            db_status = f"database_error: {str(e)}"
        
        logging.info(f"ENCRYPTION SCAN SUMMARY:")
        logging.info(f"   Vendor Domain: {domain}")
        logging.info(f"   Severity Weights Used: {severity_weights}")
        logging.info(f"   Domains/Subdomains Scanned: {domain_count}")
        logging.info(f"   Total Vulnerabilities Found: {len(vulnerabilities)}")
        logging.info(f"   Global Severity Breakdown: {total_counts}")
        logging.info(f"   Final Vendor Score: {final_score}/{initial_score} ({(final_score/initial_score)*100:.1f}%)")
        
        logging.info(f"Encryption scan completed for {domain}. Final score: {final_score}/{initial_score}")
        
        # Final progress update
        active_vulnerability_scans[scan_id]['progress'] = 95
        active_vulnerability_scans[scan_id]['logs'].append("Finalizing scan results...")
        
        # Auto-update overall vendor score after scan completion
        try:
            update_vendor_overall_score_after_scan(domain)
        except Exception as auto_update_error:
            logging.warning(f"Failed to auto-update overall score for {domain}: {auto_update_error}")
        
        # Update scan status to completed
        active_vulnerability_scans[scan_id].update({
            'status': 'completed',
            'progress': 100,
            'logs': active_vulnerability_scans[scan_id]['logs'] + ['Encryption scan completed successfully'],
            'end_time': datetime.now().isoformat(),
            'results': {
                'status': 'success',
                'domain': domain,
                'final_score': final_score,
                'max_score': initial_score,
                'subdomains_processed': domain_count,
                'vulnerabilities': vulnerabilities,
                'statistics': {
                    'domains_processed': domain_count,
                    **total_counts
                },
                'summary': {
                    'total_vulnerabilities': len(vulnerabilities),
                    'by_severity': total_counts,
                    'score_breakdown': {
                        'final_score': final_score,
                        'max_score': initial_score,
                        'percentage': round((final_score / initial_score) * 100, 2)
                    }
                },
                'report_file': output_filename,
                'database_status': db_status
            }
        })
        
    except Exception as e:
        logging.error(f"Error in encryption scan for {domain}: {e}")
        active_vulnerability_scans[scan_id].update({
            'status': 'failed',
            'progress': 0,
            'logs': active_vulnerability_scans[scan_id]['logs'] + [f'Error: {str(e)}'],
            'end_time': datetime.now().isoformat(),
            'error': str(e)
        })


@app.get('/api/encryption/scan/{scan_id}/status')
async def get_encryption_scan_status(scan_id: str):
    """Get the status of an encryption scan"""
    try:
        if scan_id not in active_vulnerability_scans:
            raise HTTPException(status_code=404, detail='Scan not found')
        
        scan_info = active_vulnerability_scans[scan_id]
        return scan_info
        
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error getting encryption scan status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get('/api/dashboard/stats')
async def get_dashboard_stats():
    """Get real-time dashboard statistics from cache/database"""
    try:
        # Get statistics from cache or database
        stats = get_dashboard_stats_cached()
        
        # Ensure all required fields are present for frontend compatibility
        required_fields = {
            'active_vendors': 0,
            'subdomains_monitored': 0,
            'vulnerabilities_found': 0,
            'high_risk_issues': 0,
            'overall_score': 0,
            'score_percentage': 0,
            'severity_breakdown': {},
            'risk_distribution': {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
        }
        
        # Merge database results with defaults to ensure no missing fields
        for field, default_value in required_fields.items():
            if field not in stats:
                stats[field] = default_value
        
        # Add total_vendors for frontend percentage calculations
        stats['total_vendors'] = stats['active_vendors']
        
        logging.info(f"Dashboard stats loaded from database: {stats}")
        return stats
        
    except Exception as e:
        logging.error(f"Error getting dashboard stats from database: {e}")
        # Fallback to default stats if database fails
        return {
            'active_vendors': 0,
            'subdomains_monitored': 0,
            'vulnerabilities_found': 0,
            'high_risk_issues': 0,
            'overall_score': 0,
            'score_percentage': 0,
            'total_vendors': 0,
            'severity_breakdown': {},
            'risk_distribution': {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
        }

# Removed file parsing functions - all scans now use database-only storage
@app.get('/api/dashboard/recent-scans')
async def get_recent_scans():
    """Get recent scan results from database showing latest unique domain+scan_type combinations"""
    try:
        # Import the database function
        from db_service import get_recent_scans_from_database
        
        logging.info("Starting recent scans query...")
        
        # Get recent scans from database
        recent_scans = get_recent_scans_from_database()
        
        logging.info(f"Retrieved {len(recent_scans)} recent scans from database")
        
        # Debug: log first few scans
        if recent_scans:
            for i, scan in enumerate(recent_scans[:2]):
                logging.info(f"Scan {i+1}: {scan}")
        else:
            logging.warning("No recent scans found in database")
            
            # Let's check if there are any scores at all
            try:
                from db_config import DatabaseConnection
                with DatabaseConnection() as db:
                    score_count = db.execute_single_query("SELECT COUNT(*) as count FROM scores")
                    logging.info(f"Total scores in database: {score_count}")
                    
                    if score_count and score_count['count'] > 0:
                        sample_scores = db.execute_query("SELECT s.id, s.score_category, s.score, s.updated_at, v.vendor_name, v.domain FROM scores s JOIN vendors v ON s.vendor_id = v.id ORDER BY s.updated_at DESC LIMIT 3")
                        logging.info(f"Sample scores: {sample_scores}")
                    else:
                        logging.warning("No scores found in database - need to run scans first")
            except Exception as debug_e:
                logging.error(f"Debug query failed: {debug_e}")
        
        return {'recent_scans': recent_scans}
        
    except Exception as e:
        logging.error(f"Error getting recent scans from database: {e}")
        import traceback
        logging.error(f"Full traceback: {traceback.format_exc()}")
        # Return empty list with proper structure if database fails
        return {'recent_scans': []}


from fastapi.responses import FileResponse, Response



def run_subdomain_discovery_background(scan_id, domain, force_rediscovery):
    """Run subdomain discovery in background thread for main domain and additional domains"""
    try:
        logging.info(f"Starting background subdomain discovery for {domain} with scan ID {scan_id}")
        
        # Update status
        active_subdomain_scans[scan_id]['status'] = 'running'
        active_subdomain_scans[scan_id]['stage'] = 'domain_collection'
        active_subdomain_scans[scan_id]['progress'] = 5
        active_subdomain_scans[scan_id]['logs'].append('Collecting all domains for discovery...')
        
        # Get all domains (main + additional) for subdomain discovery
        all_domains_to_scan = get_all_domains_for_discovery(domain)
        logging.info(f"Will perform subdomain discovery for {len(all_domains_to_scan)} domains: {all_domains_to_scan}")
        
        # Import subdomain functions from the enhanced script
        sys.path.append(app_join('Sublist3r_New'))
        from subdomains_sub import find_subdomains_sublist3r, find_subdomains_crtsh, find_alive_subdomains
        
        # Initialize combined subdomain sets
        all_subdomains_combined = set()
        
        # Process each domain
        for i, current_domain in enumerate(all_domains_to_scan):
            domain_prefix = f"[{i+1}/{len(all_domains_to_scan)}]"
            logging.info(f"{domain_prefix} Processing domain: {current_domain}")
            
            # Update progress and status
            base_progress = 10 + (i * 30 // len(all_domains_to_scan))
            active_subdomain_scans[scan_id]['progress'] = base_progress
            active_subdomain_scans[scan_id]['stage'] = f'sublist3r_{current_domain}'
            active_subdomain_scans[scan_id]['logs'].append(f'{domain_prefix} Running Sublist3r for {current_domain}...')
            
            # Use the enhanced method - combine Sublist3r and crt.sh for each domain
            # logging.info(f"{domain_prefix} Finding subdomains using Sublist3r for {current_domain}")
            # sublister_set = find_subdomains_sublist3r(current_domain)
            # logging.info(f"{domain_prefix} Found {len(sublister_set)} subdomains using Sublist3r for {current_domain}")
            
            # Update progress
            active_subdomain_scans[scan_id]['progress'] = base_progress + 10
            active_subdomain_scans[scan_id]['stage'] = f'crtsh_{current_domain}'
            active_subdomain_scans[scan_id]['logs'].append(f'{domain_prefix} Querying crt.sh for {current_domain}...')

            logging.info(f"{domain_prefix} Finding subdomains using crt.sh for {current_domain}")
            crtsh_set = find_subdomains_crtsh(current_domain)
            logging.info(f"{domain_prefix} Found {len(crtsh_set)} subdomains using crt.sh for {current_domain}")

            # Combine subdomains for this domain
            domain_subdomains = crtsh_set
            all_subdomains_combined.update(domain_subdomains)
            logging.info(f"{domain_prefix} Total subdomains for {current_domain}: {len(domain_subdomains)}")
            
            active_subdomain_scans[scan_id]['logs'].append(f'{domain_prefix} Completed {current_domain}: {len(domain_subdomains)} subdomains found')

        # Convert to sorted list for consistency
        all_subdomains = sorted(all_subdomains_combined)
        logging.info(f"Total unique subdomains from all domains: {len(all_subdomains)}")
        
        # Update progress
        active_subdomain_scans[scan_id]['progress'] = 50
        active_subdomain_scans[scan_id]['stage'] = 'pattern_filtering'
        active_subdomain_scans[scan_id]['logs'].append(f'Found {len(all_subdomains)} total unique subdomains. Applying pattern filtering for all domains...')
        
        # Apply pattern-based filtering for all domains
        logging.info(f"Applying pattern-based filtering for {domain} and additional domains")
        filtering_results = filter_subdomains_by_patterns(domain, all_subdomains, all_domains_to_scan)
        
        # Get the filtered subdomains to check
        target_subdomains = filtering_results['all_target_subdomains']
        filtered_existing = filtering_results['filtered_existing']
        generated_combinations = filtering_results['generated_combinations']
        
        logging.info(f"Pattern filtering completed:")
        logging.info(f"  - Filtered existing subdomains: {len(filtered_existing)}")
        logging.info(f"  - Generated combinations: {len(generated_combinations)}")
        logging.info(f"  - Total target subdomains to check: {len(target_subdomains)}")
        
        # Update progress
        active_subdomain_scans[scan_id]['progress'] = 70
        active_subdomain_scans[scan_id]['stage'] = 'alive_check'
        active_subdomain_scans[scan_id]['logs'].append(f'Pattern filtering completed. Checking {len(target_subdomains)} target subdomains for availability...')
        
        # Find alive subdomains from the filtered/target list
        logging.info(f"Checking which target subdomains are alive for {domain}")
        alive_subdomains = find_alive_subdomains(target_subdomains)
        logging.info(f"Found {len(alive_subdomains)} alive subdomains from {len(target_subdomains)} target subdomains")
        
        # Update progress
        active_subdomain_scans[scan_id]['progress'] = 90
        active_subdomain_scans[scan_id]['stage'] = 'saving'
        active_subdomain_scans[scan_id]['logs'].append(f'Found {len(alive_subdomains)} active subdomains. Saving to database...')
        
        # Calculate statistics based on target subdomains (filtered + generated)
        total_target_count = len(target_subdomains)
        alive_count = len(alive_subdomains)
        inactive_count = total_target_count - alive_count
        success_rate = (alive_count / total_target_count * 100) if total_target_count > 0 else 0
        
        # Create detailed results for target subdomains only
        subdomain_details = []
        alive_set = set(alive_subdomains)
        
        for subdomain in target_subdomains:
            is_alive = subdomain in alive_set
            subdomain_type = 'existing' if subdomain in filtered_existing else 'generated'
            subdomain_details.append({
                'subdomain': subdomain,
                'status': 'alive' if is_alive else 'inactive',
                'type': subdomain_type
            })
        
        # Note: File saving removed - using database integration instead
        logging.info(f"Subdomain discovery completed - results will be saved to database")
        
        # Save subdomains to database with Active/Inactive status
        try:
            replace_existing = force_rediscovery
            
            logging.info(f"Saving {len(target_subdomains)} target subdomains to database for {domain} with status detection")
            logging.info(f"Replace mode: {replace_existing}")
            
            # Use the status-aware save function with target subdomains
            db_save_success = save_subdomains_with_status_detection(domain, target_subdomains, alive_subdomains, replace_existing)
            
            if db_save_success:
                logging.info(f"Successfully saved subdomains with status to database for {domain}")
                # Invalidate cache after successful save
                invalidate_subdomain_cache(domain)
            else:
                logging.warning(f"Failed to save subdomains to database for {domain}")
        except Exception as db_error:
            logging.error(f"Error saving subdomains to database for {domain}: {db_error}")
            db_save_success = False
        
        # Store final results in scan tracking
        final_results = {
            'status': 'completed',
            'domain': domain,
            'method': 'Enhanced Pattern-Filtered (Sublist3r + crt.sh + Generated)' + (' - Forced Rediscovery' if force_rediscovery else ''),
            'skipped_discovery': False,
            'statistics': {
                'total': total_target_count,
                'alive': alive_count,
                'inactive': inactive_count,
                'success_rate': round(success_rate, 2),
                'original_discovered': len(all_subdomains),
                'filtered_existing': len(filtered_existing),
                'generated_combinations': len(generated_combinations),
                'crtsh_count': len(crtsh_set),
                'from_database': False,
                'pattern_filtered': True
            },
            'filtering_results': {
                'found_patterns': filtering_results['found_patterns'],
                'missing_patterns': filtering_results['missing_patterns']
            },
            'subdomains': subdomain_details,
            'database_saved': db_save_success,
            'storage_mode': 'replace_all' if replace_existing else 'incremental'
        }
        
        # Update scan completion
        active_subdomain_scans[scan_id]['status'] = 'completed'
        active_subdomain_scans[scan_id]['progress'] = 100
        active_subdomain_scans[scan_id]['stage'] = 'completed'
        active_subdomain_scans[scan_id]['end_time'] = datetime.now()
        active_subdomain_scans[scan_id]['results'] = final_results
        active_subdomain_scans[scan_id]['logs'].append(f'Discovery completed: {alive_count}/{total_target_count} active subdomains from target patterns')
        
        logging.info(f"Pattern-filtered subdomain discovery completed for {domain}: {alive_count}/{total_target_count} alive from target patterns ({success_rate:.2f}% success rate)")
        
    except Exception as e:
        logging.error(f"Error in background subdomain discovery for {domain}: {str(e)}")
        if scan_id in active_subdomain_scans:
            active_subdomain_scans[scan_id]['status'] = 'error'
            active_subdomain_scans[scan_id]['error'] = str(e)
            active_subdomain_scans[scan_id]['logs'].append(f'Error: {str(e)}')

def run_network_scan_api(scan_id, domain):
    """Run network scan using the API module and save to database"""
    try:
        # Import network scanner API
        from network_scanner_api import scan_network_ports
        
        # Update progress
        active_vulnerability_scans[scan_id]['progress'] = 10
        active_vulnerability_scans[scan_id]['logs'].append("Starting network ports scan...")
        
        # Get Active subdomains only for this domain
        try:
            subdomains = get_subdomains_for_domain(domain)
            if subdomains:
                # Filter for only Active subdomains
                active_subdomains = [item['subdomain'] for item in subdomains if item.get('status') == 'Active']
                subdomain_list = active_subdomains if active_subdomains else None
                
                total_count = len(subdomains)
                active_count = len(active_subdomains) if active_subdomains else 0
                logging.info(f"Found {active_count} Active subdomains out of {total_count} total for {domain} network scan")
                
                # If no active subdomains, we'll scan the main domain
                if not active_subdomains:
                    logging.info(f"No active subdomains found for {domain}. Will scan main domain instead.")
            else:
                subdomain_list = None
                logging.info(f"No subdomains found for {domain}. Will scan main domain instead.")
        except Exception as e:
            logging.warning(f"Could not get subdomains from database for {domain}: {e}. Will scan main domain instead.")
            subdomain_list = None
        
        active_vulnerability_scans[scan_id]['progress'] = 20
        active_vulnerability_scans[scan_id]['logs'].append("Scanning network ports...")
        
        # Run the network scan
        result = scan_network_ports(domain, subdomain_list)
        
        if not result:
            active_vulnerability_scans[scan_id]['status'] = 'failed'
            active_vulnerability_scans[scan_id]['logs'].append("Network scan failed")
            return
        
        active_vulnerability_scans[scan_id]['progress'] = 80
        active_vulnerability_scans[scan_id]['logs'].append("Processing scan results...")
        
        # Clean up scan tracking
        if scan_id in active_vulnerability_scans:
            del active_vulnerability_scans[scan_id]
        
        # Save results to database
        try:
            # Save the network score
            logging.info(f"Saving Network score {result['final_score']} for {domain} to database")
            score_saved = save_network_score(domain, result['final_score'])
            
            # Prepare vulnerabilities for database storage
            vuln_data_for_db = []
            for issue in result['issues_found']:
                vuln_data_for_db.append({
                    'subdomain': issue.get('subdomain', domain),
                    'title': f"Port {issue.get('port', 'Unknown')} ({issue.get('service', 'Unknown')})",
                    'description': issue.get('description', 'Network port finding'),
                    'severity': issue.get('severity', 'INFO')
                })
            
            # Save vulnerabilities to database
            if vuln_data_for_db:
                logging.info(f"Saving {len(vuln_data_for_db)} Network vulnerabilities for {domain} to database")
                vuln_saved = save_network_vulnerabilities(domain, vuln_data_for_db, update_existing=True)
            else:
                logging.info(f"No Network vulnerabilities found - clearing existing entries for {domain}")
                vuln_saved = save_network_vulnerabilities(domain, [], update_existing=True)
            
            db_status = 'success' if (score_saved and vuln_saved) else 'partial_failure'
            
        except Exception as db_error:
            logging.error(f"Error saving network scan results to database for {domain}: {db_error}")
            db_status = 'failed'
        
        # Log network scan summary for transparency
        logging.info(f"NETWORK SCAN SUMMARY:")
        logging.info(f"   Vendor Domain: {domain}")
        logging.info(f"   Subdomains Scanned: {result.get('processed_subdomains', 0)}")
        logging.info(f"   Total Issues Found: {len(result['issues_found'])}")
        logging.info(f"   Severity Breakdown: {result['statistics']}")
        logging.info(f"   Final Vendor Score: {result['final_score']}/{result['max_score']} ({(result['final_score']/result['max_score'])*100:.1f}%)")
        
        logging.info(f"Network scan completed for {domain}. Final score: {result['final_score']}/{result['max_score']}")
        
        # Auto-update overall vendor score after scan completion
        try:
            update_vendor_overall_score_after_scan(domain)
        except Exception as auto_update_error:
            logging.warning(f"Failed to auto-update overall score for {domain}: {auto_update_error}")
        
        # Store result data for API response
        active_vulnerability_scans[scan_id] = {
            'status': 'completed',
            'progress': 100,
            'domain': domain,
            'type': 'network',
            'final_score': result['final_score'],
            'max_score': result['max_score'],
            'processed_subdomains': result.get('processed_subdomains', 0),
            'statistics': result['statistics'],
            'vulnerabilities': result['issues_found'],
            'db_status': db_status,
            'logs': ['Network scan completed successfully']
        }
        
    except Exception as e:
        logging.error(f"Error in network scan for {domain}: {e}")
        active_vulnerability_scans[scan_id]['status'] = 'failed'
        active_vulnerability_scans[scan_id]['logs'].append(f"Network scan failed: {e}")


def stop_active_scan(scan_id):
    """Stop an active scan by scan ID"""
    if scan_id in active_vulnerability_scans:
        active_vulnerability_scans[scan_id]['stopped'] = True
        logging.info(f"Marked vulnerability scan {scan_id} for stopping")
        return True
    return False

@app.post('/api/dns/scan')
async def start_dns_scan(data: dict = Body(...)):
    """Start a DNS security scan (async like network scan)"""
    try:
        if not data:
            raise HTTPException(status_code=400, detail='No data provided')
        
        domain = data.get('domain')
        if not domain:
            raise HTTPException(status_code=400, detail='Domain is required')
        
        # Clean domain name
        domain = domain.strip().lower()
        domain = domain.replace('https://', '').replace('http://', '').replace('www.', '').split('/')[0]
        
        # Generate scan ID
        scan_id = f"dns_{domain}_{int(time.time())}"
        
        # Initialize scan tracking
        active_vulnerability_scans[scan_id] = {
            'domain': domain,
            'type': 'dns',
            'status': 'running',
            'progress': 0,
            'logs': [],
            'start_time': datetime.now().isoformat()
        }
        
        # Start scan in thread
        scan_thread = threading.Thread(
            target=run_dns_scan_api,
            args=(scan_id, domain)
        )
        scan_thread.daemon = True
        scan_thread.start()
        
        return {
            'scan_id': scan_id,
            'status': 'started',
            'message': f'DNS security scan started for {domain}'
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error starting DNS security scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get('/api/dns/scan/{scan_id}/status')
async def get_dns_scan_status(scan_id: str):
    """Get the status of a DNS security scan"""
    try:
        if scan_id not in active_vulnerability_scans:
            raise HTTPException(status_code=404, detail='DNS scan not found')
        
        scan = active_vulnerability_scans[scan_id]
        
        # Calculate runtime
        start_time = scan.get('start_time')
        runtime = None
        if start_time:
            try:
                start_dt = datetime.fromisoformat(start_time)
                runtime_delta = datetime.now() - start_dt
                runtime = str(runtime_delta).split('.')[0]  # Remove microseconds
            except:
                runtime = "Unknown"
        
        return {
            'status': 'success',
            'scan': {
                'scan_id': scan_id,
                'domain': scan['domain'],
                'type': scan.get('type', 'dns'),
                'status': scan.get('status', 'running'),
                'progress': scan.get('progress', 0),
                'runtime': runtime,
                'start_time': start_time,
                'logs': scan.get('logs', [])[-5:],  # Last 5 log entries
                'result': scan.get('result'),
                'error': scan.get('error')
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error getting DNS scan status: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


def run_dns_scan_api(scan_id, domain):
    """Run DNS security scan in background thread"""
    try:
        logging.info(f"Starting DNS security scan for {domain} (scan_id: {scan_id})")
        
        # Update progress
        if scan_id in active_vulnerability_scans:
            active_vulnerability_scans[scan_id]['progress'] = 10
            active_vulnerability_scans[scan_id]['logs'].append('Initializing DNS scanner...')
        
        # Import DNS scanner via package to avoid config shadowing
        sys.path.insert(0, str(get_app_root()))
        from DNS.scanner import scan_domain_dns_security

        # Update progress
        if scan_id in active_vulnerability_scans:
            active_vulnerability_scans[scan_id]['progress'] = 20
            active_vulnerability_scans[scan_id]['logs'].append('Checking subdomains...')

        # Check if domain has subdomains in database for DNS scan
        try:
            logging.info(f"Checking if {domain} has subdomains in database for DNS scan")
            has_subdomains = check_domain_has_subdomains(domain)
            
            if has_subdomains:
                # Fetch Active subdomains from database and use them for DNS scan
                logging.info(f"Subdomains found for {domain} in database, fetching Active ones for DNS scan")
                subdomain_data = get_subdomains_for_domain(domain)
                
                # Filter for only Active subdomains
                active_subdomains = [item['subdomain'] for item in subdomain_data if item.get('status') == 'Active']
                
                # Always include the main domain (assume it's active)
                if domain not in active_subdomains:
                    active_subdomains.insert(0, domain)
                
                subdomains = active_subdomains
                total_count = len(subdomain_data)
                active_count = len(active_subdomains) - (1 if domain in active_subdomains else 0)
                
                logging.info(f"Using {len(subdomains)} Active subdomains from database for DNS scan (including main domain)")
                logging.info(f"Filtered from {total_count} total subdomains to {active_count} Active subdomains + main domain")
                logging.info(f"Active subdomains for DNS scan: {subdomains[:3]}{'...' if len(subdomains) > 3 else ''}")
            else:
                # No subdomains in database, use main domain only
                logging.warning(f"No subdomains found in database for {domain}, using main domain only for DNS scan")
                subdomains = [domain]
                logging.info(f"Using main domain only for DNS scan: {domain}")
        except Exception as db_error:
            logging.error(f"Error checking subdomains from database for DNS scan: {db_error}")
            subdomains = [domain]
            logging.info(f"Database error, will scan main domain only: {domain}")

        # Update progress
        if scan_id in active_vulnerability_scans:
            active_vulnerability_scans[scan_id]['progress'] = 30
            active_vulnerability_scans[scan_id]['logs'].append(f'Scanning {len(subdomains)} domains...')

        # Update progress
        if scan_id in active_vulnerability_scans:
            active_vulnerability_scans[scan_id]['progress'] = 50
            active_vulnerability_scans[scan_id]['logs'].append('Running DNS security scan...')

        # Run DNS security scan with subdomains from database (database integration only)
        result = scan_domain_dns_security(domain, None, subdomains_list=subdomains)

        if not result:
            raise Exception('DNS security scan failed')

        # Update progress
        if scan_id in active_vulnerability_scans:
            active_vulnerability_scans[scan_id]['progress'] = 80
            active_vulnerability_scans[scan_id]['logs'].append('Saving results to database...')

        # Save results to database
        try:
            # Save the DNS score
            logging.info(f"Saving DNS score {result['final_score']} for {domain} to database")
            score_saved = save_dns_score(domain, result['final_score'])
            
            # Prepare vulnerabilities for database storage
            vuln_data_for_db = []
            for issue in result['issues_found']:
                # Use 'finding' field as title for better grouping, fallback to issue_type
                issue_title = issue.get('finding') or issue.get('issue_type', 'DNS Security Issue')
                vuln_data_for_db.append({
                    'subdomain': issue.get('domain', domain),
                    'title': issue_title,
                    'description': issue.get('description', 'DNS security issue detected'),
                    'severity': issue.get('severity', 'Medium')
                })
            
            # Save vulnerabilities to database
            if vuln_data_for_db:
                logging.info(f"Saving {len(vuln_data_for_db)} DNS vulnerabilities for {domain} to database")
                vulns_saved = save_dns_vulnerabilities(domain, vuln_data_for_db, update_existing=True)
                db_status = f"Saved {len(vuln_data_for_db)} vulnerabilities to database"
            else:
                logging.info(f"No DNS vulnerabilities found - clearing existing entries for {domain}")
                vulns_saved = save_dns_vulnerabilities(domain, [], update_existing=True)
                db_status = "Cleared existing DNS vulnerabilities"
            
            logging.info(f"DNS scan database save status: {db_status}")
            
        except Exception as db_error:
            logging.error(f"Error saving DNS results to database: {db_error}")
            db_status = f"Database save failed: {str(db_error)}"

        # Auto-update overall vendor score after scan completion
        try:
            update_vendor_overall_score_after_scan(domain)
        except Exception as auto_update_error:
            logging.warning(f"Failed to auto-update overall score for {domain}: {auto_update_error}")

        # Store final results
        if scan_id in active_vulnerability_scans:
            active_vulnerability_scans[scan_id]['progress'] = 100
            active_vulnerability_scans[scan_id]['status'] = 'completed'
            active_vulnerability_scans[scan_id]['logs'].append('DNS security scan completed successfully')
            active_vulnerability_scans[scan_id]['result'] = {
                'status': 'success',
                'domain': result['domain'],
                'final_score': result['final_score'],
                'max_score': result['max_score'],
                'vulnerabilities': result['issues_found'],
                'statistics': {
                    'subdomains_processed': result['processed_subdomains'],
                    **result['statistics']
                },
                'summary': {
                    'total_issues': len(result['issues_found']),
                    'by_severity': result['statistics'],
                    'score_breakdown': {
                        'final_score': result['final_score'],
                        'max_score': result['max_score'],
                        'percentage': round((result['final_score'] / result['max_score']) * 100, 2)
                    }
                },
                'report_file': result['report_file'],
                'database_status': db_status
            }

        logging.info(f"DNS security scan completed for {domain}. Final score: {result['final_score']}/{result['max_score']}")

    except Exception as e:
        logging.error(f"Error in DNS security scan background task: {str(e)}")
        # Update scan status to failed
        if scan_id in active_vulnerability_scans:
            active_vulnerability_scans[scan_id]['status'] = 'failed'
            active_vulnerability_scans[scan_id]['progress'] = 100
            active_vulnerability_scans[scan_id]['error'] = str(e)
            active_vulnerability_scans[scan_id]['logs'].append(f'DNS scan failed: {str(e)}')


@app.post('/api/vulnerabilities/cleanup-duplicates')
async def cleanup_vulnerabilities(request: Request, data: dict = Body(default={})):
    """Clean up duplicate vulnerabilities from the database"""
    try:
        domain = data.get('domain')
        category = data.get('category')
        
        logging.info(f"Starting vulnerability cleanup for domain: {domain}, category: {category}")
        
        # Run the cleanup
        result = cleanup_duplicate_vulnerabilities(domain=domain, category=category)
        
        if result['success']:
            logging.info(f"Vulnerability cleanup completed: {result['message']}")
            # Only audit a cleanup that actually deleted something.
            if result.get('duplicates_removed'):
                log_request_action(
                    request,
                    action='DELETE',
                    resource_type='vulnerability',
                    resource_id=domain,
                    details={
                        'domain': domain,
                        'category': category,
                        'duplicates_found': result['duplicates_found'],
                        'duplicates_removed': result['duplicates_removed'],
                    },
                )
            return {
                'status': 'success',
                'duplicates_found': result['duplicates_found'],
                'duplicates_removed': result['duplicates_removed'],
                'cleaned_items': result.get('cleaned_items', []),
                'message': result['message']
            }
        else:
            logging.error(f"Vulnerability cleanup failed: {result['error']}")
            raise HTTPException(
                status_code=500,
                detail=result['message']
            )
            
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error in vulnerability cleanup endpoint: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f'Failed to clean up vulnerabilities: {str(e)}'
        )


@app.get('/api/vulnerabilities-db/{domain}')
async def get_domain_vulnerabilities(domain: str, category: Optional[str] = Query(default=None)):
    """Get all vulnerabilities for a domain from database"""
    try:
        vulnerabilities = get_vulnerabilities_for_domain(domain, category)
        return {
            'domain': domain,
            'vulnerabilities': vulnerabilities,
            'count': len(vulnerabilities),
            'category_filter': category
        }
    except Exception as e:
        logging.error(f"Error retrieving vulnerabilities for {domain}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get('/api/vulnerabilities/report/{domain}')
async def get_vulnerability_report(domain: str, include_incidents: str = Query(default='false')):
    """Get comprehensive vulnerability report for a domain and its subdomains"""
    try:
        # Check if incidents should be included (for backward compatibility)
        include_incidents_bool = include_incidents.lower() == 'true'
        
        # Clean domain name
        domain = domain.strip().lower()
        domain = domain.replace('https://', '').replace('http://', '').replace('www.', '').split('/')[0]
        
        # Get vendor info
        vendor = get_vendor_by_domain(domain)
        if not vendor:
            raise HTTPException(
                status_code=404,
                detail='Domain not found in vendors table'
            )
        
        # Get all vulnerabilities for this domain
        vulnerabilities = get_vulnerabilities_for_domain(domain)
        logging.info(f"Retrieved {len(vulnerabilities)} total vulnerabilities for {domain} from database")
        
        # Get subdomains for context
        subdomains_data = get_subdomains_for_domain(domain)
        subdomains = [item['subdomain'] for item in subdomains_data]
        
        # Get scores for this domain
        scores_data = get_scores_for_domain(domain)
        
        # Get incidents and news data only if requested
        incidents_data = {}
        if include_incidents_bool:
            try:
                logging.info(f"Fetching incidents and news for {domain}")
                incidents_data = query_incidents_json(domain=domain, months=36)  # Get last 36 months
                logging.info(f"Successfully fetched incidents data for {domain}: {len(incidents_data.get('incidents', []))} incidents, {len(incidents_data.get('news', []))} news items")
            except Exception as incidents_error:
                logging.warning(f"Failed to fetch incidents data for {domain}: {incidents_error}")
                incidents_data = {
                    'domain': domain,
                    'since': '',
                    'summary': 'Unable to fetch incidents data',
                    'incidents': [],
                    'news': [],
                    'notes': f'Error fetching incidents: {str(incidents_error)}'
                }
        else:
            # Provide placeholder structure for frontend compatibility
            incidents_data = {
                'domain': domain,
                'since': '',
                'summary': 'Loading incidents data...',
                'incidents': [],
                'news': [],
                'notes': 'Incidents data will be loaded separately'
            }
        
        # Group vulnerabilities by category
        vulnerabilities_by_category = {}
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        
        for vuln in vulnerabilities:
            category = vuln['category']  # Fixed: use 'category' not 'score_category'
            if category not in vulnerabilities_by_category:
                vulnerabilities_by_category[category] = []
            vulnerabilities_by_category[category].append(vuln)
            
            # Count severities
            severity = vuln['severity']
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Debug logging for categories
        logging.info(f"Vulnerability categories found for {domain}: {list(vulnerabilities_by_category.keys())}")
        logging.info(f"Categories with issues count: {len(vulnerabilities_by_category)}")
        for cat, vulns in vulnerabilities_by_category.items():
            logging.info(f"  - {cat}: {len(vulns)} vulnerabilities")
        
        # Calculate summary statistics
        total_vulnerabilities = len(vulnerabilities)
        categories_with_issues = len(vulnerabilities_by_category)
        total_subdomains = len(subdomains)
        
        return {
            'status': 'success',
            'domain': domain,
            'vendor': {
                'id': vendor['id'],
                'name': vendor['name'],  # Fixed: use 'name' not 'vendor_name'
                'domain': vendor['domain'],
                'overall_score': vendor.get('securityScore', 0),
                'grade': vendor.get('grade', 'N/A'),
                'last_scanned': vendor.get('lastScan'),
                'tier': vendor.get('tier'),
                'certifications': vendor.get('certifications', {
                    'iso_27001': False,
                    'soc2': False,
                    'has_certifications': False,
                    'certifications': []
                })
            },
            'summary': {
                'total_vulnerabilities': total_vulnerabilities,
                'categories_with_issues': categories_with_issues,
                'total_subdomains': total_subdomains,
                'severity_breakdown': severity_counts
            },
            'vulnerabilities_by_category': vulnerabilities_by_category,
            'subdomains': subdomains,
            'scores': scores_data,
            'incidents': incidents_data,
            'generated_at': time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error generating vulnerability report for {domain}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f'Failed to generate vulnerability report: {str(e)}'
        )

@app.get('/api/vulnerabilities/report/{domain}/incidents')
async def get_vulnerability_report_incidents(domain: str, months: int = Query(default=12)):
    """Get incidents and news data for a domain"""
    try:
        # Clean domain name
        domain = domain.strip().lower()
        domain = domain.replace('https://', '').replace('http://', '').replace('www.', '').split('/')[0]
        
        logging.info(f"Fetching incidents and news for {domain} (last {months} months)")
        
        # Initialize news service and get data from database
        from db_service import NewsService
        news_service = NewsService()
        db_data = news_service.get_news_for_domain(domain, months)
        
        # Return database data (automatically limited to 1 year by trigger)
        incidents_data = {
            'domain': domain,
            'since': (datetime.now() - timedelta(days=months * 30)).date().isoformat(),
            'summary': f"Retrieved {db_data['total_count']} items from database (last {months} months)",
            'incidents': db_data['incidents'],
            'news': db_data['news'],
            'notes': 'Data retrieved from local database (automatically cleaned up after 1 year)'
        }
        
        logging.info(f"Successfully retrieved incidents data for {domain}: {len(db_data['incidents'])} incidents, {len(db_data['news'])} news items")
        
        return {
            'status': 'success',
            'domain': domain,
            'incidents': incidents_data
        }
            
    except Exception as e:
        logging.error(f"Error fetching incidents for {domain}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f'Failed to fetch incidents: {str(e)}'
        )

@app.get('/api/scores/{domain}/{score_category}')
async def get_domain_scores_by_category(domain: str, score_category: str):
    """Get scores for a domain filtered by category"""
    try:
        all_scores = get_scores_for_domain(domain)
        filtered_scores = [s for s in all_scores if s['category'] == score_category]
        return {
            'domain': domain,
            'category': score_category,
            'scores': filtered_scores,
            'count': len(filtered_scores)
        }
    except Exception as e:
        logging.error(f"Error retrieving {score_category} scores for {domain}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post('/api/email/scan')
async def start_email_scan(data: dict = Body(...)):
    """Start an email security scan"""
    try:
        domain = data.get('domain')
        scan_id = data.get('scan_id', f'email_{int(time.time())}')
        
        if not domain:
            raise HTTPException(
                status_code=400,
                detail='Domain is required'
            )
        
        # Clean domain name
        domain = domain.strip().lower()
        domain = domain.replace('https://', '').replace('http://', '').replace('www.', '').split('/')[0]
        
        logging.info(f"Starting email security scan for {domain} with scan ID {scan_id}")
        
        # Track this scan
        active_vulnerability_scans[scan_id] = {
            'domain': domain,
            'started': time.time(),
            'stopped': False
        }
        
        # Import and use the email security checker
        sys.path.append(app_join('email'))
        from email_security_checker import EmailSecurityChecker
        
        # Initialize and run email security checker for single domain
        checker = EmailSecurityChecker()
        
        # Run the email security scan for the single domain only
        logging.info(f"Starting email security scan for single domain: {domain}")
        
        # Scan the single domain
        result = checker.check_domain_email_security(domain)
        
        if not result:
            logging.error("No email scan results obtained")
            raise HTTPException(
                status_code=500,
                detail='No email security scan results obtained'
            )
        
        # Process single domain result and save to database
        vulnerability_count = 0
        vulnerabilities = []
        total_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        
        # Process the single result
        subdomain = result['domain']
        score = result['security_score']
        
        # Collect vulnerabilities from DMARC and SPF issues
        all_issues = []
        
        # DMARC issues
        if result['dmarc']['issues']:
            for issue in result['dmarc']['issues']:
                severity = 'High' if any(term in issue.lower() for term in ['not found', 'p=none']) else \
                          'Medium' if 'syntax error' in issue.lower() else 'Low'
                issue_data = {
                    'title': f"DMARC: {issue.split(' - ')[0] if ' - ' in issue else issue[:50]}",
                    'description': f"DMARC policy issue for {subdomain}: {issue}",
                    'severity': severity,
                    'subdomain': subdomain,
                    'category': 'Email'
                }
                all_issues.append(issue_data)
                total_counts[severity] += 1
        
        # SPF issues
        if result['spf']['issues']:
            for issue in result['spf']['issues']:
                severity = 'High' if any(term in issue.lower() for term in ['not enabled', '+all']) else \
                          'Medium' if 'syntax error' in issue.lower() else 'Low'
                issue_data = {
                    'title': f"SPF: {issue.split(' - ')[0] if ' - ' in issue else issue[:50]}",
                    'description': f"SPF policy issue for {subdomain}: {issue}",
                    'severity': severity,
                    'subdomain': subdomain,
                    'category': 'Email'
                }
                all_issues.append(issue_data)
                total_counts[severity] += 1
        
        vulnerabilities.extend(all_issues)
        vulnerability_count = len(all_issues)
        
        # Use the single domain score
        final_score = score
        initial_score = 950
        
        # Save email score to database
        db_status = "success"
        try:
            save_email_score(domain, final_score)
            
            # Save vulnerabilities to database (replace mode)
            if vulnerabilities:
                save_email_vulnerabilities(domain, vulnerabilities, update_existing=True)
            else:
                # Clear stale Email vulnerabilities if none found
                save_email_vulnerabilities(domain, [], update_existing=True)
        except Exception as db_error:
            logging.error(f"Database save error for email scan: {db_error}")
            db_status = f"Database save failed: {db_error}"
        
        # Log email scan summary for transparency
        logging.info(f"EMAIL SCAN SUMMARY:")
        logging.info(f"   Vendor Domain: {domain}")
        logging.info(f"   Domains Scanned: 1 (main domain only)")
        logging.info(f"   Total Vulnerabilities Found: {len(vulnerabilities)}")
        logging.info(f"   Severity Breakdown: {total_counts}")
        logging.info(f"   Final Vendor Score: {final_score}/{initial_score} ({(final_score/initial_score)*100:.1f}%)")
        
        logging.info(f"Email security scan completed for {domain}. Score: {final_score}, Vulnerabilities: {vulnerability_count}")
        
        # Auto-update overall vendor score after scan completion
        try:
            update_vendor_overall_score_after_scan(domain)
        except Exception as auto_update_error:
            logging.warning(f"Failed to auto-update overall score for {domain}: {auto_update_error}")
        
        return {
            'status': 'success',
            'domain': domain,
            'final_score': final_score,
            'max_score': initial_score,
            'subdomains_processed': 1,
            'vulnerabilities': vulnerabilities,
            'statistics': {
                'domains_processed': 1,
                **total_counts
            },
            'summary': {
                'total_vulnerabilities': len(vulnerabilities),
                'by_severity': total_counts,
                'score_breakdown': {
                    'final_score': final_score,
                    'max_score': initial_score,
                    'percentage': round((final_score / initial_score) * 100, 2)
                }
            },
            'database_status': db_status
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error starting email security scan: {e}")
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )


@app.post('/api/vendors/{vendor_id}/overall-score')
async def post_vendor_overall_score(vendor_id: int):
    """Recalculate the overall weighted score for a vendor AND persist it.

    This is a write. Only scan paths should call it -- persisting appends a row
    to `scores`, which is the append-only history that trend and timeline
    calculations read (see analytics_routes), and stamps vendors.last_scanned.
    Callers that merely want to display a score must use the GET route below,
    which computes the same result without writing.
    """
    return await _calculate_vendor_overall_score(vendor_id, persist=True)


@app.get('/api/vendors/{vendor_id}/overall-score')
async def get_vendor_overall_score(vendor_id: int):
    """Read-only overall score: identical computation, no database write."""
    return await _calculate_vendor_overall_score(vendor_id, persist=False)


async def _calculate_vendor_overall_score(vendor_id: int, persist: bool = False):
    """Calculate overall weighted score for a vendor using unified scoring system.

    `persist` defaults to False so that adding a new caller cannot silently
    start writing score history.
    """
    try:
        # Get vendor information
        vendors_list = get_vendors_cached()
        vendor = next((v for v in vendors_list if v['id'] == vendor_id), None)
        if not vendor:
            raise HTTPException(status_code=404, detail='Vendor not found')
        
        domain = vendor['domain']
        logging.info(f"Calculating overall score for vendor {vendor['name']} ({domain})")
        
        # Get all scores for this domain from database
        scores_data = get_scores_for_domain(domain)
        
        # Get all vulnerabilities for this domain from database
        vulnerabilities_data = get_vulnerabilities_for_domain(domain)
        
        # Organize scores by category
        category_scores = {}
        category_vulnerabilities = {}
        
        # Process scores
        for score_item in scores_data:
            category = score_item.get('score_category', score_item.get('category', 'Unknown'))
            category_scores[category.upper()] = {
                'score': score_item.get('score', 950),
                'updated_at': score_item.get('updated_at'),
                'max_score': 950
            }
        
        # Process vulnerabilities by category
        for vuln in vulnerabilities_data:
            category = vuln.get('category', 'Unknown').upper()
            if category not in category_vulnerabilities:
                category_vulnerabilities[category] = []
            category_vulnerabilities[category].append(vuln)
        
        # Create scan results structure for unified scoring
        scan_results = {}
        
        # Map database categories to unified scoring categories
        category_mapping = {
            'WEBSITE': 'WEBSITE',
            'DOMAIN_REPUTATION': 'DOMAIN_REPUTATION', 
            'ENCRYPTION': 'ENCRYPTION',
            'NETWORK': 'NETWORK',
            'EMAIL': 'EMAIL',
            'DNS': 'DNS'
        }
        
        unified_scoring = get_unified_scoring()
        
        for db_category, unified_category in category_mapping.items():
            if db_category in category_scores:
                # Use the stored individual score instead of recalculating from vulnerabilities
                stored_score = category_scores[db_category]['score']
                vulns = category_vulnerabilities.get(db_category, [])
                
                # Get vulnerability counts for metadata
                severity_counts = {
                    'CRITICAL': 0,
                    'HIGH': 0, 
                    'MEDIUM': 0,
                    'LOW': 0,
                    'INFO': 0
                }
                
                for vuln in vulns:
                    severity = vuln.get('severity', 'INFO').upper()
                    if severity in severity_counts:
                        severity_counts[severity] += 1
                
                total_vulnerabilities = sum(severity_counts.values())
                critical_high_count = severity_counts['CRITICAL'] + severity_counts['HIGH']
                
                # Use stored score with vulnerability metadata
                scan_results[unified_category] = {
                    'score': stored_score,
                    'max_score': 950,
                    'total_deduction': 950 - stored_score,
                    'total_vulnerabilities': total_vulnerabilities,
                    'critical_high_count': critical_high_count,
                    'percentage': round((stored_score / 950) * 100, 2),
                    'severity_counts': severity_counts
                }
            else:
                # Category not scanned yet, use perfect score
                scan_results[unified_category] = {
                    'score': 950,
                    'max_score': 950,
                    'total_deduction': 0,
                    'total_vulnerabilities': 0,
                    'critical_high_count': 0,
                    'percentage': 100.0
                }
        
        # Calculate overall weighted score
        overall_result = unified_scoring.calculate_overall_score(scan_results)
        
        # Update vendor's security score in cache
        vendor['securityScore'] = overall_result['overall_score']
        vendor['riskLevel'] = determine_risk_level(overall_result['overall_score'])
        
        # Save overall score to database (only when this is a scan-driven write).
        # A read path must never land here: update_vendor_overall_score appends a
        # `scores` row and stamps vendors.last_scanned, so a polled read would
        # forge scan history and make a stale vendor look freshly scanned.
        if persist:
            try:
                db_update_success = update_vendor_overall_score(domain, overall_result['overall_score'])
                if db_update_success:
                    logging.info(f"Successfully saved overall score {overall_result['overall_score']} to database for {domain}")
                else:
                    logging.warning(f"Failed to save overall score to database for {domain}")
            except Exception as db_error:
                logging.error(f"Error saving overall score to database for {domain}: {db_error}")
        
        logging.info(f"OVERALL VENDOR SCORE CALCULATION:")
        logging.info(f"   Vendor: {vendor['name']} ({domain})")
        logging.info(f"   Overall Score: {overall_result['overall_score']}/950 ({overall_result['percentage']}%)")
        logging.info(f"   Risk Level: {vendor['riskLevel']}")
        logging.info(f"   Calibration Applied: {overall_result['calibration_applied']}")
        logging.info(f"   Within Target Range: {overall_result['within_target_range']}")
        
        return {
            'status': 'success',
            'vendor_id': vendor_id,
            'vendor_name': vendor['name'],
            'domain': domain,
            'overall_score': overall_result['overall_score'],
            'max_score': overall_result['max_score'],
            'percentage': overall_result['percentage'],
            'risk_level': vendor['riskLevel'],
            'category_contributions': overall_result['category_contributions'],
            'dynamic_weights': overall_result['dynamic_weights'],
            'calibration_applied': overall_result['calibration_applied'],
            'calibration_factor': overall_result['calibration_factor'],
            'target_score': overall_result['target_score'],
            'within_target_range': overall_result['within_target_range'],
            'scan_results': scan_results,
            'category_scores': category_scores,
            'total_vulnerabilities': sum(len(vulns) for vulns in category_vulnerabilities.values())
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error calculating overall score for vendor {vendor_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f'Failed to calculate overall score: {str(e)}'
        )

@app.post('/api/vendors/comparison-scores')
async def get_vendor_comparison_scores(data: dict = Body(...)):
    """Get detailed scores for vendor comparison"""
    try:
        vendor_ids = data.get('vendor_ids', [])
        
        if not vendor_ids:
            raise HTTPException(
                status_code=400,
                detail='No vendor IDs provided'
            )
        
        # Import database functions
        from db_service import get_vendor_by_id, get_scores_for_domain, get_vulnerabilities_for_domain
        
        vendors_data = []
        
        for vendor_id in vendor_ids:
            try:
                # Get vendor basic info
                vendor = get_vendor_by_id(vendor_id)
                if not vendor:
                    continue
                
                # Get scores for this vendor
                scores = get_scores_for_domain(vendor['domain'])
                
                # Organize scores by category
                organized_scores = {}
                for score in scores:
                    category = score['category']
                    organized_scores[category] = {
                        'score': score['score'],
                        'max_score': 950,  # Standard max score
                        'time_period': score['time_period'],
                        'updated_at': score['updated_at']
                    }
                
                # Get overall score
                overall_score = vendor.get('securityScore', 0)
                
                # Add vendor data
                vendors_data.append({
                    'vendor': {
                        'id': vendor['id'],
                        'name': vendor['name'],
                        'domain': vendor['domain'],
                        'logo': vendor.get('logo'),
                        'grade': vendor.get('grade', 'N/A')
                    },
                    'scores': organized_scores,
                    'overall_score': overall_score
                })
                
            except Exception as e:
                logging.error(f"Error processing vendor {vendor_id}: {e}")
                continue
        
        return {
            'status': 'success',
            'vendors': vendors_data
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error getting vendor comparison scores: {e}")
        raise HTTPException(
            status_code=500,
            detail=f'Failed to get vendor comparison scores: {str(e)}'
        )

@app.post('/api/vendors/recalculate-all-scores')
async def recalculate_all_vendor_scores():
    """Recalculate overall scores for all vendors using unified scoring system"""
    try:
        vendors_list = get_vendors_cached()
        updated_vendors = []
        
        for vendor in vendors_list:
            try:
                # Calculate overall score for this vendor.
                # persist=True: this endpoint's whole purpose is to write back
                # recalculated scores, unlike the read-only GET route.
                response = await _calculate_vendor_overall_score(vendor['id'], persist=True)
                if response.get('status') == 'success':
                    updated_vendors.append({
                        'vendor_id': vendor['id'],
                        'name': vendor['name'],
                        'domain': vendor['domain'],
                        'old_score': vendor.get('securityScore', 0),
                        'new_score': response['overall_score'],
                        'risk_level': response['risk_level']
                    })
                    logging.info(f"Updated {vendor['name']}: {vendor.get('securityScore', 0)} -> {response['overall_score']}")
            except Exception as vendor_error:
                logging.error(f"Error updating vendor {vendor['name']}: {vendor_error}")
                continue
        
        return {
            'status': 'success',
            'message': f'Recalculated scores for {len(updated_vendors)} vendors',
            'updated_vendors': updated_vendors,
            'total_vendors': len(vendors_list)
        }
        
    except Exception as e:
        logging.error(f"Error recalculating all vendor scores: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f'Failed to recalculate scores: {str(e)}'
        )

@app.post('/api/background-scan/start')
async def start_background_full_scan(data: dict = Body(default={})):
    """Start a background full scan for all domains, filtered domains, or a specific domain"""
    try:
        # Get request data
        domain = data.get('domain')  # If provided, scan only this domain
        include_subdomains = data.get('include_subdomains', True)  # Default to True for backward compatibility
        slack_notify_on_complete = bool(data.get('slack_notify_on_complete', False))
        checkpoint_vendor = data.get('checkpoint_vendor', '')  # Vendor to start from (domain or name)
        vendor_filters = data.get('vendor_filters', {})  # Vendor filters for filtered scans
        
        # Determine scan type and validate checkpoint usage
        if domain:
            scan_type = "single"
            # Single domain scans don't use checkpoints or filters
            checkpoint_vendor = ''
            vendor_filters = {}
        elif vendor_filters and any(vendor_filters.values()):
            scan_type = "filtered"
            # Filtered scans don't use checkpoints
            checkpoint_vendor = ''
            logging.info(f"Filtered scan requested with filters: {vendor_filters}")
        else:
            scan_type = "full"
            # Only full scans can use checkpoints
        
        # Generate unique job ID (safe across HPA replicas)
        job_id = generate_job_id(scan_type)
        
        # Build log message
        log_message = f'Background {scan_type} scan starting...'
        if domain:
            log_message += f' for {domain}'
        elif scan_type == "filtered":
            log_message += f' for filtered vendors'
        log_message += f' (subdomains: {"included" if include_subdomains else "main domains only"})'
        if checkpoint_vendor and scan_type == "full":
            log_message += f' (checkpoint: starting from {checkpoint_vendor})'
        
        # Initialize job tracking
        background_jobs[job_id] = {
            'job_id': job_id,
            'status': 'starting',
            'progress': 0,
            'start_time': datetime.now(),
            'current_domain': domain if domain else None,
            'stage': 'initializing',
            'domains': [domain] if domain else [],
            'total_domains': 1 if domain else 0,
            'completed': [],
            'failed': [],
            'logs': [log_message],
            'include_subdomains': include_subdomains,
            'checkpoint_vendor': checkpoint_vendor if checkpoint_vendor and scan_type == "full" else None,
            'vendor_filters': vendor_filters if scan_type == "filtered" else {},
            'scan_type': scan_type,
            'slack_notify_on_complete': slack_notify_on_complete,
        }
        
        # Start appropriate background scan in thread
        if domain:
            scan_thread = threading.Thread(
                target=run_background_single_domain_scan,
                args=(job_id, domain, include_subdomains)
            )
        elif scan_type == "filtered":
            scan_thread = threading.Thread(
                target=run_background_filtered_scan,
                args=(job_id, include_subdomains, vendor_filters)
            )
        else:
            scan_thread = threading.Thread(
                target=run_background_full_scan_all_domains,
                args=(job_id, include_subdomains, checkpoint_vendor)
            )
        
        scan_thread.daemon = True
        scan_thread.start()
        
        # Update status to running
        background_jobs[job_id]['status'] = 'running'
        background_jobs[job_id]['logs'].append('Background scan thread started')
        
        logging.info(f"Started background {scan_type} scan job: {job_id}" + (f" for {domain}" if domain else ""))
        
        return {
            'status': 'success',
            'job_id': job_id,
            'message': f'Background {scan_type} scan started successfully' + (f' for {domain}' if domain else ''),
            'estimated_duration': 'This will run in the background even if you close the frontend',
            'domain': domain,
            'scan_type': scan_type
        }
        
    except Exception as e:
        logging.error(f"Error starting background full scan: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f'Failed to start background scan: {str(e)}'
        )

@app.get('/api/background-scan/status/{job_id}')
async def get_background_scan_status(job_id: str):
    """Get the status of a background scan job"""
    try:
        job = background_jobs.get_job_dict(job_id)
        if not job:
            raise HTTPException(
                status_code=404,
                detail='Job not found'
            )
        
        # Calculate runtime
        start_time = job.get('start_time')
        runtime = None
        if start_time:
            runtime_delta = datetime.now() - start_time
            runtime = str(runtime_delta).split('.')[0]  # Remove microseconds
        
        # Estimate remaining time
        estimated_remaining = None
        if job['progress'] > 0 and job['status'] == 'running':
            elapsed_time = (datetime.now() - start_time).total_seconds()
            estimated_total = (elapsed_time / job['progress']) * 100
            estimated_remaining_seconds = estimated_total - elapsed_time
            if estimated_remaining_seconds > 0:
                estimated_remaining = str(timedelta(seconds=int(estimated_remaining_seconds)))
        
        return {
            'status': 'success',
            'job': {
                'job_id': job_id,
                'status': job['status'],
                'progress': job['progress'],
                'current_domain': job.get('current_domain'),
                'stage': job.get('stage'),
                'total_domains': job.get('total_domains', 0),
                'completed_count': len(job.get('completed', [])),
                'failed_count': len(job.get('failed', [])),
                'runtime': runtime,
                'estimated_remaining': estimated_remaining,
                'start_time': start_time.isoformat() if start_time else None,
                'end_time': job.get('end_time').isoformat() if job.get('end_time') else None,
                'error': job.get('error'),
                'logs': job.get('logs', [])[-10:]  # Last 10 log entries
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error getting background scan status: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f'Failed to get scan status: {str(e)}'
        )

@app.get('/api/background-scan/resume-info')
async def get_resume_scan_info():
    """Get information about where to resume the last full_scan_all"""
    try:
        from scan_resume_utils import get_resume_scan_info_sync
        result = get_resume_scan_info_sync()
        return result

    except Exception as e:
        logging.error(f"Error in resume scan info endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get resume info: {str(e)}")

@app.get('/api/background-scan/list')
async def list_background_scans():
    """List all background scan jobs"""
    try:
        jobs_list = []
        for job_id, job in background_jobs.items():
            start_time = job.get('start_time')
            runtime = None
            if start_time:
                if job['status'] == 'completed' and job.get('end_time'):
                    runtime_delta = job['end_time'] - start_time
                else:
                    runtime_delta = datetime.now() - start_time
                runtime = str(runtime_delta).split('.')[0]
            
            jobs_list.append({
                'job_id': job_id,
                'status': job['status'],
                'progress': job['progress'],
                'current_domain': job.get('current_domain'),
                'total_domains': job.get('total_domains', 0),
                'completed_count': len(job.get('completed', [])),
                'failed_count': len(job.get('failed', [])),
                'runtime': runtime,
                'start_time': start_time.isoformat() if start_time else None,
                'end_time': job.get('end_time').isoformat() if job.get('end_time') else None
            })
        
        # Sort by start time (newest first)
        jobs_list.sort(key=lambda x: x['start_time'] or '', reverse=True)
        
        return {
            'status': 'success',
            'jobs': jobs_list,
            'active_jobs': len([j for j in jobs_list if j['status'] in ['starting', 'running']])
        }
        
    except Exception as e:
        logging.error(f"Error listing background scans: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f'Failed to list background scans: {str(e)}'
        )

@app.post('/api/background-scan/cancel/{job_id}')
async def cancel_background_scan(job_id: str):
    """Cancel a running background scan job"""
    try:
        job = background_jobs.get_job_dict(job_id)
        if not job:
            raise HTTPException(
                status_code=404,
                detail='Job not found'
            )
        
        if job['status'] not in ['starting', 'running']:
            raise HTTPException(
                status_code=400,
                detail=f'Cannot cancel job with status: {job["status"]}'
            )
        
        # Mark job as cancelled
        background_jobs[job_id]['status'] = 'cancelled'
        background_jobs[job_id]['end_time'] = datetime.now()
        background_jobs[job_id]['logs'].append('Job cancelled by user')
        
        logging.info(f"Cancelled background scan job: {job_id}")
        
        return {
            'status': 'success',
            'message': f'Background scan job {job_id} cancelled successfully'
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error cancelling background scan: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f'Failed to cancel background scan: {str(e)}'
        )

# Background full scan functions
_HEARTBEAT_INTERVAL_SECONDS = 120
_last_heartbeat = {}


def heartbeat_job(job_id, stage_message):
    """Prove the scan is still alive during a long, write-free inner loop.

    The stale-job reaper infers liveness from background_scan_jobs.updated_at,
    which normally advances as a side effect of per-step progress writes. Some
    steps iterate every subdomain of a vendor (avg ~123, max 255 here) with no
    intervening write, so a perfectly healthy scan can go quiet for longer than
    the reaper's threshold and be cancelled as an orphan.

    Throttled to one write per _HEARTBEAT_INTERVAL_SECONDS so a 255-subdomain
    loop costs a handful of UPDATEs, not 255.
    """
    if not job_id or job_id not in background_jobs:
        return
    now = time.time()
    if now - _last_heartbeat.get(job_id, 0) < _HEARTBEAT_INTERVAL_SECONDS:
        return
    _last_heartbeat[job_id] = now
    try:
        background_jobs[job_id]['stage'] = stage_message
    except Exception as exc:
        logging.debug(f"Heartbeat write failed for {job_id}: {exc}")


def run_full_scan_for_domain_background(job_id, domain, include_subdomains=True, scan_format='full_scan_single'):
    """Run complete security scan for a single domain in background
    
    Args:
        job_id: The job ID for tracking
        domain: The domain to scan
        include_subdomains: Whether to include subdomains in the scan
        scan_format: Type of scan ('full_scan_all', 'full_scan_single', or 'new_vendor')
    """
    # Guard: query the DB directly (bypassing cache) to confirm the vendor still exists.
    # A vendor may have been deleted after this job was queued or after the all-domains
    # loop captured its stale domain list from the cache.
    if not get_vendor_by_domain(domain):
        logging.warning(f"Skipping scan for {domain} — vendor no longer exists in the database (job {job_id})")
        if job_id in background_jobs:
            background_jobs[job_id]['status'] = 'skipped'
            background_jobs[job_id]['logs'].append(f"Vendor {domain} was deleted; scan skipped.")
        return

    try:
        logging.info(f"Starting background full scan for {domain} (Job: {job_id}, include_subdomains: {include_subdomains}, scan_format: {scan_format})")
        
        # Update job status and initialize progress tracking
        if job_id in background_jobs:
            background_jobs[job_id]['current_domain'] = domain
            background_jobs[job_id]['stage'] = 'subdomain_discovery'
            background_jobs[job_id]['progress'] = 0
            background_jobs[job_id]['logs'].append(f"Starting comprehensive scan for {domain}...")
        
        # Track scan progress
        total_steps = 7
        completed_steps = 0
        
        # Step 1: Enhanced Subdomain Discovery for all domains (Only if include_subdomains is True)
        if include_subdomains:
            logging.info(f"Step 1/7: Enhanced subdomain discovery for {domain} and additional domains")
            try:
                # Get all domains (main + additional) for subdomain discovery
                all_domains_to_scan = get_all_domains_for_discovery(domain)
                logging.info(f"Will perform subdomain discovery for {len(all_domains_to_scan)} domains: {all_domains_to_scan}")
                
                if job_id in background_jobs:
                    background_jobs[job_id]['logs'].append(f" Step 1: Discovering subdomains for {len(all_domains_to_scan)} domains: {', '.join(all_domains_to_scan)}")
                
                sys.path.append(app_join('Sublist3r_New'))
                from subdomains_sub import find_subdomains_sublist3r, find_subdomains_crtsh, find_alive_subdomains
                
                # Initialize combined subdomain sets
                all_subdomains_combined = set()
                
                # Enhanced subdomain discovery for all domains
                for i, current_domain in enumerate(all_domains_to_scan):
                    domain_prefix = f"[{i+1}/{len(all_domains_to_scan)}]"
                    logging.info(f"{domain_prefix} Discovering subdomains for {current_domain}")
                    
                    if job_id in background_jobs:
                        background_jobs[job_id]['logs'].append(f" {domain_prefix} Processing {current_domain}...")
                    
                    # Discover subdomains for this domain
                    # sublister_set = find_subdomains_sublist3r(current_domain)
                    crtsh_set = find_subdomains_crtsh(current_domain)
                    domain_subdomains = crtsh_set
                    
                    all_subdomains_combined.update(domain_subdomains)
                    logging.info(f"{domain_prefix} Found {len(domain_subdomains)} subdomains for {current_domain}")
                    
                    if job_id in background_jobs:
                        background_jobs[job_id]['logs'].append(f" {domain_prefix} Found {len(domain_subdomains)} subdomains for {current_domain}")
                
                # Convert to sorted list
                all_subdomains = sorted(all_subdomains_combined)
                logging.info(f"Total unique subdomains from all domains: {len(all_subdomains)}")
                
                # Apply pattern-based filtering for all domains
                logging.info(f"Applying pattern-based filtering for {domain} and additional domains")
                filtering_results = filter_subdomains_by_patterns(domain, all_subdomains, all_domains_to_scan)
                
                # Get the filtered subdomains to check
                target_subdomains = filtering_results['all_target_subdomains']
                filtered_existing = filtering_results['filtered_existing']
                generated_combinations = filtering_results['generated_combinations']
                
                logging.info(f"Pattern filtering completed:")
                logging.info(f"  - Filtered existing subdomains: {len(filtered_existing)}")
                logging.info(f"  - Generated combinations: {len(generated_combinations)}")
                logging.info(f"  - Total target subdomains to check: {len(target_subdomains)}")
                
                # Find alive subdomains from the filtered/target list
                alive_subdomains = find_alive_subdomains(target_subdomains)
                logging.info(f"Found {len(alive_subdomains)} alive subdomains from {len(target_subdomains)} target subdomains")
                
                # Save target subdomains to database with status detection (all under main domain)
                save_subdomains_with_status_detection(domain, target_subdomains, alive_subdomains, True)
                invalidate_subdomain_cache(domain)
                
                completed_steps += 1
                if job_id in background_jobs:
                    background_jobs[job_id]['progress'] = int((completed_steps / total_steps) * 100)
                    background_jobs[job_id]['logs'].append(f" Step 1 completed: {len(alive_subdomains)}/{len(target_subdomains)} active subdomains from {len(all_domains_to_scan)} domains")
                logging.info(f" Enhanced subdomain discovery completed for {domain}: {len(alive_subdomains)}/{len(target_subdomains)} active from {len(all_domains_to_scan)} domains")
            except Exception as e:
                if job_id in background_jobs:
                    background_jobs[job_id]['logs'].append(f" Step 1 failed: Enhanced subdomain discovery error")
                logging.error(f" Enhanced subdomain discovery failed for {domain}: {e}")
                notify_scan_step_failure(domain, "Step 1: Subdomain Discovery", str(e), job_id)
                # Continue with remaining steps even if this fails
        else:
            # Skip subdomain discovery for main domains only
            logging.info(f"Step 1/7: Skipping subdomain discovery for {domain} (main domains only)")
            completed_steps += 1
            if job_id in background_jobs:
                background_jobs[job_id]['progress'] = int((completed_steps / total_steps) * 100)
                background_jobs[job_id]['logs'].append(f" Step 1 skipped: Scanning main domain only")
            logging.info(f" Subdomain discovery skipped for {domain}: main domain only")
        
        # Check if job was cancelled
        if job_id in background_jobs and background_jobs[job_id]['status'] == 'cancelled':
            logging.info(f"Background scan job {job_id} was cancelled after step 1")
            return False
        
        # Step 2: Website Vulnerability Scan
        if job_id in background_jobs:
            background_jobs[job_id]['stage'] = 'vulnerability_scan'
        logging.info(f"Step 2/7: Scanning website vulnerabilities for {domain}")
        try:
            sys.path.append(app_join('Header_Vulnerabilities'))
            from header_vulnerabilities import process_domain, check_header_vulnerabilities, get_http_headers
            
            # Determine domains to scan based on include_subdomains parameter
            if include_subdomains:
                # Get subdomains for vulnerability scan (with error handling like individual scan)
                try:
                    subdomains = get_subdomains_for_domain(domain)
                    if subdomains:
                        active_subdomains = [item['subdomain'] for item in subdomains if item.get('status') == 'Active']
                        if domain not in active_subdomains:
                            active_subdomains.insert(0, domain)
                        logging.info(f"Background scan: Using {len(active_subdomains)} active subdomains for vulnerability scan")
                    else:
                        logging.warning(f"Background scan: No subdomains found for {domain}, using main domain only")
                        active_subdomains = [domain]
                except Exception as sub_error:
                    logging.error(f"Background scan: Error fetching subdomains for {domain}: {sub_error}")
                    active_subdomains = [domain]
            else:
                # Main domains only - scan only the primary domain
                active_subdomains = [domain]
                logging.info(f"Background scan: Scanning main domain only for vulnerability scan: {domain}")
            
            # Run vulnerability scan logic using unified scoring system
            initial_score = 950
            severity_weights = get_severity_weights('WEBSITE')
            subdomain_scores = []
            vulnerabilities_found = []
            
            for _sub_index, sub in enumerate(active_subdomains, start=1):  # Process all active subdomains like individual scan
                try:
                    # Same reasoning as the encryption step: the next job-row
                    # write is only after this whole loop, so without a
                    # heartbeat a healthy multi-hour scan looks orphaned.
                    heartbeat_job(
                        job_id,
                        f"vulnerability_scan ({_sub_index}/{len(active_subdomains)}: {sub})"
                    )
                    logging.info(f"Background scan: Processing subdomain: {sub}")
                    response = get_http_headers(sub)
                    
                    if not response:
                        logging.info(f"Background scan: No HTTP response for {sub}, skipping")
                        continue
                    
                    vulnerabilities = check_header_vulnerabilities(response)
                    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
                    
                    if vulnerabilities:
                        for vuln in vulnerabilities:
                            severity = vuln.get('severity', 'UNKNOWN')
                            if severity in severity_counts:
                                severity_counts[severity] += 1
                            
                            vulnerabilities_found.append({
                                'subdomain': sub,
                                'id': vuln.get('id', 'UNKNOWN_ID'),
                                'description': vuln.get('desc', 'Unknown vulnerability'),
                                'severity': severity
                            })
                    
                    # Calculate score for this subdomain (same logic as individual scan)
                    subdomain_score = initial_score
                    for severity, count in severity_counts.items():
                        if count > 0:
                            subdomain_score -= count * severity_weights.get(severity, 0)
                    subdomain_score = max(0, subdomain_score)
                    subdomain_scores.append(subdomain_score)
                except Exception as sub_error:
                    logging.error(f"Error scanning subdomain {sub}: {sub_error}")
            
            # Calculate final score and save
            final_score = round(sum(subdomain_scores) / len(subdomain_scores)) if subdomain_scores else initial_score
            # Use the scan_format passed to this function
            save_website_score(domain, final_score, scan_format=scan_format)
            
            # Save vulnerabilities
            if vulnerabilities_found:
                vuln_data_for_db = []
                for vuln in vulnerabilities_found:
                    vuln_data_for_db.append({
                        'subdomain': vuln['subdomain'],
                        'title': vuln['id'],
                        'description': vuln['description'],
                        'severity': vuln['severity']
                    })
                save_website_vulnerabilities(domain, vuln_data_for_db, update_existing=True)
                logging.info(f"Background scan: Saved {len(vuln_data_for_db)} vulnerabilities for {domain}")
            else:
                logging.info(f"Background scan: No Website vulnerabilities found - clearing existing entries for {domain}")
                save_website_vulnerabilities(domain, [], update_existing=True)
            
            invalidate_dashboard_cache()
            completed_steps += 1
            if job_id in background_jobs:
                background_jobs[job_id]['progress'] = int((completed_steps / total_steps) * 100)
                background_jobs[job_id]['logs'].append(f" Step 2 completed: Vulnerability scan, Score {final_score}")
            logging.info(f" Vulnerability scan completed for {domain}: Score {final_score}")
        except Exception as e:
            if job_id in background_jobs:
                background_jobs[job_id]['logs'].append(f"Step 2 failed: Vulnerability scan error")
            logging.error(f" Vulnerability scan failed for {domain}: {e}")
            notify_scan_step_failure(domain, "Step 2: Website Vulnerability Scan", str(e), job_id)
            # Continue with remaining steps
        
        # Check if job was cancelled
        if job_id in background_jobs and background_jobs[job_id]['status'] == 'cancelled':
            logging.info(f"Background scan job {job_id} was cancelled after step 2")
            return False
        
        # Step 3: Domain Reputation Scan
        if job_id in background_jobs:
            background_jobs[job_id]['stage'] = 'reputation_scan'
        logging.info(f"Step 3/7: Checking domain reputation for {domain}")
        try:
            sys.path.append(app_join('Domain Reputation'))
            from domain_hybrid import scan_domain_reputation
            
            result = scan_domain_reputation(domain, None)
            if result and not result.get('checked', True):
                # AbuseIPDB lookup failed — keep the previously stored score/findings
                completed_steps += 1
                if job_id in background_jobs:
                    background_jobs[job_id]['progress'] = int((completed_steps / total_steps) * 100)
                    background_jobs[job_id]['logs'].append(f" Step 3 skipped: Reputation not checked (AbuseIPDB unavailable), existing results kept")
                logging.warning(f" Reputation for {domain} not checked ({result.get('error')}) - keeping existing results")
            elif result:
                # Use the scan_format passed to this function
                save_domain_reputation_score(domain, result['final_score'], scan_format=scan_format)
                
                # Save reputation vulnerabilities
                if result['issues_found']:
                    vuln_data_for_db = []
                    for issue in result['issues_found']:
                        vuln_data_for_db.append({
                            'subdomain': issue.get('domain', domain),
                            'title': issue.get('issue_type', 'Reputation Issue'),
                            'description': issue.get('description', 'Domain reputation issue detected'),
                            'severity': issue.get('severity', 'Medium')
                        })
                    save_domain_reputation_vulnerabilities(domain, vuln_data_for_db, update_existing=True)
                else:
                    # Clear stale Domain Reputation vulnerabilities when none are found
                    save_domain_reputation_vulnerabilities(domain, [], update_existing=True)
                
                completed_steps += 1
                if job_id in background_jobs:
                    background_jobs[job_id]['progress'] = int((completed_steps / total_steps) * 100)
                    background_jobs[job_id]['logs'].append(f" Step 3 completed: Reputation scan, Score {result['final_score']}")
                logging.info(f" Reputation scan completed for {domain}: Score {result['final_score']}")
            else:
                completed_steps += 1  # Still count as completed even if skipped
                if job_id in background_jobs:
                    background_jobs[job_id]['progress'] = int((completed_steps / total_steps) * 100)
                    background_jobs[job_id]['logs'].append(f" Step 3 skipped: Reputation scan (API not available)")
                logging.warning(f" Reputation scan skipped for {domain} (API not available)")
        except Exception as e:
            if job_id in background_jobs:
                background_jobs[job_id]['logs'].append(f" Step 3 failed: Reputation scan error")
            logging.error(f" Reputation scan failed for {domain}: {e}")
            notify_scan_step_failure(domain, "Step 3: Domain Reputation Scan", str(e), job_id)
            # Continue with remaining steps
        
        # Check if job was cancelled
        if job_id in background_jobs and background_jobs[job_id]['status'] == 'cancelled':
            logging.info(f"Background scan job {job_id} was cancelled after step 3")
            return False
        
        # Step 4: Network Scan
        if job_id in background_jobs:
            background_jobs[job_id]['stage'] = 'network_scan'
        logging.info(f"Step 4/7: Scanning network ports for {domain}")
        try:
            from network_scanner_api import scan_network_ports
            
            # Determine domains to scan based on include_subdomains parameter
            if include_subdomains:
                # Get active subdomains for network scan
                subdomains = get_subdomains_for_domain(domain)
                active_subdomains = [item['subdomain'] for item in subdomains if item.get('status') == 'Active'] if subdomains else None
                logging.info(f"Background scan: Using active subdomains for network scan")
            else:
                # Main domains only - don't use any subdomains
                active_subdomains = None
                logging.info(f"Background scan: Scanning main domain only for network scan: {domain}")
            
            result = scan_network_ports(domain, active_subdomains)
            if result:
                # Use the scan_format passed to this function
                save_network_score(domain, result['final_score'], scan_format=scan_format)
                
                # Save network vulnerabilities
                if result['issues_found']:
                    vuln_data_for_db = []
                    for issue in result['issues_found']:
                        vuln_data_for_db.append({
                            'subdomain': issue.get('subdomain', domain),
                            'title': f"Port {issue.get('port', 'Unknown')} ({issue.get('service', 'Unknown')})",
                            'description': issue.get('description', 'Network port finding'),
                            'severity': issue.get('severity', 'INFO')
                        })
                    save_network_vulnerabilities(domain, vuln_data_for_db, update_existing=True)
                else:
                    # Clear stale Network vulnerabilities when none are found
                    save_network_vulnerabilities(domain, [], update_existing=True)
                
                completed_steps += 1
                if job_id in background_jobs:
                    background_jobs[job_id]['progress'] = int((completed_steps / total_steps) * 100)
                    background_jobs[job_id]['logs'].append(f" Step 4 completed: Network scan, Score {result['final_score']}")
                logging.info(f" Network scan completed for {domain}: Score {result['final_score']}")
        except Exception as e:
            if job_id in background_jobs:
                background_jobs[job_id]['logs'].append(f" Step 4 failed: Network scan error")
            logging.error(f" Network scan failed for {domain}: {e}")
            notify_scan_step_failure(domain, "Step 4: Network Scan", str(e), job_id)
            # Continue with remaining steps
        
        # Check if job was cancelled
        if job_id in background_jobs and background_jobs[job_id]['status'] == 'cancelled':
            logging.info(f"Background scan job {job_id} was cancelled after step 4")
            return False
        
        # Step 5: DNS Security Scan
        if job_id in background_jobs:
            background_jobs[job_id]['stage'] = 'dns_scan'
        logging.info(f"Step 5/7: Checking DNS security for {domain}")
        try:
            sys.path.insert(0, str(get_app_root()))
            from DNS.scanner import scan_domain_dns_security
            
            # Determine domains to scan based on include_subdomains parameter
            if include_subdomains:
                # Get active subdomains for DNS scan
                subdomains = get_subdomains_for_domain(domain)
                active_subdomains = [item['subdomain'] for item in subdomains if item.get('status') == 'Active']
                if domain not in active_subdomains:
                    active_subdomains.insert(0, domain)
            else:
                # Main domains only - scan only the primary domain
                active_subdomains = [domain]
            
            
            result = scan_domain_dns_security(domain, None, subdomains_list=active_subdomains)
            if result:
                # Use the scan_format passed to this function
                save_dns_score(domain, result['final_score'], scan_format=scan_format)
                
                # Save DNS vulnerabilities
                if result['issues_found']:
                    vuln_data_for_db = []
                    for issue in result['issues_found']:
                        vuln_data_for_db.append({
                            'subdomain': issue.get('domain', domain),
                            'title': issue.get('finding') or issue.get('issue_type', 'DNS Security Issue'),
                            'description': issue.get('description', 'DNS security issue detected'),
                            'severity': issue.get('severity', 'Medium')
                        })
                    save_dns_vulnerabilities(domain, vuln_data_for_db, update_existing=True)
                else:
                    # Clear stale DNS vulnerabilities when none are found
                    save_dns_vulnerabilities(domain, [], update_existing=True)
                
                completed_steps += 1
                if job_id in background_jobs:
                    background_jobs[job_id]['progress'] = int((completed_steps / total_steps) * 100)
                    background_jobs[job_id]['logs'].append(f" Step 5 completed: DNS scan, Score {result['final_score']}")
                logging.info(f" DNS scan completed for {domain}: Score {result['final_score']}")
        except Exception as e:
            if job_id in background_jobs:
                background_jobs[job_id]['logs'].append(f" Step 5 failed: DNS scan error")
            logging.error(f" DNS scan failed for {domain}: {e}")
            notify_scan_step_failure(domain, "Step 5: DNS Security Scan", str(e), job_id)
            # Continue with remaining steps
        
        # Check if job was cancelled
        if job_id in background_jobs and background_jobs[job_id]['status'] == 'cancelled':
            logging.info(f"Background scan job {job_id} was cancelled after step 5")
            return False
        
        # Step 6: Encryption Scan
        if job_id in background_jobs:
            background_jobs[job_id]['stage'] = 'encryption_scan'
        logging.info(f"Step 6/7: Scanning SSL/TLS encryption for {domain}")
        try:
            from vendor_risk_scanner_local import VendorRiskScanner
            
            # Determine domains to scan based on include_subdomains parameter
            if include_subdomains:
                # Get active subdomains for encryption scan (same logic as individual scan)
                subdomains = get_subdomains_for_domain(domain)
                if subdomains:
                    # Filter for only Active subdomains
                    active_subdomains = [subdomain['subdomain'] for subdomain in subdomains if subdomain.get('status') == 'Active']
                    
                    if active_subdomains:
                        # Always include the main domain (assume it's active)
                        if domain not in active_subdomains:
                            active_subdomains.insert(0, domain)
                        domains_to_scan = active_subdomains
                    else:
                        domains_to_scan = [domain]
                else:
                    domains_to_scan = [domain]
            else:
                # Main domains only - scan only the primary domain
                domains_to_scan = [domain]
            
            current_dir = app_join('Encryption', 'LOCAL')
            testssl_path = os.path.join(current_dir, "testssl.sh", "testssl.sh")
            scanner = VendorRiskScanner(testssl_path=testssl_path)
            
            vulnerabilities = []
            domain_scores = []
            total_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
            initial_score = 950
            severity_weights = get_severity_weights('ENCRYPTION')
            
            logging.info(f"Scanning {len(domains_to_scan)} domains for encryption vulnerabilities: {domains_to_scan}")
            
            # Scan ALL active subdomains (not limited to 5)
            for _sub_index, scan_domain in enumerate(domains_to_scan, start=1):
                try:
                    # Keep the job row's updated_at moving: this loop can run for
                    # well over an hour on a vendor with many subdomains, and the
                    # next progress write is only after the whole loop finishes.
                    heartbeat_job(
                        job_id,
                        f"encryption_scan ({_sub_index}/{len(domains_to_scan)}: {scan_domain})"
                    )
                    logging.info(f"Scanning {scan_domain} for encryption vulnerabilities")
                    result = scanner.scan_domain(scan_domain, full_scan=True)
                    
                    # Initialize domain-specific vulnerability count tracking
                    domain_severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
                    
                    # Extract testssl vulnerabilities
                    testssl_results = result.get('testssl', {})
                    if 'vulnerabilities' in testssl_results:
                        testssl_vulnerabilities = testssl_results['vulnerabilities']
                        for vuln_name, vuln_data in testssl_vulnerabilities.items():
                            severity = vuln_data.get('severity', 'MEDIUM').upper()
                            if not severity:  # Handle empty severity
                                severity = 'MEDIUM'
                            
                            # Generate better vulnerability title for grouping
                            finding_text = vuln_data.get('finding', 'SSL/TLS vulnerability detected')
                            vulnerability_title = generate_encryption_vulnerability_title(vuln_name, finding_text)
                            
                            vulnerabilities.append({
                                'domain': scan_domain,
                                'vulnerability': vulnerability_title,
                                'severity': severity,
                                'description': finding_text,
                                'category': 'Encryption'
                            })
                            # Count by severity
                            if severity in total_counts:
                                total_counts[severity] += 1
                                domain_severity_counts[severity] += 1
                    
                    # Extract enhanced security check issues
                    enhanced_checks = result.get('enhanced_security_checks', {})
                    if enhanced_checks and 'error' not in enhanced_checks:
                        # Check each security check for issues (same mapping as individual scan)
                        check_names = {
                            'ssl_availability': 'SSL not available',
                            'hostname_certificate_match': 'The site hostname does not match the SSL certificate',
                            'http_to_https_redirect': 'HTTP does not redirect to HTTPS', 
                            'https_redirect_support': 'HTTPS redirect not supported',
                            'ssl_expired': 'SSL expired',
                            'untrusted_ssl_certificate': 'Untrusted SSL certificate (Provisional)',
                            'diffie_hellman_strength': 'Common Diffie-Hellman prime used in key exchange',
                            'hsts_enforcement': 'HTTP Strict Transport Security (HSTS) not enforced',
                            'insecure_cipher_suites': 'Insecure cipher suite supported',
                            'insecure_ssl_versions': 'Insecure SSL/TLS versions available',
                            'weak_tls12_ciphers': 'Only weak cipher suites supported in TLS 1.2',
                            'ssl_certificate_chain': 'SSL certificate chain missing from server response',
                            'ssl_expiration_period': 'SSL expiration period longer than 398 days',
                            'ssl_expires_soon': 'SSL expires within 20 days',
                            'weak_ssl_algorithm': 'Weak SSL algorithm',
                            'hsts_preload_list': 'Domain was not found on the HSTS preload list',
                            'hsts_includesubdomains': 'HSTS header does not contain includeSubDomains',
                            'weak_dh_key_exchange': 'Weak Diffie-Hellman prime used in key exchange',
                            'weak_public_key_length': 'Weak public certificate key length',
                            'revoked_certificate': 'Revoked certificate in use'
                        }
                        
                        # Map each check to its severity based on the rubric
                        severity_mapping = {
                            'ssl_availability': 'CRITICAL',
                            'hostname_certificate_match': 'HIGH', 
                            'http_to_https_redirect': 'HIGH',
                            'https_redirect_support': 'MEDIUM',
                            'ssl_expired': 'HIGH',
                            'untrusted_ssl_certificate': 'HIGH',
                            'diffie_hellman_strength': 'MEDIUM',
                            'hsts_enforcement': 'MEDIUM',
                            'insecure_cipher_suites': 'MEDIUM',
                            'insecure_ssl_versions': 'MEDIUM',
                            'weak_tls12_ciphers': 'MEDIUM',
                            'ssl_certificate_chain': 'MEDIUM',
                            'ssl_expiration_period': 'MEDIUM',
                            'ssl_expires_soon': 'MEDIUM',
                            'weak_ssl_algorithm': 'MEDIUM',
                            'hsts_preload_list': 'LOW',
                            'hsts_includesubdomains': 'LOW',
                            'weak_dh_key_exchange': 'LOW',
                            'weak_public_key_length': 'LOW',
                            'revoked_certificate': 'CRITICAL'
                        }
                        
                        for check_key, check_name in check_names.items():
                            if check_key in enhanced_checks and check_key != 'summary':
                                check_result = enhanced_checks[check_key]
                                if check_result.get('issue'):
                                    # Get severity from mapping
                                    severity = severity_mapping.get(check_key, 'MEDIUM')
                                    
                                    vulnerabilities.append({
                                        'domain': scan_domain,
                                        'vulnerability': check_name,
                                        'severity': severity,
                                        'description': check_result['issue'],
                                        'category': 'Encryption'
                                    })
                                    # Count by severity
                                    if severity in total_counts:
                                        total_counts[severity] += 1
                                        domain_severity_counts[severity] += 1
                    
                    # Calculate score for this domain
                    domain_score = initial_score
                    for severity, count in domain_severity_counts.items():
                        if count > 0:
                            domain_score -= count * severity_weights.get(severity, 0)
                    domain_score = max(0, domain_score)
                    domain_scores.append(domain_score)
                    
                except Exception as sub_error:
                    logging.error(f"Error scanning encryption for {scan_domain}: {sub_error}")
            
            # Calculate final encryption score
            final_score = int(sum(domain_scores) / len(domain_scores)) if domain_scores else 950
            # Use the scan_format passed to this function
            save_encryption_score(domain, final_score, scan_format=scan_format)
            
            # Save encryption vulnerabilities
            if vulnerabilities:
                vuln_data_for_db = []
                for vuln in vulnerabilities:
                    vuln_data_for_db.append({
                        'subdomain': vuln.get('domain', domain),
                        'title': vuln.get('vulnerability', 'SSL/TLS Security Issue'),
                        'description': vuln.get('description', 'Encryption security issue detected'),
                        'severity': vuln.get('severity', 'MEDIUM')
                    })
                save_encryption_vulnerabilities(domain, vuln_data_for_db, update_existing=True)
            else:
                # Clear stale Encryption vulnerabilities when none are found
                save_encryption_vulnerabilities(domain, [], update_existing=True)
            
            completed_steps += 1
            if job_id in background_jobs:
                background_jobs[job_id]['progress'] = int((completed_steps / total_steps) * 100)
                background_jobs[job_id]['logs'].append(f" Step 6 completed: Encryption scan, Score {final_score}")
            logging.info(f" Encryption scan completed for {domain}: Score {final_score}")
        except Exception as e:
            if job_id in background_jobs:
                background_jobs[job_id]['logs'].append(f" Step 6 failed: Encryption scan error")
            logging.error(f"Encryption scan failed for {domain}: {e}")
            notify_scan_step_failure(domain, "Step 6: Encryption / SSL-TLS Scan", str(e), job_id)
            # Continue with remaining steps
        
        # Check if job was cancelled
        if job_id in background_jobs and background_jobs[job_id]['status'] == 'cancelled':
            logging.info(f"Background scan job {job_id} was cancelled after step 6")
            return False
        
        # Step 7: Email Security Scan
        if job_id in background_jobs:
            background_jobs[job_id]['stage'] = 'email_scan'
        logging.info(f"Step 7/7: Checking email security for {domain}")
        try:
            sys.path.append(app_join('email'))
            from email_security_checker import EmailSecurityChecker
            
            checker = EmailSecurityChecker()
            result = checker.check_domain_email_security(domain)
            
            if result:
                # Use the scan_format passed to this function
                save_email_score(domain, result['security_score'], scan_format=scan_format)
                
                # Process email vulnerabilities
                vulnerabilities = []
                
                # DMARC issues (same logic as individual scan)
                if result['dmarc']['issues']:
                    for issue in result['dmarc']['issues']:
                        severity = 'High' if any(term in issue.lower() for term in ['not found', 'p=none']) else \
                                  'Medium' if 'syntax error' in issue.lower() else 'Low'
                        vulnerabilities.append({
                            'title': f"DMARC: {issue.split(' - ')[0] if ' - ' in issue else issue[:50]}",
                            'description': f"DMARC policy issue for {domain}: {issue}",
                            'severity': severity,
                            'subdomain': domain,
                            'category': 'Email'
                        })
                
                # SPF issues (same logic as individual scan)
                if result['spf']['issues']:
                    for issue in result['spf']['issues']:
                        severity = 'High' if any(term in issue.lower() for term in ['not enabled', '+all']) else \
                                  'Medium' if 'syntax error' in issue.lower() else 'Low'
                        vulnerabilities.append({
                            'title': f"SPF: {issue.split(' - ')[0] if ' - ' in issue else issue[:50]}",
                            'description': f"SPF policy issue for {domain}: {issue}",
                            'severity': severity,
                            'subdomain': domain,
                            'category': 'Email'
                        })
                
                # Save email vulnerabilities (replace mode)
                if vulnerabilities:
                    save_email_vulnerabilities(domain, vulnerabilities, update_existing=True)
                else:
                    # Clear stale Email vulnerabilities when none are found
                    save_email_vulnerabilities(domain, [], update_existing=True)
                
                completed_steps += 1
                if job_id in background_jobs:
                    background_jobs[job_id]['progress'] = int((completed_steps / total_steps) * 100)
                    background_jobs[job_id]['logs'].append(f" Step 7 completed: Email scan, Score {result['security_score']}")
                logging.info(f" Email scan completed for {domain}: Score {result['security_score']}")
        except Exception as e:
            if job_id in background_jobs:
                background_jobs[job_id]['logs'].append(f" Step 7 failed: Email scan error")
            logging.error(f" Email scan failed for {domain}: {e}")
            notify_scan_step_failure(domain, "Step 7: Email Security Scan", str(e), job_id)
            # Continue to final steps
        
        # Update overall vendor score
        try:
            # Pass the scan_format to the overall score update function
            update_vendor_overall_score_after_scan(domain, scan_format=scan_format)
            if job_id in background_jobs:
                background_jobs[job_id]['logs'].append(f" Overall score updated for {domain}")
            logging.info(f" Updated overall score for {domain}")
        except Exception as e:
            if job_id in background_jobs:
                background_jobs[job_id]['logs'].append(f" Failed to update overall score")
            logging.error(f" Failed to update overall score for {domain}: {e}")
            notify_score_update_failure(domain, str(e), job_id)
        
        # Stamp the scan cursor. This is the ONLY place vendors.last_full_scan_at
        # is written, and only once every step above has run -- that exclusivity
        # is what makes stalest-first scan ordering trustworthy. Do not move this
        # into update_vendor_overall_score: non-scan paths reach that function.
        try:
            mark_vendor_full_scan_complete(domain)
        except Exception as cursor_error:
            # Non-fatal: the vendor stays "stale" and is simply retried sooner.
            logging.error(f"Failed to stamp scan cursor for {domain}: {cursor_error}")

        # Final completion update
        if job_id in background_jobs:
            background_jobs[job_id]['progress'] = 100
            background_jobs[job_id]['logs'].append(f" Background scan completed successfully for {domain}")
        
        # Invalidate AI insights cache for this domain since security data has changed
        invalidate_ai_insights_cache(domain)
        logging.info(f" Background full scan completed for {domain} - AI insights cache invalidated")
        return True
        
    except Exception as e:
        logging.error(f" Background full scan failed for {domain}: {str(e)}")
        return False

def run_background_full_scan_all_domains(job_id, include_subdomains=True, checkpoint_vendor=''):
    """Run full scan for all domains in background thread"""
    try:
        logging.info(f"Starting background full scan for all domains (Job: {job_id}, include_subdomains: {include_subdomains}, checkpoint: {checkpoint_vendor or 'none'})")
        
        # Work stalest-first. This ordering *is* the resume mechanism: a scan
        # interrupted at any point simply leaves those vendors oldest, so the
        # next run picks them up first. No checkpoint arithmetic, and no way to
        # starve the vendors that used to sit before the checkpoint.
        vendors = get_vendors_for_full_scan()
        domains = [vendor['domain'] for vendor in vendors if vendor.get('domain')]

        start_index = 0
        if checkpoint_vendor:
            # Manual "start from this vendor" only. Exact match on domain or
            # name -- the previous bidirectional substring match could resolve
            # to a different vendor entirely (e.g. checkpoint 'gopay.com.au'
            # matching a vendor whose domain is 'pay.com') and silently anchor
            # the pass in the wrong place.
            needle = checkpoint_vendor.lower().strip()
            match_index = next(
                (
                    idx for idx, v in enumerate(vendors)
                    if (v.get('domain') or '').lower().strip() == needle
                    or (v.get('vendor_name') or '').lower().strip() == needle
                ),
                None,
            )
            if match_index is None:
                logging.warning(f"Checkpoint vendor '{checkpoint_vendor}' not found, scanning all vendors stalest-first")
                if job_id in background_jobs:
                    background_jobs[job_id]['logs'].append(
                        f"Warning: Checkpoint vendor '{checkpoint_vendor}' not found, scanning all vendors stalest-first"
                    )
            else:
                start_index = match_index
                matched = vendors[start_index]
                logging.info(f"Checkpoint matched: starting from '{matched.get('vendor_name')}' ({matched.get('domain')}) at index {start_index}")
                if job_id in background_jobs:
                    background_jobs[job_id]['logs'].append(
                        f"Checkpoint matched: starting from '{matched.get('vendor_name')}' ({matched.get('domain')})"
                    )
                domains = [v['domain'] for v in vendors[start_index:] if v.get('domain')]
        
        if job_id in background_jobs:
            background_jobs[job_id]['domains'] = domains
            background_jobs[job_id]['total_domains'] = len(domains)
            background_jobs[job_id]['completed'] = []
            background_jobs[job_id]['failed'] = []
        
        logging.info(f"Found {len(domains)} domains to scan" + (f" (starting from index {start_index})" if start_index > 0 else ""))
        
        for i, domain in enumerate(domains):
            if job_id not in background_jobs or background_jobs[job_id]['status'] == 'cancelled':
                logging.info(f"Background scan job {job_id} was cancelled")
                break
            
            # Update progress
            progress = int((i / len(domains)) * 100)
            background_jobs[job_id]['progress'] = progress
            background_jobs[job_id]['current_domain'] = domain
            
            logging.info(f"Scanning domain {i+1}/{len(domains)}: {domain} (Progress: {progress}%)")
            
            try:
                # Pass 'full_scan_all' since this is scanning all domains
                success = run_full_scan_for_domain_background(job_id, domain, include_subdomains, scan_format='full_scan_all')
                if success:
                    background_jobs[job_id]['completed'].append(domain)
                    logging.info(f" Completed scan for {domain}")
                else:
                    background_jobs[job_id]['failed'].append(domain)
                    logging.error(f" Failed scan for {domain}")
            except Exception as domain_error:
                background_jobs[job_id]['failed'].append(domain)
                logging.error(f" Error scanning {domain}: {domain_error}")
        
        # Mark job as completed (unless already cancelled)
        if job_id in background_jobs:
            # Don't change status if already cancelled
            if background_jobs[job_id]['status'] != 'cancelled':
                background_jobs[job_id]['status'] = 'completed'
                background_jobs[job_id]['progress'] = 100
            
            background_jobs[job_id]['end_time'] = datetime.now()
            
            completed_count = len(background_jobs[job_id]['completed'])
            failed_count = len(background_jobs[job_id]['failed'])
            total_count = len(domains)
            
            logging.info(f" Background full scan completed (Job: {job_id})")
            logging.info(f"   Status: {background_jobs[job_id]['status']}")
            logging.info(f"   Total domains: {total_count}")
            logging.info(f"   Completed: {completed_count}")
            logging.info(f"   Failed: {failed_count}")
        
        # Invalidate all caches to refresh data
        invalidate_vendors_cache()
        invalidate_dashboard_cache()
        
    except Exception as e:
        logging.error(f" Background full scan job {job_id} failed: {str(e)}")
        if job_id in background_jobs:
            background_jobs[job_id]['status'] = 'failed'
            background_jobs[job_id]['error'] = str(e)

def run_background_filtered_scan(job_id, include_subdomains=True, vendor_filters={}):
    """Run filtered scan for vendors matching the provided filters"""
    try:
        logging.info(f"Starting background filtered scan (Job: {job_id}, include_subdomains: {include_subdomains}, filters: {vendor_filters})")
        
        # Get all vendors and apply filters
        all_vendors = get_vendors_cached()
        
        # Apply the same filtering logic as the frontend
        filtered_vendors = []
        for vendor in all_vendors:
            if not vendor.get('domain'):
                continue
                
            # Apply search filter if provided
            search_term = vendor_filters.get('search_term', '').lower()
            if search_term:
                if not (search_term in vendor.get('name', '').lower() or 
                       search_term in vendor.get('domain', '').lower()):
                    continue
            
            # Apply risk level filter
            risk_filter = vendor_filters.get('risk_levels', [])
            if risk_filter and vendor.get('riskLevel') not in risk_filter:
                continue
            
            # Apply tier filter
            tier_filter = vendor_filters.get('tiers', [])
            if tier_filter:
                vendor_tier = vendor.get('tier', 'Unknown')
                tier_match = False
                for selected_tier in tier_filter:
                    if selected_tier == 'Untiered':
                        if not vendor_tier or vendor_tier == 'Unknown' or vendor_tier.strip() == '' or vendor_tier == 'Untiered':
                            tier_match = True
                            break
                    else:
                        if selected_tier in (vendor_tier or 'Unknown').split(','):
                            tier_match = True
                            break
                if not tier_match:
                    continue
            
            # Apply portfolio filter
            portfolio_filter = vendor_filters.get('portfolios', [])
            if portfolio_filter:
                vendor_portfolio = vendor.get('portfolio', 'Unknown')
                portfolio_match = False
                for selected_portfolio in portfolio_filter:
                    if selected_portfolio in (vendor_portfolio or 'Unknown').split(','):
                        portfolio_match = True
                        break
                if not portfolio_match:
                    continue
            
            # Apply industry filter
            industry_filter = vendor_filters.get('industries', [])
            if industry_filter:
                vendor_industry = vendor.get('industry', 'Unknown')
                industry_match = False
                for selected_industry in industry_filter:
                    if selected_industry in (vendor_industry or 'Unknown').split(','):
                        industry_match = True
                        break
                if not industry_match:
                    continue
            
            # If we get here, vendor matches all filters
            filtered_vendors.append(vendor)
        
        # Extract domains from filtered vendors
        domains = [vendor['domain'] for vendor in filtered_vendors]
        
        if job_id in background_jobs:
            background_jobs[job_id]['domains'] = domains
            background_jobs[job_id]['total_domains'] = len(domains)
            background_jobs[job_id]['completed'] = []
            background_jobs[job_id]['failed'] = []
            background_jobs[job_id]['logs'].append(f"Filtered scan: {len(domains)} vendors match the filters")
        
        logging.info(f"Found {len(domains)} domains matching filters to scan")
        
        if len(domains) == 0:
            logging.warning(f"No vendors match the provided filters")
            if job_id in background_jobs:
                background_jobs[job_id]['status'] = 'completed'
                background_jobs[job_id]['progress'] = 100
                background_jobs[job_id]['end_time'] = datetime.now()
                background_jobs[job_id]['logs'].append("No vendors match the filters - scan completed")
            return
        
        for i, domain in enumerate(domains):
            if job_id not in background_jobs or background_jobs[job_id]['status'] == 'cancelled':
                logging.info(f"Background filtered scan job {job_id} was cancelled")
                break
            
            # Update progress
            progress = int((i / len(domains)) * 100)
            background_jobs[job_id]['progress'] = progress
            background_jobs[job_id]['current_domain'] = domain
            
            logging.info(f"Scanning filtered domain {i+1}/{len(domains)}: {domain} (Progress: {progress}%)")
            
            try:
                # Pass 'filtered_scan' since this is scanning filtered domains
                success = run_full_scan_for_domain_background(job_id, domain, include_subdomains, scan_format='filtered_scan')
                if success:
                    background_jobs[job_id]['completed'].append(domain)
                    logging.info(f" Completed filtered scan for {domain}")
                else:
                    background_jobs[job_id]['failed'].append(domain)
                    logging.error(f" Failed filtered scan for {domain}")
            except Exception as domain_error:
                background_jobs[job_id]['failed'].append(domain)
                logging.error(f" Error in filtered scan for {domain}: {domain_error}")
        
        # Mark job as completed (unless already cancelled)
        if job_id in background_jobs:
            # Don't change status if already cancelled
            if background_jobs[job_id]['status'] != 'cancelled':
                background_jobs[job_id]['status'] = 'completed'
                background_jobs[job_id]['progress'] = 100
            
            background_jobs[job_id]['end_time'] = datetime.now()
            
            completed_count = len(background_jobs[job_id]['completed'])
            failed_count = len(background_jobs[job_id]['failed'])
            total_count = len(domains)
            
            logging.info(f" Background filtered scan completed (Job: {job_id})")
            logging.info(f"   Status: {background_jobs[job_id]['status']}")
            logging.info(f"   Total filtered domains: {total_count}")
            logging.info(f"   Completed: {completed_count}")
            logging.info(f"   Failed: {failed_count}")
        
        # Invalidate all caches to refresh data
        invalidate_vendors_cache()
        invalidate_dashboard_cache()
        
    except Exception as e:
        logging.error(f" Background filtered scan job {job_id} failed: {str(e)}")
        if job_id in background_jobs:
            background_jobs[job_id]['status'] = 'failed'
            background_jobs[job_id]['error'] = str(e)


def _notify_api_vendor_scan_completed_slack_async(job_id: str, domain: str) -> None:
    """Post Slack when API-layer vendor creation triggered this scan (non-blocking)."""
    def _run():
        try:
            job = background_jobs.get(job_id)
            if not job or not job.get('slack_notify_on_complete'):
                return
            if job.get('status') == 'cancelled':
                return
            vendor = get_vendor_by_domain(domain)
            vendor_name = (vendor or {}).get('name') or domain
            scan_ok = job.get('status') == 'completed' and domain in job.get('completed', [])
            score = (vendor or {}).get('securityScore')
            risk = (vendor or {}).get('riskLevel')
            from slack.slack_service import send_api_vendor_scan_completed_notification
            send_api_vendor_scan_completed_notification(
                domain=domain,
                vendor_name=str(vendor_name),
                job_id=job_id,
                scan_succeeded=scan_ok,
                overall_score=score,
                risk_level=risk,
            )
        except Exception as exc:
            logging.error("Slack notification for API vendor scan completion failed: %s", exc)

    threading.Thread(target=_run, name="slack-api-vendor-scan", daemon=True).start()


def run_background_single_domain_scan(job_id, domain, include_subdomains=True):
    """Run full scan for a single domain in background thread"""
    try:
        logging.info(f"Starting background single domain scan for {domain} (Job: {job_id}, include_subdomains: {include_subdomains})")
        
        # Update job tracking
        if job_id in background_jobs:
            background_jobs[job_id]['domains'] = [domain]
            background_jobs[job_id]['total_domains'] = 1
            background_jobs[job_id]['current_domain'] = domain
            background_jobs[job_id]['completed'] = []
            background_jobs[job_id]['failed'] = []
            background_jobs[job_id]['logs'].append(f"Starting comprehensive scan for {domain}")
        
        try:
            # Determine scan_format: check if this is an auto-scan for a new vendor
            scan_format = 'full_scan_single'  # default
            if job_id in background_jobs and background_jobs[job_id].get('auto_scan'):
                scan_format = 'new_vendor'
                logging.info(f"Auto-scan detected for new vendor: {domain}, using scan_format='new_vendor'")
            
            # Run the full scan for the domain
            success = run_full_scan_for_domain_background(job_id, domain, include_subdomains, scan_format=scan_format)
            
            # Check if job was cancelled during scan
            if job_id in background_jobs and background_jobs[job_id]['status'] == 'cancelled':
                logging.info(f"Background scan job {job_id} was cancelled")
                return
            
            if success:
                if job_id in background_jobs:
                    background_jobs[job_id]['completed'].append(domain)
                    background_jobs[job_id]['logs'].append(f" Completed scan for {domain}")
                logging.info(f" Completed background scan for {domain}")
            else:
                if job_id in background_jobs:
                    background_jobs[job_id]['failed'].append(domain)
                    background_jobs[job_id]['logs'].append(f" Failed scan for {domain}")
                logging.error(f" Failed background scan for {domain}")
                notify_scan_overall_failure(domain, "Scan returned failure status", job_id)
                
        except Exception as domain_error:
            if job_id in background_jobs:
                background_jobs[job_id]['failed'].append(domain)
                background_jobs[job_id]['logs'].append(f" Error scanning {domain}: {str(domain_error)}")
            logging.error(f" Error in background scan for {domain}: {domain_error}")
        
        # Mark job as completed (unless already cancelled)
        if job_id in background_jobs:
            # Don't change status if already cancelled
            if background_jobs[job_id]['status'] != 'cancelled':
                if domain in background_jobs[job_id]['completed']:
                    background_jobs[job_id]['status'] = 'completed'
                else:
                    background_jobs[job_id]['status'] = 'failed'
                
                background_jobs[job_id]['progress'] = 100
                
            background_jobs[job_id]['end_time'] = datetime.now()
            
            completed_count = len(background_jobs[job_id]['completed'])
            failed_count = len(background_jobs[job_id]['failed'])
            
            logging.info(f"Background single domain scan completed (Job: {job_id})")
            logging.info(f"   Domain: {domain}")
            logging.info(f"   Status: {background_jobs[job_id]['status']}")
        
        # Invalidate caches to refresh data
        invalidate_vendors_cache()
        invalidate_dashboard_cache()
        
    except Exception as e:
        logging.error(f" Background single domain scan job {job_id} failed: {str(e)}")
        if job_id in background_jobs:
            background_jobs[job_id]['status'] = 'failed'
            background_jobs[job_id]['error'] = str(e)
            background_jobs[job_id]['logs'].append(f" Job failed: {str(e)}")
        notify_scan_overall_failure(domain, str(e), job_id)
    finally:
        try:
            if (
                job_id in background_jobs
                and background_jobs[job_id].get('slack_notify_on_complete')
                and background_jobs[job_id].get('status') != 'cancelled'
            ):
                _notify_api_vendor_scan_completed_slack_async(job_id, domain)
        except Exception as slack_exc:
            logging.error("Failed to schedule API vendor scan Slack notification: %s", slack_exc)


# Startup handlers run in registration order, so the schema migration must be
# registered BEFORE the scan scheduler: the scheduler starts a full scan which
# queries vendors.last_full_scan_at, a column ensure_vendor_scan_cursor() adds.
@app.on_event("startup")
async def apply_db_migrations_on_startup() -> None:
    """Auto-create / migrate database tables on container start."""
    try:
        from db_migrations import apply_pending_migrations
        apply_pending_migrations()
    except Exception as exc:
        logging.error("Database auto-migration failed on startup: %s", exc)


from routes.background_scan_scheduler import register_auto_full_scan_on_startup
register_auto_full_scan_on_startup(app, background_jobs, run_background_full_scan_all_domains)


if __name__ == '__main__':
    
    # Initialize vendor cache on startup
    logging.info("Initializing vendor cache...")
    get_vendors_cached()  # This will load and cache the vendors data
    logging.info("Vendor cache initialized successfully")
    
    try:
        from db_service import BreachRecordsService
        service = BreachRecordsService()
        logging.info("Breach records service initialized successfully")
    except Exception as e:
        logging.error(f" Failed to initialize breach records: {e}")


# Import PDF report generator from separate module
from pdf_report_generator import generate_pdf_report


if __name__ == '__main__':
    # Initialize news scheduler only when running as main app
    # initialize_news_scheduler()
    initialize_threaded_schedulers()

    # Run the FastAPI app with uvicorn
    import uvicorn
    uvicorn.run(
        app,  # Pass app object directly
        host="0.0.0.0",
        port=5005,
        reload=False  # Set to False when passing app object directly
    )