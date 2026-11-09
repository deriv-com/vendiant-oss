"""
Backend Client for Vendor Management
Handles communication with the Flask backend for vendor operations
"""

import requests
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import asyncio
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote


class BackendAPIError(Exception):
    """Raised when the backend returns a known HTTP error. Preserves status code and message."""
    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(detail)


def _extract_backend_detail(response: requests.Response) -> str:
    """Pull the most useful error message out of a backend error response."""
    try:
        data = response.json()
        # FastAPI shape: {"detail": "..."}
        if isinstance(data.get("detail"), str):
            return data["detail"]
        # Backend shape: {"error": "...", "message": "..."}
        return data.get("error") or data.get("message") or response.text[:300]
    except Exception:
        return response.text[:300] or f"HTTP {response.status_code}"

logger = logging.getLogger(__name__)

class BackendClient:
    """Client for communicating with the Flask backend for vendor operations"""
    
    def __init__(self, backend_url: str = None):
        # Use environment variable or default to container service name
        import os
        self.backend_url = backend_url or os.getenv('BACKEND_API_URL', 'http://localhost:5005')
        self.session = requests.Session()
        self.executor = ThreadPoolExecutor(max_workers=10)
    
    def _make_request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """Make HTTP request to backend"""
        url = f"{self.backend_url}{endpoint}"
        try:
            # Use longer timeout for data-heavy endpoints
            timeout = kwargs.pop('timeout', 60)  # Default 60 seconds
            response = self.session.request(method, url, timeout=timeout, **kwargs)
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            logger.error(f"Backend request failed: {method} {url} - {e}")
            raise
    
    async def _async_request(self, method: str, endpoint: str, **kwargs):
        """Make async HTTP request to backend"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self.executor, 
            lambda: self._make_request(method, endpoint, **kwargs)
        )

    async def process_breach_monitor_webhook(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Forward Breach Monitor callback payload to the backend for upsert + Slack."""
        try:
            response = await self._async_request(
                "POST",
                "/internal/breach-monitor/webhook",
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=120,
            )
            data = response.json()
            return data if isinstance(data, dict) else {}
        except requests.exceptions.HTTPError as exc:
            resp = exc.response
            status_code = resp.status_code if resp is not None else 500
            detail = _extract_backend_detail(resp) if resp is not None else str(exc)
            raise BackendAPIError(status_code, detail) from exc
        except requests.exceptions.RequestException as exc:
            logger.error("Breach Monitor webhook backend request failed: %s", exc)
            raise BackendAPIError(503, "Backend unavailable") from exc
    
    async def get_vendors(self) -> List[Dict[str, Any]]:
        """Get list of all vendors"""
        try:
            # First refresh cache to get latest data
            await self._async_request('POST', '/api/vendors/reload', 
                                    headers={'Content-Type': 'application/json'}, 
                                    json={})
            
            # Get vendors from backend
            response = await self._async_request('GET', '/api/vendors')
            vendors_data = response.json()
            
            # Transform to API format
            vendors = []
            for vendor in vendors_data:
                vendors.append({
                    "id": vendor.get("id"),
                    "name": vendor.get("name"),
                    "domain": vendor.get("domain"),
                    "description": vendor.get("description", ""),
                    "created_at": datetime.now(),  # Backend doesn't track this yet
                    "updated_at": datetime.now()   # Backend doesn't track this yet
                })
            
            return vendors
            
        except Exception as e:
            logger.error(f"Error fetching vendors: {e}")
            raise
    
    async def get_vendor_score(self, vendor_id: int) -> Optional[Dict[str, Any]]:
        """Get overall risk score for a specific vendor"""
        try:
            # Get vendor info first
            response = await self._async_request('GET', f'/api/vendors/{vendor_id}')
            vendor_data = response.json()
            
            if not vendor_data:
                return None
            
            # Get overall score
            score_response = await self._async_request('GET', f'/api/vendors/{vendor_id}/overall-score')
            score_data = score_response.json()
            
            return {
                "vendor_id": vendor_id,
                "vendor_name": vendor_data.get("name"),
                "overall_risk_score": score_data.get("overall_score", 0),
                "last_scan_date": datetime.now()  # Backend doesn't track this granularly yet
            }
            
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                return None
            raise
        except Exception as e:
            logger.error(f"Error fetching vendor score for ID {vendor_id}: {e}")
            raise
    
    async def get_category_scores(self, domain: str) -> Dict[str, Any]:
        """Get category-wise vulnerabilities and scores for a domain"""
        try:
            logger.info(f"[DEBUG] get_category_scores called for domain: {domain}")
            # Fetch all vulnerabilities in one call
            response = await self._async_request('GET', f'/api/vulnerabilities-db/{domain}')
            
            if not response or response.status_code != 200:
                logger.warning(f"Failed to fetch vulnerabilities for {domain}")
                return {}
            
            data = response.json()
            all_vulnerabilities = data.get('vulnerabilities', [])
            logger.info(f"[DEBUG] Fetched {len(all_vulnerabilities)} vulnerabilities for {domain}")
            
            # Group vulnerabilities by category with severity breakdown
            # Database uses title case with spaces: Website, Domain Reputation, etc.
            categories = ['Website', 'Domain Reputation', 'Encryption', 'Network', 'Email', 'DNS']
            category_scores = {}
            
            for cat in categories:
                category_scores[cat] = {
                    'count': 0,
                    'severity_breakdown': {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}, # Severity breakdown
                    'scores': []  # Will be populated from /api/scores endpoint
                }
            
            # Process all vulnerabilities
            for vuln in all_vulnerabilities:
                if isinstance(vuln, dict) and 'category' in vuln:
                    category = vuln['category']
                    if category in category_scores:
                        category_scores[category]['count'] += 1
                        
                        # Track severity breakdown (database uses title case: Info, Low, Medium, High, Critical)
                        severity = vuln.get('severity', 'Info')
                        if severity in category_scores[category]['severity_breakdown']:
                            category_scores[category]['severity_breakdown'][severity] += 1
                        
            # Fetch scores for each category sequentially
            for cat in categories:
                try:
                    # URL-encode category name (e.g. "Domain Reputation" -> "Domain%20Reputation")
                    encoded_cat = quote(cat)
                    logger.info(f"Fetching scores for category: {cat} (encoded: {encoded_cat})")
                    score_response = await self._async_request('GET', f'/api/scores/{domain}/{encoded_cat}')
                    if score_response and score_response.status_code == 200:
                        score_data = score_response.json()
                        scores = score_data.get('scores', [])
                        category_scores[cat]['scores'] = scores
                        logger.info(f"[DEBUG] Category {cat}: {len(scores)} scores")
                    else:
                        logger.warning(f"Non-200 response for {cat}: {score_response.status_code if score_response else 'None'}")
                        category_scores[cat]['scores'] = []
                except Exception as e:
                    logger.error(f"Could not fetch scores for {cat}: {e}", exc_info=True)
                    category_scores[cat]['scores'] = []
            
            logger.info(f"[DEBUG] Returning category_scores with {len(category_scores)} categories")
            return category_scores
        except Exception as e:
            logger.error(f"Error fetching category scores for {domain}: {e}")
            logger.exception(e)  # Full traceback
            return {}
    
    async def get_vendor_report(self, vendor_id: int) -> Optional[Dict[str, Any]]:
        """Get comprehensive security report for a specific vendor"""
        try:
            # Get vendor info
            response = await self._async_request('GET', f'/api/vendors/{vendor_id}')
            response_data = response.json()
            
            if not response_data:
                return None
            
            # Backend returns data nested under "vendor" key
            vendor_data = response_data.get("vendor", response_data)
            
            domain = vendor_data.get("domain")
            if not domain:
                return {
                    "vendor_id": vendor_id,
                    "vendor_name": vendor_data.get("name"),
                    "domain": None,
                    "overall_risk_score": 0,
                    "category_scores": {},
                    "scan_summary": {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0},
                    "last_scan_date": datetime.now()
                }
            
            # Get overall score and breakdown (this includes scan_results for all categories).
            # GET, not POST: this is a report read. The POST variant persists a
            # `scores` row and stamps vendors.last_scanned, so polling this
            # endpoint used to forge scan history for the vendor being viewed.
            score_response = await self._async_request('GET', f'/api/vendors/{vendor_id}/overall-score')
            score_data = score_response.json()
            
            # Get category-wise detailed scores (WEBSITE, DOMAIN_REPUTATION, ENCRYPTION, NETWORK, EMAIL, DNS)
            category_scores = await self.get_category_scores(domain)
            
            # Calculate scan summary from category scores (using title case to match database)
            scan_summary = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
            for category, category_data in category_scores.items():
                if isinstance(category_data, dict) and 'severity_breakdown' in category_data:
                    severity_breakdown = category_data.get('severity_breakdown', {})
                    for severity, count in severity_breakdown.items():
                        if severity in scan_summary:
                            scan_summary[severity] += count
            
            # Get subdomain count
            subdomain_count = 0
            try:
                subdomain_response = await self._async_request('GET', f'/api/subdomains/{domain}')
                logger.info(f"Subdomain API response status: {subdomain_response.status_code if subdomain_response else 'None'}")
                if subdomain_response and subdomain_response.status_code == 200:
                    subdomain_data = subdomain_response.json()
                    logger.info(f"Subdomain data structure: {list(subdomain_data.keys()) if isinstance(subdomain_data, dict) else type(subdomain_data)}")
                    
                    # Backend returns: {"subdomains": {"all": [...], "alive": [...], ...}, "count": {...}}
                    if 'count' in subdomain_data and isinstance(subdomain_data['count'], dict):
                        subdomain_count = subdomain_data['count'].get('total', 0)
                        logger.info(f"Got subdomain count from 'count.total': {subdomain_count}")
                    elif 'subdomains' in subdomain_data and isinstance(subdomain_data['subdomains'], dict):
                        all_subdomains = subdomain_data['subdomains'].get('all', [])
                        subdomain_count = len(all_subdomains) if isinstance(all_subdomains, list) else 0
                        logger.info(f"Got subdomain count from 'subdomains.all': {subdomain_count}")
                    else:
                        logger.warning(f"Unexpected subdomain data format: {subdomain_data}")
                else:
                    logger.warning(f"Failed to fetch subdomains: status={subdomain_response.status_code if subdomain_response else 'No response'}")
            except Exception as e:
                logger.error(f"Could not fetch subdomain count for {domain}: {e}", exc_info=True)
            
            # Get scan format and timestamp - check active scan first, then database
            scan_format = None
            scan_timestamp = None
            
            # First check if there's an active scan for this domain
            try:
                jobs_response = await self._async_request('GET', '/api/background-scan/list')
                if jobs_response and jobs_response.status_code == 200:
                    jobs_data = jobs_response.json()
                    active_jobs = jobs_data.get('jobs', [])
                    
                    # Check if there's an active job for this domain
                    for job in active_jobs:
                        if job.get('status') in ['running', 'starting']:
                            job_domains = job.get('domains', [])
                            current_domain = job.get('current_domain')
                            
                            # Check if this job is scanning our domain
                            if (current_domain and current_domain.lower() == domain.lower()) or \
                               (domain.lower() in [d.lower() for d in job_domains if isinstance(d, str)]):
                                # Determine scan format from job_id pattern and include_subdomains flag
                                job_id = job.get('job_id', '')
                                include_subdomains = job.get('include_subdomains', True)
                                is_auto_scan = job.get('auto_scan', False)
                                
                                if 'single_scan' in job_id:
                                    # Single domain scan - check if it includes subdomains
                                    if include_subdomains:
                                        scan_format = 'full_scan_single'  # Full scan with subdomains
                                    else:
                                        scan_format = 'individual_scan'  # Main domain only
                                elif 'auto_scan' in job_id or is_auto_scan:
                                    scan_format = 'new_vendor'  # New vendor scan (automatic)
                                elif 'full_scan' in job_id:
                                    scan_format = 'full_scan_all'  # Full scan of all vendors
                                else:
                                    scan_format = 'individual_scan'  # Individual category scan
                                
                                scan_timestamp = datetime.now().isoformat()
                                logger.info(f"Active scan detected for {domain}: format={scan_format} (job_id: {job_id}, include_subdomains: {include_subdomains})")
                                break
            except Exception as e:
                logger.warning(f"Could not check active scans for {domain}: {e}")
            
            # If no active scan, get latest completed scan from database
            if not scan_format:
                try:
                    import psycopg2
                    import os
                    
                    # Get database connection details from environment (configured in docker-compose)
                    db_config = {
                        'host': os.getenv('DB_HOST'),
                        'port': int(os.getenv('DB_PORT')),
                        'database': os.getenv('DB_NAME'),
                        'user': os.getenv('DB_USER'),
                        'password': os.getenv('DB_PASSWORD')
                    }
                    
                    conn = psycopg2.connect(**db_config)
                    cursor = conn.cursor()
                    
                    # Query to get the most recent score entry with scan_format
                    query = """
                        SELECT scan_format, updated_at
                        FROM scores
                        WHERE domain = %s AND scan_format IS NOT NULL
                        ORDER BY updated_at DESC
                        LIMIT 1
                    """
                    cursor.execute(query, (domain,))
                    result = cursor.fetchone()
                    
                    if result:
                        scan_format = result[0]
                        scan_timestamp = result[1].isoformat() if result[1] else None
                        logger.info(f"Latest completed scan info for {domain}: format={scan_format}, timestamp={scan_timestamp}")
                    
                    cursor.close()
                    conn.close()
                    
                except Exception as e:
                    logger.warning(f"Could not fetch scan format info for {domain}: {e}")
            
            return {
                "vendor_id": vendor_id,
                "vendor_name": vendor_data.get("name"),
                "domain": domain,
                "overall_risk_score": score_data.get("overall_score", 0),
                "max_score": score_data.get("max_score", 950),
                "percentage": score_data.get("percentage", 0),
                "risk_level": score_data.get("risk_level", "Unknown"),
                "category_scores": category_scores,  # Detailed category-wise scores (WEBSITE, DOMAIN_REPUTATION, ENCRYPTION, NETWORK, EMAIL, DNS)
                "category_contributions": score_data.get("category_contributions", {}),
                "dynamic_weights": score_data.get("dynamic_weights", {}),
                "scan_summary": scan_summary,
                "subdomain_count": subdomain_count,
                "scan_format": scan_format,
                "scan_timestamp": scan_timestamp,
                "total_vulnerabilities": score_data.get("total_vulnerabilities", 0),
                "last_scan_date": datetime.now()
            }
            
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                return None
            raise
        except Exception as e:
            logger.error(f"Error fetching vendor report for ID {vendor_id}: {e}")
            raise
    
    async def create_vendor(self, vendor_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new vendor"""
        try:
            # Transform API format to backend format
            backend_data = {
                "vendor_name": vendor_data["name"],
                "domain": vendor_data.get("domain", ""),
                "tier": vendor_data.get("tier",''),
                "portfolio": vendor_data.get("portfolio",''),
                "industry": vendor_data.get("industry",''),
                "auto_scan": False  # Disable backend auto-scan since API layer handles scanning
            }
            
            response = await self._async_request('POST', '/api/vendors/add', 
                                               headers={'Content-Type': 'application/json'},
                                               json=backend_data)
            
            response_data = response.json()
            
            # The backend returns: {"success": True, "message": "...", "vendor": {...}}
            if response_data.get("success") and "vendor" in response_data:
                vendor_info = response_data["vendor"]
                return {
                    "id": vendor_info.get("id"),
                    "name": vendor_info.get("name"),
                    "domain": vendor_info.get("domain"),
                    "tier": vendor_info.get("tier", ""),
                    "portfolio": vendor_info.get("portfolio", ""),
                    "created_at": datetime.now(),
                    "updated_at": datetime.now()
                }
            else:
                raise Exception(f"Backend error: {response_data.get('error', 'Unknown error')}")
            
        except requests.exceptions.HTTPError as e:
            detail = _extract_backend_detail(e.response)
            logger.warning(f"Backend rejected vendor creation ({e.response.status_code}): {detail}")
            raise BackendAPIError(status_code=e.response.status_code, detail=detail)
        except BackendAPIError:
            raise
        except Exception as e:
            logger.error(f"Error creating vendor: {e}")
            raise
    
    async def delete_vendor(self, vendor_id: int) -> bool:
        """Delete a vendor"""
        try:
            await self._async_request('DELETE', f'/api/vendors/{vendor_id}')
            return True
            
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                return False
            raise
        except Exception as e:
            logger.error(f"Error deleting vendor ID {vendor_id}: {e}")
            raise
    
    def close(self):
        """Close the client session"""
        self.session.close()
        self.executor.shutdown(wait=True)


# Global backend client instance
_backend_client = None

def get_backend_client() -> BackendClient:
    """Get or create the global backend client instance"""
    global _backend_client
    if _backend_client is None:
        _backend_client = BackendClient()
    return _backend_client

def make_backend_request(method: str, endpoint: str, **kwargs) -> Optional[requests.Response]:
    """
    Make a synchronous request to the backend service
    This function is used by the FastAPI endpoints for compatibility
    """
    try:
        client = get_backend_client()
        return client._make_request(method, endpoint, **kwargs)
    except Exception as e:
        logger.error(f"Backend request failed: {method} {endpoint} - {e}")
        return None

def get_all_vendors() -> List[Dict[str, Any]]:
    """
    Get all vendors from the backend service (synchronous)
    This function is used by the FastAPI endpoints for compatibility
    """
    try:
        # First refresh cache
        make_backend_request('POST', '/api/vendors/reload', 
                           headers={'Content-Type': 'application/json'}, 
                           json={})
        
        # Get vendors
        response = make_backend_request('GET', '/api/vendors')
        if response and response.status_code == 200:
            data = response.json()
            
            # Handle different response formats
            if isinstance(data, list):
                # Direct list of vendors
                return data
            elif isinstance(data, dict):
                # Check for common wrapper formats
                if 'vendors' in data:
                    vendors = data['vendors']
                    if isinstance(vendors, list):
                        return vendors
                elif 'data' in data:
                    vendors = data['data']
                    if isinstance(vendors, list):
                        return vendors
                else:
                    # If it's a dict but not a wrapper, log the keys for debugging
                    logger.warning(f"Backend returned dict with keys: {list(data.keys())}")
                    return []
            else:
                logger.warning(f"Backend returned unexpected data type: {type(data)}")
                return []
        else:
            logger.warning("Failed to fetch vendors from backend")
            return []
    except Exception as e:
        logger.error(f"Error fetching all vendors: {e}")
        return [] 

def trigger_background_scan_for_domain(
    domain: str,
    include_subdomains: bool = False,
    *,
    slack_notify_on_complete: bool = False,
) -> Optional[str]:
    """Trigger a background scan for a newly added domain"""
    try:
        # Prepare the scan request data
        scan_data = {
            "domain": domain,
            "include_subdomains": include_subdomains,
            "slack_notify_on_complete": slack_notify_on_complete,
        }
        
        # Make request to backend to start background scan
        scan_response = make_backend_request(
            'POST', 
            '/api/background-scan/start', 
            headers={'Content-Type': 'application/json'}, 
            json=scan_data
        )
        
        if scan_response and scan_response.status_code == 200:
            response_data = scan_response.json()
            job_id = response_data.get('job_id')
            scan_type = "main domain only" if not include_subdomains else "full (with subdomains)"
            logger.info(f"Successfully triggered {scan_type} background scan for {domain}, job_id: {job_id}")
            return job_id
        else:
            logger.warning(f"Failed to trigger background scan for {domain}: {scan_response.status_code if scan_response else 'No response'}")
            return None
            
    except Exception as e:
        logger.error(f"Error triggering background scan for {domain}: {str(e)}")
        return None



def _create_scan_status_response(scan_active: bool, scan_stage_message: str, 
                                job_id: Optional[str] = None,  
                                last_scan_completed: Optional[str] = None) -> Dict[str, Any]:
    """Helper function to create consistent scan status response"""
    return {
        "scan_active": scan_active,
        "scan_stage_message": scan_stage_message,
        "job_id": job_id,
        "last_scan_completed": last_scan_completed
    }
            
def get_scan_status_for_domain(domain: str) -> Dict[str, Any]:
    """Get the current scan status for a domain by checking active background jobs"""
    try:
        # First, check if there's an active background scan job for this domain
        jobs_response = make_backend_request('GET', '/api/background-scan/list')
        if jobs_response and jobs_response.status_code == 200:
            jobs_data = jobs_response.json()
            active_jobs = jobs_data.get('jobs', [])
            
            # Check if there's an active job for this domain
            for job in active_jobs:
                if job.get('status') in ['running', 'starting']:
                    job_domains = job.get('domains', [])
                    current_domain = job.get('current_domain')
                    
                    # Check if this job is scanning our domain
                    if (current_domain and current_domain.lower() == domain.lower()) or \
                       (domain.lower() in [d.lower() for d in job_domains if isinstance(d, str)]):
                        return _create_scan_status_response(
                            scan_active=True,
                            scan_stage_message=job.get('stage', 'Scan in progress'),
                            job_id=job.get('job_id'),
                            last_scan_completed=None
                        )
        
        # No active scan found, check vendor data for last completed scan
        vendors_response = make_backend_request('GET', '/api/vendors')
        if vendors_response and vendors_response.status_code == 200:
            response_data = vendors_response.json()
            
            # Handle wrapped response format
            if isinstance(response_data, dict) and 'vendors' in response_data:
                vendors_data = response_data['vendors']
            elif isinstance(response_data, list):
                vendors_data = response_data
            else:
                vendors_data = []
            
            for vendor in vendors_data:
                if isinstance(vendor, dict) and vendor.get('domain', '').lower() == domain.lower():
                    last_scan = vendor.get('lastScan')
                    
                    # No active scan, return completed status
                    return _create_scan_status_response(
                        scan_active=False,
                        scan_stage_message="Scan completed",
                        job_id=None,
                        last_scan_completed=last_scan if last_scan != 'Never' else None
                    )
        
        # Default: vendor not found
        return _create_scan_status_response(
            scan_active=False,
            scan_stage_message="Vendor not found",
            job_id=None,
            last_scan_completed=None
        )
            
    except Exception as e:
        logger.warning(f"Error getting scan status for {domain}: {e}")
        return _create_scan_status_response(
            scan_active=False,
            scan_stage_message="Error retrieving scan status",
            job_id=None,
            last_scan_completed=None
        )