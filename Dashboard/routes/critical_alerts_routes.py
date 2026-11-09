from fastapi import APIRouter, HTTPException, Request, Query, Depends
from typing import Optional
import logging
from datetime import datetime

# Import required functions from db_service
from db_service import (
    get_vendor_by_domain,
    get_vulnerabilities_for_domain,
    get_vendor_by_id,
    VendorService,
    SubdomainService
)

# Initialize services to avoid circular imports
vendor_service = VendorService()
subdomain_service = SubdomainService()

# Helper functions to avoid circular imports
def get_vendors_cached():
    """Get vendors from database service"""
    return vendor_service.get_all_vendors()

def get_subdomains_cached(domain):
    """Get subdomains for a domain from database service"""
    return subdomain_service.get_subdomains_by_domain(domain)

router = APIRouter()

try:
    from Dashboard.effective_permissions import require_permission
except ImportError:
    from effective_permissions import require_permission

require_view_vendors = require_permission("view_vendors")

@router.get('/api/critical-alerts')
async def get_critical_alerts(_: None = Depends(require_view_vendors)):
    """Get all critical vulnerabilities, low-scoring domains, and critical news/incidents across all scan types"""
    try:
        critical_alerts = []
        
        # Get all vendors to iterate through their domains
        vendors = get_vendors_cached()
        logging.info(f"Found {len(vendors)} vendors to check for critical alerts")
        
        # Log all domains being processed for debugging
        all_domains = [v.get('domain', '') for v in vendors if v.get('domain')]
        logging.info(f"Processing domains: {all_domains}")
        
        if not vendors:
            logging.warning("No vendors found in cache, this might indicate a database connection issue")
            return {
                'success': True,
                'critical_alerts': [],
                'total_count': 0,
                'message': 'No vendors found in database'
            }
        
        for vendor in vendors:
            domain = vendor.get('domain', '')
            vendor_name = vendor.get('name', 'Unknown Vendor')
            vendor_id = vendor.get('id')
            
            if not domain:
                continue
            
            # Check overall domain score from database using get_vendor_by_domain
            vendor_data = get_vendor_by_domain(domain)
            overall_score = None
            if vendor_data:
                overall_score = vendor_data.get('securityScore') or vendor_data.get('scores', {}).get('current')
                logging.info(f"Domain {domain} - Vendor data found: securityScore={vendor_data.get('securityScore')}, scores.current={vendor_data.get('scores', {}).get('current')}")
            else:
                logging.warning(f"Domain {domain} - No vendor data found using get_vendor_by_domain")
            logging.info(f"Domain {domain} has overall score from database: {overall_score}")
            
            # Add low-scoring domains as critical alerts (only if score exists and is below 600)
            if overall_score is not None and overall_score < 600:
                # Get last scan date in the same format as vulnerabilities
                last_scan = vendor.get('lastScan', '')
                if last_scan:
                    # Convert to ISO format like vulnerabilities
                    from datetime import datetime
                    try:
                        # Parse the lastScan format and convert to ISO
                        scan_dt = datetime.strptime(last_scan, '%Y-%m-%d %H:%M:%S')
                        detected_at = scan_dt.isoformat()
                    except:
                        detected_at = last_scan  # Fallback to original format
                else:
                    detected_at = ''
                
                alert = {
                    'id': f"{vendor_id}_low_score_{domain}",
                    'vendor_name': vendor_name,
                    'vendor_id': vendor_id,
                    'domain': domain,
                    'subdomain': domain,
                    'severity': 'CRITICAL',
                    'vulnerability': f'Low Security Score ({overall_score}/950)',
                    'description': f'Domain has an overall security score of {overall_score}/950, which is below the critical threshold of 600. This indicates significant security risks that require immediate attention.',
                    'scan_type': 'Overall Security Score',
                    'detected_at': '',
                    'category': 'Security Score'
                }
                critical_alerts.append(alert)
                logging.info(f"Added low-score alert for {domain} (score: {overall_score})")
            
            # Get vulnerabilities from database for this domain
            vulnerabilities = get_vulnerabilities_for_domain(domain)
            logging.info(f"Found {len(vulnerabilities)} total vulnerabilities for {domain}")
            
            # Filter only CRITICAL vulnerabilities
            critical_vulns = [v for v in vulnerabilities if v.get('severity', '').upper() == 'CRITICAL']
            logging.info(f"Found {len(critical_vulns)} critical vulnerabilities for {domain}")
            
            for vuln in critical_vulns:
                alert = {
                    'id': f"{vendor_id}_{vuln.get('title', 'unknown')}_{vuln.get('subdomain', domain)}",
                    'vendor_name': vendor_name,
                    'vendor_id': vendor_id,
                    'domain': domain,
                    'subdomain': vuln.get('subdomain', domain),
                    'severity': 'CRITICAL',
                    'vulnerability': vuln.get('title', vuln.get('description', 'Unknown Vulnerability')),
                    'description': vuln.get('description', ''),
                    'scan_type': vuln.get('category', 'Unknown'),
                    'detected_at': vuln.get('detected_at', ''),
                    'category': vuln.get('category', 'Unknown')
                }
                critical_alerts.append(alert)
        
        # Get critical news and incidents from all domains
        try:
            from db_service import NewsService
            news_service = NewsService()
            
            # Get all news items from the last 6 months
            all_news_data = news_service.get_all_news(months=6)
            all_news_items = all_news_data.get('items', [])
            
            # Filter only CRITICAL severity incidents (not general news)
            critical_news = [
                item for item in all_news_items 
                if item.get('severity', '').upper() == 'CRITICAL' 
                and item.get('type', '').lower() == 'incident'
            ]
            logging.info(f"Found {len(critical_news)} critical incidents from {len(all_news_items)} total items")
            
            # Convert critical news to alert format
            for news_item in critical_news:
                # Find the vendor for this domain
                vendor_for_news = next((v for v in vendors if v.get('domain') == news_item.get('domain')), None)
                vendor_name_for_news = vendor_for_news.get('name', 'Unknown Vendor') if vendor_for_news else 'Unknown Vendor'
                vendor_id_for_news = vendor_for_news.get('id', 0) if vendor_for_news else 0
                
                alert = {
                    'id': f"incident_{news_item.get('id', 'unknown')}_{news_item.get('domain', 'unknown')}",
                    'vendor_name': vendor_name_for_news,
                    'vendor_id': vendor_id_for_news,
                    'domain': news_item.get('domain', 'Unknown'),
                    'subdomain': news_item.get('domain', 'Unknown'),
                    'severity': 'CRITICAL',
                    'vulnerability': news_item.get('title', 'Critical Security Incident'),
                    'description': news_item.get('description', 'No description available'),
                    'scan_type': 'Security Incident',
                    'detected_at': news_item.get('date', news_item.get('created_at', '')),
                    'category': 'Security Incident',
                    'source_url': news_item.get('source', ''),
                    'event_type': news_item.get('type', 'incident')
                }
                critical_alerts.append(alert)
                
        except Exception as news_error:
            logging.error(f"Error fetching critical news/incidents: {news_error}")
            # Continue without news data if there's an error
        
        # Sort by detection time (most recent first)
        critical_alerts.sort(key=lambda x: x.get('detected_at', ''), reverse=True)
        
        # Count different types of alerts
        vuln_alerts = len([a for a in critical_alerts if a.get('scan_type') not in ['Overall Security Score', 'Security Incident']])
        score_alerts = len([a for a in critical_alerts if a.get('scan_type') == 'Overall Security Score'])
        incident_alerts = len([a for a in critical_alerts if a.get('scan_type') == 'Security Incident'])
        
        logging.info(f"Critical alerts summary: {len(critical_alerts)} total ({vuln_alerts} vulnerability alerts, {score_alerts} low-score alerts, {incident_alerts} critical incident alerts)")
        
        return {
            'success': True,
            'critical_alerts': critical_alerts,
            'total_count': len(critical_alerts),
            'breakdown': {
                'vulnerabilities': vuln_alerts,
                'low_scores': score_alerts,
                'critical_incidents': incident_alerts
            }
        }
        
    except Exception as e:
        logging.error(f"Error fetching critical alerts: {str(e)}")
        raise HTTPException(status_code=500, detail='Failed to fetch critical alerts')

@router.get('/api/critical-alerts/subdomain-details/{vendor_id}')
async def get_subdomain_critical_details(vendor_id: int, _: None = Depends(require_view_vendors)):
    """Get detailed critical vulnerability breakdown by subdomain for a vendor"""
    try:
        logging.info(f"Fetching subdomain details for vendor_id: {vendor_id}")
        
        # Get vendor information
        vendor = get_vendor_by_id(vendor_id)
        if not vendor:
            logging.error(f"Vendor not found for ID: {vendor_id}")
            raise HTTPException(status_code=404, detail='Vendor not found')
        
        domain = vendor.get('domain', '')
        vendor_name = vendor.get('name', 'Unknown Vendor')
        logging.info(f"Found vendor: {vendor_name} with domain: {domain}")
        
        # Get all subdomains for this vendor
        subdomains = get_subdomains_cached(domain)
        subdomain_list = [domain]  # Include main domain
        if subdomains:
            subdomain_list.extend([sub.get('subdomain', '') for sub in subdomains if sub.get('subdomain')])
        
        logging.info(f"Processing {len(subdomain_list)} subdomains for {domain}: {subdomain_list}")
        subdomain_details = []
        
        for subdomain in subdomain_list:
            # Get vulnerabilities for this specific subdomain
            vulnerabilities = get_vulnerabilities_for_domain(domain)
            subdomain_vulns = [v for v in vulnerabilities if v.get('subdomain', domain) == subdomain]
            
            logging.info(f"Subdomain {subdomain}: found {len(subdomain_vulns)} vulnerabilities out of {len(vulnerabilities)} total")
            
            # Count by severity
            severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
            critical_vulns = []
            
            for vuln in subdomain_vulns:
                severity = vuln.get('severity', 'INFO').upper()
                if severity in severity_counts:
                    severity_counts[severity] += 1
                
                if severity == 'CRITICAL':
                    critical_vulns.append({
                        'title': vuln.get('title', vuln.get('description', 'Unknown Vulnerability')),
                        'description': vuln.get('description', ''),
                        'category': vuln.get('category', 'Unknown'),
                        'detected_at': vuln.get('detected_at', '')
                    })
            
            if severity_counts['CRITICAL'] > 0:  # Only include subdomains with CRITICAL issues
                subdomain_details.append({
                    'subdomain': subdomain,
                    'is_main_domain': subdomain == domain,
                    'severity_counts': severity_counts,
                    'critical_vulnerabilities': critical_vulns,
                    'total_vulnerabilities': sum(severity_counts.values())
                })
        
        # Sort by critical count (highest first)
        subdomain_details.sort(key=lambda x: x['severity_counts']['CRITICAL'], reverse=True)
        
        logging.info(f"Returning {len(subdomain_details)} subdomains with CRITICAL vulnerabilities for {vendor_name}")
        
        return {
            'success': True,
            'vendor_name': vendor_name,
            'domain': domain,
            'subdomain_details': subdomain_details,
            'total_subdomains': len(subdomain_details)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error fetching subdomain critical details: {str(e)}")
        raise HTTPException(status_code=500, detail='Failed to fetch subdomain details')
