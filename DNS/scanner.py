#!/usr/bin/env python3
"""
DNS Security Scanner - Integrated with Vendiant Dashboard
"""

import os
import sys
import time
import threading
import concurrent.futures
from typing import List
import logging

_APP_ROOT = os.environ.get("VENDIANT_APP_ROOT", "/app")
_DASHBOARD_DIR = os.path.join(_APP_ROOT, "Dashboard")
_CUSTOM_INTEGRATIONS_DIR = os.path.join(_APP_ROOT, "custom_integrations")

# Add Dashboard path for unified scoring
if _DASHBOARD_DIR not in sys.path:
    sys.path.append(_DASHBOARD_DIR)
from unified_scoring_config import get_severity_weights, calculate_scan_score

# Configure logging
# Add custom integrations path for logger
if _CUSTOM_INTEGRATIONS_DIR not in sys.path:
    sys.path.append(_CUSTOM_INTEGRATIONS_DIR)
from logger_config import setup_logger

# Configure logging using custom logger
logger = setup_logger()

# Import our DNS scanner components
from .dns_scanner import DNSSecurityScanner
from . import config

# Threading lock for safe printing
print_lock = threading.Lock()

def safe_print(*args, **kwargs):
    """Thread-safe printing function."""
    with print_lock:
        print(*args, **kwargs)

# File operations removed - using database integration

def process_single_subdomain(subdomain, initial_score, severity_weights):
    """
    Process a single subdomain for DNS security issues.
    Returns a tuple of (subdomain, dns_issues, severity_counts, subdomain_score)
    """
    try:
        logger.info(f"Processing DNS security for: {subdomain}")
        
        # Create scanner instance
        scanner = DNSSecurityScanner()
        
        # Perform the scan
        results = scanner.scan_domain(subdomain)
        
        # Extract severity counts
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        
        # Analyze findings and categorize by severity
        dns_issues = []
        
        # Domain expiry issues
        expiry = results.get('domain_expiry', {})
        if expiry.get('is_expired'):
            dns_issues.append({'finding': 'Domain expired', 'severity': 'HIGH', 'description': 'The domain has expired, meaning anyone can purchase this domain'})
        elif expiry.get('expires_soon'):
            dns_issues.append({'finding': 'Domain expires soon', 'severity': 'MEDIUM', 'description': f"Domain expires in {expiry.get('days_until_expiry', 'unknown')} days"})
        
        # Subdomain takeover issues
        takeover = results.get('subdomain_takeover', {})
        if takeover.get('total_vulnerabilities', 0) > 0:
            dns_issues.append({'finding': 'Subdomain takeover vulnerability detected', 'severity': 'HIGH', 'description': f"{takeover.get('total_vulnerabilities')} subdomain takeover vulnerabilities detected"})
        
        # DNSSEC issues
        dnssec = results.get('dnssec_status', {})
        if not dnssec.get('enabled', False):
            dns_issues.append({'finding': 'DNSSEC not enabled', 'severity': 'LOW', 'description': 'DNSSEC is not enabled, making the domain vulnerable to DNS spoofing'})
        
        # Registrar protection issues
        protection = results.get('registrar_protection', {})
        if not protection.get('deletion_protection', False):
            dns_issues.append({'finding': 'Domain registrar or registry deletion protection not enabled', 'severity': 'LOW', 'description': 'Domain registrar deletion protection is not enabled'})
        if not protection.get('transfer_protection', False):
            dns_issues.append({'finding': 'Domain registrar or registry transfer protection not enabled', 'severity': 'LOW', 'description': 'Domain registrar transfer protection is not enabled'})
        if not protection.get('update_protection', False):
            dns_issues.append({'finding': 'Domain registrar or registry update protection not enabled', 'severity': 'LOW', 'description': 'Domain registrar update protection is not enabled'})
        
        # Count severities
        for issue in dns_issues:
            severity = issue['severity']
            severity_counts[severity] += 1
        
        # Calculate score for this subdomain
        subdomain_score = initial_score
        for severity, count in severity_counts.items():
            subdomain_score -= count * severity_weights.get(severity, 0)
        
        # Ensure score doesn't go below 0
        subdomain_score = max(0, subdomain_score)
        
        logger.info(f"Subdomain {subdomain} DNS score: {subdomain_score}/{initial_score}")
        
        return subdomain, dns_issues, severity_counts, subdomain_score
        
    except Exception as e:
        logger.error(f"Error processing DNS security for {subdomain}: {e}")
        return subdomain, [], {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}, initial_score

def scan_domain_dns_security(domain, output_file_path=None, subdomains_list=None):
    """
    Scan DNS security for a domain and its subdomains using parallel processing.
    
    Args:
        domain: Main domain name
        output_file_path: Optional custom output path (deprecated - database integration)
        subdomains_list: List of subdomains to scan (required - no file fallback)
    
    Returns:
        Dict with scan results and statistics
    """
    logger.info(f"Starting DNS security scan for {domain}")
    
    # Use provided subdomains list (database integration)
    if subdomains_list is not None:
        subdomains = subdomains_list
        logger.info(f"Using provided subdomains list: {len(subdomains)} subdomains")
    else:
        logger.error("No subdomains provided for DNS scan. Database integration required.")
        return None
    
    # Initialize scoring and results
    initial_score = 950
    
    # Use unified scoring system
    severity_weights = get_severity_weights('DNS')
    
    total_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    issues_found = []
    all_subdomain_results = []
    all_vulnerabilities = []  # Store all vulnerabilities for unified scoring
    
    logger.info(f"Processing {len(subdomains)} subdomains in parallel...")
    
    # Initialize results collection
    all_subdomain_results = []
    
    # Use ThreadPoolExecutor for concurrent processing
    max_workers = min(10, max(1, len(subdomains)))  # Ensure at least 1 worker, limit to 10
    
    # Skip parallel processing if no subdomains to process
    if len(subdomains) == 0:
        logger.warning(f"No subdomains found for {domain}, skipping parallel processing")
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all subdomain processing tasks
            future_to_subdomain = {
                executor.submit(process_single_subdomain, subdomain, initial_score, severity_weights): subdomain 
                for subdomain in subdomains
            }
            
            # Collect results as they complete
            for future in concurrent.futures.as_completed(future_to_subdomain):
                subdomain = future_to_subdomain[future]
                try:
                    subdomain_name, dns_issues, severity_counts, subdomain_score = future.result()
                    all_subdomain_results.append((subdomain_name, dns_issues, severity_counts, subdomain_score))
                    
                    # Add to global counts
                    for severity, count in severity_counts.items():
                        if severity in total_counts:
                            total_counts[severity] += count
                    
                    # Add issues to global list
                    for issue in dns_issues:
                        issues_found.append({
                            'domain': subdomain_name,
                            'finding': issue['finding'],
                            'severity': issue['severity'],
                            'description': issue['description']
                        })
                        
                        # Add to vulnerabilities list for unified scoring
                        all_vulnerabilities.append({
                            'subdomain': subdomain_name,
                            'severity': issue['severity'],
                            'category': 'DNS',
                            'description': f"{issue['finding']}: {issue['description']}",
                            'finding': issue['finding']
                        })
                        
                except Exception as e:
                    logger.error(f"Failed to process {subdomain}: {e}")
    
    # Sort results by subdomain name to maintain consistent output
    all_subdomain_results.sort(key=lambda x: x[0])
    
    # Process results for scoring
    processed_subdomains = len(all_subdomain_results)
    
    # Calculate average score across subdomains instead of accumulating all vulnerabilities
    subdomain_scores = []  # Initialize for return statement
    if all_subdomain_results:
        # Calculate individual scores for each subdomain
        total_issues = 0
        
        for subdomain_name, dns_issues, severity_counts, subdomain_score in all_subdomain_results:
            subdomain_scores.append(subdomain_score)
            total_issues += len(dns_issues)
            
            logger.debug(f"Subdomain {subdomain_name}: {subdomain_score}/950 ({len(dns_issues)} issues)")
        
        # Calculate average score across all subdomains
        final_score = int(sum(subdomain_scores) / len(subdomain_scores))
        
        logger.info(f"DNS AVERAGE SCORING:")
        logger.info(f"   Subdomains processed: {len(subdomain_scores)}")
        logger.info(f"   Individual scores: {subdomain_scores}")
        logger.info(f"   Average score: {final_score}/950")
        logger.info(f"   Total issues across all subdomains: {total_issues}")
        logger.info(f"   Score range: {min(subdomain_scores)} - {max(subdomain_scores)}")
    else:
        final_score = initial_score
        logger.info(f"No subdomains processed - using base score: {final_score}")

    logger.info(f"DNS security scan completed for {domain}")
    logger.info(f"Processed {processed_subdomains} subdomains")
    logger.info(f"Final DNS security score: {final_score}/{initial_score}")
    logger.info(f"Results stored in database - no files generated")
    
    # Return results for API consumption (no file operations)
    return {
        'domain': domain,
        'final_score': final_score,
        'max_score': initial_score,
        'processed_subdomains': processed_subdomains,
        'issues_found': issues_found,
        'statistics': total_counts,
        'subdomain_scores': subdomain_scores,
        'report_file': None  # No file generated
    }

# Summary report functions removed - using database integration

def main():
    """Main function for command line usage."""
    if len(sys.argv) < 2:
        print("Usage: python scanner.py <domain>")
        print("Example: python scanner.py example.com")
        return
    
    domain = sys.argv[1]
    print("Note: This scanner now requires database integration.")
    print("Please use the dashboard API for DNS security scanning.")
    print(f"Domain: {domain} - use /api/dns/scan endpoint")

if __name__ == "__main__":
    main()
