#!/usr/bin/env python3
"""
Encryption Scanner Integration for Vendiant Dashboard
Connects the LOCAL vendor risk scanner to the dashboard API
"""

import os
import sys
import json
import logging
import time
from typing import Dict, Any, Optional

# Add the LOCAL encryption scanner to the path
encryption_scanner_path = os.path.join(os.path.dirname(__file__), '..', 'Encryption', 'LOCAL')
sys.path.append(encryption_scanner_path)

try:
    from vendor_risk_scanner_local import VendorRiskScanner
    SCANNER_AVAILABLE = True
except (ImportError, OSError, Exception) as e:
    logging.warning(f"Vendor risk scanner not available: {e}")
    SCANNER_AVAILABLE = False

# Import database services from dashboard
from db_service import (
    save_encryption_score, 
    save_encryption_vulnerabilities,
    get_vendor_by_domain
)

logger = logging.getLogger(__name__)

class EncryptionScannerIntegration:
    """Integration layer between LOCAL vendor risk scanner and dashboard"""
    
    def __init__(self):
        """Initialize the encryption scanner integration"""
        self.scanner = None
        if SCANNER_AVAILABLE:
            try:
                self.scanner = VendorRiskScanner()
                logger.info("Vendor risk scanner initialized successfully")
            except Exception as e:
                logger.error(f"Failed to initialize vendor risk scanner: {e}")
                self.scanner = None
        else:
            logger.warning("Vendor risk scanner not available")
    
    def is_available(self) -> bool:
        """Check if the scanner is available"""
        return self.scanner is not None
    
    def scan_domain(self, domain: str, full_scan: bool = True) -> Dict[str, Any]:
        """
        Scan a domain using the LOCAL vendor risk scanner
        
        Args:
            domain: Domain to scan
            full_scan: Whether to perform full scan including testssl.sh
            
        Returns:
            Dictionary with scan results and status
        """
        if not self.scanner:
            return {
                'status': 'error',
                'message': 'Encryption scanner not available',
                'score': None
            }
        
        try:
            logger.info(f"Starting encryption scan for {domain}")
            start_time = time.time()
            
            # Run the scan
            results = self.scanner.scan_domain(domain, full_scan=full_scan)
            
            scan_duration = time.time() - start_time
            logger.info(f"Encryption scan completed for {domain} in {scan_duration:.1f}s")
            
            # Extract key information
            risk_score = results.get('risk_score', 0)
            risk_level = results.get('risk_level', 'Unknown')
            
            # Get vulnerability counts
            testssl_vulns = 0
            if 'testssl' in results and 'vulnerabilities' in results['testssl']:
                testssl_vulns = len(results['testssl']['vulnerabilities'])
            
            enhanced_issues = 0
            if 'enhanced_security_checks' in results:
                enhanced_checks = results['enhanced_security_checks']
                if isinstance(enhanced_checks, dict) and 'summary' in enhanced_checks:
                    enhanced_issues = enhanced_checks['summary'].get('issues_found', 0)
            
            return {
                'status': 'success',
                'domain': domain,
                'risk_score': risk_score,
                'risk_level': risk_level,
                'testssl_vulnerabilities': testssl_vulns,
                'enhanced_security_issues': enhanced_issues,
                'scan_duration': scan_duration,
                'full_results': results
            }
            
        except Exception as e:
            logger.error(f"Encryption scan failed for {domain}: {e}")
            return {
                'status': 'error',
                'message': f'Scan failed: {str(e)}',
                'domain': domain,
                'score': None
            }
    
    def save_results_to_database(self, domain: str, scan_results: Dict[str, Any]) -> bool:
        """
        Save scan results to the database
        
        Args:
            domain: Domain that was scanned
            scan_results: Results from scan_domain method
            
        Returns:
            True if saved successfully, False otherwise
        """
        if scan_results.get('status') != 'success':
            logger.warning(f"Not saving failed scan results for {domain}")
            return False
        
        try:
            # Get vendor information
            vendor = get_vendor_by_domain(domain)
            if not vendor:
                logger.warning(f"No vendor found for domain {domain} in database")
                return False
            
            vendor_id = vendor['id']
            risk_score = scan_results.get('risk_score', 0)
            
            # Save encryption score
            save_encryption_score(vendor_id, domain, risk_score)
            logger.info(f"Saved encryption score {risk_score} for {domain}")
            
            # Prepare vulnerabilities for database
            vulnerabilities = []
            
            # Add testssl.sh vulnerabilities
            full_results = scan_results.get('full_results', {})
            if 'testssl' in full_results and 'vulnerabilities' in full_results['testssl']:
                for vuln_id, vuln_data in full_results['testssl']['vulnerabilities'].items():
                    vulnerabilities.append({
                        'title': f"SSL/TLS: {vuln_id}",
                        'description': vuln_data.get('finding', vuln_data.get('description', '')),
                        'severity': vuln_data.get('severity', 'Medium'),
                        'subdomain': domain
                    })
            
            # Add enhanced security check issues
            if 'enhanced_security_checks' in full_results:
                for check_name, check_data in full_results['enhanced_security_checks'].items():
                    if isinstance(check_data, dict) and check_data.get('issue'):
                        vulnerabilities.append({
                            'title': check_name.replace('_', ' ').title(),
                            'description': check_data.get('issue', ''),
                            'severity': self._map_severity(check_data.get('severity', 'Medium')),
                            'subdomain': domain
                        })
            
            # Save vulnerabilities if any
            if vulnerabilities:
                save_encryption_vulnerabilities(vendor_id, domain, vulnerabilities)
                logger.info(f"Saved {len(vulnerabilities)} encryption vulnerabilities for {domain}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error saving encryption scan results to database for {domain}: {e}")
            return False
    
    def _map_severity(self, severity: str) -> str:
        """Map severity levels to standard format"""
        severity_map = {
            'info': 'Info',
            'low': 'Low',
            'medium': 'Medium',
            'high': 'High',
            'critical': 'Critical'
        }
        return severity_map.get(severity.lower(), 'Medium')
    
    def get_scan_results_path(self, domain: str) -> Optional[str]:
        """
        Get the path to the text report for a domain
        
        Args:
            domain: Domain to get report for
            
        Returns:
            Path to report file or None if not found
        """
        try:
            results_dir = os.path.join(encryption_scanner_path, 'results')
            
            # Look for domain group report (most common)
            domain_clean = domain.replace('.', '_')
            group_report = os.path.join(results_dir, f"{domain_clean}_domain_group_report.txt")
            
            if os.path.exists(group_report):
                return group_report
            
            # Look for individual report
            individual_report = os.path.join(results_dir, f"{domain_clean}_assessment_report.txt")
            if os.path.exists(individual_report):
                return individual_report
            
            return None
            
        except Exception as e:
            logger.error(f"Error finding scan results for {domain}: {e}")
            return None

# Global instance
encryption_integration = EncryptionScannerIntegration()

def scan_domain_encryption(domain: str, full_scan: bool = True, save_to_db: bool = True) -> Dict[str, Any]:
    """
    Main function to scan a domain for encryption vulnerabilities
    
    Args:
        domain: Domain to scan
        full_scan: Whether to perform full scan including testssl.sh
        save_to_db: Whether to save results to database
        
    Returns:
        Dictionary with scan results
    """
    # Perform the scan
    results = encryption_integration.scan_domain(domain, full_scan=full_scan)
    
    # Save to database if requested and scan was successful
    if save_to_db and results.get('status') == 'success':
        encryption_integration.save_results_to_database(domain, results)
    
    return results

def is_encryption_scanner_available() -> bool:
    """Check if the encryption scanner is available"""
    return encryption_integration.is_available()

def get_encryption_report_path(domain: str) -> Optional[str]:
    """Get path to encryption scan report for domain"""
    return encryption_integration.get_scan_results_path(domain) 