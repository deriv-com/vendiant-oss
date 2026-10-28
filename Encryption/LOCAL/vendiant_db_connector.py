#!/usr/bin/env python3
"""
Vendiant Database Connector for Vendor Risk Scanner LOCAL
Connects to the existing Vendiant PostgreSQL database and stores scanning results.
"""

import psycopg2
import psycopg2.extras
import json
import os
import logging
from datetime import datetime
from typing import List, Dict, Optional, Any
from contextlib import contextmanager

from database_config import get_database_config, VENDOR_RISK_MAPPING

logger = logging.getLogger(__name__)

class VendiantDBConnector:
    """Database connector for Vendor Risk Scanner integration with Vendiant platform"""
    
    def __init__(self, connection_string: str = None):
        """
        Initialize database connection
        
        Args:
            connection_string: PostgreSQL connection string. 
                             If None, will use config from database_config
        """
        if connection_string:
            self.connection_string = connection_string
        else:
            config = get_database_config()
            self.connection_string = config.get_connection_string()
        
        self.enabled = get_database_config().is_enabled()
        logger.info(f"Database integration {'enabled' if self.enabled else 'disabled'}")
    
    @contextmanager
    def get_connection(self):
        """Context manager for database connections"""
        if not self.enabled:
            logger.warning("Database is disabled, skipping connection")
            yield None
            return
            
        conn = None
        try:
            conn = psycopg2.connect(self.connection_string)
            yield conn
        except Exception as e:
            logger.error(f"Database connection error: {e}")
            if conn:
                conn.rollback()
            raise e
        finally:
            if conn:
                conn.close()
    
    def get_or_create_vendor(self, domain: str, vendor_name: str = None) -> Optional[int]:
        """
        Get existing vendor or create a new one
        
        Args:
            domain: Primary domain
            vendor_name: Vendor name (optional, defaults to domain)
            
        Returns:
            Vendor ID or None if database disabled
        """
        if not self.enabled:
            return None
            
        if not vendor_name:
            vendor_name = domain.replace('.', ' ').title()
            
        try:
            with self.get_connection() as conn:
                if not conn:
                    return None
                    
                with conn.cursor() as cur:
                    # Check if vendor exists
                    cur.execute("""
                        SELECT id FROM vendors WHERE domain = %s
                    """, (domain,))
                    result = cur.fetchone()
                    
                    if result:
                        return result[0]
                    
                    # Create new vendor
                    cur.execute("""
                        INSERT INTO vendors (vendor_name, domain, added_at)
                        VALUES (%s, %s, CURRENT_TIMESTAMP)
                        RETURNING id
                    """, (vendor_name, domain))
                    vendor_id = cur.fetchone()[0]
                    conn.commit()
                    logger.info(f"Created new vendor: {vendor_name} ({domain}) with ID {vendor_id}")
                    return vendor_id
                    
        except Exception as e:
            logger.error(f"Error getting/creating vendor for {domain}: {e}")
            return None
    
    def save_scan_scores(self, vendor_id: int, domain: str, risk_score: int, 
                        enhanced_checks: Dict[str, Any], testssl_results: Dict[str, Any]):
        """
        Save scan scores to the scores table
        
        Args:
            vendor_id: Vendor ID
            domain: Domain name
            risk_score: Overall risk score
            enhanced_checks: Enhanced security check results
            testssl_results: testssl.sh results
        """
        if not self.enabled or not vendor_id:
            return
            
        try:
            with self.get_connection() as conn:
                if not conn:
                    return
                    
                with conn.cursor() as cur:
                    # Calculate category scores
                    encryption_score = self._calculate_encryption_score(testssl_results, enhanced_checks)
                    website_score = self._calculate_website_score(enhanced_checks)
                    dns_score = self._calculate_dns_score(enhanced_checks)
                    
                    # Insert/update scores for each category
                    scores = [
                        ('Encryption', encryption_score),
                        ('Website', website_score), 
                        ('DNS', dns_score)
                    ]
                    
                    for category, score in scores:
                        cur.execute("""
                            INSERT INTO scores (vendor_id, domain, score_category, time_period, score)
                            VALUES (%s, %s, %s, 'current', %s)
                            ON CONFLICT (vendor_id, domain, score_category, time_period)
                            DO UPDATE SET 
                                score = EXCLUDED.score,
                                updated_at = CURRENT_TIMESTAMP
                        """, (vendor_id, domain, category, score))
                    
                    # Update vendor overall score
                    cur.execute("""
                        UPDATE vendors 
                        SET overall_score_current = %s,
                            last_scanned = CURRENT_TIMESTAMP
                        WHERE id = %s
                    """, (risk_score, vendor_id))
                    
                    conn.commit()
                    logger.info(f"Saved scores for vendor {vendor_id}: Encryption={encryption_score}, Website={website_score}, DNS={dns_score}")
                    
        except Exception as e:
            logger.error(f"Error saving scores for vendor {vendor_id}: {e}")
    
    def save_vulnerabilities(self, vendor_id: int, domain: str, subdomain: str,
                           vulnerabilities: List[Dict[str, Any]]):
        """
        Save vulnerabilities to the vulnerabilities table
        
        Args:
            vendor_id: Vendor ID
            domain: Main domain
            subdomain: Subdomain where vulnerability was found
            vulnerabilities: List of vulnerabilities
        """
        if not self.enabled or not vendor_id or not vulnerabilities:
            return
            
        try:
            with self.get_connection() as conn:
                if not conn:
                    return
                    
                with conn.cursor() as cur:
                    for vuln in vulnerabilities:
                        # Map vulnerability data to database format
                        title = vuln.get('title', 'Unknown Vulnerability')
                        description = vuln.get('description', vuln.get('issue', ''))
                        severity = self._map_severity(vuln.get('severity', vuln.get('risk', 'Medium')))
                        score_category = self._determine_score_category(vuln, subdomain)
                        
                        cur.execute("""
                            INSERT INTO vulnerabilities 
                            (vendor_id, domain, subdomain, score_category, title, description, severity)
                            VALUES (%s, %s, %s, %s, %s, %s, %s)
                        """, (vendor_id, domain, subdomain, score_category, title, description, severity))
                    
                    conn.commit()
                    logger.info(f"Saved {len(vulnerabilities)} vulnerabilities for {subdomain}")
                    
        except Exception as e:
            logger.error(f"Error saving vulnerabilities for {subdomain}: {e}")
    
    def save_subdomains(self, vendor_id: int, domain: str, subdomains: List[str]):
        """
        Save subdomains to the subdomains table
        
        Args:
            vendor_id: Vendor ID
            domain: Main domain
            subdomains: List of subdomain names
        """
        if not self.enabled or not vendor_id or not subdomains:
            return
            
        try:
            with self.get_connection() as conn:
                if not conn:
                    return
                    
                with conn.cursor() as cur:
                    for subdomain in subdomains:
                        cur.execute("""
                            INSERT INTO subdomains (domain, vendor_id, subdomain)
                            VALUES (%s, %s, %s)
                            ON CONFLICT (vendor_id, subdomain) DO NOTHING
                        """, (domain, vendor_id, subdomain))
                    
                    # Update subdomain count
                    cur.execute("""
                        UPDATE vendors 
                        SET subdomain_count = (
                            SELECT COUNT(*) FROM subdomains WHERE vendor_id = %s
                        )
                        WHERE id = %s
                    """, (vendor_id, vendor_id))
                    
                    conn.commit()
                    logger.info(f"Saved {len(subdomains)} subdomains for vendor {vendor_id}")
                    
        except Exception as e:
            logger.error(f"Error saving subdomains for vendor {vendor_id}: {e}")
    
    def _calculate_encryption_score(self, testssl_results: Dict[str, Any], 
                                  enhanced_checks: Dict[str, Any]) -> int:
        """Calculate encryption category score based on testssl and enhanced checks"""
        base_score = 950
        
        # Deduct points for testssl vulnerabilities
        if testssl_results and 'vulnerabilities' in testssl_results:
            vuln_count = len(testssl_results['vulnerabilities'])
            base_score -= min(vuln_count * 50, 400)  # Max 400 points deduction
        
        # Deduct points for certificate issues
        if enhanced_checks:
            cert_issues = [
                'hostname_certificate_match',
                'ssl_certificate_chain',
                'certificate_transparency'
            ]
            for check in cert_issues:
                if enhanced_checks.get(check, {}).get('issue'):
                    base_score -= 50
        
        return max(base_score, 0)
    
    def _calculate_website_score(self, enhanced_checks: Dict[str, Any]) -> int:
        """Calculate website category score based on enhanced checks"""
        base_score = 950
        
        if not enhanced_checks:
            return base_score
        
        # Website security checks
        website_checks = [
            'security_headers',
            'hsts_preload',
            'mixed_content',
            'redirect_security'
        ]
        
        for check in website_checks:
            if enhanced_checks.get(check, {}).get('issue'):
                base_score -= 25
        
        return max(base_score, 0)
    
    def _calculate_dns_score(self, enhanced_checks: Dict[str, Any]) -> int:
        """Calculate DNS category score based on enhanced checks"""
        base_score = 950
        
        if not enhanced_checks:
            return base_score
        
        # DNS security checks
        dns_checks = [
            'dns_security',
            'subdomain_security',
            'domain_reputation'
        ]
        
        for check in dns_checks:
            if enhanced_checks.get(check, {}).get('issue'):
                base_score -= 50
        
        return max(base_score, 0)
    
    def _map_severity(self, severity: str) -> str:
        """Map severity levels to database format"""
        severity_map = {
            'info': 'Low',
            'low': 'Low',
            'medium': 'Medium',
            'high': 'High',
            'critical': 'Critical'
        }
        return severity_map.get(severity.lower(), 'Medium')
    
    def _determine_score_category(self, vulnerability: Dict[str, Any], subdomain: str) -> str:
        """Determine which score category this vulnerability belongs to"""
        vuln_type = vulnerability.get('type', '').lower()
        title = vulnerability.get('title', '').lower()
        
        if any(keyword in vuln_type or keyword in title for keyword in ['ssl', 'tls', 'cert', 'crypto', 'cipher']):
            return 'Encryption'
        elif any(keyword in vuln_type or keyword in title for keyword in ['dns', 'domain']):
            return 'DNS'
        else:
            return 'Website'
    
    def health_check(self) -> bool:
        """
        Check if database connection is healthy
        
        Returns:
            True if connection is working
        """
        if not self.enabled:
            logger.info("Database health check skipped (disabled)")
            return True
            
        try:
            with self.get_connection() as conn:
                if not conn:
                    return False
                with conn.cursor() as cur:
                    cur.execute("SELECT 1")
                    return True
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return False


# Example usage and test
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Test database connection
    db = VendiantDBConnector()
    
    if db.health_check():
        print(" Database connection successful")
        
        # Test vendor creation
        vendor_id = db.get_or_create_vendor("example.com", "Example Corp")
        if vendor_id:
            print(f" Vendor created/found with ID: {vendor_id}")
        else:
            print("ℹ  Database operations skipped (disabled)")
    else:
        print(" Database connection failed") 