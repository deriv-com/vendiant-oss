# Handle imports for different execution contexts
try:
    from Dashboard.db_config import DatabaseConnection, BreachMonitorDatabaseConnection
except ImportError:
    from db_config import DatabaseConnection, BreachMonitorDatabaseConnection
import logging
from datetime import date, datetime, timezone
import sys
import os
import threading
import json
import uuid
from typing import Optional, Dict, Any, List, Set, Tuple


# Add custom integrations path for logger
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'custom_integrations'))
from logger_config import setup_logger

# Configure logging using custom logger
logger = setup_logger()


class VendorService:
    """Service class for vendor-related database operations"""
    
    def __init__(self):
        self.db = DatabaseConnection()
    
    def get_all_vendors(self):
        """Retrieve all vendors from the database"""
        query = """
        SELECT 
            id,
            vendor_name,
            domain,
            grade,
            overall_score_current,
            overall_score_1month,
            overall_score_3months,
            overall_score_12months,
            added_at,
            last_scanned,
            subdomain_count,
            trend,
            certifications,
            tier,
            portfolio,
            industry
        FROM vendors 
        ORDER BY vendor_name ASC
        """
        
        try:
            with DatabaseConnection() as db:
                results = db.execute_query(query)
                if results:
                    vendors = []
                    for row in results:
                        vendor_data = self._format_vendor_data(row)
                        vendors.append(vendor_data)
                    
                    logger.info(f"Retrieved {len(vendors)} vendors from database")
                    return vendors
                else:
                    logger.warning("No vendors found in database")
                    return []
        except Exception as e:
            logger.error(f"Error retrieving vendors: {e}")
            return []
    
    def get_vendor_by_domain(self, domain):
        """Retrieve a specific vendor by domain"""
        query = """
        SELECT 
            id,
            vendor_name,
            domain,
            grade,
            overall_score_current,
            overall_score_1month,
            overall_score_3months,
            overall_score_12months,
            added_at,
            last_scanned,
            subdomain_count,
            trend,
            certifications,
            tier,
            portfolio,
            industry
        FROM vendors 
        WHERE domain = %s
        """
        
        try:
            with DatabaseConnection() as db:
                result = db.execute_single_query(query, (domain,))
                if result:
                    return self._format_vendor_data(result)
                else:
                    logger.warning(f"No vendor found with domain: {domain}")
                    return None
        except Exception as e:
            logger.error(f"Error retrieving vendor by domain {domain}: {e}")
            return None
    
    def get_vendor_by_id(self, vendor_id):
        """Retrieve a specific vendor by ID"""
        query = """
        SELECT 
            id,
            vendor_name,
            domain,
            grade,
            overall_score_current,
            overall_score_1month,
            overall_score_3months,
            overall_score_12months,
            added_at,
            last_scanned,
            subdomain_count,
            trend,
            certifications,
            tier,
            portfolio,
            industry
        FROM vendors 
        WHERE id = %s
        """
        
        try:
            with DatabaseConnection() as db:
                result = db.execute_single_query(query, (vendor_id,))
                if result:
                    return self._format_vendor_data(result)
                else:
                    logger.warning(f"No vendor found with ID: {vendor_id}")
                    return None
        except Exception as e:
            logger.error(f"Error retrieving vendor by ID {vendor_id}: {e}")
            return None
    
    def get_vendors_by_grade(self, grade):
        """Retrieve vendors filtered by grade"""
        query = """
        SELECT 
            id,
            vendor_name,
            domain,
            grade,
            overall_score_current,
            overall_score_1month,
            overall_score_3months,
            overall_score_12months,
            added_at,
            last_scanned,
            subdomain_count,
            trend,
            certifications,
            NULL as tier,
            NULL as portfolio,
            NULL as industry
        FROM vendors 
        WHERE grade = %s
        ORDER BY overall_score_current DESC NULLS LAST
        """
        
        try:
            with DatabaseConnection() as db:
                results = db.execute_query(query, (grade,))
                if results:
                    vendors = []
                    for row in results:
                        vendor_data = self._format_vendor_data(row)
                        vendors.append(vendor_data)
                    
                    logger.info(f"Retrieved {len(vendors)} vendors with grade {grade}")
                    return vendors
                else:
                    logger.warning(f"No vendors found with grade: {grade}")
                    return []
        except Exception as e:
            logger.error(f"Error retrieving vendors by grade {grade}: {e}")
            return []
    
    def get_vendor_statistics(self):
        """Get summary statistics about vendors"""
        query = """
        SELECT 
            COUNT(*) as total_vendors,
            COUNT(CASE WHEN grade = 'A' THEN 1 END) as grade_a,
            COUNT(CASE WHEN grade = 'B' THEN 1 END) as grade_b,
            COUNT(CASE WHEN grade = 'C' THEN 1 END) as grade_c,
            COUNT(CASE WHEN grade = 'D' THEN 1 END) as grade_d,
            COUNT(CASE WHEN grade = 'F' THEN 1 END) as grade_f,
            AVG(overall_score_current) as avg_score,
            MAX(overall_score_current) as max_score,
            MIN(overall_score_current) as min_score
        FROM vendors
        WHERE overall_score_current IS NOT NULL
        """
        
        try:
            with DatabaseConnection() as db:
                result = db.execute_single_query(query)
                if result:
                    return dict(result)
                else:
                    return {}
        except Exception as e:
            logger.error(f"Error retrieving vendor statistics: {e}")
            return {}
    
    def _format_vendor_data(self, row):
        """Format database row into vendor data structure for frontend"""
        # Handle None values and convert to appropriate types
        score = row.get('overall_score_current')
        if score is None:
            score = 0
        
        # Determine risk level based on score
        risk_level = self._determine_risk_level(score)
        
        # Parse certifications from database
        certifications = self._parse_certifications(row.get('certifications', 'None'))
        
        # Format the vendor data to match the existing frontend structure
        vendor_data = {
            'id': row.get('id', 0),
            'name': row.get('vendor_name', ''),
            'domain': row.get('domain', ''),
            'category': 'General',  # Default category - can be extended later
            'riskLevel': risk_level,
            'securityScore': score,
            'grade': row.get('grade', 'N/A'),
            'lastScan': self._format_datetime(row.get('last_scanned')),
            'addedAt': self._format_datetime(row.get('added_at')),
            'subdomainCount': row.get('subdomain_count', 0),
            'trend': row.get('trend', 0),
            'certifications': certifications,
            'scores': {
                'current': row.get('overall_score_current'),
                'oneMonth': row.get('overall_score_1month'),
                'threeMonths': row.get('overall_score_3months'),
                'twelveMonths': row.get('overall_score_12months')
            },
            'logo': self._get_vendor_logo_url(row.get('vendor_name', ''), row.get('domain', '')),
            'tier': row.get('tier', 'Unknown'),
            'portfolio': row.get('portfolio', 'Unknown'),
            'industry': row.get('industry', 'Unknown')
        }
        
        return vendor_data
    
    def _determine_risk_level(self, score):
        """Determine risk level based on security score"""
        if score is None or score == 0:
            return 'unknown'
        elif score >= 800:
            return 'low'
        elif score >= 600:
            return 'medium'
        elif score >= 400:
            return 'high'
        else:
            return 'critical'
    
    def _format_datetime(self, dt):
        """Format datetime for frontend display"""
        if dt is None:
            return 'Never'
        
        if isinstance(dt, datetime):
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        
        return str(dt)
    
    def _get_vendor_logo_url(self, vendor_name, domain):
        """Generate logo URL for vendor using multiple fallback services"""
        # Use Google Favicons as primary (most reliable free service, Clearbit is blocked)
        return f"https://www.google.com/s2/favicons?domain={domain}&sz=128"
    
    def _parse_certifications(self, cert_string):
        """Parse certifications string from database into structured format"""
        if not cert_string or cert_string.lower() in ['none', 'null', '']:
            return {
                'iso_27001': False,
                'soc2': False,
                'has_certifications': False,
                'certifications': []
            }
        
        # Handle JSON format certification data (legacy support)
        try:
            import json
            if cert_string.startswith('{'):
                cert_data = json.loads(cert_string)
                # Ensure it has the required structure
                if 'iso_27001' in cert_data or 'soc2' in cert_data:
                    return cert_data
        except:
            pass
        
        # Handle simple string format (current format)
        cert_string_lower = cert_string.lower()
        iso_27001 = 'iso 27001' in cert_string_lower or 'iso27001' in cert_string_lower
        soc2 = 'soc2' in cert_string_lower or 'soc 2' in cert_string_lower
        
        certifications = []
        if iso_27001:
            certifications.append('ISO 27001')
        if soc2:
            certifications.append('SOC 2')
        
        return {
            'iso_27001': iso_27001,
            'soc2': soc2,
            'has_certifications': iso_27001 or soc2,
            'certifications': certifications,
            'raw_string': cert_string  # Keep original string for reference
        }
    
    def update_vendor_certifications(self, domain, certification_data, manually_added=False):
        """Update vendor certifications in database
        
        Args:
            domain: Vendor domain
            certification_data: Dict with certification information or simple string
            manually_added: Boolean indicating if certifications were added manually (via button).
                          If True, sets certifications_added = True. If False (automated scan),
                          only updates certifications column without changing certifications_added.
                          For automated scans, will not overwrite manually added certifications
                          if scan doesn't find certifications.
            
        Returns:
            bool: Success status
        """
        try:
            # Handle both dict and string input
            if isinstance(certification_data, dict):
                # Extract only the essential certification status
                cert_string = self._format_certifications_for_storage(certification_data)
            else:
                # Assume it's already a simple string
                cert_string = str(certification_data)
            
            # Determine if certifications were added (not "None")
            has_certifications = cert_string != 'None' and cert_string.strip() != ''
            
            # Only update certifications_added if manually added via button
            # For automated scans, only update the certifications column
            if manually_added:
                update_query = """
                UPDATE vendors 
                SET certifications = %s,
                    certifications_added = %s
                WHERE domain = %s
                """
                with DatabaseConnection() as db:
                    success = db.execute_insert(update_query, (cert_string, has_certifications, domain))
            else:
                # Automated scan - check if certifications were manually added first
                # If manually added and scan didn't find certifications, don't overwrite
                check_query = """
                SELECT certifications_added 
                FROM vendors 
                WHERE domain = %s
                """
                with DatabaseConnection() as db:
                    result = db.execute_single_query(check_query, (domain,))
                    
                    if result and result.get('certifications_added', False):
                        # Certifications were manually added
                        if not has_certifications:
                            # Scan didn't find certifications, don't overwrite manual entry
                            logger.info(f"Skipping update for {domain}: manually added certifications preserved (scan found none)")
                            return True  # Return success but didn't update
                        else:
                            # Scan found certifications, update them
                            logger.info(f"Updating manually added certifications for {domain} with scan results: {cert_string}")
                    
                    # Update certifications (either no manual entry, or scan found certifications)
                    update_query = """
                    UPDATE vendors 
                    SET certifications = %s
                    WHERE domain = %s
                    """
                    success = db.execute_insert(update_query, (cert_string, domain))
            
            if success:
                if manually_added:
                    logger.info(f"Updated certifications for {domain}: {cert_string}, certifications_added={has_certifications} (manually added)")
                else:
                    logger.info(f"Updated certifications for {domain}: {cert_string} (automated scan)")
                return True
            else:
                logger.error(f"Failed to update certifications for {domain}")
                return False
                    
        except Exception as e:
            logger.error(f"Error updating certifications for {domain}: {e}")
            return False
    
    def _format_certifications_for_storage(self, certification_data):
        """Format certification data into a simple string for database storage
        
        Args:
            certification_data: Dict with certification information
            
        Returns:
            str: Simple certification string (e.g., "ISO 27001, SOC 2" or "None")
        """
        try:
            certifications = []
            
            # Check for ISO 27001
            if certification_data.get('iso_27001', False):
                certifications.append('ISO 27001')
            
            # Check for SOC 2
            if certification_data.get('soc2', False):
                certifications.append('SOC 2')
            
            # Return simple string format
            if certifications:
                return ', '.join(certifications)
            else:
                return 'None'
                
        except Exception as e:
            logger.error(f"Error formatting certifications: {e}")
            return 'None'
    
    def delete_vendor(self, vendor_id):
        """Delete a vendor from the database
        
        Args:
            vendor_id: ID of the vendor to delete
            
        Returns:
            bool: Success status
        """
        try:
            # First, get vendor info for logger
            vendor = self.get_vendor_by_id(vendor_id)
            if not vendor:
                logger.warning(f"Vendor with ID {vendor_id} not found")
                return False
            
            vendor_name = vendor.get('name', 'Unknown')
            vendor_domain = vendor.get('domain', 'Unknown')
            
            with DatabaseConnection() as db:
                # Delete related data first (foreign key constraints)
                # Delete subdomains
                delete_subdomains_query = "DELETE FROM subdomains WHERE vendor_id = %s"
                db.execute_insert(delete_subdomains_query, (vendor_id,))
                
                # Delete vulnerability rows (table name is `vulnerabilities`, not vulnerability_scans)
                delete_vulns_query = "DELETE FROM vulnerabilities WHERE vendor_id = %s"
                if not db.execute_insert(delete_vulns_query, (vendor_id,)):
                    logger.warning(
                        "Delete vulnerabilities for vendor %s had no effect or failed (continuing)",
                        vendor_id,
                    )
                
                # Delete scores
                delete_scores_query = "DELETE FROM scores WHERE vendor_id = %s"
                db.execute_insert(delete_scores_query, (vendor_id,))
                
                # encryption_scores was legacy; schema uses vulnerabilities with score_category
                # including 'Encryption' — no separate table in current init-scripts.
                
                # Finally, delete the vendor
                delete_vendor_query = "DELETE FROM vendors WHERE id = %s"
                success = db.execute_insert(delete_vendor_query, (vendor_id,))
                
                if success:
                    logger.info(f"Successfully deleted vendor: {vendor_name} ({vendor_domain}) with ID {vendor_id}")
                    return True
                else:
                    logger.error(f"Failed to delete vendor with ID {vendor_id}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error deleting vendor with ID {vendor_id}: {e}")
            return False

# Convenience functions for backward compatibility
def get_vendors_from_database():
    """Get all vendors - main function to replace Excel loading"""
    service = VendorService()
    return service.get_all_vendors()

def get_vendor_by_domain(domain):
    """Get vendor by domain"""
    service = VendorService()
    return service.get_vendor_by_domain(domain)

def get_vendor_by_id(vendor_id):
    """Get vendor by ID"""
    service = VendorService()
    return service.get_vendor_by_id(vendor_id)

def get_vendor_statistics():
    """Get vendor statistics"""
    service = VendorService()
    return service.get_vendor_statistics()

def delete_vendor_by_id(vendor_id):
    """Delete vendor by ID"""
    service = VendorService()
    return service.delete_vendor(vendor_id)

def get_vendors_by_certifications(iso_27001=None, soc2=None, both_certifications=None):
    """Get vendors filtered by certification status
    
    Args:
        iso_27001: True/False to filter by ISO 27001, None for all
        soc2: True/False to filter by SOC 2, None for all
        both_certifications: True/False to filter by vendors with both certifications, None for all
        
    Returns:
        list: Filtered vendor list
    """
    try:
        vendors = get_vendors_from_database()
        filtered_vendors = []
        
        for vendor in vendors:
            cert_data = vendor.get('certifications', {})
            has_iso = cert_data.get('iso_27001', False)
            has_soc2 = cert_data.get('soc2', False)
            has_both = has_iso and has_soc2
            
            # Apply both certifications filter first (most specific)
            if both_certifications is not None:
                if both_certifications and not has_both:
                    continue
                elif not both_certifications and has_both:
                    continue
            
            # Apply ISO 27001 filter
            if iso_27001 is not None:
                if cert_data.get('iso_27001', False) != iso_27001:
                    continue
            
            # Apply SOC 2 filter
            if soc2 is not None:
                if cert_data.get('soc2', False) != soc2:
                    continue
            
            filtered_vendors.append(vendor)
        
        return filtered_vendors
        
    except Exception as e:
        logger.error(f"Error filtering vendors by certifications: {e}")
        return []

def update_vendor_certifications(domain, certification_data, manually_added=False):
    """Update vendor certifications
    
    Args:
        domain: Vendor domain
        certification_data: Dict with certification information or simple string
        manually_added: Boolean indicating if certifications were added manually (via button)
    """
    service = VendorService()
    return service.update_vendor_certifications(domain, certification_data, manually_added)

def update_vendor_certifications_simple(domain, iso_27001=False, soc2=False):
    """Update vendor certifications with simple boolean values
    
    Args:
        domain: Vendor domain
        iso_27001: Boolean indicating ISO 27001 certification status
        soc2: Boolean indicating SOC 2 certification status
    
    Returns:
        bool: Success status
    """
    cert_data = {
        'iso_27001': iso_27001,
        'soc2': soc2
    }
    return update_vendor_certifications(domain, cert_data)

def get_certification_statistics():
    """Get certification statistics across all vendors"""
    try:
        vendors = get_vendors_from_database()
        stats = {
            'total_vendors': len(vendors),
            'iso_27001_count': 0,
            'soc2_count': 0,
            'both_certifications': 0,
            'no_certifications': 0,
            'certification_rate': 0
        }
        
        for vendor in vendors:
            cert_data = vendor.get('certifications', {})
            has_iso = cert_data.get('iso_27001', False)
            has_soc2 = cert_data.get('soc2', False)
            
            if has_iso and has_soc2:
                stats['both_certifications'] += 1
            elif has_iso:
                stats['iso_27001_count'] += 1
            elif has_soc2:
                stats['soc2_count'] += 1
            else:
                stats['no_certifications'] += 1
        
        total_certified = stats['iso_27001_count'] + stats['soc2_count'] + stats['both_certifications']
        stats['certification_rate'] = round((total_certified / stats['total_vendors'] * 100), 1) if stats['total_vendors'] > 0 else 0
        
        return stats
        
    except Exception as e:
        logger.error(f"Error getting certification statistics: {e}")
        return {}

def get_dashboard_statistics():
    """Get comprehensive dashboard statistics from database"""
    try:
        with DatabaseConnection() as db:
            stats = {}
            
            # Get total active vendors
            vendor_query = "SELECT COUNT(*) as total FROM vendors"
            vendor_result = db.execute_single_query(vendor_query)
            stats['active_vendors'] = vendor_result['total'] if vendor_result else 0
            
            # Get total subdomains monitored
            subdomain_query = "SELECT COUNT(*) as total FROM subdomains"
            subdomain_result = db.execute_single_query(subdomain_query)
            stats['subdomains_monitored'] = subdomain_result['total'] if subdomain_result else 0
            
            # Get total vulnerabilities found
            vulnerabilities_query = "SELECT COUNT(*) as total FROM vulnerabilities"
            vulnerabilities_result = db.execute_single_query(vulnerabilities_query)
            stats['vulnerabilities_found'] = vulnerabilities_result['total'] if vulnerabilities_result else 0
            
            # Get high risk issues (Critical + High severity)
            high_risk_query = """
            SELECT COUNT(*) as total 
            FROM vulnerabilities 
            WHERE severity IN ('Critical', 'High')
            """
            high_risk_result = db.execute_single_query(high_risk_query)
            stats['high_risk_issues'] = high_risk_result['total'] if high_risk_result else 0
            
            # Get vulnerability breakdown by severity
            severity_query = """
            SELECT severity, COUNT(*) as count 
            FROM vulnerabilities 
            GROUP BY severity
            """
            severity_results = db.execute_query(severity_query)
            stats['severity_breakdown'] = {}
            if severity_results:
                for row in severity_results:
                    stats['severity_breakdown'][row['severity'].lower()] = row['count']
            
            # Get overall security score (average of current vendor scores)
            score_query = "SELECT AVG(overall_score_current) as avg_score FROM vendors WHERE overall_score_current IS NOT NULL"
            score_result = db.execute_single_query(score_query)
            stats['overall_score'] = round(score_result['avg_score']) if score_result and score_result['avg_score'] else 0
            
            # Get risk distribution based on vendor scores
            risk_distribution_query = """
            SELECT 
                CASE 
                    WHEN overall_score_current >= 800 THEN 'low'
                    WHEN overall_score_current >= 600 THEN 'medium'
                    WHEN overall_score_current >= 400 THEN 'high'
                    ELSE 'critical'
                END as risk_level,
                COUNT(*) as count
            FROM vendors 
            WHERE overall_score_current IS NOT NULL
            GROUP BY risk_level
            """
            risk_results = db.execute_query(risk_distribution_query)
            stats['risk_distribution'] = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
            if risk_results:
                for row in risk_results:
                    stats['risk_distribution'][row['risk_level']] = row['count']
            
            # Calculate percentage
            stats['score_percentage'] = round((stats['overall_score'] / 950) * 100, 1) if stats['overall_score'] else 0
            
            return stats
            
    except Exception as e:
        logger.error(f"Error getting dashboard statistics from database: {e}")
        return {
            'active_vendors': 0,
            'subdomains_monitored': 0,
            'vulnerabilities_found': 0,
            'high_risk_issues': 0,
            'overall_score': 0,
            'score_percentage': 0,
            'severity_breakdown': {},
            'risk_distribution': {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
        }

def get_recent_scans_from_database():
    """Get recent scans from database tables showing latest unique domain+scan_type combinations"""
    try:
        with DatabaseConnection() as db:
            # Get latest scans from scores table with unique domain+category combinations
            recent_scans_query = """
            WITH latest_scans AS (
                SELECT 
                    v.vendor_name,
                    v.domain,
                    s.score_category,
                    s.score,
                    s.updated_at,
                    ROW_NUMBER() OVER (PARTITION BY v.domain, s.score_category ORDER BY s.updated_at DESC) as rn
                FROM scores s
                JOIN vendors v ON s.vendor_id = v.id
                WHERE s.updated_at IS NOT NULL
            ),
            scan_results AS (
                SELECT 
                    ls.vendor_name,
                    ls.domain,
                    ls.score_category,
                    CASE 
                        WHEN ls.score_category = 'Website' THEN 'Vulnerability Scan'
                        WHEN ls.score_category = 'DNS' THEN 'DNS Security'
                        WHEN ls.score_category = 'Domain Reputation' THEN 'Domain Reputation'
                        ELSE ls.score_category
                    END as scan_type_display,
                    ls.score,
                    ls.updated_at,
                    CASE 
                        WHEN ls.score >= 800 THEN 'excellent'
                        WHEN ls.score >= 600 THEN 'good'
                        WHEN ls.score >= 400 THEN 'fair'
                        ELSE 'poor'
                    END as status,
                    CASE 
                        WHEN ls.score >= 800 THEN 'Excellent'
                        WHEN ls.score >= 600 THEN 'Good'
                        WHEN ls.score >= 400 THEN 'Fair'
                        ELSE 'Needs Attention'
                    END as result
                FROM latest_scans ls
                WHERE ls.rn = 1
            )
            SELECT * FROM scan_results
            ORDER BY updated_at DESC
            LIMIT 10
            """
            
            scan_results = db.execute_query(recent_scans_query)
            recent_scans = []
            
            if scan_results:
                for scan in scan_results:
                    # Calculate time ago
                    from datetime import datetime, timezone
                    import time
                    
                    if isinstance(scan['updated_at'], str):
                        # Parse ISO format timestamp
                        scan_time = datetime.fromisoformat(scan['updated_at'].replace('Z', '+00:00'))
                        timestamp = scan_time.timestamp()
                    else:
                        # Assume it's already a datetime object
                        timestamp = scan['updated_at'].timestamp()
                    
                    time_ago = get_time_ago_from_timestamp(timestamp)
                    
                    recent_scans.append({
                        'vendor_name': scan['vendor_name'],
                        'domain': scan['domain'],
                        'score_category': scan['score_category'],
                        'scan_type': scan['scan_type_display'],
                        'status': scan['status'],
                        'result': scan['result'],
                        'score': scan['score'],
                        'time_ago': time_ago,
                        'timestamp': timestamp
                    })
            
            return recent_scans
            
    except Exception as e:
        logger.error(f"Error getting recent scans from database: {e}")
        return []

def get_time_ago_from_timestamp(timestamp):
    """Convert timestamp to human readable time ago format"""
    try:
        import time
        now = time.time()
        diff = now - timestamp
        
        if diff < 60:
            return "Just now"
        elif diff < 3600:
            minutes = int(diff / 60)
            return f"{minutes} min{'s' if minutes != 1 else ''} ago"
        elif diff < 86400:
            hours = int(diff / 3600)
            return f"{hours} hour{'s' if hours != 1 else ''} ago"
        elif diff < 604800:
            days = int(diff / 86400)
            return f"{days} day{'s' if days != 1 else ''} ago"
        else:
            weeks = int(diff / 604800)
            return f"{weeks} week{'s' if weeks != 1 else ''} ago"
            
    except Exception as e:
        logger.error(f"Error calculating time ago: {e}")
        return "Unknown"

def add_manual_subdomain_to_database(vendor_id, domain, subdomain):
    """Add a manual subdomain to the database with manual tracking flags
    
    Args:
        vendor_id: The vendor ID
        domain: The main domain
        subdomain: The subdomain to add manually
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # First check if the subdomain already exists
        check_query = """
        SELECT id FROM subdomains 
        WHERE vendor_id = %s AND subdomain = %s
        """
        
        with DatabaseConnection() as db:
            existing = db.execute_single_query(check_query, (vendor_id, subdomain))
            
            if existing:
                logger.warning(f"Manual subdomain {subdomain} already exists for vendor {vendor_id}")
                return False
            
            # Insert the manual subdomain with tracking flags
            insert_query = """
            INSERT INTO subdomains (domain, vendor_id, subdomain, status, manually_added, manually_added_at)
            VALUES (%s, %s, %s, %s, %s, %s)
            """
            
            # Default status for manual subdomains is 'Active' (user is adding it intentionally)
            # We could later add a status check mechanism if needed
            from datetime import datetime
            result = db.execute_insert(insert_query, (
                domain, 
                vendor_id, 
                subdomain, 
                'Active',  # Default status for manual additions
                True,      # manually_added = True
                datetime.now()  # manually_added_at timestamp
            ))
            
            if result:
                logger.info(f"Successfully added manual subdomain {subdomain} for vendor {vendor_id}")
                return True
            else:
                logger.error(f"Failed to insert manual subdomain {subdomain} for vendor {vendor_id}")
                return False
                
    except Exception as e:
        logger.error(f"Error adding manual subdomain {subdomain} for vendor {vendor_id}: {e}")
        return False

class SubdomainService:
    """Service class for subdomain-related database operations"""
    
    def __init__(self):
        self.db = DatabaseConnection()
    
    def save_subdomains(self, domain, subdomains_list, replace_existing=False):
        """Save discovered subdomains for a domain
        
        Args:
            domain: The main domain
            subdomains_list: List of subdomains to save - can be strings or dicts with 'subdomain' and 'status'
            replace_existing: If True, clears existing subdomains first. If False, adds only new ones.
        """
        try:
            # First, get the vendor_id for this domain
            vendor_query = "SELECT id FROM vendors WHERE domain = %s"
            
            with DatabaseConnection() as db:
                vendor_result = db.execute_single_query(vendor_query, (domain,))
                
                if not vendor_result:
                    logger.error(f"No vendor found for domain: {domain}")
                    return False
                
                vendor_id = vendor_result['id']
                
                # If replace_existing is True, clear existing subdomains BUT preserve manually added ones
                if replace_existing:
                    logger.info(f"Replacing existing subdomains for {domain} (preserving manually added ones)")
                    # Only delete automatically discovered subdomains, preserve manually added ones
                    delete_query = "DELETE FROM subdomains WHERE vendor_id = %s AND (manually_added IS NULL OR manually_added = FALSE)"
                    db.execute_insert(delete_query, (vendor_id,))
                    
                    # Log how many manual subdomains are being preserved
                    manual_count_query = "SELECT COUNT(*) as count FROM subdomains WHERE vendor_id = %s AND manually_added = TRUE"
                    manual_count_result = db.execute_single_query(manual_count_query, (vendor_id,))
                    manual_count = manual_count_result['count'] if manual_count_result else 0
                    if manual_count > 0:
                        logger.info(f"Preserved {manual_count} manually added subdomains for {domain}")
                
                if not subdomains_list:
                    logger.info(f"No subdomains to save for domain: {domain}")
                    return True
                
                # Get existing subdomains to avoid duplicates when adding incrementally
                existing_subdomains = set()
                if not replace_existing:
                    existing_query = "SELECT subdomain FROM subdomains WHERE vendor_id = %s"
                    existing_results = db.execute_query(existing_query, (vendor_id,))
                    if existing_results:
                        existing_subdomains = {row['subdomain'] for row in existing_results}
                        logger.info(f"Found {len(existing_subdomains)} existing subdomains for {domain}")
                else:
                    # When replacing, we still need to avoid duplicating manually added subdomains
                    manual_query = "SELECT subdomain FROM subdomains WHERE vendor_id = %s AND manually_added = TRUE"
                    manual_results = db.execute_query(manual_query, (vendor_id,))
                    if manual_results:
                        existing_subdomains = {row['subdomain'] for row in manual_results}
                        logger.info(f"Found {len(existing_subdomains)} manually added subdomains to preserve for {domain}")
                
                # Prepare batch insert data - only new subdomains
                insert_data = []
                new_subdomains = []
                for subdomain_data in subdomains_list:
                    # Handle both string format and dict format
                    if isinstance(subdomain_data, str):
                        subdomain = subdomain_data.strip()
                        status = 'Inactive'  # Default status if not specified
                    elif isinstance(subdomain_data, dict):
                        subdomain = subdomain_data.get('subdomain', '').strip()
                        raw_status = str(subdomain_data.get('status', '')).lower().strip()
                        status = 'Active' if raw_status in ['active', 'alive', 'true', '1', 'yes'] else 'Inactive'
                    else:
                        continue
                    
                    if subdomain:
                        if replace_existing or subdomain not in existing_subdomains:
                            # For discovered subdomains, manually_added = FALSE and manually_added_at = NULL
                            insert_data.append((domain, vendor_id, status, subdomain, False, None))
                            new_subdomains.append(subdomain)
                            # Debug logger
                            logger.debug(f"Adding to insert_data: domain={domain}, vendor_id={vendor_id}, status={status}, subdomain={subdomain}")
                
                if insert_data:
                    # Batch insert subdomains with status and manual tracking
                    insert_query = """
                    INSERT INTO subdomains (domain, vendor_id, status, subdomain, manually_added, manually_added_at) 
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (vendor_id, subdomain) DO UPDATE SET
                        status = EXCLUDED.status,
                        domain = EXCLUDED.domain
                    WHERE subdomains.manually_added IS NOT TRUE
                    """
                    
                    success = db.execute_many(insert_query, insert_data)
                    
                    if success:
                        active_count = sum(1 for data in insert_data if data[2] == 'Active')
                        inactive_count = len(insert_data) - active_count
                        
                        if replace_existing:
                            logger.info(f"Successfully replaced all subdomains with {len(insert_data)} subdomains for {domain} ({active_count} active, {inactive_count} inactive)")
                        else:
                            logger.info(f"Successfully added {len(insert_data)} new subdomains for {domain} ({active_count} active, {inactive_count} inactive) (skipped {len(subdomains_list) - len(insert_data)} existing)")
                        return True
                    else:
                        logger.error(f"Failed to save subdomains for {domain}")
                        return False
                else:
                    if replace_existing:
                        logger.info(f"No valid subdomains to save for domain: {domain}")
                    else:
                        logger.info(f"No new subdomains to add for domain: {domain} (all {len(subdomains_list)} already exist)")
                    return True
                    
        except Exception as e:
            logger.error(f"Error saving subdomains for {domain}: {e}")
            return False
    
    def add_new_subdomains(self, domain, subdomains_list):
        """Add only new subdomains without affecting existing ones"""
        return self.save_subdomains(domain, subdomains_list, replace_existing=False)
    
    def replace_all_subdomains(self, domain, subdomains_list):
        """Replace all existing subdomains with new list"""
        return self.save_subdomains(domain, subdomains_list, replace_existing=True)
    
    def get_subdomains_by_domain(self, domain):
        """Retrieve all subdomains for a specific domain"""
        query = """
        SELECT s.subdomain, s.status, s.id as subdomain_id, v.vendor_name
        FROM subdomains s
        JOIN vendors v ON s.vendor_id = v.id
        WHERE s.domain = %s
        ORDER BY s.status DESC, s.subdomain ASC
        """
        
        try:
            with DatabaseConnection() as db:
                results = db.execute_query(query, (domain,))
                
                if results:
                    subdomains = []
                    for row in results:
                        subdomain_data = {
                            'id': row['subdomain_id'],
                            'subdomain': row['subdomain'],
                            'status': row['status'],
                            'vendor_name': row['vendor_name'],
                            'domain': domain
                        }
                        subdomains.append(subdomain_data)
                    
                    active_count = sum(1 for sub in subdomains if sub['status'] == 'Active')
                    inactive_count = len(subdomains) - active_count
                    logger.info(f"Retrieved {len(subdomains)} subdomains for domain: {domain} ({active_count} active, {inactive_count} inactive)")
                    return subdomains
                else:
                    logger.info(f"No subdomains found for domain: {domain}")
                    return []
                    
        except Exception as e:
            logger.error(f"Error retrieving subdomains for {domain}: {e}")
            return []
    
    def get_subdomains_by_vendor_id(self, vendor_id):
        """Retrieve all subdomains for a specific vendor ID"""
        query = """
        SELECT s.subdomain, s.status, s.domain, s.id as subdomain_id, v.vendor_name
        FROM subdomains s
        JOIN vendors v ON s.vendor_id = v.id
        WHERE s.vendor_id = %s
        ORDER BY s.status DESC, s.subdomain ASC
        """
        
        try:
            with DatabaseConnection() as db:
                results = db.execute_query(query, (vendor_id,))
                
                if results:
                    subdomains = []
                    for row in results:
                        subdomain_data = {
                            'id': row['subdomain_id'],
                            'subdomain': row['subdomain'],
                            'status': row['status'],
                            'domain': row['domain'],
                            'vendor_name': row['vendor_name']
                        }
                        subdomains.append(subdomain_data)
                    
                    return subdomains
                else:
                    return []
                    
        except Exception as e:
            logger.error(f"Error retrieving subdomains for vendor {vendor_id}: {e}")
            return []
    
    def get_subdomain_count_by_domain(self, domain):
        """Get count of subdomains for a specific domain"""
        query = """
        SELECT COUNT(*) as subdomain_count
        FROM subdomains s
        JOIN vendors v ON s.vendor_id = v.id
        WHERE s.domain = %s
        """
        
        try:
            with DatabaseConnection() as db:
                result = db.execute_single_query(query, (domain,))
                
                if result:
                    return result['subdomain_count']
                else:
                    return 0
                    
        except Exception as e:
            logger.error(f"Error getting subdomain count for {domain}: {e}")
            return 0
    
    def update_vendor_subdomain_count(self, domain):
        """Update the subdomain_count field in vendors table for a domain"""
        try:
            count = self.get_subdomain_count_by_domain(domain)
            
            update_query = """
            UPDATE vendors 
            SET subdomain_count = %s 
            WHERE domain = %s
            """
            
            with DatabaseConnection() as db:
                success = db.execute_insert(update_query, (count, domain))
                
                if success:
                    logger.info(f"Updated subdomain count for {domain}: {count}")
                    return True
                else:
                    logger.error(f"Failed to update subdomain count for {domain}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error updating subdomain count for {domain}: {e}")
            return False

# Convenience functions for subdomain operations
def save_subdomains_for_domain(domain, subdomains_list, replace_existing=False):
    """Save discovered subdomains for a domain
    
    Args:
        domain: The main domain
        subdomains_list: List of subdomains to save - can be strings or dicts with 'subdomain' and 'status'
        replace_existing: If True, replaces all existing subdomains. If False, adds only new ones.
    """
    service = SubdomainService()
    success = service.save_subdomains(domain, subdomains_list, replace_existing)
    
    # Update the subdomain count in vendors table
    if success:
        service.update_vendor_subdomain_count(domain)
    
    return success

def add_new_subdomains_for_domain(domain, subdomains_list):
    """Add only new subdomains for a domain (incremental update)"""
    service = SubdomainService()
    success = service.add_new_subdomains(domain, subdomains_list)
    
    # Update the subdomain count in vendors table
    if success:
        service.update_vendor_subdomain_count(domain)
    
    return success

def replace_all_subdomains_for_domain(domain, subdomains_list):
    """Replace all existing subdomains for a domain"""
    service = SubdomainService()
    success = service.replace_all_subdomains(domain, subdomains_list)
    
    # Update the subdomain count in vendors table
    if success:
        service.update_vendor_subdomain_count(domain)
    
    return success

def get_subdomains_for_domain(domain):
    """Get all subdomains for a domain"""
    service = SubdomainService()
    return service.get_subdomains_by_domain(domain)

def get_subdomains_for_vendor(vendor_id):
    """Get all subdomains for a vendor"""
    service = SubdomainService()
    return service.get_subdomains_by_vendor_id(vendor_id)

def update_vendor_overall_score(domain, overall_score, scan_format=None):
    """Update vendors.overall_score_current and append an 'Overall' row to scores.

    Args:
        domain: The domain being scored
        overall_score: The overall score value
        scan_format: What produced this score. Pass it explicitly. If omitted,
            it is inherited from the most recent score row for this domain --
            a fallback kept only for legacy callers, because inheritance is
            wrong: it copies a label forward from an unrelated earlier write,
            so rows end up claiming to come from a scan that never ran.
    """
    try:
        with DatabaseConnection() as db:
            # First, get vendor_id for this domain
            vendor_query = "SELECT id FROM vendors WHERE domain = %s"
            vendor_result = db.execute_single_query(vendor_query, (domain,))
            
            if not vendor_result:
                logger.error(f"No vendor found for domain: {domain}")
                return False
                
            vendor_id = vendor_result['id']
            
            if scan_format is None:
                # Legacy fallback. Inheriting a label from the last row written
                # for this domain is unreliable -- any writer can set it, and it
                # then propagates indefinitely. Callers should pass scan_format.
                scan_format_query = """
                SELECT scan_format, updated_at
                FROM scores
                WHERE domain = %s AND scan_format IS NOT NULL
                ORDER BY updated_at DESC
                LIMIT 1
                """

                scan_format_result = db.execute_single_query(scan_format_query, (domain,))

                scan_format = 'individual_scan'  # Default value
                if scan_format_result and scan_format_result.get('scan_format'):
                    scan_format = scan_format_result['scan_format']
                    logger.warning(
                        f"update_vendor_overall_score called without scan_format for {domain}; "
                        f"inheriting '{scan_format}' from the previous row (caller should pass it explicitly)"
                    )
                else:
                    logger.info(f"No previous scan_format found for domain {domain}, using default: {scan_format}")
            
            # Check current score before updating
            current_score_query = "SELECT overall_score_current FROM vendors WHERE domain = %s"
            current_result = db.execute_single_query(current_score_query, (domain,))
            current_score = current_result.get('overall_score_current') if current_result else None

            # Update vendors table (existing functionality)
            update_query = """
            UPDATE vendors
            SET overall_score_current = %s,
                last_scanned = NOW()
            WHERE domain = %s
            """
            
            vendors_success = db.execute_insert(update_query, (overall_score, domain))

            # Reset low_score_alert_sent_at if score improved above threshold
            # This allows re-alerting if the score falls below 750 again
            if current_score and current_score < 750 and overall_score >= 750:
                reset_alert_query = """
                UPDATE vendors
                SET low_score_alert_sent_at = NULL
                WHERE domain = %s
                """
                db.execute_insert(reset_alert_query, (domain,))
                logger.info(f"Reset low_score_alert_sent_at for {domain} (score improved from {current_score} to {overall_score})")

            # Send Slack notification for low scores
            if overall_score < 750:
                try:
                    # Check if low score alert has already been sent recently (within last 24 hours)
                    # We use low_score_alert_sent_at which is different from slack_alert_sent_at
                    alert_check_query = "SELECT low_score_alert_sent_at FROM vendors WHERE id = %s"
                    alert_check_result = db.execute_single_query(alert_check_query, (vendor_id,))

                    # Only send if no alert has been sent before (NULL)
                    # The reset logic above ensures we can re-alert when scores improve and then decline
                    should_send_alert = alert_check_result and alert_check_result['low_score_alert_sent_at'] is None

                    if should_send_alert:
                        # Get vendor name for Slack notification
                        vendor_name_query = "SELECT vendor_name FROM vendors WHERE id = %s"
                        vendor_name_result = db.execute_single_query(vendor_name_query, (vendor_id,))
                        vendor_name = vendor_name_result['vendor_name'] if vendor_name_result else 'Unknown Vendor'

                        # Import Slack notification function
                        from slack.slack_service import send_low_score_alert

                        score_data = {
                            'current_score': overall_score,
                            'threshold': 750,
                            'previous_score': current_score
                        }

                        slack_success = send_low_score_alert(vendor_name, domain, score_data)
                        if slack_success:
                            # Mark alert as sent
                            update_alert_query = "UPDATE vendors SET low_score_alert_sent_at = NOW() WHERE id = %s"
                            db.execute_insert(update_alert_query, (vendor_id,))
                            logger.info(f"Slack notification sent for low score alert: {vendor_name} ({overall_score}/950)")
                        else:
                            logger.warning(f"Failed to send Slack notification for low score alert: {vendor_name}")
                    else:
                        logger.debug(f"Low score alert already sent recently for vendor {domain} (ID: {vendor_id})")

                except Exception as slack_error:
                    logger.error(f"Error sending Slack notification for low score {domain}: {slack_error}")
                    # Don't fail the score update if Slack notification fails

            # Also save to scores table with 'Overall' category
            # NOTE: intentionally a plain INSERT, not an upsert. `scores` is
            # append-only history -- analytics_routes derives 30-day trend
            # baselines and overall_score_1month from older 'Overall' rows via
            # DISTINCT ON (vendor_id) ORDER BY updated_at DESC. Collapsing rows
            # would silently destroy trends and the score timeline.
            # (The ON CONFLICT clause removed here targeted a key that included
            # updated_at = NOW(), so it could never match and never fired.)
            score_query = """
            INSERT INTO scores (vendor_id, domain, score_category, time_period, score, scan_format, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, NOW())
            """  # noqa: E501 -- append-only: see note below
            
            scores_success = db.execute_insert(score_query, (vendor_id, domain, 'Overall', 'current', overall_score, scan_format))
            
            if vendors_success and scores_success:
                logger.info(f"Successfully updated overall score for {domain}: {overall_score}, scan_format: {scan_format} (both vendors and scores tables)")
                return True
            elif vendors_success:
                logger.warning(f"Updated vendors table but failed to update scores table for {domain}")
                return True  # Still return True since main functionality worked
            else:
                logger.error(f"Failed to update overall score for {domain}")
                return False
                
    except Exception as e:
        logger.error(f"Error updating overall score for {domain}: {e}")
        return False

class ScoreService:
    """Service class for score-related database operations"""
    
    def __init__(self):
        self.db = DatabaseConnection()
    
    def save_score(self, domain, score_category, score_value, time_period='current', scan_format='individual_scan'):
        """Save a score for a domain and category
        
        Args:
            domain: The domain being scored
            score_category: Category of score (Website, DNS, Network, etc.)
            score_value: The score value
            time_period: Time period for the score (default: 'current')
            scan_format: Type of scan that generated this score:
                        - 'full_scan_all': Scan of all vendors
                        - 'new_vendor': Initial scan of new vendor
                        - 'full_scan_single': Full scan of single vendor
                        - 'individual_scan': Single scan type (default)
        """
        try:
            # Get vendor_id for this domain
            vendor_query = "SELECT id FROM vendors WHERE domain = %s"
            
            with DatabaseConnection() as db:
                vendor_result = db.execute_single_query(vendor_query, (domain,))
                
                if not vendor_result:
                    logger.error(f"No vendor found for domain: {domain}")
                    return False
                
                vendor_id = vendor_result['id']
                
                # NOTE: intentionally a plain INSERT -- `scores` is append-only
                # history that trend/timeline queries read. See update_vendor_overall_score.
                score_query = """
                INSERT INTO scores (vendor_id, domain, score_category, time_period, score, scan_format, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, NOW())
                """  # noqa: E501 -- append-only: see note below
                
                success = db.execute_insert(score_query, (vendor_id, domain, score_category, time_period, score_value, scan_format))
                
                if success:
                    logger.info(f"Successfully saved score for {domain}, category: {score_category}, score: {score_value}, scan_format: {scan_format}")
                    return True
                else:
                    logger.error(f"Failed to save score for {domain}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error saving score for {domain}: {e}")
            return False

    def save_overall_score(self, domain, overall_score, time_period='current', scan_format='individual_scan'):
        """Save overall score to scores table with 'Overall' category"""
        return self.save_score(domain, 'Overall', overall_score, time_period, scan_format)
    
    def get_all_scores_by_domain(self, domain):
        """Get ALL scores for a domain (including Overall category and all time periods)"""
        query = """
        SELECT score_category, time_period, score, updated_at
        FROM scores s
        JOIN vendors v ON s.vendor_id = v.id
        WHERE s.domain = %s
        ORDER BY score_category, time_period, updated_at DESC
        """
        
        try:
            with DatabaseConnection() as db:
                results = db.execute_query(query, (domain,))
                
                if results:
                    scores = []
                    for row in results:
                        score_data = {
                            'category': row['score_category'],
                            'score_category': row['score_category'],
                            'time_period': row['time_period'],
                            'score': row['score'],
                            'updated_at': row['updated_at'].isoformat() if row['updated_at'] else None
                        }
                        scores.append(score_data)
                    
                    return scores
                else:
                    return []
                    
        except Exception as e:
            logger.error(f"Error retrieving all scores for {domain}: {e}")
            return []
    
    def get_scores_by_domain(self, domain):
        """Get latest scores for a domain (excluding Overall category, current period only)"""
        query = """
        SELECT DISTINCT ON (score_category) 
            score_category, time_period, score, updated_at
        FROM scores s
        JOIN vendors v ON s.vendor_id = v.id
        WHERE s.domain = %s 
            AND s.time_period = 'current'
            AND s.score_category != 'Overall'
        ORDER BY score_category, updated_at DESC
        """
        
        try:
            with DatabaseConnection() as db:
                results = db.execute_query(query, (domain,))
                
                if results:
                    scores = []
                    for row in results:
                        score_data = {
                            'category': row['score_category'],
                            'score_category': row['score_category'],  # Keep both for compatibility
                            'time_period': row['time_period'],
                            'score': row['score'],
                            'updated_at': row['updated_at'].isoformat() if row['updated_at'] else None
                        }
                        scores.append(score_data)
                    
                    return scores
                else:
                    return []
                    
        except Exception as e:
            logger.error(f"Error retrieving scores for {domain}: {e}")
            return []

class VulnerabilityService:
    """Service class for vulnerability-related database operations"""
    
    def __init__(self):
        self.db = DatabaseConnection()
    
    def save_vulnerability(self, domain, subdomain, score_category, title, description, severity):
        """Save a vulnerability for a domain/subdomain"""
        try:
            # Get vendor_id for this domain
            vendor_query = "SELECT id FROM vendors WHERE domain = %s"
            
            with DatabaseConnection() as db:
                vendor_result = db.execute_single_query(vendor_query, (domain,))
                
                if not vendor_result:
                    logger.error(f"No vendor found for domain: {domain}")
                    return False
                
                vendor_id = vendor_result['id']
                
                # Normalize severity
                normalized_severity = self._normalize_severity(severity)
                
                # Insert vulnerability
                vuln_query = """
                INSERT INTO vulnerabilities (vendor_id, domain, subdomain, score_category, title, description, severity, detected_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
                RETURNING id
                """

                vuln_result = db.execute_returning(
                    vuln_query,
                    (vendor_id, domain, subdomain, score_category, title, description, normalized_severity)
                )

                if vuln_result:
                    vuln_id = vuln_result['id']
                    logger.info(f"Successfully saved vulnerability for {domain}: {title}")
                    return True
                else:
                    logger.error(f"Failed to save vulnerability for {domain}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error saving vulnerability for {domain}: {e}")
            return False
    
    def _normalize_severity(self, severity):
        """Normalize severity values to match database constraints"""
        if not severity:
            return 'Medium'
        
        severity_upper = str(severity).upper()
        severity_mapping = {
            'LOW': 'Low',
            'MEDIUM': 'Medium', 
            'HIGH': 'High',
            'CRITICAL': 'Critical',
            'INFO': 'Info',  # Map INFO to Low
            'UNKNOWN': 'Medium'  # Default unknown to Medium
        }
        
        return severity_mapping.get(severity_upper, 'Medium')

    def save_vulnerabilities_batch(self, domain, vulnerabilities_list, score_category, update_existing=True):
        """Save multiple vulnerabilities for a domain
        
        Args:
            domain: The main domain
            vulnerabilities_list: List of vulnerabilities to save
            score_category: Category of vulnerabilities (Website, DNS, etc.)
            update_existing: If True, clears existing vulnerabilities for this domain+category first
        """
        try:
            # Get vendor_id for this domain
            vendor_query = "SELECT id FROM vendors WHERE domain = %s"
            
            with DatabaseConnection() as db:
                vendor_result = db.execute_single_query(vendor_query, (domain,))
                
                if not vendor_result:
                    logger.error(f"No vendor found for domain: {domain}")
                    return False
                
                vendor_id = vendor_result['id']
                
                # Clear existing vulnerabilities for this domain and category if updating
                if update_existing:
                    delete_query = """
                    DELETE FROM vulnerabilities 
                    WHERE vendor_id = %s AND domain = %s AND score_category = %s
                    """
                    db.execute_insert(delete_query, (vendor_id, domain, score_category))
                    logger.info(f"Cleared existing {score_category} vulnerabilities for {domain}")
                
                if not vulnerabilities_list:
                    logger.info(f"No new vulnerabilities to save for domain: {domain}, category: {score_category}")
                    return True
                
                # Remove duplicate vulnerabilities from the input list
                unique_vulnerabilities = []
                seen_vulns = set()
                
                for vuln in vulnerabilities_list:
                    subdomain = vuln.get('subdomain', domain)
                    title = vuln.get('title', 'Unknown Vulnerability')
                    description = vuln.get('description', '')
                    raw_severity = vuln.get('severity', 'Medium')
                    severity = self._normalize_severity(raw_severity)
                    
                    # Create a unique key for this vulnerability
                    vuln_key = (subdomain, title, severity)
                    
                    if vuln_key not in seen_vulns:
                        seen_vulns.add(vuln_key)
                        unique_vulnerabilities.append({
                            'subdomain': subdomain,
                            'title': title,
                            'description': description,
                            'severity': severity
                        })
                    else:
                        logger.debug(f"Skipping duplicate vulnerability: {title} for {subdomain}")
                
                if len(unique_vulnerabilities) < len(vulnerabilities_list):
                    duplicates_removed = len(vulnerabilities_list) - len(unique_vulnerabilities)
                    logger.info(f"Removed {duplicates_removed} duplicate vulnerabilities for {domain}, category: {score_category}")
                
                # Prepare batch insert data from unique vulnerabilities
                insert_data = []
                for vuln in unique_vulnerabilities:
                    insert_data.append(
                        (
                            vendor_id,
                            domain,
                            vuln['subdomain'],
                            score_category,
                            vuln['title'],
                            vuln['description'],
                            vuln['severity'],
                            datetime.now()  # detected_at
                        )
                    )
                
                # Batch insert vulnerabilities with duplicate prevention
                vuln_query = """
                INSERT INTO vulnerabilities (vendor_id, domain, subdomain, score_category, title, description, severity, detected_at)
                VALUES %s
                RETURNING id, subdomain, title, description, severity
                """

                vuln_results = db.execute_values_returning(vuln_query, insert_data)

                if vuln_results:
                    logger.info(f"Successfully saved {len(vuln_results)} new vulnerabilities for {domain}, category: {score_category}")

                    # Slack notifications for critical vulnerabilities have been disabled
                    # try:
                    #     # Get vendor name for Slack notifications
                    #     vendor_name_query = "SELECT vendor_name FROM vendors WHERE id = %s"
                    #     vendor_name_result = db.execute_single_query(vendor_name_query, (vendor_id,))
                    #     vendor_name = vendor_name_result['vendor_name'] if vendor_name_result else 'Unknown Vendor'
                    #
                    #     # Import Slack notification function
                    #     from slack.slack_service import send_critical_vulnerability_alert
                    #
                    #     # Send notifications for each critical vulnerability that hasn't been alerted yet
                    #     critical_count = 0
                    #     for vuln_result in vuln_results:
                    #         if vuln_result.get('severity', '').upper() == 'CRITICAL':
                    #             vuln_id = vuln_result['id']
                    #
                    #             # Check if alert has already been sent
                    #             alert_check_query = "SELECT slack_alert_sent_at FROM vulnerabilities WHERE id = %s"
                    #             alert_check_result = db.execute_single_query(alert_check_query, (vuln_id,))
                    #
                    #             if alert_check_result and alert_check_result['slack_alert_sent_at'] is None:
                    #                 vulnerability_data = {
                    #                     'id': vuln_id,
                    #                     'subdomain': vuln_result['subdomain'],
                    #                     'title': vuln_result['title'],
                    #                     'description': vuln_result['description'],
                    #                     'severity': vuln_result['severity'],
                    #                     'category': score_category,
                    #                     'detected_at': None
                    #                 }
                    #
                    #                 slack_success = send_critical_vulnerability_alert(vendor_name, domain, vulnerability_data)
                    #                 if slack_success:
                    #                     # Mark alert as sent
                    #                     update_alert_query = "UPDATE vulnerabilities SET slack_alert_sent_at = NOW() WHERE id = %s"
                    #                     db.execute_insert(update_alert_query, (vuln_id,))
                    #                     critical_count += 1
                    #                     logger.info(f"Slack notification sent for critical vulnerability: {vuln_result['title']}")
                    #                 else:
                    #                     logger.warning(f"Failed to send Slack notification for critical vulnerability: {vuln_result['title']}")
                    #             else:
                    #                 logger.debug(f"Slack alert already sent for vulnerability {vuln_result['title']} (ID: {vuln_id})")
                    #
                    #         if critical_count > 0:
                    #             logger.info(f"Sent Slack notifications for {critical_count} critical vulnerabilities")
                    #
                    # except Exception as slack_error:
                    #     logger.error(f"Error sending Slack notifications for batch vulnerabilities: {slack_error}")
                    #     # Don't fail the vulnerability save if Slack notification fails

                    return True
                else:
                    logger.error(f"Failed to save vulnerabilities for {domain}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error saving vulnerabilities for {domain}: {e}")
            return False
    
    def check_domain_has_subdomains(self, domain):
        """Check if a domain has any subdomains in the database"""
        try:
            vendor_query = "SELECT id FROM vendors WHERE domain = %s"
            
            with DatabaseConnection() as db:
                vendor_result = db.execute_single_query(vendor_query, (domain,))
                
                if not vendor_result:
                    logger.warning(f"No vendor found for domain: {domain}")
                    return False
                
                vendor_id = vendor_result['id']
                
                # Check if subdomains exist
                subdomain_check_query = "SELECT COUNT(*) as count FROM subdomains WHERE vendor_id = %s"
                count_result = db.execute_single_query(subdomain_check_query, (vendor_id,))
                
                if count_result and count_result['count'] > 0:
                    logger.info(f"Found {count_result['count']} subdomains for {domain} in database")
                    return True
                else:
                    logger.info(f"No subdomains found for {domain} in database")
                    return False
                    
        except Exception as e:
            logger.error(f"Error checking subdomains for {domain}: {e}")
            return False
    
    def get_vulnerabilities_by_domain(self, domain, score_category=None):
        """Get vulnerabilities for a domain, optionally filtered by category"""
        query = """
        SELECT subdomain, score_category, title, description, severity, detected_at
        FROM vulnerabilities v
        JOIN vendors ven ON v.vendor_id = ven.id
        WHERE v.domain = %s
        """
        params = [domain]
        
        if score_category:
            query += " AND v.score_category = %s"
            params.append(score_category)
        
        query += " ORDER BY detected_at DESC"
        
        try:
            with DatabaseConnection() as db:
                results = db.execute_query(query, params)
                
                if results:
                    vulnerabilities = []
                    for row in results:
                        vuln_data = {
                            'subdomain': row['subdomain'],
                            'category': row['score_category'],
                            'title': row['title'],
                            'description': row['description'],
                            'severity': row['severity'],
                            'detected_at': row['detected_at'].isoformat() if row['detected_at'] else None
                        }
                        vulnerabilities.append(vuln_data)
                    
                    return vulnerabilities
                else:
                    return []
                    
        except Exception as e:
            logger.error(f"Error retrieving vulnerabilities for {domain}: {e}")
            return []

def get_vendors_for_full_scan():
    """Vendors in the order the full-scan loop should work through them.

    Stalest first: never-scanned vendors (NULL) lead, then oldest completed
    scan. This replaces the previous checkpoint scheme, which asked "who comes
    after the last-scanned vendor?" -- a question that needed two modules to
    agree on an ordering (they didn't: resume ordered by id, the scanner by
    vendor_name) and left everything before the checkpoint unscanned because
    there was no wrap-around pass.

    Stalest-first needs no agreement and no cursor arithmetic. It is also
    self-healing: a vendor whose scan dies is still the stalest, so it is
    retried first rather than stalling the fleet, and a scan interrupted
    halfway simply resumes wherever the remaining work is oldest.
    """
    query = """
    SELECT id, vendor_name, domain, last_full_scan_at
    FROM vendors
    WHERE domain IS NOT NULL AND domain <> ''
    ORDER BY last_full_scan_at ASC NULLS FIRST, id ASC
    """
    try:
        with DatabaseConnection() as db:
            results = db.execute_query(query)
            return [dict(row) for row in (results or [])]
    except Exception as e:
        logger.error(f"Error retrieving vendors for full scan: {e}")
        return []


def mark_vendor_full_scan_complete(domain):
    """Record that a full scan finished every step for this domain.

    The scheduler orders work by this column (oldest first), so it must mean
    exactly one thing: a complete scan finished. Deliberately separate from
    vendors.last_scanned, which update_vendor_overall_score stamps and which
    several non-scan code paths therefore reach.
    """
    try:
        with DatabaseConnection() as db:
            success = db.execute_insert(
                "UPDATE vendors SET last_full_scan_at = NOW() WHERE domain = %s",
                (domain,),
            )
            if success:
                logger.info(f"Scan cursor stamped for {domain}")
            else:
                logger.warning(f"Could not stamp scan cursor for {domain}")
            return bool(success)
    except Exception as e:
        logger.error(f"Error stamping scan cursor for {domain}: {e}")
        return False


# Convenience functions for score operations
def save_website_score(domain, score_value, time_period='current', scan_format='individual_scan'):
    """Save Website (vulnerability scan) score"""
    service = ScoreService()
    return service.save_score(domain, 'Website', score_value, time_period, scan_format)

def save_domain_reputation_score(domain, score_value, time_period='current', scan_format='individual_scan'):
    """Save Domain Reputation score"""
    service = ScoreService()
    return service.save_score(domain, 'Domain Reputation', score_value, time_period, scan_format)

def save_dns_score(domain, score_value, time_period='current', scan_format='individual_scan'):
    """Save DNS score"""
    service = ScoreService()
    return service.save_score(domain, 'DNS', score_value, time_period, scan_format)

def save_network_score(domain, score_value, time_period='current', scan_format='individual_scan'):
    """Save Network score"""
    service = ScoreService()
    return service.save_score(domain, 'Network', score_value, time_period, scan_format)

def save_encryption_score(domain, score_value, time_period='current', scan_format='individual_scan'):
    """Save Encryption score"""
    service = ScoreService()
    return service.save_score(domain, 'Encryption', score_value, time_period, scan_format)

def save_email_score(domain, score_value, time_period='current', scan_format='individual_scan'):
    """Save Email score"""
    service = ScoreService()
    return service.save_score(domain, 'Email', score_value, time_period, scan_format)

# Convenience functions for vulnerability operations
def save_website_vulnerabilities(domain, vulnerabilities_list, update_existing=True):
    """Save Website (vulnerability scan) vulnerabilities"""
    service = VulnerabilityService()
    return service.save_vulnerabilities_batch(domain, vulnerabilities_list, 'Website', update_existing)

def save_domain_reputation_vulnerabilities(domain, vulnerabilities_list, update_existing=True):
    """Save Domain Reputation vulnerabilities"""
    service = VulnerabilityService()
    return service.save_vulnerabilities_batch(domain, vulnerabilities_list, 'Domain Reputation', update_existing)

def save_dns_vulnerabilities(domain, vulnerabilities_list, update_existing=True):
    """Save DNS vulnerabilities"""
    service = VulnerabilityService()
    return service.save_vulnerabilities_batch(domain, vulnerabilities_list, 'DNS', update_existing)

def save_network_vulnerabilities(domain, vulnerabilities_list, update_existing=True):
    """Save Network vulnerabilities"""
    service = VulnerabilityService()
    return service.save_vulnerabilities_batch(domain, vulnerabilities_list, 'Network', update_existing)

def save_encryption_vulnerabilities(domain, vulnerabilities_list, update_existing=True):
    """Save Encryption vulnerabilities"""
    service = VulnerabilityService()
    return service.save_vulnerabilities_batch(domain, vulnerabilities_list, 'Encryption', update_existing)

def save_email_vulnerabilities(domain, vulnerabilities_list, update_existing=True):
    """Save Email vulnerabilities"""
    service = VulnerabilityService()
    return service.save_vulnerabilities_batch(domain, vulnerabilities_list, 'Email', update_existing)

def check_domain_has_subdomains(domain):
    """Check if a domain has subdomains in the database"""
    service = VulnerabilityService()
    return service.check_domain_has_subdomains(domain)

def get_scores_for_domain(domain):
    """Get latest scores for a domain (excluding Overall category, current period only)"""
    service = ScoreService()
    return service.get_scores_by_domain(domain)

def get_all_scores_for_domain(domain):
    """Get ALL scores for a domain (including Overall category and all time periods)"""
    service = ScoreService()
    return service.get_all_scores_by_domain(domain)

def get_vulnerabilities_for_domain(domain, category=None):
    """Get vulnerabilities for a domain"""
    service = VulnerabilityService()
    return service.get_vulnerabilities_by_domain(domain, category)

def cleanup_duplicate_vulnerabilities(domain=None, category=None):
    """Remove duplicate vulnerabilities from the database
    
    Args:
        domain: Specific domain to clean up (optional)
        category: Specific category to clean up (optional)
    
    Returns:
        dict: Results of the cleanup operation
    """
    try:
        with DatabaseConnection() as db:
            # Build the WHERE clause based on parameters
            where_conditions = []
            params = []
            
            if domain:
                where_conditions.append("domain = %s")
                params.append(domain)
            
            if category:
                where_conditions.append("score_category = %s")
                params.append(category)
            
            where_clause = ""
            if where_conditions:
                where_clause = "WHERE " + " AND ".join(where_conditions)
            
            # Find duplicate vulnerabilities
            duplicate_query = f"""
            WITH duplicate_vulns AS (
                SELECT 
                    vendor_id, domain, subdomain, score_category, title, severity,
                    COUNT(*) as dup_count,
                    MIN(id) as keep_id,
                    ARRAY_AGG(id ORDER BY detected_at DESC) as all_ids
                FROM vulnerabilities
                {where_clause}
                GROUP BY vendor_id, domain, subdomain, score_category, title, severity
                HAVING COUNT(*) > 1
            )
            SELECT 
                vendor_id, domain, subdomain, score_category, title, severity,
                dup_count,
                keep_id,
                all_ids
            FROM duplicate_vulns
            ORDER BY domain, score_category, title
            """
            
            duplicates = db.execute_query(duplicate_query, params)
            
            if not duplicates:
                return {
                    'success': True,
                    'duplicates_found': 0,
                    'duplicates_removed': 0,
                    'message': 'No duplicate vulnerabilities found'
                }
            
            total_duplicates_removed = 0
            cleaned_items = []
            
            for dup in duplicates:
                # Keep the first ID, remove the rest
                ids_to_remove = [id for id in dup['all_ids'] if id != dup['keep_id']]
                
                if ids_to_remove:
                    # Delete the duplicate IDs
                    delete_query = "DELETE FROM vulnerabilities WHERE id = ANY(%s)"
                    success = db.execute_insert(delete_query, (ids_to_remove,))
                    
                    if success:
                        removed_count = len(ids_to_remove)
                        total_duplicates_removed += removed_count
                        
                        cleaned_items.append({
                            'domain': dup['domain'],
                            'subdomain': dup['subdomain'],
                            'category': dup['score_category'],
                            'title': dup['title'],
                            'severity': dup['severity'],
                            'duplicates_removed': removed_count
                        })
                        
                        logger.info(f"Removed {removed_count} duplicate entries for: {dup['title']} ({dup['domain']})")
            
            return {
                'success': True,
                'duplicates_found': len(duplicates),
                'duplicates_removed': total_duplicates_removed,
                'cleaned_items': cleaned_items,
                'message': f'Successfully removed {total_duplicates_removed} duplicate vulnerabilities'
            }
            
    except Exception as e:
        logger.error(f"Error cleaning up duplicate vulnerabilities: {e}")
        return {
            'success': False,
            'error': str(e),
            'message': 'Failed to clean up duplicate vulnerabilities'
        }

def validate_severity(severity):
    """Validate and normalize severity value"""
    service = VulnerabilityService()
    return service._normalize_severity(severity)

def add_new_vendor(vendor_name, domain, tier=None, portfolio=None, industry=None):
    """Add a new vendor to the database
    
    Args:
        vendor_name: The name of the vendor
        domain: The domain of the vendor
        tier: The tier of the vendor (optional)
        portfolio: The portfolio of the vendor (optional)
        industry: The industry of the vendor (optional)
    
    Returns:
        dict: Result with success status and vendor data or error message
    """
    try:
        with DatabaseConnection() as db:
            # Check if vendor already exists by domain
            check_query = "SELECT id, vendor_name FROM vendors WHERE domain = %s"
            existing_vendor = db.execute_single_query(check_query, (domain,))
            
            if existing_vendor:
                return {
                    'success': False,
                    'error': f'Vendor with domain {domain} already exists',
                    'existing_vendor': existing_vendor['vendor_name']
                }
            
            # Check if vendor already exists by name (case-insensitive)
            name_check_query = "SELECT id, domain FROM vendors WHERE LOWER(vendor_name) = LOWER(%s)"
            existing_name = db.execute_single_query(name_check_query, (vendor_name,))
            
            if existing_name:
                return {
                    'success': False,
                    'error': f'Vendor with name "{vendor_name}" already exists',
                    'existing_vendor': vendor_name,
                    'existing_domain': existing_name['domain']
                }
            
            # Insert new vendor
            insert_query = """
            INSERT INTO vendors (vendor_name, domain, grade, added_at, overall_score_current, subdomain_count, tier, portfolio, industry)
            VALUES (%s, %s, 'N/A', NOW(), 0, 0, %s, %s, %s)
            """
            
            # Use execute_insert to add the vendor
            success = db.execute_insert(insert_query, (vendor_name, domain, tier, portfolio, industry))
            
            if success:
                # Get the newly created vendor
                get_vendor_query = "SELECT id, vendor_name, domain, grade, added_at FROM vendors WHERE domain = %s"
                result = db.execute_single_query(get_vendor_query, (domain,))
                
                if result:
                    logger.info(f"Successfully added new vendor: {vendor_name} for domain {domain}")
                    return {
                        'success': True,
                        'vendor': {
                            'id': result['id'],
                            'name': result['vendor_name'],
                            'domain': result['domain'],
                            'grade': result['grade'],
                            'added_at': result['added_at'].strftime('%Y-%m-%d %H:%M:%S') if result['added_at'] else None
                        }
                    }
                else:
                    logger.warning(f"Vendor {vendor_name} was inserted but could not be retrieved")
                    return {
                        'success': True,
                        'vendor': {
                            'name': vendor_name,
                            'domain': domain,
                            'grade': 'N/A'
                        }
                    }
            else:
                return {
                    'success': False,
                    'error': 'Failed to insert vendor into database'
                }
                
    except Exception as e:
        logger.error(f"Error adding new vendor {vendor_name} with domain {domain}: {e}")
        return {
            'success': False,
            'error': f'Database error: {str(e)}'
        }

# Integration functions for subdomain discovery with status
def ensure_vendor_exists(domain, vendor_name=None, create_if_missing=True):
    """Check whether a vendor exists in the database, and optionally create it.
    
    Args:
        domain: The domain to check/create.
        vendor_name: Optional vendor name; defaults to a title-cased version of the domain.
        create_if_missing: When True (default) a new vendor row is inserted if none exists.
            Pass False from scan paths so that a deleted vendor is never silently re-created
            by a background job that was already in-flight at deletion time.
    
    Returns:
        bool: True if the vendor exists (or was created successfully); False otherwise.
    """
    try:
        with DatabaseConnection() as db:
            check_query = "SELECT id FROM vendors WHERE domain = %s"
            result = db.execute_single_query(check_query, (domain,))
            
            if result:
                logger.info(f"Vendor for domain {domain} already exists with ID {result['id']}")
                return True
            
            if not create_if_missing:
                logger.warning(
                    f"Vendor for domain {domain} does not exist and create_if_missing=False; "
                    "skipping creation (vendor was likely deleted while a scan was in-flight)"
                )
                return False
            
            # Creation is explicitly allowed — insert the new row.
            if vendor_name is None:
                vendor_name = domain.replace('.com', '').replace('.', ' ').title()
            
            insert_query = """
            INSERT INTO vendors (vendor_name, domain, grade, added_at)
            VALUES (%s, %s, 'N/A', NOW())
            """
            
            success = db.execute_insert(insert_query, (vendor_name, domain))
            
            if success:
                logger.info(f"Created new vendor: {vendor_name} for domain {domain}")
                return True
            else:
                logger.error(f"Failed to create vendor for domain {domain}")
                return False
                
    except Exception as e:
        logger.error(f"Error ensuring vendor exists for {domain}: {e}")
        return False

def save_subdomains_with_status_detection(domain, discovered_subdomains, alive_subdomains, replace_existing=False):
    """Save subdomains with active/inactive status based on discovery results
    
    Args:
        domain: The main domain
        discovered_subdomains: List of all discovered subdomains
        alive_subdomains: List of subdomains that responded to HTTP/HTTPS
        replace_existing: If True, replaces all existing subdomains
    """
    try:
        # Confirm vendor exists; do NOT create it here — if it was deleted while a scan was
        # in-flight, silently re-inserting it would undo the user's delete action.
        if not ensure_vendor_exists(domain, create_if_missing=False):
            logger.warning(f"Cannot save subdomains for {domain} — vendor does not exist (may have been deleted)")
            return False
        
        # Get vendor_id for exclusion filtering
        vendor = get_vendor_by_domain(domain)
        if not vendor:
            logger.error(f"Cannot get vendor info for domain {domain}")
            return False
        vendor_id = vendor['id']
        
        # Get excluded subdomains for this vendor
        excluded_subdomains = get_excluded_subdomains_set(vendor_id)
        if excluded_subdomains:
            logger.info(f"Found {len(excluded_subdomains)} excluded subdomains for {domain} - will filter them out")
        
        # Filter out excluded subdomains from discovery results
        original_count = len(discovered_subdomains)
        discovered_subdomains = [sub for sub in discovered_subdomains if sub not in excluded_subdomains]
        alive_subdomains = [sub for sub in (alive_subdomains or []) if sub not in excluded_subdomains]
        
        if excluded_subdomains and original_count > len(discovered_subdomains):
            filtered_count = original_count - len(discovered_subdomains)
            logger.info(f"Filtered out {filtered_count} excluded subdomains from discovery results for {domain}")
        
        # Convert alive subdomains to a set for faster lookup
        alive_set = set(alive_subdomains) if alive_subdomains else set()
        
        # Enhanced logger for debugging
        logger.info(f"Processing {len(discovered_subdomains)} discovered subdomains for {domain} (after exclusion filtering)")
        logger.info(f"Alive subdomains count: {len(alive_subdomains) if alive_subdomains else 0}")
        if alive_subdomains:
            logger.info(f"First few alive subdomains: {list(alive_subdomains)[:5]}")
        else:
            logger.warning(f"No alive subdomains provided for {domain}")
        
        # Create subdomain data with status
        subdomains_with_status = []
        active_count = 0
        inactive_count = 0
        
        for subdomain in discovered_subdomains:
            status = 'Active' if subdomain in alive_set else 'Inactive'
            subdomains_with_status.append({
                'subdomain': subdomain,
                'status': status
            })
            
            if status == 'Active':
                active_count += 1
            else:
                inactive_count += 1
                
            # Debug logger for first few
            if len(subdomains_with_status) <= 5:
                logger.info(f"Subdomain: {subdomain}, In alive_set: {subdomain in alive_set}, Status: {status}")
        
        logger.info(f"Status summary: {active_count} Active, {inactive_count} Inactive")
        
        # Save to database using the updated service
        service = SubdomainService()
        success = service.save_subdomains(domain, subdomains_with_status, replace_existing)
        
        # Update the subdomain count in vendors table
        if success:
            service.update_vendor_subdomain_count(domain)
            
            # Log summary statistics
            active_count = len(alive_set)
            inactive_count = len(discovered_subdomains) - active_count
            logger.info(f"Successfully saved {len(discovered_subdomains)} subdomains for {domain}: {active_count} active, {inactive_count} inactive")
        
        return success
        
    except Exception as e:
        logger.error(f"Error saving subdomains with status for {domain}: {e}")
        return False

def run_subdomain_discovery_and_save(domain, replace_existing=True):
    """Run complete subdomain discovery using subdomains_sub.py logic and save to database
    
    Args:
        domain: The domain to scan
        replace_existing: If True, replaces all existing subdomains
    
    Returns:
        dict: Results containing statistics and status
    """
    try:
        # Import the subdomain discovery functions from subdomains_sub
        import sys
        import os
        
        # Add the Sublist3r_New directory to path
        sublist3r_path = os.path.join(os.path.dirname(__file__), '..', 'Sublist3r_New')
        if os.path.exists(sublist3r_path):
            sys.path.insert(0, sublist3r_path)
            from subdomains_sub import find_all_subdomains, find_alive_subdomains
        else:
            logger.error(f"Sublist3r_New directory not found at {sublist3r_path}")
            return {'success': False, 'error': 'Subdomain discovery module not found'}
        
        logger.info(f"Starting subdomain discovery for {domain}")
        
        # Discover all subdomains
        all_subdomains = find_all_subdomains(domain)
        if not all_subdomains:
            logger.warning(f"No subdomains discovered for {domain}")
            return {'success': True, 'total_discovered': 0, 'active': 0, 'inactive': 0}
        
        logger.info(f"Discovered {len(all_subdomains)} subdomains for {domain}")
        
        # Check which subdomains are alive
        alive_subdomains = find_alive_subdomains(all_subdomains)
        logger.info(f"Found {len(alive_subdomains)} alive subdomains out of {len(all_subdomains)}")
        
        # Save to database with status
        success = save_subdomains_with_status_detection(domain, all_subdomains, alive_subdomains, replace_existing)
        
        if success:
            return {
                'success': True,
                'total_discovered': len(all_subdomains),
                'active': len(alive_subdomains),
                'inactive': len(all_subdomains) - len(alive_subdomains),
                'all_subdomains': all_subdomains,
                'alive_subdomains': alive_subdomains
            }
        else:
            return {'success': False, 'error': 'Failed to save subdomains to database'}
            
    except Exception as e:
        logger.error(f"Error during subdomain discovery for {domain}: {e}")
        return {'success': False, 'error': str(e)}

def get_subdomain_statistics_by_domain(domain):
    """Get subdomain statistics for a domain including active/inactive counts"""
    try:
        with DatabaseConnection() as db:
            stats_query = """
            SELECT 
                COUNT(*) as total_subdomains,
                COUNT(CASE WHEN status = 'Active' THEN 1 END) as active_subdomains,
                COUNT(CASE WHEN status = 'Inactive' THEN 1 END) as inactive_subdomains
            FROM subdomains s
            JOIN vendors v ON s.vendor_id = v.id
            WHERE s.domain = %s
            """
            
            result = db.execute_single_query(stats_query, (domain,))
            
            if result:
                return {
                    'total': result['total_subdomains'],
                    'active': result['active_subdomains'],
                    'inactive': result['inactive_subdomains'],
                    'activity_rate': round((result['active_subdomains'] / result['total_subdomains'] * 100), 2) if result['total_subdomains'] > 0 else 0
                }
            else:
                return {'total': 0, 'active': 0, 'inactive': 0, 'activity_rate': 0}
                
    except Exception as e:
        logger.error(f"Error getting subdomain statistics for {domain}: {e}")
        return {'total': 0, 'active': 0, 'inactive': 0, 'activity_rate': 0}


class BreachRecordsService:
    """Service class for breach records database operations"""
    
    def __init__(self):
        self.db = DatabaseConnection()
        self._ensure_table_exists()
    
    def _ensure_table_exists(self):
        """Ensure the breach_records table exists, create it if it doesn't"""
        create_table_sql = """
        CREATE TABLE IF NOT EXISTS breach_records (
            id SERIAL PRIMARY KEY,
            uuid TEXT UNIQUE NOT NULL,
            email TEXT NOT NULL,
            password_leaked INTEGER NOT NULL,
            passwords JSONB NOT NULL,
            severity TEXT,
            status TEXT,
            description TEXT,
            created_at TIMESTAMP,
            resolved_at TIMESTAMP
        );
        """
        
        try:
            with DatabaseConnection() as db:
                success = db.execute_insert(create_table_sql)
                if success:
                    logger.info(" breach_records table verified/created successfully")
                else:
                    logger.warning(" Could not verify breach_records table creation")
        except Exception as e:
            logger.error(f" Error ensuring breach_records table exists: {e}")
    
    def store_breach_record(self, breach_data):
        """Store a breach record in the database"""
        query = """
        INSERT INTO breach_records (
            uuid, email, password_leaked, passwords, severity, 
            status, description, created_at, resolved_at
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (uuid) DO UPDATE SET
            email = EXCLUDED.email,
            password_leaked = EXCLUDED.password_leaked,
            passwords = EXCLUDED.passwords,
            severity = EXCLUDED.severity,
            status = EXCLUDED.status,
            description = EXCLUDED.description,
            resolved_at = EXCLUDED.resolved_at
        RETURNING id
        """
        
        try:
            with DatabaseConnection() as db:
                # Ensure UUID exists - generate one if missing
                breach_uuid = breach_data.get('uuid')
                if not breach_uuid:
                    breach_uuid = str(uuid.uuid4())
                    logger.warning(f"Generated UUID for breach record: {breach_uuid}")
                
                # Convert passwords dict to JSON string for storage
                passwords_data = breach_data.get('passwords', {})
                passwords_json = json.dumps(passwords_data) if passwords_data else '{}'
                
                # Parse created_at if it's a string
                created_at = breach_data.get('created_at')
                if isinstance(created_at, str):
                    try:
                        created_at = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                    except:
                        created_at = datetime.now()
                elif not created_at:
                    created_at = datetime.now()
                
                # Parse resolved_at if it exists
                resolved_at = breach_data.get('resolved_at')
                if isinstance(resolved_at, str):
                    try:
                        resolved_at = datetime.fromisoformat(resolved_at.replace('Z', '+00:00'))
                    except:
                        resolved_at = None
                
                # Use execute_insert for INSERT operations to ensure proper commit
                insert_success = db.execute_insert(query, (
                    breach_uuid,
                    breach_data.get('email', 'Unknown'),
                    breach_data.get('passwords', {}).get('count', 0),
                    passwords_json,
                    breach_data.get('severity', 'Info'),
                    breach_data.get('status', 'Unknown'),
                    breach_data.get('description', 'No description available'),
                    created_at,
                    resolved_at
                ))
                
                if insert_success:
                    # Get the inserted record ID
                    id_query = "SELECT id FROM breach_records WHERE uuid = %s"
                    result = db.execute_query(id_query, (breach_uuid,))
                
                    if result:
                        breach_id = result[0]['id']
                        logger.info(f"Stored breach record with UUID: {breach_uuid}")

                        # Send Slack notification for breach records
                        try:
                            # Check if alert has already been sent
                            alert_check_query = "SELECT slack_alert_sent_at FROM breach_records WHERE id = %s"
                            alert_check_result = db.execute_single_query(alert_check_query, (breach_id,))

                            if alert_check_result and alert_check_result['slack_alert_sent_at'] is None:
                                # Import Slack notification function
                                from slack.slack_service import send_breach_alert

                                breach_data_payload = {
                                    'id': breach_id,
                                    'uuid': breach_uuid,
                                    'email': breach_data.get('email', 'Unknown'),
                                    'severity': breach_data.get('severity', 'Unknown'),
                                    'description': breach_data.get('description', 'No description available'),
                                    'password_leaked': breach_data.get('passwords', {}).get('count', 0),
                                    'created_at': created_at
                                }

                                slack_success = send_breach_alert(breach_data_payload)
                                if slack_success:
                                    # Mark alert as sent
                                    update_alert_query = "UPDATE breach_records SET slack_alert_sent_at = NOW() WHERE id = %s"
                                    db.execute_insert(update_alert_query, (breach_id,))
                                    logger.info(f"Slack notification sent for breach record: {breach_data.get('email', 'Unknown')}")
                                else:
                                    logger.warning(f"Failed to send Slack notification for breach record: {breach_data.get('email', 'Unknown')}")
                            else:
                                logger.debug(f"Slack alert already sent for breach record {breach_data.get('email', 'Unknown')} (ID: {breach_id})")

                        except Exception as slack_error:
                            logger.error(f"Error sending Slack notification for breach record {breach_uuid}: {slack_error}")
                            # Don't fail the breach record save if Slack notification fails

                        return breach_id  # Return the ID
                    else:
                        logger.warning(f"Record inserted but ID not found for UUID: {breach_uuid}")
                        return True  # At least we know it was inserted
                else:
                    logger.error(f"Failed to insert breach record with UUID: {breach_uuid}")
                    return None
                
        except Exception as e:
            logger.error(f"Error storing breach record: {e}")
            return None
    
    def get_all_breach_records(self, limit=100, offset=0):
        """Retrieve all breach records from the database"""
        query = """
        SELECT 
            id, uuid, email, password_leaked, passwords, severity,
            status, description, created_at, resolved_at
        FROM breach_records 
        ORDER BY created_at DESC
        LIMIT %s OFFSET %s
        """
        
        try:
            with DatabaseConnection() as db:
                results = db.execute_query(query, (limit, offset))
                if results:
                    breach_records = []
                    for row in results:
                        # Parse passwords JSON safely
                        passwords_data = row['passwords']
                        if isinstance(passwords_data, str):
                            try:
                                passwords_data = json.loads(passwords_data)
                            except:
                                passwords_data = {}
                        elif not passwords_data:
                            passwords_data = {}
                        
                        breach_record = {
                            'id': row['id'],
                            'uuid': row['uuid'],
                            'email': row['email'],
                            'password_leaked': row['password_leaked'],
                            'passwords': passwords_data,
                            'severity': row['severity'],
                            'status': row['status'],
                            'description': row['description'],
                            'created_at': row['created_at'].isoformat() if row['created_at'] else None,
                            'resolved_at': row['resolved_at'].isoformat() if row['resolved_at'] else None
                        }
                        breach_records.append(breach_record)
                    return breach_records
                return []
                
        except Exception as e:
            logger.error(f"Error retrieving breach records: {e}")
            return []
    
    def get_breach_records_by_email(self, email):
        """Retrieve breach records for a specific email"""
        query = """
        SELECT 
            id, uuid, email, password_leaked, passwords, severity,
            status, description, created_at, resolved_at
        FROM breach_records 
        WHERE email ILIKE %s
        ORDER BY created_at DESC
        """
        
        try:
            with DatabaseConnection() as db:
                results = db.execute_query(query, (f"%{email}%",))
                if results:
                    breach_records = []
                    for row in results:
                        # Parse passwords JSON safely
                        passwords_data = row['passwords']
                        if isinstance(passwords_data, str):
                            try:
                                passwords_data = json.loads(passwords_data)
                            except:
                                passwords_data = {}
                        elif not passwords_data:
                            passwords_data = {}
                        
                        breach_record = {
                            'id': row['id'],
                            'uuid': row['uuid'],
                            'email': row['email'],
                            'password_leaked': row['password_leaked'],
                            'passwords': passwords_data,
                            'severity': row['severity'],
                            'status': row['status'],
                            'description': row['description'],
                            'created_at': row['created_at'].isoformat() if row['created_at'] else None,
                            'resolved_at': row['resolved_at'].isoformat() if row['resolved_at'] else None
                        }
                        breach_records.append(breach_record)
                    return breach_records
                return []
                
        except Exception as e:
            logger.error(f"Error retrieving breach records for email {email}: {e}")
            return []
    
    def get_breach_statistics(self):
        """Get statistics about breach records"""
        query = """
        SELECT 
            COUNT(*) as total_breaches,
            SUM(password_leaked) as total_passwords,
            COUNT(DISTINCT email) as unique_emails,
            COUNT(CASE WHEN severity = 'Critical' THEN 1 END) as critical_breaches,
            COUNT(CASE WHEN severity = 'High' THEN 1 END) as high_breaches,
            COUNT(CASE WHEN severity = 'Medium' THEN 1 END) as medium_breaches,
            COUNT(CASE WHEN severity = 'Low' THEN 1 END) as low_breaches,
            COUNT(CASE WHEN status = 'Active' THEN 1 END) as active_breaches,
            COUNT(CASE WHEN resolved_at IS NOT NULL THEN 1 END) as resolved_breaches
        FROM breach_records
        """
        
        try:
            with DatabaseConnection() as db:
                result = db.execute_query(query)
                if result and result[0]:
                    row = result[0]
                    return {
                        'total_breaches': row['total_breaches'] or 0,
                        'total_passwords': row['total_passwords'] or 0,
                        'unique_emails': row['unique_emails'] or 0,
                        'severity_breakdown': {
                            'Critical': row['critical_breaches'] or 0,
                            'High': row['high_breaches'] or 0,
                            'Medium': row['medium_breaches'] or 0,
                            'Low': row['low_breaches'] or 0
                        },
                        'active_breaches': row['active_breaches'] or 0,
                        'resolved_breaches': row['resolved_breaches'] or 0
                    }
                return {
                    'total_breaches': 0,
                    'total_passwords': 0,
                    'unique_emails': 0,
                    'severity_breakdown': {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0},
                    'active_breaches': 0,
                    'resolved_breaches': 0
                }
                
        except Exception as e:
            logger.error(f"Error getting breach statistics: {e}")
            return {
                'total_breaches': 0,
                'total_passwords': 0,
                'unique_emails': 0,
                'severity_breakdown': {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0},
                'active_breaches': 0,
                'resolved_breaches': 0
            }
    
    def delete_breach_record(self, uuid):
        """Delete a breach record by UUID"""
        query = "DELETE FROM breach_records WHERE uuid = %s"
        
        try:
            with DatabaseConnection() as db:
                success = db.execute_insert(query, (uuid,))
                if success:
                    logger.info(f"Deleted breach record with UUID: {uuid}")
                    return True
                return False
                
        except Exception as e:
            logger.error(f"Error deleting breach record {uuid}: {e}")
            return False 

class NewsService:
    """Service for managing news and incidents data"""
    
    def store_news_item(self, domain, event_date, title, description, severity, source_url, event_type):
        """Store a single news/incident item in the database with deduplication"""
        # Import deduplication module
        try:
            from deduplication import is_potential_duplicate, sanitize_news_items
            deduplication_available = True
        except ImportError:
            logger.warning("Deduplication module not available for individual insert, proceeding without it")
            deduplication_available = False

        # Apply deduplication if available
        if deduplication_available:
            try:
                # Create and sanitize item for deduplication check (same as batch processing)
                new_item_dict = {
                    'title': title,
                    'description': description,
                    'date': event_date.isoformat() if hasattr(event_date, 'isoformat') else str(event_date),
                    'type': event_type.lower() if event_type else 'news'
                }
                sanitized_items = sanitize_news_items([new_item_dict])
                new_item = sanitized_items[0] if sanitized_items else new_item_dict

                # Get existing items for this domain (same as batch processing)
                existing_data = self.get_news_for_domain(domain, months=12)
                existing_items = existing_data.get('incidents', []) + existing_data.get('news', [])

                # Check if this item is a duplicate (using default stricter thresholds for individual inserts)
                is_duplicate = False
                for existing_item in existing_items:
                    if is_potential_duplicate(new_item, existing_item):
                        is_duplicate = True
                        logger.info(f"[Deduplication] Skipping duplicate news item for domain {domain}: '{title[:50]}...'")
                        break

                if is_duplicate:
                    return None  # Don't insert duplicate

            except Exception as e:
                logger.warning(f"Deduplication check failed for individual item {domain}: {e}, proceeding with insert")

        query = """
        INSERT INTO news (domain, event_date, title, description, severity, source_url, event_type)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (domain, title) DO NOTHING
        RETURNING id
        """
        
        try:
            with DatabaseConnection() as db:
                # Check connection before executing
                if not db.connection or db.connection.closed:
                    logger.error(f"Database connection is closed for domain {domain}")
                    return None
                
                db.cursor.execute(query, (
                    domain, event_date, title, description,
                    severity, source_url, event_type
                ))
                
                # Fetch result before commit
                result = db.cursor.fetchone()
                
                # Commit the transaction
                db.connection.commit()

                news_id = result['id'] if result else None

                # Send Slack notification for critical incidents
                if news_id and severity.upper() == 'CRITICAL' and event_type.lower() == 'incident':
                    try:
                        # Check if alert has already been sent
                        alert_check_query = "SELECT slack_alert_sent_at FROM news WHERE id = %s"
                        alert_check_result = db.execute_single_query(alert_check_query, (news_id,))

                        if alert_check_result and alert_check_result['slack_alert_sent_at'] is None:
                            # Get vendor name for Slack notification
                            vendor_query = "SELECT vendor_name FROM vendors WHERE domain = %s"
                            vendor_result = db.execute_single_query(vendor_query, (domain,))
                            vendor_name = vendor_result['vendor_name'] if vendor_result else 'Unknown Vendor'

                            # Import Slack notification function
                            from slack.slack_service import send_critical_incident_alert

                            incident_data = {
                                'id': news_id,
                                'title': title,
                                'description': description,
                                'severity': severity,
                                'date': event_date.isoformat() if hasattr(event_date, 'isoformat') else str(event_date),
                                'source': source_url,  # Include source URL for Slack alerts
                                'created_at': None  # Will be set automatically
                            }

                            slack_success = send_critical_incident_alert(vendor_name, domain, incident_data)
                            if slack_success:
                                # Mark alert as sent
                                update_alert_query = "UPDATE news SET slack_alert_sent_at = NOW() WHERE id = %s"
                                db.execute_insert(update_alert_query, (news_id,))
                                logger.info(f"Slack notification sent for critical incident: {title}")
                            else:
                                logger.warning(f"Failed to send Slack notification for critical incident: {title}")
                        else:
                            logger.debug(f"Slack alert already sent for incident {title} (ID: {news_id})")

                    except Exception as slack_error:
                        logger.error(f"Error sending Slack notification for incident {title}: {slack_error}")
                        # Don't fail the news item save if Slack notification fails

                return news_id

        except Exception as e:
            logger.error(f"Error storing news item for domain {domain}: {e}")
            return None
    
    def store_news_batch(self, domain, news_items):
        """Store multiple news/incident items for a domain with deduplication"""
        # Import deduplication module
        try:
            from deduplication import filter_out_duplicates, sanitize_news_items
            deduplication_available = True
        except ImportError:
            logger.warning("Deduplication module not available, proceeding without it")
            deduplication_available = False
        
        stored_count = 0
        duplicates_skipped = 0
        
        # Apply deduplication if available
        if deduplication_available:
            try:
                # Sanitize new items
                sanitized_items = sanitize_news_items(news_items)
                
                # Get existing items for this domain
                existing_data = self.get_news_for_domain(domain, months=12)
                existing_items = existing_data.get('incidents', []) + existing_data.get('news', [])
                
                # Filter out duplicates
                filtered_items, duplicate_indices = filter_out_duplicates(
                    sanitized_items,
                    existing_items
                )
                
                duplicates_skipped = len(duplicate_indices)
                news_items = filtered_items
                
                if duplicates_skipped > 0:
                    logger.info(
                        f"[Deduplication] Skipped {duplicates_skipped} duplicate item(s) "
                        f"for domain {domain}. Storing {len(filtered_items)} new items."
                    )
            except Exception as e:
                logger.warning(f"Deduplication error for {domain}: {e}, proceeding without it")
                # Continue without deduplication if it fails
        
        for item in news_items:
            try:
                # Parse date
                event_date = item.get('date', '')
                if not event_date:
                    event_date = datetime.now().date()
                elif isinstance(event_date, str):
                    try:
                        event_date = datetime.strptime(event_date, '%Y-%m-%d').date()
                    except:
                        event_date = datetime.now().date()
                
                # Determine event type and severity
                event_type = item.get('type', 'News').title()
                if event_type not in ['Incident', 'News']:
                    event_type = 'News'
                
                severity = item.get('severity', 'Low').title()
                if severity not in ['Low', 'Medium', 'High', 'Critical']:
                    severity = 'Low'
                
                # Store the item
                result = self.store_news_item(
                    domain=domain,
                    event_date=event_date,
                    title=item.get('title', 'Untitled')[:255],  # Limit title length
                    description=item.get('description', '')[:1000],  # Limit description length
                    severity=severity,
                    source_url=item.get('source', '#')[:500],  # Limit URL length
                    event_type=event_type
                )
                
                if result:
                    stored_count += 1
                    
            except Exception as e:
                logger.error(f"Error storing individual news item: {e}")
                continue
        
        logger.info(
            f"Stored {stored_count} news items for domain {domain} "
            f"(skipped {duplicates_skipped} duplicates)"
        )
        return stored_count
    
    def get_news_for_domain(self, domain, months=12):
        """Filter and retrieve existing news/incidents for a domain from database only (no AI fetching)"""
        # Remove duplicates before retrieving data
        try:
            duplicate_count = self.remove_duplicate_news()
            if duplicate_count > 0:
                logger.info(f"Automatically removed {duplicate_count} duplicate news entries before retrieval for domain {domain}")
        except Exception as e:
            logger.warning(f"Failed to remove duplicates before retrieval for domain {domain}: {e}")
        
        query = """
        SELECT id, domain, event_date, title, description, severity, 
               source_url, event_type, created_at
        FROM news 
        WHERE domain = %s 
          AND event_date >= CURRENT_DATE - INTERVAL %s
          AND event_date <= CURRENT_DATE
        ORDER BY event_date DESC, created_at DESC
        """
        
        # Query to get the last scan time for this domain
        last_scan_query = """
        SELECT MAX(created_at) as last_scan_time
        FROM news 
        WHERE domain = %s
        """
        
        try:
            with DatabaseConnection() as db:
                # Get the filtered news results
                results = db.execute_query(query, (domain, f"{months} months"))
                
                # Get the last scan time for this domain
                last_scan_result = db.execute_query(last_scan_query, (domain,))
                last_scan_time = None
                if last_scan_result and last_scan_result[0]['last_scan_time']:
                    last_scan_time = last_scan_result[0]['last_scan_time'].isoformat()
                
                if results:
                    news_items = []
                    incidents = []
                    
                    for row in results:
                        item = {
                            'id': row['id'],
                            'date': row['event_date'].isoformat() if row['event_date'] else '',
                            'title': row['title'],
                            'description': row['description'],
                            'severity': row['severity'],
                            'source': row['source_url'],
                            'type': row['event_type'].lower(),
                            'created_at': row['created_at'].isoformat() if row['created_at'] else None
                        }
                        
                        if row['event_type'].lower() == 'incident':
                            incidents.append(item)
                        else:
                            news_items.append(item)
                    
                    return {
                        'domain': domain,
                        'incidents': incidents,
                        'news': news_items,
                        'total_count': len(results),
                        'last_scan_time': last_scan_time
                    }
                return {
                    'domain': domain,
                    'incidents': [],
                    'news': [],
                    'total_count': 0,
                    'last_scan_time': last_scan_time
                }
                
        except Exception as e:
            logger.error(f"Error retrieving news for domain {domain}: {e}")
            return {
                'domain': domain,
                'incidents': [],
                'news': [],
                'total_count': 0,
                'error': str(e)
            }
    
    def get_all_news(self, months=12):
        """Get all recent news items across all domains"""
        # Remove duplicates before retrieving data
        try:
            duplicate_count = self.remove_duplicate_news()
            if duplicate_count > 0:
                logger.info(f"Automatically removed {duplicate_count} duplicate news entries before retrieval")
        except Exception as e:
            logger.warning(f"Failed to remove duplicates before retrieval: {e}")
        
        query = """
        SELECT n.id, n.domain, n.event_date, n.title, n.description, 
               n.severity, n.source_url, n.event_type, n.created_at,
               v.vendor_name
        FROM news n
        LEFT JOIN vendors v ON n.domain = v.domain
        WHERE n.event_date >= CURRENT_DATE - INTERVAL %s
          AND n.event_date <= CURRENT_DATE
        ORDER BY n.event_date DESC, n.created_at DESC
        """
        
        # Query to get the last scan time across all domains
        last_scan_query = """
        SELECT MAX(created_at) as last_scan_time
        FROM news
        """
        
        try:
            with DatabaseConnection() as db:
                # Get the filtered news results
                results = db.execute_query(query, (f"{months} months",))
                
                # Get the last scan time across all domains
                last_scan_result = db.execute_query(last_scan_query)
                last_scan_time = None
                if last_scan_result and last_scan_result[0]['last_scan_time']:
                    last_scan_time = last_scan_result[0]['last_scan_time'].isoformat()
                
                news_items = []
                if results:
                    news_items = [{
                        'id': row['id'],
                        'domain': row['domain'],
                        'vendor_name': row['vendor_name'],
                        'date': row['event_date'].isoformat() if row['event_date'] else '',
                        'title': row['title'],
                        'description': row['description'],
                        'severity': row['severity'],
                        'source': row['source_url'],
                        'type': row['event_type'],
                        'created_at': row['created_at'].isoformat() if row['created_at'] else None
                    } for row in results]
                
                return {
                    'items': news_items,
                    'last_scan_time': last_scan_time
                }
                
        except Exception as e:
            logger.error(f"Error retrieving all news: {e}")
            return {
                'items': [],
                'last_scan_time': None
            }
    
    def has_recent_news(self, domain, days=None, hours=None):
        """Check if domain has news/incidents from the last N days or hours"""
        if hours is not None:
            interval = f"'{hours} hours'"
            time_desc = f"{hours}h"
        elif days is not None:
            interval = f"'{days} days'"
            time_desc = f"{days}d"
        else:
            # Default to 7 days for backward compatibility
            interval = "'7 days'"
            time_desc = "7d"
            
        query = f"""
        SELECT COUNT(*) as count
        FROM news 
        WHERE domain = %s 
          AND created_at >= NOW() - INTERVAL {interval}
        """
        
        try:
            with DatabaseConnection() as db:
                result = db.execute_query(query, (domain,))
                count = result[0]['count'] if result else 0
                logger.debug(f"Domain {domain} has {count} news items in last {time_desc}")
                return count > 0
                
        except Exception as e:
            logger.error(f"Error checking recent news for domain {domain}: {e}")
            return False
    
    def cleanup_old_news(self):
        """Manually trigger cleanup of old news records"""
        query = "SELECT manual_cleanup_old_news()"
        
        try:
            with DatabaseConnection() as db:
                result = db.execute_query(query)
                deleted_count = result[0]['manual_cleanup_old_news'] if result else 0
                logger.info(f"Cleaned up {deleted_count} old news records")
                return deleted_count
                
        except Exception as e:
            logger.error(f"Error during manual news cleanup: {e}")
            return 0
    
    def remove_duplicate_news(self):
        """Remove duplicate news entries based on domain, title, event_date, and event_type"""
        try:
            with DatabaseConnection() as db:
                # Find and remove duplicates, keeping the most recent one
                cleanup_query = """
                WITH duplicate_news AS (
                    SELECT 
                        id,
                        ROW_NUMBER() OVER (
                            PARTITION BY title, event_date, event_type 
                            ORDER BY created_at DESC
                        ) as rn
                    FROM news
                )
                DELETE FROM news 
                WHERE id IN (
                    SELECT id FROM duplicate_news WHERE rn > 1
                )
                """
                
                # Get count of duplicates before deletion
                count_query = """
                WITH duplicate_news AS (
                    SELECT 
                        id,
                        ROW_NUMBER() OVER (
                            PARTITION BY domain, title, event_date, event_type 
                            ORDER BY created_at DESC
                        ) as rn
                    FROM news
                )
                SELECT COUNT(*) as duplicate_count FROM duplicate_news WHERE rn > 1
                """
                
                # Count duplicates first
                count_result = db.execute_query(count_query)
                duplicate_count = count_result[0]['duplicate_count'] if count_result else 0
                
                if duplicate_count > 0:
                    # Remove duplicates
                    db.execute_insert(cleanup_query)
                    logger.info(f"Removed {duplicate_count} duplicate news entries")
                    return duplicate_count
                else:
                    logger.info("No duplicate news entries found")
                    return 0
                    
        except Exception as e:
            logger.error(f"Error removing duplicate news: {e}")
            return 0

def _normalize_domain(domain):
    """Normalize domain by stripping whitespace, converting to lowercase, and removing trailing slashes"""
    if not domain or not isinstance(domain, str):
        return None
    return domain.strip().rstrip('/').lower()

def add_additional_domain_to_vendor(vendor_id, new_domain):
    """Add a new domain to the additional_domains JSONB field for a vendor"""
    import json
    try:
        with DatabaseConnection() as db:
            # First, get the current additional_domains for this vendor
            current_query = """
            SELECT additional_domains, vendor_name, domain as primary_domain 
            FROM vendors 
            WHERE id = %s
            """
            
            vendor_result = db.execute_single_query(current_query, (vendor_id,))
            
            if not vendor_result:
                logger.error(f"No vendor found with ID: {vendor_id}")
                return {'success': False, 'error': 'Vendor not found'}
            
            # Get current additional domains (default to empty array if None)
            current_domains = vendor_result['additional_domains'] or []
            
            # Validate that the new domain is not empty and not already exists
            if not new_domain or not new_domain.strip():
                return {'success': False, 'error': 'Domain cannot be empty'}
            
            new_domain = _normalize_domain(new_domain)
            
            # Check if domain is already the primary domain
            primary_domain_normalized = _normalize_domain(vendor_result['primary_domain'])
            if new_domain == primary_domain_normalized:
                return {'success': False, 'error': 'Domain is already the primary domain for this vendor'}
            
            # Check if domain already exists in additional_domains (normalize existing domains too)
            normalized_current_domains = [_normalize_domain(d) for d in current_domains if _normalize_domain(d)]
            if new_domain in normalized_current_domains:
                return {'success': False, 'error': 'Domain already exists in additional domains'}
            
            # Check if domain already exists as primary domain for another vendor
            domain_check_query = "SELECT vendor_name FROM vendors WHERE LOWER(domain) = %s AND id != %s"
            existing_vendor = db.execute_single_query(domain_check_query, (new_domain, vendor_id))
            
            if existing_vendor:
                return {
                    'success': False, 
                    'error': f'Domain is already the primary domain for {existing_vendor["vendor_name"]}'
                }
            
            # Normalize all existing domains and add the new one (store normalized)
            normalized_existing = [_normalize_domain(d) for d in current_domains if _normalize_domain(d)]
            # Remove duplicates and add new domain
            updated_domains = list(set(normalized_existing + [new_domain]))
            
            # Update the database
            update_query = """
            UPDATE vendors 
            SET additional_domains = %s::jsonb
            WHERE id = %s
            """
            
            success = db.execute_insert(update_query, (json.dumps(updated_domains), vendor_id))
            
            if success:
                logger.info(f"Successfully added domain '{new_domain}' to vendor {vendor_result['vendor_name']} (ID: {vendor_id})")
                return {
                    'success': True, 
                    'message': f'Domain "{new_domain}" added successfully',
                    'additional_domains': updated_domains
                }
            else:
                logger.error(f"Failed to update additional_domains for vendor ID: {vendor_id}")
                return {'success': False, 'error': 'Database update failed'}
                
    except Exception as e:
        logger.error(f"Error adding additional domain to vendor {vendor_id}: {e}")
        return {'success': False, 'error': f'Server error: {str(e)}'}

def get_vendor_additional_domains(vendor_id):
    """Get the additional domains for a vendor"""
    try:
        with DatabaseConnection() as db:
            query = """
            SELECT additional_domains, vendor_name, domain as primary_domain 
            FROM vendors 
            WHERE id = %s
            """
            
            result = db.execute_single_query(query, (vendor_id,))
            
            if not result:
                return {'success': False, 'error': 'Vendor not found'}
            
            return {
                'success': True,
                'vendor_name': result['vendor_name'],
                'primary_domain': result['primary_domain'],
                'additional_domains': result['additional_domains'] or []
            }
            
    except Exception as e:
        logger.error(f"Error getting additional domains for vendor {vendor_id}: {e}")
        return {'success': False, 'error': f'Server error: {str(e)}'}

def remove_additional_domain_from_vendor(vendor_id, domain_to_remove):
    """Remove a domain from the additional_domains JSONB field for a vendor"""
    import json
    try:
        with DatabaseConnection() as db:
            # Get current additional_domains
            current_query = """
            SELECT additional_domains, vendor_name 
            FROM vendors 
            WHERE id = %s
            """
            
            vendor_result = db.execute_single_query(current_query, (vendor_id,))
            
            if not vendor_result:
                logger.warning(f"Vendor {vendor_id} not found when trying to remove domain")
                return {'success': False, 'error': 'Vendor not found'}
            
            current_domains = vendor_result['additional_domains'] or []
            domain_to_remove = _normalize_domain(domain_to_remove)
            
            if not domain_to_remove:
                return {'success': False, 'error': 'Invalid domain provided'}
            
            # Log for debugging
            logger.info(f"Attempting to remove domain '{domain_to_remove}' from vendor {vendor_id}. Current domains: {current_domains}")
            
            # Normalize all domains for comparison (strip trailing slashes)
            normalized_current_domains = [_normalize_domain(d) for d in current_domains if _normalize_domain(d)]
            
            # Check if domain exists in the list (normalized comparison)
            if domain_to_remove not in normalized_current_domains:
                logger.warning(f"Domain '{domain_to_remove}' not found in additional domains list: {current_domains}")
                return {'success': False, 'error': f'Domain "{domain_to_remove}" not found in additional domains. Available domains: {", ".join(current_domains) if current_domains else "none"}'}
            
            # Remove the domain (normalized comparison) and store normalized domains
            updated_domains = [_normalize_domain(d) for d in current_domains if _normalize_domain(d) and _normalize_domain(d) != domain_to_remove]
            
            # Update the database
            update_query = """
            UPDATE vendors 
            SET additional_domains = %s::jsonb
            WHERE id = %s
            """
            
            success = db.execute_insert(update_query, (json.dumps(updated_domains), vendor_id))
            
            if success:
                logger.info(f"Successfully removed domain '{domain_to_remove}' from vendor {vendor_result['vendor_name']} (ID: {vendor_id})")
                return {
                    'success': True,
                    'message': f'Domain "{domain_to_remove}" removed successfully',
                    'additional_domains': updated_domains
                }
            else:
                logger.error(f"Database update failed when removing domain '{domain_to_remove}' from vendor {vendor_id}")
                return {'success': False, 'error': 'Database update failed'}
                
    except Exception as e:
        logger.error(f"Error removing additional domain from vendor {vendor_id}: {e}", exc_info=True)
        return {'success': False, 'error': f'Server error: {str(e)}'}


# ===== SUBDOMAIN EXCLUSION MANAGEMENT =====

def add_subdomain_to_exclusion_list(vendor_id, subdomain):
    """Add a subdomain to the exclusion list and remove it from active subdomains"""
    try:
        with DatabaseConnection() as db:
            # Get vendor info
            vendor_query = "SELECT domain, vendor_name FROM vendors WHERE id = %s"
            vendor_result = db.execute_single_query(vendor_query, (vendor_id,))
            
            if not vendor_result:
                logger.error(f"Vendor with ID {vendor_id} not found")
                return {"success": False, "error": "Vendor not found"}
            
            domain = vendor_result['domain']
            vendor_name = vendor_result['vendor_name']
            
            # Check if already excluded
            check_query = "SELECT id FROM excluded_subdomains WHERE vendor_id = %s AND subdomain = %s"
            existing = db.execute_single_query(check_query, (vendor_id, subdomain))
            
            if existing:
                logger.warning(f"Subdomain '{subdomain}' is already excluded for vendor {vendor_name}")
                return {"success": False, "error": "Subdomain already excluded"}
            
            # Add to exclusion list
            insert_query = """
            INSERT INTO excluded_subdomains (vendor_id, domain, subdomain)
            VALUES (%s, %s, %s)
            """
            success = db.execute_insert(insert_query, (vendor_id, domain, subdomain))
            
            if success:
                # Remove from active subdomains table
                delete_query = "DELETE FROM subdomains WHERE vendor_id = %s AND subdomain = %s"
                db.execute_insert(delete_query, (vendor_id, subdomain))
                
                logger.info(f"Successfully excluded subdomain '{subdomain}' for vendor {vendor_name} (ID: {vendor_id})")
                return {"success": True, "message": f"Subdomain '{subdomain}' excluded successfully"}
            else:
                logger.error(f"Failed to exclude subdomain '{subdomain}' for vendor {vendor_id}")
                return {"success": False, "error": "Database insert failed"}
                
    except Exception as e:
        logger.error(f"Error excluding subdomain '{subdomain}' for vendor {vendor_id}: {e}")
        return {"success": False, "error": str(e)}


def remove_subdomain_from_exclusion_list(vendor_id, subdomain):
    """Remove a subdomain from the exclusion list (allow it to be discovered again)"""
    try:
        with DatabaseConnection() as db:
            # Check if subdomain is excluded
            check_query = "SELECT id FROM excluded_subdomains WHERE vendor_id = %s AND subdomain = %s"
            existing = db.execute_single_query(check_query, (vendor_id, subdomain))
            
            if not existing:
                logger.warning(f"Subdomain '{subdomain}' is not in exclusion list for vendor {vendor_id}")
                return {"success": False, "error": "Subdomain not found in exclusion list"}
            
            # Remove from exclusion list
            delete_query = "DELETE FROM excluded_subdomains WHERE vendor_id = %s AND subdomain = %s"
            success = db.execute_insert(delete_query, (vendor_id, subdomain))
            
            if success:
                # Get vendor name for logging
                vendor_query = "SELECT vendor_name FROM vendors WHERE id = %s"
                vendor_result = db.execute_single_query(vendor_query, (vendor_id,))
                vendor_name = vendor_result['vendor_name'] if vendor_result else f"ID:{vendor_id}"
                
                logger.info(f"Successfully removed subdomain '{subdomain}' from exclusion list for vendor {vendor_name} (ID: {vendor_id})")
                return {"success": True, "message": f"Subdomain '{subdomain}' removed from exclusion list"}
            else:
                logger.error(f"Failed to remove subdomain '{subdomain}' from exclusion list for vendor {vendor_id}")
                return {"success": False, "error": "Database delete failed"}
                
    except Exception as e:
        logger.error(f"Error removing subdomain '{subdomain}' from exclusion list for vendor {vendor_id}: {e}")
        return {"success": False, "error": str(e)}


def get_excluded_subdomains_for_vendor(vendor_id):
    """Get all excluded subdomains for a vendor"""
    try:
        with DatabaseConnection() as db:
            query = """
            SELECT subdomain, excluded_at
            FROM excluded_subdomains 
            WHERE vendor_id = %s
            ORDER BY excluded_at DESC
            """
            results = db.execute_query(query, (vendor_id,))
            
            if results:
                excluded_list = []
                for row in results:
                    excluded_list.append({
                        'subdomain': row['subdomain'],
                        'excluded_at': row['excluded_at'].isoformat() if row['excluded_at'] else None
                    })
                
                logger.info(f"Retrieved {len(excluded_list)} excluded subdomains for vendor {vendor_id}")
                return {"success": True, "excluded_subdomains": excluded_list}
            else:
                logger.info(f"No excluded subdomains found for vendor {vendor_id}")
                return {"success": True, "excluded_subdomains": []}
                
    except Exception as e:
        logger.error(f"Error retrieving excluded subdomains for vendor {vendor_id}: {e}")
        return {"success": False, "error": str(e)}


def get_excluded_subdomains_set(vendor_id):
    """Get excluded subdomains as a set for efficient filtering during discovery"""
    try:
        with DatabaseConnection() as db:
            query = "SELECT subdomain FROM excluded_subdomains WHERE vendor_id = %s"
            results = db.execute_query(query, (vendor_id,))
            
            if results:
                excluded_set = {row['subdomain'] for row in results}
                logger.debug(f"Retrieved {len(excluded_set)} excluded subdomains for filtering (vendor {vendor_id})")
                return excluded_set
            else:
                return set()
                
    except Exception as e:
        logger.error(f"Error retrieving excluded subdomains set for vendor {vendor_id}: {e}")
        return set()


class AiAnalyticsService:
    """
    Service for caching AI-generated analytics summaries per domain.
    Used to avoid unnecessary model calls when vulnerabilities have not changed.
    """

    def get_cached_summary(self, domain: str, vulnerability_count: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """
        Retrieve cached AI summary for a domain. Optionally constrain by vulnerability count.
        Returns None if no matching cache entry exists.
        """
        query = """
        SELECT domain, vendor_name, ai_summary, vulnerability_count, updated_at
        FROM ai_analytics
        WHERE domain = %s
        """
        params: list = [domain]

        if vulnerability_count is not None:
            query += " AND vulnerability_count = %s"
            params.append(vulnerability_count)

        try:
            with DatabaseConnection() as db:
                result = db.execute_query(query, tuple(params))
                if result and len(result) > 0:
                    # Convert vulnerability_count to int if it exists (handle string/int mismatches)
                    vuln_count = result[0].get('vulnerability_count')
                    if vuln_count is not None:
                        try:
                            vuln_count = int(vuln_count)
                        except (ValueError, TypeError):
                            vuln_count = None
                    
                    return {
                        'domain': result[0]['domain'],
                        'vendor_name': result[0]['vendor_name'],
                        'ai_summary': result[0]['ai_summary'],
                        'vulnerability_count': vuln_count,
                        'updated_at': result[0]['updated_at'].isoformat() if result[0]['updated_at'] else None
                    }
                return None
        except Exception as e:
            logger.error(f"Error retrieving cached AI summary for {domain}: {e}")
            return None

    def should_generate(self, domain: str, vulnerability_count: Optional[int] = None) -> bool:
        """
        Determine whether a new AI summary should be generated.
        - If no cache exists, return True.
        - If a count is provided and differs from cached count, return True.
        - Otherwise, return False (reuse cached summary).
        """
        cached = self.get_cached_summary(domain)
        if not cached:
            return True

        if vulnerability_count is not None and cached.get("vulnerability_count") != vulnerability_count:
            return True

        return False

    def upsert_summary(
        self,
        domain: str,
        vendor_name: str,
        ai_summary: str,
        vulnerability_count: Optional[int] = None
    ) -> Optional[int]:
        """
        Insert or update the AI summary for a domain. Returns the record ID if successful.
        """
        query = """
        INSERT INTO ai_analytics (domain, vendor_name, ai_summary, vulnerability_count, updated_at)
        VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP)
        ON CONFLICT (domain) DO UPDATE SET
            vendor_name = EXCLUDED.vendor_name,
            ai_summary = EXCLUDED.ai_summary,
            vulnerability_count = EXCLUDED.vulnerability_count,
            updated_at = CURRENT_TIMESTAMP
        RETURNING id
        """

        try:
            with DatabaseConnection() as db:
                # Check connection before executing
                if not db.connection or db.connection.closed:
                    logger.error(f"Database connection is closed for domain {domain}")
                    return None
                
                # Execute the INSERT/UPDATE query
                db.cursor.execute(query, (domain, vendor_name, ai_summary, vulnerability_count))
                
                # Fetch result before commit
                result = db.cursor.fetchone()
                
                # Commit the transaction
                db.connection.commit()
                
                if result:
                    record_id = result['id']
                    logger.info(f"Successfully upserted AI analytics for {domain} (ID: {record_id}, vulnerability_count: {vulnerability_count})")
                    return record_id
                else:
                    logger.warning(f"upsert_summary query returned no result for {domain}")
                    return None
        except Exception as e:
            import traceback
            logger.error(f"Error upserting AI analytics for {domain}: {e}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            if db.connection:
                db.connection.rollback()
            return None

    def get_or_reuse_summary(
        self,
        domain: str,
        vulnerability_count: Optional[int] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Return the cached summary if vulnerability count hasn't increased.
        Only regenerates when count increases (new vulnerabilities found).
        Returns None if a refresh is needed (count increased or no cache exists).
        """
        cached = self.get_cached_summary(domain)
        if cached:
            cached_count = cached.get("vulnerability_count")
            
            # If no count provided in request, reuse cache
            if vulnerability_count is None:
                logger.info(f"Reusing cached summary for {domain} (no count provided)")
                return cached
            
            # If cached count is None (old record), reuse cache but log it
            # This handles old records created before vulnerability_count was added
            if cached_count is None:
                logger.info(f"Reusing cached summary for {domain} (old record without vulnerability_count)")
                return cached
            
            # Convert to int for comparison (handle string/int mismatches)
            try:
                cached_count_int = int(cached_count) if cached_count is not None else None
                current_count_int = int(vulnerability_count) if vulnerability_count is not None else None
            except (ValueError, TypeError):
                logger.warning(f"Invalid vulnerability_count values for {domain}: cached={cached_count}, current={vulnerability_count}")
                return cached  # Reuse cache if we can't compare
            
            # Only regenerate if count increased (new vulnerabilities found)
            if current_count_int is not None and cached_count_int is not None:
                if current_count_int > cached_count_int:
                    logger.info(f"Vulnerability count increased for {domain}: {cached_count_int} -> {current_count_int}, will regenerate")
                    return None
                elif current_count_int == cached_count_int:
                    logger.info(f"Reusing cached summary for {domain} (vulnerability count unchanged: {current_count_int})")
                else:
                    logger.info(f"Reusing cached summary for {domain} (vulnerability count decreased: {cached_count_int} -> {current_count_int})")
            
            # Reuse cache if count stayed same or decreased
            return cached
        return None


class BreachMonitorRecordsService:
    """PostgreSQL storage for breach platform breach breach API results.

    All database operations in this class connect to the vendiant_breaches
    database via BreachMonitorDatabaseConnection (controlled by DB_NAME_BREACHES
    env var) rather than the main vendiant_dashboard database.
    """

    _UPSERT_SQL = """
    INSERT INTO breach_monitor_records (
        breach_monitor_uid, record_type, validated,
        email, domain, username, web_address, fullname, information_display_name,
        address, city, company, country, state, zip, telephone, date_register, dob, network_ip_ipv4_number,
        password_exposed, event_at,
        information,
        incident_name, source_channel, source_record_type, breach_classification,
        confidence, url_source, source_url, score_attribution, score_authentication,
        source_description, recommendations,
        source
    ) VALUES (
        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
    )
    ON CONFLICT (breach_monitor_uid) DO UPDATE SET
        record_type = EXCLUDED.record_type,
        validated = EXCLUDED.validated,
        email = EXCLUDED.email,
        domain = EXCLUDED.domain,
        username = EXCLUDED.username,
        web_address = EXCLUDED.web_address,
        fullname = EXCLUDED.fullname,
        information_display_name = EXCLUDED.information_display_name,
        address = EXCLUDED.address,
        city = EXCLUDED.city,
        company = EXCLUDED.company,
        country = EXCLUDED.country,
        state = EXCLUDED.state,
        zip = EXCLUDED.zip,
        telephone = EXCLUDED.telephone,
        date_register = EXCLUDED.date_register,
        dob = EXCLUDED.dob,
        network_ip_ipv4_number = EXCLUDED.network_ip_ipv4_number,
        password_exposed = EXCLUDED.password_exposed,
        event_at = EXCLUDED.event_at,
        information = EXCLUDED.information,
        incident_name = EXCLUDED.incident_name,
        source_channel = EXCLUDED.source_channel,
        source_record_type = EXCLUDED.source_record_type,
        breach_classification = EXCLUDED.breach_classification,
        confidence = EXCLUDED.confidence,
        url_source = EXCLUDED.url_source,
        source_url = EXCLUDED.source_url,
        score_attribution = EXCLUDED.score_attribution,
        score_authentication = EXCLUDED.score_authentication,
        source_description = EXCLUDED.source_description,
        recommendations = EXCLUDED.recommendations,
        source = EXCLUDED.source,
        updated_at = NOW()
    """

    # Schema check runs once per process: the service is instantiated per
    # request (every Breach Monitor webhook), and running CREATE/ALTER each time cost
    # an extra pooled connection per webhook, enough to exhaust the pool under
    # a delivery burst.
    _schema_ready = False
    _schema_lock = threading.Lock()

    def __init__(self):
        self.db = BreachMonitorDatabaseConnection()
        self._ensure_table_exists()

    def _ensure_table_exists(self) -> None:
        cls = BreachMonitorRecordsService
        if cls._schema_ready:
            return
        with cls._schema_lock:
            if cls._schema_ready:
                return
            cls._schema_ready = self._create_or_migrate_table()

    def _create_or_migrate_table(self) -> bool:
        create_table_sql = """
        CREATE TABLE IF NOT EXISTS breach_monitor_records (
            id BIGSERIAL PRIMARY KEY,
            breach_monitor_uid TEXT NOT NULL,
            record_type TEXT NOT NULL DEFAULT 'breach',
            validated SMALLINT NOT NULL DEFAULT 0,
            email TEXT,
            domain TEXT,
            username TEXT,
            web_address TEXT,
            fullname TEXT,
            information_display_name TEXT,
            address TEXT,
            city TEXT,
            company TEXT,
            country TEXT,
            state TEXT,
            zip TEXT,
            telephone TEXT,
            date_register TEXT,
            dob TEXT,
            network_ip_ipv4_number TEXT,
            password_exposed SMALLINT NOT NULL DEFAULT 0,
            event_at TIMESTAMPTZ,
            information JSONB NOT NULL DEFAULT '{}'::jsonb,
            incident_name TEXT,
            source_channel TEXT,
            source_record_type TEXT,
            breach_classification TEXT,
            confidence TEXT,
            url_source TEXT,
            source_url TEXT,
            score_attribution INTEGER,
            score_authentication INTEGER,
            source_description TEXT,
            recommendations TEXT,
            source JSONB NOT NULL DEFAULT '{}'::jsonb,
            ingested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            CONSTRAINT breach_monitor_records_uid_unique UNIQUE (breach_monitor_uid)
        );
        """
        migrate_sql = """
        ALTER TABLE breach_monitor_records
            ADD COLUMN IF NOT EXISTS client_slack_alert_sent_at TIMESTAMPTZ;
        ALTER TABLE breach_monitor_records
            ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active';
        """
        try:
            with BreachMonitorDatabaseConnection() as db:
                if not db.execute_insert(create_table_sql):
                    return False
                logger.info("breach_monitor_records table verified/created successfully")
                return bool(db.execute_insert(migrate_sql))
        except Exception as e:
            logger.error(f"Error ensuring breach_monitor_records table exists: {e}")
            return False

    @staticmethod
    def _parse_information_date(raw: Any) -> Optional[datetime]:
        if raw is None:
            return None
        if isinstance(raw, datetime):
            if raw.tzinfo is None:
                return raw.replace(tzinfo=timezone.utc)
            return raw
        s = str(raw).strip()
        if not s:
            return None
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d"):
            try:
                return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        try:
            return datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            return None

    @staticmethod
    def _int_or_none(value: Any) -> Optional[int]:
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _resolve_information_dict(inf: Dict[str, Any]) -> Dict[str, Any]:
        try:
            from Dashboard.breach_monitor_webhook import resolve_stored_information
        except ImportError:
            from breach_monitor_webhook import resolve_stored_information
        return resolve_stored_information(inf)

    @staticmethod
    def _row_tuple_from_api_result(r: Dict[str, Any]) -> Optional[tuple]:
        from psycopg2.extras import Json

        inf = BreachMonitorRecordsService._resolve_information_dict(r.get("information") or {})
        src = r.get("source") or {}
        uid = (inf.get("uid") or "").strip()
        if not uid:
            return None

        pwd_raw = inf.get("password")
        try:
            password_exposed = int(pwd_raw) if pwd_raw is not None else 0
        except (TypeError, ValueError):
            password_exposed = 0

        event_at = BreachMonitorRecordsService._parse_information_date(inf.get("date"))

        return (
            uid,
            r.get("type") or "breach",
            int(r.get("validated", 0) or 0),
            inf.get("email"),
            inf.get("domain"),
            inf.get("username"),
            inf.get("web_address"),
            inf.get("fullname"),
            inf.get("name"),
            inf.get("address"),
            inf.get("city"),
            inf.get("company"),
            inf.get("country"),
            inf.get("state"),
            inf.get("zip"),
            inf.get("telephone"),
            inf.get("date_register"),
            inf.get("dob"),
            inf.get("network_ip_ipv4_number"),
            password_exposed,
            event_at,
            Json(inf),
            src.get("name"),
            src.get("source"),
            src.get("type"),
            src.get("breach_type"),
            src.get("confidence"),
            src.get("url_source"),
            src.get("url"),
            BreachMonitorRecordsService._int_or_none(src.get("score_attribution")),
            BreachMonitorRecordsService._int_or_none(src.get("score_authentication")),
            src.get("description"),
            src.get("recommendations"),
            Json(src),
        )

    def _fetch_existing_breach_monitor_uids(self, uids: List[str]) -> Set[str]:
        """Return the subset of ``uids`` that already exist in breach_monitor_records."""
        uniq = list(dict.fromkeys(uids))
        if not uniq:
            return set()
        q = """
            SELECT breach_monitor_uid FROM breach_monitor_records
            WHERE breach_monitor_uid = ANY(%s)
        """
        try:
            with BreachMonitorDatabaseConnection() as db:
                rows = db.execute_query(q, (uniq,))
                if not rows:
                    return set()
                return {
                    str(r.get("breach_monitor_uid", ""))
                    for r in rows
                    if r.get("breach_monitor_uid")
                }
        except Exception as e:
            logger.error(f"Breach Monitor _fetch_existing_breach_monitor_uids: {e}")
            return set()

    @staticmethod
    def breach_monitor_api_result_to_credential_leak_alert(api_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build a dict compatible with :func:`slack.slack_service.format_single_alert_message`
        for ``scan_type == 'Credential Leak'`` (same layout as credential-leak Slack alerts).
        """
        try:
            from breach_monitor_export import breach_is_employee_record
        except ImportError:
            from Dashboard.breach_monitor_export import breach_is_employee_record

        inf = BreachMonitorRecordsService._resolve_information_dict(
            api_result.get("information") or {}
        )

        # Same employee-vs-client classification used by the dashboard/export
        # (information.domain in EMPLOYEE_EMAIL_DOMAINS), so Slack alerts stay
        # consistent with how leaks are labeled everywhere else in the app.
        # Classify off the *resolved* information: hashed monitoring records keep
        # the readable domain under information.masked, so classifying the raw
        # payload labeled every employee leak as "client" and dropped it from the
        # immediate employee Slack alert.
        leak_category = (
            "employee" if breach_is_employee_record({"information": inf}) else "client"
        )
        src = api_result.get("source") or {}
        email = (inf.get("email") or "").strip() or "Unknown"
        desc = (src.get("description") or "").strip()
        source_name = (src.get("name") or inf.get("name") or "").strip()
        if not desc:
            desc = (
                f"breach platform breach record"
                + (f" ({source_name})" if source_name else "")
                + "."
            )
        desc = desc[:2000]
        sev_raw = (
            src.get("confidence")
            or src.get("breach_type")
            or src.get("breach_classification")
            or inf.get("breach_classification")
            or "unknown"
        )
        severity = str(sev_raw).strip().lower()[:80] or "unknown"
        pwd_raw = inf.get("password")
        try:
            password_leaked = 1 if int(pwd_raw) != 0 else 0
        except (TypeError, ValueError):
            password_leaked = 1 if pwd_raw else 0
        ts_raw = inf.get("date")
        timestamp = "Unknown"
        if ts_raw is not None:
            timestamp = str(ts_raw).strip()[:80] or "Unknown"
        uid = (inf.get("uid") or "").strip()[:120]
        web_address = (inf.get("web_address") or "").strip()[:500]
        username = (inf.get("username") or "").strip()[:200]
        domain = (inf.get("domain") or "").strip()[:200]
        breach_type = (src.get("breach_type") or "").strip()[:80]
        confidence = (src.get("confidence") or "").strip()[:80]
        record_type = (api_result.get("type") or src.get("type") or "").strip()[:80]
        source_channel = (src.get("source") or "").strip()[:80]
        recommendations = (src.get("recommendations") or "").strip()[:1000]
        ingested_date = (src.get("ingested_date") or "").strip()[:80]
        password_plain = (inf.get("password_plain") or "").strip()
        return {
            "id": uid or "unknown",
            "email": email[:320],
            "username": username,
            "domain": domain,
            "source_name": source_name[:200],
            "breach_type": breach_type,
            "confidence": confidence,
            "record_type": record_type,
            "source_channel": source_channel,
            "severity": severity,
            "description": desc,
            "recommendations": recommendations,
            "password_leaked": password_leaked,
            "password_plain": password_plain,
            "timestamp": timestamp,
            "ingested_date": ingested_date,
            "web_address": web_address,
            "scan_type": "Credential Leak",
            "leak_category": leak_category,
        }

    def upsert_api_results_with_stats(
        self,
        results: List[Dict[str, Any]],
        out_new_summaries: Optional[List[Dict[str, Any]]] = None,
    ) -> Tuple[int, int, int]:
        """
        Upsert Breach Monitor API result objects.

        Returns ``(rows_written, new_uid_rows, rows_updating_existing_uid)``.
        A row counts as *new* when its ``information.uid`` was not in the database before
        this call and is the first occurrence of that uid in this batch; duplicate uids in
        the same batch count as updates after the first.

        If ``out_new_summaries`` is provided, append one :meth:`breach_monitor_api_result_to_credential_leak_alert`
        dict per newly inserted UID (same order as discovery within this batch).
        """
        rows: List[tuple] = []
        row_sources: List[Dict[str, Any]] = []
        skipped = 0
        for r in results:
            if not isinstance(r, dict):
                skipped += 1
                continue
            t = self._row_tuple_from_api_result(r)
            if t is None:
                skipped += 1
                continue
            rows.append(t)
            row_sources.append(r)

        if skipped:
            logger.warning(
                f"Breach Monitor upsert: skipped {skipped} records without information.uid"
            )

        if not rows:
            return (0, 0, 0)

        all_uids = [t[0] for t in rows]
        existing = self._fetch_existing_breach_monitor_uids(all_uids)
        seen_new_in_batch: Set[str] = set()
        new_rows = 0
        upd_rows = 0
        for i, t in enumerate(rows):
            uid = t[0]
            if uid in existing:
                upd_rows += 1
            elif uid in seen_new_in_batch:
                upd_rows += 1
            else:
                new_rows += 1
                seen_new_in_batch.add(uid)
                if out_new_summaries is not None:
                    out_new_summaries.append(
                        self.breach_monitor_api_result_to_credential_leak_alert(row_sources[i])
                    )

        try:
            with BreachMonitorDatabaseConnection() as db:
                ok = db.execute_many(self._UPSERT_SQL, rows)
                if ok:
                    return (len(rows), new_rows, upd_rows)
                logger.error("Breach Monitor upsert: execute_many failed")
                return (0, 0, 0)
        except Exception as e:
            logger.error(f"Breach Monitor upsert error: {e}")
            return (0, 0, 0)

    def upsert_api_results(self, results: List[Dict[str, Any]]) -> int:
        """Upsert Breach Monitor API result objects. Returns number of rows written."""
        written, new_n, upd_n = self.upsert_api_results_with_stats(results)
        if written:
            logger.info(
                "Breach Monitor upsert: %s rows (%s new uid(s), %s update(s))",
                written,
                new_n,
                upd_n,
            )
        return written

    @staticmethod
    def _json_obj(val: Any) -> Dict[str, Any]:
        if isinstance(val, dict):
            return val
        if isinstance(val, str):
            try:
                parsed = json.loads(val)
                return parsed if isinstance(parsed, dict) else {}
            except json.JSONDecodeError:
                return {}
        return {}

    # Allowlisted SQL date expressions for Breach Monitor range filters (never interpolate raw input).
    _BREACH_MONITOR_DATE_FIELD_SQL = {
        "ingested": (
            "COALESCE("
            "NULLIF(TRIM(source->>'ingested_date'), '')::timestamptz, "
            "ingested_at"
            ")::date"
        ),
        "exposure": "event_at::date",
    }

    def _row_to_api_result(self, row: Dict[str, Any], resolve_fn: Any) -> Dict[str, Any]:
        info = self._json_obj(row.get("information"))
        src = self._json_obj(row.get("source"))
        ingested_at = row.get("ingested_at")
        if isinstance(src, dict) and not (src.get("ingested_date") or "").strip():
            if ingested_at is not None:
                ingested_date_str = (
                    ingested_at.strftime("%Y-%m-%d %H:%M:%S")
                    if hasattr(ingested_at, "strftime")
                    else str(ingested_at)[:19]
                )
                src = {**src, "ingested_date": ingested_date_str}
        resolved_at = row.get("resolved_at")
        false_positive_at = row.get("false_positive_at")
        return resolve_fn({
            "type": row.get("record_type") or "breach",
            "information": info,
            "source": src,
            "validated": int(row.get("validated", 0) or 0),
            "breach_monitor_uid": row.get("breach_monitor_uid"),
            "status": row.get("status") or "active",
            "resolved_at": str(resolved_at)[:19] if resolved_at else None,
            "resolved_by": row.get("resolved_by"),
            "false_positive_at": str(false_positive_at)[:19] if false_positive_at else None,
            "false_positive_by": row.get("false_positive_by"),
        })

    @staticmethod
    def _resolve_stored_record_for_display_fn() -> Any:
        try:
            from Dashboard.breach_monitor_webhook import resolve_stored_record_for_display
        except ImportError:
            from breach_monitor_webhook import resolve_stored_record_for_display
        return resolve_stored_record_for_display

    def get_all_api_results(
        self,
        date_from: Optional[date] = None,
        date_to: Optional[date] = None,
        date_field: str = "ingested",
    ) -> List[Dict[str, Any]]:
        """
        Return breach records in the same shape as Breach Monitor API `data.results` items.

        Optional ``date_from`` / ``date_to`` are inclusive filters on the column
        selected by ``date_field``:
        - ``ingested``: displayed ingested date (source.ingested_date, else ingested_at)
        - ``exposure``: event_at (exposure / breach event date)
        """
        field_key = (date_field or "ingested").strip().lower()
        date_expr = self._BREACH_MONITOR_DATE_FIELD_SQL.get(field_key)
        if date_expr is None:
            date_expr = self._BREACH_MONITOR_DATE_FIELD_SQL["ingested"]

        conditions: List[str] = []
        params: List[Any] = []
        if date_from is not None:
            conditions.append(f"{date_expr} >= %s")
            params.append(date_from)
        if date_to is not None:
            conditions.append(f"{date_expr} <= %s")
            params.append(date_to)
        where_clause = ""
        if conditions:
            where_clause = "WHERE " + " AND ".join(conditions)
        query = f"""
        SELECT breach_monitor_uid, record_type, validated, information, source, ingested_at,
               status, resolved_at, resolved_by, false_positive_at, false_positive_by
        FROM breach_monitor_records
        {where_clause}
        ORDER BY COALESCE(
            NULLIF(TRIM(source->>'ingested_date'), '')::timestamptz,
            ingested_at
        ) DESC NULLS LAST, id DESC
        """
        resolve_fn = self._resolve_stored_record_for_display_fn()
        out: List[Dict[str, Any]] = []
        try:
            with BreachMonitorDatabaseConnection() as db:
                rows = db.execute_query(query, tuple(params) if params else None)
                if not rows:
                    return []
                for row in rows:
                    out.append(self._row_to_api_result(row, resolve_fn))
                return out
        except Exception as e:
            logger.error(f"Error loading Breach Monitor breach records: {e}")
            return []

    def get_api_results_by_uids(
        self,
        uids: List[str],
        *,
        batch_size: int = 500,
        date_from: Optional[date] = None,
        date_to: Optional[date] = None,
        date_field: str = "ingested",
    ) -> List[Dict[str, Any]]:
        """
        Load breach records for the given Breach Monitor UIDs in batches.

        Returns results in the same order as ``uids`` (unknown UIDs omitted).
        Optional date range uses the same column semantics as ``get_all_api_results``.
        """
        ordered_uids = [u for u in uids if u]
        if not ordered_uids:
            return []
        if batch_size <= 0:
            batch_size = 500

        field_key = (date_field or "ingested").strip().lower()
        date_expr = self._BREACH_MONITOR_DATE_FIELD_SQL.get(field_key)
        if date_expr is None:
            date_expr = self._BREACH_MONITOR_DATE_FIELD_SQL["ingested"]

        date_conditions: List[str] = []
        date_params: List[Any] = []
        if date_from is not None:
            date_conditions.append(f"{date_expr} >= %s")
            date_params.append(date_from)
        if date_to is not None:
            date_conditions.append(f"{date_expr} <= %s")
            date_params.append(date_to)
        date_sql = (" AND " + " AND ".join(date_conditions)) if date_conditions else ""

        resolve_fn = self._resolve_stored_record_for_display_fn()
        by_uid: Dict[str, Dict[str, Any]] = {}
        query = f"""
        SELECT breach_monitor_uid, record_type, validated, information, source, ingested_at,
               status, resolved_at, resolved_by, false_positive_at, false_positive_by
        FROM breach_monitor_records
        WHERE breach_monitor_uid = ANY(%s){date_sql}
        """
        try:
            with BreachMonitorDatabaseConnection() as db:
                for i in range(0, len(ordered_uids), batch_size):
                    chunk = ordered_uids[i : i + batch_size]
                    params: Tuple[Any, ...] = (chunk, *date_params)
                    rows = db.execute_query(query, params)
                    if not rows:
                        continue
                    for row in rows:
                        uid = str(row.get("breach_monitor_uid") or "").strip()
                        if not uid or uid in by_uid:
                            continue
                        by_uid[uid] = self._row_to_api_result(row, resolve_fn)
        except Exception as e:
            logger.error(f"Error loading Breach Monitor breach records by UID: {e}")
            return []

        return [by_uid[uid] for uid in ordered_uids if uid in by_uid]

    def resolve_breach(self, breach_monitor_uid: str, resolved_by: str) -> bool:
        try:
            with BreachMonitorDatabaseConnection() as db:
                rows = db.execute_query(
                    "SELECT id FROM breach_monitor_records WHERE breach_monitor_uid = %s",
                    (breach_monitor_uid,),
                )
                if not rows:
                    return False
                db.execute_insert(
                    """UPDATE breach_monitor_records
                       SET status = 'resolved', resolved_at = NOW(), resolved_by = %s
                       WHERE breach_monitor_uid = %s""",
                    (resolved_by, breach_monitor_uid),
                )
                return True
        except Exception as e:
            logger.error(f"resolve_breach: {e}")
            return False

    def unresolve_breach(self, breach_monitor_uid: str) -> bool:
        try:
            with BreachMonitorDatabaseConnection() as db:
                rows = db.execute_query(
                    "SELECT id FROM breach_monitor_records WHERE breach_monitor_uid = %s",
                    (breach_monitor_uid,),
                )
                if not rows:
                    return False
                db.execute_insert(
                    """UPDATE breach_monitor_records
                       SET status = 'active', resolved_at = NULL, resolved_by = NULL
                       WHERE breach_monitor_uid = %s""",
                    (breach_monitor_uid,),
                )
                return True
        except Exception as e:
            logger.error(f"unresolve_breach: {e}")
            return False

    def bulk_resolve_breaches(self, breach_monitor_uids: List[str], resolved_by: str) -> int:
        if not breach_monitor_uids:
            return 0
        try:
            with BreachMonitorDatabaseConnection() as db:
                db.execute_insert(
                    """UPDATE breach_monitor_records
                       SET status = 'resolved', resolved_at = NOW(), resolved_by = %s
                       WHERE breach_monitor_uid = ANY(%s)""",
                    (resolved_by, breach_monitor_uids),
                )
                rows = db.execute_query(
                    "SELECT COUNT(*) AS c FROM breach_monitor_records WHERE breach_monitor_uid = ANY(%s) AND status = 'resolved'",
                    (breach_monitor_uids,),
                )
                return int(rows[0]["c"]) if rows else 0
        except Exception as e:
            logger.error(f"bulk_resolve_breaches: {e}")
            return 0

    def bulk_unresolve_breaches(self, breach_monitor_uids: List[str]) -> int:
        if not breach_monitor_uids:
            return 0
        try:
            with BreachMonitorDatabaseConnection() as db:
                db.execute_insert(
                    """UPDATE breach_monitor_records
                       SET status = 'active', resolved_at = NULL, resolved_by = NULL
                       WHERE breach_monitor_uid = ANY(%s)""",
                    (breach_monitor_uids,),
                )
                rows = db.execute_query(
                    "SELECT COUNT(*) AS c FROM breach_monitor_records WHERE breach_monitor_uid = ANY(%s) AND status = 'active'",
                    (breach_monitor_uids,),
                )
                return int(rows[0]["c"]) if rows else 0
        except Exception as e:
            logger.error(f"bulk_unresolve_breaches: {e}")
            return 0

    def mark_false_positive(self, breach_monitor_uid: str, marked_by: str) -> bool:
        try:
            with BreachMonitorDatabaseConnection() as db:
                rows = db.execute_query(
                    "SELECT id FROM breach_monitor_records WHERE breach_monitor_uid = %s",
                    (breach_monitor_uid,),
                )
                if not rows:
                    return False
                db.execute_insert(
                    """UPDATE breach_monitor_records
                       SET status = 'false_positive',
                           false_positive_at = NOW(),
                           false_positive_by = %s,
                           resolved_at = NULL,
                           resolved_by = NULL
                       WHERE breach_monitor_uid = %s""",
                    (marked_by, breach_monitor_uid),
                )
                return True
        except Exception as e:
            logger.error(f"mark_false_positive: {e}")
            return False

    def unmark_false_positive(self, breach_monitor_uid: str) -> bool:
        try:
            with BreachMonitorDatabaseConnection() as db:
                rows = db.execute_query(
                    "SELECT id FROM breach_monitor_records WHERE breach_monitor_uid = %s",
                    (breach_monitor_uid,),
                )
                if not rows:
                    return False
                db.execute_insert(
                    """UPDATE breach_monitor_records
                       SET status = 'active',
                           false_positive_at = NULL,
                           false_positive_by = NULL
                       WHERE breach_monitor_uid = %s""",
                    (breach_monitor_uid,),
                )
                return True
        except Exception as e:
            logger.error(f"unmark_false_positive: {e}")
            return False

    def bulk_mark_false_positive(self, breach_monitor_uids: List[str], marked_by: str) -> int:
        if not breach_monitor_uids:
            return 0
        try:
            with BreachMonitorDatabaseConnection() as db:
                db.execute_insert(
                    """UPDATE breach_monitor_records
                       SET status = 'false_positive',
                           false_positive_at = NOW(),
                           false_positive_by = %s,
                           resolved_at = NULL,
                           resolved_by = NULL
                       WHERE breach_monitor_uid = ANY(%s)""",
                    (marked_by, breach_monitor_uids),
                )
                rows = db.execute_query(
                    "SELECT COUNT(*) AS c FROM breach_monitor_records WHERE breach_monitor_uid = ANY(%s) AND status = 'false_positive'",
                    (breach_monitor_uids,),
                )
                return int(rows[0]["c"]) if rows else 0
        except Exception as e:
            logger.error(f"bulk_mark_false_positive: {e}")
            return 0

    def bulk_unmark_false_positive(self, breach_monitor_uids: List[str]) -> int:
        if not breach_monitor_uids:
            return 0
        try:
            with BreachMonitorDatabaseConnection() as db:
                db.execute_insert(
                    """UPDATE breach_monitor_records
                       SET status = 'active',
                           false_positive_at = NULL,
                           false_positive_by = NULL
                       WHERE breach_monitor_uid = ANY(%s)""",
                    (breach_monitor_uids,),
                )
                rows = db.execute_query(
                    "SELECT COUNT(*) AS c FROM breach_monitor_records WHERE breach_monitor_uid = ANY(%s) AND status = 'active'",
                    (breach_monitor_uids,),
                )
                return int(rows[0]["c"]) if rows else 0
        except Exception as e:
            logger.error(f"bulk_unmark_false_positive: {e}")
            return 0

    def get_breach_monitor_api_payload(
        self,
        date_from: Optional[date] = None,
        date_to: Optional[date] = None,
        date_field: str = "ingested",
    ) -> Dict[str, Any]:
        """Full wrapper matching legacy JSON file response shape."""
        all_results = self.get_all_api_results(
            date_from=date_from,
            date_to=date_to,
            date_field=date_field,
        )
        return {
            "status": 200,
            "description": "OK",
            "data": {
                "results": all_results,
                "query": {
                    "pagination": {
                        "total": len(all_results),
                        "count": len(all_results),
                        "page": 0,
                    }
                },
                "next_id": "",
            },
        }

    def count_records(self) -> int:
        q = "SELECT COUNT(*) AS c FROM breach_monitor_records"
        try:
            with BreachMonitorDatabaseConnection() as db:
                row = db.execute_single_query(q)
                if row and row.get("c") is not None:
                    return int(row["c"])
        except Exception as e:
            logger.error(f"Breach Monitor count_records: {e}")
        return 0

    def breach_monitor_uids_all_exist_in_db(self, uids: List[str]) -> bool:
        """
        True when every distinct information.uid in ``uids`` exists in breach_monitor_records.
        Used to stop live Breach Monitor email pagination once a page only contains rows already stored.
        False when ``uids`` is empty (cannot infer full overlap).
        """
        uniq = list(dict.fromkeys(s.strip() for s in uids if s and str(s).strip()))
        if not uniq:
            return False
        q = """
            SELECT COUNT(*) AS c
            FROM breach_monitor_records
            WHERE breach_monitor_uid = ANY(%s)
        """
        try:
            with BreachMonitorDatabaseConnection() as db:
                row = db.execute_single_query(q, (uniq,))
                if not row or row.get("c") is None:
                    return False
                return int(row["c"]) == len(uniq)
        except Exception as e:
            logger.error(f"breach_monitor_uids_all_exist_in_db: {e}")
            return False

    def get_distinct_incident_names(self) -> List[str]:
        """Return sorted list of all distinct incident_name values from breach_monitor_records."""
        q = """
            SELECT DISTINCT incident_name
            FROM breach_monitor_records
            WHERE incident_name IS NOT NULL AND incident_name <> ''
            ORDER BY incident_name ASC
        """
        try:
            with BreachMonitorDatabaseConnection() as db:
                rows = db.execute_query(q)
                if not rows:
                    return []
                return [row["incident_name"] for row in rows if row.get("incident_name")]
        except Exception as e:
            logger.error(f"get_distinct_incident_names: {e}")
            return []

    def fetch_pending_client_leak_slack_rows(self) -> List[Dict[str, Any]]:
        """
        Client credential leaks not yet included in a daily Slack digest.

        Employee leaks are excluded (same domain rules as the dashboard). Rows on the
        Slack ignore list are still returned so callers can mark them processed without
        notifying.
        """
        try:
            from breach_monitor_export import breach_is_employee_record
        except ImportError:
            from Dashboard.breach_monitor_export import breach_is_employee_record

        q = """
            SELECT breach_monitor_uid, record_type, validated, information, source,
                   ingested_at, email, domain, incident_name
            FROM breach_monitor_records
            WHERE client_slack_alert_sent_at IS NULL
              AND COALESCE(status, 'active') = 'active'
            ORDER BY ingested_at ASC NULLS LAST, id ASC
        """
        out: List[Dict[str, Any]] = []
        try:
            with BreachMonitorDatabaseConnection() as db:
                rows = db.execute_query(q)
                if not rows:
                    return []
                for row in rows:
                    record = {
                        "type": row.get("record_type") or "breach",
                        "information": self._json_obj(row.get("information")),
                        "source": self._json_obj(row.get("source")),
                        "validated": int(row.get("validated", 0) or 0),
                        "breach_monitor_uid": row.get("breach_monitor_uid"),
                    }
                    if breach_is_employee_record(record):
                        continue
                    ingested_at = row.get("ingested_at")
                    out.append({
                        "breach_monitor_uid": str(row.get("breach_monitor_uid") or "").strip(),
                        "email": str(row.get("email") or "").strip(),
                        "incident_name": str(row.get("incident_name") or "").strip(),
                        "ingested_at": ingested_at,
                        "password_plain": str(
                            self._resolve_information_dict(record.get("information") or {}).get(
                                "password_plain"
                            )
                            or ""
                        ).strip(),
                    })
                return out
        except Exception as e:
            logger.error(f"fetch_pending_client_leak_slack_rows: {e}")
            return []

    def mark_client_leak_slack_alerts_sent(self, uids: List[str]) -> bool:
        """Mark client leak rows as included in a daily Slack digest."""
        uniq = sorted({str(uid).strip() for uid in uids if str(uid).strip()})
        if not uniq:
            return True
        q = """
            UPDATE breach_monitor_records
            SET client_slack_alert_sent_at = NOW()
            WHERE breach_monitor_uid = ANY(%s)
              AND client_slack_alert_sent_at IS NULL
        """
        try:
            with BreachMonitorDatabaseConnection() as db:
                return bool(db.execute_insert(q, (uniq,)))
        except Exception as e:
            logger.error(f"mark_client_leak_slack_alerts_sent: {e}")
            return False

    def get_passwords_for_email(self, email: str) -> List[str]:
        """Return sorted list of distinct non-empty password_plain values for the given email."""
        q = """
            SELECT DISTINCT information->>'password_plain' AS password_plain
            FROM breach_monitor_records
            WHERE LOWER(email) = %s
              AND information->>'password_plain' IS NOT NULL
              AND information->>'password_plain' <> ''
            ORDER BY 1 ASC
        """
        try:
            with BreachMonitorDatabaseConnection() as db:
                rows = db.execute_query(q, (email.strip().lower(),))
                if not rows:
                    return []
                return [row["password_plain"] for row in rows if row.get("password_plain")]
        except Exception as e:
            logger.error(f"get_passwords_for_email: {e}")
            return []


class BreachMonitorIgnoreListService:
    """Manages Slack notification suppression rules for Breach Monitor breach alerts."""

    _TABLE = "breach_monitor_ignore_list"

    def __init__(self) -> None:
        self.db = DatabaseConnection()
        self._ensure_table_exists()

    def _ensure_table_exists(self) -> None:
        sql = """
        CREATE TABLE IF NOT EXISTS breach_monitor_ignore_list (
            id            BIGSERIAL PRIMARY KEY,
            email         TEXT NOT NULL,
            incident_names TEXT[] NOT NULL DEFAULT '{}',
            passwords      TEXT[] NOT NULL DEFAULT '{}',
            notes         TEXT,
            created_by    TEXT,
            created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            CONSTRAINT breach_monitor_ignore_list_email_unique UNIQUE (email)
        );
        CREATE INDEX IF NOT EXISTS idx_breach_monitor_ignore_email
            ON breach_monitor_ignore_list (email);
        ALTER TABLE breach_monitor_ignore_list
            ADD COLUMN IF NOT EXISTS passwords TEXT[] NOT NULL DEFAULT '{}';
        """
        try:
            with DatabaseConnection() as db:
                db.execute_insert(sql)
        except Exception as e:
            logger.warning(f"BreachMonitorIgnoreListService._ensure_table_exists: {e}")

    def get_all(self) -> List[Dict[str, Any]]:
        """Return all ignore-list entries ordered by email."""
        q = """
            SELECT id, email, incident_names, passwords, notes, created_by, created_at, updated_at
            FROM breach_monitor_ignore_list
            ORDER BY email ASC
        """
        try:
            with DatabaseConnection() as db:
                rows = db.execute_query(q)
                if not rows:
                    return []
                out = []
                for row in rows:
                    out.append({
                        "id": row["id"],
                        "email": row["email"],
                        "incident_names": list(row.get("incident_names") or []),
                        "passwords": list(row.get("passwords") or []),
                        "notes": row.get("notes"),
                        "created_by": row.get("created_by"),
                        "created_at": row["created_at"].isoformat() if row.get("created_at") else None,
                        "updated_at": row["updated_at"].isoformat() if row.get("updated_at") else None,
                    })
                return out
        except Exception as e:
            logger.error(f"BreachMonitorIgnoreListService.get_all: {e}")
            return []

    def upsert(
        self,
        email: str,
        incident_names: List[str],
        passwords: List[str],
        notes: Optional[str],
        created_by: Optional[str],
    ) -> Optional[Dict[str, Any]]:
        """
        Insert or update an ignore-list entry for the given email.
        On conflict the incident_names, passwords, notes, created_by and updated_at are replaced.
        Returns the upserted row or None on failure.
        """
        email = email.strip().lower()
        cleaned = sorted({n.strip() for n in incident_names if n and n.strip()})
        cleaned_pwds = sorted({p for p in passwords if p})
        q = """
            INSERT INTO breach_monitor_ignore_list
                (email, incident_names, passwords, notes, created_by, updated_at)
            VALUES (%s, %s, %s, %s, %s, NOW())
            ON CONFLICT (email) DO UPDATE SET
                incident_names = EXCLUDED.incident_names,
                passwords      = EXCLUDED.passwords,
                notes          = EXCLUDED.notes,
                created_by     = EXCLUDED.created_by,
                updated_at     = NOW()
            RETURNING id, email, incident_names, passwords, notes, created_by, created_at, updated_at
        """
        try:
            with DatabaseConnection() as db:
                row = db.execute_returning(q, (email, cleaned, cleaned_pwds, notes, created_by))
                if not row:
                    return None
                return {
                    "id": row["id"],
                    "email": row["email"],
                    "incident_names": list(row.get("incident_names") or []),
                    "passwords": list(row.get("passwords") or []),
                    "notes": row.get("notes"),
                    "created_by": row.get("created_by"),
                    "created_at": row["created_at"].isoformat() if row.get("created_at") else None,
                    "updated_at": row["updated_at"].isoformat() if row.get("updated_at") else None,
                }
        except Exception as e:
            logger.error(f"BreachMonitorIgnoreListService.upsert: {e}")
            return None

    def delete(self, entry_id: int) -> bool:
        """Delete an ignore-list entry by id. Returns True on success."""
        q = "DELETE FROM breach_monitor_ignore_list WHERE id = %s"
        try:
            with DatabaseConnection() as db:
                return bool(db.execute_insert(q, (entry_id,)))
        except Exception as e:
            logger.error(f"BreachMonitorIgnoreListService.delete: {e}")
            return False

    def should_suppress(self, email: str, incident_name: str, password: Optional[str] = None) -> bool:
        """
        Return True when the Slack alert for (email, incident_name) should be suppressed.
        - Empty incident_names AND empty passwords → suppress all alerts for this email.
        - Non-empty incident_names → suppress if incident_name is in the list.
        - Non-empty passwords → suppress if password matches an entry in the list.
        - Email not in list → do NOT suppress.
        """
        q = """
            SELECT incident_names, passwords
            FROM breach_monitor_ignore_list
            WHERE email = %s
            LIMIT 1
        """
        try:
            with DatabaseConnection() as db:
                row = db.execute_single_query(q, (email.strip().lower(),))
                if row is None:
                    return False
                names: List[str] = list(row.get("incident_names") or [])
                pwds: List[str] = list(row.get("passwords") or [])
                if not names and not pwds:
                    return True
                if incident_name and incident_name in names:
                    return True
                if password and password in pwds:
                    return True
                return False
        except Exception as e:
            logger.error(f"BreachMonitorIgnoreListService.should_suppress: {e}")
            return False
