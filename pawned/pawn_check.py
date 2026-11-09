#!/usr/bin/env python3

"""
Vendiant Breach Checker
Monitors Have I Been Pwned RSS feed and compares breaches against vendor database
"""

import urllib.request
import urllib.parse
import xml.etree.ElementTree as ET
import re
from datetime import datetime
from typing import List, Dict, Optional, Any
import logging
import sys
import os
from difflib import SequenceMatcher
import ssl

# Configure logging
# Add custom integrations path for logger
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'custom_integrations'))
from logger_config import setup_logger

# Configure logging using custom logger
logger = setup_logger()

# Load environment variables from root .env file
try:
    from dotenv import load_dotenv
    env_path = os.path.join(os.path.dirname(__file__), '..', '.env')
    load_dotenv(env_path)
    logger.info(f"Loaded environment variables from {env_path}")
except ImportError:
    logger.warning("python-dotenv not available, using system environment variables")

# Add parent directory to path for database imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'Dashboard'))
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'Postgress'))

# Database imports with fallback
VendiantDB = None
get_vendors_from_database = None

try:
    from Dashboard.db_service import get_vendors_from_database as db_get_vendors
    get_vendors_from_database = db_get_vendors
    logger.info("Successfully imported db_service.get_vendors_from_database")
except ImportError as e:
    logger.warning(f"Dashboard import error: {e}")

try:
    from Postgress.database_connector import VendiantDB
    logger.info("Successfully imported VendiantDB")
except ImportError as e:
    logger.warning(f"Database connector import error: {e}")

# Fallback database connection using direct psycopg2 if available
try:
    import psycopg2
    PSYCOPG2_AVAILABLE = True
    logger.info("psycopg2 available for direct database connections")
except ImportError:
    PSYCOPG2_AVAILABLE = False
    logger.warning("psycopg2 not available")

class HaveIBeenPwnedChecker:
    """
    Checker class for monitoring Have I Been Pwned breaches against vendor database
    """
    
    def __init__(self):
        self.hibp_rss_url = "https://feeds.feedburner.com/HaveIBeenPwnedLatestBreaches"
        self.db = None
        self.database_url = None
        
        # Try to initialize database connection
        self._initialize_database()
    
    def _initialize_database(self):
        """Initialize database connection using available methods"""
        
        # Method 1: Try direct psycopg2 with DATABASE_URL (most reliable)
        if PSYCOPG2_AVAILABLE:
            try:
                # Use DATABASE_URL if available (this works!)
                self.database_url = os.getenv('DATABASE_URL')
                if self.database_url:
                    # Test the connection
                    conn = psycopg2.connect(self.database_url)
                    conn.close()
                    logger.info(f"Using DATABASE_URL: {self.database_url}")
                    return
            except Exception as e:
                logger.warning(f"DATABASE_URL connection failed: {e}")
        
        # Method 2: Try VendiantDB if available (fallback)
        if VendiantDB is not None:
            try:
                self.db = VendiantDB()
                logger.info("Initialized VendiantDB connection")
                return
            except Exception as e:
                logger.warning(f"VendiantDB initialization failed: {e}")
        
        # Method 3: Try building connection string manually
        if PSYCOPG2_AVAILABLE:
            try:
                # Build connection string from environment variables
                db_config = {
                    'host': os.getenv('DB_HOST'),
                    'port': os.getenv('DB_PORT'),
                    'database': os.getenv('DB_NAME'),
                    'user': os.getenv('DB_USER'),
                    'password': os.getenv('DB_PASSWORD')
                }
                
                # Build connection string
                if db_config['password']:
                    self.database_url = f"postgresql://{db_config['user']}:{db_config['password']}@{db_config['host']}:{db_config['port']}/{db_config['database']}"
                else:
                    self.database_url = f"postgresql://{db_config['user']}@{db_config['host']}:{db_config['port']}/{db_config['database']}"
                
                # Test the connection
                conn = psycopg2.connect(self.database_url)
                conn.close()
                logger.info(f"Built database connection: {db_config['user']}@{db_config['host']}:{db_config['port']}/{db_config['database']}")
                return
                
            except Exception as e:
                logger.warning(f"Manual connection failed: {e}")
        
        logger.error("No database connection available - will use fallback data")
    
    def fetch_breach_feed(self) -> Optional[str]:
        """
        Fetch the latest breach data from Have I Been Pwned RSS feed
        
        Returns:
            XML content as string or None if failed
        """
        try:
            headers = {
                'User-Agent': 'Vendiant Security Platform/1.0 (Breach Monitor)'
            }
            
            req = urllib.request.Request(self.hibp_rss_url, headers=headers)
            
            # Create SSL context that doesn't verify certificates (for RSS feeds)
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            with urllib.request.urlopen(req, timeout=30, context=ssl_context) as response:
                xml_content = response.read().decode('utf-8')
            
            logger.info("Successfully fetched Have I Been Pwned RSS feed")
            return xml_content
            
        except Exception as e:
            logger.error(f"Failed to fetch breach feed: {e}")
            return None
    
    def parse_breach_feed(self, xml_content: str) -> List[Dict[str, Any]]:
        """
        Parse XML feed content and extract breach information
        
        Args:
            xml_content: Raw XML content from RSS feed
            
        Returns:
            List of breach dictionaries
        """
        breaches = []
        
        try:
            root = ET.fromstring(xml_content)
            
            # Find all item elements in the RSS feed
            for item in root.findall('.//item'):
                breach_data = {}
                
                # Extract basic information
                title_elem = item.find('title')
                description_elem = item.find('description')
                link_elem = item.find('link')
                pub_date_elem = item.find('pubDate')
                
                if title_elem is not None:
                    breach_data['title'] = title_elem.text
                    # Extract breach name and account count from title
                    title_parts = title_elem.text.split(' - ')
                    if len(title_parts) >= 2:
                        breach_data['breach_name'] = title_parts[0]
                        # Extract account count if present
                        count_match = re.search(r'([\d,]+)\s+breached accounts', title_parts[1])
                        if count_match:
                            breach_data['account_count'] = int(count_match.group(1).replace(',', ''))
                
                if description_elem is not None:
                    breach_data['description'] = description_elem.text
                    # Try to extract domain/company info from description
                    domains = self.extract_domains_from_description(description_elem.text)
                    if domains:
                        breach_data['related_domains'] = domains
                
                if link_elem is not None:
                    breach_data['link'] = link_elem.text
                
                if pub_date_elem is not None:
                    breach_data['pub_date'] = pub_date_elem.text
                    breach_data['parsed_date'] = self.parse_pub_date(pub_date_elem.text)
                
                breaches.append(breach_data)
            
            logger.info(f"Parsed {len(breaches)} breaches from feed")
            return breaches
            
        except ET.ParseError as e:
            logger.error(f"Failed to parse XML feed: {e}")
            return []
    
    def extract_domains_from_description(self, description: str) -> List[str]:
        """
        Extract potential domain names from breach description
        
        Args:
            description: Breach description text
            
        Returns:
            List of domain names found
        """
        domains = []
        
        # Common patterns for extracting domains
        domain_patterns = [
            r'\b([a-zA-Z0-9-]+\.(?:com|org|net|io|co|uk|de|fr|jp|au|ca))\b',
            r'https?://([^/\s]+)',
            r'www\.([^/\s]+)',
        ]
        
        for pattern in domain_patterns:
            matches = re.findall(pattern, description.lower())
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0] if match[0] else match[1]
                
                # Clean up the domain
                domain = match.strip().replace('www.', '')
                if '.' in domain and len(domain) > 3:
                    domains.append(domain)
        
        return list(set(domains))  # Remove duplicates
    
    def parse_pub_date(self, pub_date_str: str) -> Optional[datetime]:
        """
        Parse publication date string to datetime object
        
        Args:
            pub_date_str: Publication date string from RSS
            
        Returns:
            Parsed datetime or None
        """
        try:
            # Common RSS date formats
            date_formats = [
                '%a, %d %b %Y %H:%M:%S %Z',
                '%a, %d %b %Y %H:%M:%S %z',
                '%Y-%m-%dT%H:%M:%SZ',
                '%Y-%m-%d %H:%M:%S'
            ]
            
            for date_format in date_formats:
                try:
                    return datetime.strptime(pub_date_str, date_format)
                except ValueError:
                    continue
            
            logger.warning(f"Could not parse date: {pub_date_str}")
            return None
            
        except Exception as e:
            logger.error(f"Error parsing date {pub_date_str}: {e}")
            return None
    
    def get_vendors_from_database(self) -> List[Dict[str, Any]]:
        """
        Retrieve all vendors from the database
        
        Returns:
            List of vendor dictionaries
        """
        # Method 1: Try direct psycopg2 connection (most reliable)
        if PSYCOPG2_AVAILABLE and self.database_url:
            try:
                conn = psycopg2.connect(self.database_url)
                cursor = conn.cursor()
                query = """
                    SELECT id, vendor_name, domain, grade, added_at, last_scanned
                    FROM vendors
                    ORDER BY vendor_name
                """
                cursor.execute(query)
                results = cursor.fetchall()
                
                vendors = []
                for row in results:
                    vendors.append({
                        'id': row[0],
                        'vendor_name': row[1],
                        'domain': row[2],
                        'grade': row[3] or 'N/A',
                        'added_at': row[4],
                        'last_scanned': row[5]
                    })
                
                cursor.close()
                conn.close()
                
                logger.info(f"Retrieved {len(vendors)} vendors using direct DATABASE_URL connection")
                return vendors
                
            except Exception as e:
                logger.warning(f"Direct psycopg2 query failed: {e}")
        
        # Method 2: Try using the imported function (fallback)
        if get_vendors_from_database is not None:
            try:
                vendors = get_vendors_from_database()
                if vendors:
                    logger.info(f"Retrieved {len(vendors)} vendors using db_service")
                    return vendors
            except Exception as e:
                logger.warning(f"db_service failed: {e}")
        
        # Method 3: Try VendiantDB connection (fallback)
        if self.db is not None:
            try:
                with self.db.get_connection() as conn:
                    cursor = conn.cursor()
                    query = """
                        SELECT id, vendor_name, domain, grade, added_at, last_scanned
                        FROM vendors
                        ORDER BY vendor_name
                    """
                    cursor.execute(query)
                    results = cursor.fetchall()
                    
                    vendors = []
                    for row in results:
                        vendors.append({
                            'id': row[0],
                            'vendor_name': row[1],
                            'domain': row[2],
                            'grade': row[3],
                            'added_at': row[4],
                            'last_scanned': row[5]
                        })
                    
                    logger.info(f"Retrieved {len(vendors)} vendors from VendiantDB")
                    return vendors
                    
            except Exception as e:
                logger.warning(f"VendiantDB query failed: {e}")
        
        # Fallback: Return empty list
        logger.error("No database connection available")
        return []
    
    def calculate_similarity(self, text1: str, text2: str) -> float:
        """
        Calculate similarity between two text strings
        
        Args:
            text1, text2: Strings to compare
            
        Returns:
            Similarity ratio between 0 and 1
        """
        return SequenceMatcher(None, text1.lower(), text2.lower()).ratio()
    
    def check_vendor_matches(self, breaches: List[Dict[str, Any]], vendors: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Check for matches between breach data and vendor database
        
        Args:
            breaches: List of breach data from HIBP
            vendors: List of vendors from database
            
        Returns:
            List of potential matches with confidence scores
        """
        matches = []
        
        for breach in breaches:
            breach_name = breach.get('breach_name', '').lower()
            related_domains = breach.get('related_domains', [])
            
            for vendor in vendors:
                vendor_name = vendor.get('vendor_name', '').lower()
                vendor_domain = vendor.get('domain', '').lower()
                
                # Check for EXACT domain matches first (highest confidence)
                domain_match_score = 0.0
                exact_domain_match = False
                for domain in related_domains:
                    domain_clean = domain.lower().strip()
                    vendor_domain_clean = vendor_domain.lower().strip()
                    
                    # Exact domain match
                    if domain_clean == vendor_domain_clean:
                        domain_match_score = 1.0
                        exact_domain_match = True
                        break
                    # Check if vendor domain is the exact subdomain or parent domain
                    elif (domain_clean.endswith('.' + vendor_domain_clean) or 
                          vendor_domain_clean.endswith('.' + domain_clean)):
                        domain_match_score = max(domain_match_score, 0.95)
                        exact_domain_match = True
                    # Very strict similarity for domains (90%+ similar)
                    elif len(vendor_domain_clean) > 3 and len(domain_clean) > 3:
                        similarity = self.calculate_similarity(vendor_domain_clean, domain_clean)
                        if similarity >= 0.9:
                            domain_match_score = max(domain_match_score, similarity)
                
                # Check for ONLY EXACT company name matches (nothing else!)
                name_match_score = 0.0
                vendor_name_clean = vendor_name.lower().strip()
                breach_name_clean = breach_name.lower().strip()
                
                # ONLY EXACT MATCH: Complete exact name match (100% confidence)
                if vendor_name_clean == breach_name_clean:
                    name_match_score = 1.0
                    logger.info(f"EXACT MATCH: Vendor '{vendor_name}' exactly matches breach '{breach_name}'")
                
                # Handle normalized versions for cases like "Pi-hole" vs "ThePi-Hole"
                elif len(vendor_name_clean) > 2 and len(breach_name_clean) > 2:
                    # Normalize by removing punctuation and spaces for comparison
                    vendor_normalized = vendor_name_clean.replace('-', '').replace('_', '').replace(' ', '').replace('.', '')
                    breach_normalized = breach_name_clean.replace('-', '').replace('_', '').replace(' ', '').replace('.', '')
                    
                    # ONLY if the normalized versions are EXACTLY the same
                    if vendor_normalized == breach_normalized:
                        name_match_score = 1.0
                        logger.info(f"NORMALIZED EXACT MATCH: Vendor '{vendor_name}' exactly matches breach '{breach_name}' (normalized)")
                
                # ONLY ACCEPT PERFECT MATCHES
                confidence = max(domain_match_score, name_match_score)
                
                # Only include 100% EXACT matches - no fuzzy matching at all
                if confidence == 1.0:
                    # Determine match reason for transparency
                    match_reason = []
                    
                    # Check for domain matches
                    if domain_match_score == 1.0 and exact_domain_match:
                        match_reason.append("exact_domain_match")
                    
                    # Check for name matches (only exact matches allowed)
                    if name_match_score == 1.0:
                        vendor_normalized = vendor_name_clean.replace('-', '').replace('_', '').replace(' ', '').replace('.', '')
                        breach_normalized = breach_name_clean.replace('-', '').replace('_', '').replace(' ', '').replace('.', '')
                        
                        if vendor_name_clean == breach_name_clean:
                            match_reason.append("exact_breach_name_match")
                        elif vendor_normalized == breach_normalized:
                            match_reason.append("normalized_exact_breach_name_match")
                    
                    matches.append({
                        'vendor': vendor,
                        'breach': breach,
                        'confidence': confidence,
                        'domain_match_score': domain_match_score,
                        'name_match_score': name_match_score,
                        'match_type': 'domain' if domain_match_score > name_match_score else 'name',
                        'match_reasons': match_reason
                    })
        
        # Sort by confidence score
        matches.sort(key=lambda x: x['confidence'], reverse=True)
        
        logger.info(f"Found {len(matches)} EXACT vendor-breach matches (100% confidence only)")
        
        # Log match breakdown for transparency  
        exact_name_matches = len([m for m in matches if any("exact_breach_name" in reason for reason in m.get('match_reasons', []))])
        normalized_matches = len([m for m in matches if any("normalized_exact" in reason for reason in m.get('match_reasons', []))])
        domain_matches = len([m for m in matches if any("exact_domain" in reason for reason in m.get('match_reasons', []))])
        logger.info(f"Match breakdown: {exact_name_matches} exact name matches, {normalized_matches} normalized exact matches, {domain_matches} domain matches")
        
        return matches
    
    def check_breaches(self) -> Dict[str, Any]:
        """
        Main function to check for breaches affecting vendors
        
        Returns:
            Dictionary with results and matches
        """
        try:
            # Fetch latest breach data
            xml_content = self.fetch_breach_feed()
            if not xml_content:
                return {
                    'success': False,
                    'error': 'Failed to fetch breach feed',
                    'matches': []
                }
            
            # Parse breach data
            breaches = self.parse_breach_feed(xml_content)
            if not breaches:
                return {
                    'success': False,
                    'error': 'Failed to parse breach data',
                    'matches': []
                }
            
            # Get vendors from database
            vendors = self.get_vendors_from_database()
            if not vendors:
                return {
                    'success': False,
                    'error': 'No vendors found in database',
                    'matches': []
                }
            
            # Check for matches
            matches = self.check_vendor_matches(breaches, vendors)
            
            return {
                'success': True,
                'total_breaches': len(breaches),
                'total_vendors': len(vendors),
                'matches': matches,
                'last_checked': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error in breach checking: {e}")
            return {
                'success': False,
                'error': str(e),
                'matches': []
            }

def main():
    """Main function for testing"""
    checker = HaveIBeenPwnedChecker()
    results = checker.check_breaches()
    
    print("=== Breach Check Results ===")
    print(f"Success: {results['success']}")
    
    if results['success']:
        print(f"Total breaches checked: {results['total_breaches']}")
        print(f"Total vendors in database: {results['total_vendors']}")
        print(f"Potential matches found: {len(results['matches'])}")
        
        for i, match in enumerate(results['matches'][:5]):  # Show top 5 matches
            print(f"\nMatch {i+1}:")
            print(f"  Vendor: {match['vendor']['vendor_name']} ({match['vendor']['domain']})")
            print(f"  Breach: {match['breach']['breach_name']}")
            print(f"  Confidence: {match['confidence']:.2f}")
            print(f"  Match Type: {match['match_type']}")
    else:
        print(f"Error: {results['error']}")

if __name__ == "__main__":
    main()
