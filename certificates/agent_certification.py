#!/usr/bin/env python3
"""
Single Agent Certification Checker
==================================

Uses a single AI agent to check for security certifications:
- ISO 27001 certification
- SOC 2 (SOC II) certification

Features:
- Single AI agent with real-time web search capabilities
- Database integration - loads domains from PostgreSQL database
- Fallback to text file if database is unavailable
- Console output only - no file generation
- Optimized for speed and efficiency

Usage:
    python3 agent_certification.py
    
Environment:
    OPENAI_API_KEY - Required API key for OpenAI access
    OPENAI_MODEL_NAME - Model name (defaults to gpt-5.6-luna)
    DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD - Database connection settings
"""

import json
import logging
import time
import os
import sys
from datetime import datetime
from typing import Dict, List, Optional
import sys
from dotenv import load_dotenv
# import threading  # Commented out - no threading
# from concurrent.futures import ThreadPoolExecutor, as_completed  # Commented out - no threading
from openai import OpenAI

# Import Supabase LLM logger
try:
    sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'custom_integrations'))
    from supabase_logger import log_llm_call
    SUPABASE_LOGGING_AVAILABLE = True
except ImportError:
    SUPABASE_LOGGING_AVAILABLE = False
    print("Warning: Supabase logging not available. Install supabase-py and configure environment variables.")

load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))

# API Configuration - any OpenAI-compatible endpoint (OPENAI_BASE_URL)
api_key = os.getenv('OPENAI_API_KEY')
_base = os.getenv('OPENAI_BASE_URL', 'https://api.openai.com/v1').rstrip('/')
if not _base.endswith('/v1'):
    _base = f"{_base}/v1"
api_base_url = _base
model_name = os.getenv('OPENAI_MODEL_NAME', 'gpt-5.6-luna')

client = OpenAI(api_key=api_key, base_url=api_base_url)

def extract_response_text(response) -> str:
    """Extract plain text from an OpenAI Responses API response."""
    output_text = getattr(response, "output_text", None)
    if output_text:
        return output_text

    text_parts = []
    for output_item in getattr(response, "output", []) or []:
        content_items = output_item.get("content", []) if isinstance(output_item, dict) else getattr(output_item, "content", [])
        for content_item in content_items or []:
            text = content_item.get("text") if isinstance(content_item, dict) else getattr(content_item, "text", None)
            if text:
                text_parts.append(text)

    return "\n".join(text_parts)

# Add Dashboard path for database access
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'Dashboard'))
from db_service import VendorService

# Add custom integrations path for logger
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'custom_integrations'))
from logger_config import setup_logger

# Setup logger using custom configuration
logger = setup_logger()

# Thread-safe locks (commented out - no threading)
# results_lock = threading.Lock()
# progress_lock = threading.Lock()

class SingleAgentCertificationChecker:
    """Single agent certification checker using Perplexity Sonar"""
    
    def __init__(self, use_database: bool = True, domains_file: str = 'domain.txt', max_workers: int = 4, batch_size: int = 3):
        """
        Initialize the single agent certification checker
        
        Args:
            use_database: Whether to load domains from database (True) or text file (False)
            domains_file: Path to file containing domains to check (used only if use_database=False)
            max_workers: Maximum number of concurrent threads
            batch_size: Number of domains per batch
        """
        # Validate API key
        if not api_key:
            logger.error("API key required! Set OPENAI_API_KEY environment variable")
            raise ValueError("API key required")
            
        self.use_database = use_database
        self.domains_file = domains_file
        
        # Initialize database service if using database
        if self.use_database:
            self.vendor_service = VendorService()
        
        # OpenAI Client Configuration
        self.client = client
        
        # Model configuration
        self.model = model_name  # Perplexity Sonar
        
        # Threading configuration
        self.max_workers = max_workers
        self.batch_size = batch_size
        
        # Results storage
        self.results = []
        self.certified_domains = {
            'iso_27001': [],
            'soc2': [],
            'both': []
        }
        
        # Progress tracking
        self.processed_count = 0
        self.total_domains = 0
        
        logger.info("Single Agent Certification Checker initialized")
        logger.info(f"Model: {self.model}")
        logger.info(f"Configuration: {max_workers} workers, batch size {batch_size}")
        logger.info(f"Data source: {'Database' if self.use_database else 'Text file'}")
    
    def load_domains(self) -> List[str]:
        """Load domains from database or file"""
        if self.use_database:
            return self._load_domains_from_database()
        else:
            return self._load_domains_from_file()
    
    def _load_domains_from_database(self) -> List[str]:
        """Load domains from database"""
        logger.info("Loading domains from database")
        domains = []
        
        try:
            vendors = self.vendor_service.get_all_vendors()
            if vendors:
                for vendor in vendors:
                    domain = vendor.get('domain', '').strip()
                    if domain and '.' in domain and not domain.startswith('http'):
                        domains.append(domain)
                
                logger.info(f"Loaded {len(domains)} domains from database")
                return domains
            else:
                logger.warning("No vendors found in database")
                return []
                
        except Exception as e:
            logger.error(f"Error loading domains from database: {e}")
            return []
    
    def _load_domains_from_file(self) -> List[str]:
        """Load domains from file (fallback method)"""
        logger.info(f"Loading domains from {self.domains_file}")
        domains = []
        
        try:
            with open(self.domains_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#') or line.lower() in ['main website']:
                        continue
                    
                    if '|' in line:
                        domain = line.split('|')[-1].strip()
                    else:
                        domain = line.strip()
                    
                    if '.' in domain and not domain.startswith('http'):
                        domains.append(domain)
                    
            logger.info(f"Loaded {len(domains)} valid domains from file")
            return domains
            
        except FileNotFoundError:
            logger.error(f"Domain file not found: {self.domains_file}")
            return []
        except Exception as e:
            logger.error(f"Error loading domains from file: {e}")
            return []
    
    def query_domain(self, domain: str) -> Dict:
        """
        Query domain for certifications using Perplexity Sonar
        """
        prompt = f"""
        You are a security compliance analyst with real-time web search capabilities.

            Task:
             Analyze the domain {domain} and determine if they have the following security certifications:
             1. ISO 27001 certification
             2. SOC 2 (SOC II) certification

            Instructions:
            - Carefully examine the vendor's official website, including the footer (which often acts as a sitemap to Trust, Security, Compliance, Privacy Policy, or Legal/Regulatory pages).
            - Browse the Trust Center, Compliance, and Policy pages for **direct evidence** such as certificates, badges, explicit statements, or official press releases about the certifications.
            - Look for clear, current (within the past 2 years), and direct mentions of "ISO 27001" or "SOC 2".

            Strict Evidence Criteria:
            - Mark "certified": true ONLY if you find clear, direct, and recent evidence (certificate, badge, official press release, or explicit statement) and provide the actual source URL to the proof!
            - Include a brief direct quote or snippet from the evidence if possible.
            - Do NOT speculate or infer. Do NOT use generic security commitments as evidence.

            If you find no direct evidence, set certified=false and explain what you searched in "details".

            Respond ONLY in this exact JSON format (no extra text):

            {{
                "domain": "{domain}",
                "iso_27001": {{
                    "certified": true/false,
                    "details": "direct evidence quote or explanation of search and 'Not found'",
                    "validity_date": "date found on source or 'Not found'",
                    "source_url": "URL to certificate or 'Not found'"
                }},
                "soc2": {{
                    "certified": true/false,
                    "details": "direct evidence quote or explanation of search and 'Not found'",
                    "validity_date": "date found on source or 'Not found'",
                    "source_url": "URL to certification or 'Not found'"
                }},
                "pages_checked": ["list page titles or URLs checked"],
                "confidence": "high/medium/low",
                "search_method": "real_time_web_search",
                "model": "{self.model}"
            }}

            Return only this JSON. Do not include any other commentary or summary.
        """
        
        return self._make_api_request(domain, prompt)
    
    def _make_api_request(self, domain: str, prompt: str) -> Dict:
        """Make API request using OpenAI client with error handling and Supabase logging"""
        try:
            logger.debug(f"Querying {domain} with {self.model}")

            # Prepare input for logging
            input_text = prompt

            response = self.client.responses.create(
                model=self.model,
                instructions="You are a security compliance analyst with real-time web search capabilities.",
                input=prompt,
                tools=[{"type": "web_search"}],
                temperature=0.1,
                max_output_tokens=1500,
            )

            content = extract_response_text(response)

            # Log successful call to Supabase
            if SUPABASE_LOGGING_AVAILABLE:
                status = getattr(response, "status", None)
                incomplete_details = getattr(response, "incomplete_details", None)
                finish_reason = getattr(incomplete_details, "reason", None) or status
                log_llm_call(
                    model=self.model,
                    provider="openai",
                    request_data={"input": input_text, "model": self.model, "tools": [{"type": "web_search"}], "max_output_tokens": 1500},
                    response_data={"finish_reason": finish_reason},
                    context={"domain": domain, "operation": "certification_check"},
                    service="agent_certification"
                )

            try:
                # Extract JSON from response
                if '```json' in content:
                    json_start = content.find('```json') + 7
                    json_end = content.find('```', json_start)
                    content = content[json_start:json_end].strip()
                elif '```' in content:
                    json_start = content.find('```') + 3
                    json_end = content.find('```', json_start)
                    content = content[json_start:json_end].strip()
                
                certification_info = json.loads(content)
                certification_info['model'] = model_name
                logger.debug(f"Successfully analyzed {domain}")
                return certification_info
                
            except json.JSONDecodeError:
                logger.warning(f"Could not parse JSON for {domain}")
                return {
                    "domain": domain,
                    "iso_27001": {"certified": False, "details": "Parse error", "validity_date": "Not found"},
                    "soc2": {"certified": False, "details": "Parse error", "validity_date": "Not found"},
                    "confidence": "low",
                    "error": "JSON parse failed",
                    "model": model_name,
                    "raw_response": content
                }
                
        except Exception as e:
            logger.error(f"API error for {domain}: {e}")

            # Log failed call to Supabase
            if SUPABASE_LOGGING_AVAILABLE:
                log_llm_call(
                    model=self.model,
                    provider="openai",
                    request_data={"input": prompt, "model": self.model, "tools": [{"type": "web_search"}], "max_output_tokens": 1500},
                    error_message=str(e),
                    context={"domain": domain, "operation": "certification_check"},
                    service="agent_certification"
                )

            return {
                "domain": domain,
                "iso_27001": {"certified": False, "details": "Query failed", "validity_date": "Not found"},
                "soc2": {"certified": False, "details": "Query failed", "validity_date": "Not found"},
                "confidence": "low",
                "error": str(e),
                "model": model_name
            }
    
    def process_domain(self, domain: str) -> Dict:
        """Process single domain with progress tracking"""
        result = self.query_domain(domain)
        result['checked_at'] = datetime.now().isoformat()
        
        # Update progress (threading lock commented out)
        # with progress_lock:
        self.processed_count += 1
        if self.processed_count % 10 == 0:
            progress_pct = (self.processed_count / self.total_domains) * 100
            logger.info(f"Progress: {self.processed_count}/{self.total_domains} ({progress_pct:.1f}%)")
        
        time.sleep(0.3)  # Rate limiting
        return result
    
    def run_scan(self, domains: List[str]) -> List[Dict]:
        """Run certification scan on all domains"""
        logger.info("=" * 70)
        logger.info("STARTING SINGLE AGENT CERTIFICATION SCAN")
        logger.info("=" * 70)
        
        self.total_domains = len(domains)
        logger.info(f"Scanning {len(domains)} domains with {self.model}...")
        
        all_results = []
        
        # Sequential processing (threading commented out)
        for i, domain in enumerate(domains, 1):
            try:
                logger.info(f"Processing {i}/{len(domains)}: {domain}")
                result = self.process_domain(domain)
                all_results.append(result)
                
                # Log certifications found
                iso_cert = result.get('iso_27001', {}).get('certified', False)
                soc2_cert = result.get('soc2', {}).get('certified', False)
                if iso_cert or soc2_cert:
                    certs = []
                    if iso_cert:
                        certs.append("ISO 27001")
                    if soc2_cert:
                        certs.append("SOC2")
                    logger.info(f"CERTIFIED: {domain} - {', '.join(certs)}")
                    
            except Exception as e:
                logger.error(f"Failed to process {domain}: {e}")
        
        # Original threading code (commented out)
        # with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
        #     # Submit all domains
        #     future_to_domain = {
        #         executor.submit(self.process_domain, domain): domain 
        #         for domain in domains
        #     }
        #     
        #     # Collect results
        #     for future in as_completed(future_to_domain):
        #         domain = future_to_domain[future]
        #         try:
        #             result = future.result()
        #             all_results.append(result)
        #             
        #             # Log certifications found
        #             iso_cert = result.get('iso_27001', {}).get('certified', False)
        #             soc2_cert = result.get('soc2', {}).get('certified', False)
        #             if iso_cert or soc2_cert:
        #                 certs = []
        #                 if iso_cert:
        #                     certs.append("ISO 27001")
        #                 if soc2_cert:
        #                     certs.append("SOC2")
        #                 logger.info(f"CERTIFIED: {domain} - {', '.join(certs)}")
        #                 
        #         except Exception as e:
        #             logger.error(f"Failed to process {domain}: {e}")
        
        self.results = all_results
        logger.info(f"Scan completed: {len(all_results)} domains processed")
        return all_results
    
    def categorize_results(self, results: List[Dict]):
        """Categorize results for reporting"""
        for result in results:
            iso_cert = result.get('iso_27001', {}).get('certified', False)
            soc2_cert = result.get('soc2', {}).get('certified', False)
            domain = result['domain']
            
            # with results_lock:  # Threading lock commented out
            if iso_cert and soc2_cert:
                self.certified_domains['both'].append(domain)
            elif iso_cert:
                self.certified_domains['iso_27001'].append(domain)
            elif soc2_cert:
                self.certified_domains['soc2'].append(domain)
    
    def display_results(self):
        """Display comprehensive single agent results to console"""
        logger.info("Displaying single agent certification results...")
        
        # Count totals
        total_domains = len(self.results)
        iso_count = len(self.certified_domains['iso_27001'])
        soc2_count = len(self.certified_domains['soc2'])
        both_count = len(self.certified_domains['both'])
        total_certified = iso_count + soc2_count + both_count
        
        # Display report
        print("\n" + "=" * 90)
        print("SINGLE AGENT CERTIFICATION ANALYSIS REPORT")
        print("=" * 90)
        print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total Domains Analyzed: {total_domains}")
        print(f"Processing Configuration: {self.max_workers} workers, {self.batch_size} batch size")
        print("")
        print("MODEL CONFIGURATION:")
        print(f"• Agent: {self.model}")
        print(f"• Capabilities: Real-time web search, current information")
        print(f"• Processing Mode: Single agent, streamlined workflow")
        print("")
        print("CERTIFICATION SUMMARY:")
        print(f"• ISO 27001 Only: {iso_count} domains")
        print(f"• SOC2 Only: {soc2_count} domains")
        print(f"• Both Certifications: {both_count} domains")
        print(f"• Total Certified: {total_certified} domains")
        print(f"• Certification Rate: {(total_certified/total_domains*100):.1f}%")
        print("")
        
        if self.certified_domains['both']:
            print("DOMAINS WITH BOTH CERTIFICATIONS:")
            print("-" * 70)
            for domain in self.certified_domains['both']:
                print(f"* {domain}")
            print("")
        
        if self.certified_domains['iso_27001']:
            print("DOMAINS WITH ISO 27001 ONLY:")
            print("-" * 70)
            for domain in self.certified_domains['iso_27001']:
                print(f"* {domain}")
            print("")
            
        if self.certified_domains['soc2']:
            print("DOMAINS WITH SOC2 ONLY:")
            print("-" * 70)
            for domain in self.certified_domains['soc2']:
                print(f"* {domain}")
            print("")
        
        print("=" * 90)
        print("END OF SINGLE AGENT REPORT")
        print("=" * 90)
        
        # Return summary data for further use if needed
        summary_data = {
            "generated_at": datetime.now().isoformat(),
            "agent_config": {
                "model": model_name,
                "max_workers": self.max_workers,
                "batch_size": self.batch_size,
                "total_processed": len(self.results)
            },
            "total_domains": total_domains,
            "certification_summary": {
                "iso_27001_only": iso_count,
                "soc2_only": soc2_count,
                "both_certifications": both_count,
                "total_certified": total_certified,
                "certification_rate_percent": round(total_certified/total_domains*100, 1)
            },
            "certified_domains": self.certified_domains,
            "detailed_results": self.results
        }
        
        return summary_data
    
    def run_complete_scan(self):
        """Execute complete single agent certification scan"""
        start_time = time.time()
        
        logger.info("=" * 90)
        logger.info("STARTING SINGLE AGENT CERTIFICATION SCAN")
        logger.info(f"Agent: {self.model}")
        logger.info("=" * 90)
        
        # Load domains
        domains = self.load_domains()
        if not domains:
            logger.error("No domains to scan!")
            return
        
        # Run scan
        results = self.run_scan(domains)
        
        # Categorize and display results
        self.categorize_results(results)
        
        if self.results:
            end_time = time.time()
            processing_time = end_time - start_time
            
            summary = self.display_results()
            
            logger.info("")
            logger.info("SINGLE AGENT CERTIFICATION SCAN COMPLETE!")
            logger.info("=" * 90)
            logger.info(f"FINAL RESULTS:")
            logger.info(f"   Total Domains: {summary['total_domains']}")
            logger.info(f"   ISO 27001 Only: {summary['certification_summary']['iso_27001_only']}")
            logger.info(f"   SOC2 Only: {summary['certification_summary']['soc2_only']}")
            logger.info(f"   Both Certs: {summary['certification_summary']['both_certifications']}")
            logger.info(f"   Certification Rate: {summary['certification_summary']['certification_rate_percent']}%")
            logger.info(f"   Processing Time: {processing_time:.1f} seconds")
            logger.info("=" * 90)
        else:
            logger.error("No results to report")

def main():
    """Main execution function"""
    print("Single Agent Certification Checker")
    print("=" * 90)
    print(f"Agent: {model_name}")
    print("=" * 90)
    
    # Check for API key
    if not api_key:
        print("Please set OPENAI_API_KEY environment variable")
        return 1
    
    try:
        # Initialize single agent checker with database by default
        checker = SingleAgentCertificationChecker(
            use_database=True,  # Use database by default
            domains_file="domain.txt",  # Fallback file if database fails
            max_workers=6,  # Higher worker count for single agent
            batch_size=10   # Larger batch size for efficiency
        )
        
        # Run scan
        checker.run_complete_scan()
        
        print("\nSingle agent scan completed! Results displayed above.")
        
        return 0
        
    except Exception as e:
        print(f"Single agent scan failed: {e}")
        return 1

if __name__ == "__main__":
    exit(main()) 