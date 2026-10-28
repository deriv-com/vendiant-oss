#!/usr/bin/env python3
"""
Email Security Checker
======================

Comprehensive DMARC and SPF email security analysis tool for single domain analysis.
Implements manual checks for email authentication policies including:
- DMARC policy validation (p=none, p=quarantine, p=reject)
- SPF record analysis (+all, -all, ~all, ?all)
- Syntax validation and policy recommendations

Usage:
    python3 email_security_checker.py

Features:
- Single domain analysis (no subdomain discovery)
- Detailed DMARC and SPF analysis
- Security recommendations
- Comprehensive reporting
- Manual verification guidance
"""

import subprocess
import re
import json
import logging
import time
import os
import sys
from datetime import datetime
from typing import Dict, List, Optional, Tuple

_APP_ROOT = os.environ.get("VENDIANT_APP_ROOT", "/app")
_DASHBOARD_DIR = os.path.join(_APP_ROOT, "Dashboard")
_CUSTOM_INTEGRATIONS_DIR = os.path.join(_APP_ROOT, "custom_integrations")

# Add Dashboard path for unified scoring
if _DASHBOARD_DIR not in sys.path:
    sys.path.append(_DASHBOARD_DIR)
from unified_scoring_config import get_severity_weights, calculate_scan_score

# Setup logging
# Add custom integrations path for logger
if _CUSTOM_INTEGRATIONS_DIR not in sys.path:
    sys.path.append(_CUSTOM_INTEGRATIONS_DIR)
from logger_config import setup_logger

# Configure logging using custom logger
logger = setup_logger()

class EmailSecurityChecker:
    """Email security checker for single domain analysis using dig commands"""
    
    def __init__(self):
        """Initialize the email security checker for single domain analysis"""
        logger.info("Email Security Checker initialized for single domain analysis")
    
    def run_dig_command(self, domain: str, record_type: str) -> Tuple[str, int]:
        """
        Run dig command and return output and return code
        
        Args:
            domain: Domain to query
            record_type: DNS record type (TXT, MX, etc.)
            
        Returns:
            Tuple of (output, return_code)
        """
        try:
            cmd = ['dig', '+short', domain, record_type]
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=10
            )
            return result.stdout.strip(), result.returncode
        except subprocess.TimeoutExpired:
            logger.warning(f"Dig command timed out for {domain} {record_type}")
            return "", 1
        except Exception as e:
            logger.error(f"Error running dig for {domain} {record_type}: {e}")
            return "", 1
    
    def check_dmarc_policy(self, domain: str) -> Dict:
        """
        Check DMARC policy for domain
        Based on image: Manual search for p=none, p=quarantine, p=reject
        """
        logger.debug(f"Checking DMARC policy for {domain}")
        
        # Query DMARC record
        dmarc_domain = f"_dmarc.{domain}"
        output, return_code = self.run_dig_command(dmarc_domain, 'TXT')
        
        result = {
            'domain': domain,
            'dmarc_record': output,
            'policy': None,
            'policy_found': False,
            'issues': [],
            'recommendations': [],
            'raw_output': output
        }
        
        if return_code != 0 or not output:
            result['issues'].append("DMARC policy not found - If dig returns 'no answer,' record not present")
            result['recommendations'].append("Implement DMARC policy with p=quarantine or p=reject")
            return result
        
        # Clean up the output (remove quotes)
        dmarc_record = output.replace('"', '').replace('\\', '')
        result['dmarc_record'] = dmarc_record
        
        # Check for p=none (Warning condition)
        if 'p=none' in dmarc_record.lower():
            result['policy'] = 'none'
            result['policy_found'] = True
            result['issues'].append("DMARC policy is p=none - Manual search for p=none in DMARC record")
            result['recommendations'].append("Upgrade to p=quarantine or p=reject for better security")
        
        # Check for p=quarantine (Warning condition)
        elif 'p=quarantine' in dmarc_record.lower():
            result['policy'] = 'quarantine'
            result['policy_found'] = True
            result['issues'].append("DMARC policy p=quarantine - Manual search for p=quarantine")
            result['recommendations'].append("Consider upgrading to p=reject for maximum security")
        
        # Check for p=reject (Good)
        elif 'p=reject' in dmarc_record.lower():
            result['policy'] = 'reject'
            result['policy_found'] = True
            result['recommendations'].append("DMARC policy p=reject is properly configured")
        
        else:
            result['issues'].append("DMARC policy not clearly defined or malformed")
            result['recommendations'].append("Verify DMARC record syntax and set explicit policy")
        
        # Check for percentage less than 100%
        pct_match = re.search(r'pct=(\d+)', dmarc_record.lower())
        if pct_match:
            percentage = int(pct_match.group(1))
            if percentage < 100:
                result['issues'].append(f"DMARC policy percentage less than 100% - Manually check if pct= exists and value<100")
                result['recommendations'].append(f"Increase pct to 100 for full policy enforcement (currently {percentage}%)")
        
        return result
    
    def check_spf_policy(self, domain: str) -> Dict:
        """
        Check SPF policy for domain
        Based on image: Look for +all, -all, ~all, ?all, ptr mechanisms
        """
        logger.debug(f"Checking SPF policy for {domain}")
        
        # Query SPF record
        output, return_code = self.run_dig_command(domain, 'TXT')
        
        result = {
            'domain': domain,
            'spf_record': None,
            'spf_found': False,
            'mechanisms': [],
            'issues': [],
            'recommendations': [],
            'raw_output': output
        }
        
        if return_code != 0 or not output:
            result['issues'].append("SPF not enabled - If no record with v=spf1, SPF not present")
            result['recommendations'].append("Implement SPF record with appropriate mechanisms")
            return result
        
        # Look for SPF record in TXT records
        spf_records = []
        for line in output.split('\n'):
            if 'v=spf1' in line.lower():
                spf_records.append(line.replace('"', '').replace('\\', ''))
        
        if not spf_records:
            result['issues'].append("SPF not enabled - If no record with v=spf1, SPF not present")
            result['recommendations'].append("Implement SPF record starting with v=spf1")
            return result
        
        result['spf_found'] = True
        spf_record = spf_records[0]  # Use first SPF record found
        result['spf_record'] = spf_record
        
        # Check for syntax errors (basic validation)
        if not spf_record.lower().startswith('v=spf1'):
            result['issues'].append("SPF syntax error - You'll have to spot obvious typos yourself; dig doesn't validate syntax")
            result['recommendations'].append("Fix SPF record syntax - must start with v=spf1")
        
        # Check for +all mechanism (Warning)
        if '+all' in spf_record:
            result['issues'].append("SPF policy uses +all - Look for +all in the SPF result")
            result['recommendations'].append("Replace +all with -all for better security")
            result['mechanisms'].append('+all')
        
        # Check for ?all mechanism (Warning)
        if '?all' in spf_record:
            result['issues'].append("SPF policy uses ?all - Look for ?all in the SPF result")
            result['recommendations'].append("Replace ?all with -all for definitive policy")
            result['mechanisms'].append('?all')
        
        # Check for ~all mechanism (Warning)
        if '~all' in spf_record:
            result['issues'].append("SPF policy uses ~all - Look for ~all in the SPF result")
            result['recommendations'].append("Consider upgrading to -all for stricter policy")
            result['mechanisms'].append('~all')
        
        # Check for -all mechanism (Good)
        if '-all' in spf_record:
            result['recommendations'].append("SPF policy uses -all - properly configured")
            result['mechanisms'].append('-all')
        
        # Check for ptr mechanism (Warning)
        if 'ptr' in spf_record.lower():
            result['issues'].append("SPF ptr mechanism used - Look for ptr in the SPF result")
            result['recommendations'].append("PTR mechanism is deprecated and slow - replace with ip4/ip6 or include")
            result['mechanisms'].append('ptr')
        
        # Extract other mechanisms
        mechanisms = re.findall(r'\b(ip[46]:|include:|a:|mx:|redirect=)', spf_record.lower())
        result['mechanisms'].extend(mechanisms)
        
        return result
    
    def calculate_security_score(self, dmarc_result: Dict, spf_result: Dict) -> int:
        """
        Calculate security score (0-950) using unified scoring system
        
        Uses the unified scoring system with dynamic weighting for EMAIL category (10% base weight)
        """
        initial_score = 950
        all_vulnerabilities = []
        
        # Get unified severity weights
        severity_weights = get_severity_weights('EMAIL')
        
        # Analyze DMARC issues and add to vulnerabilities list
        for issue in dmarc_result['issues']:
            severity = 'INFO'
            issue_lower = issue.lower()
            # Map using robust substring checks to avoid phrasing mismatches
            if "dmarc policy not found" in issue_lower:
                severity = 'HIGH'
            elif "p=none" in issue_lower:
                severity = 'HIGH'
            elif "p=quarantine" in issue_lower:
                severity = 'LOW'
            elif "percentage less than 100%" in issue_lower:
                severity = 'LOW'
            
            all_vulnerabilities.append({
                'severity': severity,
                'category': 'EMAIL',
                'description': f"DMARC: {issue}",
                'type': 'DMARC'
            })
        
        # Analyze SPF issues and add to vulnerabilities list
        for issue in spf_result['issues']:
            severity = 'INFO'
            if "SPF not enabled" in issue:
                severity = 'HIGH'
            elif "SPF policy uses +all" in issue:
                severity = 'HIGH'
            elif "SPF syntax error" in issue:
                severity = 'MEDIUM'
            elif "SPF policy uses ?all" in issue:
                severity = 'LOW'
            elif "SPF policy uses ~all" in issue:
                severity = 'LOW'
            elif "SPF ptr mechanism used" in issue:
                severity = 'LOW'
            
            all_vulnerabilities.append({
                'severity': severity,
                'category': 'EMAIL',
                'description': f"SPF: {issue}",
                'type': 'SPF'
            })
        
        # Use unified scoring system for final score calculation
        if all_vulnerabilities:
            unified_result = calculate_scan_score(all_vulnerabilities, 'EMAIL')
            final_score = unified_result['score']
            logger.info(f" UNIFIED SCORING - Email Category:")
            logger.info(f"   Total Issues: {unified_result['total_vulnerabilities']}")
            logger.info(f"   Critical/High Count: {unified_result['critical_high_count']}")
            logger.info(f"   Total Deduction: {unified_result['total_deduction']}")
            logger.info(f"   Final Score: {final_score}/{initial_score} ({unified_result['percentage']}%)")
        else:
            final_score = initial_score
            logger.info(f"No email security issues found - using base score: {final_score}")
        
        return final_score
    
    def get_overall_status(self, score: int) -> str:
        """Get overall security status based on score (0-950)"""
        if score >= 760:  # 80% of 950
            return "SECURE"
        elif score >= 570:  # 60% of 950
            return "MODERATE"
        elif score >= 380:  # 40% of 950
            return "WEAK"
        else:
            return "VULNERABLE"
    
    def check_domain_email_security(self, domain: str) -> Dict:
        """
        Comprehensive email security check for a single domain
        """
        logger.info(f"Analyzing email security for {domain}")
        
        start_time = time.time()
        
        # Run DMARC and SPF checks
        dmarc_result = self.check_dmarc_policy(domain)
        spf_result = self.check_spf_policy(domain)
        
        # Calculate security score
        security_score = self.calculate_security_score(dmarc_result, spf_result)
        
        # Combine results
        result = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'dmarc': dmarc_result,
            'spf': spf_result,
            'security_score': security_score,
            'overall_status': self.get_overall_status(security_score),
            'scan_time': round(time.time() - start_time, 2)
        }
        
        return result
    
    def generate_report(self, result: Dict):
        """Generate comprehensive email security report for single domain - database only, no files"""
        logger.info("Email security scan completed - results stored in database")
        
        domain = result['domain']
        security_score = result['security_score']
        overall_status = result['overall_status']
        
        # Count issues by severity for logging
        severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        
        for issue in result['dmarc']['issues']:
            if "DMARC policy is p=none" in issue or "DMARC policy not found" in issue:
                severity_counts["HIGH"] += 1
            elif "DMARC policy is p=quarantine" in issue or "percentage less than 100%" in issue:
                severity_counts["LOW"] += 1
        
        for issue in result['spf']['issues']:
            if "SPF not enabled" in issue or "SPF policy uses +all" in issue:
                severity_counts["HIGH"] += 1
            elif "SPF syntax error" in issue:
                severity_counts["MEDIUM"] += 1
            elif "SPF policy uses ?all" in issue or "SPF policy uses ~all" in issue or "SPF ptr mechanism used" in issue:
                severity_counts["LOW"] += 1
        
        # Log summary instead of writing files
        logger.info("=" * 80)
        logger.info("EMAIL SECURITY ANALYSIS SUMMARY")
        logger.info("=" * 80)
        logger.info(f"Domain: {domain}")
        logger.info(f"Security Score: {security_score}/950 ({overall_status})")
        logger.info(f"Scan Time: {result['scan_time']} seconds")
        logger.info(f"Issue Breakdown - HIGH: {severity_counts['HIGH']}, MEDIUM: {severity_counts['MEDIUM']}, LOW: {severity_counts['LOW']}")
        
        if result['dmarc']['issues']:
            logger.info("DMARC Issues:")
            for issue in result['dmarc']['issues']:
                logger.info(f"  • {issue}")
        
        if result['spf']['issues']:
            logger.info("SPF Issues:")
            for issue in result['spf']['issues']:
                logger.info(f"  • {issue}")
        
        logger.info("Results stored in database - no files generated")
    
    def scan_domain_email_security(self, domain: str):
        """Execute email security scan for a single domain - database integration only"""
        start_time = time.time()
        
        logger.info("=" * 70)
        logger.info("STARTING EMAIL SECURITY SCAN")
        logger.info("=" * 70)
        logger.info(f"Target domain: {domain}")
        
        # Process single domain
        result = self.check_domain_email_security(domain)
        
        # Generate report (logging only, no files)
        if result:
            end_time = time.time()
            processing_time = end_time - start_time
            
            self.generate_report(result)
            
            logger.info("")
            logger.info("EMAIL SECURITY SCAN COMPLETE!")
            logger.info("=" * 70)
            logger.info(f"Domain: {domain}")
            logger.info(f"Security Score: {result['security_score']}/950")
            logger.info(f"Status: {result['overall_status']}")
            logger.info(f"Processing Time: {processing_time:.1f} seconds")
            logger.info("=" * 70)
            
            return result
        else:
            logger.error("Failed to scan domain")
            return None

def main():
    """Main execution function"""
    print("Email Security Checker")
    print("=" * 70)
    print("DMARC and SPF Policy Analysis")
    print("=" * 70)
    
    try:
        # Initialize checker
        checker = EmailSecurityChecker()
        
        # Get domain to scan from user input
        domain_to_scan = input("Enter the domain to scan (e.g., example.com): ").strip()
        if not domain_to_scan:
            print("Domain cannot be empty. Please try again.")
            return 1
        
        # Run scan for the single domain
        result = checker.scan_domain_email_security(domain_to_scan)
        
        if result:
            print(f"\nEmail security scan completed!")
            print(f"Domain: {result['domain']}")
            print(f"Security Score: {result['security_score']}/950")
            print(f"Status: {result['overall_status']}")
            print("Results are stored in database - no files generated")
        else:
            print("Email security scan failed.")
            return 1
        
        return 0
        
    except Exception as e:
        print(f"Email security scan failed: {e}")
        return 1

if __name__ == "__main__":
    exit(main()) 