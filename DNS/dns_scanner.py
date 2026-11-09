#!/usr/bin/env python3
"""
DNS Security Scanner
Checks for domain expiration, subdomain takeover, DNSSEC, and protection settings
"""

import os
import sys
import logging
import subprocess
import socket
import time
import json
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import requests
import dns.resolver
import dns.flags

_APP_ROOT = os.environ.get("VENDIANT_APP_ROOT", "/app")
_DASHBOARD_DIR = os.path.join(_APP_ROOT, "Dashboard")
_CUSTOM_INTEGRATIONS_DIR = os.path.join(_APP_ROOT, "custom_integrations")

# Add Dashboard path for unified scoring
if _DASHBOARD_DIR not in sys.path:
    sys.path.append(_DASHBOARD_DIR)
from unified_scoring_config import get_severity_weights, calculate_scan_score
import whois
import concurrent.futures

# Import our configuration
from . import config

# Set up logging
# Add custom integrations path for logger
if _CUSTOM_INTEGRATIONS_DIR not in sys.path:
    sys.path.append(_CUSTOM_INTEGRATIONS_DIR)
from logger_config import setup_logger

# Configure logging using custom logger
logger = setup_logger()

class DNSSecurityScanner:
    """Comprehensive DNS security scanner."""
    
    def __init__(self):
        self.results = {}
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = config.DNS_TIMEOUT
        self.dns_resolver.nameservers = config.DNS_SERVERS
        
    def scan_domain(self, domain: str) -> Dict[str, Any]:
        """
        Perform comprehensive DNS security scan on a domain.
        Returns results dictionary with all findings.
        """
        logger.info(f"Starting DNS security scan for: {domain}")
        
        # Initialize results
        self.results[domain] = {
            "domain": domain,
            "scan_timestamp": datetime.now().isoformat(),
            "domain_expiry": {},
            "subdomain_takeover": {},
            "dnssec_status": {},
            "registrar_protection": {},
            "dns_configuration": {},
            "risk_score": 950,  # Start with perfect score
            "risk_level": "Low Risk",
            "recommendations": []
        }
        
        try:
            # 1. Check domain expiration status
            logger.info(f"Checking domain expiration for {domain}")
            self._check_domain_expiry(domain)
            
            # 2. Check for subdomain takeover vulnerabilities
            logger.info(f"Checking subdomain takeover vulnerabilities for {domain}")
            self._check_subdomain_takeover(domain)
            
            # 3. Check DNSSEC status
            logger.info(f"Checking DNSSEC status for {domain}")
            self._check_dnssec(domain)
            
            # 4. Check registrar protection settings
            logger.info(f"Checking registrar protection settings for {domain}")
            self._check_registrar_protection(domain)
            
            # 5. Check DNS configuration
            logger.info(f"Checking DNS configuration for {domain}")
            self._check_dns_configuration(domain)
            
            # 6. Calculate risk score
            self._calculate_risk_score(domain)
            
            # 7. Generate recommendations
            self._generate_recommendations(domain)
            
            logger.info(f"DNS scan completed for {domain}")
            
        except Exception as e:
            logger.error(f"Error scanning {domain}: {str(e)}")
            self.results[domain]["error"] = str(e)
            
        return self.results[domain]
    
    def _check_domain_expiry(self, domain: str) -> None:
        """Check domain expiration status using whois."""
        try:
            w = whois.whois(domain)
            
            expiry_info = {
                "registrar": getattr(w, 'registrar', 'Unknown'),
                "creation_date": None,
                "expiration_date": None,
                "days_until_expiry": None,
                "status": "Unknown",
                "is_expired": False,
                "expires_soon": False
            }
            
            # Handle expiration date
            expiration_date = getattr(w, 'expiration_date', None)
            if expiration_date:
                if isinstance(expiration_date, list):
                    expiration_date = expiration_date[0]
                
                expiry_info["expiration_date"] = expiration_date.isoformat() if expiration_date else None
                
                if expiration_date:
                    days_until_expiry = (expiration_date - datetime.now()).days
                    expiry_info["days_until_expiry"] = days_until_expiry
                    
                    if days_until_expiry < 0:
                        expiry_info["status"] = "EXPIRED"
                        expiry_info["is_expired"] = True
                    elif days_until_expiry <= config.EXPIRY_CRITICAL_DAYS:
                        expiry_info["status"] = "EXPIRES_VERY_SOON"
                        expiry_info["expires_soon"] = True
                    elif days_until_expiry <= config.EXPIRY_WARNING_DAYS:
                        expiry_info["status"] = "EXPIRES_SOON"
                        expiry_info["expires_soon"] = True
                    else:
                        expiry_info["status"] = "VALID"
            
            # Handle creation date
            creation_date = getattr(w, 'creation_date', None)
            if creation_date:
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                expiry_info["creation_date"] = creation_date.isoformat() if creation_date else None
            
            self.results[domain]["domain_expiry"] = expiry_info
            
        except Exception as e:
            logger.warning(f"Failed to get whois info for {domain}: {str(e)}")
            self.results[domain]["domain_expiry"] = {
                "error": str(e),
                "status": "CHECK_FAILED"
            }
    
    def _check_subdomain_takeover(self, domain: str) -> None:
        """Check for subdomain takeover vulnerabilities using parallel processing."""
        try:
            takeover_info = {
                "vulnerable_subdomains": [],
                "checked_subdomains": [],
                "total_vulnerabilities": 0,
                "severity": "Low"
            }
            
            # Get common subdomains to check using parallel resolution
            subdomains = self._enumerate_subdomains(domain)
            takeover_info["checked_subdomains"] = subdomains[:config.MAX_SUBDOMAINS_CHECK]
            
            # Check each subdomain for takeover vulnerabilities in parallel
            vulnerable_subdomains = []
            max_workers = min(5, max(1, len(takeover_info["checked_subdomains"])))  # Ensure at least 1 worker, limit to 5
            
            # Skip parallel processing if no subdomains to check
            if len(takeover_info["checked_subdomains"]) == 0:
                logger.info(f"No subdomains to check for takeover vulnerabilities for {domain}")
            else:
                with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                    future_to_subdomain = {
                        executor.submit(self._check_single_subdomain_takeover, subdomain): subdomain 
                        for subdomain in takeover_info["checked_subdomains"]
                    }
                    
                    for future in concurrent.futures.as_completed(future_to_subdomain):
                        subdomain = future_to_subdomain[future]
                        try:
                            if future.result():
                                vulnerable_subdomains.append(subdomain)
                        except Exception as e:
                            logger.debug(f"Error checking subdomain {subdomain}: {e}") 
            
            takeover_info["vulnerable_subdomains"] = vulnerable_subdomains
            takeover_info["total_vulnerabilities"] = len(vulnerable_subdomains)
            
            if takeover_info["total_vulnerabilities"] > 0:
                takeover_info["severity"] = "Critical"
            
            self.results[domain]["subdomain_takeover"] = takeover_info
            
        except Exception as e:
            logger.warning(f"Failed subdomain takeover check for {domain}: {str(e)}")
            self.results[domain]["subdomain_takeover"] = {
                "error": str(e),
                "total_vulnerabilities": 0
            }
    
    def _check_single_subdomain_resolution(self, subdomain_tuple):
        """Check if a single subdomain resolves (for parallel processing)."""
        sub, domain = subdomain_tuple
        subdomain = f"{sub}.{domain}"
        try:
            # Try to resolve the subdomain
            socket.gethostbyname(subdomain)
            return subdomain
        except socket.gaierror:
            # Subdomain doesn't exist, skip
            return None
    
    def _enumerate_subdomains(self, domain: str) -> List[str]:
        """Enumerate common subdomains for the domain using parallel DNS resolution."""
        common_subdomains = [
            "www", "mail", "ftp", "blog", "www1", "www2", "ns", "ns1", "ns2",
            "smtp", "secure", "vpn", "m", "shop", "api", "dev", "staging",
            "test", "admin", "email", "webmail", "server", "pop",
            "pop3", "imap", "app", "apps", "help", "go", "video", "live", "photos"
        ]
        
        found_subdomains = []
        
        # Use parallel processing for subdomain resolution
        max_workers = min(10, max(1, len(common_subdomains)))  # Ensure at least 1 worker
        
        # Skip parallel processing if no subdomains to enumerate
        if len(common_subdomains) == 0:
            logger.info(f"No common subdomains to enumerate for {domain}")
            return found_subdomains
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Create tuples of (subdomain_prefix, domain) for parallel processing
            subdomain_tuples = [(sub, domain) for sub in common_subdomains]
            
            # Submit all subdomain resolution tasks
            future_to_sub = {
                executor.submit(self._check_single_subdomain_resolution, sub_tuple): sub_tuple 
                for sub_tuple in subdomain_tuples
            }
            
            # Collect results as they complete
            for future in concurrent.futures.as_completed(future_to_sub):
                try:
                    result = future.result()
                    if result:
                        found_subdomains.append(result)
                except Exception as e:
                    logger.debug(f"Error resolving subdomain: {e}")
        
        return found_subdomains
    
    def _check_single_subdomain_takeover(self, subdomain: str) -> bool:
        """Check if a single subdomain is vulnerable to takeover."""
        try:
            response = requests.get(f"http://{subdomain}", 
                                  timeout=config.NETWORK_TIMEOUT, 
                                  allow_redirects=True)
            content = response.text.lower()
            
            # Check for takeover signatures
            for service, signatures in config.TAKEOVER_SIGNATURES.items():
                for signature in signatures:
                    if signature.lower() in content:
                        logger.warning(f"Subdomain takeover vulnerability found: {subdomain} -> {service}")
                        return True
            
            return False
            
        except Exception as e:
            # If we can't connect, it might be vulnerable
            logger.debug(f"Could not check {subdomain}: {str(e)}")
            return False
    
    def _check_dnssec(self, domain: str) -> None:
        """Check DNSSEC status for the domain."""
        try:
            dnssec_info = {
                "enabled": False,
                "valid": False,
                "algorithms": [],
                "ds_records": [],
                "status": "DISABLED"
            }
            
            # Try to get DS records
            try:
                ds_records = self.dns_resolver.resolve(domain, 'DS')
                dnssec_info["ds_records"] = [str(record) for record in ds_records]
                dnssec_info["enabled"] = True
                
                # Try to validate DNSSEC
                try:
                    # Use dig to validate DNSSEC
                    result = subprocess.run([
                        "dig", "+dnssec", "+multiline", domain, "A"
                    ], capture_output=True, text=True, timeout=config.DNS_TIMEOUT)
                    
                    if "ad" in result.stdout.lower() and "NOERROR" in result.stdout:
                        dnssec_info["valid"] = True
                        dnssec_info["status"] = "ENABLED_AND_VALID"
                    else:
                        dnssec_info["status"] = "ENABLED_BUT_INVALID"
                        
                except subprocess.TimeoutExpired:
                    dnssec_info["status"] = "VALIDATION_TIMEOUT"
                    
            except dns.resolver.NoAnswer:
                dnssec_info["status"] = "DISABLED"
            except dns.resolver.NXDOMAIN:
                dnssec_info["status"] = "DOMAIN_NOT_FOUND"
            
            self.results[domain]["dnssec_status"] = dnssec_info
            
        except Exception as e:
            logger.warning(f"Failed DNSSEC check for {domain}: {str(e)}")
            self.results[domain]["dnssec_status"] = {
                "error": str(e),
                "enabled": False,
                "status": "CHECK_FAILED"
            }
    
    def _check_registrar_protection(self, domain: str) -> None:
        """Check registrar protection settings via whois."""
        try:
            w = whois.whois(domain)
            
            protection_info = {
                "deletion_protection": False,
                "transfer_protection": False,
                "update_protection": False,
                "status_codes": [],
                "raw_status": []
            }
            
            # Get domain status
            status = getattr(w, 'status', [])
            if isinstance(status, str):
                status = [status]
            
            protection_info["raw_status"] = status
            
            # Analyze status codes for protection settings
            for status_item in status:
                status_lower = status_item.lower()
                protection_info["status_codes"].append(status_item)
                
                # Check for various protection types
                if any(keyword in status_lower for keyword in ['clientdeleteprohibited', 'serverdeleteprohibited']):
                    protection_info["deletion_protection"] = True
                
                if any(keyword in status_lower for keyword in ['clienttransferprohibited', 'servertransferprohibited']):
                    protection_info["transfer_protection"] = True
                
                if any(keyword in status_lower for keyword in ['clientupdateprohibited', 'serverupdateprohibited']):
                    protection_info["update_protection"] = True
            
            self.results[domain]["registrar_protection"] = protection_info
            
        except Exception as e:
            logger.warning(f"Failed registrar protection check for {domain}: {str(e)}")
            self.results[domain]["registrar_protection"] = {
                "error": str(e),
                "deletion_protection": False,
                "transfer_protection": False,
                "update_protection": False
            }
    
    def _check_dns_configuration(self, domain: str) -> None:
        """Check DNS configuration and records."""
        try:
            dns_config = {
                "nameservers": [],
                "a_records": [],
                "mx_records": [],
                "txt_records": [],
                "cname_records": [],
                "soa_record": None,
                "has_spf": False,
                "has_dmarc": False,
                "dns_propagation_issues": False
            }
            
            # Check A records
            try:
                a_records = self.dns_resolver.resolve(domain, 'A')
                dns_config["a_records"] = [str(record) for record in a_records]
            except Exception:
                pass
            
            # Check MX records
            try:
                mx_records = self.dns_resolver.resolve(domain, 'MX')
                dns_config["mx_records"] = [str(record) for record in mx_records]
            except Exception:
                pass
            
            # Check TXT records for SPF/DMARC
            try:
                txt_records = self.dns_resolver.resolve(domain, 'TXT')
                for record in txt_records:
                    txt_str = str(record).replace('"', '')
                    dns_config["txt_records"].append(txt_str)
                    
                    if txt_str.startswith('v=spf1'):
                        dns_config["has_spf"] = True
                    if txt_str.startswith('v=DMARC1'):
                        dns_config["has_dmarc"] = True
            except Exception:
                pass
            
            # Check SOA record
            try:
                soa = self.dns_resolver.resolve(domain, 'SOA')
                dns_config["soa_record"] = str(soa[0])
            except Exception:
                pass
            
            # Check nameservers
            try:
                ns_records = self.dns_resolver.resolve(domain, 'NS')
                dns_config["nameservers"] = [str(record) for record in ns_records]
            except Exception:
                pass
            
            self.results[domain]["dns_configuration"] = dns_config
            
        except Exception as e:
            logger.warning(f"Failed DNS configuration check for {domain}: {str(e)}")
            self.results[domain]["dns_configuration"] = {
                "error": str(e)
            }
    
    def _calculate_risk_score(self, domain: str) -> None:
        """Calculate risk score based on findings using unified scoring system."""
        # Get unified severity weights
        severity_weights = get_severity_weights('DNS')
        
        # Collect all vulnerabilities for unified scoring
        vulnerabilities = []
        
        # Domain expiry issues
        expiry = self.results[domain].get("domain_expiry", {})
        if expiry.get("is_expired"):
            vulnerabilities.append({
                'title': 'Domain expired',
                'severity': 'HIGH',
                'description': 'Domain has expired and is no longer accessible'
            })
        elif expiry.get("expires_soon"):
            vulnerabilities.append({
                'title': 'Domain expires soon',
                'severity': 'MEDIUM', 
                'description': f"Domain expires in {expiry.get('days_until_expiry', 'unknown')} days"
            })
        
        # Subdomain takeover issues
        takeover = self.results[domain].get("subdomain_takeover", {})
        if takeover.get("total_vulnerabilities", 0) > 0:
            vulnerabilities.append({
                'title': 'Subdomain takeover vulnerability detected',
                'severity': 'HIGH',
                'description': f"{takeover.get('total_vulnerabilities')} subdomain takeover vulnerabilities detected"
            })
        
        # DNSSEC issues
        dnssec = self.results[domain].get("dnssec_status", {})
        if not dnssec.get("enabled", False):
            vulnerabilities.append({
                'title': 'DNSSEC not enabled',
                'severity': 'LOW',
                'description': 'DNSSEC is not enabled, making the domain vulnerable to DNS spoofing'
            })
        
        # Registrar protection issues
        protection = self.results[domain].get("registrar_protection", {})
        if not protection.get("deletion_protection", False):
            vulnerabilities.append({
                'title': 'Domain registrar deletion protection not enabled',
                'severity': 'LOW',
                'description': 'Domain registrar deletion protection is not enabled'
            })
        
        if not protection.get("transfer_protection", False):
            vulnerabilities.append({
                'title': 'Domain registrar transfer protection not enabled',
                'severity': 'LOW',
                'description': 'Domain registrar transfer protection is not enabled'
            })
        
        if not protection.get("update_protection", False):
            vulnerabilities.append({
                'title': 'Domain registrar update protection not enabled',
                'severity': 'LOW',
                'description': 'Domain registrar update protection is not enabled'
            })
        
        # Use unified scoring system
        if vulnerabilities:
            unified_result = calculate_scan_score(vulnerabilities, 'DNS')
            score = unified_result['score']
            self.results[domain]["risk_score"] = score
            self.results[domain]["vulnerabilities"] = vulnerabilities
            self.results[domain]["scoring_details"] = unified_result
        else:
            # No vulnerabilities found - perfect score
            self.results[domain]["risk_score"] = 950
            self.results[domain]["vulnerabilities"] = []
            self.results[domain]["scoring_details"] = {
                'score': 950,
                'max_score': 950,
                'total_deduction': 0,
                'total_vulnerabilities': 0,
                'critical_high_count': 0,
                'percentage': 100.0
            }
        
        # Get the final score from the results
        score = self.results[domain]["risk_score"]
        
        # Determine risk level based on 950-point scale
        if score >= 800:
            risk_level = "Low Risk"
        elif score >= 600:
            risk_level = "Medium Risk"
        elif score >= 400:
            risk_level = "High Risk"
        else:
            risk_level = "Critical Risk"
        
        self.results[domain]["risk_level"] = risk_level
    
    def _generate_recommendations(self, domain: str) -> None:
        """Generate security recommendations based on findings."""
        recommendations = []
        
        # Domain expiry recommendations
        expiry = self.results[domain].get("domain_expiry", {})
        if expiry.get("is_expired"):
            recommendations.append("CRITICAL: Renew expired domain immediately")
        elif expiry.get("expires_soon"):
            recommendations.append("HIGH: Renew domain before expiration")
        
        # Subdomain takeover recommendations
        takeover = self.results[domain].get("subdomain_takeover", {})
        if takeover.get("total_vulnerabilities", 0) > 0:
            recommendations.append("CRITICAL: Fix subdomain takeover vulnerabilities")
            for vuln in takeover.get("vulnerable_subdomains", []):
                recommendations.append(f"  - Secure or remove vulnerable subdomain: {vuln}")
        
        # DNSSEC recommendations
        dnssec = self.results[domain].get("dnssec_status", {})
        if not dnssec.get("enabled", False):
            recommendations.append("HIGH: Enable DNSSEC for your domain")
        elif dnssec.get("enabled") and not dnssec.get("valid"):
            recommendations.append("HIGH: Fix DNSSEC validation issues")
        
        # Registrar protection recommendations
        protection = self.results[domain].get("registrar_protection", {})
        if not protection.get("deletion_protection", False):
            recommendations.append("MEDIUM: Enable domain deletion protection")
        if not protection.get("update_protection", False):
            recommendations.append("MEDIUM: Enable domain update protection")
        
        self.results[domain]["recommendations"] = recommendations
    
    def generate_report(self, domain: str, format: str = "text") -> str:
        """Generate comprehensive DNS security report."""
        if domain not in self.results:
            return f"No scan results found for {domain}"
        
        results = self.results[domain]
        
        if format == "json":
            return json.dumps(results, indent=2)
        elif format == "html":
            return self._generate_html_report(domain, results)
        else:
            return self._generate_text_report(domain, results)
    
    def _generate_text_report(self, domain: str, results: Dict) -> str:
        """Generate text format report."""
        report = f"""
DNS SECURITY ASSESSMENT REPORT
{'='*60}
Domain: {domain}
Scan Date: {results.get('scan_timestamp', 'Unknown')}
Risk Score: {results.get('risk_score', 0)}/950 ({results.get('risk_level', 'Unknown')})

EXECUTIVE SUMMARY
{'-'*30}
Overall Security Score: {results.get('risk_score', 0)}/950
Risk Level: {results.get('risk_level', 'Unknown')}

DOMAIN SECURITY CHECKS
{'-'*30}
"""
        
        # Domain Expiry
        expiry = results.get('domain_expiry', {})
        report += f"""
1. DOMAIN EXPIRATION STATUS
   Status: {expiry.get('status', 'Unknown')}
   Registrar: {expiry.get('registrar', 'Unknown')}
   Expiration Date: {expiry.get('expiration_date', 'Unknown')}
   Days Until Expiry: {expiry.get('days_until_expiry', 'Unknown')}
"""
        
        # Subdomain Takeover
        takeover = results.get('subdomain_takeover', {})
        report += f"""
2. SUBDOMAIN TAKEOVER VULNERABILITIES
   Total Vulnerabilities: {takeover.get('total_vulnerabilities', 0)}
   Checked Subdomains: {len(takeover.get('checked_subdomains', []))}
   Vulnerable Subdomains: {', '.join(takeover.get('vulnerable_subdomains', [])) or 'None'}
"""
        
        # DNSSEC
        dnssec = results.get('dnssec_status', {})
        report += f"""
3. DNSSEC STATUS
   Enabled: {dnssec.get('enabled', False)}
   Valid: {dnssec.get('valid', False)}
   Status: {dnssec.get('status', 'Unknown')}
"""
        
        # Registrar Protection
        protection = results.get('registrar_protection', {})
        report += f"""
4. REGISTRAR PROTECTION SETTINGS
   Deletion Protection: {protection.get('deletion_protection', False)}
   Transfer Protection: {protection.get('transfer_protection', False)}
   Update Protection: {protection.get('update_protection', False)}
"""
        
        # DNS Configuration
        dns_config = results.get('dns_configuration', {})
        report += f"""
5. DNS CONFIGURATION
   Nameservers: {len(dns_config.get('nameservers', []))} configured
   A Records: {len(dns_config.get('a_records', []))} found
   MX Records: {len(dns_config.get('mx_records', []))} found
   SPF Record: {'Present' if dns_config.get('has_spf') else 'Missing'}
   DMARC Record: {'Present' if dns_config.get('has_dmarc') else 'Missing'}
"""
        
        # Security Issues
        issues = results.get('security_issues', [])
        if issues:
            report += f"""
SECURITY ISSUES FOUND
{'-'*30}
"""
            for i, issue in enumerate(issues, 1):
                report += f"{i}. {issue}\n"
        
        # Recommendations
        recommendations = results.get('recommendations', [])
        if recommendations:
            report += f"""
RECOMMENDATIONS
{'-'*30}
"""
            for i, rec in enumerate(recommendations, 1):
                report += f"{i}. {rec}\n"
        
        report += f"""
{'-'*60}
Report generated by DNS Security Scanner v1.0
{'-'*60}
"""
        
        return report
    
    def _generate_html_report(self, domain: str, results: Dict) -> str:
        """Generate HTML format report."""
        risk_score = results.get('risk_score', 0)
        risk_level = results.get('risk_level', 'Unknown')
        
        # Determine risk color
        if risk_level == "Low Risk":
            risk_color = "#28a745"
        elif risk_level == "Medium Risk":
            risk_color = "#ffc107"
        elif risk_level == "High Risk":
            risk_color = "#fd7e14"
        else:
            risk_color = "#dc3545"
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>DNS Security Report - {domain}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #f8f9fa; padding: 20px; border-radius: 5px; }}
        .risk-score {{ font-size: 24px; font-weight: bold; color: {risk_color}; }}
        .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
        .pass {{ color: #28a745; font-weight: bold; }}
        .fail {{ color: #dc3545; font-weight: bold; }}
        .warning {{ color: #ffc107; font-weight: bold; }}
        .unknown {{ color: #6c757d; font-weight: bold; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>DNS Security Assessment Report</h1>
        <p><strong>Domain:</strong> {domain}</p>
        <p><strong>Scan Date:</strong> {results.get('scan_timestamp', 'Unknown')}</p>
        <p class="risk-score">Risk Score: {risk_score}/950 ({risk_level})</p>
    </div>
"""
        
        # Domain Expiry Section
        expiry = results.get('domain_expiry', {})
        html += f"""
    <div class="section">
        <h2>Domain Expiration Status</h2>
        <table>
            <tr><th>Property</th><th>Value</th></tr>
            <tr><td>Status</td><td class="{'fail' if expiry.get('is_expired') else 'warning' if expiry.get('expires_soon') else 'pass'}">{expiry.get('status', 'Unknown')}</td></tr>
            <tr><td>Registrar</td><td>{expiry.get('registrar', 'Unknown')}</td></tr>
            <tr><td>Expiration Date</td><td>{expiry.get('expiration_date', 'Unknown')}</td></tr>
            <tr><td>Days Until Expiry</td><td>{expiry.get('days_until_expiry', 'Unknown')}</td></tr>
        </table>
    </div>
"""
        
        # Subdomain Takeover Section
        takeover = results.get('subdomain_takeover', {})
        html += f"""
    <div class="section">
        <h2>Subdomain Takeover Vulnerabilities</h2>
        <table>
            <tr><th>Property</th><th>Value</th></tr>
            <tr><td>Total Vulnerabilities</td><td class="{'fail' if takeover.get('total_vulnerabilities', 0) > 0 else 'pass'}">{takeover.get('total_vulnerabilities', 0)}</td></tr>
            <tr><td>Checked Subdomains</td><td>{len(takeover.get('checked_subdomains', []))}</td></tr>
            <tr><td>Vulnerable Subdomains</td><td>{', '.join(takeover.get('vulnerable_subdomains', [])) or 'None'}</td></tr>
        </table>
    </div>
"""
        
        # DNSSEC Section
        dnssec = results.get('dnssec_status', {})
        html += f"""
    <div class="section">
        <h2>DNSSEC Status</h2>
        <table>
            <tr><th>Property</th><th>Value</th></tr>
            <tr><td>Enabled</td><td class="{'pass' if dnssec.get('enabled', False) else 'fail'}">{dnssec.get('enabled', False)}</td></tr>
            <tr><td>Valid</td><td class="{'pass' if dnssec.get('valid', False) else 'fail'}">{dnssec.get('valid', False)}</td></tr>
            <tr><td>Status</td><td>{dnssec.get('status', 'Unknown')}</td></tr>
        </table>
    </div>
"""
        
        # Registrar Protection Section
        protection = results.get('registrar_protection', {})
        html += f"""
    <div class="section">
        <h2>Registrar Protection Settings</h2>
        <table>
            <tr><th>Protection Type</th><th>Status</th></tr>
            <tr><td>Deletion Protection</td><td class="{'pass' if protection.get('deletion_protection', False) else 'fail'}">{protection.get('deletion_protection', False)}</td></tr>
            <tr><td>Transfer Protection</td><td class="{'pass' if protection.get('transfer_protection', False) else 'fail'}">{protection.get('transfer_protection', False)}</td></tr>
            <tr><td>Update Protection</td><td class="{'pass' if protection.get('update_protection', False) else 'fail'}">{protection.get('update_protection', False)}</td></tr>
        </table>
    </div>
"""
        
        # Recommendations
        recommendations = results.get('recommendations', [])
        if recommendations:
            html += """
    <div class="section">
        <h2>Recommendations</h2>
        <ul>
"""
            for rec in recommendations:
                html += f"            <li>{rec}</li>\n"
            html += """
        </ul>
    </div>
"""
        
        html += """
    <div class="section">
        <p><em>Report generated by DNS Security Scanner v1.0</em></p>
    </div>
</body>
</html>
"""
        
        return html 