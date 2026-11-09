#!/usr/bin/env python3
"""
Vendor Risk Scanner - SSL/Encryption Analysis Tool
Focusing on encryption and SSL security.

This tool integrates multiple security assessment services:
_scan_testssl() - testssl.sh integration
_scan_security_headers() - HTTP security headers analysis
_enhanced_security_checks() - 11 enhanced security checks
_calculate_risk_score() - Risk scoring logic
_generate_recommendations() - Security recommendations
_generate_text_report() - Report generation
-gives detailed certificate information

"""

import json
import subprocess
import requests
import time
import argparse
import os
import sys
from datetime import datetime, timedelta
from urllib.parse import urlparse
import concurrent.futures
from typing import Dict, List, Any, Optional
import logging

# Import certificate inspection functions - REMOVED: cert_inspector_local.py deleted
# Certificate analysis now handled by enhanced_security_checks_local.py

# Import enhanced security checks
from enhanced_security_checks_local import EnhancedSecurityChecker

# Import configuration
import config_local as config

_APP_ROOT = os.environ.get("VENDIANT_APP_ROOT", "/app")
_DASHBOARD_DIR = os.path.join(_APP_ROOT, "Dashboard")

# Import unified scoring system
if _DASHBOARD_DIR not in sys.path:
    sys.path.append(_DASHBOARD_DIR)
from unified_scoring_config import get_unified_scoring, get_severity_weights

# Configure logging with timestamped log files
def setup_logging():
    """Setup logging with timestamped log files for each run.

    Uses the LOG_DIR env var when set; otherwise falls back to /tmp/logs so
    that this module works in read-only-rootfs containers.  If directory creation still fails the
    function falls back to console-only logging instead of raising.
    """
    from datetime import datetime
    import os

    # Prefer an explicit override, then /tmp/logs (always writable).
    # Avoid CWD-relative paths — the working directory varies by caller.
    logs_dir = os.environ.get(
        "LOG_DIR",
        os.path.join("/tmp", "vendor_risk_logs"),
    )

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = os.path.join(logs_dir, f"vendor_risk_scan_{timestamp}.log")

    handlers: list = [logging.StreamHandler()]

    try:
        os.makedirs(logs_dir, exist_ok=True)
        handlers.insert(0, logging.FileHandler(log_filename))
    except OSError as exc:
        logging.getLogger(__name__).warning(
            "Could not create log directory %s (%s). File logging disabled.",
            logs_dir,
            exc,
        )
        log_filename = None

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(name)s - %(message)s',
        handlers=handlers,
        force=True,
    )

    logger = logging.getLogger(__name__)
    logger.info("="*80)
    logger.info("NEW VENDOR RISK SCANNING SESSION STARTED")
    if log_filename:
        logger.info(f"Log file: {log_filename}")
    logger.info(f"Session timestamp: {timestamp}")
    logger.info("="*80)

    return log_filename

# Setup logging and get the log filename
try:
    log_filename = setup_logging()
except Exception as _setup_exc:  # noqa: BLE001
    logging.basicConfig(level=logging.INFO, force=True)
    logging.getLogger(__name__).warning("setup_logging() failed: %s", _setup_exc)
    log_filename = None
logger = logging.getLogger(__name__)

class VendorRiskScanner:
    """Main scanner class that orchestrates all security assessments."""
    
    def __init__(self, testssl_path: str = None):
        if testssl_path is None:
            encryption_local_dir = os.path.join(
                os.environ.get("VENDIANT_APP_ROOT", "/app"),
                "Encryption",
                "LOCAL",
            )
            testssl_path = os.path.join(encryption_local_dir, "testssl.sh", "testssl.sh")
        self.testssl_path = testssl_path
        self.security_headers_api = "https://securityheaders.com"
        self.results = {}
        
    def scan_domain(self, domain: str, full_scan: bool = True) -> Dict[str, Any]:
        """
        Perform comprehensive security scan of a domain.
        
        Args:
            domain: Target domain to scan
            full_scan: Whether to perform full scan including time-intensive tests
            
        Returns:
            Dictionary containing all scan results
        basically the structure of how the report should look like
        """
        logger.info(f"Starting vendor risk scan for: {domain}")
        
        # Initialize results structure
        self.results[domain] = {
            "scan_timestamp": datetime.now().isoformat(),
            "domain": domain,
            "testssl": {},
            "certificate_transparency": {},
            "detailed_certificate": {},
            "enhanced_security_checks": {},
            "risk_score": 0,
            "risk_level": "Unknown",
            "risk_factors": [],
            "recommendations": []
        }
        
        # Run scans concurrently where possible
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = []
            
            # Enhanced security checks handle most security assessments
            futures.append(executor.submit(self._enhanced_security_checks, domain))
            
            # testssl.sh for comprehensive SSL/TLS vulnerability assessment
            if full_scan:
                futures.append(executor.submit(self._scan_testssl, domain))
            
            # Wait for all scans to complete
            concurrent.futures.wait(futures)
        
        # Extract certificate information sequentially (to avoid threading conflicts)
        self._certificate_extraction(domain)
        
        # Calculate risk score and generate recommendations
        self._calculate_risk_score(domain)
        self._generate_recommendations(domain)
        
        logger.info(f"Scan completed for {domain}. Risk score: {self.results[domain]['risk_score']}")
        return self.results[domain]

    
    
    def _scan_testssl(self, domain: str) -> None:
        """Run testssl.sh scan on domain."""
        try:
            logger.info(f"Starting testssl.sh scan for {domain}")
            
            if not self.testssl_path or not os.path.exists(self.testssl_path):
                logger.error(f"testssl.sh not found at {self.testssl_path}")
                self.results[domain]["testssl"] = {"error": "testssl.sh not available"}
                return
            
            # Clean up any existing "-" file in testssl.sh directory that could interfere
            testssl_dir = os.path.dirname(self.testssl_path)
            dash_file = os.path.join(testssl_dir, "-")
            if os.path.exists(dash_file):
                try:
                    os.remove(dash_file)
                    logger.info(f"Removed interfering file: {dash_file}")
                except Exception as cleanup_error:
                    logger.warning(f"Could not remove {dash_file}: {cleanup_error}")
            
            # Use a temporary file instead of stdout to avoid conflicts with files named "-"
            import tempfile
            temp_json_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, dir=testssl_dir)
            temp_json_path = temp_json_file.name
            temp_json_file.close()
            
            try:
                # Prepare testssl.sh command
                cmd = [
                    self.testssl_path,
                    "--jsonfile", temp_json_path,  # Output JSON to temporary file
                    "--quiet",
                    "--warnings", "off",
                    domain
                ]
                
                # Add any additional options from config
                if hasattr(config, 'TESTSSL_OPTIONS') and config.TESTSSL_OPTIONS:
                    # Insert options before the domain
                    cmd = cmd[:-1] + config.TESTSSL_OPTIONS + [domain]
                
                logger.info(f"Running testssl.sh: {' '.join(cmd)}")
                
                # Run testssl.sh with timeout
                # Suppress stderr to avoid printf errors from testssl.sh (known issue with certain SSL responses)
                # These are non-fatal warnings that don't affect the JSON output
                result = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,  # Suppress stderr to avoid printf errors
                    text=True,
                    timeout=config.TESTSSL_TIMEOUT,
                    cwd=os.path.dirname(self.testssl_path)
                )
                
                # Check if JSON file was created (even if returncode != 0, testssl.sh might have partial results)
                json_file_exists = os.path.exists(temp_json_path) and os.path.getsize(temp_json_path) > 0
                
                if result.returncode == 0 or json_file_exists:
                    try:
                        # Read JSON output from temporary file
                        with open(temp_json_path, 'r') as f:
                            json_lines = [line for line in f if line.strip()]
                        
                        testssl_data = []
                        for line in json_lines:
                            try:
                                testssl_data.append(json.loads(line))
                            except json.JSONDecodeError:
                                continue
                        
                        # Parse results into our format
                        parsed_results = self._parse_testssl_results(testssl_data)
                        self.results[domain]["testssl"] = parsed_results
                        
                        vuln_count = len(parsed_results.get("vulnerabilities", {}))
                        logger.info(f"testssl.sh scan completed for {domain}: {vuln_count} vulnerabilities found")
                        
                    except Exception as parse_error:
                        logger.error(f"Failed to parse testssl.sh output for {domain}: {str(parse_error)}")
                        self.results[domain]["testssl"] = {"error": f"Parse error: {str(parse_error)}"}
                else:
                    # testssl.sh failed, but check if we have partial results in JSON file
                    if json_file_exists:
                        try:
                            logger.warning(f"testssl.sh exited with code {result.returncode} for {domain}, but JSON file exists. Attempting to parse partial results...")
                            with open(temp_json_path, 'r') as f:
                                json_lines = [line for line in f if line.strip()]
                            
                            testssl_data = []
                            for line in json_lines:
                                try:
                                    testssl_data.append(json.loads(line))
                                except json.JSONDecodeError:
                                    continue
                            
                            if testssl_data:
                                parsed_results = self._parse_testssl_results(testssl_data)
                                self.results[domain]["testssl"] = parsed_results
                                vuln_count = len(parsed_results.get("vulnerabilities", {}))
                                logger.info(f"testssl.sh partial results parsed for {domain}: {vuln_count} vulnerabilities found (scan had errors but produced usable data)")
                            else:
                                logger.error(f"testssl.sh failed for {domain}: JSON file exists but contains no valid data")
                                self.results[domain]["testssl"] = {"error": "testssl.sh failed and produced no usable results"}
                        except Exception as partial_parse_error:
                            logger.error(f"testssl.sh failed for {domain} and partial parse also failed: {str(partial_parse_error)}")
                            self.results[domain]["testssl"] = {"error": f"testssl.sh failed: exit code {result.returncode}"}
                    else:
                        logger.error(f"testssl.sh failed for {domain}: exit code {result.returncode}, no JSON output file created")
                        self.results[domain]["testssl"] = {"error": f"testssl.sh failed: exit code {result.returncode} (likely printf errors in testssl.sh script)"}
            finally:
                # Clean up temporary file
                try:
                    if os.path.exists(temp_json_path):
                        os.unlink(temp_json_path)
                except Exception as cleanup_error:
                    logger.warning(f"Could not remove temporary file {temp_json_path}: {cleanup_error}")
                
        except subprocess.TimeoutExpired:
            logger.error(f"testssl.sh timed out for {domain}")
            self.results[domain]["testssl"] = {"error": "Scan timed out"}
        except Exception as e:
            logger.error(f"testssl.sh scan failed for {domain}: {str(e)}")
            self.results[domain]["testssl"] = {"error": str(e)}


    
    
    def _parse_testssl_results(self, data: List) -> Dict:
        """Parse testssl.sh results into standardized format."""
        results = {
            "protocols": {},
            "ciphers": {},
            "vulnerabilities": {},
            "certificate": {}
        }
        
        for finding in data:
            section = finding.get("section", "")
            id_name = finding.get("id", "")
            finding_type = finding.get("finding", "")
            severity = finding.get("severity", "")
            
            if "protocol" in section.lower():
                results["protocols"][id_name] = {
                    "finding": finding_type,
                    "severity": severity
                }
            elif "cipher" in section.lower():
                results["ciphers"][id_name] = {
                    "finding": finding_type,
                    "severity": severity
                }
            elif "vulnerabilit" in section.lower():
                results["vulnerabilities"][id_name] = {
                    "finding": finding_type,
                    "severity": severity
                }
        
        return results
    
    def _extract_certificate_info(self, domain: str, port: int = 443) -> Dict:
        """Extract certificate information using OpenSSL."""
        logger.info(f"Extracting certificate information for {domain}:{port}")
        
        try:
            # Use OpenSSL to get certificate information
            cmd = [
                'openssl', 's_client', '-connect', f'{domain}:{port}',
                '-servername', domain, '-showcerts'
            ]
            
            result = subprocess.run(
                cmd, input='', text=True, capture_output=True, timeout=30
            )
            
            if result.returncode != 0:
                logger.error(f"OpenSSL certificate extraction failed for {domain}: {result.stderr}")
                return {"error": f"Certificate extraction failed: {result.stderr}"}
            
            output = result.stdout
            
            # Extract certificate from output (get the first cert)
            cert_start = output.find('-----BEGIN CERTIFICATE-----')
            cert_end = output.find('-----END CERTIFICATE-----')
            
            if cert_start == -1 or cert_end == -1:
                logger.error(f"No certificate found in OpenSSL output for {domain}")
                return {"error": "No certificate found in output"}
            
            cert_data = output[cert_start:cert_end + len('-----END CERTIFICATE-----')]
            
            # Save certificate to temporary file for parsing
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as temp_cert:
                temp_cert.write(cert_data)
                temp_cert_path = temp_cert.name
            
            try:
                # Parse certificate details using OpenSSL
                cert_info = {}
                
                # Get subject
                subject_cmd = ['openssl', 'x509', '-in', temp_cert_path, '-noout', '-subject']
                subject_result = subprocess.run(subject_cmd, capture_output=True, text=True, timeout=10)
                if subject_result.returncode == 0:
                    subject_line = subject_result.stdout.strip()
                    # Extract subject from "subject=CN=domain.com,O=Org,C=US" format
                    if 'subject=' in subject_line:
                        subject = subject_line.split('subject=', 1)[1]
                        cert_info['subject'] = self._format_certificate_field(subject)
                    else:
                        cert_info['subject'] = "Unknown"
                
                # Get issuer
                issuer_cmd = ['openssl', 'x509', '-in', temp_cert_path, '-noout', '-issuer']
                issuer_result = subprocess.run(issuer_cmd, capture_output=True, text=True, timeout=10)
                if issuer_result.returncode == 0:
                    issuer_line = issuer_result.stdout.strip()
                    # Extract issuer from "issuer=C=US,O=Amazon,CN=Amazon RSA 2048 M04" format
                    if 'issuer=' in issuer_line:
                        issuer = issuer_line.split('issuer=', 1)[1]
                        cert_info['issuer'] = self._format_certificate_field(issuer)
                    else:
                        cert_info['issuer'] = "Unknown"
                
                # Get signature algorithm
                sigalg_cmd = ['openssl', 'x509', '-in', temp_cert_path, '-noout', '-text']
                sigalg_result = subprocess.run(sigalg_cmd, capture_output=True, text=True, timeout=10)
                if sigalg_result.returncode == 0:
                    text_output = sigalg_result.stdout
                    
                    # Extract signature algorithm
                    for line in text_output.split('\n'):
                        if 'Signature Algorithm:' in line:
                            cert_info['key_algorithm'] = line.split(':', 1)[1].strip()
                            break
                    else:
                        cert_info['key_algorithm'] = "Unknown"
                    
                    # Extract key size
                    for line in text_output.split('\n'):
                        if 'RSA Public Key:' in line or 'Public-Key:' in line:
                            # Look for pattern like "RSA Public Key: (2048 bit)" or "Public-Key: (2048 bit)"
                            if '(' in line and 'bit' in line:
                                key_size_part = line.split('(')[1].split('bit')[0].strip()
                                cert_info['key_size'] = f"{key_size_part} bits"
                                break
                    else:
                        cert_info['key_size'] = "Unknown"
                
                # Get expiry information
                dates_cmd = ['openssl', 'x509', '-in', temp_cert_path, '-noout', '-dates']
                dates_result = subprocess.run(dates_cmd, capture_output=True, text=True, timeout=10)
                if dates_result.returncode == 0:
                    dates_output = dates_result.stdout
                    
                    # Parse notAfter date
                    for line in dates_output.split('\n'):
                        if line.startswith('notAfter='):
                            not_after_str = line.split('=', 1)[1]
                            try:
                                from datetime import datetime
                                # Parse date format like "Mar 17 23:59:59 2025 GMT"
                                not_after = datetime.strptime(not_after_str.strip(), "%b %d %H:%M:%S %Y %Z")
                                days_until_expiry = (not_after - datetime.now()).days
                                cert_info['days_until_expiry'] = days_until_expiry
                            except Exception as date_error:
                                logger.warning(f"Failed to parse certificate expiry date for {domain}: {date_error}")
                                cert_info['days_until_expiry'] = "Unknown"
                            break
                    else:
                        cert_info['days_until_expiry'] = "Unknown"
                
                logger.info(f"Certificate information extracted successfully for {domain}")
                return cert_info
                
            finally:
                # Clean up temporary file
                import os
                try:
                    os.unlink(temp_cert_path)
                except:
                    pass
            
        except subprocess.TimeoutExpired:
            logger.error(f"Certificate extraction timed out for {domain}")
            return {"error": "Certificate extraction timed out"}
        except Exception as e:
            logger.error(f"Certificate extraction failed for {domain}: {str(e)}")
            return {"error": f"Certificate extraction failed: {str(e)}"}
    
    def _format_certificate_field(self, field_string: str) -> str:
        """Format certificate field to match the required output format."""
        # Convert "CN=domain.com,O=Org,C=US" to "b'CN'=b'domain.com', b'O'=b'Org', b'C'=b'US'"
        if not field_string:
            return "Unknown"
        
        # Split by comma and process each component
        components = []
        for component in field_string.split(','):
            component = component.strip()
            if '=' in component:
                key, value = component.split('=', 1)
                components.append(f"b'{key.strip()}'=b'{value.strip()}'")
            else:
                components.append(f"b'{component}'")
        
        return ', '.join(components)
    
    def _certificate_extraction(self, domain: str) -> None:
        """Extract certificate information and store in results."""
        try:
            logger.info(f"Starting certificate extraction for {domain}")
            
            cert_info = self._extract_certificate_info(domain)
            self.results[domain]["certificate_details"] = cert_info
            
            logger.info(f"Certificate extraction completed for {domain}")
            
        except Exception as e:
            logger.error(f"Certificate extraction failed for {domain}: {str(e)}")
            self.results[domain]["certificate_details"] = {"error": str(e)}
    
    def _calculate_risk_score(self, domain: str) -> None:
        """Calculate risk score from scan results using unified scoring system."""
        risk_factors = []
        vulnerabilities = []

        results = self.results[domain]

        # Enhanced security checks - collect risk factors and create vulnerability objects
        enhanced_checks = results.get("enhanced_security_checks", {})
        if "error" not in enhanced_checks:
            
            # SSL Availability Check (CRITICAL if not available)
            ssl_availability = enhanced_checks.get("ssl_availability", {})
            if not ssl_availability.get("available", True):
                risk_factors.append("CRITICAL: SSL not available")
                vulnerabilities.append({
                    'severity': 'CRITICAL',
                    'vulnerability': 'SSL not available',
                    'description': 'SSL/TLS is not available on this domain'
                })

            # Hostname Certificate Match (HIGH if mismatch)
            hostname_check = enhanced_checks.get("hostname_certificate_match", {})
            if hostname_check.get("issue") and "hostname does not match" in hostname_check.get("issue", "").lower():
                risk_factors.append("HIGH: Hostname does not match SSL certificate")
                vulnerabilities.append({
                    'severity': 'HIGH',
                    'vulnerability': 'Hostname certificate mismatch',
                    'description': hostname_check.get("issue", "")
                })

            # HTTP to HTTPS Redirect (HIGH if not redirecting)
            http_redirect = enhanced_checks.get("http_to_https_redirect", {})
            if http_redirect.get("issue") and "does not redirect" in http_redirect.get("issue", "").lower():
                risk_factors.append("HIGH: HTTP does not redirect to HTTPS")
                vulnerabilities.append({
                    'severity': 'HIGH',
                    'vulnerability': 'HTTP to HTTPS redirect missing',
                    'description': http_redirect.get("issue", "")
                })

            # HTTPS Redirect Support (MEDIUM if not supported)
            https_redirect = enhanced_checks.get("https_redirect_support", {})
            if https_redirect.get("issue"):
                risk_factors.append("MEDIUM: HTTPS redirect not supported")
                vulnerabilities.append({
                    'severity': 'MEDIUM',
                    'vulnerability': 'HTTPS redirect support missing',
                    'description': https_redirect.get("issue", "")
                })

            # HSTS Enforcement (MEDIUM if not enforced)
            hsts_enforcement = enhanced_checks.get("hsts_enforcement", {})
            if hsts_enforcement.get("issue") and "not enforced" in hsts_enforcement.get("issue", "").lower():
                risk_factors.append("MEDIUM: HTTP Strict Transport Security (HSTS) not enforced")
                vulnerabilities.append({
                    'severity': 'MEDIUM',
                    'vulnerability': 'HSTS not enforced',
                    'description': hsts_enforcement.get("issue", "")
                })

            # HSTS includeSubDomains (LOW if missing)
            if hsts_enforcement.get("configuration_issues"):
                for issue in hsts_enforcement["configuration_issues"]:
                    if "includeSubDomains" in issue:
                        risk_factors.append("LOW: HSTS header does not contain includeSubDomains")
                        vulnerabilities.append({
                            'severity': 'LOW',
                            'vulnerability': 'HSTS includeSubDomains missing',
                            'description': issue
                        })
                        break

            # Weak TLS 1.2 Ciphers (MEDIUM/LOW based on severity)
            weak_tls12 = enhanced_checks.get("weak_tls12_ciphers", {})
            if weak_tls12.get("issue"):
                severity = "MEDIUM" if "only weak cipher suites" in weak_tls12.get("issue", "").lower() else "LOW"
                risk_factors.append(f"{severity}: Weak cipher suites supported in TLS 1.2")
                vulnerabilities.append({
                    'severity': severity,
                    'vulnerability': 'Weak TLS 1.2 cipher suites',
                    'description': weak_tls12.get("issue", "")
                })

            # Diffie-Hellman Strength
            dh_check = enhanced_checks.get("diffie_hellman_strength", {})
            if dh_check.get("issue"):
                severity = "MEDIUM" if "common" in dh_check.get("issue", "").lower() else "LOW"
                risk_factors.append(f"{severity}: Weak Diffie-Hellman prime used in key exchange")
                vulnerabilities.append({
                    'severity': severity,
                    'vulnerability': 'Weak Diffie-Hellman parameters',
                    'description': dh_check.get("issue", "")
                })

            # Insecure SSL/TLS Versions (MEDIUM if found)
            insecure_ssl = enhanced_checks.get("insecure_ssl_versions", {})
            if insecure_ssl.get("issue"):
                risk_factors.append("MEDIUM: Insecure SSL/TLS versions available")
                vulnerabilities.append({
                    'severity': 'MEDIUM',
                    'vulnerability': 'Insecure SSL/TLS versions',
                    'description': insecure_ssl.get("issue", "")
                })

            # Insecure Cipher Suites (MEDIUM if found)
            insecure_ciphers = enhanced_checks.get("insecure_cipher_suites", {})
            if insecure_ciphers.get("issue"):
                risk_factors.append("MEDIUM: Insecure cipher suite supported")
                vulnerabilities.append({
                    'severity': 'MEDIUM',
                    'vulnerability': 'Insecure cipher suites',
                    'description': insecure_ciphers.get("issue", "")
                })

            # SSL Certificate Chain (MEDIUM if missing)
            cert_chain = enhanced_checks.get("ssl_certificate_chain", {})
            if cert_chain.get("issue"):
                risk_factors.append("MEDIUM: SSL certificate chain missing from server response")
                vulnerabilities.append({
                    'severity': 'MEDIUM',
                    'vulnerability': 'Incomplete certificate chain',
                    'description': cert_chain.get("issue", "")
                })

        # Certificate Details Analysis
        cert_details = results.get("certificate_details", {})
        if "error" not in cert_details and cert_details:
            # Check certificate expiry
            days_until_expiry = cert_details.get("days_until_expiry")
            if isinstance(days_until_expiry, int):
                if days_until_expiry <= 0:
                    risk_factors.append("HIGH: SSL expired")
                    vulnerabilities.append({
                        'severity': 'HIGH',
                        'vulnerability': 'SSL certificate expired',
                        'description': f'Certificate expired {abs(days_until_expiry)} days ago'
                    })
                elif days_until_expiry <= 20:
                    risk_factors.append("MEDIUM: SSL expires within 20 days")
                    vulnerabilities.append({
                        'severity': 'MEDIUM',
                        'vulnerability': 'SSL certificate expires soon',
                        'description': f'Certificate expires in {days_until_expiry} days'
                    })
                elif days_until_expiry > 398:
                    risk_factors.append("MEDIUM: SSL expiration period longer than 398 days")
                    vulnerabilities.append({
                        'severity': 'MEDIUM',
                        'vulnerability': 'SSL certificate validity too long',
                        'description': f'Certificate expires in {days_until_expiry} days (longer than recommended)'
                    })

            # Check key algorithm and size
            key_algorithm = cert_details.get("key_algorithm", "").lower()
            key_size = cert_details.get("key_size", "")
            
            # Weak SSL Algorithm check
            if any(weak_alg in key_algorithm for weak_alg in ["md5", "sha1", "des"]):
                risk_factors.append("MEDIUM: Weak SSL algorithm")
                vulnerabilities.append({
                    'severity': 'MEDIUM',
                    'vulnerability': 'Weak SSL signature algorithm',
                    'description': f'Certificate uses weak algorithm: {cert_details.get("key_algorithm", "Unknown")}'
                })

            # Weak key size check
            if "bits" in key_size:
                try:
                    key_bits = int(key_size.split()[0])
                    if key_bits < 2048:
                        risk_factors.append("LOW: Weak public certificate key length")
                        vulnerabilities.append({
                            'severity': 'LOW',
                            'vulnerability': 'Weak certificate key length',
                            'description': f'Certificate key size {key_bits} bits is below recommended 2048 bits'
                        })
                except (ValueError, IndexError):
                    pass

        # testssl.sh vulnerabilities - collect risk factors and create vulnerability objects
        testssl = results.get("testssl", {})
        testssl_vulnerabilities = testssl.get("vulnerabilities", {})
        for vuln, details in testssl_vulnerabilities.items():
            severity = details.get("severity", "").upper()
            if severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                risk_factors.append(f"{severity}: {vuln}")
                vulnerabilities.append({
                    'severity': severity,
                    'vulnerability': vuln,
                    'description': details.get("finding", "SSL/TLS vulnerability detected")
                })

        # HSTS Preload List Check (LOW severity)
        hsts_enforcement = enhanced_checks.get("hsts_enforcement", {})
        if hsts_enforcement.get("hsts_enforced") and not hsts_enforcement.get("preload", False):
            risk_factors.append("LOW: Domain was not found on the HSTS preload list")
            vulnerabilities.append({
                'severity': 'LOW',
                'vulnerability': 'HSTS preload list missing',
                'description': 'Domain is not included in the HSTS preload list'
            })

        # Store risk factors
        self.results[domain]["risk_factors"] = risk_factors

        # Calculate actual score using unified scoring system
        try:
            scoring_system = get_unified_scoring()
            score_result = scoring_system.calculate_individual_scan_score(vulnerabilities, 'ENCRYPTION')

            # Set the calculated score and risk level
            self.results[domain]["risk_score"] = score_result['score']
            self.results[domain]["risk_level"] = scoring_system.get_risk_level(score_result['score'])

            # Store additional scoring details
            self.results[domain]["scoring_details"] = {
                'max_score': score_result['max_score'],
                'total_deduction': score_result['total_deduction'],
                'deduction_breakdown': score_result['deduction_breakdown'],
                'severity_counts': score_result['severity_counts'],
                'total_vulnerabilities': score_result['total_vulnerabilities'],
                'percentage': score_result['percentage']
            }

            logger.info(f"Calculated encryption score for {domain}: {score_result['score']}/950 ({score_result['percentage']}%) - {self.results[domain]['risk_level']} risk")

        except Exception as e:
            logger.error(f"Failed to calculate score for {domain}: {str(e)}")
            # Fallback to old behavior
            self.results[domain]["risk_score"] = 0
            self.results[domain]["risk_level"] = "Unknown"
    
    def _generate_recommendations(self, domain: str) -> None:
        """Generate security recommendations based on scan results."""
        recommendations = []
        results = self.results[domain]
        
        # SSL/TLS recommendations based on testssl.sh results
        testssl = results.get("testssl", {})
        vulnerabilities = testssl.get("vulnerabilities", {})
        if vulnerabilities:
            recommendations.append("Address SSL/TLS vulnerabilities found by testssl.sh")
        
        # Security recommendations from enhanced checks
        enhanced_checks = results.get("enhanced_security_checks", {})
        if "error" not in enhanced_checks:
            # HSTS recommendations
            hsts_enforcement = enhanced_checks.get("hsts_enforcement", {})
            if hsts_enforcement.get("issue"):
                recommendations.append("Implement proper HSTS enforcement")
            
            # HTTP to HTTPS redirect recommendations
            http_redirect = enhanced_checks.get("http_to_https_redirect", {})
            if http_redirect.get("issue"):
                recommendations.append("Configure HTTP to HTTPS redirects")
        
        # HSTS enforcement recommendations
        hsts_enforcement = enhanced_checks.get("hsts_enforcement", {})
        if hsts_enforcement.get("issue"):
            recommendations.append("Fix HSTS configuration issues")
        
        # General security recommendations
        enhanced_checks = results.get("enhanced_security_checks", {})
        if "error" not in enhanced_checks:
            summary = enhanced_checks.get("summary", {})
            if summary.get("issues_found", 0) > 0:
                recommendations.append("Address security issues found in enhanced security checks")
        
        # Vulnerability-specific recommendations
        testssl = results.get("testssl", {})
        vulnerabilities = testssl.get("vulnerabilities", {})
        for vuln, details in vulnerabilities.items():
            if details.get("severity") in ["HIGH", "CRITICAL"]:
                recommendations.append(f"Immediately address critical vulnerability: {vuln}")
        
        # Enhanced security recommendations
        enhanced_checks = results.get("enhanced_security_checks", {})
        if "error" not in enhanced_checks:
            summary = enhanced_checks.get("summary", {})
            issues = summary.get("all_issues", [])
            
            for issue in issues:
                if "ssl not available" in issue.lower():
                    recommendations.append("Configure SSL/TLS on the server")
                elif "hostname does not match" in issue.lower():
                    recommendations.append("Update SSL certificate to include proper hostname/SAN")
                elif "http does not redirect" in issue.lower():
                    recommendations.append("Configure HTTP to HTTPS redirects")
                elif "hsts" in issue.lower() and "includesubdomains" in issue.lower():
                    recommendations.append("Add includeSubDomains directive to HSTS header")
                elif "certificate chain" in issue.lower():
                    recommendations.append("Fix SSL certificate chain configuration")
                elif "revocation" in issue.lower():
                    recommendations.append("Ensure certificate revocation checking is available")
                elif "weak cipher" in issue.lower() and "tls 1.2" in issue.lower():
                    recommendations.append("Disable weak cipher suites in TLS 1.2 configuration and Configure strong cipher suites for TLS 1.2 (ECDHE+AESGCM, ECDHE+CHACHA20)")
                elif "diffie-hellman" in issue.lower():
                    recommendations.append("Upgrade Diffie-Hellman parameters to 2048+ bits or use ECDHE")
                elif "hsts" in issue.lower() and "not enforced" in issue.lower():
                    recommendations.append("Implement HTTP Strict Transport Security (HSTS) header")
                elif "https redirect not supported" in issue.lower():
                    recommendations.append("Configure proper HTTPS redirect support")
                elif "insecure ssl" in issue.lower() or "insecure tls" in issue.lower():
                    recommendations.append("Disable insecure SSL/TLS protocol versions (SSLv2, SSLv3, TLS 1.0, TLS 1.1)")
                elif "insecure cipher suite" in issue.lower():
                    recommendations.append("Remove insecure cipher suites (NULL, anonymous, export, RC4, DES)")
                elif "common diffie-hellman prime" in issue.lower():
                    recommendations.append("Replace common DH primes with unique, strong parameters")
                elif "ssl certificate chain missing" in issue.lower():
                    recommendations.append("Configure complete SSL certificate chain including intermediate certificates")
        
        # Certificate security recommendations
        enhanced_checks = results.get("enhanced_security_checks", {})
        if "error" not in enhanced_checks:
            summary = enhanced_checks.get("summary", {})
            issues = summary.get("all_issues", [])
            
            for issue in issues:
                if "expired" in issue.lower():
                    recommendations.append("Renew expired SSL certificate immediately")
                elif "expires soon" in issue.lower():
                    recommendations.append("Renew SSL certificate before expiration")
                elif "weak key size" in issue.lower():
                    recommendations.append("Generate new SSL certificate with 2048+ bit key size")
                elif "weak signature" in issue.lower() or "sha1" in issue.lower():
                    recommendations.append("Replace SSL certificate using SHA-1 with SHA-256 or stronger")
                elif "md5" in issue.lower():
                    recommendations.append("Replace SSL certificate using MD5 with SHA-256 or stronger")
            
                        # Certificate recommendations would go here if we had cert_inspector data
            # For now, we rely on enhanced security checks for certificate issues
        
        results["recommendations"] = recommendations
    
    def generate_report(self, domain: str, format: str = "json") -> str:
        """Generate formatted report of scan results."""
        if domain not in self.results:
            return f"No scan results found for {domain}"
        
        results = self.results[domain]
        if format.lower() == "text":
            return self._generate_text_report(results)
        
        else:
            return "Unsupported format. Use 'json', 'html', or 'text'"
    
    
    
    def _generate_text_report(self, results: Dict) -> str:
        """Generate plain text report."""
        risk_score = results.get("risk_score", 0)
        risk_level = "Low" if risk_score >= 800 else "Medium" if risk_score >= 600 else "High" if risk_score >= 400 else "Critical"
        
        # Certificate information - detailed certificate details from OpenSSL
        cert_details = results.get('certificate_details', {})
        cert_section = ""
        
        # Add detailed certificate information if available
        if "error" not in cert_details and cert_details:
            cert_section = f"""
CERTIFICATE DETAILS
{'-'*20}
Subject: {cert_details.get('subject', 'Unknown')}
Issuer: {cert_details.get('issuer', 'Unknown')}
Key Algorithm: {cert_details.get('key_algorithm', 'Unknown')}
Key Size: {cert_details.get('key_size', 'Unknown')}
Days Until Expiry: {cert_details.get('days_until_expiry', 'Unknown')}

"""
        
        # Add certificate security issues from enhanced security checks
        enhanced_checks = results.get('enhanced_security_checks', {})
        if "error" not in enhanced_checks and enhanced_checks:
            # Get certificate-related issues from enhanced checks
            cert_issues = []
            
            # Check hostname certificate match
            hostname_check = enhanced_checks.get("hostname_certificate_match", {})
            if hostname_check.get("issue"):
                cert_issues.append(hostname_check["issue"])
            
            # Check SSL certificate chain
            chain_check = enhanced_checks.get("ssl_certificate_chain", {})
            if chain_check.get("issue"):
                cert_issues.append(chain_check["issue"])
            
            if cert_issues:
                cert_section += f"""CERTIFICATE SECURITY ANALYSIS
{'-'*30}
Issues found:
"""
                for issue in cert_issues:
                    cert_section += f"- {issue}\n"
                cert_section += "\n"
        
        # Enhanced Security Checks section
        enhanced_checks = results.get('enhanced_security_checks', {})
        enhanced_section = ""
        if "error" not in enhanced_checks and enhanced_checks:
            enhanced_section = f"""
ENHANCED SECURITY CHECKS
{'-'*25}
"""
            
            check_names = {
                'ssl_availability': 'SSL/TLS Availability',
                'hostname_certificate_match': 'Hostname Certificate Match',
                'http_to_https_redirect': 'HTTP to HTTPS Redirect',
                'hsts_enforcement': 'HSTS Enforcement',
                'weak_tls12_ciphers': 'TLS 1.2 Cipher Security',
                'diffie_hellman_strength': 'Diffie-Hellman Strength',
                'https_redirect_support': 'HTTPS Redirect Support',
                'insecure_ssl_versions': 'Insecure SSL/TLS Versions',
                'insecure_cipher_suites': 'Insecure Cipher Suites',
                'ssl_certificate_chain': 'SSL Certificate Chain'
            }
            
            for check_key, check_name in check_names.items():
                if check_key in enhanced_checks and check_key != 'summary':
                    check_result = enhanced_checks[check_key]
                    if check_result.get('issue'):
                        # Failed check
                        enhanced_section += f"{check_name}: FAILED - {check_result['issue']}\n"
                    elif check_result.get('error'):
                        # Error in check
                        enhanced_section += f"{check_name}: ERROR - {check_result['error']}\n"
                    else:
                        # Passed check
                        enhanced_section += f"{check_name}: PASSED\n"
            
            # Summary
            summary = enhanced_checks.get('summary', {})
            if summary:
                total_checks = summary.get('total_checks', 0)
                issues_found = summary.get('issues_found', 0)
                enhanced_section += f"\nSummary: {issues_found} issues found out of {total_checks} checks\n"
        
        # Critical Security Checks section - highlighting the specific checks requested
        critical_checks_section = self._generate_critical_security_checks_section_text(results)
        
        # Comprehensive Security Status section - all requested checks
        comprehensive_status_section = self._generate_comprehensive_security_status_section_text(results)
        
        # Certificate Security Analysis section
        cert_security_analysis = results.get('certificate_analysis', {})
        cert_security_section = ""
        if "error" not in cert_security_analysis and cert_security_analysis:
            security_analysis = cert_security_analysis.get('security_analysis', {})
            issues = security_analysis.get('issues', [])
            recommendations = security_analysis.get('recommendations', [])
            
            if issues or recommendations:
                cert_security_section = f"""
CERTIFICATE SECURITY ANALYSIS
{'-'*30}
"""
                if issues:
                    cert_security_section += "Issues:\n"
                    for issue in issues:
                        cert_security_section += f"- {issue}\n"
                
                if recommendations:
                    cert_security_section += "Recommendations:\n" 
                    for rec in recommendations:
                        cert_security_section += f"- {rec}\n"
                
                cert_security_section += "\n"
        
        # Check if there are testssl vulnerabilities to include in report
        testssl_results = results.get('testssl', {})
        vulnerabilities = testssl_results.get('vulnerabilities', {})
        vuln_count = len(vulnerabilities)
        
        # Generate testssl section only if there are vulnerabilities
        testssl_section = ""
        if vuln_count > 0:
            testssl_section = f"""
TESTSSL.SH RESULTS
{'-'*20}
Vulnerabilities Found: {vuln_count}
"""
            # Add details about vulnerabilities
            for vuln_name, vuln_details in vulnerabilities.items():
                severity = vuln_details.get('severity', 'Unknown')
                finding = vuln_details.get('finding', 'No details')
                testssl_section += f"• {vuln_name} ({severity}): {finding}\n"
            testssl_section += "\n"
        
        report = f"""
VENDOR RISK ASSESSMENT REPORT
{'='*50}

Domain: {results['domain']}
Scan Date: {results['scan_timestamp']}
Risk Score: {risk_score}/950 ({risk_level} Risk)
{testssl_section}{cert_section}ENHANCED SECURITY CHECKS
{'-'*20}
Issues Found: {results.get('enhanced_security_checks', {}).get('summary', {}).get('issues_found', 'N/A')}

RISK FACTORS
{'-'*20}
"""
        for factor in results.get('risk_factors', []):
            report += f"• {factor}\n"
        
        # REMOVED: Recommendations section as requested
        # No longer including recommendations in reports
        
        report += enhanced_section
        report += critical_checks_section
        report += comprehensive_status_section
        # report += cert_security_section # This line is removed as per the edit hint
        
        return report

    def _generate_comprehensive_security_status_section_text(self, results: Dict) -> str:
        """Generate comprehensive security status section showing all requested checks."""
        
        # Get all relevant data
        enhanced_checks = results.get('enhanced_security_checks', {})
        testssl = results.get('testssl', {})
        
        # Initialize all checks status
        security_status = {}
        
        # 1. Encryption vulnerability management (from testssl.sh)
        vulnerabilities = testssl.get('vulnerabilities', {})
        if vulnerabilities:
            critical_vulns = [v for v in vulnerabilities.values() if v.get('severity') in ['HIGH', 'CRITICAL']]
            if critical_vulns:
                security_status['encryption_vulnerability'] = {"status": "FAILED", "message": f"Critical encryption vulnerabilities detected: {len(critical_vulns)} issues"}
            else:
                security_status['encryption_vulnerability'] = {"status": "PASSED", "message": "No critical encryption vulnerabilities detected"}
        else:
            security_status['encryption_vulnerability'] = {"status": "PASSED", "message": "No encryption vulnerabilities detected"}
        
        # 2. Revoked certificate in use (basic check - would need OCSP validation for full check)
        security_status['revoked_certificate'] = {"status": "UNKNOWN", "message": "Certificate revocation status not checked (requires OCSP validation)"}
        
        # 3. Untrusted SSL certificate (from enhanced security checks)
        hostname_check = enhanced_checks.get('hostname_certificate_match', {})
        if hostname_check.get('issue') and 'hostname does not match' in hostname_check.get('issue', '').lower():
            security_status['untrusted_certificate'] = {"status": "FAILED", "message": "SSL certificate hostname mismatch detected"}
        else:
            security_status['untrusted_certificate'] = {"status": "PASSED", "message": "SSL certificate appears trusted"}
        
        # 4. Weak SSL algorithm (from enhanced security checks)
        weak_ciphers = enhanced_checks.get('weak_tls12_ciphers', {})
        insecure_ciphers = enhanced_checks.get('insecure_cipher_suites', {})
        if weak_ciphers.get('issue') or insecure_ciphers.get('issue'):
            weak_alg_issue = weak_ciphers.get('issue', '') or insecure_ciphers.get('issue', '')
            security_status['weak_ssl_algorithm'] = {"status": "FAILED", "message": weak_alg_issue}
        else:
            security_status['weak_ssl_algorithm'] = {"status": "PASSED", "message": "Strong SSL algorithms in use"}
        
        # Generate text section
        text_section = f"""
COMPREHENSIVE SECURITY STATUS
{'-'*35}
All vendor risk security checks:

"""
        
        check_names = {
            'encryption_vulnerability': 'Encryption Vulnerability Management',
            'revoked_certificate': 'Revoked Certificate Check',
            'untrusted_certificate': 'Untrusted SSL Certificate',
            'weak_ssl_algorithm': 'Weak SSL Algorithm'
        }
        
        for check_key, check_name in check_names.items():
            status_info = security_status[check_key]
            status = status_info['status']
            message = status_info['message']
            
            text_section += f'{check_name}: {status} - {message}\n'
        
        text_section += "\n"
        return text_section

   

    def _generate_critical_security_checks_section(self, results: Dict) -> str:
        """Generate a dedicated section for critical security checks."""
        # Check if we're generating HTML or text (based on context)
        # For now, we'll generate HTML version and create a separate text version
        
        # Get enhanced security checks
        enhanced_checks = results.get('enhanced_security_checks', {})
        
        # Get HSTS enforcement status from enhanced security checks
        hsts_enforcement = enhanced_checks.get('hsts_enforcement', {})
        
        # Get certificate security analysis
        cert_info = results.get('detailed_certificate', {})
        cert_security = cert_info.get('security_analysis', {}) if cert_info else {}
        
        # Critical checks to highlight
        critical_status = {}
        
        # 1. HSTS enforcement check (includes preload directive checking)
        if hsts_enforcement.get('hsts_enforced', False) and hsts_enforcement.get('preload', False):
            critical_status['hsts_preload'] = {"status": "PASSED", "message": "HSTS properly enforced with preload directive"}
        elif hsts_enforcement.get('hsts_enforced', False):
            critical_status['hsts_preload'] = {"status": "WARNING", "message": "HSTS enforced but preload directive missing"}
        else:
            critical_status['hsts_preload'] = {"status": "FAILED", "message": "HSTS not properly enforced"}
        
        # 2. HSTS header does not contain includeSubDomains
        hsts_enforcement = enhanced_checks.get('hsts_enforcement', {})
        if hsts_enforcement.get('includes_subdomains', False):
            critical_status['hsts_includesubdomains'] = {"status": "PASSED", "message": "HSTS header contains includeSubDomains"}
        elif hsts_enforcement.get('configuration_issues'):
            issues = hsts_enforcement['configuration_issues']
            subdomain_issue = any('includeSubDomains' in issue for issue in issues)
            if subdomain_issue:
                critical_status['hsts_includesubdomains'] = {"status": "FAILED", "message": "HSTS header does not contain includeSubDomains"}
            else:
                critical_status['hsts_includesubdomains'] = {"status": "PASSED", "message": "HSTS header contains includeSubDomains"}
        else:
            critical_status['hsts_includesubdomains'] = {"status": "FAILED", "message": "HSTS header does not contain includeSubDomains"}
        
        # 3. Weak Diffie-Hellman prime used in key exchange
        dh_check = enhanced_checks.get('diffie_hellman_strength', {})
        if dh_check.get('dh_secure', True):
            critical_status['weak_dh'] = {"status": "PASSED", "message": "Strong Diffie-Hellman parameters"}
        elif dh_check.get('issue'):
            critical_status['weak_dh'] = {"status": "FAILED", "message": dh_check['issue']}
        else:
            critical_status['weak_dh'] = {"status": "UNKNOWN", "message": "Could not verify Diffie-Hellman strength"}
        
        # 4. Weak public certificate key length (from DH key exchange analysis)
        dh_check = enhanced_checks.get('diffie_hellman_strength', {})
        dh_info = dh_check.get('dh_info', {})
        
        # Check for weak key sizes in DH parameters
        weak_key_found = False
        weak_key_message = ""
        
        if dh_info.get('weakness'):
            weak_key_found = True
            weak_key_message = dh_info['weakness']
        elif dh_info.get('temp_key'):
            # Parse temp key info for key sizes
            temp_key = dh_info['temp_key']
            if 'DH, 512 bits' in temp_key or 'DH, 768 bits' in temp_key or 'DH, 1024 bits' in temp_key:
                weak_key_found = True
                weak_key_message = f"Weak key size detected in {temp_key}"
        
        if weak_key_found:
            critical_status['weak_key'] = {"status": "FAILED", "message": weak_key_message}
        else:
            critical_status['weak_key'] = {"status": "PASSED", "message": "Certificate key length is adequate"}
        
        # 5. Weak cipher suites supported in TLS 1.2
        tls12_cipher = enhanced_checks.get('weak_tls12_ciphers', {})
        
        if tls12_cipher.get('issue'):
            critical_status['weak_tls12'] = {"status": "FAILED", "message": tls12_cipher['issue']}
        elif tls12_cipher.get('tls12_cipher_secure', True):
            critical_status['weak_tls12'] = {"status": "PASSED", "message": "Strong TLS 1.2 cipher suites supported"}
        else:
            critical_status['weak_tls12'] = {"status": "UNKNOWN", "message": "Could not verify TLS 1.2 cipher strength"}
        
        # Generate HTML version
        html_section = """
        <div class="section">
            <h2>Critical Security Status</h2>
            <p><em>Key security checks specifically requested:</em></p>
        """
        
        check_names = {
            'hsts_preload': 'HSTS Preload List Status',
            'hsts_includesubdomains': 'HSTS includeSubDomains Directive',
            'weak_dh': 'Diffie-Hellman Key Exchange Strength', 
            'weak_key': 'Certificate Key Length',
            'weak_tls12': 'TLS 1.2 Cipher Suite Strength'
        }
        
        for check_key, check_name in check_names.items():
            status_info = critical_status[check_key]
            status = status_info['status']
            message = status_info['message']
            
            if status == "PASSED":
                html_section += f'<p class="good"><strong>{check_name}:</strong> ✓ {message}</p>'
            elif status == "FAILED":
                html_section += f'<p class="critical"><strong>{check_name}:</strong> ✗ {message}</p>'
            else:
                html_section += f'<p class="warning"><strong>{check_name}:</strong> ? {message}</p>'
        
        html_section += "</div>"
        return html_section

    def _generate_critical_security_checks_section_text(self, results: Dict) -> str:
        """Generate text version of critical security checks section."""
        # Get enhanced security checks
        enhanced_checks = results.get('enhanced_security_checks', {})
        
        # Get HSTS enforcement status from enhanced security checks
        hsts_enforcement = enhanced_checks.get('hsts_enforcement', {})
        
        # Get certificate security analysis from enhanced security checks
        enhanced_checks = results.get('enhanced_security_checks', {})
        
        # Critical checks to highlight
        critical_status = {}
        
        # 1. HSTS enforcement check (includes preload directive checking)
        if hsts_enforcement.get('hsts_enforced', False) and hsts_enforcement.get('preload', False):
            critical_status['hsts_preload'] = {"status": "PASSED", "message": "HSTS properly enforced with preload directive"}
        elif hsts_enforcement.get('hsts_enforced', False):
            critical_status['hsts_preload'] = {"status": "WARNING", "message": "HSTS enforced but preload directive missing"}
        else:
            critical_status['hsts_preload'] = {"status": "FAILED", "message": "HSTS not properly enforced"}
        
        # 2. HSTS header does not contain includeSubDomains
        if hsts_enforcement.get('includes_subdomains', False):
            critical_status['hsts_includesubdomains'] = {"status": "PASSED", "message": "HSTS header contains includeSubDomains"}
        elif hsts_enforcement.get('configuration_issues'):
            issues = hsts_enforcement['configuration_issues']
            subdomain_issue = any('includeSubDomains' in issue for issue in issues)
            if subdomain_issue:
                critical_status['hsts_includesubdomains'] = {"status": "FAILED", "message": "HSTS header does not contain includeSubDomains"}
            else:
                critical_status['hsts_includesubdomains'] = {"status": "PASSED", "message": "HSTS header contains includeSubDomains"}
        else:
            critical_status['hsts_includesubdomains'] = {"status": "FAILED", "message": "HSTS header does not contain includeSubDomains"}
        
        # 3. Weak Diffie-Hellman prime used in key exchange
        dh_check = enhanced_checks.get('diffie_hellman_strength', {})
        if dh_check.get('dh_secure', True):
            critical_status['weak_dh'] = {"status": "PASSED", "message": "Strong Diffie-Hellman parameters"}
        elif dh_check.get('issue'):
            critical_status['weak_dh'] = {"status": "FAILED", "message": dh_check['issue']}
        else:
            critical_status['weak_dh'] = {"status": "UNKNOWN", "message": "Could not verify Diffie-Hellman strength"}
        
        # 4. Weak public certificate key length (from DH key exchange analysis)
        dh_check = enhanced_checks.get('diffie_hellman_strength', {})
        dh_info = dh_check.get('dh_info', {})
        
        # Check for weak key sizes in DH parameters
        weak_key_found = False
        weak_key_message = ""
        
        if dh_info.get('weakness'):
            weak_key_found = True
            weak_key_message = dh_info['weakness']
        elif dh_info.get('temp_key'):
            # Parse temp key info for key sizes
            temp_key = dh_info['temp_key']
            if 'DH, 512 bits' in temp_key or 'DH, 768 bits' in temp_key or 'DH, 1024 bits' in temp_key:
                weak_key_found = True
                weak_key_message = f"Weak key size detected in {temp_key}"
        
        if weak_key_found:
            critical_status['weak_key'] = {"status": "FAILED", "message": weak_key_message}
        else:
            critical_status['weak_key'] = {"status": "PASSED", "message": "Certificate key length is adequate"}
        
        # 5. Weak cipher suites supported in TLS 1.2
        tls12_cipher = enhanced_checks.get('weak_tls12_ciphers', {})
        
        if tls12_cipher.get('issue'):
            critical_status['weak_tls12'] = {"status": "FAILED", "message": tls12_cipher['issue']}
        elif tls12_cipher.get('tls12_cipher_secure', True):
            critical_status['weak_tls12'] = {"status": "PASSED", "message": "Strong TLS 1.2 cipher suites supported"}
        else:
            critical_status['weak_tls12'] = {"status": "UNKNOWN", "message": "Could not verify TLS 1.2 cipher strength"}
        
        # Generate text version
        text_section = f"""
CRITICAL SECURITY STATUS
{'-'*25}
Key security checks specifically requested:

"""
        
        check_names = {
            'hsts_preload': 'HSTS Preload List Status',
            'hsts_includesubdomains': 'HSTS includeSubDomains Directive',
            'weak_dh': 'Diffie-Hellman Key Exchange Strength', 
            'weak_key': 'Certificate Key Length',
            'weak_tls12': 'TLS 1.2 Cipher Suite Strength'
        }
        
        for check_key, check_name in check_names.items():
            status_info = critical_status[check_key]
            status = status_info['status']
            message = status_info['message']
            
            if status == "PASSED":
                text_section += f'{check_name}: PASSED - {message}\n'
            elif status == "FAILED":
                text_section += f'{check_name}: FAILED - {message}\n'
            else:
                text_section += f'{check_name}: UNKNOWN - {message}\n'
        
        text_section += "\n"
        return text_section

    def _generate_comprehensive_security_status_html(self, results: Dict) -> str:
        """Generate comprehensive security status section for HTML report with all requested checks."""
        enhanced_checks = results.get('enhanced_security_checks', {})
        hsts_enforcement = enhanced_checks.get('hsts_enforcement', {})
        
        # Collect status for all 8 requested checks
        comprehensive_status = {}
        
        # 1. HSTS enforcement check (includes preload directive checking)
        if hsts_enforcement.get('hsts_enforced', False) and hsts_enforcement.get('preload', False):
            comprehensive_status['hsts_preload'] = {"status": "PASSED", "message": "HSTS properly enforced with preload directive"}
        elif hsts_enforcement.get('hsts_enforced', False):
            comprehensive_status['hsts_preload'] = {"status": "WARNING", "message": "HSTS enforced but preload directive missing"}
        else:
            comprehensive_status['hsts_preload'] = {"status": "FAILED", "message": "HSTS not properly enforced"}
        
        # 2. HSTS header does not contain includeSubDomains
        if hsts_enforcement.get('includes_subdomains', False):
            comprehensive_status['hsts_includesubdomains'] = {"status": "PASSED", "message": "HSTS header contains includeSubDomains"}
        elif hsts_enforcement.get('configuration_issues'):
            issues = hsts_enforcement['configuration_issues']
            subdomain_issue = any('includeSubDomains' in issue for issue in issues)
            if subdomain_issue:
                comprehensive_status['hsts_includesubdomains'] = {"status": "FAILED", "message": "HSTS header does not contain includeSubDomains"}
            else:
                comprehensive_status['hsts_includesubdomains'] = {"status": "PASSED", "message": "HSTS header contains includeSubDomains"}
        else:
            comprehensive_status['hsts_includesubdomains'] = {"status": "UNKNOWN", "message": "Could not verify HSTS includeSubDomains directive"}
        
        # 3. Weak Diffie-Hellman prime used in key exchange
        dh_check = enhanced_checks.get('diffie_hellman_strength', {})
        if dh_check.get('dh_secure', True):
            comprehensive_status['weak_dh'] = {"status": "PASSED", "message": "Strong Diffie-Hellman parameters"}
        elif dh_check.get('issue'):
            comprehensive_status['weak_dh'] = {"status": "FAILED", "message": dh_check['issue']}
        else:
            comprehensive_status['weak_dh'] = {"status": "UNKNOWN", "message": "Could not verify Diffie-Hellman strength"}
        
        # 4. Weak public certificate key length (from DH key exchange analysis)
        dh_check = enhanced_checks.get('diffie_hellman_strength', {})
        dh_info = dh_check.get('dh_info', {})
        
        # Check for weak key sizes in DH parameters
        weak_key_found = False
        weak_key_message = ""
        
        if dh_info.get('weakness'):
            weak_key_found = True
            weak_key_message = dh_info['weakness']
        elif dh_info.get('temp_key'):
            # Parse temp key info for key sizes
            temp_key = dh_info['temp_key']
            if 'DH, 512 bits' in temp_key or 'DH, 768 bits' in temp_key or 'DH, 1024 bits' in temp_key:
                weak_key_found = True
                weak_key_message = f"Weak key size detected in {temp_key}"
        
        if weak_key_found:
            comprehensive_status['weak_key'] = {"status": "FAILED", "message": weak_key_message}
        else:
            comprehensive_status['weak_key'] = {"status": "PASSED", "message": "Certificate key length is adequate"}
        
        # 5. Weak cipher suites supported in TLS 1.2
        tls12_cipher = enhanced_checks.get('weak_tls12_ciphers', {})
        if tls12_cipher.get('issue'):
            comprehensive_status['weak_tls12'] = {"status": "FAILED", "message": tls12_cipher['issue']}
        elif tls12_cipher.get('tls12_cipher_secure', True):
            comprehensive_status['weak_tls12'] = {"status": "PASSED", "message": "Strong TLS 1.2 cipher suites supported"}
        else:
            comprehensive_status['weak_tls12'] = {"status": "UNKNOWN", "message": "Could not verify TLS 1.2 cipher strength"}
        
        # 6. Encryption vulnerability management
        vuln_mgmt_issues = []
        if not enhanced_checks.get('ssl_availability', {}).get('available', True):
            vuln_mgmt_issues.append("SSL not available")
        if enhanced_checks.get('insecure_ssl_versions', {}).get('insecure_versions'):
            vuln_mgmt_issues.append("Insecure SSL/TLS versions supported")
        if enhanced_checks.get('insecure_cipher_suites', {}).get('insecure_ciphers'):
            vuln_mgmt_issues.append("Insecure cipher suites supported")
        
        if vuln_mgmt_issues:
            comprehensive_status['encryption_vuln'] = {"status": "FAILED", "message": f"Encryption vulnerability management issues: {'; '.join(vuln_mgmt_issues)}"}
        else:
            comprehensive_status['encryption_vuln'] = {"status": "PASSED", "message": "No encryption vulnerabilities detected"}
        
        # 7. Revoked certificate in use
        # This would require OCSP checking - for now mark as not implemented
        comprehensive_status['revoked_cert'] = {"status": "UNKNOWN", "message": "Revoked certificate check not implemented (requires OCSP validation)"}
        
        # 8. Untrusted SSL certificate (from hostname check)
        hostname_check = enhanced_checks.get('hostname_certificate_match', {})
        if hostname_check.get('issue'):
            comprehensive_status['untrusted_cert'] = {"status": "FAILED", "message": f"SSL certificate issue: {hostname_check['issue']}"}
        else:
            comprehensive_status['untrusted_cert'] = {"status": "PASSED", "message": "SSL certificate appears trusted"}
        
        # Generate HTML
        html_section = """
        <div class="section">
            <h2>Comprehensive Security Status</h2>
            <p><em>All security checks as requested:</em></p>
        """
        
        check_names = {
            'hsts_preload': 'HSTS Preload List Status',
            'hsts_includesubdomains': 'HSTS includeSubDomains Directive',
            'weak_dh': 'Diffie-Hellman Key Exchange Strength', 
            'weak_key': 'Certificate Key Length',
            'weak_tls12': 'TLS 1.2 Cipher Suite Strength',
            'encryption_vuln': 'Encryption Vulnerability Management',
            'revoked_cert': 'Revoked Certificate Check',
            'untrusted_cert': 'SSL Certificate Trust'
        }
        
        for check_key, check_name in check_names.items():
            status_info = comprehensive_status[check_key]
            status = status_info['status']
            message = status_info['message']
            
            if status == "PASSED":
                html_section += f'<p><strong>{check_name}:</strong> <span class="passed">PASSED</span> - {message}</p>'
            elif status == "FAILED":
                html_section += f'<p><strong>{check_name}:</strong> <span class="failed">FAILED</span> - {message}</p>'
            else:
                html_section += f'<p><strong>{check_name}:</strong> <span class="unknown">UNKNOWN</span> - {message}</p>'
        
        html_section += "</div>"
        return html_section

    
    
    def _enhanced_security_checks(self, domain: str) -> None:
        """Run enhanced security checks using the EnhancedSecurityChecker."""
        try:
            logger.info(f"Starting enhanced security checks for {domain}")
            
            # Enhanced security checks with detailed certificate inspection
            enhanced_checker = EnhancedSecurityChecker(timeout=config.ENHANCED_SECURITY_TIMEOUT)
            enhanced_results = enhanced_checker.run_all_checks(domain)
            
            self.results[domain]["enhanced_security_checks"] = enhanced_results
            logger.info(f"Enhanced security checks completed for {domain}")
            
        except Exception as e:
            logger.error(f"Enhanced security checks failed for {domain}: {str(e)}")
            self.results[domain]["enhanced_security_checks"] = {"error": str(e)}


def main():
    """Main function for command-line usage."""
    parser = argparse.ArgumentParser(description="Vendor Risk Scanner - SSL/Encryption Analysis")
    parser.add_argument("domain", help="Domain to scan")
    parser.add_argument("--format", choices=["json", "html", "text"], default="json", 
                       help="Output format")
    parser.add_argument("--quick", action="store_true", 
                       help="Perform quick scan (skip time-intensive tests)")
    parser.add_argument("--output", help="Output file path")
    parser.add_argument("--testssl-path", default=None,
                       help="Path to testssl.sh script (default: auto-detect)")
    parser.add_argument("--detailed-cert", action="store_true",
                       help="Include detailed certificate inspection (enabled by default)")
    
    args = parser.parse_args()
    
    # Initialize scanner
    scanner = VendorRiskScanner()
    
    # Perform scan
    try:
        results = scanner.scan_domain(args.domain, full_scan=not args.quick)
        
        # Generate report
        report = scanner.generate_report(args.domain, format=args.format)
        
        # Output results
        if args.output:
            with open(args.output, 'w') as f:
                f.write(report)
            print(f"Report saved to {args.output}")
        else:
            print(report)
            
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Scan failed: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main() 