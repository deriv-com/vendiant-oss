#!/usr/bin/env python3
"""
Enhanced Security Checks Module
Implements additional security validations that were missing from the core scanner.
OPTIMIZED FOR FAST EXECUTION
"""

import requests
import socket
import ssl
import subprocess
import re
from urllib.parse import urlparse
from typing import Dict, List, Tuple, Optional
import logging

logger = logging.getLogger(__name__)

class EnhancedSecurityChecker:
    """Additional security checks for comprehensive vendor risk assessment."""
    
    def __init__(self, timeout: int = 10):
        self.timeout = min(timeout, 30)  # Cap timeout at 30 seconds max
    
    def check_ssl_availability(self, domain: str, port: int = 443) -> Dict:
        """Check if SSL/TLS is available on the domain."""
        logger.info(f"Checking SSL availability for {domain}:{port}")
        try:
            context = ssl.create_default_context()
            context.check_hostname = False  # We'll check hostname separately
            context.verify_mode = ssl.CERT_NONE  # Don't verify cert for availability check
            
            with socket.create_connection((domain, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    result = {
                        "available": True,
                        "protocol": ssock.version(),
                        "cipher": ssock.cipher()[0] if ssock.cipher() else "Unknown"
                    }
                    logger.info(f"SSL availability check passed for {domain} - Protocol: {result['protocol']}, Cipher: {result['cipher']}")
                    return result
        except Exception as e:
            logger.warning(f"SSL availability check failed for {domain}: {str(e)}")
            return {
                "available": False,
                "error": str(e),
                "issue": "SSL not available"
            }
    
    def check_hostname_certificate_match(self, domain: str, port: int = 443) -> Dict:
        """Check if hostname matches the SSL certificate."""
        logger.info(f"Checking hostname certificate match for {domain}:{port}")
        try:
            import fnmatch
            context = ssl.create_default_context()
            context.check_hostname = False  # We want to manually check hostname
            context.verify_mode = ssl.CERT_OPTIONAL  # Get cert even if invalid or self-signed 
            with socket.create_connection((domain, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    if not cert:
                        return {
                            "hostname_matches": False,
                            "error": "No certificate presented by server",
                            "issue": "No certificate available"
                        }
                    # Check subject alternative names
                    san_list = []
                    if 'subjectAltName' in cert:
                        san_list = [name[1] for name in cert['subjectAltName'] if name[0] == 'DNS']
                    
                    # Check common name
                    common_name = None
                    if 'subject' in cert:
                        for attr in cert['subject']:
                            if attr[0][0] == 'commonName':
                                common_name = attr[0][1]
                                break
                    
                    # Verify hostname match inline (normalize domain to lowercase)
                    hostname_match = False
                    domain_lower = domain.lower()
                    
                    # Check SANs first (preferred)
                    for san in san_list:
                        san_lower = san.lower()
                        # Handle wildcard certificates
                        if san_lower.startswith('*.'):
                            pattern = san_lower.replace('*.', '*.')
                            if fnmatch.fnmatch(domain_lower, pattern):
                                hostname_match = True
                                break
                        elif san_lower == domain_lower:
                            hostname_match = True
                            break
                    
                    # Check common name if no SANs matched
                    if not hostname_match and common_name:
                        common_name_lower = common_name.lower()
                        if common_name_lower.startswith('*.'):
                            pattern = common_name_lower.replace('*.', '*.')
                            if fnmatch.fnmatch(domain_lower, pattern):
                                hostname_match = True
                        elif common_name_lower == domain_lower:
                            hostname_match = True
                    
                    result = {
                        "hostname_matches": hostname_match,
                        "common_name": common_name,
                        "subject_alt_names": san_list,
                        "issue": None if hostname_match else "Hostname does not match SSL certificate"
                    }
                    
                    if hostname_match:
                        logger.info(f"Hostname certificate match passed for {domain} - CN: {common_name}, SANs: {len(san_list)}")
                    else:
                        logger.warning(f"Hostname certificate match failed for {domain} - CN: {common_name}, SANs: {san_list}")
                    
                    return result
                    
        except Exception as e:
            logger.error(f"Hostname certificate match check failed for {domain}: {str(e)}")
            return {
                "hostname_matches": False,
                "error": str(e),
                "issue": "Could not verify hostname certificate match"
            }
    
    def check_http_to_https_redirect(self, domain: str) -> Dict:
        """Check if HTTP redirects to HTTPS."""
        logger.info(f"Checking HTTP to HTTPS redirect for {domain}")
        try:
            # Test HTTP request
            http_url = f"http://{domain}"
            response = requests.get(http_url, allow_redirects=True, timeout=self.timeout)
            
            # Check if final URL is HTTPS
            final_url = response.url
            redirects_to_https = final_url.startswith('https://')
            
            #Quick domain check
            from urllib.parse import urlparse
            final_domain = urlparse(final_url).netloc.replace('www.', '')
            original_domain = domain.replace('www.', '')
            same_domain = final_domain == original_domain
            
            # Generate warning if redirects to different domain
            warning = None
            if redirects_to_https and not same_domain:
                warning = f"HTTP redirects to HTTPS but on different domain: {final_domain}"
            
            # Get redirect chain
            redirect_chain = []
            if hasattr(response, 'history'):
                for resp in response.history:
                    redirect_chain.append({
                        "status_code": resp.status_code,
                        "location": resp.headers.get('Location', ''),
                        "url": resp.url
                    })
            
            redirect_chain.append({
                "status_code": response.status_code,
                "url": response.url
            })
            
            result = {
                "redirects_to_https": redirects_to_https,
                "final_url": final_url,
                "redirect_chain": redirect_chain,
                "same_domain": same_domain,
                "warning": warning,
                "issue": None if redirects_to_https else "HTTP does not redirect to HTTPS"
            }
            
            if redirects_to_https:
                logger.info(f"HTTP to HTTPS redirect check passed for {domain} - Redirects: {len(redirect_chain)-1}")
                if warning:
                    logger.warning(f"⚠️ {warning}")
            else:
                logger.warning(f"HTTP to HTTPS redirect check failed for {domain} - Final URL: {final_url}")
            
            return result
            
        except Exception as e:
            logger.error(f"HTTP to HTTPS redirect check failed for {domain}: {str(e)}")
            return {
                "redirects_to_https": False,
                "error": str(e),
                "issue": "Unable to verify HTTP to HTTPS redirect configuration"
            }
    
    def check_weak_tls12_ciphers(self, domain: str, port: int = 443) -> Dict:
        """Check for weak cipher suites in TLS 1.2."""
        logger.info(f"Checking TLS 1.2 cipher suites for {domain}:{port}")
        import re
        if not re.match(r'^[a-zA-Z0-9\.\-]+$', domain):
            return {
                "tls12_cipher_secure": False,
                "error": "Invalid domain format",
                "issue": "Invalid domain"
            }
        
        # Use OpenSSL to check TLS 1.2 cipher suites
        try:
            # Test specific weak cipher suites
            weak_cipher_tests = {
                'NULL': 'NULL-SHA:NULL-MD5',
                'EXPORT': 'EXP-RC4-MD5:EXP-DES-CBC-SHA',
                'DES': 'DES-CBC-SHA',
                '3DES': 'DES-CBC3-SHA',
                'RC4': 'RC4-SHA:RC4-MD5',
                'MD5': 'RC4-MD5',
                'ADH': 'ADH-AES256-SHA:ADH-AES128-SHA',
                'AECDH': 'AECDH-AES256-SHA:AECDH-AES128-SHA'
            }
            
            weak_ciphers_found = []
        
            # Test each weak cipher category
            for weak_type, cipher_string in weak_cipher_tests.items():
                cmd = [
                    'openssl', 's_client', '-connect', f'{domain}:{port}',
                    '-tls1_2', '-cipher', cipher_string
                ]
                
                try:
                    result = subprocess.run(cmd, input='Q\n', text=True, capture_output=True, timeout=5)
                    
                    if result.returncode == 0:
                        # Extract cipher name from output
                        for line in result.stdout.split('\n'):
                            if 'Cipher    :' in line:
                                cipher_name = line.split(':')[1].strip()
                                if cipher_name and cipher_name != '0000':
                                    weak_ciphers_found.append(f"{weak_type}: {cipher_name}")
                                break
                except:
                    continue
            
            # If weak ciphers found, return failure
            if weak_ciphers_found:
                logger.warning(f"TLS 1.2 cipher check failed for {domain} - Weak ciphers: {weak_ciphers_found}")
                return {
                    "tls12_cipher_secure": False,
                    "cipher_name": "Multiple weak ciphers",
                    "weak_components": weak_ciphers_found,
                    "issue": "Weak cipher suites supported in TLS 1.2"
                }
            
            # If no weak ciphers, test what strong cipher is used
            cmd = [
                'openssl', 's_client', '-connect', f'{domain}:{port}',
                '-tls1_2', '-cipher', 'HIGH:!aNULL:!eNULL'
            ]
            
            result = subprocess.run(cmd, input='Q\n', text=True, capture_output=True, timeout=self.timeout)
            if result.returncode == 0:
                # Extract cipher for informational purposes only
                cipher_name = "Unknown"
                for line in result.stdout.split('\n'):
                    if 'Cipher    :' in line:
                        cipher_name = line.split(':')[1].strip()
                        break
                
                # ✅ SIMPLIFIED - No redundant checking!
                logger.info(f"TLS 1.2 cipher check passed for {domain} - Cipher: {cipher_name}")
                return {
                    "tls12_cipher_secure": True,
                    "cipher_name": cipher_name,
                    "weak_components": []
                }
            else:
                # Connection with strong ciphers failed
                logger.warning(f"TLS 1.2 strong cipher connection failed for {domain}: {result.stderr}")
                return {
                    "tls12_cipher_secure": False,
                    "error": result.stderr,
                    "issue": "TLS 1.2 connection failed or not supported"
                }
                
        except Exception as e:
            logger.error(f"TLS 1.2 cipher check failed for {domain}: {str(e)}")
            return {
                "tls12_cipher_secure": False,
                "error": str(e),
                "issue": "Could not check TLS 1.2 cipher suites"
            }
    
    def check_diffie_hellman_strength(self, domain: str, port: int = 443) -> Dict:
        """Check for weak Diffie-Hellman parameters."""
        logger.info(f"Checking Diffie-Hellman strength for {domain}:{port}")
        try:
            # Use OpenSSL to check DH parameters
            cmd = [
                'openssl', 's_client', '-connect', f'{domain}:{port}',
                '-cipher', 'DHE'
            ]
            
            result = subprocess.run(cmd, input='', text=True, capture_output=True, timeout=self.timeout)
            
            if result.returncode == 0:
                output = result.stdout
                
                # Look for DH key exchange information
                dh_info = {}
                weak_dh_found = False
                common_dh_found = False
                
                # Parse DH parameters from output
                for line in output.split('\n'):
                    if 'Server Temp Key:' in line:
                        dh_info['temp_key'] = line.strip()
                        # Check for weak DH key sizes
                        if 'DH, 512 bits' in line or 'DH, 768 bits' in line or 'DH, 1024 bits' in line:
                            weak_dh_found = True
                            dh_info['weakness'] = "Weak DH key size detected"
                        # Check for common DH primes (RFC 5114 groups)
                        if 'DH, 1024 bits' in line:
                            common_dh_found = True
                            dh_info['common_prime'] = "Common Diffie-Hellman prime detected (1024-bit)"
                
                # Check for common weak primes (simplified check)
                if 'unable to load DH parameters' in output:
                    logger.warning(f"Diffie-Hellman check failed for {domain} - DH parameters not properly configured")
                    return {
                        "dh_secure": False,
                        "issue": "DH parameters not properly configured"
                    }
                elif weak_dh_found:
                    logger.warning(f"Diffie-Hellman check failed for {domain} - Weak DH detected: {dh_info}")
                    return {
                        "dh_secure": False,
                        "dh_info": dh_info,
                        "issue": "Weak Diffie-Hellman prime used in key exchange"
                    }
                elif common_dh_found:
                    logger.warning(f"Diffie-Hellman check failed for {domain} - Common DH prime detected: {dh_info}")
                    return {
                        "dh_secure": False,
                        "dh_info": dh_info,
                        "issue": "Common Diffie-Hellman prime used in key exchange"
                    }
                else:
                    logger.info(f"Diffie-Hellman check passed for {domain} - Strong DH parameters: {dh_info}")
                    return {
                        "dh_secure": True,
                        "dh_info": dh_info
                    }
            else:
                logger.info(f"Diffie-Hellman check passed for {domain} - DHE ciphers not supported (ECDHE likely used)")
                return {
                    "dh_secure": True,  # No DH ciphers supported, not an issue
                    "note": "DHE ciphers not supported (ECDHE likely used instead)"
                }
                
        except Exception as e:
            logger.error(f"Diffie-Hellman check failed for {domain}: {str(e)}")
            return {
                "dh_secure": False,
                "error": str(e),
                "issue": "Could not check Diffie-Hellman parameters"
            }
    
    def check_hsts_enforcement(self, domain: str) -> Dict:
        """Check if HTTP Strict Transport Security (HSTS) is properly enforced."""
        logger.info(f"Checking HSTS enforcement for {domain}")
        try:
            response = requests.get(f"https://{domain}", timeout=self.timeout)
            hsts_header = response.headers.get('Strict-Transport-Security', '')
            
            if not hsts_header:
                logger.warning(f"HSTS enforcement check failed for {domain} - No HSTS header found")
                return {
                    "hsts_enforced": False,
                    "issue": "HTTP Strict Transport Security (HSTS) not enforced"
                }
            
            # Parse HSTS header
            max_age_match = re.search(r'max-age=(\d+)', hsts_header)
            max_age = int(max_age_match.group(1)) if max_age_match else 0
            
            includes_subdomains = (
                'includeSubDomains' in hsts_header or 
                'includesubdomains' in hsts_header.lower()
            )
            
            preload = 'preload' in hsts_header.lower()
            
            # Check for weak HSTS configuration
            issues = []
            if max_age < 31536000:  # Less than 1 year
                issues.append("HSTS max-age too short (should be >= 1 year)")
            
            if not includes_subdomains:
                issues.append("HSTS header does not contain includeSubDomains")
            
            result = {
                "hsts_enforced": True,
                "max_age": max_age,
                "includes_subdomains": includes_subdomains,
                "preload": preload,
                "hsts_header": hsts_header,
                "configuration_issues": issues
            }
            
            if issues:
                result["issue"] = f"HSTS configuration issues: {'; '.join(issues)}"
                logger.warning(f"HSTS enforcement check has issues for {domain} - {issues}")
            else:
                logger.info(f"HSTS enforcement check passed for {domain} - max-age: {max_age}")
            
            return result
            
        except Exception as e:
            logger.error(f"HSTS enforcement check failed for {domain}: {str(e)}")
            return {
                "hsts_enforced": False,
                "error": str(e),
                "issue": "Could not check HSTS enforcement"
            }
    
    def check_https_redirect_support(self, domain: str) -> Dict:
        """Check if HTTPS redirect is properly supported."""
        logger.info(f"Checking HTTPS redirect support for {domain}")
        try:
            # Check if the domain supports HTTPS at all
            try:
                https_response = requests.get(f"https://{domain}", timeout=self.timeout, allow_redirects=False)
                https_supported = True
                https_status = https_response.status_code
            except:
                https_supported = False
                https_status = None
            
            # Check HTTP to HTTPS redirect
            try:
                http_response = requests.get(f"http://{domain}", timeout=self.timeout, allow_redirects=False)
                http_status = http_response.status_code
                location_header = http_response.headers.get('Location', '')
                redirects_to_https = location_header.startswith('https://')
            except:
                http_status = None
                redirects_to_https = False
            
            if not https_supported:
                logger.warning(f"HTTPS redirect support check failed for {domain} - HTTPS not supported")
                return {
                    "https_redirect_supported": False,
                    "https_supported": False,
                    "issue": "HTTPS redirect not supported"
                }
            
            if not redirects_to_https:
                logger.warning(f"HTTPS redirect support check failed for {domain} - HTTP does not redirect to HTTPS")
                return {
                    "https_redirect_supported": False,
                    "https_supported": True,
                    "http_status": http_status,
                    "redirects_to_https": False,
                    "issue": "HTTP requests do not redirect to HTTPS protocol"
                }
            
            logger.info(f"HTTPS redirect support check passed for {domain}")
            return {
                "https_redirect_supported": True,
                "https_supported": True,
                "http_status": http_status,
                "https_status": https_status,
                "redirects_to_https": True
            }
            
        except Exception as e:
            logger.error(f"HTTPS redirect support check failed for {domain}: {str(e)}")
            return {
                "https_redirect_supported": False,
                "error": str(e),
                "issue": "Could not check HTTPS redirect support"
            }
    
    def check_insecure_ssl_versions(self, domain: str, port: int = 443) -> Dict:
        """Check for insecure SSL/TLS versions."""
        logger.info(f"Checking for insecure SSL/TLS versions for {domain}:{port}")
        try:
            insecure_protocols = []
            protocol_tests = {
                'SSLv2': ['-ssl2'],
                'SSLv3': ['-ssl3'],
                'TLSv1.0': ['-tls1'],
                'TLSv1.1': ['-tls1_1']
            }
            
            for protocol_name, openssl_args in protocol_tests.items():
                try:
                    cmd = ['openssl', 's_client', '-connect', f'{domain}:{port}'] + openssl_args
                    result = subprocess.run(cmd, input='', text=True, capture_output=True, timeout=5)
                    
                    if result.returncode == 0 and 'CONNECTED' in result.stdout:
                        insecure_protocols.append(protocol_name)
                        logger.warning(f"Insecure protocol {protocol_name} supported by {domain}")
                    
                except subprocess.TimeoutExpired:
                    # Timeout is fine, means protocol probably not supported
                    pass
                except Exception:
                    # Other errors are fine, means protocol not supported
                    pass
            
            if insecure_protocols:
                logger.warning(f"Insecure SSL/TLS versions check failed for {domain} - Protocols: {insecure_protocols}")
                return {
                    "secure_ssl_versions": False,
                    "insecure_protocols": insecure_protocols,
                    "issue": f"Insecure SSL/TLS versions available: {', '.join(insecure_protocols)}"
                }
            else:
                logger.info(f"Insecure SSL/TLS versions check passed for {domain}")
                return {
                    "secure_ssl_versions": True,
                    "insecure_protocols": []
                }
            
        except Exception as e:
            logger.error(f"Insecure SSL/TLS versions check failed for {domain}: {str(e)}")
            return {
                "secure_ssl_versions": False,
                "error": str(e),
                "issue": "Could not check SSL/TLS versions"
            }
    
    def check_insecure_cipher_suites(self, domain: str, port: int = 443) -> Dict:
        """Check for insecure cipher suites."""
        logger.info(f"Checking for insecure cipher suites for {domain}:{port}")
        try:
            # Test for various insecure cipher categories
            insecure_cipher_tests = {
                'NULL ciphers': 'NULL',
                'Anonymous ciphers': 'ADH',
                'Export ciphers': 'EXPORT',
                'RC4 ciphers': 'RC4',
                'DES ciphers': 'DES',
                '3DES ciphers': '3DES'
            }
            
            insecure_ciphers_found = []
            
            for cipher_category, cipher_string in insecure_cipher_tests.items():
                try:
                    cmd = [
                        'openssl', 's_client', '-connect', f'{domain}:{port}',
                        '-cipher', cipher_string
                    ]
                    
                    result = subprocess.run(cmd, input='', text=True, capture_output=True, timeout=5)
                    
                    if result.returncode == 0 and 'CONNECTED' in result.stdout:
                        # Extract actual cipher used
                        cipher_line = None
                        for line in result.stdout.split('\n'):
                            if 'Cipher    :' in line:
                                cipher_line = line.strip()
                                break
                        
                        if cipher_line:
                            actual_cipher = cipher_line.split(':')[1].strip()
                            insecure_ciphers_found.append({
                                'category': cipher_category,
                                'cipher': actual_cipher
                            })
                            logger.warning(f"Insecure cipher found for {domain}: {cipher_category} - {actual_cipher}")
                    
                except subprocess.TimeoutExpired:
                    # Timeout is good, means cipher not supported
                    pass
                except Exception:
                    # Other errors are fine
                    pass
            
            if insecure_ciphers_found:
                categories = [c['category'] for c in insecure_ciphers_found]
                logger.warning(f"Insecure cipher suites check failed for {domain} - Categories: {categories}")
                return {
                    "secure_cipher_suites": False,
                    "insecure_ciphers": insecure_ciphers_found,
                    "issue": f"Insecure cipher suite supported: {', '.join(categories)}"
                }
            else:
                logger.info(f"Insecure cipher suites check passed for {domain}")
                return {
                    "secure_cipher_suites": True,
                    "insecure_ciphers": []
                }
            
        except Exception as e:
            logger.error(f"Insecure cipher suites check failed for {domain}: {str(e)}")
            return {
                "secure_cipher_suites": False,
                "error": str(e),
                "issue": "Could not check cipher suites"
            }
    
    def check_ssl_certificate_chain(self, domain: str, port: int = 443) -> Dict:
        """Check if SSL certificate chain is complete and properly configured."""
        logger.info(f"Checking SSL certificate chain for {domain}:{port}")
        try:
            # Use OpenSSL to verify certificate chain
            cmd = [
                'openssl', 's_client', '-connect', f'{domain}:{port}',
                '-verify_return_error', '-verify', '5'
            ]
            
            result = subprocess.run(cmd, input='', text=True, capture_output=True, timeout=self.timeout)
            
            output = result.stdout + result.stderr
            
            # Check for common chain issues
            chain_issues = []
            
            if 'unable to get local issuer certificate' in output.lower():
                chain_issues.append("Missing intermediate certificate in chain")
            
            if 'unable to verify the first certificate' in output.lower():
                chain_issues.append("Cannot verify certificate chain")
            
            if 'certificate verify failed' in output.lower():
                chain_issues.append("Certificate verification failed")
            
            if 'unable to get issuer certificate' in output.lower():
                chain_issues.append("Cannot find issuer certificate")
            
            # Check if chain is incomplete by looking for specific indicators
            if 'verify error:num=20' in output:  # unable to get local issuer certificate
                chain_issues.append("Incomplete certificate chain - missing root CA")
            
            if 'verify error:num=21' in output:  # unable to verify the first certificate
                chain_issues.append("Unable to verify first certificate in chain")
            
            # Also check for successful verification
            verification_success = (
                'verify return:1' in output or 
                'verification successful' in output.lower() or
                'verify ok' in output.lower()
            )
            
            if chain_issues:
                logger.warning(f"SSL certificate chain check failed for {domain} - Issues: {chain_issues}")
                return {
                    "certificate_chain_complete": False,
                    "chain_issues": chain_issues,
                    "issue": f"SSL certificate chain missing from server response: {'; '.join(chain_issues)}"
                }
            elif verification_success:
                logger.info(f"SSL certificate chain check passed for {domain}")
                return {
                    "certificate_chain_complete": True,
                    "chain_issues": []
                }
            else:
                # Inconclusive result
                logger.warning(f"SSL certificate chain check inconclusive for {domain}")
                return {
                    "certificate_chain_complete": False,
                    "chain_issues": ["Verification inconclusive"],
                    "issue": "Could not verify SSL certificate chain completeness"
                }
            
        except Exception as e:
            logger.error(f"SSL certificate chain check failed for {domain}: {str(e)}")
            return {
                "certificate_chain_complete": False,
                "error": str(e),
                "issue": "Could not check SSL certificate chain"
            }
    
    def run_all_checks(self, domain: str) -> Dict:
        """Run all enhanced security checks for a domain."""
        logger.info(f"Running enhanced security checks for {domain}")
        
        checks = {
            "ssl_availability": self.check_ssl_availability(domain),
            "hostname_certificate_match": self.check_hostname_certificate_match(domain),
            "http_to_https_redirect": self.check_http_to_https_redirect(domain),
            "weak_tls12_ciphers": self.check_weak_tls12_ciphers(domain),
            "diffie_hellman_strength": self.check_diffie_hellman_strength(domain),
            "hsts_enforcement": self.check_hsts_enforcement(domain),
            "https_redirect_support": self.check_https_redirect_support(domain),
            "insecure_ssl_versions": self.check_insecure_ssl_versions(domain),
            "insecure_cipher_suites": self.check_insecure_cipher_suites(domain),
            "ssl_certificate_chain": self.check_ssl_certificate_chain(domain)
        }
        
        # Collect all issues with severity classification
        issues = []
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        
        for check_name, result in checks.items():
            if result.get("issue"):
                # Classify severity based on the check type and issue
                severity = self._classify_issue_severity(check_name, result["issue"])
                result["severity"] = severity
                severity_counts[severity] += 1
                issues.append({
                    "check": check_name,
                    "issue": result["issue"],
                    "severity": severity
                })
        
        # Store the count before adding summary
        total_checks_count = len(checks)
        
        checks["summary"] = {
            "total_checks": total_checks_count,
            "issues_found": len(issues),
            "all_issues": [item["issue"] for item in issues],
            "severity_breakdown": severity_counts,
            "detailed_issues": issues
        }
        
        logger.info(f"Enhanced security checks completed for {domain}: {len(issues)} issues found")
        return checks
    
    def _classify_issue_severity(self, check_name: str, issue_text: str) -> str:
        """Classify the severity of a security issue based on check type and issue text."""
        issue_lower = issue_text.lower()
        
        # CRITICAL severity issues
        if check_name == "ssl_availability" and "ssl not available" in issue_lower:
            return "CRITICAL"
        
        # HIGH severity issues
        if check_name == "hostname_certificate_match" and "hostname does not match" in issue_lower:
            return "HIGH"
        if check_name == "http_to_https_redirect" and "does not redirect" in issue_lower:
            return "HIGH"
        if "ssl expired" in issue_lower or "certificate expired" in issue_lower:
            return "HIGH"
        if "untrusted ssl certificate" in issue_lower:
            return "HIGH"
        
        # MEDIUM severity issues
        if check_name == "diffie_hellman_strength" and "common" in issue_lower:
            return "MEDIUM"
        if check_name == "hsts_enforcement" and "not enforced" in issue_lower:
            return "MEDIUM"
        if check_name == "https_redirect_support" and "not supported" in issue_lower:
            return "MEDIUM"
        if check_name == "insecure_cipher_suites":
            return "MEDIUM"
        if check_name == "insecure_ssl_versions":
            return "MEDIUM"
        if check_name == "weak_tls12_ciphers" and "only weak cipher suites" in issue_lower:
            return "MEDIUM"
        if check_name == "ssl_certificate_chain" and "chain missing" in issue_lower:
            return "MEDIUM"
        if "ssl expiration period longer than 398 days" in issue_lower:
            return "MEDIUM"
        if "ssl expires within 20 days" in issue_lower:
            return "MEDIUM"
        if "weak ssl algorithm" in issue_lower:
            return "MEDIUM"
        
        # LOW severity issues
        if check_name == "diffie_hellman_strength" and "weak" in issue_lower:
            return "LOW"
        if check_name == "hsts_enforcement" and "includeSubDomains" in issue_lower:
            return "LOW"
        if check_name == "weak_tls12_ciphers" and "weak cipher suites" in issue_lower:
            return "LOW"
        if "hsts preload list" in issue_lower:
            return "LOW"
        if "weak public certificate key length" in issue_lower:
            return "LOW"
        
        # Default to MEDIUM for unclassified issues
        return "MEDIUM"


def main():
    """Test the enhanced security checker."""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python3 enhanced_security_checks.py <domain>")
        sys.exit(1)
    
    domain = sys.argv[1]
    checker = EnhancedSecurityChecker()
    results = checker.run_all_checks(domain)
    
    print(f"\nENHANCED SECURITY CHECKS: {domain}")
    print("=" * 50)
    
    for check_name, result in results.items():
        if check_name == "summary":
            continue
            
        print(f"\n{check_name.replace('_', ' ').title()}:")
        print("-" * 30)
        
        if result.get("issue"):
            print(f"ISSUE: {result['issue']}")
        elif result.get("error"):
            print(f"ERROR: {result['error']}")
        else:
            print("PASSED")
            
        # Print additional details
        for key, value in result.items():
            if key not in ["issue", "error"] and value is not None:
                print(f"  {key}: {value}")
    
    # Summary
    summary = results["summary"]
    print(f"\nSUMMARY:")
    print("-" * 20)
    print(f"Total Checks: {summary['total_checks']}")
    print(f"Issues Found: {summary['issues_found']}")
    
    if summary["all_issues"]:
        print("\nAll Issues:")
        for issue in summary["all_issues"]:
            print(f"  - {issue}")


if __name__ == "__main__":
    main() 