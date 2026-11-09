"""
Network port exposure scanner.

Resolves each subdomain to an IP, asks the configured network-scanning
provider (see ``Network/providers`` and ``docs/NETWORK_SCANNING.md``) which
ports are open, maps every open port to a severity and produces a score in
the dashboard's unified format.

The scanning tool itself is pluggable: set ``NETWORK_SCAN_PROVIDER`` to
``socket`` (default, built-in TCP connect scan), ``nmap`` or
``your.module:YourProvider``.
"""

import os
import logging
import time
import socket
import sys
import threading
from dotenv import load_dotenv

_NETWORK_DIR = os.path.dirname(os.path.abspath(__file__))
if _NETWORK_DIR not in sys.path:
    sys.path.insert(0, _NETWORK_DIR)
from providers import (
    NetworkScanAuthError,
    NetworkScanError,
    NetworkScanNoDataError,
    get_provider,
)

_APP_ROOT = os.environ.get("VENDIANT_APP_ROOT", "/app")
_DASHBOARD_DIR = os.path.join(_APP_ROOT, "Dashboard")
_CUSTOM_INTEGRATIONS_DIR = os.path.join(_APP_ROOT, "custom_integrations")

# Add Dashboard path for unified scoring
if _DASHBOARD_DIR not in sys.path:
    sys.path.insert(0, _DASHBOARD_DIR)
from unified_scoring_config import get_severity_weights, calculate_scan_score
from scan_health_notifier import notify_external_api_failure

# Add custom integrations path for logger
if _CUSTOM_INTEGRATIONS_DIR not in sys.path:
    sys.path.append(_CUSTOM_INTEGRATIONS_DIR)
from logger_config import setup_logger

# Configure logging using custom logger
logger = setup_logger()

# Load environment variables from root .env file
load_dotenv(os.path.join(_APP_ROOT, ".env"))

# Global rate limiter — honours the provider's request interval across all
# threads (hosted scanning APIs usually allow ~1 request per second; local
# scanners set the interval to 0).
_provider_lock = threading.Lock()
_provider_last_call = 0.0

def _provider_scan(provider, ip_address, hostname):
    """Thread-safe host lookup that respects ``provider.request_interval_seconds``."""
    global _provider_last_call
    interval = float(getattr(provider, "request_interval_seconds", 0) or 0)
    if interval <= 0:
        return provider.scan_host(ip_address, hostname=hostname)
    with _provider_lock:
        elapsed = time.monotonic() - _provider_last_call
        if elapsed < interval:
            time.sleep(interval - elapsed)
        _provider_last_call = time.monotonic()
        return provider.scan_host(ip_address, hostname=hostname)

# Port severity mappings
PORT_SEVERITY_MAPPING = {
    21: {
        "service": "FTP", 
        "severity": "HIGH", 
        "description": "Port 21 (FTP): Sensitive to brute-force, plain text credentials, outdated protocol and major attack vector."
    },
    22: {
        "service": "SSH", 
        "severity": "HIGH", 
        "description": "Port 22 (SSH): Remote shell, critical for system access, often brute-forced; must use strong authentication."
    },
    23: {
        "service": "Telnet", 
        "severity": "CRITICAL", 
        "description": "Port 23 (Telnet): Unencrypted remote shell, easily sniffed/abused. Should NEVER be exposed publicly."
    },
    25: {
        "service": "SMTP", 
        "severity": "MEDIUM", 
        "description": "Port 25 (SMTP): Mail transfer; often abused for spam and enumeration if unfiltered."
    },
    53: {
        "service": "DNS", 
        "severity": "MEDIUM", 
        "description": "Port 53 (DNS): Name resolution service, risk of amplification, info leakage, and DNS attacks."
    },
    80: {
        "service": "HTTP", 
        "severity": "LOW", 
        "description": "Port 80 (HTTP): Common web port, susceptible to app vulnerabilities, requires regular updates and patching."
    },
    110: {
        "service": "POP3", 
        "severity": "HIGH", 
        "description": "Port 110 (POP3): Mail retrieval, commonly plain text, exposes credentials and sensitive data."
    },
    143: {
        "service": "IMAP", 
        "severity": "HIGH", 
        "description": "Port 143 (IMAP): Mail retrieval, often insecure; may expose credentials and inbox contents."
    },
    389: {
        "service": "LDAP", 
        "severity": "HIGH", 
        "description": "Port 389 (LDAP): Directory service, possible credential or domain data leakage; known for misconfigurations."
    },
    443: {
        "service": "HTTPS", 
        "severity": "INFO", 
        "description": "Port 443 (HTTPS): Acceptable risk if up-to-date and maintained; subject to application risk."
    },
    445: {
        "service": "SMB", 
        "severity": "CRITICAL", 
        "description": "Port 445 (SMB): Major worm/exploit vector (EternalBlue, etc), never expose publicly."
    },
    1433: {
        "service": "MS SQL Server", 
        "severity": "HIGH", 
        "description": "Port 1433 (MS SQL Server): Database, exposed to brute-force and data exfiltration if unprotected."
    },
    1521: {
        "service": "Oracle DB", 
        "severity": "HIGH", 
        "description": "Port 1521 (Oracle DB): Database, high-value target, possible data loss or remote execution."
    },
    3306: {
        "service": "MySQL", 
        "severity": "CRITICAL", 
        "description": "Port 3306 (MySQL): Database: major breach/exfil risk, often weakly configured."
    },
    3389: {
        "service": "RDP", 
        "severity": "CRITICAL", 
        "description": "Port 3389 (RDP): Remote management, common ransomware attack vector; frequent unauthorized access attempts."
    },
    5432: {
        "service": "PostgreSQL", 
        "severity": "HIGH", 
        "description": "Port 5432 (PostgreSQL): Database, brute force and exfiltration risk if publicly exposed."
    },
    5900: {
        "service": "VNC", 
        "severity": "HIGH", 
        "description": "Port 5900 (VNC): Remote desktop, risks of unauthenticated or weakly protected access."
    },
    6379: {
        "service": "Redis", 
        "severity": "HIGH", 
        "description": "Port 6379 (Redis): Key-value store, commonly misconfigured, no auth by default, data and code injection risk."
    },
    9200: {
        "service": "Elasticsearch", 
        "severity": "HIGH", 
        "description": "Port 9200 (Elasticsearch): Search/analytics cluster, known mass-data leak risk, often left open without auth."
    },
    11211: {
        "service": "Memcached", 
        "severity": "HIGH", 
        "description": "Port 11211 (Memcached): Cache server, risk of DDoS amplification and info leaks if not properly firewalled."
    }
}

def resolve_domain_to_ip(domain):
    """Resolve domain name to IP address"""
    try:
        ip = socket.gethostbyname(domain)
        logger.info(f"Resolved {domain} to IP: {ip}")
        return ip
    except socket.gaierror as e:
        logger.warning(f"Could not resolve {domain} to IP: {e}")
        return None

def analyze_port_severity(port):
    """Analyze port severity based on predefined mappings"""
    if port in PORT_SEVERITY_MAPPING:
        return PORT_SEVERITY_MAPPING[port]
    else:
        # Default severity for unknown ports
        return {"service": "Unknown", "severity": "INFO", "description": f"Port {port} - Unknown service, requires manual review"}

def _empty_result(subdomain, ip_address, error, info_count=1):
    return {
        'subdomain': subdomain, 'ip_address': ip_address,
        'ports': [], 'findings': [],
        'severity_counts': {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": info_count},
        'error': error
    }


def scan_subdomain_ports(subdomain, provider=None):
    """Scan a single subdomain with the configured provider and return findings."""
    logger.info(f"Scanning subdomain: {subdomain}")

    if provider is None:
        provider = get_provider()

    # First resolve the subdomain to an IP address
    ip_address = resolve_domain_to_ip(subdomain)
    if not ip_address:
        return _empty_result(subdomain, None, 'Could not resolve domain to IP address')

    api_name = "Network Scanner"
    max_retries = 3
    host = None
    for attempt in range(max_retries):
      try:
        host = _provider_scan(provider, ip_address, subdomain)
        break
      except NetworkScanNoDataError as e:
        # The provider simply has nothing on this host: not a failure, no alert.
        logger.info("No network data for %s (%s) from %s: %s", subdomain, ip_address, provider.name, e)
        return _empty_result(subdomain, ip_address, "No network information available for this IP")
      except NetworkScanAuthError as e:
        logger.error("Network scan provider '%s' rejected credentials: %s", provider.name, e)
        notify_external_api_failure(api_name, str(e), domain=subdomain, status_code=401, attempts=attempt + 1)
        return _empty_result(subdomain, ip_address, f"Network scan provider credentials rejected ({provider.name})")
      except NetworkScanError as e:
        raw = str(e)
        if attempt < max_retries - 1:
            backoff = 2 ** attempt * 2  # 2s, 4s
            logger.warning(
                "%s error for %s (attempt %d/%d), retrying in %ds: %s",
                provider.name, subdomain, attempt + 1, max_retries, backoff, raw
            )
            time.sleep(backoff)
            continue
        logger.error("%s error for %s (%s): %s", provider.name, subdomain, ip_address, raw)
        notify_external_api_failure(api_name, raw, domain=subdomain, attempts=max_retries)
        return _empty_result(subdomain, ip_address, raw)
      except Exception as e:
        error_msg = str(e)
        logger.error(f"Unexpected error for {subdomain}: {error_msg}")
        if attempt < max_retries - 1:
            time.sleep(2 ** attempt * 2)
            continue
        notify_external_api_failure(api_name, error_msg, domain=subdomain, attempts=max_retries)
        if "timeout" in error_msg.lower():
            error_msg = "Network timeout - host may be slow or unreachable"
        elif "connection" in error_msg.lower():
            error_msg = "Connection error - host may be unreachable"
        elif "json" in error_msg.lower():
            error_msg = "Provider response parsing error"
        return _empty_result(subdomain, ip_address, error_msg)

    if host is None:
        return _empty_result(subdomain, ip_address, "Network scan returned no result")

    if host.ports:
        findings = []
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

        for port in host.ports:
            port_analysis = analyze_port_severity(port)
            severity = port_analysis['severity']
            severity_counts[severity] += 1

            # Enrich with whatever service details the provider returned
            service = host.service_for_port(port)
            product = service.product if service and service.product else "Unknown"
            version = service.version if service else ""
            banner = (service.banner if service else "").strip()

            findings.append({
                'port': port,
                'service': port_analysis['service'],
                'severity': severity,
                'description': port_analysis['description'],
                'product': product,
                'version': version,
                'banner': banner[:100] + "..." if len(banner) > 100 else banner
            })

        return {
            'subdomain': subdomain,
            'ip_address': ip_address,
            'ports': list(host.ports),
            'findings': findings,
            'severity_counts': severity_counts,
            'error': None
        }
    else:
        return {
            'subdomain': subdomain,
            'ip_address': ip_address,
            'ports': [],
            'findings': [],
            'severity_counts': {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
            'error': None
        }


def scan_network_ports(domain, subdomains_list=None):
    """
    Scan network ports for a domain and its subdomains.
    Returns data in dashboard-compatible format.
    
    Args:
        domain: Main domain name
        subdomains_list: List of subdomains to scan (required - no file fallback)
    
    Returns:
        Dict with scan results and statistics
    """
    logger.info(f"Starting network ports scan for {domain}")

    # Resolve and validate the configured scanning provider
    try:
        provider = get_provider()
        provider.validate_config()
    except NetworkScanError as e:
        logger.error(f"Network scan provider is not usable: {e}")
        notify_external_api_failure("Network Scanner", str(e), domain=domain)
        return None
    logger.info(f"Using network scan provider: {provider.name}")
    
    # Use provided subdomains list or fall back to main domain
    if not subdomains_list:
        logger.info(f"No subdomains provided for network scan. Scanning main domain: {domain}")
        subdomains_list = [domain]
    
    logger.info(f"Scanning {len(subdomains_list)} domains from database")
    
    # Initialize scoring system
    initial_score = 950
    
    # Use unified scoring system
    severity_weights = get_severity_weights('NETWORK')
    
    total_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    subdomain_scores = []
    processed_subdomains = 0
    all_findings = []
    all_vulnerabilities = []  # Store all vulnerabilities for unified scoring
    subdomain_results = []
    
    for subdomain in subdomains_list:
        try:
            result = scan_subdomain_ports(subdomain, provider)
            subdomain_results.append(result)
            processed_subdomains += 1
            
            # Calculate score for this subdomain
            subdomain_score = initial_score
            severity_counts = result['severity_counts']
            
            for severity, count in severity_counts.items():
                if severity in total_counts:
                    total_counts[severity] += count
                subdomain_score -= count * severity_weights.get(severity, 0)
            
            # Ensure score doesn't go below 0
            subdomain_score = max(0, subdomain_score)
            subdomain_scores.append(subdomain_score)
            
            # Add findings to overall list
            for finding in result['findings']:
                all_findings.append({
                    'subdomain': subdomain,
                    'port': finding['port'],
                    'service': finding['service'],
                    'severity': finding['severity'],
                    'description': finding['description'],
                    'product': finding['product'],
                    'version': finding['version'],
                    'banner': finding['banner']
                })
                
                # Add to vulnerabilities list for unified scoring
                all_vulnerabilities.append({
                    'subdomain': subdomain,
                    'severity': finding['severity'],
                    'category': 'NETWORK',
                    'description': f"Port {finding['port']} ({finding['service']}): {finding['description']}",
                    'port': finding['port'],
                    'service': finding['service']
                })
            
            logger.info(f"Subdomain {subdomain} score: {subdomain_score}/{initial_score}")
                
        except Exception as e:
            logger.error(f"Error processing subdomain {subdomain}: {e}")
            continue
    
    # Calculate average score across subdomains instead of accumulating all vulnerabilities
    if subdomain_scores:
        # Calculate average score across all subdomains
        final_score = int(sum(subdomain_scores) / len(subdomain_scores))

        logger.info(f"NETWORK AVERAGE SCORING:")
        logger.info(f"   Subdomains processed: {len(subdomain_scores)}")
        logger.info(f"   Individual scores: {subdomain_scores}")
        logger.info(f"   Average score: {final_score}/950")
        logger.info(f"   Total issues across all subdomains: {len(all_vulnerabilities)}")
        logger.info(f"   Score range: {min(subdomain_scores)} - {max(subdomain_scores)}")
    else:
        final_score = initial_score
        logger.info(f"No subdomains processed - using base score: {final_score}")
    
    logger.info(f"Network scan completed for {domain}. Final score: {final_score}/{initial_score}")
    
    # Return results in dashboard-compatible format (no file operations)
    return {
        'domain': domain,
        'final_score': final_score,
        'max_score': initial_score,
        'processed_subdomains': processed_subdomains,
        'issues_found': all_findings,
        'statistics': total_counts,
        'subdomain_scores': subdomain_scores,
        'subdomain_results': subdomain_results,
        'total_ports_found': sum(len(r['ports']) for r in subdomain_results)
    }

if __name__ == "__main__":
    # Usage: python network_scanner_api.py <domain> [subdomain ...]
    if len(sys.argv) < 2:
        print("Usage: python network_scanner_api.py <domain> [subdomain ...]")
        sys.exit(1)
    domain = sys.argv[1]
    result = scan_network_ports(domain, sys.argv[2:] or None)
    if result:
        print(f"Network scan completed for {domain}")
        print(f"Final score: {result['final_score']}/{result['max_score']}")
        print(f"Total findings: {len(result['issues_found'])}") 