import requests, time, os
import logging
import sys
import urllib3

# Suppress SSL warnings since we're skipping verification for compatibility
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_APP_ROOT = os.environ.get("VENDIANT_APP_ROOT", "/app")
_DASHBOARD_DIR = os.path.join(_APP_ROOT, "Dashboard")
_CUSTOM_INTEGRATIONS_DIR = os.path.join(_APP_ROOT, "custom_integrations")

# Add Dashboard path for unified scoring
if _DASHBOARD_DIR not in sys.path:
    sys.path.insert(0, _DASHBOARD_DIR)
from unified_scoring_config import get_severity_weights, calculate_scan_score

# Configure logging
# Add custom integrations path for logger
if _CUSTOM_INTEGRATIONS_DIR not in sys.path:
    sys.path.append(_CUSTOM_INTEGRATIONS_DIR)
from logger_config import setup_logger

# Configure logging using custom logger
logger = setup_logger()

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
USER_AGENT = 'Mozilla/5.0 (compatible; VulnerabilityFetcher/1.0)'
HEADERS_TO_CHECK = ['server', 'x-powered-by']
HEADERS_TO_CHECK_1 = ['content-security-policy', 'x-content-type-options', 'x-frame-options', 'set-cookie', 'referrer-policy', 'permissions-policy','x-aspnet-version','x-aspnetmvc-version']

risk_levels = {
    "CSP is not implemented": "MEDIUM",
    "CSP implemented unsafely": "MEDIUM",
    "CSP allows insecure active sources": "MEDIUM",
    "CSP allows insecure passive sources": "LOW",
    "CSP contains unsafe-eval": "LOW",
    "HttpOnly cookies not used": "MEDIUM",
    "Secure cookies not used": "MEDIUM",
    "Server Information header exposed": "MEDIUM",
    "X-Frame-Options is not deny or sameorigin": "MEDIUM",
    "X-Powered-By header exposed": "MEDIUM",
    "Referrer Policy is unsafe-url": "LOW",
    "X-Content-Type-Options is not nosniff": "LOW",
    "Specific ASP.NET version exposed via header": "LOW",
    "Use of ASP.NET exposed via header": "LOW",
}


def get_http_headers(domain):
    urls = [f"https://{domain}", f"http://{domain}"]
    logger.info(f"Getting HTTP headers for {domain}")
    for url in urls:
        try:
            # Increase timeout and add better error handling
            r = requests.get(
                url, 
                headers={'User-Agent': USER_AGENT}, 
                timeout=(10, 15),  # (connect_timeout, read_timeout)
                allow_redirects=True,
                verify=False  # Skip SSL verification to avoid certificate issues
            )
            logger.info(f"Successfully retrieved headers from {url}")
            return r
        except requests.exceptions.Timeout as e:
            logger.warning(f"Timeout retrieving headers from {url}: {e}")
            continue
        except requests.exceptions.SSLError as e:
            logger.warning(f"SSL error retrieving headers from {url}: {e}")
            continue
        except requests.exceptions.ConnectionError as e:
            logger.warning(f"Connection error retrieving headers from {url}: {e}")
            continue
        except requests.exceptions.RequestException as e:
            logger.warning(f"Request error retrieving headers from {url}: {e}")
            continue
        except Exception as e:
            logger.warning(f"Unexpected error retrieving headers from {url}: {e}")
            continue
    logger.error(f"Failed to retrieve headers for {domain} from all URLs")
    return None


def check_header_vulnerabilities(response):
    vulnerabilities = []
    headers = {h.lower(): val for h, val in response.headers.items()}

    # CSP Checks
    if 'content-security-policy' not in headers:
        vulnerabilities.append({
            'id': 'CSP_NOT_IMPLEMENTED',
            'desc': 'No valid Content Security Policy is implemented. This increases the risk of XSS and clickjacking attacks.',
            'severity': risk_levels['CSP is not implemented']
        })
    else:
        csp = headers['content-security-policy']
        if "'unsafe-inline'" in csp or "data:" in csp:
            vulnerabilities.append({
                'id': 'CSP_UNSAFE',
                'desc': 'The Content Security Policy may not restrict sources appropriately, or may contain unsafe-inline without the use of a nonce or hash. This increases the risk of XSS attacks.',
                'severity': risk_levels['CSP implemented unsafely']
            })
        if 'script-src' in csp and ('http:' in csp or 'https:' in csp):
             vulnerabilities.append({
                'id': 'CSP_INSECURE_ACTIVE',
                'desc': 'The Content Security Policy on this site alLows insecure active content.',
                'severity': risk_levels['CSP allows insecure active sources']
            })
        if 'img-src' in csp and 'http:' in csp:
            vulnerabilities.append({
                'id': 'CSP_INSECURE_PASSIVE',
                'desc': 'The Content Security Policy on this site alLows insecure passive content.',
                'severity': risk_levels['CSP allows insecure passive sources']
            })
        if "'unsafe-eval'" in csp:
            vulnerabilities.append({
                'id': 'CSP_UNSAFE_EVAL',
                'desc': 'The Content Security Policy is implemented with unsafe-eval, reducing protection against XSS attacks.',
                'severity': risk_levels['CSP contains unsafe-eval']
            })
    
    # Cookie Checks
    if 'set-cookie' in headers:
        if 'httponly' not in headers['set-cookie'].lower():
            vulnerabilities.append({
                'id': 'HTTPONLY_COOKIE_NOT_USED',
                'desc': 'HttpOnly cookies not used',
                'severity': risk_levels['HttpOnly cookies not used']
            })
        if 'secure' not in headers['set-cookie'].lower():
            vulnerabilities.append({
                'id': 'SECURE_COOKIE_NOT_USED',
                'desc': 'When secure cookies are not used, there is an increased risk of third parties intercepting Information contained in these cookies. The website configuration should be changed so that all Set-Cookie headers include secure.',
                'severity': risk_levels['Secure cookies not used']
            })

    # Server Header
    if 'server' in headers:
        vulnerabilities.append({
            'id': 'SERVER_HEADER_EXPOSED',
            'desc': 'The X-Powered-By header reveals Information about specific technology used on the server. This Information can be used to exploit vulnerabilities. The server configuration should be changed to remove this header.',
            'severity': risk_levels['Server Information header exposed']
        })

    # X-Frame-Options
    if 'x-frame-options' in headers:
        xfo = headers['x-frame-options'].lower()
        if xfo not in ['deny', 'sameorigin']:
            vulnerabilities.append({
                'id': 'XFO_NOT_DENY_OR_SAMEORIGIN',
                'desc': 'Browsers may display this websites content in frames. This can lead to clickjacking attacks.',
                'severity': risk_levels['X-Frame-Options is not deny or sameorigin']
            })

    # X-Powered-By
    if 'x-powered-by' in headers:
        vulnerabilities.append({
            'id': 'X_POWERED_BY_EXPOSED',
            'desc': 'The X-Powered-By header reveals Information about specific technology used on the server. This Information can be used to exploit vulnerabilities. The server configuration should be changed to remove this header.',
            'severity': risk_levels['X-Powered-By header exposed']
        })
    
    # Referrer Policy
    if 'referrer-policy' in headers and headers['referrer-policy'].lower() == 'unsafe-url':
        vulnerabilities.append({
            'id': 'REFERRER_POLICY_UNSAFE',
            'desc': 'The full URL (stripped of parameters) is sent in the referrer header when performing same-origin or cross-origin requests. This can expose sensitive Information.',
            'severity': risk_levels['Referrer Policy is unsafe-url']
        })

    # X-Content-Type-Options
    if 'x-content-type-options' not in headers or headers.get('x-content-type-options', '').lower() != 'nosniff':
        vulnerabilities.append({
            'id': 'XCTO_NOT_NOSNIFF',
            'desc': 'Browsers may interpret files as a different MIME type than what is specified in the Content-Type HTTP header. This can lead to MIME confusion attacks.',
            'severity': risk_levels['X-Content-Type-Options is not nosniff']
        })

    # ASP.NET
    if 'x-aspnet-version' in headers:
        vulnerabilities.append({
            'id': 'ASPNET_VERSION_EXPOSED',
            'desc': 'Exposing a specific ASP.NET version in the ASP.NET version header makes it easier for attackers to exploit certain vulnerabilities. The website configuration should be changed to remove this header completely.',
            'severity': risk_levels['Specific ASP.NET version exposed via header']
        })
    elif 'x-aspnetmvc-version' in headers:
         vulnerabilities.append({
            'id': 'ASPNET_EXPOSED',
            'desc': 'Exposing the ASP.NET version header indicates that the site is built with ASP.NET, which makes it easier for attackers to exploit certain vulnerabilities. The website configuration should be changed to remove this header.',
            'severity': risk_levels['Use of ASP.NET exposed via header']
        })

    return vulnerabilities


def process_domain(domain):
    """Process domain for header vulnerabilities - database integration only"""
    logger.info(f"--- Processing domain: {domain} ---")
    response = get_http_headers(domain)
    if not response:
        logger.warning(f"No HTTP response for {domain}, skipping further processing.")
        return {"INFO": 1}, []

    headers = response.headers
    all_vulnerabilities = check_header_vulnerabilities(response)
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    # Process vulnerabilities for database storage
    vulnerability_details = []
    if all_vulnerabilities:
        logger.info(f"Found {len(all_vulnerabilities)} vulnerabilities for {domain}")
        
        for v in all_vulnerabilities:
            severity = v.get('severity', 'UNKNOWN')
            
            if severity in severity_counts:
                severity_counts[severity] += 1
            
            # Store vulnerability details for database
            vulnerability_details.append({
                'id': v.get('id', 'UNKNOWN_ID'),
                'description': v.get('desc', 'Unknown vulnerability'),
                'severity': severity
            })
    else:
        logger.info(f"No vulnerabilities found for {domain}")

    return severity_counts, vulnerability_details

if __name__ == "__main__":
    logger.info("Header vulnerabilities scanner now uses database integration")
    logger.info("Please use the dashboard API for vulnerability scanning")
    logger.info("Use /api/vulnerabilities/scan endpoint with domain parameter")
    
    # Example usage for testing (requires database integration)
    domain = 'example.com'  # Change this for testing
    print(f"To scan {domain}, use the dashboard API:")
    print(f"POST /api/vulnerabilities/scan with {{'domain': '{domain}'}}")
    print("Results will be stored in database automatically")