import os
import requests
import socket
import sys
import time
from dotenv import load_dotenv
from datetime import datetime, timedelta
import logging

_APP_ROOT = os.environ.get("VENDIANT_APP_ROOT", "/app")
_DASHBOARD_DIR = os.path.join(_APP_ROOT, "Dashboard")
_CUSTOM_INTEGRATIONS_DIR = os.path.join(_APP_ROOT, "custom_integrations")

# Add Dashboard path for unified scoring
if _DASHBOARD_DIR not in sys.path:
    sys.path.insert(0, _DASHBOARD_DIR)
from unified_scoring_config import get_severity_weights, calculate_scan_score
from scan_health_notifier import notify_external_api_failure

# SETTINGS
OUTPUT_DIR = os.path.join(_APP_ROOT, "Results")  # Output folder for results
CONFIDENCE_THRESHOLD = 50  # Minimum abuse confidence percentage to include findings
ABUSEIPDB_MAX_ATTEMPTS = 3  # Total attempts per lookup before alerting
ABUSEIPDB_BACKOFF_SECONDS = 2  # Base delay between attempts (doubles each retry)
ABUSEIPDB_RETRYABLE_STATUS = {429, 500, 502, 503, 504}

# Configure logging
# Add custom integrations path for logger
if _CUSTOM_INTEGRATIONS_DIR not in sys.path:
    sys.path.append(_CUSTOM_INTEGRATIONS_DIR)
from logger_config import setup_logger

# Configure logging using custom logger
logger = setup_logger()

# Load API key from root .env file (optional in production — secrets come from env)
_env_file = os.path.join(_APP_ROOT, ".env")
if os.path.exists(_env_file):
    load_dotenv(_env_file)
API_KEY = os.getenv('ABUSE_API_KEY')  # Place your AbuseIPDB API key in root .env as ABUSE_API_KEY

# Report category mapping (see above)
CATEGORY_MAPPING = {
    3: "Suspected of distributing malware",      # Malware
    5: "Suspected of botnet activity",           # Botnet
    9: "Suspected of unsolicited scanning in last 90 days",  # Port scan/unwanted
    15: "Suspected of distributing malware in last 90 days",  # Malware distributor
    18: "Suspected of unwanted software",        # Unwanted software
}

FINDINGS = {
    "Suspected of botnet activity": {
        "desc": "This IP/domain has been reported as a source of botnet activity in the last 30 days. The server should be checked and any offending software removed.",
        "severity": "HIGH",
        "weight": 5,
    },
    "Suspected of distributing malware": {
        "desc": "This IP/domain has been reported for distributing malware in the last 30 days. The server should be checked and any offending software removed.",
        "severity": "HIGH",
        "weight": 5,
    },
    "Suspected of unwanted software": {
        "desc": "This website may be attempting to install unwanted software. The website should be checked and any offending code removed.",
        "severity": "HIGH",
        "weight": 5,
    },
    "Suspected of distributing malware in last 90 days": {
        "desc": "This IP/domain has been reported for distributing malware in the last 90 days. The server should be checked and any offending software removed.",
        "severity": "INFO",
        "weight": 0,
    },
    "Suspected of unsolicited scanning in last 90 days": {
        "desc": "This IP/domain has been reported for performing unsolicited scanning in the last 90 days. The server should be checked to ensure this behavior is intentional and not the result of malware.",
        "severity": "INFO",
        "weight": 0,
    }
}

def resolve_domain(domain):
    try:
        logger.info(f"Resolving domain: {domain}")
        ip = socket.gethostbyname(domain)
        logger.info(f"Successfully resolved {domain} to {ip}")
        return ip
    except Exception as e:
        logger.error(f"Could not resolve {domain}: {e}")
        return None

def abuseipdb_check(ip):
    headers = {
        'Key': API_KEY,
        'Accept': 'application/json',
    }
    params = {
        'ipAddress': ip,
        'maxAgeInDays': '90',
        'verbose': ''
    }
    url = 'https://api.abuseipdb.com/api/v2/check'
    last_error = None
    last_status_code = None

    # Retry transient failures (timeouts, connection errors, 429/5xx) with
    # exponential backoff; only alert Slack once every attempt has failed.
    for attempt in range(1, ABUSEIPDB_MAX_ATTEMPTS + 1):
        try:
            logger.info(f"Checking IP {ip} with AbuseIPDB (attempt {attempt}/{ABUSEIPDB_MAX_ATTEMPTS})")
            resp = requests.get(url, headers=headers, params=params, timeout=10)
            resp.raise_for_status()
            result = resp.json()
            logger.info(f"Successfully checked {ip} - found {len(result.get('data', {}).get('reports', []))} reports")
            return result
        except requests.exceptions.HTTPError as e:
            last_error = e
            last_status_code = e.response.status_code if e.response is not None else None
            logger.warning(f"AbuseIPDB HTTP error for {ip} (attempt {attempt}/{ABUSEIPDB_MAX_ATTEMPTS}): {e}")
            if last_status_code not in ABUSEIPDB_RETRYABLE_STATUS:
                break  # e.g. 401/403/422 — retrying won't help
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
            last_error = e
            last_status_code = None
            logger.warning(f"AbuseIPDB request failed for {ip} (attempt {attempt}/{ABUSEIPDB_MAX_ATTEMPTS}): {e}")
        except Exception as e:
            last_error = e
            last_status_code = None
            logger.error(f"Error checking {ip} in AbuseIPDB: {e}")
            break

        if attempt < ABUSEIPDB_MAX_ATTEMPTS:
            time.sleep(ABUSEIPDB_BACKOFF_SECONDS * (2 ** (attempt - 1)))

    logger.error(f"AbuseIPDB lookup failed for {ip}: {last_error}")
    notify_external_api_failure(
        "AbuseIPDB", str(last_error), domain=ip, status_code=last_status_code, attempts=attempt
    )
    return None

def analyze_abuseipdb_result(result, confidence_threshold=50):
    '''
    Returns a list of findings for the IP address.
    Only includes findings if the abuse confidence percentage is >= threshold.
    
    Args:
        result: AbuseIPDB API response
        confidence_threshold: Minimum confidence percentage (default: 50)
    '''
    findings_found = []

    if not result or 'data' not in result:
        logger.debug("No data found in AbuseIPDB result")
        return findings_found

    data = result['data']
    
    # Check abuse confidence percentage threshold
    abuse_confidence = data.get('abuseConfidencePercentage', 0)
    logger.info(f"Abuse confidence percentage: {abuse_confidence}%")
    
    if abuse_confidence < confidence_threshold:
        logger.info(f"Abuse confidence {abuse_confidence}% is below threshold {confidence_threshold}% - skipping")
        return findings_found
    
    # If confidence is above threshold, proceed with analysis
    if 'reports' not in data or not data['reports']:
        logger.debug("No reports found in AbuseIPDB result")
        return findings_found

    now = datetime.utcnow()
    days_30 = now - timedelta(days=30)
    days_90 = now - timedelta(days=90)

    logger.debug(f"Analyzing {len(data['reports'])} reports with confidence {abuse_confidence}%")

    for report in data['reports']:
        try:
            report_time = datetime.strptime(report['reportedAt'], "%Y-%m-%dT%H:%M:%S%z").replace(tzinfo=None)
            for cat in report['categories']:
                mapped = CATEGORY_MAPPING.get(cat)
                if not mapped:
                    continue
                    
                if mapped == "Suspected of botnet activity" and report_time >= days_30:
                    if mapped not in [f['finding'] for f in findings_found]:
                        findings_found.append({
                            'finding': mapped, 
                            'details': FINDINGS[mapped],
                            'confidence': abuse_confidence
                        })
                elif mapped == "Suspected of distributing malware" and report_time >= days_30:
                    if mapped not in [f['finding'] for f in findings_found]:
                        findings_found.append({
                            'finding': mapped, 
                            'details': FINDINGS[mapped],
                            'confidence': abuse_confidence
                        })
                elif mapped == "Suspected of unwanted software" and report_time >= days_30:
                    if mapped not in [f['finding'] for f in findings_found]:
                        findings_found.append({
                            'finding': mapped, 
                            'details': FINDINGS[mapped],
                            'confidence': abuse_confidence
                        })
                elif mapped == "Suspected of distributing malware in last 90 days" and report_time >= days_90:
                    if mapped not in [f['finding'] for f in findings_found]:
                        findings_found.append({
                            'finding': mapped, 
                            'details': FINDINGS[mapped],
                            'confidence': abuse_confidence
                        })
                elif mapped == "Suspected of unsolicited scanning in last 90 days" and report_time >= days_90:
                    if mapped not in [f['finding'] for f in findings_found]:
                        findings_found.append({
                            'finding': mapped, 
                            'details': FINDINGS[mapped],
                            'confidence': abuse_confidence
                        })
        except Exception as e:
            logger.warning(f"Error parsing report: {e}")
            continue

    logger.info(f"Found {len(findings_found)} unique findings above {confidence_threshold}% confidence threshold")
    return findings_found

def scan_domain_reputation(domain, output_file_path=None):
    """
    Scan a single domain for reputation issues.
    Only reports findings with abuse confidence >= CONFIDENCE_THRESHOLD (50%).
    
    Args:
        domain: Single domain string to scan
        output_file_path: Optional custom output path (deprecated - database integration)
    
    Returns:
        Dict with scan results and statistics
    """
    logger.info(f"Starting domain reputation scan for {domain}")
    
    # Check if API key is available
    if not API_KEY:
        logger.error("ABUSE_API_KEY not found in environment variables. Please add it to the root .env file.")
        return None

    # Initialize scoring system
    initial_score = 950
    total_weight = 0
    issues_found = []
    all_vulnerabilities = []  # Store vulnerabilities for unified scoring
    # False when the AbuseIPDB lookup could not be completed — the score is then
    # a placeholder, not a clean result, and callers must not persist it.
    checked = True
    error = None
    
    # Get unified severity weights
    severity_weights_unified = get_severity_weights('DOMAIN_REPUTATION')

    logger.info(f"Scanning domain reputation for {domain} - results will be stored in database")
    
    try:
        # Process single domain
        ip = resolve_domain(domain)
        if not ip:
            logger.info(f"Could not resolve domain {domain} to IP address")
            final_score = initial_score  # No deduction for resolution failure
        else:
            result = abuseipdb_check(ip)
            if result is None:
                checked = False
                error = "AbuseIPDB lookup failed after retries"
                logger.warning(f"Reputation for {domain} ({ip}) NOT checked - AbuseIPDB unavailable")
            findings = analyze_abuseipdb_result(result, CONFIDENCE_THRESHOLD)
            
            # Process findings if any exist
            if findings:
                logger.info(f"Found {len(findings)} reputation issues for {domain}")
                for finding_data in findings:
                    finding = finding_data['finding']
                    details = finding_data['details']
                    confidence = finding_data.get('confidence', 0)
                    severity = details['severity']
                    desc = details['desc']
                    weight = details['weight']
                    
                    logger.info(f"[{severity}] {finding} (Confidence: {confidence}%)")
                    
                    # Add weight to total (direct subtraction)
                    total_weight += weight
                    
                    # Add to issues list for response
                    issues_found.append({
                        'domain': domain,
                        'finding': finding,
                        'severity': severity,
                        'description': desc,
                        'confidence': confidence,
                        'weight': weight
                    })
                    
                    # Add to vulnerabilities list for unified scoring
                    all_vulnerabilities.append({
                        'domain': domain,
                        'severity': severity.upper(),
                        'category': 'DOMAIN_REPUTATION',
                        'description': desc,
                        'confidence': confidence
                    })
            else:
                logger.info(f"No concerning findings for {domain} above {CONFIDENCE_THRESHOLD}% confidence threshold")
            
            # Use unified scoring system for final score calculation
            if all_vulnerabilities:
                unified_result = calculate_scan_score(all_vulnerabilities, 'DOMAIN_REPUTATION')
                final_score = unified_result['score']
                logger.info(f" UNIFIED SCORING - Domain Reputation Category:")
                logger.info(f"   Total Issues: {unified_result['total_vulnerabilities']}")
                logger.info(f"   Critical/High Count: {unified_result['critical_high_count']}")
                logger.info(f"   Total Deduction: {unified_result['total_deduction']}")
                logger.info(f"   Final Score: {final_score}/{initial_score} ({unified_result['percentage']}%)")
                logger.info(f"   Legacy weight deducted: {total_weight} (for comparison)")
            else:
                final_score = initial_score
                logger.info(f"No reputation issues found - using base score: {final_score}")
            
            logger.info(f"Domain {domain} score: {final_score}/{initial_score}")

    except Exception as e:
        logger.error(f"Error processing domain {domain}: {e}")
        final_score = initial_score  # No deduction for processing errors
        checked = False
        error = str(e)

    logger.info(f"Scan completed successfully")
    logger.info(f"Final security score: {final_score}/{initial_score}")
    logger.info(f"Total issues found: {len(issues_found)}")
    logger.info(f"Results stored in database - no files generated")
    
    # Return results for API consumption (no file operations)
    return {
        'domain': domain,
        'final_score': final_score,
        'max_score': initial_score,
        'total_weight_deducted': total_weight,
        'issues_found': issues_found,
        'checked': checked,
        'error': error,
        'report_file': None  # No file generated
    }

def main(target_domain=None):
    """Main function for command line usage"""
    # Get domain from user input if not provided
    domain = target_domain
    if not domain:
        domain = input("Enter the domain to scan (e.g., example.com): ").strip()
        if not domain:
            print("Domain cannot be empty. Please try again.")
            return
    
    # Call the single domain scan function
    result = scan_domain_reputation(domain)
    
    if result and not result['checked']:
        print(f"\nReputation NOT checked: {result['error']}")
    elif result:
        print(f"\nDomain Reputation Security Score: {result['final_score']}/{result['max_score']}")
        print(f"Total weight deducted: {result['total_weight_deducted']}")
        print(f"Issues found: {len(result['issues_found'])}")
        print(f"Report saved to: {result['report_file']}")
    else:
        print("Scan failed. Please check the logs for more details.")
    
if __name__ == "__main__":
    import sys
    target_domain = sys.argv[1] if len(sys.argv) > 1 else None
    main(target_domain)


