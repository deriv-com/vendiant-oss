import sublist3r
import requests
import socket
import os
import sys
import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import time

_APP_ROOT = os.environ.get("VENDIANT_APP_ROOT", "/app")
_CUSTOM_INTEGRATIONS_DIR = os.path.join(_APP_ROOT, "custom_integrations")

# Configure logging
# Add custom integrations path for logger
if _CUSTOM_INTEGRATIONS_DIR not in sys.path:
    sys.path.append(_CUSTOM_INTEGRATIONS_DIR)
from logger_config import setup_logger

# Configure logging using custom logger
logger = setup_logger()

# Global request configuration
REQUEST_TIMEOUT = 15
MAX_RETRIES = 2
REQUEST_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
}

def safe_request(url, timeout=REQUEST_TIMEOUT, **kwargs):
    """Make a safe HTTP request with retries and error handling"""
    session = requests.Session()
    session.headers.update(REQUEST_HEADERS)
    
    for attempt in range(MAX_RETRIES):
        try:
            response = session.get(url, timeout=timeout, **kwargs)
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            if attempt == MAX_RETRIES - 1:
                raise e
            time.sleep(1)  # Brief delay before retry
    return None

def find_subdomains_sublist3r(domain):
    """Use Sublist3r with all available engines including new ones"""
    try:
        # Import here to avoid threading issues
        import signal
        # Disable signal handling in sublist3r to avoid threading issues
        original_signal = getattr(signal, 'signal', None)
        if original_signal:
            signal.signal = lambda *args: None
        
        subdomains = sublist3r.main(
            domain=domain,
            threads=30,  # Reduced to avoid threading issues
            savefile=None,
            ports=None,
            silent=True,
            verbose=False,
            enable_bruteforce=False,  # Disable to avoid signal issues
            engines=None,  # Use all engines
        )
        
        # Restore signal handling
        if original_signal:
            signal.signal = original_signal
            
        return set(subdomains) if subdomains else set()
        
    except Exception as e:
        logger.warning(f"Sublist3r execution failed: {e}")
        return set()

def find_subdomains_crtsh(domain):
    """Enhanced crt.sh query with JSON API and retry logic"""
    logger.info(f"Querying crt.sh for subdomains of {domain}")
    url = f'https://crt.sh/?q=%25.{domain}&output=json'
    
    max_retries = 3
    retry_delay = 2  # seconds
    
    for attempt in range(max_retries):
        try:
            resp = safe_request(url, timeout=30)
            entries = resp.json()
            logger.info(f"Successfully retrieved {len(entries)} entries from crt.sh on attempt {attempt + 1}")
            break
        except Exception as e:
            logger.warning(f"Error retrieving data from crt.sh (attempt {attempt + 1}/{max_retries}): {e}")
            if attempt < max_retries - 1:
                logger.info(f"Retrying crt.sh query in {retry_delay} seconds...")
                time.sleep(retry_delay)
                retry_delay *= 2  # Exponential backoff
                continue
            else:
                logger.error(f"Failed to retrieve data from crt.sh after {max_retries} attempts")
                return set()

    subdomains = set()
    for entry in entries:
        names = entry.get('name_value', '').split('\n')
        for name in names:
            name = name.strip()
            # Remove wildcard prefix and filter the root domain
            if name.startswith('*.'):
                name = name[2:]
            if name == domain:
                continue
            if name.endswith('.' + domain) or name == domain:
                subdomains.add(name)
    return subdomains

def find_subdomains_hackertarget(domain):
    """Query HackerTarget API"""
    logger.info(f"Querying HackerTarget for subdomains of {domain}")
    url = f'https://api.hackertarget.com/hostsearch/?q={domain}'
    try:
        resp = safe_request(url, timeout=15)
        text = resp.text
        
        # Check for API limit errors
        if 'API count exceeded' in text or 'error' in text.lower():
            logger.warning(f"HackerTarget API limit reached or error: {text[:100]}")
            return set()
            
        subdomains = set()
        for line in text.split('\n'):
            if ',' in line and line.strip():
                subdomain = line.split(',')[0].strip()
                if subdomain.endswith(domain) and subdomain != domain:
                    subdomains.add(subdomain)
        logger.info(f"Found {len(subdomains)} subdomains from HackerTarget")
        return subdomains
    except requests.exceptions.RequestException as e:
        logger.warning(f"HackerTarget network error: {e}")
        return set()
    except Exception as e:
        logger.error(f"Error querying HackerTarget: {e}")
        return set()

def find_subdomains_rapiddns(domain):
    """Query RapidDNS"""
    logger.info(f"Querying RapidDNS for subdomains of {domain}")
    url = f'https://rapiddns.io/subdomain/{domain}?full=1'
    try:
        resp = safe_request(url, timeout=20)
        text = resp.text
        subdomains = set()
        # Extract domains from table rows
        domain_regex = re.compile(r'<td>([^<]+\.' + re.escape(domain) + r')</td>')
        matches = domain_regex.findall(text)
        for subdomain in matches:
            subdomain = subdomain.strip()
            if subdomain.endswith(domain) and subdomain != domain:
                subdomains.add(subdomain)
        logger.info(f"Found {len(subdomains)} subdomains from RapidDNS")
        return subdomains
    except Exception as e:
        logger.warning(f"Error querying RapidDNS: {e}")
        return set()

def find_subdomains_bufferover(domain):
    """Query BufferOver DNS API"""
    logger.info(f"Querying BufferOver for subdomains of {domain}")
    
    # Try multiple BufferOver endpoints
    endpoints = [
        f'https://dns.bufferover.run/dns?q=.{domain}',
        f'https://tls.bufferover.run/dns?q=.{domain}'
    ]
    
    for url in endpoints:
        try:
            resp = safe_request(url, timeout=15)
            data = resp.json()
            subdomains = set()
            
            # Check both FDNS_A and RDNS data
            for key in ['FDNS_A', 'RDNS']:
                if key in data and data[key]:
                    for entry in data[key]:
                        if ',' in entry:
                            subdomain = entry.split(',')[1].strip()
                            if subdomain.endswith(domain) and subdomain != domain:
                                subdomains.add(subdomain)
            
            if subdomains:
                logger.info(f"Found {len(subdomains)} subdomains from BufferOver")
                return subdomains
                
        except requests.exceptions.RequestException as e:
            logger.debug(f"BufferOver endpoint {url} failed: {e}")
            continue
        except Exception as e:
            logger.debug(f"BufferOver parsing error for {url}: {e}")
            continue
    
    logger.warning("All BufferOver endpoints failed or returned no data")
    return set()

def find_subdomains_anubis(domain):
    """Query Anubis API"""
    logger.info(f"Querying Anubis for subdomains of {domain}")
    url = f'https://jldc.me/anubis/subdomains/{domain}'
    try:
        resp = safe_request(url, timeout=20)
        subdomains_list = resp.json()
        subdomains = set()
        for subdomain in subdomains_list:
            subdomain = subdomain.strip()
            if subdomain.endswith(domain) and subdomain != domain:
                subdomains.add(subdomain)
        logger.info(f"Found {len(subdomains)} subdomains from Anubis")
        return subdomains
    except Exception as e:
        logger.warning(f"Error querying Anubis: {e}")
        return set()

def find_subdomains_wayback(domain):
    """Query Wayback Machine"""
    logger.info(f"Querying Wayback Machine for subdomains of {domain}")
    url = f'http://web.archive.org/cdx/search/cdx?url=*.{domain}&output=txt&fl=original&collapse=urlkey'
    try:
        resp = safe_request(url, timeout=25)
        text = resp.text
        subdomains = set()
        for line in text.split('\n'):
            if line.strip():
                try:
                    from urllib.parse import urlparse
                    parsed_url = urlparse(line.strip())
                    subdomain = parsed_url.netloc
                    if subdomain.endswith(domain) and subdomain != domain:
                        subdomains.add(subdomain)
                except:
                    continue
        logger.info(f"Found {len(subdomains)} subdomains from Wayback Machine")
        return subdomains
    except Exception as e:
        logger.warning(f"Error querying Wayback Machine: {e}")
        return set()

def find_subdomains_alienvault(domain):
    """Query AlienVault OTX"""
    logger.info(f"Querying AlienVault OTX for subdomains of {domain}")
    url = f'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns'
    try:
        resp = safe_request(url, timeout=20)
        data = resp.json()
        subdomains = set()
        if 'passive_dns' in data:
            for entry in data['passive_dns']:
                if 'hostname' in entry:
                    subdomain = entry['hostname'].strip()
                    if subdomain.endswith(domain) and subdomain != domain:
                        subdomains.add(subdomain)
        logger.info(f"Found {len(subdomains)} subdomains from AlienVault OTX")
        return subdomains
    except Exception as e:
        logger.warning(f"Error querying AlienVault OTX: {e}")
        return set()

def find_all_subdomains(domain):
    """Find subdomains using all available methods"""
    logger.info(f"Starting comprehensive subdomain enumeration for {domain}")
    
    # Dictionary to store results from each source
    sources = {}
    
    # Use ThreadPoolExecutor for parallel execution
    with ThreadPoolExecutor(max_workers=6) as executor:
        # Submit all tasks with error handling
        future_to_source = {}
        
        # Submit tasks individually with try-catch
        sources_to_try = [
            (find_subdomains_crtsh, "crt.sh"),
            (find_subdomains_hackertarget, "HackerTarget"),
            (find_subdomains_rapiddns, "RapidDNS"),
            (find_subdomains_bufferover, "BufferOver"),
            (find_subdomains_anubis, "Anubis"),
            (find_subdomains_wayback, "WaybackMachine"),
            (find_subdomains_alienvault, "AlienVault")
        ]
        
        for func, name in sources_to_try:
            try:
                future = executor.submit(func, domain)
                future_to_source[future] = name
            except Exception as e:
                logger.warning(f"Failed to submit {name} task: {e}")
                sources[name] = set()
        
        # Run Sublist3r separately to avoid threading issues
        try:
            logger.info("Running Sublist3r...")
            sublist3r_results = find_subdomains_sublist3r(domain)
            sources["Sublist3r"] = sublist3r_results
            logger.info(f"Sublist3r: Found {len(sublist3r_results)} subdomains")
        except Exception as e:
            logger.error(f"Sublist3r failed: {e}")
            sources["Sublist3r"] = set()
        
        # Collect results as they complete
        for future in as_completed(future_to_source):
            source = future_to_source[future]
            try:
                result = future.result()
                sources[source] = result
                logger.info(f"{source}: Found {len(result)} subdomains")
            except Exception as e:
                logger.error(f"Error in {source}: {e}")
                sources[source] = set()
    
    # Combine all results
    all_subdomains = set()
    for source, subdomains in sources.items():
        all_subdomains.update(subdomains)
    
    # Log statistics per source
    logger.info("\n--- Source Statistics ---")
    for source, subdomains in sources.items():
        logger.info(f"{source}: {len(subdomains)} subdomains")
    
    logger.info(f"Total unique subdomains: {len(all_subdomains)}")
    return sorted(all_subdomains)

def is_http_alive(subdomain):
    """Check if a subdomain is alive by testing DNS resolution and HTTP/HTTPS response."""
    try:
        # Quick DNS check first
        socket.gethostbyname(subdomain)
    except socket.gaierror:
        return None
    
    # Check HTTPS first (more common)
    for protocol in ['https', 'http']:
        try:
            r = requests.get(f"{protocol}://{subdomain}", timeout=15, verify=False, allow_redirects=True)
            if r.status_code < 500:
                return subdomain
        except requests.RequestException:
            continue
    return None

def find_alive_subdomains(subdomains, max_workers=30):
    """Find alive subdomains with improved performance"""
    alive = []
    logger.info(f"Checking {len(subdomains)} subdomains for HTTP/HTTPS responses with {max_workers} workers")
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(is_http_alive, sub) for sub in subdomains]
        for i, future in enumerate(as_completed(futures), 1):
            result = future.result()
            if result:
                alive.append(result)
            
            # Progress logger every 100 checks
            if i % 100 == 0:
                logger.info(f"Checked {i}/{len(subdomains)} subdomains, found {len(alive)} alive")
    
    logger.info(f"Found {len(alive)} alive subdomains out of {len(subdomains)} total")
    return alive

# File writing functions removed - using database integration instead

if __name__ == "__main__":
    domain = "example.com"  # Change this to your target domain
    
    print(f"Starting comprehensive subdomain enumeration for {domain}")
    print("This may take several minutes...")
    
    # Find all subdomains
    all_subdomains = find_all_subdomains(domain)
    print(f"Total unique subdomains found: {len(all_subdomains)}")
    
    # Check which subdomains are alive
    print("Checking which subdomains are alive...")
    alive_subdomains = find_alive_subdomains(all_subdomains)
    print(f"Found {len(alive_subdomains)} alive subdomains.")
    
    # Calculate and display statistics
    num_unmaintained = len(all_subdomains) - len(alive_subdomains)
    if all_subdomains:
        percentage_alive = (len(alive_subdomains) / len(all_subdomains)) * 100
        percentage_unmaintained = 100 - percentage_alive
    else:
        percentage_alive = percentage_unmaintained = 0
    
    print(f"\n--- Final Statistics ---")
    print(f"Total unique subdomains found: {len(all_subdomains)}")
    print(f"Alive (HTTP/HTTPS responding) subdomains: {len(alive_subdomains)} ({percentage_alive:.2f}%)")
    print(f"Unmaintained (not HTTP/HTTPS responsive): {num_unmaintained} ({percentage_unmaintained:.2f}%)")
    
    print("\nNote: Results are now saved to database instead of files.")
    print("Use the dashboard API to access subdomain data.")