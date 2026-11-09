import requests
import socket
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_subdomains(domain):
    """
    Queries crt.sh for subdomains of a given domain.
    Returns a sorted list of unique subdomains (no wildcards, no root domain).
    """
    logging.info(f"Querying crt.sh for subdomains of {domain}")
    url = f'https://crt.sh/?q=%25.{domain}&output=json'
    try:
        resp = requests.get(url, timeout=60)
        resp.raise_for_status()
        entries = resp.json()
        logging.info(f"Successfully retrieved {len(entries)} entries from crt.sh")
    except Exception as e:
        logging.error(f"Error retrieving data from crt.sh: {e}")
        return []

    subdomains = set()
    for entry in entries:
        for name in entry['name_value'].split('\n'):
            name = name.strip()
            # Filter: skip wildcards and the root domain itself
            if name.startswith('*.'):
                name = name[2:]
            if name == domain:
                continue
            if name.endswith('.' + domain) or name == domain:
                subdomains.add(name)
    if domain not in subdomains:
        subdomains.add(domain)

    logging.info(f"Found {len(subdomains)} unique subdomains")
    return sorted(subdomains)


def is_http_alive(subdomain):
    # First, try DNS
    logging.info(f"Checking DNS for {subdomain}")
    try:
        socket.gethostbyname(subdomain)
        logging.info(f"DNS resolved for {subdomain}")
    except socket.gaierror:
        logging.warning(f"DNS resolution failed for {subdomain}")
        return None
    # Then, try HTTP(S)
    logging.info(f"Checking HTTP/S for {subdomain}")
    try:
        r = requests.get(f"https://{subdomain}", timeout=3, verify=True)
        if r.status_code < 500:
            logging.info(f"Subdomain {subdomain} is alive on HTTPS with status code {r.status_code}")
            return subdomain
    except requests.RequestException:
        pass
    # Try http:// as well, if https fails (optional)
    try:
        r = requests.get(f"http://{subdomain}", timeout=3, verify=True)
        if r.status_code < 500:
            logging.info(f"Subdomain {subdomain} is alive on HTTP with status code {r.status_code}")
            return subdomain
    except requests.RequestException:
        pass
    logging.warning(f"Subdomain {subdomain} is not alive on HTTP or HTTPS")
    return None

def find_alive_subdomains(subdomains, max_workers=20):
    alive = []
    logging.info(f"Finding alive subdomains from a list of {len(subdomains)} with {max_workers} workers")
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(is_http_alive, sub) for sub in subdomains]
        for future in as_completed(futures):
            result = future.result()
            if result:
                alive.append(result)
    logging.info(f"Found {len(alive)} alive subdomains")
    return alive


def save_subdomains_to_file(subdomains, folder_name, filename):
    """Saves a list of subdomains to a text file in the specified folder under Results directory."""
    # Create Results directory and subfolder if they don't exist
    results_dir = "Results"
    folder_path = os.path.join(results_dir, folder_name)
    os.makedirs(folder_path, exist_ok=True)
    
    # Create full file path
    file_path = os.path.join(folder_path, filename)
    
    logging.info(f"Saving {len(subdomains)} subdomains to {file_path}")
    with open(file_path, 'w') as f:
        for subdomain in subdomains:
            f.write(f"{subdomain}\n")
    logging.info(f"Successfully saved subdomains to {file_path}")


# Example usage:
if __name__ == "__main__":
    domain = 'example.com'
    all_subdomains = get_subdomains(domain)
    print(f"Total subdomains found: {len(all_subdomains)}")
    save_subdomains_to_file(all_subdomains, "All Domains", f"{domain}_all_subdomains.txt")

    alive_list = find_alive_subdomains(all_subdomains)
    print(f"Alive (HTTP/HTTPS responding) subdomains: {len(alive_list)}")
    save_subdomains_to_file(alive_list, "Alive Domains", f"{domain}_alive_subdomains.txt")

    # Calculate unmaintained
    num_unmaintained = len(all_subdomains) - len(alive_list)
    if all_subdomains:
        percentage_unmaintained = (num_unmaintained / len(all_subdomains)) * 100
    else:
        percentage_unmaintained = 0

    print(f"Unmaintained (not HTTP/HTTPS responsive): {num_unmaintained} ({percentage_unmaintained:.2f}%)")
    print(f"Maintained (responsive): {len(alive_list)} ({100 - percentage_unmaintained:.2f}%)")