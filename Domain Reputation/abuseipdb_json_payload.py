#!/usr/bin/env python3
"""
AbuseIPDB JSON Payload Retrieval Script
This script retrieves and displays the exact JSON payload from AbuseIPDB API
"""

import os
import json
import requests
import socket
from urllib.parse import urlparse
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def extract_domain_from_url(url):
    """Extract domain from URL"""
    try:
        # Add protocol if missing
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        parsed = urlparse(url)
        domain = parsed.netloc
        
        # Remove www. prefix if present
        if domain.startswith('www.'):
            domain = domain[4:]
            
        print(f"✓ Extracted domain '{domain}' from URL: {url}")
        return domain
    except Exception as e:
        print(f"✗ Could not extract domain from URL {url}: {e}")
        return None

def resolve_domain_to_ip(domain):
    """Resolve a domain name to IP address"""
    try:
        ip = socket.gethostbyname(domain)
        print(f"✓ Resolved {domain} to {ip}")
        return ip
    except Exception as e:
        print(f"✗ Could not resolve {domain}: {e}")
        return None

def get_abuseipdb_json(ip_address, max_age_days=90, verbose=True):
    """
    Get the exact JSON payload from AbuseIPDB API
    
    Args:
        ip_address (str): IP address to check
        max_age_days (int): Maximum age of reports in days (default: 90)
        verbose (bool): Include verbose report details (default: True)
    
    Returns:
        dict: Raw JSON response from AbuseIPDB
    """
    
    # Get API key from environment
    api_key = os.getenv('ABUSE_API_KEY')
    if not api_key:
        print("✗ Error: ABUSE_API_KEY not found in environment variables")
        print("  Please add your AbuseIPDB API key to your .env file as ABUSE_API_KEY=your_key_here")
        return None
    
    # API endpoint and headers
    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {
        'Key': api_key,
        'Accept': 'application/json',
    }
    
    # Parameters for the API request
    params = {
        'ipAddress': ip_address,
        'maxAgeInDays': str(max_age_days),
    }
    
    # Add verbose parameter if requested
    if verbose:
        params['verbose'] = ''
    
    try:
        print(f"🔍 Querying AbuseIPDB for IP: {ip_address}")
        print(f"   Max age: {max_age_days} days")
        print(f"   Verbose: {verbose}")
        print(f"   URL: {url}")
        print(f"   Params: {params}")
        print()
        
        # Make the API request
        response = requests.get(url, headers=headers, params=params, timeout=30)
        
        # Check if request was successful
        response.raise_for_status()
        
        # Parse JSON response
        json_data = response.json()
        
        print("✓ Successfully retrieved data from AbuseIPDB")
        return json_data
        
    except requests.exceptions.RequestException as e:
        print(f"✗ HTTP Request Error: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"   Status Code: {e.response.status_code}")
            print(f"   Response Text: {e.response.text}")
        return None
    except json.JSONDecodeError as e:
        print(f"✗ JSON Decode Error: {e}")
        print(f"   Raw response: {response.text}")
        return None
    except Exception as e:
        print(f"✗ Unexpected Error: {e}")
        return None

def print_json_payload(json_data, save_to_file=None):
    """
    Pretty print the JSON payload
    
    Args:
        json_data (dict): JSON data to print
        save_to_file (str): Optional file path to save the JSON
    """
    if not json_data:
        print("No JSON data to display")
        return
    
    # Pretty print the JSON
    formatted_json = json.dumps(json_data, indent=2, sort_keys=True)
    
    print("=" * 80)
    print("ABUSEIPDB JSON PAYLOAD")
    print("=" * 80)
    print(formatted_json)
    print("=" * 80)
    
    # Save to file if requested
    if save_to_file:
        try:
            with open(save_to_file, 'w') as f:
                f.write(formatted_json)
            print(f"✓ JSON payload saved to: {save_to_file}")
        except Exception as e:
            print(f"✗ Error saving to file: {e}")

def analyze_payload_structure(json_data):
    """
    Analyze and explain the structure of the JSON payload
    """
    if not json_data:
        return
    
    print("\n" + "=" * 80)
    print("PAYLOAD STRUCTURE ANALYSIS")
    print("=" * 80)
    
    if 'data' in json_data:
        data = json_data['data']
        
        print(f"📊 Basic Information:")
        print(f"   IP Address: {data.get('ipAddress', 'N/A')}")
        print(f"   Public IP: {data.get('isPublic', 'N/A')}")
        print(f"   IP Version: {data.get('ipVersion', 'N/A')}")
        print(f"   ISP: {data.get('isp', 'N/A')}")
        print(f"   Country: {data.get('countryCode', 'N/A')}")
        print(f"   Usage Type: {data.get('usageType', 'N/A')}")
        
        print(f"\n📈 Abuse Statistics:")
        print(f"   Abuse Confidence: {data.get('abuseConfidencePercentage', 'N/A')}%")
        print(f"   Total Reports: {data.get('totalReports', 'N/A')}")
        print(f"   Distinct Users Reported: {data.get('numDistinctUsers', 'N/A')}")
        print(f"   Last Reported: {data.get('lastReportedAt', 'N/A')}")
        
        if 'reports' in data and data['reports']:
            print(f"\n📋 Report Details:")
            print(f"   Number of Reports: {len(data['reports'])}")
            
            for i, report in enumerate(data['reports'][:3], 1):  # Show first 3 reports
                print(f"\n   Report #{i}:")
                print(f"      Reported At: {report.get('reportedAt', 'N/A')}")
                print(f"      Comment: {report.get('comment', 'N/A')}")
                print(f"      Categories: {report.get('categories', 'N/A')}")
                print(f"      Reporter Country: {report.get('reporterCountryCode', 'N/A')}")
            
            if len(data['reports']) > 3:
                print(f"   ... and {len(data['reports']) - 3} more reports")
        else:
            print(f"\n📋 No detailed reports found")
    
    print("\n" + "=" * 80)

def main():
    """Main function to execute the script with hardcoded URL"""
    
    # Hardcoded configuration
    target = "https://example.com"
    max_age_days = 90
    verbose = True
    save_to_file = None
    analyze = True
    
    # Check if target looks like an IP address
    try:
        socket.inet_aton(target)
        ip_address = target
        print(f"🎯 Target is IP address: {ip_address}")
    except socket.error:
        # Target is either a domain or URL
        # Check if it looks like a URL (contains protocol or common URL patterns)
        if ('://' in target or 
            target.startswith('www.') or 
            '/' in target or 
            target.count('.') > 1):
            print(f"🎯 Target appears to be URL: {target}")
            domain = extract_domain_from_url(target)
            if not domain:
                print("Exiting due to URL parsing failure")
                return 1
        else:
            print(f"🎯 Target is domain: {target}")
            domain = target
        
        # Resolve domain to IP
        ip_address = resolve_domain_to_ip(domain)
        if not ip_address:
            print("Exiting due to domain resolution failure")
            return 1
    
    # Get the JSON payload
    json_data = get_abuseipdb_json(ip_address, max_age_days, verbose)
    
    if json_data:
        # Print the raw JSON payload
        print_json_payload(json_data, save_to_file)
        
        # Analyze the payload structure if requested
        if analyze:
            analyze_payload_structure(json_data)
        
        print(f"\n✓ Successfully retrieved AbuseIPDB data for {target}")
        return 0
    else:
        print(f"\n✗ Failed to retrieve AbuseIPDB data for {target}")
        return 1

if __name__ == "__main__":
    exit(main()) 