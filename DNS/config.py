# DNS Scanner Configuration
# Similar to encryption scanner but for DNS security checks

# Timeouts (in seconds) - Optimized for faster processing
NETWORK_TIMEOUT = 10  # Reduced from 30 to 10 seconds
DNS_TIMEOUT = 5       # Reduced from 15 to 5 seconds
WHOIS_TIMEOUT = 10    # Reduced from 20 to 10 seconds
SUBDOMAIN_TIMEOUT = 30  # Reduced from 60 to 30 seconds

# DNS Security Check Configuration
DNS_SERVERS = [
    "8.8.8.8",      # Google DNS
    "1.1.1.1",      # Cloudflare DNS
    "208.67.222.222"  # OpenDNS
]

# DNS Security Severity Mapping (uses unified scoring system)
DNS_SEVERITY_MAPPING = {
    # Domain expiry issues
    "domain_expired": "HIGH",           # Domain is expired - critical security risk
    "domain_expires_soon": "MEDIUM",          # Expires within 30 days - high risk
    
    # Subdomain takeover vulnerabilities
    "subdomain_takeover": "HIGH",       # Subdomain takeover vulnerability - critical
    
    # DNSSEC configuration
    "dnssec_disabled": "LOW",               # DNSSEC not enabled - low risk (common)
    
    # Registrar protection settings
    "no_deletion_protection": "LOW",        # No deletion protection - low risk
    "no_transfer_protection": "LOW",        # No transfer protection - low risk  
    "no_update_protection": "LOW",          # No update protection - low risk
        
    # Positive findings (no penalty)
    "transfer_protection_enabled": "INFO",  # Transfer protection enabled - informational
    "dnssec_enabled": "INFO",               # DNSSEC enabled - informational
}

# Risk Level Thresholds (950-point scale)
RISK_LEVEL_THRESHOLDS = {
    (0, 100): "Low Risk",
    (101, 300): "Medium Risk", 
    (301, 600): "High Risk",
    (601, 950): "Critical Risk"
}

# Common subdomain takeover signatures
TAKEOVER_SIGNATURES = {
    "github.io": ["There isn't a GitHub Pages site here."],
    "herokuapp.com": ["No such app"],
    "wordpress.com": ["Do you want to register"],
    "tumblr.com": ["Whatever you were looking for doesn't currently exist"],
    "shopify.com": ["Sorry, this shop is currently unavailable"],
    "surge.sh": ["project not found"],
    "bitbucket.io": ["Repository not found"],
    "fastly.com": ["Fastly error: unknown domain"],
    "s3.amazonaws.com": ["NoSuchBucket", "The specified bucket does not exist"]
}

# DNSSEC validation servers
DNSSEC_VALIDATORS = [
    "8.8.8.8",
    "1.1.1.1"
]

# Domain expiration warning thresholds (days)
EXPIRY_WARNING_DAYS = 30
EXPIRY_CRITICAL_DAYS = 7

# Maximum number of subdomains to check for takeover - Reduced for faster processing
MAX_SUBDOMAINS_CHECK = 25  # Reduced from 50 to 25 