"""
Configuration file for Vendor Risk Scanner
Contains API endpoints, timeouts, and other configurable settings.
"""

# API Endpoints
SSL_LABS_API = "https://api.ssllabs.com/api/v3"
MOZILLA_OBSERVATORY_API = "https://observatory-api.mdn.mozilla.net/api/v2"
SECURITY_HEADERS_API = "https://securityheaders.com"
HSTS_PRELOAD_API = "https://hstspreload.org/api/v2/status"
CERTIFICATE_TRANSPARENCY_API = "https://crt.sh"

# Timeout settings (in seconds) - BALANCED APPROACH
NETWORK_TIMEOUT = 150         # Restored from 15 to 150 seconds
SSL_LABS_POLL_INTERVAL = 100  # Restored from 5 to 100 seconds
SSL_LABS_MAX_WAIT_TIME = 3600 # Restored from 120 to 3600 seconds (1 hour max)
TESTSSL_TIMEOUT = 300         # Reduced to 5 minutes to prevent hangs
MOZILLA_OBSERVATORY_TIMEOUT = 200  # Restored from 20 to 200 seconds
ENHANCED_SECURITY_TIMEOUT = 30      # Reduced to 30 seconds per check

# Default scan settings
MAX_CONCURRENT_SCANS = 6  # Reduced from 6 to 3 for stability
DEFAULT_USER_AGENT = "VendorRiskScanner/2.0"

# Risk scoring weights (scaled for 950-point system)
RISK_WEIGHTS = {
    "ssl_grade": {
        "A+": 0, "A": -25, "A-": -50, "B": -100, 
        "C": -175, "D": -250, "F": -350
    },
    "mozilla_score_threshold": 50,
    "missing_header_penalty": 25,
    "hsts_preload_penalty": 50,
    "vulnerability_penalties": {
        "CRITICAL": 125,
        "HIGH": 100,
        "MEDIUM": 50,
        "LOW": 25
    },
    "risk_level_thresholds": {
        "Low": 800,      # 800-950 points
        "Medium": 600,   # 600-799 points  
        "High": 400,     # 400-599 points
        "Critical": 0    # 0-399 points
    }
}

# Security headers to check
SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP", 
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "x-xss-protection": "X-XSS-Protection",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy"
}

# testssl.sh configuration - RESTORED TO CONSERVATIVE SETTINGS
TESTSSL_OPTIONS = [
    "--quiet",
    "--warnings", "off", 
    "--color", "0",
    "--jsonfile"
]

# Performance optimization flags - DISABLED FOR STABILITY
ENABLE_FAST_SCANNING = True
SKIP_SLOW_CHECKS = False
PARALLEL_CHECKS_ENABLED = True 