"""
Shared configuration and state management for the Dashboard application.
This module provides shared variables and configurations to avoid circular imports.
"""
import logging

# Shared scan tracking
active_vulnerability_scans = {}  # Track vulnerability scans specifically

# AI Insights cache configuration
ai_insights_cache = {}  # Format: {cache_key: {'insights': data, 'timestamp': time, 'data_hash': hash}}
AI_CACHE_DURATION = 3600  # 1 hour in seconds

# Subdomain cache - shared to avoid circular imports
subdomain_cache = {}

def invalidate_subdomain_cache(domain=None):
    """Invalidate subdomain cache for a specific domain or all domains"""
    global subdomain_cache
    
    if domain:
        cache_key = domain.lower().strip()
        if cache_key in subdomain_cache:
            del subdomain_cache[cache_key]
            logging.info(f"Subdomain cache invalidated for {domain}")
    else:
        subdomain_cache.clear()
        logging.info("All subdomain caches invalidated")

# Other shared configurations can be added here as needed
