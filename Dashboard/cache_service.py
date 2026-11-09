"""
Cache Service Module

This module provides caching functionality for the Vendiant dashboard application.
It includes caching for vendors, subdomains, dashboard statistics, and AI insights.
"""

import logging
from datetime import datetime
from typing import Dict, List, Optional, Any

# Cache storage variables
vendors_cache = None
vendors_cache_timestamp = None
CACHE_EXPIRY_MINUTES = 60  # Cache vendors for 60 minutes (stable data)

subdomain_cache = {}  # Format: {domain: {'data': subdomain_data, 'timestamp': datetime, 'ttl': seconds}}
SUBDOMAIN_CACHE_TTL = 15 * 60  # Cache subdomains for 15 minutes

dashboard_stats_cache = None
dashboard_stats_cache_timestamp = None
DASHBOARD_CACHE_TTL = 2 * 60  # Cache dashboard stats for 2 minutes

ai_insights_cache = {}  # Format: {cache_key: {'insights': data, 'timestamp': time, 'data_hash': hash}}
AI_CACHE_DURATION = 3600  # 1 hour in seconds


def get_vendors_cached():
    """
    Get vendors from cache or load from database if cache is expired/empty.
    
    Returns:
        List: Cached vendor data or freshly loaded data from database
    """
    global vendors_cache, vendors_cache_timestamp
    
    current_time = datetime.now()
    
    # Check if cache exists and is still valid
    if (vendors_cache is not None and 
        vendors_cache_timestamp is not None and 
        (current_time - vendors_cache_timestamp).total_seconds() < CACHE_EXPIRY_MINUTES * 60):
        logging.debug("Using cached vendors data")
        return vendors_cache
    
    # Cache is expired or doesn't exist, reload from PostgreSQL
    logging.info("Cache expired or empty, reloading vendors from PostgreSQL")
    
    # Import here to avoid circular imports
    from db_service import get_vendors_from_database
    
    vendors_cache = get_vendors_from_database()
    vendors_cache_timestamp = current_time
    
    return vendors_cache


def invalidate_vendors_cache():
    """Invalidate the vendors cache to force reload on next access"""
    global vendors_cache, vendors_cache_timestamp
    vendors_cache = None
    vendors_cache_timestamp = None
    logging.info("Vendors cache invalidated - will reload from PostgreSQL on next access")


def get_subdomains_cached(domain: str) -> List[Dict]:
    """
    Get subdomains from cache or load from database if cache is expired/empty.
    
    Args:
        domain (str): The domain to get subdomains for
        
    Returns:
        List[Dict]: List of subdomain data
    """
    global subdomain_cache
    
    current_time = datetime.now()
    cache_key = domain.lower().strip()
    
    # Check if cache exists and is still valid
    if cache_key in subdomain_cache:
        cached_item = subdomain_cache[cache_key]
        time_diff = (current_time - cached_item['timestamp']).total_seconds()
        
        if time_diff < cached_item.get('ttl', SUBDOMAIN_CACHE_TTL):
            logging.debug(f"Using cached subdomain data for {domain}")
            return cached_item['data']
        else:
            # Cache expired, remove it
            del subdomain_cache[cache_key]
            logging.debug(f"Cache expired for {domain}, removed from cache")
    
    # Cache miss or expired, fetch from database
    logging.info(f"Cache miss for {domain}, fetching subdomains from database")
    try:
        # Import here to avoid circular imports
        from db_service import get_subdomains_for_domain
        
        subdomain_data = get_subdomains_for_domain(domain)
        
        # Cache the result
        subdomain_cache[cache_key] = {
            'data': subdomain_data,
            'timestamp': current_time,
            'ttl': SUBDOMAIN_CACHE_TTL
        }
        
        logging.info(f"Cached {len(subdomain_data)} subdomains for {domain}")
        return subdomain_data
    except Exception as e:
        logging.error(f"Error fetching subdomains for {domain}: {e}")
        return []


def invalidate_subdomain_cache(domain: Optional[str] = None):
    """
    Invalidate subdomain cache for a specific domain or all domains.
    
    Args:
        domain (Optional[str]): Specific domain to invalidate, or None for all domains
    """
    global subdomain_cache
    
    if domain:
        cache_key = domain.lower().strip()
        if cache_key in subdomain_cache:
            del subdomain_cache[cache_key]
            logging.info(f"Subdomain cache invalidated for {domain}")
    else:
        subdomain_cache.clear()
        logging.info("All subdomain caches invalidated")


def get_dashboard_stats_cached() -> Dict[str, Any]:
    """
    Get dashboard stats from cache or load from database if cache is expired/empty.
    
    Returns:
        Dict[str, Any]: Dashboard statistics data
    """
    global dashboard_stats_cache, dashboard_stats_cache_timestamp
    
    current_time = datetime.now()
    
    # Check if cache exists and is still valid
    if (dashboard_stats_cache is not None and 
        dashboard_stats_cache_timestamp is not None and 
        (current_time - dashboard_stats_cache_timestamp).total_seconds() < DASHBOARD_CACHE_TTL):
        logging.debug("Using cached dashboard stats")
        return dashboard_stats_cache
    
    # Cache is expired or doesn't exist, reload from database
    logging.info("Dashboard cache expired or empty, reloading from database")
    try:
        # Import here to avoid circular imports
        from db_service import get_dashboard_statistics
        
        dashboard_stats_cache = get_dashboard_statistics()
        dashboard_stats_cache_timestamp = current_time
        logging.info("Dashboard stats cached successfully")
        return dashboard_stats_cache
    except Exception as e:
        logging.error(f"Error fetching dashboard stats: {e}")
        return {
            'active_vendors': 0,
            'subdomains_monitored': 0,
            'vulnerabilities_found': 0,
            'high_risk_issues': 0,
            'overall_score': 0,
            'score_percentage': 0,
            'severity_breakdown': {},
            'risk_distribution': {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
        }


def invalidate_dashboard_cache():
    """Invalidate the dashboard stats cache"""
    global dashboard_stats_cache, dashboard_stats_cache_timestamp
    dashboard_stats_cache = None
    dashboard_stats_cache_timestamp = None
    logging.info("Dashboard cache invalidated")


def get_ai_insights_cache() -> Dict[str, Any]:
    """
    Get the AI insights cache dictionary.
    
    Returns:
        Dict[str, Any]: AI insights cache
    """
    return ai_insights_cache


def clear_ai_insights_cache():
    """Clear all AI insights cache entries"""
    global ai_insights_cache
    ai_insights_cache.clear()
    logging.info("AI insights cache cleared")


def invalidate_ai_insights_cache(cache_key: str):
    """
    Invalidate a specific AI insights cache entry.
    
    Args:
        cache_key (str): The cache key to invalidate
    """
    global ai_insights_cache
    if cache_key in ai_insights_cache:
        del ai_insights_cache[cache_key]
        logging.info(f"AI insights cache invalidated for key: {cache_key}")


def get_cache_stats() -> Dict[str, Any]:
    """
    Get statistics about all caches.
    
    Returns:
        Dict[str, Any]: Cache statistics
    """
    current_time = datetime.now()
    
    stats = {
        'vendors_cache': {
            'exists': vendors_cache is not None,
            'timestamp': vendors_cache_timestamp.isoformat() if vendors_cache_timestamp else None,
            'age_seconds': (current_time - vendors_cache_timestamp).total_seconds() if vendors_cache_timestamp else None,
            'expired': False
        },
        'subdomain_cache': {
            'entries': len(subdomain_cache),
            'domains': list(subdomain_cache.keys())
        },
        'dashboard_stats_cache': {
            'exists': dashboard_stats_cache is not None,
            'timestamp': dashboard_stats_cache_timestamp.isoformat() if dashboard_stats_cache_timestamp else None,
            'age_seconds': (current_time - dashboard_stats_cache_timestamp).total_seconds() if dashboard_stats_cache_timestamp else None,
            'expired': False
        },
        'ai_insights_cache': {
            'entries': len(ai_insights_cache),
            'keys': list(ai_insights_cache.keys())
        }
    }
    
    # Check if caches are expired
    if vendors_cache_timestamp:
        stats['vendors_cache']['expired'] = (current_time - vendors_cache_timestamp).total_seconds() >= CACHE_EXPIRY_MINUTES * 60
    
    if dashboard_stats_cache_timestamp:
        stats['dashboard_stats_cache']['expired'] = (current_time - dashboard_stats_cache_timestamp).total_seconds() >= DASHBOARD_CACHE_TTL
    
    return stats


def clear_all_caches():
    """Clear all caches"""
    global vendors_cache, vendors_cache_timestamp, subdomain_cache, dashboard_stats_cache, dashboard_stats_cache_timestamp, ai_insights_cache
    
    vendors_cache = None
    vendors_cache_timestamp = None
    subdomain_cache.clear()
    dashboard_stats_cache = None
    dashboard_stats_cache_timestamp = None
    ai_insights_cache.clear()
    
    logging.info("All caches cleared")
