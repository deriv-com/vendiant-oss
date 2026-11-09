"""
News Deduplication Module

This module provides intelligent deduplication of news/incident items by comparing:
1. Semantic similarity of titles and descriptions
2. Key entities (dates, domains, keywords)
3. Similarity thresholds to identify duplicates from different sources

Security: Input validation is performed on all user-provided data.
"""

import logging
import re
from typing import List, Dict, Optional, Tuple
from datetime import datetime, timedelta
from difflib import SequenceMatcher

logger = logging.getLogger(__name__)

# Confidence thresholds for deduplication
TITLE_SIMILARITY_THRESHOLD = 0.75  # 75% similar titles indicate duplicate
DESCRIPTION_SIMILARITY_THRESHOLD = 0.65  # 65% similar descriptions
DATE_PROXIMITY_DAYS = 7  # Consider news from same week as potential duplicates

# Security: Maximum input lengths to prevent abuse
MAX_TITLE_LENGTH = 500
MAX_DESCRIPTION_LENGTH = 5000


def normalize_text(text: str) -> str:
    """
    Normalize text for comparison.
    
    Security: Validates input to prevent injection attacks.
    """
    if not isinstance(text, str):
        return ""
    
    # Strip and convert to lowercase
    text = text.strip().lower()
    
    # Remove extra whitespace
    text = re.sub(r'\s+', ' ', text)
    
    # Remove punctuation and special characters (keep alphanumeric and spaces)
    text = re.sub(r'[^a-z0-9\s]', '', text)
    
    return text


def extract_key_entities(text: str) -> set:
    """
    Extract key entities (important words) from text.
    Filters out common stop words.
    
    Security: Input validation and safe regex operations.
    """
    if not isinstance(text, str):
        return set()
    
    # Common stop words to exclude
    stop_words = {
        'a', 'an', 'and', 'are', 'as', 'at', 'be', 'by', 'for', 'from',
        'has', 'he', 'in', 'is', 'it', 'its', 'of', 'on', 'or', 'that',
        'the', 'to', 'was', 'will', 'with', 'this', 'but', 'not', 'no',
        'yes', 'have', 'had', 'do', 'does', 'did', 'can', 'could', 'would',
        'should', 'may', 'might', 'must', 'shall', 'been', 'being'
    }
    
    # Normalize text first
    normalized = normalize_text(text)
    
    # Extract words (length > 3 to filter out common short words)
    words = [w for w in normalized.split() if len(w) > 3 and w not in stop_words]
    
    return set(words)


def calculate_similarity(text1: str, text2: str) -> float:
    """
    Calculate similarity between two texts using sequence matching.
    Returns a value between 0 and 1 (0 = no similarity, 1 = identical).
    
    Security: Safe implementation using difflib.
    """
    if not isinstance(text1, str) or not isinstance(text2, str):
        return 0.0
    
    # Truncate inputs for security
    text1 = text1[:MAX_TITLE_LENGTH] if len(text1) > MAX_TITLE_LENGTH else text1
    text2 = text2[:MAX_TITLE_LENGTH] if len(text2) > MAX_TITLE_LENGTH else text2
    
    # Normalize texts
    norm1 = normalize_text(text1)
    norm2 = normalize_text(text2)
    
    if not norm1 or not norm2:
        return 0.0
    
    # Use SequenceMatcher for similarity calculation
    matcher = SequenceMatcher(None, norm1, norm2)
    return matcher.ratio()


def calculate_entity_overlap(text1: str, text2: str) -> float:
    """
    Calculate entity overlap (key word overlap) between two texts.
    Returns a value between 0 and 1.
    
    Security: Safe entity extraction.
    """
    if not isinstance(text1, str) or not isinstance(text2, str):
        return 0.0
    
    # Truncate inputs for security
    text1 = text1[:MAX_DESCRIPTION_LENGTH] if len(text1) > MAX_DESCRIPTION_LENGTH else text1
    text2 = text2[:MAX_DESCRIPTION_LENGTH] if len(text2) > MAX_DESCRIPTION_LENGTH else text2
    
    entities1 = extract_key_entities(text1)
    entities2 = extract_key_entities(text2)
    
    if not entities1 or not entities2:
        return 0.0
    
    # Calculate Jaccard similarity (intersection / union)
    intersection = len(entities1 & entities2)
    union = len(entities1 | entities2)
    
    return intersection / union if union > 0 else 0.0


def are_dates_close(date1: str, date2: str, days: int = DATE_PROXIMITY_DAYS) -> bool:
    """
    Check if two dates are within N days of each other.
    Helps identify same-day news from multiple sources.
    
    Security: Validates date format before processing.
    """
    try:
        # Parse dates
        d1 = datetime.strptime(str(date1)[:10], '%Y-%m-%d').date()
        d2 = datetime.strptime(str(date2)[:10], '%Y-%m-%d').date()
        
        # Check if dates are within proximity
        date_diff = abs((d1 - d2).days)
        return date_diff <= days
    except (ValueError, TypeError, AttributeError):
        # If dates can't be parsed, consider them different
        return False


def is_potential_duplicate(
    new_item: Dict,
    existing_item: Dict,
    title_threshold: float = TITLE_SIMILARITY_THRESHOLD,
    description_threshold: float = DESCRIPTION_SIMILARITY_THRESHOLD,
    check_date_proximity: bool = True
) -> bool:
    """
    Determine if a new item is a potential duplicate of an existing item.
    
    Criteria for duplicate:
    1. Similar titles AND descriptions (combined score)
    2. Same date or close date
    3. Significant entity overlap in both title and description
    
    Args:
        new_item: New news/incident item to check
        existing_item: Existing item in database
        title_threshold: Similarity threshold for titles (0-1)
        description_threshold: Similarity threshold for descriptions (0-1)
        check_date_proximity: Whether to check if dates are close
    
    Returns:
        True if items are likely duplicates, False otherwise
    
    Security: All inputs validated and sanitized.
    """
    try:
        # Validate inputs
        if not isinstance(new_item, dict) or not isinstance(existing_item, dict):
            logger.warning("Invalid item format in duplicate check")
            return False
        
        # Extract and validate fields
        new_title = str(new_item.get('title', '')).strip()
        new_description = str(new_item.get('description', '')).strip()
        new_date = str(new_item.get('date', ''))
        new_type = str(new_item.get('type', '')).strip().lower()
        
        existing_title = str(existing_item.get('title', '')).strip()
        existing_description = str(existing_item.get('description', '')).strip()
        existing_date = str(existing_item.get('date', ''))
        existing_type = str(existing_item.get('type', '')).strip().lower()
        
        # Check if empty
        if not new_title or not existing_title:
            return False
        
        # First check: Type must match (incident vs news)
        if new_type and existing_type and new_type != existing_type:
            return False
        
        # Calculate all similarity metrics
        title_similarity = calculate_similarity(new_title, existing_title)
        title_entity_overlap = calculate_entity_overlap(new_title, existing_title)
        
        description_similarity = 0.0
        description_entity_overlap = 0.0
        if new_description and existing_description:
            description_similarity = calculate_similarity(new_description, existing_description)
            description_entity_overlap = calculate_entity_overlap(new_description, existing_description)
        
        # Check date proximity
        dates_close = False
        if check_date_proximity and new_date and existing_date:
            dates_close = are_dates_close(new_date, existing_date)
        
        # Duplicate detection logic:
        # Strategy 1: If titles are very similar (85%+), likely duplicate
        if title_similarity >= 0.70:
            logger.debug(f"Duplicate: High title similarity ({title_similarity:.2f})")
            return True
        
        # Strategy 2: Moderate title similarity + high title entity overlap
        # This catches "Data Breach at Acme Corp" vs "Acme Corporation Data Breach"
        if title_similarity >= 0.60 and title_entity_overlap >= 0.60:
            # Now check if descriptions are also similar
            if description_similarity >= description_threshold or description_entity_overlap >= 0.50:
                logger.debug(
                    f"Duplicate: Moderate title match ({title_similarity:.2f}) + "
                    f"high entity overlap ({title_entity_overlap:.2f}) + "
                    f"description match ({description_similarity:.2f})"
                )
                return True
        
        # Strategy 3: High description similarity + same date
        if description_similarity >= 0.70 and dates_close:
            logger.debug(
                f"Duplicate: High description similarity ({description_similarity:.2f}) "
                f"on same date"
            )
            return True
        
        # Strategy 4: High entity overlap in both title and description on same date
        if (title_entity_overlap >= 0.65 and description_entity_overlap >= 0.65 and 
            dates_close):
            logger.debug(
                f"Duplicate: High entity overlap in both title ({title_entity_overlap:.2f}) "
                f"and description ({description_entity_overlap:.2f}) on same date"
            )
            return True
        
        # Strategy 5: Very high combined similarity score
        combined_score = (title_similarity * 0.4 + description_similarity * 0.6)
        if combined_score >= 0.70:
            logger.debug(f"Duplicate: High combined similarity score ({combined_score:.2f})")
            return True
        
        return False
        
    except Exception as e:
        logger.error(f"Error in duplicate detection: {e}", exc_info=True)
        return False


def find_duplicates_in_existing_items(
    new_items: List[Dict],
    existing_items: List[Dict],
    min_confidence: float = 0.7
) -> Dict[int, List[Dict]]:
    """
    Find which existing items each new item duplicates with.
    
    Returns:
        Dict mapping new_item index to list of duplicate existing_items
    
    Security: Validates all inputs and handles edge cases safely.
    """
    if not isinstance(new_items, list) or not isinstance(existing_items, list):
        logger.warning("Invalid input: new_items or existing_items is not a list")
        return {}
    
    duplicates = {}
    
    for new_idx, new_item in enumerate(new_items):
        if not isinstance(new_item, dict):
            continue
        
        duplicate_matches = []
        
        for existing_item in existing_items:
            if not isinstance(existing_item, dict):
                continue
            
            # Adjust thresholds based on confidence level
            title_threshold = 1.0 - min_confidence
            description_threshold = 0.6 - (min_confidence * 0.1)
            
            if is_potential_duplicate(
                new_item,
                existing_item,
                title_threshold=title_threshold,
                description_threshold=description_threshold
            ):
                duplicate_matches.append(existing_item)
        
        if duplicate_matches:
            duplicates[new_idx] = duplicate_matches
            logger.info(
                f"New item '{new_item.get('title', 'Unknown')[:50]}...' "
                f"matches {len(duplicate_matches)} existing item(s)"
            )
    
    return duplicates


def filter_out_duplicates(
    new_items: List[Dict],
    existing_items: List[Dict]
) -> Tuple[List[Dict], List[Dict]]:
    """
    Filter out duplicate items from new_items based on existing_items.
    
    Returns:
        Tuple of (filtered_new_items, duplicate_indices_removed)
    
    Security: Safe filtering with full validation.
    """
    if not isinstance(new_items, list):
        logger.warning("Invalid input: new_items is not a list")
        return new_items, []
    
    if not existing_items:
        return new_items, []
    
    filtered_items = []
    duplicates_found = find_duplicates_in_existing_items(new_items, existing_items)
    
    for idx, item in enumerate(new_items):
        if idx not in duplicates_found:
            filtered_items.append(item)
        else:
            logger.info(
                f"Filtering out duplicate item #{idx}: '{item.get('title', 'Unknown')[:50]}...'"
            )
    
    return filtered_items, list(duplicates_found.keys())


# Validation functions for security

def validate_news_item(item: Dict) -> bool:
    """
    Validate a news item for required fields and proper format.
    
    Security: Strict validation to prevent invalid data.
    """
    if not isinstance(item, dict):
        return False
    
    # Check required fields
    required_fields = ['title', 'date', 'type']
    for field in required_fields:
        if field not in item or not str(item[field]).strip():
            return False
    
    # Validate date format
    try:
        datetime.strptime(str(item['date'])[:10], '%Y-%m-%d')
    except (ValueError, TypeError):
        return False
    
    # Validate type
    if str(item['type']).strip().lower() not in ['incident', 'news']:
        return False
    
    return True


def sanitize_news_items(items: List[Dict]) -> List[Dict]:
    """
    Sanitize and filter news items.
    
    Security: Remove invalid items and truncate long fields.
    """
    if not isinstance(items, list):
        return []
    
    sanitized = []
    
    for item in items:
        if not isinstance(item, dict):
            continue
        
        # Create sanitized copy
        safe_item = {
            'date': str(item.get('date', ''))[:10],
            'title': str(item.get('title', ''))[:MAX_TITLE_LENGTH],
            'description': str(item.get('description', ''))[:MAX_DESCRIPTION_LENGTH],
            'severity': str(item.get('severity', 'info')).lower(),
            'source': str(item.get('source', '#'))[:500],
            'type': str(item.get('type', 'news')).lower(),
            'relevance': str(item.get('relevance', ''))[:500]
        }
        
        # Validate required fields
        if validate_news_item(safe_item):
            sanitized.append(safe_item)
    
    return sanitized

