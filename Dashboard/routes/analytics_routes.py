from fastapi import APIRouter, HTTPException
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import logging
import sys
import os

# Add custom integrations path for logger
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'custom_integrations'))
from logger_config import setup_logger

# Configure logging using custom logger
logger = setup_logger()

# Import database services
from db_config import DatabaseConnection
from cache_service import get_vendors_cached

router = APIRouter()

TREND_LOOKBACK_DAYS = 30
MIN_BASELINE_AGE_DAYS = 7


def _get_vendor_current_score(vendor: Dict[str, Any]) -> Optional[float]:
    """Resolve the vendor's current overall score from cached vendor payload."""
    score = vendor.get('securityScore')
    if score is None:
        score = vendor.get('overall_score')
    if score is None:
        score = (vendor.get('scores') or {}).get('current')
    if score is None or score <= 0:
        return None
    return float(score)


def _get_vendor_snapshot_score(
    vendor: Dict[str, Any],
    snapshot_by_vendor_id: Dict[int, int],
) -> Optional[float]:
    """
    Read a precomputed ~1-month snapshot from cache or a batch-loaded DB map.
    Cached vendors expose this under scores.oneMonth, not overall_score_1month.
    """
    scores = vendor.get('scores') or {}
    one_month = scores.get('oneMonth')
    if one_month is not None and one_month > 0:
        return float(one_month)

    top_level = vendor.get('overall_score_1month')
    if top_level is not None and top_level > 0:
        return float(top_level)

    vendor_id = vendor.get('id')
    if vendor_id and vendor_id in snapshot_by_vendor_id:
        snapshot = snapshot_by_vendor_id[vendor_id]
        if snapshot and snapshot > 0:
            return float(snapshot)

    return None


def _load_vendor_snapshot_columns(vendor_ids: List[int]) -> Dict[int, int]:
    """Batch-load overall_score_1month from vendors (not present on cached payloads)."""
    if not vendor_ids:
        return {}

    with DatabaseConnection() as db:
        rows = db.execute_query(
            """
            SELECT id, overall_score_1month
            FROM vendors
            WHERE id = ANY(%s)
              AND overall_score_1month IS NOT NULL
              AND overall_score_1month > 0
            """,
            (vendor_ids,),
        )

    return {row['id']: row['overall_score_1month'] for row in rows}


def _load_historical_baselines_from_scores(
    vendor_ids: List[int],
    thirty_days_ago: datetime,
) -> Dict[int, float]:
    """
    Batch-load baseline overall scores per vendor from the scores table.
    Priority:
      1) Latest Overall score on or before the 30-day cutoff
      2) Earliest Overall score within the last 30 days (if scan history is recent only)
    """
    if not vendor_ids:
        return {}

    window_start = thirty_days_ago
    baselines: Dict[int, float] = {}

    with DatabaseConnection() as db:
        before_cutoff = db.execute_query(
            """
            SELECT DISTINCT ON (vendor_id)
                vendor_id,
                score
            FROM scores
            WHERE vendor_id = ANY(%s)
              AND score_category = 'Overall'
              AND updated_at <= %s
            ORDER BY vendor_id, updated_at DESC
            """,
            (vendor_ids, thirty_days_ago),
        )
        for row in before_cutoff:
            if row.get('score') and row['score'] > 0:
                baselines[row['vendor_id']] = float(row['score'])

        missing_ids = [vid for vid in vendor_ids if vid not in baselines]
        if missing_ids:
            earliest_in_window = db.execute_query(
                """
                SELECT DISTINCT ON (vendor_id)
                    vendor_id,
                    score,
                    updated_at
                FROM scores
                WHERE vendor_id = ANY(%s)
                  AND score_category = 'Overall'
                  AND updated_at >= %s
                ORDER BY vendor_id, updated_at ASC
                """,
                (missing_ids, window_start),
            )
            now = datetime.now()
            for row in earliest_in_window:
                updated_at = row.get('updated_at')
                if not updated_at or not row.get('score') or row['score'] <= 0:
                    continue
                if updated_at.tzinfo is not None:
                    updated_at = updated_at.replace(tzinfo=None)
                age_days = (now - updated_at).days
                if age_days >= MIN_BASELINE_AGE_DAYS:
                    baselines[row['vendor_id']] = float(row['score'])

    return baselines


def _get_historical_score_30_days_ago(
    vendor: Dict[str, Any],
    thirty_days_ago: datetime,
    snapshot_by_vendor_id: Dict[int, int],
    score_baselines_by_vendor_id: Dict[int, float],
) -> Optional[float]:
    """
    Resolve a vendor's baseline score (~30 days ago) for trend calculation.
    """
    snapshot_score = _get_vendor_snapshot_score(vendor, snapshot_by_vendor_id)
    if snapshot_score is not None:
        return snapshot_score

    vendor_id = vendor.get('id')
    if vendor_id and vendor_id in score_baselines_by_vendor_id:
        return score_baselines_by_vendor_id[vendor_id]

    return None


def _sync_monthly_score_snapshots() -> int:
    """
    Backfill vendors.overall_score_1month from Overall score history when unset.
    Scans only update overall_score_current; without this, monthly trend columns stay empty.
    """
    try:
        with DatabaseConnection() as db:
            result = db.execute_insert(
                """
                UPDATE vendors v
                SET overall_score_1month = hist.score
                FROM (
                    SELECT DISTINCT ON (s.vendor_id)
                        s.vendor_id,
                        s.score
                    FROM scores s
                    WHERE s.score_category = 'Overall'
                      AND s.updated_at <= NOW() - INTERVAL '30 days'
                    ORDER BY s.vendor_id, s.updated_at DESC
                ) hist
                WHERE v.id = hist.vendor_id
                  AND hist.score > 0
                  AND (v.overall_score_1month IS NULL OR v.overall_score_1month = 0)
                """
            )
            return bool(result)
    except Exception as e:
        logger.warning("[TREND] Could not sync monthly score snapshots: %s", e)
        return False


def _calculate_vendor_trends(
    vendors: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Calculate 30-day score trends for all vendors with a valid current score and baseline.
    Returns vendor dicts including integer trend (current - baseline).
    """
    current_date = datetime.now()
    thirty_days_ago = current_date - timedelta(days=TREND_LOOKBACK_DAYS)

    vendor_ids = [v['id'] for v in vendors if v.get('id')]
    snapshot_by_vendor_id = _load_vendor_snapshot_columns(vendor_ids)
    score_baselines_by_vendor_id = _load_historical_baselines_from_scores(
        vendor_ids,
        thirty_days_ago,
    )

    logger.info(
        "[TREND] Baseline sources: %s vendor snapshots, %s score-history baselines (cutoff %s)",
        len(snapshot_by_vendor_id),
        len(score_baselines_by_vendor_id),
        thirty_days_ago.strftime('%Y-%m-%d'),
    )

    vendors_with_trends: List[Dict[str, Any]] = []
    vendors_with_baseline = 0

    for vendor in vendors:
        current_score = _get_vendor_current_score(vendor)
        if current_score is None:
            continue

        vendor_id = vendor.get('id', 0)
        vendor_name = vendor.get('name', 'Unknown')

        try:
            baseline_score = _get_historical_score_30_days_ago(
                vendor,
                thirty_days_ago,
                snapshot_by_vendor_id,
                score_baselines_by_vendor_id,
            )
            if baseline_score is None or baseline_score <= 0:
                continue

            vendors_with_baseline += 1
            trend_30_days = int(round(current_score - baseline_score))
        except Exception as e:
            logger.warning("[TREND] Error calculating trend for vendor %s: %s", vendor_name, e)
            continue

        vendors_with_trends.append({
            'id': vendor_id,
            'name': vendor_name,
            'score': int(current_score),
            'tier': vendor.get('tier', 'Untiered'),
            'trend': trend_30_days,
        })

    logger.info(
        "[TREND] %s vendors with baselines, %s with non-zero trend",
        vendors_with_baseline,
        sum(1 for v in vendors_with_trends if v['trend'] != 0),
    )
    return vendors_with_trends


def get_highest_rated_vendors(limit: int = 5) -> List[Dict[str, Any]]:
    """
    Get highest rated vendors sorted by score
    
    Args:
        limit: Number of vendors to return (default: 5)
    
    Returns:
        List of vendor dictionaries with id, name, score, tier, trend
    """
    try:
        vendors = get_vendors_cached()
        
        valid_vendors = []
        for vendor in vendors:
            current_score = vendor.get('overall_score', 0) or vendor.get('securityScore', 0)
            if not current_score or current_score <= 0:
                continue
            
            valid_vendors.append({
                'id': vendor.get('id', 0),
                'name': vendor.get('name', 'Unknown'),
                'score': int(current_score),
                'tier': vendor.get('tier', 'Untiered'),
                'trend': 0  # No trend calculation for highest/lowest rated
            })
        
        # Sort by score descending and return top N
        sorted_by_score = sorted(valid_vendors, key=lambda x: x['score'], reverse=True)
        return sorted_by_score[:limit]
        
    except Exception as e:
        logger.error(f"Error getting highest rated vendors: {e}")
        return []


def get_lowest_rated_vendors(limit: int = 5) -> List[Dict[str, Any]]:
    """
    Get lowest rated vendors sorted by score
    
    Args:
        limit: Number of vendors to return (default: 5)
    
    Returns:
        List of vendor dictionaries with id, name, score, tier, trend
    """
    try:
        vendors = get_vendors_cached()
        
        valid_vendors = []
        for vendor in vendors:
            current_score = vendor.get('overall_score', 0) or vendor.get('securityScore', 0)
            if not current_score or current_score <= 0:
                continue
            
            valid_vendors.append({
                'id': vendor.get('id', 0),
                'name': vendor.get('name', 'Unknown'),
                'score': int(current_score),
                'tier': vendor.get('tier', 'Untiered'),
                'trend': 0  # No trend calculation for highest/lowest rated
            })
        
        # Sort by score ascending and return bottom N (reversed to show lowest first)
        sorted_by_score = sorted(valid_vendors, key=lambda x: x['score'])
        return sorted_by_score[:limit][::-1]  # Reverse to show lowest first
        
    except Exception as e:
        logger.error(f"Error getting lowest rated vendors: {e}")
        return []


def get_greatest_improvement_30_days(limit: int = 5) -> List[Dict[str, Any]]:
    """
    Get vendors with greatest improvement in the last 30 days
    
    Args:
        limit: Number of vendors to return (default: 5)
    
    Returns:
        List of vendor dictionaries with id, name, score, tier, trend
    """
    try:
        vendors = get_vendors_cached()
        vendors_with_trends = _calculate_vendor_trends(vendors)

        improved = [v for v in vendors_with_trends if v['trend'] > 0]
        logger.info(
            "[IMPROVEMENT] Returning %s vendors (from %s with positive trend)",
            min(limit, len(improved)),
            len(improved),
        )
        return sorted(improved, key=lambda x: x['trend'], reverse=True)[:limit]

    except Exception as e:
        logger.error(f"Error getting greatest improvement vendors: {e}")
        return []


def get_greatest_decline_30_days(limit: int = 5) -> List[Dict[str, Any]]:
    """
    Get vendors with greatest decline in the last 30 days
    
    Args:
        limit: Number of vendors to return (default: 5)
    
    Returns:
        List of vendor dictionaries with id, name, score, tier, trend
    """
    try:
        vendors = get_vendors_cached()
        vendors_with_trends = _calculate_vendor_trends(vendors)

        declined = [v for v in vendors_with_trends if v['trend'] < 0]
        logger.info(
            "[DECLINE] Returning %s vendors (from %s with negative trend)",
            min(limit, len(declined)),
            len(declined),
        )
        return sorted(declined, key=lambda x: x['trend'])[:limit]

    except Exception as e:
        logger.error(f"Error getting greatest decline vendors: {e}")
        return []


@router.get('/api/analytics/domain-distribution')
async def get_domain_distribution():
    """Get domain distribution data for heatmap visualization"""
    try:
        vendors = get_vendors_cached()
        
        # Risk levels (A-F) and their score ranges
        risk_levels = ['A', 'B', 'C', 'D', 'F']
        risk_ranges = ['801-950', '601-800', '401-600', '201-400', '0-200']
        
        # Tiers (must match frontend order: Tier 1, Tier 2, Tier 3, Untiered)
        tiers = ['Tier 1', 'Tier 2', 'Tier 3', 'Untiered']
        
        # Initialize data matrix: [risk_level][tier] = count
        data = [[0 for _ in range(len(tiers))] for _ in range(len(risk_levels))]
        
        total_domains = 0
        
        for vendor in vendors:
            current_score = vendor.get('overall_score', 0) or vendor.get('securityScore', 0)
            if not current_score or current_score <= 0:
                continue
            
            total_domains += 1
            
            # Determine risk level based on score
            risk_index = None
            if current_score >= 801:
                risk_index = 0  # A (801-950)
            elif current_score >= 601:
                risk_index = 1  # B (601-800)
            elif current_score >= 401:
                risk_index = 2  # C (401-600)
            elif current_score >= 201:
                risk_index = 3  # D (201-400)
            else:
                risk_index = 4  # F (0-200)
            
            # Determine tier
            tier = vendor.get('tier', 'Untiered')
            tier_index = None
            if tier == 'Tier 1':
                tier_index = 0
            elif tier == 'Tier 2':
                tier_index = 1
            elif tier == 'Tier 3':
                tier_index = 2
            else:  # Untiered or any other value
                tier_index = 3
            
            # Increment count in the matrix
            if risk_index is not None and tier_index is not None:
                data[risk_index][tier_index] += 1
        
        logger.info(f"Domain distribution calculated: {total_domains} total domains")
        
        return {
            'riskLevels': risk_levels,
            'riskRanges': risk_ranges,
            'tiers': tiers,
            'data': data,
            'totalDomains': total_domains
        }
        
    except Exception as e:
        logger.error(f"Error getting domain distribution: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get('/api/analytics/vendor-performance')
async def get_vendor_performance():
    """Get vendor performance data for analytics tables"""
    try:
        if _sync_monthly_score_snapshots():
            logger.info("[TREND] Backfilled overall_score_1month snapshots from score history")

        # Get data from separate functions
        highest_rated = get_highest_rated_vendors(limit=5)
        lowest_rated = get_lowest_rated_vendors(limit=5)
        greatest_improvement = get_greatest_improvement_30_days(limit=5)
        greatest_decline = get_greatest_decline_30_days(limit=5)
        
        logger.info(f"Analytics data: {len(highest_rated)} highest, {len(lowest_rated)} lowest, "
                   f"{len(greatest_improvement)} improvements, {len(greatest_decline)} declines")
        
        # Log detailed data for debugging
        if greatest_improvement:
            logger.info(f"Improvement vendors: {[{'name': v.get('name'), 'trend': v.get('trend'), 'score': v.get('score')} for v in greatest_improvement]}")
        else:
            logger.warning("No improvement vendors found")
            
        if greatest_decline:
            logger.info(f"Decline vendors: {[{'name': v.get('name'), 'trend': v.get('trend'), 'score': v.get('score')} for v in greatest_decline]}")
        else:
            logger.warning("No decline vendors found")
        
        return {
            'status': 'success',
            'highest': highest_rated,
            'lowest': lowest_rated,
            'improvement': greatest_improvement,
            'decline': greatest_decline
        }
        
    except Exception as e:
        logger.error(f"Error getting vendor performance: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get('/api/analytics/vendors-by-cell')
async def get_vendors_by_cell(riskLevel: str, riskRange: str, tier: str):
    """Get vendors for a specific heatmap cell"""
    try:
        vendors = get_vendors_cached()
        
        # Parse risk range (e.g., "801-950")
        risk_parts = riskRange.split('-')
        if len(risk_parts) != 2:
            raise HTTPException(status_code=400, detail="Invalid risk range format")
        
        min_score = int(risk_parts[0])
        max_score = int(risk_parts[1])
        
        # Filter vendors by score range and tier
        filtered_vendors = []
        for vendor in vendors:
            score = vendor.get('overall_score', 0) or vendor.get('securityScore', 0)
            vendor_tier = vendor.get('tier', 'Untiered')
            
            # Check if score is in range and tier matches
            if min_score <= score <= max_score and vendor_tier == tier:
                filtered_vendors.append({
                    'id': vendor.get('id'),
                    'name': vendor.get('name'),
                    'domain': vendor.get('domain'),
                    'score': score,
                    'tier': vendor_tier
                })
        
        logger.info(f"Found {len(filtered_vendors)} vendors for {riskLevel} ({riskRange}) - {tier}")
        
        return {
            'status': 'success',
            'vendors': filtered_vendors,
            'count': len(filtered_vendors)
        }
        
    except Exception as e:
        logger.error(f"Error getting vendors by cell: {e}")
        raise HTTPException(status_code=500, detail=str(e))
