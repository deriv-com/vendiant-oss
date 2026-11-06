from fastapi import APIRouter, HTTPException, Request, Query, Body, Depends
from fastapi.responses import JSONResponse
from typing import Optional
import logging
import os
import sys
from datetime import datetime, timedelta

# Add path for Dashboard module imports
dashboard_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if dashboard_path not in sys.path:
    sys.path.append(dashboard_path)

# Import Dashboard module functions
from db_config import DatabaseConnection
from audit_service import log_request_action

router = APIRouter()

try:
    from Dashboard.effective_permissions import require_permission
except ImportError:
    from effective_permissions import require_permission

require_view_portfolios   = require_permission("view_portfolios")
require_create_portfolios = require_permission("view_portfolios", "create_portfolios")
require_manage_portfolios = require_permission("view_portfolios", "manage_portfolios")
require_delete_portfolios = require_permission("view_portfolios", "delete_portfolios")
require_view_vendors      = require_permission("view_vendors")

# Audit details record which vendors moved; cap the list so one bulk edit cannot
# write an unbounded blob into audit_logs.details.
_MAX_AUDITED_NAMES = 20


def _name_sample(names: list) -> dict:
    """Vendor names for an audit row, truncated with an explicit overflow count."""
    ordered = sorted({str(n).strip() for n in names if str(n or "").strip()})
    sample = {"vendor_names": ordered[:_MAX_AUDITED_NAMES], "vendor_count": len(ordered)}
    if len(ordered) > _MAX_AUDITED_NAMES:
        sample["vendor_names_omitted"] = len(ordered) - _MAX_AUDITED_NAMES
    return sample

@router.get('/api/portfolios/stats')
async def get_portfolio_stats(_: None = Depends(require_view_portfolios)):
    """Get portfolio statistics - individual portfolios only"""
    try:
        with DatabaseConnection() as db:
            # Get individual portfolio statistics (split comma-separated portfolios)
            query = """
                WITH RECURSIVE split_portfolios AS (
                    SELECT 
                        vendor_name,
                        domain,
                        overall_score_current,
                        TRIM(SPLIT_PART(portfolio, ',', 1)) as individual_portfolio,
                        portfolio,
                        1 as pos
                    FROM vendors 
                    WHERE portfolio IS NOT NULL 
                    AND overall_score_current IS NOT NULL
                    AND portfolio != ''
                    
                    UNION ALL
                    
                    SELECT 
                        vendor_name,
                        domain,
                        overall_score_current,
                        TRIM(SPLIT_PART(portfolio, ',', pos + 1)) as individual_portfolio,
                        portfolio,
                        pos + 1
                    FROM split_portfolios
                    WHERE TRIM(SPLIT_PART(portfolio, ',', pos + 1)) != ''
                )
                SELECT 
                    individual_portfolio as portfolio,
                    COUNT(*) as vendor_count,
                    ROUND(AVG(overall_score_current), 2) as avg_score,
                    ARRAY_AGG(vendor_name ORDER BY overall_score_current DESC) as vendors,
                    ARRAY_AGG(domain ORDER BY overall_score_current DESC) as domains,
                    ARRAY_AGG(overall_score_current ORDER BY overall_score_current DESC) as scores
                FROM split_portfolios
                WHERE individual_portfolio != ''
                GROUP BY individual_portfolio
                ORDER BY avg_score DESC
            """
            results = db.execute_query(query)
        
        portfolio_stats = []
        for row in results:
            portfolio_stats.append({
                'portfolio': row['portfolio'],
                'vendor_count': row['vendor_count'],
                'avg_score': float(row['avg_score']),
                'vendors': row['vendors'],
                'domains': row['domains'],
                'scores': row['scores']
            })
        
        return {
            'portfolios': portfolio_stats,
            'total_portfolios': len(portfolio_stats),
            'timestamp': datetime.now().isoformat()
        }
        
    except Exception as e:
        logging.error(f"Error retrieving portfolio statistics: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post('/api/portfolios/compare')
async def compare_portfolios(data: dict = Body(...), _: None = Depends(require_view_portfolios)):
    """Compare two portfolios to find common vendors"""
    try:
        portfolio1 = data.get('portfolio1')
        portfolio2 = data.get('portfolio2')
        
        if not portfolio1 or not portfolio2:
            raise HTTPException(status_code=400, detail='Both portfolio1 and portfolio2 are required')
        
        with DatabaseConnection() as db:
            # Find common vendors between two portfolios
            query = """
                WITH RECURSIVE split_portfolios AS (
                    SELECT 
                        vendor_name,
                        domain,
                        overall_score_current,
                        TRIM(SPLIT_PART(portfolio, ',', 1)) as individual_portfolio,
                        portfolio,
                        1 as pos
                    FROM vendors 
                    WHERE portfolio IS NOT NULL 
                    AND overall_score_current IS NOT NULL
                    AND portfolio != ''
                    
                    UNION ALL
                    
                    SELECT 
                        vendor_name,
                        domain,
                        overall_score_current,
                        TRIM(SPLIT_PART(portfolio, ',', pos + 1)) as individual_portfolio,
                        portfolio,
                        pos + 1
                    FROM split_portfolios
                    WHERE TRIM(SPLIT_PART(portfolio, ',', pos + 1)) != ''
                ),
                portfolio1_vendors AS (
                    SELECT vendor_name, domain, overall_score_current
                    FROM split_portfolios 
                    WHERE individual_portfolio = %s AND individual_portfolio != ''
                ),
                portfolio2_vendors AS (
                    SELECT vendor_name, domain, overall_score_current
                    FROM split_portfolios 
                    WHERE individual_portfolio = %s AND individual_portfolio != ''
                )
                SELECT 
                    p1.vendor_name,
                    p1.domain,
                    p1.overall_score_current as score1,
                    p2.overall_score_current as score2,
                    ROUND((p1.overall_score_current + p2.overall_score_current) / 2.0, 2) as avg_score
                FROM portfolio1_vendors p1
                INNER JOIN portfolio2_vendors p2 ON p1.vendor_name = p2.vendor_name
                ORDER BY avg_score DESC
            """
            results = db.execute_query(query, (portfolio1, portfolio2))
        
        common_vendors = []
        for row in results:
            common_vendors.append({
                'vendor_name': row['vendor_name'],
                'domain': row['domain'],
                'score1': row['score1'],
                'score2': row['score2'],
                'avg_score': float(row['avg_score'])
            })
        
        return {
            'portfolio1': portfolio1,
            'portfolio2': portfolio2,
            'common_vendors': common_vendors,
            'common_count': len(common_vendors),
            'timestamp': datetime.now().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error comparing portfolios: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post('/api/portfolios/create')
async def create_portfolio(
    request: Request,
    data: dict = Body(...),
    _: None = Depends(require_create_portfolios),
):
    """Create a new portfolio with selected vendors"""
    try:
        portfolio_name = data.get('portfolio_name', '').strip()
        vendor_ids = data.get('vendor_ids', [])
        
        if not portfolio_name:
            raise HTTPException(status_code=400, detail='Portfolio name is required')
        
        if not vendor_ids:
            raise HTTPException(status_code=400, detail='At least one vendor must be selected')
        
        with DatabaseConnection() as db:
            # Check if portfolio name already exists
            check_query = """
                SELECT COUNT(*) as count FROM vendors 
                WHERE portfolio LIKE %s OR portfolio LIKE %s OR portfolio LIKE %s OR portfolio = %s
            """
            existing = db.execute_single_query(check_query, (
                f'%,{portfolio_name},%', 
                f'{portfolio_name},%', 
                f'%,{portfolio_name}', 
                portfolio_name
            ))
            
            if existing and existing['count'] > 0:
                raise HTTPException(status_code=409, detail=f'Portfolio "{portfolio_name}" already exists')
            
            # Get vendor details to validate they exist
            vendor_placeholders = ','.join(['%s'] * len(vendor_ids))
            vendor_query = f"SELECT id, vendor_name, portfolio FROM vendors WHERE id IN ({vendor_placeholders})"
            vendors = db.execute_query(vendor_query, vendor_ids)
            
            if len(vendors) != len(vendor_ids):
                raise HTTPException(status_code=400, detail='Some vendors not found')
            
            # Update vendors to add them to the new portfolio
            updated_count = 0
            for vendor in vendors:
                current_portfolio = vendor.get('portfolio', '') or ''
                
                # Add portfolio to existing portfolios (comma-separated)
                if current_portfolio and current_portfolio.strip():
                    new_portfolio = f"{current_portfolio},{portfolio_name}"
                else:
                    new_portfolio = portfolio_name
                
                update_query = "UPDATE vendors SET portfolio = %s WHERE id = %s"
                success = db.execute_insert(update_query, (new_portfolio, vendor['id']))
                if success:
                    updated_count += 1
            
            if updated_count == 0:
                raise HTTPException(status_code=500, detail='Failed to create portfolio')
            
            log_request_action(
                request,
                action='CREATE',
                resource_type='PORTFOLIO',
                resource_id=portfolio_name,
                details={
                    'portfolio': portfolio_name,
                    **_name_sample([v.get('vendor_name') for v in vendors]),
                },
            )

            return {
                'success': True,
                'message': f'Portfolio "{portfolio_name}" created successfully with {updated_count} vendors',
                'portfolio_name': portfolio_name,
                'vendor_count': updated_count,
                'timestamp': datetime.now().isoformat()
            }
            
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error creating portfolio: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.delete('/api/portfolios/{portfolio_name}')
async def delete_portfolio(
    request: Request,
    portfolio_name: str,
    _: None = Depends(require_delete_portfolios),
):
    """Delete a portfolio by removing it from all vendors"""
    try:
        if not portfolio_name or not portfolio_name.strip():
            raise HTTPException(status_code=400, detail='Portfolio name is required')
        
        portfolio_name = portfolio_name.strip()
        
        with DatabaseConnection() as db:
            # Find all vendors with this portfolio
            find_query = """
                SELECT id, vendor_name, portfolio FROM vendors 
                WHERE portfolio LIKE %s OR portfolio LIKE %s OR portfolio LIKE %s OR portfolio = %s
            """
            vendors = db.execute_query(find_query, (
                f'%,{portfolio_name},%', 
                f'{portfolio_name},%', 
                f'%,{portfolio_name}', 
                portfolio_name
            ))
            
            if not vendors:
                raise HTTPException(status_code=404, detail=f'Portfolio "{portfolio_name}" not found')
            
            # Update each vendor to remove the portfolio
            updated_count = 0
            for vendor in vendors:
                current_portfolio = vendor.get('portfolio', '') or ''
                
                # Remove the portfolio from the comma-separated list
                portfolios = [p.strip() for p in current_portfolio.split(',') if p.strip()]
                portfolios = [p for p in portfolios if p != portfolio_name]
                
                new_portfolio = ','.join(portfolios) if portfolios else None
                
                update_query = "UPDATE vendors SET portfolio = %s WHERE id = %s"
                success = db.execute_insert(update_query, (new_portfolio, vendor['id']))
                if success:
                    updated_count += 1
            
            log_request_action(
                request,
                action='DELETE',
                resource_type='PORTFOLIO',
                resource_id=portfolio_name,
                details={
                    'portfolio': portfolio_name,
                    **_name_sample([v.get('vendor_name') for v in vendors]),
                },
            )

            return {
                'success': True,
                'message': f'Portfolio "{portfolio_name}" deleted successfully. Removed from {updated_count} vendors.',
                'portfolio_name': portfolio_name,
                'vendors_updated': updated_count,
                'timestamp': datetime.now().isoformat()
            }
            
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error deleting portfolio: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get('/api/portfolios/{portfolio_name}/vendors')
async def get_portfolio_vendors(portfolio_name: str, _: None = Depends(require_view_portfolios)):
    """Get all vendors in a specific portfolio"""
    try:
        if not portfolio_name or not portfolio_name.strip():
            raise HTTPException(status_code=400, detail='Portfolio name is required')
        
        portfolio_name = portfolio_name.strip()
        
        with DatabaseConnection() as db:
            query = """
                SELECT id, vendor_name, domain, overall_score_current, grade, tier, industry
                FROM vendors 
                WHERE portfolio LIKE %s OR portfolio LIKE %s OR portfolio LIKE %s OR portfolio = %s
                ORDER BY vendor_name ASC
            """
            vendors = db.execute_query(query, (
                f'%,{portfolio_name},%', 
                f'{portfolio_name},%', 
                f'%,{portfolio_name}', 
                portfolio_name
            ))
            
            vendor_list = []
            for vendor in vendors:
                vendor_list.append({
                    'id': vendor['id'],
                    'vendor_name': vendor['vendor_name'],
                    'domain': vendor['domain'],
                    'score': vendor['overall_score_current'] or 0,
                    'grade': vendor['grade'] or 'N/A',
                    'tier': vendor['tier'] or 'Unknown',
                    'industry': vendor['industry'] or 'Unknown'
                })
            
            return {
                'portfolio_name': portfolio_name,
                'vendors': vendor_list,
                'vendor_count': len(vendor_list),
                'timestamp': datetime.now().isoformat()
            }
            
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error getting portfolio vendors: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post('/api/portfolios/{portfolio_name}/vendors/add')
async def add_vendors_to_portfolio(
    request: Request,
    portfolio_name: str,
    data: dict = Body(...),
    _: None = Depends(require_manage_portfolios),
):
    """Add vendors to an existing portfolio"""
    try:
        if not portfolio_name or not portfolio_name.strip():
            raise HTTPException(status_code=400, detail='Portfolio name is required')
        
        portfolio_name = portfolio_name.strip()
        vendor_ids = data.get('vendor_ids', [])
        
        if not vendor_ids:
            raise HTTPException(status_code=400, detail='At least one vendor must be selected')
        
        with DatabaseConnection() as db:
            # Verify portfolio exists
            check_query = """
                SELECT COUNT(*) as count FROM vendors 
                WHERE portfolio LIKE %s OR portfolio LIKE %s OR portfolio LIKE %s OR portfolio = %s
            """
            existing = db.execute_single_query(check_query, (
                f'%,{portfolio_name},%', 
                f'{portfolio_name},%', 
                f'%,{portfolio_name}', 
                portfolio_name
            ))
            
            if not existing or existing['count'] == 0:
                raise HTTPException(status_code=404, detail=f'Portfolio "{portfolio_name}" not found')
            
            # Get vendor details
            vendor_placeholders = ','.join(['%s'] * len(vendor_ids))
            vendor_query = f"SELECT id, vendor_name, portfolio FROM vendors WHERE id IN ({vendor_placeholders})"
            vendors = db.execute_query(vendor_query, vendor_ids)
            
            if len(vendors) != len(vendor_ids):
                raise HTTPException(status_code=400, detail='Some vendors not found')
            
            # Add vendors to portfolio
            updated_count = 0
            already_in_portfolio = 0
            
            for vendor in vendors:
                current_portfolio = vendor.get('portfolio', '') or ''
                
                # Check if vendor is already in this portfolio
                portfolios = [p.strip() for p in current_portfolio.split(',') if p.strip()]
                if portfolio_name in portfolios:
                    already_in_portfolio += 1
                    continue
                
                # Add portfolio to existing portfolios
                if current_portfolio and current_portfolio.strip():
                    new_portfolio = f"{current_portfolio},{portfolio_name}"
                else:
                    new_portfolio = portfolio_name
                
                update_query = "UPDATE vendors SET portfolio = %s WHERE id = %s"
                success = db.execute_insert(update_query, (new_portfolio, vendor['id']))
                if success:
                    updated_count += 1
            
            message = f"Added {updated_count} vendors to portfolio '{portfolio_name}'"
            if already_in_portfolio > 0:
                message += f". {already_in_portfolio} vendors were already in the portfolio"
            
            log_request_action(
                request,
                action='ADD VENDORS',
                resource_type='PORTFOLIO',
                resource_id=portfolio_name,
                details={
                    'portfolio': portfolio_name,
                    'vendors_added': updated_count,
                    'vendors_already_in_portfolio': already_in_portfolio,
                    **_name_sample([v.get('vendor_name') for v in vendors]),
                },
            )

            return {
                'success': True,
                'message': message,
                'portfolio_name': portfolio_name,
                'vendors_added': updated_count,
                'vendors_already_in_portfolio': already_in_portfolio,
                'timestamp': datetime.now().isoformat()
            }
            
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error adding vendors to portfolio: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post('/api/portfolios/{portfolio_name}/vendors/remove')
async def remove_vendors_from_portfolio(
    request: Request,
    portfolio_name: str,
    data: dict = Body(...),
    _: None = Depends(require_manage_portfolios),
):
    """Remove vendors from a portfolio"""
    try:
        if not portfolio_name or not portfolio_name.strip():
            raise HTTPException(status_code=400, detail='Portfolio name is required')
        
        portfolio_name = portfolio_name.strip()
        vendor_ids = data.get('vendor_ids', [])
        
        if not vendor_ids:
            raise HTTPException(status_code=400, detail='At least one vendor must be selected')
        
        with DatabaseConnection() as db:
            # Get vendor details
            vendor_placeholders = ','.join(['%s'] * len(vendor_ids))
            vendor_query = f"SELECT id, vendor_name, portfolio FROM vendors WHERE id IN ({vendor_placeholders})"
            vendors = db.execute_query(vendor_query, vendor_ids)
            
            if len(vendors) != len(vendor_ids):
                raise HTTPException(status_code=400, detail='Some vendors not found')
            
            # Remove vendors from portfolio
            updated_count = 0
            not_in_portfolio = 0
            
            for vendor in vendors:
                current_portfolio = vendor.get('portfolio', '') or ''
                
                # Remove the portfolio from the comma-separated list
                portfolios = [p.strip() for p in current_portfolio.split(',') if p.strip()]
                
                if portfolio_name not in portfolios:
                    not_in_portfolio += 1
                    continue
                
                portfolios = [p for p in portfolios if p != portfolio_name]
                new_portfolio = ','.join(portfolios) if portfolios else None
                
                update_query = "UPDATE vendors SET portfolio = %s WHERE id = %s"
                success = db.execute_insert(update_query, (new_portfolio, vendor['id']))
                if success:
                    updated_count += 1
            
            message = f"Removed {updated_count} vendors from portfolio '{portfolio_name}'"
            if not_in_portfolio > 0:
                message += f". {not_in_portfolio} vendors were not in the portfolio"
            
            log_request_action(
                request,
                action='REMOVE VENDORS',
                resource_type='PORTFOLIO',
                resource_id=portfolio_name,
                details={
                    'portfolio': portfolio_name,
                    'vendors_removed': updated_count,
                    'vendors_not_in_portfolio': not_in_portfolio,
                    **_name_sample([v.get('vendor_name') for v in vendors]),
                },
            )

            return {
                'success': True,
                'message': message,
                'portfolio_name': portfolio_name,
                'vendors_removed': updated_count,
                'vendors_not_in_portfolio': not_in_portfolio,
                'timestamp': datetime.now().isoformat()
            }
            
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error removing vendors from portfolio: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get('/api/vendors/available')
async def get_available_vendors(_: None = Depends(require_view_vendors)):
    """Get all vendors that can be added to portfolios"""
    try:
        with DatabaseConnection() as db:
            query = """
                SELECT id, vendor_name, domain, overall_score_current, grade, tier, industry, portfolio
                FROM vendors 
                ORDER BY vendor_name ASC
            """
            vendors = db.execute_query(query)
            
            vendor_list = []
            for vendor in vendors:
                vendor_list.append({
                    'id': vendor['id'],
                    'vendor_name': vendor['vendor_name'],
                    'domain': vendor['domain'],
                    'score': vendor['overall_score_current'] or 0,
                    'grade': vendor['grade'] or 'N/A',
                    'tier': vendor['tier'] or 'Unknown',
                    'industry': vendor['industry'] or 'Unknown',
                    'current_portfolios': vendor['portfolio'] or ''
                })
            
            return {
                'vendors': vendor_list,
                'total_count': len(vendor_list),
                'timestamp': datetime.now().isoformat()
            }
            
    except Exception as e:
        logging.error(f"Error getting available vendors: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")