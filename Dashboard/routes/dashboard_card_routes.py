from fastapi import APIRouter, HTTPException, Request, Query, Body
from typing import Optional, Dict, Any, List
import logging
import time
import os
import sys
from dotenv import load_dotenv

# Add custom integrations path for logger
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', 'custom_integrations'))
from logger_config import setup_logger

# Configure logging using custom logger
logger = setup_logger()

# Load environment variables
load_dotenv()

# Import database services
from db_config import DatabaseConnection
from db_service import get_vendors_from_database

router = APIRouter()

@router.get('/api/dashboard/vendors-with-scores')
async def get_vendors_with_scores():
    """Get all vendors with their scores for the dashboard card"""
    try:
        vendors_data = get_vendors_from_database()
        
        # Format for frontend
        formatted_vendors = []
        for vendor in vendors_data:
            formatted_vendors.append({
                'id': vendor.get('id'),
                'name': vendor.get('name'),
                'domain': vendor.get('domain'),
                'score': vendor.get('securityScore', 0),
                'grade': vendor.get('grade', 'N/A'),
                'tier': vendor.get('tier'),
                'portfolio': vendor.get('portfolio'),
                'industry': vendor.get('industry'),
                'lastScan': vendor.get('lastScan'),
                'logo': vendor.get('logo')
            })
        
        return {
            'status': 'success',
            'vendors': formatted_vendors,
            'total': len(formatted_vendors)
        }
        
    except Exception as e:
        logger.error(f"Error getting vendors with scores: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get('/api/dashboard/subdomains-by-vendor')
async def get_subdomains_by_vendor():
    """Get all subdomains grouped by vendor for the dashboard card"""
    try:
        query = """
        SELECT 
            v.id as vendor_id,
            v.vendor_name,
            v.domain,
            v.grade,
            v.overall_score_current,
            COUNT(s.id) FILTER (WHERE s.status = 'Active') as subdomain_count
        FROM vendors v
        LEFT JOIN subdomains s ON v.id = s.vendor_id
        GROUP BY v.id, v.vendor_name, v.domain, v.grade, v.overall_score_current
        ORDER BY v.vendor_name
        """
        
        with DatabaseConnection() as db:
            results = db.execute_query(query)
            
            formatted_data = []
            if results:
                for row in results:
                    formatted_data.append({
                        'vendor_id': row['vendor_id'],
                        'vendor_name': row['vendor_name'],
                        'domain': row['domain'],
                        'grade': row['grade'],
                        'score': row['overall_score_current'] or 0,
                        'subdomain_count': row['subdomain_count']
                    })
            
            return {
                'status': 'success',
                'data': formatted_data,
                'total_vendors': len(formatted_data)
            }
            
    except Exception as e:
        logger.error(f"Error getting subdomains by vendor: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get('/api/dashboard/vulnerabilities-by-vendor')
async def get_vulnerabilities_by_vendor():
    """Get all vulnerabilities grouped by vendor for the dashboard card"""
    try:
        query = """
        SELECT 
            v.id as vendor_id,
            v.vendor_name,
            v.domain,
            v.grade,
            v.overall_score_current,
            COUNT(vuln.id) as vulnerability_count,
            COUNT(CASE WHEN vuln.severity = 'Critical' THEN 1 END) as critical_count,
            COUNT(CASE WHEN vuln.severity = 'High' THEN 1 END) as high_count,
            COUNT(CASE WHEN vuln.severity = 'Medium' THEN 1 END) as medium_count,
            COUNT(CASE WHEN vuln.severity = 'Low' THEN 1 END) as low_count
        FROM vendors v
        LEFT JOIN vulnerabilities vuln ON v.id = vuln.vendor_id
        GROUP BY v.id, v.vendor_name, v.domain, v.grade, v.overall_score_current
        ORDER BY v.vendor_name
        """
        
        with DatabaseConnection() as db:
            results = db.execute_query(query)
            
            formatted_data = []
            if results:
                for row in results:
                    formatted_data.append({
                        'vendor_id': row['vendor_id'],
                        'vendor_name': row['vendor_name'],
                        'domain': row['domain'],
                        'grade': row['grade'],
                        'score': row['overall_score_current'] or 0,
                        'vulnerability_count': row['vulnerability_count'],
                        'severity_breakdown': {
                            'critical': row['critical_count'],
                            'high': row['high_count'],
                            'medium': row['medium_count'],
                            'low': row['low_count']
                        }
                    })
            
            return {
                'status': 'success',
                'data': formatted_data,
                'total_vendors': len(formatted_data),
                'total_vulnerabilities': sum(item['vulnerability_count'] for item in formatted_data)
            }
            
    except Exception as e:
        logger.error(f"Error getting vulnerabilities by vendor: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get('/api/dashboard/high-risk-by-vendor')
async def get_high_risk_by_vendor():
    """Get high-risk issues (Critical and High severity) grouped by vendor for the dashboard card"""
    try:
        query = """
        SELECT 
            v.id as vendor_id,
            v.vendor_name,
            v.domain,
            v.grade,
            v.overall_score_current,
            COUNT(vuln.id) as high_risk_count,
            COUNT(CASE WHEN vuln.severity = 'Critical' THEN 1 END) as critical_count,
            COUNT(CASE WHEN vuln.severity = 'High' THEN 1 END) as high_count
        FROM vendors v
        LEFT JOIN vulnerabilities vuln ON v.id = vuln.vendor_id
        WHERE vuln.severity IN ('Critical', 'High')
        GROUP BY v.id, v.vendor_name, v.domain, v.grade, v.overall_score_current
        HAVING COUNT(vuln.id) > 0
        ORDER BY COUNT(CASE WHEN vuln.severity = 'Critical' THEN 1 END) DESC, v.vendor_name
        """
        
        with DatabaseConnection() as db:
            results = db.execute_query(query)
            
            formatted_data = []
            if results:
                for row in results:
                    formatted_data.append({
                        'vendor_id': row['vendor_id'],
                        'vendor_name': row['vendor_name'],
                        'domain': row['domain'],
                        'grade': row['grade'],
                        'score': row['overall_score_current'] or 0,
                        'high_risk_count': row['high_risk_count'],
                        'critical_count': row['critical_count'],
                        'high_count': row['high_count']
                    })
            
            return {
                'status': 'success',
                'data': formatted_data,
                'total_vendors': len(formatted_data),
                'total_issues': sum(item['high_risk_count'] for item in formatted_data)
            }
            
    except Exception as e:
        logger.error(f"Error getting high-risk issues by vendor: {e}")
        raise HTTPException(status_code=500, detail=str(e))
