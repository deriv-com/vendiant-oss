"""
API Audit Service for fetching audit logs from the API layer
"""

import logging
import sys
import os
from typing import Optional, Dict, Any, List
from db_config import DatabaseConnection
from datetime_utils import serialize_timestamp

# Add custom integrations path for logger
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'custom_integrations'))
from logger_config import setup_logger

# Configure logging using custom logger
logger = setup_logger()


class APIAuditService:
    """Service class for API audit logging operations"""
    
    def __init__(self):
        self.db = DatabaseConnection()
        self._ensure_schema()

    def _ensure_schema(self):
        """Ensure request_audit_log.timestamp stores timezone-aware UTC values."""
        migration_sql = """
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1
                FROM information_schema.columns
                WHERE table_schema = 'public'
                  AND table_name = 'request_audit_log'
                  AND column_name = 'timestamp'
                  AND data_type = 'timestamp without time zone'
            ) THEN
                ALTER TABLE request_audit_log
                ALTER COLUMN timestamp TYPE TIMESTAMP WITH TIME ZONE
                USING timestamp AT TIME ZONE 'UTC';
            END IF;
        END $$;
        """

        try:
            with DatabaseConnection() as db:
                db.execute_insert(migration_sql)
        except Exception as e:
            logger.error(f"Error migrating request_audit_log.timestamp to TIMESTAMPTZ: {e}")
    
    def get_api_audit_logs(
        self,
        credential_id: Optional[int] = None,
        key_name: Optional[str] = None,
        endpoint_filter: Optional[str] = None,
        method_filter: Optional[str] = None,
        success_filter: Optional[bool] = None,
        limit: int = 100,
        offset: int = 0,
        days_back: Optional[int] = 30
    ) -> List[Dict[str, Any]]:
        """
        Retrieve API audit logs from request_audit_log table
        
        Args:
            credential_id: Filter by specific credential ID
            key_name: Filter by API key name
            endpoint_filter: Filter by endpoint path (partial match)
            method_filter: Filter by HTTP method
            success_filter: Filter by success status
            limit: Maximum number of records to return
            offset: Number of records to skip
            days_back: Number of days to look back
            
        Returns:
            List of API audit log records
        """
        
        # Build the WHERE clause
        where_conditions = []
        params = []
        
        if days_back is not None:
            where_conditions.append("timestamp >= NOW() - INTERVAL '%s days'")
            params.append(days_back)
        
        if credential_id is not None:
            where_conditions.append("credential_id = %s")
            params.append(credential_id)
        
        if key_name:
            where_conditions.append("key_name ILIKE %s")
            params.append(f"%{key_name}%")
        
        if endpoint_filter:
            where_conditions.append("endpoint_path ILIKE %s")
            params.append(f"%{endpoint_filter}%")
        
        if method_filter:
            where_conditions.append("http_method = %s")
            params.append(method_filter.upper())
        
        if success_filter is not None:
            where_conditions.append("success = %s")
            params.append(success_filter)
        
        where_clause = "WHERE " + " AND ".join(where_conditions) if where_conditions else ""
        
        query = f"""
            SELECT 
                id, credential_id, key_name, action, client_ip, user_agent,
                timestamp, response_code, success, endpoint_path, http_method,
                request_summary, request_data
            FROM request_audit_log
            {where_clause}
            ORDER BY timestamp DESC
            LIMIT %s OFFSET %s
        """
        
        params.extend([limit, offset])
        
        try:
            with DatabaseConnection() as db:
                results = db.execute_query(query, params)
                if results:
                    api_logs = []
                    for row in results:
                        log_entry = {
                            'id': row['id'],
                            'credential_id': row['credential_id'],
                            'key_name': row['key_name'],
                            'action': row['action'],
                            'client_ip': str(row['client_ip']) if row['client_ip'] else None,
                            'user_agent': row['user_agent'],
                            'timestamp': serialize_timestamp(row['timestamp']),
                            'response_code': row['response_code'],
                            'success': row['success'],
                            'endpoint_path': row['endpoint_path'],
                            'http_method': row['http_method'],
                            'request_summary': row['request_summary'],
                            'request_data': row['request_data'] if row['request_data'] else None
                        }
                        api_logs.append(log_entry)
                    
                    logger.info(f"Retrieved {len(api_logs)} API audit logs")
                    return api_logs
                else:
                    logger.info("No API audit logs found")
                    return []
                    
        except Exception as e:
            logger.error(f"Error retrieving API audit logs: {e}")
            return []
    
    def get_api_audit_logs_count(
        self,
        credential_id: Optional[int] = None,
        key_name: Optional[str] = None,
        endpoint_filter: Optional[str] = None,
        method_filter: Optional[str] = None,
        success_filter: Optional[bool] = None,
        days_back: Optional[int] = 30
    ) -> int:
        """
        Get count of API audit logs matching the filters
        
        Returns:
            Total count of matching records
        """
        
        # Build the WHERE clause (same logic as get_api_audit_logs)
        where_conditions = []
        params = []
        
        if days_back is not None:
            where_conditions.append("timestamp >= NOW() - INTERVAL '%s days'")
            params.append(days_back)
        
        if credential_id is not None:
            where_conditions.append("credential_id = %s")
            params.append(credential_id)
        
        if key_name:
            where_conditions.append("key_name ILIKE %s")
            params.append(f"%{key_name}%")
        
        if endpoint_filter:
            where_conditions.append("endpoint_path ILIKE %s")
            params.append(f"%{endpoint_filter}%")
        
        if method_filter:
            where_conditions.append("http_method = %s")
            params.append(method_filter.upper())
        
        if success_filter is not None:
            where_conditions.append("success = %s")
            params.append(success_filter)
        
        where_clause = "WHERE " + " AND ".join(where_conditions) if where_conditions else ""
        
        query = f"""
            SELECT COUNT(*) as total
            FROM request_audit_log
            {where_clause}
        """
        
        try:
            with DatabaseConnection() as db:
                results = db.execute_query(query, params)
                if results and len(results) > 0:
                    return results[0]['total']
                return 0
                
        except Exception as e:
            logger.error(f"Error getting API audit logs count: {e}")
            return 0
    
    def get_api_audit_stats(self, days_back: int = 30) -> Dict[str, Any]:
        """
        Get API audit statistics
        
        Args:
            days_back: Number of days to look back
            
        Returns:
            Dictionary with statistics
        """
        
        try:
            with DatabaseConnection() as db:
                # Get overall stats
                stats_query = """
                    SELECT 
                        COUNT(*) as total_requests,
                        COUNT(CASE WHEN success = true THEN 1 END) as successful_requests,
                        COUNT(CASE WHEN success = false THEN 1 END) as failed_requests,
                        COUNT(DISTINCT credential_id) as unique_credentials,
                        COUNT(DISTINCT key_name) as unique_keys,
                        COUNT(DISTINCT client_ip) as unique_ips,
                        COUNT(DISTINCT endpoint_path) as unique_endpoints
                    FROM request_audit_log 
                    WHERE timestamp >= NOW() - INTERVAL '%s days'
                """
                
                stats_results = db.execute_query(stats_query, [days_back])
                stats = stats_results[0] if stats_results else {}
                
                # Get breakdown by HTTP method
                method_query = """
                    SELECT http_method, COUNT(*) as count
                    FROM request_audit_log 
                    WHERE timestamp >= NOW() - INTERVAL '%s days'
                    GROUP BY http_method
                    ORDER BY count DESC
                """
                
                method_results = db.execute_query(method_query, [days_back])
                methods_breakdown = {row['http_method']: row['count'] for row in method_results} if method_results else {}
                
                # Get breakdown by endpoint
                endpoint_query = """
                    SELECT endpoint_path, COUNT(*) as count
                    FROM request_audit_log 
                    WHERE timestamp >= NOW() - INTERVAL '%s days'
                    GROUP BY endpoint_path
                    ORDER BY count DESC
                    LIMIT 10
                """
                
                endpoint_results = db.execute_query(endpoint_query, [days_back])
                endpoints_breakdown = {row['endpoint_path']: row['count'] for row in endpoint_results} if endpoint_results else {}
                
                # Get breakdown by key name
                key_query = """
                    SELECT key_name, COUNT(*) as count
                    FROM request_audit_log 
                    WHERE timestamp >= NOW() - INTERVAL '%s days' AND key_name IS NOT NULL
                    GROUP BY key_name
                    ORDER BY count DESC
                    LIMIT 10
                """
                
                key_results = db.execute_query(key_query, [days_back])
                keys_breakdown = {row['key_name']: row['count'] for row in key_results} if key_results else {}
                
                # Calculate success rate
                total_requests = stats.get('total_requests', 0)
                successful_requests = stats.get('successful_requests', 0)
                success_rate = (successful_requests / total_requests * 100) if total_requests > 0 else 0
                
                return {
                    'total_requests': total_requests,
                    'successful_requests': successful_requests,
                    'failed_requests': stats.get('failed_requests', 0),
                    'success_rate': round(success_rate, 2),
                    'unique_credentials': stats.get('unique_credentials', 0),
                    'unique_keys': stats.get('unique_keys', 0),
                    'unique_ips': stats.get('unique_ips', 0),
                    'unique_endpoints': stats.get('unique_endpoints', 0),
                    'methods_breakdown': methods_breakdown,
                    'endpoints_breakdown': endpoints_breakdown,
                    'keys_breakdown': keys_breakdown
                }
                
        except Exception as e:
            logger.error(f"Error getting API audit stats: {e}")
            return {
                'total_requests': 0,
                'successful_requests': 0,
                'failed_requests': 0,
                'success_rate': 0,
                'unique_credentials': 0,
                'unique_keys': 0,
                'unique_ips': 0,
                'unique_endpoints': 0,
                'methods_breakdown': {},
                'endpoints_breakdown': {},
                'keys_breakdown': {}
            }


# Global instance
api_audit_service = APIAuditService()
