import hashlib
import json
import logging
from datetime import datetime
from typing import Optional, Dict, Any, List
import psycopg2
import psycopg2.extras
from config.settings import get_config, get_db_connection

logger = logging.getLogger(__name__)

class AuditLogger:
    """Handles audit logging for API requests"""
    
    def __init__(self, database_url: str = None):
        self.config = get_config()
        self.database_url = database_url or self.config.DATABASE_URL
    
    def _get_db_connection(self):
        """Get database connection"""
        return get_db_connection()
    
    def log_request(self, credential_id: Optional[int], endpoint_path: str, 
                   http_method: str, client_ip: str, user_agent: str = None,
                   success: bool = True, response_code: int = 200,
                   action: str = None, request_data: Dict[str, Any] = None,
                   key_name: str = None):
        """
        Log an API request to the audit trail
        
        Args:
            credential_id: ID of the API credential used (None for unauthenticated requests)
            endpoint_path: The API endpoint path
            http_method: HTTP method (GET, POST, DELETE, etc.)
            client_ip: Client IP address
            user_agent: User agent string
            success: Whether the request was successful
            response_code: HTTP response code
            action: Custom action description
            request_data: Request payload data (will be sanitized)
            key_name: Name of the API key used (for easier identification)
        """
        try:
            # Convert invalid/spoofed IPs to NULL for PostgreSQL INET column
            client_ip_for_db: Optional[str]
            if not client_ip or client_ip.lower() == "unknown":
                client_ip_for_db = None
            else:
                try:
                    import ipaddress as _ipaddress
                    _ipaddress.ip_address(client_ip)
                    client_ip_for_db = client_ip
                except (ValueError, AttributeError):
                    client_ip_for_db = None

            # Generate request hash for deduplication/tracking
            request_hash = self._generate_request_hash(
                credential_id, endpoint_path, http_method, client_ip
            )
            
            # Create request summary
            request_summary = self._create_request_summary(
                endpoint_path, http_method, success, response_code
            )
            
            # Sanitize request data (remove sensitive information)
            sanitized_data = self._sanitize_request_data(request_data) if request_data else None
            
            with self._get_db_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        INSERT INTO request_audit_log 
                        (credential_id, key_name, action, client_ip, user_agent, request_data,
                         response_code, success, endpoint_path, http_method, 
                         request_hash, request_summary)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """, (
                        credential_id, key_name, action, client_ip_for_db, user_agent, 
                        json.dumps(sanitized_data) if sanitized_data else None,
                        response_code, success, endpoint_path, http_method,
                        request_hash, request_summary
                    ))
                    conn.commit()


        except Exception as e:
            logger.error(f"Error logging API request: {str(e)}")
            # Don't raise exception to avoid breaking the main request flow
    
    def _generate_request_hash(self, credential_id: Optional[int], endpoint_path: str,
                              http_method: str, client_ip: str) -> str:
        """Generate a hash for the request for tracking purposes"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")  # Minute precision
        hash_input = f"{credential_id}:{endpoint_path}:{http_method}:{client_ip}:{timestamp}"
        return hashlib.md5(hash_input.encode()).hexdigest()[:16]
    
    def _create_request_summary(self, endpoint_path: str, http_method: str,
                               success: bool, response_code: int) -> str:
        """Create a human-readable summary of the request"""
        status = "SUCCESS" if success else "FAILED"
        return f"{http_method} {endpoint_path} - {status} ({response_code})"
    
    def _sanitize_request_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Remove sensitive information from request data before logging
        
        Args:
            data: Original request data
            
        Returns:
            Sanitized data with sensitive fields removed or masked
        """
        if not isinstance(data, dict):
            return {}
        
        # List of sensitive field names to remove or mask
        sensitive_fields = {
            'password', 'passwd', 'pwd', 'secret', 'token', 'key', 'api_key',
            'authorization', 'auth', 'credential', 'private_key', 'cert',
            'certificate', 'hash', 'signature'
        }
        
        sanitized = {}
        for key, value in data.items():
            key_lower = key.lower()
            
            # Check if field is sensitive
            if any(sensitive in key_lower for sensitive in sensitive_fields):
                sanitized[key] = "[REDACTED]"
            elif isinstance(value, dict):
                # Recursively sanitize nested dictionaries
                sanitized[key] = self._sanitize_request_data(value)
            elif isinstance(value, list):
                # Handle lists (sanitize each item if it's a dict)
                sanitized[key] = [
                    self._sanitize_request_data(item) if isinstance(item, dict) else item
                    for item in value
                ]
            else:
                sanitized[key] = value
        
        return sanitized
    
    def get_audit_logs(self, credential_id: Optional[int] = None, 
                      start_date: Optional[datetime] = None,
                      end_date: Optional[datetime] = None,
                      limit: int = 100, offset: int = 0) -> List[Dict]:
        """
        Retrieve audit logs with optional filtering
        
        Args:
            credential_id: Filter by specific credential ID
            start_date: Filter logs after this date
            end_date: Filter logs before this date
            limit: Maximum number of records to return
            offset: Number of records to skip
            
        Returns:
            List of audit log records
        """
        try:
            with self._get_db_connection() as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                    # Build WHERE clause
                    where_conditions = []
                    params = []
                    
                    if credential_id is not None:
                        where_conditions.append("credential_id = %s")
                        params.append(credential_id)
                    
                    if start_date:
                        where_conditions.append("timestamp >= %s")
                        params.append(start_date)
                    
                    if end_date:
                        where_conditions.append("timestamp <= %s")
                        params.append(end_date)
                    
                    where_clause = "WHERE " + " AND ".join(where_conditions) if where_conditions else ""
                    
                    # Add limit and offset
                    params.extend([limit, offset])
                    
                    query = f"""
                        SELECT id, credential_id, key_name, action, client_ip, user_agent,
                               timestamp, response_code, success, endpoint_path,
                               http_method, request_summary
                        FROM request_audit_log
                        {where_clause}
                        ORDER BY timestamp DESC
                        LIMIT %s OFFSET %s
                    """
                    
                    cursor.execute(query, params)
                    return [dict(row) for row in cursor.fetchall()]
                    
        except Exception as e:
            logger.error(f"Error retrieving audit logs: {str(e)}")
            return []
    
    def get_audit_stats(self, credential_id: Optional[int] = None,
                       days: int = 30) -> Dict[str, Any]:
        """
        Get audit statistics for a credential or overall
        
        Args:
            credential_id: Specific credential ID (None for overall stats)
            days: Number of days to look back
            
        Returns:
            Dictionary with statistics
        """
        try:
            with self._get_db_connection() as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                    if credential_id is not None:
                        cursor.execute("""
                            SELECT
                                COUNT(*) as total_requests,
                                COUNT(CASE WHEN success = true THEN 1 END) as successful_requests,
                                COUNT(CASE WHEN success = false THEN 1 END) as failed_requests,
                                COUNT(DISTINCT credential_id) as unique_credentials,
                                COUNT(DISTINCT client_ip) as unique_ips,
                                COUNT(DISTINCT endpoint_path) as unique_endpoints
                            FROM request_audit_log
                            WHERE timestamp > NOW() - INTERVAL '1 day' * %s
                            AND credential_id = %s
                        """, (days, credential_id))
                    else:
                        cursor.execute("""
                            SELECT
                                COUNT(*) as total_requests,
                                COUNT(CASE WHEN success = true THEN 1 END) as successful_requests,
                                COUNT(CASE WHEN success = false THEN 1 END) as failed_requests,
                                COUNT(DISTINCT credential_id) as unique_credentials,
                                COUNT(DISTINCT client_ip) as unique_ips,
                                COUNT(DISTINCT endpoint_path) as unique_endpoints
                            FROM request_audit_log
                            WHERE timestamp > NOW() - INTERVAL '1 day' * %s
                        """, (days,))
                    
                    stats = dict(cursor.fetchone())
                    
                    # Calculate success rate
                    if stats['total_requests'] > 0:
                        stats['success_rate'] = (stats['successful_requests'] / stats['total_requests']) * 100
                    else:
                        stats['success_rate'] = 0
                    
                    return stats
                    
        except Exception as e:
            logger.error(f"Error getting audit stats: {str(e)}")
            return {}
    
    def cleanup_old_logs(self, retention_days: int = None) -> int:
        """
        Clean up old audit logs beyond retention period
        
        Args:
            retention_days: Number of days to retain (uses config default if None)
            
        Returns:
            Number of records deleted
        """
        if retention_days is None:
            retention_days = self.config.AUDIT_LOG_RETENTION_DAYS
        
        try:
            with self._get_db_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        DELETE FROM request_audit_log 
                        WHERE timestamp < NOW() - INTERVAL '%s days'
                    """, (retention_days,))
                    
                    deleted_count = cursor.rowcount
                    conn.commit()
                    
                    logger.info(f"Cleaned up {deleted_count} old audit log records")
                    return deleted_count
                    
        except Exception as e:
            logger.error(f"Error cleaning up audit logs: {str(e)}")
            return 0 