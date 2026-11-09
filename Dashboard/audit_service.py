"""
Audit Service for logging user actions in the dashboard
"""

from db_config import DatabaseConnection
import ipaddress
import logging
from datetime import datetime
import json
import sys
import os
from typing import Optional, Dict, Any, List
from datetime_utils import serialize_timestamp

# Add custom integrations path for logger
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'custom_integrations'))
from logger_config import setup_logger

# Configure logging using custom logger
logger = setup_logger()


def _sanitize_ip(value: Optional[str]) -> Optional[str]:
    """
    Return `value` only if it is a real IP address, else None.

    audit_logs.ip_address is INET, so an unparseable value makes the whole
    INSERT fail and the action goes unrecorded. Since the candidate IP can come
    from a client-supplied X-Forwarded-For header, a junk value would otherwise
    be a way to suppress your own audit row. Losing the IP is acceptable;
    losing the record of who did what is not.
    """
    if not value:
        return None
    candidate = str(value).strip()
    if not candidate:
        return None
    # Strip a port suffix ("1.2.3.4:5678"), which proxies sometimes append.
    if candidate.count(":") == 1 and "." in candidate:
        candidate = candidate.split(":", 1)[0]
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        logger.debug("Discarding unparseable audit IP address: %r", value)
        return None


class AuditService:
    """Service class for audit logging operations"""

    @staticmethod
    def _vendor_delete_row_includes_slack_context(details: Optional[Dict[str, Any]]) -> bool:
        """
        True when a vendor DELETE log row has enough context for a single useful Slack alert.

        Manual dashboard logs (after DELETE /api/vendors/{id}) set action_type and vendor_name;
        automatic middleware rows did not, which produced a second 'Unknown Vendor' message.
        """
        if not isinstance(details, dict):
            return False
        if details.get("action_type") == "delete_vendor":
            return True
        return bool((details.get("vendor_name") or "").strip())

    def __init__(self):
        self.db = DatabaseConnection()
        self._ensure_table_exists()
    
    def _ensure_table_exists(self):
        """Ensure the audit_logs table exists"""
        create_table_sql = """
        CREATE TABLE IF NOT EXISTS audit_logs (
            id SERIAL PRIMARY KEY,
            user_id TEXT NOT NULL,
            user_name TEXT,
            user_email TEXT NOT NULL,
            user_role TEXT,
            action TEXT NOT NULL,
            resource_type TEXT,
            resource_id TEXT,
            details JSONB,
            ip_address INET,
            user_agent TEXT,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
        
        -- Create indexes if they don't exist
        CREATE INDEX IF NOT EXISTS idx_audit_logs_user_email ON audit_logs(user_email);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_resource_type ON audit_logs(resource_type);
        """
        
        try:
            with DatabaseConnection() as db:
                success = db.execute_insert(create_table_sql)
                if success:
                    logger.info(" audit_logs table verified/created successfully")
                else:
                    logger.warning(" Could not verify audit_logs table creation")
        except Exception as e:
            logger.error(f" Error ensuring audit_logs table exists: {e}")
    
    def log_action(
        self,
        user_id: str,
        user_email: str,
        action: str,
        user_name: Optional[str] = None,
        user_role: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> bool:
        """
        Log a user action to the audit trail
        
        Args:
            user_id: User ID from authentication system
            user_email: Email address of the user
            action: Action performed (e.g., CREATE, UPDATE, DELETE, VIEW, SCAN)
            user_name: Display name of the user
            user_role: Role of the user (admin/user)
            resource_type: Type of resource affected (e.g., vendor, scan, subdomain)
            resource_id: ID or identifier of the affected resource
            details: Additional details about the action
            ip_address: IP address of the user
            user_agent: User agent string from the browser
        
        Returns:
            bool: True if logged successfully, False otherwise
        """
        
        insert_query = """
        INSERT INTO audit_logs (
            user_id, user_name, user_email, user_role, action,
            resource_type, resource_id, details, ip_address, user_agent
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        
        try:
            # Convert details to JSON string if provided
            details_json = json.dumps(details) if details else None
            
            params = (
                user_id,
                user_name,
                user_email,
                user_role,
                action,
                resource_type,
                resource_id,
                details_json,
                _sanitize_ip(ip_address),
                user_agent
            )
            
            with DatabaseConnection() as db:
                success = db.execute_insert(insert_query, params)
                if success:
                    logger.info(f" Audit log recorded: {user_email} performed {action}")

                    # Send Slack notification for critical audit actions
                    api_key_actions = ['CREATE', 'DELETE', 'ACTIVATED', 'REVOKED']
                    is_vendor_deletion = action.upper() == 'DELETE' and resource_type and resource_type.lower() in ['vendor', 'vendors']
                    is_api_key_action = action.upper() in api_key_actions and resource_type and resource_type.lower() in ['api_key', 'api key', 'apikey']
                    # Only Slack vendor deletes that include a real name (from manual /api/audit-logs/log).
                    # Generic middleware rows only had endpoint/method → duplicate "Unknown Vendor" alerts.
                    vendor_delete_slack = is_vendor_deletion and AuditService._vendor_delete_row_includes_slack_context(
                        details
                    )

                    if vendor_delete_slack or is_api_key_action:
                        try:
                            # First get the audit log ID that was just inserted
                            # We need to get the latest audit log for this user/action to check slack_alert_sent_at
                            audit_id_query = """
                            SELECT id, slack_alert_sent_at FROM audit_logs
                            WHERE user_email = %s AND action = %s AND created_at >= NOW() - INTERVAL '1 minute'
                            ORDER BY created_at DESC LIMIT 1
                            """
                            audit_result = db.execute_single_query(audit_id_query, (user_email, action))

                            if audit_result and audit_result['slack_alert_sent_at'] is None:
                                # Import Slack notification functions
                                import sys
                                import os
                                sys.path.append(os.path.dirname(__file__))

                                if is_api_key_action:
                                    # Handle API key actions
                                    from slack.slack_service import send_api_key_alert

                                    # Extract API key name from details
                                    api_key_name = 'Unknown'
                                    if details and isinstance(details, dict):
                                        api_key_name = details.get('api_key_name', 'Unknown')

                                    slack_success = send_api_key_alert(
                                        action=action,
                                        api_key_name=api_key_name,
                                        user_email=user_email,
                                        timestamp=str(datetime.now())
                                    )
                                else:
                                    # Handle vendor deletions (existing logic)
                                    from slack.slack_service import send_audit_log_alert

                                    audit_data = {
                                        'id': audit_result['id'],
                                        'user_id': user_id,
                                        'user_name': user_name or 'Unknown',
                                        'user_email': user_email,
                                        'user_role': user_role or 'User',
                                        'action': action,
                                        'resource_type': resource_type,
                                        'resource_id': resource_id,
                                        'details': details,
                                        'ip_address': ip_address,
                                        'user_agent': user_agent,
                                        'created_at': datetime.now()
                                    }

                                    slack_success = send_audit_log_alert(audit_data)

                                if slack_success:
                                    # Mark alert as sent
                                    update_alert_query = "UPDATE audit_logs SET slack_alert_sent_at = NOW() WHERE id = %s"
                                    db.execute_insert(update_alert_query, (audit_result['id'],))
                                    logger.info(f"Slack notification sent for audit log: {user_email} performed {action}")
                                else:
                                    logger.warning(f"Failed to send Slack notification for audit log: {user_email} performed {action}")
                            else:
                                logger.debug(f"Slack alert already sent for audit log {user_email} {action}")

                        except Exception as slack_error:
                            logger.error(f"Error sending Slack notification for audit log {user_email} {action}: {slack_error}")
                            # Don't fail the audit log if Slack notification fails

                    return True
                else:
                    logger.error(f" Failed to record audit log for {user_email}")
                    return False
                    
        except Exception as e:
            logger.error(f" Error recording audit log: {e}")
            return False
    
    def get_user_audit_logs(
        self,
        user_email: Optional[str] = None,
        user_name: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        action_filter: Optional[str] = None,
        resource_type_filter: Optional[str] = None,
        days_back: Optional[int] = 30
    ) -> List[Dict[str, Any]]:
        """
        Retrieve audit logs with optional filtering
        
        Args:
            user_email: Filter by specific user email (None for all users)
            user_name: Filter by specific user name (None for all users)
            limit: Maximum number of logs to return
            offset: Number of logs to skip (for pagination)
            action_filter: Filter by specific action
            resource_type_filter: Filter by specific resource type
            days_back: Number of days back to retrieve logs (None for all)
        
        Returns:
            List of audit log dictionaries
        """
        
        # Build the query with optional filters
        query = """
        SELECT 
            id, user_id, user_name, user_email, user_role, action,
            resource_type, resource_id, details, ip_address, user_agent, created_at
        FROM audit_logs
        WHERE 1=1
        """
        params = []
        
        if user_email:
            query += " AND user_email = %s"
            params.append(user_email)
        
        if user_name:
            query += " AND user_name ILIKE %s"
            params.append(f"%{user_name}%")
        
        if action_filter:
            query += " AND action = %s"
            params.append(action_filter)
        
        if resource_type_filter:
            query += " AND resource_type = %s"
            params.append(resource_type_filter)
        
        if days_back:
            query += " AND created_at >= NOW() - INTERVAL %s"
            params.append(f"{days_back} days")
        
        query += " ORDER BY created_at DESC LIMIT %s OFFSET %s"
        params.extend([limit, offset])
        
        try:
            with DatabaseConnection() as db:
                results = db.execute_query(query, params)
                if results:
                    audit_logs = []
                    for row in results:
                        log_entry = {
                            'id': row['id'],
                            'user_id': row['user_id'],
                            'user_name': row['user_name'],
                            'user_email': row['user_email'],
                            'user_role': row['user_role'],
                            'action': row['action'],
                            'resource_type': row['resource_type'],
                            'resource_id': row['resource_id'],
                            'details': row['details'] if row['details'] else None,
                            'ip_address': str(row['ip_address']) if row['ip_address'] else None,
                            'user_agent': row['user_agent'],
                            'created_at': serialize_timestamp(row['created_at'])
                        }
                        audit_logs.append(log_entry)
                    
                    logger.info(f" Retrieved {len(audit_logs)} audit logs")
                    return audit_logs
                else:
                    logger.info("ℹ No audit logs found")
                    return []
                    
        except Exception as e:
            logger.error(f"Error retrieving audit logs: {e}")
            return []
    
    def get_audit_logs_count(
        self,
        user_email: Optional[str] = None,
        user_name: Optional[str] = None,
        action_filter: Optional[str] = None,
        resource_type_filter: Optional[str] = None,
        days_back: Optional[int] = 30
    ) -> int:
        """
        Get total count of audit logs matching filters
        
        Returns:
            Total count of matching audit logs
        """
        
        query = "SELECT COUNT(*) as count FROM audit_logs WHERE 1=1"
        params = []
        
        if user_email:
            query += " AND user_email = %s"
            params.append(user_email)
        
        if user_name:
            query += " AND user_name ILIKE %s"
            params.append(f"%{user_name}%")
        
        if action_filter:
            query += " AND action = %s"
            params.append(action_filter)
        
        if resource_type_filter:
            query += " AND resource_type = %s"
            params.append(resource_type_filter)
        
        if days_back:
            query += " AND created_at >= NOW() - INTERVAL %s"
            params.append(f"{days_back} days")
        
        try:
            with DatabaseConnection() as db:
                result = db.execute_single_query(query, params)
                return result['count'] if result else 0
                
        except Exception as e:
            logger.error(f"Error getting audit logs count: {e}")
            return 0
    
    def get_audit_stats(self, days_back: int = 30) -> Dict[str, Any]:
        """
        Get audit statistics for the dashboard
        
        Args:
            days_back: Number of days back to analyze
        
        Returns:
            Dictionary with audit statistics
        """
        
        try:
            with DatabaseConnection() as db:
                # Total actions in the period
                total_query = """
                SELECT COUNT(*) as total_actions
                FROM audit_logs 
                WHERE created_at >= NOW() - INTERVAL %s
                """
                total_result = db.execute_single_query(total_query, (f"{days_back} days",))
                total_actions = total_result['total_actions'] if total_result else 0
                
                # Actions by type
                actions_query = """
                SELECT action, COUNT(*) as count
                FROM audit_logs 
                WHERE created_at >= NOW() - INTERVAL %s
                GROUP BY action
                ORDER BY count DESC
                """
                actions_results = db.execute_query(actions_query, (f"{days_back} days",))
                actions_breakdown = {row['action']: row['count'] for row in actions_results} if actions_results else {}
                
                # Most active users
                users_query = """
                SELECT user_email, user_name, COUNT(*) as action_count
                FROM audit_logs 
                WHERE created_at >= NOW() - INTERVAL %s
                GROUP BY user_email, user_name
                ORDER BY action_count DESC
                LIMIT 10
                """
                users_results = db.execute_query(users_query, (f"{days_back} days",))
                top_users = [
                    {
                        'email': row['user_email'],
                        'name': row['user_name'],
                        'action_count': row['action_count']
                    }
                    for row in users_results
                ] if users_results else []
                
                return {
                    'total_actions': total_actions,
                    'actions_breakdown': actions_breakdown,
                    'top_users': top_users,
                    'period_days': days_back
                }
                
        except Exception as e:
            logger.error(f"Error getting audit stats: {e}")
            return {
                'total_actions': 0,
                'actions_breakdown': {},
                'top_users': [],
                'period_days': days_back
            }


# Global audit service instance
audit_service = AuditService()


def _client_ip(request: Any) -> Optional[str]:
    """
    Caller IP, preferring the proxy-forwarded address. None if unparseable.

    CF-Connecting-IP comes first: the Cloudflare edge overwrites it with the
    real client, whereas the leftmost X-Forwarded-For entry is whatever the
    client sent. The frontend forwards both (clientIpProxyHeaders).
    """
    try:
        cf_ip = _sanitize_ip(request.headers.get("CF-Connecting-IP"))
        if cf_ip:
            return cf_ip
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            candidate = _sanitize_ip(forwarded.split(",")[0])
            if candidate:
                return candidate
        if request.client:
            return _sanitize_ip(request.client.host)
    except Exception:
        pass
    return None


def log_request_action(
    request: Any,
    *,
    action: str,
    resource_type: str,
    resource_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> bool:
    """
    Record a state change from inside the route that performs it.

    Audit rows are written by the specific create/update/delete function rather
    than by request middleware, because only the handler knows *what* changed --
    the role that was renamed, the members added, the vendors removed. A
    middleware sees the URL and nothing else, which produced rows like
    "Updated / Access role 1" that carried no information.

    `request` is a Starlette/FastAPI Request; identity comes from the X-User-*
    headers the dashboard sets. Never raises: a failed audit write must not fail
    the user's action.
    """
    try:
        user_email = (request.headers.get("X-User-Email") or "").strip()
        if not user_email:
            logger.warning("Skipping audit row for %s %s: no X-User-Email header", action, resource_type)
            return False
        return audit_service.log_action(
            user_id=request.headers.get("X-User-ID") or "unknown",
            user_email=user_email,
            action=action,
            user_name=request.headers.get("X-User-Name"),
            user_role=request.headers.get("X-User-Role"),
            resource_type=resource_type,
            resource_id=str(resource_id)[:500] if resource_id else None,
            details=details or {},
            ip_address=_client_ip(request),
            user_agent=request.headers.get("User-Agent"),
        )
    except Exception as e:
        logger.error("Audit log failed for %s %s: %s", action, resource_type, e)
        return False


def log_user_action(
    user_id: str,
    user_email: str,
    action: str,
    user_name: Optional[str] = None,
    user_role: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None
) -> bool:
    """
    Convenience function to log user actions
    """
    return audit_service.log_action(
        user_id=user_id,
        user_email=user_email,
        action=action,
        user_name=user_name,
        user_role=user_role,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details,
        ip_address=ip_address,
        user_agent=user_agent
    )
