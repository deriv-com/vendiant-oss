import secrets
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Tuple, Any
import psycopg2
import psycopg2.extras
import logging
from config.settings import get_config, get_db_connection

logger = logging.getLogger(__name__)

WEBHOOK_SCOPE = "webhook"

VALID_SCOPES = {
    "vendors:list":   "List all vendors",
    "vendors:read":   "Read vendor domain scores",
    "reports:read":   "Read domain reports",
    "vendors:add":    "Add new vendors",
    "vendors:delete": "Delete vendors",
    "scans:run":      "Trigger full domain scans",
    WEBHOOK_SCOPE:    "Breach Monitor Webhook Callbacks only",
}

READ_ONLY_SCOPES = ["vendors:list", "vendors:read", "reports:read"]
# Admin wildcard (*) does not include webhook — that scope is issued only as a dedicated key.
ADMIN_SCOPES = [k for k in VALID_SCOPES if k != WEBHOOK_SCOPE]
WEBHOOK_ONLY_SCOPES = [WEBHOOK_SCOPE]


def validate_finegrained_scopes(scopes: List[str]) -> None:
    """Enforce scope rules for fine-grained API keys."""
    if WEBHOOK_SCOPE in scopes and scopes != WEBHOOK_ONLY_SCOPES:
        raise ValueError(
            f"The '{WEBHOOK_SCOPE}' scope must be the only scope on a key "
            "(it cannot be combined with other permissions)"
        )


def is_webhook_only_scopes(scopes: List[str]) -> bool:
    return scopes == WEBHOOK_ONLY_SCOPES


def resolve_scopes(credential: dict) -> List[str]:
    """Return the effective scope list for a validated credential dict."""
    group = credential.get("group_name", "read_only")
    if group == "admin":
        return ["*"]
    if group == "finegrained":
        scopes = credential.get("finegrained_scopes") or []
        if isinstance(scopes, list):
            return scopes
        # JSONB may deserialise as a list already; guard against dict
        return []
    # read_only and any unknown group
    return READ_ONLY_SCOPES


class APIKeyManager:
    """Manages API key generation, validation, and lifecycle"""
    
    def __init__(self, database_url: str = None):
        self.config = get_config()
        self.database_url = database_url or self.config.DATABASE_URL
        # Initialize Argon2 password hasher with secure defaults
        self.ph = PasswordHasher(
            time_cost=3,      # Number of iterations
            memory_cost=65536, # Memory usage in KiB (64 MB)
            parallelism=1,    # Number of parallel threads
            hash_len=32,      # Length of hash in bytes
            salt_len=16       # Length of salt in bytes
        )
        
    def _get_available_groups(self) -> List[Dict]:
        """Get available groups from database with descriptions"""
        try:
            with self._get_db_connection() as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                    cursor.execute("SELECT group_name, description FROM access_groups ORDER BY group_name;")
                    groups = [{'name': row['group_name'], 'description': row['description']} for row in cursor.fetchall()]
                    return groups if groups else [
                        {'name': 'read_only', 'description': 'Read-only access'},
                        {'name': 'admin', 'description': 'Full administrative access'}
                    ]  # fallback
        except Exception as e:
            logger.warning(f"Could not fetch groups from database: {e}")
            return [
                {'name': 'read_only', 'description': 'Read-only access'},
                {'name': 'admin', 'description': 'Full administrative access'}
            ]  # fallback
    
    def _get_rate_limit_for_credential(self, credential_id: int) -> tuple:
        """Get rate limit and scope for a credential
        
        Returns:
            tuple: (requests_per_minute, scope)
        """
        try:
            with self._get_db_connection() as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                    # Get credential group
                    cursor.execute("""
                        SELECT ac.group_name 
                        FROM api_credentials ac
                        WHERE ac.id = %s AND ac.group_name IS NOT NULL
                    """, (credential_id,))
                    
                    result = cursor.fetchone()
                    group_name = result['group_name'] if result else None
                    
                    # All groups use the same rate limit of 50 requests/minute
                    return 50, group_name or 'read_only'
                        
        except Exception as e:
            logger.error(f"Error getting rate limit for credential {credential_id}: {e}")
            return 50, 'read_only'  # fallback
        
    def _get_db_connection(self):
        """Get database connection"""
        return get_db_connection()
    
    def generate_api_key(self, name: str, description: str = None,
                        created_by: str = None, expires_days: int = None,
                        request_limit: int = None, group_name: str = None,
                        finegrained_scopes: List[str] = None) -> Tuple[str, str]:
        """
        Generate a new API key using cryptographically secure methods
        
        Returns:
            Tuple of (api_key, key_id) where api_key is the full key to give to user
        """
        # Generate cryptographically secure random key using secrets module
        # Using URL-safe base64 characters for better entropy
        random_part = secrets.token_urlsafe(self.config.API_KEY_LENGTH)[:self.config.API_KEY_LENGTH]
        full_key = f"{self.config.API_KEY_PREFIX}{random_part}"
        
        # Create Argon2 hash for secure storage
        key_hash = self.ph.hash(full_key)
        
        key_prefix = full_key[:15]  # Store first 15 chars for identification
        
        # Set expiration
        expires_at = None
        if expires_days is not None:
            # Explicit expiry days provided (including 0 for immediate expiry)
            expires_at = datetime.now() + timedelta(days=expires_days)
        # If expires_days is None, expires_at remains None (permanent key)
        
        # Set request limit
        if request_limit is None:
            request_limit = self.config.DEFAULT_RATE_LIMIT
            
        # Set default group if not provided
        if group_name is None:
            available_groups = self._get_available_groups()
            group_name = available_groups[0]['name'] if available_groups else 'read_only'

        # Validate and normalise finegrained_scopes
        if group_name == 'finegrained':
            if not finegrained_scopes:
                raise ValueError("finegrained_scopes must be a non-empty list when group_name is 'finegrained'")
            invalid = [s for s in finegrained_scopes if s not in VALID_SCOPES]
            if invalid:
                raise ValueError(f"Invalid scopes: {invalid}. Valid scopes: {list(VALID_SCOPES.keys())}")
            validate_finegrained_scopes(finegrained_scopes)
        else:
            finegrained_scopes = None

        try:
            with self._get_db_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        INSERT INTO api_credentials
                        (credential_hash, credential_prefix, name, description,
                         request_limit, created_by, expires_at, group_name,
                         finegrained_scopes, assigned_at, assigned_by, is_enabled)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        RETURNING id
                    """, (key_hash, key_prefix, name, description,
                          request_limit, created_by, expires_at, group_name,
                          psycopg2.extras.Json(finegrained_scopes) if finegrained_scopes else None,
                          datetime.now(), created_by, True))
                    
                    key_id = cursor.fetchone()[0]
                    conn.commit()
                    
                    logger.info(f"Generated API key {key_prefix}... for {name}")
                    return full_key, str(key_id)
                    
        except Exception as e:
            logger.error(f"Error generating API key: {str(e)}")
            raise
    
    def validate_api_key(self, api_key: str) -> Optional[Dict]:
        """
        Validate an API key using Argon2 verification and return credential info
        
        Returns:
            Dict with credential info if valid, None if invalid
        """
        if not api_key or not api_key.startswith(self.config.API_KEY_PREFIX):
            return None
        
        try:
            with self._get_db_connection() as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                    # Get the prefix to narrow down search
                    key_prefix = api_key[:15]
                    
                    cursor.execute("""
                        SELECT id, name, description, request_limit, is_enabled,
                               expires_at, last_accessed, group_name, finegrained_scopes, credential_hash
                        FROM api_credentials 
                        WHERE credential_prefix = %s AND is_enabled = true
                    """, (key_prefix,))
                    
                    credentials = cursor.fetchall()
                    
                    # Verify the API key against stored Argon2 hashes
                    credential = None
                    for cred in credentials:
                        try:
                            self.ph.verify(cred['credential_hash'], api_key)
                            credential = cred
                            break
                        except VerifyMismatchError:
                            continue
                    
                    if not credential:
                        return None
                    
                    # Check if expired
                    if credential['expires_at'] and credential['expires_at'] < datetime.now():
                        logger.warning(f"API key {api_key[:15]}... has expired")
                        return None
                    
                    # Update last accessed time
                    cursor.execute("""
                        UPDATE api_credentials 
                        SET last_accessed = CURRENT_TIMESTAMP 
                        WHERE id = %s
                    """, (credential['id'],))
                    conn.commit()
                    
                    return dict(credential)
                    
        except Exception as e:
            logger.error(f"Error validating API key: {str(e)}")
            return None
    
    def get_api_key_permissions(self, credential_id: int) -> List[str]:
        """Return effective scopes for a credential by id."""
        try:
            with self._get_db_connection() as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                    cursor.execute("""
                        SELECT group_name, finegrained_scopes
                        FROM api_credentials
                        WHERE id = %s
                    """, (credential_id,))
                    row = cursor.fetchone()
                    if not row:
                        return []
                    return resolve_scopes(dict(row))
        except Exception as e:
            logger.error(f"Error getting API key permissions: {str(e)}")
            return []
    
    def assign_group_to_key(self, credential_id: int, group_name: str, 
                           assigned_by: str = None) -> bool:
        """Assign a permission group to an API key"""
        try:
            with self._get_db_connection() as conn:
                with conn.cursor() as cursor:
                    # Check if group exists
                    cursor.execute("SELECT 1 FROM access_groups WHERE group_name = %s", (group_name,))
                    if not cursor.fetchone():
                        logger.error(f"Access group {group_name} does not exist")
                        return False
                    
                    # Assign group to credential by updating the api_credentials table
                    cursor.execute("""
                        UPDATE api_credentials 
                        SET group_name = %s, assigned_at = %s, assigned_by = %s
                        WHERE id = %s
                    """, (group_name, datetime.now(), assigned_by, credential_id))
                    
                    conn.commit()
                    logger.info(f"Assigned group {group_name} to credential {credential_id}")
                    return True
                    
        except Exception as e:
            logger.error(f"Error assigning group to API key: {str(e)}")
            return False
    
    def revoke_api_key(self, credential_id: int) -> bool:
        """Revoke (disable) an API key"""
        try:
            with self._get_db_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        UPDATE api_credentials 
                        SET is_enabled = false 
                        WHERE id = %s
                    """, (credential_id,))
                    
                    conn.commit()
                    logger.info(f"Revoked API key {credential_id}")
                    return True
                    
        except Exception as e:
            logger.error(f"Error revoking API key: {str(e)}")
            return False
    
    def unrevoke_api_key(self, credential_id: int) -> bool:
        """Unrevoke (re-enable) an API key"""
        try:
            with self._get_db_connection() as conn:
                with conn.cursor() as cursor:
                    # First check if the key exists and is currently disabled
                    cursor.execute("""
                        SELECT is_enabled, expires_at 
                        FROM api_credentials 
                        WHERE id = %s
                    """, (credential_id,))
                    
                    result = cursor.fetchone()
                    if not result:
                        logger.warning(f"API key {credential_id} not found")
                        return False
                    
                    is_enabled, expires_at = result
                    
                    # Check if key is already enabled
                    if is_enabled:
                        logger.warning(f"API key {credential_id} is already enabled")
                        return False
                    
                    # Check if key has expired
                    if expires_at and expires_at < datetime.now():
                        logger.warning(f"Cannot unrevoke expired API key {credential_id}")
                        return False
                    
                    # Re-enable the key
                    cursor.execute("""
                        UPDATE api_credentials 
                        SET is_enabled = true 
                        WHERE id = %s
                    """, (credential_id,))
                    
                    conn.commit()
                    logger.info(f"Unrevoked API key {credential_id}")
                    return True
                    
        except Exception as e:
            logger.error(f"Error unrevoking API key: {str(e)}")
            return False
    
    def update_api_key_permissions(self, credential_id: int, group_name: str,
                                    finegrained_scopes: List[str] = None,
                                    name: str = None, description: str = None,
                                    expires_at: Optional[datetime] = None,
                                    clear_expiry: bool = False) -> bool:
        """Update name, description, expiry, permission group, and/or scopes of an API key."""
        if group_name == 'finegrained':
            if not finegrained_scopes:
                raise ValueError("finegrained_scopes must be non-empty for finegrained group")
            invalid = [s for s in finegrained_scopes if s not in VALID_SCOPES]
            if invalid:
                raise ValueError(f"Invalid scopes: {invalid}")
            validate_finegrained_scopes(finegrained_scopes)
        else:
            finegrained_scopes = None

        try:
            with self._get_db_connection() as conn:
                with conn.cursor() as cursor:
                    # Build SET clause dynamically so None fields are skipped
                    sets = [
                        "group_name = %s",
                        "finegrained_scopes = %s",
                        "assigned_at = %s",
                    ]
                    values: list = [
                        group_name,
                        psycopg2.extras.Json(finegrained_scopes) if finegrained_scopes else None,
                        datetime.now(),
                    ]
                    if name is not None:
                        sets.append("name = %s")
                        values.append(name)
                    if description is not None:
                        sets.append("description = %s")
                        values.append(description)
                    if clear_expiry:
                        sets.append("expires_at = NULL")
                    elif expires_at is not None:
                        sets.append("expires_at = %s")
                        values.append(expires_at)

                    values.append(credential_id)
                    cursor.execute(
                        f"UPDATE api_credentials SET {', '.join(sets)} WHERE id = %s",
                        values,
                    )
                    if cursor.rowcount == 0:
                        return False
                    conn.commit()
                    logger.info(f"Updated API key {credential_id} → group={group_name}")
                    return True
        except Exception as e:
            logger.error(f"Error updating API key: {str(e)}")
            raise

    def delete_api_key(self, credential_id: int) -> bool:
        """Permanently delete an API key from the database"""
        try:
            with self._get_db_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("""
                        DELETE FROM api_credentials 
                        WHERE id = %s
                    """, (credential_id,))
                    
                    rows_deleted = cursor.rowcount
                    conn.commit()
                    
                    if rows_deleted > 0:
                        logger.info(f"Deleted API key {credential_id}")
                        return True
                    else:
                        logger.warning(f"API key {credential_id} not found for deletion")
                        return False
                    
        except Exception as e:
            logger.error(f"Error deleting API key: {str(e)}")
            return False
    
    def get_credential_groups(self, credential_id: int) -> List[Dict]:
        """Get groups assigned to a credential"""
        try:
            with self._get_db_connection() as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                    cursor.execute("""
                        SELECT ac.group_name, ag.description, ag.permissions
                        FROM api_credentials ac
                        JOIN access_groups ag ON ac.group_name = ag.group_name
                        WHERE ac.id = %s AND ac.group_name IS NOT NULL
                    """, (credential_id,))
                    
                    return [dict(row) for row in cursor.fetchall()]
                    
        except Exception as e:
            logger.error(f"Error getting credential groups: {str(e)}")
            return []

    def list_api_keys(self, include_disabled: bool = False) -> List[Dict]:
        """List all API keys (without the actual key values)"""
        try:
            with self._get_db_connection() as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                    if include_disabled:
                        cursor.execute("""
                            SELECT id, credential_hash, credential_prefix, name, description,
                                   request_limit, is_enabled, created_at,
                                   last_accessed, expires_at, created_by, group_name,
                                   finegrained_scopes
                            FROM api_credentials
                            ORDER BY created_at DESC
                        """)
                    else:
                        cursor.execute("""
                            SELECT id, credential_hash, credential_prefix, name, description,
                                   request_limit, is_enabled, created_at,
                                   last_accessed, expires_at, created_by, group_name,
                                   finegrained_scopes
                            FROM api_credentials
                            WHERE is_enabled = true
                            ORDER BY created_at DESC
                        """)
                    
                    return [dict(row) for row in cursor.fetchall()]
                    
        except Exception as e:
            logger.error(f"Error listing API keys: {str(e)}")
            return []
    
    def check_rate_limit(self, credential_id: int) -> bool:
        """
        Check if API key has exceeded rate limit based on scope
        
        Returns:
            bool: True if within limit, False if exceeded
        """
        try:
            # Get rate limit for this credential
            requests_per_minute, scope = self._get_rate_limit_for_credential(credential_id)
            window_minutes = 1
            
            with self._get_db_connection() as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                    
                    # Count requests in the last minute
                    cursor.execute("""
                        SELECT COUNT(*) as count FROM request_audit_log 
                        WHERE credential_id = %s 
                        AND timestamp > NOW() - INTERVAL '%s minutes'
                        AND response_code < 500
                    """, (credential_id, window_minutes))
                    
                    result = cursor.fetchone()
                    current_count = result['count'] if result else 0
                    
                    # Log rate limit check for debugging
                    logger.debug(f"Rate limit check for credential {credential_id}: {current_count}/{requests_per_minute} requests in last {window_minutes} minute(s)")
                    
                    if current_count >= requests_per_minute:
                        logger.warning(f"Rate limit exceeded for credential {credential_id}: {current_count}/{requests_per_minute} requests per minute")
                        return False
                    
                    return True
                    
        except Exception as e:
            logger.error(f"Error checking rate limit: {str(e)}")
            return False
    
    def get_rate_limit_info(self, credential_id: int) -> Dict[str, Any]:
        """
        Get rate limit information for an API key
        
        Returns:
            Dict with rate limit details
        """
        try:
            # Get rate limit for this credential
            requests_per_minute, scope = self._get_rate_limit_for_credential(credential_id)
            
            with self._get_db_connection() as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                    
                    # Count current requests in the last minute
                    cursor.execute("""
                        SELECT COUNT(*) as count FROM request_audit_log 
                        WHERE credential_id = %s 
                        AND timestamp > NOW() - INTERVAL '1 minute'
                        AND response_code < 500
                    """, (credential_id,))
                    
                    result = cursor.fetchone()
                    current_count = result['count'] if result else 0
                    remaining = max(0, requests_per_minute - current_count)
                    
                    return {
                        'scope': scope,
                        'requests_per_minute': requests_per_minute,
                        'current_usage': current_count,
                        'remaining': remaining,
                        'reset_time': 60 - datetime.now().second  # Seconds until next minute
                    }
                    
        except Exception as e:
            import traceback
            logger.error(f"Error getting rate limit info: {str(e)}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            return {
                'scope': 'unknown',
                'requests_per_minute': 50,
                'current_usage': 0,
                'remaining': 50,
                'reset_time': 60
            } 