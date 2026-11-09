from fastapi import HTTPException, status, Request
from typing import Optional, List, Dict, Any
import logging
import ipaddress
from auth.api_key_manager import APIKeyManager, resolve_scopes
from middleware.audit_logger import AuditLogger

logger = logging.getLogger(__name__)

class FastAPIAuth:
    """FastAPI authentication utilities"""
    
    def __init__(self):
        self.api_key_manager = APIKeyManager()
        self.audit_logger = AuditLogger()
    
    def _get_client_ip(self, request: Request) -> str:
        """
        Return the resolved client IP.

        The reject_spoofed_ip_headers middleware (main.py) runs first and writes
        the authoritative value to request.state.real_client_ip, applying trusted-
        proxy logic and spoofing detection.  Read from there so all layers agree
        on a single IP rather than each re-parsing the headers independently.
        """
        return getattr(request.state, "real_client_ip", None) or (
            request.client.host if request.client else "unknown"
        )

    def _audit_request_data(self, request: Request) -> Optional[Dict[str, Any]]:
        """Return sanitized request body for audit logging (set by cache_request_body_middleware)."""
        body = getattr(request.state, "request_body", None)
        if isinstance(body, dict):
            return self.audit_logger._sanitize_request_data(body)
        return None
    
    async def verify_api_key(self, request: Request) -> dict:
        """Verify API key and return credential info"""
        api_key = request.headers.get("X-API-Key")
        client_ip = self._get_client_ip(request)
        user_agent = request.headers.get("user-agent", "Unknown")
        
        if not api_key:
            self.audit_logger.log_request(
                credential_id=None,
                endpoint_path=str(request.url.path),
                http_method=request.method,
                client_ip=client_ip,
                user_agent=user_agent,
                success=False,
                response_code=401,
                request_data=self._audit_request_data(request),
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="API key required. Include X-API-Key header.",
                headers={"WWW-Authenticate": "ApiKey"}
            )
        
        # Validate API key
        credential = self.api_key_manager.validate_api_key(api_key)
        if not credential:
            self.audit_logger.log_request(
                credential_id=None,
                endpoint_path=str(request.url.path),
                http_method=request.method,
                client_ip=client_ip,
                user_agent=user_agent,
                success=False,
                response_code=401,
                request_data=self._audit_request_data(request),
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key",
                headers={"WWW-Authenticate": "ApiKey"}
            )
        
        # Check rate limits
        if not self.api_key_manager.check_rate_limit(credential['id']):
            # Get detailed rate limit info for better error message
            rate_info = self.api_key_manager.get_rate_limit_info(credential['id'])
            
            self.audit_logger.log_request(
                credential_id=credential['id'],
                key_name=credential.get('name'),
                endpoint_path=str(request.url.path),
                http_method=request.method,
                client_ip=client_ip,
                user_agent=user_agent,
                success=False,
                response_code=429
            )
            
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "error": "Rate limit exceeded",
                    "message": f"You have exceeded the rate limit for your API key scope ({rate_info['scope']})",
                    "rate_limit": {
                        "requests_per_minute": rate_info['requests_per_minute'],
                        "current_usage": rate_info['current_usage'],
                        "remaining": rate_info['remaining'],
                        "reset_in_seconds": rate_info['reset_time'],
                        "scope": rate_info['scope']
                    },
                    "retry_after": rate_info['reset_time']
                },
                headers={
                    "Retry-After": str(rate_info['reset_time']),
                    "X-RateLimit-Limit": str(rate_info['requests_per_minute']),
                    "X-RateLimit-Remaining": str(rate_info['remaining']),
                    "X-RateLimit-Reset": str(rate_info['reset_time']),
                    "X-RateLimit-Scope": rate_info['scope']
                }
            )
        
        return credential
    
    def _deny(self, request: Request, credential: dict, detail: str):
        """Log and raise a 403."""
        client_ip = self._get_client_ip(request)
        self.audit_logger.log_request(
            credential_id=credential['id'],
            key_name=credential.get('name'),
            endpoint_path=str(request.url.path),
            http_method=request.method,
            client_ip=self._get_client_ip(request),
            user_agent=request.headers.get("user-agent", "Unknown"),
            success=False,
            response_code=403
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)

    def require_scope(self, required_scope: str):
        """Return a FastAPI dependency that enforces a single scope."""
        async def check(request: Request) -> dict:
            credential = await self.verify_api_key(request)
            scopes = resolve_scopes(credential)
            if "*" not in scopes and required_scope not in scopes:
                logger.warning(
                    f"Scope denied — credential {credential['id']} needs '{required_scope}', has {scopes}"
                )
                self._deny(request, credential, f"Scope '{required_scope}' required for this operation")
            return credential
        return check

    async def require_read_access(self, request: Request) -> dict:
        """Kept for backwards compatibility — requires any read scope."""
        return await self.require_scope("vendors:list")(request)

    async def require_admin_access(self, request: Request) -> dict:
        """Kept for backwards compatibility — requires admin (wildcard) scope."""
        return await self.require_scope("vendors:add")(request)

# Global instance
fastapi_auth = FastAPIAuth() 